// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const (
	walAppKey            = "appCreate"
	walRotateRootCreds   = "rotateRootCreds"
	walAppRoleAssignment = "appRoleAssign"
	walPurgeDeleted      = "purgeDeleted"
	walServicePrincipal  = "servicePrincipalCleanup"
)

// Eventually expire the WAL if for some reason the rollback operation consistently fails
var maxWALAge = 24 * time.Hour

func (b *azureSecretBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	if kind != walRotateRootCreds {
		if err := ctx.Err(); err != nil {
			return err
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < time.Second {
			return errors.New("rollback pass deadline near; retaining WAL for a later pass")
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		ctx = api.WithoutInlineCleanupRetries(ctx)
	}
	switch kind {
	case walAppKey:
		return b.rollbackAppWAL(ctx, req, data)
	case walRotateRootCreds:
		return b.rollbackRootWAL(ctx, req, data)
	case walAppRoleAssignment:
		return b.rollbackRoleAssignWAL(ctx, req, data)
	case walPurgeDeleted:
		return b.rollbackPurgeWAL(ctx, req, data)
	case walServicePrincipal:
		return b.rollbackSPWAL(ctx, req, data)
	default:
		return fmt.Errorf("unknown rollback type %q", kind)
	}
}

type walApp struct {
	AppID      string
	AppObjID   string
	SPObjID    string
	IssuedAt   time.Time
	Expiration time.Time
}

func (b *azureSecretBackend) rollbackAppWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	// Decode the WAL data
	var entry walApp
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &entry,
	})
	if err != nil {
		return err
	}
	err = d.Decode(data)
	if err != nil {
		return err
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	rollbackLogger := b.Logger().With("appID", entry.AppID, "appObjID", entry.AppObjID)
	rollbackLogger.Debug("rollback: attempting to delete app")

	var principals []api.ServicePrincipal
	var spErr error
	if entry.SPObjID != "" {
		principals = []api.ServicePrincipal{{ID: entry.SPObjID, AppID: entry.AppID}}
	} else {
		principals, spErr = client.provider.FindServicePrincipalsForCleanup(ctx, entry.AppID)
	}
	err = client.deleteApp(b.reconciliationContext(ctx, entry.IssuedAt, entry.AppObjID), entry.AppObjID, true)
	appErr := b.deferPurge(ctx, req.Storage, err)
	// App deletion cascades only the soft delete. SP cleanup must survive
	// independently, even when discovery fails or the app is already purged.
	for _, sp := range principals {
		if sp.ID == "" || !strings.EqualFold(sp.AppID, entry.AppID) {
			spErr = errors.Join(spErr, errors.New("cleanup service principal has missing ID or mismatched app ID"))
			continue
		}
		cleanupErr := client.deleteServicePrincipal(b.reconciliationContext(ctx, entry.IssuedAt, sp.ID), sp.ID, true)
		spErr = errors.Join(spErr, b.deferPurge(ctx, req.Storage, cleanupErr))
	}
	err = errors.Join(spErr, appErr)
	if err != nil {
		rollbackLogger.Warn("rollback: error deleting app", "err", err)

		// If we don't succeed within maxWALAge (e.g. client creds have changed
		// and the delete will never succeed), unconditionally remove the WAL.
		if time.Now().After(entry.Expiration) && ctx.Err() == nil {
			rollbackLogger.Warn("rollback: app WAL expired prior to rollback; resources may still exist")
			return nil
		}
		return err
	}

	rollbackLogger.Debug("rollback: deleted app")
	return nil
}

type walPurge struct {
	Resource   string
	ObjectID   string
	Expiration time.Time
}

type walSP struct {
	ObjectID          string
	PermanentlyDelete bool
	IssuedAt          time.Time
	Expiration        time.Time
}

func (b *azureSecretBackend) rollbackSPWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	var entry walSP
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339), Result: &entry,
	})
	if err != nil {
		return err
	}
	if err := d.Decode(data); err != nil {
		return err
	}
	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}
	err = c.deleteServicePrincipal(b.reconciliationContext(ctx, entry.IssuedAt, entry.ObjectID), entry.ObjectID, entry.PermanentlyDelete)
	if err = b.deferPurge(ctx, req.Storage, err); err != nil {
		b.Logger().Warn("rollback: service principal cleanup failed", "objectID", entry.ObjectID, "err", err)
		if time.Now().After(entry.Expiration) && ctx.Err() == nil {
			b.Logger().Warn("rollback: service principal WAL expired; object may remain", "objectID", entry.ObjectID)
			return nil
		}
	}
	return err
}

// deferPurge records a pending permanent deletion as a WAL entry and reports
// success. Soft deletion was established, or the explicitly enabled age-based
// absence heuristic accepted it. Vault retries after WALRollbackMinAge.
// Other errors pass through.
func (b *azureSecretBackend) deferPurge(ctx context.Context, s logical.Storage, err error) error {
	var pending *api.PurgePendingError
	if !errors.As(err, &pending) {
		return err
	}
	entry := &walPurge{Resource: pending.Resource, ObjectID: pending.ObjectID, Expiration: time.Now().Add(maxWALAge)}
	if _, walErr := framework.PutWAL(ctx, s, walPurgeDeleted, entry); walErr != nil {
		return errors.Join(err, fmt.Errorf("error recording deferred permanent deletion: %w", walErr))
	}
	b.Logger().Info("permanent deletion deferred to WAL rollback", "resource", pending.Resource,
		"objectID", pending.ObjectID, "reason", pending.Err)
	return nil
}

func (b *azureSecretBackend) rollbackPurgeWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	var entry walPurge
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &entry,
	})
	if err != nil {
		return err
	}
	if err := d.Decode(data); err != nil {
		return err
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	rollbackLogger := b.Logger().With("resource", entry.Resource, "objectID", entry.ObjectID)
	if err := client.purgeDeletedObject(ctx, entry.ObjectID); err != nil {
		rollbackLogger.Warn("rollback: error permanently deleting object", "err", err)
		if time.Now().After(entry.Expiration) && ctx.Err() == nil {
			rollbackLogger.Warn("rollback: purge WAL expired prior to rollback; object may remain in deleted items")
			return nil
		}
		return err
	}

	rollbackLogger.Debug("rollback: permanently deleted object")
	return nil
}

type walRotateRoot struct{}

func (b *azureSecretBackend) rollbackRootWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	b.Logger().Debug("rolling back config")
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return err
	}

	config.NewClientSecret = ""
	config.NewClientSecretCreated = time.Time{}
	config.NewClientSecretExpirationDate = time.Time{}
	config.NewClientSecretKeyID = ""

	err = b.saveConfig(ctx, config, req.Storage)
	if err != nil {
		return err
	}

	b.updatePassword = false

	return nil
}

type walAppRoleAssign struct {
	SpID              string
	AssignmentIDs     []string
	RoleAssignmentIDs []string
	AzureRoles        []*AzureRole
	Expiration        time.Time
}

func (b *azureSecretBackend) rollbackRoleAssignWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	// Decode the WAL data
	var entry walAppRoleAssign
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &entry,
	})
	if err != nil {
		return err
	}
	err = d.Decode(data)
	if err != nil {
		return err
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	rollbackLogger := b.Logger().With("principalId", entry.SpID)
	rollbackLogger.Debug("rollback: attempting to remove role assignments for service principal")

	// Older issuance WALs have scope/name pairs; revoke WALs contain full IDs.
	roleAssignments := append([]string(nil), entry.RoleAssignmentIDs...)
	if len(entry.AssignmentIDs) != len(entry.AzureRoles) {
		return errors.New("role assignment WAL has mismatched assignment IDs and scopes")
	}
	for i, assignmentID := range entry.AssignmentIDs {
		if entry.AzureRoles[i] == nil {
			return fmt.Errorf("azure role was nil for service principal: %s", entry.SpID)
		}
		roleAssignments = append(roleAssignments, fmt.Sprintf("%s/providers/Microsoft.Authorization/roleAssignments/%s",
			entry.AzureRoles[i].Scope,
			assignmentID))
	}

	if err := client.unassignRoles(ctx, roleAssignments); err != nil {
		rollbackLogger.Warn("rollback: role assignment cleanup failed", "assignmentIDs", roleAssignments, "err", err)
		if time.Now().After(entry.Expiration) && ctx.Err() == nil {
			rollbackLogger.Warn("rollback: role assignment WAL expired prior to rollback; resources may still exist", "assignmentIDs", roleAssignments)
			return nil
		}
		return err
	}
	return nil
}
