// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

type cleanupFailureProvider struct {
	AzureProvider
	app  func(context.Context, string, bool) error
	sp   func(context.Context, string, bool) error
	role func(context.Context, string) error
	find func(context.Context, string) ([]api.ServicePrincipal, error)
}

func (p *cleanupFailureProvider) DeleteApplication(ctx context.Context, id string, permanent bool) error {
	if p.app != nil {
		return p.app(ctx, id, permanent)
	}
	return p.AzureProvider.DeleteApplication(ctx, id, permanent)
}

func (p *cleanupFailureProvider) DeleteServicePrincipal(ctx context.Context, id string, permanent bool) error {
	if p.sp != nil {
		return p.sp(ctx, id, permanent)
	}
	return p.AzureProvider.DeleteServicePrincipal(ctx, id, permanent)
}

func (p *cleanupFailureProvider) DeleteRoleAssignmentByID(ctx context.Context, id string) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error) {
	if p.role != nil {
		return armauthorization.RoleAssignmentsClientDeleteByIDResponse{}, p.role(ctx, id)
	}
	return p.AzureProvider.DeleteRoleAssignmentByID(ctx, id)
}

func (p *cleanupFailureProvider) FindServicePrincipalsForCleanup(ctx context.Context, appID string) ([]api.ServicePrincipal, error) {
	if p.find != nil {
		return p.find(ctx, appID)
	}
	return p.AzureProvider.FindServicePrincipalsForCleanup(ctx, appID)
}

type failingCleanupStorage struct{ logical.Storage }

func (s failingCleanupStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if strings.HasPrefix(entry.Key, framework.WALPrefix) {
		return errors.New("WAL storage unavailable")
	}
	return s.Storage.Put(ctx, entry)
}

func cleanupLease() *logical.Secret {
	return &logical.Secret{InternalData: map[string]interface{}{
		"app_object_id": "app", "sp_object_id": "sp", "permanently_delete": true,
		"role_assignment_ids": []interface{}{"good-role", "bad-role"},
		"issued_at":           time.Now().Add(-time.Hour).Format(time.RFC3339Nano),
	}}
}

func TestRevocationPersistsFailedHousekeeping(t *testing.T) {
	b, s := getTestBackendMocked(t, true)
	ctx := context.Background()
	c, err := b.getClient(ctx, s)
	require.NoError(t, err)
	var calls []string
	c.provider = &cleanupFailureProvider{
		AzureProvider: c.provider,
		app:           func(context.Context, string, bool) error { calls = append(calls, "app"); return nil },
		role: func(_ context.Context, id string) error {
			calls = append(calls, id)
			if id == "bad-role" {
				return errors.New("role deletion denied")
			}
			return nil
		},
		sp: func(context.Context, string, bool) error {
			calls = append(calls, "sp")
			return errors.New("SP deletion uncertain")
		},
	}
	resp, err := b.spRevoke(ctx, &logical.Request{Storage: s, Secret: cleanupLease()}, nil)
	require.NoError(t, err)
	require.Len(t, resp.Warnings, 2)
	require.Equal(t, []string{"app", "good-role", "bad-role", "sp"}, calls)
	ids, err := framework.ListWAL(ctx, s)
	require.NoError(t, err)
	require.Len(t, ids, 2)
	for _, id := range ids {
		entry, err := framework.GetWAL(ctx, s, id)
		require.NoError(t, err)
		data := entry.Data.(map[string]interface{})
		switch entry.Kind {
		case walAppRoleAssignment:
			require.Equal(t, []interface{}{"bad-role"}, data["RoleAssignmentIDs"])
		case walServicePrincipal:
			require.Equal(t, "sp", data["ObjectID"])
		default:
			t.Fatalf("unexpected WAL kind %q", entry.Kind)
		}
	}

	// A new backend instance consumes the persisted records, not in-memory state.
	restarted, _, _, _ := getTestBackendWithStorage(t, false, s, false)
	resp, err = restarted.HandleRequest(ctx, &logical.Request{
		Operation: logical.RollbackOperation, Storage: s, Data: map[string]interface{}{"immediate": true},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())
	ids, err = framework.ListWAL(ctx, s)
	require.NoError(t, err)
	require.Empty(t, ids)
}

func TestRevocationFailsIfHousekeepingCannotBeRecorded(t *testing.T) {
	for _, stage := range []string{"app purge", "role", "SP soft delete", "SP purge"} {
		t.Run(stage, func(t *testing.T) {
			b, s := getTestBackendMocked(t, true)
			ctx := context.Background()
			c, err := b.getClient(ctx, s)
			require.NoError(t, err)
			p := &cleanupFailureProvider{AzureProvider: c.provider}
			failure := errors.New("Graph failure")
			switch stage {
			case "app purge":
				p.app = func(context.Context, string, bool) error {
					return &api.PurgePendingError{Resource: "application", ObjectID: "app", Err: failure}
				}
			case "role":
				p.role = func(context.Context, string) error { return failure }
			case "SP soft delete":
				p.sp = func(context.Context, string, bool) error { return failure }
			case "SP purge":
				p.sp = func(context.Context, string, bool) error {
					return &api.PurgePendingError{Resource: "service principal", ObjectID: "sp", Err: failure}
				}
			}
			c.provider = p
			_, err = b.spRevoke(ctx, &logical.Request{Storage: failingCleanupStorage{s}, Secret: cleanupLease()}, nil)
			require.ErrorContains(t, err, "WAL storage unavailable")
		})
	}
}

func TestApplicationRollbackCleansServicePrincipal(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy or ambiguous creation", true: "recorded SP"}[known], func(t *testing.T) {
			b, s := getTestBackendMocked(t, true)
			ctx := context.Background()
			c, err := b.getClient(ctx, s)
			require.NoError(t, err)
			var calls []string
			entry := &walApp{AppID: "client-id", AppObjID: "app", IssuedAt: time.Now().Add(-time.Hour), Expiration: time.Now().Add(maxWALAge)}
			if known {
				entry.SPObjID = "sp"
			}
			c.provider = &cleanupFailureProvider{
				AzureProvider: c.provider,
				find: func(_ context.Context, appID string) ([]api.ServicePrincipal, error) {
					require.False(t, known)
					require.Equal(t, entry.AppID, appID)
					return []api.ServicePrincipal{{ID: "sp", AppID: appID}}, nil
				},
				app: func(context.Context, string, bool) error { calls = append(calls, "app"); return nil },
				sp: func(_ context.Context, id string, permanent bool) error {
					require.Equal(t, "sp", id)
					require.True(t, permanent)
					calls = append(calls, "sp")
					return &api.PurgePendingError{Resource: "service principal", ObjectID: id, Err: errors.New("purge delay")}
				},
			}
			require.NoError(t, b.walRollback(ctx, &logical.Request{Storage: s}, walAppKey, entry))
			require.Equal(t, []string{"app", "sp"}, calls)
			require.Equal(t, []walPurge{{Resource: "service principal", ObjectID: "sp"}}, purgeWALs(t, s))
		})
	}
}

func TestApplicationRollbackRetainsDiscoveryFailures(t *testing.T) {
	b, s := getTestBackendMocked(t, true)
	ctx := context.Background()
	c, err := b.getClient(ctx, s)
	require.NoError(t, err)
	appDeleted := false
	c.provider = &cleanupFailureProvider{AzureProvider: c.provider,
		find: func(context.Context, string) ([]api.ServicePrincipal, error) {
			return nil, errors.New("discovery denied")
		},
		app: func(context.Context, string, bool) error { appDeleted = true; return nil },
	}
	err = b.walRollback(ctx, &logical.Request{Storage: s}, walAppKey, &walApp{
		AppID: "client", AppObjID: "app", Expiration: time.Now().Add(maxWALAge),
	})
	require.ErrorContains(t, err, "discovery denied")
	require.True(t, appDeleted, "SP discovery failure must not prevent revoking the app")
}

func TestRollbackBudgetAndCancellationRetainWAL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, s := getTestBackendMocked(t, true)
		ctx := context.Background()
		c, err := b.getClient(ctx, s)
		require.NoError(t, err)
		calls := 0
		c.provider = &cleanupFailureProvider{AzureProvider: c.provider,
			sp: func(ctx context.Context, _ string, _ bool) error {
				calls++
				<-ctx.Done()
				return ctx.Err()
			},
		}
		entry := &walSP{ObjectID: "sp", PermanentlyDelete: true, Expiration: time.Now().Add(-time.Hour)}
		start := time.Now()
		err = b.walRollback(ctx, &logical.Request{Storage: s}, walServicePrincipal, entry)
		require.ErrorIs(t, err, context.DeadlineExceeded, "deadline must not expire the WAL")
		require.Equal(t, 5*time.Second, time.Since(start))
		ctx, cancel := context.WithTimeout(ctx, time.Millisecond)
		defer cancel()
		require.ErrorContains(t, b.walRollback(ctx, &logical.Request{Storage: s}, walServicePrincipal, entry), "retaining WAL")
		require.Equal(t, 1, calls)
	})
}

func TestLeaseIssuedAt(t *testing.T) {
	now := time.Now().UTC()
	secret := &logical.Secret{InternalData: map[string]interface{}{}}
	secret.IssueTime = now.Add(-time.Hour)
	got, err := leaseIssuedAt(secret)
	require.NoError(t, err)
	require.Equal(t, secret.IssueTime, got)
	secret.InternalData["issued_at"] = now.Format(time.RFC3339Nano)
	got, err = leaseIssuedAt(secret)
	require.NoError(t, err)
	require.Equal(t, now, got)
	for _, value := range []interface{}{42, "", "bad date", time.Time{}.Format(time.RFC3339Nano)} {
		secret.InternalData["issued_at"] = value
		_, err := leaseIssuedAt(secret)
		require.Error(t, err)
	}
	delete(secret.InternalData, "issued_at")
	secret.IssueTime = time.Time{}
	got, err = leaseIssuedAt(secret)
	require.NoError(t, err)
	require.True(t, got.IsZero())
}

type failWALReplacementStorage struct {
	logical.Storage
	writes     int
	failDelete bool
}

func (s *failWALReplacementStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if strings.HasPrefix(entry.Key, framework.WALPrefix) {
		s.writes++
		if s.writes == 2 && !s.failDelete {
			return errors.New("replacement write failed")
		}
	}
	return s.Storage.Put(ctx, entry)
}

func (s *failWALReplacementStorage) Delete(ctx context.Context, key string) error {
	if strings.HasPrefix(key, framework.WALPrefix) && s.failDelete {
		return errors.New("original WAL delete failed")
	}
	return s.Storage.Delete(ctx, key)
}

func TestIssuanceWALReplacementRetainsCleanup(t *testing.T) {
	for _, failDelete := range []bool{false, true} {
		t.Run(map[bool]string{false: "replacement write", true: "original delete"}[failDelete], func(t *testing.T) {
			b, s := getTestBackendMocked(t, true)
			ctx := context.Background()
			c, err := b.getClient(ctx, s)
			require.NoError(t, err)
			storage := &failWALReplacementStorage{Storage: s, failDelete: failDelete}
			_, err = b.createSPSecret(ctx, storage, c, "test", &roleEntry{})
			require.Error(t, err)
			ids, err := framework.ListWAL(ctx, s)
			require.NoError(t, err)
			count := 1
			if failDelete {
				count = 2
			}
			require.Len(t, ids, count)
			recordedSP := false
			for _, id := range ids {
				entry, err := framework.GetWAL(ctx, s, id)
				require.NoError(t, err)
				require.Equal(t, walAppKey, entry.Kind)
				data := entry.Data.(map[string]interface{})
				require.NotEmpty(t, data["AppID"])
				require.NotEmpty(t, data["AppObjID"])
				recordedSP = recordedSP || data["SPObjID"] != ""
			}
			require.Equal(t, failDelete, recordedSP)
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.RollbackOperation, Storage: s, Data: map[string]interface{}{"immediate": true},
			})
			require.NoError(t, err)
			require.False(t, resp.IsError())
			require.Empty(t, c.provider.(*mockProvider).servicePrincipals)
		})
	}
}

func TestRevokeLegacyAbsentApplicationRetainsPurge(t *testing.T) {
	b, s := getTestBackendMocked(t, true)
	ctx := context.Background()
	c, err := b.getClient(ctx, s)
	require.NoError(t, err)
	c.provider = &graphCleanupProvider{AzureProvider: c.provider, graph: cleanupGraph(t,
		cleanupGraphStep{"/applications/app", 404, ""},
		cleanupGraphStep{"/directory/deletedItems/app", 403, ""},
		cleanupGraphStep{"/directory/deletedItems/app", 403, "GET"},
		cleanupGraphStep{"/applications/app", 404, "GET"},
		cleanupGraphStep{"/applications/app", 404, "GET"},
		cleanupGraphStep{"/applications/app", 404, "GET"},
		cleanupGraphStep{"/servicePrincipals/sp", 404, ""},
		cleanupGraphStep{"/directory/deletedItems/sp", 204, ""},
	)}
	secret := cleanupLease()
	delete(secret.InternalData, "issued_at")
	resp, err := b.spRevoke(ctx, &logical.Request{Storage: s, Secret: secret}, nil)
	require.NoError(t, err)
	require.Empty(t, resp.Warnings)
	require.Equal(t, []walPurge{{Resource: "application", ObjectID: "app"}}, purgeWALs(t, s))
}
