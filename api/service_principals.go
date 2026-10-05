// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/microsoftgraph/msgraph-sdk-go/directory"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
)

type ServicePrincipalClient interface {
	// CreateServicePrincipal in Azure. The password returned is the actual password that the appID was created with
	CreateServicePrincipal(ctx context.Context, appID string, startDate time.Time, endDate time.Time) (id string, password string, err error)
	DeleteServicePrincipal(ctx context.Context, spObjectID string, permanentlyDelete bool) error
	FindServicePrincipalsForCleanup(ctx context.Context, appID string) ([]ServicePrincipal, error)
}

type ServicePrincipal struct {
	ID    string
	AppID string
}

// FindServicePrincipalsForCleanup includes soft-deleted principals, including
// those left by a lost create response or by password-failure cleanup.
func (c *MSGraphClient) FindServicePrincipalsForCleanup(ctx context.Context, appID string) ([]ServicePrincipal, error) {
	if _, err := uuid.Parse(appID); err != nil {
		return nil, fmt.Errorf("find cleanup service principals: invalid app ID: %w", err)
	}
	filter := fmt.Sprintf("appId eq '%s'", appID)
	active := c.client.ServicePrincipals()
	deleted := c.client.Directory().DeletedItems().GraphServicePrincipal()
	var result []ServicePrincipal
	seen := make(map[string]bool)
	for _, isDeleted := range []bool{false, true} {
		next := ""
		for {
			var page models.ServicePrincipalCollectionResponseable
			var err error
			if isDeleted {
				config := &directory.DeletedItemsGraphServicePrincipalRequestBuilderGetRequestConfiguration{Options: noSDKRetry()}
				builder := deleted
				if next == "" {
					config.QueryParameters = &directory.DeletedItemsGraphServicePrincipalRequestBuilderGetQueryParameters{Filter: &filter}
				} else {
					builder = deleted.WithUrl(next)
				}
				page, err = builder.Get(ctx, config)
			} else {
				config := &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{Options: noSDKRetry()}
				builder := active
				if next == "" {
					config.QueryParameters = &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{Filter: &filter}
				} else {
					builder = active.WithUrl(next)
				}
				page, err = builder.Get(ctx, config)
			}
			if err != nil {
				return nil, fmt.Errorf("find cleanup service principals (deleted=%t)%s: %w", isDeleted, GraphErrorDetails(err), err)
			}
			if page == nil {
				return nil, errors.New("find cleanup service principals: missing response")
			}
			for _, item := range page.GetValue() {
				sp := getServicePrincipalResponse(item)
				if sp.ID == "" || !strings.EqualFold(sp.AppID, appID) {
					return nil, errors.New("find cleanup service principals: missing ID or mismatched app ID")
				}
				if !seen[sp.ID] {
					seen[sp.ID] = true
					result = append(result, sp)
				}
			}
			next = ptrToString(page.GetOdataNextLink())
			if next == "" {
				break
			}
		}
	}
	return result, nil
}

func (c *MSGraphClient) CreateServicePrincipal(ctx context.Context, appID string, startDate time.Time, endDate time.Time) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()

	spReq := models.NewServicePrincipal()
	spReq.SetAppId(&appID)

	var sp models.ServicePrincipalable
	err := retryServicePrincipalStage(ctx, true, func() error {
		var err error
		sp, err = c.client.ServicePrincipals().Post(ctx, spReq, &serviceprincipals.ServicePrincipalsRequestBuilderPostRequestConfiguration{
			Options: noSDKRetry(),
		})
		return err
	})
	if err != nil {
		return "", "", fmt.Errorf("create service principal POST: %w", err)
	}

	if sp == nil || ptrToString(sp.GetId()) == "" || appID == "" ||
		!strings.EqualFold(ptrToString(sp.GetAppId()), appID) {
		return "", "", fmt.Errorf("create service principal POST: missing ID or mismatched app ID; application WAL cleanup required")
	}
	spID := *sp.GetId()

	passwordReq := serviceprincipals.NewItemAddPasswordPostRequestBody()
	passwordCredential := models.NewPasswordCredential()
	passwordCredential.SetStartDateTime(&startDate)
	passwordCredential.SetEndDateTime(&endDate)

	passwordReq.SetPasswordCredential(passwordCredential)

	var password models.PasswordCredentialable
	err = retryServicePrincipalStage(ctx, false, func() error {
		var err error
		password, err = c.client.ServicePrincipals().ByServicePrincipalId(spID).AddPassword().Post(ctx, passwordReq, &serviceprincipals.ItemAddPasswordRequestBuilderPostRequestConfiguration{
			Options: noSDKRetry(),
		})
		return err
	})
	if err == nil && (password == nil || ptrToString(password.GetSecretText()) == "") {
		err = fmt.Errorf("missing secret in response; password outcome is uncertain")
	}

	if err != nil {
		// Cleanup must still be attempted after request cancellation. The app WAL
		// remains the durable fallback if this bounded best-effort delete fails.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		cleanupErr := c.DeleteServicePrincipal(cleanupCtx, spID, false)
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("delete service principal after password failure: %w", cleanupErr)
		}
		merr := multierror.Append(fmt.Errorf("add service principal password POST: %w", err), cleanupErr)
		return "", "", merr.ErrorOrNil()
	}
	return spID, *password.GetSecretText(), nil
}

func retryServicePrincipalStage(ctx context.Context, creating bool, post func() error) error {
	stage := "add_service_principal_password"
	if creating {
		stage = "create_service_principal"
	}
	SetIssuanceStage(ctx, stage)
	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, lastErr)
		}
		if attempt > 0 {
			RecordIssuanceRetry(ctx, stage)
		}
		err := post()
		if !isServicePrincipalPropagationError(err, creating) {
			return err
		}
		lastErr = err
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}

func isServicePrincipalPropagationError(err error, creating bool) bool {
	var graphErr *odataerrors.ODataError
	if !errors.As(err, &graphErr) || graphErr.GetErrorEscaped() == nil {
		return false
	}
	detail := graphErr.GetErrorEscaped()
	code := strings.ToLower(ptrToString(detail.GetCode()))
	message := strings.ToLower(ptrToString(detail.GetMessage()))
	status := graphErr.GetStatusCode()

	// This specific denial can occur before the newly created app is visible.
	// Other permission errors must not be treated as propagation failures.
	localApp := creating && strings.Contains(message, "the backing application of the service principal being created must be in the local tenant")
	if status == http.StatusForbidden && code == "authorization_requestdenied" {
		return localApp
	}
	if status != http.StatusBadRequest && status != http.StatusNotFound {
		return false
	}
	if code != "request_badrequest" && code != "badrequest" && code != "request_resourcenotfound" {
		return false
	}
	if strings.Contains(message, "does not exist or one of its queried reference-property objects are not present") {
		return true
	}
	return creating && (localApp || strings.Contains(message, "does not reference a valid application object"))
}

func (c *MSGraphClient) DeleteServicePrincipal(ctx context.Context, spObjectID string, permanentlyDelete bool) error {
	return deleteGraphObject(ctx, "service principal", spObjectID, permanentlyDelete, cleanupOperations{
		softDelete: func(ctx context.Context) error {
			return c.client.ServicePrincipals().ByServicePrincipalId(spObjectID).Delete(ctx,
				&serviceprincipals.ServicePrincipalItemRequestBuilderDeleteRequestConfiguration{Options: noSDKRetry()})
		},
		confirmDeleted: func(ctx context.Context) error {
			obj, err := c.client.Directory().DeletedItems().ByDirectoryObjectId(spObjectID).Get(ctx,
				&directory.DeletedItemsDirectoryObjectItemRequestBuilderGetRequestConfiguration{Options: noSDKRetry()})
			if err != nil {
				return fmt.Errorf("check deleted items%s: %w", GraphErrorDetails(err), err)
			}
			sp, ok := obj.(models.ServicePrincipalable)
			if !ok || !strings.EqualFold(ptrToString(sp.GetId()), spObjectID) {
				return errors.New("check deleted items: response is not the expected service principal")
			}
			return nil
		},
		purge: func(ctx context.Context) error {
			return c.purgeDeletedObject(ctx, spObjectID)
		},
		readActive: func(ctx context.Context) error {
			sp, err := c.client.ServicePrincipals().ByServicePrincipalId(spObjectID).Get(ctx,
				&serviceprincipals.ServicePrincipalItemRequestBuilderGetRequestConfiguration{Options: noSDKRetry()})
			if err != nil {
				return err
			}
			if sp == nil || !strings.EqualFold(ptrToString(sp.GetId()), spObjectID) {
				return errors.New("check active service principal: missing or mismatched ID")
			}
			return nil
		},
	}, waitCleanup)
}

func (c *MSGraphClient) ListServicePrincipals(ctx context.Context, spObjectID string) ([]ServicePrincipal, error) {
	filter := fmt.Sprintf("appId eq '%s'", spObjectID)
	requestParameters := &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
		Filter: &filter,
	}

	configuration := &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}

	spList, err := c.client.ServicePrincipals().Get(ctx, configuration)
	if err != nil {
		return nil, err
	}

	var result []ServicePrincipal
	for _, sp := range spList.GetValue() {
		result = append(result, getServicePrincipalResponse(sp))
	}
	return result, nil
}

func (c *MSGraphClient) GetServicePrincipalByID(ctx context.Context, spObjectID string) (ServicePrincipal, error) {
	sp, err := c.client.ServicePrincipals().ByServicePrincipalId(spObjectID).Get(ctx, nil)
	if err != nil {
		return ServicePrincipal{}, err
	}

	return getServicePrincipalResponse(sp), nil
}

func getServicePrincipalResponse(sp models.ServicePrincipalable) ServicePrincipal {
	if sp != nil {
		return ServicePrincipal{
			ID:    ptrToString(sp.GetId()),
			AppID: ptrToString(sp.GetAppId()),
		}
	}
	return ServicePrincipal{
		ID:    "",
		AppID: "",
	}
}
