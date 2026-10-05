// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/require"
)

func TestRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	t.Parallel()
	t.Run("First try success", func(t *testing.T) {
		_, err := retry(context.Background(), func() (interface{}, bool, error) {
			return nil, true, nil
		})
		assertErrorIsNil(t, err)
	})

	t.Run("Three retries", func(t *testing.T) {
		t.Parallel()
		count := 0

		_, err := retry(context.Background(), func() (interface{}, bool, error) {
			count++
			if count >= 3 {
				return nil, true, nil
			}
			return nil, false, nil
		})
		equal(t, count, 3)

		assertErrorIsNil(t, err)
	})

	t.Run("Error on attempt", func(t *testing.T) {
		t.Parallel()
		_, err := retry(context.Background(), func() (interface{}, bool, error) {
			return nil, true, errors.New("Fail")
		})
		if err == nil || !strings.Contains(err.Error(), "Fail") {
			t.Fatalf("expected failure error, got: %v", err)
		}
	})

	// timeout test
	t.Run("Timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode.")
		}
		t.Parallel()
		start := time.Now()

		timeout := 10 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		called := 0
		_, err := retry(ctx, func() (interface{}, bool, error) {
			called++
			return nil, false, nil
		})
		elapsed := time.Now().Sub(start)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if called == 0 {
			t.Fatalf("retryable function was never called")
		}
		assertDuration(t, elapsed, timeout, 250*time.Millisecond)
	})

	t.Run("Cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(1 * time.Second)
			cancel()
		}()

		start := time.Now()
		_, err := retry(ctx, func() (interface{}, bool, error) {
			return nil, false, nil
		})
		elapsed := time.Now().Sub(start)
		assertDuration(t, elapsed, 1*time.Second, 250*time.Millisecond)

		if err == nil {
			t.Fatalf("expected err: got nil")
		}
		underlyingErr := errors.Unwrap(err)
		if underlyingErr != context.Canceled {
			t.Fatalf("expected %s, got: %v", context.Canceled, err)
		}
	})
}

type failingSPProvider struct {
	AzureProvider
	err       error
	deleteErr error
	calls     int
}

func (p *failingSPProvider) CreateServicePrincipal(context.Context, string, time.Time, time.Time) (string, string, error) {
	p.calls++
	return "", "", p.err
}

func (p *failingSPProvider) DeleteApplication(ctx context.Context, id string, permanentlyDelete bool) error {
	if p.deleteErr != nil {
		return p.deleteErr
	}
	return p.AzureProvider.DeleteApplication(ctx, id, permanentlyDelete)
}

func TestSPCreateFailureRetainsWAL(t *testing.T) {
	for _, failure := range []error{
		errors.New("the backing application of the service principal being created must be in the local tenant"),
		errors.New("does not exist or one of its queried reference-property objects are not present"),
		errors.New("service principal name is already in use"),
		errors.New("Authorization_RequestDenied"),
		errors.New("add service principal password POST: uncertain outcome; delete failed"),
		context.Canceled,
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			b, s := getTestBackendMocked(t, true)
			mp := newMockProvider().(*mockProvider)
			p := &failingSPProvider{AzureProvider: mp, err: failure}
			b.getProvider = func(context.Context, hclog.Logger, logical.SystemView, *clientSettings) (AzureProvider, error) {
				return p, nil
			}
			testRoleCreate(t, b, s, "test", testRole)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation, Path: "creds/test", Storage: s,
			})
			require.ErrorIs(t, err, failure)
			require.Nil(t, resp)
			require.Equal(t, 1, p.calls, "must not retry the combined provider operation")

			ctx := context.Background()
			entries, err := framework.ListWAL(ctx, s)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			entry, err := framework.GetWAL(ctx, s, entries[0])
			require.NoError(t, err)
			require.Equal(t, walAppKey, entry.Kind)
			appID := entry.Data.(map[string]interface{})["AppObjID"].(string)
			require.Contains(t, mp.applications, appID)
			p.deleteErr = errors.New("application delete failed")
			require.ErrorIs(t, b.walRollback(ctx, &logical.Request{Storage: s}, entry.Kind, entry.Data), p.deleteErr)
			retained, err := framework.GetWAL(ctx, s, entries[0])
			require.NoError(t, err)
			require.NotNil(t, retained)
			require.Contains(t, mp.applications, appID)
			p.deleteErr = nil
			require.NoError(t, b.walRollback(ctx, &logical.Request{Storage: s}, entry.Kind, entry.Data))
			require.NotContains(t, mp.applications, appID)
			require.NotContains(t, mp.deletedObjects, appID, "rollback permanently deletes the app")
			require.NoError(t, framework.DeleteWAL(ctx, s, entries[0]))
			entries, err = framework.ListWAL(ctx, s)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}

func TestSPCreateCanceledBeforeProvider(t *testing.T) {
	p := &failingSPProvider{err: errors.New("must not be called")}
	c := &client{provider: p}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err := c.createSP(ctx, api.Application{AppID: "app"}, time.Hour)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, p.calls)
}

type groupMembershipProvider struct {
	AzureProvider
	failGroup string
	err       error
	groups    []string
	members   []string
	check     func(context.Context)
	results   []error
}

func (p *groupMembershipProvider) AddGroupMember(ctx context.Context, groupID, memberID string) error {
	p.groups = append(p.groups, groupID)
	p.members = append(p.members, memberID)
	if p.check != nil {
		p.check(ctx)
	}
	if len(p.groups) <= len(p.results) {
		return p.results[len(p.groups)-1]
	}
	if groupID == p.failGroup {
		return p.err
	}
	return nil
}

func TestGroupMembershipErrorContext(t *testing.T) {
	for _, failGroup := range []string{"first-group", "second-group"} {
		for _, withMetadata := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/metadata=%t", failGroup, withMetadata), func(t *testing.T) {
				graphErr := odataerrors.NewODataError()
				detail := odataerrors.NewMainError()
				message := "Membership modification denied."
				detail.SetMessage(&message)
				graphErr.SetErrorEscaped(detail)
				graphErr.SetStatusCode(403)
				if withMetadata {
					code := "Authorization_RequestDenied"
					detail.SetCode(&code)
					graphErr.GetResponseHeaders().Add("Request-Id", "graph-correlation-id")
					graphErr.GetResponseHeaders().Add("Other-Header", "must-not-be-disclosed")
				} else {
					graphErr.SetResponseHeaders(nil)
				}
				p := &groupMembershipProvider{
					failGroup: failGroup,
					err:       fmt.Errorf("provider: %w", graphErr),
				}
				c := &client{provider: p}
				err := c.addGroupMemberships(context.Background(), "new-sp", []*AzureGroup{
					{GroupName: "First group", ObjectID: "first-group"},
					{GroupName: "Second group", ObjectID: "second-group"},
				})
				require.ErrorIs(t, err, graphErr)
				var got *odataerrors.ODataError
				require.ErrorAs(t, err, &got)
				require.Same(t, graphErr, got)
				require.ErrorContains(t, err, fmt.Sprintf("group_object_id=%q", failGroup))
				require.ErrorContains(t, err, `sp_object_id="new-sp"`)
				require.ErrorContains(t, err, "graph_status=403")
				require.ErrorContains(t, err, message)
				require.NotContains(t, err.Error(), "must-not-be-disclosed")
				if withMetadata {
					require.ErrorContains(t, err, `graph_code="Authorization_RequestDenied"`)
					require.ErrorContains(t, err, `graph_request_id="graph-correlation-id"`)
				} else {
					require.ErrorContains(t, err, `graph_code=""`)
					require.ErrorContains(t, err, `graph_request_id=""`)
				}
				if failGroup == "first-group" {
					require.ErrorContains(t, err, `group_name="First group"`)
					require.Equal(t, []string{"first-group"}, p.groups)
					require.Equal(t, []string{"new-sp"}, p.members)
				} else {
					require.ErrorContains(t, err, `group_name="Second group"`)
					require.Equal(t, []string{"first-group", "second-group"}, p.groups)
					require.Equal(t, []string{"new-sp", "new-sp"}, p.members)
				}
			})
		}
	}
}

func TestGroupMembershipNonGraphError(t *testing.T) {
	for _, failure := range []error{io.ErrUnexpectedEOF, context.Canceled, nil} {
		p := &groupMembershipProvider{failGroup: "group", err: failure}
		c := &client{provider: p}
		err := c.addGroupMemberships(context.Background(), "sp", []*AzureGroup{{ObjectID: "group"}})
		require.Equal(t, []string{"group"}, p.groups)
		if failure == nil {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, failure)
			require.ErrorContains(t, err, `group_object_id="group"`)
			require.ErrorContains(t, err, `sp_object_id="sp"`)
			require.NotContains(t, err.Error(), "graph_status")
		}
	}
}

// assertDuration with a certain amount of flex in the exact value
func assertDuration(t *testing.T, actual, expected, delta time.Duration) {
	t.Helper()

	diff := actual - expected
	if diff < 0 {
		diff = -diff
	}

	if diff > delta {
		t.Fatalf("Actual duration %s does not equal expected %s with delta %s", actual, expected, delta)
	}
}
