// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type unusedGraphCredential struct{}

func (unusedGraphCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, errors.New("local Graph tests must not request a token")
}

type membershipResponse struct {
	method    string
	body      string
	group     string
	status    int
	code      string
	message   string
	requestID string
	inner     map[string]string
}

func membershipHTTPClient(t *testing.T, responses ...membershipResponse) (*client, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(calls.Add(1)) - 1
		if !assert.Less(t, i, len(responses), "unexpected membership request") {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		response := responses[i]
		method := response.method
		if method == "" {
			method = http.MethodPost
		}
		assert.Equal(t, method, r.Method)
		assert.Empty(t, r.Header.Get("Authorization"))
		if method == http.MethodPost {
			assert.Equal(t, "/v1.0/groups/"+response.group+"/members/$ref", r.URL.Path)
			var reader io.Reader = r.Body
			if r.Header.Get("Content-Encoding") == "gzip" {
				compressed, err := gzip.NewReader(r.Body)
				if !assert.NoError(t, err) {
					http.Error(w, "invalid compression", http.StatusBadRequest)
					return
				}
				defer compressed.Close()
				reader = compressed
			}
			var body map[string]string
			assert.NoError(t, json.NewDecoder(reader).Decode(&body))
			assert.Equal(t, "https://graph.microsoft.com/v1.0/directoryObjects/new-sp", body["@odata.id"])
		} else {
			assert.Equal(t, "/v1.0/groups/"+response.group+"/members/new-sp/graph.servicePrincipal", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Other-Header", "must-not-be-disclosed")
		if response.requestID != "" {
			w.Header().Set("Request-Id", response.requestID)
		}
		w.WriteHeader(response.status)
		if response.body != "" {
			_, err := io.WriteString(w, response.body)
			assert.NoError(t, err)
		} else if response.status != http.StatusNoContent {
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code": response.code, "message": response.message, "innerError": response.inner,
				},
			}))
		}
	}))
	t.Cleanup(server.Close)
	graph, err := api.NewMSGraphClient(server.URL, unusedGraphCredential{})
	require.NoError(t, err)
	return &client{provider: &provider{groupsClient: graph}}, calls
}

func TestGroupMembershipHTTPDiagnostics(t *testing.T) {
	for _, headerID := range []string{"header-id", ""} {
		for _, bodyMetadata := range []bool{true, false} {
			t.Run(fmt.Sprintf("header=%s/body=%t", headerID, bodyMetadata), func(t *testing.T) {
				failure := membershipResponse{
					group: "second", status: 403, code: "Authorization_RequestDenied",
					message: "Membership modification denied.", requestID: headerID,
				}
				if bodyMetadata {
					failure.inner = map[string]string{
						// Graph's real format: UTC without a zone designator.
						"request-id": "body-id", "date": "2026-10-01T14:00:00",
					}
				}
				c, calls := membershipHTTPClient(t,
					membershipResponse{group: "first", status: 204},
					failure,
				)
				err := c.addGroupMemberships(context.Background(), "new-sp", []*AzureGroup{
					{GroupName: "First", ObjectID: "first"},
					{GroupName: "Second", ObjectID: "second"},
				})
				require.ErrorContains(t, err, `group_name="Second"`)
				require.ErrorContains(t, err, `group_object_id="second"`)
				require.ErrorContains(t, err, `sp_object_id="new-sp"`)
				require.ErrorContains(t, err, "graph_status=403")
				require.ErrorContains(t, err, `graph_code="Authorization_RequestDenied"`)
				require.ErrorContains(t, err, failure.message)
				expectedID := headerID
				if expectedID == "" && bodyMetadata {
					expectedID = "body-id"
				}
				require.ErrorContains(t, err, fmt.Sprintf("graph_request_id=%q", expectedID))
				expectedDate := ""
				if bodyMetadata {
					expectedDate = "2026-10-01T14:00:00Z"
				}
				require.ErrorContains(t, err, fmt.Sprintf("graph_date=%q", expectedDate))
				require.NotContains(t, err.Error(), "must-not-be-disclosed")
				var graphErr *odataerrors.ODataError
				require.ErrorAs(t, err, &graphErr)
				require.Equal(t, 403, graphErr.GetStatusCode())
				require.EqualValues(t, 2, calls.Load(), "other permission errors must not retry")
			})
		}
	}
}

func TestGroupMembershipHTTPPropagation(t *testing.T) {
	for _, failure := range []membershipResponse{
		{status: 404, code: "Request_ResourceNotFound", message: "Resource unavailable"},
		{status: 400, code: "Request_BadRequest", message: "Resource 'sp' does not exist or one of its queried reference-property objects are not present."},
		{status: 400, code: "BadRequest", message: "The source resource object or one of the objects being referenced don't exist."},
	} {
		t.Run(failure.code, func(t *testing.T) {
			t.Parallel()
			failure.group = "second"
			c, calls := membershipHTTPClient(t,
				membershipResponse{group: "first", status: 204},
				failure,
				membershipResponse{group: "second", status: 204},
			)
			err := c.addGroupMemberships(context.Background(), "new-sp", []*AzureGroup{
				{ObjectID: "first"}, {ObjectID: "second"},
			})
			require.NoError(t, err)
			require.EqualValues(t, 3, calls.Load(), "retry only the failed group")
		})
	}
}

func TestGroupMembershipPropagationMatcher(t *testing.T) {
	for _, tc := range []struct {
		status  int
		code    string
		message string
	}{
		{403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation."},
		{403, "Request_ResourceNotFound", "not found"},
		{404, "Authorization_RequestDenied", "not found"},
		{500, "Request_ResourceNotFound", "not found"},
		{503, "Request_BadRequest", "The source resource object or one of the objects being referenced don't exist."},
		{400, "Request_BadRequest", "One or more added object references already exist."},
		{400, "Request_BadRequest", "Insufficient privileges to complete the operation."},
		{400, "Request_BadRequest", "please try again"},
		{400, "OtherError", "The source resource object or one of the objects being referenced don't exist."},
	} {
		err := odataerrors.NewODataError()
		err.SetStatusCode(tc.status)
		detail := odataerrors.NewMainError()
		detail.SetCode(&tc.code)
		detail.SetMessage(&tc.message)
		err.SetErrorEscaped(detail)
		require.False(t, isGroupMembershipPropagationError(fmt.Errorf("wrapped: %w", err)), "%+v", tc)
	}
	require.False(t, isGroupMembershipPropagationError(errors.New("Request_ResourceNotFound")))
	require.False(t, isGroupMembershipPropagationError(context.Canceled))
	require.False(t, isGroupMembershipPropagationError(nil))
	require.False(t, isGroupMembershipPropagationError(odataerrors.NewODataError()))
}

func TestGroupMembershipHTTPTimeout(t *testing.T) {
	c, calls := membershipHTTPClient(t, membershipResponse{
		group: "group", status: 404, code: "Request_ResourceNotFound",
		message: "Resource unavailable", inner: map[string]string{"request-id": "last-failure"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := c.addGroupMemberships(ctx, "new-sp", []*AzureGroup{{ObjectID: "group"}})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, "Resource unavailable")
	require.ErrorContains(t, err, `graph_request_id="last-failure"`)
	require.EqualValues(t, 1, calls.Load())
}

func TestGroupMembershipCanceledBeforeRequest(t *testing.T) {
	c, calls := membershipHTTPClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.addGroupMemberships(ctx, "sp", []*AzureGroup{{ObjectID: "group"}})
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, calls.Load())
}

func TestGroupMembershipRetryBudget(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Hour, 20 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			ctx := context.Background()
			if timeout != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			before := time.Now()
			p := &groupMembershipProvider{check: func(ctx context.Context) {
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				if timeout != 0 && timeout < retryTimeout {
					require.WithinDuration(t, before.Add(timeout), deadline, time.Second)
				} else {
					require.False(t, deadline.Before(before.Add(retryTimeout)))
					require.LessOrEqual(t, time.Until(deadline), retryTimeout)
				}
			}}
			c := &client{provider: p}
			require.NoError(t, c.addGroupMemberships(ctx, "sp", []*AzureGroup{{ObjectID: "group"}}))
			require.Len(t, p.groups, 1)
		})
	}
}

func TestGroupMembershipCancellationRetainsGraphError(t *testing.T) {
	graphErr := odataerrors.NewODataError()
	graphErr.SetStatusCode(404)
	detail := odataerrors.NewMainError()
	code, message := "Request_ResourceNotFound", "Resource unavailable"
	detail.SetCode(&code)
	detail.SetMessage(&message)
	graphErr.SetErrorEscaped(detail)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &groupMembershipProvider{
		failGroup: "group", err: graphErr,
		check: func(context.Context) { cancel() },
	}
	c := &client{provider: p}
	err := c.addGroupMemberships(ctx, "sp", []*AzureGroup{{ObjectID: "group"}})
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, graphErr)
	require.ErrorContains(t, err, "Resource unavailable")
	require.Len(t, p.groups, 1)
}

func membershipDenial(requestID string) error {
	err := odataerrors.NewODataError()
	err.SetStatusCode(403)
	detail := odataerrors.NewMainError()
	code, message := "Authorization_RequestDenied", "Insufficient privileges to complete the operation."
	detail.SetCode(&code)
	detail.SetMessage(&message)
	err.SetErrorEscaped(detail)
	err.GetResponseHeaders().Add("request-id", requestID)
	return err
}

func TestGroupMembershipHTTPAuthorizationRecovery(t *testing.T) {
	for _, deniedGroup := range []string{"first", "second"} {
		t.Run(deniedGroup, func(t *testing.T) {
			t.Parallel()
			steps := []membershipResponse{
				{group: "first", status: 204},
				{group: "second", status: 204},
			}
			denied := membershipResponse{
				group: deniedGroup, status: 403, code: "Authorization_RequestDenied",
				message: "Insufficient privileges to complete the operation.", requestID: "denial-id",
			}
			if deniedGroup == "first" {
				steps = append([]membershipResponse{denied}, steps...)
			} else {
				steps = []membershipResponse{steps[0], denied, steps[1]}
			}
			c, calls := membershipHTTPClient(t, steps...)
			var logs bytes.Buffer
			c.logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Debug})
			err := c.addGroupMemberships(context.Background(), "new-sp", []*AzureGroup{
				{ObjectID: "first"}, {ObjectID: "second"},
			})
			require.NoError(t, err)
			require.EqualValues(t, 3, calls.Load())
			require.Contains(t, logs.String(), "retrying group membership authorization denial")
			require.Contains(t, logs.String(), "denial-id")
			require.Contains(t, logs.String(), "group membership recovered after retry")
			require.NotContains(t, logs.String(), "must-not-be-disclosed")
		})
	}
}

func TestGroupMembershipDenialExhaustion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		var attempts []time.Time
		p := &groupMembershipProvider{
			failGroup: "group",
			check:     func(context.Context) { attempts = append(attempts, time.Now()) },
		}
		for i := 1; i <= 5; i++ {
			p.results = append(p.results, membershipDenial(fmt.Sprintf("denial-%d", i)))
		}
		c := &client{provider: p, logger: hclog.New(&hclog.LoggerOptions{Output: &logs})}
		err := c.addGroupMemberships(context.Background(), "sp", []*AzureGroup{
			{ObjectID: "group"}, {ObjectID: "must-not-be-attempted"},
		})
		require.ErrorIs(t, err, p.results[4])
		require.ErrorContains(t, err, `graph_request_id="denial-5"`)
		require.Equal(t, []string{"group", "group", "group", "group", "group"}, p.groups)
		require.Equal(t, []string{"sp", "sp", "sp", "sp", "sp"}, p.members)
		require.Len(t, attempts, 5)
		for i, delay := range []time.Duration{2, 4, 8, 16} {
			require.Equal(t, delay*time.Second, attempts[i+1].Sub(attempts[i]))
		}
		for i := 1; i <= 5; i++ {
			require.Contains(t, logs.String(), fmt.Sprintf("denial-%d", i))
		}
		require.Contains(t, logs.String(), "group membership authorization retries exhausted")
		require.NotContains(t, logs.String(), "recovered")
	})
}

func TestGroupMembershipDenialCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint(deadline), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var ctx context.Context
				var cancel context.CancelFunc
				expected := context.Canceled
				if deadline {
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					expected = context.DeadlineExceeded
				} else {
					ctx, cancel = context.WithCancel(context.Background())
					go func() {
						time.Sleep(time.Second)
						cancel()
					}()
				}
				defer cancel()
				denial := membershipDenial("cancelled-denial")
				p := &groupMembershipProvider{failGroup: "group", err: denial}
				c := &client{provider: p, logger: hclog.NewNullLogger()}
				err := c.addGroupMemberships(ctx, "sp", []*AzureGroup{{ObjectID: "group"}})
				require.ErrorIs(t, err, expected)
				require.ErrorIs(t, err, denial)
				require.ErrorContains(t, err, "cancelled-denial")
				require.Len(t, p.groups, 1)
			})
		})
	}
}

func TestGroupMembershipAuthorizationMatcher(t *testing.T) {
	require.True(t, isGroupMembershipAuthorizationDenied(fmt.Errorf("wrapped: %w", membershipDenial("id"))))
	for _, tc := range []struct {
		status        int
		code, message string
	}{
		{401, "Authorization_RequestDenied", "Insufficient privileges to complete the operation."},
		{400, "Authorization_RequestDenied", "Insufficient privileges to complete the operation."},
		{500, "Authorization_RequestDenied", "Insufficient privileges to complete the operation."},
		{403, "OtherError", "Insufficient privileges to complete the operation."},
		{403, "Authorization_RequestDenied", "Other permission denial"},
		{403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation. Additional restriction."},
	} {
		graphErr := odataerrors.NewODataError()
		graphErr.SetStatusCode(tc.status)
		detail := odataerrors.NewMainError()
		detail.SetCode(&tc.code)
		detail.SetMessage(&tc.message)
		graphErr.SetErrorEscaped(detail)
		require.False(t, isGroupMembershipAuthorizationDenied(graphErr), "%+v", tc)
	}
	require.False(t, isGroupMembershipAuthorizationDenied(nil))
	require.False(t, isGroupMembershipAuthorizationDenied(errors.New("Insufficient privileges to complete the operation.")))
	require.False(t, isGroupMembershipAuthorizationDenied(odataerrors.NewODataError()))
}

func TestGroupMembershipInFlightCancellationRetainsDenial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		denial := membershipDenial("previous-graph-denial")
		p := &groupMembershipProvider{failGroup: "group", results: []error{denial}}
		p.check = func(ctx context.Context) {
			if len(p.groups) == 2 {
				<-ctx.Done()
				p.err = ctx.Err()
			}
		}
		var logs bytes.Buffer
		c := &client{provider: p, logger: hclog.New(&hclog.LoggerOptions{Output: &logs})}
		err := c.addGroupMemberships(ctx, "sp", []*AzureGroup{{ObjectID: "group"}})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorIs(t, err, denial)
		require.ErrorContains(t, err, `graph_request_id="previous-graph-denial"`)
		require.Len(t, p.groups, 2)
		require.Contains(t, logs.String(), "group membership cancelled")
		require.Equal(t, 2, strings.Count(logs.String(), "previous-graph-denial"))
	})
}

func TestGroupMembershipHTTPDenialThenDuplicate(t *testing.T) {
	for _, verified := range []bool{true, false} {
		t.Run(fmt.Sprint(verified), func(t *testing.T) {
			t.Parallel()
			check := membershipResponse{method: http.MethodGet, group: "group", status: 200, body: `{"id":"new-sp"}`}
			if !verified {
				check = membershipResponse{method: http.MethodGet, group: "group", status: 403,
					code: "Authorization_RequestDenied", message: "Insufficient privileges to complete the operation."}
			}
			c, calls := membershipHTTPClient(t,
				membershipResponse{group: "group", status: 403, code: "Authorization_RequestDenied",
					message: "Insufficient privileges to complete the operation."},
				membershipResponse{group: "group", status: 400, code: "Request_BadRequest",
					message: "One or more added object references already exist for the following modified properties: 'members'."},
				check,
			)
			err := c.addGroupMemberships(context.Background(), "new-sp", []*AzureGroup{{ObjectID: "group"}})
			if verified {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "verify existing group membership")
				require.ErrorContains(t, err, "graph_status=400")
			}
			require.EqualValues(t, 3, calls.Load(), "no repeated POST after an unverified duplicate")
		})
	}
}

func TestGroupMembershipDenialIssuanceAndWAL(t *testing.T) {
	for _, recover := range []bool{true, false} {
		t.Run(fmt.Sprint(recover), func(t *testing.T) {
			b, s := getTestBackendMocked(t, true)
			mp := newMockProvider().(*mockProvider)
			p := &groupMembershipProvider{
				AzureProvider: mp, failGroup: "first", err: membershipDenial("issuance-denied"),
			}
			if recover {
				p.results = []error{p.err, nil, nil}
			}
			b.getProvider = func(context.Context, hclog.Logger, logical.SystemView, *clientSettings) (AzureProvider, error) {
				return p, nil
			}
			c, err := b.getClient(context.Background(), s)
			require.NoError(t, err)
			initialApps := len(mp.applications)
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				resp, err := b.createSPSecret(ctx, s, c, "test", &roleEntry{AzureGroups: []*AzureGroup{
					{ObjectID: "first"}, {ObjectID: "second"},
				}})
				require.Len(t, mp.applications, initialApps+1, "never recreate the application")
				require.Len(t, mp.servicePrincipals, 1, "never recreate the service principal/password operation")
				wals, walErr := framework.ListWAL(ctx, s)
				require.NoError(t, walErr)
				if recover {
					require.NoError(t, err)
					require.NotNil(t, resp)
					require.NotEmpty(t, resp.Data["client_id"])
					require.NotEmpty(t, resp.Data["client_secret"])
					require.Equal(t, []string{"first", "first", "second"}, p.groups)
					require.Empty(t, wals)
				} else {
					require.ErrorIs(t, err, p.err)
					require.Nil(t, resp)
					require.Len(t, p.groups, 5)
					require.Len(t, wals, 2, "retain application and role-assignment WALs")
					for _, id := range wals {
						entry, err := framework.GetWAL(ctx, s, id)
						require.NoError(t, err)
						require.NoError(t, b.walRollback(ctx, &logical.Request{Storage: s}, entry.Kind, entry.Data))
						require.NoError(t, framework.DeleteWAL(ctx, s, id))
					}
					require.Len(t, mp.applications, initialApps)
					wals, err = framework.ListWAL(ctx, s)
					require.NoError(t, err)
					require.Empty(t, wals)
				}
			})
		})
	}
}
