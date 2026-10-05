// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAgeBasedCleanupReconciliation(t *testing.T) {
	for _, resource := range []string{"applications", "servicePrincipals"} {
		for _, tc := range []struct {
			name    string
			age     time.Duration
			unknown bool
			accept  bool
		}{
			{"recent", time.Minute, false, false},
			{"future", -time.Hour, false, false},
			{"below threshold", CleanupLeaseAgeThreshold - time.Nanosecond, false, false},
			{"at threshold", CleanupLeaseAgeThreshold, false, true},
			{"old", time.Hour, false, true},
			{"legacy unknown", 0, true, true},
		} {
			for _, permanent := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/permanent=%t", resource, tc.name, permanent), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						missing := graphError("Request_ResourceNotFound", "not found")
						active := "/v1.0/" + resource + "/" + testAppID
						deleted := "/v1.0/directory/deletedItems/" + testAppID
						steps := []graphStep{{method: "DELETE", path: active, status: 404, body: missing}}
						if permanent {
							steps = append(steps, graphStep{method: "DELETE", path: deleted, status: 404, body: missing})
						}
						steps = append(steps, graphStep{method: "GET", path: deleted, status: 403,
							body: graphError("Authorization_RequestDenied", "Insufficient privileges to complete the operation.")})
						if tc.accept {
							for i := 0; i < 3; i++ {
								steps = append(steps, graphStep{method: "GET", path: active, status: 404, body: missing})
							}
						}
						c := scriptedGraph(t, steps...)
						issued := time.Now().Add(-tc.age)
						if tc.unknown {
							issued = time.Time{}
						}
						accepted := false
						ctx := WithCleanupReconciliation(WithoutInlineCleanupRetries(context.Background()), issued, func() { accepted = true })
						start := time.Now()
						fn := c.DeleteApplication
						if resource == "servicePrincipals" {
							fn = c.DeleteServicePrincipal
						}
						err := fn(ctx, testAppID, permanent)
						var pending *PurgePendingError
						require.Equal(t, tc.accept, accepted)
						if tc.accept {
							require.Equal(t, 2*time.Second, time.Since(start), "three reads must be spaced")
							if permanent {
								require.ErrorAs(t, err, &pending, "heuristic acceptance must retain purge housekeeping")
							} else {
								require.NoError(t, err)
							}
						} else {
							require.Error(t, err)
							require.False(t, errors.As(err, &pending))
						}
					})
				})
			}
		}
	}
}

func TestReconciliationPurgeFirst(t *testing.T) {
	c := scriptedGraph(t,
		graphStep{method: "DELETE", path: "/v1.0/applications/" + testAppID, status: 404, body: graphError("Request_ResourceNotFound", "missing")},
		graphStep{method: "DELETE", path: "/v1.0/directory/deletedItems/" + testAppID, status: 204},
	)
	ctx := WithCleanupReconciliation(context.Background(), time.Now(), func() { t.Fatal("not a heuristic success") })
	require.NoError(t, c.DeleteApplication(ctx, testAppID, true))
}

func TestReconciliationRejectsActiveOrUnreadableObject(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"active", 200, deletedApp(testAppID)},
		{"denied", 403, graphError("Authorization_RequestDenied", "denied")},
		{"throttled", 429, graphError("TooManyRequests", "wait")},
		{"server error", 503, graphError("ServiceUnavailable", "wait")},
		{"unrecognized not found", 404, graphError("OtherError", "not found")},
		{"wrong ID", 200, deletedApp("wrong")},
		{"empty response", 204, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			missing := graphError("Request_ResourceNotFound", "missing")
			c := scriptedGraph(t,
				graphStep{method: "DELETE", path: "/v1.0/applications/" + testAppID, status: 404, body: missing},
				deletedAppStep(404, missing),
				graphStep{method: "GET", path: "/v1.0/applications/" + testAppID, status: 404, body: missing},
				graphStep{method: "GET", path: "/v1.0/applications/" + testAppID, status: tc.status, body: tc.body},
			)
			ctx := WithCleanupReconciliation(WithoutInlineCleanupRetries(context.Background()), time.Time{}, func() { t.Fatal("unsafe acceptance") })
			synctest.Test(t, func(t *testing.T) {
				require.Error(t, c.DeleteApplication(ctx, testAppID, false))
			})
		})
	}
}

func TestReconciliationCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		missing := graphError("Request_ResourceNotFound", "missing")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := scriptedGraph(t,
			graphStep{method: "DELETE", path: "/v1.0/applications/" + testAppID, status: 404, body: missing},
			deletedAppStep(404, missing),
			graphStep{method: "GET", path: "/v1.0/applications/" + testAppID, status: 404, body: missing,
				check: func(*http.Request) { cancel() }},
		)
		ctx = WithCleanupReconciliation(ctx, time.Time{}, func() { t.Fatal("cancelled cleanup accepted") })
		require.ErrorIs(t, c.DeleteApplication(ctx, testAppID, false), context.Canceled)
	})
}

func TestCleanupPrincipalDiscovery(t *testing.T) {
	active := "/v1.0/servicePrincipals"
	deleted := "/v1.0/directory/deletedItems/graph.servicePrincipal"
	filterCheck := func(r *http.Request) {
		require.Equal(t, "appId eq '"+testAppID+"'", r.URL.Query().Get("$filter"))
	}
	c := scriptedGraph(t,
		graphStep{method: "GET", path: active, status: 200,
			body: `{"value":[` + spSuccess + `],"@odata.nextLink":"https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next"}`, check: filterCheck},
		graphStep{method: "GET", path: active, status: 200, body: `{"value":[]}`,
			check: func(r *http.Request) { require.Equal(t, "next", r.URL.Query().Get("$skiptoken")) }},
		graphStep{method: "GET", path: deleted, status: 200,
			body: `{"value":[` + spSuccess + `],"@odata.nextLink":"https://graph.microsoft.com` + deleted + `?$skiptoken=next"}`, check: filterCheck},
		graphStep{method: "GET", path: deleted, status: 200,
			body: `{"value":[{"id":"another","appId":"` + testAppID + `"}]}`},
	)
	found, err := c.FindServicePrincipalsForCleanup(context.Background(), testAppID)
	require.NoError(t, err)
	require.Equal(t, []ServicePrincipal{{ID: testSPID, AppID: testAppID}, {ID: "another", AppID: testAppID}}, found)

	for _, body := range []string{`{"value":[{"id":"wrong","appId":"different"}]}`, `{"value":[{"appId":"` + testAppID + `"}]}`} {
		c := scriptedGraph(t, graphStep{method: "GET", path: active, status: 200, body: body})
		_, err := c.FindServicePrincipalsForCleanup(context.Background(), testAppID)
		require.ErrorContains(t, err, "missing ID or mismatched app ID")
	}
	c = scriptedGraph(t,
		graphStep{method: "GET", path: active, status: 200, body: `{"value":[]}`},
		graphStep{method: "GET", path: deleted, status: 403, body: graphError("Authorization_RequestDenied", "denied")},
	)
	_, err = c.FindServicePrincipalsForCleanup(context.Background(), testAppID)
	require.ErrorContains(t, err, "deleted=true")
	_, err = scriptedGraph(t).FindServicePrincipalsForCleanup(context.Background(), "")
	require.ErrorContains(t, err, "invalid app ID")
}
