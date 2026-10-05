// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/require"
)

func TestGraphObjectCleanup(t *testing.T) {
	for _, resource := range []string{"application", "service principal"} {
		for _, tc := range []struct {
			name        string
			active      int
			purge       int
			activeCode  string
			permanent   bool
			failedStage string
		}{
			{name: "soft delete", active: 204},
			{name: "already soft deleted", active: 404},
			{name: "permanent delete", active: 204, purge: 204, permanent: true},
			{name: "purge after active missing", active: 404, purge: 204, permanent: true},
			{name: "both missing", active: 404, purge: 404, permanent: true},
			{name: "purge denied", active: 404, purge: 403, permanent: true, failedStage: "permanently delete"},
			{name: "active denied", active: 403, purge: 204, permanent: true, failedStage: "delete active"},
			{name: "active denied and purge absent", active: 403, purge: 404, permanent: true, failedStage: "delete active"},
			{name: "unrecognized 404", active: 404, activeCode: "OtherError", failedStage: "delete active"},
			{name: "missing text with 400", active: 400, failedStage: "delete active"},
		} {
			t.Run(resource+"/"+tc.name, func(t *testing.T) {
				activePath := "/v1.0/applications/" + testAppID
				if resource == "service principal" {
					activePath = "/v1.0/servicePrincipals/" + testAppID
				}
				code := tc.activeCode
				if code == "" {
					code = "Request_ResourceNotFound"
				}
				if tc.active == 403 {
					code = "Authorization_RequestDenied"
				}
				steps := []graphStep{{method: http.MethodDelete, path: activePath, status: tc.active,
					body: graphError(code, "Resource does not exist or one of its queried reference-property objects are not present.")}}
				if tc.active == 404 && code == "Request_ResourceNotFound" {
					body := deletedApp(testAppID)
					if resource == "service principal" {
						body = deletedSP(testAppID)
					}
					steps = append(steps, deletedAppStep(200, body))
				}
				if tc.permanent && tc.failedStage != "delete active" {
					purgeCode := "Request_ResourceNotFound"
					if tc.purge == 403 {
						purgeCode = "Authorization_RequestDenied"
					}
					steps = append(steps, graphStep{method: http.MethodDelete,
						path: "/v1.0/directory/deletedItems/" + testAppID, status: tc.purge,
						body: graphError(purgeCode, "permanent delete response")})
				}
				c := scriptedGraph(t, steps...)
				deleteObject := c.DeleteApplication
				if resource == "service principal" {
					deleteObject = c.DeleteServicePrincipal
				}
				err := deleteObject(context.Background(), testAppID, tc.permanent)
				if tc.failedStage == "" {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, tc.failedStage+" "+resource)
					require.ErrorContains(t, err, testAppID)
					var graphErr *odataerrors.ODataError
					require.ErrorAs(t, err, &graphErr)
					status := tc.active
					if tc.failedStage == "permanently delete" {
						status = tc.purge
					}
					require.Equal(t, status, graphErr.GetStatusCode())
					var pending *PurgePendingError
					require.Equal(t, tc.failedStage == "permanently delete", errors.As(err, &pending),
						"only an unfinished purge after a confirmed soft delete is deferred")
				}
			})
		}
	}
}

func deletedApp(id string) string {
	return `{"@odata.type":"#microsoft.graph.application","id":"` + id + `"}`
}

func deletedSP(id string) string {
	return `{"@odata.type":"#microsoft.graph.servicePrincipal","id":"` + id + `"}`
}

func deletedAppStep(status int, body string) graphStep {
	return graphStep{method: http.MethodGet, path: "/v1.0/directory/deletedItems/" + testAppID, status: status, body: body}
}

// Resume after the purge was denied: the app is already soft-deleted, so the
// next attempt must still reach the purge.
func TestGraphCleanupAfterPartialSuccess(t *testing.T) {
	for _, resource := range []string{"applications", "servicePrincipals"} {
		t.Run(resource, func(t *testing.T) {
			denied := graphError("Authorization_RequestDenied", "permanent delete denied")
			body := deletedApp(testAppID)
			if resource == "servicePrincipals" {
				body = deletedSP(testAppID)
			}
			steps := []graphStep{
				{method: http.MethodDelete, path: "/v1.0/" + resource + "/" + testAppID, status: 204},
				{method: http.MethodDelete, path: "/v1.0/directory/deletedItems/" + testAppID, status: 403, body: denied},
				{method: http.MethodDelete, path: "/v1.0/" + resource + "/" + testAppID,
					status: 404, body: graphError("Request_ResourceNotFound", "already deleted")},
			}
			steps = append(steps, deletedAppStep(200, body))
			steps = append(steps, graphStep{method: http.MethodDelete, path: "/v1.0/directory/deletedItems/" + testAppID, status: 204})
			c := scriptedGraph(t, steps...)
			deleteObject := c.DeleteApplication
			if resource == "servicePrincipals" {
				deleteObject = c.DeleteServicePrincipal
			}
			err := deleteObject(context.Background(), testAppID, true)
			var pending *PurgePendingError
			require.ErrorAs(t, err, &pending)
			require.ErrorContains(t, err, "permanently delete")
			require.ErrorContains(t, err, "graph_status=403")
			require.NoError(t, deleteObject(context.Background(), testAppID, true))
		})
	}
}

// A 404 for the active application is accepted only when the application is
// confirmed in deleted items. Anything else must fail so that revocation and
// WAL rollback retry instead of abandoning an application that may still be
// active (for example, one not yet replicated shortly after creation).
func TestDeleteApplicationRequiresSoftDeleteConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		check  graphStep
		target error
	}{
		{name: "not in deleted items", check: deletedAppStep(404, graphError("Request_ResourceNotFound", "not found"))},
		{name: "check denied", check: deletedAppStep(403, graphError("Authorization_RequestDenied", "denied"))},
		{name: "different object", check: deletedAppStep(200, deletedApp("other-id"))},
		{name: "not an application", check: deletedAppStep(200, `{"@odata.type":"#microsoft.graph.servicePrincipal","id":"`+testAppID+`"}`)},
		{name: "empty response", check: deletedAppStep(204, "")},
		{name: "transport failure", check: graphStep{method: http.MethodGet, path: "/v1.0/directory/deletedItems/" + testAppID, err: io.ErrUnexpectedEOF}, target: io.ErrUnexpectedEOF},
	} {
		for _, permanent := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/permanent=%t", tc.name, permanent), func(t *testing.T) {
				t.Parallel()
				steps := []graphStep{
					graphStep{method: http.MethodDelete, path: "/v1.0/applications/" + testAppID,
						status: 404, body: graphError("Request_ResourceNotFound", "not visible")},
					tc.check,
				}
				if tc.name == "not in deleted items" || tc.name == "transport failure" {
					initial := append([]graphStep(nil), steps...)
					for i := 0; i < maxCleanupRetries; i++ {
						steps = append(steps, initial...)
					}
				}
				c := scriptedGraph(t, steps...)
				err := c.DeleteApplication(context.Background(), testAppID, permanent)
				require.ErrorContains(t, err, "delete active application")
				require.ErrorContains(t, err, "not confirmed in deleted items")
				require.ErrorContains(t, err, testAppID)
				require.False(t, isGraphResourceNotFound(err), "must not be reclassified as absent")
				var graphErr *odataerrors.ODataError
				require.ErrorAs(t, err, &graphErr)
				require.Equal(t, 404, graphErr.GetStatusCode(), "original DELETE response first")
				if tc.target != nil {
					require.ErrorIs(t, err, tc.target)
				}
			})
		}
	}
}

func TestGraphUTCDate(t *testing.T) {
	want := time.Date(2026, 10, 2, 7, 26, 21, 0, time.UTC)
	_, nowOffset := time.Now().Zone()
	// Kiota appends today's local offset; time.Parse returns time.Local when it
	// matches the zone at that date, otherwise a fixed zone (DST mismatch).
	kiota, err := time.Parse(time.RFC3339, "2026-10-02T07:26:21"+time.Now().Format("-07:00"))
	require.NoError(t, err)
	require.Equal(t, want, graphUTCDate(kiota), "zone-less Graph value parsed with local offset")
	require.Equal(t, want, graphUTCDate(time.Date(2026, 10, 2, 7, 26, 21, 0, time.FixedZone("kiota", nowOffset))), "DST mismatch")
	require.Equal(t, want, graphUTCDate(want), "explicit Z")
	require.Equal(t, want, graphUTCDate(want.In(time.FixedZone("x", nowOffset+3600))), "explicit other offset")
}

func TestGraphCleanupCancellation(t *testing.T) {
	for _, resource := range []string{"applications", "servicePrincipals"} {
		for _, beforeRequest := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/before=%t", resource, beforeRequest), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var steps []graphStep
				if beforeRequest {
					cancel()
				} else {
					steps = append(steps, graphStep{
						method: http.MethodDelete, path: "/v1.0/" + resource + "/" + testAppID,
						status: 204, check: func(*http.Request) { cancel() },
					})
				}
				c := scriptedGraph(t, steps...)
				deleteObject := c.DeleteApplication
				if resource == "servicePrincipals" {
					deleteObject = c.DeleteServicePrincipal
				}
				require.ErrorIs(t, deleteObject(ctx, testAppID, true), context.Canceled)
			})
		}
	}
}

func TestRemoveGroupMemberCleanup(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		ok     bool
	}{
		{204, "", true},
		{404, "Request_ResourceNotFound", true},
		{404, "OtherError", false},
		{403, "Authorization_RequestDenied", false},
		{400, "Request_ResourceNotFound", false},
	} {
		t.Run(fmt.Sprintf("%d/%s", tc.status, tc.code), func(t *testing.T) {
			c := scriptedGraph(t, graphStep{
				method: http.MethodDelete, path: "/v1.0/groups/group/members/" + testSPID + "/$ref",
				status: tc.status, body: graphError(tc.code, "Resource missing"),
			})
			err := c.RemoveGroupMember(context.Background(), "group", testSPID)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, `group_object_id="group"`)
				require.ErrorContains(t, err, testSPID)
				require.ErrorContains(t, err, fmt.Sprintf("graph_status=%d", tc.status))
			}
		})
	}
}

func TestNotFoundDoesNotSuppressOtherErrors(t *testing.T) {
	missing := odataerrors.NewODataError()
	missing.SetStatusCode(404)
	detail := odataerrors.NewMainError()
	code, message := "Request_ResourceNotFound", "missing"
	detail.SetCode(&code)
	detail.SetMessage(&message)
	missing.SetErrorEscaped(detail)
	require.True(t, isGraphResourceNotFound(fmt.Errorf("wrapped: %w", missing)))
	require.False(t, isGraphResourceNotFound(errors.Join(missing, errors.New("permission denied"))))
	require.False(t, isGraphResourceNotFound(errors.New("Status=404")))
	require.False(t, isGraphResourceNotFound(odataerrors.NewODataError()))
}

func TestGraphCleanupTransportErrors(t *testing.T) {
	for _, resource := range []string{"applications", "servicePrincipals"} {
		t.Run(resource, func(t *testing.T) {
			c := scriptedGraph(t, graphStep{
				method: http.MethodDelete, path: "/v1.0/" + resource + "/" + testAppID, err: io.ErrUnexpectedEOF,
			}, deletedAppStep(403, graphError("Authorization_RequestDenied", "check denied")))
			deleteObject := c.DeleteApplication
			if resource == "servicePrincipals" {
				deleteObject = c.DeleteServicePrincipal
			}
			require.ErrorIs(t, deleteObject(context.Background(), testAppID, false), io.ErrUnexpectedEOF)
		})
	}
	c := scriptedGraph(t, graphStep{
		method: http.MethodDelete, path: "/v1.0/groups/group/members/" + testSPID + "/$ref", err: io.ErrUnexpectedEOF,
	})
	require.ErrorIs(t, c.RemoveGroupMember(context.Background(), "group", testSPID), io.ErrUnexpectedEOF)
}

func TestRemoveGroupMemberCancelled(t *testing.T) {
	c := scriptedGraph(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, c.RemoveGroupMember(ctx, "group", testSPID), context.Canceled)
}
