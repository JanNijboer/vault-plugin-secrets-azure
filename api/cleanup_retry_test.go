// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/require"
)

const (
	cleanupDone = iota
	cleanupPending
	cleanupFailed
)

func TestStagedGraphCleanup(t *testing.T) {
	for _, resource := range []string{"applications", "servicePrincipals"} {
		active := "/v1.0/" + resource + "/" + testAppID
		deleted := "/v1.0/directory/deletedItems/" + testAppID
		body := deletedApp(testAppID)
		if resource == "servicePrincipals" {
			body = deletedSP(testAppID)
		}
		soft := graphStep{method: "DELETE", path: active, status: 204}
		visible := graphStep{method: "GET", path: deleted, status: 200, body: body}
		missingDeleted := graphStep{method: "GET", path: deleted, status: 404, body: graphError("Request_ResourceNotFound", "not visible")}
		missingActive := graphStep{method: "DELETE", path: active, status: 404, body: missingDeleted.body}
		purge := graphStep{method: "DELETE", path: deleted, status: 204}
		purgeMissing := graphStep{method: "DELETE", path: deleted, status: 404, body: missingDeleted.body}
		propagation := graphError("Authorization_RequestDenied", "Insufficient privileges to complete the operation.")
		denied := graphStep{method: "DELETE", path: deleted, status: 403, body: propagation}
		deniedCheck := graphStep{method: "GET", path: deleted, status: 403, body: propagation}
		for _, tc := range []struct {
			name      string
			steps     []graphStep
			outcome   int
			errorText string
		}{
			// Soft delete succeeded: purge directly, without a deleted-items read.
			{"purge right after soft delete", []graphStep{soft, purge}, cleanupDone, ""},
			{"purge propagation denial", []graphStep{soft, denied, denied, purge}, cleanupDone, ""},
			{"purge not yet visible", []graphStep{soft, purgeMissing, purge}, cleanupDone, ""},
			{"purge ambiguous then retry", []graphStep{
				soft, {method: "DELETE", path: deleted, err: io.ErrUnexpectedEOF}, purge,
			}, cleanupDone, ""},
			{"purge server error then retry", []graphStep{
				soft, {method: "DELETE", path: deleted, status: 503, body: graphError("ServiceUnavailable", "temporary")}, purge,
			}, cleanupDone, ""},
			{"persistent purge denial deferred", []graphStep{soft, denied, denied, denied, denied, denied}, cleanupPending, "graph_status=403"},
			{"purge ambiguous then absent deferred", []graphStep{
				soft, {method: "DELETE", path: deleted, err: io.ErrUnexpectedEOF},
				purgeMissing, purgeMissing, purgeMissing, purgeMissing,
			}, cleanupPending, "retry limit"},
			{"other purge denial deferred", []graphStep{
				soft, {method: "DELETE", path: deleted, status: 403, body: graphError("Authorization_RequestDenied", "different denial")},
			}, cleanupPending, "different denial"},
			{"purge throttled deferred", []graphStep{
				soft, {method: "DELETE", path: deleted, status: 429, body: graphError("TooManyRequests", "throttled")},
			}, cleanupPending, "graph_status=429"},
			// Soft delete outcome unclear: confirm in deleted items first.
			{"soft 404 while still active", []graphStep{missingActive, missingDeleted, soft, purge}, cleanupDone, ""},
			{"soft 404 already deleted", []graphStep{missingActive, visible, purge}, cleanupDone, ""},
			{"soft 404 already purged after confirmation", []graphStep{missingActive, visible, purgeMissing}, cleanupDone, ""},
			{"soft 404 confirmation propagation denial", []graphStep{missingActive, deniedCheck, missingActive, visible, purge}, cleanupDone, ""},
			{"lost soft response committed", []graphStep{{method: "DELETE", path: active, err: io.ErrUnexpectedEOF}, visible, purge}, cleanupDone, ""},
			{"transport timeout before cleanup deadline", []graphStep{
				{method: "DELETE", path: active, err: context.DeadlineExceeded}, visible, purge,
			}, cleanupDone, ""},
			{"lost soft response not committed", []graphStep{
				{method: "DELETE", path: active, err: io.ErrUnexpectedEOF}, missingDeleted, soft, purge,
			}, cleanupDone, ""},
			{"soft server error", []graphStep{
				{method: "DELETE", path: active, status: 503, body: graphError("ServiceUnavailable", "temporary")},
				missingDeleted, soft, purge,
			}, cleanupDone, ""},
			{"soft permission denied", []graphStep{
				{method: "DELETE", path: active, status: 403, body: propagation},
			}, cleanupFailed, "delete active"},
			{"soft throttled", []graphStep{
				{method: "DELETE", path: active, status: 429, body: graphError("TooManyRequests", "throttled")},
			}, cleanupFailed, "graph_status=429"},
			{"confirmation other denial", []graphStep{
				missingActive, {method: "GET", path: deleted, status: 403, body: graphError("Authorization_RequestDenied", "different denial")},
			}, cleanupFailed, "not confirmed in deleted items"},
			{"confirmation denial persists", []graphStep{
				missingActive, deniedCheck, missingActive, deniedCheck, missingActive, deniedCheck,
				missingActive, deniedCheck, missingActive, deniedCheck,
			}, cleanupFailed, "retry limit"},
			{"both locations absent", []graphStep{
				missingActive, missingDeleted, missingActive, missingDeleted, missingActive, missingDeleted,
				missingActive, missingDeleted, missingActive, missingDeleted,
			}, cleanupFailed, "not confirmed in deleted items"},
			{"retry limit shared across stages", []graphStep{
				missingActive, missingDeleted, soft, denied, denied, denied, denied,
			}, cleanupPending, "retry limit"},
			{"wrong deleted object", []graphStep{
				missingActive, {method: "GET", path: deleted, status: 200, body: deletedApp("wrong-id")},
			}, cleanupFailed, "not the expected"},
			{"wrong deleted type", []graphStep{
				missingActive, {method: "GET", path: deleted, status: 200, body: `{"@odata.type":"#microsoft.graph.group","id":"` + testAppID + `"}`},
			}, cleanupFailed, "not the expected"},
		} {
			t.Run(resource+"/"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					c := scriptedGraph(t, tc.steps...)
					fn := c.DeleteApplication
					if resource == "servicePrincipals" {
						fn = c.DeleteServicePrincipal
					}
					start := time.Now()
					err := fn(context.Background(), testAppID, true)
					var pending *PurgePendingError
					switch tc.outcome {
					case cleanupDone:
						require.NoError(t, err)
					case cleanupPending:
						require.ErrorAs(t, err, &pending)
						require.Equal(t, testAppID, pending.ObjectID)
						require.ErrorContains(t, err, "permanently delete")
						require.ErrorContains(t, err, tc.errorText)
					case cleanupFailed:
						require.False(t, errors.As(err, &pending), "soft delete was not established: %v", err)
						require.ErrorContains(t, err, tc.errorText)
						require.ErrorContains(t, err, "cleanup incomplete")
						require.False(t, isGraphResourceNotFound(err), "must not hide incomplete cleanup")
					}
					require.LessOrEqual(t, time.Since(start), cleanupTimeout)
				})
			})
		}
	}
}

func TestCleanupWaitsAndDeadlines(t *testing.T) {
	t.Run("exponential jitter and shared limit", func(t *testing.T) {
		calls, waits := 0, 0
		ops := cleanupOperations{
			softDelete:     func(context.Context) error { calls++; return io.ErrUnexpectedEOF },
			confirmDeleted: func(context.Context) error { return io.ErrUnexpectedEOF },
			purge:          func(context.Context) error { t.Fatal("unexpected purge"); return nil },
		}
		err := deleteGraphObject(context.Background(), "application", testAppID, true, ops,
			func(ctx context.Context, delay time.Duration) error {
				ceiling := time.Second << waits
				require.GreaterOrEqual(t, delay, ceiling/2)
				require.Less(t, delay, ceiling)
				waits++
				return nil
			})
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		require.Equal(t, maxCleanupRetries+1, calls)
		require.Equal(t, maxCleanupRetries, waits)
	})
	t.Run("waits stop before the budget runs out", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var attempts []time.Duration
			start := time.Now()
			ops := cleanupOperations{
				softDelete: func(context.Context) error { return nil },
				purge: func(context.Context) error {
					attempts = append(attempts, time.Since(start))
					time.Sleep(time.Second) // slow Graph responses
					return errPropagationDenial
				},
			}
			err := deleteGraphObject(context.Background(), "application", testAppID, true, ops, waitCleanup)
			var pending *PurgePendingError
			require.ErrorAs(t, err, &pending)
			require.ErrorContains(t, err, "time budget exhausted")
			require.Less(t, attempts[len(attempts)-1], cleanupTimeout-time.Second)
			require.Less(t, time.Since(start), cleanupTimeout)
		})
	})
	for _, deadline := range []time.Duration{time.Millisecond, time.Hour} {
		t.Run(deadline.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), deadline)
				defer cancel()
				start := time.Now()
				ops := cleanupOperations{
					softDelete:     func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
					confirmDeleted: func(context.Context) error { t.Fatal("request after deadline"); return nil },
				}
				err := deleteGraphObject(ctx, "application", testAppID, true, ops, waitCleanup)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.Equal(t, min(deadline, cleanupTimeout), time.Since(start))
			})
		})
	}
	t.Run("own deadline after soft delete defers purge", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ops := cleanupOperations{
				softDelete: func(context.Context) error { return nil },
				purge:      func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
			}
			err := deleteGraphObject(context.Background(), "application", testAppID, true, ops, waitCleanup)
			var pending *PurgePendingError
			require.ErrorAs(t, err, &pending)
			require.ErrorIs(t, err, context.DeadlineExceeded)
		})
	})
	t.Run("caller deadline after soft delete fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ops := cleanupOperations{
				softDelete: func(context.Context) error { return nil },
				purge:      func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
			}
			err := deleteGraphObject(ctx, "application", testAppID, true, ops, waitCleanup)
			var pending *PurgePendingError
			require.False(t, errors.As(err, &pending), "the caller cannot record a WAL after its deadline")
			require.ErrorIs(t, err, context.DeadlineExceeded)
		})
	})
	t.Run("cancel backoff", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops := cleanupOperations{
				softDelete: func(context.Context) error { return nil },
				purge: func(context.Context) error {
					go func() { time.Sleep(time.Millisecond); cancel() }()
					return io.ErrUnexpectedEOF
				},
			}
			err := deleteGraphObject(ctx, "application", testAppID, true, ops, waitCleanup)
			var pending *PurgePendingError
			require.False(t, errors.As(err, &pending))
			require.ErrorIs(t, err, context.Canceled)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	})
	t.Run("rollback makes one purge attempt", func(t *testing.T) {
		purges := 0
		ops := cleanupOperations{
			softDelete: func(context.Context) error { return nil },
			purge:      func(context.Context) error { purges++; return errPropagationDenial },
		}
		err := deleteGraphObject(WithoutInlinePurgeRetries(context.Background()), "application", testAppID, true, ops,
			func(context.Context, time.Duration) error { t.Fatal("unexpected wait"); return nil })
		var pending *PurgePendingError
		require.ErrorAs(t, err, &pending)
		require.Equal(t, 1, purges)
	})
}

var errPropagationDenial = func() error {
	err := odataerrors.NewODataError()
	err.SetStatusCode(http.StatusForbidden)
	detail := odataerrors.NewMainError()
	code, message := "Authorization_RequestDenied", "Insufficient privileges to complete the operation."
	detail.SetCode(&code)
	detail.SetMessage(&message)
	err.SetErrorEscaped(detail)
	return err
}()

// The revocation retry after a deferred purge sees the active object gone and
// must still reach the purge after confirming it in deleted items.
func TestCleanupResumeAfterDeferredPurge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		active := graphStep{method: http.MethodDelete, path: "/v1.0/applications/" + testAppID, status: 204}
		visible := deletedAppStep(200, deletedApp(testAppID))
		purge := graphStep{method: http.MethodDelete, path: "/v1.0/directory/deletedItems/" + testAppID, status: 403,
			body: graphError("Authorization_RequestDenied", "Insufficient privileges to complete the operation.")}
		steps := []graphStep{active}
		for i := 0; i <= maxCleanupRetries; i++ {
			steps = append(steps, purge)
		}
		active.status, active.body = 404, graphError("Request_ResourceNotFound", "gone")
		purge.status, purge.body = 204, ""
		steps = append(steps, active, visible, purge)
		c := scriptedGraph(t, steps...)
		var pending *PurgePendingError
		require.ErrorAs(t, c.DeleteApplication(context.Background(), testAppID, true), &pending)
		require.NoError(t, c.DeleteApplication(context.Background(), testAppID, true))
	})
}

func TestPurgeDeletedObject(t *testing.T) {
	deleted := "/v1.0/directory/deletedItems/" + testAppID
	for _, tc := range []struct {
		name      string
		step      graphStep
		errorText string
	}{
		{"purged", graphStep{method: http.MethodDelete, path: deleted, status: 204}, ""},
		{"already absent", graphStep{method: http.MethodDelete, path: deleted, status: 404,
			body: graphError("Request_ResourceNotFound", "gone")}, ""},
		{"still propagating", graphStep{method: http.MethodDelete, path: deleted, status: 403,
			body: graphError("Authorization_RequestDenied", "Insufficient privileges to complete the operation.")}, "graph_status=403"},
		{"transport failure", graphStep{method: http.MethodDelete, path: deleted, err: io.ErrUnexpectedEOF}, "permanently delete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := scriptedGraph(t, tc.step)
			err := c.PurgeDeletedObject(context.Background(), testAppID)
			if tc.errorText == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.errorText)
				require.ErrorContains(t, err, testAppID)
			}
		})
	}
	require.ErrorContains(t, scriptedGraph(t).PurgeDeletedObject(context.Background(), ""), "missing object ID")
}

func TestCleanupMissingID(t *testing.T) {
	c := scriptedGraph(t)
	require.ErrorContains(t, c.DeleteApplication(context.Background(), "", true), "missing object ID")
	require.ErrorContains(t, c.DeleteServicePrincipal(context.Background(), "", true), "missing object ID")
}

func TestCleanupDoesNotRetryCancellationOrUnknownErrors(t *testing.T) {
	for _, err := range []error{context.Canceled, errors.New("unknown failure")} {
		require.False(t, cleanupTransient(err))
	}
}
