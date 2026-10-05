// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	khttp "github.com/microsoft/kiota-http-go"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	core "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/require"
)

const (
	testAppID = "11111111-1111-1111-1111-111111111111"
	testSPID  = "22222222-2222-2222-2222-222222222222"
	spPath    = "/v1.0/servicePrincipals"
	spSuccess = `{"id":"` + testSPID + `","appId":"` + testAppID + `"}`
	pwSuccess = `{"secretText":"one-time-secret"}`
	missing   = "Resource '" + testSPID + "' does not exist or one of its queried reference-property objects are not present."
	localApp  = "When using this permission, the backing application of the service principal being created must be in the local tenant"
	duplicate = "The service principal cannot be created, updated, or restored because the service principal name " + testAppID + " is already in use."
)

type graphStep struct {
	method string
	path   string
	status int
	body   string
	err    error
	check  func(*http.Request)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise serialization, error mapping, request options and the real SDK
// middleware, not just a mock of the combined provider method.
func scriptedGraph(t *testing.T, steps ...graphStep) *MSGraphClient {
	t.Helper()
	next := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		require.Less(t, next, len(steps), "unexpected HTTP request: %s %s", r.Method, r.URL)
		step := steps[next]
		next++
		require.Equal(t, step.method, r.Method)
		require.Equal(t, step.path, r.URL.Path)
		if step.check != nil {
			step.check(r)
		}
		if step.err != nil {
			return nil, step.err
		}
		return &http.Response{
			StatusCode: step.status,
			Header: http.Header{
				"Content-Type": {"application/json"},
				"Retry-After":  {"0"},
			},
			Body:          io.NopCloser(strings.NewReader(step.body)),
			ContentLength: int64(len(step.body)),
			Request:       r,
		}, nil
	})
	httpClient := core.GetDefaultClient(&core.GraphClientOptions{})
	httpClient.Transport = khttp.NewCustomTransportWithParentTransport(transport, core.GetDefaultMiddlewaresWithOptions(&core.GraphClientOptions{})...)
	adapter, err := msgraph.NewGraphRequestAdapterWithParseNodeFactoryAndSerializationWriterFactoryAndHttpClient(
		&authentication.AnonymousAuthenticationProvider{}, nil, nil, httpClient)
	require.NoError(t, err)
	t.Cleanup(func() { require.Equal(t, len(steps), next, "HTTP request count") })
	return &MSGraphClient{client: msgraph.NewGraphServiceClient(adapter)}
}

func graphError(code, message string) string {
	body, _ := json.Marshal(map[string]any{"error": map[string]string{"code": code, "message": message}})
	return string(body)
}

func createStep(status int, body string) graphStep {
	return graphStep{method: http.MethodPost, path: spPath, status: status, body: body}
}

func passwordStep(status int, body string) graphStep {
	return graphStep{method: http.MethodPost, path: spPath + "/" + testSPID + "/addPassword", status: status, body: body}
}

func deleteStep(status int, body string) graphStep {
	return graphStep{method: http.MethodDelete, path: spPath + "/" + testSPID, status: status, body: body}
}

func TestServicePrincipalPropagation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		creating bool
		status   int
		code     string
		message  string
	}{
		{"application reference", true, 400, "Request_BadRequest", "does not reference a valid application object"},
		{"local tenant", true, 403, "Authorization_RequestDenied", localApp},
		{"create missing reference", true, 400, "Request_BadRequest", missing},
		{"create resource not found", true, 404, "Request_ResourceNotFound", missing},
		{"password missing reference", false, 400, "Request_BadRequest", missing},
		{"password resource not found", false, 404, "Request_ResourceNotFound", missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			failure := graphError(tc.code, tc.message)
			steps := []graphStep{createStep(201, spSuccess), passwordStep(200, pwSuccess)}
			if tc.creating {
				steps = append([]graphStep{createStep(tc.status, failure)}, steps...)
			} else {
				steps = []graphStep{steps[0], passwordStep(tc.status, failure), steps[1]}
			}
			start := time.Now().UTC().Truncate(time.Second)
			end := start.Add(time.Hour)
			for i := range steps {
				if strings.HasSuffix(steps[i].path, "/addPassword") {
					steps[i].check = func(r *http.Request) {
						var reader io.Reader = r.Body
						if r.Header.Get("Content-Encoding") == "gzip" {
							compressed, err := gzip.NewReader(r.Body)
							require.NoError(t, err)
							defer compressed.Close()
							reader = compressed
						}
						var body struct {
							PasswordCredential struct {
								Start time.Time `json:"startDateTime"`
								End   time.Time `json:"endDateTime"`
							} `json:"passwordCredential"`
						}
						require.NoError(t, json.NewDecoder(reader).Decode(&body))
						require.Equal(t, start, body.PasswordCredential.Start)
						require.Equal(t, end, body.PasswordCredential.End)
					}
				}
			}
			c := scriptedGraph(t, steps...)
			id, password, err := c.CreateServicePrincipal(context.Background(), testAppID, start, end)
			require.NoError(t, err)
			require.Equal(t, testSPID, id)
			require.Equal(t, "one-time-secret", password)
		})
	}
}

func TestServicePrincipalTerminalFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		err    error
	}{
		{"already in use", 400, graphError("Request_BadRequest", duplicate), nil},
		{"conflict", 409, graphError("Request_Conflict", duplicate), nil},
		{"permission", 403, graphError("Authorization_RequestDenied", "Insufficient privileges to complete the operation"), nil},
		{"permission mentioning propagation", 403, graphError("Authorization_RequestDenied", missing), nil},
		{"generic not found", 404, graphError("Request_ResourceNotFound", "not found"), nil},
		{"generic retry suggestion", 400, graphError("Request_BadRequest", "propagation; please try again; could not find"), nil},
		{"unknown error code", 400, graphError("OtherError", missing), nil},
		{"throttled", 429, graphError("TooManyRequests", "throttled"), nil},
		{"server failure", 500, graphError("InternalServerError", missing), nil},
		{"unavailable", 503, graphError("ServiceUnavailable", missing), nil},
		{"gateway timeout", 504, graphError("GatewayTimeout", missing), nil},
		{"lost response", 0, "", io.ErrUnexpectedEOF},
		{"truncated success", 201, `{"id":`, nil},
		{"empty success", 204, "", nil},
		{"missing fields", 200, `{}`, nil},
	} {
		for _, creating := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/create=%t", tc.name, creating), func(t *testing.T) {
				t.Parallel()
				failed := createStep(tc.status, tc.body)
				if !creating {
					failed = passwordStep(tc.status, tc.body)
				}
				failed.err = tc.err
				steps := []graphStep{failed}
				stage := "create service principal POST"
				if !creating {
					steps = []graphStep{createStep(201, spSuccess), failed, deleteStep(204, "")}
					stage = "add service principal password POST"
				}
				c := scriptedGraph(t, steps...)
				id, password, err := c.CreateServicePrincipal(context.Background(), testAppID, time.Now(), time.Now().Add(time.Hour))
				require.ErrorContains(t, err, stage)
				require.Empty(t, id)
				require.Empty(t, password)
				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				} else if tc.status >= 400 {
					var graphErr *odataerrors.ODataError
					require.ErrorAs(t, err, &graphErr)
					require.Equal(t, tc.status, graphErr.GetStatusCode())
				}
			})
		}
	}
}

func TestServicePrincipalRejectsUnverifiedApp(t *testing.T) {
	for _, body := range []string{
		`{"id":"` + testSPID + `"}`,
		`{"id":"` + testSPID + `","appId":"other-app"}`,
		`{"appId":"` + testAppID + `"}`,
	} {
		t.Run(body, func(t *testing.T) {
			c := scriptedGraph(t, createStep(201, body))
			_, _, err := c.CreateServicePrincipal(context.Background(), testAppID, time.Now(), time.Now())
			require.ErrorContains(t, err, "missing ID or mismatched app ID")
		})
	}
}

func TestServicePrincipalRetryBudget(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Hour, 20 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			ctx := context.Background()
			if timeout != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			before := time.Now()
			var firstDeadline time.Time
			create := createStep(201, spSuccess)
			create.check = func(r *http.Request) {
				var ok bool
				firstDeadline, ok = r.Context().Deadline()
				require.True(t, ok)
				if timeout != 0 && timeout < 80*time.Second {
					callerDeadline, _ := ctx.Deadline()
					require.Equal(t, callerDeadline, firstDeadline)
				} else {
					require.False(t, firstDeadline.Before(before.Add(80*time.Second)))
					require.LessOrEqual(t, time.Until(firstDeadline), 80*time.Second)
				}
			}
			password := passwordStep(200, pwSuccess)
			password.check = func(r *http.Request) {
				deadline, ok := r.Context().Deadline()
				require.True(t, ok)
				require.Equal(t, firstDeadline, deadline, "both stages share one budget")
			}
			c := scriptedGraph(t, create, password)
			_, _, err := c.CreateServicePrincipal(ctx, testAppID, time.Now(), time.Now().Add(time.Hour))
			require.NoError(t, err)
		})
	}
}

func TestServicePrincipalPasswordDoesNotRetryApplicationErrors(t *testing.T) {
	for _, failure := range []graphStep{
		passwordStep(403, graphError("Authorization_RequestDenied", localApp)),
		passwordStep(400, graphError("Request_BadRequest", "does not reference a valid application object")),
	} {
		c := scriptedGraph(t, createStep(201, spSuccess), failure, deleteStep(204, ""))
		_, _, err := c.CreateServicePrincipal(context.Background(), testAppID, time.Now(), time.Now())
		require.Error(t, err)
	}
}

func TestServicePrincipalCancellation(t *testing.T) {
	t.Run("before creation", func(t *testing.T) {
		c := scriptedGraph(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err := c.CreateServicePrincipal(ctx, testAppID, time.Now(), time.Now())
		require.ErrorIs(t, err, context.Canceled)
	})
	for _, creating := range []bool{true, false} {
		for _, ambiguous := range []bool{true, false} {
			t.Run(fmt.Sprintf("create=%t/ambiguous=%t", creating, ambiguous), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				failed := createStep(404, graphError("Request_ResourceNotFound", missing))
				if !creating {
					failed = passwordStep(404, graphError("Request_ResourceNotFound", missing))
				}
				failed.check = func(*http.Request) { cancel() }
				if ambiguous {
					failed.err = context.Canceled
				}
				steps := []graphStep{failed}
				if !creating {
					cleanup := deleteStep(204, "")
					cleanup.check = func(r *http.Request) {
						require.NoError(t, r.Context().Err())
						deadline, ok := r.Context().Deadline()
						require.True(t, ok)
						require.LessOrEqual(t, time.Until(deadline), 10*time.Second)
					}
					steps = []graphStep{createStep(201, spSuccess), failed, cleanup}
				}
				c := scriptedGraph(t, steps...)
				_, _, err := c.CreateServicePrincipal(ctx, testAppID, time.Now(), time.Now())
				require.ErrorIs(t, err, context.Canceled)
				if !ambiguous {
					require.ErrorContains(t, err, missing)
				}
			})
		}
	}
	t.Run("deadline during propagation wait", func(t *testing.T) {
		c := scriptedGraph(t, createStep(404, graphError("Request_ResourceNotFound", missing)))
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, _, err := c.CreateServicePrincipal(ctx, testAppID, time.Now(), time.Now())
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorContains(t, err, missing)
	})
}

func TestServicePrincipalCleanupFailure(t *testing.T) {
	c := scriptedGraph(t,
		createStep(201, spSuccess),
		passwordStep(403, graphError("Authorization_RequestDenied", "password denied")),
		deleteStep(403, graphError("Authorization_RequestDenied", "delete denied")),
	)
	_, _, err := c.CreateServicePrincipal(context.Background(), testAppID, time.Now(), time.Now())
	require.ErrorContains(t, err, "password denied")
	require.ErrorContains(t, err, "delete denied")
	require.ErrorContains(t, err, "delete service principal after password failure")
}

func TestApplicationPOSTsDoNotRetry(t *testing.T) {
	for _, password := range []bool{true, false} {
		for _, status := range []int{429, 503, 504} {
			t.Run(fmt.Sprintf("password=%t/status=%d", password, status), func(t *testing.T) {
				path := "/v1.0/applications"
				if password {
					path += "/" + testAppID + "/addPassword"
				}
				c := scriptedGraph(t, graphStep{
					method: http.MethodPost, path: path, status: status,
					body: graphError("ServerError", "outcome unknown"),
				})
				var err error
				if password {
					_, err = c.AddApplicationPassword(context.Background(), testAppID, "test", time.Now())
				} else {
					_, err = c.CreateApplication(context.Background(), "test", "", nil)
				}
				require.Error(t, err)
			})
		}
	}
}

func TestPropagationMatcherRejectsUntypedErrors(t *testing.T) {
	require.False(t, isServicePrincipalPropagationError(errors.New(missing), true))
	require.False(t, isServicePrincipalPropagationError(nil, true))
	require.False(t, isServicePrincipalPropagationError(odataerrors.NewODataError(), true))
}
