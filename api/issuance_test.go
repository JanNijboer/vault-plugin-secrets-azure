// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestServicePrincipalIssuanceSummary(t *testing.T) {
	for _, tc := range []struct {
		name        string
		steps       []graphStep
		deadline    time.Duration
		createRetry int
		passRetry   int
		elapsed     int
		failedStage string
	}{
		{name: "ordinary success", steps: []graphStep{createStep(201, spSuccess), passwordStep(200, pwSuccess)}},
		{name: "both stages recover", steps: []graphStep{
			createStep(404, graphError("Request_ResourceNotFound", missing)),
			createStep(201, spSuccess),
			passwordStep(404, graphError("Request_ResourceNotFound", missing)),
			passwordStep(200, pwSuccess),
		}, createRetry: 1, passRetry: 1, elapsed: 4000},
		{name: "password denied and cleanup already done", steps: []graphStep{
			createStep(201, spSuccess),
			passwordStep(403, graphError("Authorization_RequestDenied", "denied")),
			deleteStep(404, graphError("Request_ResourceNotFound", missing)),
			{method: "GET", path: "/v1.0/directory/deletedItems/" + testSPID, status: 200, body: deletedSP(testSPID)},
		}, failedStage: "add_service_principal_password"},
		{name: "ambiguous create", steps: []graphStep{
			{method: "POST", path: spPath, err: io.ErrUnexpectedEOF},
		}, failedStage: "create_service_principal"},
		{name: "cancelled create wait", steps: []graphStep{
			createStep(404, graphError("Request_ResourceNotFound", missing)),
		}, deadline: time.Second, elapsed: 1000, failedStage: "create_service_principal"},
		{name: "cancelled password wait", steps: []graphStep{
			createStep(201, spSuccess),
			passwordStep(404, graphError("Request_ResourceNotFound", missing)),
			deleteStep(204, ""),
		}, deadline: time.Second, elapsed: 1000, failedStage: "add_service_principal_password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs bytes.Buffer
				logger := hclog.New(&hclog.LoggerOptions{Output: &logs, JSONFormat: true, Level: hclog.Info})
				ctx := context.Background()
				if tc.deadline != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.deadline)
					defer cancel()
				}
				ctx, finish := StartIssuance(ctx, logger)
				c := scriptedGraph(t, tc.steps...)
				_, _, err := c.CreateServicePrincipal(ctx, testAppID, time.Now(), time.Now().Add(time.Hour))
				finish(err == nil)
				outcome := "success"
				if tc.failedStage == "" {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					outcome = "failure"
				}
				var summary map[string]interface{}
				require.NoError(t, json.Unmarshal(logs.Bytes(), &summary), "exactly one log line")
				require.Equal(t, "credential issuance summary", summary["@message"])
				require.Equal(t, outcome, summary["outcome"])
				require.Equal(t, tc.failedStage, summary["failed_stage"])
				require.EqualValues(t, tc.createRetry, summary["sp_create_retries"])
				require.EqualValues(t, tc.passRetry, summary["sp_password_retries"])
				require.EqualValues(t, tc.elapsed, summary["elapsed_ms"])
				require.Zero(t, summary["verified_duplicate_memberships"])
				require.NotContains(t, logs.String(), "one-time-secret")
			})
		})
	}
}

func TestIssuanceObservationsAreRequestLocal(t *testing.T) {
	var logs bytes.Buffer
	logger := hclog.New(&hclog.LoggerOptions{Output: &logs, JSONFormat: true, Level: hclog.Info})
	first, finishFirst := StartIssuance(context.Background(), logger)
	second, finishSecond := StartIssuance(context.Background(), logger)
	SetIssuanceStage(first, "create_service_principal")
	RecordIssuanceRetry(first, "create_service_principal")
	logVerifiedGroupMembership(first, "group", "sp")
	finishSecond(true)
	finishFirst(false)
	decoder := json.NewDecoder(&logs)
	var duplicate, secondSummary, firstSummary map[string]interface{}
	require.NoError(t, decoder.Decode(&duplicate))
	require.NoError(t, decoder.Decode(&secondSummary))
	require.NoError(t, decoder.Decode(&firstSummary))
	require.Equal(t, "group membership already present and verified", duplicate["@message"])
	require.EqualValues(t, 0, secondSummary["sp_create_retries"])
	require.EqualValues(t, 0, secondSummary["verified_duplicate_memberships"])
	require.EqualValues(t, 1, firstSummary["sp_create_retries"])
	require.EqualValues(t, 1, firstSummary["verified_duplicate_memberships"])
	require.Equal(t, "create_service_principal", firstSummary["failed_stage"])
	// Instrumenting non-issuance operations must not affect either request.
	SetIssuanceStage(context.Background(), "unrelated")
	RecordIssuanceRetry(context.Background(), "create_service_principal")
	require.NotEqual(t, first, second)
}
