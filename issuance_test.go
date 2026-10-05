// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/require"
)

func issuanceSummary(t *testing.T, logs []byte) map[string]interface{} {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(logs))
	var summary map[string]interface{}
	for {
		var entry map[string]interface{}
		err := decoder.Decode(&entry)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if entry["@message"] == "credential issuance summary" {
			require.Nil(t, summary, "one summary per request")
			summary = entry
		}
	}
	require.NotNil(t, summary)
	return summary
}

func TestCredentialReadSummary(t *testing.T) {
	for _, tc := range []struct {
		name        string
		static      bool
		missingRole bool
		recover     bool
		propagation bool
		denied      bool
		cancelWait  bool
		wantAuth    int
		wantProp    int
		wantStage   string
	}{
		{name: "ordinary dynamic"},
		{name: "ordinary static", static: true},
		{name: "missing role", missingRole: true, wantStage: "load_role"},
		{name: "authorization recovery", recover: true, wantAuth: 1},
		{name: "mixed recovery", recover: true, propagation: true, wantAuth: 1, wantProp: 1},
		{name: "authorization exhausted", denied: true, wantAuth: 4, wantStage: "add_group_memberships"},
		{name: "cancelled wait", denied: true, cancelWait: true, wantStage: "add_group_memberships"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, storage := getTestBackendMocked(t, true)
				var logs bytes.Buffer
				logger := hclog.New(&hclog.LoggerOptions{Output: &logs, JSONFormat: true, Level: hclog.Info})
				require.NoError(t, b.Setup(context.Background(), &logical.BackendConfig{
					Logger: logger, System: b.System(), StorageView: storage,
				}))
				c, err := b.getClient(context.Background(), storage)
				require.NoError(t, err)
				baseProvider := c.provider
				role := &roleEntry{AzureGroups: []*AzureGroup{{ObjectID: "first"}, {ObjectID: "second"}}}
				if tc.static {
					role.ApplicationObjectID, role.ApplicationID = "existing-app-object", "existing-app-id"
				}
				if !tc.missingRole {
					require.NoError(t, saveRole(context.Background(), storage, role, "observed"))
				}
				if tc.recover || tc.denied {
					denial := membershipDenial("summary-denial")
					p := &groupMembershipProvider{AzureProvider: baseProvider, failGroup: "first", err: denial}
					if tc.recover {
						p.results = []error{denial, nil, nil}
						if tc.propagation {
							propagation := membershipDenial("summary-propagation")
							var graphErr *odataerrors.ODataError
							require.ErrorAs(t, propagation, &graphErr)
							graphErr.SetStatusCode(404)
							code := "Request_ResourceNotFound"
							graphErr.GetErrorEscaped().SetCode(&code)
							p.results = append([]error{propagation}, p.results...)
						}
					}
					c.provider = p
				}
				ctx := context.Background()
				if tc.cancelWait {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, time.Second)
					defer cancel()
				}
				req := &logical.Request{
					Operation: logical.ReadOperation, Path: "creds/observed", MountPoint: "azure-engine-patched/",
					ID: "issuance-request", Storage: storage,
				}
				resp, err := b.HandleRequest(ctx, req)
				outcome := "success"
				if tc.wantStage != "" {
					outcome = "failure"
					require.True(t, err != nil || resp.IsError())
				} else {
					require.NoError(t, err)
					require.NotEmpty(t, resp.Data["client_secret"])
					require.NotContains(t, logs.String(), resp.Data["client_secret"])
				}
				if tc.cancelWait {
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
				require.NotContains(t, logs.String(), testClientSecret)
				summary := issuanceSummary(t, logs.Bytes())
				require.Equal(t, "azure-engine-patched/creds/observed", summary["path"])
				require.Equal(t, "issuance-request", summary["request_id"])
				require.Equal(t, "observed", summary["role"])
				require.Equal(t, outcome, summary["outcome"])
				require.Equal(t, tc.wantStage, summary["failed_stage"])
				require.EqualValues(t, tc.wantAuth, summary["group_authorization_retries"])
				require.EqualValues(t, tc.wantProp, summary["group_propagation_retries"])
				if tc.recover {
					require.GreaterOrEqual(t, summary["elapsed_ms"].(float64), float64(2000))
					logs.Reset()
					c.provider = baseProvider
					_, err = b.HandleRequest(context.Background(), req)
					require.NoError(t, err)
					summary = issuanceSummary(t, logs.Bytes())
					require.EqualValues(t, 0, summary["group_authorization_retries"], "no cross-request accumulation")
					require.EqualValues(t, 0, summary["group_propagation_retries"])
				}
			})
		})
	}
}

type roleRetryProvider struct {
	AzureProvider
	attempts int
}

func (p *roleRetryProvider) CreateRoleAssignment(ctx context.Context, scope, name string, params armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
	p.attempts++
	if p.attempts == 1 {
		return armauthorization.RoleAssignmentsClientCreateResponse{}, errors.New("PrincipalNotFound")
	}
	return p.AzureProvider.CreateRoleAssignment(ctx, scope, name, params)
}

func TestRoleAssignmentRetrySummary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		ctx, finish := api.StartIssuance(context.Background(), hclog.New(&hclog.LoggerOptions{
			Output: &logs, JSONFormat: true, Level: hclog.Info,
		}))
		p := &roleRetryProvider{AzureProvider: newMockProvider()}
		c := &client{provider: p}
		_, err := c.assignRoles(ctx, "sp", []*AzureRole{{RoleID: "role-1"}, {RoleID: "role-2"}}, []string{"id-1", "id-2"})
		require.NoError(t, err)
		finish(true)
		require.Equal(t, 3, p.attempts)
		require.EqualValues(t, 1, issuanceSummary(t, logs.Bytes())["role_assignment_retries"])
	})
}
