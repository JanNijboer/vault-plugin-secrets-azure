// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/require"
)

const existingMembership = "One or more added object references already exist for the following modified properties: 'members'."

func TestAddGroupMemberVerifiesDuplicate(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		err         error
		wantSuccess bool
	}{
		{"matching SP", 200, `{"id":"` + testSPID + `"}`, nil, true},
		{"different SP", 200, `{"id":"different-sp"}`, nil, false},
		{"missing ID", 200, `{}`, nil, false},
		{"empty response", 204, "", nil, false},
		{"malformed response", 200, `{"id":`, nil, false},
		{"not visible", 404, graphError("Request_ResourceNotFound", "not found"), nil, false},
		{"verification forbidden", 403, graphError("Authorization_RequestDenied", "Insufficient privileges to complete the operation."), nil, false},
		{"transport failure", 0, "", io.ErrUnexpectedEOF, false},
		{"cancelled", 0, "", context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			ctx, finish := StartIssuance(context.Background(), hclog.New(&hclog.LoggerOptions{
				Output: &logs, JSONFormat: true, Level: hclog.Info,
			}))
			c := scriptedGraph(t,
				graphStep{method: http.MethodPost, path: "/v1.0/groups/group/members/$ref",
					status: 400, body: graphError("Request_BadRequest", existingMembership)},
				graphStep{method: http.MethodGet, path: "/v1.0/groups/group/members/" + testSPID + "/graph.servicePrincipal",
					status: tc.status, body: tc.body, err: tc.err},
			)
			err := c.AddGroupMember(ctx, "group", testSPID)
			finish(err == nil)
			decoder := json.NewDecoder(&logs)
			var entry map[string]interface{}
			require.NoError(t, decoder.Decode(&entry))
			if tc.wantSuccess {
				require.NoError(t, err)
				require.Equal(t, "group membership already present and verified", entry["@message"])
				require.Equal(t, testSPID, entry["sp_object_id"])
				require.Equal(t, "group", entry["group_object_id"])
				require.NoError(t, decoder.Decode(&entry))
				require.EqualValues(t, 1, entry["verified_duplicate_memberships"])
			} else {
				require.EqualValues(t, 0, entry["verified_duplicate_memberships"])
				require.ErrorContains(t, err, existingMembership)
				require.ErrorContains(t, err, "verify existing group membership")
				var graphErr *odataerrors.ODataError
				require.ErrorAs(t, err, &graphErr)
				require.Equal(t, 400, graphErr.GetStatusCode(), "keep the original POST failure first")
				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				}
			}
			require.Equal(t, "credential issuance summary", entry["@message"])
			require.Equal(t, io.EOF, decoder.Decode(&entry), "no extra log entries")
		})
	}
}

func TestAddGroupMemberDoesNotVerifyOtherFailures(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		code, message string
		err           error
	}{
		{"permission denial", 403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.", nil},
		{"other duplicate property", 400, "Request_BadRequest", "One or more added object references already exist for the following modified properties: 'owners'.", nil},
		{"wrong status", 403, "Request_BadRequest", existingMembership, nil},
		{"wrong code", 400, "OtherError", existingMembership, nil},
		{"lost POST response", 0, "", "", io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := scriptedGraph(t, graphStep{method: http.MethodPost, path: "/v1.0/groups/group/members/$ref",
				status: tc.status, body: graphError(tc.code, tc.message), err: tc.err})
			err := c.AddGroupMember(context.Background(), "group", testSPID)
			require.Error(t, err)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
	require.False(t, isGroupMemberAlreadyPresent(nil))
	require.False(t, isGroupMemberAlreadyPresent(odataerrors.NewODataError()))
	require.False(t, isGroupMemberAlreadyPresent(errors.New(existingMembership)))
}
