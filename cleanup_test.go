// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package azuresecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cleanupGraphStep struct {
	path   string
	status int
	// method defaults to DELETE; GET steps answer the deleted-items check.
	method string
}

// confirmDeleted is the deleted-items GET before purge or after an active 404.
func confirmDeleted(appObjectID string) cleanupGraphStep {
	return cleanupGraphStep{path: "/directory/deletedItems/" + appObjectID, status: 200, method: http.MethodGet}
}

type graphCleanupProvider struct {
	AzureProvider
	graph *api.MSGraphClient
}

func (p *graphCleanupProvider) DeleteApplication(ctx context.Context, id string, permanent bool) error {
	return p.graph.DeleteApplication(ctx, id, permanent)
}

func (p *graphCleanupProvider) DeleteServicePrincipal(ctx context.Context, id string, permanent bool) error {
	return p.graph.DeleteServicePrincipal(ctx, id, permanent)
}

func (p *graphCleanupProvider) PurgeDeletedObject(ctx context.Context, id string) error {
	return p.graph.PurgeDeletedObject(ctx, id)
}

func (p *graphCleanupProvider) RemoveGroupMember(ctx context.Context, group, member string) error {
	return p.graph.RemoveGroupMember(ctx, group, member)
}

func cleanupGraph(t *testing.T, steps ...cleanupGraphStep) *api.MSGraphClient {
	t.Helper()
	var calls atomic.Int32
	servicePrincipals := make(map[string]bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := int(calls.Add(1)) - 1
		if !assert.Less(t, index, len(steps), "unexpected cleanup request") {
			http.Error(w, "unexpected request", 400)
			return
		}
		step := steps[index]
		method := step.method
		if method == "" {
			method = http.MethodDelete
		}
		assert.Equal(t, method, r.Method)
		assert.Equal(t, "/v1.0"+step.path, r.URL.Path)
		if strings.HasPrefix(step.path, "/servicePrincipals/") {
			servicePrincipals[strings.TrimPrefix(step.path, "/servicePrincipals/")] = true
		}
		assert.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Request-Id", "cleanup-correlation")
		w.WriteHeader(step.status)
		if step.status == 200 {
			id := step.path[strings.LastIndex(step.path, "/")+1:]
			objectType := "#microsoft.graph.application"
			if servicePrincipals[id] {
				objectType = "#microsoft.graph.servicePrincipal"
			}
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{
				"@odata.type": objectType, "id": id,
			}))
		} else if step.status != 204 {
			code, message := "Request_ResourceNotFound", "already removed"
			if step.status == 403 {
				// Graph's response for both propagation delay and missing rights.
				code, message = "Authorization_RequestDenied", "Insufficient privileges to complete the operation."
			}
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{"code": code, "message": message},
			}))
		}
	}))
	t.Cleanup(func() {
		server.Close()
		require.EqualValues(t, len(steps), calls.Load())
	})
	graph, err := api.NewMSGraphClient(server.URL, unusedGraphCredential{})
	require.NoError(t, err)
	return graph
}

// Revocation succeeds once both objects are soft-deleted; an unfinished purge
// becomes a WAL entry that rollback retries until Graph allows it.
func TestRevocationDefersPendingPurge(t *testing.T) {
	b, s := getTestBackendMocked(t, true)
	// One purge attempt per object; inline retry timing is covered in api.
	ctx := api.WithoutInlinePurgeRetries(context.Background())
	c, err := b.getClient(ctx, s)
	require.NoError(t, err)
	issued, err := b.createSPSecret(ctx, s, c, "cleanup", &roleEntry{
		PermanentlyDelete: true, AzureGroups: []*AzureGroup{{ObjectID: "group-1"}, {ObjectID: "group-2"}},
	})
	require.NoError(t, err)
	app := issued.Secret.InternalData["app_object_id"].(string)
	sp := issued.Secret.InternalData["sp_object_id"].(string)
	c.provider = &graphCleanupProvider{AzureProvider: c.provider, graph: cleanupGraph(t,
		cleanupGraphStep{"/applications/" + app, 204, ""},
		cleanupGraphStep{"/directory/deletedItems/" + app, 403, ""},
		cleanupGraphStep{"/groups/group-1/members/" + sp + "/$ref", 404, ""},
		cleanupGraphStep{"/groups/group-2/members/" + sp + "/$ref", 403, ""},
		cleanupGraphStep{"/servicePrincipals/" + sp, 204, ""},
		cleanupGraphStep{"/directory/deletedItems/" + sp, 204, ""},
		// WAL rollback: still propagating, then purged.
		cleanupGraphStep{"/directory/deletedItems/" + app, 403, ""},
		cleanupGraphStep{"/directory/deletedItems/" + app, 204, ""},
	)}
	fakeSaveLoad(issued.Secret)
	req := &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: issued.Secret}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Len(t, resp.Warnings, 1, "a deferred purge is not a warning")
	require.Contains(t, resp.Warnings[0], "group-2")
	require.Equal(t, []walPurge{{Resource: "application", ObjectID: app}}, purgeWALs(t, s))

	rollback := &logical.Request{Operation: logical.RollbackOperation, Storage: s, Data: map[string]interface{}{"immediate": true}}
	resp, err = b.HandleRequest(ctx, rollback)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "graph_status=403")
	require.Len(t, purgeWALs(t, s), 1)
	resp, err = b.HandleRequest(ctx, rollback)
	require.NoError(t, err)
	require.False(t, resp.IsError())
	require.Empty(t, purgeWALs(t, s))
}

// purgeWALs returns the pending purges without their expiration times, and
// fails if any other WAL kind is present.
func purgeWALs(t *testing.T, s logical.Storage) []walPurge {
	t.Helper()
	ctx := context.Background()
	ids, err := framework.ListWAL(ctx, s)
	require.NoError(t, err)
	var entries []walPurge
	for _, id := range ids {
		wal, err := framework.GetWAL(ctx, s, id)
		require.NoError(t, err)
		require.Equal(t, walPurgeDeleted, wal.Kind)
		data := wal.Data.(map[string]interface{})
		entries = append(entries, walPurge{Resource: data["Resource"].(string), ObjectID: data["ObjectID"].(string)})
	}
	return entries
}

// Rollback of a failed issuance soft-deletes the app, makes one purge attempt
// and converts an unfinished purge into a purge WAL. A failed soft delete keeps
// the application WAL.
func TestApplicationWALDefersPurge(t *testing.T) {
	b, s := getTestBackendMocked(t, true)
	ctx := context.Background()
	c, err := b.getClient(ctx, s)
	require.NoError(t, err)
	c.provider = &graphCleanupProvider{AzureProvider: c.provider, graph: cleanupGraph(t,
		cleanupGraphStep{"/applications/app", 403, ""},
		cleanupGraphStep{"/applications/app", 204, ""},
		cleanupGraphStep{"/directory/deletedItems/app", 403, ""},
		cleanupGraphStep{"/directory/deletedItems/app", 403, ""},
		cleanupGraphStep{"/directory/deletedItems/app", 404, ""},
	)}
	id, err := framework.PutWAL(ctx, s, walAppKey, &walApp{
		AppID: "app-id", AppObjID: "app", Expiration: time.Now().Add(maxWALAge),
	})
	require.NoError(t, err)
	req := &logical.Request{Operation: logical.RollbackOperation, Storage: s, Data: map[string]interface{}{"immediate": true}}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "delete active application")
	wals, err := framework.ListWAL(ctx, s)
	require.NoError(t, err)
	require.Equal(t, []string{id}, wals)

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp.IsError())
	require.Equal(t, []walPurge{{Resource: "application", ObjectID: "app"}}, purgeWALs(t, s))

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Len(t, purgeWALs(t, s), 1)

	// Absent from deleted items after the purge was deferred: done.
	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp.IsError())
	require.Empty(t, purgeWALs(t, s))
}

func TestExpiredPurgeWALIsDropped(t *testing.T) {
	b, s := getTestBackendMocked(t, true)
	ctx := context.Background()
	c, err := b.getClient(ctx, s)
	require.NoError(t, err)
	c.provider = &graphCleanupProvider{AzureProvider: c.provider, graph: cleanupGraph(t,
		cleanupGraphStep{"/directory/deletedItems/app", 403, ""},
	)}
	_, err = framework.PutWAL(ctx, s, walPurgeDeleted, &walPurge{
		Resource: "application", ObjectID: "app", Expiration: time.Now().Add(-time.Minute),
	})
	require.NoError(t, err)
	req := &logical.Request{Operation: logical.RollbackOperation, Storage: s, Data: map[string]interface{}{"immediate": true}}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp.IsError())
	require.Empty(t, purgeWALs(t, s))
}

// Reproduces the live sequence: the app's DELETE returned 404 shortly after
// creation while the app was still active. Revocation must fail (Vault keeps
// the lease and retries) regardless of permanently_delete.
func TestRevocationFailsWhenApplicationNotConfirmedDeleted(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		t.Run(fmt.Sprintf("permanently_delete=%t", permanent), func(t *testing.T) {
			b, s := getTestBackendMocked(t, true)
			ctx := context.Background()
			c, err := b.getClient(ctx, s)
			require.NoError(t, err)
			issued, err := b.createSPSecret(ctx, s, c, "lag", &roleEntry{PermanentlyDelete: permanent})
			require.NoError(t, err)
			app := issued.Secret.InternalData["app_object_id"].(string)
			sp := issued.Secret.InternalData["sp_object_id"].(string)
			var steps []cleanupGraphStep
			for i := 0; i < 5; i++ {
				steps = append(steps, cleanupGraphStep{"/applications/" + app, 404, ""})
				if permanent {
					steps = append(steps, cleanupGraphStep{"/directory/deletedItems/" + app, 404, ""})
				}
				steps = append(steps,
					cleanupGraphStep{"/directory/deletedItems/" + app, 404, http.MethodGet},
				)
			}
			// Vault's retry: the app is now visible and deleted normally.
			steps = append(steps, cleanupGraphStep{"/applications/" + app, 204, ""})
			if permanent {
				steps = append(steps, cleanupGraphStep{"/directory/deletedItems/" + app, 204, ""})
			}
			steps = append(steps,
				cleanupGraphStep{"/servicePrincipals/" + sp, 404, ""},
			)
			if permanent {
				steps = append(steps, cleanupGraphStep{"/directory/deletedItems/" + sp, 404, ""})
			}
			steps = append(steps, confirmDeleted(sp))
			if permanent {
				steps = append(steps, cleanupGraphStep{"/directory/deletedItems/" + sp, 204, ""})
			}
			c.provider = &graphCleanupProvider{AzureProvider: c.provider, graph: cleanupGraph(t, steps...)}
			fakeSaveLoad(issued.Secret)
			req := &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: issued.Secret}
			_, err = b.HandleRequest(ctx, req)
			require.ErrorContains(t, err, "delete active application")
			require.ErrorContains(t, err, "not confirmed in deleted items")
			require.Empty(t, purgeWALs(t, s), "an unconfirmed soft delete must not be deferred")
			_, err = b.HandleRequest(ctx, req)
			require.NoError(t, err)
			require.Empty(t, purgeWALs(t, s))
		})
	}
}
