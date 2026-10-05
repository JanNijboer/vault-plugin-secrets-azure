// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
)

type issuanceContextKey struct{}

type issuanceObservation struct {
	mu         sync.Mutex
	logger     hclog.Logger
	stage      string
	retries    map[string]int
	duplicates int
}

// StartIssuance attaches request-local diagnostics without changing provider
// interfaces. The caller must invoke finish once when its handler returns.
func StartIssuance(ctx context.Context, logger hclog.Logger) (context.Context, func(success bool)) {
	if logger == nil {
		logger = hclog.Default()
	}
	start := time.Now()
	observation := &issuanceObservation{logger: logger, stage: "load_client", retries: make(map[string]int)}
	ctx = context.WithValue(ctx, issuanceContextKey{}, observation)
	return ctx, func(success bool) {
		observation.mu.Lock()
		defer observation.mu.Unlock()
		outcome, failedStage := "failure", observation.stage
		if success {
			outcome, failedStage = "success", ""
		}
		fields := []interface{}{
			"outcome", outcome, "elapsed_ms", time.Since(start).Milliseconds(), "failed_stage", failedStage,
			"sp_create_retries", observation.retries["create_service_principal"],
			"sp_password_retries", observation.retries["add_service_principal_password"],
			"role_assignment_retries", observation.retries["assign_roles"],
			"group_propagation_retries", observation.retries["group_propagation"],
			"group_authorization_retries", observation.retries["group_authorization"],
			"verified_duplicate_memberships", observation.duplicates,
		}
		if success {
			logger.Info("credential issuance summary", fields...)
		} else {
			logger.Warn("credential issuance summary", fields...)
		}
	}
}

// SetIssuanceStage identifies the operation whose failure would stop issuance.
// Calls outside a credential-read request do not collect a summary.
func SetIssuanceStage(ctx context.Context, stage string) {
	if observation, ok := ctx.Value(issuanceContextKey{}).(*issuanceObservation); ok {
		observation.mu.Lock()
		defer observation.mu.Unlock()
		observation.stage = stage
	}
}

// RecordIssuanceRetry counts an additional plugin attempt immediately before
// calling the provider, not a scheduled wait or an SDK HTTP retry.
func RecordIssuanceRetry(ctx context.Context, stage string) {
	if observation, ok := ctx.Value(issuanceContextKey{}).(*issuanceObservation); ok {
		observation.mu.Lock()
		defer observation.mu.Unlock()
		observation.retries[stage]++
	}
}

func logVerifiedGroupMembership(ctx context.Context, groupID, memberID string) {
	logger := hclog.Default()
	if observation, ok := ctx.Value(issuanceContextKey{}).(*issuanceObservation); ok {
		observation.mu.Lock()
		observation.duplicates++
		logger = observation.logger
		observation.mu.Unlock()
	}
	logger.Info("group membership already present and verified", "group_object_id", groupID, "sp_object_id", memberID)
}
