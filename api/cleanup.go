// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

// cleanupTimeout bounds the inline work per object. Directory propagation can
// deny a permanent delete for several seconds after the soft delete; when that
// outlasts this budget the purge is reported as pending so the caller can defer
// it to a WAL entry that Vault retries after the propagation delay.
const cleanupTimeout = 10 * time.Second

const (
	maxCleanupRetries = 4
	// Leave room for the request after the final wait.
	cleanupRequestMargin = 2 * time.Second
)

// PurgePendingError reports that soft deletion was established (or absence was
// accepted by the age heuristic), but permanent deletion remains unconfirmed.
// Callers must record the object for a later purge before reporting success.
type PurgePendingError struct {
	Resource string
	ObjectID string
	Err      error
}

func (e *PurgePendingError) Error() string {
	return fmt.Sprintf("permanently delete %s (object_id=%q%s): pending: %v", e.Resource, e.ObjectID, GraphErrorDetails(e.Err), e.Err)
}

func (e *PurgePendingError) Unwrap() error { return e.Err }

type noInlinePurgeRetriesKey struct{}
type cleanupReconciliationKey struct{}
type noInlineCleanupRetriesKey struct{}

// CleanupLeaseAgeThreshold gates the explicitly enabled absence heuristic.
const CleanupLeaseAgeThreshold = 5 * time.Minute

type cleanupReconciliation struct {
	issuedAt time.Time
	onAbsent func()
}

// WithCleanupReconciliation enables purge-first reconciliation and the
// age-based absence heuristic. A zero issue time means a legacy, unknown age.
// onAbsent is called only when three spaced active GETs return typed 404s.
func WithCleanupReconciliation(ctx context.Context, issuedAt time.Time, onAbsent func()) context.Context {
	return context.WithValue(ctx, cleanupReconciliationKey{}, cleanupReconciliation{issuedAt, onAbsent})
}

// WithoutInlineCleanupRetries leaves retries to the next WAL pass. The
// age-based absence check still needs spaced reads to avoid a single stale 404.
func WithoutInlineCleanupRetries(ctx context.Context) context.Context {
	return context.WithValue(WithoutInlinePurgeRetries(ctx), noInlineCleanupRetriesKey{}, true)
}

// WithoutInlinePurgeRetries makes cleanup attempt the permanent delete once
// and report it as pending instead of waiting for directory propagation. Use
// it where waiting is costly and the purge is retried later anyway, such as
// WAL rollback.
func WithoutInlinePurgeRetries(ctx context.Context) context.Context {
	return context.WithValue(ctx, noInlinePurgeRetriesKey{}, true)
}

type cleanupOperations struct {
	softDelete     func(context.Context) error
	confirmDeleted func(context.Context) error
	purge          func(context.Context) error
	readActive     func(context.Context) error
}

func deleteGraphObject(ctx context.Context, resource, id string, permanent bool, ops cleanupOperations, wait func(context.Context, time.Duration) error) error {
	noPurgeRetries, _ := ctx.Value(noInlinePurgeRetriesKey{}).(bool)
	noCleanupRetries, _ := ctx.Value(noInlineCleanupRetriesKey{}).(bool)
	reconcile, reconcileEnabled := ctx.Value(cleanupReconciliationKey{}).(cleanupReconciliation)
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	defer cancel()
	stage := "delete active " + resource
	var lastErr error
	softDeleted, confirmed := false, false
	fail := func(err error) error {
		// The soft delete is what revokes the credentials. Once it is
		// established, an unfinished purge is deferred rather than failed,
		// unless the caller itself was cancelled.
		if softDeleted && parent.Err() == nil {
			return &PurgePendingError{Resource: resource, ObjectID: id, Err: err}
		}
		// A not-found response during reconciliation is not proof of cleanup.
		// Keep it inspectable without allowing callers to normalize it away.
		return fmt.Errorf("%s (object_id=%q%s): %w", stage, id, GraphErrorDetails(err),
			errors.Join(errors.New("cleanup incomplete"), err))
	}
	if id == "" {
		return fail(errors.New("missing object ID"))
	}
	for retries := 0; ; {
		if err := ctx.Err(); err != nil {
			return fail(errors.Join(err, lastErr))
		}
		var err error
		if !softDeleted {
			stage = "delete active " + resource
			err = ops.softDelete(ctx)
			if err == nil {
				softDeleted = true
				if !permanent {
					return nil
				}
				continue
			}
			if !cleanupTransient(err) && !isGraphResourceNotFound(err) {
				return fail(err)
			}
			if ctx.Err() != nil {
				return fail(errors.Join(ctx.Err(), err))
			}
			softMissing := isGraphResourceNotFound(err)
			if reconcileEnabled && permanent {
				purgeErr := ops.purge(ctx)
				if purgeErr == nil {
					return nil
				}
				if ctx.Err() != nil {
					return fail(errors.Join(ctx.Err(), err, purgeErr))
				}
				if !cleanupTransient(purgeErr) && !isGraphResourceNotFound(purgeErr) && !cleanupPropagationDenial(purgeErr) {
					return fail(errors.Join(err, purgeErr))
				}
				err = errors.Join(err, purgeErr)
			}
			// A failed response does not establish whether DELETE committed.
			// Check before retrying, including when the active endpoint says 404.
			checkErr := ops.confirmDeleted(ctx)
			if checkErr == nil {
				softDeleted, confirmed = true, true
				if !permanent {
					return nil
				}
				continue
			}
			err = errors.Join(err, fmt.Errorf("not confirmed in deleted items: %w", checkErr))
			if !cleanupTransient(checkErr) && !isGraphResourceNotFound(checkErr) && !cleanupPropagationDenial(checkErr) {
				return fail(err)
			}
			if reconcileEnabled && softMissing && ops.readActive != nil &&
				(reconcile.issuedAt.IsZero() || time.Since(reconcile.issuedAt) >= CleanupLeaseAgeThreshold) &&
				(isGraphResourceNotFound(checkErr) || cleanupPropagationDenial(checkErr)) {
				absent := true
				for read := 0; read < 3; read++ {
					if read > 0 {
						if waitErr := wait(ctx, time.Second); waitErr != nil {
							return fail(errors.Join(err, waitErr))
						}
					}
					if ctx.Err() != nil {
						return fail(errors.Join(err, ctx.Err()))
					}
					activeErr := ops.readActive(ctx)
					if !isGraphResourceNotFound(activeErr) {
						absent = false
						if activeErr != nil {
							return fail(errors.Join(err, activeErr))
						}
						break
					}
				}
				if absent {
					if ctx.Err() != nil {
						return fail(errors.Join(err, ctx.Err()))
					}
					if reconcile.onAbsent != nil {
						reconcile.onAbsent()
					}
					if permanent {
						// Absence is inferred, not a confirmed purge. Keep a
						// durable follow-up rather than silently losing cleanup.
						softDeleted = true
						return fail(err)
					}
					return nil
				}
			}
			if noCleanupRetries {
				return fail(err)
			}
		} else {
			stage = "permanently delete " + resource
			err = ops.purge(ctx)
			// Absence is proof only after this call saw the object in deleted
			// items; right after our own soft delete it may be propagation.
			if err == nil || (confirmed && isGraphResourceNotFound(err)) {
				return nil
			}
			if noPurgeRetries || (!cleanupTransient(err) && !isGraphResourceNotFound(err) && !cleanupPropagationDenial(err)) {
				return fail(err)
			}
		}
		lastErr = err
		if retries == maxCleanupRetries {
			return fail(fmt.Errorf("cleanup retry limit reached: %w", err))
		}
		ceiling := time.Second << retries
		delay := ceiling/2 + time.Duration(rand.Int63n(int64(ceiling/2)))
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline) - cleanupRequestMargin
			if remaining <= 0 {
				return fail(fmt.Errorf("cleanup time budget exhausted: %w", err))
			}
			delay = min(delay, remaining)
		}
		if err := wait(ctx, delay); err != nil {
			return fail(errors.Join(err, lastErr))
		}
		retries++
	}
}

func waitCleanup(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func cleanupTransient(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	// An individual transport timeout can occur before our deadline. Reconcile
	// that uncertain outcome; the caller's expired context still stops requests.
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var graphErr *odataerrors.ODataError
	if errors.As(err, &graphErr) {
		switch graphErr.GetStatusCode() {
		case http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway,
			http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		default:
			// Leave throttling to a later Vault pass rather than retrying
			// sooner than Graph's Retry-After.
			return false
		}
	}
	var networkError net.Error
	return errors.As(err, &networkError) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func cleanupPropagationDenial(err error) bool {
	var graphErr *odataerrors.ODataError
	if !errors.As(err, &graphErr) || graphErr.GetStatusCode() != http.StatusForbidden || graphErr.GetErrorEscaped() == nil {
		return false
	}
	detail := graphErr.GetErrorEscaped()
	return strings.EqualFold(ptrToString(detail.GetCode()), "Authorization_RequestDenied") &&
		ptrToString(detail.GetMessage()) == "Insufficient privileges to complete the operation."
}
