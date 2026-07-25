// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestShouldBlock_StaleCacheFailsClosed pins the property that makes fail-closed mode
// time-bounded rather than failure-detection-bounded.
//
// lastRefreshErr is edge-triggered: it is only set once a refresh has RUN and FAILED. A
// partition beginning immediately after a successful refresh therefore leaves it nil, and
// every non-match was served as a confident all-clear from a cache that could no longer
// observe a new kill — while pub/sub was down for the same partition, so a kill issued
// through a reachable replica was invisible for the whole window. A wedged reconcile loop
// made it indefinite.
func TestShouldBlock_StaleCacheFailsClosed(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	r := &Redis{
		killedAgents:      map[string]bool{},
		killedSessions:    map[string]bool{},
		reconcileInterval: 30 * time.Second,
		now:               func() time.Time { return now },
	}
	r.started.Store(true)
	r.lastRefreshOK = base // a refresh just succeeded

	// Fresh cache: a non-match is a confident all-clear.
	if blocked, err := r.ShouldBlock(context.Background(), "a", "s"); blocked || err != nil {
		t.Fatalf("a freshly-confirmed cache must serve a non-match cleanly; blocked=%v err=%v", blocked, err)
	}

	// One missed reconcile tick is ordinary jitter and must not deny.
	now = base.Add(45 * time.Second)
	if blocked, err := r.ShouldBlock(context.Background(), "a", "s"); blocked || err != nil {
		t.Fatalf("one missed tick is jitter, not an outage; blocked=%v err=%v", blocked, err)
	}

	// Two intervals with no confirmed refresh means the loop is not converging.
	now = base.Add(61 * time.Second)
	blocked, err := r.ShouldBlock(context.Background(), "a", "s")
	if blocked {
		t.Error("a staleness denial reports an error rather than a synthetic match")
	}
	if !errors.Is(err, ErrBackendUnreachable) {
		t.Fatalf("a stale cache must fail closed with ErrBackendUnreachable, got %v", err)
	}

	// HealthStatus must agree — the whole point of the shared gate chain. A probe
	// reporting "ok" through a state the data plane denies on is the divergence that
	// hand-mirroring the two chains produced.
	if r.HealthStatus() == nil {
		t.Error("HealthStatus must report degraded whenever ShouldBlock is denying on staleness")
	}

	// A confirmed refresh clears it.
	r.lastRefreshOK = now
	if blocked, err := r.ShouldBlock(context.Background(), "a", "s"); blocked || err != nil {
		t.Fatalf("a fresh refresh must clear the staleness denial; blocked=%v err=%v", blocked, err)
	}
	if r.HealthStatus() != nil {
		t.Errorf("HealthStatus must recover with the data plane, got %v", r.HealthStatus())
	}
}

// TestShouldBlock_StaleCacheServedUnderFailOpen pins that fail-open keeps its bargain:
// trading guaranteed revocation for availability is exactly what it opts into, so the
// staleness gate must not deny there.
func TestShouldBlock_StaleCacheServedUnderFailOpen(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	r := &Redis{
		killedAgents:      map[string]bool{},
		killedSessions:    map[string]bool{},
		reconcileInterval: 30 * time.Second,
		failOpen:          true,
		now:               func() time.Time { return now },
	}
	r.started.Store(true)
	r.lastRefreshOK = base

	now = base.Add(10 * time.Minute)
	if blocked, err := r.ShouldBlock(context.Background(), "a", "s"); blocked || err != nil {
		t.Fatalf("fail-open must keep serving a stale cache; blocked=%v err=%v", blocked, err)
	}
	// The operator signal still fires even though the data plane is permissive.
	if r.HealthStatus() == nil {
		t.Error("HealthStatus must still report the stale cache under fail-open")
	}
}

// TestShouldBlock_CachedKillBlocksEvenWhenStale pins that a KNOWN kill is unconditional.
// Staleness governs only the confidence of a NON-match; it must never weaken a match.
func TestShouldBlock_CachedKillBlocksEvenWhenStale(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	r := &Redis{
		killedAgents:      map[string]bool{"rogue": true},
		killedSessions:    map[string]bool{},
		reconcileInterval: 30 * time.Second,
		now:               func() time.Time { return now },
	}
	r.started.Store(true)
	r.lastRefreshOK = base
	now = base.Add(time.Hour)

	blocked, err := r.ShouldBlock(context.Background(), "rogue", "")
	if !blocked || err != nil {
		t.Fatalf("a cached kill must block unconditionally, even on a stale cache; blocked=%v err=%v", blocked, err)
	}
}

// TestStaleness_UsesDefaultWhenIntervalUnset guards the zero-value path: a Redis built
// without WithReconcileInterval must not compute a zero staleness window, which would make
// every non-match stale and deny all traffic.
func TestStaleness_UsesDefaultWhenIntervalUnset(t *testing.T) {
	t.Parallel()
	r := &Redis{}
	if got, want := r.staleness(), 2*defaultReconcileInterval; got != want {
		t.Fatalf("staleness() = %v, want %v", got, want)
	}
}
