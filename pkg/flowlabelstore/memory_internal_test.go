// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package flowlabelstore

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// numSessions reads the live session count under the lock. len of the internal map
// is not observable from the external test package, so the maxKeys invariants that
// assert "the map must not grow" / "a slot was reclaimed" live in-package.
func numSessions(m *InMemory) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sets)
}

// TestInMemory_WithMaxKeys_FailsClosedAtCapacity verifies the key bound: once the map
// is full, an Add creating a NEW session is refused without growing the map, while an
// existing session keeps accumulating; a slot freed by Clear is then reusable.
func TestInMemory_WithMaxKeys_FailsClosedAtCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewInMemory(WithMaxKeys(2))

	require.NoError(t, m.Add(ctx, "s1", "pii"))
	require.NoError(t, m.Add(ctx, "s2", "secret"))
	require.Equal(t, 2, numSessions(m))

	// A previously-unseen session past the bound is refused, fails closed, and the
	// map does not grow.
	err := m.Add(ctx, "s3", "phi")
	require.Error(t, err, "a new session at capacity must fail closed")
	assert.Contains(t, err.Error(), "session limit reached (2)")
	assert.Equal(t, 2, numSessions(m), "a refused Add must not grow the map")

	// An existing session still accumulates — the bound gates only NEW sessions.
	require.NoError(t, m.Add(ctx, "s1", "public"))
	got, err := m.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, []string{"pii", "public"}, got)
	assert.Equal(t, 2, numSessions(m))

	// Clear frees a slot; the new session is then admitted.
	require.NoError(t, m.Clear(ctx, "s2"))
	assert.Equal(t, 1, numSessions(m))
	require.NoError(t, m.Add(ctx, "s3", "phi"), "a slot freed by Clear must be reusable")
	assert.Equal(t, 2, numSessions(m))
}

// TestInMemory_Add_EmptyLabelsCreatesNoKey verifies that an empty-labels Add is a true
// no-op: it must not materialize a session entry (which would consume a maxKeys slot)
// nor make Get report a present session.
func TestInMemory_Add_EmptyLabelsCreatesNoKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewInMemory(WithMaxKeys(1))

	require.NoError(t, m.Add(ctx, "empty"))
	assert.Equal(t, 0, numSessions(m), "Add with no labels must not create a key")
	got, err := m.Get(ctx, "empty")
	require.NoError(t, err)
	assert.Empty(t, got)

	// The sole slot is still free, so a real session is admitted.
	require.NoError(t, m.Add(ctx, "real", "pii"))
	assert.Equal(t, 1, numSessions(m))
}

// TestInMemory_Remove_ReclaimsSlotWhenEmptied verifies that removing a session's last
// label drops the map entry, freeing its maxKeys slot for a new session.
func TestInMemory_Remove_ReclaimsSlotWhenEmptied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewInMemory(WithMaxKeys(1))

	require.NoError(t, m.Add(ctx, "s1", "pii"))
	require.Error(t, m.Add(ctx, "s2", "secret"), "at capacity, a new session is refused")

	// Removing s1's last label empties its set, reclaiming the map slot (an empty set
	// is indistinguishable from an absent session), so s2 is then admitted.
	require.NoError(t, m.Remove(ctx, "s1", "pii"))
	assert.Equal(t, 0, numSessions(m), "removing the last label must reclaim the slot")
	require.NoError(t, m.Add(ctx, "s2", "secret"))
	assert.Equal(t, 1, numSessions(m))
}

// TestInMemory_MaxKeys_UnlimitedByDefault confirms the default (no WithMaxKeys,
// equivalently WithMaxKeys(0) or a negative) leaves the session count unbounded.
func TestInMemory_MaxKeys_UnlimitedByDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, m := range []*InMemory{NewInMemory(), NewInMemory(WithMaxKeys(0)), NewInMemory(WithMaxKeys(-1))} {
		for i := 0; i < 1000; i++ {
			sk := "session-" + string(rune('a'+i%26)) + "-" + string(rune('0'+i%10))
			if err := m.Add(ctx, sk, "pii"); err != nil {
				t.Fatalf("unbounded store returned error at add %d: %v", i, err)
			}
		}
	}
}

// TestInMemory_IdleTTL_ReclaimsAbandonedAnchor is the reclamation path a task-anchored key
// had none of: session teardown never reaches it (clearing on disconnect would let an agent
// launder a task's taint by reconnecting), so without an idle bound the map grew one key per
// distinct task_id for the life of the process and the maxKeys ceiling became a cliff.
func TestInMemory_IdleTTL_ReclaimsAbandonedAnchor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	start := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	now := start
	clock := &now
	m := NewInMemory(WithMemoryIdleTTL(time.Hour), WithTimeFunc(func() time.Time { return *clock }))

	require.NoError(t, m.Add(ctx, "task-abandoned", "pii"))
	require.Equal(t, 1, numSessions(m))
	require.Equal(t, 1, m.Len(), "Len reports what the store is holding, sweep or no sweep")

	// Inside the bound the taint is intact — the TTL is a reclamation bound, not a taint
	// lifetime, so nothing ages out while the anchor is still within it.
	*clock = start.Add(59 * time.Minute)
	got, err := m.Get(ctx, "task-abandoned")
	require.NoError(t, err)
	assert.Equal(t, []string{"pii"}, got)

	// That Get refreshed it, so the bound runs from the read rather than from the write.
	*clock = start.Add(59*time.Minute + 59*time.Minute)
	got, err = m.Get(ctx, "task-abandoned")
	require.NoError(t, err)
	assert.Equal(t, []string{"pii"}, got, "a read must keep a live anchor alive")

	// Now leave it alone for a full TTL: it reads as clean, and the sweep reclaims the slot.
	*clock = clock.Add(time.Hour)
	got, err = m.Get(ctx, "task-abandoned")
	require.NoError(t, err)
	assert.Empty(t, got)
	m.Cleanup()
	assert.Equal(t, 0, numSessions(m), "an abandoned anchor must be reclaimed by the sweep")
}

// TestInMemory_IdleTTL_LiveAnchorNeverAgesOut is the fail-open this bound must not become.
// A windowed marker that expired on wall-clock age would drop a long session's taint
// mid-flow; the bound measures INACTIVITY instead, so an anchor touched by either leg —
// a source Add or a sink Get — stays live indefinitely.
func TestInMemory_IdleTTL_LiveAnchorNeverAgesOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	m := NewInMemory(WithMemoryIdleTTL(time.Hour), WithTimeFunc(func() time.Time { return *clock }))

	require.NoError(t, m.Add(ctx, "live", "pii"))
	for i := 0; i < 48; i++ {
		*clock = clock.Add(30 * time.Minute)
		if i%2 == 0 {
			require.NoError(t, m.Add(ctx, "live", "secret"))
			continue
		}
		got, err := m.Get(ctx, "live")
		require.NoError(t, err)
		require.NotEmpty(t, got, "a session doing nothing but sink checks must keep its taint")
	}
	m.Cleanup()
	got, err := m.Get(ctx, "live")
	require.NoError(t, err)
	assert.Equal(t, []string{"pii", "secret"}, got)
}

// TestInMemory_IdleTTL_RemoveDoesNotRefresh mirrors the Redis backend: a removal is a
// rollback or a teardown shrinking the taint, not activity, so it must not extend the
// idle bound.
func TestInMemory_IdleTTL_RemoveDoesNotRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	m := NewInMemory(WithMemoryIdleTTL(time.Hour), WithTimeFunc(func() time.Time { return *clock }))

	require.NoError(t, m.Add(ctx, "s1", "pii", "secret"))
	*clock = now.Add(59 * time.Minute)
	require.NoError(t, m.Remove(ctx, "s1", "secret"))
	*clock = now.Add(61 * time.Minute)
	got, err := m.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Empty(t, got, "Remove must not have refreshed the idle bound")
}

// TestInMemory_IdleTTL_OffByDefaultAndFloored covers both ends of the knob.
//
// Unset or non-positive is OFF, which is this store's historical behavior and the right
// default: a session-anchored key belongs to a live session that may simply be quiet, and
// its real reclamation is the transport's teardown, so expiring it would age a taint out
// from under a session still going to make another call. A positive sub-second value is
// raised to one second rather than honored, for the reason the Redis backend floors its
// own: it would reclaim a live anchor on its next touch.
func TestInMemory_IdleTTL_OffByDefaultAndFloored(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, ttl := range []time.Duration{0, -time.Hour} {
		m := NewInMemory(WithMemoryIdleTTL(ttl))
		assert.Zero(t, m.effectiveTTL(), "a non-positive TTL disables reclamation")
		assert.False(t, m.idleReclamation())
	}
	assert.Zero(t, NewInMemory().effectiveTTL(), "unset is off")

	m := NewInMemory(WithMemoryIdleTTL(500 * time.Millisecond))
	assert.Equal(t, time.Second, m.effectiveTTL(), "a sub-second bound is raised, never honored")
	require.NoError(t, m.Add(ctx, "s1", "pii"))
	got, err := m.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, []string{"pii"}, got)
}

// TestInMemory_NoReclamationByDefault is the regression guard for the fail-open a
// default-on bound would have been: with no TTL configured a taint survives any amount of
// idleness, because a quiet session is not an abandoned one and its reclamation is the
// transport's teardown.
func TestInMemory_NoReclamationByDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	start := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	now := start
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))

	require.NoError(t, m.Add(ctx, "quiet-session", "pii"))
	now = start.Add(30 * 24 * time.Hour)
	m.Cleanup()
	got, err := m.Get(ctx, "quiet-session")
	require.NoError(t, err)
	assert.Equal(t, []string{"pii"}, got, "provenance is monotonic when no idle bound is configured")

	// And the sweep does not even start, rather than waking forever to collect nothing.
	ctxCancel, cancel := context.WithCancel(context.Background())
	defer cancel()
	assert.False(t, m.StartCleanup(ctxCancel, time.Millisecond))
}

// TestInMemory_IdledOutAnchorDoesNotHoldACeilingSlot is the interaction between the two
// bounds: an anchor past its idle TTL is no longer live, so it must not be what refuses a
// genuinely new one. Without this the ceiling would still be reached by abandoned keys
// between sweeps.
func TestInMemory_IdledOutAnchorDoesNotHoldACeilingSlot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	m := NewInMemory(WithMaxKeys(1), WithMemoryIdleTTL(time.Hour),
		WithTimeFunc(func() time.Time { return *clock }))

	require.NoError(t, m.Add(ctx, "task-old", "pii"))
	require.Error(t, m.Add(ctx, "task-new", "pii"), "at capacity with a LIVE anchor, a new one is refused")

	*clock = now.Add(2 * time.Hour)
	require.NoError(t, m.Add(ctx, "task-new", "pii"),
		"an idled-out anchor must not hold the ceiling slot against a live one")
	assert.Equal(t, 1, numSessions(m))
}

// TestInMemory_PressureWarning fires before the cliff and again only after the count falls
// back below the threshold. The ceiling's failure mode gives no other signal: the store
// admits every anchor right up to the bound and then fails closed on the next one.
func TestInMemory_PressureWarning(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := NewInMemory(WithMaxKeys(10), WithLogger(logger))

	for i := 0; i < 8; i++ {
		require.NoError(t, m.Add(ctx, fmt.Sprintf("s%d", i), "pii"))
	}
	assert.NotContains(t, buf.String(), "approaching", "no warning below the threshold")

	require.NoError(t, m.Add(ctx, "s8", "pii")) // 9/10 == the 90% threshold
	assert.Contains(t, buf.String(), "approaching its key ceiling")
	first := strings.Count(buf.String(), "approaching its key ceiling")
	require.NoError(t, m.Add(ctx, "s9", "pii"))
	assert.Equal(t, first, strings.Count(buf.String(), "approaching its key ceiling"),
		"the approach warning latches rather than firing per admitted anchor")

	// The cliff itself says so in its own terms: the deny an operator sees reads as a
	// backend fault, and the action here is different.
	require.Error(t, m.Add(ctx, "s10", "pii"))
	assert.Contains(t, buf.String(), "at its key ceiling")
	atCeiling := strings.Count(buf.String(), "at its key ceiling")
	require.Error(t, m.Add(ctx, "s11", "pii"))
	assert.Equal(t, atCeiling, strings.Count(buf.String(), "at its key ceiling"),
		"the ceiling warning is one line per episode, not one per denied call")
}

// TestInMemory_StartCleanup_ReclaimsWithoutBeingTouched is the point of the background
// sweep: the lazy expiry on the access paths never runs for an anchor nothing accesses
// again, which is exactly what an abandoned anchor is.
func TestInMemory_StartCleanup_ReclaimsWithoutBeingTouched(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := now
	m := NewInMemory(WithMemoryIdleTTL(time.Hour), WithTimeFunc(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}))

	require.NoError(t, m.Add(ctx, "abandoned", "pii"))
	mu.Lock()
	clock = now.Add(2 * time.Hour)
	mu.Unlock()

	require.True(t, m.StartCleanup(ctx, 5*time.Millisecond))
	assert.False(t, m.StartCleanup(ctx, time.Hour), "StartCleanup is idempotent while live")
	assert.Eventually(t, func() bool { return numSessions(m) == 0 }, 2*time.Second, 5*time.Millisecond,
		"the background sweep must reclaim an anchor nothing will touch again")

	// An already-canceled context starts nothing rather than wedging the lifecycle.
	dead, stop := context.WithCancel(context.Background())
	stop()
	assert.False(t, NewInMemory().StartCleanup(dead, time.Millisecond))
}

// TestInMemory_AtCeilingSweepIsRateLimited is why the ceiling stays cheap to hit. A store
// sitting at its bound with nothing reclaimable would otherwise pay a full O(n) map scan
// under the exclusive lock on every refused call — so the ceiling, whose job is to make a
// flood cheap to refuse, would amplify it into a store-wide stall at the flood's own rate.
func TestInMemory_AtCeilingSweepIsRateLimited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	start := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	now := start
	m := NewInMemory(WithMaxKeys(1), WithMemoryIdleTTL(time.Hour),
		WithTimeFunc(func() time.Time { return now }))

	require.NoError(t, m.Add(ctx, "live", "pii"))

	// The first refusal sweeps (nothing is reclaimable, so it still refuses) and stamps
	// the sweep clock; the next one inside the interval must not scan again.
	require.Error(t, m.Add(ctx, "new-1", "pii"))
	first := m.lastReclaim
	require.False(t, first.IsZero(), "the first at-ceiling admission attempt sweeps")

	now = start.Add(time.Second)
	require.Error(t, m.Add(ctx, "new-2", "pii"))
	assert.Equal(t, first, m.lastReclaim, "a refusal inside the interval must not re-scan")

	// Past the interval it sweeps again — and by then the held anchor has idled out, so
	// the new one is admitted rather than refused for a slot nothing is using.
	now = start.Add(DefaultCleanupInterval + time.Hour)
	require.NoError(t, m.Add(ctx, "new-3", "pii"))
	assert.True(t, m.lastReclaim.After(first))
}
