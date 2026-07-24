// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package flowlabelstore_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
)

// Both built-in backends must satisfy the capability.FlowLabelStore contract
// (Add/Get/Remove/Clear). A backend that dropped a method becomes a build failure
// here rather than an opaque runtime deny; each line documents the one-assertion
// pattern a third-party backend uses to guard itself.
var (
	_ capability.FlowLabelStore = (*flowlabelstore.InMemory)(nil)
	_ capability.FlowLabelStore = (*flowlabelstore.Redis)(nil)
)

// namedStore pairs a backend with a label so the shared behavior table runs each case
// against both implementations through the capability.FlowLabelStore interface.
type namedStore struct {
	name  string
	store capability.FlowLabelStore
}

// bothBackends builds a fresh InMemory and a fresh miniredis-backed Redis store, so a
// shared table exercises the two implementations identically. Each call gets its own
// miniredis, cleaned up with the test.
func bothBackends(t *testing.T) []namedStore {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return []namedStore{
		{"memory", flowlabelstore.NewInMemory()},
		{"redis", flowlabelstore.NewRedis(client)},
	}
}

func TestFlowLabelStore_AddUnionsIdempotently(t *testing.T) {
	ctx := context.Background()
	for _, tc := range bothBackends(t) {
		t.Run(tc.name, func(t *testing.T) {
			// Separate Adds accumulate into one set.
			require.NoError(t, tc.store.Add(ctx, "s1", "pii"))
			require.NoError(t, tc.store.Add(ctx, "s1", "secret"))
			// Re-adding present labels (and a mix of present + new) is a no-op union,
			// never an error and never a duplicate.
			require.NoError(t, tc.store.Add(ctx, "s1", "pii"))
			require.NoError(t, tc.store.Add(ctx, "s1", "secret", "public"))

			got, err := tc.store.Get(ctx, "s1")
			require.NoError(t, err)
			assert.Equal(t, []string{"pii", "public", "secret"}, got)
		})
	}
}

func TestFlowLabelStore_GetDedupsAndSorts(t *testing.T) {
	ctx := context.Background()
	for _, tc := range bothBackends(t) {
		t.Run(tc.name, func(t *testing.T) {
			// One Add carrying duplicates in unsorted order: Get returns the set,
			// deduplicated and sorted for a deterministic result.
			require.NoError(t, tc.store.Add(ctx, "s", "zebra", "alpha", "zebra", "mango", "alpha"))
			got, err := tc.store.Get(ctx, "s")
			require.NoError(t, err)
			assert.Equal(t, []string{"alpha", "mango", "zebra"}, got)
		})
	}
}

func TestFlowLabelStore_RemoveTargetedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	for _, tc := range bothBackends(t) {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.store.Add(ctx, "s", "a", "b", "c"))

			// Remove is targeted: only the named label goes, the rest remain.
			require.NoError(t, tc.store.Remove(ctx, "s", "b"))
			got, err := tc.store.Get(ctx, "s")
			require.NoError(t, err)
			assert.Equal(t, []string{"a", "c"}, got)

			// Idempotent: removing an already-absent label (and an unknown one) is a
			// no-op, not an error, and does not disturb the rest.
			require.NoError(t, tc.store.Remove(ctx, "s", "b"))
			require.NoError(t, tc.store.Remove(ctx, "s", "never-present"))
			got, err = tc.store.Get(ctx, "s")
			require.NoError(t, err)
			assert.Equal(t, []string{"a", "c"}, got)

			// Removing the remaining labels empties the session; Get then reads clean.
			require.NoError(t, tc.store.Remove(ctx, "s", "a", "c"))
			got, err = tc.store.Get(ctx, "s")
			require.NoError(t, err)
			assert.Empty(t, got)
		})
	}
}

func TestFlowLabelStore_ClearEmpties(t *testing.T) {
	ctx := context.Background()
	for _, tc := range bothBackends(t) {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.store.Add(ctx, "s", "pii", "secret"))
			require.NoError(t, tc.store.Clear(ctx, "s"))

			got, err := tc.store.Get(ctx, "s")
			require.NoError(t, err)
			assert.Empty(t, got, "Clear must release the whole set")

			// Clearing an already-absent session is a no-op.
			require.NoError(t, tc.store.Clear(ctx, "s"))
		})
	}
}

func TestFlowLabelStore_AbsentSessionReturnsEmptyNotError(t *testing.T) {
	ctx := context.Background()
	for _, tc := range bothBackends(t) {
		t.Run(tc.name, func(t *testing.T) {
			// A never-touched session is clean, not a fault: an absent taint reads as
			// an empty carried set, never an error the engine would deny on.
			got, err := tc.store.Get(ctx, "never-seen")
			require.NoError(t, err)
			assert.Empty(t, got)

			// Remove/Clear on an absent session are likewise no-op successes.
			require.NoError(t, tc.store.Remove(ctx, "never-seen", "x"))
			require.NoError(t, tc.store.Clear(ctx, "never-seen"))
		})
	}
}

func TestFlowLabelStore_SessionsStayDisjoint(t *testing.T) {
	ctx := context.Background()
	for _, tc := range bothBackends(t) {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.store.Add(ctx, "s1", "pii"))
			require.NoError(t, tc.store.Add(ctx, "s2", "secret"))

			// Each session's set is namespaced by its own (opaque, caller-namespaced)
			// key, so one session never observes another's taint.
			got1, err := tc.store.Get(ctx, "s1")
			require.NoError(t, err)
			assert.Equal(t, []string{"pii"}, got1)
			got2, err := tc.store.Get(ctx, "s2")
			require.NoError(t, err)
			assert.Equal(t, []string{"secret"}, got2)

			// Mutating one session leaves the other intact.
			require.NoError(t, tc.store.Clear(ctx, "s1"))
			got2, err = tc.store.Get(ctx, "s2")
			require.NoError(t, err)
			assert.Equal(t, []string{"secret"}, got2, "clearing s1 must not touch s2")
		})
	}
}

// TestFlowLabelStore_LifecycleThroughInterface drives a full source -> sink -> rollback
// -> teardown lifecycle purely through the capability.FlowLabelStore interface, so the
// exercise matches exactly what the enforcement engine sees.
func TestFlowLabelStore_LifecycleThroughInterface(t *testing.T) {
	ctx := context.Background()
	for _, tc := range bothBackends(t) {
		t.Run(tc.name, func(t *testing.T) {
			// tc.store is already a capability.FlowLabelStore, so the exercise is through
			// the same interface the enforcement engine sees.
			store := tc.store

			// Source reads assert labels; a later sink observes the accumulated set.
			require.NoError(t, store.Add(ctx, "sess", "pii"))
			require.NoError(t, store.Add(ctx, "sess", "confidential"))
			carried, err := store.Get(ctx, "sess")
			require.NoError(t, err)
			assert.Equal(t, []string{"confidential", "pii"}, carried)

			// A fail-closed rollback removes exactly the faulted call's label (D3).
			require.NoError(t, store.Remove(ctx, "sess", "confidential"))
			carried, err = store.Get(ctx, "sess")
			require.NoError(t, err)
			assert.Equal(t, []string{"pii"}, carried)

			// Session teardown reclaims all state; a reused id starts clean (FR-H2).
			require.NoError(t, store.Clear(ctx, "sess"))
			carried, err = store.Get(ctx, "sess")
			require.NoError(t, err)
			assert.Empty(t, carried)
		})
	}
}

// TestInMemory_Concurrent_NoRace hammers all four methods across many goroutines on a
// shared store over overlapping session keys. Run under -race, it asserts the
// RWMutex-guarded map is race-free and never panics; the interleaving is
// nondeterministic, so only per-call success is asserted.
func TestInMemory_Concurrent_NoRace(t *testing.T) {
	t.Parallel()
	store := flowlabelstore.NewInMemory()
	ctx := context.Background()

	const (
		goroutines = 64
		iterations = 300
		sessions   = 8
	)
	labels := []string{"pii", "secret", "public", "phi"}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				sk := fmt.Sprintf("session-%d", (g+i)%sessions)
				label := labels[i%len(labels)]
				switch i % 4 {
				case 0:
					assert.NoError(t, store.Add(ctx, sk, label))
				case 1:
					_, err := store.Get(ctx, sk)
					assert.NoError(t, err)
				case 2:
					assert.NoError(t, store.Remove(ctx, sk, label))
				case 3:
					assert.NoError(t, store.Clear(ctx, sk))
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestRedis_IdleTTL_RefreshedOnAddAndGet pins the Redis idle-TTL contract: Add stamps
// the TTL, both Get and Add refresh it (so a live session never loses its taint,
// FR-H1), an un-refreshed key expires past the bound (the orphaned-session safety net),
// and Clear deletes the key outright.
func TestRedis_IdleTTL_RefreshedOnAddAndGet(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	const ttl = 100 * time.Second
	store := flowlabelstore.NewRedis(client, flowlabelstore.WithIdleTTL(ttl))
	ctx := context.Background()
	const key = "flowlabels:s1"

	// Add stamps the idle TTL.
	require.NoError(t, store.Add(ctx, "s1", "pii"))
	require.InDelta(t, ttl.Seconds(), mr.TTL(key).Seconds(), 2, "Add must stamp the idle TTL")

	// Burn most of the TTL on Redis's clock; a Get must refresh it to the full bound,
	// so a session that is only being READ (sink after sink) never loses its taint.
	mr.FastForward(90 * time.Second)
	require.InDelta(t, 10.0, mr.TTL(key).Seconds(), 3, "precondition: TTL should have counted down")
	got, err := store.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, []string{"pii"}, got)
	require.InDelta(t, ttl.Seconds(), mr.TTL(key).Seconds(), 2, "Get must refresh the idle TTL")

	// Burn most again; a further Add (source write) must likewise refresh it.
	mr.FastForward(90 * time.Second)
	require.NoError(t, store.Add(ctx, "s1", "secret"))
	require.InDelta(t, ttl.Seconds(), mr.TTL(key).Seconds(), 2, "Add must refresh the idle TTL")

	// A refreshed key survives a burn shorter than the TTL.
	mr.FastForward(90 * time.Second)
	require.True(t, mr.Exists(key), "a key within its refreshed TTL must survive")

	// With no further refresh it expires past the idle bound and the taint is
	// reclaimed (the safety net for a Clear that never arrives).
	mr.FastForward(ttl)
	assert.False(t, mr.Exists(key), "an un-refreshed key must expire past the idle TTL")
	got, err = store.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Empty(t, got, "an expired session reads clean")

	// Clear DELs the key outright.
	require.NoError(t, store.Add(ctx, "s2", "x"))
	require.True(t, mr.Exists("flowlabels:s2"))
	require.NoError(t, store.Clear(ctx, "s2"))
	assert.False(t, mr.Exists("flowlabels:s2"), "Clear must delete the session's key")
}

// TestRedis_WithIdleTTL_BelowOneSecondFallsBackToDefault verifies a misconfigured idle TTL
// below one second is ignored in favor of DefaultIdleTTL rather than capping a live session's
// taint at Redis EXPIRE's one-second granularity — fail safe, not open. It covers both the
// non-positive values (a zero/negative EXPIRE would drop the taint at once) and a sub-second
// value like 500ms (which would otherwise truncate to a ~1s taint lifetime).
func TestRedis_WithIdleTTL_BelowOneSecondFallsBackToDefault(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()

	for _, ttl := range []time.Duration{0, -time.Second, 500 * time.Millisecond, time.Second - time.Nanosecond} {
		store := flowlabelstore.NewRedis(client, flowlabelstore.WithIdleTTL(ttl))
		require.NoError(t, store.Add(ctx, "s", "pii"))
		assert.InDelta(t, flowlabelstore.DefaultIdleTTL.Seconds(), mr.TTL("flowlabels:s").Seconds(), 5,
			"an idle TTL below one second must fall back to DefaultIdleTTL")
		require.NoError(t, store.Clear(ctx, "s"))
	}
}

// TestRedis_MultiInstance_SharedTaint verifies the property the Redis backend exists
// for (FR-H4): a source read on one instance and a sink on another, pointed at the
// same Redis, see the same session taint — provenance is enforceable across a
// horizontally-scaled deployment, not just per-process.
func TestRedis_MultiInstance_SharedTaint(t *testing.T) {
	mr := miniredis.RunT(t)
	clientA := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	clientB := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	instanceA := flowlabelstore.NewRedis(clientA)
	instanceB := flowlabelstore.NewRedis(clientB)
	ctx := context.Background()

	require.NoError(t, instanceA.Add(ctx, "sess", "pii"))

	got, err := instanceB.Get(ctx, "sess")
	require.NoError(t, err)
	assert.Equal(t, []string{"pii"}, got, "a second instance must see the first's taint")

	// Teardown on either instance clears it for both.
	require.NoError(t, instanceB.Clear(ctx, "sess"))
	got, err = instanceA.Get(ctx, "sess")
	require.NoError(t, err)
	assert.Empty(t, got)
}
