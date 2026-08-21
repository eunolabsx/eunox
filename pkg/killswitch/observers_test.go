// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Authoritative for the observer contract — conformance_test.go states cross-backend rules
// only, and this surface's edge cases (dedup, revive, unregister, re-entrancy) are pinned here
// for both backends.
//
// Test suite for the revocationObservers registry and both backends'
// ObserveRevocations implementations: notify-on-gain dedup, notify-outside-lock
// (re-entrant ShouldBlock), idempotent unregister, delivery via pub/sub vs the
// reconcile loop, and concurrency of observe/unregister against notify. This surface
// once shipped with no coverage at all, and both bugs the tests below pin (the
// notify/unregister data race and the missed local-kill notify) went out with it.

package killswitch

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRevocationObservers_ConcurrentObserveUnregisterNotify is the -race
// regression test: notify copies only the slice header under RLock and
// iterates after releasing the lock, so an unregister that mutates the shared
// backing array in place (the pre-fix slices.DeleteFunc(o.fns, ...)) races a
// concurrent notify's iteration over that same array. Run with -race.
func TestRevocationObservers_ConcurrentObserveUnregisterNotify(t *testing.T) {
	t.Parallel()
	var o revocationObservers

	done := make(chan struct{})
	var wg sync.WaitGroup

	// One goroutine notifies continuously, racing every observe/unregister below.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				o.notify(Revocation{AgentID: "x"})
			}
		}
	}()

	// Several goroutines continuously register and immediately unregister, so the
	// backing array churns while notify is iterating it.
	const workers = 8
	const iterations = 200
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for range iterations {
				unregister := o.observe(func(Revocation) {})
				unregister()
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(done)
	wg.Wait()
}

// TestInMemory_ObserveRevocations_NotifiesOnGain pins that each dimension
// (global/agent/session) notifies with the correct Revocation fields the
// moment the backend's local view gains that kill.
func TestInMemory_ObserveRevocations_NotifiesOnGain(t *testing.T) {
	t.Parallel()
	m := NewInMemory()
	ctx := context.Background()

	var mu sync.Mutex
	var events []Revocation
	unregister := m.ObserveRevocations(func(ev Revocation) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	defer unregister()

	require.NoError(t, m.ActivateGlobal(ctx))
	require.NoError(t, m.KillAgent(ctx, "agent-1"))
	require.NoError(t, m.KillSession(ctx, "sess-1"))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 3)
	assert.Equal(t, Revocation{Global: true}, events[0])
	assert.Equal(t, Revocation{AgentID: "agent-1"}, events[1])
	assert.Equal(t, Revocation{SessionID: "sess-1"}, events[2])
}

// TestInMemory_ObserveRevocations_NoNotifyOnRepeatOrRevive pins the dedup
// contract: only a state CHANGE notifies. Re-killing an already-killed
// identity, or reviving one, reclaims nothing new and must not fire.
func TestInMemory_ObserveRevocations_NoNotifyOnRepeatOrRevive(t *testing.T) {
	t.Parallel()
	m := NewInMemory()
	ctx := context.Background()
	var calls atomic.Int32
	m.ObserveRevocations(func(Revocation) { calls.Add(1) })

	require.NoError(t, m.KillAgent(ctx, "agent-1"))
	require.NoError(t, m.KillAgent(ctx, "agent-1")) // already killed: no new gain
	require.NoError(t, m.ReviveAgent(ctx, "agent-1"))
	require.NoError(t, m.KillSession(ctx, "sess-1"))
	require.NoError(t, m.ReviveSession(ctx, "sess-1"))
	require.NoError(t, m.ActivateGlobal(ctx))
	require.NoError(t, m.ActivateGlobal(ctx)) // already active: no new gain
	require.NoError(t, m.DeactivateGlobal(ctx))

	// Exactly three real gains: the first KillAgent, the first KillSession, and
	// the first ActivateGlobal.
	assert.Equal(t, int32(3), calls.Load())
}

// TestInMemory_ObserveRevocations_CalledOutsideLock verifies an observer may
// re-enter the backend (the documented correct response to a Revocation) from
// within its own callback without deadlocking, i.e. notify runs outside the
// backend's state lock.
func TestInMemory_ObserveRevocations_CalledOutsideLock(t *testing.T) {
	t.Parallel()
	m := NewInMemory()
	ctx := context.Background()

	done := make(chan bool, 1)
	m.ObserveRevocations(func(ev Revocation) {
		blocked, err := m.ShouldBlock(ctx, ev.AgentID, "")
		done <- err == nil && blocked
	})

	require.NoError(t, m.KillAgent(ctx, "agent-reentrant"))

	select {
	case ok := <-done:
		assert.True(t, ok, "observer must see its own kill when it re-asks ShouldBlock")
	case <-time.After(2 * time.Second):
		t.Fatal("observer callback must not deadlock when it calls back into the backend")
	}
}

// TestInMemory_ObserveRevocations_UnregisterIdempotent pins that the returned
// unregister may be called more than once without panicking, and that after
// unregistering the observer receives no further events.
func TestInMemory_ObserveRevocations_UnregisterIdempotent(t *testing.T) {
	t.Parallel()
	m := NewInMemory()
	var calls atomic.Int32
	unregister := m.ObserveRevocations(func(Revocation) { calls.Add(1) })

	unregister()
	unregister() // must not panic on double-call

	require.NoError(t, m.KillAgent(context.Background(), "agent-1"))
	assert.Equal(t, int32(0), calls.Load(), "unregistered observer must not be notified")
}

// TestInMemory_ObserveRevocations_MultipleObserversAllNotified pins that every
// registered observer is called, and that unregistering one leaves the others
// intact — the identity-by-id contract slices.DeleteFunc(id ==) depends on.
func TestInMemory_ObserveRevocations_MultipleObserversAllNotified(t *testing.T) {
	t.Parallel()
	m := NewInMemory()
	ctx := context.Background()

	var a, b, c atomic.Int32
	unregA := m.ObserveRevocations(func(Revocation) { a.Add(1) })
	m.ObserveRevocations(func(Revocation) { b.Add(1) })
	m.ObserveRevocations(func(Revocation) { c.Add(1) })

	require.NoError(t, m.KillAgent(ctx, "agent-1"))
	assert.Equal(t, int32(1), a.Load())
	assert.Equal(t, int32(1), b.Load())
	assert.Equal(t, int32(1), c.Load())

	unregA()
	require.NoError(t, m.KillAgent(ctx, "agent-2"))
	assert.Equal(t, int32(1), a.Load(), "unregistered observer must not see the second kill")
	assert.Equal(t, int32(2), b.Load())
	assert.Equal(t, int32(2), c.Load())
}

// TestInMemory_ObserveRevocations_NilFuncIsNoop pins that observe(nil) returns
// a harmless no-op unregister rather than panicking later inside notify.
func TestInMemory_ObserveRevocations_NilFuncIsNoop(t *testing.T) {
	t.Parallel()
	m := NewInMemory()
	unregister := m.ObserveRevocations(nil)
	require.NotPanics(t, func() {
		unregister()
		_ = m.KillAgent(context.Background(), "agent-1")
	})
}

// TestRedis_ObserveRevocations_LocalKillNotifies is the regression test for the
// missed local kill: one issued through THIS instance's own Manager (KillAgent, KillSession,
// ActivateGlobal) must reach this instance's own observers exactly once, not
// zero times. Before the fix, setBlock/ActivateGlobal updated the local cache
// but never called observers.notify, and the instance's own pub/sub echo
// deduped against the already-updated cache — so the observer was never
// called at all.
func TestRedis_ObserveRevocations_LocalKillNotifies(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	r.Start(t.Context())
	defer r.Stop()

	var mu sync.Mutex
	var events []Revocation
	unregister := r.ObserveRevocations(func(ev Revocation) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	defer unregister()

	ctx := context.Background()
	require.NoError(t, r.KillAgent(ctx, "agent-local"))
	require.NoError(t, r.KillSession(ctx, "sess-local"))
	require.NoError(t, r.ActivateGlobal(ctx))

	seen := func(match func(Revocation) bool) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, ev := range events {
			if match(ev) {
				return true
			}
		}
		return false
	}
	require.Eventually(t, func() bool {
		return seen(func(ev Revocation) bool { return ev.AgentID == "agent-local" })
	}, 2*time.Second, 10*time.Millisecond, "KillAgent issued through this instance must notify its own observers")
	require.Eventually(t, func() bool {
		return seen(func(ev Revocation) bool { return ev.SessionID == "sess-local" })
	}, 2*time.Second, 10*time.Millisecond, "KillSession issued through this instance must notify its own observers")
	require.Eventually(t, func() bool {
		return seen(func(ev Revocation) bool { return ev.Global })
	}, 2*time.Second, 10*time.Millisecond, "ActivateGlobal issued through this instance must notify its own observers")

	// Give the instance's own pub/sub echo time to arrive and confirm the existing
	// dedup (against the already-updated cache) still prevents a SECOND delivery.
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	counts := map[string]int{}
	for _, ev := range events {
		switch {
		case ev.Global:
			counts["global"]++
		case ev.AgentID != "":
			counts["agent"]++
		case ev.SessionID != "":
			counts["session"]++
		}
	}
	assert.Equal(t, 1, counts["agent"], "local agent kill must notify exactly once (no double delivery from local write + own pub/sub echo)")
	assert.Equal(t, 1, counts["session"], "local session kill must notify exactly once")
	assert.Equal(t, 1, counts["global"], "local global activation must notify exactly once")
}

// TestRedis_ObserveRevocations_ReviveDoesNotNotify pins that ReviveAgent/
// ReviveSession/DeactivateGlobal, which carry no Revocation counterpart, do not
// call observers — mirroring InMemory.
func TestRedis_ObserveRevocations_ReviveDoesNotNotify(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	r.Start(t.Context())
	defer r.Stop()

	ctx := context.Background()
	require.NoError(t, r.KillAgent(ctx, "agent-1"))
	require.NoError(t, r.KillSession(ctx, "sess-1"))
	require.NoError(t, r.ActivateGlobal(ctx))

	// Drain the kill/activate echoes before observing, so only revive/deactivate
	// events are captured below.
	time.Sleep(200 * time.Millisecond)

	var calls atomic.Int32
	r.ObserveRevocations(func(Revocation) { calls.Add(1) })

	require.NoError(t, r.ReviveAgent(ctx, "agent-1"))
	require.NoError(t, r.ReviveSession(ctx, "sess-1"))
	require.NoError(t, r.DeactivateGlobal(ctx))
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, int32(0), calls.Load(), "revive/deactivate must not notify: nothing to reclaim on a restored session")
}

// TestRedis_ObserveRevocations_PubSubDelivers verifies a kill issued through a
// DIFFERENT instance sharing the same Redis reaches this instance's observers
// via the pub/sub echo path (as opposed to the reconcile loop).
func TestRedis_ObserveRevocations_PubSubDelivers(t *testing.T) {
	t.Parallel()
	mr := newMiniredisT(t)

	issuer := newRedisClientT(t, mr)
	issuer.Start(t.Context())
	defer issuer.Stop()

	observer := newRedisClientT(t, mr)
	observer.Start(t.Context())
	defer observer.Stop()

	var got atomic.Pointer[Revocation]
	observer.ObserveRevocations(func(ev Revocation) { got.Store(&ev) })

	require.NoError(t, issuer.KillAgent(context.Background(), "agent-remote"))

	require.Eventually(t, func() bool {
		ev := got.Load()
		return ev != nil && ev.AgentID == "agent-remote"
	}, 2*time.Second, 10*time.Millisecond, "a kill from another instance must reach this instance's observers via pub/sub")
}

// TestRedis_ObserveRevocations_ReconcileDelivers verifies a kill discovered
// purely by a reconcile-style refreshState call (no pub/sub involved) still
// notifies observers — the fallback path the ObserveRevocations doc promises
// for a dropped publish.
func TestRedis_ObserveRevocations_ReconcileDelivers(t *testing.T) {
	t.Parallel()
	// newStartedTestRedis, not Start: no pub/sub listener runs, isolating the
	// reconcile-only path.
	r, mr := newStartedTestRedis(t)

	var got atomic.Pointer[Revocation]
	r.ObserveRevocations(func(ev Revocation) { got.Store(&ev) })

	require.NoError(t, mr.Set(redisAgentPrefix+"agent-reconciled", "1"))
	require.NoError(t, r.refreshState(context.Background()))

	ev := got.Load()
	require.NotNil(t, ev, "a kill discovered purely by refreshState (reconcile) must still notify observers")
	assert.Equal(t, "agent-reconciled", ev.AgentID)
}

// TestRedis_ObserveRevocations_ReentrantRefreshDoesNotDeadlock pins the contract's "called
// OUTSIDE the backend's lock so it may call back in" for refreshMu, not just mu. A kill
// discovered by the reconcile scan used to be delivered with refreshMu still held, so an
// observer re-entering any refresh-taking method self-deadlocked: the reconcile goroutine
// wedged for the process's life (the cache goes stale, so fail-closed denies all traffic
// and fail-open stops learning of new kills) and a later Stop hung forever on wg.Wait.
//
// Reset is the re-entry used because it is the shipped method that reaches refreshMu (its
// post-clear re-seed goes through refreshState); the pre-existing re-entrancy test only
// exercises ShouldBlock, which takes mu alone.
func TestRedis_ObserveRevocations_ReentrantRefreshDoesNotDeadlock(t *testing.T) {
	t.Parallel()
	r, mr := newStartedTestRedis(t)

	var reentered atomic.Bool
	r.ObserveRevocations(func(Revocation) {
		// Reset deletes the kill keys first, so its re-seed gains nothing and this
		// cannot recurse; under the pre-fix delivery it simply never returns.
		_ = r.Reset(context.Background())
		reentered.Store(true)
	})

	require.NoError(t, mr.Set(redisAgentPrefix+"agent-reentrant", "1"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.refreshState(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("refreshState deadlocked delivering a revocation to an observer that re-entered the Manager")
	}
	assert.True(t, reentered.Load(), "the observer must have run")
}

// TestRedis_ObserveRevocations_StartTimeRevocationDoesNotDeadlockStop pins the same
// "may call back in" contract at the OTHER lifecycle lock. Start holds lifeMu across its
// whole body — including the initial snapshot — and Stop takes lifeMu, so an observer
// reacting to a kill already present at startup by stopping the switch deadlocked against
// the Start that was notifying it.
//
// The kill is written straight into miniredis with no publish, so only the initial
// snapshot can find it: the delivery under test is Start's, not the listener's.
func TestRedis_ObserveRevocations_StartTimeRevocationDoesNotDeadlockStop(t *testing.T) {
	t.Parallel()
	r, mr := newTestRedis(t)
	require.NoError(t, mr.Set(redisAgentPrefix+"agent-at-start", "1"))

	var stopped atomic.Bool
	r.ObserveRevocations(func(Revocation) {
		r.Stop()
		stopped.Store(true)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Start(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Start deadlocked delivering a startup revocation to an observer that called Stop")
	}
	assert.True(t, stopped.Load(), "the observer must have run")
}

// TestRedis_ObserveRevocations_UnregisterIdempotent mirrors the InMemory case
// for the Redis backend.
func TestRedis_ObserveRevocations_UnregisterIdempotent(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	r.Start(t.Context())
	defer r.Stop()

	var calls atomic.Int32
	unregister := r.ObserveRevocations(func(Revocation) { calls.Add(1) })
	unregister()
	unregister() // must not panic on double-call

	require.NoError(t, r.KillAgent(context.Background(), "agent-1"))
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, int32(0), calls.Load(), "unregistered observer must not be notified")
}

// newMiniredisT starts a miniredis server for the test and returns its address,
// cleaning up on test completion.
func newMiniredisT(t *testing.T) string {
	t.Helper()
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)
	return mr.Addr()
}

// newRedisClientT builds a *Redis kill switch pointed at a running miniredis
// address, closing its client on test cleanup.
func newRedisClientT(t *testing.T, addr string) *Redis {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedis(client)
}
