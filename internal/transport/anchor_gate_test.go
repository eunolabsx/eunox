// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionAnchorKey and taskAnchorKey render the expected turn key through the SAME resolver
// the transport and the engine both go through. Spelling the bytes here instead would pin the
// encoding in a second place — which is the drift the shared resolver exists to remove — while
// what these tests are actually about is WHICH anchor a request resolves to (task or session,
// and under which id), not how it is spelled.
func sessionAnchorKey(sessionID string) string {
	return enforcement.ResolveStateAnchor(false, false, "", sessionID).Key()
}

func taskAnchorKey(taskID string) string {
	return enforcement.ResolveStateAnchor(true, true, taskID, "some-session").Key()
}

// TestAnchorGates_ExcludeWithinAKeyAndNotAcross is the primitive's contract: one turn per
// key, and keys are independent. The second half matters as much as the first — a registry
// that serialized everything would turn a gateway's whole traffic into one queue.
func TestAnchorGates_ExcludeWithinAKeyAndNotAcross(t *testing.T) {
	t.Parallel()
	g := newAnchorGates()

	end := g.begin("a")
	held := make(chan struct{})
	go func() {
		defer close(held)
		g.begin("a")() // blocks until the turn above is released, then releases its own
	}()
	select {
	case <-held:
		t.Fatal("a second holder of the same anchor must wait its turn")
	case <-time.After(20 * time.Millisecond):
	}

	// A different anchor is not blocked by it.
	other := make(chan struct{})
	go func() {
		defer close(other)
		g.begin("b")()
	}()
	select {
	case <-other:
	case <-time.After(time.Second):
		t.Fatal("a different anchor must not queue behind this one")
	}

	end()
	select {
	case <-held:
	case <-time.After(time.Second):
		t.Fatal("the waiter must run once the turn is released")
	}
}

// TestAnchorGates_ReleaseIsIdempotent pins what the two callers depend on: the handler
// releases right after its decision and the same func is deferred as a backstop, so it is
// called twice on every serialized request.
func TestAnchorGates_ReleaseIsIdempotent(t *testing.T) {
	t.Parallel()
	g := newAnchorGates()
	end := g.begin("a")
	end()
	require.NotPanics(t, end, "the second release must be a no-op, not an unlock of an unlocked mutex")

	// And the turn really is free afterwards.
	done := make(chan struct{})
	go func() { defer close(done); g.begin("a")() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the anchor must be free after release")
	}
}

// TestAnchorGates_ReclaimsIdleAnchors is the bound on the registry. A gateway route serves an
// unbounded number of sessions over its life, so a map that only grew would be a slow leak
// keyed by session id.
func TestAnchorGates_ReclaimsIdleAnchors(t *testing.T) {
	t.Parallel()
	g := newAnchorGates()
	for i := range 100 {
		key := sessionAnchorKey(string(rune('a'+i%26)) + string(rune('0'+i/26)))
		g.begin(key)()
	}
	assert.Zero(t, g.size(), "a released anchor must not be retained")

	// A gate with a waiter is retained until BOTH are done.
	end := g.begin("held")
	waiting := make(chan func(), 1)
	go func() { waiting <- g.begin("held") }()
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, 1, g.size(), "one gate serves both the holder and its waiter")
	end()
	(<-waiting)()
	assert.Zero(t, g.size())
}

// TestAnchorGates_NilRegistryIsANoOp: a non-serialized route holds no registry, and the call
// site must not have to branch on it.
func TestAnchorGates_NilRegistryIsANoOp(t *testing.T) {
	t.Parallel()
	var g *anchorGates
	require.NotPanics(t, func() { g.begin("a")() })
}

// TestDecisionAnchor_FollowsTheStateAnchor pins the property the anchor keying exists for: the
// turn is taken on the key the accumulated state lives on. Under task-anchored state two sessions
// carrying one validated task id resolve to ONE key — a per-session lock did not span that,
// so their decisions were not serialized against state they share.
func TestDecisionAnchor_FollowsTheStateAnchor(t *testing.T) {
	t.Parallel()
	taskClaims := &pdp.JWTClaims{Subject: "agent-1", TaskID: "task-42"}
	noTaskClaims := &pdp.JWTClaims{Subject: "agent-1"}

	anchored := &UpstreamRoute{taskAnchored: true}
	sessionOnly := &UpstreamRoute{}

	t.Run("two sessions on one task share a turn", func(t *testing.T) {
		assert.Equal(t,
			anchored.decisionAnchor("sess-a", taskClaims),
			anchored.decisionAnchor("sess-b", taskClaims),
			"the state is keyed on the task, so the turn must be too")
	})

	t.Run("a token with no task id falls back to the session", func(t *testing.T) {
		a := anchored.decisionAnchor("sess-a", noTaskClaims)
		b := anchored.decisionAnchor("sess-b", noTaskClaims)
		assert.NotEqual(t, a, b, "the engine keys these on their sessions, so the turn must too")
		assert.Equal(t, sessionAnchorKey("sess-a"), a)
	})

	t.Run("no token at all falls back to the session", func(t *testing.T) {
		assert.Equal(t, sessionAnchorKey("sess-a"), anchored.decisionAnchor("sess-a", nil))
	})

	t.Run("a route that does not anchor on the task ignores the claim", func(t *testing.T) {
		assert.Equal(t, sessionAnchorKey("sess-a"), sessionOnly.decisionAnchor("sess-a", taskClaims),
			"an operator who did not enable task anchoring must see exactly the per-session turn")
		assert.NotEqual(t,
			sessionOnly.decisionAnchor("sess-a", taskClaims),
			sessionOnly.decisionAnchor("sess-b", taskClaims))
	})

	t.Run("a session and a task of the same name are different anchors", func(t *testing.T) {
		assert.NotEqual(t,
			anchored.decisionAnchor("x", &pdp.JWTClaims{TaskID: "x"}),
			sessionOnly.decisionAnchor("x", nil))
	})

	t.Run("the request's claims come from its context on the host path", func(t *testing.T) {
		ctx := pdp.WithJWTClaims(context.Background(), taskClaims)
		assert.Equal(t, taskAnchorKey("task-42"), anchored.decisionAnchorFromContext(ctx, "sess-a"))
		assert.Equal(t, sessionAnchorKey("sess-a"), anchored.decisionAnchorFromContext(context.Background(), "sess-a"))
	})
}

// TestDecisionTurn_SpansTwoSessionsSharingATask is the acceptance test for the cross-session
// case: a declassifying call holds its turn across the upstream forward, and under task
// anchoring the concurrent decision that must not interleave can be on ANOTHER session. With
// a per-session gate that second decision ran unserialized; with the anchor-keyed one it
// waits.
func TestDecisionTurn_SpansTwoSessionsSharingATask(t *testing.T) {
	t.Parallel()
	claims := &pdp.JWTClaims{Subject: "agent-1", TaskID: "task-42"}

	for name, tc := range map[string]struct {
		route      *UpstreamRoute
		wantShared bool
	}{
		"task-anchored: shared":       {&UpstreamRoute{taskAnchored: true, decideGates: newAnchorGates()}, true},
		"session-anchored: unrelated": {&UpstreamRoute{decideGates: newAnchorGates()}, false},
	} {
		t.Run(name, func(t *testing.T) {
			// Session A takes its turn and holds it, as a declassifying call does across its
			// forward.
			endA := tc.route.decideGates.begin(tc.route.decisionAnchor("sess-a", claims))

			var started atomic.Bool
			ready := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				close(ready)
				end := tc.route.decideGates.begin(tc.route.decisionAnchor("sess-b", claims))
				started.Store(true)
				end()
			}()
			<-ready
			time.Sleep(30 * time.Millisecond)

			if tc.wantShared {
				assert.False(t, started.Load(),
					"the two sessions share one task, so B's decision must not interleave with A's two-phase clear")
			} else {
				assert.True(t, started.Load(),
					"sessions with independent state must keep independent turns")
			}
			endA()
			wg.Wait()
			assert.True(t, started.Load())
		})
	}
}

// TestAnchorGates_BeginWithinGivesUp pins the bound the server-initiated leg depends on: a
// busy anchor is reported, not waited for. That leg runs on the session's single
// upstream-reader goroutine — the same goroutine that delivers every upstream response — so an
// unbounded wait behind a declassifying call's turn stalls the whole session's response path,
// and under task anchoring the turn holder can be a different session entirely.
func TestAnchorGates_BeginWithinGivesUp(t *testing.T) {
	t.Parallel()
	g := newAnchorGates()
	held := g.begin("a")

	end, ok := g.beginWithin("a", 20*time.Millisecond)
	assert.False(t, ok, "a busy anchor must be reported rather than waited for")
	assert.Nil(t, end, "and no turn was taken, so there is nothing to release")

	// The abandoned wait must not pin the gate: once the holder releases, the anchor is
	// reclaimed exactly as if the wait had never happened.
	held()
	assert.Zero(t, g.size(), "an abandoned wait must drop its reference")

	// A free anchor is entered immediately.
	end, ok = g.beginWithin("a", time.Second)
	require.True(t, ok)
	require.NotNil(t, end)
	end()
	assert.Zero(t, g.size())
}

// TestSessionGate_HeldOnceForTheSessionsLife is the shape the per-request registry round trip
// was costing. On a route that anchors state on the SESSION, the turn's anchor is a per-session
// constant, so resolving it through the route-wide registry on every enforced call took a
// route-wide mutex, minted a map entry and deleted it again — the refcount fell to zero the
// moment a non-overlapping request finished, so ordinary sequential traffic re-created the same
// entry per call on the decision path, and the mutex's contention scaled with the route's whole
// request rate rather than with contending anchors.
//
// The session holds one gate instead. What this pins is that the cached gate is the SAME gate
// the registry path resolves — not a second keying scheme — and that it survives a request
// completing.
func TestSessionGate_HeldOnceForTheSessionsLife(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates()}
	sess := &httpSession{id: "sess-a", route: rt}
	sess.holdDecisionGate()
	require.NotNil(t, sess.decideGate, "a session-anchored route caches its gate")
	require.Equal(t, 1, rt.decideGates.size())

	held := sess.decideGate
	for range 50 {
		end := sess.beginDecisionTurn(context.Background())
		end()
		assert.Same(t, held, sess.decideGate, "the gate must not be re-minted per request")
		assert.Equal(t, 1, rt.decideGates.size(), "and the registry must not be re-entered per request")
	}

	// The registry path resolves the very same gate, so the cache is an optimization rather
	// than a second turn a concurrent resolver could take independently.
	viaRegistry, drop := rt.decideGates.hold(rt.decisionAnchor(sess.id, nil))
	assert.Same(t, held, viaRegistry)
	drop()

	// And it is released at teardown, so a long-lived route holds one gate per LIVE session
	// rather than one per session it has ever served.
	sess.dropDecideGate()
	assert.Zero(t, rt.decideGates.size())
}

// TestSessionGate_TaskAnchoredRouteResolvesPerRequest is the negative half: caching is only
// correct where the anchor cannot change between requests. A task-anchored route's anchor comes
// from each request's own validated claims, and two sessions sharing a task must reach ONE gate
// — which is exactly what the registry is for.
func TestSessionGate_TaskAnchoredRouteResolvesPerRequest(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true}
	a := &httpSession{id: "sess-a", route: rt}
	b := &httpSession{id: "sess-b", route: rt}
	a.holdDecisionGate()
	b.holdDecisionGate()
	assert.Nil(t, a.decideGate, "a task-anchored route must not pin a per-session gate")
	assert.Zero(t, rt.decideGates.size())

	// Two sessions, one task: the second must wait for the first, which is only true if both
	// resolved through the registry.
	ctx := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{TaskID: "task-42"})
	end := a.beginDecisionTurn(ctx)
	waiting := make(chan func(), 1)
	go func() { waiting <- b.beginDecisionTurn(ctx) }()
	select {
	case <-waiting:
		t.Fatal("a second session sharing the task must wait for the turn")
	case <-time.After(20 * time.Millisecond):
	}
	end()
	(<-waiting)()
	assert.Zero(t, rt.decideGates.size(), "and the shared gate is reclaimed once both are done")
}

// TestSessionGate_UnregisteredSessionStillSerializes covers the fallback. The cache is set at
// registration; anything that never registered (a test-assembled session) must still take a
// real turn rather than silently running unserialized, because the registry path is the
// always-correct one and the cache is the special case.
func TestSessionGate_UnregisteredSessionStillSerializes(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates()}
	sess := &httpSession{id: "sess-a", route: rt}
	require.Nil(t, sess.decideGate)

	end := sess.beginDecisionTurn(context.Background())
	held := make(chan struct{})
	go func() { defer close(held); sess.beginDecisionTurn(context.Background())() }()
	select {
	case <-held:
		t.Fatal("an unregistered session must still be serialized against itself")
	case <-time.After(20 * time.Millisecond):
	}
	end()
	select {
	case <-held:
	case <-time.After(time.Second):
		t.Fatal("the turn must be free after release")
	}
}
