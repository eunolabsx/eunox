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
func sessionAnchor(sessionID string) enforcement.StateAnchor {
	return enforcement.ResolveStateAnchor(false, false, "", sessionID)
}

func taskAnchor(taskID string) enforcement.StateAnchor {
	return enforcement.ResolveStateAnchor(true, true, taskID, "some-session")
}

// The rendered forms, for the ticket queues and the gate registry, which are keyed by string.
func sessionAnchorKey(sessionID string) string { return sessionAnchor(sessionID).Key() }

func taskAnchorKey(taskID string) string { return taskAnchor(taskID).Key() }

// beginTurn and beginTurnWithin drive the registry's one entry point, anchorGates.acquire,
// which is what httpSession.acquireDecisionTurn calls for a task-anchored route and for any
// session holding no cached gate. They are two lines in the test rather than two methods on
// the registry because that is all they were: a pair of production entry points that the
// session-held gate left with no production callers would have gone on being the code these
// tests pin while the code that runs is somewhere else.
func beginTurn(g *anchorGates, key string) func() {
	end, _ := g.acquire(key, turnWait{})
	return end
}

func beginTurnWithin(g *anchorGates, key string, d time.Duration) (func(), bool) {
	return g.acquire(key, turnWait{perHolder: d, total: d})
}

// TestAnchorGates_ExcludeWithinAKeyAndNotAcross is the primitive's contract: one turn per
// key, and keys are independent. The second half matters as much as the first — a registry
// that serialized everything would turn a gateway's whole traffic into one queue.
func TestAnchorGates_ExcludeWithinAKeyAndNotAcross(t *testing.T) {
	t.Parallel()
	g := newAnchorGates()

	end := beginTurn(g, "a")
	held := make(chan struct{})
	go func() {
		defer close(held)
		beginTurn(g, "a")() // blocks until the turn above is released, then releases its own
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
		beginTurn(g, "b")()
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
	end := beginTurn(g, "a")
	end()
	require.NotPanics(t, end, "the second release must be a no-op, not an unlock of an unlocked mutex")

	// And the turn really is free afterwards.
	done := make(chan struct{})
	go func() { defer close(done); beginTurn(g, "a")() }()
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
		beginTurn(g, key)()
	}
	assert.Zero(t, g.size(), "a released anchor must not be retained")

	// A gate with a waiter is retained until BOTH are done.
	end := beginTurn(g, "held")
	waiting := make(chan func(), 1)
	go func() { waiting <- beginTurn(g, "held") }()
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
	require.NotPanics(t, func() { beginTurn(g, "a")() })
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
		assert.Equal(t, sessionAnchor("sess-a"), a)
	})

	t.Run("no token at all falls back to the session", func(t *testing.T) {
		assert.Equal(t, sessionAnchor("sess-a"), anchored.decisionAnchor("sess-a", nil))
	})

	t.Run("a route that does not anchor on the task ignores the claim", func(t *testing.T) {
		assert.Equal(t, sessionAnchor("sess-a"), sessionOnly.decisionAnchor("sess-a", taskClaims),
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
		assert.Equal(t, taskAnchor("task-42"), anchored.decisionAnchorFromContext(ctx, "sess-a"))
		assert.Equal(t, sessionAnchor("sess-a"), anchored.decisionAnchorFromContext(context.Background(), "sess-a"))
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
			endA := beginTurn(tc.route.decideGates, tc.route.decisionAnchor("sess-a", claims).Key())

			var started atomic.Bool
			ready := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				close(ready)
				end := beginTurn(tc.route.decideGates, tc.route.decisionAnchor("sess-b", claims).Key())
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
	held := beginTurn(g, "a")

	end, ok := beginTurnWithin(g, "a", 20*time.Millisecond)
	assert.False(t, ok, "a busy anchor must be reported rather than waited for")
	assert.Nil(t, end, "and no turn was taken, so there is nothing to release")

	// The abandoned wait must not pin the gate: once the holder releases, the anchor is
	// reclaimed exactly as if the wait had never happened.
	held()
	assert.Zero(t, g.size(), "an abandoned wait must drop its reference")

	// A free anchor is entered immediately.
	end, ok = beginTurnWithin(g, "a", time.Second)
	require.True(t, ok)
	require.NotNil(t, end)
	end()
	assert.Zero(t, g.size())
}

// TestAnchorGates_TurnFirstWhenTheDeadlineHasPassed pins the stdio twin's guarantee on this
// leg: a timer that fires in the same instant the turn comes up loses, so a caller is never
// refused a turn it could have had.
//
// take is a select over a free turn and an expired giveUp, and Go resolves a ready two-arm
// select UNIFORMLY — so with the deadline already passed and the turn sitting free, roughly
// half of these calls used to come back as a hard turn_unavailable sampling denial for a
// decision that could have run. decisionSerializer.beginWithin states the opposite property
// explicitly and the two legs are meant to answer identically; only this one lacked it.
func TestAnchorGates_TurnFirstWhenTheDeadlineHasPassed(t *testing.T) {
	t.Parallel()
	g := newAnchorGates()

	// An ALREADY-ELAPSED window, so the give-up arm is ready on EVERY iteration and both
	// select arms race on every one of them. A window long enough to be won by the turn arm
	// would leave the rest of the loop racing nothing.
	expired := turnWait{perHolder: time.Nanosecond, total: time.Nanosecond}

	for i := 0; i < 200; i++ {
		end, ok := g.acquire("a", expired)
		require.True(t, ok, "iteration %d: a free turn must win over an expired deadline", i)
		require.NotNil(t, end)
		end()
	}
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
	rt := &UpstreamRoute{decideGates: newAnchorGates(), pdp: pdp.DenyAllPDP{}}
	sess := newTestSession(&httpSession{id: "sess-a", route: rt})
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
	viaRegistry, drop := rt.decideGates.hold(rt.decisionAnchor(sess.id, nil).Key())
	assert.Same(t, held, viaRegistry)
	drop()

	// And it is released by the TEARDOWN FUNNEL, not by a hand call: releaseSessionState is
	// the one path that runs on every teardown reason, and driving it is what makes this
	// assertion about the release production performs. See
	// TestSessionGate_ReleasedOnEveryTeardownPath.
	releaseSessionState(sess)
	assert.Zero(t, rt.decideGates.size())
}

// TestSessionGate_ReleasedOnEveryTeardownPath is the leak guard, and it drives the funnel
// rather than the drop.
//
// A session-lifetime hold is only bounded if something always releases it, and close() is NOT
// that something: a local upstream that exits on its own (crash, clean exit, an unreadable
// frame) has its session reaped by the cleanup goroutine, which deletes the registry entry and
// calls releaseSessionState WITHOUT ever calling close() — the path releaseSessionState's own
// doc exists to cover. Releasing the gate anywhere else retained one per such session for the
// proxy's life, which is exactly the accumulation the registry refcounts to prevent, and a
// test that called dropDecideGate directly could not see it.
func TestSessionGate_ReleasedOnEveryTeardownPath(t *testing.T) {
	t.Parallel()
	for name, teardown := range map[string]func(*httpSession){
		// The natural-upstream-exit path: what the cleanup goroutine runs after <-sess.done,
		// with no close() anywhere in it.
		"upstream exited on its own": func(s *httpSession) { releaseSessionState(s) },
		// An explicit teardown (idle reap, DELETE, kill, shutdown) closes first and is reaped
		// by the same goroutine afterwards.
		"explicit close then reap": func(s *httpSession) { s.close(0); releaseSessionState(s) },
	} {
		t.Run(name, func(t *testing.T) {
			rt := &UpstreamRoute{decideGates: newAnchorGates(), pdp: pdp.DenyAllPDP{}}
			sess := newTestSession(&httpSession{id: "sess-x", route: rt})
			sess.holdDecisionGate()
			require.Equal(t, 1, rt.decideGates.size())
			teardown(sess)
			assert.Zero(t, rt.decideGates.size(),
				"a gate held for a session's life must be released on every teardown path, not just close()")
		})
	}
}

// TestSessionGate_TaskAnchoredRouteResolvesPerRequest is the negative half: the PIN serves a
// request only when the request RESOLVES the anchor it was taken for. Here neither session
// presented a task at initialize, so each pins its own session anchor — and requests that do
// carry a task resolve an anchor neither pinned, so each session reaches it through its span
// cache instead, and both must land on ONE gate, which is exactly what task anchoring is for.
// (What the span cache changes is who HOLDS that gate between calls; what it must not change is
// that there is one of it. See session_gate_cache_test.go.)
func TestSessionGate_TaskAnchoredRouteResolvesPerRequest(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	a := newTestSession(&httpSession{id: "sess-a", route: rt})
	b := newTestSession(&httpSession{id: "sess-b", route: rt})
	a.holdDecisionGate()
	b.holdDecisionGate()
	require.Equal(t, sessionAnchor("sess-a"), a.decideAnchor, "a session with no task claim anchors on itself")
	require.Equal(t, 2, rt.decideGates.size(), "two sessions, two session-anchored gates")

	ctx := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{TaskID: "task-42"})
	require.Nil(t, a.gateFor(rt.decisionAnchorFromContext(ctx, a.id)),
		"a request resolving another anchor must not be served the cached gate")

	// Two sessions, one task: the second must wait for the first, which is only true if both
	// fell through to the registry.
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
	assert.Equal(t, 3, rt.decideGates.size(),
		"three live gates: each session's own, plus the ONE both sessions resolved for task-42 — "+
			"which each now holds through its span cache rather than re-minting per call")
	releaseSessionState(a)
	releaseSessionState(b)
	assert.Zero(t, rt.decideGates.size())
}

// TestSessionGate_CacheFollowsTheResolvedAnchor is the property that replaced "this route does
// not anchor on the task, so the anchor cannot change".
//
// That restatement was correct for the two anchor kinds that exist and asserted independently
// of enforcement.ResolveStateAnchor, which is the function that actually decides. A third kind
// (an agent id, a conversation, a delegation chain) breaks every caller of the resolver at
// compile time — and a hand-written restatement of its outcome compiles untouched, leaving the
// session serving turns on a gate the per-request path no longer reaches while the engine writes
// state under the new key: two callers on one logical anchor, holding independent turns.
//
// Deciding from the resolved anchor is correct for any number of kinds by construction. The
// bonus is here too: a task-anchored session that stays on one task now uses the fast path,
// which the bool could not express.
func TestSessionGate_CacheFollowsTheResolvedAnchor(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	claims := &pdp.JWTClaims{Subject: "agent-1", TaskID: "task-42"}
	sess := newTestSession(&httpSession{id: "sess-a", route: rt, claims: claims})
	sess.holdDecisionGate()
	require.Equal(t, taskAnchor("task-42"), sess.decideAnchor, "the session's own task is what it caches")
	require.NotNil(t, sess.decideGate)
	require.Equal(t, 1, rt.decideGates.size())

	// A request on that same task takes the cached gate and never re-enters the registry.
	held := sess.decideGate
	ctx := pdp.WithJWTClaims(context.Background(), claims)
	for range 20 {
		sess.beginDecisionTurn(ctx)()
		assert.Same(t, held, sess.decideGate)
		assert.Equal(t, 1, rt.decideGates.size(), "a session that stays on one task must not re-enter the registry")
	}
	// The server-initiated leg reads the session's captured claims, so it resolves the same
	// anchor and takes the same gate.
	end, ok := sess.beginDecisionTurnWithin(turnWait{perHolder: time.Second, total: time.Second})
	require.True(t, ok)
	end()
	assert.Equal(t, 1, rt.decideGates.size())

	// A request resolving a DIFFERENT anchor must not be served the cached turn: it goes
	// through the registry, so it excludes another session on that anchor and not this one.
	other := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{Subject: "agent-1", TaskID: "task-99"})
	require.Nil(t, sess.gateFor(rt.decisionAnchorFromContext(other, sess.id)))
	sibling := newTestSession(&httpSession{id: "sess-b", route: rt})
	endOther := sess.beginDecisionTurn(other)
	blocked := make(chan struct{})
	go func() { defer close(blocked); sibling.beginDecisionTurn(other)() }()
	select {
	case <-blocked:
		t.Fatal("two callers on one resolved anchor must share a turn, cache or no cache")
	case <-time.After(20 * time.Millisecond):
	}
	// ...and the session's OWN anchor is still free while that one is held, which a single
	// per-session lock could not have expressed.
	free := sess.beginDecisionTurn(ctx)
	require.NotNil(t, free)
	free()
	endOther()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("the turn must advance once released")
	}
	releaseSessionState(sess)
	releaseSessionState(sibling)
	assert.Zero(t, rt.decideGates.size(),
		"both sessions spanned onto task-99 and each cached its gate, so both teardowns are what empties the registry")
}

// TestSessionGate_UnregisteredSessionStillSerializes covers the fallback. The cache is set at
// registration; anything that never registered (a test-assembled session) must still take a
// real turn rather than silently running unserialized, because the registry path is the
// always-correct one and the cache is the special case.
func TestSessionGate_UnregisteredSessionStillSerializes(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates()}
	sess := newTestSession(&httpSession{id: "sess-a", route: rt})
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
