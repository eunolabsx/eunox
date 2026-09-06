// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// registryGate returns the route registry's live gate for key, under the registry's own mutex —
// the tests below assert about map contents while other goroutines are queued on gates, and an
// unsynchronized read of that map is a race the detector would (rightly) fail on.
func registryGate(g *anchorGates, key string) *anchorGate {
	g.reg.lock()
	defer g.reg.unlock()
	return g.reg.entries[key]
}

// taskCtx builds a request context carrying a validated task claim, which is what a
// task-anchored route resolves its anchor from.
func taskCtx(task string) context.Context {
	return pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{Subject: "agent-1", TaskID: task})
}

// spanningSession builds a registered-shaped session on a task-anchored route: it pins the gate
// for its own anchor exactly as registerSession does, so what the tests below exercise is the
// path a real request takes.
func spanningSession(t *testing.T, rt *UpstreamRoute, id, ownTask string) *httpSession {
	t.Helper()
	var claims *pdp.JWTClaims
	if ownTask != "" {
		claims = &pdp.JWTClaims{Subject: "agent-1", TaskID: ownTask}
	}
	sess := newTestSession(&httpSession{id: id, route: rt, claims: claims})
	sess.holdDecisionGate()
	return sess
}

// visit drives one request per named task through sess, in order, for passes rounds. Filling and
// then WARMING is what the tests below need: an entry is only shed once a full pass of the cache
// has gone by without a use of it (gateCache.admitsLocked), so making one entry the coldest means
// using the others, not merely inserting more.
func visit(sess *httpSession, passes int, tasks ...string) {
	for range passes {
		for _, task := range tasks {
			sess.beginDecisionTurn(taskCtx(task))()
		}
	}
}

// fillTasks names the maxCachedSessionGates anchors the tests below fill the cache with.
func fillTasks() []string {
	names := make([]string, maxCachedSessionGates)
	for i := range names {
		names[i] = fmt.Sprintf("task-%d", i)
	}
	return names
}

// TestGateCache_SpanningSessionStopsReenteringTheRegistry is the shape this cache exists for.
//
// A session pins the gate for the anchor it registered on, and that pin serves every request
// while the session stays on it. A session that MOVES to a second task matched the pin on
// nothing after the move, so every enforced call went back through the route-wide registry —
// a mutex, a map insert and a map delete per call, since the refcount fell to zero the instant
// each request finished. That is the shape task anchoring exists to enable (one long-lived
// connection, task-1 then task-2 … task-n), so the fast path was absent precisely where it was
// wanted.
//
// What is pinned here is the OBSERVABLE consequence: the registry stops being re-entered, which
// shows up as the gate for the second task surviving the request that resolved it.
func TestGateCache_SpanningSessionStopsReenteringTheRegistry(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	sess := spanningSession(t, rt, "sess-a", "task-1")
	require.Equal(t, taskAnchor("task-1"), sess.decideAnchor)
	require.Equal(t, 1, rt.decideGates.size())

	// The session moves to task-2. The FIRST call there resolves through the registry and the
	// cache keeps the gate; every call after it is served without re-entering the registry,
	// which is visible as a stable gate identity and a stable registry size.
	ctx := taskCtx("task-2")
	sess.beginDecisionTurn(ctx)()
	require.Equal(t, 1, sess.decideCache.size(), "the second anchor is cached, not re-resolved")
	require.Equal(t, 2, rt.decideGates.size(), "and its gate is held, not reclaimed at the end of the call")

	held := registryGate(rt.decideGates, taskAnchor("task-2").Key())
	require.NotNil(t, held)
	for range 50 {
		sess.beginDecisionTurn(ctx)()
		assert.Same(t, held, registryGate(rt.decideGates, taskAnchor("task-2").Key()),
			"a spanning session must not re-mint its anchor's gate per call")
		assert.Equal(t, 2, rt.decideGates.size())
	}

	// The pin still serves the session's own anchor, at no cost and with no cache entry.
	sess.beginDecisionTurn(taskCtx("task-1"))()
	assert.Equal(t, 1, sess.decideCache.size(), "the pinned anchor never enters the cache")

	releaseSessionStateForTest(sess)
	assert.Zero(t, rt.decideGates.size(), "teardown returns every reference, pinned and cached alike")
	assert.Zero(t, sess.decideCache.size())
}

// TestGateCache_CachedGateIsTheRegistrysGate is the correctness half. A faster path to a turn is
// only a turn if it is the SAME turn: two callers on one resolved anchor must exclude each
// other whether one of them is served from a session cache or not. A cache that minted its own
// gate would be silently unserialized — the failure the decision turn exists to prevent, on the
// path with no second reader to notice.
func TestGateCache_CachedGateIsTheRegistrysGate(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	a := spanningSession(t, rt, "sess-a", "task-1")
	b := spanningSession(t, rt, "sess-b", "task-9")
	t.Cleanup(func() { releaseSessionStateForTest(a); releaseSessionStateForTest(b) })

	// Both sessions span onto task-7, so both are served from their own caches.
	ctx := taskCtx("task-7")
	a.beginDecisionTurn(ctx)()
	b.beginDecisionTurn(ctx)()
	require.Equal(t, 1, a.decideCache.size())
	require.Equal(t, 1, b.decideCache.size())

	// Held by a, wanted by b: b must wait, which is only true if the two caches resolved the
	// same gate.
	end := a.beginDecisionTurn(ctx)
	entered := make(chan struct{})
	go func() { defer close(entered); b.beginDecisionTurn(ctx)() }()
	select {
	case <-entered:
		t.Fatal("two sessions on one resolved anchor must share a turn, cached or not")
	case <-time.After(20 * time.Millisecond):
	}
	// And a's OWN anchor is free while that one is held: sharing a turn is per anchor, not per
	// session.
	a.beginDecisionTurn(taskCtx("task-1"))()
	end()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the shared turn must advance once released")
	}
}

// TestGateCache_EvictionNeverDropsAGateInUse is the hazard the whole design is arranged around.
//
// Evicting an entry returns its registry reference, and that reference is the only thing
// stopping the registry reclaiming the gate and building a FRESH one for the same anchor under
// the next caller. A request that read the old gate and has not yet taken its turn would then
// be serialized against nobody. So an entry with users is retired rather than dropped, and the
// last user returns the reference.
//
// The test holds a turn on an anchor, then drives enough other anchors through the cache to
// evict it, and asserts the gate the holder is on is still the gate the registry hands out.
func TestGateCache_EvictionNeverDropsAGateInUse(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	sess := spanningSession(t, rt, "sess-a", "own")
	t.Cleanup(func() { releaseSessionStateForTest(sess) })

	victim := taskCtx("task-victim")
	end := sess.beginDecisionTurn(victim) // held for the whole test: the entry has a user
	victimGate := registryGate(rt.decideGates, taskAnchor("task-victim").Key())
	require.NotNil(t, victimGate)

	// Fill the rest of the cache, then WARM those entries so the victim is the coldest by more
	// than a full pass — which is what makes it shed-able at all (gateCache.admitsLocked) — and
	// one more anchor to actually shed it.
	warm := fillTasks()[1:]
	visit(sess, 3, warm...)
	require.Equal(t, maxCachedSessionGates, sess.decideCache.size(), "the victim plus the warm set fill it")
	visit(sess, 1, "task-displacer")
	assert.Equal(t, maxCachedSessionGates, sess.decideCache.size(), "the cache holds no more than its cap")

	// The evicted-but-in-use gate is still the registry's gate for that anchor, so a second
	// caller on it is excluded by the turn this test is holding.
	stillThere, drop := rt.decideGates.hold(taskAnchor("task-victim").Key())
	assert.Same(t, victimGate, stillThere,
		"a retired entry keeps its reference until its last user leaves; reclaiming it here "+
			"would hand the next caller a second gate for one anchor")
	blocked := make(chan struct{})
	go func() { defer close(blocked); e, _ := stillThere.take(turnWait{}); e() }()
	select {
	case <-blocked:
		t.Fatal("the turn is held; a second caller on the same gate must wait")
	case <-time.After(20 * time.Millisecond):
	}
	end()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("the turn must advance once released")
	}
	drop()

	// And once the last user has left, the retired entry's reference is returned rather than
	// stranded: nothing but this test's own sessions holds the anchor now.
	assert.Nil(t, registryGate(rt.decideGates, taskAnchor("task-victim").Key()),
		"the last user of a retired entry must return its reference")
}

// TestGateCache_CapBoundsWhatOneSessionPins is the memory bound. The anchors are validated task
// claims, so a client with many tasks — or one authenticated client minting them — must not be
// able to pin one route gate per task for the life of a connection. Every request is still
// served past the cap, from the registry path that served all of them before this cache existed;
// what the cap bounds is what the SESSION holds, not what it may ask for.
func TestGateCache_CapBoundsWhatOneSessionPins(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	sess := spanningSession(t, rt, "sess-a", "own")

	const anchors = maxCachedSessionGates * 5
	for i := range anchors {
		end := sess.beginDecisionTurn(taskCtx(fmt.Sprintf("task-%d", i)))
		require.NotNil(t, end, "every request is served, cached or not")
		end()
		assert.LessOrEqual(t, sess.decideCache.size(), maxCachedSessionGates)
	}
	assert.Equal(t, maxCachedSessionGates, sess.decideCache.size())
	// One session gate for the pin plus the capped cache, never one per anchor ever seen.
	assert.Equal(t, maxCachedSessionGates+1, rt.decideGates.size())

	releaseSessionStateForTest(sess)
	assert.Zero(t, rt.decideGates.size())
}

// TestGateCache_ReleasedOnEveryTeardownPath is the leak guard, and it drives the teardown FUNNEL
// rather than the drop — for the reason the pinned gate's own guard does. A local upstream that
// exits on its own is reaped without close() ever being called, so a cache released anywhere
// else retains up to maxCachedSessionGates route gates per such session for the proxy's life.
func TestGateCache_ReleasedOnEveryTeardownPath(t *testing.T) {
	t.Parallel()
	for name, teardown := range map[string]func(*httpSession){
		"upstream exited on its own": func(s *httpSession) { releaseSessionStateForTest(s) },
		"explicit close then reap":   func(s *httpSession) { s.close(0); releaseSessionStateForTest(s) },
	} {
		t.Run(name, func(t *testing.T) {
			rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
			sess := spanningSession(t, rt, "sess-x", "own")
			for i := range 3 {
				sess.beginDecisionTurn(taskCtx(fmt.Sprintf("task-%d", i)))()
			}
			require.Equal(t, 4, rt.decideGates.size())
			teardown(sess)
			assert.Zero(t, rt.decideGates.size(),
				"every gate a session cached must be returned on every teardown path, not just close()")
		})
	}
}

// TestGateCache_TeardownRetiresAnEntryStillInUse is the teardown arm of the same hazard
// eviction has. releaseSessionObjectState drains in-flight requests first, but the drain is BOUNDED —
// a handler wedged past the budget outlives it — so close() must not return a reference a
// request is still queued on either. It retires such an entry instead, and the request that
// leaves last is what returns it.
func TestGateCache_TeardownRetiresAnEntryStillInUse(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	sess := spanningSession(t, rt, "sess-a", "own")

	spanned := taskAnchor("task-late")
	end, ok := sess.beginTurn(spanned, turnWait{})
	require.True(t, ok)
	require.Equal(t, 1, sess.decideCache.size())

	// Teardown while that request still holds its turn: the cache empties, but the gate the
	// request is on must survive — reclaiming it would let a later caller be handed a second
	// gate for the anchor and be serialized against nobody.
	sess.decideCache.close()
	assert.Zero(t, sess.decideCache.size())
	assert.NotNil(t, registryGate(rt.decideGates, spanned.Key()),
		"a retired entry keeps its reference while a request is still on its gate")

	end()
	assert.Nil(t, registryGate(rt.decideGates, spanned.Key()),
		"and the last user returns it, so teardown strands nothing")

	sess.dropDecideGate()
	assert.Zero(t, rt.decideGates.size())
}

// TestGateCache_ShedsTheColdestEntry pins WHICH entry the cap sheds. The cap bounds the memory;
// which entry it sheds is what decides whether a session that keeps returning to the same few
// tasks keeps its fast path. Shedding the oldest USE (not the oldest insert) is what makes a
// re-visited anchor stay.
func TestGateCache_ShedsTheColdestEntry(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	sess := spanningSession(t, rt, "sess-a", "own")
	t.Cleanup(func() { releaseSessionStateForTest(sess) })

	// Fill the cache exactly, then keep using every entry EXCEPT task-1 — which leaves task-1
	// the coldest by more than a full pass, and every other entry in rotation.
	all := fillTasks()
	visit(sess, 1, all...)
	require.Equal(t, maxCachedSessionGates, sess.decideCache.size())
	warm := append([]string{all[0]}, all[2:]...)
	visit(sess, 2, warm...)

	// One more anchor now shows the choice: task-1 goes, task-0 stays.
	visit(sess, 1, "task-new")
	assert.Equal(t, maxCachedSessionGates, sess.decideCache.size())
	assert.NotNil(t, registryGate(rt.decideGates, taskAnchor("task-0").Key()),
		"an anchor still in rotation keeps its place: what is shed is the COLDEST, not the oldest insert")
	assert.Nil(t, registryGate(rt.decideGates, taskAnchor("task-1").Key()),
		"the entry the session stopped using is the one shed")
	assert.NotNil(t, registryGate(rt.decideGates, taskAnchor("task-new").Key()))
}

// TestGateCache_KeepsEntriesStillInRotation is the anti-thrash rule, and it is a COST property
// rather than a correctness one — which is why it is pinned rather than left to a benchmark
// nobody runs.
//
// A session cycling one more live anchor than the cache holds is the only workload that reaches
// the cap. Under plain least-recently-used eviction it sheds, on every single request, the entry
// the next request wants: it loses every hit AND adds this file's bookkeeping to the registry
// round trip it would have paid anyway, measurably slower than having no cache at all. So an
// entry is only shed once a full pass has gone by without a use of it, and a session whose live
// set does not fit keeps the entries that do rather than losing the cache for all of them.
func TestGateCache_KeepsEntriesStillInRotation(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	sess := spanningSession(t, rt, "sess-a", "own")
	t.Cleanup(func() { releaseSessionStateForTest(sess) })

	// One more live anchor than the cache can hold, cycled round-robin many times over.
	cycle := append(fillTasks(), "task-overflow")
	visit(sess, 10, cycle...)

	assert.Equal(t, maxCachedSessionGates, sess.decideCache.size())
	for _, task := range fillTasks() {
		assert.NotNilf(t, registryGate(rt.decideGates, taskAnchor(task).Key()),
			"%s is used every pass and must keep its entry; shedding it per miss is the thrash this rule exists to stop", task)
	}
	assert.Nil(t, registryGate(rt.decideGates, taskAnchor("task-overflow").Key()),
		"the anchor that does not fit takes the registry path, which is what every request took before this cache")
}

// TestGateCache_ClosedCacheStillServesTurns covers a request racing its own session's teardown.
// The cache stops admitting once closed — taking a reference a torn-down session will never
// return is the leak the cap exists to prevent — but the request must still take a real turn
// rather than silently running unserialized, so it falls through to the registry.
func TestGateCache_ClosedCacheStillServesTurns(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	sess := spanningSession(t, rt, "sess-a", "own")
	sess.decideCache.close()

	ctx := taskCtx("task-late")
	end := sess.beginDecisionTurn(ctx)
	require.NotNil(t, end, "a closed cache must not mean an unserialized decision")
	assert.Zero(t, sess.decideCache.size(), "a closed cache admits nothing")

	entered := make(chan struct{})
	go func() { defer close(entered); sess.beginDecisionTurn(ctx)() }()
	select {
	case <-entered:
		t.Fatal("the registry fallback must still exclude a second caller on the anchor")
	case <-time.After(20 * time.Millisecond):
	}
	end()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the turn must advance once released")
	}
	releaseSessionStateForTest(sess)
	assert.Zero(t, rt.decideGates.size())
}

// TestGateCache_ConcurrentMissesFileOneEntry pins the double-insert race: two requests on one
// session can miss the same anchor concurrently and each take its own registry reference. One
// entry must win the slot and the loser's reference must be returned, or the cache holds two
// references (and two LRU lives) for one anchor and the cap stops meaning what it says.
func TestGateCache_ConcurrentMissesFileOneEntry(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	sess := spanningSession(t, rt, "sess-a", "own")

	ctx := taskCtx("task-hot")
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			sess.beginDecisionTurn(ctx)()
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, 1, sess.decideCache.size(), "one anchor, one entry, however many requests raced")
	assert.Equal(t, 2, rt.decideGates.size(), "the pin plus one cached gate")
	releaseSessionStateForTest(sess)
	assert.Zero(t, rt.decideGates.size(), "no surplus reference survives the race")
}

// TestGateCache_AbandonedBoundedWaitReleasesItsUse covers the give-up arm. beginTurn is
// wait-agnostic by construction — the same three-tier lookup serves the unbounded host path and
// the bounded server-initiated one — so the cache has to return a use that took no turn at all,
// or an abandoned wait pins its entry against eviction for the session's life.
//
// It drives beginTurn directly rather than through beginDecisionTurnWithin, because the only
// bounded caller today resolves the session's OWN claims and is therefore served by the pin: the
// cache's bounded arm is reached by construction, not by any wiring that exists. Which is the
// reason to test it — the arm has to already be right when a second bounded caller appears.
func TestGateCache_AbandonedBoundedWaitReleasesItsUse(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{decideGates: newAnchorGates(), taskAnchored: true, pdp: pdp.DenyAllPDP{}}
	sess := spanningSession(t, rt, "sess-a", "own")
	spanned := taskAnchor("task-8")

	// Hold the turn from elsewhere so the bounded waiter cannot get it.
	blocker, ok := rt.decideGates.acquire(spanned.Key(), turnWait{})
	require.True(t, ok)

	end, taken := sess.beginTurn(spanned, turnWait{perHolder: 20 * time.Millisecond, total: 40 * time.Millisecond})
	require.False(t, taken, "the turn is held; a bounded waiter must give up")
	require.Nil(t, end)
	blocker()

	// The entry exists and has no users, so the cap may shed it — which is what a leaked use
	// would prevent, since a retired entry with a phantom user never returns its reference.
	// Filling and warming the cache around it is how that is observable.
	require.Equal(t, 1, sess.decideCache.size())
	visit(sess, 3, fillTasks()[1:]...)
	visit(sess, 1, "task-displacer")
	assert.Equal(t, maxCachedSessionGates, sess.decideCache.size())
	assert.Nil(t, registryGate(rt.decideGates, spanned.Key()),
		"an abandoned wait must return its use, so its entry can be shed and its gate reclaimed")

	releaseSessionStateForTest(sess)
	assert.Zero(t, rt.decideGates.size())
}

// TestGateCache_NonSerializedRouteCachesNothing: a route whose policy needs no decision turn has
// no gate registry at all, so there is nothing to cache and every request must still be served.
func TestGateCache_NonSerializedRouteCachesNothing(t *testing.T) {
	t.Parallel()
	rt := &UpstreamRoute{taskAnchored: true, pdp: pdp.DenyAllPDP{}} // no decideGates
	sess := spanningSession(t, rt, "sess-a", "own")
	require.False(t, rt.serializes())

	for i := range 4 {
		end := sess.beginDecisionTurn(taskCtx(fmt.Sprintf("task-%d", i)))
		require.NotNil(t, end)
		end()
	}
	assert.Zero(t, sess.decideCache.size(), "nothing to cache without a registry to cache from")
	releaseSessionStateForTest(sess)
}

// TestGateCache_AcquireRejectsNilReceiverAndRegistry pins the two no-op guards directly: the
// cache is reached through a session field, and a route may carry no registry at all.
func TestGateCache_AcquireRejectsNilReceiverAndRegistry(t *testing.T) {
	t.Parallel()
	anchor := enforcement.StateAnchor{Kind: enforcement.AnchorKindTask, ID: "task-1"}

	var nilCache *gateCache
	_, _, ok := nilCache.acquire(anchor, newAnchorGates())
	assert.False(t, ok)

	var c gateCache
	_, _, ok = c.acquire(anchor, nil)
	assert.False(t, ok, "a route with no gate registry has nothing to cache")
	assert.Zero(t, c.size())
}
