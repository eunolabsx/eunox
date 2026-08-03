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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		key := anchorKindSession + string(rune('a'+i%26)) + string(rune('0'+i/26))
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
		assert.Equal(t, anchorKindSession+"sess-a", a)
	})

	t.Run("no token at all falls back to the session", func(t *testing.T) {
		assert.Equal(t, anchorKindSession+"sess-a", anchored.decisionAnchor("sess-a", nil))
	})

	t.Run("a route that does not anchor on the task ignores the claim", func(t *testing.T) {
		assert.Equal(t, anchorKindSession+"sess-a", sessionOnly.decisionAnchor("sess-a", taskClaims),
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
		assert.Equal(t, anchorKindTask+"task-42", anchored.decisionAnchorFromContext(ctx, "sess-a"))
		assert.Equal(t, anchorKindSession+"sess-a", anchored.decisionAnchorFromContext(context.Background(), "sess-a"))
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
