// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The decision turn, keyed on the state ANCHOR (the validated task under task anchoring, else
// the session) rather than on the session, so two sessions sharing a task share one turn
// instead of racing each other's flow-label/antecedent/budget state.
//
// In-process only: two eunox instances on one Redis backend still hold independent turns for
// the same task (see docs/threat-model-mcp.md); the decision-time label intersection bounds
// the damage either way.

package transport

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// serializes reports whether this route decides under a turn. Reads the gate registry's
// presence rather than a parallel bool so the two states cannot disagree.
func (r *UpstreamRoute) serializes() bool { return r != nil && r.decideGates != nil }

// decisionAnchor is the anchor a request's decision serializes on: the validated task when the
// route anchors state on the task and the caller presented one, else the session.
//
// Resolves through enforcement.ResolveStateAnchor — the same function the engine's own key
// builder uses — so the turn and the state key cannot silently come to disagree about which
// anchor this is. Returns the resolved StateAnchor (not its rendered key) so a session caching
// a gate can compare resolutions without rendering one.
//
// claims must be VALIDATED: resolving from an unverified token would let a caller choose which
// turn it takes. The session fallback matches the engine's: no token, or a token with no task
// id, anchors on the session.
func (r *UpstreamRoute) decisionAnchor(sessionID string, claims *pdp.JWTClaims) enforcement.StateAnchor {
	return resolveDecisionAnchor(r != nil && r.taskAnchored, claims, sessionID)
}

// resolveDecisionAnchor is the one place a transport turns its anchoring setting, a request's
// claims, and a session id into the turn's anchor — both transports share it so the fallback
// logic can't diverge from the engine's own key builder.
func resolveDecisionAnchor(taskAnchored bool, claims *pdp.JWTClaims, sessionID string) enforcement.StateAnchor {
	id, hasTask := "", false
	if taskAnchored {
		id, hasTask = pdp.TaskAnchor(claims)
	}
	return enforcement.ResolveStateAnchor(taskAnchored, hasTask, id, sessionID)
}

// decisionAnchorFromContext is decisionAnchor for the host request path, whose validated
// claims ride the request context (attached by handleMCP's pre-dispatch token validation).
func (r *UpstreamRoute) decisionAnchorFromContext(ctx context.Context, sessionID string) enforcement.StateAnchor {
	return r.decisionAnchor(sessionID, pdp.JWTClaimsPtr(ctx))
}

// anchorGates hands out one refcounted decision gate per anchor key, so an idle anchor holds
// no memory on a long-lived gateway route serving an unbounded number of sessions.
//
// The map/key/refcount machinery is the shared keyedRegistry (keyed_registry.go); this type is
// only the TURN itself. Its reclaim trigger is the plain one (no holders left); stdio's FIFO,
// which must also outlive the tickets it handed out, supplies its own.
type anchorGates struct {
	reg keyedRegistry[*anchorGate]
}

// anchorGate is one anchor's turn: a one-slot channel rather than sync.Mutex because the
// server-initiated leg must be able to GIVE UP on a bounded wait (see turnWait), which a mutex
// cannot offer. The embedded keyedEntry lets a holder keep the gate across many turns without
// a map lookup; the turn channel itself is guarded by nothing — a send/receive IS the sync.
type anchorGate struct {
	keyedEntry
	turn chan struct{}
	// handoffs counts turns TAKEN, so a bounded waiter can tell "the holder is stuck" from "the
	// queue is moving" (its window bounds one HOLDER). Atomic, not mutex-guarded, since the
	// turn channel itself is guarded by nothing.
	handoffs atomic.Uint64
}

// entry exposes this gate's registry bookkeeping (keyedRegistryValue).
func (a *anchorGate) entry() *keyedEntry { return &a.keyedEntry }

// newAnchorGates builds an empty registry, one per route: a task id shared by two routes
// addresses different state and must not share a turn.
func newAnchorGates() *anchorGates {
	g := &anchorGates{}
	g.reg.init(func() *anchorGate { return &anchorGate{turn: make(chan struct{}, 1)} }, nil)
	return g
}

// hold returns this anchor's gate with a reference taken, plus the func that drops it, so a
// caller may keep one gate across many turns (see keyedRegistry.hold). A nil registry yields a
// nil gate and a no-op drop, so a non-serialized route needs no branch.
func (g *anchorGates) hold(key string) (gate *anchorGate, drop func()) {
	if g == nil {
		return nil, func() {}
	}
	return g.reg.hold(key)
}

// acquire takes the turn for key under w's give-up rule, holding a registry reference only for
// the turn's length so the map doesn't grow one entry per anchor ever served. The registry
// lock covers only the map operation, never the turn itself. A nil registry is a no-op.
func (g *anchorGates) acquire(key string, w turnWait) (end func(), ok bool) {
	if g == nil {
		return func() {}, true
	}
	// Referenced BEFORE the (possibly blocking) take, so the gate this caller is queued on
	// cannot be reclaimed and replaced while it waits.
	gate, drop := g.hold(key)
	release, ok := gate.take(w)
	if !ok {
		// No turn was taken, so nothing is released — only this caller's reference is dropped,
		// which is what keeps an abandoned wait from pinning the gate.
		drop()
		return nil, false
	}
	// Composed rather than wrapped in a sync.OnceFunc: both halves are already idempotent.
	return func() { release(); drop() }, true
}

// take waits for this gate's turn under w's give-up rule and returns the idempotent release.
//
// The turn is re-checked on the give-up arm: Go's select resolves a free-turn-vs-expired-timer
// race uniformly, so without the recheck a caller could be refused a turn that was in fact
// available at that instant. The window is per HOLDER (see turnWait): an expiry that finds the
// handoff count unchanged since it started means the holder is stuck, not that the queue moved.
func (a *anchorGate) take(w turnWait) (end func(), ok bool) {
	if a == nil {
		return func() {}, true
	}
	if !w.bounded() {
		a.turn <- struct{}{}
		return a.held(), true
	}
	deadline := time.Now().Add(w.total)
	timer := time.NewTimer(w.window(deadline))
	defer timer.Stop()
	for {
		// Read BEFORE the wait, so a handoff during the window is what the comparison sees.
		holder := a.handoffs.Load()
		select {
		case a.turn <- struct{}{}:
			return a.held(), true
		case <-timer.C:
			// The turn is checked FIRST on the way out: a timer that fires in the same instant
			// the turn comes up loses, so a caller is never refused a turn it could have had.
			select {
			case a.turn <- struct{}{}:
				return a.held(), true
			default:
			}
			// The window is clamped to what is left of the ceiling, so this arm firing with no
			// handoff behind it means EITHER the holder is stuck or the ceiling has arrived.
			rest := w.window(deadline)
			if a.handoffs.Load() == holder || rest <= 0 {
				return nil, false
			}
			timer.Reset(rest)
		}
	}
}

// held records that this caller now holds the turn and returns the idempotent release. Bumped
// on ACQUIRE (not release) so a waiter whose window opened while the turn was free still
// observes a handoff that happened within it.
func (a *anchorGate) held() func() {
	a.handoffs.Add(1)
	return sync.OnceFunc(func() { <-a.turn })
}

// size reports how many gates are live. Test-only visibility into the refcounting that keeps a
// long-lived gateway from accumulating one entry per session it has ever served.
func (g *anchorGates) size() int { return g.reg.size() }
