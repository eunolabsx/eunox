// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The decision turn, keyed on the state ANCHOR rather than on the session.
//
// Serializing a session's decision phase closes the source->sink race within one connection
// (see serialize.go). It is the wrong unit under WithTaskAnchoredState: the accumulated state
// — the flow-label set, the antecedent history, the budgets — is keyed on the validated task
// there, and two sessions can share one task. A per-session gate hands those two sessions
// independent turns, so the serialization does not span the state it is serializing.
//
// This registry hands out ONE gate per anchor instead, so two sessions sharing a task share a
// turn and the turn spans the key the state lives on. Under the default session anchoring the
// key IS the session id, so the behavior is byte-for-byte what a per-session mutex gave — an
// operator who has not enabled task anchoring cannot be affected by this.
//
// SCOPE, stated rather than implied: this is an in-PROCESS gate. Two eunox instances sharing
// one Redis backend still hold independent turns for the same task, so the residual the
// per-session gate had across sessions remains across INSTANCES. Closing that needs a
// distributed lease on the decision path — a store round trip per declassifying call, held
// across an upstream round trip — which is a different trade than this one and is recorded in
// docs/threat-model-mcp.md rather than assumed away here. What bounds the damage in both
// deployments is the decision-time intersection: the labels a clear may remove are resolved
// inside the decision, so a taint acquired after that point cannot be laundered by it.

package transport

import (
	"context"
	"sync"
	"time"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// serializes reports whether this route runs its decisions under a turn — i.e. whether its
// policy is flow- or sequenceBlock-relevant. It reads the gate registry's presence rather
// than a parallel bool, so "serialized" and "has somewhere to serialize on" cannot disagree.
func (r *UpstreamRoute) serializes() bool { return r != nil && r.decideGates != nil }

// decisionAnchor is the anchor this route serializes a request's decision on: the validated
// task when the route anchors state on the task and the caller presented one, the session
// otherwise.
//
// It resolves through enforcement.ResolveStateAnchor — the SAME function the engine's own key
// builder resolves through — rather than re-deriving the fallback here. A turn taken on a key
// the state does not live on is not serialization at all, and two independent readings of
// "which anchor is this" is exactly where the gate and the key come to disagree, silently,
// since nothing in the process ever compares them. The claim lookup likewise goes through
// pdp.TaskAnchor, which reads the same claim through the same resolver the key builder uses,
// so the two agree even about the cases that are NOT a task (a padded claim, a numeric one).
//
// It returns the resolved enforcement.StateAnchor rather than its rendered key, because one
// caller has to COMPARE two resolutions: a session caching a gate must be able to ask whether
// this request resolves the anchor it cached, and a comparable two-string struct answers that
// without rendering anything. Key() is applied where the registry is actually addressed.
//
// claims must be the VALIDATED claims — the transport's HTTP entry point verifies the bearer
// token before dispatch and attaches them to the request context. Resolving this from an
// unverified token would let a caller choose which turn it takes, and therefore choose not to
// share one.
//
// The session fallback is exactly the engine's: a request with no token is anchored on its
// session, and so is one whose token carries no task id (which the engine refuses outright
// under task anchoring — a turn on the session is the right one for a call that is about to
// be denied).
func (r *UpstreamRoute) decisionAnchor(sessionID string, claims *pdp.JWTClaims) enforcement.StateAnchor {
	return resolveDecisionAnchor(r != nil && r.taskAnchored, claims, sessionID)
}

// resolveDecisionAnchor is the one place a transport turns (its anchoring setting, a request's
// validated claims, a session id) into the turn's anchor. Both transports call it — a second
// hand-rolled copy of the fallback branching is the shape this whole seam exists to remove,
// and the engine's key builder resolving through enforcement.ResolveStateAnchor while a
// transport re-derived it is precisely how the turn and the key would come to disagree.
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

// anchorGates hands out one decision gate per anchor key, refcounted so an idle anchor holds
// no memory. A gateway route serves an unbounded number of sessions over its lifetime, and a
// map that only ever grew would be a slow leak keyed by session id.
type anchorGates struct {
	mu    sync.Mutex
	gates map[string]*anchorGate
}

// anchorGate is one anchor's turn, plus the count of holders keeping it in the registry.
//
// The turn is a one-slot channel rather than a sync.Mutex because one caller has to be able to
// GIVE UP: the server-initiated leg waits for it on the session's single upstream-reader
// goroutine, and a mutex offers no bounded acquire. A token in the channel means the turn is
// held; taking the turn is a send, releasing it a receive.
type anchorGate struct {
	turn chan struct{}
	refs int
	// registry and key are what a release needs to drop this gate's reference. They are on the
	// gate so a holder can keep the gate itself for a whole session (see hold) and take turns
	// on it without going back through the map — the registry round trip is what the
	// per-request path pays, and a session-anchored route has nothing to look up.
	registry *anchorGates
	key      string
}

// newAnchorGates builds an empty registry. One per route: routes carry independent policies
// and their own key namespace, so a task id shared by two routes addresses two different sets
// of state and must not share a turn.
func newAnchorGates() *anchorGates {
	return &anchorGates{gates: map[string]*anchorGate{}}
}

// hold returns this anchor's gate with a reference taken, plus the func that drops it. The
// gate stays in the registry until every holder has dropped, so a caller may keep one across
// many turns.
//
// It is the seam that keeps the registry off the per-request path for a route that does not
// anchor on the task. There, a session's anchor is a CONSTANT — the session id — so resolving
// it per request meant a registry mutex, a map lookup, an insert and a delete on every single
// enforced call, plus the garbage each produced: the refcount fell to zero the instant a
// non-overlapping request finished, so the steady state for ordinary sequential traffic was
// create-insert-lookup-delete per call on the path this file's own comment calls the
// microsecond decision path. Worse, that mutex is route-wide, so its contention scaled with
// the route's whole request rate rather than with contending anchors. A session that holds
// its one gate for its lifetime pays all of that once. Task-anchored routes still resolve per
// request, because there the anchor genuinely varies per call and cross-session sharing is
// the entire point.
//
// A nil registry yields a nil gate and a no-op drop, so a non-serialized route needs no branch
// at the call site.
func (g *anchorGates) hold(key string) (gate *anchorGate, drop func()) {
	if g == nil {
		return nil, func() {}
	}
	g.mu.Lock()
	gate = g.gates[key]
	if gate == nil {
		gate = &anchorGate{turn: make(chan struct{}, 1), registry: g, key: key}
		g.gates[key] = gate
	}
	gate.refs++
	g.mu.Unlock()
	return gate, sync.OnceFunc(gate.drop)
}

// drop releases one reference to this gate, deleting it from the registry at zero.
func (a *anchorGate) drop() {
	g := a.registry
	g.mu.Lock()
	a.refs--
	if a.refs == 0 {
		// Deleted only at zero, and only while holding the registry lock, so a waiter that
		// already took a reference keeps the gate it is queued on. A later hold under the same
		// key creates a fresh gate, which is correct precisely because nobody holds the old one.
		delete(g.gates, a.key)
	}
	g.mu.Unlock()
}

// acquire takes the turn for key, giving up if giveUp fires first (nil waits forever). It is
// the per-request path: it holds a reference only for the length of the turn, which is what
// keeps a route's gate map from growing one entry per anchor it has ever served.
//
// The registry lock is held only across the map operations, never across the turn itself —
// otherwise one session's decision would block every other anchor's lookup. The gate is
// leaf-level: nothing else is locked under it, so it cannot participate in a cycle, and a
// request only ever holds one.
//
// A nil registry is a no-op returning a no-op release, so a non-serialized route needs no
// branch at the call site.
func (g *anchorGates) acquire(key string, giveUp <-chan time.Time) (end func(), ok bool) {
	if g == nil {
		return func() {}, true
	}
	// Referenced BEFORE the (possibly blocking) take, so the gate this caller is queued on
	// cannot be reclaimed and replaced while it waits.
	gate, drop := g.hold(key)
	release, ok := gate.take(giveUp)
	if !ok {
		// No turn was taken, so nothing is released — only this caller's reference is dropped,
		// which is what keeps an abandoned wait from pinning the gate.
		drop()
		return nil, false
	}
	// Composed rather than wrapped in a third sync.OnceFunc: both halves are already
	// idempotent, so a guard over them would only allocate a second Once for a property they
	// each carry — on the path this file calls the microsecond decision path.
	return func() { release(); drop() }, true
}

// take waits for this gate's turn and returns the idempotent release, or ok=false when giveUp
// fires first (nil waits forever). It touches no registry state: a caller holding the gate
// across many turns (a session's cached gate) needs the turn and nothing else.
//
// The release is idempotent (sync.OnceFunc), matching decisionSerializer.begin: a handler
// releases right after its decision and defers the same func as a backstop.
func (a *anchorGate) take(giveUp <-chan time.Time) (end func(), ok bool) {
	if a == nil {
		return func() {}, true
	}
	select {
	case a.turn <- struct{}{}:
		return sync.OnceFunc(func() { <-a.turn }), true
	case <-giveUp:
		return nil, false
	}
}

// size reports how many gates are live. Test-only: the refcounting is what keeps a long-lived
// gateway from accumulating one entry per session it has ever served, and that is invisible
// from the outside otherwise.
func (g *anchorGates) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.gates)
}
