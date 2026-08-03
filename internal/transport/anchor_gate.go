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

	"github.com/eunolabs/eunox/internal/pdp"
)

// anchorKindSession and anchorKindTask keep the two kinds of key disjoint, so a session named
// X and a task named X never share a turn. The separator is a NUL, which neither a session id
// nor a task claim can contain.
const (
	anchorKindSession = "session\x00"
	anchorKindTask    = "task\x00"
)

// serializes reports whether this route runs its decisions under a turn — i.e. whether its
// policy is flow- or sequenceBlock-relevant. It reads the gate registry's presence rather
// than a parallel bool, so "serialized" and "has somewhere to serialize on" cannot disagree.
func (r *UpstreamRoute) serializes() bool { return r != nil && r.decideGates != nil }

// decisionAnchor is the key this route serializes a request's decision on: the validated task
// when the route anchors state on the task and the caller presented one, the session
// otherwise. It mirrors the engine's own anchor resolution (see pdp.TaskAnchor, which reads
// the same claim through the same resolver the key builder uses), because a turn taken on a
// key the state does not live on is not serialization at all.
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
func (r *UpstreamRoute) decisionAnchor(sessionID string, claims *pdp.JWTClaims) string {
	if r != nil && r.taskAnchored {
		if id, ok := pdp.TaskAnchor(claims); ok {
			return anchorKindTask + id
		}
	}
	return anchorKindSession + sessionID
}

// decisionAnchorFromContext is decisionAnchor for the host request path, whose validated
// claims ride the request context (attached by handleMCP's pre-dispatch token validation).
func (r *UpstreamRoute) decisionAnchorFromContext(ctx context.Context, sessionID string) string {
	return r.decisionAnchor(sessionID, pdp.JWTClaimsPtr(ctx))
}

// anchorGates hands out one decision gate per anchor key, refcounted so an idle anchor holds
// no memory. A gateway route serves an unbounded number of sessions over its lifetime, and a
// map that only ever grew would be a slow leak keyed by session id.
type anchorGates struct {
	mu    sync.Mutex
	gates map[string]*anchorGate
}

// anchorGate is one anchor's turn: a mutex held across a decision (and, for a declassifying
// call, across its commit), plus the count of holders keeping it in the registry.
type anchorGate struct {
	turn sync.Mutex
	refs int
}

// newAnchorGates builds an empty registry. One per route: routes carry independent policies
// and their own key namespace, so a task id shared by two routes addresses two different sets
// of state and must not share a turn.
func newAnchorGates() *anchorGates {
	return &anchorGates{gates: map[string]*anchorGate{}}
}

// begin blocks until this anchor's turn is free and returns the release func. The release is
// idempotent (sync.OnceFunc), matching decisionSerializer.begin: a handler releases right
// after its decision and defers the same func as a backstop for the paths that return before
// deciding, so the turn advances exactly once.
//
// The registry lock is held only across the map operations, never across the turn itself —
// otherwise one session's decision would block every other anchor's lookup. The gate is
// leaf-level: nothing else is locked under it, so it cannot participate in a cycle, and a
// request only ever holds one.
//
// A nil registry is a no-op returning a no-op release, so a non-serialized route needs no
// branch at the call site.
func (g *anchorGates) begin(key string) (end func()) {
	if g == nil {
		return func() {}
	}
	g.mu.Lock()
	gate := g.gates[key]
	if gate == nil {
		gate = &anchorGate{}
		g.gates[key] = gate
	}
	gate.refs++
	g.mu.Unlock()

	gate.turn.Lock()
	return sync.OnceFunc(func() {
		gate.turn.Unlock()
		g.mu.Lock()
		gate.refs--
		if gate.refs == 0 {
			// Deleted only at zero, and only while holding the registry lock, so a waiter
			// that already took a reference keeps the gate it is queued on. A later begin
			// under the same key creates a fresh gate, which is correct precisely because
			// nobody holds the old one.
			delete(g.gates, key)
		}
		g.mu.Unlock()
	})
}

// size reports how many gates are live. Test-only: the refcounting is what keeps a long-lived
// gateway from accumulating one entry per session it has ever served, and that is invisible
// from the outside otherwise.
func (g *anchorGates) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.gates)
}
