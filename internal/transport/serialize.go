// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Decision serialization. A
// flow-label source's write and a later sink's read happen in two independent
// requests, which the transports otherwise dispatch on concurrent goroutines; without
// ordering, a client that pipelines a tainting read and an egress on one session can let
// the sink read before the source's label commits and slip the taint (the demo's 17/20
// nondeterminism). Serializing the DECISION phase — the PDP decision and its
// state write, NOT the upstream forward — closes that race: a source received before an
// egress commits its label first. The forward stays concurrent, so only the microsecond
// decision path serializes, not the slow upstream round-trip.
//
// The unit of serialization is the state ANCHOR, not the connection: under
// WithTaskAnchoredState two sessions share one key, and a turn that does not span it is not
// serializing the state it is there to order. HTTP takes its turn from the route's
// anchor-keyed gate registry (anchor_gate.go) — it has no serial reader (net/http runs a
// goroutine per POST), so mutual exclusion in arrival-at-the-lock order is the best a
// concurrent-POST transport can do, and sufficient for the realistic pattern where the egress
// follows the read's response.
//
// stdio uses the FIFO decisionSerializer below instead, and its turn is per-PROXY, which for
// stdio is exactly the anchor: one host connection, one session, and no per-request token, so
// every request on it anchors on that session (task anchoring falls back to the session for a
// caller with no token). Being a single serial reader, it can do better than mutual exclusion
// — the reader hands out a ticket per enforced request AS IT ARRIVES and each handler waits
// its ticket, so the order is proxy-RECEIPT order rather than scheduler order.

package transport

import (
	"context"
	"sync"
)

// decisionEndKey carries the decision-turn release func through the stdio
// handler context. The single-threaded reader reserves the ticket and begins the turn,
// then threads the resulting end func here so handleHostRequest — whose signature the
// many direct test callers depend on — can attach it to dispatchParams without a new
// parameter. (HTTP sets dispatchParams.endDecision directly at its single call site.)
type decisionEndKey struct{}

// withDecisionEnd threads the decision-lock release func for a serialized enforced
// request. Absent for a non-serialized request, where decisionEndFromContext returns nil.
func withDecisionEnd(ctx context.Context, end func()) context.Context {
	return context.WithValue(ctx, decisionEndKey{}, end)
}

// decisionEndFromContext returns the threaded decision-lock release func, or nil when the
// request is not serialized.
func decisionEndFromContext(ctx context.Context) func() {
	end, _ := ctx.Value(decisionEndKey{}).(func())
	return end
}

// decisionSerializer serializes a session's decision phase in FIFO (proxy-receipt) order. The
// single-threaded stdio reader reserves a monotonically increasing ticket per enforced
// request AS IT ARRIVES (take), and each request's handler goroutine waits for its
// ticket to come up (begin) before running the PDP decision + state write, then advances
// the turn (the returned end). Reserving the ticket in the reader — not in the racing
// handler goroutine — is what makes the order RECEIPT order rather than
// scheduler-dependent. The gate is leaf-level (no other lock is taken under it) and never
// held across the upstream forward, so it cannot deadlock with the upstream call or the
// audit drainer.
//
// Liveness: because the turn is held across the decision's flow-store round-trip, one slow
// decision does impose head-of-line blocking — later tickets (and, for the sampling leg,
// the upstream reader that borrows the gate) wait behind it. This is a bounded slowdown,
// not a deadlock: the decision path is microseconds on the in-memory backend, and the
// Redis backend's client carries its own read/write timeouts, so a stalled backend fails
// the decision closed and advances the turn rather than parking it forever. It is the
// accepted cost of the per-session ordering guarantee (a non-flow/non-sequenceBlock
// session takes no ticket and keeps full parallelism).
type decisionSerializer struct {
	mu      sync.Mutex
	cond    *sync.Cond
	handed  uint64 // next ticket to hand out
	serving uint64 // ticket currently allowed to run its decision
}

// newDecisionSerializer builds a ready gate. One per StdioProxy, which is one host
// connection and therefore one session and one anchor; the HTTP transport uses the route's
// anchor-keyed registry instead, because there a turn can have to span two sessions.
func newDecisionSerializer() *decisionSerializer {
	g := &decisionSerializer{}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// take reserves the next ticket in receipt order. Call it from the single-threaded
// reader BEFORE dispatching the request's handler goroutine, and only for a request that
// will actually reach begin (an enforced method that was admitted, not one already
// rejected), so every reserved ticket is eventually served — an un-begun ticket would
// stall every later one behind it.
func (g *decisionSerializer) take() uint64 {
	g.mu.Lock()
	t := g.handed
	g.handed++
	g.mu.Unlock()
	return t
}

// begin blocks until ticket t is the one being served, then returns the end func that
// advances the turn to t+1. end is idempotent (sync.Once), so a handler that releases
// early (right after its decision, before the forward) and a deferred backstop end (for
// a path that returns before the decision, e.g. malformed params) together call it
// exactly once — the turn advances on the first, the second is a no-op.
func (g *decisionSerializer) begin(t uint64) (end func()) {
	g.mu.Lock()
	for g.serving != t {
		g.cond.Wait()
	}
	g.mu.Unlock()
	// sync.OnceFunc guards the turn-advance: the Decide* handler ends the critical section
	// right after its decision (before the forward), and the serve loop defers the same end
	// as a backstop for a path that returns before the decision (malformed params), so the
	// turn advances exactly once either way.
	return sync.OnceFunc(func() {
		g.mu.Lock()
		g.serving++
		g.cond.Broadcast()
		g.mu.Unlock()
	})
}
