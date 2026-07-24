// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Per-session decision serialization (docs/flow-label-hardening.md piece B). A
// flow-label source's write and a later sink's read happen in two independent
// requests, which the transports otherwise dispatch on concurrent goroutines; without
// ordering, a client that pipelines a tainting read and an egress on one session can let
// the sink read before the source's label commits and slip the taint (the demo's 17/20
// nondeterminism). Serializing the per-session DECISION phase — the PDP decision and its
// state write, NOT the upstream forward — closes that race: a source received before an
// egress commits its label first. The forward stays concurrent, so only the microsecond
// decision path serializes, not the slow upstream round-trip.
//
// stdio (a single serial reader) uses the FIFO decisionSerializer below so the order is
// proxy-RECEIPT order: the reader hands out a ticket per enforced request as it arrives,
// and each handler waits its ticket before deciding. HTTP has no serial reader (net/http
// runs a goroutine per POST), so a per-session mutex on the httpSession gives mutual
// exclusion in arrival-at-the-lock order — the best a concurrent-POST transport can do,
// and sufficient for the realistic pattern where the egress follows the read's response.

package transport

import (
	"context"
	"sync"
)

// decisionEndKey carries the per-session decision-lock release func through the stdio
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
// scheduler-dependent. The gate is leaf-level and never held across the upstream
// forward, so it cannot deadlock with the upstream call or the audit drainer.
type decisionSerializer struct {
	mu      sync.Mutex
	cond    *sync.Cond
	handed  uint64 // next ticket to hand out
	serving uint64 // ticket currently allowed to run its decision
}

// newDecisionSerializer builds a ready gate. A gate is created per session (per StdioProxy;
// per httpSession would use the mutex path instead), so its tickets never cross sessions.
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
