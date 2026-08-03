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
// stdio uses the FIFO decisionSerializer below, which is anchor-keyed too — one ticket queue
// per anchor — and can do BETTER than mutual exclusion within each: being a single serial
// reader, it hands out a ticket per enforced request AS IT ARRIVES and each handler waits its
// ticket, so the order is proxy-RECEIPT order rather than scheduler order.
//
// Today a stdio host resolves one anchor and one only: it has a single host connection, and
// no path on it attaches a validated token, so every request falls back to the session (task
// anchoring anchors a caller with no token on its session). The keying is therefore not
// carrying weight yet — and that is precisely why it is here rather than assumed. The
// premise "stdio has one session and no per-request token" was enforced by a CLI flag check
// in another package (--jwks-uri is refused on a stdio host) while StdioProxyOptions.PDP is
// an exported seam any embedder can hand a JWTPDP; the first per-request token channel on
// this transport would have made a single FIFO queue silently stop being "the anchor", with
// no seam to reach for and no test that would fail. Resolving the anchor through the same
// enforcement.ResolveStateAnchor the engine's key builder uses means such a channel gets
// correct keying by construction instead.

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

// decisionSerializer serializes an ANCHOR's decision phase in FIFO (proxy-receipt) order. The
// single-threaded stdio reader reserves a monotonically increasing ticket per enforced
// request AS IT ARRIVES (take), and each request's handler goroutine waits for its
// ticket to come up (begin) before running the PDP decision + state write, then advances
// the turn (the returned end). Reserving the ticket in the reader — not in the racing
// handler goroutine — is what makes the order RECEIPT order rather than
// scheduler-dependent. The gate is leaf-level (no other lock is taken under it) and never
// held across the upstream forward, so it cannot deadlock with the upstream call or the
// audit drainer.
//
// One ticket QUEUE per anchor, for the reason the HTTP registry has one gate per anchor: the
// turn has to span the key the accumulated state lives on, and requests on two different
// anchors share no state and must not queue behind each other. A stdio host resolves exactly
// one anchor today (see the file comment), so in practice there is one queue and the behavior
// is what a single queue gave.
//
// Liveness: because the turn is held across the decision's flow-store round-trip, one slow
// decision does impose head-of-line blocking — later tickets ON THAT ANCHOR (and, for the
// sampling leg, the upstream reader that borrows the gate) wait behind it. This is a bounded
// slowdown, not a deadlock: the decision path is microseconds on the in-memory backend, and
// the Redis backend's client carries its own read/write timeouts, so a stalled backend fails
// the decision closed and advances the turn rather than parking it forever. It is the
// accepted cost of the ordering guarantee (a non-flow/non-sequenceBlock session takes no
// ticket and keeps full parallelism).
type decisionSerializer struct {
	mu sync.Mutex
	// queues holds one FIFO per LIVE anchor. An entry is dropped once every ticket it handed
	// out has been served, so a proxy that ever serves many anchors does not accumulate one
	// counter pair per anchor it has seen — the same reason the HTTP gate registry refcounts.
	queues map[string]*ticketQueue
}

// ticketQueue is one anchor's FIFO turn.
type ticketQueue struct {
	anchor  string
	cond    *sync.Cond // over the serializer's mu; broadcasts wake only this anchor's waiters
	handed  uint64     // next ticket to hand out
	serving uint64     // ticket currently allowed to run its decision
	live    int        // tickets handed out whose turn has not yet been advanced
}

// decisionTicket is a reserved place in one anchor's queue. Its zero value is the
// "not serialized" ticket, which begin treats as a no-op.
type decisionTicket struct {
	queue *ticketQueue
	n     uint64
}

// newDecisionSerializer builds a ready gate. One per StdioProxy, which is one host
// connection; the anchors within it are keyed, so a future per-request token channel on this
// transport orders each anchor's decisions independently rather than funnelling every
// caller through one queue. The HTTP transport uses the route's anchor-keyed gate registry
// instead, because there a turn can have to span two sessions.
func newDecisionSerializer() *decisionSerializer {
	return &decisionSerializer{queues: map[string]*ticketQueue{}}
}

// take reserves the next ticket in receipt order for anchor. Call it from the single-threaded
// reader BEFORE dispatching the request's handler goroutine, and only for a request that
// will actually reach begin (an enforced method that was admitted, not one already
// rejected), so every reserved ticket is eventually served — an un-begun ticket would
// stall every later one behind it on the same anchor.
func (g *decisionSerializer) take(anchor string) decisionTicket {
	g.mu.Lock()
	defer g.mu.Unlock()
	q := g.queues[anchor]
	if q == nil {
		q = &ticketQueue{anchor: anchor, cond: sync.NewCond(&g.mu)}
		g.queues[anchor] = q
	}
	t := decisionTicket{queue: q, n: q.handed}
	q.handed++
	q.live++
	return t
}

// begin blocks until ticket t is the one being served on its anchor, then returns the end
// func that advances that anchor's turn. end is idempotent (sync.Once), so a handler that
// releases early (right after its decision, before the forward) and a deferred backstop end
// (for a path that returns before the decision, e.g. malformed params) together call it
// exactly once — the turn advances on the first, the second is a no-op.
//
// A zero ticket (a request that was never serialized) returns a no-op end, so a caller needs
// no branch of its own.
func (g *decisionSerializer) begin(t decisionTicket) (end func()) {
	q := t.queue
	if q == nil {
		return func() {}
	}
	g.mu.Lock()
	for q.serving != t.n {
		q.cond.Wait()
	}
	g.mu.Unlock()
	// sync.OnceFunc guards the turn-advance: the Decide* handler ends the critical section
	// right after its decision (before the forward), and the serve loop defers the same end
	// as a backstop for a path that returns before the decision (malformed params), so the
	// turn advances exactly once either way.
	return sync.OnceFunc(func() {
		g.mu.Lock()
		q.serving++
		q.live--
		if q.live == 0 {
			// Every ticket this queue handed out has been served, so nothing is queued on it
			// and nothing can be: a later take under the same anchor builds a fresh queue,
			// which is correct precisely because no waiter holds the old one.
			delete(g.queues, q.anchor)
		}
		q.cond.Broadcast()
		g.mu.Unlock()
	})
}

// size reports how many anchor queues are live. Test-only, for the same reason the HTTP
// registry exposes one: the drop-at-zero is what keeps a long-lived proxy from accumulating
// an entry per anchor it has ever served, and that is invisible from the outside.
func (g *decisionSerializer) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.queues)
}
