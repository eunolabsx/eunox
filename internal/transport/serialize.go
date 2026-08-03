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
// A stdio host resolves ONE anchor, and the reason is structural rather than incidental: it
// has a single host connection, so whatever identity that connection carries is the identity
// every request on it carries. StdioProxy therefore resolves its anchor once and pins that
// anchor's queue for the proxy's life — the registry is not on its per-request path at all,
// the same conclusion the HTTP side reaches for a session-anchored route.
//
// The keying is still here, rather than a bare pair of counters, for two reasons. It is what
// makes the primitive correct for a caller that resolves more than one anchor, which is what
// the HTTP transport is. And it puts the premise in ONE place: previously "stdio has one
// session and no per-request token" was held up by a CLI flag check in another package
// (--jwks-uri is refused on a stdio host) while StdioProxyOptions.PDP is an exported seam any
// embedder can hand a JWTPDP. Now the proxy resolves its anchor through the same
// enforcement.ResolveStateAnchor the engine's key builder uses, from the same claims its
// engine decides with — so an embedder that attaches connection-level claims gets a turn on
// the key its state actually lives on. Giving stdio PER-REQUEST tokens would make the pin
// wrong, and the pin is where that change has to be made; it is a seam rather than an
// assumption spread across two packages.

package transport

import (
	"context"
	"sync"
	"time"
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
// decision does impose head-of-line blocking — later tickets ON THAT ANCHOR wait behind it.
// For a host request that is a bounded slowdown, not a deadlock: each waits on its own handler
// goroutine, the decision path is microseconds on the in-memory backend, and the Redis
// backend's client carries its own read/write timeouts, so a stalled backend fails the decision
// closed and advances the turn rather than parking it forever. It is the accepted cost of the
// ordering guarantee (a non-flow/non-sequenceBlock session takes no ticket and keeps full
// parallelism).
//
// The sampling leg is the one waiter for which that reasoning does NOT hold, because it waits
// on the upstream READER goroutine — the only goroutine that can deliver the response the turn
// holder is itself waiting for. That is a cycle rather than a slowdown, so that leg waits
// through beginWithin and fails closed instead; see beginWithin for the full shape.
type decisionSerializer struct {
	// queues holds one FIFO per LIVE anchor, through the shared keyedRegistry
	// (keyed_registry.go): the map, the key, the pin count and the delete-at-zero are that
	// registry's, so a proxy that ever serves many anchors does not accumulate one counter
	// pair per anchor it has seen, and the HTTP gate registry's lifetime cannot drift from
	// this one. What is supplied HERE is the reclaim trigger that genuinely differs — a FIFO
	// with no pin can still have handed out tickets whose waiters are parked on it, so it
	// stays until handed == serving as well.
	//
	// Its mutex guards the ticket counters below too (each queue's cond is built over it), so
	// there is exactly one lock between "which queue is this" and "whose turn is it".
	queues keyedRegistry[*ticketQueue]
}

// ticketQueue is one anchor's FIFO turn.
type ticketQueue struct {
	keyedEntry            // the registry's key + pin count (see decisionSerializer.queues)
	cond       *sync.Cond // over the registry's mutex; broadcasts wake only this anchor's waiters
	handed     uint64     // next ticket to hand out
	serving    uint64     // ticket currently allowed to run its decision
	// abandoned holds the tickets whose waiter gave up (beginWithin). The turn SKIPS them when
	// serving reaches them, which is what makes giving up safe: without it an abandoned ticket
	// is a hole in the FIFO that every later ticket on this anchor waits behind forever, so a
	// bounded wait would have traded a bounded stall for an unbounded one. Nil until the first
	// give-up, which on every deployment is never.
	abandoned map[uint64]struct{}
}

// entry exposes this queue's registry bookkeeping (keyedRegistryValue). The refs it carries
// are the long-lived PINS (see hold); tickets in flight are deliberately not counted there —
// handed != serving already says a ticket is outstanding, and a second counter restating that
// is one more thing to keep in agreement, one that a future path leaving it above zero would
// silently pin the queue with forever.
func (q *ticketQueue) entry() *keyedEntry { return &q.keyedEntry }

// idleQueue is the registry's extra reclaim condition for a FIFO: an unpinned queue may be
// dropped only once every ticket it handed out has been served. A waiter — which by
// definition holds a ticket the serving counter has not reached — therefore always keeps the
// queue it is parked on.
func idleQueue(q *ticketQueue) bool { return q.handed == q.serving }

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
	g := &decisionSerializer{}
	g.queues.init(
		func() *ticketQueue { return &ticketQueue{cond: sync.NewCond(g.queues.locker())} },
		idleQueue,
	)
	return g
}

// take reserves the next ticket in receipt order for anchor. Call it from the single-threaded
// reader BEFORE dispatching the request's handler goroutine, and only for a request that
// will actually reach begin (an enforced method that was admitted, not one already
// rejected), so every reserved ticket is eventually served — an un-begun ticket would
// stall every later one behind it on the same anchor.
func (g *decisionSerializer) take(anchor string) decisionTicket {
	g.queues.lock()
	defer g.queues.unlock()
	return g.queues.entryLocked(anchor).ticket()
}

// takeOn reserves the next ticket on a queue the caller already holds pinned, skipping the
// registry entirely. Same receipt-order contract as take.
//
// q must be non-nil. A nil-tolerant version would return the zero ticket, which begin treats
// as "this request is not serialized" — so a caller that had not pinned a queue would run its
// decisions unserialized, silently, which is the fail-open the turn exists to close. Callers
// that may hold no pin resolve through take instead; see StdioProxy.takeDecisionTicket.
func (g *decisionSerializer) takeOn(q *ticketQueue) decisionTicket {
	g.queues.lock()
	defer g.queues.unlock()
	return q.ticket()
}

// hold returns this anchor's queue pinned, plus the func that unpins it. A caller that keeps
// one across many requests takes tickets straight off the queue (queue.ticket) and never
// touches the registry again.
//
// It is what keeps the map off the per-request path where the anchor cannot vary. A stdio
// host has one connection and no per-request token channel, so every request on it resolves
// the same anchor — and re-resolving it per request meant rendering the key, taking the
// registry mutex, and creating and destroying the same queue on every enforced call, since
// the queue is reclaimed the moment its last ticket is served. That is the cost the HTTP
// side of this seam pays once per session; there is no reason for the transport with a
// SINGLE anchor to pay it per request. The keying stays because it is what makes the
// primitive right for a caller that ever resolves more than one.
func (g *decisionSerializer) hold(anchor string) (queue *ticketQueue, unpin func()) {
	if g == nil {
		return nil, func() {}
	}
	return g.queues.hold(anchor)
}

// ticket reserves the next place in this queue's FIFO. Caller holds the registry's mutex.
func (q *ticketQueue) ticket() decisionTicket {
	t := decisionTicket{queue: q, n: q.handed}
	q.handed++
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
//
// It waits without a bound, which is right for the host path: each host request waits on its
// OWN handler goroutine, so a slow turn holder delays that request and nothing else. The
// server-initiated leg does not have that property and uses beginWithin.
func (g *decisionSerializer) begin(t decisionTicket) (end func()) {
	// With no bound there is no give-up path — the wait loop can only exit on the turn — so ok
	// is invariably true and the end func is never nil. A future second reason to give up would
	// have to make this branch, rather than silently returning a nil release to a deferred call.
	end, _ = g.beginWithin(t, 0)
	return end
}

// beginWithin is begin bounded by d: it reports ok=false when the ticket's turn has not come
// up within d, having ABANDONED the ticket so no later one queues behind it. d <= 0 waits
// forever (what begin does).
//
// The bound exists for one caller — the server-initiated (sampling) leg — and for one hazard,
// which on this transport is a CYCLE rather than a slow turn:
//
//   - handleUpstreamRequest runs INLINE on the upstream reader goroutine, and that goroutine is
//     also the only one that delivers upstream responses to waiting host handlers;
//   - a declassifying host call deliberately holds its turn across the whole upstream round
//     trip (finishDecision does not release it while a clear is pending), because the two
//     phases of the clear are one critical section;
//   - so a sampling request arriving mid-clear parks the reader on a turn that is waiting for
//     a response only that reader can deliver.
//
// That deadlocks until --upstream-timeout fires, and forever when it is 0. The wait is bounded
// here and the caller fails the sampling request CLOSED (samplingTurnDenial), which is exactly
// what the HTTP leg already does with the identical hazard — the two legs now answer "what
// happens when the turn is held by a declassifying call" the same way.
//
// Abandoning is what makes bounding safe. The queue's invariant is handed/serving, so a ticket
// nobody will ever begin is a hole every later ticket waits behind; recording it in abandoned
// lets the turn skip it when serving arrives, which is the difference between a bounded stall
// and an unbounded one.
func (g *decisionSerializer) beginWithin(t decisionTicket, d time.Duration) (end func(), ok bool) {
	q := t.queue
	if q == nil {
		return func() {}, true
	}
	// sync.Cond has no bounded Wait, so the bound is a timer that broadcasts. gaveUp is this
	// call's own variable, written and read under g.mu; a broadcast wakes every waiter on the
	// anchor and each re-checks its own two conditions, which is the ordinary spurious-wakeup
	// discipline the loop already had.
	gaveUp := false
	if d > 0 {
		timer := time.AfterFunc(d, func() {
			g.queues.lock()
			defer g.queues.unlock()
			gaveUp = true
			q.cond.Broadcast()
		})
		defer timer.Stop()
	}
	g.queues.lock()
	for q.serving != t.n && !gaveUp {
		q.cond.Wait()
	}
	if q.serving != t.n {
		// The turn is checked FIRST on the way out: a timer that fires in the same instant the
		// turn comes up loses, so a caller is never refused a turn it could have had.
		q.abandonLocked(t.n)
		g.queues.unlock()
		return nil, false
	}
	g.queues.unlock()
	// sync.OnceFunc guards the turn-advance: the Decide* handler ends the critical section
	// right after its decision (before the forward), and the serve loop defers the same end
	// as a backstop for a path that returns before the decision (malformed params), so the
	// turn advances exactly once either way.
	return sync.OnceFunc(func() {
		g.queues.lock()
		q.advanceLocked()
		// The turn moving can make this queue reclaimable without any reference changing —
		// once every ticket it handed out has been served (and nobody has pinned it), nothing
		// is queued on it and nothing can be: a later take under the same anchor builds a
		// fresh queue, which is correct precisely because no waiter holds the old one.
		g.queues.reapLocked(q)
		q.cond.Broadcast()
		g.queues.unlock()
	}), true
}

// abandonLocked records that ticket n will never be begun, so advanceLocked skips it. Caller
// holds the registry's mutex.
//
// Only a ticket that has NOT come up can be abandoned (beginWithin checks the turn first), so
// n is always strictly ahead of serving and the entry is always consumed by a later advance:
// every ticket before it is outstanding, and each of those either ends or abandons in turn.
func (q *ticketQueue) abandonLocked(n uint64) {
	if q.abandoned == nil {
		q.abandoned = map[uint64]struct{}{}
	}
	q.abandoned[n] = struct{}{}
}

// advanceLocked moves the turn to the next ticket that still has a waiter, skipping any that
// were abandoned. Caller holds the registry's mutex.
//
// Skipping is a loop rather than a single step because abandonments can be consecutive (a
// wedged reader that gives up twice), and one un-skipped hole stalls the anchor for good.
func (q *ticketQueue) advanceLocked() {
	q.serving++
	for {
		if _, skipped := q.abandoned[q.serving]; !skipped {
			return
		}
		delete(q.abandoned, q.serving)
		q.serving++
	}
}

// size reports how many anchor queues are live. Test-only, for the same reason the HTTP
// registry exposes one: the drop-at-zero is what keeps a long-lived proxy from accumulating
// an entry per anchor it has ever served, and that is invisible from the outside.
func (g *decisionSerializer) size() int { return g.queues.size() }
