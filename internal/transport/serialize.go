// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Decision serialization. A flow-label source's write and a later sink's read happen in
// two independent requests, dispatched on concurrent goroutines by both transports;
// without ordering, a client pipelining a tainting read and an egress on one session can
// let the sink read before the source's label commits and slip the taint. Serializing only
// the DECISION phase (PDP decision + state write, not the upstream forward) closes that
// race — the forward stays concurrent, so only the microsecond decision path serializes.
//
// The unit of serialization is the state ANCHOR, not the connection: under
// WithTaskAnchoredState two sessions share one key, so the turn must span it too. HTTP
// takes its turn from the route's anchor-keyed gate registry (anchor_gate.go) — with no
// serial reader (net/http runs a goroutine per POST), mutual exclusion in arrival-at-the-
// lock order is the best a concurrent-POST transport can do.
//
// stdio uses the FIFO decisionSerializer below, also anchor-keyed, and does BETTER than
// mutual exclusion: being a single serial reader, it hands out a ticket per enforced
// request AS IT ARRIVES and each handler waits its ticket, so order is proxy-RECEIPT order
// rather than scheduler order.
//
// A stdio host resolves exactly ONE anchor — structural, not incidental: one host
// connection means whatever identity it carries is every request's identity. StdioProxy
// resolves its anchor once and pins that anchor's queue for the proxy's life; the registry
// is not on its per-request path at all, the conclusion the HTTP side reaches for a
// session-anchored route too.
//
// The keying stays anyway, rather than a bare pair of counters, for two reasons: it makes
// the primitive correct for a caller resolving more than one anchor (HTTP), and it puts the
// "stdio has one anchor" premise in ONE place — the proxy resolves it through the same
// enforcement.ResolveStateAnchor the engine's key builder uses, so an embedder attaching
// connection-level claims gets a turn on the key its state actually lives on.

package transport

import (
	"context"
	"sync"
	"time"
)

// decisionEndKey carries the decision-turn release func through the stdio handler
// context: the single-threaded reader reserves the ticket and begins the turn, then
// threads the end func here so handleHostRequest can attach it to dispatchParams without a
// new parameter. (HTTP sets dispatchParams.endDecision directly at its call site.)
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

// decisionSerializer serializes an ANCHOR's decision phase in FIFO (proxy-receipt) order.
// The single-threaded stdio reader reserves a monotonically increasing ticket per enforced
// request AS IT ARRIVES (take), and each request's handler waits for its ticket to come up
// (begin) before running the PDP decision + state write, then advances the turn (the
// returned end). Reserving the ticket in the reader — not the racing handler goroutine —
// is what makes the order RECEIPT order rather than scheduler-dependent. The gate is
// leaf-level and never held across the upstream forward, so it cannot deadlock with the
// upstream call or the audit drainer.
//
// One ticket QUEUE per anchor, for the same reason the HTTP registry has one gate per
// anchor: two anchors share no state and must not queue behind each other.
//
// Liveness: because the turn is held across the decision's flow-store round-trip, one slow
// decision imposes head-of-line blocking on later tickets on that anchor. Bounded, not a
// deadlock: the decision path is microseconds on the in-memory backend, and the Redis
// backend carries its own timeouts, so a stalled backend fails closed and advances the
// turn rather than parking it forever. Accepted cost of the ordering guarantee.
//
// The sampling leg is the one waiter where that reasoning does NOT hold, because it waits
// on the upstream READER goroutine — the only one that can deliver the response the turn
// holder is itself waiting for. That's a cycle rather than a slowdown, so it waits through
// beginWithin and fails closed instead; see beginWithin for the full shape.
type decisionSerializer struct {
	// queues holds one FIFO per LIVE anchor, through the shared keyedRegistry
	// (keyed_registry.go): the map, key, pin count and delete-at-zero are that
	// registry's. Supplied HERE is the reclaim trigger that genuinely differs — a FIFO
	// with no pin can still have handed out tickets whose waiters are parked on it, so
	// it stays until handed == serving too.
	//
	// Its mutex also guards the ticket counters below (each queue's cond is built over
	// it), so there's exactly one lock between "which queue" and "whose turn".
	queues keyedRegistry[*ticketQueue]
}

// ticketQueue is one anchor's FIFO turn.
type ticketQueue struct {
	keyedEntry            // the registry's key + pin count (see decisionSerializer.queues)
	cond       *sync.Cond // over the registry's mutex; broadcasts wake only this anchor's waiters
	handed     uint64     // next ticket to hand out
	serving    uint64     // ticket currently allowed to run its decision
	// abandoned holds tickets whose waiter gave up (beginWithin). The turn SKIPS them
	// when serving reaches them — without it an abandoned ticket is a hole every later
	// ticket on this anchor waits behind forever, trading a bounded stall for an
	// unbounded one. Nil until the first give-up, which on every deployment is never.
	abandoned map[uint64]struct{}
}

// entry exposes this queue's registry bookkeeping. Tickets in flight are deliberately not
// counted there — handed != serving already says a ticket is outstanding, and a second
// counter restating that is one more thing to keep in agreement.
func (q *ticketQueue) entry() *keyedEntry { return &q.keyedEntry }

// idleQueue is the registry's extra reclaim condition for a FIFO: an unpinned queue may be
// dropped only once every ticket it handed out has been served.
func idleQueue(q *ticketQueue) bool { return q.handed == q.serving }

// decisionTicket is a reserved place in one anchor's queue. Its zero value is the
// "not serialized" ticket, which begin treats as a no-op.
type decisionTicket struct {
	queue *ticketQueue
	n     uint64
}

// newDecisionSerializer builds a ready gate. One per StdioProxy (one host connection); the
// anchors within it are keyed so a future per-request token channel could order each
// anchor's decisions independently.
func newDecisionSerializer() *decisionSerializer {
	g := &decisionSerializer{}
	g.queues.init(
		func() *ticketQueue { return &ticketQueue{cond: sync.NewCond(g.queues.locker())} },
		idleQueue,
	)
	return g
}

// take reserves the next ticket in receipt order for anchor. Call it from the
// single-threaded reader BEFORE dispatching the request's handler goroutine, and only for
// a request that will actually reach begin (an admitted enforced method), so every
// reserved ticket is eventually served — an un-begun ticket stalls every later one behind
// it on the same anchor.
func (g *decisionSerializer) take(anchor string) decisionTicket {
	g.queues.lock()
	defer g.queues.unlock()
	return g.queues.entryLocked(anchor).ticket()
}

// takeOn reserves the next ticket on a queue the caller already holds pinned, skipping the
// registry entirely. Same receipt-order contract as take.
//
// q must be non-nil: a nil-tolerant version would silently run every later request on this
// anchor unserialized, the fail-open the turn exists to close. Callers that may hold no
// pin resolve through take instead; see StdioProxy.takeDecisionTicket.
func (g *decisionSerializer) takeOn(q *ticketQueue) decisionTicket {
	g.queues.lock()
	defer g.queues.unlock()
	return q.ticket()
}

// hold returns this anchor's queue pinned, plus the func that unpins it. A caller that
// keeps one across many requests takes tickets straight off the queue and never touches
// the registry again.
//
// It's what keeps the map off the per-request path where the anchor cannot vary: a stdio
// host has one connection and resolves the same anchor every request, so re-resolving it
// per request would render the key, take the registry mutex, and create/destroy the same
// queue on every enforced call. The keying stays because it's what makes the primitive
// right for a caller that ever resolves more than one anchor.
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
// func that advances that anchor's turn. end is idempotent (sync.Once): a handler that
// releases early (right after its decision, before the forward) and a deferred backstop
// end (for a path returning before the decision) together call it exactly once.
//
// A zero ticket (never serialized) returns a no-op end, so a caller needs no branch.
//
// It waits without a bound, which is right for the host path: each host request waits on
// its OWN handler goroutine, so a slow turn holder delays only that request. The
// server-initiated leg does not have that property and uses beginWithin.
func (g *decisionSerializer) begin(t decisionTicket) (end func()) {
	// With no bound there is no give-up path, so ok is invariably true and end is never
	// nil. A future second reason to give up would have to make this branch explicit.
	end, _ = g.beginWithin(t, turnWait{})
	return end
}

// turnWait is a bounded waiter's give-up rule, in TWO parts, because the two answer
// different questions and collapsing them served neither once server-initiated requests
// stopped serializing.
//
// perHolder bounds ONE turn HOLDER: a waiter gives up when the request currently holding
// the turn has held it that long without handing off. It does NOT bound the waiter's own
// elapsed wait — a waiter behind a moving queue is waiting on real work like the unbounded
// host path, while one behind a stuck holder is waiting on the hazard the bound exists
// for. (Previously the window started at ARRIVAL: inline handlers got a fresh window for
// free, but once concurrent, N waiters starting one window together all expired at the
// same instant, refusing N requests for one slow holder.)
//
// total is the absolute ceiling, keeping "the queue is moving" from meaning "forever": a
// waiter holds one of the server-request pool's slots, so a steady stream of sub-perHolder
// holders would otherwise park a slot indefinitely.
//
// A zero perHolder is the unbounded wait (what begin does); total is read only when
// perHolder is set.
type turnWait struct {
	perHolder time.Duration
	total     time.Duration
}

// bounded reports whether this waiter gives up at all.
func (w turnWait) bounded() bool { return w.perHolder > 0 }

// window is how long to wait before re-examining: one holder's window, or whatever is
// left of the ceiling when that's less. Without the clamp the ceiling is only evaluated at
// a perHolder boundary, so the real bound silently drifts past total for any pair that
// doesn't divide evenly. A non-positive result means the ceiling has passed.
func (w turnWait) window(deadline time.Time) time.Duration {
	rest := time.Until(deadline)
	if rest < w.perHolder {
		return rest
	}
	return w.perHolder
}

// beginWithin is begin bounded by w: it reports ok=false when the ticket's turn has not
// come up under w's rule, having ABANDONED the ticket so no later one queues behind it. An
// unbounded w waits forever (what begin does).
//
// The bound exists for one caller, the server-initiated (sampling) leg, and began as a
// bound on a WEDGE: that leg used to run inline on the upstream reader — the only
// goroutine that delivers upstream responses — while a declassifying host call holds its
// turn across the whole upstream round trip, so a sampling request arriving mid-clear
// parked the reader on a turn whose holder was waiting for a response only that reader
// could deliver. That wedge is gone now that the leg runs on its own goroutine
// (serverRequestPool).
//
// What's left is an UNBOUNDED WAIT — a different hazard, which is why the rule is
// per-holder rather than per-arrival: without a bound the wait is limited only by
// --upstream-timeout, which may be 0 (never), while the waiter holds a pool slot the
// whole time. See turnWait.
//
// Abandoning is what makes bounding safe: recording a given-up ticket lets the turn skip
// it when serving arrives, the difference between a bounded stall and an unbounded one.
func (g *decisionSerializer) beginWithin(t decisionTicket, w turnWait) (end func(), ok bool) {
	q := t.queue
	if q == nil {
		return func() {}, true
	}
	// sync.Cond has no bounded Wait, so the bound is a timer that broadcasts. expired is
	// this call's own variable, written and read under g.mu; a broadcast wakes every
	// waiter on the anchor and each re-checks its own conditions.
	expired := false
	var timer *time.Timer
	var deadline time.Time
	if w.bounded() {
		deadline = time.Now().Add(w.total)
		timer = time.AfterFunc(w.window(deadline), func() {
			g.queues.lock()
			defer g.queues.unlock()
			expired = true
			q.cond.Broadcast()
		})
		defer timer.Stop()
	}
	g.queues.lock()
	// The ticket holding the turn when this window opened. A change means the queue
	// handed off while we waited — progress, not the stall the bound is for.
	holder := q.serving
	for q.serving != t.n {
		if expired {
			if q.serving == holder {
				break
			}
			// A fresh window for the new holder: this waiter isn't stalled, it's queued
			// behind completing work. window() clamps to what's left of the ceiling, so a
			// moving queue expires AT total rather than at the first perHolder multiple past it.
			rest := w.window(deadline)
			if rest <= 0 {
				break
			}
			holder = q.serving
			expired = false
			timer.Reset(rest)
			continue
		}
		q.cond.Wait()
	}
	if q.serving != t.n {
		// The turn is checked FIRST on the way out (the loop condition): a timer firing
		// the same instant the turn comes up loses, so a caller is never refused a turn
		// it could have had.
		q.abandonLocked(t.n)
		g.queues.unlock()
		return nil, false
	}
	g.queues.unlock()
	// sync.OnceFunc guards the turn-advance: the Decide* handler ends the critical
	// section right after its decision, and the serve loop defers the same end as a
	// backstop for a path returning before the decision, so it advances exactly once.
	return sync.OnceFunc(func() {
		g.queues.lock()
		q.advanceLocked()
		// The turn moving can make this queue reclaimable without any reference
		// changing — once every ticket it handed out has been served (and nobody has
		// pinned it), a later take under the same anchor builds a fresh queue, correct
		// precisely because no waiter holds the old one.
		g.queues.reapLocked(q)
		q.cond.Broadcast()
		g.queues.unlock()
	}), true
}

// abandonLocked records that ticket n will never be begun, so advanceLocked skips it.
// Caller holds the registry's mutex.
//
// Only a ticket that has NOT come up can be abandoned (beginWithin checks the turn
// first), so n is always ahead of serving and always consumed by a later advance.
func (q *ticketQueue) abandonLocked(n uint64) {
	if q.abandoned == nil {
		q.abandoned = map[uint64]struct{}{}
	}
	q.abandoned[n] = struct{}{}
}

// advanceLocked moves the turn to the next ticket that still has a waiter, skipping any
// that were abandoned. Caller holds the registry's mutex.
//
// A loop rather than a single step because abandonments can be consecutive (a wedged
// reader that gives up twice), and one un-skipped hole stalls the anchor for good.
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

// size reports how many anchor queues are live. Test-only: the drop-at-zero behavior is
// what keeps a long-lived proxy from accumulating an entry per anchor it has ever served,
// and that is invisible from the outside.
func (g *decisionSerializer) size() int { return g.queues.size() }
