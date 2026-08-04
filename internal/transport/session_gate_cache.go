// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The decision gates a session caches for anchors OTHER than its own.
//
// A session pins the gate for the anchor it resolved at registration and reads it
// lock-free (httpSession.decideAnchor/decideGate). That pin serves every session-anchored
// request, and every task-anchored session that stays on one task — every session that
// does not SPAN. What it doesn't serve is the shape task anchoring exists for: an agent
// runtime running task-1 … task-n over one long-lived connection. Each such request
// resolves an anchor the pin doesn't match and went back through the route's gate
// registry — a route-wide mutex, a map insert and delete, per enforced call, since the
// registry refcount falls to zero the instant a non-overlapping request finishes. Correct,
// but the whole cost the pin exists to remove, paid every call for the session's life.
//
// Re-pointing the PIN instead is what this deliberately does not do: its three fields are
// written once at registration and read with no lock, so moving them means dropping the
// previous registry reference — the only thing keeping the registry from reclaiming that
// gate and building a fresh one under a request that read the old pointer. Two gates for
// one anchor is not slow, it is unserialized, silently, on the path with no second reader
// to notice.
//
// So the extra anchors get a cache with the synchronization that hazard needs, and the pin
// stays exactly as it was. Three rules make it safe:
//
//   - A cached entry holds its own registry reference for as long as the cache holds it.
//   - Every request taking a turn on a cached gate is COUNTED for the whole turn, so an
//     entry can never lose its reference while a request is queued on its gate.
//   - Shedding therefore never drops a reference in use: an entry with users is RETIRED
//     instead — removed from the map, its reference returned by whichever request leaves
//     last. Ordinary refcount discipline, kept on the SESSION's mutex (uncontended) rather
//     than the route's (contended by every session on the route).
//
// The bound is a memory cap, not a working-set estimate: the anchors are validated task
// claims, so a client minting many must not pin one gate per task for a connection's life.
// The cap sheds the COLDEST entry, and only once the session has stopped cycling through it
// (admitsLocked) — plain LRU is wrong here, measurably: on the workload that reaches the
// cap it sheds, per request, the entry the next request wants, losing every hit and adding
// this file's bookkeeping on top.
//
// It deliberately doesn't reuse keyedRegistry (the map+refcount+delete-at-zero shape the
// two decision-turn primitives share): its key is the RESOLVED anchor (a comparable struct,
// not a rendered string — rendering one per lookup would be an allocation on the path this
// exists to make cheaper), and its count is requests on a value owned by ANOTHER registry,
// not a hold/drop refcount over a value it owns itself — the reclaim it drives is "return
// someone else's reference," which is what retirement means and an `idle` predicate can't
// express.

package transport

import (
	"sync"

	"github.com/eunolabs/eunox/pkg/enforcement"
)

// maxCachedSessionGates caps how many non-pinned anchors one session may hold gates for.
//
// It bounds MEMORY, not the working set: each entry is a map slot plus a small struct and
// the route gate it references, on the order of a kilobyte — without a cap a client
// running a long series of tasks over one connection would pin one gate per task it ever
// touched. Eight covers a session interleaving a handful of live tasks while keeping the
// per-session ceiling small; it's also the unit the admission rule measures staleness in
// (an entry sheds once a full pass of the cache has gone by unused), so the cap and "still
// in rotation" can't drift apart into two constants.
const maxCachedSessionGates = 8

// gateCache holds one session's decision gates for anchors its pin does not cover. Zero
// value ready to use, allocating nothing until a session actually spans — the overwhelming
// majority of sessions.
type gateCache struct {
	// mu guards every field below and every entry's own bookkeeping. It's the session's
	// own lock: the requests contending for it are bounded by that session's reqSem, so
	// it carries none of the route-wide contention this cache exists to avoid.
	mu sync.Mutex
	// entries is keyed on the RESOLVED anchor rather than its rendered key, so a lookup
	// compares the same two-string struct the pin compares and renders nothing. nil
	// until the first insert.
	entries map[enforcement.StateAnchor]*cachedGate
	// tick orders entries by recency of USE: every hit and admission stamps the next
	// value; a refusal advances nothing. A counter rather than a timestamp because the
	// admission rule needs "how many passes ago", not a duration, and a clock read per
	// request would cost more than the map lookup it accompanies.
	tick uint64
	// closed is set at session teardown, stopping the cache admitting anything new — a
	// request racing teardown resolves through the registry instead of taking a
	// reference this session will never drop.
	closed bool
}

// cachedGate is one cached anchor: the route gate, the registry reference the cache holds
// for it, and the count of requests currently on it.
type cachedGate struct {
	gate *anchorGate
	// drop releases the registry reference this entry holds. Idempotent (the registry
	// returns a sync.OnceFunc), since retire-then-close can reach it twice.
	drop func()
	// users is the number of requests that have acquired this entry and not yet
	// released — what makes shedding safe: an entry with users is retired rather than
	// dropped, so a request queued on the gate cannot have it reclaimed beneath it.
	users int
	// used is the tick value of this entry's most recent use, what admitsLocked
	// compares against the current tick.
	used uint64
	// retired marks an entry taken out of the map while still in use; the last user to
	// leave returns the reference. Nothing new can join it — no longer reachable from
	// entries.
	retired bool
}

// acquire returns the cached gate for anchor with a use recorded, plus the idempotent func
// that ends that use. ok is false when the caller must resolve through the route registry
// instead — a non-serializing route, or a session already torn down.
//
// The use is held for the whole turn, not just the lookup: the caller must call release
// only after finishing with the gate (see httpSession.beginTurn, which composes it behind
// the turn's own release). Releasing early would put the entry back in reach of being shed
// while a request is still queued on its gate — the one hazard this file guards against.
//
// reg is the route's gate registry — passed rather than reached for, so this type never
// needs a back-pointer to the session or route.
func (c *gateCache) acquire(anchor enforcement.StateAnchor, reg *anchorGates) (gate *anchorGate, release func(), ok bool) {
	if c == nil || reg == nil {
		return nil, nil, false
	}
	e, admits := c.lookup(anchor)
	if e != nil {
		return e.gate, c.releaser(e), true
	}
	// "Would not admit" is answered by the LOOKUP rather than discovered by the insert:
	// a refused insert has already taken a registry reference it must hand back, paying
	// four route-wide mutex acquisitions where the plain registry path pays two. Both
	// refusal reasons (closed cache, full-and-cycling) are steady states, so that
	// doubling would be a per-request cost.
	if !admits {
		return nil, nil, false
	}
	// Referenced OUTSIDE c.mu: the registry is a lock of its own, and nesting it under
	// the session's would gain nothing on the miss path. Losing a race here just costs
	// one extra reference, dropped below.
	g, drop := reg.hold(anchor.Key())
	if g == nil {
		// Unreachable while a non-nil registry always yields a gate, and a fail-CLOSED
		// backstop rather than a case: anchorGate.take is nil-tolerant (a no-op
		// release), so filing a nil gate here would run every later request on this
		// anchor unserialized while every test still passed.
		drop()
		return nil, nil, false
	}
	e, kept := c.insert(anchor, g, drop)
	if !kept {
		// Either a concurrent request inserted this anchor first (its entry is what we
		// got back) or the cache is closed. Our own reference is surplus either way.
		drop()
	}
	if e == nil {
		return nil, nil, false
	}
	return e.gate, c.releaser(e), true
}

// lookup records a use of anchor's entry and returns it, or nil when not cached. admits
// reports whether the cache would TAKE one — false once closed, and false while full of
// entries still in rotation. Asking here is what lets acquire skip a registry round trip
// it would only hand back.
func (c *gateCache) lookup(anchor enforcement.StateAnchor) (entry *cachedGate, admits bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, false
	}
	e, present := c.entries[anchor]
	if !present {
		return nil, c.admitsLocked()
	}
	c.touchLocked(e)
	return e, true
}

// admitsLocked reports whether a new anchor may be filed: there is room, or the coldest
// entry has gone a full pass of the cache without a use. Caller holds c.mu.
//
// The second clause keeps the cap from THRASHING. Shedding least-recently-used on every
// miss is wrong for the workload that reaches the cap: a session cycling through one more
// live anchor than the cache holds sheds, every request, the entry the next request
// wants — missing every time and paying this file's bookkeeping on top. Measured ~30%
// slower than no cache at all; the rule below is ~45% FASTER, because entries that do fit
// keep hitting (BenchmarkDecisionTurn_SpanThrashing vs BenchmarkDecisionTurn_SpanUncached).
//
// An entry is shed only once the session has stopped cycling through it — a full pass,
// maxCachedSessionGates uses with none of them its own. A session whose live anchors don't
// fit keeps the ones that do and takes the always-correct registry path for the rest,
// instead of losing the cache for all of them.
//
// The tick advances only on a USE (hit or admission), never a refusal, so the comparison
// means "passes of the cache" rather than "requests". A session resolving each anchor
// exactly once fills the cache and freezes: bounded at the cap, paying one map lookup over
// the registry path per request — the honest cost of a workload no cache can help.
func (c *gateCache) admitsLocked() bool {
	if len(c.entries) < maxCachedSessionGates {
		return true
	}
	_, coldest := c.coldestLocked()
	return coldest != nil && c.tick-coldest.used > uint64(maxCachedSessionGates)
}

// coldestLocked returns the least recently used entry and its key, or the zero anchor and
// nil for an empty cache. Caller holds c.mu.
//
// A linear scan rather than an ordered structure: the cap is small enough that a scan is
// cheaper than the bookkeeping any ordering would add to the HIT path, which is the path
// that matters.
func (c *gateCache) coldestLocked() (enforcement.StateAnchor, *cachedGate) {
	var coldestKey enforcement.StateAnchor
	var coldest *cachedGate
	for k, e := range c.entries {
		if coldest == nil || e.used < coldest.used {
			coldestKey, coldest = k, e
		}
	}
	return coldestKey, coldest
}

// insert files anchor's entry, shedding the coldest one when the cap is reached and the
// admission rule allows it, and records a use of whatever entry ends up serving anchor.
// kept reports whether the caller's registry reference was taken over by the cache; when
// false the caller must drop it.
//
// A nil entry with kept=false means the cache would not admit — closed, or full and still
// cycling — and the caller must use the registry.
func (c *gateCache) insert(anchor enforcement.StateAnchor, gate *anchorGate, drop func()) (entry *cachedGate, kept bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, false
	}
	// Re-checked under the lock: two requests on this session can miss concurrently and
	// both reach the registry, each getting its own reference to the SAME gate.
	// Whoever files first wins the slot; the other's reference is surplus — never a
	// second entry, which would double the footprint and give one anchor two recencies.
	if e, present := c.entries[anchor]; present {
		c.touchLocked(e)
		return e, false
	}
	// Re-asked under this lock: acquire asked before releasing it to take the registry
	// reference, and a concurrent request may have filled the last slot since.
	if !c.admitsLocked() {
		return nil, false
	}
	// Shed BEFORE filing, so the entry that just arrived is never its own victim and
	// the map never exceeds the cap even transiently.
	if len(c.entries) >= maxCachedSessionGates {
		if k, coldest := c.coldestLocked(); coldest != nil {
			c.retireLocked(k, coldest)
		}
	}
	if c.entries == nil {
		c.entries = make(map[enforcement.StateAnchor]*cachedGate, maxCachedSessionGates)
	}
	e := &cachedGate{gate: gate, drop: drop}
	c.entries[anchor] = e
	c.touchLocked(e)
	return e, true
}

// touchLocked records a use of e and stamps it as the most recently used. Caller holds c.mu.
func (c *gateCache) touchLocked(e *cachedGate) {
	c.tick++
	e.used = c.tick
	e.users++
}

// retireLocked takes e out of the cache, returning its registry reference if it can.
// Caller holds c.mu. The ONE place an entry leaves, shared by the cap and by teardown,
// since the condition it turns on is the whole safety argument and two copies of it is one
// copy that can be fixed alone.
//
// An entry with no users has its reference released here. One WITH users cannot: a
// request that read its gate is queued on it, and dropping the last reference lets the
// registry reclaim it and build a FRESH gate for the same anchor under a later caller —
// two gates, no mutual exclusion, on the path with no second reader to notice. It's
// retired instead: removed from the map, its reference returned by the last user to leave.
func (c *gateCache) retireLocked(key enforcement.StateAnchor, e *cachedGate) {
	delete(c.entries, key)
	if e.users > 0 {
		e.retired = true
		return
	}
	e.drop()
}

// releaser returns the idempotent func ending one use of e. Idempotent because the
// decision turn's release is: a handler releases right after its decision and defers the
// same func as a backstop, and this rides behind that one.
func (c *gateCache) releaser(e *cachedGate) func() {
	return sync.OnceFunc(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		e.users--
		// The last user of a retired entry is what returns its reference to the
		// registry. A live entry keeps its reference; it's still reachable and serving.
		if e.retired && e.users == 0 {
			e.drop()
		}
	})
}

// close releases every reference this cache holds and stops it admitting anything more.
//
// Called from releaseSessionState, on the one funnel every teardown passes through and
// AFTER the in-flight drains — the same placement and reasons as the pinned gate's own
// drop: a session whose upstream exits on its own never reaches close(), and a reference
// returned while a request is still taking turns on the gate would let the registry
// reclaim it under that request. The drain makes users zero in the ordinary case; an entry
// that somehow still has one is retired rather than dropped, so the bound holds even if a
// handler outlives the drain's budget.
func (c *gateCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for k, e := range c.entries {
		c.retireLocked(k, e)
	}
	c.entries = nil
}

// size reports how many anchors this cache holds. Test-only: the cap and the
// release-on-teardown are what keep a long-lived session from pinning one route gate per
// task it has ever served, invisible from the outside otherwise.
func (c *gateCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
