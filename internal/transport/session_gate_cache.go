// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The decision gates a session caches for anchors OTHER than its own.
//
// A session pins the gate for the anchor it resolved at registration and reads it lock-free
// (httpSession.decideAnchor/decideGate). That pin serves every request on a session-anchored
// route, and every request on a task-anchored session that stays on one task — which is to say
// every session that does not SPAN. What it does not serve is the shape task anchoring exists
// for: an agent runtime that opens one long-lived connection at task-1 and then runs
// task-2 … task-n over it. Each of those requests resolves an anchor the pin does not match, so
// each one went back through the route's gate registry — a route-wide mutex, a map insert and a
// map delete, per enforced call, since the registry refcount falls to zero the instant a
// non-overlapping request finishes. Correct (the registry is the always-correct path), but it
// is the whole cost the pin exists to remove, paid on every call for the life of the session.
//
// Re-pointing the PIN instead is what this deliberately does not do. Its three fields are
// written once at registration and read with no lock by every concurrent request, and moving
// them means dropping the previous registry reference — the reference is the only thing keeping
// the registry from reclaiming that gate and building a fresh one under a request that read the
// old pointer and has not yet taken its turn. Two gates for one anchor is not slow, it is
// unserialized: the guarantee the turn exists for is gone, silently, on the path that has no
// second reader to notice.
//
// So the extra anchors get a cache with the synchronization that hazard actually needs, and the
// pin stays exactly as it was. The rules that make it safe are three:
//
//   - A cached entry holds its own registry reference, for as long as the cache holds it.
//   - Every request that takes a turn on a cached gate is COUNTED for the whole turn, so an
//     entry can never lose its reference while a request is queued on the gate it names.
//   - Shedding an entry therefore never drops a reference in use: an entry with users is retired
//     instead — removed from the map so nothing new joins it, its reference returned by whichever
//     request leaves last. Which is the ordinary refcount discipline, kept on the SESSION's mutex
//     (uncontended: one session's own requests) rather than on the route's (contended by every
//     session on the route).
//
// The bound is a cap on entries, and it is a memory bound rather than a working-set estimate:
// the anchors are validated task claims, so a legitimate client with many tasks — or one
// authenticated client minting them — must not be able to pin one gate per task for the life of
// a connection. What the cap sheds is the COLDEST entry, and only once the session has stopped
// cycling through it (admitsLocked); a session whose live anchors do not fit keeps the ones that
// do and takes the registry path for the rest. Plain least-recently-used eviction is the obvious
// rule and is wrong here, measurably: on the one workload that reaches the cap it sheds, per
// request, the entry the next request wants, so it loses every hit AND adds this file's
// bookkeeping to the round trip it would have paid anyway.
//
// It deliberately does not reuse keyedRegistry, which is the one home for the map + refcount +
// delete-at-zero shape the two decision-turn primitives share, and the reason is that two of the
// three pieces genuinely differ. Its key is the RESOLVED anchor, a comparable struct, not the
// rendered string key — rendering one per lookup is an allocation on the path this exists to
// make cheaper. And the count here is not a hold/drop refcount over a value the registry owns:
// it counts REQUESTS on a value owned by another registry, so the reclaim it drives is
// "return someone else's reference", which is what retirement below means and what an `idle`
// predicate cannot express. What they share is the discipline, not the code.

package transport

import (
	"sync"

	"github.com/eunolabs/eunox/pkg/enforcement"
)

// maxCachedSessionGates caps how many non-pinned anchors one session may hold gates for.
//
// It bounds MEMORY, not the working set. Each entry is a map slot plus a small struct and the
// route gate it references (a one-slot channel and two counters), so the cap costs a session on
// the order of a kilobyte — and without one, a client running a long series of tasks over a
// single connection would pin one gate per task it ever touched until the connection closed.
// Eight is chosen to cover the shape this cache is for (a session interleaving a handful of
// live tasks) while keeping that per-session ceiling small. It is also the unit the admission
// rule measures staleness in — an entry is shed once a full pass of the cache has gone by
// without a use — so the cap and "still in rotation" cannot drift apart into two constants.
const maxCachedSessionGates = 8

// gateCache holds one session's decision gates for anchors its pin does not cover. Its zero
// value is ready to use and allocates nothing until a session actually spans, which is the
// overwhelming majority of sessions.
type gateCache struct {
	// mu guards every field below AND every entry's own bookkeeping. It is the session's own
	// lock: the requests contending for it are that session's, bounded by its reqSem, so it
	// carries none of the route-wide contention that made the registry round trip worth
	// avoiding in the first place.
	mu sync.Mutex
	// entries is the cache proper, keyed on the RESOLVED anchor rather than on its rendered
	// key, so a lookup compares the same two-string struct the pin compares and renders
	// nothing. nil until the first insert.
	entries map[enforcement.StateAnchor]*cachedGate
	// tick orders entries by recency of USE: every hit and every admission stamps its entry
	// with the next value, and a refusal advances nothing. A counter rather than a timestamp
	// because what the admission rule needs is "how many passes of the cache ago", not a
	// duration — and because a monotonic clock read per request would cost more than the map
	// lookup it accompanies.
	tick uint64
	// closed is set at session teardown. It stops the cache admitting anything new, so a
	// request racing teardown resolves through the registry (always correct) instead of
	// taking a reference this session will never drop.
	closed bool
}

// cachedGate is one cached anchor: the route gate, the registry reference the cache holds for
// it, and the count of requests currently on it.
type cachedGate struct {
	gate *anchorGate
	// drop releases the registry reference this entry holds. Idempotent (the registry returns
	// a sync.OnceFunc), which matters because retire-then-close can reach it twice.
	drop func()
	// users is the number of requests that have acquired this entry and not yet released.
	// It is what makes shedding safe: an entry with users is retired rather than dropped, so a
	// request queued on the gate cannot have that gate reclaimed and replaced beneath it.
	users int
	// used is the tick value of this entry's most recent use — what admitsLocked compares
	// against the current tick to tell an entry still in rotation from a cold one.
	used uint64
	// retired marks an entry taken out of the map (by the cap or by teardown) while still in
	// use. The last user to leave returns the reference. Nothing new can join it: it is no
	// longer reachable from entries.
	retired bool
}

// acquire returns the cached gate for anchor with a use recorded, plus the idempotent func that
// ends that use. ok is false when the caller must resolve through the route registry instead —
// a route that does not serialize at all, or a session already torn down.
//
// The use is held for the whole turn, not just for the lookup: the caller must call release
// only after it has finished with the gate (see httpSession.beginTurn, which composes it behind
// the turn's own release). Releasing early would put the entry back in reach of being shed while
// a request is still queued on its gate, which is the one hazard this file is arranged around.
//
// reg is the route's gate registry — passed rather than reached for, so this type never needs a
// back-pointer to the session or the route.
func (c *gateCache) acquire(anchor enforcement.StateAnchor, reg *anchorGates) (gate *anchorGate, release func(), ok bool) {
	if c == nil || reg == nil {
		return nil, nil, false
	}
	e, admits := c.lookup(anchor)
	if e != nil {
		return e.gate, c.releaser(e), true
	}
	// "Would not admit" is answered by the LOOKUP rather than discovered by the insert, because
	// the two cost differently: a refused insert has already taken a registry reference it must
	// then hand back, so the request pays FOUR acquisitions of the route-wide mutex where the
	// plain registry path pays two. Both refusal reasons — a closed cache, and a full one whose
	// entries are all still in rotation — are steady states rather than one-offs, so that
	// doubling would be what a session in either of them paid per request.
	if !admits {
		return nil, nil, false
	}
	// Referenced OUTSIDE c.mu: the registry is a lock of its own, and taking it under the
	// session's would nest two locks on the miss path for no reason. The cost of losing a race
	// here is one extra reference, dropped below.
	g, drop := reg.hold(anchor.Key())
	if g == nil {
		// Unreachable while a non-nil registry always yields a gate, and a fail-CLOSED backstop
		// rather than a case: anchorGate.take is nil-tolerant (it returns a no-op release), so
		// filing a nil gate here would run every later request on this anchor unserialized while
		// every test still passed. Sending the caller to the registry costs a round trip; caching
		// nothing costs the guarantee.
		drop()
		return nil, nil, false
	}
	e, kept := c.insert(anchor, g, drop)
	if !kept {
		// Either a concurrent request inserted this anchor first (its entry is what we got
		// back) or the cache is closed. Our own reference is surplus either way.
		drop()
	}
	if e == nil {
		return nil, nil, false
	}
	return e.gate, c.releaser(e), true
}

// lookup records a use of anchor's entry and returns it, or nil when the cache does not hold
// one. admits reports whether the cache would TAKE one — false once closed, and false while it
// is full of entries still in rotation. Both are different answers from "not cached yet", and
// asking here is what lets acquire skip a registry round trip it would only hand back.
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

// admitsLocked reports whether a new anchor may be filed: there is room, or the coldest entry
// has gone a full pass of the cache without a use. Caller holds c.mu.
//
// The second clause is what keeps the cap from turning into a THRASH. Shedding the least
// recently used entry on every miss is the obvious rule and is wrong for the one workload the
// cap is reached by: a session cycling through one more live anchor than the cache holds sheds,
// on every request, the entry the next request wants — so it misses every time AND pays this
// file's bookkeeping on top of the registry round trip it would have paid anyway. Measured, that
// was ~30% slower per call than no cache at all; with the rule below the same workload is ~45%
// FASTER than it, because the entries that do fit keep hitting
// (BenchmarkDecisionTurn_SpanThrashing against its control, BenchmarkDecisionTurn_SpanUncached).
//
// An entry is therefore only shed once the session has stopped cycling through it, and "stopped"
// is measured in the cache's own unit rather than a tuned one: a full pass, maxCachedSessionGates
// uses, with none of them its own. A session whose live anchors do not fit keeps the ones that
// do and takes the always-correct registry path for the rest — which is what every request took
// before this cache existed — instead of losing the cache for all of them.
//
// The tick advances only on a USE (a hit or an admission), never on a refusal, which is what
// makes the comparison mean "passes of the cache" rather than "requests". A session that resolves
// each anchor exactly once therefore fills the cache and then freezes, holding those entries
// unused for its life: bounded at the cap, and each of its requests pays one map lookup over the
// registry path — the honest cost of a workload no cache of any shape can help.
func (c *gateCache) admitsLocked() bool {
	if len(c.entries) < maxCachedSessionGates {
		return true
	}
	_, coldest := c.coldestLocked()
	return coldest != nil && c.tick-coldest.used > uint64(maxCachedSessionGates)
}

// coldestLocked returns the least recently used entry and its key, or the zero anchor and nil
// for an empty cache. Caller holds c.mu.
//
// A linear scan rather than an ordered structure: the cap is small enough that a scan over it is
// cheaper than the bookkeeping any ordering would add to the HIT path, which is the path that
// matters.
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
// admission rule allows it, and records a use of whatever entry ends up serving anchor. kept
// reports whether the caller's registry reference was taken over by the cache; when it is false
// the caller must drop it.
//
// A nil entry with kept=false means the cache would not admit — closed, or full and still
// cycling — and the caller must use the registry.
func (c *gateCache) insert(anchor enforcement.StateAnchor, gate *anchorGate, drop func()) (entry *cachedGate, kept bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, false
	}
	// Re-checked under the lock: two requests on this session can miss concurrently and both
	// reach the registry, which hands each its own reference to the SAME gate. Whoever files
	// first wins the slot and the other's reference is surplus — never a second entry, which
	// would double the cache's footprint for one anchor and give it two independent recencies.
	if e, present := c.entries[anchor]; present {
		c.touchLocked(e)
		return e, false
	}
	// Re-asked under this lock: acquire asked before releasing it to take the registry
	// reference, and a concurrent request may have filled the last slot since.
	if !c.admitsLocked() {
		return nil, false
	}
	// Shed BEFORE filing, so the entry that just arrived is never its own victim and the map
	// never exceeds the cap even transiently.
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

// retireLocked takes e out of the cache, returning its registry reference if it can. Caller
// holds c.mu. It is the ONE place an entry leaves, shared by the cap and by teardown, because
// the condition it turns on is the whole safety argument and two copies of it is one copy that
// can be fixed alone.
//
// An entry with no users has its reference released here. One WITH users cannot: a request that
// read its gate is queued on that gate, and dropping the last reference lets the registry
// reclaim it and build a FRESH gate for the same anchor under a later caller — two gates, no
// mutual exclusion, on the path with no second reader to notice. It is retired instead: removed
// from the map so nothing new joins it, its reference returned by the last user to leave (see
// releaser).
func (c *gateCache) retireLocked(key enforcement.StateAnchor, e *cachedGate) {
	delete(c.entries, key)
	if e.users > 0 {
		e.retired = true
		return
	}
	e.drop()
}

// releaser returns the idempotent func ending one use of e. Idempotent because the decision
// turn's release is: a handler releases right after its decision and defers the same func as a
// backstop, and this rides behind that one.
func (c *gateCache) releaser(e *cachedGate) func() {
	return sync.OnceFunc(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		e.users--
		// The last user of a retired entry is what returns its reference to the registry. A
		// live entry keeps its reference; it is still reachable and still serving.
		if e.retired && e.users == 0 {
			e.drop()
		}
	})
}

// close releases every reference this cache holds and stops it admitting anything more.
//
// Called from releaseSessionState, on the one funnel every teardown passes through and AFTER
// the in-flight drains — the same placement and the same two reasons as the pinned gate's own
// drop: a session whose upstream exits on its own never reaches close(), and a reference
// returned while a request is still taking turns on the gate would let the registry reclaim it
// under that request. The drain makes users zero in the ordinary case; an entry that somehow
// still has one is retired rather than dropped, so the bound holds even if a handler outlives
// the drain's budget.
func (c *gateCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for k, e := range c.entries {
		c.retireLocked(k, e)
	}
	c.entries = nil
}

// size reports how many anchors this cache holds. Test-only: the cap and the release-on-
// teardown are what keep a long-lived session from pinning one route gate per task it has ever
// served, and that is invisible from the outside otherwise.
func (c *gateCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
