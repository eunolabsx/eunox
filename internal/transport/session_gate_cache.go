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
//   - Eviction therefore never drops a reference in use: an entry with users is retired instead
//     — removed from the map so nothing new joins it, its reference dropped by whichever request
//     leaves last. Which is the ordinary refcount discipline, kept on the SESSION's mutex
//     (uncontended: one session's own requests) rather than on the route's (contended by every
//     session on the route).
//
// The bound is a cap on entries with LRU eviction, and it is a memory bound rather than a
// working-set estimate: the anchors are validated task claims, so a legitimate client with many
// tasks — or one authenticated client minting them — must not be able to pin one gate per task
// for the life of a connection. Past the cap the least recently used entry goes and the request
// that displaced it is served; a session whose anchors genuinely cycle wider than the cap falls
// back to the registry for the ones that miss, which is the always-correct path it took for all
// of them before.

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
// live tasks) while keeping that per-session ceiling small; a session that cycles wider than it
// still gets the cache for its most recent eight anchors and the registry for the rest.
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
	// tick orders entries for LRU eviction: every acquire stamps the entry with the next
	// value. A counter rather than a timestamp because it needs only an ordering, and because
	// a monotonic clock read per request would cost more than the map lookup it accompanies.
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
	// It is what makes eviction safe: an entry with users is retired rather than dropped, so
	// a request queued on the gate cannot have that gate reclaimed and replaced beneath it.
	users int
	// used is the tick value of the most recent acquire — the LRU ordering.
	used uint64
	// retired marks an entry evicted from the map (or caught by teardown) while still in use.
	// The last user to leave drops the reference. Nothing new can join it: it is no longer
	// reachable from entries.
	retired bool
}

// acquire returns the cached gate for anchor with a use recorded, plus the idempotent func that
// ends that use. ok is false when the caller must resolve through the route registry instead —
// a route that does not serialize at all, or a session already torn down.
//
// The use is held for the whole turn, not just for the lookup: the caller must call release
// only after it has finished with the gate (see httpSession.beginTurn, which composes it behind
// the turn's own release). Releasing early would put the entry back in reach of eviction while
// a request is still queued on its gate, which is the one thing this cache exists to prevent.
//
// reg is the route's gate registry — passed rather than reached for, so this type never needs a
// back-pointer to the session or the route.
func (c *gateCache) acquire(anchor enforcement.StateAnchor, reg *anchorGates) (gate *anchorGate, release func(), ok bool) {
	if c == nil || reg == nil {
		return nil, nil, false
	}
	if e := c.use(anchor); e != nil {
		return e.gate, c.releaser(e), true
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

// use records a use of anchor's entry and returns it, or nil when the cache does not hold one.
func (c *gateCache) use(anchor enforcement.StateAnchor) *cachedGate {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	e, present := c.entries[anchor]
	if !present {
		return nil
	}
	c.touchLocked(e)
	return e
}

// insert files anchor's entry, evicting the least recently used one when the cap is reached,
// and records a use of whatever entry ends up serving anchor. kept reports whether the caller's
// registry reference was taken over by the cache; when it is false the caller must drop it.
//
// A nil entry with kept=false means the cache is closed and the caller must use the registry.
func (c *gateCache) insert(anchor enforcement.StateAnchor, gate *anchorGate, drop func()) (entry *cachedGate, kept bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, false
	}
	// Re-checked under the lock: two requests on this session can miss concurrently and both
	// reach the registry, which hands each its own reference to the SAME gate. Whoever files
	// first wins the slot and the other's reference is surplus — never a second entry, which
	// would double the cache's footprint for one anchor and mean two independent LRU lives.
	if e, present := c.entries[anchor]; present {
		c.touchLocked(e)
		return e, false
	}
	if c.entries == nil {
		c.entries = make(map[enforcement.StateAnchor]*cachedGate, maxCachedSessionGates)
	}
	e := &cachedGate{gate: gate, drop: drop}
	c.entries[anchor] = e
	c.touchLocked(e)
	// Evicted AFTER the insert and AFTER the new entry is stamped, so the entry that just
	// arrived is the most recently used and can never be its own victim.
	c.evictLocked()
	return e, true
}

// touchLocked records a use of e and stamps it as the most recently used. Caller holds c.mu.
func (c *gateCache) touchLocked(e *cachedGate) {
	c.tick++
	e.used = c.tick
	e.users++
}

// evictLocked drops the least recently used entry while the cache is over its cap. Caller holds
// c.mu.
//
// An entry with no users has its registry reference released here. One WITH users cannot: a
// request that read its gate is queued on that gate, and dropping the last reference lets the
// registry reclaim it and build a fresh gate for the same anchor under a later caller — two
// gates, no mutual exclusion. It is retired instead: removed from the map so nothing new joins
// it, its reference dropped by the last user to leave (see releaser).
//
// A loop rather than a single step because the cap is also enforced when entries are retired
// rather than dropped, and because one pass leaves the invariant true for exactly one insert.
func (c *gateCache) evictLocked() {
	for len(c.entries) > maxCachedSessionGates {
		var victimKey enforcement.StateAnchor
		var victim *cachedGate
		for k, e := range c.entries {
			if victim == nil || e.used < victim.used {
				victimKey, victim = k, e
			}
		}
		if victim == nil { // unreachable while the loop condition holds; a guard, not a case
			return
		}
		delete(c.entries, victimKey)
		if victim.users > 0 {
			victim.retired = true
			continue
		}
		victim.drop()
	}
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
		delete(c.entries, k)
		if e.users > 0 {
			e.retired = true
			continue
		}
		e.drop()
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
