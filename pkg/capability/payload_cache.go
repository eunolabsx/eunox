// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"container/list"
	"sync"
	"time"
)

// PayloadCache is an in-process, FIFO-with-refresh, TTL-bounded cache for verified token
// payloads of type T, safe for concurrent use and keyed by an opaque caller-supplied
// string (a token hash — see HashTokenKey). It is the shared engine behind the JWT
// verified-token cache in internal/pdp (T = *JWTClaims, shared by pointer because
// JWTClaims is immutable after validation); a caller whose payload type is mutable
// instead should copy in and out via PayloadCacheConfig.Clone, the axis on which
// consumers can differ.
//
// On a Get hit the caller skips whatever expensive verification produced the payload
// for entries populated within the last MaxEntryTTL; a miss always returns the zero
// value so the caller falls through to full verification (fail closed).
//
// Security trade-off: a payload is served for up to min(MaxEntryTTL, the payload's
// own remaining lifetime) after its entry was populated, so set MaxEntryTTL shorter
// than the required revocation-propagation SLA.
//
// Eviction order is INSERTION order, refreshed on Put, not recency of use: Get does
// not promote the entry it hits. So a hot key that is read constantly but never
// re-Put is evicted ahead of a colder key inserted after it. That is deliberate for
// the verified-token use — an entry's value is bounded by MaxEntryTTL from when it
// was populated, so keeping it alive on reads would only extend the window in which
// a revoked token still verifies — but it is NOT an LRU, and sizing the cache as if
// reads protected an entry will mis-predict its hit rate.
//
// Bounds are maintained entirely by lazy pruning on Get/Put; there is no background
// sweep goroutine.
type PayloadCache[T any] struct {
	cfg PayloadCacheConfig[T]
	mu  sync.RWMutex
	// entries is keyed by the caller-supplied opaque key (a token hash), so a large
	// token never occupies significant key memory.
	entries map[string]*payloadCacheEntry[T]
	// insertOrder is a doubly-linked list of cache keys in insertion order (front =
	// oldest). Each entry back-points to its element, enabling O(1) eviction in Put and
	// Invalidate.
	insertOrder *list.List
}

// PayloadCacheConfig configures a PayloadCache. Clone is required; the rest default.
type PayloadCacheConfig[T any] struct {
	// MaxEntryTTL is the maximum duration a payload is retained, regardless of its own
	// expiry. 0 uses the default (30s). Shorter increases freshness (revocation
	// propagates faster); longer reduces upstream round-trips.
	MaxEntryTTL time.Duration
	// MaxSize is the maximum number of entries; 0 uses the default (4096). At the limit
	// the oldest entries are evicted.
	MaxSize int
	// Now is an optional clock for testing; defaults to time.Now.
	Now func() time.Time
	// Clone copies a payload on the way into Put and out of Get, so a caller mutating
	// its copy can neither corrupt the cached entry nor race a concurrent reader. It
	// returns ok=false to signal the copy failed, in which case the entry is not cached
	// (Put) or the lookup is treated as a miss (Get) — fail closed. A caller whose
	// payload type is immutable and read-only by contract passes an identity function
	// (return the same value, true) to share by pointer.
	Clone func(T) (T, bool)
}

const (
	defaultMaxEntryTTL = 30 * time.Second
	defaultMaxSize     = 4096
)

// payloadCacheEntry holds a cached payload, its eviction deadline, and a pointer to
// its node in the insertion-order list.
type payloadCacheEntry[T any] struct {
	payload   T
	expiresAt time.Time
	listElem  *list.Element // back-pointer for O(1) removal from insertOrder
}

// NewPayloadCache creates a new PayloadCache. Bounds are maintained entirely by lazy
// pruning on Get/Put. Clone must be non-nil.
func NewPayloadCache[T any](cfg PayloadCacheConfig[T]) *PayloadCache[T] {
	if cfg.MaxEntryTTL <= 0 {
		cfg.MaxEntryTTL = defaultMaxEntryTTL
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = defaultMaxSize
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// Clone is load-bearing, not optional: both Get and Put call it, and a nil one made
	// every cache operation a nil-func PANIC rather than the fail-closed miss the rest of
	// this type is written around. The panic would land on the JWT verify hot path, which
	// turns a construction mistake in a library consumer into a crashed proxy. Substitute
	// a clone that always reports failure: Get returns a miss and Put declines to cache,
	// so the cache degrades into a no-op -- correct, just uncached -- exactly as it does
	// when a real Clone fails.
	if cfg.Clone == nil {
		var zero T
		cfg.Clone = func(T) (T, bool) { return zero, false }
	}
	return &PayloadCache[T]{
		cfg: cfg,
		// No size hint: an unused cache (e.g. a per-route JWTPDP wrapper that never puts)
		// costs an empty map, not MaxSize preallocated buckets. A populated cache grows
		// on demand up to MaxSize.
		entries:     make(map[string]*payloadCacheEntry[T]),
		insertOrder: list.New(),
	}
}

// Get returns the cached payload for key, or (zero, false) if absent, expired, or the
// clone-out failed. A nil receiver always misses (so a consumer built without a cache
// stays fail-closed). The returned value is Clone's copy, so a caller writing through
// it cannot corrupt the shared entry or race a concurrent reader.
func (c *PayloadCache[T]) Get(key string) (T, bool) {
	var zero T
	if c == nil {
		return zero, false
	}
	// Hold the read lock across the lookup AND the expiry check so a concurrent
	// Invalidate cannot interleave between them (a TOCTOU that served a just-revoked
	// entry).
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok {
		return zero, false
	}
	// Sample the clock under the lock, immediately before the check: a pre-lock sample
	// can go stale while Get waits on RLock contention, serving an entry that expired
	// during the wait. Now() does not touch c.mu, so this is deadlock-free.
	now := c.cfg.Now()
	if !now.Before(entry.expiresAt) {
		// Expired — treat as miss. Inclusive boundary (now >= expiresAt): expiresAt is
		// capped at the payload expiry and validity requires now strictly before it.
		return zero, false
	}
	// Return Clone's copy so a caller mutating the payload cannot corrupt the cached
	// entry or race a reader. Fail closed (miss) if the copy fails.
	cp, cloneOK := c.cfg.Clone(entry.payload)
	if !cloneOK {
		return zero, false
	}
	return cp, true
}

// Put stores payload under key with entry TTL = min(cfg.MaxEntryTTL, expUnix - now),
// so the cache never serves a structurally expired payload. expUnix is the payload's
// own expiry (Unix seconds). A nil receiver, or a non-positive expUnix / remaining
// lifetime, is not cached (fail closed): an entry with no enforceable lifetime must
// not linger past any revocation cap. If MaxSize would be exceeded the oldest-inserted
// entries are evicted.
func (c *PayloadCache[T]) Put(key string, payload T, expUnix int64) {
	if c == nil || expUnix <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Sample the clock under the lock, like Get: a pre-lock sample can go stale while
	// Put waits on Lock contention, inflating the entry TTL so a just-expired payload is
	// cached past its true expiry. Get and Put must agree on the clock.
	now := c.cfg.Now()

	// Determine eviction time: min(MaxEntryTTL, payload's remaining lifetime).
	entryTTL := c.cfg.MaxEntryTTL
	payloadRemaining := time.Unix(expUnix, 0).Sub(now)
	if payloadRemaining <= 0 {
		// Already expired; nothing to cache.
		return
	}
	if payloadRemaining < entryTTL {
		entryTTL = payloadRemaining
	}

	// Store Clone's copy so a caller mutating its payload after Put cannot change what a
	// later Get returns. Fail closed (do not cache) if the copy fails.
	stored, cloneOK := c.cfg.Clone(payload)
	if !cloneOK {
		return
	}
	entry := &payloadCacheEntry[T]{
		payload:   stored,
		expiresAt: now.Add(entryTTL),
	}

	if existing, exists := c.entries[key]; exists {
		// Update path: reuse the existing list element (else the old node orphans and the
		// eviction counter drifts), and move it to the back so a refreshed payload resets
		// its eviction position. This is the ONLY promotion: Put refreshes, Get does not,
		// which is what makes the order FIFO-with-refresh rather than LRU.
		c.insertOrder.MoveToBack(existing.listElem)
		entry.listElem = existing.listElem
	} else {
		// Reclaim the contiguous run of expired entries from the front before deciding on
		// eviction, so a size eviction does not displace a live entry while stale ones
		// occupy the cache. Stops at the first live entry, so it is O(1) when nothing has
		// expired.
		for {
			front := c.insertOrder.Front()
			if front == nil {
				break
			}
			oldest := front.Value.(string)
			e, ok := c.entries[oldest]
			if !ok || now.Before(e.expiresAt) {
				break // front is live (or already gone): stop reclaiming
			}
			c.insertOrder.Remove(front)
			delete(c.entries, oldest)
		}
		// Per-payload TTLs are min(MaxEntryTTL, remaining), so a short-lived payload can
		// expire while sitting BEHIND a live front the contiguous reclaim never reaches;
		// without this sweep the capacity loop would evict a LIVE entry while stale ones
		// still occupy the cache. It runs only when the front reclaim left us at capacity,
		// so a cache with room pays nothing.
		//
		// This single write-locked sweep replaced a read-locked pre-scan that collected
		// the same keys before taking the write lock. The pre-scan could not remove this
		// pass -- it sampled the clock under the READ lock, so an entry that was live then
		// and expired in the read->write window was missing from its list, and the
		// authoritative sweep had to run anyway. The result was two full O(n) scans per
		// Put in the steady-state-full case (the common one: at capacity, nothing expired)
		// to do the work of one, plus an extra lock round-trip and ~50 lines of two-phase
		// reasoning. The sweep here is strictly more accurate: one pass, one clock, taken
		// under the lock that actually mutates.
		if c.insertOrder.Len() >= c.cfg.MaxSize {
			for el := c.insertOrder.Front(); el != nil; {
				next := el.Next()
				ek := el.Value.(string)
				if e, ok := c.entries[ek]; !ok || !now.Before(e.expiresAt) {
					c.insertOrder.Remove(el)
					delete(c.entries, ek)
				}
				el = next
			}
		}
		// If still at capacity after reclaiming expired entries, evict the oldest (now
		// necessarily live) entry to make room (O(1): remove front of list).
		for c.insertOrder.Len() >= c.cfg.MaxSize {
			front := c.insertOrder.Front()
			if front == nil {
				break
			}
			oldest := front.Value.(string)
			c.insertOrder.Remove(front)
			delete(c.entries, oldest)
		}
		// Add new key to back of list and store the element pointer.
		elem := c.insertOrder.PushBack(key)
		entry.listElem = elem
	}
	c.entries[key] = entry
}

// Invalidate removes a specific key immediately. Removal is O(1). Nil-receiver safe.
//
// NOTE: eunox itself never calls this — nothing in the proxy learns of a revocation
// out of band, so the only revocation bound it offers today is the entry TTL
// (min(MaxEntryTTL, the token's own exp)). This is library API for an embedder that
// DOES have such a signal; do not read its existence as evidence that a revocation
// feed is wired.
func (c *PayloadCache[T]) Invalidate(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		delete(c.entries, key)
		if entry.listElem != nil {
			c.insertOrder.Remove(entry.listElem)
		}
	}
}

// Len returns the number of entries currently held (including expired-but-not-yet-swept
// entries). Nil-receiver safe.
func (c *PayloadCache[T]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
