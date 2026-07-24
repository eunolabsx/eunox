// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// White-box tests for PayloadCache: the shared engine behind the JWT verified-token
// cache. In-package so the tests can assert the load-bearing consistency invariant
// (insertOrder.Len() == len(entries)) that an eviction/reclaim bug would break, and can
// drive the clock deterministically. The cache sits on the bearer-token verify hot path,
// so its eviction, expiry, and fail-closed clone behaviours are security-relevant.

package capability

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeClock is a deterministic clock. Its field is written only by the test's main
// goroutine outside any concurrent phase, so read-only concurrent Now() calls are safe.
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

type box struct{ v int }

// copyClone deep-copies a *box, the mutable-payload case PayloadCacheConfig.Clone exists
// for; failClone models a copy that cannot be made (fail closed).
func copyClone(b *box) (*box, bool) {
	if b == nil {
		return nil, false
	}
	return &box{v: b.v}, true
}

func failClone(*box) (*box, bool) { return nil, false }

// newBoxCache builds a *box cache with a deterministic clock started at a fixed base.
func newBoxCache(t *testing.T, maxSize int, maxTTL time.Duration, clk *fakeClock) *PayloadCache[*box] {
	t.Helper()
	return NewPayloadCache(PayloadCacheConfig[*box]{
		MaxEntryTTL: maxTTL,
		MaxSize:     maxSize,
		Now:         clk.now,
		Clone:       copyClone,
	})
}

// assertInvariant checks the list/map length agreement that every eviction and reclaim
// path must preserve; a drift here is exactly the class of bug the linked-list eviction
// bookkeeping can introduce.
func assertInvariant(t *testing.T, c *PayloadCache[*box]) {
	t.Helper()
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.insertOrder.Len() != len(c.entries) {
		t.Fatalf("invariant broken: insertOrder.Len()=%d, len(entries)=%d", c.insertOrder.Len(), len(c.entries))
	}
}

func TestPayloadCache_GetHitReturnsIndependentClone(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 0, time.Hour, clk)

	orig := &box{v: 42}
	c.Put("k", orig, clk.t.Unix()+3600)

	got, ok := c.Get("k")
	if !ok {
		t.Fatal("Get miss on a fresh live entry")
	}
	if got == orig {
		t.Error("Get returned the caller's original pointer; Clone must copy in and out")
	}
	if got.v != 42 {
		t.Errorf("Get value = %d, want 42", got.v)
	}
	// Mutating the returned copy must not affect a later Get (proves clone-out isolation).
	got.v = 99
	again, _ := c.Get("k")
	if again.v != 42 {
		t.Errorf("cached entry corrupted by caller mutation: got %d, want 42", again.v)
	}
}

func TestPayloadCache_GetMissAbsent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 0, time.Hour, clk)
	if _, ok := c.Get("absent"); ok {
		t.Error("Get on an absent key must miss")
	}
}

func TestPayloadCache_GetExpiryBoundaryInclusive(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 0, time.Hour, clk)
	c.Put("k", &box{v: 1}, clk.t.Unix()+3600) // entry expiresAt = base + 1h (payload == MaxEntryTTL)

	clk.t = time.Unix(1_000_000+3600, 0).Add(-time.Nanosecond)
	if _, ok := c.Get("k"); !ok {
		t.Error("Get just before expiry must hit")
	}
	clk.t = time.Unix(1_000_000+3600, 0) // exactly expiresAt: inclusive boundary => miss
	if _, ok := c.Get("k"); ok {
		t.Error("Get at exactly expiresAt must miss (now >= expiresAt is expired)")
	}
}

func TestPayloadCache_GetCloneFailureIsMiss(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := NewPayloadCache(PayloadCacheConfig[*box]{
		MaxSize: 4, Now: clk.now, Clone: failClone,
	})
	c.Put("k", &box{v: 1}, clk.t.Unix()+3600)
	// Put also clones, so a failing clone means nothing was stored: the miss here is
	// really "never cached". Assert the fail-closed outcome either way.
	if _, ok := c.Get("k"); ok {
		t.Error("a failing clone must produce a Get miss (fail closed)")
	}
}

func TestPayloadCache_NilReceiverIsSafe(t *testing.T) {
	var c *PayloadCache[*box]
	if _, ok := c.Get("k"); ok {
		t.Error("nil-receiver Get must miss")
	}
	c.Put("k", &box{v: 1}, 1<<40) // must not panic
	c.Invalidate("k")             // must not panic
	if n := c.Len(); n != 0 {
		t.Errorf("nil-receiver Len = %d, want 0", n)
	}
}

func TestPayloadCache_PutTTLCapByPayloadExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 0, 30*time.Second, clk) // MaxEntryTTL 30s
	c.Put("k", &box{v: 1}, clk.t.Unix()+5)      // payload remaining 5s < 30s => cap at 5s

	clk.t = time.Unix(1_000_000+5, 0)
	if _, ok := c.Get("k"); ok {
		t.Error("entry must expire at the payload's own expiry (5s), not MaxEntryTTL")
	}
}

func TestPayloadCache_PutTTLCapByMaxEntryTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 0, 30*time.Second, clk) // MaxEntryTTL 30s
	c.Put("k", &box{v: 1}, clk.t.Unix()+3600)   // payload remaining 1h > 30s => cap at 30s

	clk.t = time.Unix(1_000_000+29, 0)
	if _, ok := c.Get("k"); !ok {
		t.Error("entry must still be live at 29s (< MaxEntryTTL 30s)")
	}
	clk.t = time.Unix(1_000_000+30, 0)
	if _, ok := c.Get("k"); ok {
		t.Error("entry must expire at MaxEntryTTL (30s) even though the payload lives longer")
	}
}

func TestPayloadCache_PutFailClosedInputs(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 4, time.Hour, clk)

	c.Put("zero-exp", &box{v: 1}, 0)              // expUnix <= 0
	c.Put("neg-exp", &box{v: 1}, -5)              // negative
	c.Put("past-exp", &box{v: 1}, clk.t.Unix()-1) // already expired (remaining <= 0)
	if n := c.Len(); n != 0 {
		t.Errorf("fail-closed Put inputs must not cache anything; Len = %d, want 0", n)
	}

	// A failing clone must also not cache.
	cf := NewPayloadCache(PayloadCacheConfig[*box]{MaxSize: 4, Now: clk.now, Clone: failClone})
	cf.Put("k", &box{v: 1}, clk.t.Unix()+3600)
	if n := cf.Len(); n != 0 {
		t.Errorf("failing clone must not cache; Len = %d, want 0", n)
	}
}

func TestPayloadCache_EvictsOldestAtMaxSize(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 4, time.Hour, clk)

	for i := 0; i < 5; i++ { // insert 5 distinct live keys into a size-4 cache
		c.Put("k"+strconv.Itoa(i), &box{v: i}, clk.t.Unix()+3600)
	}
	if n := c.Len(); n != 4 {
		t.Errorf("Len = %d, want 4 (bounded by MaxSize)", n)
	}
	if _, ok := c.Get("k0"); ok {
		t.Error("oldest-inserted key k0 must have been evicted")
	}
	if _, ok := c.Get("k4"); !ok {
		t.Error("newest key k4 must be present")
	}
	assertInvariant(t, c)
}

func TestPayloadCache_UpdateRefreshesEvictionPosition(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 3, time.Hour, clk)

	c.Put("k0", &box{v: 0}, clk.t.Unix()+3600)
	c.Put("k1", &box{v: 1}, clk.t.Unix()+3600)
	c.Put("k2", &box{v: 2}, clk.t.Unix()+3600)
	c.Put("k0", &box{v: 10}, clk.t.Unix()+3600) // re-Put k0: moves it to the back (freshest)
	c.Put("k3", &box{v: 3}, clk.t.Unix()+3600)  // evicts the now-oldest, which is k1 (not k0)

	if _, ok := c.Get("k0"); !ok {
		t.Error("re-Put k0 must survive: it was refreshed to the back of the eviction order")
	}
	if _, ok := c.Get("k1"); ok {
		t.Error("k1 must be evicted: after k0's refresh it was the oldest")
	}
	if got, ok := c.Get("k0"); !ok || got.v != 10 {
		t.Errorf("k0 value = %v (ok=%v), want 10 (the refreshed payload)", got, ok)
	}
	if n := c.Len(); n != 3 {
		t.Errorf("Len = %d, want 3", n)
	}
	assertInvariant(t, c)
}

func TestPayloadCache_ReclaimsExpiredBehindLiveFront(t *testing.T) {
	// The intricate two-phase path: a live entry sits at the FRONT (oldest inserted) while
	// entries behind it expire. A naive size-eviction would drop the live front; the
	// reclaim passes must instead remove the expired middle/rear entries and admit the new
	// key without evicting the live front.
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 4, time.Hour, clk)

	c.Put("live-front", &box{v: 0}, clk.t.Unix()+3600) // long TTL, inserted first (front)
	c.Put("s1", &box{v: 1}, clk.t.Unix()+5)            // short TTL
	c.Put("s2", &box{v: 2}, clk.t.Unix()+5)
	c.Put("s3", &box{v: 3}, clk.t.Unix()+5)

	clk.t = time.Unix(1_000_000+10, 0) // s1..s3 now expired; live-front still live
	c.Put("k4", &box{v: 4}, clk.t.Unix()+3600)

	if _, ok := c.Get("live-front"); !ok {
		t.Error("the live front entry must survive: expired entries behind it are reclaimed first")
	}
	if _, ok := c.Get("k4"); !ok {
		t.Error("the new key must be admitted after reclaiming expired entries")
	}
	if n := c.Len(); n != 2 {
		t.Errorf("Len = %d, want 2 (live-front + k4; s1..s3 reclaimed)", n)
	}
	assertInvariant(t, c)
}

func TestPayloadCache_Invalidate(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 4, time.Hour, clk)

	c.Put("k", &box{v: 1}, clk.t.Unix()+3600)
	c.Put("keep", &box{v: 2}, clk.t.Unix()+3600)
	c.Invalidate("k")

	if _, ok := c.Get("k"); ok {
		t.Error("Invalidate must remove the entry immediately (revocation)")
	}
	if _, ok := c.Get("keep"); !ok {
		t.Error("Invalidate must not remove other keys")
	}
	if n := c.Len(); n != 1 {
		t.Errorf("Len = %d, want 1 after invalidating one of two", n)
	}
	c.Invalidate("absent") // no-op, must not panic or drift
	assertInvariant(t, c)
}

func TestPayloadCache_LenCountsUnsweptExpired(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c := newBoxCache(t, 4, time.Hour, clk)
	c.Put("k", &box{v: 1}, clk.t.Unix()+5)

	clk.t = time.Unix(1_000_000+10, 0) // k expired but not swept (no Get/Put touched it)
	if n := c.Len(); n != 1 {
		t.Errorf("Len = %d, want 1 (expired-but-not-yet-swept entries are still counted)", n)
	}
	if _, ok := c.Get("k"); ok {
		t.Error("an expired entry must still Get-miss even though Len counts it")
	}
}

func TestPayloadCache_ConcurrentGetPutStaysConsistent(t *testing.T) {
	// Race-detector coverage: many goroutines Put/Get/Invalidate over overlapping keys.
	// The clock is fixed and only read during the parallel phase, so no clock write races
	// the readers. Asserts the size bound holds throughout and the list/map invariant
	// survives the concurrent eviction bookkeeping.
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	const maxSize = 64
	c := newBoxCache(t, maxSize, time.Hour, clk)

	const workers = 32
	const ops = 1000
	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < ops; i++ {
				key := "k" + strconv.Itoa((w*7+i)%128) // overlapping key space across workers
				switch i % 3 {
				case 0:
					c.Put(key, &box{v: i}, clk.t.Unix()+3600)
				case 1:
					c.Get(key)
				default:
					if i%9 == 8 {
						c.Invalidate(key)
					} else {
						c.Get(key)
					}
				}
				if n := c.Len(); n > maxSize {
					t.Errorf("Len = %d exceeded MaxSize %d", n, maxSize)
					return
				}
			}
		}(w)
	}
	close(start)
	wg.Wait()
	assertInvariant(t, c)
}
