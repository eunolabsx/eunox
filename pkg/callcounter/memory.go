// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// DefaultCleanupInterval is the period at which StartCleanup fires.
const DefaultCleanupInterval = 5 * time.Minute

// entry tracks call timestamps for sliding-window counting. windowSec records the
// window this entry is counted with; the map is keyed by (key, windowSec), so it
// is fixed once the entry exists. Cleanup scales its staleness threshold off it so
// a still-live long-window counter (e.g. a weekly maxCalls quota) is never dropped
// mid-window.
type entry struct {
	timestamps []time.Time
	windowSec  int
}

// storageKey namespaces the entry map by (key, windowSec) so each window gets its
// own slice and a shorter window's prune can never destroy timestamps a longer
// window still counts (the cross-window prune that let a multi-window maxCalls
// quota fail open). Redis isolates windows the same way via its sorted-set key, so
// the two backends stay structurally equivalent.
//
// The window is a trailing ":<decimal>" segment whose digits contain no colon, so
// distinct (key, windowSec) pairs always map to distinct strings even when key
// contains colons. The result is only built here for map lookup, never parsed
// back, so no caller can forge a collision.
func storageKey(key string, windowSec int) string {
	return key + ":" + strconv.Itoa(windowSec)
}

// InMemory is a sliding-window call counter backed by in-process memory.
// Suitable for single-replica deployments or testing.
type InMemory struct {
	mu      sync.RWMutex
	entries map[string]*entry
	now     func() time.Time
	// maxKeys bounds how many distinct keys the map may hold at once; 0 (the
	// default) leaves it unbounded. See WithMaxKeys and admitNewKey.
	maxKeys int

	// cleanupMu guards the cleanup-goroutine lifecycle state below. It replaces a
	// plain atomic flag released on goroutine exit, under which "flag set" meant both
	// "a goroutine is running" and "a goroutine is tearing down" — a StartCleanup
	// racing the prior goroutine's exit could then lose the restart and leave cleanup
	// permanently off. See StartCleanup.
	cleanupMu sync.Mutex
	// cleanupCtx governs the live cleanup goroutine and cleanupDone is closed when that
	// goroutine exits; both nil when no goroutine is (or has been) started. Guarded by
	// cleanupMu. Tracking the goroutine's own context lets a restart distinguish "still
	// running under a live context" (idempotent no-op) from "context canceled, on its
	// way out" (wait for exit, then start fresh).
	cleanupCtx  context.Context
	cleanupDone chan struct{}
}

// InMemoryOption configures the InMemory counter.
type InMemoryOption func(*InMemory)

// WithTimeFunc sets a custom time function (for testing).
func WithTimeFunc(fn func() time.Time) InMemoryOption {
	return func(m *InMemory) {
		m.now = fn
	}
}

// WithMaxKeys bounds the number of map entries the counter holds at once,
// capping the heap the map can consume between Cleanup cycles when unique keys
// arrive faster than Cleanup reclaims them (the fresh-session-per-request case;
// see NewInMemory). The bound is on (key, window) BUCKETS, not on distinct keys:
// one key counted over two window lengths occupies two entries, so n is a ceiling
// on buckets and a lower ceiling than n on the distinct keys admitted. Once the
// map holds n entries, a call under a *new* bucket is
// refused with an error; both callers treat that fail-closed (maxCalls denies the
// call, and the sequenceBlock recorder surfaces it so the engine denies). The cost
// at the ceiling is availability — a new-key call is denied (CONDITION_FAILED)
// while the map is full — not a bypass; existing keys keep counting and a key
// reclaimed by Cleanup frees a slot. A value <= 0 (the default) is unbounded.
func WithMaxKeys(n int) InMemoryOption {
	return func(m *InMemory) {
		m.maxKeys = n
	}
}

// NewInMemory creates an in-memory sliding-window call counter.
//
// The key set is unbounded by default: every distinct (session, tool) pair is one
// map entry, reclaimed only when Cleanup runs. A deployment that mints a fresh
// session per request (short-lived HTTP connections with UUID Mcp-Session-Id) thus
// peaks at one entry per unique session at the cleanup boundary, which a caller
// driving unique IDs can push arbitrarily high. For such deployments prefer the
// Redis backend (per-key TTL, off-heap) or pass WithMaxKeys to bound the count.
//
// Quota size is a second, orthogonal heap concern: IncrementIfBelow retains up to
// limit timestamps per (key, window), so a large maxCalls.count also favours
// Redis (see IncrementIfBelow).
func NewInMemory(opts ...InMemoryOption) *InMemory {
	m := &InMemory{
		entries: make(map[string]*entry),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// admitNewKey returns an error when inserting a previously-unseen key would push
// the live key count past maxKeys; nil when the set is unbounded (maxKeys <= 0) or
// has room. Call under m.mu and only on the new-key path (an existing key grows
// the map by nothing). This is the fail-closed backstop for the unbounded-map
// growth described on NewInMemory.
func (m *InMemory) admitNewKey() error {
	if m.maxKeys > 0 && len(m.entries) >= m.maxKeys {
		return fmt.Errorf("callcounter: key limit reached (%d)", m.maxKeys)
	}
	return nil
}

// IncrementAndGet records a call and returns the number of calls within the
// window, capped at maxEntries. Only the most-recent maxEntries in-window
// timestamps are kept, so a key under sustained traffic stores a bounded slice.
//
// Keeping the NEWEST entries makes the cap correct for a sliding window: the
// newest ages out last, so a later Peek still reports presence as long as any call
// remains in-window. The dropped oldest surplus would have expired first anyway,
// so it can never raise a future count past maxEntries.
func (m *InMemory) IncrementAndGet(_ context.Context, key string, windowSec, maxEntries int) (int64, error) {
	// Reject an out-of-range window before touching state: an overflowing windowSec
	// would wrap the cutoff and silently reset the counter (a fail-open bypass). A
	// non-positive maxEntries is likewise rejected (see checkMaxEntries).
	if err := checkWindowSec(windowSec); err != nil {
		return 0, err
	}
	if err := checkMaxEntries(maxEntries); err != nil {
		return 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := floorToMicro(m.now())
	window := time.Duration(windowSec) * time.Second
	cutoff := now.Add(-window)

	// Namespace the entry by window (storageKey) so two windows on the same key
	// never share one slice.
	sk := storageKey(key, windowSec)
	e, ok := m.entries[sk]
	if !ok {
		if err := m.admitNewKey(); err != nil {
			return 0, err
		}
		// Record the window so Cleanup can scale its staleness threshold to it (set
		// once at creation; the map is keyed by windowSec, so it never changes).
		e = &entry{windowSec: windowSec}
		m.entries[sk] = e
	}

	// Remove expired timestamps, reusing the existing backing array in place.
	// The slice stays in oldest-first order.
	valid := pruneInWindow(e, cutoff)

	// Add current timestamp (still the newest, so order is preserved).
	valid = append(valid, now)

	// Cap to the most-recent maxEntries by dropping the oldest surplus from the
	// front. copy is a forward shift over the same backing array (dst index < src
	// index), so it is safe despite the overlap.
	if len(valid) > maxEntries {
		n := copy(valid, valid[len(valid)-maxEntries:])
		valid = valid[:n]
	}

	// Reclaim the backing array if a past burst left it mostly empty.
	valid = compactTimestamps(valid)
	e.timestamps = valid

	return int64(len(valid)), nil
}

// compactMinCap is the smallest backing-array capacity worth reclaiming in
// compactTimestamps. Below it the wasted memory is trivial and the copy would
// only add churn to the common case of a key that never bursts.
const compactMinCap = 64

// compactTimestamps returns ts unchanged unless its backing array is both large
// (cap > compactMinCap) and mostly empty (live length below a quarter of
// capacity), in which case it copies the live timestamps into a right-sized slice
// so the oversized array can be garbage collected.
//
// IncrementAndGet prunes via [:0] reslicing, which keeps appends amortised O(1)
// but never shrinks capacity: without this, a burst of N calls that drains to a
// handful would pin an N-element array for as long as the key stays live (Cleanup
// only deletes whole stale entries, never shrinks a live one).
//
// The 25% threshold keeps the copy off the steady-state hot path: append leaves a
// grow-only slice at ~50% utilisation (~80% above 1024 elements) climbing toward
// 100% as the window fills, so ordinary churn never dips to 25% — only a real drop
// in live count does. The copy is thus paid once per burst-then-drain cycle, and
// each copy is of the small live set, dwarfed by the regrowth it would do anyway.
func compactTimestamps(ts []time.Time) []time.Time {
	// len(ts) < cap(ts)/4 rather than len(ts)*4 < cap(ts): the multiplication
	// form overflows int on 32-bit platforms once len(ts) > 2^29, wrapping
	// negative and firing the copy spuriously. The division form is equivalent
	// (cap/4 floors the threshold) and cannot overflow.
	if cap(ts) > compactMinCap && len(ts) < cap(ts)/4 {
		compact := make([]time.Time, len(ts))
		copy(compact, ts)
		return compact
	}
	return ts
}

// pruneInWindow drops expired timestamps from e's backing array, reusing it in
// place ([:0] reslice), and returns the surviving slice in oldest-first order. A
// timestamp survives iff it is strictly after cutoff — the single source of the
// window-boundary predicate, so it cannot drift from the Redis backend's paired
// "<= cutoff is expired" ZREMRANGEBYSCORE bound. Callers append the new timestamp
// and/or compact as their path requires.
func pruneInWindow(e *entry, cutoff time.Time) []time.Time {
	valid := e.timestamps[:0]
	for _, ts := range e.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	return valid
}

// floorToMicro floors t to microsecond precision so a recorded timestamp encodes
// the same instant the Redis backend would (Redis stores UnixMicro scores and
// cannot distinguish sub-microsecond timing), which otherwise made the two
// backends disagree at the window boundary. It subtracts the sub-microsecond
// remainder rather than calling time.Truncate, which would strip the monotonic
// reading Add preserves. Flooring is monotonic, so the oldest-first ordering the
// prune relies on holds.
func floorToMicro(t time.Time) time.Time {
	return t.Add(-time.Duration(t.Nanosecond() % 1000))
}

// IncrementIfBelow records a call for key only when the in-window count is
// strictly below limit, doing the prune, count, and record under a single lock so
// the check and record are atomic. It is the rate-limiting counterpart of
// IncrementAndGet that maxCalls uses: a denied call appends no timestamp, which
// previously grew the slice unbounded and kept the lockout from clearing under
// retries.
//
// It returns the resulting in-window count (post-record when admitted, current
// otherwise), whether admitted, and — when rejected — how long until a slot frees.
// Expired timestamps are pruned on every call, including denials.
//
// There is no maxEntries cap (unlike IncrementAndGet): the slice is bounded by
// limit, which scales with the quota, so a maxCalls limit in the millions retains
// a correspondingly large per-key slice on the heap. Prefer the Redis backend for
// large quotas.
func (m *InMemory) IncrementIfBelow(_ context.Context, key string, windowSec int, limit int64) (count int64, admitted bool, retryAfter time.Duration, err error) {
	if err := checkWindowSec(windowSec); err != nil {
		return 0, false, 0, err
	}
	// Fail closed before touching map state: a limit<1 can never admit, so no entry
	// should be created or counted against maxKeys (matching the Redis backend,
	// which writes nothing on a denied call). A structured error keeps a
	// misconfigured limit distinguishable from an exhausted quota.
	if err := checkLimit(limit); err != nil {
		return 0, false, 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := floorToMicro(m.now())
	window := time.Duration(windowSec) * time.Second
	cutoff := now.Add(-window)

	// Namespace the entry by window (storageKey) so two windows on the same key
	// never share one slice.
	sk := storageKey(key, windowSec)
	e, ok := m.entries[sk]
	if !ok {
		if err := m.admitNewKey(); err != nil {
			return 0, false, 0, err
		}
		// Record the window so Cleanup can scale its staleness threshold (set once;
		// never changes).
		e = &entry{windowSec: windowSec}
		m.entries[sk] = e
	}

	// Drop expired timestamps. Writing the pruned slice back on every call (admitted
	// or denied) is what bounds a rate-limited key's storage.
	valid := pruneInWindow(e, cutoff)

	cur := int64(len(valid))
	if cur >= limit {
		// Reclaim the backing array if a past burst left it mostly empty, matching
		// IncrementAndGet so a denied-but-drained key does not pin its peak array.
		valid = compactTimestamps(valid)
		e.timestamps = valid
		// Advisory retry-after estimate; details in retryAfterFromPivot.
		return cur, false, retryAfterFromPivot(valid, cur, limit, window, now), nil
	}

	// Below the limit: record the call.
	valid = append(valid, now)
	valid = compactTimestamps(valid)
	e.timestamps = valid
	return int64(len(valid)), true, 0, nil
}

// IncrementIfAllBelow admits a call against several maxCalls buckets atomically
// under a single lock: all buckets are recorded only when every (key, windowSec,
// limit) is strictly below its limit; otherwise nothing is recorded and the
// blocking bucket is reported. Holding m.mu across the whole check-and-commit
// closes the multi-maxCalls TOCTOU a per-bucket IncrementIfBelow would leave. See
// the capability.CallCounter contract.
func (m *InMemory) IncrementIfAllBelow(_ context.Context, keys []string, windowSecs []int, limits []int64) (admitted bool, deniedIndex int, count int64, retryAfter time.Duration, err error) {
	// Validate the batch (slice lengths, non-empty, per-bucket window/limit, distinct
	// (key, windowSec) buckets) and fail closed before touching map state: a
	// misconfigured window/limit must not create a phantom entry or admit a partial
	// set, and a duplicate (key, windowSec) bucket would let the commit loop below
	// silently overwrite one entry (a fail-open under-count that diverges from Redis).
	// checkBatch is shared with the Redis backend so both reject the same inputs.
	if e := checkBatch(keys, windowSecs, limits); e != nil {
		return false, 0, 0, 0, e
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := floorToMicro(m.now())

	// Each bucket keys a distinct window-namespaced entry (storageKey), and two
	// maxCalls on one constraint must declare distinct windows (rejected at manifest
	// load); checkDistinctBuckets above also fails the call closed if a direct consumer
	// passes colliding (key, windowSec) buckets, so the storage keys within a committed
	// batch never collide.
	type bucketState struct {
		sk     string
		e      *entry // nil until the bucket's first admitted call
		valid  []time.Time
		window time.Duration
		cur    int64
	}
	states := make([]bucketState, len(keys))
	blocked := -1
	for i := range keys {
		window := time.Duration(windowSecs[i]) * time.Second
		cutoff := now.Add(-window)
		sk := storageKey(keys[i], windowSecs[i])
		st := bucketState{sk: sk, window: window}
		if e, ok := m.entries[sk]; ok {
			// Prune expired timestamps and write back now: idempotent maintenance the
			// single-key path also does on every call, so doing it before the admit
			// decision (and on the deny path) is safe and bounds storage.
			valid := compactTimestamps(pruneInWindow(e, cutoff))
			e.timestamps = valid
			st.e = e
			st.valid = valid
			st.cur = int64(len(valid))
		}
		states[i] = st
		// Report the FIRST full bucket (by slice order), not the one with the longest
		// retry-after: the caller retries when this one frees and, if a tighter
		// sibling still blocks, is denied again with that sibling's hint. Admission is
		// unchanged either way; only the first hint differs.
		if blocked < 0 && st.cur >= limits[i] {
			blocked = i
		}
	}

	if blocked >= 0 {
		// At least one bucket is full: record nothing new (each existing entry was
		// already pruned above) and report the blocking bucket with the same
		// retry-after estimate IncrementIfBelow gives.
		b := states[blocked]
		return false, blocked, b.cur, retryAfterFromPivot(b.valid, b.cur, limits[blocked], b.window, now), nil
	}

	// All buckets have headroom → commit every one. Pre-check the key cap against the
	// number of absent buckets so the batch is all-or-nothing against maxKeys too.
	newKeys := 0
	for i := range states {
		if states[i].e == nil {
			newKeys++
		}
	}
	if m.maxKeys > 0 && len(m.entries)+newKeys > m.maxKeys {
		return false, 0, 0, 0, fmt.Errorf("callcounter: key limit reached (%d)", m.maxKeys)
	}
	var maxCount int64
	for i := range states {
		e := states[i].e
		if e == nil {
			e = &entry{windowSec: windowSecs[i]}
			m.entries[states[i].sk] = e
		}
		e.timestamps = compactTimestamps(append(e.timestamps, now))
		// Report the max post-admission total across buckets (no single binding bucket
		// on the admit path) per the capability.CallCounter contract — the bucket closest
		// to its limit, the most useful figure for the caller.
		if c := int64(len(e.timestamps)); c > maxCount {
			maxCount = c
		}
	}
	return true, 0, maxCount, 0, nil
}

// Peek returns the number of calls recorded for key within the window WITHOUT
// recording one. It is the read-only counterpart of IncrementAndGet used by
// sequenceBlock to test whether a tool has already run. It neither appends nor
// prunes — a pure observation must not mutate state, or checking "has A run?"
// while evaluating B would itself register a call to A.
func (m *InMemory) Peek(_ context.Context, key string, windowSec int) (int64, error) {
	if err := checkWindowSec(windowSec); err != nil {
		return 0, err
	}

	// Read lock only: a pure observation, so concurrent Peeks proceed in parallel;
	// only the writers take the exclusive Lock.
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, ok := m.entries[storageKey(key, windowSec)]
	if !ok {
		return 0, nil
	}

	// Floor to microsecond precision to match the recorded timestamps and the Redis
	// backend; without it a call in the final sub-microsecond could be counted by
	// IncrementAndGet but reported as 0 here, a boundary disagreement that could
	// fail-open a sequenceBlock gate.
	cutoff := floorToMicro(m.now()).Add(-time.Duration(windowSec) * time.Second)
	var count int64
	for _, ts := range e.timestamps {
		if ts.After(cutoff) {
			count++
		}
	}
	return count, nil
}

// retryAfterFromPivot estimates how long until the in-window count next drops below
// limit: the last call that must age out is valid[cur-limit] in oldest-first order,
// and a slot frees one window after it was recorded. Returns 0 when the pivot index
// is out of range or the estimate is non-positive. Shared by IncrementIfBelow and
// IncrementIfAllBelow (both deny paths) so the two cannot drift. The index is kept in
// int64 since int(cur-limit) truncates on 32-bit (MaxLimit is 1<<53).
//
// "Oldest-first" holds only under a monotonically non-decreasing clock (production
// time.Now()); a backward-jumping test clock (WithTimeFunc) can leave valid unsorted
// and make this imperfect. Tolerated rather than sorted: the hint is purely advisory
// (the caller clamps and falls back to the full window) and carries no security weight.
func retryAfterFromPivot(valid []time.Time, cur, limit int64, window time.Duration, now time.Time) time.Duration {
	if idx := cur - limit; idx >= 0 && idx < int64(len(valid)) {
		if r := valid[idx].Add(window).Sub(now); r > 0 {
			return r
		}
	}
	return 0
}

// StartCleanup launches a single background goroutine that calls Cleanup on every
// interval tick until ctx is canceled, returning whether this call started it.
// Call once after constructing a process-lifetime counter. A non-positive interval
// defaults to DefaultCleanupInterval.
//
// It is idempotent: the cleanupMu-guarded lifecycle ensures the first call wins
// (returns true; its ctx/interval govern the goroutine) and later calls with the
// goroutine still live are no-ops (return false). A second goroutine would double the
// cleanup cost and leak, since nothing returns a handle to stop it.
//
// A later call with a live context can restart cleanup after the prior goroutine's
// context was canceled — recovering gracefully where a fired sync.Once could not.
// The lifecycle is guarded by cleanupMu (not a released-on-exit atomic flag) so the
// documented restart-after-cancel sequence (cancel ctx1, then StartCleanup(ctx2))
// is deterministic even when the restart races the prior goroutine's teardown: the
// restart observes the prior context is canceled, waits for that goroutine to exit,
// then starts fresh. (Cancellation that lands concurrently with — rather than
// before — a restart remains best-effort: a goroutine seen running under a still-live
// context is treated as a no-op.)
func (m *InMemory) StartCleanup(ctx context.Context, interval time.Duration) bool {
	// Refuse an already-canceled context without starting anything.
	if ctx.Err() != nil {
		return false
	}
	if interval <= 0 {
		interval = DefaultCleanupInterval
	}

	m.cleanupMu.Lock()
	defer m.cleanupMu.Unlock()

	if m.cleanupDone != nil {
		// A goroutine has been started. If its context is still live, a goroutine is
		// genuinely running and this call is the idempotent no-op. If its context is
		// already canceled, that goroutine is exiting (or already gone): wait for it to
		// finish, then fall through to start a fresh one, so the restart is never lost.
		if m.cleanupCtx != nil && m.cleanupCtx.Err() == nil {
			return false
		}
		<-m.cleanupDone // bounded: a canceled context makes the goroutine return promptly
		m.cleanupCtx = nil
		m.cleanupDone = nil
	}

	done := make(chan struct{})
	m.cleanupCtx = ctx
	m.cleanupDone = done
	go func() {
		t := time.NewTicker(interval)
		// Closing done (not requiring cleanupMu) lets a restarting caller waiting above
		// observe this goroutine's exit and re-arm.
		defer func() {
			t.Stop()
			close(done)
		}()
		for {
			select {
			case <-t.C:
				m.Cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()
	return true
}

// cleanupDeleteBatch bounds how many stale keys Cleanup deletes per lock
// acquisition in its second phase, so a single pass never stalls concurrent
// IncrementAndGet/Peek callers for longer than O(batch) even when tens of
// thousands of keys expire together.
const cleanupDeleteBatch = 256

// shouldDeleteEntry reports whether e holds no decision-affecting state and may be
// reclaimed: no timestamps, or a most-recent timestamp older than
// cleanupMarginFactor times its largest window — the same margin Redis applies via
// its key TTL, keeping the two backends equivalent.
//
// Keying staleness to the entry's own window (not a fixed 24h) is essential: a
// long-window maxCalls quota that goes idle past 24h must not have its still-live
// counter wiped, or the next call would silently reset the quota mid-window — a
// fail-open bypass. An entry with no recorded window falls back to 24h; only
// reachable via direct map injection (tests).
//
// "Most-recent" is found by scanning the whole slice rather than reading the last
// element: under a backward-jumping test clock (WithTimeFunc) appends can leave an
// older timestamp last, which a last-element check would misjudge. Production
// time.Now() is monotonic, so the scan is redundant there but harmless.
func shouldDeleteEntry(e *entry, now time.Time) bool {
	if len(e.timestamps) == 0 {
		return true
	}
	staleAfter := 24 * time.Hour
	if e.windowSec > 0 {
		staleAfter = time.Duration(e.windowSec) * cleanupMarginFactor * time.Second
	}
	latest := e.timestamps[0]
	for _, ts := range e.timestamps[1:] {
		if ts.After(latest) {
			latest = ts
		}
	}
	// Use <= (!After), not strict <, so an entry exactly staleAfter old is deleted
	// this sweep, matching Redis's TTL eviction at-or-after the boundary (strict <
	// held InMemory keys one cycle longer).
	return !latest.After(now.Add(-staleAfter))
}

// Cleanup removes entries whose counters can no longer affect any decision,
// preventing unbounded memory growth. Call periodically. The dropped-entry
// criterion lives in shouldDeleteEntry.
//
// It runs in two phases so it never holds the lock for the whole pass: (1) under a
// read lock, scan and collect stale keys; (2) delete them in bounded batches,
// re-acquiring the write lock per batch so waiting callers get through between
// batches. Staleness is re-checked under the lock before each delete: a concurrent
// IncrementAndGet may have revived a key phase 1 saw as stale, and deleting it then
// would reset a live quota (fail-open).
func (m *InMemory) Cleanup() {
	// Phase 1 only reads, so a read lock suffices and lets concurrent readers (Peek)
	// proceed during the O(N) scan.
	m.mu.RLock()
	now := m.now()
	var toDelete []string
	for key, e := range m.entries {
		if shouldDeleteEntry(e, now) {
			toDelete = append(toDelete, key)
		}
	}
	m.mu.RUnlock()

	for start := 0; start < len(toDelete); start += cleanupDeleteBatch {
		end := start + cleanupDeleteBatch
		if end > len(toDelete) {
			end = len(toDelete)
		}
		m.mu.Lock()
		now := m.now()
		for _, key := range toDelete[start:end] {
			// Both guards are load-bearing; do not simplify either away. `ok`
			// skips a key already deleted since phase 1; the repeated
			// shouldDeleteEntry skips one a concurrent IncrementAndGet has revived.
			// Dropping a revived key would reset a live maxCalls quota (fail-open).
			if e, ok := m.entries[key]; ok && shouldDeleteEntry(e, now) {
				delete(m.entries, key)
			}
		}
		m.mu.Unlock()
	}
}
