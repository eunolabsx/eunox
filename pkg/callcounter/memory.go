// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// DefaultCleanupInterval is the period at which StartCleanup fires.
const DefaultCleanupInterval = 5 * time.Minute

// entry tracks call timestamps for sliding-window counting. windowSec is fixed at
// creation; Cleanup scales staleness off it so a long-window counter never drops mid-window.
type entry struct {
	timestamps []time.Time
	windowSec  int
	// weights carries one magnitude per timestamp; nil for a pure counting key (avoids
	// growing memory for maxCalls/sequenceBlock keys). INVARIANT: len is 0 or == len(timestamps).
	weights []float64
}

// weightedTotal sums live weights oldest-first, matching the Redis backend's score-ordered
// scan so both accumulate the same IEEE-754 double from the same sequence.
func weightedTotal(liveWeights []float64) float64 {
	total := 0.0
	for _, w := range liveWeights {
		total += w
	}
	return total
}

// storageKey namespaces the entry map by (key, windowSec) so a shorter window's prune can
// never destroy timestamps a longer window still counts (the fail-open a shared slice risked).
func storageKey(key string, windowSec int) string {
	return key + ":" + strconv.Itoa(windowSec)
}

// InMemory is a sliding-window call counter backed by in-process memory.
// Suitable for single-replica deployments or testing.
type InMemory struct {
	mu      sync.RWMutex
	entries map[string]*entry
	now     func() time.Time
	// maxKeys bounds live (key, window) STORAGE ENTRIES, not logical keys; 0 is unbounded.
	// See WithMaxKeys.
	maxKeys int
	// maxWeightedEntries bounds live entries under weighted accounting; a package
	// invariant, not an operator knob (the lowering option is test-only).
	maxWeightedEntries int

	// cleanupMu guards the cleanup-goroutine lifecycle. A plain atomic flag released on
	// exit could not distinguish "running" from "tearing down", losing a racing restart.
	cleanupMu sync.Mutex
	// cleanupCtx governs the live goroutine; cleanupDone closes on its exit. Tracking the
	// goroutine's own context lets a restart distinguish "still running" from "tearing down".
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

// WithMaxKeys bounds live (key, window) STORAGE ENTRIES; a *new* entry past it is refused
// fail-closed (availability cost only). Size against entries, not logical keys — a tool
// counted under two windows occupies two slots.
func WithMaxKeys(n int) InMemoryOption {
	return func(m *InMemory) {
		m.maxKeys = n
	}
}

// withMaxWeightedEntries lowers the weighted retention ceiling for tests, so they can reach
// it without writing 100k entries; unexported since it is a package invariant, not a knob.
func withMaxWeightedEntries(n int) InMemoryOption {
	return func(m *InMemory) {
		m.maxWeightedEntries = n
	}
}

// NewInMemory creates an in-memory sliding-window call counter, unbounded by default —
// prefer Redis or WithMaxKeys for a fresh-session-per-request deployment.
func NewInMemory(opts ...InMemoryOption) *InMemory {
	m := &InMemory{
		entries:            make(map[string]*entry),
		now:                time.Now,
		maxWeightedEntries: MaxWeightedEntriesPerKey,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// admitNewKey refuses a new (key, window) entry once maxKeys is reached; nil when unbounded
// or there is room. Call under m.mu, new-entry path only.
func (m *InMemory) admitNewKey() error {
	if m.maxKeys > 0 && len(m.entries) >= m.maxKeys {
		return m.errEntryLimit()
	}
	return nil
}

// errEntryLimit is the one entry-limit refusal, shared by single-key admission and the
// multi-bucket commit's own count check, so callers match on one spelling.
func (m *InMemory) errEntryLimit() error {
	return fmt.Errorf("callcounter: entry limit reached (%d)", m.maxKeys)
}

// errWeightedEntryLimit is the per-key counterpart of errEntryLimit. It names neither key
// nor session — those reach an operator via the audit record's structured fields.
func (m *InMemory) errWeightedEntryLimit() error {
	return fmt.Errorf("callcounter: weighted entry limit reached (%d entries in one window)", m.maxWeightedEntries)
}

// IncrementAndGet records a call and returns the in-window count, capped at maxEntries by
// keeping the NEWEST entries (the dropped surplus would have expired first anyway).
func (m *InMemory) IncrementAndGet(_ context.Context, key string, windowSec, maxEntries int) (int64, error) {
	// An overflowing windowSec would wrap the cutoff and silently reset the counter
	// (fail-open); checkMaxEntries rejects a non-positive cap the same way.
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

	// Remove expired timestamps in place, oldest-first order preserved; a weighted key's
	// magnitudes are pruned in lockstep (pruneInWindow).
	valid, validWeights, weighted := pruneInWindow(e, cutoff)

	// Add current timestamp; a counting call against a key that also carries magnitudes
	// contributes weight 1 — the weight at which a total is a count.
	valid, validWeights = appendCall(valid, validWeights, now, 1, weighted)

	valid, validWeights = trimOldest(valid, validWeights, maxEntries)

	storeEntry(e, valid, validWeights, weighted)

	return int64(len(valid)), nil
}

// isWeighted reports whether an entry tracks a magnitude per timestamp — the one spelling
// of the weights invariant every path asks.
func isWeighted(e *entry) bool { return e.weights != nil && len(e.weights) == len(e.timestamps) }

// appendCall appends one call at now; a weighted entry also appends the magnitude. weighted
// is passed in by the caller so a mid-life transition is decided once, not re-derived here.
func appendCall(ts []time.Time, weights []float64, now time.Time, weight float64, weighted bool) (outTS []time.Time, outWeights []float64) {
	ts = append(ts, now)
	if weighted {
		weights = append(weights, weight)
	}
	return ts, weights
}

// trimOldest keeps the newest n entries, dropping the surplus from the front. The copy is
// a forward shift (dst index < src index), so it is safe despite the overlap.
func trimOldest(ts []time.Time, weights []float64, n int) (outTS []time.Time, outWeights []float64) {
	if len(ts) <= n {
		return ts, weights
	}
	drop := len(ts) - n
	ts = ts[:copy(ts, ts[drop:])]
	if len(weights) > 0 {
		weights = weights[:copy(weights, weights[drop:])]
	}
	return ts, weights
}

// storeEntry compacts and writes the pair back to e, the one place the weights invariant is
// established; weighted is passed in since an aged-out entry's empty slice looks like nil.
func storeEntry(e *entry, ts []time.Time, weights []float64, weighted bool) {
	// Compaction must reallocate both slices on the SAME predicate, or a compacted
	// timestamp slice would sit beside an uncompacted weights slice, breaking the invariant.
	if shouldCompact(cap(ts), len(ts)) {
		compact := make([]time.Time, len(ts))
		copy(compact, ts)
		ts = compact
		if weighted {
			cw := make([]float64, len(weights))
			copy(cw, weights)
			weights = cw
		}
	}
	e.timestamps = ts
	if weighted {
		// Never nil for a weighted entry: an emptied one keeps a zero-length slice so it
		// stays weighted across a window it fully aged out of.
		if weights == nil {
			weights = []float64{}
		}
		e.weights = weights
	}
}

// compactMinCap is the smallest capacity worth reclaiming; below it the wasted memory is
// trivial and the copy would only add churn.
const compactMinCap = 64

// shouldCompact is the one reclamation predicate both the timestamp and weighted paths
// share. Uses length < capacity/4 rather than length*4 < capacity, which overflows int on
// 32-bit past length > 2^29.
func shouldCompact(capacity, length int) bool {
	return capacity > compactMinCap && length < capacity/4
}

// pruneInWindow drops expired timestamps in place, oldest-first; survives iff strictly
// after cutoff (matching Redis's ZREMRANGEBYSCORE "<= cutoff is expired" bound). Weights
// are pruned in LOCKSTEP so the two slices can never diverge.
func pruneInWindow(e *entry, cutoff time.Time) (ts []time.Time, weights []float64, weighted bool) {
	weighted = isWeighted(e)
	valid := e.timestamps[:0]
	var validWeights []float64
	if weighted {
		validWeights = e.weights[:0]
	}
	for i, ts := range e.timestamps {
		if !ts.After(cutoff) {
			continue
		}
		valid = append(valid, ts)
		if weighted {
			validWeights = append(validWeights, e.weights[i])
		}
	}
	return valid, validWeights, weighted
}

// floorToMicro floors t to microsecond precision, matching Redis's UnixMicro scores.
// Subtracts the remainder rather than time.Truncate, which would strip the monotonic reading.
func floorToMicro(t time.Time) time.Time {
	return t.Add(-time.Duration(t.Nanosecond() % 1000))
}

// retryAfterForWeight estimates how long until `needed` weight ages out — the weighted
// analogue of retryAfterFromPivot. Advisory only; returns 0 when nothing can free enough.
func retryAfterForWeight(valid []time.Time, weights []float64, needed float64, window time.Duration, now time.Time) time.Duration {
	if needed <= 0 {
		return 0
	}
	freed := 0.0
	for i, ts := range valid {
		freed += weights[i]
		if freed >= needed {
			if r := ts.Add(window).Sub(now); r > 0 {
				return r
			}
			return 0
		}
	}
	return 0
}

// AdmitAll admits against several quota buckets atomically under one lock, all-or-nothing,
// closing the multi-bucket TOCTOU a per-bucket admission would leave. See capability.CallCounter.
func (m *InMemory) AdmitAll(_ context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	// Validate and fail closed before touching state: a duplicate bucket would let the
	// commit loop silently overwrite one entry. checkBuckets is shared with Redis.
	if e := checkBuckets(buckets); e != nil {
		return false, 0, 0, 0, e
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := floorToMicro(m.now())

	// Each bucket keys a distinct window-namespaced entry; checkDistinctBuckets already
	// failed closed on any collision, so storage keys within a batch never collide.
	type bucketState struct {
		// b is the bucket this state belongs to, held directly so later loops don't
		// re-associate it by index.
		b        *capability.QuotaBucket
		sk       string
		e        *entry // nil until the bucket's first admitted call
		valid    []time.Time
		weights  []float64
		weighted bool // this key already carries per-entry weights
		window   time.Duration
		cur      float64
		// Filled in by the commit pre-pass, once every bucket is known to have headroom.
		post          float64
		record        bool // this bucket's call moves the total, so it is written
		writeWeighted bool // the write carries weights (this key, or this bucket, is weighted)
	}
	states := make([]bucketState, len(buckets))
	blocked := -1
	for i := range buckets {
		b := &buckets[i]
		window := time.Duration(b.WindowSec) * time.Second
		cutoff := now.Add(-window)
		st := bucketState{b: b, sk: storageKey(b.Key, b.WindowSec), window: window}
		if e, ok := m.entries[st.sk]; ok {
			// Prune and write back now: idempotent maintenance also done on the single-key
			// paths, safe before the admit decision and on the deny path.
			valid, validWeights, weighted := pruneInWindow(e, cutoff)
			storeEntry(e, valid, validWeights, weighted)
			st.e, st.valid, st.weights, st.weighted = e, e.timestamps, e.weights, weighted
			st.cur = bucketTotal(b.Counted, e.timestamps, e.weights)
		}
		states[i] = st
		// Report the FIRST bucket without headroom, not the longest retry-after: the caller
		// retries when this frees and is denied again by a still-blocking sibling.
		if blocked < 0 && st.cur+bucketWeight(b) > b.Limit {
			blocked = i
		}
	}

	if blocked >= 0 {
		// At least one bucket is full: record nothing new (already pruned above) and
		// report it with the same retry-after estimate its single-bucket sibling gives.
		st := states[blocked]
		return false, blocked, st.cur, bucketRetryAfter(st.b, st.valid, st.weights, st.cur, st.window, now), nil
	}

	// Every bucket has headroom → commit all. Resolve ONCE what each would do so the entry
	// ceilings below and the commit loop cannot disagree about which buckets write.
	var maxTotal float64
	newKeys := 0
	for i := range states {
		st := &states[i]
		st.post = st.cur + bucketWeight(st.b)
		// A weight that cannot move the total is admitted WITHOUT being recorded — it can
		// never affect a future decision, and recording it would grow a key without bound.
		st.record = st.post != st.cur
		// This key is weighted from here on if it was before OR this bucket is weighted.
		st.writeWeighted = st.weighted || !st.b.Counted
		if st.record && st.e == nil {
			// Counted only for a bucket that will actually WRITE: a zero-weight call on an
			// unseen key records nothing, so charging maxKeys here would create a phantom.
			newKeys++
		}
		// Report the max post-admission total across buckets per the capability.CallCounter
		// contract — the bucket closest to its limit, the most useful figure.
		if st.post > maxTotal {
			maxTotal = st.post
		}
	}

	// Both ceilings are checked against the WHOLE batch before any bucket writes, so the
	// commit stays all-or-nothing against them too, not just the quota.
	if m.maxKeys > 0 && len(m.entries)+newKeys > m.maxKeys {
		return false, 0, 0, 0, m.errEntryLimit()
	}
	for i := range states {
		st := &states[i]
		// Gated on the BUCKET's own accounting, not the key's current format: a counted
		// bucket's own limit is its retention (mirrors the Lua script's `counted ~= 1`
		// gate), so it must not be bound by a weighted ceiling on a key another bucket
		// happened to leave in weighted format — that would cap maxCalls at a bound no
		// operator wrote.
		if st.record && !st.b.Counted && m.maxWeightedEntries > 0 &&
			len(st.valid) >= m.maxWeightedEntries {
			return false, 0, 0, 0, m.errWeightedEntryLimit()
		}
	}

	for i := range states {
		st := &states[i]
		if !st.record {
			continue
		}
		e := st.e
		if e == nil {
			e = &entry{windowSec: st.b.WindowSec}
			m.entries[st.sk] = e
			st.e = e
		}
		ts, weights := e.timestamps, e.weights
		if st.writeWeighted && len(weights) != len(ts) {
			// A key that had only counted calls has an implicit weight of 1 for each,
			// which materializing now makes explicit so later prunes and sums stay exact.
			weights = make([]float64, len(ts))
			for j := range weights {
				weights[j] = 1
			}
		}
		ts, weights = appendCall(ts, weights, now, bucketWeight(st.b), st.writeWeighted)
		storeEntry(e, ts, weights, st.writeWeighted)
	}
	return true, 0, maxTotal, 0, nil
}

// bucketWeight is what one call contributes: one entry for counted, its declared magnitude
// for weighted. The single spelling so admit, commit, and retry-estimate cannot disagree.
func bucketWeight(b *capability.QuotaBucket) float64 {
	if b.Counted {
		return 1
	}
	return b.Weight
}

// bucketTotal reads a bucket's current in-window total under its own accounting: the entry
// count (O(1)) for a counted bucket, the weight sum (O(n)) for a weighted one.
func bucketTotal(counted bool, ts []time.Time, weights []float64) float64 {
	if counted {
		return float64(len(ts))
	}
	if len(weights) != len(ts) {
		// A key that has only ever taken counted calls carries no per-entry weights; each
		// of those calls weighed exactly 1, so its total is its count.
		return float64(len(ts))
	}
	return weightedTotal(weights)
}

// bucketRetryAfter estimates when a blocked bucket frees enough for THIS call. Advisory;
// the caller clamps and falls back to the full window.
func bucketRetryAfter(b *capability.QuotaBucket, valid []time.Time, weights []float64, cur float64, window time.Duration, now time.Time) time.Duration {
	if b.Counted {
		// Counting: the last entry to age out is at index cur-limit, read directly rather
		// than walked. Redis takes the same rank pivot for a counted bucket.
		return retryAfterFromPivot(valid, int64(cur), int64(b.Limit), window, now)
	}
	// Below the counted branch, which never reads it.
	needed := cur + bucketWeight(b) - b.Limit
	if len(weights) != len(valid) {
		// Weighted bucket over a key that holds only counted entries: each weighs 1.
		weights = make([]float64, len(valid))
		for i := range weights {
			weights[i] = 1
		}
	}
	return retryAfterForWeight(valid, weights, needed, window, now)
}

// Peek returns the in-window call count WITHOUT recording one — a pure observation must
// not mutate state, or checking "has A run?" while evaluating B would register a call.
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

	// Floor to microsecond precision to match recorded timestamps and Redis; without it a
	// boundary disagreement could fail-open a sequenceBlock gate.
	cutoff := floorToMicro(m.now()).Add(-time.Duration(windowSec) * time.Second)
	var count int64
	for _, ts := range e.timestamps {
		if ts.After(cutoff) {
			count++
		}
	}
	return count, nil
}

// retryAfterFromPivot estimates when the count next drops below limit at valid[cur-limit]
// (kept int64 since a limit may reach 1<<53). Advisory only, so an unsorted test clock is
// tolerated rather than guarded against.
func retryAfterFromPivot(valid []time.Time, cur, limit int64, window time.Duration, now time.Time) time.Duration {
	if idx := cur - limit; idx >= 0 && idx < int64(len(valid)) {
		if r := valid[idx].Add(window).Sub(now); r > 0 {
			return r
		}
	}
	return 0
}

// StartCleanup launches a background goroutine calling Cleanup on every interval tick
// until ctx is canceled; idempotent (cleanupMu-guarded, first call wins) and can restart
// after a prior context was canceled, unlike a fired sync.Once.
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
		// Still live: idempotent no-op. Already canceled: wait for it to exit, then fall
		// through to start fresh, so the restart is never lost.
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

// cleanupDeleteBatch bounds stale-key deletes per lock acquisition, so a sweep never
// stalls concurrent IncrementAndGet/Peek callers longer than O(batch).
const cleanupDeleteBatch = 256

// shouldDeleteEntry reports whether e may be reclaimed: no timestamps, or its most-recent
// one older than cleanupMarginFactor*window (mirroring Redis's key TTL) — keyed to the
// entry's own window so a live long-window quota is never wiped mid-window.
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
	// Use <= (!After), not strict <, so an entry exactly staleAfter old is deleted this
	// sweep, matching Redis's TTL eviction at-or-after the boundary.
	return !latest.After(now.Add(-staleAfter))
}

// Cleanup removes entries that can no longer affect any decision, in two phases so it
// never holds the lock for the whole pass; staleness is re-checked before each delete.
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
			// Both guards matter: `ok` skips a key already deleted since phase 1; the
			// repeated shouldDeleteEntry skips one a concurrent write has revived.
			if e, ok := m.entries[key]; ok && shouldDeleteEntry(e, now) {
				delete(m.entries, key)
			}
		}
		m.mu.Unlock()
	}
}
