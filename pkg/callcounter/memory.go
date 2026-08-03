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

// entry tracks call timestamps for sliding-window counting. windowSec records the
// window this entry is counted with; the map is keyed by (key, windowSec), so it
// is fixed once the entry exists. Cleanup scales its staleness threshold off it so
// a still-live long-window counter (e.g. a weekly maxCalls quota) is never dropped
// mid-window.
type entry struct {
	timestamps []time.Time
	windowSec  int
	// weights carries one magnitude per timestamp for a key that has ever taken a
	// WEIGHTED admission (an AdmitAll bucket with Counted unset). It is nil for a pure
	// counting key, which is every
	// maxCalls and sequenceBlock key: a count needs no per-entry magnitude, and carrying
	// a parallel float64 slice for them would grow the in-memory footprint the threat
	// model bounds by a third for nothing.
	//
	// INVARIANT: len(weights) is either 0 or exactly len(timestamps). Once an entry
	// becomes weighted it stays weighted, and the counting paths append an implicit 1 so
	// the two slices never diverge — a short weights slice would silently under-count a
	// total, the fail-open direction. pruneInWindow drops from both in lockstep.
	weights []float64
}

// weightedTotal sums live weights, oldest-first — matching the Redis backend's
// score-ordered scan, so the two backends accumulate the same IEEE-754 double from the same
// sequence. An empty set totals zero.
//
// It takes only the weights: the commit materializes an implicit 1 per counted call before
// calling this, so the "no weights means every entry weighs one" fallback could never be
// reached and advertised a contract no caller exercised.
func weightedTotal(liveWeights []float64) float64 {
	total := 0.0
	for _, w := range liveWeights {
		total += w
	}
	return total
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
	// maxKeys bounds how many (key, window) STORAGE ENTRIES the map may hold at once
	// -- not logical keys; 0 (the default) leaves it unbounded. See WithMaxKeys and
	// admitNewKey.
	maxKeys int
	// maxWeightedEntries bounds the live entries ONE storage entry may hold under
	// weighted accounting. Defaults to MaxWeightedEntriesPerKey; the option that
	// lowers it is test-only, because this is a package invariant both backends
	// enforce identically rather than an operator knob.
	maxWeightedEntries int

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

// WithMaxKeys bounds the number of STORAGE ENTRIES the counter holds at once,
// capping the heap the map can consume between Cleanup cycles when unique keys
// arrive faster than Cleanup reclaims them (the fresh-session-per-request case;
// see NewInMemory). Once the map holds n entries, a call under a *new* entry is
// refused with an error; both callers treat that fail-closed (maxCalls denies the
// call, and the sequenceBlock recorder surfaces it so the engine denies). The cost
// at the ceiling is availability — a new-entry call is denied (CONDITION_FAILED)
// while the map is full — not a bypass; existing entries keep counting and one
// reclaimed by Cleanup frees a slot. A value <= 0 (the default) is unbounded.
//
// The unit is the (key, window) pair the map is keyed by (see storageKey), NOT the
// logical key: a tool counted under two distinct maxCalls windows occupies two of
// the n slots, so the ceiling is reached after n/windows logical keys, sooner than
// a "distinct keys" reading of n would predict. Size the bound against the entry
// count, not the key count.
func WithMaxKeys(n int) InMemoryOption {
	return func(m *InMemory) {
		m.maxKeys = n
	}
}

// withMaxWeightedEntries lowers the per-key weighted retention ceiling from
// MaxWeightedEntriesPerKey. Unexported on purpose: the ceiling is a package invariant
// both backends enforce identically, not an operator knob, and an operator who could
// raise it would re-open the growth it exists to bound. Tests use it to reach the
// ceiling without writing 100k entries.
func withMaxWeightedEntries(n int) InMemoryOption {
	return func(m *InMemory) {
		m.maxWeightedEntries = n
	}
}

// NewInMemory creates an in-memory sliding-window call counter.
//
// The entry set is unbounded by default: every distinct (session, tool, window)
// combination is one map entry, reclaimed only when Cleanup runs. A deployment that
// mints a fresh session per request (short-lived HTTP connections with UUID
// Mcp-Session-Id) thus peaks at one entry per unique session per window at the
// cleanup boundary, which a caller driving unique IDs can push arbitrarily high. For
// such deployments prefer the Redis backend (per-key TTL, off-heap) or pass
// WithMaxKeys to bound the count.
//
// Quota size is a second, orthogonal heap concern, and the two accountings differ. A
// COUNTED bucket retains up to its limit in timestamps per (key, window) — no separate
// retention cap, the bound IS the quota — so a large maxCalls.count favours Redis. A
// WEIGHTED bucket has no such implicit bound: its total is the sum of caller-supplied
// magnitudes, so arbitrarily many sub-threshold entries fit under one limit. That set
// is bounded by MaxWeightedEntriesPerKey instead, which refuses the commit rather than
// growing the key (and the per-admission re-sum) without limit.
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

// admitNewKey returns an error when inserting a previously-unseen (key, window)
// storage entry would push the live entry count past maxKeys; nil when the set is
// unbounded (maxKeys <= 0) or has room. Call under m.mu and only on the new-entry
// path (an existing entry grows the map by nothing). This is the fail-closed
// backstop for the unbounded-map growth described on NewInMemory.
func (m *InMemory) admitNewKey() error {
	if m.maxKeys > 0 && len(m.entries) >= m.maxKeys {
		return m.errEntryLimit()
	}
	return nil
}

// errEntryLimit is the one entry-limit refusal, shared by the single-key admission above
// and the multi-bucket atomic commit's own count check — which needs a different
// PREDICATE (it admits several new keys at once) but must not grow a second spelling of
// the same refusal for a caller to have to match on.
func (m *InMemory) errEntryLimit() error {
	return fmt.Errorf("callcounter: entry limit reached (%d)", m.maxKeys)
}

// errWeightedEntryLimit is the per-key counterpart of errEntryLimit: the map has room,
// but ONE weighted (key, window) is holding as many live entries as it may. It names
// neither the key nor the session — an error reaches an operator through a denial
// message, and the key embeds identifiers the audit record carries in structured fields.
func (m *InMemory) errWeightedEntryLimit() error {
	return fmt.Errorf("callcounter: weighted entry limit reached (%d entries in one window)", m.maxWeightedEntries)
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
	// The slice stays in oldest-first order. A weighted key's magnitudes are pruned in
	// lockstep (pruneInWindow); a counting key has none.
	valid, validWeights, weighted := pruneInWindow(e, cutoff)

	// Add current timestamp (still the newest, so order is preserved). A counting call
	// against a key that ALSO carries magnitudes contributes weight 1 — the weight at
	// which a total is a count.
	valid, validWeights = appendCall(valid, validWeights, now, 1, weighted)

	// Cap to the most-recent maxEntries by dropping the oldest surplus from the front.
	valid, validWeights = trimOldest(valid, validWeights, maxEntries)

	// Reclaim the backing arrays if a past burst left them mostly empty.
	storeEntry(e, valid, validWeights, weighted)

	return int64(len(valid)), nil
}

// isWeighted reports whether an entry tracks a magnitude per timestamp. It is the one
// spelling of the weights invariant (nil, or exactly parallel), so every path that grows
// or shrinks the pair asks the same question.
func isWeighted(e *entry) bool { return e.weights != nil && len(e.weights) == len(e.timestamps) }

// appendCall appends one call at now to the pruned pair. A counting entry (nil weights)
// appends only the timestamp; a weighted one appends the magnitude too — which for a call
// arriving through one of the counting methods is 1, the weight that makes a total equal a
// count. Callers pass weighted so a mid-life transition to weighted is decided once, above,
// rather than re-derived from the possibly-emptied slices here.
func appendCall(ts []time.Time, weights []float64, now time.Time, weight float64, weighted bool) (outTS []time.Time, outWeights []float64) {
	ts = append(ts, now)
	if weighted {
		weights = append(weights, weight)
	}
	return ts, weights
}

// trimOldest keeps the newest n entries of the pair, dropping the surplus from the front.
// copy is a forward shift over each backing array (dst index < src index), so it is safe
// despite the overlap.
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

// storeEntry compacts and writes the pair back to e, keeping the weights invariant. Every
// mutating path ends here, so "weights is nil or exactly parallel" is established in one
// place rather than at each of the four sites that could break it.
//
// weighted is passed rather than re-derived: an entry that has fully aged out has an EMPTY
// weights slice, which is indistinguishable from a counting entry's nil one by length
// alone. Reverting such an entry to counting would make its next total a call count rather
// than a magnitude sum — a silent under-count for every weight above 1.
func storeEntry(e *entry, ts []time.Time, weights []float64, weighted bool) {
	// Compaction reallocates; the pair must be reallocated on the SAME predicate, or a
	// compacted timestamp slice would sit beside an uncompacted weights slice of a
	// different length, breaking the invariant every total depends on.
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

// compactMinCap is the smallest backing-array capacity worth reclaiming in
// compactTimestamps. Below it the wasted memory is trivial and the copy would
// only add churn to the common case of a key that never bursts.
const compactMinCap = 64

// shouldCompact is the reclamation predicate, factored out so the timestamp-only path and
// the weighted pair reclaim on exactly the same condition — a pair that compacted one
// slice and not the other would break the parallel-length invariant.
//
// length < capacity/4 rather than length*4 < capacity: the multiplication form overflows
// int on 32-bit platforms once length > 2^29, wrapping negative and firing the copy
// spuriously. The division form is equivalent (capacity/4 floors the threshold) and cannot
// overflow.
func shouldCompact(capacity, length int) bool {
	return capacity > compactMinCap && length < capacity/4
}

// pruneInWindow drops expired timestamps from e's backing array, reusing it in
// place ([:0] reslice), and returns the surviving slice in oldest-first order. A
// timestamp survives iff it is strictly after cutoff — the single source of the
// window-boundary predicate, so it cannot drift from the Redis backend's paired
// "<= cutoff is expired" ZREMRANGEBYSCORE bound. Callers append the new timestamp
// and/or compact as their path requires.
//
// A weighted entry's parallel weights are pruned in LOCKSTEP and returned alongside, so
// the two slices can never diverge: a weights slice that kept an expired entry's magnitude
// would over-count a total (denying calls a window has already freed), and one that lost a
// live entry's would under-count it (the fail-open direction). nil in, nil out, so a
// counting key pays nothing.
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

// retryAfterForWeight estimates how long until `needed` units of weight age out, so a
// refused call of a given magnitude would fit. It walks oldest-first, accumulating the
// weight each expiry would free, and returns when the entry that crosses `needed` leaves
// the window — the weighted analogue of retryAfterFromPivot's rank-(count-limit) pivot.
//
// Returns 0 when the estimate is non-positive or nothing in the window can free enough
// (a call whose own weight exceeds the whole limit never fits, however long the caller
// waits — the hint is advisory and must not promise otherwise). The caller clamps and
// falls back to the full window, so an imprecise hint carries no security weight.
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

// AdmitAll admits a call against several quota buckets atomically under a single lock: all
// buckets are recorded only when every one has headroom; otherwise nothing is recorded and
// the blocking bucket is reported. Holding m.mu across the whole check-and-commit closes
// the multi-bucket TOCTOU a per-bucket admission would leave.
//
// The batch may MIX accountings — a counted bucket (maxCalls) beside a weighted one (a
// cumulative blastRadius bound) — and that is the point: committing the two separately
// would let a call the second denies spend the first's budget. See the
// capability.CallCounter contract.
func (m *InMemory) AdmitAll(_ context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	// Validate the batch and fail closed before touching map state: a misconfigured
	// window/weight/limit must not create a phantom entry or admit a partial set, and a
	// duplicate bucket would let the commit loop below silently overwrite one entry (a
	// fail-open under-count that diverges from Redis). checkBuckets is shared with the
	// Redis backend so both reject the same inputs.
	if e := checkBuckets(buckets); e != nil {
		return false, 0, 0, 0, e
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := floorToMicro(m.now())

	// Each bucket keys a distinct window-namespaced entry (storageKey); checkDistinctBuckets
	// above fails the call closed if a caller passes colliding buckets, so the storage keys
	// within a committed batch never collide.
	type bucketState struct {
		// b is the bucket this state belongs to. Held here rather than re-indexed as
		// buckets[i] at each later loop: states is built one-per-bucket, so carrying the
		// pointer keeps the two from being re-associated by index three more times.
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
			// Prune expired entries and write back now: idempotent maintenance the
			// single-key paths also do on every call, so doing it before the admit decision
			// (and on the deny path) is safe and bounds storage.
			valid, validWeights, weighted := pruneInWindow(e, cutoff)
			storeEntry(e, valid, validWeights, weighted)
			st.e, st.valid, st.weights, st.weighted = e, e.timestamps, e.weights, weighted
			st.cur = bucketTotal(b.Counted, e.timestamps, e.weights)
		}
		states[i] = st
		// Report the FIRST bucket without headroom (by slice order), not the one with the
		// longest retry-after: the caller retries when this one frees and, if a tighter
		// sibling still blocks, is denied again with that sibling's hint.
		if blocked < 0 && st.cur+bucketWeight(b) > b.Limit {
			blocked = i
		}
	}

	if blocked >= 0 {
		// At least one bucket is full: record nothing new (each existing entry was already
		// pruned above) and report the blocking bucket with the same retry-after estimate
		// its single-bucket sibling gives.
		st := states[blocked]
		return false, blocked, st.cur, bucketRetryAfter(st.b, st.valid, st.weights, st.cur, st.window, now), nil
	}

	// Every bucket has headroom → commit all of them. Resolve ONCE what each bucket would
	// do — its post-admission total, whether that total moves at all, and whether the
	// write is weighted — so the two entry ceilings below and the commit loop after them
	// cannot disagree about which buckets write.
	var maxTotal float64
	newKeys := 0
	for i := range states {
		st := &states[i]
		st.post = st.cur + bucketWeight(st.b)
		// A weight that cannot move the total is admitted WITHOUT being recorded: it can
		// never affect a future decision, and recording it is the one case that would grow
		// a key without bound.
		st.record = st.post != st.cur
		// This key is weighted from here on if it was before OR this bucket is weighted.
		st.writeWeighted = st.weighted || !st.b.Counted
		if st.record && st.e == nil {
			// Counted only for a bucket that will actually WRITE. A zero-weight call on an
			// unseen key records nothing, so charging it against maxKeys (and denying on a
			// full map) would create a phantom the Redis backend never creates.
			newKeys++
		}
		// Report the max post-admission total across buckets (no single binding bucket on
		// the admit path) per the capability.CallCounter contract — the bucket closest to
		// its limit, the most useful figure for the caller.
		if st.post > maxTotal {
			maxTotal = st.post
		}
	}

	// Both entry ceilings are checked against the WHOLE batch before any bucket is
	// written, so the commit stays all-or-nothing against them the way it is against the
	// quota itself. maxKeys bounds the map; maxWeightedEntries bounds one weighted key,
	// whose entry count its own limit does not bound (see MaxWeightedEntriesPerKey).
	if m.maxKeys > 0 && len(m.entries)+newKeys > m.maxKeys {
		return false, 0, 0, 0, m.errEntryLimit()
	}
	for i := range states {
		st := &states[i]
		if st.record && st.writeWeighted && m.maxWeightedEntries > 0 &&
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

// bucketWeight is what one call contributes to a bucket: exactly one entry for a counted
// bucket, its declared magnitude for a weighted one. It is the single spelling of "maxCalls
// is this with every weight equal to 1", so the admit test, the commit and the retry
// estimate cannot disagree about it.
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

// bucketRetryAfter estimates when a blocked bucket frees enough for THIS call, under the
// bucket's own accounting. Advisory in both cases; the caller clamps and falls back to the
// full window.
func bucketRetryAfter(b *capability.QuotaBucket, valid []time.Time, weights []float64, cur float64, window time.Duration, now time.Time) time.Duration {
	needed := cur + bucketWeight(b) - b.Limit
	if b.Counted {
		// Counting: the last entry that must age out is at index cur-limit in oldest-first
		// order, which retryAfterFromPivot reads directly rather than walking. This does
		// NOT depend on whether the key also carries weights — cur is a COUNT for a
		// counted bucket, so measuring `needed` in calls and `freed` in weight would give
		// a hint in mismatched units on exactly the mixed key where the two differ. Redis
		// always takes the rank pivot for a counted bucket; this is that same rule.
		return retryAfterFromPivot(valid, int64(cur), int64(b.Limit), window, now)
	}
	if len(weights) != len(valid) {
		// Weighted bucket over a key that holds only counted entries: each weighs 1.
		weights = make([]float64, len(valid))
		for i := range weights {
			weights[i] = 1
		}
	}
	return retryAfterForWeight(valid, weights, needed, window, now)
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
// is out of range or the estimate is non-positive. The index is kept in int64 since
// int(cur-limit) truncates on 32-bit (a limit may reach MaxWeightedTotal, 1<<53).
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
