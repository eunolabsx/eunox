// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package callcounter provides a sliding-window call counter for rate limiting.
package callcounter

import (
	"fmt"
	"math"
	"time"
)

// checkDistinctBuckets reports an error if any (key, windowSec) pair repeats in an
// IncrementIfAllBelow batch. Two buckets sharing a (key, windowSec) resolve to one
// physical storage key; committing both would either silently drop one (InMemory's
// map overwrite — a fail-open under-count) or double-count into one set (Redis), so
// the two backends would diverge. The in-product caller never produces a colliding
// batch (validateMaxCallsWindowsDistinct rejects two maxCalls on one constraint
// sharing a window), so this is a shared fail-closed guard for a direct pkg/callcounter
// consumer passing the unsupported input — keeping both backends equivalent.
func checkDistinctBuckets(keys []string, windowSecs []int) error {
	// Key on storageKey(key, windowSec) — the exact physical key the InMemory backend
	// commits each bucket under, and injective over (key, windowSec) (the window is a
	// trailing ":<decimal>" with no embedded colon). So a storageKey collision is
	// precisely a duplicate (key, windowSec) bucket, with no over- or under-rejection.
	seen := make(map[string]struct{}, len(keys))
	for i := range keys {
		sk := storageKey(keys[i], windowSecs[i])
		if _, dup := seen[sk]; dup {
			return fmt.Errorf("callcounter: IncrementIfAllBelow received duplicate (key, windowSec) buckets")
		}
		seen[sk] = struct{}{}
	}
	return nil
}

// checkBatch validates an IncrementIfAllBelow batch before either backend touches
// storage, so a malformed batch fails closed identically on both. It rejects
// mismatched slice lengths, an empty batch, any out-of-range window/limit, and a
// duplicate (key, windowSec) bucket (via checkDistinctBuckets). It is the single
// source of the batch preamble the InMemory and Redis IncrementIfAllBelow share, so
// the two cannot drift.
func checkBatch(keys []string, windowSecs []int, limits []int64) error {
	if len(keys) != len(windowSecs) || len(keys) != len(limits) {
		return fmt.Errorf("callcounter: IncrementIfAllBelow slice lengths differ (%d/%d/%d)", len(keys), len(windowSecs), len(limits))
	}
	if len(keys) == 0 {
		return fmt.Errorf("callcounter: IncrementIfAllBelow requires at least one bucket")
	}
	// Validate every bucket and fail closed before touching state: a misconfigured
	// window/limit must not create a phantom entry or admit a partial set.
	for i := range keys {
		if e := checkWindowSec(windowSecs[i]); e != nil {
			return e
		}
		if e := checkLimit(limits[i]); e != nil {
			return e
		}
	}
	// Reject duplicate (key, windowSec) buckets up front: two buckets sharing a
	// physical storage key cannot be committed consistently, so fail closed on both
	// backends rather than silently drop (InMemory) or double-count (Redis).
	return checkDistinctBuckets(keys, windowSecs)
}

// cleanupMarginFactor is the multiple of a window after which a counter's state
// can be safely reclaimed: InMemory.Cleanup drops an entry once its newest
// timestamp is older than windowSec*cleanupMarginFactor, and Redis sets the key
// TTL to the same. MaxWindowSeconds divides by this same factor, so widening the
// margin re-derives the overflow bound in lockstep rather than leaving it stale.
const cleanupMarginFactor = 2

// MaxWindowSeconds is the largest windowSec any backend accepts. Both compute a
// cleanup/TTL margin of windowSec*cleanupMarginFactor*time.Second; since
// time.Duration is int64 nanoseconds, a larger windowSec overflows that product,
// wraps to a tiny/negative duration, and lands the cutoff (or TTL) at/after "now"
// — every call reads as the first in its window and the quota fails open.
// ~4.6e9 seconds (~146 years) is beyond any real window, so rejecting more costs
// nothing.
//
// The min with math.MaxInt keeps the constant representable as the int windowSec
// is passed as: on 64-bit the overflow bound binds; on 32-bit math.MaxInt binds
// and is the true max (a 32-bit windowSec can't exceed it, and the margin still
// can't overflow). Without it, int(MaxWindowSeconds) would truncate on 32-bit.
const MaxWindowSeconds = min(
	math.MaxInt64/(cleanupMarginFactor*int64(time.Second)),
	math.MaxInt,
)

// MaxEntries is the largest retention cap any backend accepts. The Redis trim
// widens to int64 (-(int64(maxEntries)+1)) and is what actually prevents overflow;
// this cap exists so checkMaxEntries does not accept math.MaxInt, where the older
// int-width -(maxEntries+1) wrapped through math.MinInt and turned the trim into a
// no-op. math.MaxInt32 (~2.1e9) dwarfs any real cap (sequenceBlock uses 1,
// maxCalls the quota).
const MaxEntries = math.MaxInt32

// MaxLimit is the largest admission threshold IncrementIfBelow accepts. The Redis
// Lua backend reads the limit via tonumber(), an IEEE-754 float64 exact only up to
// 2^53; a larger limit would be silently rounded to a threshold the caller never
// set. Capping at 2^53 keeps both backends' enforced threshold identical to the
// request and rejects out-of-range limits up front. No real quota approaches 2^53.
//
// Typed int64 (not an untyped constant): the limit > MaxLimit comparison takes
// int64 either way, but as a bare fmt.Errorf variadic argument an untyped 1<<53
// would default to int and fail to compile on 32-bit targets (GOARCH=386, arm,
// mips), where int is 32 bits. retryAfterFromPivot in memory.go already notes
// MaxLimit exceeds 32-bit int range; typing it here keeps every use site 32-bit-safe.
const MaxLimit int64 = 1 << 53

// checkWindowSec is the single guardrail both call-counter backends call before any
// duration arithmetic. It rejects a non-positive window (no meaningful span) and
// one above MaxWindowSeconds (which overflows time.Duration), so an out-of-range
// value fails closed at the backend — the engine surfaces the error and denies —
// rather than overflowing into a fail-open counter reset.
func checkWindowSec(windowSec int) error {
	if windowSec < 1 {
		return fmt.Errorf("callcounter: windowSec must be >= 1, got %d", windowSec)
	}
	if int64(windowSec) > MaxWindowSeconds {
		return fmt.Errorf("callcounter: windowSec %d exceeds maximum %d seconds (overflows time.Duration)", windowSec, MaxWindowSeconds)
	}
	return nil
}

// checkMaxEntries guards the IncrementAndGet retention cap. A non-positive cap is
// rejected (fail closed) rather than treated as "unbounded" — an unbounded
// in-window slice is the heap-growth sink, and no real caller needs one
// (sequenceBlock needs maxEntries=1, maxCalls uses IncrementIfBelow). A
// 0-means-unlimited escape hatch could silently re-open that sink.
func checkMaxEntries(maxEntries int) error {
	if maxEntries < 1 {
		return fmt.Errorf("callcounter: maxEntries must be >= 1, got %d", maxEntries)
	}
	if maxEntries > MaxEntries {
		return fmt.Errorf("callcounter: maxEntries must be <= %d, got %d", MaxEntries, maxEntries)
	}
	return nil
}

// checkLimit guards the IncrementIfBelow admission threshold. A limit<1 can never
// admit, but that denial is a misconfiguration, not an exhausted quota, and the
// two must be distinguishable: returning a structured error (rather than a silent
// nil denial reading as "rate limit exceeded") lets the caller surface and audit
// it. The manifest loader already rejects maxCalls.count<1; this guards direct
// library use that bypasses it.
func checkLimit(limit int64) error {
	if limit < 1 {
		return fmt.Errorf("callcounter: limit must be >= 1, got %d", limit)
	}
	if limit > MaxLimit {
		return fmt.Errorf("callcounter: limit must be <= %d (the largest integer the Redis Lua backend represents exactly as a float64), got %d", MaxLimit, limit)
	}
	return nil
}
