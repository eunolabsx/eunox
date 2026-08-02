// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package callcounter provides a sliding-window call counter for rate limiting.
package callcounter

import (
	"fmt"
	"math"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// checkDistinctBuckets reports an error if any (Key, WindowSec) pair repeats in an
// AdmitAll batch. Two buckets sharing a (Key, WindowSec) resolve to one physical storage
// key; committing both would either silently drop one (InMemory's map overwrite — a
// fail-open under-count) or double-count into one set (Redis), so the two backends would
// diverge. The in-product caller never produces a colliding batch (the manifest loader
// rejects two quota conditions on one constraint sharing a bucket), so this is a shared
// fail-closed guard for a direct pkg/callcounter consumer passing the unsupported input.
func checkDistinctBuckets(buckets []capability.QuotaBucket) error {
	// Key on storageKey(Key, WindowSec) — the exact physical key the InMemory backend
	// commits each bucket under, and injective over the pair (the window is a trailing
	// ":<decimal>" with no embedded colon). So a storageKey collision is precisely a
	// duplicate bucket, with no over- or under-rejection.
	seen := make(map[string]struct{}, len(buckets))
	for i := range buckets {
		sk := storageKey(buckets[i].Key, buckets[i].WindowSec)
		if _, dup := seen[sk]; dup {
			return fmt.Errorf("callcounter: AdmitAll received duplicate (key, windowSec) buckets")
		}
		seen[sk] = struct{}{}
	}
	return nil
}

// checkBuckets validates an AdmitAll batch before either backend touches storage, so a
// malformed batch fails closed identically on both. It rejects an empty batch, any
// out-of-range window, weight or limit, and a duplicate bucket. It is the single source of
// the batch preamble the InMemory and Redis AdmitAll share, so the two cannot drift.
func checkBuckets(buckets []capability.QuotaBucket) error {
	if len(buckets) == 0 {
		return fmt.Errorf("callcounter: AdmitAll requires at least one bucket")
	}
	// Validate every bucket and fail closed before touching state: a misconfigured
	// window/weight/limit must not create a phantom entry or admit a partial set.
	for i := range buckets {
		if e := checkWindowSec(buckets[i].WindowSec); e != nil {
			return e
		}
		if e := checkTotalLimit(buckets[i].Limit); e != nil {
			return e
		}
		if buckets[i].Counted {
			// A counted bucket contributes exactly one entry, so its weight is not read;
			// its LIMIT must still be a whole number of calls the backends can compare
			// exactly, which checkTotalLimit's range already guarantees.
			continue
		}
		if e := checkWeight(buckets[i].Weight); e != nil {
			return e
		}
	}
	return checkDistinctBuckets(buckets)
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

// MaxWeightedTotal re-exports the contract's bound so a backend guard reads it beside the
// other backend limits. It lives in pkg/capability because the CallCounter contract that
// documents it does, and because the ENGINE has to apply the same bound to a resolved
// magnitude before handing it to a backend — and the engine must not import a backend
// package to learn what its own contract promises.
const MaxWeightedTotal = capability.MaxWeightedTotal

// checkWeight guards one call's contribution to a weighted total. A NaN or infinite
// weight is rejected rather than added: NaN poisons every later comparison into false
// (which admits forever — the fail-OPEN direction), and an infinity saturates the total so
// nothing is ever admitted again. A negative weight is rejected because a magnitude is
// non-negative by construction and a negative one would let a caller REFUND its own
// consumed quota, which is the bypass a cumulative bound exists to close. A weight above
// MaxWeightedTotal cannot be summed exactly and is refused rather than rounded.
//
// Zero IS admitted: a genuinely zero-magnitude action consumes no budget, and the
// alternative — refusing it — would deny a call the policy considers weightless.
func checkWeight(weight float64) error {
	if math.IsNaN(weight) || math.IsInf(weight, 0) {
		return fmt.Errorf("callcounter: weight must be a finite number, got %v", weight)
	}
	if weight < 0 {
		return fmt.Errorf("callcounter: weight must not be negative, got %v", weight)
	}
	if weight > MaxWeightedTotal {
		return fmt.Errorf("callcounter: weight must be <= %v (the largest value both backends represent exactly), got %v", MaxWeightedTotal, weight)
	}
	return nil
}

// checkTotalLimit guards the AddIfTotalBelow admission threshold, mirroring checkLimit.
// A non-positive limit can never admit anything with a positive weight, but that is a
// misconfiguration rather than an exhausted budget and the two must stay distinguishable:
// a structured error lets the caller surface and audit it instead of reading it as
// "cumulative bound reached".
func checkTotalLimit(limit float64) error {
	if math.IsNaN(limit) || math.IsInf(limit, 0) {
		return fmt.Errorf("callcounter: total limit must be a finite number, got %v", limit)
	}
	if limit <= 0 {
		return fmt.Errorf("callcounter: total limit must be > 0, got %v", limit)
	}
	if limit > MaxWeightedTotal {
		return fmt.Errorf("callcounter: total limit must be <= %v (the largest value both backends represent exactly), got %v", MaxWeightedTotal, limit)
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
