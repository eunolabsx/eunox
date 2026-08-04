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

// checkDistinctBuckets rejects a batch with a repeated (Key, WindowSec) pair: two buckets
// sharing one physical storage key would silently drop one or double-count instead.
func checkDistinctBuckets(buckets []capability.QuotaBucket) error {
	// storageKey is injective over (Key, WindowSec), so a collision here is exactly a
	// duplicate bucket.
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

// checkBuckets validates an AdmitAll batch before either backend touches storage — the
// single source of the batch preamble InMemory and Redis AdmitAll share, so both fail
// closed identically.
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
			// A counted bucket's LIMIT is a number of CALLS — checkTotalLimit alone only
			// bounds the range, not integrality.
			if e := checkCountedLimit(buckets[i].Limit); e != nil {
				return e
			}
			continue
		}
		if e := checkWeight(buckets[i].Weight); e != nil {
			return e
		}
	}
	return checkDistinctBuckets(buckets)
}

// cleanupMarginFactor is the reclaim margin (in window multiples) both InMemory.Cleanup
// and Redis's key TTL use; MaxWindowSeconds divides by it to stay in lockstep.
const cleanupMarginFactor = 2

// MaxWindowSeconds is the largest windowSec accepted: beyond it, windowSec*cleanupMarginFactor
// overflows time.Duration and wraps the quota's cutoff open. math.MaxInt bounds it on 32-bit.
const MaxWindowSeconds = min(
	math.MaxInt64/(cleanupMarginFactor*int64(time.Second)),
	math.MaxInt,
)

// MaxEntries is the largest retention cap accepted: above it, the Redis trim's
// -(maxEntries+1) can wrap through int overflow and silently become a no-op.
const MaxEntries = math.MaxInt32

// MaxWeightedEntriesPerKey bounds live entries per weighted (key, window) in both
// backends: unlike a counted bucket (whose limit IS its retention), a caller-controlled
// magnitude could otherwise grow one key — and its O(n) re-sum cost — without bound.
const MaxWeightedEntriesPerKey = 100_000

// checkWindowSec rejects a non-positive or over-MaxWindowSeconds window before duration
// arithmetic runs, so an out-of-range value fails closed rather than overflowing the counter.
func checkWindowSec(windowSec int) error {
	if windowSec < 1 {
		return fmt.Errorf("callcounter: windowSec must be >= 1, got %d", windowSec)
	}
	if int64(windowSec) > MaxWindowSeconds {
		return fmt.Errorf("callcounter: windowSec %d exceeds maximum %d seconds (overflows time.Duration)", windowSec, MaxWindowSeconds)
	}
	return nil
}

// checkMaxEntries rejects a non-positive cap rather than treating it as "unbounded":
// an unbounded in-window slice is a heap-growth sink no real caller needs.
func checkMaxEntries(maxEntries int) error {
	if maxEntries < 1 {
		return fmt.Errorf("callcounter: maxEntries must be >= 1, got %d", maxEntries)
	}
	if maxEntries > MaxEntries {
		return fmt.Errorf("callcounter: maxEntries must be <= %d, got %d", MaxEntries, maxEntries)
	}
	return nil
}

// MaxWeightedTotal re-exports the contract's bound from pkg/capability, so the engine can
// apply it without importing a backend package.
const MaxWeightedTotal = capability.MaxWeightedTotal

// checkWeight rejects NaN/Inf (poisons comparisons fail-open), negative (would let a
// caller refund its own quota), and over-MaxWeightedTotal weights; zero is admitted.
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

// checkCountedLimit rejects a counted bucket's limit below 1 (a misconfiguration, distinct
// from an exhausted quota) or fractional (which would deny on InMemory but fault Redis's
// ZRANGE retry-after pivot, `total - limit`).
func checkCountedLimit(limit float64) error {
	if limit < 1 {
		return fmt.Errorf("callcounter: counted bucket limit must be >= 1, got %v", limit)
	}
	if limit != math.Trunc(limit) {
		return fmt.Errorf("callcounter: counted bucket limit must be a whole number of calls, got %v", limit)
	}
	return nil
}

// checkTotalLimit rejects a non-positive, NaN/Inf, or over-MaxWeightedTotal limit as a
// structured misconfiguration error, distinct from an exhausted-budget denial.
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
