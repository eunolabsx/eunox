// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import "time"

// This file holds test-only shims over the real admission/outcome API. They keep
// synchronous, single-probe driving conveniences out of the production Breaker
// surface: allowReq, markSuccess, markFailure, and reset had no production caller
// (production drives the breaker exclusively through allowProbe/Do and, on recovery,
// through the half-open probe cycle). Being in a _test.go file, none of this compiles
// into the production binary.

// allowReq admits a request and discards the probe, for tests that assert only on
// admission (a discarded half-open probe keeps its reserved slot, matching a caller
// that never reports). Production admits through allowProbe/Do.
func (b *Breaker) allowReq() bool {
	admitted, _ := b.allowProbe()
	return admitted
}

// markSuccess reports a success against the CURRENT half-open generation, so a
// synchronous single-probe test can drive an outcome without threading a probe
// through. Reading the live generation is exactly what a freshly admitted probe
// carries, so this matches the probe path for the synchronous case.
func (b *Breaker) markSuccess() {
	b.recordSuccess(b.currentGen())
}

// markFailure is the failure counterpart of markSuccess, reporting against the
// current half-open generation.
func (b *Breaker) markFailure() {
	b.recordFailure(b.currentGen())
}

// currentGen reads the live half-open generation under the read lock.
func (b *Breaker) currentGen() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.halfOpenGen
}

// reset forces the breaker back to closed state and clears failure counters. It has
// no production caller (the breaker recovers through the half-open probe cycle), so
// it lives here as a test-only helper.
func (b *Breaker) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.state = StateClosed
	b.consecutiveFails = 0
	b.lastFailureTime = time.Time{}
	b.halfOpenProbes = 0
	b.halfOpenSuccess = 0
	// Bump the generation so any in-flight probe from before this reset reports a
	// stale (dropped) outcome rather than perturbing the reset breaker.
	b.halfOpenGen++
	b.lastTransitionAt = b.now()
}
