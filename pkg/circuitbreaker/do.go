// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"context"
	"errors"
)

// Do executes fn only if the breaker allows it, recording success/failure from the
// returned error (nil = success). If the breaker is open it returns ErrOpen without
// calling fn. Context cancellation is respected.
//
// A nil b or nil fn panics: these are constructor-guard invariants that surface
// misuse at the call-site rather than silently misbehaving at runtime.
func Do[T any](ctx context.Context, b *Breaker, fn func(ctx context.Context) (T, error)) (T, error) {
	var zero T
	if b == nil {
		panic("circuitbreaker: breaker must not be nil")
	}
	if fn == nil {
		panic("circuitbreaker: fn must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return zero, err
	}

	admitted, pr := b.allowProbe()
	if !admitted {
		return zero, ErrOpen
	}

	// Report exactly one outcome through the generation-bound probe so that, with
	// overlapping probes (HalfOpenMaxProbes > 1), a slow probe finishing after a
	// reopen is dropped rather than counted toward closing the new window. A
	// closed-state admission reserves no slot, so a stale-generation drop of its
	// outcome is harmless either way.
	//
	// If fn panics, record a failure before the panic unwinds so a half-open breaker
	// re-opens instead of staying wedged with a spent-but-unreported probe (which would
	// reject all traffic indefinitely — at the default HalfOpenMaxProbes of 1 just as
	// much as above it, since one unreported probe fills a one-probe window). The panic
	// is not recovered.
	completed := false
	defer func() {
		if !completed {
			// fn panicked. Unlike a clean client cancellation (neutral, below), a panic
			// is a defect, so record it as a failure: this reports the mandatory single
			// outcome and re-opens a half-open breaker. The panic propagates unchanged.
			pr.failure()
		}
	}()

	result, err := fn(ctx)
	completed = true
	if err != nil {
		if clientCanceled(ctx, err) {
			// A client-initiated cancellation is not evidence the upstream is
			// unhealthy, so recording it as a failure would let a burst of cancels trip
			// the breaker on a healthy upstream. Report the neutral drop instead: it
			// reports exactly one outcome and frees the slot, but counts as neither
			// success nor failure. (context.DeadlineExceeded is left as a failure on
			// purpose — a persistently slow upstream must still trip the breaker.)
			pr.drop()
			return zero, err
		}
		pr.failure()
		return zero, err
	}

	pr.success()
	return result, nil
}

// clientCanceled reports whether err is a client-initiated cancellation that must
// not count as an upstream failure. It requires both that err wraps context.Canceled
// AND that the caller's own ctx was canceled: an upstream returning context.Canceled
// from its own context while the caller's ctx is still live is an upstream failure
// and must count. context.DeadlineExceeded does not qualify — it is the request
// timeout, an upstream-health signal that must trip the breaker.
func clientCanceled(ctx context.Context, err error) bool {
	return errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled)
}
