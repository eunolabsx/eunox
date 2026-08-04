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

	// Report exactly one outcome through the generation-bound probe so an overlapping
	// slow probe finishing after a reopen is dropped rather than counted toward the new
	// window.
	//
	// If fn panics, record a failure before the panic unwinds so a half-open breaker
	// re-opens instead of staying wedged with a spent-but-unreported probe. The panic
	// is not recovered.
	completed := false
	defer func() {
		if !completed {
			// fn panicked. Unlike a clean client cancellation (neutral, below), a panic
			// is a defect: record it as a failure so the panic propagates unchanged.
			pr.failure()
		}
	}()

	result, err := fn(ctx)
	completed = true
	if err != nil {
		if clientCanceled(ctx, err) {
			// A client-initiated cancellation is not evidence the upstream is unhealthy,
			// so a burst of cancels must not trip the breaker; drop it neutrally instead.
			// (DeadlineExceeded stays a failure — a persistently slow upstream must trip it.)
			pr.drop()
			return zero, err
		}
		pr.failure()
		return zero, err
	}

	pr.success()
	return result, nil
}

// clientCanceled reports whether err is a client-initiated cancellation, requiring both
// that err wraps context.Canceled AND the caller's own ctx was canceled — an upstream
// returning Canceled from its own context while ctx is still live is a real failure.
func clientCanceled(ctx context.Context, err error) bool {
	return errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled)
}
