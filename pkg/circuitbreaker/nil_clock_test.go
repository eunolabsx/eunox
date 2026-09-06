// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eunolabs/eunox/pkg/circuitbreaker"
)

// New replaces every non-positive Config field with its default rather than failing; a clock
// option holding no value takes the same treatment. b.now() is read only once a failure has
// been recorded, so a nil panicked inside the outage this breaker exists to survive.
func TestNew_ValuelessClockLeavesTheDefault(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig(), circuitbreaker.WithClock(nil))
	boom := errors.New("upstream down")
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		_, _ = circuitbreaker.Do(ctx, b, func(context.Context) (int, error) { return 0, boom })
	}
	if b.State() == circuitbreaker.StateClosed {
		t.Fatal("ten consecutive failures must move the breaker off closed")
	}
}
