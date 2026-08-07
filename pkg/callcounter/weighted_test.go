// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter_test

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
)

// The weighted sliding-window sum behind the cumulative blastRadius bound. Both backends
// are driven through the SAME table, because the property that matters is that they agree:
// a budget that admits on one replica and denies on another is not a budget.

// weightedBackends returns the two production backends under one clock, so a table test
// exercises both without repeating itself. The Redis backend runs against miniredis.
func weightedBackends(t *testing.T, now func() time.Time) map[string]capability.CallCounter {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return map[string]capability.CallCounter{
		"memory": callcounter.NewInMemory(callcounter.WithTimeFunc(now)),
		"redis":  callcounter.NewRedisForTest(t, client, callcounter.WithRedisTimeFunc(now)),
	}
}

// TestAdmitWeighted_SumsMagnitudes is the case the whole feature exists for: four hundred
// individually-permitted small actions, each legal, whose AGGREGATE is the problem. Here
// the budget is 100 and every call is 30 — three admit, the fourth does not, and no per-call
// bound would have caught it.
func TestAdmitWeighted_SumsMagnitudes(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for i := 1; i <= 3; i++ {
				total, admitted, _, err := admitWeighted(ctx, c, "refunds", 3600, 30, 100)
				require.NoError(t, err)
				assert.True(t, admitted, "call %d of 30 against a budget of 100 must be admitted", i)
				assert.InDelta(t, float64(30*i), total, 1e-9)
			}
			total, admitted, retryAfter, err := admitWeighted(ctx, c, "refunds", 3600, 30, 100)
			require.NoError(t, err)
			assert.False(t, admitted, "the fourth call would take the total to 120, past the budget of 100")
			assert.InDelta(t, 90.0, total, 1e-9, "a denied call reports the CURRENT total, not the would-be one")
			assert.Positive(t, retryAfter, "a denial must estimate when enough weight ages out")
		})
	}
}

// TestAdmitWeighted_DeniedCallRecordsNothing is the commit rule the issue calls out
// explicitly: an over-limit call must not write its weight, or a burst of refusals extends
// its own lockout past the window that actually spent the budget.
func TestAdmitWeighted_DeniedCallRecordsNothing(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			_, admitted, _, err := admitWeighted(ctx, c, "k", 60, 90, 100)
			require.NoError(t, err)
			require.True(t, admitted)

			// Ten refused attempts at a magnitude that does not fit.
			for i := 0; i < 10; i++ {
				_, admitted, _, err := admitWeighted(ctx, c, "k", 60, 50, 100)
				require.NoError(t, err)
				require.False(t, admitted)
			}
			// The budget still holds exactly what the ADMITTED call spent, so a call that
			// does fit is still admitted.
			total, admitted, _, err := admitWeighted(ctx, c, "k", 60, 10, 100)
			require.NoError(t, err)
			assert.True(t, admitted, "refused calls must not have consumed budget")
			assert.InDelta(t, 100.0, total, 1e-9)
		})
	}
}

// TestAdmitWeighted_ExactlyAtTheBoundIsAdmitted pins the comparison's direction: a
// cumulative bound reads "no MORE than N", so a call landing exactly on N is permitted and
// the next positive magnitude is not. It mirrors maxCalls, where the limit-th call is the
// last admitted one.
func TestAdmitWeighted_ExactlyAtTheBoundIsAdmitted(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			total, admitted, _, err := admitWeighted(ctx, c, "k", 60, 100, 100)
			require.NoError(t, err)
			assert.True(t, admitted)
			assert.InDelta(t, 100.0, total, 1e-9)

			_, admitted, _, err = admitWeighted(ctx, c, "k", 60, 0.01, 100)
			require.NoError(t, err)
			assert.False(t, admitted, "the budget is spent; anything further must be refused")
		})
	}
}

// TestAdmitWeighted_WeightAgesOutOfTheWindow pins that the budget is a SLIDING window and
// not a permanent ledger: once the window has passed, the magnitude it held is free again.
func TestAdmitWeighted_WeightAgesOutOfTheWindow(t *testing.T) {
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	clock := base
	for name, c := range weightedBackends(t, func() time.Time { return clock }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			clock = base
			_, admitted, _, err := admitWeighted(ctx, c, "aging", 60, 100, 100)
			require.NoError(t, err)
			require.True(t, admitted)

			_, admitted, _, err = admitWeighted(ctx, c, "aging", 60, 1, 100)
			require.NoError(t, err)
			require.False(t, admitted, "the budget is spent while the first call is in-window")

			clock = base.Add(61 * time.Second)
			total, admitted, _, err := admitWeighted(ctx, c, "aging", 60, 100, 100)
			require.NoError(t, err)
			assert.True(t, admitted, "the first call aged out, so the whole budget is free again")
			assert.InDelta(t, 100.0, total, 1e-9)
		})
	}
}

// TestAdmitWeighted_FractionalMagnitudes covers the canonical unit: money. A currency
// amount is not an integer, and a backend that truncated one would silently under-charge
// every call.
func TestAdmitWeighted_FractionalMagnitudes(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for i := 0; i < 4; i++ {
				_, admitted, _, err := admitWeighted(ctx, c, "usd", 3600, 10.5, 42)
				require.NoError(t, err)
				require.True(t, admitted, "10.50 x %d is within 42", i+1)
			}
			total, admitted, _, err := admitWeighted(ctx, c, "usd", 3600, 0.5, 42)
			require.NoError(t, err)
			assert.False(t, admitted, "42.00 is already spent; a truncating backend would admit here")
			assert.InDelta(t, 42.0, total, 1e-9)
		})
	}
}

// TestAdmitWeighted_WindowsAreIsolated pins that two windows on one key are independent
// budgets, exactly as they are for maxCalls: the backends namespace storage by
// (key, windowSec), so a short window's prune can never destroy a longer one's total.
func TestAdmitWeighted_WindowsAreIsolated(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			_, admitted, _, err := admitWeighted(ctx, c, "k", 60, 50, 100)
			require.NoError(t, err)
			require.True(t, admitted)

			total, admitted, _, err := admitWeighted(ctx, c, "k", 3600, 50, 100)
			require.NoError(t, err)
			assert.True(t, admitted)
			assert.InDelta(t, 50.0, total, 1e-9, "the hourly budget must not see the minute budget's spend")
		})
	}
}

// TestAdmitWeighted_RejectsMalformedInput pins the fail-closed guards. Each of these
// would corrupt the budget rather than exhaust it, so each must be a structured ERROR the
// engine can distinguish from "bound reached" — and must write nothing.
func TestAdmitWeighted_RejectsMalformedInput(t *testing.T) {
	nan := math.NaN()
	inf := math.Inf(1)
	cases := []struct {
		name          string
		windowSec     int
		weight, limit float64
		why           string
	}{
		{"non-positive window", 0, 1, 100, "no meaningful span"},
		{"NaN weight", 60, nan, 100, "every later comparison would admit"},
		{"infinite weight", 60, inf, 100, "the budget would never admit again"},
		{"negative weight", 60, -50, 100, "a caller could refund its own consumed budget"},
		{"oversized weight", 60, 1 << 54, 1 << 53, "cannot be summed exactly"},
		{"zero limit", 60, 1, 0, "a misconfiguration, not an exhausted budget"},
		{"negative limit", 60, 1, -1, "a misconfiguration, not an exhausted budget"},
		{"NaN limit", 60, 1, nan, "a bound that cannot be compared bounds nothing"},
		{"oversized limit", 60, 1, 1 << 54, "would be rounded to a threshold nobody set"},
	}
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					_, admitted, _, err := admitWeighted(ctx, c, "bad", tc.windowSec, tc.weight, tc.limit)
					require.Error(t, err, "%s: %s", tc.name, tc.why)
					assert.False(t, admitted)
				})
			}
			// Nothing above created state: a fresh call against the same key still sees an
			// empty budget.
			total, admitted, _, err := admitWeighted(ctx, c, "bad", 60, 1, 100)
			require.NoError(t, err)
			assert.True(t, admitted)
			assert.InDelta(t, 1.0, total, 1e-9, "a refused-as-malformed call must have recorded nothing")
		})
	}
}

// TestAdmitWeighted_ZeroWeightIsAdmitted pins that a genuinely weightless action consumes
// no budget rather than being refused. Zero is a legal magnitude; refusing it would deny a
// call the policy itself considers free.
func TestAdmitWeighted_ZeroWeightIsAdmitted(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			_, admitted, _, err := admitWeighted(ctx, c, "z", 60, 100, 100)
			require.NoError(t, err)
			require.True(t, admitted)
			total, admitted, _, err := admitWeighted(ctx, c, "z", 60, 0, 100)
			require.NoError(t, err)
			assert.True(t, admitted, "a zero-magnitude action fits in a fully spent budget")
			assert.InDelta(t, 100.0, total, 1e-9)
		})
	}
}

// TestAdmitWeighted_CountedCallsWeighOne pins the generalization the contract claims: a
// key written by the COUNTING primitive reads back as weight 1 per call, so maxCalls is
// this with every weight equal to 1 rather than a separate accounting system that happens
// to live nearby.
func TestAdmitWeighted_CountedCallsWeighOne(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for i := 0; i < 3; i++ {
				_, admitted, _, err := admitCounted(ctx, c, "shared", 60, 10)
				require.NoError(t, err)
				require.True(t, admitted)
			}
			total, admitted, _, err := admitWeighted(ctx, c, "shared", 60, 1, 10)
			require.NoError(t, err)
			assert.True(t, admitted)
			assert.InDelta(t, 4.0, total, 1e-9, "three counted calls weigh 3, plus this one")
		})
	}
}

// TestAdmitWeighted_BackendsAgree drives the same interleaved sequence through both
// backends and compares every answer. Divergence is the failure mode a two-backend control
// cannot tolerate: a budget that admits on one replica and denies on another is not a
// budget, and the in-memory backend accumulates in float64 for exactly this reason.
func TestAdmitWeighted_BackendsAgree(t *testing.T) {
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	clock := base
	backends := weightedBackends(t, func() time.Time { return clock })
	mem, rds := backends["memory"], backends["redis"]
	ctx := context.Background()

	weights := []float64{10.5, 0.25, 99, 7.125, 3, 0.5, 40, 12}
	for i, w := range weights {
		clock = base.Add(time.Duration(i) * time.Second)
		memTotal, memOK, _, err := admitWeighted(ctx, mem, "agree", 30, w, 120)
		require.NoError(t, err)
		rdsTotal, rdsOK, _, err := admitWeighted(ctx, rds, "agree", 30, w, 120)
		require.NoError(t, err)
		assert.Equal(t, memOK, rdsOK, "step %d (weight %v): backends disagreed on admission", i, w)
		assert.Equal(t, memTotal, rdsTotal, "step %d (weight %v): backends disagreed on the total", i, w)
	}
}

// TestAdmitWeighted_WeightlessCallsAreNotRecorded pins the one weight class that had no
// bound. `cur + 0 > limit` is never true, so a zero-magnitude call was admitted AND
// appended every time — one key growing without limit for the whole window, with every
// later call re-summing it under the counter's lock (and, on Redis, re-scanning the whole
// sorted set). A weight that cannot move the total can never affect a future decision, so
// it is admitted without being recorded.
func TestAdmitWeighted_WeightlessCallsAreNotRecorded(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for i := 0; i < 5000; i++ {
				total, admitted, _, err := admitWeighted(ctx, c, "free", 3600, 0, 100)
				require.NoError(t, err)
				require.True(t, admitted, "a weightless action consumes no budget and must be admitted")
				require.Zero(t, total)
			}
			// The budget is untouched and, crucially, nothing accumulated: a real call of
			// the full budget still fits.
			total, admitted, _, err := admitWeighted(ctx, c, "free", 3600, 100, 100)
			require.NoError(t, err)
			assert.True(t, admitted)
			assert.InDelta(t, 100.0, total, 1e-9)
		})
	}
}

// TestAdmitCounted_SubOneAndFractionalLimitsFailClosed pins the guard a counted bucket
// needs beyond the shared range check, on BOTH backends.
//
// A counted bucket's limit is a number of calls. checkTotalLimit only bounds it to
// (0, MaxWeightedTotal], which leaves two shapes that must not reach a backend:
//
//   - Below 1. It can never admit, but that is a MISCONFIGURATION, not an exhausted
//     quota, and a silent nil denial is indistinguishable from "rate limit exceeded" to
//     every caller and every audit record.
//   - Fractional. It additionally makes the two backends DISAGREE — the one thing the
//     shared batch validation exists to prevent: in memory it compares directly and
//     denies, while the Redis script derives its retry pivot as `total - limit` and hands
//     that fractional index to ZRANGE, which errors the whole admission.
//
// Written against AdmitAll directly rather than through the AdmitCounted helper, whose
// int64 limit cannot express either shape.
func TestAdmitCounted_SubOneAndFractionalLimitsFailClosed(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for name, c := range weightedBackends(t, func() time.Time { return fixed }) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			for _, tc := range []struct {
				limit float64
				want  string
			}{
				{0.5, "limit must be >= 1"},
				{0.999, "limit must be >= 1"},
				{2.5, "whole number of calls"},
				{1e6 + 0.5, "whole number of calls"},
			} {
				admitted, _, _, _, err := c.AdmitAll(ctx, []capability.QuotaBucket{
					{Key: "counted", WindowSec: 60, Counted: true, Limit: tc.limit},
				})
				require.Error(t, err, "counted limit %v must fail closed with a structured error, not a silent denial", tc.limit)
				assert.Contains(t, err.Error(), tc.want)
				assert.False(t, admitted, "nothing is admitted on the error path")
			}
			// The whole numbers on either side of the rejected band still admit.
			for _, limit := range []float64{1, 2, 1000} {
				admitted, _, _, _, err := c.AdmitAll(ctx, []capability.QuotaBucket{
					{Key: fmt.Sprintf("ok-%v", limit), WindowSec: 60, Counted: true, Limit: limit},
				})
				require.NoError(t, err, "a whole-number counted limit must be accepted")
				assert.True(t, admitted)
			}
		})
	}
}
