// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"context"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// WithRedisTimeFunc exposes the unexported clock-injection option to the
// external test package (callcounter_test) without widening the production API
// surface. This file is compiled only under `go test`.
func WithRedisTimeFunc(fn func() time.Time) redisOption {
	return withTimeFunc(fn)
}

// ParseAdmitAllReply exposes the unexported AdmitAll reply decoder to the external test
// package so the fail-closed type-assertion behaviour can be tested with crafted replies (a
// wrong element type can't be produced through the real Lua script via miniredis). The
// decoder's job is to fail closed on one rather than default to a zero total, which would
// read as an unspent budget and admit. Compiled only under `go test`.
func ParseAdmitAllReply(res interface{}) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return parseAdmitAllReply(res)
}

// AdmitCounted and AdmitWeighted commit ONE bucket through AdmitAll — the single-bucket
// admission the decision path makes for a lone maxCalls or a lone cumulative blastRadius —
// returning it in the shape the two retired single-bucket methods (IncrementIfBelow,
// AddIfTotalBelow) had. They live here so BOTH test packages share one spelling.
//
// They exist so the quota cases below read as what they pin (a limit admits up to its
// bound, a denied call records nothing, a window ages out) rather than as batch plumbing,
// AND so that coverage lands on the primitive production actually calls. That is the point
// of the retirement: a backend that got AdmitAll subtly wrong while implementing the
// retired pair correctly would have looked fully tested, because the only tests exercising
// single-bucket semantics called methods no decision path reached.
//
// The counted form takes an int64 limit because a counted bound IS a whole number of calls;
// QuotaBucket carries it as a float64 so one struct serves both accountings.
func AdmitCounted(ctx context.Context, c capability.CallCounter, key string, windowSec int, limit int64) (count int64, admitted bool, retryAfter time.Duration, err error) {
	admitted, _, total, retryAfter, err := c.AdmitAll(ctx, []capability.QuotaBucket{{
		Key: key, WindowSec: windowSec, Counted: true, Limit: float64(limit),
	}})
	return int64(total), admitted, retryAfter, err
}

// AdmitWeighted is AdmitCounted's weight-summing twin; see that doc.
func AdmitWeighted(ctx context.Context, c capability.CallCounter, key string, windowSec int, weight, limit float64) (total float64, admitted bool, retryAfter time.Duration, err error) {
	admitted, _, total, retryAfter, err = c.AdmitAll(ctx, []capability.QuotaBucket{{
		Key: key, WindowSec: windowSec, Weight: weight, Limit: limit,
	}})
	return total, admitted, retryAfter, err
}
