// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import "time"

// WithRedisTimeFunc exposes the unexported clock-injection option to the
// external test package (callcounter_test) without widening the production API
// surface. This file is compiled only under `go test`.
func WithRedisTimeFunc(fn func() time.Time) redisOption {
	return withTimeFunc(fn)
}

// ParseIncrIfBelowReply exposes the unexported IncrementIfBelow reply decoder to
// the external test package so the fail-closed type-assertion behaviour can be
// tested with crafted replies (a wrong element type can't be produced through the
// real Lua script via miniredis). Compiled only under `go test`.
func ParseIncrIfBelowReply(res interface{}) (count int64, admitted bool, retryAfter time.Duration, err error) {
	return parseIncrIfBelowReply(res)
}
