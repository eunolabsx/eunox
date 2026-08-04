// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package durationsentinel resolves the "zero means default, negative means disabled,
// anything else is verbatim" convention several unrelated call sites in this codebase
// share, so a correction to the idiom applies once instead of being rediscovered per copy.
package durationsentinel

import "time"

// Resolve applies the sentinel convention to configured, given defaultVal for
// the zero case: zero selects defaultVal, negative is clamped to zero
// (disabled), and any other value passes through unchanged.
func Resolve(configured, defaultVal time.Duration) time.Duration {
	switch {
	case configured == 0:
		return defaultVal
	case configured < 0:
		return 0
	default:
		return configured
	}
}
