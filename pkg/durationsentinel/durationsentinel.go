// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package durationsentinel resolves the "zero means use the default, negative
// means disabled, anything else is verbatim" convention a configured
// time.Duration follows at several unrelated call sites across this codebase
// (JWT clock-skew leeway, kill-switch tombstone TTL, ...). Those sites use
// unrelated default magnitudes for unrelated purposes and live in packages
// with no dependency relationship to one another, so centralizing the
// resolution itself — not any particular default — is what this package is
// for: a correction to the idiom (a new edge case, a changed meaning for
// "negative") now needs applying once instead of being rediscovered
// independently at every copy.
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
