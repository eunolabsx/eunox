// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNearestString(t *testing.T) {
	cands := []string{"argument", "values", "operations", "windowSeconds"}
	cases := []struct {
		name, input string
		candidates  []string
		want        string
	}{
		{"single-edit typo", "arguments", cands, "argument"},
		{"transposition within range", "vaules", cands, "values"},
		{"case-insensitive", "ARGUMENT", cands, "argument"},
		{"too far returns empty", "completely-different", cands, ""},
		{"distance 3 is not close enough", "abc", []string{"xyz"}, ""},
		{"distance 2 qualifies", "ab", []string{"abcd"}, "abcd"},
		{"no candidates", "argument", nil, ""},
		{"ties resolve to earliest candidate", "aa", []string{"ab", "ba"}, "ab"},
		{"empty input falls back to candidate length", "", []string{"ab"}, "ab"},
		{"empty candidate within range", "ab", []string{""}, ""},
		// A single multi-byte rune typo is one rune-edit away. Byte-indexed distance
		// would over-count it (the 2-byte "ï" vs 1-byte "i" reads as 2 byte-edits)
		// and could push it past the threshold or mis-rank it; rune-aware distance
		// keeps it at 1 so the candidate is still suggested.
		{"multi-byte single-rune typo", "tïmeWindow", []string{"timeWindow"}, "timeWindow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NearestString(tc.input, tc.candidates))
		})
	}
}
