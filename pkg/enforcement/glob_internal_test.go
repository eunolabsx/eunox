// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"strings"
	"testing"
)

// TestMatchValueGlobSegmentCap verifies that a "**" pattern matched
// against an attacker-supplied value with an excessive '/' segment count fails
// closed (no match) instead of allocating an unbounded DP table.
func TestMatchValueGlobSegmentCap(t *testing.T) {
	// A value just over the cap must not match, even though "/data/**" would
	// otherwise subtree-match it.
	huge := "/data" + strings.Repeat("/x", maxGlobSegments+5)
	if MatchValueGlob("/data/**", huge) {
		t.Errorf("oversized value (%d segments) matched; want fail-closed deny", maxGlobSegments+6)
	}

	// A value comfortably within the cap must still match normally, so the guard
	// does not regress legitimate subtree matching.
	ok := "/data" + strings.Repeat("/x", 10)
	if !MatchValueGlob("/data/**", ok) {
		t.Errorf("legitimate value %q did not match /data/**", ok)
	}
}
