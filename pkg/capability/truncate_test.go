// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestTruncateUTF8 exercises the normalize-then-rune-safe-cut helper three layers build
// on — internal/audit's field bound, internal/transport's sanitizeClaimedID, and
// pkg/enforcement's denial-details bound — so the "make an attacker string safe for the
// signed tape" logic is pinned once, in the package that owns it. It moved here from
// internal/audit when that package's one-line re-export was retired: the tests had been
// exercising the wrapper, so this primitive had none of its own.
func TestTruncateUTF8(t *testing.T) {
	// Under the limit: returned untouched.
	if got := TruncateUTF8("abc", 10); got != "abc" {
		t.Errorf("TruncateUTF8 must not alter an under-limit string, got %q", got)
	}
	// Non-positive limit truncates to "", with no marker (unlike BoundString).
	if got := TruncateUTF8("abc", 0); got != "" {
		t.Errorf("TruncateUTF8(s, 0) = %q, want \"\"", got)
	}
	if got := TruncateUTF8("abc", -1); got != "" {
		t.Errorf("TruncateUTF8(s, -1) = %q, want \"\"", got)
	}
	// Cuts to exactly the byte limit, never over, and never carries BoundString's
	// visible marker.
	s := strings.Repeat("x", 1000)
	got := TruncateUTF8(s, 50)
	if len(got) != 50 {
		t.Errorf("TruncateUTF8(s, 50) = %d bytes, want exactly 50", len(got))
	}
	if strings.Contains(got, "truncated") {
		t.Errorf("TruncateUTF8 must not add BoundString's marker, got %q", got)
	}
	// Truncation lands on a rune boundary, never splitting a multi-byte rune.
	multiByte := strings.Repeat("世", 100)
	for limit := 1; limit < 20; limit++ {
		got := TruncateUTF8(multiByte, limit)
		if len(got) > limit {
			t.Errorf("TruncateUTF8(s, %d) = %d bytes, exceeds the limit", limit, len(got))
		}
		if !utf8.ValidString(got) {
			t.Errorf("TruncateUTF8(s, %d) produced invalid UTF-8: %q", limit, got)
		}
	}
	// Invalid UTF-8 is normalized before the cut.
	if got := TruncateUTF8("sess-\xc3-tail", 200); got != "sess-�-tail" {
		t.Errorf("TruncateUTF8 must replace invalid UTF-8, got %q", got)
	}
}
