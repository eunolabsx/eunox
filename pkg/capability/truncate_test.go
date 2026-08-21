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

// TestSanitizeControlRunes pins the walk two layers now share: internal/audit's
// SanitizeAuditField (a target or session id going into a single-line diagnostic) and
// internal/transport's bound on a remote upstream's error body (bytes of the adversary's
// choosing reaching an operator's terminal). Both fail the same way if the rune set drifts.
func TestSanitizeControlRunes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain text is untouched", in: "read_file failed", want: "read_file failed"},
		// The terminal-driving half: ESC starts every ANSI sequence, BEL terminates an OSC one.
		{name: "escape sequences are neutralized", in: "a\x1b[2Jb\x07c", want: "a [2Jb c"},
		{name: "newlines cannot forge a second log line", in: "real\n[eunox] ALL CLEAR", want: "real [eunox] ALL CLEAR"},
		{name: "carriage return, which alone can overwrite a line", in: "a\rb", want: "a b"},
		// C1 controls: unicode.IsControl covers 0x80-0x9F, U+009B being CSI.
		{name: "C1 controls too", in: "a\u009bmb", want: "a mb"},
		// The two the category misses, which is the whole reason this is not a bare IsControl.
		{name: "U+2028 line separator", in: "a\u2028b", want: "a b"},
		{name: "U+2029 paragraph separator", in: "a\u2029b", want: "a b"},
		// Mapped, not dropped: dropping joins the tokens either side and changes what the
		// value reads as.
		{name: "a control between words leaves the words apart", in: "one\ttwo", want: "one two"},
		// Non-ASCII text a reader legitimately needs survives — this is not a printable-ASCII
		// filter like the reflected-revision bound, whose input comes from a closed set.
		{name: "non-ASCII text survives", in: "ne peut pas ouvrir « fichier »", want: "ne peut pas ouvrir « fichier »"},
		{name: "invalid UTF-8 becomes the replacement rune", in: "a\xffb", want: "a\ufffdb"},
		{name: "empty stays empty", in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeControlRunes(tc.in); got != tc.want {
				t.Errorf("SanitizeControlRunes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
