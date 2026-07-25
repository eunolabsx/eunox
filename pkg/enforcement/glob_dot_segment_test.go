// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"testing"

	"github.com/eunolabs/eunox/pkg/enforcement"
)

// TestMatchValueGlob_SlashlessDotSegmentConfinement covers the confinement gap a
// slashless allowedValues pattern used to have: confinePathStylePattern rejects a
// "."/".." segment after decoding, but the slashless branch only counted '/' — and
// ".." carries none. A pattern whose metacharacters can match two dots (".*", "??",
// "*.*", "[.][.]") therefore admitted the bare traversal value "..", which an
// upstream resolves to the PARENT of the directory the operator scoped the grant to.
//
// The realistic manifest is `allowedValues: [".*"]` on a path argument, written to
// permit dotfiles like ".env" in the tool's working directory; it must not also
// permit `{"path": ".."}`.
func TestMatchValueGlob_SlashlessDotSegmentConfinement(t *testing.T) {
	t.Parallel()

	denied := []struct {
		name    string
		pattern string
		value   string
	}{
		{"dotfile grant does not admit parent traversal", ".*", ".."},
		{"dotfile grant does not admit the CWD", ".*", "."},
		{"two-char wildcard does not admit parent traversal", "??", ".."},
		{"single-char wildcard does not admit the CWD", "?", "."},
		{"star-dot-star does not admit parent traversal", "*.*", ".."},
		{"class pattern does not admit parent traversal", "[.][.]", ".."},
		{"class range does not admit parent traversal", "[.-9][.-9]", ".."},
		{"escaped-dot pattern does not admit the CWD", `\.`, "."},
		// The confinement decodes once before the dot scan, so the percent-encoded
		// spellings an upstream resolves to ".." are denied on the same rule.
		{"percent-encoded parent traversal", ".*", "%2e%2e"},
		{"partially encoded parent traversal", ".*", ".%2e"},
		{"uppercase percent-encoded parent traversal", "??????", "%2E%2E"},
		{"backslash-folded parent traversal is still one segment", "??", `..`},
	}
	for _, c := range denied {
		if enforcement.MatchValueGlob(c.pattern, c.value) {
			t.Errorf("%s: MatchValueGlob(%q, %q) = true, want false (slashless dot-segment confinement)", c.name, c.pattern, c.value)
		}
	}

	// The rule is exactly "the single segment is '.' or '..'", not "the value starts
	// with a dot": ordinary dotfiles and dot-bearing names must still match, or the
	// fix would silently break every legitimate ".*" grant.
	allowed := []struct {
		name    string
		pattern string
		value   string
	}{
		{"dotfile still matches", ".*", ".env"},
		{"dot-prefixed directory name still matches", ".*", ".config"},
		{"three dots is an ordinary name", ".*", "..."},
		{"double-dot with a suffix is an ordinary name", ".*", "..bashrc"},
		{"extension glob still matches", "*.csv", "report.csv"},
		{"name containing dots still matches", "*", "a..b"},
		{"embedded dot-dot is not a segment", "*", "x..y"},
		// Whole-pattern "*"/"**" are documented to match ANY value (they are the
		// explicit allow-all escape hatch and never reach confinement), unchanged here.
		{"bare star still matches anything", "*", ".."},
		{"bare double-star still matches anything", "**", ".."},
	}
	for _, c := range allowed {
		if !enforcement.MatchValueGlob(c.pattern, c.value) {
			t.Errorf("%s: MatchValueGlob(%q, %q) = false, want true", c.name, c.pattern, c.value)
		}
	}
}

// TestValidateValueGlob_SlashlessDotSegmentIsDead mirrors the runtime rule at load:
// once confineSlashlessPattern denies a "."/".." value, a slashless pattern that
// spells one literally can only ever match a value the runtime rejects — a silently
// dead deny-all grant. Reject it up front, exactly as the path-style branch already
// rejects "/reports/../secret", so the operator sees the mistake instead of a rule
// that matches nothing.
func TestValidateValueGlob_SlashlessDotSegmentIsDead(t *testing.T) {
	t.Parallel()

	dead := []string{".", ".."}
	for _, p := range dead {
		if err := enforcement.ValidateValueGlob(p); err == nil {
			t.Errorf("ValidateValueGlob(%q) = nil, want an error (the runtime confinement denies every value it could match)", p)
		}
	}

	// Patterns that merely CONTAIN dots stay valid: only a whole segment equal to
	// "." or ".." is unmatchable.
	live := []string{".*", "..*", "...", "?", "??", "*.csv", ".env", "[.]x", "*"}
	for _, p := range live {
		if err := enforcement.ValidateValueGlob(p); err != nil {
			t.Errorf("ValidateValueGlob(%q) = %v, want nil", p, err)
		}
	}
}
