// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/enforcement"
)

// TestMatchValueGlob exercises the allowedValues value matcher: the bare-"*"
// allow-all wildcard, "**" crossing '/', the unchanged single-'*' semantics,
// and fail-closed handling of malformed patterns.
func TestMatchValueGlob(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		// Bare "*"/"**" match anything, including values with '/'. This is the
		// fix for the "allow any value" footgun.
		{"bare star matches simple token", "*", "json", true},
		{"bare star matches path with slash", "*", "/reports/q3.pdf", true},
		{"bare star matches deep path", "*", "/a/b/c/d", true},
		{"bare star matches uri", "*", "file:///etc/passwd", true},
		{"bare star matches empty", "*", "", true},
		{"bare doublestar matches path with slash", "**", "/reports/sub/q3.pdf", true},

		// A single '*' inside a pattern does NOT cross '/': unchanged from the
		// original path.Match behaviour.
		{"single star matches one segment", "/reports/*", "/reports/q3.pdf", true},
		{"single star denies subdirectory", "/reports/*", "/reports/sub/q3.pdf", false},
		{"single star denies sibling tree", "/reports/*", "/internal/secret.txt", false},
		{"single star no slash value", "report*", "report_secret", true},

		// A "**" path segment crosses '/' and matches zero or more segments.
		{"doublestar matches one level", "/reports/**", "/reports/q3.pdf", true},
		{"doublestar matches deep level", "/reports/**", "/reports/sub/q3.pdf", true},
		{"doublestar matches deeper level", "/reports/**", "/reports/a/b/c.pdf", true},
		{"doublestar matches zero levels", "/reports/**", "/reports", true},
		{"doublestar respects prefix", "/reports/**", "/internal/secret.txt", false},
		{"doublestar in middle", "/a/**/z", "/a/b/c/z", true},
		{"doublestar in middle single", "/a/**/z", "/a/b/z", true},
		{"doublestar in middle mismatch tail", "/a/**/z", "/a/b/c/y", false},

		// Other glob metacharacters keep their single-segment meaning.
		{"question mark single char", "/v?", "/v1", true},
		{"question mark does not cross slash", "/v?", "/v/1", false},
		{"char class match", "/log[0-9]", "/log3", true},
		{"char class no match", "/log[0-9]", "/logx", false},

		// A character class not scoped to one segment (e.g. "[^z]", unlike the
		// "[^/]" idiom) must not let one class element absorb a literal '/'
		// already present in the value, spanning two segments a single-segment
		// pattern element was scoped to.
		{"class not excluding slash denies double-slash over-match", "/reports/[^x]file", "/reports//file", false},
		{"class not excluding slash denies cross-segment span", "/a/x[^z]y/b", "/a/x/y/b", false},
		// "[^/]" (explicitly excluding '/') is the correct, confined idiom and
		// must still be admitted: the class consumes exactly one non-'/'
		// character, matching path.Match's own semantics.
		{"class explicitly excluding slash stays confined to one char", "/pub/r[^/]port", "/pub/r/port", false},
		{"class explicitly excluding slash matches one char", "/pub/r[^/]port", "/pub/rXport", true},
		// A '/' written INSIDE a bracket class (a class member, not a fixed
		// pattern-side separator) must not be counted toward the pattern's
		// REQUIRED separator count: when the value has no more slashes than the
		// pattern's outside-bracket literal count, the class must have consumed
		// a non-'/' character, so the match is admitted like any ordinary
		// single-segment class.
		{"slash inside class is a class member, not a required separator", "a[/x]b", "axb", true},
		// But when the value DOES have an extra slash the pattern's outside-
		// bracket literal count doesn't account for, the guard denies it even
		// though raw path.Match would allow the class to consume that '/' --
		// path.Match("a[/x]b", "a/b") is true, yet MatchValueGlob's stricter,
		// security-motivated policy is that NO bracket class may ever cross a
		// segment boundary, whether it excludes '/' via negation ("[^z]"),
		// fails to exclude it ("[^x]"), or explicitly lists it as a member
		// ("[/x]") -- all three shapes are denied the same way once the value's
		// slash count exceeds what the pattern's literal text alone accounts
		// for.
		{"slash inside class still denied when it would need to match a real separator", "a[/x]b", "a/b", false},
		{"negated slash-inclusive class matches one non-member char", "/reports/[^x]y", "/reports/zy", true},

		// Exact literals (no metacharacters) match only themselves.
		{"literal exact", "/public/index.html", "/public/index.html", true},
		{"literal mismatch", "/public/index.html", "/public/other.html", false},

		// Malformed patterns fail closed (no panic, no match).
		{"malformed class no doublestar", "/reports/[invalid", "/reports/x", false},
		{"malformed class with doublestar", "/[invalid/**", "/x/y", false},

		// A rooted "/**" pattern must not match an empty (non-absolute) value:
		// the leading-"/" anchor and an empty value disagree on rootedness, so the
		// asymmetric-root pre-check denies it.
		{"doublestar-root does not match empty string", "/**", "", false},
		{"doublestar-root matches root slash", "/**", "/", true},
		{"doublestar-root matches absolute path", "/**", "/a/b", true},
		{"doublestar-root denies relative value", "/**", "a/b", false},
		{"relative doublestar denies rooted value", "reports/**", "/reports/x", false},

		// Multiple non-adjacent "**" groups: the linear DP matcher handles k>1
		// correctly and without the old O(n^k) backtracking blowup.
		{"two doublestars match", "/a/**/b/**/c", "/a/x/y/b/z/c", true},
		{"two doublestars match minimal", "/a/**/b/**/c", "/a/b/c", true},
		{"two doublestars mismatch tail", "/a/**/b/**/c", "/a/x/y/z", false},
		{"two doublestars need literal between", "/a/**/b/**/c", "/a/x/y/c", false},
		{"adjacent doublestars collapse", "/a/**/**/c", "/a/x/y/c", true},

		// Path-confinement: a path-style PATTERN (contains '/') must reject a VALUE
		// that carries a "." or ".." traversal segment, even though the literal text
		// is prefixed by the confined directory. "/reports/**" textually matches
		// "/reports/../../etc/passwd" but that value escapes the subtree on the
		// upstream filesystem, so it fails closed.
		{"doublestar rejects parent traversal", "/reports/**", "/reports/../../etc/passwd", false},
		{"doublestar rejects single parent", "/reports/**", "/reports/../secret", false},
		{"doublestar rejects dot segment", "/reports/**", "/reports/./q3.pdf", false},
		{"single star rejects parent traversal", "/reports/*", "/reports/../etc", false},
		{"literal path rejects embedded parent", "/a/b/c", "/a/b/../c", false},
		// Backslash traversal: an upstream that treats '\' as a separator would
		// resolve these outside the subtree, so normalize '\' -> '/' and reject.
		{"doublestar rejects backslash traversal", "/reports/**", "/reports/..\\..\\etc\\passwd", false},
		{"doublestar rejects mixed backslash parent", "/reports/**", "/reports/sub\\..\\..\\secret", false},
		// Percent-encoded traversal: an upstream that URI-decodes the value resolves
		// %2f -> '/' and %2e -> '.', so a traversal hidden as "..%2f.." or "%2e%2e"
		// escapes the subtree even though no literal segment equals "..". Decoding
		// before the segment scan surfaces it. Mixed case and a percent-encoded
		// backslash (%5c) are covered too.
		{"doublestar rejects percent-slash traversal", "/reports/**", "/reports/..%2f..%2fetc%2fpasswd", false},
		{"doublestar rejects percent-dot traversal", "/reports/**", "/reports/%2e%2e/%2e%2e/etc/passwd", false},
		{"doublestar rejects mixed-case percent traversal", "/reports/**", "/reports/..%2F..%2Fetc", false},
		{"single star rejects percent-dot parent", "/reports/*", "/reports/%2e%2e", false},
		{"doublestar rejects percent-backslash traversal", "/reports/**", "/reports/..%5c..%5csecret", false},
		// A malformed percent-escape fails closed (no match) rather than slipping
		// through on its literal form.
		{"doublestar rejects malformed percent-escape", "/reports/**", "/reports/%2g/x", false},
		// Double-encoding decodes one level: %252e -> %2e (not "."), so a
		// single-decoding upstream sees a harmless literal and the value is allowed.
		{"doublestar allows double-encoded dot", "/reports/**", "/reports/%252e%252e/x", true},
		// A legitimately percent-encoded leaf with no traversal still matches.
		{"doublestar allows percent-encoded space leaf", "/reports/**", "/reports/q3%20final.pdf", true},
		// The confined value with no traversal still matches (allow side preserved).
		{"doublestar allows clean nested path", "/reports/**", "/reports/sub/q3.pdf", true},
		{"doublestar allows clean leaf", "/reports/**", "/reports/q3.pdf", true},
		// "dotfiles" and names that merely CONTAIN dots are not traversal segments,
		// so they are unaffected: only an exact "." or ".." segment is rejected.
		{"doublestar allows dotfile name", "/reports/**", "/reports/.env", true},
		{"doublestar allows dotted name", "/reports/**", "/reports/a..b/x", true},
		{"doublestar allows triple-dot name", "/reports/**", "/reports/.../x", true},
		// A non-path pattern (no '/') is a plain scalar/enum glob: a ".." value there
		// is an ordinary literal and matches normally — the path-confinement guard
		// must not bleed into non-path allowedValues.
		{"non-path pattern matches dotdot literal", "..", "..", true},
		{"non-path star matches dotdot value", "*", "..", true},
		{"non-path star matches dot value", "*", ".", true},
		// An encoded separator (%2f / %5c) must NOT let a single '*' span a '/' the
		// operator scoped to one segment: an upstream that decodes once resolves a
		// deeper path than the literal form. Fail closed.
		{"single star denies encoded-slash subdirectory", "/reports/*", "/reports/sub%2fsecret", false},
		{"single star denies encoded-slash leaf", "/public/*", "/public/private%2fkey.pem", false},
		{"single star denies encoded-backslash subdirectory", "/reports/*", "/reports/sub%5csecret", false},
		// A legitimately percent-encoded non-separator value still matches its own
		// segment: %2a -> '*' is not a separator, so the segment count is unchanged.
		{"single star allows encoded-star leaf", "/reports/*", "/reports/50%2aoff", true},
		// A "**" already spans separators, so an encoded separator inside its scope
		// is no traversal escape and must still match (the single-segment count guard
		// applies only to single-'*' confinement, not to "**").
		{"doublestar allows encoded-slash within subtree", "/reports/**", "/reports/a%2fb", true},
		{"doublestar allows deep encoded-slash within subtree", "/reports/**", "/reports/sub%2fq3.pdf", true},
		// ...but traversal out of a "**" subtree is still blocked, encoded or not.
		{"doublestar still denies encoded traversal out", "/reports/**", "/reports/..%2f..%2fetc", false},
		// Mixed '*'+"**": the single-'*' segment still confines its own segment even
		// though "**" co-occurs, so an encoded separator that lands in the '*' segment
		// is rejected (it spans a '/' the operator scoped to one segment). The
		// encoded-separator guard must NOT be disabled wholesale just because the
		// pattern contains "**".
		{"mixed star-doublestar denies encoded-slash in single-star segment", "/a/*/**", "/a/x%2fy/z", false},
		{"mixed star-doublestar denies encoded-backslash in single-star segment", "/a/*/**", "/a/x%5cy/z", false},
		{"mixed doublestar-star denies encoded-slash in trailing single-star segment", "/a/**/*", "/a/b/x%2fy", false},
		// ...but an encoded separator that lands in the "**" portion of the same mixed
		// pattern is still admitted: "**" spans separators, the single-'*' matches a
		// clean segment, so this is no single-segment widening.
		{"mixed star-doublestar allows encoded-slash in doublestar segment", "/a/*/**", "/a/b/x%2fy", true},
		{"mixed star-doublestar allows encoded-slash deep in doublestar segment", "/a/*/**", "/a/b/c/x%2fy", true},
		// A trailing single-'*' that is forced onto a separator-spanning segment is
		// denied even though the value would be in scope under either decode reading
		// (the decoded "/x/y", or the literal one-segment "/x%2fy"). The guard cannot
		// tell that "**" could have absorbed the segment and left the '*' a clean one,
		// so it fails closed. Pinned so this over-deny stays intentional, not incidental.
		{"mixed doublestar-star denies separator-spanning sole segment", "/**/*", "/x%2fy", false},

		// Slashless single-segment patterns ('*.csv', 'file-?', '[abc].log') scope
		// the value to one segment just like a slash-bearing '/reports/*'. A value
		// smuggling an encoded ('%2f', '%5c') or literal ('\') separator would let
		// the upstream resolve a subpath the operator never granted, so it must be
		// denied even though plain path.Match matches the literal '%'/'\' bytes.
		{"slashless star denies encoded-slash traversal", "*.csv", "..%2f..%2fetc%2fpasswd.csv", false},
		{"slashless star denies mixed-case encoded traversal", "*.csv", "..%2F..%2Fetc%2Fshadow.csv", false},
		{"slashless star denies backslash traversal", "*.csv", "..\\..\\etc\\passwd.csv", false},
		{"slashless star denies encoded-backslash traversal", "*.csv", "..%5c..%5csecret.csv", false},
		{"slashless star denies encoded-slash subdirectory", "*.csv", "sub%2fsecret.csv", false},
		{"slashless question mark denies encoded-slash", "v?.txt", "v%2f.txt", false},
		{"slashless class denies encoded-slash", "[abc].log", "a%2fb.log", false},
		// Legitimate slashless values with no smuggled separator still match; a
		// percent-encoded non-separator (space) and a literal '%' filename are kept.
		{"slashless star allows plain leaf", "*.csv", "q3-report.csv", true},
		{"slashless star allows encoded-space leaf", "*.csv", "q3%20report.csv", true},
		{"slashless star allows literal-percent leaf", "*.csv", "50%off.csv", true},
		{"slashless star allows encoded-dot leaf", "*.csv", "q3%2ereport.csv", true},
		// An embedded NUL (truncation vector) fails closed on the slashless path too.
		{"slashless star denies embedded NUL", "*.csv", "safe.csv\x00.exe", false},
		// A valid encoded separator riding alongside a MALFORMED escape must still be
		// rejected: the whole value fails to percent-decode, but a lenient upstream would
		// resolve the good %2f, so the guard must not fall back to a literal match.
		{"slashless star denies encoded-slash with trailing bad escape", "*.csv", "..%2f..%2fetc%2fpasswd%zz.csv", false},
		{"slashless star denies encoded-backslash with bad escape", "*.csv", "..%5c..%5csecret%zz.csv", false},
		// A slashless character class must not absorb a LITERAL '/' already present in
		// the value: Go's path.Match applies no '/'-exclusion inside "[…]", so a
		// negated class ("[^0-9]", "[^z]") or a range straddling 0x2f matches the
		// leading '/' and would admit a rooted/absolute path the single-segment grant
		// never scoped. '*'/'?' cannot match a '/' at all, so a legitimate leaf still
		// matches; only the class-crossing bypass is removed.
		{"slashless negated class denies leading literal slash", "[^0-9]*.txt", "/passwd.txt", false},
		{"slashless negated class denies rooted single char", "[^z]bc", "/bc", false},
		{"slashless negated class denies parent-dir reference", "[^z]*", "/..", false},
		{"slashless range straddling 0x2f denies leading slash", "[.-9]bc", "/bc", false},
		{"slashless negated class still matches a plain leaf", "[^0-9]*.txt", "passwd.txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := enforcement.MatchValueGlob(tt.pattern, tt.value); got != tt.want {
				t.Errorf("MatchValueGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// TestMatchValueGlob_NoBacktrackingBlowup guards the fix for the value-driven
// DoS: a manifest pattern with several non-adjacent "**" groups matched
// against a long attacker-supplied value used to recurse O(n^k) times. The
// linear DP matcher returns essentially instantly, so a generous deadline
// catches any regression to exponential backtracking. The value is built so the
// pattern cannot match, which is the worst case for backtracking (it explores
// every suffix combination before failing).
func TestMatchValueGlob_NoBacktrackingBlowup(t *testing.T) {
	t.Parallel()
	pattern := "/a/**/b/**/c/**/d" // k = 3 non-adjacent "**" groups
	var sb strings.Builder
	sb.WriteString("/a")
	for i := 0; i < 4000; i++ {
		sb.WriteString("/x")
	}
	value := sb.String() // no "b"/"c"/"d" literals, so the match fails

	done := make(chan bool, 1)
	go func() {
		done <- enforcement.MatchValueGlob(pattern, value)
	}()
	select {
	case got := <-done:
		if got {
			t.Fatalf("expected no match for %q against a long non-matching value", pattern)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MatchValueGlob did not return within 5s — backtracking blowup regression")
	}
}

// TestValidateValueGlob pins that ValidateValueGlob accepts exactly the patterns
// MatchValueGlob can evaluate, and rejects a "**"-bearing pattern whose bracket
// class spans a "/" — which a whole-string path.Match validator wrongly accepts
// while the runtime segment matcher treats as dead (matches nothing). It must
// agree with the runtime decomposition so load validation and matching cannot
// diverge.
func TestValidateValueGlob(t *testing.T) {
	t.Parallel()
	valid := []string{"*", "**", "/reports/*", "/reports/**", "/a/b/c", "[a-z]/**", "literal", "a[1]"}
	for _, p := range valid {
		if err := enforcement.ValidateValueGlob(p); err != nil {
			t.Errorf("ValidateValueGlob(%q) = %v, want nil", p, err)
		}
	}
	invalid := []string{
		"/reports/[invalid", // unclosed class, no "**"
		"[a/b]/**",          // class spanning "/" with "**": valid whole-string, dead at runtime
		"/[invalid/**",      // bad segment with "**"
		"[unclosed",         // bare unclosed class
		// A path-style pattern with a literal "." or ".." segment is unmatchable:
		// any value carrying the required segment is rejected by the runtime
		// confinement scan first, so the pattern is a silently dead deny-all.
		"/**/../x",
		"/a/./b",
		"/reports/../secret",
		// An encoded path separator makes every candidate value decode to contain a
		// '/', which the runtime confinement denies — so the grant is a dead deny-all.
		"a%2fb",
		"file%5cname",
		"a%2Fb", // case-insensitive
		// A "**" pattern exceeding the runtime segment cap matches nothing.
		strings.Repeat("a/", 1001) + "**",
	}
	for _, p := range invalid {
		if err := enforcement.ValidateValueGlob(p); err == nil {
			t.Errorf("ValidateValueGlob(%q) = nil, want an error", p)
		}
	}
}
