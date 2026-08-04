// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// errPathMalformedEscape and errPathNUL are distinguished, not a single bool, because
// callers treat them differently: a malformed '%' is a legal filename character for a
// non-decoding upstream, while an embedded NUL is a truncation vector that must always deny.
var (
	errPathMalformedEscape = errors.New("malformed percent-escape")
	errPathNUL             = errors.New("embedded NUL byte")
)

// decodePathForConfinement folds a value to the form an upstream will resolve before a
// path-confinement guard inspects it: '\' folds to '/', percent-decoded once (%2f -> '/',
// %2e -> '.'), then '\' folded again. Callers MUST fail closed on a non-nil error rather
// than match the literal; an embedded NUL (literal or %00) is rejected because a
// NUL-truncating upstream would resolve a different file than the guard inspects
// (CWE-158/CWE-626). Shared by MatchValueGlob and handleAllowedExtensions so both
// normalize the same smuggling class in lock-step.
//
// errPathNUL wins over errPathMalformedEscape even when the NUL is encoded alongside some
// OTHER malformed escape (url.PathUnescape fails the whole value), so the lenient fallback
// callers apply on a malformed escape never treats "%00" as literal characters.
func decodePathForConfinement(value string) (string, error) {
	folded := strings.ReplaceAll(value, "\\", "/")
	// Check BEFORE decoding so a literal NUL fails closed regardless of escape validity.
	if strings.IndexByte(folded, 0) >= 0 {
		return "", errPathNUL
	}
	decoded, err := url.PathUnescape(folded)
	if err != nil {
		if containsEncodedNUL(folded) {
			return "", errPathNUL
		}
		return "", errPathMalformedEscape
	}
	decoded = strings.ReplaceAll(decoded, "\\", "/")
	if strings.IndexByte(decoded, 0) >= 0 { // still catch %00 -> NUL
		return "", errPathNUL
	}
	return decoded, nil
}

// containsEncodedSeparator reports whether s contains a percent-encoded path separator
// token (%2f, %5c), case-insensitively. Shared by the runtime fail-closed path (a value
// with an otherwise-malformed escape) and the load-time pattern check, so the two rejection
// rules stay in lock-step.
func containsEncodedSeparator(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c")
}

// containsEncodedNUL reports whether s contains a percent-encoded NUL token (%00),
// case-insensitively. decodePathForConfinement's only caller: it can only catch an
// encoded %00 by inspection AFTER url.PathUnescape fails whole on some OTHER malformed
// escape, to decide whether errPathNUL must still win over errPathMalformedEscape.
//
// Deliberately NOT folded into containsEncodedSeparator: they answer different questions
// (leaves the confined subtree vs. resolves a different path), and the separator token is
// also checked at load against a pattern's literal text where NUL has no such meaning.
func containsEncodedNUL(s string) bool {
	return strings.Contains(strings.ToLower(s), "%00")
}

// globClassPlaceholder stands in for an elided bracket class. It must be a byte that can
// never form part of an encoded-separator token, so eliding a class cannot splice one
// into existence.
const globClassPlaceholder = '\x00'

// scanPatternLiterals walks a glob pattern once and hands emit each byte path.Match
// compares LITERALLY — bracket classes elided to a placeholder, backslash escapes
// resolved to the character they escape.
//
// One definition of "what counts as a literal", shared by two callers asking different
// questions of the same walk (does the literal text hide an encoded separator; how many
// '/' does path.Match require) so a second hand-mirrored walk cannot drift the security
// boundary the '/' count enforces. The callback form avoids materializing a string for
// the counter, which runs per pattern on every enforced call.
//
// Mirrors path.Match's scanChunk: '[' opens a class, ']' closes an OPEN one (no nesting;
// unopened is an ordinary literal), a backslash-escaped character is one literal unit. A
// token split by a wildcard ("%2*f") still loads — fail-closed direction, not a security
// boundary.
func scanPatternLiterals(pattern string, emit func(byte)) {
	inClass := false
	for i := 0; i < len(pattern); i++ {
		switch {
		case pattern[i] == '\\' && i+1 < len(pattern):
			i++
			if !inClass {
				emit(pattern[i])
			}
		case pattern[i] == '[':
			if !inClass {
				emit(globClassPlaceholder)
			}
			inClass = true
		case pattern[i] == ']':
			// Unopened ']' is an ordinary literal and must be EMITTED, not dropped:
			// swallowing it could splice non-adjacent bytes into a false encoded separator
			// ("a%2]f" -> "a%2f"), rejecting a valid grant at load.
			if !inClass {
				emit(pattern[i])
				break
			}
			inClass = false
		default:
			if !inClass {
				emit(pattern[i])
			}
		}
	}
}

// patternLiteralsOutsideClasses renders a glob pattern with bracket classes replaced by a
// placeholder, leaving only what path.Match compares literally — so "[a%2f]" (a class
// MEMBER, consuming one value character) is not misread as an encoded separator.
func patternLiteralsOutsideClasses(pattern string) string {
	var b strings.Builder
	b.Grow(len(pattern))
	scanPatternLiterals(pattern, func(c byte) { _ = b.WriteByte(c) })
	return b.String()
}

// countPatternPathSeparators counts the '/' path.Match treats as required, allocation-free
// by driving the shared walk with a counter instead of materializing the rendered string.
func countPatternPathSeparators(pattern string) int {
	n := 0
	scanPatternLiterals(pattern, func(b byte) {
		if b == '/' {
			n++
		}
	})
	return n
}

// maxGlobSegments caps the segment count a "**" pattern matches, so an attacker-supplied
// value's slash count cannot drive an unbounded O(m*n) allocation in matchGlobSegments.
const maxGlobSegments = 1000

// ValidateValueGlob reports whether pattern is a well-formed allowedValues glob, using the
// SAME structural decomposition MatchValueGlob applies at runtime so the two cannot
// disagree (a whole-string path.Match would load a "**" pattern whose bracket class spans
// a "/" as valid, then silently match nothing at runtime). Returns path.ErrBadPattern for
// a malformed pattern, nil otherwise.
func ValidateValueGlob(pattern string) error {
	// Whole-pattern wildcards match anything and are never path.Match'd at runtime.
	if pattern == "*" || pattern == "**" {
		return nil
	}
	// A pattern with an ENCODED separator in its LITERAL text is a silently dead grant:
	// the runtime confinement denies any value that decodes to contain one. Reject it at
	// load instead. Bracket classes are elided first, so "[a%2f]" (a class member, not a
	// separator) is unaffected.
	if containsEncodedSeparator(patternLiteralsOutsideClasses(pattern)) {
		return fmt.Errorf("%w: pattern contains an encoded path separator (%%2f/%%5c); the runtime confinement denies any value that decodes to a separator, so the grant would match nothing", path.ErrBadPattern)
	}
	// A "**" pattern with more segments than matchGlobSegments' runtime cap is likewise a
	// dead grant (segment count is one more than the '/' count); reject it at load.
	if strings.Contains(pattern, "**") && strings.Count(pattern, "/") >= maxGlobSegments {
		return fmt.Errorf("%w: pattern has more than %d path segments, exceeding the runtime match cap; the grant would match nothing", path.ErrBadPattern, maxGlobSegments)
	}
	// A segment that is exactly "."/".." can never match, since the runtime confinement
	// scan rejects it first; a silently dead grant otherwise. Applies to a slashless
	// pattern too (confineSlashlessPattern rejects it the same way).
	for _, seg := range strings.Split(pattern, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: pattern contains an unmatchable %q segment", path.ErrBadPattern, seg)
		}
	}
	// Without a "**" the runtime is exactly path.Match on the whole pattern.
	if !strings.Contains(pattern, "**") {
		_, err := path.Match(pattern, "")
		return err
	}
	// With a "**", the runtime splits on "/" and path.Match's each segment; a
	// literal "**" segment is matched specially (never path.Match'd), so skip it.
	for _, seg := range strings.Split(pattern, "/") {
		if seg == "**" {
			continue
		}
		if _, err := path.Match(seg, ""); err != nil {
			return err
		}
	}
	return nil
}

// confinePathStylePattern applies subtree confinement to a path-style ("/"-bearing)
// allowedValues pattern. It decodes every separator/dot alias an upstream resolves before
// a "."/".." scan, so a value like "/reports/..%2f..%2fetc%2fpasswd" cannot smuggle a
// traversal past the guard. Returns the backslash-folded value, the per-segment
// separator-spanning flags for a "**" pattern (nil otherwise), and ok=false to deny.
func confinePathStylePattern(pattern, value string) (folded string, valSpansSep []bool, ok bool) {
	scan, err := decodePathForConfinement(value)
	if err != nil {
		return value, nil, false
	}
	for _, seg := range strings.Split(scan, "/") {
		if seg == ".." || seg == "." {
			return value, nil, false
		}
	}
	folded = strings.ReplaceAll(value, "\\", "/")
	// An encoded separator would let a single-segment element span a '/' the operator
	// scoped to one segment; fail closed since the proxy cannot know if the upstream
	// decodes it. A non-"**" pattern confines every segment via one total-count
	// comparison; a "**" pattern is mixed, so flag each spanning segment instead.
	if !strings.Contains(pattern, "**") {
		valueSlashes := strings.Count(folded, "/")
		if strings.Count(scan, "/") != valueSlashes {
			return folded, nil, false
		}
		// Pattern and value must ALSO agree on segment count: without this, a class that
		// does not exclude '/' (e.g. "[^z]") could span TWO value segments via path.Match's
		// whole-value fast path. countPatternPathSeparators counts only '/' outside a
		// bracket class, the same scan the load-time check uses.
		if countPatternPathSeparators(pattern) != valueSlashes {
			return folded, nil, false
		}
		return folded, nil, true
	}
	segs := strings.Split(folded, "/")
	// Cap the caller-controlled segment count before the per-segment decode and
	// allocation, at the same bound matchGlobSegments enforces.
	if len(segs) > maxGlobSegments {
		return folded, nil, false
	}
	valSpansSep = make([]bool, len(segs))
	for i, seg := range segs {
		dec, derr := decodePathForConfinement(seg)
		valSpansSep[i] = derr != nil || strings.Contains(dec, "/")
	}
	return folded, valSpansSep, true
}

// confineSlashlessPattern reports whether a value is safe to match against a slashless
// single-segment pattern ('*.csv', 'file-?', ...). A slashless pattern is a single-segment
// grant, so any '/' is illegitimate — including one matched via a class Go's path.Match
// does not exclude '/' from (e.g. '[^z]') — so any '/' at all denies, after decoding an
// encoded separator or '\' a lenient upstream would resolve into a subpath.
//
// A bare "."/".." is also denied (names the tool's working directory or its parent): the
// '/'-count guard alone would not catch it, since ".." carries no separator.
func confineSlashlessPattern(value string) bool {
	scan, err := decodePathForConfinement(value)
	if errors.Is(err, errPathNUL) {
		return false
	}
	if errors.Is(err, errPathMalformedEscape) {
		// A valid encoded separator riding alongside the bad escape must still deny:
		// url.PathUnescape failed whole, so matching the literal form would treat "%2f"
		// as an ordinary character while a lenient upstream resolves it as a separator.
		if containsEncodedSeparator(value) {
			return false
		}
		scan = strings.ReplaceAll(value, "\\", "/")
	}
	if strings.Count(scan, "/") != 0 {
		return false
	}
	// scan is now known to hold no '/', so it is exactly one segment: applying the
	// path-style branch's per-segment dot rule to it is the same rule, not a new one.
	return scan != "." && scan != ".."
}

// MatchValueGlob reports whether an argument value matches an allowedValues glob.
// It is the single matcher for argument-VALUE globbing, shared by the engine's
// allowedValues handler and the JWT PDP shorthand so the two cannot diverge.
//
// Semantics are a superset of [path.Match]:
//
//   - Whole-pattern "*" and "**" match ANY value, including one with '/' (plain
//     path.Match would restrict "*" to values with no '/', denying paths/URIs).
//   - A "**" segment matches zero or more '/'-separated segments, so "/reports/**"
//     matches "/reports/q3.pdf" and "/reports/sub/q3.pdf".
//   - Every other pattern keeps path.Match semantics: a single '*' matches a run
//     of non-'/' characters and does NOT cross '/'.
//
// This matches argument *values*; target *names* use [MatchesResource]
// (single-segment, no "**"). The glob applies only to string values; non-string
// values match by exact equality. A malformed pattern reports false (fail closed),
// and is also rejected at manifest load.
func MatchValueGlob(pattern, value string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}
	// valSpansSep[j] flags a value segment that decodes to span a '/' (an encoded
	// separator), consumed by matchGlobSegments to forbid a single-segment pattern
	// element from matching it while still letting a "**" segment absorb it.
	var valSpansSep []bool
	// A path-style pattern confines a value to a subtree; a slashless pattern is a
	// single-segment grant. Both reject a value that traverses or smuggles a separator.
	if strings.Contains(pattern, "/") {
		var ok bool
		value, valSpansSep, ok = confinePathStylePattern(pattern, value)
		if !ok {
			return false
		}
	} else if !confineSlashlessPattern(value) {
		return false
	}
	// Fast path: without a "**" the matcher is exactly path.Match, so existing
	// single-'*' patterns are byte-for-byte unchanged.
	if !strings.Contains(pattern, "**") {
		matched, err := path.Match(pattern, value)
		return err == nil && matched
	}
	// Pattern and value must agree on being rooted (start with "/"). Otherwise
	// strings.Split("/**", "/") and strings.Split("", "/") both yield a leading ""
	// segment, so "/**" would match "" even though "" is not an absolute path.
	if strings.HasPrefix(pattern, "/") != strings.HasPrefix(value, "/") {
		return false
	}
	// A "**" appears somewhere: match segment-by-segment so a literal "**"
	// segment can span '/'. Non-"**" segments still delegate to path.Match, so
	// '*', '?' and '[...]' keep their single-segment meaning within a segment.
	return matchGlobSegments(strings.Split(pattern, "/"), strings.Split(value, "/"), valSpansSep)
}

// matchGlobSegments matches '/'-split pattern segments against '/'-split value segments. A
// literal "**" matches zero or more value segments; every other segment matches exactly
// one via path.Match. valSpansSep, when non-nil, flags a value segment as consumable only
// by a "**" segment, so a co-occurring single '*' cannot be widened past its scope.
//
// Runs as a bottom-up DP over suffixes (dp[i][j] == pat[i:] matches val[j:]),
// O(len(pat)*len(val)) time/space — removing the O(n^k) backtracking the recursive matcher
// had for k non-adjacent "**" groups, a value-driven DoS since n is attacker-influenced.
func matchGlobSegments(pat, val []string, valSpansSep []bool) bool {
	m, n := len(pat), len(val)
	// n is caller/attacker controlled, so cap it (and m) before the (m+1)*(n+1) DP
	// allocation. Documented as a hard limit in docs/capability-manifest-guide.md.
	if n > maxGlobSegments || m > maxGlobSegments {
		return false
	}
	// dp[i][j] == pat[i:] matches val[j:]; the extra row/column hold the
	// fully-consumed base cases.
	dp := make([][]bool, m+1)
	for i := range dp {
		dp[i] = make([]bool, n+1)
	}
	// Empty pattern matches only an empty value.
	dp[m][n] = true
	for i := m - 1; i >= 0; i-- {
		if pat[i] == "**" {
			// Match zero value segments, or consume one and stay on this "**".
			for j := n; j >= 0; j-- {
				dp[i][j] = dp[i+1][j] || (j < n && dp[i][j+1])
			}
			continue
		}
		// A non-"**" segment must not itself match a separator-spanning value segment
		// (a "**" segment, handled above, still may).
		for j := n - 1; j >= 0; j-- {
			if len(valSpansSep) > j && valSpansSep[j] {
				continue // leaves dp[i][j] false: a single segment cannot match a separator-spanning value
			}
			matched, err := path.Match(pat[i], val[j])
			dp[i][j] = err == nil && matched && dp[i+1][j+1]
		}
	}
	return dp[0][0]
}
