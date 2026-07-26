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

// errPathMalformedEscape and errPathNUL are the two fail-closed reasons
// decodePathForConfinement can reject a value. They are distinguished (rather
// than a single bool) because handleAllowedExtensions treats them differently: a
// malformed '%' is a legal filename character for an upstream that does not
// percent-decode, while an embedded NUL is a truncation vector that must always
// deny.
var (
	errPathMalformedEscape = errors.New("malformed percent-escape")
	errPathNUL             = errors.New("embedded NUL byte")
)

// decodePathForConfinement folds a value to the form an upstream will resolve
// before a path-confinement guard inspects its '/'-split segments: '\' folds to
// '/', the value is percent-decoded once (%2f -> '/', %2e -> '.'), and a decoded
// '\' is folded again. It returns a non-nil error (errPathMalformedEscape or
// errPathNUL) for input callers MUST fail closed on rather than matching the
// literal. An embedded NUL (literal or decoded %00) is rejected because a
// NUL-truncating upstream would resolve a different file than the guard inspects
// (CWE-158/CWE-626). The single decode pass mirrors an upstream that decodes once,
// so a doubly-encoded %252e stays %2e. Shared by MatchValueGlob and
// handleAllowedExtensions so they normalize the same smuggling class in lock-step.
func decodePathForConfinement(value string) (string, error) {
	folded := strings.ReplaceAll(value, "\\", "/")
	// Reject an embedded NUL BEFORE decoding so a literal NUL fails closed
	// regardless of escape validity: errPathNUL must win over
	// errPathMalformedEscape, else the lenient malformed-escape branch in
	// handleAllowedExtensions would match a NUL-bearing path literally.
	if strings.IndexByte(folded, 0) >= 0 {
		return "", errPathNUL
	}
	decoded, err := url.PathUnescape(folded)
	if err != nil {
		return "", errPathMalformedEscape
	}
	decoded = strings.ReplaceAll(decoded, "\\", "/")
	if strings.IndexByte(decoded, 0) >= 0 { // still catch %00 -> NUL
		return "", errPathNUL
	}
	return decoded, nil
}

// containsEncodedSeparator reports whether s contains a percent-encoded path
// separator token (%2f for '/', %5c for '\'), case-insensitively. Two callers:
// on the runtime fail-closed path when a VALUE cannot be fully percent-decoded (a
// malformed escape elsewhere in it), so a valid encoded separator riding alongside
// the bad escape is still caught rather than matched as literal bytes; and at load
// on a PATTERN's literal text (via patternLiteralsOutsideClasses), where such a
// token marks a silently dead grant. Sharing one token definition keeps the load
// rejection and the runtime denial in lock-step.
func containsEncodedSeparator(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c")
}

// globClassPlaceholder stands in for an elided bracket class in
// patternLiteralsOutsideClasses. It must be a byte that can never form part of an
// encoded-separator token, so eliding a class cannot splice one into existence.
const globClassPlaceholder = '\x00'

// patternLiteralsOutsideClasses renders a glob pattern with every bracket class
// replaced by a single placeholder, leaving only the characters path.Match compares
// literally. A '%', '2' or 'f' written INSIDE a class ("[a%2f]") is a class MEMBER —
// the class consumes one value character — so such a pattern is a live grant and
// must not be read as an encoded separator. Mirrors path.Match's scanChunk, as
// countPatternPathSeparators does: '[' opens a class and ']' closes an OPEN one (no
// nesting) while a ']' with no class open is an ordinary literal, and a
// backslash-escaped character is a single literal unit that neither opens nor closes
// one. The scan is deliberately literal-only: a token split by a
// wildcard ("%2*f") still loads, matching the fail-closed direction — this rejects
// unmatchable grants, it is not a security boundary.
func patternLiteralsOutsideClasses(pattern string) string {
	var b strings.Builder
	inClass := false
	for i := 0; i < len(pattern); i++ {
		switch {
		case pattern[i] == '\\' && i+1 < len(pattern):
			i++
			if !inClass {
				b.WriteByte(pattern[i])
			}
		case pattern[i] == '[':
			if !inClass {
				b.WriteByte(globClassPlaceholder)
			}
			inClass = true
		case pattern[i] == ']':
			// A ']' only closes a class that is actually open. With no open '[' it is an
			// ordinary literal in path.Match's grammar, so it must be EMITTED, not dropped:
			// swallowing it splices its neighbours together, and two bytes that were never
			// adjacent in the pattern can then read as an encoded separator ("a%2]f" would
			// render "a%2f"), rejecting a valid, matchable grant at load.
			if !inClass {
				b.WriteByte(pattern[i])
				break
			}
			inClass = false
		default:
			if !inClass {
				b.WriteByte(pattern[i])
			}
		}
	}
	return b.String()
}

// maxGlobSegments caps the '/'-separated segment count a "**" pattern matches, so
// an attacker-supplied value's slash count cannot drive an unbounded O(m*n)
// allocation in matchGlobSegments. 1000 is far above any legitimate path/URI
// depth; an oversized value fails closed.
const maxGlobSegments = 1000

// ValidateValueGlob reports whether pattern is a well-formed allowedValues glob,
// using the SAME structural decomposition MatchValueGlob applies at runtime so the
// two cannot disagree. A whole-string path.Match would diverge for a "**"-bearing
// pattern whose bracket class spans a "/" (e.g. "[a/b]/**"): it parses as one valid
// class but yields an ErrBadPattern segment at runtime, loading clean yet matching
// nothing (a silently dead, deny-all policy). Returns path.ErrBadPattern for a
// malformed pattern, nil otherwise.
func ValidateValueGlob(pattern string) error {
	// Whole-pattern wildcards match anything and are never path.Match'd at runtime.
	if pattern == "*" || pattern == "**" {
		return nil
	}
	// A pattern carrying an ENCODED path separator (%2f, %5c) in its LITERAL text is a
	// silently dead grant: the runtime confinement decodes a candidate value's separators
	// and denies any that decode to contain one, so the only value such a pattern could
	// match is itself denied. Reject it at load (like the "."/".." segments below) so the
	// operator sees the mistake instead of a rule that matches nothing. Write a literal
	// '/' for a separator. Bracket classes are elided first: "[a%2f]" spells a class whose
	// members include '%', '2' and 'f', and it matches those values at runtime.
	if containsEncodedSeparator(patternLiteralsOutsideClasses(pattern)) {
		return fmt.Errorf("%w: pattern contains an encoded path separator (%%2f/%%5c); the runtime confinement denies any value that decodes to a separator, so the grant would match nothing", path.ErrBadPattern)
	}
	// A "**" pattern with more '/'-separated segments than the runtime cap is likewise a
	// dead grant: matchGlobSegments refuses to match beyond maxGlobSegments. Segment
	// count is one more than the '/' count, so "count >= cap" is "segments > cap". (A
	// non-"**" pattern is matched whole by path.Match with no cap, so it is unaffected.)
	// Reject it at load rather than let it silently match nothing.
	if strings.Contains(pattern, "**") && strings.Count(pattern, "/") >= maxGlobSegments {
		return fmt.Errorf("%w: pattern has more than %d path segments, exceeding the runtime match cap; the grant would match nothing", path.ErrBadPattern, maxGlobSegments)
	}
	// A pattern segment that is exactly "."/".." can never match: the runtime
	// confinement scan rejects any value whose corresponding segment decodes to one
	// first, so the pattern loads clean but is a silently dead, deny-all grant.
	// Applied to a slashless pattern too — it is a single segment, and
	// confineSlashlessPattern rejects a "."/".." value the same way the path-style
	// branch does — so load-time rejection and runtime denial stay in lock-step.
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

// countPatternPathSeparators counts the '/' characters in a non-"**" glob
// pattern that [path.Match] treats as a required literal separator: every match
// must reproduce it exactly as a '/' at the corresponding position in the value,
// since neither '*' nor '?' ever consumes a '/' and every other literal
// character must match itself exactly. A '/' written inside a bracket class
// ("[…]", e.g. "[/x]" or "[^/]") is a class MEMBER instead — the class consumes
// exactly one value character, which may or may not be '/' — so it is excluded.
// Mirrors path.Match's own scanChunk exactly: '[' opens a class and ']' closes
// it (no nesting, no "]-right-after-[ is literal" special case, matching Go's
// implementation), and a backslash-escaped character (including an escaped '/')
// is a single literal unit that still counts as a required separator when it
// decodes to '/', but is never re-examined for class-boundary significance.
func countPatternPathSeparators(pattern string) int {
	count := 0
	inClass := false
	for i := 0; i < len(pattern); i++ {
		switch {
		case pattern[i] == '\\' && i+1 < len(pattern):
			i++
			if pattern[i] == '/' && !inClass {
				count++
			}
		case pattern[i] == '[':
			inClass = true
		case pattern[i] == ']':
			inClass = false
		case pattern[i] == '/' && !inClass:
			count++
		}
	}
	return count
}

// confinePathStylePattern applies subtree confinement to a path-style ("/"-bearing)
// allowedValues pattern. It decodes every separator/dot alias an upstream resolves
// ('\' separators and percent-encoding) before a "."/".." scan, so a value like
// "/reports/..%2f..%2fetc%2fpasswd" cannot smuggle a traversal past the guard (a
// malformed escape fails closed). It returns the backslash-folded value (so a
// '\'-style value still matches a '/'-style pattern; percent-decoding stays scoped
// to the confinement scan so a legitimately percent-encoded value matches its
// pattern literally), the per-segment separator-spanning flags for a "**" pattern
// (nil otherwise, for matchGlobSegments), and ok=false when the value must be denied.
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
	// An encoded separator (%2f, or %5c folded to '/') would let a single-segment
	// element ('*', '?', '[…]') span a '/' the operator scoped to one segment. The
	// proxy cannot know whether the upstream decodes it, so fail closed. A non-"**"
	// pattern confines every segment, so one total-'/'-count comparison rejects an
	// encoded separator anywhere; a "**" pattern is mixed (a "**" segment may span
	// separators, a co-occurring single-'*' may not), so flag each separator-spanning
	// value segment for matchGlobSegments instead.
	if !strings.Contains(pattern, "**") {
		valueSlashes := strings.Count(folded, "/")
		if strings.Count(scan, "/") != valueSlashes {
			return folded, nil, false
		}
		// Pattern and value must ALSO agree on segment count: without this, a class
		// that does not exclude '/' (e.g. "[^z]") matches a literal '/' already in the
		// value via path.Match's whole-value fast path, letting one class element span
		// TWO value segments the pattern's literal text scoped to one. Count only
		// pattern-side '/' that path.Match treats as a required separator — one inside a
		// bracket class is a class MEMBER, not a separator (see countPatternPathSeparators).
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

// confineSlashlessPattern reports whether a value is safe to match against a
// slashless single-segment pattern ('*.csv', 'file-?', '[abc].log', ...).
// A slashless pattern is by definition a single-segment grant, so no legitimate
// match can contain a '/': path.Match's '*' and '?' never cross '/', and a
// character class that DOES match one ('[^0-9]', '[^z]', a range straddling
// 0x2f like '[.-9]') is precisely the segment-confinement bypass this guards —
// Go's path.Match applies no '/'-exclusion inside '[…]', so a class consumes a
// literal '/' like any other rune. Comparing against the raw '/' count (as the
// path-style branch can, because '**' segments legitimately span separators)
// would admit such a value; a slashless pattern has no legitimate '/' at all, so
// forbid it outright after decoding. This also confines an encoded separator
// (%2f, %5c) or a literal '\' that a lenient upstream would resolve into a
// subpath ("..%2f..%2fetc%2f..."), the same traversal the slash-bearing branch
// confines. An embedded NUL always fails closed; a merely malformed '%' is a legal
// filename char for a non-decoding upstream, so it folds only '\' and matches the
// literal form — but still denies when a VALID encoded separator rides alongside the
// bad escape ("..%2f..%2fetc%zz"), which a lenient upstream would resolve.
//
// A bare "."/".." is denied for the same reason confinePathStylePattern denies it
// segment-by-segment: it names the tool's working directory or its PARENT, so a
// slashless grant an operator wrote to scope one segment (e.g. ".*" for dotfiles
// like ".env", or "??") would otherwise also admit the traversal value "..", which
// the upstream resolves outside the intended directory. The '/'-count guard alone
// does not catch it — ".." carries no separator — so the dot check must be explicit.
func confineSlashlessPattern(value string) bool {
	scan, err := decodePathForConfinement(value)
	if errors.Is(err, errPathNUL) {
		return false
	}
	if errors.Is(err, errPathMalformedEscape) {
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
	// separator such as %2f). Populated only for a path-style "**" pattern and
	// consumed by matchGlobSegments, which forbids a single-segment pattern element
	// from matching such a value while still letting a "**" segment absorb it. Nil
	// otherwise (the non-"**" path uses the total-count guard below).
	var valSpansSep []bool
	// Path-confinement: a path-style pattern (contains '/') confines a value to a
	// subtree (e.g. "/reports/**"), while a slashless pattern is a single-segment
	// grant; both reject a value that traverses or smuggles a separator out of scope.
	// The two branches are extracted into confine* helpers to keep MatchValueGlob flat.
	if strings.Contains(pattern, "/") {
		var ok bool
		// The path-style branch folds '\' into value and, for a "**" pattern, computes
		// the per-segment separator flags, so it returns both back for use below.
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

// matchGlobSegments matches '/'-split pattern segments against '/'-split value
// segments. A literal "**" segment matches zero or more value segments; every
// other segment matches exactly one value segment via path.Match.
//
// valSpansSep, when non-nil, is index-aligned with val and flags value segments
// that decode to span a '/' (an encoded separator). Such a segment may be consumed
// only by a "**" segment, so a single '*' co-occurring with "**" cannot be widened
// past the one segment the operator scoped. Nil when no per-segment confinement
// applies.
//
// It runs as a bottom-up DP over suffixes: dp[i][j] reports whether pat[i:] matches
// val[j:]. A "**" segment matches zero segments (dp[i+1][j]) or consumes one and
// stays (dp[i][j+1]); any other advances both via path.Match. O(len(pat)*len(val))
// time and space, removing the O(n^k) backtracking the recursive matcher had for k
// non-adjacent "**" groups — a value-driven DoS since n is attacker-influenced.
func matchGlobSegments(pat, val []string, valSpansSep []bool) bool {
	m, n := len(pat), len(val)
	// n is caller/attacker controlled, so cap it (and m) at maxGlobSegments — far
	// above any legitimate depth — before the (m+1)*(n+1) DP allocation. Documented
	// as a hard limit in docs/capability-manifest-guide.md.
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
		// A non-"**" segment must match exactly one value segment -- and one that
		// does not itself decode to span a '/', so a single-segment element never
		// absorbs an encoded separator the operator scoped out (a "**" segment,
		// handled above, still may).
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
