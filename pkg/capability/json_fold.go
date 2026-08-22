// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// FoldJSONKey canonicalizes a JSON object key so that any two keys encoding/json could bind
// to the same struct field map to the same value — each rune replaced by its Unicode
// simple-fold orbit representative, grouping every case variant the decoder's field matcher
// treats as equal.
//
// strings.ToLower is NOT sufficient: U+017F (LATIN SMALL LETTER LONG S) is already lower
// case, so ToLower leaves "deſcription" distinct from "description" while the decoder folds
// them together and keeps the LAST — a scan folding with ToLower sees no collision and
// misses the tool-poisoning shape the duplicate-key scans exist to catch.
//
// Lives in capability (reachable from every layer) rather than beside either caller, because
// the JSON-RPC envelope scan and the tools/list entry scan must fold identically — two copies
// of this rule is how one previously ended up on ToLower while the other was hardened.
//
// The decoder's matcher is strings.EqualFold, so this is canonicalCaseFold under the name
// that says which equivalence it stands in for; the JSON name is what lets a scan site state
// the relation it is closing rather than a fold it happens to use.
func FoldJSONKey(key string) string {
	return canonicalCaseFold(key)
}

// canonicalCaseFold returns s with each rune replaced by its Unicode simple-fold orbit
// representative, so that canonicalCaseFold(a) == canonicalCaseFold(b) exactly when
// strings.EqualFold(a, b) reports true: both are rune-wise orbit equality, and a
// representative is invariant across an orbit.
//
// That equality is the whole point — it is what lets a load-time dedup refuse in one pass
// the collisions an EqualFold matcher would otherwise resolve at runtime. A case MAPPING
// cannot stand in for it in either direction: strings.ToLower leaves U+017F (LATIN SMALL
// LETTER LONG S) distinct from "s" and strings.ToUpper leaves U+212A (KELVIN SIGN) distinct
// from "K", both of which EqualFold matches.
//
// A string already in canonical form is returned as-is, no allocation: canonicalFoldRune
// picks the representative that makes an ordinary lower-case ASCII string its own canonical
// form, so the common case (run per key of every scanned JSON object) pays nothing.
func canonicalCaseFold(s string) string {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		// An invalid byte decodes to (RuneError, 1) and is NOT left alone: the builder path
		// rewrites it to the replacement character. Two strings differing only in invalid
		// bytes then fold together — which is what EqualFold reports for them too, since it
		// decodes each to RuneError and compares orbits.
		if c := canonicalFoldRune(r); c != r || (r == utf8.RuneError && size == 1) {
			return canonicalCaseFoldFrom(s, i)
		}
		i += size
	}
	return s
}

// canonicalCaseFoldFrom builds the folded string once the scan finds a rune at start that is
// not already canonical; everything before start scanned clean and is copied verbatim.
func canonicalCaseFoldFrom(s string, start int) string {
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:start])
	for _, r := range s[start:] {
		b.WriteRune(canonicalFoldRune(r))
	}
	return b.String()
}

// canonicalFoldRune returns r's Unicode simple-fold orbit representative: the largest ASCII
// member when the orbit has one, else the largest member overall.
//
// Orbit-invariance is all correctness needs; preferring ASCII is purely to make the common
// key its own canonical form. E.g. the orbit {'s','S',U+017F}: taking the SMALLEST member
// maps it to 'S', so "arguments" differs from its own fold and allocates every call — taking
// the largest ASCII member maps it to 's', leaving lower-case ASCII keys unchanged.
func canonicalFoldRune(r rune) rune {
	// A rune with no case variants has a single-member orbit: SimpleFold returns r itself
	// and the loop never runs.
	best := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		best = preferredFoldRune(best, f)
	}
	return best
}

// preferredFoldRune picks between two members of one orbit: an ASCII member beats a
// non-ASCII one, otherwise the larger rune wins — within ASCII that's always the lower-case
// letter of an {upper, lower} pair, making an ordinary lower-case key its own fold.
func preferredFoldRune(a, b rune) rune {
	aASCII, bASCII := a < utf8.RuneSelf, b < utf8.RuneSelf
	if aASCII != bASCII {
		if aASCII {
			return a
		}
		return b
	}
	return max(a, b)
}
