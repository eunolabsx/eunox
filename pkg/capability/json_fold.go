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
// A key already in canonical form is returned as-is, no allocation: canonicalFoldRune picks
// the representative that makes an ordinary lower-case ASCII key its own canonical form, so
// the common case (run per key of every scanned JSON object) pays nothing.
func FoldJSONKey(key string) string {
	for i := 0; i < len(key); {
		r, size := utf8.DecodeRuneInString(key[i:])
		// An invalid byte decodes to (RuneError, 1) and is NOT left alone: the builder path
		// rewrites it to the replacement character. Two keys differing only in invalid bytes
		// then fold together — over-reporting a duplicate, the fail-closed direction.
		if c := canonicalFoldRune(r); c != r || (r == utf8.RuneError && size == 1) {
			return foldJSONKeyFrom(key, i)
		}
		i += size
	}
	return key
}

// foldJSONKeyFrom builds the folded key once the scan finds a rune at start that is not
// already canonical; everything before start scanned clean and is copied verbatim.
func foldJSONKeyFrom(key string, start int) string {
	var b strings.Builder
	b.Grow(len(key))
	b.WriteString(key[:start])
	for _, r := range key[start:] {
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
