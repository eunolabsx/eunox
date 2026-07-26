// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// FoldJSONKey canonicalizes a JSON object key so that any two keys encoding/json could
// bind to the same struct field map to the same value. Each rune is replaced by a single
// fixed representative of its Unicode simple-fold orbit, which groups every case variant
// the decoder's field matcher treats as equal.
//
// strings.ToLower is NOT sufficient: U+017F (LATIN SMALL LETTER LONG S) is already lower
// case, so ToLower leaves "deſcription" distinct from "description", while the decoder
// folds them together and keeps the LAST. A scan that folds with ToLower therefore sees no
// collision and clears an entry whose decoded value differs from what a case-sensitive
// host renders — the tool-poisoning shape the duplicate-key scans exist to catch.
//
// This lives in capability rather than beside either caller because both the JSON-RPC
// envelope scan and the tools/list entry scan must fold identically: two copies of this
// rule is how one of them ended up on ToLower while the other was hardened. capability is
// reachable from every layer, so both reach the same implementation.
//
// A key already in canonical form is returned as-is, with no allocation. Which
// representative the orbit picks is arbitrary — any fixed choice yields the same
// equivalence classes — so canonicalFoldRune picks the one that makes the ordinary
// lower-case ASCII key ("name", "arguments", "description") its own canonical form. This
// runs per key of every scanned JSON object, so an allocation on the common case is a
// real cost paid for nothing.
func FoldJSONKey(key string) string {
	for i := 0; i < len(key); {
		r, size := utf8.DecodeRuneInString(key[i:])
		// An invalid byte decodes to (RuneError, 1) and is NOT left alone: the builder
		// path rewrites it to the replacement character, the same normalization a range
		// loop over the string performs. Two keys differing only in invalid bytes then
		// fold together, which over-reports a duplicate — the fail-closed direction.
		if c := canonicalFoldRune(r); c != r || (r == utf8.RuneError && size == 1) {
			return foldJSONKeyFrom(key, i)
		}
		i += size
	}
	return key
}

// foldJSONKeyFrom builds the folded key once the scan has found a rune at start that is
// not already canonical. Everything before start scanned clean, so it is copied verbatim
// rather than re-folded rune by rune.
func foldJSONKeyFrom(key string, start int) string {
	var b strings.Builder
	b.Grow(len(key))
	b.WriteString(key[:start])
	for _, r := range key[start:] {
		b.WriteRune(canonicalFoldRune(r))
	}
	return b.String()
}

// canonicalFoldRune returns r's Unicode simple-fold orbit representative: the largest
// ASCII member when the orbit has one, else the largest member overall.
//
// The choice is orbit-invariant — every member of an orbit walks the same cycle and so
// selects the same representative — which is the only property the fold needs; preferring
// ASCII is purely to make the common key its own canonical form. Consider the two orbits
// that reach outside ASCII: {'s','S',U+017F} and {'k','K',U+212A}. Taking the SMALLEST
// member maps them (and every other ASCII letter's orbit) to the upper-case letter, so
// "arguments" and "name" alike differ from their own fold and allocate on every call.
// Taking the largest ASCII member maps both to 's' and 'k', leaving every lower-case
// ASCII key unchanged.
func canonicalFoldRune(r rune) rune {
	// A rune with no case variants (digits, punctuation, most of Unicode) has a
	// single-member orbit: SimpleFold returns r itself and the loop never runs.
	best := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		best = preferredFoldRune(best, f)
	}
	return best
}

// preferredFoldRune picks between two members of one orbit: an ASCII member beats a
// non-ASCII one, and otherwise the larger rune wins. Within ASCII the larger of a
// {upper, lower} pair is always the lower-case letter, which is what makes an ordinary
// lower-case key its own fold.
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
