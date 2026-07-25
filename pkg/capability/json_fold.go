// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"unicode"
)

// FoldJSONKey canonicalizes a JSON object key so that any two keys encoding/json could
// bind to the same struct field map to the same value. Each rune is replaced by the
// smallest member of its Unicode simple-fold orbit, which groups every case variant the
// decoder's field matcher treats as equal.
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
func FoldJSONKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		// SimpleFold walks the orbit in a cycle back to r; take its smallest member so
		// every equivalent rune canonicalizes identically.
		lowest := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < lowest {
				lowest = f
			}
		}
		b.WriteRune(lowest)
	}
	return b.String()
}
