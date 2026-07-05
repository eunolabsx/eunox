// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzClassifyRedactableLeaf_GuardMatchesFullDecode is the safety net for
// classifyRedactableLeaf's fast-path guard: the guard is a reactively-grown byte
// allowlist ('{' anywhere, or a leading '"' or '[') that has already been patched
// twice for two real DLP evasions, and nothing downstream re-checks a leaf the
// guard rejects — if the guard wrongly says leafKindOther, the leaf passes through
// with zero further inspection.
//
// This asserts the invariant the guard is supposed to encode: "guard says skip"
// implies "attempting a full JSON decode would also find nothing redactable" (no
// container, no further string-encoding layer). It does this by independently
// re-implementing the decode step WITHOUT the byte pre-filter, and checking that
// whenever the fast path would bail to leafKindOther, an unconditional decode
// attempt agrees. If a future guard edit (or JSON grammar corner case) breaks
// that equivalence, this fuzz target should find it rather than silently
// widening the redaction bypass.
func FuzzClassifyRedactableLeaf_GuardMatchesFullDecode(f *testing.F) {
	// Seeds: plain prose, genuine scalars, and the two prior real evasions (a
	// unicode-escaped-brace string layer, and the same wrapped in an array) —
	// each of which the guard must NOT reject, since they decode to a container
	// or a further string layer.
	f.Add(`hello world`)
	f.Add(`42`)
	f.Add(`true`)
	f.Add(`null`)
	f.Add(`{"a":1}`)
	f.Add(`"{\"ssn\":\"SECRET\"}"`)
	f.Add(`["{\"ssn\":\"SECRET\"}"]`)
	f.Add(`[1, 2, 3]`)
	f.Add(``)
	f.Add(`   `)
	f.Add(string(rune(0xFEFF)) + `{}`) // BOM-prefixed object
	f.Add(`report[2024].pdf`)
	f.Add(`a footnote[1] aside`)

	f.Fuzz(func(t *testing.T, s string) {
		_, kind := classifyRedactableLeaf(s)

		// Independently decode s the same way classifyRedactableLeaf does internally,
		// but WITHOUT the fast-path byte guard, to see what an unconditional decode
		// attempt would have found.
		trimmed := trimLeadingSpaceAndBOM(s)
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.UseNumber()
		var val interface{}
		decodeErr := dec.Decode(&val)
		cleanSingleValue := decodeErr == nil && !dec.More()

		var wouldFindSomething bool
		if cleanSingleValue {
			switch val.(type) {
			case map[string]interface{}, []interface{}, string:
				wouldFindSomething = true
			}
		}

		if kind == leafKindOther && wouldFindSomething {
			t.Fatalf("classifyRedactableLeaf(%q) = leafKindOther (guard skipped it), but an unconditional decode finds a redactable container/string layer (%#v) — the fast-path guard is under-inclusive and would let this leaf's content bypass redaction", s, val)
		}
	})
}
