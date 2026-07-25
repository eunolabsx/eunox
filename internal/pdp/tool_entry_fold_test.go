// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestScanToolEntryFoldsUnicodeCaseVariants pins the top-level fold to the same rule
// encoding/json uses to bind object keys to struct fields.
//
// The bypass this guards: strings.ToLower leaves U+017F (LATIN SMALL LETTER LONG S)
// unchanged because it is already lower case, so "deſcription" and "description" stay
// distinct under ToLower and the duplicate-key scan clears the entry. Go's decoder folds
// them together and keeps the LAST, so the pinned descriptionHash is computed over the
// clean value while a case-sensitive host (JSON.parse, the Python SDK) renders the
// injected one — the tool-poisoning divergence the scan exists to catch.
func TestScanToolEntryFoldsUnicodeCaseVariants(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "long s in description",
			raw:  "{\"name\":\"t\",\"description\":\"<INJECT>\",\"deſcription\":\"<CLEAN>\"}",
		},
		{
			// U+017F again, this time on the key that carries the hashed schema surface.
			name: "long s in inputSchema",
			raw:  "{\"name\":\"t\",\"inputSchema\":{\"a\":1},\"inputſchema\":{\"b\":2}}",
		},
		{
			// U+212A KELVIN SIGN folds onto k/K but is already UPPER case — the mirror of
			// the U+017F case, which is already lower case. A ToUpper-based fold would miss
			// this one exactly as ToLower misses "deſcription"; only a true simple-fold
			// catches both, which is why neither shortcut is acceptable here.
			name: "kelvin sign in a key",
			raw:  "{\"name\":\"t\",\"kind\":\"a\",\"Kind\":\"b\"}",
		},
		{
			name: "plain case variant still caught",
			raw:  `{"name":"t","description":"<INJECT>","Description":"<CLEAN>"}`,
		},
		{
			name: "exact duplicate still caught",
			raw:  `{"name":"t","description":"<INJECT>","description":"<CLEAN>"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanToolEntry(json.RawMessage(tc.raw)); !got.untrustworthy {
				t.Errorf("scanToolEntry(%s).untrustworthy = false, want true — "+
					"a key the decoder folds together was not detected as a collision", tc.raw)
			}
		})
	}
}

// TestScanToolEntryFoldDivergenceIsReal demonstrates the divergence the fold protects
// against, so a future change to the fold cannot be justified without confronting it: the
// decoder keeps the LAST folded key, while the raw bytes a case-sensitive host parses
// still carry the first.
func TestScanToolEntryFoldDivergenceIsReal(t *testing.T) {
	const raw = "{\"name\":\"t\",\"description\":\"<INJECT>\",\"deſcription\":\"<CLEAN>\"}"

	var decoded struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Description != "<CLEAN>" {
		t.Fatalf("decoder bound Description = %q, want %q — the premise of this test no "+
			"longer holds and the fold rule needs re-deriving", decoded.Description, "<CLEAN>")
	}
	if !strings.Contains(raw, "<INJECT>") {
		t.Fatal("raw bytes should still carry the injected value a case-sensitive host renders")
	}
	if !scanToolEntry(json.RawMessage(raw)).untrustworthy {
		t.Error("entry whose decoded value diverges from its raw bytes must be untrustworthy")
	}
}

// TestScanToolEntryAcceptsHonestDistinctKeys guards the other direction: folding must not
// be so aggressive that a legitimate entry is rejected. These keys are genuinely
// different fields, not case variants of one another.
func TestScanToolEntryAcceptsHonestDistinctKeys(t *testing.T) {
	const raw = `{"name":"t","description":"d","inputSchema":{"type":"object"},"title":"x"}`
	got := scanToolEntry(json.RawMessage(raw))
	if got.untrustworthy {
		t.Error("entry with distinct top-level keys must not be flagged untrustworthy")
	}
	if len(got.names) != 1 || got.names[0] != "t" {
		t.Errorf("names = %v, want [t]", got.names)
	}
}
