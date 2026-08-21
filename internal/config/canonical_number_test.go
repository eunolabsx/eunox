// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// CanonicalNumberLiteral answers what this loader's YAML -> interface{} -> JSON
// renormalization does to a numeric literal, so the registry can refuse publishing a
// contract whose digest would not survive being copied into a manifest. Its whole value is
// that it AGREES with the loader, so the agreement is what these tests assert — a table of
// expected spellings alone would keep passing if the loader's own pipeline changed.

// TestCanonicalNumberLiteral_MatchesWhatTheLoaderStores runs each literal through a real
// manifest load and compares the stored blast radius against the helper's answer.
func TestCanonicalNumberLiteral_MatchesWhatTheLoaderStores(t *testing.T) {
	for _, literal := range []string{"1", "1.0", "1e3", "1.50", "0", "100", "12345678901234567890", "0.1"} {
		t.Run(literal, func(t *testing.T) {
			canonical, ok := CanonicalNumberLiteral(literal)
			if !ok {
				t.Fatalf("%q must be recognized as a number", literal)
			}
			path := filepath.Join(t.TempDir(), "manifest.json")
			body := fmt.Sprintf(`{"schemaVersion":"0.2","name":"m","version":"1.0.0",
			  "capabilities":[{"target":"tool:t","actions":["call"],
			   "effect":{"class":"reversible","blastRadius":{"value":%s,"unit":"rows"}}}]}`, literal)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			m, err := LoadManifest(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			stored := m.Capabilities[0].Effect.BlastRadius.Value.String()
			if stored != canonical {
				t.Fatalf("CanonicalNumberLiteral(%q) = %q but the loader stores %q; the registry's publish-time refusal is derived from this answer, so a disagreement lets an unpinnable entry ship", literal, canonical, stored)
			}
		})
	}
}

// TestCanonicalNumberLiteral_NonNumbers: a literal this pipeline does not read as a number
// has no canonical numeric spelling, and reporting one would have the caller "correct" a
// value into something else entirely.
func TestCanonicalNumberLiteral_NonNumbers(t *testing.T) {
	for _, literal := range []string{"", "abc", "1,2", "true", "null", "[1]"} {
		t.Run(literal, func(t *testing.T) {
			if got, ok := CanonicalNumberLiteral(literal); ok {
				t.Fatalf("%q is not a number, got canonical form %q", literal, got)
			}
		})
	}
}
