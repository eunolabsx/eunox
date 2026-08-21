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
	for _, literal := range []string{"1", "1.0", "1e3", "1.50", "0", "100", "12345678901234567890", "0.1", "1e999"} {
		t.Run(literal, func(t *testing.T) {
			canonical, _, ok := CanonicalNumberLiteral(literal)
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

// TestCanonicalNumberLiteral_ExactReportsWhetherTheNumberSurvives: a
// renormalization that merely re-spells has a form the caller can recommend writing; one
// that ROUNDS has none, and a caller that offered the rounded form as the correction would
// be telling an author to declare a magnitude they did not write.
func TestCanonicalNumberLiteral_ExactReportsWhetherTheNumberSurvives(t *testing.T) {
	for literal, wantExact := range map[string]bool{
		"1":                              true,
		"1.0":                            true,
		"1e3":                            true,
		"12345678901234567890":           true,
		"9007199254740993":               true,  // 2^53+1: yaml resolves an integer through int64/uint64, so it never reaches a float
		"1e999":                          true,  // past float64's range: yaml leaves it a string and the loader stores it verbatim
		"123456789012345678901234567890": false, // rounds: 1.2345678901234568e+29
		"18446744073709551616":           false, // 2^64, the first integer past uint64 and so the first that rounds
	} {
		t.Run(literal, func(t *testing.T) {
			canonical, exact, ok := CanonicalNumberLiteral(literal)
			if !ok {
				t.Fatalf("%q must be recognized as a number", literal)
			}
			if exact != wantExact {
				t.Fatalf("CanonicalNumberLiteral(%q) = %q, exact=%v; want exact=%v", literal, canonical, exact, wantExact)
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
			if got, _, ok := CanonicalNumberLiteral(literal); ok {
				t.Fatalf("%q is not a number, got canonical form %q", literal, got)
			}
		})
	}
}
