// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// TestFoldJSONKey_EquivalenceClasses is the property that matters: two keys fold to the
// same value exactly when encoding/json's field matcher would bind them to the same
// struct field. The concrete representative the fold picks is an implementation detail,
// so this asserts agreement and disagreement, never a literal output.
func TestFoldJSONKey_EquivalenceClasses(t *testing.T) {
	t.Parallel()
	same := [][]string{
		{"name", "Name", "NAME", "nAmE"},
		// U+017F LATIN SMALL LETTER LONG S is already lower case, so strings.ToLower
		// leaves it distinct while the decoder folds it onto 's'. This pair is the whole
		// reason the fold is not ToLower.
		{"description", "deſcription", "Description", "DESCRIPTION"},
		{"inputSchema", "inputſchema", "INPUTSCHEMA", "inputschema"},
		// U+212A KELVIN SIGN is the mirror case: already UPPER case, so a ToUpper-based
		// fold would miss it.
		{"key", "Key", "KEY", "Key"},
		{"uri", "URI", "Uri"},
	}
	for _, group := range same {
		want := FoldJSONKey(group[0])
		for _, k := range group[1:] {
			if got := FoldJSONKey(k); got != want {
				t.Errorf("FoldJSONKey(%q) = %q, want it to equal FoldJSONKey(%q) = %q", k, got, group[0], want)
			}
		}
	}

	distinct := []string{"name", "names", "nome", "uri", "url", "description", "descriptions"}
	seen := map[string]string{}
	for _, k := range distinct {
		f := FoldJSONKey(k)
		if prev, dup := seen[f]; dup {
			t.Errorf("FoldJSONKey(%q) and FoldJSONKey(%q) both = %q; distinct keys must not fold together", prev, k, f)
		}
		seen[f] = k
	}
}

// TestFoldJSONKey_LowerCaseASCIIIsItsOwnFold pins the property the no-allocation fast
// path depends on. It is also what lets a caller compare a folded wire key against a
// derived constant without a second fold.
func TestFoldJSONKey_LowerCaseASCIIIsItsOwnFold(t *testing.T) {
	t.Parallel()
	for _, k := range []string{"name", "arguments", "uri", "tools", "description", "inputschema", "jsonrpc", "id", "method", "params", "result", "error", "key", "s", ""} {
		if got := FoldJSONKey(k); got != k {
			t.Errorf("FoldJSONKey(%q) = %q, want it unchanged", k, got)
		}
	}
}

// TestFoldJSONKey_NoAllocationOnCanonicalKeys: the fold runs per key of every scanned
// JSON object, so the common case must not allocate. Before the fast path every ordinary
// key differed from its own fold (the orbit representative was the UPPER-case letter) and
// allocated a fresh string on every call.
func TestFoldJSONKey_NoAllocationOnCanonicalKeys(t *testing.T) {
	for _, k := range []string{"name", "arguments", "description", "inputschema"} {
		if got := testing.AllocsPerRun(100, func() { _ = FoldJSONKey(k) }); got != 0 {
			t.Errorf("FoldJSONKey(%q) allocated %v times per run, want 0", k, got)
		}
	}
}

// TestCanonicalFoldRune_IsOrbitInvariant is the correctness backstop for the
// representative choice: every member of a simple-fold orbit must select the same one, or
// the fold would report two case variants as distinct keys and the duplicate-key scans
// would clear an entry the decoder collapses. Swept over the whole BMP rather than a
// hand-picked table, so a future change to the preference rule cannot pass by accident.
func TestCanonicalFoldRune_IsOrbitInvariant(t *testing.T) {
	t.Parallel()
	for r := rune(0); r <= 0xFFFF; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		want := canonicalFoldRune(r)
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if got := canonicalFoldRune(f); got != want {
				t.Fatalf("canonicalFoldRune(%U) = %U but canonicalFoldRune(%U) = %U; orbit members must agree", f, got, r, want)
			}
		}
	}
}

// TestFoldJSONKey_InvalidUTF8NormalizesToReplacement pins the pre-existing handling of a
// key carrying invalid UTF-8: the bytes are normalized to the replacement character, so
// two such keys fold together and the scan reports a duplicate. That over-reports rather
// than under-reports, which is the fail-closed direction, and the fast path must not
// quietly change it by passing the raw bytes through.
func TestFoldJSONKey_InvalidUTF8NormalizesToReplacement(t *testing.T) {
	t.Parallel()
	a := FoldJSONKey("na\xffme")
	b := FoldJSONKey("na\xfeme")
	if a != b {
		t.Errorf("FoldJSONKey(%q) = %q and FoldJSONKey(%q) = %q; invalid bytes must normalize identically", "na\xffme", a, "na\xfeme", b)
	}
	if !utf8.ValidString(a) {
		t.Errorf("FoldJSONKey(%q) = %q, want valid UTF-8", "na\xffme", a)
	}
}

// TestCanonicalCaseFold_IsEqualFoldsCanonicalForm pins the property every caller of the
// fold relies on and that no caller can check for itself: two strings fold to the same
// value EXACTLY when strings.EqualFold reports them equal. A load-time dedup keyed on the
// fold is only a certificate about an EqualFold matcher's behavior while that holds — the
// effect.byArgument table certified unambiguous at load and then colliding at runtime is
// what a ToLower-based dedup produced.
func TestCanonicalCaseFold_IsEqualFoldsCanonicalForm(t *testing.T) {
	t.Parallel()
	corpus := []string{
		"", "s", "S", "ſ", "select", "SELECT", "ſelect", "ſELECT",
		"k", "K", "K", "key", "KEY", "Key",
		"drop", "DROP", "DrOp", "delete", "ı", "I", "i",
		"straße", "STRASSE", "ß", "ss", "SS",
		"na\xffme", "na\xfeme", "na�me", "name",
		"İ", "ΐ", "ΐ", "σ", "ς", "Σ",
	}
	for _, a := range corpus {
		for _, b := range corpus {
			want := strings.EqualFold(a, b)
			if got := canonicalCaseFold(a) == canonicalCaseFold(b); got != want {
				t.Errorf("canonicalCaseFold(%q)==canonicalCaseFold(%q) is %v, but strings.EqualFold reports %v; the fold must be EqualFold's canonical form", a, b, got, want)
			}
		}
	}
}

// TestCanonicalCaseFold_IsEqualFoldsCanonicalFormOverBMPPairs sweeps the same property over
// every simple-fold orbit in the BMP rather than a hand-picked corpus, so a future change to
// the representative rule cannot preserve the table above by accident.
func TestCanonicalCaseFold_IsEqualFoldsCanonicalFormOverBMPPairs(t *testing.T) {
	t.Parallel()
	for r := rune(0); r <= 0xFFFF; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			a, b := "x"+string(r)+"y", "x"+string(f)+"y"
			if !strings.EqualFold(a, b) {
				t.Fatalf("strings.EqualFold(%q, %q) is false for two members of one orbit; the premise of this test is wrong", a, b)
			}
			if canonicalCaseFold(a) != canonicalCaseFold(b) {
				t.Fatalf("canonicalCaseFold(%q) != canonicalCaseFold(%q), but strings.EqualFold matches them", a, b)
			}
		}
	}
}
