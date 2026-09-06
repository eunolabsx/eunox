// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"strings"
	"testing"
)

// The exact arm exists to compare integers around and above 2^63 — which is precisely where
// a zero-value big.Float's default precision of 64 bits stopped being exact. Both sides of
// the comparison rounded to the same value, so a magnitude ONE OVER the bound compared equal
// and was admitted: fail-open, at exactly the boundary the arm polices, and reachable at
// wei-scale magnitudes a token-transfer tool really carries.
func TestBlastRadiusComparisonIsExactPastSixtyFourMantissaBits(t *testing.T) {
	for _, tc := range []struct {
		name         string
		value, limit string
	}{
		// 2^64 + 1 against 2^64: the first integer the old precision could not separate.
		{"just past 2^64", "18446744073709551617", "18446744073709551616"},
		// 10^20 + 1 against 10^20: the same failure at a magnitude an operator would author.
		{"just past 10^20", "100000000000000000001", "100000000000000000000"},
		// Far above the grammar's midpoint, to show the fix is not tuned to one width.
		{"120 significant bits", "1329227995784915872903807060280344577", "1329227995784915872903807060280344576"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := ParseBlastRadiusNumber(json.Number(tc.value))
			if !ok {
				t.Fatalf("ParseBlastRadiusNumber(%q) refused a bounded decimal literal", tc.value)
			}
			if got := v.Text('f', -1); got != tc.value {
				t.Fatalf("the parsed magnitude rounded: got %s, want %s", got, tc.value)
			}
			eff := &ResolvedEffect{Class: EffectReversible, BlastRadius: v, Annotated: true}

			ceiling := &EffectCeiling{MaxBlastRadius: num(tc.limit)}
			if exceeds, _ := ceiling.Exceeds(eff); !exceeds {
				t.Fatalf("%s must exceed the ceiling %s", tc.value, tc.limit)
			}
			// The bound itself still passes, so the fix did not turn the comparison into a
			// strictly-less-than one.
			atBound, _ := ParseBlastRadiusNumber(json.Number(tc.limit))
			if exceeds, _ := ceiling.Exceeds(&ResolvedEffect{Class: EffectReversible, BlastRadius: atBound, Annotated: true}); exceeds {
				t.Fatalf("%s is AT the ceiling %s and must pass", tc.limit, tc.limit)
			}
		})
	}
}

// Two spellings of one value must still compare equal: big.Rat normalizes to lowest terms
// before SetRat sizes the mantissa, so the precision a literal is read at is a property of
// its VALUE and not of how many characters the author typed. Without that, deriving precision
// per-literal would report a longer spelling of the same number as strictly greater.
func TestBlastRadiusEqualValuesCompareEqualHoweverSpelled(t *testing.T) {
	for _, pair := range [][2]string{
		{"0.1", "0.10"},
		{"250", "2.5e2"},
		{"18446744073709551616", "1.8446744073709551616e19"},
		{"0", "0.000"},
	} {
		a, aok := ParseBlastRadiusNumber(json.Number(pair[0]))
		b, bok := ParseBlastRadiusNumber(json.Number(pair[1]))
		if !aok || !bok {
			t.Fatalf("both %q and %q are bounded decimal literals", pair[0], pair[1])
		}
		if a.Cmp(b) != 0 {
			t.Fatalf("%q and %q are the same value but compared %d", pair[0], pair[1], a.Cmp(b))
		}
	}
}

// A small fraction keeps the precision — and so the short rendering — it had before, which is
// what keeps the audit record's blast_radius field readable.
func TestBlastRadiusFractionsRenderShort(t *testing.T) {
	for _, s := range []string{"0.1", "19.99", "1.5"} {
		v, ok := ParseBlastRadiusNumber(json.Number(s))
		if !ok {
			t.Fatalf("ParseBlastRadiusNumber(%q) refused a bounded decimal literal", s)
		}
		if got := v.Text('f', -1); got != s {
			t.Fatalf("%q rendered as %q; a fraction must not gain digits from the exact parse", s, got)
		}
	}
}

// The string arm is the one whose literal is both caller-supplied and outside JSON's number
// grammar, so it gets the same exactness — and the same grammar refusal.
func TestBlastRadiusStringArgumentIsParsedExactly(t *testing.T) {
	spec := &BlastRadiusSpec{Argument: "amount"}
	v, ok := spec.resolve(map[string]interface{}{"amount": "  18446744073709551617  "})
	if !ok {
		t.Fatal("a bounded decimal string is a magnitude")
	}
	if got := v.Text('f', -1); got != "18446744073709551617" {
		t.Fatalf("the string arm rounded: got %s", got)
	}
	if _, ok := spec.resolve(map[string]interface{}{"amount": "0x1p4"}); ok {
		t.Fatal("a non-decimal literal is not a magnitude")
	}
}

// exceedsNumber now reads its limit through the same bounded parse as the value, so a bound
// outside the grammar is unreadable rather than parsed verbatim: reading the two sides of one
// comparison differently is what the shared parse exists to prevent. The loader already
// refuses such a bound on an authored ceiling; this closes the exported WithEffectCeiling
// seam, which never passes through it.
func TestEffectCeiling_ExceedsIsFailClosedOnAnUnboundedLimit(t *testing.T) {
	v, _ := ParseBlastRadiusNumber(json.Number("1"))
	eff := &ResolvedEffect{Class: EffectReversible, BlastRadius: v, Annotated: true}
	for _, limit := range []string{
		strings.Repeat("9", MaxNumericLiteralLen+1), // over the length bound
		"1e100000000", // over the exponent bound
		"0x1p4",       // outside the decimal grammar
	} {
		ceiling := &EffectCeiling{MaxBlastRadius: num(limit)}
		if exceeds, _ := ceiling.Exceeds(eff); !exceeds {
			t.Fatalf("a limit this comparison cannot read (%.20s) must fail closed", limit)
		}
	}
}

// The DoS bound is what keeps the exact parse from being a lever: it is applied before the
// big.Rat that would otherwise materialize the integer the literal names.
func TestParseBlastRadiusNumberStillRefusesAnUnboundedLiteral(t *testing.T) {
	for _, s := range []string{"1e100000000", strings.Repeat("1", MaxNumericLiteralLen+1), "1p1000000", "1/2"} {
		if _, ok := ParseBlastRadiusNumber(json.Number(s)); ok {
			t.Fatalf("%.20s is outside NumericLiteralBounded and must not parse", s)
		}
	}
}

// A receipt's claimed magnitude is compared against the decision's through the same parse, so
// the exactness reaches the consistency check rather than stopping at the ceiling.
func TestReceiptBlastRadiusComparisonIsExact(t *testing.T) {
	declared, ok := ParseBlastRadiusNumber(json.Number("18446744073709551616"))
	if !ok {
		t.Fatal("bounded literal")
	}
	claimed, ok := ParseBlastRadiusNumber(json.Number("18446744073709551617"))
	if !ok {
		t.Fatal("bounded literal")
	}
	if claimed.Cmp(declared) <= 0 {
		t.Fatal("a receipt claiming one more than the decision's magnitude must compare greater")
	}
	// And the sizing rule itself: an integer is carried at whatever precision it needs.
	if got := claimed.Prec(); got < 65 {
		t.Fatalf("a 65-bit integer was carried at %d bits of precision", got)
	}
}

// String and AuditDetails are reached with whatever ResolveEffect handed back, so a nil
// effect must render rather than panic — the rule Exceeds already states for itself and its
// two siblings did not follow. AuditDetails must also stay WRITABLE: both in-tree callers
// copy their own fields into what it returns, so an empty map would move the panic one line
// down.
func TestResolvedEffectAccessorsAreNilSafe(t *testing.T) {
	var eff *ResolvedEffect

	if got := eff.String(); got != "unresolved" {
		t.Fatalf("String() on a nil effect = %q", got)
	}

	d := eff.AuditDetails()
	if d == nil {
		t.Fatal("AuditDetails() must return a writable map, never nil")
	}
	if d["effect"] != true {
		t.Fatal("the layer marker must survive, so a SIEM rule keyed on it still selects the record")
	}
	if d["effect_unresolved"] != true {
		t.Fatal("the record must name the unresolved state rather than omitting the effect fields")
	}
	d["ceiling_exceeded"] = []string{"effect_unresolved"} // the write both callers perform
}
