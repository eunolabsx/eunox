// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
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

// Two spellings of one value must compare equal: the width a literal is read at is fixed, so
// it cannot be a property of how many characters the author typed. A per-literal width does
// exactly that, and reports a longer spelling of one number as strictly greater than itself.
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

// Parse width serves the comparison; the RENDER is bounded separately, so the audit record's
// blast_radius field stays the number the author wrote rather than the ~1200 digits a
// non-dyadic value has at the comparison width.
func TestBlastRadiusRenderIsBoundedAndFaithful(t *testing.T) {
	for _, s := range []string{"0.1", "19.99", "1.5", "250", "18446744073709551617"} {
		v, ok := ParseBlastRadiusNumber(json.Number(s))
		if !ok {
			t.Fatalf("ParseBlastRadiusNumber(%q) refused a bounded decimal literal", s)
		}
		if got := BlastRadiusText(v); got != s {
			t.Fatalf("%q rendered as %q", s, got)
		}
	}

	// A caller-supplied argument is the input the bound exists for: it must not render to
	// thousands of digits on every refusal, synchronously, inside the decision.
	worst := "0." + strings.Repeat("9", MaxNumericLiteralLen-8) + "e-1024"
	v, ok := ParseBlastRadiusNumber(json.Number(worst))
	if !ok {
		t.Fatalf("%.12s... is inside NumericLiteralBounded", worst)
	}
	if got := len(BlastRadiusText(v)); got > 2*MaxNumericLiteralLen {
		t.Fatalf("the worst in-grammar literal rendered %d chars", got)
	}

	// A caller that decoded without UseNumber lost the literal; its magnitude still renders as
	// the number it wrote, not as the 55-digit exact value of the float64 behind it.
	spec := &BlastRadiusSpec{Argument: "amount"}
	f, ok := spec.resolve(map[string]interface{}{"amount": 0.1})
	if !ok {
		t.Fatal("a float64 argument is a magnitude")
	}
	if got := BlastRadiusText(f); got != "0.1" {
		t.Fatalf("float64 0.1 rendered as %q", got)
	}
}

// The property a bound actually depends on, over the range where the old parse was wrong and
// where a per-literal width made it wrong differently: if a value is over its bound exactly,
// the comparison must say so. Sweeping adjacent decimals is what finds this — the committed
// cases before it were all integers, which is the arm that is exact by construction.
func TestBlastRadiusComparisonAgreesWithExactArithmetic(t *testing.T) {
	rnd := rand.New(rand.NewSource(20260906))
	for i := 0; i < 20000; i++ {
		whole := rnd.Int63n(1 << 62)
		frac := rnd.Intn(9)
		lower := fmt.Sprintf("%d.%d", whole, frac)
		upper := fmt.Sprintf("%d.%d", whole, frac+1)

		v, okv := ParseBlastRadiusNumber(json.Number(upper))
		l, okl := ParseBlastRadiusNumber(json.Number(lower))
		if !okv || !okl {
			t.Fatalf("%q and %q are bounded decimal literals", upper, lower)
		}
		ev, _ := new(big.Rat).SetString(upper)
		el, _ := new(big.Rat).SetString(lower)

		// Both directions: the fail-OPEN (over its bound, reported as within) and the
		// fail-CLOSED regression a per-literal width introduced (within, reported as over).
		if got, want := v.Cmp(l) > 0, ev.Cmp(el) > 0; got != want {
			t.Fatalf("%s vs %s: comparison says exceeds=%v, exact arithmetic says %v", upper, lower, got, want)
		}
		if got, want := l.Cmp(v) > 0, el.Cmp(ev) > 0; got != want {
			t.Fatalf("%s vs %s: comparison says exceeds=%v, exact arithmetic says %v", lower, upper, got, want)
		}
	}
}

// The shapes the sweep above generalizes, kept by name because each was a verified wrong
// verdict: the first two under the bound and reported over it, the rest over and reported
// within.
func TestBlastRadiusComparisonNamedRegressions(t *testing.T) {
	for _, tc := range []struct {
		value, limit string
		exceeds      bool
	}{
		{"1.1", "1.100000000000000000001", false},
		{"0.1", "0.100000000000000000021", false},
		{"100000000000000000000.3", "100000000000000000000.2", true},
		{"0.30000000000000000000000000000000000000001", "0.3", true},
		{"1376241083072480382061353.56", "1376241083072480382061353.55", true},
	} {
		v, _ := ParseBlastRadiusNumber(json.Number(tc.value))
		ceiling := &EffectCeiling{MaxBlastRadius: num(tc.limit)}
		eff := &ResolvedEffect{Class: EffectReversible, BlastRadius: v, Annotated: true}
		if exceeds, _ := ceiling.Exceeds(eff); exceeds != tc.exceeds {
			t.Errorf("%s against %s: exceeds=%v, want %v", tc.value, tc.limit, exceeds, tc.exceeds)
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
	// And the sizing rule itself: an integer is carried at whatever width it needs, exactly.
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
}

// A bound this comparison cannot read refuses every quantified call for the process's
// lifetime, so it must not report the ACTION as too large — that sends an operator to tune
// the call rather than to the one literal that is wrong. Reachable only through
// WithEffectCeiling, which takes a ceiling directly and never passes through the loader.
func TestEffectCeiling_UnreadableBoundNamesItselfRatherThanTheAction(t *testing.T) {
	v, _ := ParseBlastRadiusNumber(json.Number("5"))
	eff := &ResolvedEffect{Class: EffectReversible, BlastRadius: v, Annotated: true}
	for _, limit := range []string{
		"Inf", "+Inf", // the natural spellings of "no magnitude bound"
		"1e2000",                         // over the exponent bound
		"0x10", "1_000", "1p10", "0b101", // outside the decimal grammar
		strings.Repeat("9", MaxNumericLiteralLen+1), // over the length bound
	} {
		ceiling := &EffectCeiling{MaxBlastRadius: num(limit)}
		exceeds, reasons := ceiling.Exceeds(eff)
		if !exceeds {
			t.Fatalf("a bound this comparison cannot read (%.12s) must fail closed", limit)
		}
		if len(reasons) != 1 || reasons[0] != "blast_radius_bound_unreadable" {
			t.Fatalf("%.12s: reasons = %v, want [blast_radius_bound_unreadable]", limit, reasons)
		}
	}
	// A readable bound still reports the action, so the new reason did not swallow the old one.
	over := &EffectCeiling{MaxBlastRadius: num("1")}
	if _, reasons := over.Exceeds(eff); len(reasons) != 1 || reasons[0] != "blast_radius" {
		t.Fatalf("reasons = %v, want [blast_radius]", reasons)
	}
}
