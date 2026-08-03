// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

// num builds a *json.Number for a manifest numeric literal.
func num(s string) *json.Number {
	n := json.Number(s)
	return &n
}

func TestEffectClassOrdering(t *testing.T) {
	cases := []struct {
		class, limit string
		want         bool
	}{
		{EffectReversible, EffectReversible, true},
		{EffectReversible, EffectIrreversible, true},
		{EffectCompensable, EffectIrreversible, true},
		{EffectCompensable, EffectReversible, false},
		{EffectIrreversible, EffectCompensable, false},
		// Fail closed on either side being outside the closed vocabulary: an unknown
		// class cannot be shown to sit under a bound, so it must not pass one.
		{"catastrophic", EffectIrreversible, false},
		{EffectReversible, "mild", false},
		{"", EffectIrreversible, false},
	}
	for _, c := range cases {
		if got := EffectClassAtMost(c.class, c.limit); got != c.want {
			t.Errorf("EffectClassAtMost(%q, %q) = %v, want %v", c.class, c.limit, got, c.want)
		}
	}
}

func TestResolveEffect(t *testing.T) {
	amount := &BlastRadiusSpec{Argument: "amount", Unit: "usd"}

	cases := []struct {
		name          string
		contract      *EffectContract
		args          map[string]interface{}
		wantClass     string
		wantQuant     bool
		wantRadius    string
		wantAnnotated bool
		wantCompensat string
	}{
		{
			name:      "no contract resolves to the fail-closed default",
			contract:  nil,
			wantClass: EffectIrreversible,
		},
		{
			name:          "a contract with no class still resolves to irreversible but counts as annotated",
			contract:      &EffectContract{Idempotent: true},
			wantClass:     EffectIrreversible,
			wantAnnotated: true,
		},
		{
			name:          "fixed blast radius",
			contract:      &EffectContract{Class: EffectReversible, BlastRadius: &BlastRadiusSpec{Value: num("12")}},
			wantClass:     EffectReversible,
			wantQuant:     true,
			wantRadius:    "12",
			wantAnnotated: true,
		},
		{
			name:          "blast radius from a numeric argument",
			contract:      &EffectContract{Class: EffectCompensable, CompensatingAction: "tool:reverse", BlastRadius: amount},
			args:          map[string]interface{}{"amount": json.Number("5000")},
			wantClass:     EffectCompensable,
			wantQuant:     true,
			wantRadius:    "5000",
			wantAnnotated: true,
			wantCompensat: "tool:reverse",
		},
		{
			name:          "a missing argument leaves the call unquantified, not zero",
			contract:      &EffectContract{Class: EffectCompensable, CompensatingAction: "tool:reverse", BlastRadius: amount},
			args:          map[string]interface{}{},
			wantClass:     EffectCompensable,
			wantAnnotated: true,
			wantCompensat: "tool:reverse",
		},
		{
			name:          "a list argument contributes its length",
			contract:      &EffectContract{Class: EffectIrreversible, BlastRadius: &BlastRadiusSpec{Argument: "to"}},
			args:          map[string]interface{}{"to": []interface{}{"a@x", "b@x", "c@x"}},
			wantClass:     EffectIrreversible,
			wantQuant:     true,
			wantRadius:    "3",
			wantAnnotated: true,
		},
		{
			name:          "a non-numeric string argument has no magnitude and is not counted by length",
			contract:      &EffectContract{Class: EffectIrreversible, BlastRadius: &BlastRadiusSpec{Argument: "note"}},
			args:          map[string]interface{}{"note": "delete everything"},
			wantClass:     EffectIrreversible,
			wantAnnotated: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ResolveEffect(c.contract, c.args)
			if got.Class != c.wantClass {
				t.Errorf("class = %q, want %q", got.Class, c.wantClass)
			}
			if got.Quantified() != c.wantQuant {
				t.Errorf("quantified = %v, want %v", got.Quantified(), c.wantQuant)
			}
			if c.wantQuant && got.BlastRadius.Text('f', -1) != c.wantRadius {
				t.Errorf("blastRadius = %s, want %s", got.BlastRadius.Text('f', -1), c.wantRadius)
			}
			if got.Annotated != c.wantAnnotated {
				t.Errorf("annotated = %v, want %v", got.Annotated, c.wantAnnotated)
			}
			if got.CompensatingAction != c.wantCompensat {
				t.Errorf("compensatingAction = %q, want %q", got.CompensatingAction, c.wantCompensat)
			}
		})
	}
}

// TestResolveEffect_ByArgument pins the argument-parameterized contract: the same tool is
// a different effect depending on what it is asked to do, decided by a static table.
func TestResolveEffect_ByArgument(t *testing.T) {
	contract := &EffectContract{
		Class: EffectReversible,
		ByArgument: &EffectByArgument{
			Argument: "query",
			Cases: map[string]EffectCase{
				"SELECT": {Class: EffectReversible},
				"DROP":   {Class: EffectIrreversible},
			},
		},
	}

	cases := []struct {
		name, query, wantClass string
	}{
		{"exact case match", "SELECT", EffectReversible},
		{"first-token match", "DROP TABLE users", EffectIrreversible},
		{"case-insensitive", "drop table users", EffectIrreversible},
		// The uncovered value is the load-bearing one: a table that does not mention a
		// value has NOT said the value is safe, so it must not fall back to the
		// permissive base contract.
		{"uncovered value falls to the fail-closed default, not the base contract", "TRUNCATE mytable", EffectIrreversible},
		{"absent argument falls to the fail-closed default", "", EffectIrreversible},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := map[string]interface{}{}
			if c.query != "" {
				args["query"] = c.query
			}
			if got := ResolveEffect(contract, args); got.Class != c.wantClass {
				t.Errorf("class for %q = %q, want %q", c.query, got.Class, c.wantClass)
			}
		})
	}

	t.Run("a declared default applies to an uncovered value", func(t *testing.T) {
		withDefault := *contract
		withDefault.ByArgument = &EffectByArgument{
			Argument: contract.ByArgument.Argument,
			Cases:    contract.ByArgument.Cases,
			Default:  &EffectCase{Class: EffectCompensable, CompensatingAction: "tool:restore"},
		}
		got := ResolveEffect(&withDefault, map[string]interface{}{"query": "TRUNCATE mytable"})
		if got.Class != EffectCompensable || got.CompensatingAction != "tool:restore" {
			t.Fatalf("want the declared default, got %+v", got)
		}
	})

	t.Run("a case may set the blast radius", func(t *testing.T) {
		byArg := &EffectContract{
			Class: EffectReversible,
			ByArgument: &EffectByArgument{
				Argument: "op",
				Cases: map[string]EffectCase{
					"transfer": {Class: EffectIrreversible, BlastRadius: &BlastRadiusSpec{Argument: "amount", Unit: "usd"}},
				},
			},
		}
		got := ResolveEffect(byArg, map[string]interface{}{"op": "transfer", "amount": json.Number("250")})
		if !got.Quantified() || got.BlastRadius.Text('f', -1) != "250" || got.Unit != "usd" {
			t.Fatalf("want a 250 usd blast radius, got %+v", got)
		}
	})
}

func TestEffectCeiling_Exceeds(t *testing.T) {
	quantified := func(n string) *ResolvedEffect {
		v, _ := ParseBlastRadiusNumber(json.Number(n))
		return &ResolvedEffect{Class: EffectReversible, BlastRadius: v, Annotated: true}
	}

	cases := []struct {
		name        string
		ceiling     *EffectCeiling
		effect      *ResolvedEffect
		wantExceeds bool
		wantReason  string
	}{
		{
			name:        "nil ceiling never fires",
			ceiling:     nil,
			effect:      UnannotatedEffect(),
			wantExceeds: false,
		},
		{
			name:        "an unset ceiling is treated as absent, not as satisfied",
			ceiling:     &EffectCeiling{OnExceed: OnExceedDeny},
			effect:      UnannotatedEffect(),
			wantExceeds: false,
		},
		{
			name:        "an unannotated action exceeds a class ceiling — the flywheel",
			ceiling:     &EffectCeiling{MaxEffectClass: EffectCompensable},
			effect:      UnannotatedEffect(),
			wantExceeds: true,
			wantReason:  "effect_class",
		},
		{
			name:        "a class under the bound passes",
			ceiling:     &EffectCeiling{MaxEffectClass: EffectCompensable},
			effect:      &ResolvedEffect{Class: EffectCompensable, Annotated: true},
			wantExceeds: false,
		},
		{
			name:        "an unquantified action exceeds ANY finite magnitude bound",
			ceiling:     &EffectCeiling{MaxBlastRadius: num("100")},
			effect:      &ResolvedEffect{Class: EffectReversible, Annotated: true},
			wantExceeds: true,
			wantReason:  "blast_radius_unknown",
		},
		{
			name:        "a magnitude over the bound exceeds",
			ceiling:     &EffectCeiling{MaxBlastRadius: num("100")},
			effect:      quantified("101"),
			wantExceeds: true,
			wantReason:  "blast_radius",
		},
		{
			name:        "a magnitude exactly at the bound passes",
			ceiling:     &EffectCeiling{MaxBlastRadius: num("100")},
			effect:      quantified("100"),
			wantExceeds: false,
		},
		{
			name:        "requireCompensation fires only above the class bound",
			ceiling:     &EffectCeiling{MaxEffectClass: EffectCompensable, RequireCompensation: true},
			effect:      &ResolvedEffect{Class: EffectIrreversible, Annotated: true},
			wantExceeds: true,
			wantReason:  "no_compensating_action",
		},
		{
			name:        "a declared compensating action does not clear the class bound by itself",
			ceiling:     &EffectCeiling{MaxEffectClass: EffectCompensable, RequireCompensation: true},
			effect:      &ResolvedEffect{Class: EffectIrreversible, CompensatingAction: "tool:reverse", Annotated: true},
			wantExceeds: true,
			wantReason:  "effect_class",
		},
		{
			name:        "requireCompensation does not fire for an action under the class bound",
			ceiling:     &EffectCeiling{MaxEffectClass: EffectIrreversible, RequireCompensation: true},
			effect:      &ResolvedEffect{Class: EffectReversible, Annotated: true},
			wantExceeds: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			exceeds, reasons := c.ceiling.Exceeds(c.effect)
			if exceeds != c.wantExceeds {
				t.Fatalf("exceeds = %v (reasons %v), want %v", exceeds, reasons, c.wantExceeds)
			}
			if !c.wantExceeds {
				return
			}
			found := false
			for _, r := range reasons {
				if r == c.wantReason {
					found = true
				}
			}
			if !found {
				t.Fatalf("reasons %v must contain %q", reasons, c.wantReason)
			}
		})
	}
}

// TestEffectCeiling_ExceedsIsFailClosedOnAnUnreadableBound pins that a ceiling whose
// bound cannot be parsed refuses rather than passes. A bound that reads as satisfied
// would silently disable the check it was written to impose.
func TestEffectCeiling_ExceedsIsFailClosedOnAnUnreadableBound(t *testing.T) {
	v, _ := ParseBlastRadiusNumber(json.Number("1"))
	eff := &ResolvedEffect{Class: EffectReversible, BlastRadius: v, Annotated: true}
	ceiling := &EffectCeiling{MaxBlastRadius: num("not-a-number")}
	if exceeds, _ := ceiling.Exceeds(eff); !exceeds {
		t.Fatal("an unreadable maxBlastRadius must fail closed")
	}
}

// TestEffectCeiling_OutcomeDefaultsToEscalate pins the default: an action over the
// ceiling routes to human approval, not to an outright refusal, unless the operator asked
// for one.
func TestEffectCeiling_OutcomeDefaultsToEscalate(t *testing.T) {
	var nilCeiling *EffectCeiling
	for _, c := range []*EffectCeiling{nilCeiling, {}, {MaxEffectClass: EffectReversible}} {
		if got := c.Outcome(); got != OnExceedEscalate {
			t.Fatalf("Outcome() = %q, want %q", got, OnExceedEscalate)
		}
	}
	deny := &EffectCeiling{MaxEffectClass: EffectReversible, OnExceed: OnExceedDeny}
	if got := deny.Outcome(); got != OnExceedDeny {
		t.Fatalf("Outcome() = %q, want %q", got, OnExceedDeny)
	}
}

// TestEffectConditionsRoundtripThroughTheWrapper pins that both new condition types
// marshal with their discriminator and decode back, so a manifest digest computed over
// them is stable and an unknown field is rejected.
func TestEffectConditionsRoundtripThroughTheWrapper(t *testing.T) {
	for _, cond := range []Condition{
		EffectClassCondition{Allow: []string{EffectReversible, EffectCompensable}},
		BlastRadiusCondition{Max: num("500")},
		BlastRadiusCondition{MaxTotal: num("2000"), WindowSeconds: 3600},
		BlastRadiusCondition{Max: num("500"), MaxTotal: num("2000"), WindowSeconds: 3600},
	} {
		b, err := json.Marshal(ConditionWrapper{Condition: cond})
		if err != nil {
			t.Fatalf("marshal %T: %v", cond, err)
		}
		var back ConditionWrapper
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if back.ConditionType() != cond.ConditionType() {
			t.Fatalf("roundtrip type = %q, want %q", back.ConditionType(), cond.ConditionType())
		}
	}

	// A misspelled key must be a load error, not a silently wider policy.
	var w ConditionWrapper
	if err := json.Unmarshal([]byte(`{"type":"blastRadius","maxx":5}`), &w); err == nil {
		t.Fatal("an unknown field on a blastRadius condition must be rejected")
	}
	if err := json.Unmarshal([]byte(`{"type":"effectClass","allowed":["reversible"]}`), &w); err == nil {
		t.Fatal("an unknown field on an effectClass condition must be rejected")
	}
}

// TestResolvedEffectAuditDetailsAreStructured pins that the audit detail block carries
// scalars, never prose: a structured field with a sentence in it is unqueryable and the
// audit discipline forbids it.
func TestResolvedEffectAuditDetailsAreStructured(t *testing.T) {
	v, _ := ParseBlastRadiusNumber(json.Number("42"))
	eff := ResolvedEffect{
		Class: EffectCompensable, BlastRadius: v, Unit: "rows",
		CompensatingAction: "tool:restore", Ref: "eunox/postgres.delete@sha256:" + zeroHex(), Annotated: true,
	}
	d := eff.AuditDetails()
	for _, k := range []string{"effect_class", "blast_radius", "blast_radius_unit", "compensating_action", "effect_contract", "annotated"} {
		if _, ok := d[k]; !ok {
			t.Errorf("audit details must carry %q, got %v", k, d)
		}
	}
	if d["blast_radius"] != "42" {
		t.Errorf("blast_radius = %v, want the exact literal 42", d["blast_radius"])
	}
	// An unquantified effect must omit the magnitude rather than report a misleading 0.
	bare := UnannotatedEffect().AuditDetails()
	if _, ok := bare["blast_radius"]; ok {
		t.Errorf("an unquantified effect must not report a blast_radius, got %v", bare)
	}
	if bare["annotated"] != false {
		t.Errorf("an unannotated effect must report annotated=false, got %v", bare)
	}
}

// zeroHex is a well-formed 64-char lowercase hex digest for a fixture ref.
func zeroHex() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

// TestEffectVocabularyAccessors pins the closed-set accessors and that the exported
// vocabulary cannot be mutated through the copy callers receive — an exported mutable
// vocabulary would let any code in the process widen what counts as a valid class.
func TestEffectVocabularyAccessors(t *testing.T) {
	for _, c := range []string{EffectReversible, EffectCompensable, EffectIrreversible} {
		if !IsEffectClass(c) {
			t.Errorf("IsEffectClass(%q) must be true", c)
		}
	}
	for _, c := range []string{"", "safe", "REVERSIBLE"} {
		if IsEffectClass(c) {
			t.Errorf("IsEffectClass(%q) must be false — the vocabulary is closed and case-exact", c)
		}
	}
	v := EffectClassVocabulary()
	v[0] = "tampered"
	if EffectClassVocabulary()[0] != EffectReversible {
		t.Fatal("EffectClassVocabulary must hand out a copy, not the package's own slice")
	}
	if got := SortedEffectClasses([]string{EffectIrreversible, EffectReversible, "unknown"}); got[0] != EffectReversible {
		t.Fatalf("SortedEffectClasses must order by consequence, got %v", got)
	}
}

// TestEffectContractDigestIsStableAndExcludesItsOwnRef pins the two properties the
// registry pin depends on: the digest is a pure function of the contract's content
// (independent of how a source document ordered its keys, because encoding/json sorts map
// keys), and a contract carrying its own ref digests to that same ref — a self-reference
// cannot be inside its own digest.
func TestEffectContractDigestIsStableAndExcludesItsOwnRef(t *testing.T) {
	build := func(cases map[string]EffectCase) *EffectContract {
		return &EffectContract{
			Class:      EffectReversible,
			ByArgument: &EffectByArgument{Argument: "op", Cases: cases},
		}
	}
	a := build(map[string]EffectCase{"SELECT": {Class: EffectReversible}, "DROP": {Class: EffectIrreversible}})
	b := build(map[string]EffectCase{"DROP": {Class: EffectIrreversible}, "SELECT": {Class: EffectReversible}})
	da, err := EffectContractDigest(a)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	db, err := EffectContractDigest(b)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if da != db {
		t.Fatalf("map-key order must not change the digest: %s vs %s", da, db)
	}

	withRef := *a
	withRef.Ref = "acme/server.tool@" + da
	dr, err := EffectContractDigest(&withRef)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if dr != da {
		t.Fatalf("ref must be excluded from the digest: %s vs %s", dr, da)
	}

	if _, err := EffectContractDigest(nil); err == nil {
		t.Fatal("a nil contract must not digest to something")
	}

	id, digest, ok := SplitEffectRef(withRef.Ref)
	if !ok || id != "acme/server.tool" || digest != da {
		t.Fatalf("SplitEffectRef(%q) = (%q, %q, %v)", withRef.Ref, id, digest, ok)
	}
	for _, bad := range []string{"", "no-at-sign", "@sha256:x", "id@"} {
		if _, _, ok := SplitEffectRef(bad); ok {
			t.Errorf("SplitEffectRef(%q) must not report ok", bad)
		}
	}
}

// TestEffectByArgumentMatchesNonStringKeys pins that a decision table can key on a numeric
// or boolean argument, not only a string — an effect that turns on a flag or a tier number
// is as ordinary as one that turns on a SQL verb.
func TestEffectByArgumentMatchesNonStringKeys(t *testing.T) {
	contract := &EffectContract{
		Class: EffectReversible,
		ByArgument: &EffectByArgument{
			Argument: "permanent",
			Cases: map[string]EffectCase{
				"true":  {Class: EffectIrreversible},
				"false": {Class: EffectReversible},
			},
		},
	}
	if got := ResolveEffect(contract, map[string]interface{}{"permanent": true}); got.Class != EffectIrreversible {
		t.Fatalf("a boolean argument must match its case, got %q", got.Class)
	}
	numeric := &EffectContract{
		Class:      EffectReversible,
		ByArgument: &EffectByArgument{Argument: "tier", Cases: map[string]EffectCase{"3": {Class: EffectIrreversible}}},
	}
	if got := ResolveEffect(numeric, map[string]interface{}{"tier": json.Number("3")}); got.Class != EffectIrreversible {
		t.Fatalf("a numeric argument must match its case, got %q", got.Class)
	}
}

// TestResolvedEffectStringNamesTheUnquantifiedCase pins the operator-facing rendering:
// an unquantified effect must SAY so rather than print a misleading zero, and an
// unannotated one must be distinguishable from one that was declared irreversible.
func TestResolvedEffectStringNamesTheUnquantifiedCase(t *testing.T) {
	bare := UnannotatedEffect().String()
	if !strings.Contains(bare, "blastRadius=unquantified") || !strings.Contains(bare, "unannotated") {
		t.Fatalf("unannotated rendering must name both facts, got %q", bare)
	}
	v, _ := ParseBlastRadiusNumber(json.Number("7"))
	full := (&ResolvedEffect{Class: EffectCompensable, BlastRadius: v, Unit: "rows",
		CompensatingAction: "tool:restore", Annotated: true}).String()
	for _, want := range []string{"class=compensable", "blastRadius=7 rows", "compensatingAction=tool:restore"} {
		if !strings.Contains(full, want) {
			t.Fatalf("rendering must contain %q, got %q", want, full)
		}
	}
	if strings.Contains(full, "unannotated") {
		t.Fatalf("an annotated effect must not render as unannotated: %q", full)
	}
}

// TestEffectArgumentReferencesHonorNestedPaths pins that the effect layer resolves an
// `argument` reference through the SAME grammar every condition uses. A bare map index
// made the documented "$." syntax resolve to ABSENT: the decision table never matched, a
// permissive default applied to the exact call it was written to catch, and a blast radius
// silently went unquantified — all while the manifest loaded clean.
func TestEffectArgumentReferencesHonorNestedPaths(t *testing.T) {
	table := &EffectContract{
		Class: EffectReversible,
		ByArgument: &EffectByArgument{
			Argument: "$.filters.query",
			Cases:    map[string]EffectCase{"DROP": {Class: EffectIrreversible}},
			Default:  &EffectCase{Class: EffectReversible},
		},
	}
	nested := map[string]interface{}{"filters": map[string]interface{}{"query": "DROP TABLE customers"}}
	if got := ResolveEffect(table, nested).Class; got != EffectIrreversible {
		t.Fatalf("a nested byArgument reference must resolve, got class %q", got)
	}

	radius := &EffectContract{Class: EffectIrreversible, BlastRadius: &BlastRadiusSpec{Argument: "$.body.amount"}}
	got := ResolveEffect(radius, map[string]interface{}{"body": map[string]interface{}{"amount": json.Number("5000")}})
	if !got.Quantified() || got.BlastRadius.Text('f', -1) != "5000" {
		t.Fatalf("a nested blastRadius reference must resolve, got %+v", got)
	}

	// The "$$." escape addresses a literal top-level key that itself starts with "$.".
	escaped := &EffectContract{Class: EffectIrreversible, BlastRadius: &BlastRadiusSpec{Argument: "$$.amount"}}
	if e := ResolveEffect(escaped, map[string]interface{}{"$.amount": json.Number("7")}); !e.Quantified() {
		t.Fatalf("the escaped literal form must resolve, got %+v", e)
	}
	// A malformed path fails closed rather than matching something unintended.
	bad := &EffectContract{Class: EffectIrreversible, BlastRadius: &BlastRadiusSpec{Argument: "$.a..b"}}
	if e := ResolveEffect(bad, map[string]interface{}{"a": map[string]interface{}{"b": json.Number("1")}}); e.Quantified() {
		t.Fatal("a malformed path must resolve unquantified, not match")
	}
}

// TestBlastRadiusRejectsANegativeMagnitude pins the fail-closed treatment of a
// caller-controlled magnitude. A magnitude is non-negative by construction — the loader
// refuses a negative bound for exactly that reason — but the ARGUMENT value comes from the
// request, and an unchecked negative compared below every bound and under every ceiling.
func TestBlastRadiusRejectsANegativeMagnitude(t *testing.T) {
	c := &EffectContract{Class: EffectCompensable, CompensatingAction: "tool:recharge",
		BlastRadius: &BlastRadiusSpec{Argument: "amount", Unit: "usd"}}
	got := ResolveEffect(c, map[string]interface{}{"amount": json.Number("-1000000")})
	if got.Quantified() {
		t.Fatalf("a negative magnitude must resolve unquantified, got %s", got.BlastRadius.Text('f', -1))
	}
	// Unquantified exceeds any finite bound, so the call is refused rather than admitted.
	if over, _ := (&EffectCeiling{MaxBlastRadius: num("500")}).Exceeds(got); !over {
		t.Fatal("an unquantifiable magnitude must exceed a finite ceiling")
	}
	// Zero is a legitimate magnitude and must still quantify.
	if z := ResolveEffect(c, map[string]interface{}{"amount": json.Number("0")}); !z.Quantified() {
		t.Fatal("zero is a magnitude and must quantify")
	}
}

// TestNumericLiteralBoundedAcceptsDecimalOnly pins the shared literal grammar. Three
// layers gate a caller-supplied literal on this one predicate, so a form it admits is a
// form all three hand to an arbitrary-precision parser.
func TestNumericLiteralBoundedAcceptsDecimalOnly(t *testing.T) {
	accepted := []string{
		"0", "5", "-5", "+5", "250", "0.5", ".5", "5.", "-0.125",
		"1e10", "1E10", "1e+10", "1e-10", "1.5e3", "-1.5E-3", "0e0",
		strings.Repeat("9", MaxNumericLiteralLen),
		"1e" + strconv.Itoa(MaxNumericLiteralExp),
		"1e-" + strconv.Itoa(MaxNumericLiteralExp),
	}
	for _, s := range accepted {
		if !NumericLiteralBounded(s) {
			t.Errorf("NumericLiteralBounded(%q) = false, want true", s)
		}
	}

	rejected := []string{
		// The vector: a binary exponent scales by a power of two that no decimal-digit
		// budget bounds, and the pre-fix guard scanned only for 'e'/'E'.
		"1p1000000", "1P64", "0x1p64", "0X1P1000000", "0x10",
		// Go literal spellings whose value differs from the decimal a caller wrote.
		"1_000", "1_0e1_0",
		// Forms big.Rat/big.Float accept that are not magnitudes at all.
		"1/3", "Inf", "+Inf", "-Inf", "inf", "NaN",
		// Structurally malformed.
		"", " ", "+", "-", ".", "e10", "1e", "1e+", "5abc", "1.2.3", "1 2", "٥",
		// Over-bound length and exponent.
		strings.Repeat("9", MaxNumericLiteralLen+1),
		"1e" + strconv.Itoa(MaxNumericLiteralExp+1),
		"1e-" + strconv.Itoa(MaxNumericLiteralExp+1),
		"1e99999999999999999999", // an exponent too long for a machine int
	}
	for _, s := range rejected {
		if NumericLiteralBounded(s) {
			t.Errorf("NumericLiteralBounded(%q) = true, want false", s)
		}
	}
}

// TestBlastRadiusRejectsANonDecimalStringMagnitude pins the one arm where a caller
// controls a literal that is NOT constrained by JSON's number grammar. A string tool
// argument reaches big.Float.SetString directly, and SetString accepts binary exponents
// and hex floats: "1p100000000" is eleven bytes that render, on the denial path, as
// hundreds of megabytes of decimal digits — synchronously, inside the per-session
// decision. It must resolve unquantified (which exceeds every bound) instead.
func TestBlastRadiusRejectsANonDecimalStringMagnitude(t *testing.T) {
	c := &EffectContract{Class: EffectIrreversible, BlastRadius: &BlastRadiusSpec{Argument: "amount"}}
	// Every literal here is one big.Float.SetString accepts ("1/3" is big.Rat's alone,
	// so it is pinned in the grammar table above rather than through this arm).
	for _, arg := range []string{"1p100000000", "0x1p1000000", "0x1p64", "1_000", "Inf"} {
		t.Run(arg, func(t *testing.T) {
			// Establish that this literal really is one big.Float would have taken, so
			// the test fails if the guard is the only thing standing between a caller
			// and the parse.
			if _, ok := new(big.Float).SetString(arg); !ok {
				t.Fatalf("precondition: big.Float.SetString(%q) rejected it anyway", arg)
			}
			got := ResolveEffect(c, map[string]interface{}{"amount": arg})
			if got.Quantified() {
				t.Fatalf("%q must resolve unquantified, got %s", arg, got.BlastRadius.Text('f', -1))
			}
			if over, _ := (&EffectCeiling{MaxBlastRadius: num("500")}).Exceeds(got); !over {
				t.Fatalf("%q resolved unquantified but did not exceed a finite ceiling", arg)
			}
		})
	}
	// A decimal string magnitude is unaffected — this arm still quantifies.
	if got := ResolveEffect(c, map[string]interface{}{"amount": " 250 "}); !got.Quantified() ||
		got.BlastRadius.Text('f', -1) != "250" {
		t.Fatalf("a decimal string magnitude must still quantify, got %s", got)
	}
}

// TestBlastRadiusFailsClosedOnNaNAndInf pins that an unevaluable float argument denies
// rather than panicking the enforcement goroutine. big.Float.SetFloat64 PANICS on NaN, and
// this branch exists for a direct caller of the exported engine that decoded arguments
// without UseNumber — i.e. one whose input the proxy never screened.
func TestBlastRadiusFailsClosedOnNaNAndInf(t *testing.T) {
	c := &EffectContract{Class: EffectIrreversible, BlastRadius: &BlastRadiusSpec{Argument: "amount"}}
	for name, v := range map[string]float64{"NaN": math.NaN(), "+Inf": math.Inf(1), "-Inf": math.Inf(-1)} {
		t.Run(name, func(t *testing.T) {
			if got := ResolveEffect(c, map[string]interface{}{"amount": v}); got.Quantified() {
				t.Fatalf("%s must resolve unquantified", name)
			}
		})
	}
	if got := ResolveEffect(c, map[string]interface{}{"amount": 42.5}); !got.Quantified() {
		t.Fatal("an ordinary float64 argument must still quantify")
	}
}

// TestEffectVerbMatchingHandlesAllWhitespace pins that the first-verb fallback uses the
// shared OperationVerb rule. Splitting on a space alone made a newline- or tab-formatted
// statement — the norm from a model — miss its case and fall to the table default, so an
// ordinary multi-line SELECT escalated under any ceiling with no diagnosable cause.
func TestEffectVerbMatchingHandlesAllWhitespace(t *testing.T) {
	c := &EffectContract{
		Class: EffectIrreversible,
		ByArgument: &EffectByArgument{
			Argument: "query",
			Cases:    map[string]EffectCase{"SELECT": {Class: EffectReversible}},
			Default:  &EffectCase{Class: EffectIrreversible},
		},
	}
	for _, q := range []string{"SELECT id FROM t", "SELECT\n  id\nFROM t", "SELECT\tid FROM t", "  SELECT id  "} {
		if got := ResolveEffect(c, map[string]interface{}{"query": q}).Class; got != EffectReversible {
			t.Errorf("%q must resolve reversible, got %q", q, got)
		}
	}
	if got := ResolveEffect(c, map[string]interface{}{"query": "DROP\nTABLE t"}).Class; got != EffectIrreversible {
		t.Errorf("an uncovered verb must still fall to the default, got %q", got)
	}
}

// TestByArgumentCaseLookupIsDeterministic pins that a programmatically-built table with
// two keys that fold together resolves the same way every time. The loader rejects the
// shape, but map-order iteration made the resolved effect class differ between two
// identical calls — disqualifying for a layer whose whole claim is determinism.
func TestByArgumentCaseLookupIsDeterministic(t *testing.T) {
	c := &EffectContract{
		Class: EffectReversible,
		ByArgument: &EffectByArgument{
			Argument: "q",
			Cases: map[string]EffectCase{
				"DROP": {Class: EffectIrreversible},
				"drop": {Class: EffectReversible},
			},
		},
	}
	first := ResolveEffect(c, map[string]interface{}{"q": "DROP TABLE t"}).Class
	for range 200 {
		if got := ResolveEffect(c, map[string]interface{}{"q": "DROP TABLE t"}).Class; got != first {
			t.Fatalf("a colliding table must resolve deterministically: got both %q and %q", first, got)
		}
	}
}

// TestResolvedClassNeverInheritsAnIncompatibleCompensation pins the compensable invariant
// on the RESOLVED effect, not only on the authored one. A byArgument row that RAISES the
// class inherited the base block's compensatingAction and produced exactly the pairing the
// loader refuses — an irreversible action carrying something claiming to reverse it —
// which suppressed the ceiling's no_compensating_action reason and put a false
// compensating action on the escalation record a human is expected to act on.
func TestResolvedClassNeverInheritsAnIncompatibleCompensation(t *testing.T) {
	c := &EffectContract{
		Class: EffectCompensable, CompensatingAction: "tool:restore_backup",
		ByArgument: &EffectByArgument{
			Argument: "query",
			Cases: map[string]EffectCase{
				"DROP": {Class: EffectIrreversible},
				// A row that overlays nothing leaves the base contract intact — the
				// contrast leg for the clearing rule below.
				"UPDATE": {},
			},
		},
	}
	got := ResolveEffect(c, map[string]interface{}{"query": "DROP TABLE customers"})
	if got.Class != EffectIrreversible {
		t.Fatalf("class = %q, want irreversible", got.Class)
	}
	if got.CompensatingAction != "" {
		t.Fatalf("an irreversible resolution must not carry a compensating action, got %q", got.CompensatingAction)
	}
	if _, ok := got.AuditDetails()["compensating_action"]; ok {
		t.Fatal("the audit record must not claim a compensating action for an irreversible action")
	}
	ceiling := &EffectCeiling{MaxEffectClass: EffectCompensable, RequireCompensation: true}
	_, reasons := ceiling.Exceeds(got)
	var sawNoComp bool
	for _, r := range reasons {
		if r == "no_compensating_action" {
			sawNoComp = true
		}
	}
	if !sawNoComp {
		t.Fatalf("the consequence gate must report the missing compensation, got %v", reasons)
	}
	// A row that stays compensable keeps the inherited action — the clearing rule applies
	// to the RESOLVED class, so it must not strip a compensation that is still valid.
	kept := ResolveEffect(c, map[string]interface{}{"query": "UPDATE t SET x = 1"})
	if kept.Class != EffectCompensable || kept.CompensatingAction != "tool:restore_backup" {
		t.Fatalf("a compensable resolution must keep its compensating action, got %+v", kept)
	}
}

// TestCeilingWithOnlyRequireCompensationIsNotSet pins that a ceiling incapable of firing
// does not report itself as active. Exceeds gates the compensation leg on being ABOVE the
// class bound, so with no maxEffectClass it can never fire — and IsSet is what the wiring
// gate (HasEffectCeiling) reads to decide whether a ceiling is in force at all.
func TestCeilingWithOnlyRequireCompensationIsNotSet(t *testing.T) {
	c := &EffectCeiling{RequireCompensation: true}
	if c.IsSet() {
		t.Fatal("a ceiling that can never fire must not report itself as set")
	}
	if over, reasons := c.Exceeds(&ResolvedEffect{Class: EffectIrreversible, Annotated: true}); over {
		t.Fatalf("and it must refuse nothing, got %v", reasons)
	}
}

// TestCeilingRequireCompensationWithoutAClassBoundIsRefused covers the shape the test
// above does NOT: requireCompensation alongside maxBlastRadius but with no maxEffectClass.
// IsSet reports true there (the magnitude bound is real), so the ceiling IS in force —
// while the compensation leg, gated on being above the class bound, could never fire. An
// operator who wrote it got a requirement that silently bounded nothing.
//
// The manifest loader rejects the shape, so this is unreachable from a manifest; the
// exported WithEffectCeiling seam takes a ceiling directly and never passes through the
// loader, which is the caller this closes it for. An unevaluable ceiling leg must fail
// closed, and it names the misconfiguration rather than reporting a consequence that was
// never assessed.
func TestCeilingRequireCompensationWithoutAClassBoundIsRefused(t *testing.T) {
	c := &EffectCeiling{MaxBlastRadius: num("1000"), RequireCompensation: true}
	if !c.IsSet() {
		t.Fatal("a ceiling with a real magnitude bound is in force")
	}
	// Well under every bound the ceiling states, and compensable besides: the only reason
	// to refuse it is that the ceiling itself cannot be evaluated as written.
	v, _ := ParseBlastRadiusNumber(json.Number("1"))
	over, reasons := c.Exceeds(&ResolvedEffect{
		Class: EffectCompensable, BlastRadius: v,
		CompensatingAction: "tool:undo", Annotated: true,
	})
	if !over {
		t.Fatal("a ceiling whose compensation leg can never fire must not admit silently")
	}
	if len(reasons) != 1 || reasons[0] != "ceiling_misconfigured" {
		t.Fatalf("reasons = %v, want exactly [ceiling_misconfigured] — the token must name the\n"+
			"misconfiguration, not a consequence the ceiling never actually assessed", reasons)
	}
}

// TestResolvedEffectQuantifiedTracksTheBlastRadius pins that the two cannot disagree.
// Quantified was a stored bool set alongside BlastRadius, so a directly-constructed
// ResolvedEffect could carry Quantified: true with a nil pointer — and the very next thing
// every reader does with a quantified effect is dereference it to compare or render it.
func TestResolvedEffectQuantifiedTracksTheBlastRadius(t *testing.T) {
	if (&ResolvedEffect{Class: EffectReversible}).Quantified() {
		t.Error("an effect with no blast radius must not report itself quantified")
	}
	v, _ := ParseBlastRadiusNumber(json.Number("3"))
	if !(&ResolvedEffect{Class: EffectReversible, BlastRadius: v}).Quantified() {
		t.Error("an effect carrying a blast radius must report itself quantified")
	}
	// A nil receiver reaches this through a caller that did not check ok on the context
	// lookup. Unquantified is the fail-closed answer; a panic is not an answer at all.
	var nilEff *ResolvedEffect
	if nilEff.Quantified() {
		t.Error("a nil effect must read as unquantified, not quantified")
	}
}

// TestBlastRadiusHasVelocity pins the predicate the engine keys DEFERRAL on and the loader
// keys its one-committing-condition rule on. Both halves are required because either alone
// bounds nothing: a total with no window has no window to sum over, and a window with no
// total bounds nothing. A half-set condition must therefore report NO velocity, so the
// engine treats it as the boundless condition it is and fails it closed, rather than
// deferring and committing against a bound that does not exist.
func TestBlastRadiusHasVelocity(t *testing.T) {
	cases := []struct {
		name string
		cond *BlastRadiusCondition
		want bool
	}{
		{"both halves", &BlastRadiusCondition{MaxTotal: num("2000"), WindowSeconds: 3600}, true},
		{"per-call only", &BlastRadiusCondition{Max: num("500")}, false},
		{"total with no window", &BlastRadiusCondition{MaxTotal: num("2000")}, false},
		{"window with no total", &BlastRadiusCondition{WindowSeconds: 3600}, false},
		{"non-positive window", &BlastRadiusCondition{MaxTotal: num("2000"), WindowSeconds: 0}, false},
		{"nil condition", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cond.HasVelocity(); got != tc.want {
				t.Fatalf("HasVelocity() = %v, want %v", got, tc.want)
			}
		})
	}
}
