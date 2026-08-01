// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
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
			if got.Quantified != c.wantQuant {
				t.Errorf("quantified = %v, want %v", got.Quantified, c.wantQuant)
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
		if !got.Quantified || got.BlastRadius.Text('f', -1) != "250" || got.Unit != "usd" {
			t.Fatalf("want a 250 usd blast radius, got %+v", got)
		}
	})
}

func TestEffectCeiling_Exceeds(t *testing.T) {
	quantified := func(n string) ResolvedEffect {
		v, _ := ParseBlastRadiusNumber(json.Number(n))
		return ResolvedEffect{Class: EffectReversible, BlastRadius: v, Quantified: true, Annotated: true}
	}

	cases := []struct {
		name        string
		ceiling     *EffectCeiling
		effect      ResolvedEffect
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
			effect:      ResolvedEffect{Class: EffectCompensable, Annotated: true},
			wantExceeds: false,
		},
		{
			name:        "an unquantified action exceeds ANY finite magnitude bound",
			ceiling:     &EffectCeiling{MaxBlastRadius: num("100")},
			effect:      ResolvedEffect{Class: EffectReversible, Annotated: true},
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
			effect:      ResolvedEffect{Class: EffectIrreversible, Annotated: true},
			wantExceeds: true,
			wantReason:  "no_compensating_action",
		},
		{
			name:        "a declared compensating action does not clear the class bound by itself",
			ceiling:     &EffectCeiling{MaxEffectClass: EffectCompensable, RequireCompensation: true},
			effect:      ResolvedEffect{Class: EffectIrreversible, CompensatingAction: "tool:reverse", Annotated: true},
			wantExceeds: true,
			wantReason:  "effect_class",
		},
		{
			name:        "requireCompensation does not fire for an action under the class bound",
			ceiling:     &EffectCeiling{MaxEffectClass: EffectIrreversible, RequireCompensation: true},
			effect:      ResolvedEffect{Class: EffectReversible, Annotated: true},
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
	eff := ResolvedEffect{Class: EffectReversible, BlastRadius: v, Quantified: true, Annotated: true}
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
	} {
		b, err := json.Marshal(ConditionWrapper{Condition: cond})
		if err != nil {
			t.Fatalf("marshal %T: %v", cond, err)
		}
		var back ConditionWrapper
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if back.Condition.ConditionType() != cond.ConditionType() {
			t.Fatalf("roundtrip type = %q, want %q", back.Condition.ConditionType(), cond.ConditionType())
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
		Class: EffectCompensable, BlastRadius: v, Quantified: true, Unit: "rows",
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
