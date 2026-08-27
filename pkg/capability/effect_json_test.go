// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// constraintWith wraps an effect block in the smallest valid constraint, so every case is
// decoded through the seam a library consumer actually reaches rather than through
// EffectContract directly. It also pins that the check survives the outer decoder handing
// the block over to a custom UnmarshalJSON.
func constraintWith(effect string) string {
	return `{"target":"tool:db_query","actions":["call"],"effect":` + effect + `}`
}

// The effect subtree was the one nested policy object at the exported Constraint seam that
// decoded leniently, so a misspelled key was silently dropped. Both drops WIDEN:
// "byArguments" deletes the escalation table, leaving the base class applied to the very
// argument values the table existed to escalate, and a misspelled "ref" skips the effect.ref
// integrity pin. ValidateEffectContract sees the decoded struct, not the key that never
// bound, so nothing downstream can catch either.
//
// The nested rows are the point of the table, not padding: strictness comes from ONE
// decoder at the block root, so a typo at depth is what proves the recursion still covers a
// type with no decoder of its own.
func TestEffectContractDecode_RejectsUnknownField(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{
			name: "misspelled byArgument deletes the escalation table",
			json: `{"class":"reversible","byArguments":{"argument":"op","cases":{"DROP":{"class":"irreversible"}}}}`,
			want: `effect: unknown field "byArguments"`,
		},
		{
			name: "misspelled ref skips the integrity pin",
			json: `{"class":"reversible","reff":"eunox/db.query@sha256:` + zeroHex() + `"}`,
			want: `effect: unknown field "reff"`,
		},
		{
			name: "typo in the base blastRadius leaves the action unquantified",
			json: `{"class":"irreversible","blastRadius":{"valuee":500}}`,
			want: `effect: unknown field "valuee"`,
		},
		{
			name: "typo inside a case row drops that row's escalation",
			json: `{"byArgument":{"argument":"op","cases":{"DROP":{"classs":"irreversible"}}}}`,
			want: `effect: unknown field "classs"`,
		},
		{
			name: "typo inside the table's default row",
			json: `{"byArgument":{"argument":"op","cases":{},"default":{"compensatingActon":"tool:restore"}}}`,
			want: `effect: unknown field "compensatingActon"`,
		},
		{
			name: "misspelled default falls back to the fail-closed default silently",
			json: `{"byArgument":{"argument":"op","cases":{},"defaultt":{"class":"reversible"}}}`,
			want: `effect: unknown field "defaultt"`,
		},
		{
			name: "typo in a case row's blastRadius, four levels down",
			json: `{"byArgument":{"argument":"rows","cases":{"delete":{"blastRadius":{"arguent":"rows"}}}}}`,
			want: `effect: unknown field "arguent"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Constraint
			err := json.Unmarshal([]byte(constraintWith(tc.json)), &c)
			if err == nil {
				t.Fatalf("effect %s decoded clean, want a rejection", tc.json)
			}
			if got := err.Error(); got != tc.want {
				t.Errorf("error = %q, want %q", got, tc.want)
			}
		})
	}
}

// The top-level ceiling is the other exported effect object a consumer decodes without the
// binary's manifest key check. A dropped key here raises the consequence bound: a misspelled
// maxBlastRadius leaves the magnitude dimension unbounded.
func TestEffectCeilingDecode_RejectsUnknownField(t *testing.T) {
	cases := []struct{ name, json, want string }{
		{"misspelled maxEffectClass", `{"maxEffectClas":"reversible"}`, `effectCeiling: unknown field "maxEffectClas"`},
		{"misspelled maxBlastRadius", `{"maxEffectClass":"reversible","maxBlastRadiuss":100}`, `effectCeiling: unknown field "maxBlastRadiuss"`},
		{"misspelled onExceed", `{"maxEffectClass":"reversible","onExceeed":"deny"}`, `effectCeiling: unknown field "onExceeed"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c EffectCeiling
			err := json.Unmarshal([]byte(tc.json), &c)
			if err == nil {
				t.Fatalf("ceiling %s decoded clean, want a rejection", tc.json)
			}
			if got := err.Error(); got != tc.want {
				t.Errorf("error = %q, want %q", got, tc.want)
			}
		})
	}
}

// An unknown key and an AMBIGUOUS one are different holes, and the unknown-key check passes
// the second by construction: both spellings fold to a known name, so encoding/json binds
// them to the same field and keeps the LAST. That reproduces both widenings from a document
// a reviewer reads as correct — a "ByArgument": null sibling deletes the table a correct
// byArgument declared, a "REF" sibling drops the pin — and the widened block then re-digests
// to a value that validates against its own effect.ref.
func TestEffectDecode_RejectsAmbiguousKey(t *testing.T) {
	cases := []struct{ name, json, want string }{
		{
			name: "case-variant sibling deletes the escalation table",
			json: `{"class":"reversible","byArgument":{"argument":"op","cases":{"DROP":{"class":"irreversible"}}},"ByArgument":null}`,
			want: `members "byArgument" and "ByArgument"`,
		},
		{
			name: "case-variant sibling drops the integrity pin",
			json: `{"class":"irreversible","ref":"eunox/db.query@sha256:` + zeroHex() + `","REF":""}`,
			want: `members "ref" and "REF"`,
		},
		{
			name: "case-variant sibling substitutes the class a reviewer read",
			json: `{"class":"irreversible","CLASS":"reversible"}`,
			want: `members "class" and "CLASS"`,
		},
		{
			name: "ambiguity at depth, in the table's own keys",
			json: `{"byArgument":{"argument":"op","Argument":"other","cases":{}}}`,
			want: `members "argument" and "Argument"`,
		},
		{
			name: "two case rows the table cannot tell apart",
			json: `{"byArgument":{"argument":"op","cases":{"DROP":{"class":"irreversible"},"drop":{"class":"reversible"}}}}`,
			want: `members "DROP" and "drop"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Constraint
			err := json.Unmarshal([]byte(constraintWith(tc.json)), &c)
			if err == nil {
				t.Fatalf("effect %s decoded clean, want a rejection", tc.json)
			}
			if !strings.HasPrefix(err.Error(), "effect: ") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it prefixed by the block and naming %s", err, tc.want)
			}
		})
	}

	var ceiling EffectCeiling
	if err := json.Unmarshal([]byte(`{"maxEffectClass":"reversible","MaxEffectClass":""}`), &ceiling); err == nil {
		t.Error("an ambiguous ceiling bound decoded clean; the last spelling silently sets the bound")
	}
}

// The check must not reject what a lenient decode would have BOUND: every real spelling, a
// LONE case variant of one (encoding/json binds case-insensitively, and only a fold
// COLLISION is ambiguous), and an absent or empty block. The manifest loader is
// independently stricter here — it matches keys exactly, so it refuses a lone variant this
// seam accepts — which is the safe direction and not this decoder's rule to restate.
func TestEffectDecode_AcceptsWhatEncodingJSONBinds(t *testing.T) {
	variant := `{"CLASS":"compensable","ByArgument":{"ARGUMENT":"op","Cases":{"drop":{"Class":"irreversible"}}}}`
	for _, tc := range []struct{ name, json string }{
		{"absent block", `null`},
		{"empty block", `{}`},
		{"lone case variants", variant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Constraint
			if err := json.Unmarshal([]byte(constraintWith(tc.json)), &c); err != nil {
				t.Fatalf("effect %s must decode, got %v", tc.json, err)
			}
		})
	}

	// Accepting a variant is only correct if it BINDS: a decoder that admitted the document
	// and dropped the table would pass an error-only assertion while silently widening.
	t.Run("lone case variants bind", func(t *testing.T) {
		var c Constraint
		if err := json.Unmarshal([]byte(constraintWith(variant)), &c); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if c.Effect == nil || c.Effect.ByArgument == nil {
			t.Fatal("case-variant document decoded to an empty contract")
		}
		if c.Effect.Class != EffectCompensable {
			t.Errorf("class = %q, want %q", c.Effect.Class, EffectCompensable)
		}
		if got := c.Effect.ByArgument.Argument; got != "op" {
			t.Errorf("byArgument.argument = %q, want %q", got, "op")
		}
		if got := c.Effect.ByArgument.Cases["drop"].Class; got != EffectIrreversible {
			t.Errorf("case row class = %q, want %q", got, EffectIrreversible)
		}
	})

	// A fully populated block must arrive intact, not merely without error.
	t.Run("full contract arrives intact", func(t *testing.T) {
		var c Constraint
		if err := json.Unmarshal([]byte(constraintWith(fullContractJSON)), &c); err != nil {
			t.Fatalf("decode: %v", err)
		}
		e := c.Effect
		if e == nil || e.ByArgument == nil || e.BlastRadius == nil {
			t.Fatalf("contract lost a nested block: %+v", e)
		}
		if e.Class != EffectCompensable || !e.Idempotent || e.CompensatingAction != "tool:refund" {
			t.Errorf("base fields = %+v", e)
		}
		if e.BlastRadius.Argument != "amount" || e.BlastRadius.Unit != "usd" {
			t.Errorf("blastRadius = %+v", e.BlastRadius)
		}
		if e.ByArgument.Argument != "op" || len(e.ByArgument.Cases) != 1 {
			t.Errorf("byArgument = %+v", e.ByArgument)
		}
		if e.ByArgument.Default == nil || e.ByArgument.Default.Class != EffectReversible {
			t.Errorf("default row = %+v", e.ByArgument.Default)
		}
		if e.Ref == "" {
			t.Error("ref dropped")
		}
		row := e.ByArgument.Cases["DROP"]
		if row.Idempotent == nil || *row.Idempotent {
			t.Errorf("case idempotent = %v, want an explicit false", row.Idempotent)
		}
		if row.BlastRadius == nil || row.BlastRadius.Value == nil || row.BlastRadius.Value.String() != "500" {
			t.Errorf("case blastRadius = %+v", row.BlastRadius)
		}
	})
}

var fullContractJSON = `{
	"class":"compensable","idempotent":true,"compensatingAction":"tool:refund",
	"blastRadius":{"argument":"amount","unit":"usd"},
	"byArgument":{"argument":"op","cases":{"DROP":{"class":"irreversible","idempotent":false,
		"blastRadius":{"value":500,"unit":"rows"}}},"default":{"class":"reversible"}},
	"ref":"eunox/db.query@sha256:` + zeroHex() + `"
}`

// encoding/json MERGES into a non-zero destination, so a reused value would carry fields the
// new document never declared. For a contract that includes a stale ref — an integrity pin
// over content that is no longer there — and a stale blastRadius, which turns an action the
// second document left unquantified (exceeding any finite ceiling) into one that passes.
func TestEffectDecode_ReplacesRatherThanMerges(t *testing.T) {
	var e EffectContract
	first := `{"class":"irreversible","ref":"pinned","compensatingAction":"tool:undo","blastRadius":{"value":9},` +
		`"byArgument":{"argument":"op","cases":{"DROP":{"class":"irreversible"}}}}`
	if err := json.Unmarshal([]byte(first), &e); err != nil {
		t.Fatalf("first decode: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"class":"reversible"}`), &e); err != nil {
		t.Fatalf("second decode: %v", err)
	}
	if want := (EffectContract{Class: EffectReversible}); !reflect.DeepEqual(e, want) {
		t.Errorf("re-decode = %+v, want exactly %+v — the second document declared none of the rest", e, want)
	}
}

// Strictness comes from ONE decoder per block, which works only because dropping the
// outermost type's method set lets DisallowUnknownFields recurse into the nested types
// itself. A nested type that grew its own UnmarshalJSON would silently opt its whole subtree
// back OUT of that flag — the same fail-open this change closed, reintroduced by a plausible
// edit with every existing test still green. So the property is asserted over the type graph
// rather than left to whoever makes that edit noticing.
func TestEffectDecode_NoNestedTypeOptsOutOfTheRecursion(t *testing.T) {
	unmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	seen := map[reflect.Type]bool{}
	var walk func(t *testing.T, typ reflect.Type, path string, root bool)
	walk = func(t *testing.T, typ reflect.Type, path string, root bool) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map ||
			typ.Kind() == reflect.Array {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		// json.Number is bound by encoding/json's own literal handling, not by a method.
		if !root && reflect.PointerTo(typ).Implements(unmarshaler) {
			t.Errorf("%s (%s) has its own UnmarshalJSON: DisallowUnknownFields stops at it, "+
				"so every key under it decodes leniently again", path, typ)
		}
		for i := range typ.NumField() {
			f := typ.Field(i)
			if f.PkgPath != "" {
				continue
			}
			walk(t, f.Type, path+"."+f.Name, false)
		}
	}
	walk(t, reflect.TypeOf(EffectContract{}), "EffectContract", true)
	walk(t, reflect.TypeOf(EffectCeiling{}), "EffectCeiling", true)
	// The walk is only meaningful if it actually reached the nested policy objects.
	for _, want := range []any{BlastRadiusSpec{}, EffectByArgument{}, EffectCase{}} {
		if !seen[reflect.TypeOf(want)] {
			t.Errorf("type walk never reached %T; the guard is vacuous", want)
		}
	}
}

// A blast-radius literal above 2^53 must reach the digest and the ceiling comparison as the
// author wrote it. This guards the decoder boundary, not any one decoder option: the fields
// are *json.Number, so encoding/json preserves the literal either way, and what would break
// it is a future edit that routes these values through a float.
func TestEffectDecode_PreservesExactNumericLiterals(t *testing.T) {
	const literal = "9007199254740993"
	var c Constraint
	if err := json.Unmarshal([]byte(constraintWith(
		`{"blastRadius":{"value":`+literal+`},"byArgument":{"argument":"op","cases":`+
			`{"delete":{"blastRadius":{"value":`+literal+`}}}}}`)), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c.Effect == nil || c.Effect.BlastRadius == nil || c.Effect.ByArgument == nil {
		t.Fatalf("contract lost a nested block: %+v", c.Effect)
	}
	got := []*json.Number{c.Effect.BlastRadius.Value, c.Effect.ByArgument.Cases["delete"].BlastRadius.Value}
	for i, n := range got {
		if n == nil || n.String() != literal {
			t.Errorf("literal %d = %v, want %s preserved exactly", i, n, literal)
		}
	}
}

// An effect.ref pin is verified by recomputing EffectContractDigest over the DECODED block,
// so a decoder that reshaped any field would turn every pinned manifest into a false
// tampering report against an author who changed nothing.
func TestEffectDecode_RoundTripsThroughTheDigest(t *testing.T) {
	src := `{"class":"irreversible","idempotent":true,"compensatingAction":"tool:restore",` +
		`"blastRadius":{"value":1,"unit":"rows"},` +
		`"byArgument":{"argument":"op","cases":{"drop":{"class":"irreversible"}},"default":{"class":"reversible"}}}`
	var first EffectContract
	if err := json.Unmarshal([]byte(src), &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want, err := EffectContractDigest(&first)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	encoded, err := json.Marshal(&first)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var second EffectContract
	if err := json.Unmarshal(encoded, &second); err != nil {
		t.Fatalf("re-decode %s: %v", encoded, err)
	}
	got, err := EffectContractDigest(&second)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if got != want {
		t.Fatalf("digest after a marshal/unmarshal round trip = %s, want %s", got, want)
	}
}

// A non-object where a policy object belongs must still be a load error, and must name the
// block the author wrote: the stand-in type the strict decode goes through is not a name the
// manifest grammar has, so an operator cannot look it up.
func TestEffectDecode_RejectsNonObject(t *testing.T) {
	for _, tc := range []struct{ json, want string }{
		{`"reversible"`, "capability.EffectContract"},
		{`["reversible"]`, "capability.EffectContract"},
		{`7`, "capability.EffectContract"},
	} {
		t.Run(tc.json, func(t *testing.T) {
			var c Constraint
			err := json.Unmarshal([]byte(constraintWith(tc.json)), &c)
			if err == nil {
				t.Fatalf("effect %s decoded clean, want a rejection", tc.json)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %s", err, tc.want)
			}
			if strings.Contains(err.Error(), "Fields") {
				t.Errorf("error = %q names the decode stand-in rather than the block", err)
			}
		})
	}
}
