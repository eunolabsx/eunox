// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"strings"
	"testing"
)

// The effect subtree was the one nested policy object at the exported Constraint seam
// that decoded leniently, so a misspelled key was silently dropped. Both drops WIDEN:
// "byArguments" deletes the escalation table, leaving the base class applied to the very
// argument values the table existed to escalate, and a misspelled "ref" skips the
// effect.ref integrity pin. ValidateEffectContract sees the decoded struct, not the key
// that never bound, so nothing downstream can catch either.
//
// Decoded through Constraint rather than through EffectContract directly: that is the
// seam a library consumer reaches, and it also pins that the check survives the outer
// decoder handing the block over to a custom UnmarshalJSON.
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
			want: `effect: blastRadius: unknown field "valuee"`,
		},
		{
			name: "typo inside a case row drops that row's escalation",
			json: `{"byArgument":{"argument":"op","cases":{"DROP":{"classs":"irreversible"}}}}`,
			want: `effect: byArgument: case: unknown field "classs"`,
		},
		{
			name: "typo inside the table's default row",
			json: `{"byArgument":{"argument":"op","cases":{},"default":{"compensatingActon":"tool:restore"}}}`,
			want: `effect: byArgument: case: unknown field "compensatingActon"`,
		},
		{
			name: "misspelled default falls back to the fail-closed default silently",
			json: `{"byArgument":{"argument":"op","cases":{},"defaultt":{"class":"reversible"}}}`,
			want: `effect: byArgument: unknown field "defaultt"`,
		},
		{
			name: "typo in a case row's blastRadius",
			json: `{"byArgument":{"argument":"rows","cases":{"delete":{"blastRadius":{"arguent":"rows"}}}}}`,
			want: `effect: byArgument: case: blastRadius: unknown field "arguent"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Constraint
			err := json.Unmarshal([]byte(`{"target":"tool:db_query","actions":["call"],"effect":`+tc.json+`}`), &c)
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
// binary's manifest key check. A dropped key here raises the consequence bound: a
// misspelled maxBlastRadius leaves the magnitude dimension unbounded.
func TestEffectCeilingDecode_RejectsUnknownField(t *testing.T) {
	for _, tc := range []struct{ json, want string }{
		{`{"maxEffectClas":"reversible"}`, `effectCeiling: unknown field "maxEffectClas"`},
		{`{"maxEffectClass":"reversible","maxBlastRadiuss":100}`, `effectCeiling: unknown field "maxBlastRadiuss"`},
		{`{"maxEffectClass":"reversible","onExceeed":"deny"}`, `effectCeiling: unknown field "onExceeed"`},
	} {
		var c EffectCeiling
		err := json.Unmarshal([]byte(tc.json), &c)
		if err == nil {
			t.Fatalf("ceiling %s decoded clean, want a rejection", tc.json)
		}
		if got := err.Error(); got != tc.want {
			t.Errorf("error = %q, want %q", got, tc.want)
		}
	}
}

// The check must not reject what a lenient decode would have bound: every real spelling,
// any case variant of one (encoding/json binds case-insensitively, so rejecting a variant
// would refuse a manifest that used to load), and an absent block.
func TestEffectDecode_AcceptsWhatEncodingJSONBinds(t *testing.T) {
	full := `{
		"class":"compensable","idempotent":true,"compensatingAction":"tool:refund",
		"blastRadius":{"argument":"amount","unit":"usd"},
		"byArgument":{"argument":"op","cases":{"DROP":{"class":"irreversible","idempotent":false,
			"blastRadius":{"value":500,"unit":"rows"}}},"default":{"class":"reversible"}},
		"ref":"eunox/db.query@sha256:` + zeroHex() + `"
	}`
	for _, tc := range []string{
		full,
		`{"CLASS":"reversible","ByArgument":{"ARGUMENT":"op","Cases":{"drop":{"Class":"irreversible"}}}}`,
		`null`,
		`{}`,
	} {
		var c Constraint
		if err := json.Unmarshal([]byte(`{"target":"tool:db_query","actions":["call"],"effect":`+tc+`}`), &c); err != nil {
			t.Fatalf("effect %s must decode, got %v", tc, err)
		}
	}

	// The fully-populated block must arrive intact, not merely without error.
	var c Constraint
	if err := json.Unmarshal([]byte(`{"target":"tool:db_query","actions":["call"],"effect":`+full+`}`), &c); err != nil {
		t.Fatalf("full contract: %v", err)
	}
	e := c.Effect
	switch {
	case e == nil:
		t.Fatal("effect block dropped")
	case e.Class != EffectCompensable || !e.Idempotent || e.CompensatingAction != "tool:refund":
		t.Errorf("base fields = %+v", e)
	case e.BlastRadius == nil || e.BlastRadius.Argument != "amount" || e.BlastRadius.Unit != "usd":
		t.Errorf("blastRadius = %+v", e.BlastRadius)
	case e.ByArgument == nil || e.ByArgument.Argument != "op" || len(e.ByArgument.Cases) != 1:
		t.Errorf("byArgument = %+v", e.ByArgument)
	case e.ByArgument.Default == nil || e.ByArgument.Default.Class != EffectReversible:
		t.Errorf("default row = %+v", e.ByArgument.Default)
	case e.Ref == "":
		t.Error("ref dropped")
	}
	row := e.ByArgument.Cases["DROP"]
	if row.Idempotent == nil || *row.Idempotent {
		t.Errorf("case idempotent = %v, want an explicit false", row.Idempotent)
	}
	if row.BlastRadius == nil || row.BlastRadius.Value == nil || row.BlastRadius.Value.String() != "500" {
		t.Errorf("case blastRadius = %+v", row.BlastRadius)
	}
}

// A custom UnmarshalJSON does not inherit the caller's decoder options, so the UseNumber
// both readers of these blocks set (Constraint.UnmarshalJSON, internal/registry's corpus
// loader) stops at the effect boundary. Re-set there, a blast-radius literal above 2^53
// still reaches the digest and the ceiling comparison as the author wrote it — a float64
// widening would round it into a neighbouring magnitude.
func TestEffectDecode_PreservesExactNumericLiterals(t *testing.T) {
	const literal = "9007199254740993"
	var c Constraint
	if err := json.Unmarshal([]byte(`{"target":"tool:db_delete","actions":["call"],"effect":`+
		`{"blastRadius":{"value":`+literal+`},"byArgument":{"argument":"op","cases":`+
		`{"delete":{"blastRadius":{"value":`+literal+`}}}}}}`), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := []*json.Number{c.Effect.BlastRadius.Value, c.Effect.ByArgument.Cases["delete"].BlastRadius.Value}
	for i, n := range got {
		if n == nil || n.String() != literal {
			t.Errorf("literal %d = %v, want %s preserved exactly", i, n, literal)
		}
	}
}

// Digest inputs must be byte-stable across the new decode: an effect.ref pin is verified
// by recomputing EffectContractDigest over the decoded block, so a decoder that reshaped
// any field would turn every pinned manifest into a false tampering report.
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

// A non-object where a policy object belongs must still be a load error rather than a
// silently absent contract — the same failure mode the unknown-key check exists for.
func TestEffectDecode_RejectsNonObject(t *testing.T) {
	for _, tc := range []string{`"reversible"`, `["reversible"]`, `7`} {
		var c Constraint
		if err := json.Unmarshal([]byte(`{"target":"tool:t","actions":["call"],"effect":`+tc+`}`), &c); err == nil {
			t.Errorf("effect %s decoded clean, want a rejection", tc)
		} else if !strings.HasPrefix(err.Error(), "effect: ") {
			t.Errorf("error = %q, want it prefixed by the offending block", err)
		}
	}
}
