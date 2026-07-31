// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Numeric policy literals above 2^53 must survive unmarshalling byte-exact. A
// plain json.Unmarshal widens them to float64, which rounds 9007199254740993 to
// 9007199254740992 and would authorize the adjacent integer. unmarshalCondition
// and Constraint.UnmarshalJSON decode with UseNumber so the literal stays a
// json.Number.
func TestUnmarshalCondition_PreservesLargeIntegerValues(t *testing.T) {
	const big = "9007199254740993" // 2^53 + 1, not representable exactly as float64
	data := []byte(`{"type":"allowedValues","argument":"id","values":[` + big + `]}`)

	cond, err := unmarshalCondition(data)
	if err != nil {
		t.Fatalf("unmarshalCondition: %v", err)
	}
	av, ok := cond.(*AllowedValuesCondition)
	if !ok {
		t.Fatalf("expected *AllowedValuesCondition, got %T", cond)
	}
	if len(av.Values) != 1 {
		t.Fatalf("expected 1 value, got %d", len(av.Values))
	}
	num, ok := av.Values[0].(json.Number)
	if !ok {
		t.Fatalf("expected json.Number value (UseNumber), got %T (%v)", av.Values[0], av.Values[0])
	}
	if num.String() != big {
		t.Fatalf("large integer value rounded: got %q, want %q", num.String(), big)
	}
}

// argumentSchema.enum literals above 2^53 must likewise survive Constraint
// unmarshalling exactly.
func TestConstraintUnmarshal_PreservesLargeIntegerEnum(t *testing.T) {
	const big = "9007199254740993"
	data := []byte(`{"target":"tool:x","actions":["call"],"argumentSchema":{"type":"object","properties":{"id":{"enum":[` + big + `]}}}}`)

	var c Constraint
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("Constraint unmarshal: %v", err)
	}
	if c.ArgumentSchema == nil {
		t.Fatal("argumentSchema not decoded")
	}
	idSchema := c.ArgumentSchema.Properties["id"]
	if idSchema == nil || len(idSchema.Enum) != 1 {
		t.Fatalf("enum not decoded: %+v", c.ArgumentSchema)
	}
	num, ok := idSchema.Enum[0].(json.Number)
	if !ok {
		t.Fatalf("expected json.Number enum value, got %T (%v)", idSchema.Enum[0], idSchema.Enum[0])
	}
	if num.String() != big {
		t.Fatalf("large integer enum rounded: got %q, want %q", num.String(), big)
	}
}

// argumentSchema minimum/maximum bounds must be decoded exactly: an integer bound
// above 2^53 does not round-trip through float64, so it is rejected at load rather
// than silently rounded into a neighbouring value that would admit an argument
// strictly below the written minimum (or above the written maximum).
func TestConstraintUnmarshal_RejectsLossyNumericBound(t *testing.T) {
	cases := []struct {
		name string
		key  string
		val  string
	}{
		{"minimum above 2^53", "minimum", "1700000000000000001"},
		{"maximum above 2^53", "maximum", "9007199254740993"},
		// Beyond int64 range (2^64+1): FloatToInt64(f) alone would miss this (f is
		// out of int64 range, so it is not a "whole int64" per that check), which is
		// why exactFloatBound's exactness check must also trigger on orig.IsInt() —
		// any integer literal, at any magnitude — not only on FloatToInt64(f).
		{"minimum beyond int64 range", "minimum", "18446744073709551617"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"target":"tool:x","actions":["call"],"argumentSchema":{"type":"object","properties":{"ts":{"` + tc.key + `":` + tc.val + `}}}}`)
			var c Constraint
			if err := json.Unmarshal(data, &c); err == nil {
				t.Fatalf("expected a lossy %s bound %s to be rejected, got no error", tc.key, tc.val)
			}
		})
	}
}

// TestConstraintUnmarshal_RejectsFractionalBoundThatRoundsToWholeNumber is the
// regression for exactFloatBound's old orig.IsInt() gate: it skipped the
// round-trip-exactness check for any bound written with a decimal point, even
// when the bound's magnitude is large enough that float64 rounds away the
// fractional part entirely. 9007199254740993.5 (2^53 + 1.5) is not itself an
// integer literal, so the old check let it through untouched — but float64
// rounds it to the WHOLE number 9007199254740994.0, which compareToBound's
// exact-int64 fast path (pkg/enforcement/schema.go) then treats as an exact
// integer bound the manifest never wrote, silently admitting an argument at
// that rounded boundary. The bound must be rejected at load instead.
func TestConstraintUnmarshal_RejectsFractionalBoundThatRoundsToWholeNumber(t *testing.T) {
	for _, key := range []string{"minimum", "maximum"} {
		t.Run(key, func(t *testing.T) {
			data := []byte(`{"target":"tool:x","actions":["call"],"argumentSchema":{"type":"object","properties":{"ts":{"` + key + `":9007199254740993.5}}}}`)
			var c Constraint
			if err := json.Unmarshal(data, &c); err == nil {
				t.Fatal("expected rejection of a fractional bound that rounds to a whole float64 number, got no error")
			}
		})
	}
}

// An exactly-representable bound (including a large power-of-two-divisible integer and
// an ordinary fractional value) must still load and be preserved.
func TestConstraintUnmarshal_AcceptsExactNumericBound(t *testing.T) {
	cases := []struct {
		key  string
		val  string
		want float64
	}{
		{"minimum", "9007199254740992", 9007199254740992}, // exactly 2^53
		{"maximum", "3.5", 3.5},
		{"minimum", "-1000", -1000},
		// Ordinary decimal fractions are NOT exactly representable in float64 but must load:
		// a fractional bound is compared in float64 on both sides, so its approximation is
		// consistent. Rejecting these would fail common price/threshold manifests closed.
		{"minimum", "19.99", 19.99},
		{"minimum", "0.1", 0.1},
		{"maximum", "3.14", 3.14},
		{"maximum", "1.7e18", 1.7e18}, // integer VALUE in exponent form, exactly representable
	}
	for _, tc := range cases {
		data := []byte(`{"target":"tool:x","actions":["call"],"argumentSchema":{"type":"object","properties":{"ts":{"` + tc.key + `":` + tc.val + `}}}}`)
		var c Constraint
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatalf("exact bound %s=%s must load: %v", tc.key, tc.val, err)
		}
		ts := c.ArgumentSchema.Properties["ts"]
		var got *float64
		if tc.key == "minimum" {
			got = ts.Minimum
		} else {
			got = ts.Maximum
		}
		if got == nil || *got != tc.want {
			t.Fatalf("bound %s=%s: got %v, want %v", tc.key, tc.val, got, tc.want)
		}
	}
}

// TestEveryArgumentCarryingConditionImplementsArgumentNamer is the reflection
// guard behind FM-3 drift coverage: any condition type that carries an `Argument`
// field MUST implement ArgumentNamer, so conditionArgumentNames (and the drift
// check that backs it) cannot silently skip it. A new argument-carrying condition
// type that forgets the ArgumentName method fails here rather than degrading FM-3
// coverage invisibly.
// A typed-nil condition pointer (not a nil interface) carries a concrete type, so
// the nil-interface guard in ConditionWrapper.MarshalJSON is skipped; marshalCondition
// must still emit "null" rather than dereference the nil pointer through the
// value-receiver ConditionType() and panic. This mirrors the directive sibling guard
// (see TestDirectiveWrapper_TypedNilPointer_MarshalsToNull). Covers every pointer case.
func TestConditionWrapper_TypedNilPointer_MarshalsToNull(t *testing.T) {
	for _, ct := range knownConditionTypes {
		cond := newCondition(ct) // non-nil pointer to the concrete struct
		if cond == nil {
			t.Fatalf("newCondition(%q) returned nil", ct)
		}
		// Construct a typed-nil pointer of the same concrete type.
		typedNil := reflect.Zero(reflect.TypeOf(cond)).Interface().(Condition)
		w := ConditionWrapper{Condition: typedNil}
		data, err := json.Marshal(w)
		if err != nil {
			t.Errorf("condition type %q: typed-nil marshal returned error: %v", ct, err)
			continue
		}
		if string(data) != "null" {
			t.Errorf("condition type %q: typed-nil marshaled to %q, want \"null\"", ct, string(data))
		}
	}
}

func TestEveryArgumentCarryingConditionImplementsArgumentNamer(t *testing.T) {
	for _, ct := range knownConditionTypes {
		cond := newCondition(ct)
		if cond == nil {
			t.Fatalf("newCondition(%q) returned nil — knownConditionTypes and newCondition disagree", ct)
		}
		// cond is a pointer to the concrete struct; inspect the underlying struct.
		v := reflect.ValueOf(cond).Elem()
		if v.Kind() != reflect.Struct {
			continue
		}
		if _, hasArg := v.Type().FieldByName("Argument"); !hasArg {
			continue
		}
		if _, ok := cond.(ArgumentNamer); !ok {
			t.Errorf("condition type %q has an Argument field but does not implement ArgumentNamer; "+
				"add an ArgumentName() method so it is covered by FM-3 drift checking", ct)
		}
	}
}

// ── strict unknown-field decode ─────────────────────────────────────────────

// unmarshalCondition rejects a field name no condition struct binds. A lenient decode
// silently DROPS a misspelled field, which for a condition means a policy quietly wider
// than the operator wrote: "notAfterr" leaves NotAfter zero and enforces only the lower
// bound of the window.
func TestUnmarshalCondition_RejectsUnknownField(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string // substring the error must name
	}{
		{
			name: "timeWindow bound typo enforces only one side",
			json: `{"type":"timeWindow","notBefore":"09:00","notAfterr":"17:00"}`,
			want: `unknown field "notAfterr"`,
		},
		{
			name: "maxCalls limit typo",
			json: `{"type":"maxCalls","maxx":5,"windowSeconds":60}`,
			want: `unknown field "maxx"`,
		},
		{
			name: "allowedValues argument typo",
			json: `{"type":"allowedValues","arguments":"path","values":["/tmp"]}`,
			want: `unknown field "arguments"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unmarshalCondition([]byte(tc.json))
			if err == nil {
				t.Fatalf("unmarshalCondition(%s) = nil error, want a rejection", tc.json)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %s", err, tc.want)
			}
		})
	}
}

// The unknown-field check must not reject anything a lenient decode would have bound:
// the "type" discriminator (no condition struct has it as a field) and any field name
// spelled in a different case, since encoding/json binds case-insensitively.
func TestUnmarshalCondition_AcceptsDiscriminatorAndCaseVariants(t *testing.T) {
	cases := []string{
		`{"type":"timeWindow","notBefore":"09:00","notAfter":"17:00"}`,
		`{"type":"timeWindow","NOTBEFORE":"09:00","notafter":"17:00"}`,
		`{"TYPE":"timeWindow","notBefore":"09:00"}`,
	}
	for _, j := range cases {
		if _, err := unmarshalCondition([]byte(j)); err != nil {
			t.Errorf("unmarshalCondition(%s) = %v, want it accepted (the decode would bind these)", j, err)
		}
	}
}

// Every condition type this build models must survive a round-trip through the strict
// decoder. A field the check does not know about would make a perfectly valid manifest
// unloadable, so this pins jsonFieldNames against every registered type at once rather
// than relying on per-type cases to stay complete.
func TestUnmarshalCondition_StrictCheckAcceptsEveryMarshaledConditionType(t *testing.T) {
	for _, ct := range knownConditionTypes {
		cond := newCondition(ct)
		if cond == nil {
			t.Fatalf("newCondition(%q) returned nil", ct)
		}
		data, err := marshalCondition(cond)
		if err != nil {
			t.Fatalf("marshalCondition(%q): %v", ct, err)
		}
		if _, err := unmarshalCondition(data); err != nil {
			t.Errorf("condition %q does not survive its own marshaling under the strict decode: %v (marshaled: %s)", ct, err, data)
		}
	}
}

// jsonFieldNames reports the lowercased names encoding/json would bind, honoring the
// json tag (including a renamed field and an omitempty suffix) and skipping both "-"
// and unexported fields.
func TestJSONFieldNames(t *testing.T) {
	type sample struct {
		Renamed  string `json:"wireName"`
		Omitted  string `json:"trimmed,omitempty"`
		Skipped  string `json:"-"`
		NoTag    string
		unexport string //nolint:unused // present to prove unexported fields are skipped
	}
	got := jsonFieldNames(&sample{})
	for _, want := range []string{"wirename", "trimmed", "notag"} {
		if !got[want] {
			t.Errorf("jsonFieldNames missing %q; got %v", want, got)
		}
	}
	for _, absent := range []string{"skipped", "renamed", "omitted", "unexport"} {
		if got[absent] {
			t.Errorf("jsonFieldNames should not contain %q; got %v", absent, got)
		}
	}
}

// The per-type memo must return the same content on a cache hit as on the miss that
// populated it — a broken cache would silently start rejecting valid fields.
func TestJSONFieldNames_CachedResultMatchesFresh(t *testing.T) {
	first := jsonFieldNames(&TimeWindowCondition{})
	second := jsonFieldNames(&TimeWindowCondition{})
	if len(first) != len(second) {
		t.Fatalf("cached result differs in size: %v vs %v", first, second)
	}
	for k := range first {
		if !second[k] {
			t.Errorf("cached result lost key %q", k)
		}
	}
}

// Constraint.UnmarshalJSON applies the same rule one level up. It decoded leniently,
// so a misspelled "principal" — the field that decides WHO a constraint governs —
// bound nothing and left Principal nil, which applies the constraint to every caller.
// Same silent-widening class the condition check closes, on the field where widening
// costs the most.
func TestConstraintUnmarshalJSON_RejectsUnknownField(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{
			name: "misspelled principal silently widens to every caller",
			json: `{"target":"tool:read_file","actions":["call"],"principals":{"sub":["alice"]}}`,
			want: `unknown field "principals"`,
		},
		{
			name: "misspelled conditions drops the whole restriction",
			json: `{"target":"tool:read_file","actions":["call"],"condition":[{"type":"maxCalls","count":1,"windowSeconds":60}]}`,
			want: `unknown field "condition"`,
		},
		{
			name: "misspelled descriptionHash drops the pin",
			json: `{"target":"tool:read_file","actions":["call"],"descriptionhashh":"sha256:abc"}`,
			want: `unknown field "descriptionhashh"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Constraint
			err := c.UnmarshalJSON([]byte(tc.json))
			if err == nil {
				t.Fatalf("UnmarshalJSON(%s) = nil error, want a rejection", tc.json)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %s", err, tc.want)
			}
		})
	}
}

// ArgumentSchema.UnmarshalJSON likewise, including at nesting depth: every
// properties/items value decodes through the same method, so the check recurses for
// free and a typo buried in a nested object is caught where it was written.
func TestArgumentSchemaUnmarshalJSON_RejectsUnknownField(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{
			name: "misspelled maxLength validates length not at all",
			json: `{"type":"string","maxLen":8}`,
			want: `unknown field "maxLen"`,
		},
		{
			name: "typo nested under properties",
			json: `{"type":"object","properties":{"path":{"type":"string","patern":"^/tmp/"}}}`,
			want: `unknown field "patern"`,
		},
		{
			name: "typo nested under items",
			json: `{"type":"array","items":{"type":"string","enumm":["a"]}}`,
			want: `unknown field "enumm"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s ArgumentSchema
			err := s.UnmarshalJSON([]byte(tc.json))
			if err == nil {
				t.Fatalf("UnmarshalJSON(%s) = nil error, want a rejection", tc.json)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %s", err, tc.want)
			}
		})
	}
}

// Neither strict decoder may reject what a lenient decode would have bound: every real
// field, in any case spelling, and a full round-trip of what MarshalJSON emits.
func TestStrictDecoders_AcceptEveryRealField(t *testing.T) {
	full := `{"target":"tool:read_file","actions":["call"],"enforcement":"audit",` +
		`"descriptionHash":"sha256:abc","principal":{"sub":["alice"]},` +
		`"argumentSchema":{"type":"object","properties":{"path":{"type":"string","pattern":"^/tmp/",` +
		`"minLength":1,"maxLength":64}},"required":["path"],"additionalProperties":false,` +
		`"items":null,"minItems":0,"maxItems":4,"minimum":1,"maximum":8,"enum":[1,2],"description":"d"},` +
		`"conditions":[{"type":"maxCalls","count":1,"windowSeconds":60}],` +
		`"directives":[{"type":"redactFields","fields":["$.ssn"]}]}`
	var c Constraint
	if err := c.UnmarshalJSON([]byte(full)); err != nil {
		t.Fatalf("a constraint using every field must decode: %v", err)
	}
	// Case variants: encoding/json binds case-insensitively, so the check must too.
	if err := (&Constraint{}).UnmarshalJSON([]byte(`{"TARGET":"tool:x","Actions":["call"],"PRINCIPAL":{"sub":["a"]}}`)); err != nil {
		t.Errorf("case-variant field names must be accepted: %v", err)
	}
	if err := (&ArgumentSchema{}).UnmarshalJSON([]byte(`{"TYPE":"string","MaxLength":4}`)); err != nil {
		t.Errorf("case-variant schema field names must be accepted: %v", err)
	}
	// Round-trip: whatever MarshalJSON emits must decode back.
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := (&Constraint{}).UnmarshalJSON(out); err != nil {
		t.Fatalf("round-trip of MarshalJSON output must decode: %v (%s)", err, out)
	}
}
