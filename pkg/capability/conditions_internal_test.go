// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"reflect"
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
		// Beyond int64 range (2^64+1): wholeInt64Float(f) alone would miss this (f is
		// out of int64 range, so it is not a "whole int64" per that check), which is
		// why exactFloatBound's exactness check must also trigger on orig.IsInt() —
		// any integer literal, at any magnitude — not only on wholeInt64Float(f).
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
