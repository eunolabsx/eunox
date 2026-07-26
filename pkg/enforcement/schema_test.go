// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for argumentSchema structural validation: ordering, INVALID_PARAMS precedence.
package enforcement_test

import (
	"context"
	"encoding/json"
	"math"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helpers

func intPtrC(n int) *int           { return &n }
func floatPtrC(f float64) *float64 { return &f }

// TestValidateArgumentSchema_NativeCompositeArguments pins that a direct caller of
// the exported ValidateArgumentSchema passing a NATIVE typed composite — the JSON
// decoder only ever yields []interface{}/map[string]interface{}, but a library
// caller can hand-build []string/[]int/map[string]int — has its array/object
// keywords enforced, not silently skipped. Such a value matched no arm of the type
// switch and fell through to "valid" (a fail-open), dropping a declared
// items/minItems/maxItems (or required) restriction.
func TestValidateArgumentSchema_NativeCompositeArguments(t *testing.T) {
	t.Parallel()

	t.Run("native []string over maxItems is rejected", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"tags": {
					MaxItems: intPtrC(3),
					Items:    &capability.ArgumentSchema{Type: capability.SchemaType{Single: "string"}},
				},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"tags": []string{"a", "b", "c", "d"}}, schema)
		require.Error(t, err, "maxItems:3 must be enforced against a native []string of length 4")
		assert.Contains(t, err.Error(), "maxItems")
	})

	t.Run("native []string within maxItems is accepted", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"tags": {MaxItems: intPtrC(3)},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"tags": []string{"a", "b"}}, schema)
		assert.NoError(t, err)
	})

	t.Run("native []int under minItems is rejected", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"ns": {MinItems: intPtrC(2)},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"ns": []int{1}}, schema)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "minItems")
	})

	t.Run("native map missing required key is rejected as an object", func(t *testing.T) {
		// No explicit Type: with one set, schemaCheckType already rejects the native
		// map as "unknown" — that pre-existing guard is not what this exercises. Omitting
		// Type forces the value through the new default arm, which must route it to
		// object validation and enforce required, rather than silently passing it.
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"obj": {
					Required: []string{"need"},
				},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"obj": map[string]int{"other": 1}}, schema)
		require.Error(t, err, "a native map[string]int must be routed through object validation")
		assert.Contains(t, err.Error(), "need")
	})

	// The subtests below declare an explicit Type — the standard, recommended way to
	// write an array/object schema. Before the fix schemaJSONTypeOf returned "unknown"
	// for native composites, so schemaCheckType rejected them up front with a misleading
	// `expected type "array", got "unknown"` and the native-composite validator never ran
	// (dead for any typed schema). schemaJSONTypeOf now classifies these via reflect.

	t.Run("typed array: native []string over maxItems is rejected", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"tags": {
					Type:     capability.SchemaType{Single: "array"},
					MaxItems: intPtrC(3),
				},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"tags": []string{"a", "b", "c", "d"}}, schema)
		require.Error(t, err, "type:array + maxItems:3 must reach the array validator for a native []string")
		assert.Contains(t, err.Error(), "maxItems")
	})

	t.Run("typed array: native []int under minItems is rejected", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"ns": {
					Type:     capability.SchemaType{Single: "array"},
					MinItems: intPtrC(2),
				},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"ns": []int{1}}, schema)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "minItems")
	})

	t.Run("typed array: valid native []string passes", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"tags": {
					Type:     capability.SchemaType{Single: "array"},
					MinItems: intPtrC(1),
					MaxItems: intPtrC(3),
				},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"tags": []string{"a", "b"}}, schema)
		assert.NoError(t, err, "a valid native []string must no longer be rejected as \"unknown\" under type:array")
	})

	t.Run("typed object: native map[string]int missing required key is rejected", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"obj": {
					Type:     capability.SchemaType{Single: "object"},
					Required: []string{"need"},
				},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"obj": map[string]int{"other": 1}}, schema)
		require.Error(t, err, "type:object must reach object validation for a native map[string]int")
		assert.Contains(t, err.Error(), "need")
	})

	t.Run("typed object: valid native map[string]int passes", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"obj": {
					Type:     capability.SchemaType{Single: "object"},
					Required: []string{"need"},
				},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"obj": map[string]int{"need": 1}}, schema)
		assert.NoError(t, err)
	})

	t.Run("untyped: a non-string-keyed map fails closed in the native-composite validator", func(t *testing.T) {
		// No Type: declared, so schemaCheckType is skipped and the value reaches
		// schemaValidateNativeComposite directly. A non-string-keyed map cannot model a JSON
		// object and must be rejected there, not silently passed.
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"obj": {Required: []string{"need"}},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"obj": map[int]string{1: "x"}}, schema)
		require.Error(t, err, "a non-string-keyed native map must fail closed even under an untyped schema")
		assert.Contains(t, err.Error(), "object key is not a string")
	})

	t.Run("typed array: a non-string-keyed map still fails closed at the type check", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"obj": {Type: capability.SchemaType{Single: "object"}},
			},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"obj": map[int]string{1: "x"}}, schema)
		require.Error(t, err, "a non-string-keyed map cannot model a JSON object and must fail closed")
		assert.Contains(t, err.Error(), "unknown")
	})
}

// TestArgumentSchema_RequiredFieldMissing verifies that a tool call
// missing a required field returns INVALID_PARAMS (not CONDITION_FAILED).
func TestArgumentSchema_RequiredFieldMissing(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraints := []capability.Constraint{
		{
			Target:  "query_db",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Required: []string{"sql"},
			},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "sql",
					Values:   []interface{}{"SELECT *"},
				},
			},
		},
	}

	req := &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "query_db",
		Arguments: map[string]interface{}{}, // missing "sql"
	}

	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeInvalidParams, resp.Denial.Code)
	assert.Equal(t, "argumentSchema", resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, `"sql"`)
}

// TestArgumentSchema_StructureWins_MalformedAndPolicyViolating verifies that when a
// request is BOTH schema-invalid AND policy-violating, INVALID_PARAMS is
// returned (structure takes precedence over condition failures).
func TestArgumentSchema_StructureWins_MalformedAndPolicyViolating(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	minLen := 10
	constraints := []capability.Constraint{
		{
			Target:  "send_email",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Required: []string{"to", "body"},
				Properties: map[string]*capability.ArgumentSchema{
					"body": {MinLength: &minLen},
				},
			},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "to",
					Values:   []interface{}{"@corp.example"},
				},
			},
		},
	}

	// Missing required field "body" AND "to" value violates allowedValues.
	req := &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "send_email",
		Arguments: map[string]interface{}{"to": "attacker@evil.com"},
	}

	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	// Structure (schema) wins: INVALID_PARAMS, not CONDITION_FAILED.
	assert.Equal(t, capability.ErrCodeInvalidParams, resp.Denial.Code)
}

// TestArgumentSchema_SchemaPass_ConditionFail verifies that when the schema passes
// but a condition fails, the denial code is CONDITION_FAILED.
func TestArgumentSchema_SchemaPass_ConditionFail(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraints := []capability.Constraint{
		{
			Target:  "read_file",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Required: []string{"path"},
			},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "path",
					Values:   []interface{}{"/reports/*"},
				},
			},
		},
	}

	// Schema passes (path is present) but condition fails (path not in /reports/).
	req := &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "read_file",
		Arguments: map[string]interface{}{"path": "/etc/passwd"},
	}

	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	// A value outside the allowedValues set denies with VALUE_NOT_PERMITTED,
	// matching the JWT enforcement path's denial_code. The point of this
	// test is that the schema-pass-but-condition-fail path is a real condition
	// denial, not a schema/params error.
	assert.Equal(t, capability.ErrCodeValueNotPermitted, resp.Denial.Code)
	assert.NotEqual(t, capability.ErrCodeInvalidParams, resp.Denial.Code)
}

// TestArgumentSchema_SchemaPass_ConditionPass_Allow verifies the happy path: schema
// passes, condition passes → allow with no denial.
func TestArgumentSchema_SchemaPass_ConditionPass_Allow(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraints := []capability.Constraint{
		{
			Target:  "read_file",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Required: []string{"path"},
			},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "path",
					Values:   []interface{}{"/reports/*"},
				},
			},
		},
	}

	req := &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "read_file",
		Arguments: map[string]interface{}{"path": "/reports/q3.pdf"},
	}

	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.Nil(t, resp.Denial)
}

// TestArgumentSchema_NilSchema_NoInvalidParams verifies that a constraint without an
// argumentSchema is not subjected to schema validation.
func TestArgumentSchema_NilSchema_NoInvalidParams(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraints := []capability.Constraint{
		{
			Target:  "any_tool",
			Actions: []string{"call"},
			// No ArgumentSchema — schema validation stage is skipped entirely.
		},
	}

	req := &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "any_tool",
		Arguments: map[string]interface{}{"random": "data"},
	}

	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// TestArgumentSchema_PatternViolation verifies that a pattern violation
// returns INVALID_PARAMS before any condition runs.
func TestArgumentSchema_PatternViolation(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraints := []capability.Constraint{
		{
			Target:  "create_report",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Required: []string{"title"},
				Properties: map[string]*capability.ArgumentSchema{
					"title": {Pattern: `^[A-Z]`},
				},
			},
			Conditions: []capability.Condition{
				// This condition would pass for any title — but must never run
				// when the schema rejects the input first.
				&capability.AllowedValuesCondition{
					Argument: "title",
					Values:   []interface{}{"*"},
				},
			},
		},
	}

	req := &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "create_report",
		Arguments: map[string]interface{}{"title": "lowercase-start"},
	}

	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeInvalidParams, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "pattern")
}

// TestArgumentSchema_MinimumViolation verifies numeric minimum is
// enforced and returns INVALID_PARAMS.
func TestArgumentSchema_MinimumViolation(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	minVal := 1.0
	constraints := []capability.Constraint{
		{
			Target:  "paginate",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"page": {Minimum: &minVal},
				},
			},
		},
	}

	req := &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "paginate",
		Arguments: map[string]interface{}{"page": float64(0)},
	}

	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeInvalidParams, resp.Denial.Code)
}

// TestArgumentSchema_AdditionalPropertiesDenied verifies that
// additional properties are rejected when additionalProperties is false.
func TestArgumentSchema_AdditionalPropertiesDenied(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	noExtra := false
	constraints := []capability.Constraint{
		{
			Target:  "strict_tool",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"name": {},
				},
				AdditionalProperties: &noExtra,
			},
		},
	}

	req := &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "strict_tool",
		Arguments: map[string]interface{}{"name": "Alice", "role": "admin"},
	}

	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeInvalidParams, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "additional property")
}

// TestArgumentSchema_ValidateUnit exercises ValidateArgumentSchema
// directly for unit coverage.
func TestArgumentSchema_ValidateUnit(t *testing.T) {
	t.Parallel()

	minLen := 3

	cases := []struct {
		name    string
		args    map[string]interface{}
		schema  *capability.ArgumentSchema
		wantErr bool
		errFrag string
	}{
		{
			name:   "nil schema passes",
			args:   map[string]interface{}{"x": "y"},
			schema: nil,
		},
		{
			name:    "required field missing",
			args:    map[string]interface{}{},
			schema:  &capability.ArgumentSchema{Required: []string{"id"}},
			wantErr: true,
			errFrag: `"id"`,
		},
		{
			name:   "required field present",
			args:   map[string]interface{}{"id": "abc"},
			schema: &capability.ArgumentSchema{Required: []string{"id"}},
		},
		{
			name: "minLength violation",
			args: map[string]interface{}{"q": "ab"},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"q": {MinLength: &minLen},
				},
			},
			wantErr: true,
			errFrag: "minLength",
		},
		{
			name: "array minItems violation",
			args: map[string]interface{}{"ids": []interface{}{}},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"ids": {MinItems: intPtrC(1)},
				},
			},
			wantErr: true,
			errFrag: "minItems",
		},
		{
			name: "enum violation",
			args: map[string]interface{}{"color": "purple"},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"color": {Enum: []interface{}{"red", "blue"}},
				},
			},
			wantErr: true,
			errFrag: "enum",
		},
		{
			name: "maximum violation",
			args: map[string]interface{}{"score": float64(110)},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"score": {Maximum: floatPtrC(100)},
				},
			},
			wantErr: true,
			errFrag: "maximum",
		},
		{
			// a non-float64 numeric arg (Go int, from a programmatic caller)
			// must still be range-checked, not silently pass minimum/maximum.
			name: "maximum violation with non-float64 int arg",
			args: map[string]interface{}{"score": int(110)},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"score": {Maximum: floatPtrC(100)},
				},
			},
			wantErr: true,
			errFrag: "maximum",
		},
		{
			name: "int64 within maximum passes",
			args: map[string]interface{}{"score": int64(50)},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"score": {Maximum: floatPtrC(100)},
				},
			},
		},
		{
			// an integer Go value must satisfy a declared type:integer rather
			// than being rejected as an unknown type.
			name: "int arg satisfies declared integer type",
			args: map[string]interface{}{"n": int(5)},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"n": {Type: capability.SchemaType{Single: "integer"}},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := enforcement.ValidateArgumentSchema(tc.args, tc.schema)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errFrag)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ── schema.Type keyword enforcement ───────────────────────────────────────────

// TestValidateArgumentSchema_TypeKeyword_NumberSentForString verifies that the
// engine's argument schema validator rejects a number sent where {type:string}
// is declared (the type keyword was previously never compared to the value's type).
func TestValidateArgumentSchema_TypeKeyword_NumberSentForString(t *testing.T) {
	t.Parallel()
	maxLen := 5
	schema := &capability.ArgumentSchema{
		Type:      capability.SchemaType{Single: "string"},
		MaxLength: &maxLen,
	}
	// A float64 must fail {type:string, maxLength:5} — before the fix it
	// fell through the type switch with no error, bypassing maxLength.
	err := enforcement.ValidateArgumentSchema(map[string]interface{}{"v": float64(99)}, &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{"v": schema},
	})
	require.Error(t, err, "regression: float should fail {type:string}")
	assert.Contains(t, err.Error(), "expected type")
}

// TestValidateArgumentSchema_TypeKeyword_CorrectType_Passes verifies the
// positive case: a value of the declared type passes.
func TestValidateArgumentSchema_TypeKeyword_CorrectType_Passes(t *testing.T) {
	t.Parallel()
	maxLen := 10
	schema := &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{
			"name": {
				Type:      capability.SchemaType{Single: "string"},
				MaxLength: &maxLen,
			},
		},
	}
	err := enforcement.ValidateArgumentSchema(map[string]interface{}{"name": "alice"}, schema)
	require.NoError(t, err, "regression: correct type should pass")
}

// TestValidateArgumentSchema_EnumDoesNotBypassType pins: enum and
// type are independent JSON Schema keywords that must both hold. A value that
// matches the enum must still satisfy the declared type — an enum hit must not
// short-circuit the type check. Here {type:string, enum:[1,2]} with the JSON
// number 1 matches the enum (numericEqual) but is the wrong type, so it must be
// rejected rather than reaching the upstream as a number.
func TestValidateArgumentSchema_EnumDoesNotBypassType(t *testing.T) {
	t.Parallel()
	schema := &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{
			"v": {
				Type: capability.SchemaType{Single: "string"},
				Enum: []interface{}{1, 2},
			},
		},
	}
	err := enforcement.ValidateArgumentSchema(map[string]interface{}{"v": float64(1)}, schema)
	require.Error(t, err, "value matching enum must still satisfy type:string")
	assert.Contains(t, err.Error(), "expected type")
}

// TestValidateArgumentSchema_EnumMatchCorrectTypePasses is the positive
// counterpart: a value matching the enum AND the declared type passes.
func TestValidateArgumentSchema_EnumMatchCorrectTypePasses(t *testing.T) {
	t.Parallel()
	schema := &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{
			"color": {
				Type: capability.SchemaType{Single: "string"},
				Enum: []interface{}{"red", "blue"},
			},
		},
	}
	err := enforcement.ValidateArgumentSchema(map[string]interface{}{"color": "red"}, schema)
	require.NoError(t, err, "value matching both enum and type must pass")
}

// TestValidateArgumentSchema_TypeKeyword_MultiType verifies that multi-type
// schemas accept any listed type.
func TestValidateArgumentSchema_TypeKeyword_MultiType(t *testing.T) {
	t.Parallel()
	schema := &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{
			"val": {
				Type: capability.SchemaType{Multiple: []string{"string", "number"}},
			},
		},
	}
	assert.NoError(t, enforcement.ValidateArgumentSchema(map[string]interface{}{"val": "hello"}, schema))
	assert.NoError(t, enforcement.ValidateArgumentSchema(map[string]interface{}{"val": float64(42)}, schema))

	err := enforcement.ValidateArgumentSchema(map[string]interface{}{"val": true}, schema)
	require.Error(t, err, "bool should fail [string,number]")
}

// TestValidateArgumentSchema_TypeKeyword_ObjectAdditionalProperties verifies
// the concrete bypass: a non-object sent where {type:object,additionalProperties:false}
// must fail (before the fix it silently passed).
func TestValidateArgumentSchema_TypeKeyword_ObjectAdditionalProperties(t *testing.T) {
	t.Parallel()
	f := false
	schema := &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{
			"opts": {
				Type:                 capability.SchemaType{Single: "object"},
				AdditionalProperties: &f,
			},
		},
	}
	err := enforcement.ValidateArgumentSchema(map[string]interface{}{"opts": "not-an-object"}, schema)
	require.Error(t, err, "regression: string should fail {type:object,additionalProperties:false}")
}

// ── integer type: reject numbers with a fractional part ───────────────────────

// TestValidateArgumentSchema_IntegerType verifies that {type: integer} rejects
// numbers with a fractional part while accepting whole-valued numbers. JSON has a
// single numeric type, so 42 and 3.14 both decode to float64; the validator must
// distinguish them. Before the fix, "integer" was an unconditional alias for
// "number" and 3.14 passed — making the integer constraint a no-op.
// TestValidateArgumentSchema_EnumNumericBridge verifies the enum check bridges
// the int/float64 type gap: an enum populated with bare Go ints (as a
// programmatic or embedded caller writes it) must match a request argument that
// arrives as float64 from JSON decoding, matching handleAllowedValues. Values
// outside the enum are still denied.
func TestValidateArgumentSchema_EnumNumericBridge(t *testing.T) {
	t.Parallel()

	schema := func() *capability.ArgumentSchema {
		return &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"count": {Enum: []interface{}{int(1), int(2), int(3)}}, // bare Go ints
			},
		}
	}

	cases := []struct {
		name    string
		value   float64
		wantErr bool
	}{
		{name: "float64 2 matches int enum", value: float64(2)},
		{name: "float64 1 matches int enum", value: float64(1)},
		{name: "float64 3 matches int enum", value: float64(3)},
		{name: "float64 4 not in enum denied", value: float64(4), wantErr: true},
		{name: "float64 2.5 not in enum denied", value: float64(2.5), wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := enforcement.ValidateArgumentSchema(map[string]interface{}{"count": tc.value}, schema())
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "enum")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateArgumentSchema_EnumLargeIntPrecision pins the precision half of the
// large-integer fix: a request number decoded with UseNumber arrives as a
// json.Number, and the enum check must compare it at full int64 precision BEFORE
// the float64 coercion the keyword checks need. Two integers above 2^53 that share
// a float64 representation (9007199254740992 and 9007199254740993) must not be
// conflated, or a manifest enum authorizing one would silently admit the other.
func TestValidateArgumentSchema_EnumLargeIntPrecision(t *testing.T) {
	t.Parallel()

	schema := func() *capability.ArgumentSchema {
		return &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"id": {Enum: []interface{}{int64(9007199254740992)}},
			},
		}
	}

	cases := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{name: "exact large int matches", value: json.Number("9007199254740992")},
		{name: "distinct large int denied", value: json.Number("9007199254740993"), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := enforcement.ValidateArgumentSchema(map[string]interface{}{"id": tc.value}, schema())
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "enum")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateArgumentSchema_IntegerType(t *testing.T) {
	t.Parallel()

	integerSchema := func() *capability.ArgumentSchema {
		return &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"count": {Type: capability.SchemaType{Single: "integer"}},
			},
		}
	}

	cases := []struct {
		name    string
		value   float64
		wantErr bool
	}{
		{name: "3.14 fails", value: 3.14, wantErr: true},
		{name: "0.1 fails", value: 0.1, wantErr: true},
		{name: "-2.9 fails", value: -2.9, wantErr: true},
		{name: "42 passes", value: 42},
		{name: "0 passes", value: 0},
		{name: "-3 passes", value: -3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := enforcement.ValidateArgumentSchema(map[string]interface{}{"count": tc.value}, integerSchema())
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "integer")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateArgumentSchema_IntegerType_MultiType verifies integer-ness within a
// multi-type schema: a fractional number satisfies [integer, number] (via number)
// but not [integer, string]. The integer check must not over-reject a value that a
// sibling type legitimately accepts.
func TestValidateArgumentSchema_IntegerType_MultiType(t *testing.T) {
	t.Parallel()

	intOrNumber := &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{
			"v": {Type: capability.SchemaType{Multiple: []string{"integer", "number"}}},
		},
	}
	// 3.14 is not an integer but is a number → accepted via "number".
	assert.NoError(t, enforcement.ValidateArgumentSchema(map[string]interface{}{"v": float64(3.14)}, intOrNumber))

	intOrString := &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{
			"v": {Type: capability.SchemaType{Multiple: []string{"integer", "string"}}},
		},
	}
	// 3.14 is neither a whole-number integer nor a string → rejected.
	require.Error(t, enforcement.ValidateArgumentSchema(map[string]interface{}{"v": float64(3.14)}, intOrString))
	// 7 is a whole number → accepted via "integer".
	assert.NoError(t, enforcement.ValidateArgumentSchema(map[string]interface{}{"v": float64(7)}, intOrString))
}

// ── deterministic property-validation order ───────────────────────────────────

// TestValidateArgumentSchema_DeterministicMultiViolation verifies that when an
// object violates more than one property schema at once, the same error surfaces
// on every run. Map iteration order is nondeterministic, so before the fix the
// reported violation depended on which key the runtime happened to visit first;
// the validator now sorts property names and reports the lexicographically-first
// failing one. Running each case many times catches a regression to plain map
// ranging, which would surface a different error on some iteration.
func TestValidateArgumentSchema_DeterministicMultiViolation(t *testing.T) {
	t.Parallel()

	minLen := 5

	cases := []struct {
		name    string
		args    map[string]interface{}
		schema  *capability.ArgumentSchema
		wantErr string
	}{
		{
			// "alpha" and "beta" both fail minLength; "alpha" sorts first.
			name: "two minLength violations report first key",
			args: map[string]interface{}{"alpha": "a", "beta": "b"},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"alpha": {MinLength: &minLen},
					"beta":  {MinLength: &minLen},
				},
			},
			wantErr: "$.alpha: string length 1 is less than minLength 5",
		},
		{
			// Mixed violation kinds across several keys: "aaa" (enum), "mmm"
			// (maximum), "zzz" (pattern) all fail; "aaa" sorts first.
			name: "mixed violations report lexicographically-first key",
			args: map[string]interface{}{
				"zzz": "lowercase",
				"mmm": float64(999),
				"aaa": "purple",
			},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"aaa": {Enum: []interface{}{"red", "blue"}},
					"mmm": {Maximum: floatPtrC(100)},
					"zzz": {Pattern: `^[A-Z]`},
				},
			},
			wantErr: "$.aaa: value not in enum",
		},
		{
			// Several disallowed extra properties; "extra1" sorts first.
			name: "multiple additional properties report first key",
			args: map[string]interface{}{
				"extra3": 1, "extra1": 2, "extra2": 3, "known": "ok",
			},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"known": {},
				},
				AdditionalProperties: func() *bool { b := false; return &b }(),
			},
			wantErr: `$: additional property "extra1" is not allowed`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Repeat enough times that a nondeterministic order would, with
			// overwhelming probability, surface a different error at least once.
			for i := 0; i < 200; i++ {
				err := enforcement.ValidateArgumentSchema(tc.args, tc.schema)
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error(),
					"validation error must be identical across runs (iteration %d)", i)
			}
		})
	}
}

// TestArgumentSchema_IntegerType_DeniedThroughEngine verifies that a non-integer
// value against {type: integer} is denied with INVALID_PARAMS through the full
// engine, before any condition runs — closing the gap where e.g. LIMIT 3.14 would
// reach the upstream interpreted as a whole number. A whole-number value still
// passes.
func TestArgumentSchema_IntegerType_DeniedThroughEngine(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraints := []capability.Constraint{
		{
			Target:  "query_db",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"limit": {Type: capability.SchemaType{Single: "integer"}},
				},
			},
		},
	}

	// Non-integer is denied with INVALID_PARAMS.
	resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "query_db",
		Arguments: map[string]interface{}{"limit": float64(3.14)},
	}, constraints)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeInvalidParams, resp.Denial.Code)

	// Whole-number value passes.
	resp = e.ValidateAction(context.Background(), &capability.EnforceRequest{
		SessionID: "sess",
		ToolName:  "query_db",
		Arguments: map[string]interface{}{"limit": float64(3)},
	}, constraints)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// TestValidateArgumentSchema_OverflowingJSONNumberFailsClosed pins: a
// numeric argument whose magnitude overflows float64 (here 1e400, arriving as a
// json.Number from a UseNumber-decoded request) must NOT silently pass when the
// schema declares minimum/maximum but omits an explicit `type`. Before the fix,
// the un-coercible json.Number fell through the type switch and returned nil
// (ALLOW), bypassing the bounds entirely. It must now fail closed with a
// "numeric value out of representable range" validation error.
func TestValidateArgumentSchema_OverflowingJSONNumberFailsClosed(t *testing.T) {
	t.Parallel()

	// A type-less {minimum, maximum} schema on the "n" property.
	schema := func() *capability.ArgumentSchema {
		return &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"n": {Minimum: floatPtrC(0), Maximum: floatPtrC(100)},
			},
		}
	}

	cases := []struct {
		name    string
		value   interface{}
		wantErr bool
		errSub  string
	}{
		// Deny: an overflowing json.Number cannot be represented as float64, so it
		// can neither be bounds-checked nor trusted — fail closed.
		{name: "overflow json.Number denied", value: json.Number("1e400"), wantErr: true, errSub: "out of representable range"},
		{name: "negative overflow json.Number denied", value: json.Number("-1e400"), wantErr: true, errSub: "out of representable range"},
		// Allow: an in-range json.Number coerces to float64 and satisfies the bounds.
		{name: "in-range json.Number allowed", value: json.Number("42")},
		// Deny on the bound itself, proving the bounds still apply to coercible numbers.
		{name: "above-max json.Number denied", value: json.Number("101"), wantErr: true, errSub: "exceeds maximum"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := enforcement.ValidateArgumentSchema(map[string]interface{}{"n": tc.value}, schema())
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSub)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateArgumentSchema_NonFiniteFailsClosed pins: a NaN/Inf numeric argument
// must fail closed against a {minimum, maximum} schema. strconv.ParseFloat accepts
// "NaN"/"Inf"/"Infinity", so the coercion succeeds and the resulting NaN satisfies
// neither v < min nor v > max — bypassing both bounds — unless explicitly rejected.
func TestValidateArgumentSchema_NonFiniteFailsClosed(t *testing.T) {
	t.Parallel()

	schema := func() *capability.ArgumentSchema {
		return &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"n": {Minimum: floatPtrC(0), Maximum: floatPtrC(100)},
			},
		}
	}

	cases := []struct {
		name    string
		value   interface{}
		wantErr bool
		errSub  string
	}{
		{name: "json.Number NaN denied", value: json.Number("NaN"), wantErr: true, errSub: "non-finite"},
		{name: "programmatic NaN denied", value: math.NaN(), wantErr: true, errSub: "non-finite"},
		{name: "json.Number Inf denied", value: json.Number("Inf"), wantErr: true, errSub: "non-finite"},
		{name: "programmatic +Inf denied", value: math.Inf(1), wantErr: true, errSub: "non-finite"},
		{name: "programmatic -Inf denied", value: math.Inf(-1), wantErr: true, errSub: "non-finite"},
		{name: "in-range value still allowed", value: json.Number("42")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := enforcement.ValidateArgumentSchema(map[string]interface{}{"n": tc.value}, schema())
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSub)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	// Also enforce the guard under an explicit numeric type, which routes through
	// the same coercion/guard before schemaCheckType.
	for _, typ := range []string{"integer", "number"} {
		t.Run("type_"+typ+"_NaN_denied", func(t *testing.T) {
			t.Parallel()
			s := &capability.ArgumentSchema{Properties: map[string]*capability.ArgumentSchema{
				"n": {Type: capability.SchemaType{Single: typ}},
			}}
			err := enforcement.ValidateArgumentSchema(map[string]interface{}{"n": json.Number("NaN")}, s)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "non-finite")
		})
	}
}

// TestValidateArgumentSchema_BoundLargeIntPrecision pins: minimum/maximum bounds on
// integers at or above 2^53 must be compared at int64 precision, not the rounded
// float64. 9007199254740993 (2^53+1) rounds to 9007199254740992 (2^53) when coerced
// to float64; against maximum 9007199254740992 the rounded compare would pass it
// (a fail-open). The exact int64 compare must deny it.
func TestValidateArgumentSchema_BoundLargeIntPrecision(t *testing.T) {
	t.Parallel()

	maxSchema := func() *capability.ArgumentSchema {
		return &capability.ArgumentSchema{Properties: map[string]*capability.ArgumentSchema{
			"n": {Maximum: floatPtrC(9007199254740992)}, // 2^53
		}}
	}
	minSchema := func() *capability.ArgumentSchema {
		return &capability.ArgumentSchema{Properties: map[string]*capability.ArgumentSchema{
			"n": {Minimum: floatPtrC(-9007199254740992)}, // -2^53
		}}
	}

	cases := []struct {
		name    string
		schema  *capability.ArgumentSchema
		value   interface{}
		wantErr bool
	}{
		{name: "2^53+1 over max denied", schema: maxSchema(), value: json.Number("9007199254740993"), wantErr: true},
		{name: "2^53 at max allowed", schema: maxSchema(), value: json.Number("9007199254740992")},
		{name: "-(2^53+1) under min denied", schema: minSchema(), value: json.Number("-9007199254740993"), wantErr: true},
		{name: "-2^53 at min allowed", schema: minSchema(), value: json.Number("-9007199254740992")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := enforcement.ValidateArgumentSchema(map[string]interface{}{"n": tc.value}, tc.schema)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// namedPath / namedPort / namedFlag are the shapes a direct (library) caller of the
// exported ValidateArgumentSchema can hand-build that the JSON decoder never produces.
type namedPath string
type namedPort int
type namedFlag bool

// TestValidateArgumentSchema_NamedScalarArguments pins that a NAMED scalar type has its
// keyword checks enforced rather than silently skipped.
//
// `type namedPath string` is not assignable to interface{}.(string), so it matched no arm
// of the type switch, fell through past every string/number keyword, and returned nil —
// a fail-open that dropped a declared pattern/minLength/maxLength/minimum/maximum. It is
// unreachable from the proxy's own JSON path (which yields only stdlib decode types), but
// an embedder calling the engine directly could hit it, and the failure is silent.
func TestValidateArgumentSchema_NamedScalarArguments(t *testing.T) {
	t.Parallel()

	t.Run("typeless: named string violating maxLength is rejected", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{"p": {MaxLength: intPtrC(3)}},
		}
		err := enforcement.ValidateArgumentSchema(map[string]interface{}{"p": namedPath("/etc/passwd")}, schema)
		require.Error(t, err, "a named string type must still be length-checked")
		assert.Contains(t, err.Error(), "maxLength")
	})

	t.Run("typeless: named string violating pattern is rejected", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{"p": {Pattern: `^/srv/`}},
		}
		err := enforcement.ValidateArgumentSchema(map[string]interface{}{"p": namedPath("/etc/passwd")}, schema)
		require.Error(t, err, "a named string type must still be pattern-checked")
		assert.Contains(t, err.Error(), "pattern")
	})

	t.Run("typed: named string is classified as a string, not unknown", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"p": {Type: capability.SchemaType{Single: "string"}, MinLength: intPtrC(1)},
			},
		}
		assert.NoError(t, enforcement.ValidateArgumentSchema(
			map[string]interface{}{"p": namedPath("/srv/data")}, schema),
			"a valid named string under type:string must not be rejected as unknown")
	})

	t.Run("typeless: named int over maximum is rejected", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{"port": {Maximum: floatPtrC(1024)}},
		}
		err := enforcement.ValidateArgumentSchema(map[string]interface{}{"port": namedPort(8080)}, schema)
		require.Error(t, err, "a named integer type must still be bound-checked")
		assert.Contains(t, err.Error(), "maximum")
	})

	// A named scalar must still MATCH an enum entry written with the same named type.
	// unwrapNamedScalar rewrites the argument, and reflect.DeepEqual is
	// type-identity-sensitive, so unwrapping only the argument would turn a match that
	// held before into a denial — a silent fail-closed regression for an embedder whose
	// enum and arguments share a domain type.
	t.Run("named string matches a named enum entry", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"p": {Enum: []interface{}{namedPath("/srv/a"), namedPath("/srv/b")}},
			},
		}
		assert.NoError(t, enforcement.ValidateArgumentSchema(
			map[string]interface{}{"p": namedPath("/srv/a")}, schema))
		// Cross-form: the entry written plainly, the argument named, and vice versa.
		assert.NoError(t, enforcement.ValidateArgumentSchema(
			map[string]interface{}{"p": "/srv/b"}, schema))
		require.Error(t, enforcement.ValidateArgumentSchema(
			map[string]interface{}{"p": namedPath("/etc/passwd")}, schema))
	})

	t.Run("named bool carries no keyword and passes", func(t *testing.T) {
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{
				"f": {Type: capability.SchemaType{Single: "boolean"}},
			},
		}
		assert.NoError(t, enforcement.ValidateArgumentSchema(map[string]interface{}{"f": namedFlag(true)}, schema))
	})

	t.Run("json.Number keeps its numeric semantics", func(t *testing.T) {
		// json.Number is itself a named string type; unwrapping it to a plain string
		// would lose the int64-exact bound comparison the number path depends on.
		schema := &capability.ArgumentSchema{
			Properties: map[string]*capability.ArgumentSchema{"n": {Maximum: floatPtrC(9007199254740992)}},
		}
		err := enforcement.ValidateArgumentSchema(
			map[string]interface{}{"n": json.Number("9007199254740993")}, schema)
		require.Error(t, err, "json.Number must stay on the exact numeric path")
		assert.Contains(t, err.Error(), "maximum")
	})
}
