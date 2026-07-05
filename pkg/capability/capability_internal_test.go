// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package capability tests capability token JSON models and related payload types.

// Additional coverage for polymorphic JSON (de)serialization, action-validation
// tables, and obligation/directive/condition envelope edge cases.

// Regression tests for the removed annotate obligation type.

package capability

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionRoundTripByType(t *testing.T) {
	tests := []struct {
		name       string
		condition  Condition
		wantType   string
		assertFunc func(*testing.T, Condition)
	}{
		{
			name:      "time window",
			condition: TimeWindowCondition{NotBefore: "2025-01-01T00:00:00Z", NotAfter: "2025-12-31T23:59:59Z"},
			wantType:  ConditionTypeTimeWindow,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*TimeWindowCondition)
				assert.Equal(t, "2025-01-01T00:00:00Z", typed.NotBefore)
				assert.Equal(t, "2025-12-31T23:59:59Z", typed.NotAfter)
			},
		},
		{
			name:      "ip range",
			condition: IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			wantType:  ConditionTypeIPRange,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{"10.0.0.0/8"}, condition.(*IPRangeCondition).CIDRs)
			},
		},
		{
			name:      "allowed operations",
			condition: AllowedOperationsCondition{Operations: []string{"read", "write"}},
			wantType:  ConditionTypeAllowedOperations,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{"read", "write"}, condition.(*AllowedOperationsCondition).Operations)
			},
		},
		{
			name:      "allowed extensions",
			condition: AllowedExtensionsCondition{Extensions: []string{".txt", ".csv"}},
			wantType:  ConditionTypeAllowedExtensions,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{".txt", ".csv"}, condition.(*AllowedExtensionsCondition).Extensions)
			},
		},
		{
			name:      "allowed tables",
			condition: AllowedTablesCondition{Tables: []string{"users"}, Columns: map[string][]string{"users": {"id", "name"}}},
			wantType:  ConditionTypeAllowedTables,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*AllowedTablesCondition)
				assert.Equal(t, []string{"users"}, typed.Tables)
				assert.Equal(t, []string{"id", "name"}, typed.Columns["users"])
			},
		},
		{
			name:      "max calls",
			condition: MaxCallsCondition{Count: 42, WindowSeconds: 300},
			wantType:  ConditionTypeMaxCalls,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*MaxCallsCondition)
				assert.Equal(t, 42, typed.Count)
				assert.Equal(t, 300, typed.WindowSeconds)
			},
		},
		{
			name:      "recipient domain",
			condition: RecipientDomainCondition{Domains: []string{"example.com"}},
			wantType:  ConditionTypeRecipientDomain,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{"example.com"}, condition.(*RecipientDomainCondition).Domains)
			},
		},
		{
			name:      "policy",
			condition: PolicyCondition{Backend: "opa", Config: map[string]interface{}{"bundle": "main"}, Input: map[string]interface{}{"team": "infra"}},
			wantType:  ConditionTypePolicy,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*PolicyCondition)
				assert.Equal(t, "opa", typed.Backend)
				assert.Equal(t, "main", typed.Config.(map[string]interface{})["bundle"])
				assert.Equal(t, "infra", typed.Input.(map[string]interface{})["team"])
			},
		},
		{
			name:      "custom",
			condition: CustomCondition{Name: "labelMatch", Config: map[string]interface{}{"label": "trusted"}},
			wantType:  ConditionTypeCustom,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*CustomCondition)
				assert.Equal(t, "labelMatch", typed.Name)
				assert.Equal(t, "trusted", typed.Config.(map[string]interface{})["label"])
			},
		},
		{
			name:      "allowed values",
			condition: AllowedValuesCondition{Argument: "format", Values: []interface{}{"json", "csv", true, nil}},
			wantType:  ConditionTypeAllowedValues,
			assertFunc: func(t *testing.T, condition Condition) {
				typed := condition.(*AllowedValuesCondition)
				assert.Equal(t, "format", typed.Argument)
				require.Len(t, typed.Values, 4)
				assert.Equal(t, "json", typed.Values[0])
				assert.Equal(t, "csv", typed.Values[1])
			},
		},
		{
			name:      "sequence block",
			condition: SequenceBlockCondition{AfterTools: []string{"read_credentials", "tool:list_secrets"}},
			wantType:  ConditionTypeSequenceBlock,
			assertFunc: func(t *testing.T, condition Condition) {
				assert.Equal(t, []string{"read_credentials", "tool:list_secrets"}, condition.(*SequenceBlockCondition).AfterTools)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.condition)
			require.NoError(t, err)
			assert.Contains(t, string(data), `"type":"`+tt.wantType+`"`)

			var wrapper ConditionWrapper
			require.NoError(t, json.Unmarshal(data, &wrapper))
			require.NotNil(t, wrapper.Condition)
			assert.Equal(t, tt.wantType, wrapper.ConditionType())
			tt.assertFunc(t, wrapper.Condition)
		})
	}
}

func TestConstraintWithMixedConditionsRoundTrip(t *testing.T) {
	// redactFields is a directive, not a condition. A constraint
	// with conditions-only (no redactFields) still round-trips normally.
	constraint := Constraint{
		Target:  "tool:mailer",
		Actions: []string{"call"},
		Conditions: []Condition{
			RecipientDomainCondition{Domains: []string{"example.com"}},
			MaxCallsCondition{Count: 5, WindowSeconds: 60},
		},
		Directives: []Directive{
			RedactFieldsDirective{Fields: []string{"ssn"}},
		},
	}

	data, err := json.Marshal(constraint)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"type":"recipientDomain"`)
	assert.Contains(t, string(data), `"type":"maxCalls"`)
	assert.Contains(t, string(data), `"type":"redactFields"`)

	var decoded Constraint
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Conditions, 2)
	assert.IsType(t, &RecipientDomainCondition{}, decoded.Conditions[0])
	assert.IsType(t, &MaxCallsCondition{}, decoded.Conditions[1])
	require.Len(t, decoded.Directives, 1)
	assert.IsType(t, &RedactFieldsDirective{}, decoded.Directives[0])
	assert.Equal(t, []string{"ssn"}, decoded.Directives[0].(*RedactFieldsDirective).Fields)
}

func TestConstraintEnforcementRoundTrip(t *testing.T) {
	// Audit mode serializes and restores; IsAuditOnly reflects it.
	audit := Constraint{Target: "tool:read_file", Actions: []string{"call"}, Enforcement: EnforcementAudit}
	data, err := json.Marshal(audit)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"enforcement":"audit"`)

	var decoded Constraint
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, EnforcementAudit, decoded.Enforcement)
	assert.True(t, decoded.IsAuditOnly())

	// Default (absent) enforcement is omitted from the wire form and is not audit.
	plain := Constraint{Target: "tool:read_file", Actions: []string{"call"}}
	pdata, err := json.Marshal(plain)
	require.NoError(t, err)
	assert.NotContains(t, string(pdata), "enforcement")

	var pdecoded Constraint
	require.NoError(t, json.Unmarshal(pdata, &pdecoded))
	assert.False(t, pdecoded.IsAuditOnly())
}

func TestConstraintRedactFieldsInConditions_MigrationHint(t *testing.T) {
	// redactFields in conditions must be rejected with a migration hint.
	raw := `{"target":"tool:mailer","actions":["call"],"conditions":[{"type":"redactFields","fields":["ssn"]}]}`
	var c Constraint
	err := json.Unmarshal([]byte(raw), &c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directives")
}

func TestObligationRoundTrip(t *testing.T) {
	tests := []Obligation{
		{Type: "redactFields", Paths: []string{"$.user.ssn", "$.secret"}},
	}

	for _, obligation := range tests {
		data, err := json.Marshal(obligation)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"type":"`+obligation.Type+`"`)

		var decoded Obligation
		require.NoError(t, json.Unmarshal(data, &decoded))
		assert.Equal(t, obligation, decoded)
	}
}

func TestEnforceRequestResponseRoundTrip(t *testing.T) {
	request := EnforceRequest{
		SessionID: "session-1",
		ToolName:  "sql.query",
		Arguments: map[string]interface{}{"statement": "select 1", "limit": 10},
		Context: EnforceRequestContext{
			SourceIP: "10.0.0.10",
			Now:      "2025-03-01T12:00:00Z",
		},
	}

	requestData, err := json.Marshal(request)
	require.NoError(t, err)

	var decodedRequest EnforceRequest
	require.NoError(t, json.Unmarshal(requestData, &decodedRequest))
	assert.Equal(t, request.SessionID, decodedRequest.SessionID)
	assert.Equal(t, request.ToolName, decodedRequest.ToolName)
	assert.Equal(t, request.Context.SourceIP, decodedRequest.Context.SourceIP)
	assert.Equal(t, request.Context.Now, decodedRequest.Context.Now)

	response := EnforceResponse{
		RequestID: "request-1",
		Decision:  DecisionDeny,
		Obligations: []Obligation{
			{Type: "redactFields", Paths: []string{"$.user.ssn"}},
		},
		Denial: &DenialInfo{
			Code:          ErrCodeConditionFailed,
			ConditionType: ConditionTypeRecipientDomain,
			Message:       "recipient domain not allowed",
			Details:       map[string]interface{}{"recipient": "alice@blocked.test"},
		},
		DecidedAt: "2025-03-01T12:00:05Z",
	}

	responseData, err := json.Marshal(response)
	require.NoError(t, err)

	var decodedResponse EnforceResponse
	require.NoError(t, json.Unmarshal(responseData, &decodedResponse))
	assert.Equal(t, response.RequestID, decodedResponse.RequestID)
	assert.Equal(t, response.Decision, decodedResponse.Decision)
	require.Len(t, decodedResponse.Obligations, 1)
	assert.Equal(t, response.Obligations, decodedResponse.Obligations)
	require.NotNil(t, decodedResponse.Denial)
	assert.Equal(t, response.Denial.Code, decodedResponse.Denial.Code)
	assert.Equal(t, response.Denial.ConditionType, decodedResponse.Denial.ConditionType)
	assert.Equal(t, response.Denial.Message, decodedResponse.Denial.Message)
	assert.Equal(t, response.Denial.Details["recipient"], decodedResponse.Denial.Details["recipient"])
}

func TestSchemaTypeJSON(t *testing.T) {
	single := SchemaType{Single: "object"}
	singleData, err := json.Marshal(single)
	require.NoError(t, err)
	assert.Equal(t, `"object"`, string(singleData))

	var decodedSingle SchemaType
	require.NoError(t, json.Unmarshal(singleData, &decodedSingle))
	assert.Equal(t, single, decodedSingle)

	multiple := SchemaType{Multiple: []string{"object", "null"}}
	multipleData, err := json.Marshal(multiple)
	require.NoError(t, err)
	assert.JSONEq(t, `["object","null"]`, string(multipleData))

	var decodedMultiple SchemaType
	require.NoError(t, json.Unmarshal(multipleData, &decodedMultiple))
	assert.Equal(t, multiple, decodedMultiple)
}

func TestUnknownConditionTypeReturnsError(t *testing.T) {
	data := []byte(`{"target":"tool:test","actions":["read"],"conditions":[{"type":"unknownKind","value":1}]}`)

	var constraint Constraint
	err := json.Unmarshal(data, &constraint)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown condition type: "unknownKind"`)
}

func TestConditionMissingTypeReturnsTargetedError(t *testing.T) {
	// A condition entry missing "type" must get the same targeted "missing required
	// 'type' field" message as the directive twin (unmarshalDirective), not the
	// generic "unknown condition type: ''" that newCondition("") would otherwise
	// produce.
	data := []byte(`{"target":"tool:test","actions":["read"],"conditions":[{"argument":"path"}]}`)

	var constraint Constraint
	err := json.Unmarshal(data, &constraint)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required 'type'")
	assert.NotContains(t, err.Error(), `unknown condition type: ""`)
}

func TestConstraintUnmarshal_TargetKey_Accepted(t *testing.T) {
	data := []byte(`{"target":"tool:read_file","actions":["call"]}`)
	var c Constraint
	require.NoError(t, json.Unmarshal(data, &c))
	assert.Equal(t, "tool:read_file", c.Target)
	assert.Equal(t, []string{"call"}, c.Actions)
}

type unsupportedCondition struct{}

func (unsupportedCondition) ConditionType() string { return "unsupported" }

func TestSchemaTypeIsZero(t *testing.T) {
	assert.True(t, SchemaType{}.IsZero())
	assert.False(t, SchemaType{Single: "string"}.IsZero())
	assert.False(t, SchemaType{Multiple: []string{"string", "null"}}.IsZero())
}

func TestMarshalConditionErrors(t *testing.T) {
	_, err := marshalCondition(unsupportedCondition{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported condition payload")

	_, err = json.Marshal(ConditionWrapper{Condition: unsupportedCondition{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported condition payload")
}

func TestConstraintUnmarshalJSONErrors(t *testing.T) {
	var constraint Constraint

	err := json.Unmarshal([]byte(`{"target":"tool:test","actions":["read"],"conditions":[{"type":"unknownKind","value":1}]}`), &constraint)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown condition type: "unknownKind"`)

	err = json.Unmarshal([]byte(`{"target":"tool:test","actions":["read"],"conditions":[{"type":123}]}`), &constraint)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot unmarshal number into Go struct field")

	// A near-miss type name offers a "did you mean" hint.
	err = json.Unmarshal([]byte(`{"target":"tool:test","actions":["call"],"conditions":[{"type":"allowedValue","argument":"path","values":["/x"]}]}`), &constraint)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown condition type: "allowedValue" (did you mean "allowedValues"?)`)
}

func TestSchemaTypeUnmarshalJSONInvalidValue(t *testing.T) {
	var schemaType SchemaType

	err := json.Unmarshal([]byte(`123`), &schemaType)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema type must be string, array of strings, or null")
}

func TestObligationRemovedAnnotateAndUnknownType(t *testing.T) {
	// The "annotate" obligation type was dead code — no directive produced it and
	// the engine never emitted it — and has been removed. It now
	// marshals and unmarshals as an unknown type, exactly like any other
	// unrecognized discriminator.
	_, err := json.Marshal(Obligation{Type: "annotate"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown obligation type: "annotate"`)

	var decoded Obligation
	err = json.Unmarshal([]byte(`{"type":"annotate","key":"classification","value":"restricted"}`), &decoded)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown obligation type: "annotate"`)

	_, err = json.Marshal(Obligation{Type: "unknown"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown obligation type: "unknown"`)

	err = json.Unmarshal([]byte(`{"type":"unknown"}`), &decoded)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown obligation type: "unknown"`)
}

func TestConstraintEmptyConditionsList(t *testing.T) {
	var decoded Constraint
	err := json.Unmarshal([]byte(`{"target":"tool:echo","actions":["call"],"conditions":[]}`), &decoded)
	require.NoError(t, err)
	require.NotNil(t, decoded.Conditions)
	assert.Empty(t, decoded.Conditions)

	data, err := json.Marshal(decoded)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"conditions":[]`)
}

func TestConditionJSONMalformedTypeField(t *testing.T) {
	var wrapper ConditionWrapper
	err := json.Unmarshal([]byte(`{"type":{"nested":true}}`), &wrapper)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot unmarshal object into Go struct field")

	data, err := json.Marshal(ConditionWrapper{})
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))
}

func TestConditionWrapper_UnmarshalJSON_Null(t *testing.T) {
	var w ConditionWrapper
	err := json.Unmarshal([]byte("null"), &w)
	require.NoError(t, err)
	assert.Nil(t, w.Condition)
}

func TestSchemaType_MarshalJSON_Null(t *testing.T) {
	data, err := json.Marshal(SchemaType{})
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))
}

func TestArgumentSchema_MarshalJSON_OmitsNullType(t *testing.T) {
	// A nested leaf schema that sets only a keyword (here, pattern) carries no
	// type. It must serialize without a "type" key — never "type":null, which the
	// struct-typed field's no-op omitempty plus SchemaType's null rendering used to
	// produce — so round-tripped/init-generated manifests stay clean.
	schema := ArgumentSchema{
		Type: SchemaType{Single: "object"},
		Properties: map[string]*ArgumentSchema{
			"path": {Pattern: "^/data/"},
		},
	}
	data, err := json.Marshal(schema)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"type":null`)
	// The top-level type, which IS set, must still be present.
	assert.Contains(t, string(data), `"type":"object"`)

	// Round-trips: the typeless leaf decodes back to a zero SchemaType.
	var decoded ArgumentSchema
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.True(t, decoded.Properties["path"].Type.IsZero())
	assert.Equal(t, "^/data/", decoded.Properties["path"].Pattern)
	assert.Equal(t, "object", decoded.Type.Single)
}

func TestSchemaType_UnmarshalJSON_InvalidType(t *testing.T) {
	var s SchemaType
	err := json.Unmarshal([]byte("123"), &s)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema type must be string, array of strings, or null")
}

func TestConstraint_MarshalJSON_NilConditions(t *testing.T) {
	c := Constraint{Target: "r", Actions: []string{"a"}}
	data, err := json.Marshal(c)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"conditions"`)
}

// TestConstraint_UnmarshalJSON_MalformedJSON verifies that Constraint.UnmarshalJSON
// propagates errors when the input JSON cannot be decoded.
func TestConstraint_UnmarshalJSON_MalformedJSON(t *testing.T) {
	t.Parallel()
	var c Constraint
	// "conditions" must be an array; a scalar string triggers a type mismatch error.
	err := json.Unmarshal([]byte(`{"target":"r","conditions":"not-an-array"}`), &c)
	require.Error(t, err, "UnmarshalJSON must return an error for malformed conditions")
}

// TestUnmarshalCondition_Errors covers the redactFields-in-conditions migration
// hint, the unknown-type branch, and a malformed-envelope error.
func TestUnmarshalCondition_Errors(t *testing.T) {
	t.Parallel()

	t.Run("redactFields rejected in conditions", func(t *testing.T) {
		t.Parallel()
		_, err := unmarshalCondition([]byte(`{"type":"redactFields","fields":["x"]}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "directives")
	})

	t.Run("unknown type", func(t *testing.T) {
		t.Parallel()
		_, err := unmarshalCondition([]byte(`{"type":"nope"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown condition type")
	})

	t.Run("malformed envelope", func(t *testing.T) {
		t.Parallel()
		_, err := unmarshalCondition([]byte(`{"type":123}`))
		require.Error(t, err)
	})

	t.Run("malformed payload after envelope", func(t *testing.T) {
		t.Parallel()
		// Valid type, but the body shape is wrong for the concrete struct.
		_, err := unmarshalCondition([]byte(`{"type":"maxCalls","count":"not-a-number"}`))
		require.Error(t, err)
	})
}

// TestValidActionsFor covers every target-type branch and the default.
func TestValidActionsFor(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"call", "*"}, validActionsFor(TargetTypeTool))
	assert.Equal(t, []string{"read", "*"}, validActionsFor(TargetTypeResource))
	assert.Equal(t, []string{"get", "*"}, validActionsFor(TargetTypePrompt))
	assert.Equal(t, []string{"allow", "*"}, validActionsFor(TargetTypeSystem))
	assert.Equal(t, []string{"*"}, validActionsFor(TargetType("bogus")))
}

// TestSchemaType_UnmarshalJSON covers string, array, null, and the error path.
func TestSchemaType_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	var single SchemaType
	require.NoError(t, json.Unmarshal([]byte(`"string"`), &single))
	assert.Equal(t, "string", single.Single)

	var multi SchemaType
	require.NoError(t, json.Unmarshal([]byte(`["string","number"]`), &multi))
	assert.Equal(t, []string{"string", "number"}, multi.Multiple)

	var null SchemaType
	require.NoError(t, json.Unmarshal([]byte(`null`), &null))
	assert.True(t, null.IsZero())

	var bad SchemaType
	err := json.Unmarshal([]byte(`{"unexpected":true}`), &bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be string")
}

// TestMarshalDirective covers value-type, pointer-type, and the unsupported
// payload default.
func TestMarshalDirective(t *testing.T) {
	t.Parallel()

	valBytes, err := marshalDirective(RedactFieldsDirective{Fields: []string{"a"}})
	require.NoError(t, err)
	assert.Contains(t, string(valBytes), "redactFields")

	ptrBytes, err := marshalDirective(&RedactFieldsDirective{Fields: []string{"b"}})
	require.NoError(t, err)
	assert.Contains(t, string(ptrBytes), "redactFields")

	_, err = marshalDirective(unsupportedDirective{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported directive payload")
}

// unsupportedDirective is a Directive the marshaler does not know how to encode.
type unsupportedDirective struct{}

func (unsupportedDirective) DirectiveType() string    { return "mystery" }
func (unsupportedDirective) ToObligation() Obligation { return Obligation{} }

// TestUnmarshalDirective_Errors covers the missing-type, unknown-type, malformed
// envelope, and malformed-payload branches.
func TestUnmarshalDirective_Errors(t *testing.T) {
	t.Parallel()

	t.Run("missing type", func(t *testing.T) {
		t.Parallel()
		_, err := unmarshalDirective([]byte(`{}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing required 'type'")
	})

	t.Run("unknown type", func(t *testing.T) {
		t.Parallel()
		_, err := unmarshalDirective([]byte(`{"type":"nope"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown directive type")
	})

	t.Run("malformed envelope", func(t *testing.T) {
		t.Parallel()
		_, err := unmarshalDirective([]byte(`{"type":123}`))
		require.Error(t, err)
	})

	t.Run("malformed payload", func(t *testing.T) {
		t.Parallel()
		_, err := unmarshalDirective([]byte(`{"type":"redactFields","fields":"not-an-array"}`))
		require.Error(t, err)
	})

	t.Run("valid round trip", func(t *testing.T) {
		t.Parallel()
		d, err := unmarshalDirective([]byte(`{"type":"redactFields","fields":["x"]}`))
		require.NoError(t, err)
		rd, ok := d.(*RedactFieldsDirective)
		require.True(t, ok)
		assert.Equal(t, []string{"x"}, rd.Fields)
	})
}

// TestObligation_JSON covers Marshal/Unmarshal for both shapes and the
// unknown-type errors.
func TestObligation_JSON(t *testing.T) {
	t.Parallel()

	t.Run("redactFields round trip", func(t *testing.T) {
		t.Parallel()
		b, err := json.Marshal(Obligation{Type: "redactFields", Paths: []string{"a", "b"}})
		require.NoError(t, err)
		var got Obligation
		require.NoError(t, json.Unmarshal(b, &got))
		assert.Equal(t, "redactFields", got.Type)
		assert.Equal(t, []string{"a", "b"}, got.Paths)
	})

	t.Run("annotate is now an unknown type", func(t *testing.T) {
		t.Parallel()
		// The annotate obligation type was removed as dead code; it now behaves
		// like any other unrecognized discriminator on both marshal and unmarshal.
		_, err := json.Marshal(Obligation{Type: "annotate"})
		require.Error(t, err)
		var got Obligation
		err = json.Unmarshal([]byte(`{"type":"annotate","key":"k","value":"v"}`), &got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown obligation type")
	})

	t.Run("marshal unknown type errors", func(t *testing.T) {
		t.Parallel()
		_, err := json.Marshal(Obligation{Type: "bogus"})
		require.Error(t, err)
	})

	t.Run("unmarshal unknown type errors", func(t *testing.T) {
		t.Parallel()
		var o Obligation
		err := json.Unmarshal([]byte(`{"type":"bogus"}`), &o)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown obligation type")
	})

	t.Run("unmarshal malformed envelope errors", func(t *testing.T) {
		t.Parallel()
		var o Obligation
		err := json.Unmarshal([]byte(`{"type":123}`), &o)
		require.Error(t, err)
	})

	t.Run("unmarshal redactFields with malformed payload errors", func(t *testing.T) {
		t.Parallel()
		var o Obligation
		// paths must be an array of strings; a string here fails the typed decode.
		err := json.Unmarshal([]byte(`{"type":"redactFields","paths":"not-an-array"}`), &o)
		require.Error(t, err)
	})
}

// ── The only supported obligation type is redactFields ────────────────────────

// TestObligation_OnlyRedactFieldsSupported pins that the obligation surface is
// limited to redactFields after the dead "annotate" type was removed.
func TestObligation_OnlyRedactFieldsSupported(t *testing.T) {
	t.Parallel()

	// redactFields round-trips.
	b, err := json.Marshal(Obligation{Type: DirectiveTypeRedactFields, Paths: []string{"ssn"}})
	require.NoError(t, err)
	var got Obligation
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, DirectiveTypeRedactFields, got.Type)
	assert.Equal(t, []string{"ssn"}, got.Paths)

	// annotate is gone — it now errors like any other unknown discriminator.
	_, err = json.Marshal(Obligation{Type: "annotate"})
	require.Error(t, err)
	err = json.Unmarshal([]byte(`{"type":"annotate","key":"k","value":"v"}`), &got)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown obligation type")
}
