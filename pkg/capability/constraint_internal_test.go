// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"testing"
)

// TestConstraintJSONRoundTripPrincipal guards against the regression
// where constraintJSON omitted the Principal field so a principal-scoped
// constraint silently lost its identity restriction on any json.Marshal ->
// json.Unmarshal round-trip and then matched every caller.
func TestConstraintJSONRoundTripPrincipal(t *testing.T) {
	orig := Constraint{
		Target:    "tool:read_secrets",
		Actions:   []string{"call"},
		Principal: map[string][]string{"sub": {"alice"}, "iss": {"https://idp.example"}},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Constraint
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Principal) != len(orig.Principal) {
		t.Fatalf("Principal lost on round-trip: got %v, want %v", got.Principal, orig.Principal)
	}
	for k, want := range orig.Principal {
		gotVals, ok := got.Principal[k]
		if !ok || len(gotVals) != len(want) {
			t.Fatalf("Principal[%q] = %v, want %v", k, gotVals, want)
		}
		for i := range want {
			if gotVals[i] != want[i] {
				t.Fatalf("Principal[%q][%d] = %q, want %q", k, i, gotVals[i], want[i])
			}
		}
	}

	// The restriction must still be enforced after the round-trip: an unlisted
	// principal must not match, while a listed one must. PrincipalMatches requires
	// every listed claim key to match, so supply both sub and iss.
	if got.PrincipalMatches(map[string]interface{}{"sub": "mallory", "iss": "https://idp.example"}) {
		t.Error("PrincipalMatches allowed an unlisted sub after round-trip (constraint widened to all callers)")
	}
	if !got.PrincipalMatches(map[string]interface{}{"sub": "alice", "iss": "https://idp.example"}) {
		t.Error("PrincipalMatches denied the listed principal after round-trip")
	}
}

// TestConstraintUnmarshalClearsStale guards against the case where
// Constraint.UnmarshalJSON only assigned Conditions and Directives when the
// decoded slices were non-nil. Unmarshalling an explicit null (or an object that
// omits the keys) into a reused Constraint therefore left the previous policy
// objects in place, so a policy reload kept enforcing conditions and applying
// redaction directives that had been removed.
func TestConstraintUnmarshalClearsStale(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"explicit null", `{"target":"tool:x","actions":["call"],"conditions":null,"directives":null}`},
		{"omitted keys", `{"target":"tool:x","actions":["call"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Seed a constraint that already carries a condition and a directive,
			// mirroring a reused destination value during a policy reload.
			c := Constraint{
				Target:     "tool:x",
				Actions:    []string{"call"},
				Conditions: []Condition{AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp"}}},
				Directives: []Directive{RedactFieldsDirective{Fields: []string{"secret"}}},
			}

			if err := json.Unmarshal([]byte(tc.input), &c); err != nil {
				t.Fatalf("reload unmarshal: %v", err)
			}
			if c.Conditions != nil {
				t.Errorf("Conditions not cleared on reload: %+v", c.Conditions)
			}
			if c.Directives != nil {
				t.Errorf("Directives not cleared on reload: %+v", c.Directives)
			}
		})
	}
}

// ── ParseTarget ───────────────────────────────────────────────────────

func TestParseTarget_ValidPrefixes(t *testing.T) {
	cases := []struct {
		input    string
		wantType TargetType
		wantBare string
	}{
		{"tool:read_file", TargetTypeTool, "read_file"},
		{"tool:read_*", TargetTypeTool, "read_*"},
		{"tool:*", TargetTypeTool, "*"},
		{"resource:file:///data/reports/*", TargetTypeResource, "file:///data/reports/*"},
		{"resource:db://warehouse/orders", TargetTypeResource, "db://warehouse/orders"},
		{"resource:*", TargetTypeResource, "*"},
		{"prompt:code_review", TargetTypePrompt, "code_review"},
		{"prompt:*", TargetTypePrompt, "*"},
		{"prompt:code_*", TargetTypePrompt, "code_*"},
		{"system:sampling/createMessage", TargetTypeSystem, "sampling/createMessage"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, bare, err := ParseTarget(tc.input)
			if err != nil {
				t.Fatalf("ParseTarget(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.wantType {
				t.Errorf("type = %q, want %q", got, tc.wantType)
			}
			if bare != tc.wantBare {
				t.Errorf("bare = %q, want %q", bare, tc.wantBare)
			}
		})
	}
}

func TestParseTarget_MissingPrefix(t *testing.T) {
	cases := []string{
		"read_file",
		"sampling/createMessage",
		"prompts/code_review",
		"file:///data/reports",
		"",
		"*",
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			_, _, err := ParseTarget(s)
			if err == nil {
				t.Errorf("ParseTarget(%q) = nil, want error for missing prefix", s)
			}
		})
	}
}

func TestParseTarget_UnrecognizedPrefix(t *testing.T) {
	cases := []string{
		"tools:read_file",
		"resources:file:///data",
		"prompts:code_review",
		"unknown:foo",
		"x:bar",
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			_, _, err := ParseTarget(s)
			if err == nil {
				t.Errorf("ParseTarget(%q) = nil, want error for unrecognized prefix", s)
			}
		})
	}
}

func TestParseTarget_EmptyBare(t *testing.T) {
	cases := []string{
		"tool:",
		"resource:",
		"prompt:",
		"system:",
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			_, _, err := ParseTarget(s)
			if err == nil {
				t.Errorf("ParseTarget(%q) = nil, want error for empty bare name", s)
			}
		})
	}
}

// ── ValidateActionForTargetType ───────────────────────────────────────────────

func TestValidateActionForTargetType_ValidPairs(t *testing.T) {
	cases := []struct {
		targetType TargetType
		action     string
	}{
		{TargetTypeTool, "call"},
		{TargetTypeTool, "*"},
		{TargetTypeResource, "read"},
		{TargetTypeResource, "*"},
		{TargetTypePrompt, "get"},
		{TargetTypePrompt, "*"},
		{TargetTypeSystem, "allow"},
		{TargetTypeSystem, "*"},
	}
	for _, tc := range cases {
		t.Run(string(tc.targetType)+":"+tc.action, func(t *testing.T) {
			if err := ValidateActionForTargetType(tc.targetType, tc.action); err != nil {
				t.Errorf("ValidateActionForTargetType(%q, %q) = %v, want nil", tc.targetType, tc.action, err)
			}
		})
	}
}

func TestValidateActionForTargetType_InvalidPairs(t *testing.T) {
	cases := []struct {
		targetType TargetType
		action     string
	}{
		// tool: only allows call and *
		{TargetTypeTool, "read"},
		{TargetTypeTool, "get"},
		{TargetTypeTool, "allow"},
		// resource: only allows read and *
		{TargetTypeResource, "call"},
		{TargetTypeResource, "get"},
		{TargetTypeResource, "allow"},
		// prompt: only allows get and *
		{TargetTypePrompt, "call"},
		{TargetTypePrompt, "read"},
		{TargetTypePrompt, "allow"},
		// system: only allows allow and *
		{TargetTypeSystem, "call"},
		{TargetTypeSystem, "read"},
		{TargetTypeSystem, "get"},
	}
	for _, tc := range cases {
		t.Run(string(tc.targetType)+":"+tc.action, func(t *testing.T) {
			if err := ValidateActionForTargetType(tc.targetType, tc.action); err == nil {
				t.Errorf("ValidateActionForTargetType(%q, %q) = nil, want error for invalid pairing", tc.targetType, tc.action)
			}
		})
	}
}
