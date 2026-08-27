// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactFieldsDirective_RoundTrip(t *testing.T) {
	dir := RedactFieldsDirective{Fields: []string{"$.user.ssn", "creditCard"}}

	data, err := json.Marshal(DirectiveWrapper{Directive: dir})
	require.NoError(t, err)
	assert.Contains(t, string(data), `"type":"redactFields"`)
	assert.Contains(t, string(data), `"fields"`)

	var decoded DirectiveWrapper
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, DirectiveTypeRedactFields, decoded.DirectiveType())
	rd := decoded.Directive.(*RedactFieldsDirective)
	assert.Equal(t, []string{"$.user.ssn", "creditCard"}, rd.Fields)
}

func TestRedactFieldsDirective_Pointer_RoundTrip(t *testing.T) {
	dir := &RedactFieldsDirective{Fields: []string{"secret"}}

	data, err := json.Marshal(DirectiveWrapper{Directive: dir})
	require.NoError(t, err)

	var decoded DirectiveWrapper
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, DirectiveTypeRedactFields, decoded.DirectiveType())
	assert.Equal(t, []string{"secret"}, decoded.Directive.(*RedactFieldsDirective).Fields)
}

func TestDirectiveWrapper_NullRoundTrip(t *testing.T) {
	w := DirectiveWrapper{}
	data, err := json.Marshal(w)
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))

	var decoded DirectiveWrapper
	require.NoError(t, json.Unmarshal([]byte("null"), &decoded))
	assert.Nil(t, decoded.Directive)
}

func TestDirectiveWrapper_TypedNilPointer_MarshalsToNull(t *testing.T) {
	// A typed-nil pointer (not a nil interface) carries a concrete type, so the
	// nil-interface guard in MarshalJSON is skipped; marshalDirective must still
	// emit "null" rather than dereference the nil pointer through the value-receiver
	// DirectiveType() and panic.
	w := DirectiveWrapper{Directive: (*RedactFieldsDirective)(nil)}
	data, err := json.Marshal(w)
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))
}

func TestUnknownDirectiveType_RejectsAtLoad(t *testing.T) {
	// An unknown directive type must be rejected fail-closed.
	raw := `{"type":"purgeDatabase","target":"*"}`
	var w DirectiveWrapper
	err := json.Unmarshal([]byte(raw), &w)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown directive type")
	assert.Contains(t, err.Error(), "purgeDatabase")
}

func TestDirectiveMissingType_RejectsAtLoad(t *testing.T) {
	raw := `{"fields":["ssn"]}`
	var w DirectiveWrapper
	err := json.Unmarshal([]byte(raw), &w)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}

func TestConstraint_DirectivesRoundTrip(t *testing.T) {
	// A constraint with both conditions and directives round-trips via JSON.
	c := Constraint{
		Target:  "tool:read_file",
		Actions: []string{"call"},
		Conditions: []Condition{
			AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
		},
		Directives: []Directive{
			&RedactFieldsDirective{Fields: []string{"$.user.ssn", "$.creditCard"}},
		},
	}

	data, err := json.Marshal(c)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"type":"allowedValues"`)
	assert.Contains(t, string(data), `"type":"redactFields"`)

	var decoded Constraint
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Conditions, 1)
	require.Len(t, decoded.Directives, 1)
	assert.Equal(t, DirectiveTypeRedactFields, decoded.Directives[0].DirectiveType())
	rd := decoded.Directives[0].(*RedactFieldsDirective)
	assert.Equal(t, []string{"$.user.ssn", "$.creditCard"}, rd.Fields)
}

func TestConstraint_NoDirectives_RoundTrips(t *testing.T) {
	// A constraint with no directives should round-trip without a "directives" key.
	c := Constraint{
		Target:  "tool:query_db",
		Actions: []string{"call"},
	}
	data, err := json.Marshal(c)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "directives")

	var decoded Constraint
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Nil(t, decoded.Directives)
}

func TestConstraint_UnknownDirectiveType_FailsClosed(t *testing.T) {
	// An unknown directive type in a constraint must fail at load time.
	raw := `{"target":"tool:foo","actions":["call"],"directives":[{"type":"selfDestruct"}]}`
	var c Constraint
	err := json.Unmarshal([]byte(raw), &c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown directive type")
}

func TestConstraint_MultipleDirectives_RoundTrip(t *testing.T) {
	c := Constraint{
		Target:  "tool:read_file",
		Actions: []string{"call"},
		Directives: []Directive{
			&RedactFieldsDirective{Fields: []string{"ssn"}},
			&RedactFieldsDirective{Fields: []string{"creditCard", "cvv"}},
		},
	}

	data, err := json.Marshal(c)
	require.NoError(t, err)

	var decoded Constraint
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Directives, 2)
	assert.Equal(t, []string{"ssn"}, decoded.Directives[0].(*RedactFieldsDirective).Fields)
	assert.Equal(t, []string{"creditCard", "cvv"}, decoded.Directives[1].(*RedactFieldsDirective).Fields)
}

func TestRedactFieldsDirective_EmptyFields_RoundTrip(t *testing.T) {
	dir := RedactFieldsDirective{Fields: []string{}}
	data, err := json.Marshal(DirectiveWrapper{Directive: dir})
	require.NoError(t, err)

	var decoded DirectiveWrapper
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.NotNil(t, decoded.Directive)
	assert.Equal(t, DirectiveTypeRedactFields, decoded.DirectiveType())
}

// ── strict unknown-field decode ─────────────────────────────────────────────

// unmarshalDirective rejects a field name no directive struct binds. This matters more
// than the condition case: a misspelled redactFields path key decodes to an EMPTY path
// list, and an empty list makes the forward path attach the redactFields obligation — so
// the audit tape records a redaction as applied while the response is masked nowhere.
func TestUnmarshalDirective_RejectsUnknownField(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{
			name: "redactFields fields typo yields a silently empty path list",
			json: `{"type":"redactFields","fieldss":["user.ssn"]}`,
			want: `unknown field "fieldss"`,
		},
		{
			name: "redactFields singular typo",
			json: `{"type":"redactFields","field":"user.ssn"}`,
			want: `unknown field "field"`,
		},
		{
			// "paths" is the OBLIGATION's spelling (ToObligation maps fields -> Paths),
			// not the manifest's, so it is a plausible operator mistake and must be caught
			// rather than decoded into an empty, mask-nothing directive.
			name: "redactFields written with the obligation's key",
			json: `{"type":"redactFields","paths":["user.ssn"]}`,
			want: `unknown field "paths"`,
		},
		{
			name: "labelOutput typo",
			json: `{"type":"labelOutput","labelss":["pii"]}`,
			want: `unknown field "labelss"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unmarshalDirective([]byte(tc.json))
			require.Error(t, err, "want %s rejected, not decoded to an empty directive", tc.json)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// The check must not reject what a lenient decode would have bound: the discriminator
// and any case variant of a real field name.
func TestUnmarshalDirective_AcceptsDiscriminatorAndCaseVariants(t *testing.T) {
	for _, j := range []string{
		`{"type":"redactFields","fields":["user.ssn"]}`,
		`{"type":"redactFields","FIELDS":["user.ssn"]}`,
		`{"type":"labelOutput","Labels":["pii"]}`,
	} {
		_, err := unmarshalDirective([]byte(j))
		assert.NoError(t, err, "want %s accepted (the decode would bind it)", j)
	}
}

// Every directive type this build models must survive a round-trip through the strict
// decoder, so the field-name check cannot make a valid manifest unloadable.
func TestUnmarshalDirective_StrictCheckAcceptsEveryMarshaledDirectiveType(t *testing.T) {
	for _, dt := range []string{DirectiveTypeRedactFields, DirectiveTypeLabelOutput} {
		target := newDirective(dt)
		require.NotNil(t, target, "newDirective(%q) returned nil", dt)
		data, err := marshalDirective(target)
		require.NoError(t, err, "marshalDirective(%q)", dt)
		_, err = unmarshalDirective(data)
		assert.NoError(t, err, "directive %q does not survive its own marshaling (marshaled: %s)", dt, data)
	}
}

// ── number-preserving decode ────────────────────────────────────────────────

// numericTestDirective exists only to make the directive decoder's number handling
// observable: no shipped directive carries a numeric field, so the property has to be
// pinned against a registered type rather than against the corpus.
type numericTestDirective struct {
	Threshold json.Number `json:"threshold"`
	Any       any         `json:"any"`
}

func (numericTestDirective) DirectiveType() string { return "numericForTest" }
func (numericTestDirective) ToObligation() Obligation {
	return Obligation{Type: "numericForTest"}
}

// unmarshalDirective must decode with UseNumber, the same sequence unmarshalCondition
// uses. Without it an `any`-typed policy literal above 2^53 widens to float64 and rounds
// into a neighbouring value — the exact widening the condition decoder documents guarding
// against, on its otherwise line-for-line twin.
func TestUnmarshalDirective_PreservesExactNumericLiterals(t *testing.T) {
	// Not parallel, and must not become so: it adds an entry to a package-global registry
	// that sibling parallel tests range over, and marshalDirective has no arm for the fake.
	const token = "numericForTest"
	const literal = "9007199254740993"
	directivePrototypes[token] = tokenSpec[Directive]{
		New:   func() Directive { return &numericTestDirective{} },
		Since: SchemaVersion01,
		State: StateNone,
		Uses:  usesNothing,
	}
	t.Cleanup(func() { delete(directivePrototypes, token) })

	d, err := unmarshalDirective([]byte(`{"type":"` + token + `","threshold":` + literal + `,"any":` + literal + `}`))
	require.NoError(t, err)
	typed, ok := d.(*numericTestDirective)
	require.True(t, ok, "decoded into %T", d)
	assert.Equal(t, literal, typed.Threshold.String())
	assert.Equal(t, json.Number(literal), typed.Any, "an interface-typed literal must stay json.Number, not widen to float64")
}
