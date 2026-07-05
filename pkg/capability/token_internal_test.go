// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfirmation_RoundTripPreservesUnmodeledMember pins that a cnf object carrying a
// method Confirmation does not model (e.g. an RFC 8705 x5t#S256 mTLS binding) survives a
// marshal/unmarshal round-trip — the deep copy the token cache performs — so
// IsSenderConstrained still reports true afterward. Re-emitting the full decoded cnf object
// (the authoritative members map), rather than only the typed fields, is what makes the
// round-trip faithful.
func TestConfirmation_RoundTripPreservesUnmodeledMember(t *testing.T) {
	t.Parallel()
	var conf Confirmation
	require.NoError(t, json.Unmarshal([]byte(`{"x5t#S256":"def456"}`), &conf))
	require.True(t, conf.IsSenderConstrained(), "an unmodeled cnf member must count as sender-constrained")

	b, err := json.Marshal(&conf)
	require.NoError(t, err)
	assert.JSONEq(t, `{"x5t#S256":"def456"}`, string(b), "an unmodeled member must survive re-marshal")

	var back Confirmation
	require.NoError(t, json.Unmarshal(b, &back))
	assert.True(t, back.IsSenderConstrained(), "IsSenderConstrained must stay true across the round-trip")
	assert.Equal(t, conf, back, "the Confirmation must round-trip faithfully")
}

// TestConfirmation_ModeledAndExtraMarshal pins that modeled methods and unmodeled members
// co-exist in one flat cnf object on re-marshal (round-tripped verbatim from the decoded
// members map).
func TestConfirmation_ModeledAndExtraMarshal(t *testing.T) {
	t.Parallel()
	var conf Confirmation
	require.NoError(t, json.Unmarshal([]byte(`{"jkt":"abc","x5t#S256":"def"}`), &conf))
	assert.Equal(t, "abc", conf.JKT)
	require.Contains(t, conf.members, "x5t#S256")

	b, err := json.Marshal(&conf)
	require.NoError(t, err)
	assert.JSONEq(t, `{"jkt":"abc","x5t#S256":"def"}`, string(b))
}

// TestConfirmation_RoundTripPreservesSenderConstrained pins Confirmation's
// decode-then-re-encode round-trip fidelity: every cnf shape that is sender-constrained
// on first decode stays sender-constrained after a round-trip, and an empty cnf stays
// unconstrained. The empty-valued and null modeled members ({"jkt":""}, {"jkt":null})
// are the cases a typed-fields-only model dropped — re-marshaling to {} and downgrading
// a sender-constrained token to a bearer token.
func TestConfirmation_RoundTripPreservesSenderConstrained(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cnf         string
		constrained bool
	}{
		{`{"jkt":"abc"}`, true},
		{`{"kid":"ref"}`, true},
		{`{"jwk":{"kty":"EC"}}`, true},
		{`{"x5t#S256":"def"}`, true},
		{`{"jkt":"abc","x5t#S256":"def"}`, true},
		{`{"jkt":""}`, true},   // empty-valued modeled member — a member is a member
		{`{"jkt":null}`, true}, // null-valued modeled member
		{`{"kid":""}`, true},   // symmetric for kid
		{`{}`, false},          // empty cnf carries no binding
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.cnf, func(t *testing.T) {
			t.Parallel()
			var first Confirmation
			require.NoError(t, json.Unmarshal([]byte(tc.cnf), &first))
			require.Equal(t, tc.constrained, first.IsSenderConstrained(), "first decode")

			b, err := json.Marshal(&first)
			require.NoError(t, err)
			var second Confirmation
			require.NoError(t, json.Unmarshal(b, &second))
			assert.Equal(t, tc.constrained, second.IsSenderConstrained(),
				"sender-constrained status must survive the round-trip (marshaled: %s)", b)
		})
	}
}

// TestCnfIsSenderConstrained pins the shared predicate the IdP path reuses so the two token
// paths cannot drift: nil is not constraining, a non-object is malformed (fail closed at
// the caller), an empty object carries no binding, and any member (modeled or unmodeled)
// is constraining.
func TestCnfIsSenderConstrained(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		v               interface{}
		wantConstrained bool
		wantMalformed   bool
	}{
		{"nil is not constraining", nil, false, false},
		{"non-object number is malformed", 5.0, false, true},
		{"non-object string is malformed", "foo", false, true},
		{"empty object is not constraining", map[string]interface{}{}, false, false},
		{"modeled jkt is constraining", map[string]interface{}{"jkt": "abc"}, true, false},
		{"unmodeled member is constraining", map[string]interface{}{"x5t#S256": "def"}, true, false},
		// A malformed binding with an empty-valued or null modeled member must still fail
		// closed (any member present ⇒ sender-constrained), not decode to an all-empty
		// Confirmation and be accepted as a plain bearer token.
		{"empty-valued modeled member is constraining", map[string]interface{}{"jkt": ""}, true, false},
		{"null modeled member is constraining", map[string]interface{}{"jkt": nil}, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotC, gotM := CnfIsSenderConstrained(tc.v)
			assert.Equal(t, tc.wantConstrained, gotC, "constrained")
			assert.Equal(t, tc.wantMalformed, gotM, "malformed")
		})
	}
}
