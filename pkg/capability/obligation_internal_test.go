// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestObligation_MarshalPathsNeverNull asserts the "always [], never null"
// convention: a nil Paths and an empty-slice Paths both marshal to "paths":[],
// and a populated slice round-trips its elements.
func TestObligation_MarshalPathsNeverNull(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		obl  Obligation
		want string
	}{
		{
			name: "nil paths marshals to empty array",
			obl:  Obligation{Type: DirectiveTypeRedactFields, Paths: nil},
			want: `{"type":"redactFields","paths":[]}`,
		},
		{
			name: "empty paths marshals to empty array",
			obl:  Obligation{Type: DirectiveTypeRedactFields, Paths: []string{}},
			want: `{"type":"redactFields","paths":[]}`,
		},
		{
			name: "populated paths round-trip",
			obl:  Obligation{Type: DirectiveTypeRedactFields, Paths: []string{"user.ssn", "result.secret"}},
			want: `{"type":"redactFields","paths":["user.ssn","result.secret"]}`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(tt.obl)
			if err != nil {
				t.Fatalf("Marshal(%v) returned error: %v", tt.obl, err)
			}
			if string(b) != tt.want {
				t.Errorf("Marshal(%v) = %s, want %s", tt.obl, b, tt.want)
			}
		})
	}
}

// TestObligation_PopulatedPathsRoundTrip asserts a populated Paths survives a
// marshal/unmarshal round-trip unchanged.
func TestObligation_PopulatedPathsRoundTrip(t *testing.T) {
	t.Parallel()

	orig := Obligation{Type: DirectiveTypeRedactFields, Paths: []string{"a", "b.c"}}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	var got Obligation
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if !reflect.DeepEqual(got, orig) {
		t.Errorf("round-trip = %+v, want %+v", got, orig)
	}
}

// TestObligation_UnknownTypeFailsMarshal asserts an unknown discriminator fails
// closed on marshal.
func TestObligation_UnknownTypeFailsMarshal(t *testing.T) {
	t.Parallel()

	if _, err := json.Marshal(Obligation{Type: "bogus"}); err == nil {
		t.Error("marshaling an unknown obligation type must return an error")
	}
}
