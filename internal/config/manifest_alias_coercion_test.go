// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The coercion guard's alias behaviour. Its own file because manifest_test.go binds `yaml` as
// a local for its fixture strings, which cannot coexist with importing the package by that name.

package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestRejectCoercedScalars_FollowsAnAliasedMapping is the alias blind-spot regression: the
// walk descended into an AliasNode, whose Content is empty, so an aliased MAPPING's fields
// were checked only at the anchor's DEFINITION site — under whatever key sat there, which is
// not the key that decides whether they are numeric policy fields. `&a {value: 010}` defined
// under a harmless key and referenced as `effect: {blastRadius: *a}` therefore loaded coerced.
func TestRejectCoercedScalars_FollowsAnAliasedMapping(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, src string
		wantErr   bool
	}{
		{
			name:    "aliased mapping under a numeric policy key",
			src:     "defs:\n  a: &a\n    value: 010\ncapabilities:\n  - target: \"tool:x\"\n    effect:\n      blastRadius: *a\n",
			wantErr: true,
		},
		{
			name: "the same anchor where no numeric key applies stays legal",
			src:  "defs:\n  a: &a\n    value: 010\nelsewhere: *a\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var n yaml.Node
			if err := yaml.Unmarshal([]byte(tc.src), &n); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			err := rejectCoercedValueScalars(&n, false)
			if tc.wantErr && err == nil {
				t.Fatal("an aliased mapping's coerced scalar must be refused wherever it is REFERENCED")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

// TestRejectCoercedScalars_TerminatesOnASelfReferentialAlias pins the bound the visited set
// carries: following aliases means an anchor that references itself would otherwise recurse
// forever, and an alias GRAPH would expand exponentially if the set were visit-and-forget.
func TestRejectCoercedScalars_TerminatesOnASelfReferentialAlias(t *testing.T) {
	t.Parallel()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte("root: &loop\n  self: *loop\n"), &n); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- rejectCoercedValueScalars(&n, false) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the coercion walk did not terminate on a self-referential anchor")
	}
}
