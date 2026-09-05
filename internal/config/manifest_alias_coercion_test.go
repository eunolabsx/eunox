// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The coercion guard's alias behaviour. Its own file because manifest_test.go binds `yaml` as
// a local for its fixture strings, which cannot coexist with importing the package by that name.

package config

import (
	"fmt"
	"strings"
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

// TestRejectCoercedScalars_FollowsAMergeKey is the merge-key blind spot: the walk carried the
// literal key text down, so a mapping merged in with `<<:` was checked under enclosing key
// "<<", where no scoped numeric field is declared — `<<: {max: 010}` on a blastRadius
// condition loaded enforcing 8 while the inline spelling was refused. A merged mapping's
// pairs belong to the mapping that merges them, so they must be checked under ITS key.
func TestRejectCoercedScalars_FollowsAMergeKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, src string
		wantErr   bool
	}{
		{
			name:    "merged condition bound under conditions",
			src:     "capabilities:\n  - target: \"tool:x\"\n    conditions:\n      - type: blastRadius\n        <<: &s {max: 010}\n",
			wantErr: true,
		},
		{
			name:    "merged cumulative bound under conditions",
			src:     "defs:\n  a: &a {maxTotal: 0600}\ncapabilities:\n  - target: \"tool:x\"\n    conditions:\n      - type: blastRadius\n        <<: *a\n",
			wantErr: true,
		},
		{
			name:    "merged magnitude under effect.blastRadius",
			src:     "capabilities:\n  - target: \"tool:x\"\n    effect:\n      blastRadius:\n        <<: &v {value: 1.0}\n",
			wantErr: true,
		},
		{
			name:    "the list form merges several mappings and is checked the same way",
			src:     "defs:\n  a: &a {max: 1}\n  b: &b {maxTotal: 020}\ncapabilities:\n  - target: \"tool:x\"\n    conditions:\n      - type: blastRadius\n        <<: [*a, *b]\n",
			wantErr: true,
		},
		{
			name:    "merged ceiling bound under effectCeiling",
			src:     "effectCeiling:\n  <<: &c {maxBlastRadius: 010}\n",
			wantErr: true,
		},
		{
			// A quoted "<<" is a literal key in yaml.v3, so its pairs are NOT merged into
			// the condition and are not that block's numeric fields. Checking them there
			// would refuse a value the policy never carries, under a key the loader's own
			// key check is what reports.
			name: "the quoted spelling is a literal key, not a merge",
			src:  "capabilities:\n  - target: \"tool:x\"\n    conditions:\n      - type: blastRadius\n        \"<<\": {max: 010}\n",
		},
		{
			// An explicit key beats a merged one, so this enforces max=8 and the merged
			// text is inert — refused all the same, as an unscoped `count: 010` in the
			// same position already was. The guard refuses ambiguous TEXT wherever a
			// policy number can appear; it does not model merge precedence.
			name:    "a merged value an explicit key shadows is still refused",
			src:     "capabilities:\n  - target: \"tool:x\"\n    conditions:\n      - type: blastRadius\n        max: 8\n        <<: &s {max: 010}\n",
			wantErr: true,
		},
		{
			name: "a merge where no scoped numeric key applies stays legal",
			src:  "defs:\n  a: &a {max: 010}\nelsewhere:\n  <<: *a\n",
		},
		{
			name: "a merged number whose text round-trips is accepted",
			src:  "capabilities:\n  - target: \"tool:x\"\n    conditions:\n      - type: blastRadius\n        <<: &s {max: 8}\n",
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
				t.Fatal("a coerced policy number merged in with `<<` must be refused exactly as the inline spelling is")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

// TestRejectCoercedScalars_MergeChainStaysLinear is the cost bound on inheriting the enclosing
// key across a merge: the visited set is keyed on (node, key), so carrying every key down a
// merge chain re-walks a shared anchor once per key it is reachable under. A 15 KB document of
// this shape took 126 ms before the key was canonicalized to the scoped vocabulary.
func TestRejectCoercedScalars_MergeChainStaysLinear(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	const depth = 400
	fmt.Fprintf(&b, "d%d: &a%d {ok: 1}\n", depth, depth)
	for i := depth - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "d%d: &a%d {<<: *a%d}\n", i, i, i+1)
	}
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "k%d:\n  <<: *a0\n", i)
	}
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(b.String()), &n); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- rejectCoercedValueScalars(&n, false) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected refusal: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("the coercion walk took %v on a %d-byte merge chain; the visited set is not collapsing", elapsed, b.Len())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the coercion walk did not finish on a merge chain")
	}
}
