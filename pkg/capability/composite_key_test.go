// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"testing"
)

// TestCompositeKeyJoin_MatchesTheFlattenedSpelling is what makes the two-group form safe to
// reach for: it must produce the SAME bytes as flattening the groups into one variadic list.
// The key addresses a live counter/flow bucket in both the in-memory and Redis backends, so a
// divergence would not fail — it would quietly account a call against a different bucket than
// the one the same policy used yesterday.
func TestCompositeKeyJoin_MatchesTheFlattenedSpelling(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		prefix     string
		head, tail []string
	}{
		{"both groups", "maxcalls", []string{"route", "sess-1"}, []string{"tool", "export"}},
		{"empty head", "seq", nil, []string{"sess-1", "tool", "export"}},
		{"empty tail", "flow", []string{"route", "task", "task-42"}, nil},
		{"both empty", "declassify", nil, nil},
		{"empty prefix", "", []string{"a"}, []string{"b"}},
		// The anti-forgery property is the point of the length prefixes: a part carrying the
		// separator or a NUL must not be able to spell another tuple's key, in either group.
		{"separators in a part", "seq", []string{"a:1:b"}, []string{"c\x00d", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			flat := append(append([]string{}, tc.head...), tc.tail...)
			want := CompositeKey(tc.prefix, flat...)
			if got := CompositeKeyJoin(tc.prefix, tc.head, tc.tail); got != want {
				t.Errorf("CompositeKeyJoin = %q, want %q — the two spellings must encode identically", got, want)
			}
		})
	}
}

// TestCompositeKeyJoin_IsInjectiveAcrossTheGroupBoundary pins the property the length prefixes
// exist for, at the seam the two-group form adds: where a part ENDS is carried by its own
// length tag, so moving the boundary between head and tail cannot produce one key from two
// different tuples.
func TestCompositeKeyJoin_IsInjectiveAcrossTheGroupBoundary(t *testing.T) {
	t.Parallel()
	// Same concatenated text, different part boundaries.
	a := CompositeKeyJoin("seq", []string{"ab"}, []string{"c"})
	b := CompositeKeyJoin("seq", []string{"a"}, []string{"bc"})
	if a == b {
		t.Fatalf("distinct tuples collide on one key: both = %q", a)
	}
	if !strings.HasPrefix(a, "seq:") {
		t.Errorf("key = %q, want the prefix emitted verbatim so the backends' namespaces stay disjoint", a)
	}
}
