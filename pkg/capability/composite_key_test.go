// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"testing"
)

// TestCompositeKey_EncodesTheseExactBytes is the GOLDEN half, and the one that matters: the
// key addresses a live counter/flow bucket in both the in-memory and Redis backends, so a
// change to the encoding does not fail — it quietly accounts a call against a different bucket
// than the one the same policy used yesterday, resetting every budget and orphaning every
// sequenceBlock antecedent in a running deployment.
//
// Literal expected strings, deliberately. The equivalence table below cannot stand in for this:
// CompositeKey delegates to CompositeKeyJoin, so both sides of that comparison move together.
func TestCompositeKey_EncodesTheseExactBytes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		got    string
		want   string
		reason string
	}{
		{
			name:   "a counter key",
			got:    CompositeKey("maxcalls", "route", "sess-1", "tool", "export"),
			want:   "maxcalls:5:route:6:sess-1:4:tool:6:export",
			reason: "prefix verbatim, then each part as :<byte length>:<bytes>",
		},
		{
			name: "the same key through the two-group form",
			got:  CompositeKeyJoin("maxcalls", []string{"route", "sess-1"}, []string{"tool", "export"}),
			want: "maxcalls:5:route:6:sess-1:4:tool:6:export",
		},
		{
			name:   "an empty part still carries its tag",
			got:    CompositeKey("seq", "", "x"),
			want:   "seq:0::1:x",
			reason: "dropping the tag for an empty part would make (\"\",\"x\") and (\"x\") one key",
		},
		{
			name:   "a part carrying the separator",
			got:    CompositeKey("flow", "a:1:b"),
			want:   "flow:5:a:1:b",
			reason: "the length prefix is what makes a caller-supplied \":\" unable to forge another tuple",
		},
		{
			name: "a NUL-bearing part",
			got:  CompositeKey("seq", "a\x00b"),
			want: "seq:3:a\x00b",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Errorf("key = %q, want %q — %s\n  Changing this encoding re-keys every deployed counter and flow bucket; if that is genuinely intended it needs a migration, not a test update.", tc.got, tc.want, tc.reason)
			}
		})
	}
}

// TestCompositeKeyJoin_MatchesTheFlattenedSpelling is what makes the two-group form safe to
// reach for: it must produce the SAME bytes as flattening the groups into one variadic list.
// It is a RELATIVE check — both sides share one encoder — so it says the grouping is invisible,
// not what the bytes are; the golden table above says that.
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
