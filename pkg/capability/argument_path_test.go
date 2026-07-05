// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"reflect"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

func TestIsArgumentPath(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"$.a.b", true},
		{"$.a", true},
		{"$.", true}, // prefix present (segments still reports it malformed)
		{"a.b", false},
		{"path", false},
		{"", false},
		{"$a", false},   // missing dot after $
		{"$$.x", false}, // escaped literal, not a traversal path
	}
	for _, tc := range tests {
		if got := capability.IsArgumentPath(tc.ref); got != tc.want {
			t.Errorf("IsArgumentPath(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestIsEscapedArgumentLiteral(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"$$.x", true},
		{"$$.a.b", true},
		{"$$$.x", true},  // deeper escape: also a valid trigger (2+ leading '$' then '.')
		{"$$$$.x", true}, // and deeper still
		{"$.x", false},   // exactly one leading '$': the traversal sentinel, not an escape
		{"$$", false},    // two dollars but no trailing '.': not an escape
		{"$$$", false},   // three dollars but no trailing '.': not an escape
		{"x", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := capability.IsEscapedArgumentLiteral(tc.ref); got != tc.want {
			t.Errorf("IsEscapedArgumentLiteral(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestArgumentLiteralKey(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		{"$$.x", "$.x"},
		{"$$.a.b", "$.a.b"},
		{"$$$.x", "$$.x"},   // deeper escape unwraps to the once-escaped literal key
		{"$$$$.x", "$$$.x"}, // and one more level
		{"a.b", "a.b"},      // unescaped literal: unchanged
		{"owner", "owner"},
	}
	for _, tc := range tests {
		if got := capability.ArgumentLiteralKey(tc.ref); got != tc.want {
			t.Errorf("ArgumentLiteralKey(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

// TestArgumentEscape_NoCollisionAtAnyDepth is the regression for the residual
// collision a fixed single-level "$$." escape would have: a tool argument
// literally named "$$.x" (itself starting with the shortest escape prefix) must
// still be reachable, distinctly from the escaped form of "$.x" — and this must
// hold at every deeper level ("$$$.x", "$$$$.x", ...), not just the first.
func TestArgumentEscape_NoCollisionAtAnyDepth(t *testing.T) {
	tests := []struct {
		ref      string
		wantPath bool   // IsArgumentPath
		wantKey  string // the literal key an unescaped/escaped ref resolves to
	}{
		{"$.x", true, ""},        // pure traversal: args["x"], not a literal-key case
		{"$$.x", false, "$.x"},   // references the literal key "$.x"
		{"$$$.x", false, "$$.x"}, // references the literal key "$$.x" -- NOT "$.x" again
		{"$$$$.x", false, "$$$.x"},
	}
	for _, tc := range tests {
		if got := capability.IsArgumentPath(tc.ref); got != tc.wantPath {
			t.Errorf("IsArgumentPath(%q) = %v, want %v", tc.ref, got, tc.wantPath)
		}
		if tc.wantPath {
			continue
		}
		if got := capability.ArgumentLiteralKey(tc.ref); got != tc.wantKey {
			t.Errorf("ArgumentLiteralKey(%q) = %q, want %q", tc.ref, got, tc.wantKey)
		}
	}
	// Every escaped ref in the table above unescapes to a DISTINCT literal key —
	// no two refs collide on the same resolved key.
	seen := make(map[string]string)
	for _, tc := range tests {
		if tc.wantPath {
			continue
		}
		if prior, ok := seen[tc.wantKey]; ok {
			t.Fatalf("both %q and %q resolve to the same literal key %q", prior, tc.ref, tc.wantKey)
		}
		seen[tc.wantKey] = tc.ref
	}
}

func TestArgumentPathSegments(t *testing.T) {
	tests := []struct {
		ref  string
		want []string
	}{
		{"$.a.b.c", []string{"a", "b", "c"}},
		{"$.owner", []string{"owner"}},
		{"path", nil},   // not a path
		{"$.", nil},     // empty body → malformed
		{"$.a..b", nil}, // empty segment → malformed
		{"$.a.", nil},   // trailing dot → malformed
		{"$..a", nil},   // leading empty segment → malformed
	}
	for _, tc := range tests {
		got := capability.ArgumentPathSegments(tc.ref)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ArgumentPathSegments(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestArgumentRootKey(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		{"$.a.b.c", "a"},
		{"$.owner", "owner"},
		{"owner", "owner"},
		{"a.b", "a.b"},  // literal dotted key: the whole thing is the key
		{"$.", "$."},    // malformed path falls back to the literal reference
		{"$$.x", "$.x"}, // escaped literal: unescapes to the real key
	}
	for _, tc := range tests {
		if got := capability.ArgumentRootKey(tc.ref); got != tc.want {
			t.Errorf("ArgumentRootKey(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}
