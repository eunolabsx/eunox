// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestRefuseAmbiguousJSONKeys_RefusesWhatTheDecoderWouldResolve is the property: every
// document this refuses is one encoding/json decodes CLEANLY, keeping the last of two
// members a reader sees as different keys. The assertion pairs both halves, so a fold that
// stopped agreeing with the decoder would show up as a document that decodes to the second
// value and is nonetheless accepted.
func TestRefuseAmbiguousJSONKeys_RefusesWhatTheDecoderWouldResolve(t *testing.T) {
	t.Parallel()
	type target struct {
		PublicKey string `json:"publicKey"`
	}
	for name, doc := range map[string]string{
		"exact duplicate":  `{"publicKey":"reviewed","publicKey":"substituted"}`,
		"case variant":     `{"publicKey":"reviewed","PublicKey":"substituted"}`,
		"upper case first": `{"PUBLICKEY":"reviewed","publicKey":"substituted"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var decoded target
			require.NoError(t, json.Unmarshal([]byte(doc), &decoded),
				"the premise: a decoder accepts this document without complaint")
			require.Equal(t, "substituted", decoded.PublicKey,
				"the premise: it keeps the LAST member, which is not the one read top-down")

			err := capability.RefuseAmbiguousJSONKeys([]byte(doc))
			require.Error(t, err, "a document whose decoded value is not the one a reviewer reads must be refused")
			assert.Contains(t, err.Error(), "the top-level object")
		})
	}
}

// TestRefuseAmbiguousJSONKeys_Nested walks the whole document, not just its root: the
// substitution is worth as much one level down (a key inside a "keys" array) as at the top.
func TestRefuseAmbiguousJSONKeys_Nested(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ doc, names string }{
		"inside an array element": {`{"keys":[{"kty":"OKP"},{"x":"a","X":"b"}]}`, `"keys[1]"`},
		"inside a nested object":  {`{"effect":{"class":"irreversible","Class":"reversible"}}`, `"effect"`},
		"deeper still":            {`{"a":{"b":[{"c":{"v":1,"V":2}}]}}`, `"a.b[0].c"`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := capability.RefuseAmbiguousJSONKeys([]byte(tc.doc))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.names, "the refusal must name where the ambiguity is")
		})
	}
}

// TestRefuseAmbiguousJSONKeys_AcceptsUnambiguousDocuments: sibling objects each get their
// own member set, so a name repeated across siblings (or between an object and its parent)
// is not a duplicate — over-refusing here would reject ordinary key sets and JWKS documents.
func TestRefuseAmbiguousJSONKeys_AcceptsUnambiguousDocuments(t *testing.T) {
	t.Parallel()
	for name, doc := range map[string]string{
		"repeated across siblings": `{"keys":[{"kid":"a"},{"kid":"b"}]}`,
		"repeated in a child":      `{"kid":"a","inner":{"kid":"b"}}`,
		"scalar document":          `"just a string"`,
		"empty object":             `{}`,
		"nulls and numbers":        `{"a":null,"b":1.5,"c":[1,2,3],"d":true}`,
		"unicode distinct keys":    `{"schön":1,"schon":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, capability.RefuseAmbiguousJSONKeys([]byte(doc)))
		})
	}
}

// TestRefuseAmbiguousJSONKeys_LeavesMalformedInputToTheDecoder: this is a pre-decode guard,
// so a syntax error must come back from the decode that follows — which names the offset and
// the expected type — rather than from a walk that can only say "something went wrong".
func TestRefuseAmbiguousJSONKeys_LeavesMalformedInputToTheDecoder(t *testing.T) {
	t.Parallel()
	for name, doc := range map[string]string{
		"truncated":       `{"a":`,
		"not json at all": `keys = 1`,
		"empty":           ``,
		"trailing comma":  `{"a":1,}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, capability.RefuseAmbiguousJSONKeys([]byte(doc)))
		})
	}
}

// TestRefuseAmbiguousJSONKeys_RefusesUnwalkableNesting: the walk is recursive and the Token
// API imposes no depth limit of its own, so a deeply-nested document would recurse until the
// stack overflows — an uncatchable fatal error on operator-supplied input. Exceeding the
// bound is a REFUSAL rather than a skipped scan: stopping silently would leave everything
// below the cut unchecked, which is where the ambiguity would then be planted.
func TestRefuseAmbiguousJSONKeys_RefusesUnwalkableNesting(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat(`{"a":`, 5000) + `1` + strings.Repeat(`}`, 5000)
	err := capability.RefuseAmbiguousJSONKeys([]byte(deep))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nests more than")
}
