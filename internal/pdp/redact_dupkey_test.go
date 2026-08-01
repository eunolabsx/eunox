// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The redaction path decodes upstream results with encoding/json, which resolves a
// duplicate object key LAST-WINS. A host is free to resolve it FIRST-WINS (JSON.parse and
// the Python SDK both do). Every response below therefore decodes, for this redactor, to a
// shape carrying no redactable field — so nothing changes, the ORIGINAL bytes are eligible
// to be returned verbatim, and the audit record still reports the obligation applied while
// the host renders the secret. All of them must fail closed instead.

var redactDataSSN = []capability.Obligation{
	{Type: capability.DirectiveTypeRedactFields, Paths: []string{"data.ssn"}},
}

// assertRedactionFailsClosed asserts ApplyRedactObligs refused the body outright rather
// than returning bytes: a redaction that cannot be verified must never forward.
func assertRedactionFailsClosed(t *testing.T, body []byte, obligs []capability.Obligation, secret string) {
	t.Helper()
	out, err := ApplyRedactObligs(body, obligs)
	require.Error(t, err, "an unverifiable response must fail closed, got %q", string(out))
	assert.Nil(t, out, "a fail-closed redaction must return no bytes at all")
	assert.NotContains(t, err.Error(), secret, "the error must not itself carry the secret")
}

// The headline smuggle: the second `data` wins for Go (an empty object, nothing to
// redact), the first wins for the host (the ssn).
func TestApplyRedactObligs_DuplicateEnvelopeKeySmugglesPastRedaction(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"ok"}],"data":{"ssn":"123-45-6789"},"data":{}}`)
	assertRedactionFailsClosed(t, body, redactDataSSN, "123-45-6789")
}

// The same shape one level down: a duplicate key NESTED inside the envelope. Go keeps the
// empty inner object; a first-wins host renders the ssn.
func TestApplyRedactObligs_NestedDuplicateKeySmugglesPastRedaction(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"data":{"ssn":"123-45-6789"},"data":{}}}`)
	assertRedactionFailsClosed(t, body, redactDataSSN, "123-45-6789")
}

// A duplicate key inside a JSON text content item. The envelope-level gate cannot see this
// one — inside the envelope the item's body is a single JSON string token — so the leaf
// classifier has to carry its own check.
func TestApplyRedactObligs_DuplicateKeyInsideTextItemSmugglesPastRedaction(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"{\"data\":{\"ssn\":\"123-45-6789\"},\"data\":{}}"}]}`)
	assertRedactionFailsClosed(t, body, redactDataSSN, "123-45-6789")
}

// The same, hidden under a second JSON-string encoding layer, so the recursion has to
// re-scan the container it finally unwraps rather than scanning only the outermost leaf.
func TestApplyRedactObligs_DuplicateKeyUnderDoubleEncodingSmugglesPastRedaction(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"blob":"\"{\\\"data\\\":{\\\"ssn\\\":\\\"123-45-6789\\\"},\\\"data\\\":{}}\""}}`)
	assertRedactionFailsClosed(t, body, redactDataSSN, "123-45-6789")
}

// A duplicate key inside an ARRAY-rooted doubly-encoded leaf. The scan admits array roots
// on this path (unlike a tools/list entry, which must be an object), so the objects inside
// still get walked instead of the whole leaf being waved through.
func TestApplyRedactObligs_DuplicateKeyInsideArrayLeafSmugglesPastRedaction(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":"[{\"data\":{\"ssn\":\"123-45-6789\"},\"data\":{}}]"}`)
	assertRedactionFailsClosed(t, body, redactDataSSN, "123-45-6789")
}

// A case-variant collision among the envelope's own keys: encoding/json binds object keys
// to struct fields case-insensitively and keeps the last, so any struct-shaped consumer of
// these bytes resolves them differently than the case-sensitive host. Same rule as the
// list filters, so the two surfaces cannot drift.
func TestApplyRedactObligs_CaseVariantEnvelopeKeyFailsClosed(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"ok"}],"Data":{"ssn":"123-45-6789"},"data":{}}`)
	assertRedactionFailsClosed(t, body, redactDataSSN, "123-45-6789")
}

// The fold must be Unicode simple-fold, not strings.ToLower: U+017F is already lower case,
// so ToLower leaves it distinct from its ASCII twin and the collision goes unseen.
func TestApplyRedactObligs_UnicodeFoldEnvelopeKeyFailsClosed(t *testing.T) {
	t.Parallel()
	// "ſ" is the long s, which simple-folds to 's': "ſsn" collides with "ssn".
	body := []byte("{\"ſsn\":\"123-45-6789\",\"ssn\":\"masked\"}")
	assertRedactionFailsClosed(t, body,
		[]capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"ssn"}}},
		"123-45-6789")
}

// The gate must not newly refuse honest responses. Case-distinct NESTED siblings are legal
// (a schema carrying both "Name" and "name"), so the fold is scoped to the root object's
// own keys exactly as the tools/list entry scan scopes it.
func TestApplyRedactObligs_CaseDistinctNestedSiblingsStillRedact(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"Name":"A","name":"b","data":{"ssn":"123-45-6789"}}}`)
	out, err := ApplyRedactObligs(body, redactDataSSN)
	require.NoError(t, err, "case-distinct nested siblings are legal and must not fail closed")
	s := string(out)
	assert.NotContains(t, s, "123-45-6789")
	assert.Contains(t, s, `"Name":"A"`)
	assert.Contains(t, s, `"name":"b"`)
}

// A response with nothing to redact still returns its ORIGINAL bytes verbatim: the gate
// runs before the walk, so it must not disturb the byte-for-byte passthrough guarantee.
func TestApplyRedactObligs_CleanResponseStillPassesThroughVerbatim(t *testing.T) {
	t.Parallel()
	body := []byte(`{"zeta":1,"alpha":{"beta":"<b>&amp;</b>"},"content":[{"type":"text","text":"plain prose"}]}`)
	out, err := ApplyRedactObligs(body, redactDataSSN)
	require.NoError(t, err)
	assert.Equal(t, string(body), string(out), "an untouched response must be returned byte-for-byte")
}

// The gate is scoped to responses that actually carry an obligation: with no redact paths
// there is nothing to verify, and a duplicate key is the transport's business, not this
// engine's.
func TestApplyRedactObligs_DuplicateKeyWithoutRedactPathsPassesThrough(t *testing.T) {
	t.Parallel()
	body := []byte(`{"data":{"ssn":"123-45-6789"},"data":{}}`)
	out, err := ApplyRedactObligs(body, nil)
	require.NoError(t, err)
	assert.Equal(t, string(body), string(out))
}

// A BOM-prefixed envelope is trimmed before the scan runs. Scanning the untrimmed bytes
// would report every such response ambiguous (encoding/json rejects a leading BOM) and
// fail closed on responses that redact correctly today.
func TestApplyRedactObligs_BOMPrefixedEnvelopeStillRedacts(t *testing.T) {
	t.Parallel()
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"data":{"ssn":"123-45-6789"}}`)...)
	out, err := ApplyRedactObligs(body, redactDataSSN)
	require.NoError(t, err, "a BOM-prefixed envelope must still be redactable")
	assert.NotContains(t, string(out), "123-45-6789")
}

// Prose that merely mentions duplicate-looking keys is not a container and must keep
// passing through: the leaf classifier only scans what decodes to one clean JSON value.
func TestApplyRedactObligs_ProseLeafWithBracesStillPassesThrough(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"see {\"a\":1} and {\"a\":2} above"}]}`)
	out, err := ApplyRedactObligs(body, redactDataSSN)
	require.NoError(t, err, "prose containing JSON fragments is not a container and must pass through")
	assert.Equal(t, string(body), string(out))
}

// scanJSONKeys is shared with the tools/list entry gate. Array roots are admitted only for
// the caller that has them (redaction); a tools/list entry that is an array stays
// untrustworthy, with a knowably-empty candidate-name set.
func TestScanJSONKeys_ArrayRootScopedToRedactionCaller(t *testing.T) {
	t.Parallel()
	arr := []byte(`[{"a":1,"a":2}]`)
	fold := redactionFoldKeys([]string{"a"})

	entry := scanJSONKeys(arr, jsonKeyScanOpts{})
	assert.True(t, entry.untrustworthy, "a tools/list entry may not be an array")
	assert.True(t, entry.namesComplete, "a non-object entry root poisons nothing")

	assert.True(t, redactionKeysAmbiguous(arr, fold), "a duplicate key inside an array root must be caught")
	assert.False(t, redactionKeysAmbiguous([]byte(`[{"a":1},{"a":2}]`), fold),
		"the same key in two sibling array elements is not a duplicate")
	assert.False(t, redactionKeysAmbiguous([]byte(`{"a":{"b":1},"c":{"b":2}}`), fold),
		"the same key under two different parents is not a duplicate")
	assert.True(t, redactionKeysAmbiguous([]byte(strings.Repeat(`{"a":`, maxDuplicateKeyScanDepth+2)), fold),
		"a pathologically deep value fails closed")
}

// The case-variant rule on the redaction path is SCOPED to names the redaction depends on
// resolving (redactionFoldKeys), and applies at every depth. Two properties fall out, and
// both are the point:
//
//   - One `[` cannot turn the gate off. Keying the fold to raw stack depth made the verdict
//     depend on whether the value happened to be wrapped in an array, since the bracket
//     occupies a level of its own — so `{"Name":..,"name":..}` was refused while the
//     byte-identical `[{"Name":..,"name":..}]` was not.
//   - An unrelated case-variant pair is NOT refused. The unscoped rule folded every root
//     key, which is derived from encoding/json binding a tools/list entry to a STRUCT;
//     nothing on the redaction path is struct-bound (envelope and leaves alike decode into
//     map[string]interface{}, whose keys are exact), so refusing an honest
//     {"Data":..,"data":..} under an obligation naming neither was a pure false positive.
func TestRedactionKeysAmbiguous_FoldIsScopedAndDepthUniform(t *testing.T) {
	// The obligation names `data.ssn`, so `data` and `ssn` are the names whose case
	// variants matter. `name` is named by nothing.
	scoped := redactionFoldKeys([]string{"data.ssn"})
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		// An exact duplicate is caller-independent: any depth, any key, any root shape.
		{"object root, exact duplicate", `{"n":1,"n":2}`, true},
		{"array root, exact duplicate", `[{"n":1,"n":2}]`, true},
		{"nested exact duplicate", `{"o":{"n":1,"n":2}}`, true},
		{"array root, distinct keys", `[{"a":1,"b":2}]`, false},

		// A case variant of a NAMED segment is refused wherever it appears — the array
		// wrapper and the nesting depth are both irrelevant.
		{"object root, named case variant", `{"Data":"a","data":"b"}`, true},
		{"array root, named case variant", `[{"Data":"a","data":"b"}]`, true},
		{"nested named case variant", `{"o":{"SSN":"a","ssn":"b"}}`, true},

		// A case variant of a name the obligation does not touch is honest data.
		{"object root, unnamed case variant", `{"Name":"a","name":"b"}`, false},
		{"array root, unnamed case variant", `[{"Name":"a","name":"b"}]`, false},
		{"nested unnamed case variant", `{"o":{"Name":"a","name":"b"}}`, false},

		// The protocol-reserved envelope keys are always in scope: ApplyRedactObligs
		// dispatches on them exactly, so a variant spelling would silently take the
		// weaker generic walk instead of the content-array one.
		{"reserved key case variant", `{"Content":[],"content":[]}`, true},
	} {
		if got := redactionKeysAmbiguous([]byte(tc.raw), scoped); got != tc.want {
			t.Errorf("%s: redactionKeysAmbiguous(%s) = %v, want %v", tc.name, tc.raw, got, tc.want)
		}
	}
}

// The reserved-key scope is not cosmetic. ApplyRedactObligs reads result["content"]
// EXACTLY, so the content-array pass — with its fail-closed guard on a resource item whose
// embedded body this redactor cannot walk — runs over the canonical spelling only, while a
// case variant falls to the lenient generic sibling walk. A consumer that binds the result
// case-insensitively resolves the variant as its content and renders the payload the strict
// pass never saw.
func TestApplyRedactObligs_CaseVariantOfReservedEnvelopeKeyFailsClosed(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[],"Content":[{"type":"resource","resource":{"text":"123-45-6789"}}]}`)
	assertRedactionFailsClosed(t, body, redactDataSSN, "123-45-6789")
}

// One level below the envelope, ApplyRedactObligs reads a content ITEM's keys exactly too:
// obj["type"] picks the per-type treatment and obj["text"] is the body it walks. A case
// variant therefore routes the redactor to one value while a case-insensitive consumer binds
// the other — and because nothing matched, the ORIGINAL bytes are forwarded with the record
// reporting the obligation applied.
func TestApplyRedactObligs_CaseVariantOfContentItemKeyFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		body string
	}{
		{"text body variant", `{"content":[{"type":"text","text":"benign","Text":"123-45-6789"}]}`},
		{"type selector variant", `{"content":[{"type":"image","Type":"text","text":"123-45-6789"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertRedactionFailsClosed(t, []byte(tc.body),
				[]capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"ssn"}}},
				"123-45-6789")
		})
	}
}

// The item keys are in the fold SCOPE, not exempt from path matching: an obligation that
// names "text" must still mask a field called text, the way it would any other name.
func TestApplyRedactObligs_ContentItemKeyIsStillRedactableByName(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"payload":{"text":"123-45-6789"}}}`)
	out, err := ApplyRedactObligs(body,
		[]capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"payload.text"}}})
	require.NoError(t, err, "naming an item key as a redact path is legitimate")
	assert.NotContains(t, string(out), "123-45-6789")
}

// The companion honest case: an unmodelled sibling key whose case variant the obligation
// never names must keep redacting rather than fail the whole response closed.
func TestApplyRedactObligs_UnnamedCaseVariantSiblingsStillRedact(t *testing.T) {
	t.Parallel()
	body := []byte(`{"Report":"A","report":"b","data":{"ssn":"123-45-6789"}}`)
	out, err := ApplyRedactObligs(body, redactDataSSN)
	require.NoError(t, err, "case variants of names the obligation does not touch are honest data")
	s := string(out)
	assert.NotContains(t, s, "123-45-6789")
	assert.Contains(t, s, `"Report":"A"`)
	assert.Contains(t, s, `"report":"b"`)
}

// End-to-end: the array wrapper must not let a case-variant sibling carry the obligated
// field past the redactor.
func TestApplyRedactObligs_ArrayLeafCaseVariantFailsClosed(t *testing.T) {
	obl := []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"data.ssn"}}}
	arrLeaf := `{"content":[{"type":"text","text":"[{\"data\":{\"ssn\":\"SECRET\"},\"Data\":{\"ssn\":\"SECRET\"}}]"}]}`
	out, err := ApplyRedactObligs([]byte(arrLeaf), obl)
	if err == nil {
		t.Fatalf("an array-rooted leaf with a case-variant sibling must fail closed; got %s", out)
	}
	if bytes.Contains(out, []byte("SECRET")) {
		t.Errorf("the obligated field must not be forwarded; got %s", out)
	}
}
