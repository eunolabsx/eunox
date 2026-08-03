// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"encoding/json"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sibling-key pass exists because a result envelope may legally carry keys beyond the
// two MCP models, and a named field sitting in one of them was forwarded unredacted while
// the audit record reported the obligation applied. That rationale applies verbatim one
// level down: a content ITEM may legally carry `annotations`, `_meta`, or a vendor
// extension, and nothing walked them either. These pin the item level.

const redactSSNValue = "123-45-6789"

// assertRedactedSSN asserts the body came back masked at every declared position: no
// occurrence of the secret survives, and the sentinel is present.
func assertRedactedSSN(t *testing.T, body []byte, obligs []capability.Obligation) []byte {
	t.Helper()
	out, err := ApplyRedactObligs(body, obligs)
	require.NoError(t, err)
	assert.NotContains(t, string(out), redactSSNValue, "the declared field must not survive in the forwarded bytes")
	assert.Contains(t, string(out), redactedSentinel, "a masked field keeps its key and carries the sentinel")
	return out
}

// A field under an unmodelled key of a TEXT content item. Before the item-level walk this
// was forwarded verbatim, while the identical object one level out (an envelope sibling)
// was masked.
func TestApplyRedactObligs_ContentItemSiblingKeyIsRedacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"benign","extra":{"data":{"ssn":"` + redactSSNValue + `"}}}]}`)
	assertRedactedSSN(t, body, redactDataSSN)
}

// _meta is legal on a content item per the MCP schema, so an upstream needs no vendor
// extension at all to reach this shape.
func TestApplyRedactObligs_ContentItemMetaKeyIsRedacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"benign","_meta":{"data":{"ssn":"` + redactSSNValue + `"}}}]}`)
	assertRedactedSSN(t, body, redactDataSSN)
}

// An image item carries no addressable JSON body of its own, which is why it passes
// through — but a sibling key on it is as addressable as any other, so the walk must
// still run before the pass-through.
func TestApplyRedactObligs_ImageItemSiblingKeyIsRedacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"image","data":"e30=","mimeType":"image/png","note":{"data":{"ssn":"` + redactSSNValue + `"}}}]}`)
	out := assertRedactedSSN(t, body, redactDataSSN)
	// The item's own binary payload is untouched: `data` here is base64 text, not a JSON
	// container, so the walk leaves it exactly as the upstream sent it.
	assert.Contains(t, string(out), `"e30="`)
}

// The envelope-sibling spelling, which already worked. Kept beside the three above so the
// four shapes of the same field are pinned as ONE outcome rather than three plus a note.
func TestApplyRedactObligs_EnvelopeSiblingKeyStillRedacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"benign"}],"extra":{"data":{"ssn":"` + redactSSNValue + `"}}}`)
	assertRedactedSSN(t, body, redactDataSSN)
}

// A doubly-encoded blob at a key named `data` ON THE ITEM: the item-relative anchoring is
// what makes "data.ssn" reach it, exactly as the envelope-relative one does a level out.
func TestApplyRedactObligs_ContentItemDoublyEncodedSiblingIsRedacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"benign","data":"{\"ssn\":\"` + redactSSNValue + `\"}"}]}`)
	assertRedactedSSN(t, body, redactDataSSN)
}

// A field sitting DIRECTLY on the item, tested against its own name — the item-level twin
// of the envelope-root pass. The value walk only ever sees a key's VALUE, so without this
// the bare spelling of the same obligation forwarded the secret.
func TestApplyRedactObligs_ContentItemDirectFieldIsRedacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"benign","ssn":"` + redactSSNValue + `"}]}`)
	assertRedactedSSN(t, body, []capability.Obligation{
		{Type: capability.DirectiveTypeRedactFields, Paths: []string{"ssn"}},
	})
}

// The item's text body is redacted EXACTLY ONCE: the sibling walk skips `text`, so the
// body keeps the treatment its own pass gives it and is not re-processed (which would
// re-encode an already-redacted container, or mask the whole body under a bare "text"
// path).
func TestApplyRedactObligs_ContentItemTextBodyRedactedExactlyOnce(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"{\"data\":{\"ssn\":\"` + redactSSNValue + `\"},\"keep\":\"kept\"}"}]}`)
	out := assertRedactedSSN(t, body, redactDataSSN)

	var env struct {
		Content []map[string]json.RawMessage `json:"content"`
	}
	require.NoError(t, json.Unmarshal(out, &env))
	require.Len(t, env.Content, 1)
	var text string
	require.NoError(t, json.Unmarshal(env.Content[0]["text"], &text), "the body stays a JSON string, decoded once")

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &decoded), "the body is still a single-encoded JSON object, not re-wrapped")
	data, ok := decoded["data"].(map[string]interface{})
	require.True(t, ok, "the container the path descends is preserved, not masked wholesale")
	assert.Equal(t, redactedSentinel, data["ssn"])
	assert.Equal(t, "kept", decoded["keep"], "content no path matched is preserved")
}

// A bare path naming a key the item dispatch reads is exempt at the item root: masking
// `text` wholesale would discard the body its own pass redacts with rigor, and masking
// `type` would leave an item a spec-conformant host cannot classify. The nested field of
// the same name is still masked by the body's own pass, so the exemption costs nothing.
func TestApplyRedactObligs_ContentItemDispatchKeysExemptAtItemRoot(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"{\"text\":\"secret-body\"}"}]}`)
	out, err := ApplyRedactObligs(body, []capability.Obligation{
		{Type: capability.DirectiveTypeRedactFields, Paths: []string{"text"}},
	})
	require.NoError(t, err)
	assert.NotContains(t, string(out), "secret-body", "a field named text INSIDE the body is still masked")

	var env struct {
		Content []map[string]json.RawMessage `json:"content"`
	}
	require.NoError(t, json.Unmarshal(out, &env))
	require.Len(t, env.Content, 1)
	var typ string
	require.NoError(t, json.Unmarshal(env.Content[0]["type"], &typ))
	assert.Equal(t, "text", typ, "the item's type is never masked")
	var text string
	require.NoError(t, json.Unmarshal(env.Content[0]["text"], &text), "the body is still a string, not the sentinel")
	assert.Contains(t, text, redactedSentinel)
}

// An image/audio item carrying no addressable sibling still passes through byte-for-byte:
// nothing matched, so the ORIGINAL envelope is returned rather than a re-marshaled one.
func TestApplyRedactObligs_BinaryItemWithNoSiblingPassesThroughVerbatim(t *testing.T) {
	t.Parallel()
	for _, typ := range []string{"image", "audio"} {
		body := []byte(`{"content":[{"type":"` + typ + `","data":"e30=","mimeType":"application/octet-stream"}]}`)
		out, err := ApplyRedactObligs(body, redactDataSSN)
		require.NoError(t, err)
		assert.Equal(t, string(body), string(out), "%s: an item with nothing to mask is preserved byte-for-byte", typ)
	}
}

// The fail-closed arm stays AHEAD of the sibling walk: a resource item is refused outright,
// whatever else it carries, so the walk can never be what decides a response the redactor
// cannot inspect.
func TestApplyRedactObligs_ResourceItemStillFailsClosedBeforeTheSiblingWalk(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"resource","resource":{"uri":"file:///x","text":"whatever"},"note":{"data":{"ssn":"` + redactSSNValue + `"}}}]}`)
	assertRedactionFailsClosed(t, body, redactDataSSN, redactSSNValue)
}

// A duplicate key inside a doubly-encoded blob at an item's sibling key is untrustworthy
// for the reason it is anywhere else: this redactor's decode keeps the last, a first-wins
// host renders the first. The item-level walk reaches it through the same shared leaf
// classifier, so the gate applies there too rather than only on the paths that had one.
func TestApplyRedactObligs_ContentItemSiblingDuplicateKeyFailsClosed(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"benign","extra":"{\"data\":{\"ssn\":\"` + redactSSNValue + `\"},\"data\":{}}"}]}`)
	assertRedactionFailsClosed(t, body, redactDataSSN, redactSSNValue)
}

// The gap the item walk itself could reopen, one type dispatch away: an image/audio item has
// NO body pass, so if the walk skipped `text` unconditionally that key would be inspected by
// no pass at all — the exact shape #204 closed for every other key.
func TestApplyRedactObligs_TextOnABinaryItemIsStillWalked(t *testing.T) {
	t.Parallel()
	for _, typ := range []string{"image", "audio"} {
		body := []byte(`{"content":[{"type":"` + typ + `","data":"e30=","mimeType":"image/png","text":"{\"data\":{\"ssn\":\"` + redactSSNValue + `\"}}"}]}`)
		out, err := ApplyRedactObligs(body, redactDataSSN)
		require.NoError(t, err, typ)
		assert.NotContains(t, string(out), redactSSNValue,
			"%s: a `text` key on an item whose dispatch runs no body pass must still be walked", typ)
	}
}

// A single-segment path naming one of a content item's protocol-structural keys must not
// replace it with the string sentinel: that is a hard protocol failure (a struct-binding host
// cannot decode the result at all) in place of the field-level masking the operator asked for
// — the same trade the envelope root makes for its reserved keys.
func TestApplyRedactObligs_ContentItemProtocolKeysAreNotMaskedWholesale(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"_meta", "annotations", "data", "mimeType"} {
		body := []byte(`{"content":[{"type":"image","data":"e30=","mimeType":"image/png","_meta":{"a":1},"annotations":{"b":2}}]}`)
		out, err := ApplyRedactObligs(body, []capability.Obligation{
			{Type: capability.DirectiveTypeRedactFields, Paths: []string{key}},
		})
		require.NoError(t, err, key)
		assert.NotContains(t, string(out), `"`+key+`":"`+redactedSentinel+`"`,
			"%s carries protocol structure on a content item; masking it wholesale hands the host an item it cannot decode", key)
	}

	// The exemption costs the obligation nothing: a declared field INSIDE one of them is
	// still masked, which is the whole point of walking the item's keys.
	body := []byte(`{"content":[{"type":"text","text":"ok","_meta":{"data":{"ssn":"` + redactSSNValue + `"}}}]}`)
	assertRedactedSSN(t, body, redactDataSSN)
}
