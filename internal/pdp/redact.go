// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// redactFields directive: mask JSON paths in tool-call result text. Applied
// post-allow only, so nothing here participates in the allow/deny decision — it
// shapes a response the PDP has already permitted.
//
// Split out of pdp.go (the PolicyDecisionPoint contract and ManifestPDP): this engine
// shares no state with either, taking only the upstream result bytes plus the
// obligations already collected and returning bytes.

package pdp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ApplyRedactObligs applies redactFields obligations to a tools/call result, returning
// redacted bytes or an error. It MUST NOT return unredacted bytes when redact paths are
// non-empty and the response cannot be structurally verified (fail closed; see the
// capability-manifest guide § 5a).
//
// The result decodes into a generic map so unmodeled fields survive the round-trip.
// Redaction covers (1) each content item's text body plus its other keys, (2)
// structuredContent, and (3) every other top-level envelope key. Content that isn't a
// clean JSON container (prose, malformed JSON, a scalar) passes through unchanged —
// redactFields only redacts cleanly-parseable JSON, never fails closed over string
// content it can't parse. It DOES fail closed on a structural/resource guard: an
// unparseable envelope, duplicate or case-colliding object keys (see
// redactionKeysAmbiguous / refuseReservedRootKeyVariants), an unverifiable content
// shape, the depth bound, or a resource/resource_link item (whose embedded body this
// redactor cannot inspect, so an upstream could otherwise hide a field there).
func ApplyRedactObligs(resultBytes []byte, obligs []capability.Obligation) ([]byte, error) {
	if len(obligs) == 0 {
		return resultBytes, nil
	}

	var paths []string
	for _, ob := range obligs {
		if ob.Type == capability.DirectiveTypeRedactFields {
			paths = append(paths, ob.Paths...)
		}
	}
	if len(paths) == 0 {
		return resultBytes, nil
	}
	// Normalize the optional "$."/"$" JSONPath root marker ONCE here (paths is a fresh
	// slice). Every downstream consumer takes the normalized slice and does NOT
	// re-strip — stripping twice is not idempotent for an original "$.$…" spelling
	// (a field literally named "$"), which would leak.
	for i := range paths {
		paths[i] = normalizeDotPathRoot(paths[i])
	}
	// Resolve the fold scope once and thread it with paths through the whole walk,
	// rather than re-deriving it per leaf.
	spec := redactSpec{paths: paths, fold: redactionFoldKeys(paths)}

	// Preserve the original bytes so an untouched response returns verbatim rather
	// than re-marshaled — encoding/json sorts map keys, which would reorder the
	// envelope even when nothing was redacted.
	original := resultBytes

	// Strip leading UTF-8 BOM(s) and JSON whitespace: encoding/json rejects a BOM, so
	// a BOM-prefixed envelope would otherwise fail the whole response closed.
	resultBytes = trimLeadingSpaceAndBOM(resultBytes)

	// UseNumber so non-redacted integers above 2^53 round-trip byte-exact.
	var result map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(resultBytes))
	dec.UseNumber()
	if err := dec.Decode(&result); err != nil {
		return nil, fmt.Errorf("redactFields: failed to parse upstream response: %w", err)
	}
	// A JSON null envelope decodes into a nil map with no error — not a structurally
	// valid tools/call result, so fail closed like every other non-object envelope.
	if result == nil {
		return nil, fmt.Errorf("redactFields: response envelope is JSON null, not an object; cannot verify redaction (fail closed)")
	}
	// Decode stops after the first value; trailing tokens mean a malformed/ambiguous
	// container, refused rather than silently dropped on re-marshal.
	if dec.More() {
		return nil, fmt.Errorf("redactFields: trailing data after response envelope; cannot verify redaction (fail closed)")
	}
	if err := refuseUntrustworthyEnvelopeKeys(resultBytes, result, spec.fold); err != nil {
		return nil, err
	}

	// (1) Redact within each content item. Any structurally unverifiable shape could
	// hide the named field, so it fails the whole response closed rather than forward
	// unredacted.
	changed := false
	if raw, present := result["content"]; present {
		content, ok := raw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("redactFields: response 'content' is present but is not an array (%T); cannot verify redaction (fail closed)", raw)
		}
		for _, item := range content {
			obj, ok := item.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("redactFields: response 'content' item is not an object (%T); cannot verify redaction (fail closed)", item)
			}
			c, err := redactContentItem(obj, spec)
			if err != nil {
				return nil, err // fail closed
			}
			if c {
				changed = true
			}
		}
	}

	// (2) Redact within structuredContent (MCP 2025-06+ structured result), in place.
	scChanged, scErr := redactStructuredContentField(result, spec)
	if scErr != nil {
		return nil, scErr // fail closed
	}
	if scChanged {
		changed = true
	}

	// (3) Redact within every OTHER top-level result key. `content` and
	// `structuredContent` are the two shapes MCP defines, but a legal result may carry
	// more, and this function's contract is that unmodeled fields "survive the
	// round-trip" — which meant a named field under any other key was forwarded
	// unredacted. Masking (rather than failing closed on an unmodeled key) is the
	// right trade: `_meta`/annotations/vendor extensions are ordinary and legitimate.
	sibChanged, sibErr := redactSiblingTopLevelKeys(result, spec)
	if sibErr != nil {
		return nil, sibErr // fail closed
	}
	if sibChanged {
		changed = true
	}

	// No path matched anything: return the original bytes verbatim (key order, scalar
	// formatting, BOM all intact) rather than re-marshal, which would reorder keys.
	if !changed {
		return original, nil
	}

	// Re-serialize WITHOUT HTML escaping: the default escaping of <, >, & would rewrite
	// passthrough content (URLs, HTML/XML, code) even in fields no redaction touched.
	out, err := marshalNoHTMLEscape(result)
	if err != nil {
		return nil, fmt.Errorf("redactFields: failed to re-marshal redacted response: %w", err)
	}
	return out, nil
}

// redactContentItem redacts ONE `content` item in place and reports whether anything
// was masked — the per-item body of pass (1), split out so ApplyRedactObligs stays a
// loop over the array.
//
// The type dispatch decides what happens to the item's body (text walked, image/audio
// have none, resource/resource_link fail closed), and every item that survives then has
// its remaining keys walked by redactContentItemSiblings — the fail-closed arm stays
// ahead of the walk.
func redactContentItem(obj map[string]interface{}, spec redactSpec) (bool, error) {
	t, ok := obj["type"].(string)
	if !ok || t == "" {
		return false, fmt.Errorf("redactFields: response 'content' item has no string 'type'; cannot verify redaction (fail closed)")
	}
	if t != "text" {
		switch t {
		case "resource", "resource_link":
			// Nests a `resource` object that can carry a `text`/`blob` body this
			// redactor does NOT walk. Silently forwarding it would let an upstream
			// evade a declared obligation by embedding the field there, so fail
			// the whole response closed. See docs/capability-manifest-guide.md.
			return false, fmt.Errorf("redactFields: response 'content' item type %q carries an embedded resource body this redactor cannot inspect; cannot verify redaction (fail closed)", t)
		default:
			if !isRecognizedContentType(t) {
				return false, fmt.Errorf("redactFields: response 'content' item has unrecognized type %q; cannot verify redaction (fail closed)", t)
			}
			// Recognized binary media (image/audio) has no addressable JSON body of
			// its own, but may carry keys that do — so it falls through to the key
			// walk rather than being passed through whole.
			//
			// bodyHandled is FALSE here deliberately: this item's `text` (nothing
			// forbids one) got no body pass, so the walk must treat it as an
			// ordinary key — otherwise it would be inspected by no pass at all.
			return redactContentItemKeys(obj, spec, t, false)
		}
	}
	raw, present := obj["text"]
	if !present {
		// Reported apart from the type mismatch below: %T renders an ABSENT member as
		// <nil>, so the operator debugging a broken upstream was told a body exists
		// with the wrong type when the item carries none at all. Same deny either way.
		return false, fmt.Errorf("redactFields: text content item has no 'text' body; cannot verify redaction (fail closed)")
	}
	text, ok := raw.(string)
	if !ok {
		return false, fmt.Errorf("redactFields: text content item has a non-string 'text' body (%T); cannot verify redaction (fail closed)", raw)
	}
	redacted, err := redactJSONText(text, spec)
	if err != nil {
		return false, err // fail closed
	}
	changed := redacted != text
	obj["text"] = redacted
	// The item's other keys, AFTER its body: this pass already handled `text`.
	sibChanged, sibErr := redactContentItemKeys(obj, spec, t, true)
	if sibErr != nil {
		return false, sibErr // fail closed
	}
	return changed || sibChanged, nil
}

// redactContentItemKeys applies the redaction paths to a `content` item's keys.
// bodyHandled reports whether the caller already ran `text` through its own pass — when
// it did, `text` is skipped here so the body is processed exactly once; when it did not
// (image/audio, no body pass), `text` is walked like any other key, since a key no pass
// inspects is the whole defect this walk exists to close. `type` is always skipped.
//
// content/structuredContent are the shapes MCP defines, but a content ITEM may legally
// carry more (`annotations`, `_meta`, vendor extensions) that no other pass walks —
// without this, {"content":[{"type":"text","text":"benign","extra":{"ssn":"…"}}]}
// defeated the obligation while the identical field one level out was masked.
//
// Both anchorings of redactSiblingValue apply here for the same reasons stated there.
// Paths also apply to the item map ITSELF first (see redactSiblingTopLevelKeys), since
// the value walk below only ever sees a key's VALUE and would miss
// {"type":"text","text":"benign","ssn":"123-45-6789"}. A single-segment path naming one
// of the item's PROTOCOL-structural keys is exempt from that pass alone (see
// contentItemRootExempt); every other key is ordinary data.
func redactContentItemKeys(obj map[string]interface{}, spec redactSpec, itemType string, bodyHandled bool) (bool, error) {
	changed := false
	reserved := contentItemReservedKeys(itemType)
	for _, p := range spec.paths {
		if contentItemRootExempt(p, reserved) {
			continue
		}
		if redactDotPathRec(obj, p) {
			changed = true
		}
	}
	for key, val := range obj {
		if key == "type" || (key == "text" && bodyHandled) {
			continue
		}
		out, c, err := redactSiblingValue(key, val, spec)
		if err != nil {
			return false, err // fail closed
		}
		if c {
			// Containers are mutated in place, so this write only matters for a string leaf
			// (replaced by value); assigning to an already-present key during the range is safe.
			obj[key] = out
			changed = true
		}
	}
	return changed, nil
}

// contentItemRootExempt reports whether a redact path must not be applied at a content
// item's root — envelopeRootExempt one level down, same reason: masking one of the
// item's PROTOCOL-structural keys wholesale (annotations, _meta, resource are objects)
// hands a host a content item it cannot decode. Costs nothing: the value walk still
// descends every one of these, so a field hidden INSIDE `_meta` is still masked.
//
// A DOTTED path through one is not exempt — it names a leaf, and masking it is what the
// operator asked for.
func contentItemRootExempt(path string, reserved map[string]struct{}) bool {
	if strings.Contains(path, ".") {
		return false
	}
	_, isReserved := reserved[path]
	return isReserved
}

// redactionKeysAmbiguous reports whether raw — a result envelope, or a JSON container
// unwrapped from a string leaf — carries an object key this redactor cannot trust to
// match what a host renders.
//
//   - An EXACT duplicate key, at any depth, is always untrustworthy: Go keeps the last
//     and a first-wins host parser renders the first — the bypass this gate exists for:
//     {"data":{"ssn":…},"data":{}} decodes empty, so nothing matches and the ORIGINAL
//     bytes (carrying the ssn) return verbatim while the record reports it redacted.
//   - A CASE-VARIANT collision is untrustworthy only for a name this redaction actually
//     depends on resolving (see spec.fold / redactionFoldKeys) — unlike the */list entry
//     gate, which folds every root key because entries bind to a struct.
//
// Runs the SAME scan as the */list entry gate (scanJSONKeys), with array roots admitted
// since structuredContent and unwrapped leaves may legally be arrays.
func redactionKeysAmbiguous(raw []byte, fold map[string]struct{}) bool {
	return scanJSONKeys(raw, jsonKeyScanOpts{allowArrayRoot: true, foldKeys: fold}).untrustworthy
}

// redactSpec is one redactFields obligation set, resolved once per response.
type redactSpec struct {
	// paths are the dot-paths to mask, with the optional "$."/"$" JSONPath root marker
	// already stripped exactly once (see normalizeDotPathRoot). Downstream consumers
	// take them as-is and never re-strip.
	paths []string
	// fold is the scoped case-variant set redactionKeysAmbiguous applies; see
	// redactionFoldKeys.
	fold map[string]struct{}
}

// redactionFoldKeys returns the folded key names a case variant of which would change
// what this redaction resolves — the scope of redactionKeysAmbiguous's case-variant
// rule. Two sources, both about resolution rather than case as such:
//
//   - Every SEGMENT of every redact path: the masking walk looks segments up exactly
//     (obj[key]), so ["ssn"] with a response carrying both "ssn" and "SSN" leaves a
//     sibling a case-insensitive host would render unmasked.
//   - Every key ApplyRedactObligs itself dispatches on exactly (mcpReservedRootKeys,
//     mcpContentItemKeys): an exact-match dispatch IS a resolution, so
//     {"content":[],"Content":[{"type":"resource",…}]} passes the strict pass over an
//     empty array and the lenient one over the payload, while a case-insensitive host
//     binds the payload as content.
//
// Segments are collected from the whole path (not just the head), since a leaf scan
// sees the blob's own root where "data.ssn" is looked up as "ssn".
func redactionFoldKeys(paths []string) map[string]struct{} {
	fold := make(map[string]struct{}, len(paths)+len(mcpReservedRootKeys)+len(mcpContentItemKeys))
	for k := range mcpReservedRootKeys {
		fold[capability.FoldJSONKey(k)] = struct{}{}
	}
	for k := range mcpContentItemKeys {
		fold[capability.FoldJSONKey(k)] = struct{}{}
	}
	for _, p := range paths {
		for _, seg := range strings.Split(p, ".") {
			fold[capability.FoldJSONKey(seg)] = struct{}{}
		}
	}
	return fold
}

// recognizedContentTypes is the set of MCP content-item types this build models.
// Redaction applies only to "text" items (and structuredContent); image/audio carry no
// addressable JSON body and pass through unchanged. An unrecognized type fails closed.
//
// resource/resource_link are recognized (so the unrecognized-type guard doesn't fire)
// but, unlike image/audio, do NOT pass through when a redactFields obligation is
// active: ApplyRedactObligs fails the response closed over them instead, since their
// nested text/blob body cannot be walked.
var recognizedContentTypes = map[string]struct{}{
	"text":          {},
	"image":         {},
	"audio":         {},
	"resource":      {},
	"resource_link": {},
}

// isRecognizedContentType reports whether t is an MCP content-item type this
// build models (see recognizedContentTypes).
func isRecognizedContentType(t string) bool {
	_, ok := recognizedContentTypes[t]
	return ok
}

// utf8BOM is the UTF-8 byte-order mark (U+FEFF), kept as raw bytes to keep the source
// ASCII-clean. encoding/json rejects a leading BOM and TrimSpace ignores it, so
// redaction strips it explicitly — otherwise a BOM-prefixed container evades redaction.
var utf8BOM = string([]byte{0xEF, 0xBB, 0xBF})

// trimLeadingSpaceAndBOM returns s with its entire leading run of UTF-8 BOMs and JSON
// whitespace removed. Generic over string/[]byte so the two redaction paths share one
// implementation without heap-copying a string leaf just to trim it; the result is a
// reslice of s (no copy).
//
// The whole run must go, not just an offset-0 BOM — a BOM behind a tab or doubled would
// otherwise survive and misclassify a real JSON container as prose.
func trimLeadingSpaceAndBOM[T ~string | ~[]byte](s T) T {
	i := 0
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
			i++
		}
		// string(s[i:i+3]) is free for a string operand and a bounded 3-byte copy for
		// a []byte operand — never the whole leaf.
		if i+len(utf8BOM) <= len(s) && string(s[i:i+len(utf8BOM)]) == utf8BOM {
			i += len(utf8BOM)
			continue
		}
		return s[i:]
	}
}

// marshalNoHTMLEscape marshals v as JSON without escaping <, >, & (and
// U+2028/U+2029), which the redaction path must not do or it would mutate
// passthrough content. The encoder's trailing newline is trimmed.
func marshalNoHTMLEscape(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// redactJSONText redacts the given dot-paths from a single text content item whose body
// may be JSON — a thin wrapper over redactContainerString: a string parsing cleanly as a
// JSON object/array is redacted and re-serialized (recursively, including doubly-encoded
// nested containers); anything else passes through unchanged.
func redactJSONText(text string, spec redactSpec) (string, error) {
	out, _, err := redactContainerString(text, spec, "", 0)
	return out, err
}

// redactContainerString redacts a string that is a (possibly multiply doubly-encoded)
// JSON container — the shared core of the text-content path, the structuredContent
// string path, and the nested string-leaf walk, so the classify/redact/recurse/
// re-serialize policy lives once. A clean JSON object/array is unwrapped, redacted (keys
// AND nested JSON-container string values, up to maxRedactionDepth), and re-serialized.
// A string decoding to ANOTHER JSON string recurses into it, so a container hidden under
// multiple string-encoding layers is still reached. Anything else — prose, a scalar,
// malformed or embedded JSON — passes through byte-for-byte; redactFields never fails
// closed over content it cannot parse (see docs/threat-model-mcp.md). prefix rebases
// dot-paths to the string's position; depth bounds the recursion across both the
// container-key walk AND the string-layer unwrap, so total forced encoding depth is capped.
func redactContainerString(s string, spec redactSpec, prefix string, depth int) (redacted string, changed bool, err error) {
	if depth > maxRedactionDepth {
		return "", false, fmt.Errorf("redactFields: nested JSON content exceeds the redaction depth limit %d; cannot verify redaction (fail closed)", maxRedactionDepth)
	}
	decoded, kind := classifyRedactableLeaf(s, spec.fold)
	switch kind {
	case leafKindString:
		// A further string-encoding layer: recurse into the decoded inner string.
		inner, innerChanged, ierr := redactContainerString(decoded.(string), spec, prefix, depth+1)
		if ierr != nil {
			return "", false, ierr
		}
		if !innerChanged {
			return s, false, nil // nothing matched at any layer: preserve the original bytes
		}
		return finalizeRedactedLeaf(inner)
	case leafKindAmbiguous:
		// The envelope-level gate cannot see this: inside the envelope the leaf is a
		// single string token, and its duplicate keys only become keys once decoded
		// here. Without this check the identical smuggle works one layer down.
		return "", false, fmt.Errorf("redactFields: nested JSON content carries a duplicate or case-variant object key, so its decode may differ from what a host renders; cannot verify redaction (fail closed)")
	case leafKindContainer:
		changed, err = redactStructuredContentValue(decoded, spec, prefix, depth)
		if err != nil {
			return "", false, err // depth-limit guard or an internal re-marshal error
		}
		if !changed {
			return s, false, nil // nothing matched at any depth: preserve the original bytes
		}
		return finalizeRedactedLeaf(decoded)
	default:
		// Prose, a scalar, malformed, or embedded JSON: return byte-for-byte.
		return s, false, nil
	}
}

// finalizeRedactedLeaf re-marshals a redacted leaf value back to JSON text, sharing the
// marshal-and-wrap-error tail both redactContainerString branches would otherwise
// duplicate. Always reports changed=true: both callers already know something changed
// before calling this.
func finalizeRedactedLeaf(v interface{}) (redacted string, changed bool, err error) {
	out, merr := marshalNoHTMLEscape(v)
	if merr != nil {
		return "", false, fmt.Errorf("redactFields: failed to re-marshal redacted JSON content: %w", merr)
	}
	return string(out), true, nil
}

// maxRedactionDepth (256) is the operative bound on the redactable depth of ANY
// structuredContent/text value, plain or doubly-encoded — a resource guard capping
// worst-case re-marshal/prefix-build cost against an adversarial input, not a content
// check. encoding/json's own ~10000-level decode cap is a far higher, separate bound
// that a response nested past it never reaches (it fails to decode first).
const maxRedactionDepth = 256

// leafRedactionKind classifies what a one-layer JSON decode of a redaction leaf yielded.
type leafRedactionKind int

const (
	// leafKindOther is prose, a genuine scalar, malformed JSON, or JSON embedded in
	// prose: not redactable, passed through unchanged.
	leafKindOther leafRedactionKind = iota
	// leafKindContainer is a JSON object or array: the shape redactFields acts on directly.
	leafKindContainer
	// leafKindString is a JSON string scalar: a further string-encoding layer that must
	// be recursed into, not treated as terminal.
	leafKindString
	// leafKindAmbiguous is a container whose keys duplicate or case-collide on a name
	// this redaction resolves by matching (redactionFoldKeys) — the caller fails the
	// whole response closed, since the field could be hidden behind the ambiguity.
	leafKindAmbiguous
)

// classifyRedactableLeaf decodes ONE JSON layer of the string s and reports what it
// found: leafKindContainer (redactable), leafKindString (a further encoding layer the
// caller must decode again), leafKindAmbiguous (duplicate/case-colliding keys, fail
// closed), or leafKindOther (pass through unchanged). redactFields never fails closed
// over content it cannot parse — only valid JSON is redacted.
//
// Fast-path guard: a string with no '{', no leading '"', and no leading '[' cannot name
// an object key or wrap one, so the decoder is skipped entirely. The leading-'"'/'['
// arms exist only for a nested encoding layer or array wrapper: a doubly-encoded value
// can spell its inner braces as unicode escapes, so the once-decoded string starts with
// '"' and contains no literal '{' — bailing on '{' alone would skip that layer and let
// the object it wraps pass through unredacted (see redactNestedJSONStrings). Do not
// "harmonize" the three checks to all use HasPrefix without re-deriving this.
func classifyRedactableLeaf(s string, fold map[string]struct{}) (decoded interface{}, kind leafRedactionKind) {
	trimmed := trimLeadingSpaceAndBOM(s)
	looksLikeJSON := strings.ContainsRune(trimmed, '{') || strings.HasPrefix(trimmed, `"`) || strings.HasPrefix(trimmed, `[`)
	if !looksLikeJSON {
		return nil, leafKindOther
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var val interface{}
	// Decode stops after the first value; a decode error OR trailing tokens means s is not
	// a single clean JSON value (malformed, or JSON embedded in prose) — pass through.
	if dec.Decode(&val) != nil || dec.More() {
		return nil, leafKindOther
	}
	switch v := val.(type) {
	case map[string]interface{}, []interface{}:
		// The decode above collapsed any duplicate key last-wins; scan the leaf's own
		// bytes for that (or a root-level case-variant collision) before acting on the
		// decoded value — the only point where a string becomes a container.
		if redactionKeysAmbiguous([]byte(trimmed), fold) {
			return nil, leafKindAmbiguous
		}
		return val, leafKindContainer
	case string:
		// A further string-encoding layer; the recursion re-enters here with the
		// decoded inner string.
		return v, leafKindString
	default:
		return nil, leafKindOther // a genuine JSON scalar (number/bool/null): no object key
	}
}

// redactJSONValue applies every dot-path redaction to a decoded JSON value, handling a
// top-level object or array of objects, and reports whether it masked a field. A value
// matching no path (including any scalar) reports false, so the caller leaves the
// ORIGINAL bytes untouched — re-marshaling would reorder keys and could change scalar
// byte representation (1e308 -> 1e+308) even where nothing was redacted.
func redactJSONValue(val interface{}, paths []string) bool {
	switch v := val.(type) {
	case map[string]interface{}:
		changed := false
		for _, p := range paths {
			// paths arrive already root-normalized; redact via the raw worker so
			// the marker is NOT stripped a second time (not idempotent for a path
			// that still begins with "$." after the first strip).
			if redactDotPathRec(v, p) {
				changed = true
			}
		}
		return changed
	case []interface{}:
		// Recurse into every element so objects at any nesting depth are redacted.
		changed := false
		for _, item := range v {
			if redactJSONValue(item, paths) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

// mcpContentItemKeys are the keys ApplyRedactObligs reads EXACTLY off a `content` item:
// obj["type"] selects the per-type treatment, and obj["text"] is the body it then walks.
//
// In the case-variant fold scope for the same reason the reserved ROOT keys are — an
// exact-match dispatch is a resolution, so a case variant routes the redactor to one
// value while a case-insensitive consumer binds the other. Unlike the root keys they
// are NOT exempted from path matching (envelopeRootExempt): a redact path may
// legitimately name a nested field called "text", and masking it is intended.
var mcpContentItemKeys = map[string]struct{}{
	"type": {},
	"text": {},
}

// textItemReservedKeys and binaryItemReservedKeys are a content item's PROTOCOL-
// structural keys, per type. (resource/resource_link need no set — refused before any walk.)
//
// Exempt from WHOLESALE masking at the item root, exactly as mcpReservedRootKeys is at
// the envelope root: the sentinel is a string, and replacing a protocol object
// (annotations, _meta) or typed field with one yields an item a struct-binding SDK
// cannot decode. Not a redaction gap — the value walk still descends every one of
// these, so a field hidden inside `_meta` is still masked.
//
// Split by type rather than unioned, because the union costs real coverage: `data` is
// the binary payload on an image item and an ordinary field name anywhere else, so
// exempting it everywhere would forward a declared `data` on a text item.
//
// Deliberately NOT in the case-variant fold scope, unlike the two dispatch keys: a
// variant here routes a key TOWARD the item-root mask, never away from a stricter
// pass — over-redaction, the safe direction.
var (
	textItemReservedKeys = map[string]struct{}{
		"type": {}, "text": {}, "annotations": {}, "_meta": {},
	}
	binaryItemReservedKeys = map[string]struct{}{
		"type": {}, "data": {}, "mimeType": {}, "annotations": {}, "_meta": {},
	}
)

// contentItemReservedKeys returns the protocol-structural keys of a content item of type t.
// An unrecognized type never reaches here (the dispatch fails the response closed), so the
// text set is the conservative default rather than a case that runs.
func contentItemReservedKeys(t string) map[string]struct{} {
	switch t {
	case "image", "audio":
		return binaryItemReservedKeys
	default:
		return textItemReservedKeys
	}
}

// mcpReservedRootKeys are the MCP result-envelope keys that carry protocol STRUCTURE
// rather than tool data. The envelope-root redaction pass masks a named key wholesale
// with the string sentinel, which is right for an unmodeled sibling but wrong for
// these: `isError` is a bool and `contents`/`messages` are arrays, so replacing one
// with "[redacted]" yields a result a spec-conformant host cannot decode at all.
// content/structuredContent additionally get their own shape-specific passes.
var mcpReservedRootKeys = map[string]struct{}{
	"content":           {},
	"structuredContent": {},
	"isError":           {},
	"contents":          {},
	"messages":          {},
	"_meta":             {},
}

// mcpReservedRootKeysFolded maps each reserved envelope key's FOLDED spelling to its
// canonical one, so a top-level key can be tested against the whole set with a single
// lookup instead of a fold-per-reserved-key scan for every key of every response.
var mcpReservedRootKeysFolded = foldedReservedRootKeys()

func foldedReservedRootKeys() map[string]string {
	m := make(map[string]string, len(mcpReservedRootKeys))
	for k := range mcpReservedRootKeys {
		m[capability.FoldJSONKey(k)] = k
	}
	return m
}

// refuseUntrustworthyEnvelopeKeys runs both of the envelope's key-trust gates — one
// question asked two ways, can this redactor's reading of these keys be trusted to
// match the host's:
//
//   - redactionKeysAmbiguous fires on a COLLISION: the decode above resolved any
//     duplicate key last-wins, while a host may resolve first-wins, so the ORIGINAL
//     bytes could be forwarded unredacted while the record reports the obligation applied.
//   - refuseReservedRootKeyVariants covers the LONE variant, which collides with
//     nothing and so trips no collision rule at all.
func refuseUntrustworthyEnvelopeKeys(raw []byte, result map[string]interface{}, fold map[string]struct{}) error {
	if redactionKeysAmbiguous(raw, fold) {
		return fmt.Errorf("redactFields: response envelope carries a duplicate or case-variant object key, so its decode may differ from what a host renders; cannot verify redaction (fail closed)")
	}
	return refuseReservedRootKeyVariants(result)
}

// refuseReservedRootKeyVariants fails the response closed when a top-level key folds to
// a reserved envelope key but isn't spelled canonically — {"Content":[...]} — with no
// canonical sibling.
//
// redactionKeysAmbiguous can't catch this: its rule fires on a COLLISION, and a lone
// variant collides with nothing. It then misses ApplyRedactObligs' exact-match dispatch
// and falls to the strictly weaker redactSiblingTopLevelKeys — no resource-body guard,
// no shape checks. A case-insensitive host (the Go MCP SDK's struct binding, .NET's
// PropertyNameCaseInsensitive) then binds the variant as the real content while the
// canonical spelling of the same bytes correctly fails closed.
//
// Refusing is the only safe direction and costs an honest upstream nothing — a variant
// of a protocol-reserved key is not a shape a spec-conformant server emits.
//
// Offenders are sorted before one is named so two identical responses fail identically.
func refuseReservedRootKeyVariants(result map[string]interface{}) error {
	var variants []string
	for k := range result {
		canon, reserved := mcpReservedRootKeysFolded[capability.FoldJSONKey(k)]
		if !reserved || k == canon {
			continue
		}
		variants = append(variants, k)
	}
	if len(variants) == 0 {
		return nil
	}
	sort.Strings(variants)
	k := variants[0]
	canon := mcpReservedRootKeysFolded[capability.FoldJSONKey(k)]
	return fmt.Errorf("redactFields: response top-level key %q is a case variant of the reserved key %q, which a case-insensitive host may bind as the real one; cannot verify redaction (fail closed)", k, canon)
}

// envelopeRootExempt reports whether a redact path must not be applied at the envelope
// root. Only a SINGLE-SEGMENT path naming a reserved component is exempt — that
// spelling would mask the whole component.
//
// A dotted path is NOT exempt, and this is load-bearing: the manifest guide recommends
// the fully-qualified dotted spelling for a nested field, e.g. `structuredContent.ssn`.
// Exempting by HEAD instead would make the recommended spelling redact nothing while
// the audit record still reported the obligation applied.
func envelopeRootExempt(path string) bool {
	if strings.Contains(path, ".") {
		return false
	}
	_, reserved := mcpReservedRootKeys[path]
	return reserved
}

// redactSiblingTopLevelKeys applies the redaction paths to every top-level result key
// OTHER than content and structuredContent, which ApplyRedactObligs handles with their
// own shape-specific rigor.
//
// Split out to keep ApplyRedactObligs within the cognitive-complexity budget — it is
// the third of the three passes described there, and skipping it forwards a field the
// manifest declared redactable simply because the upstream put it under an unmodeled key.
func redactSiblingTopLevelKeys(result map[string]interface{}, spec redactSpec) (bool, error) {
	changed := false
	// Match paths against the ENVELOPE itself before descending into values: the
	// descent below only ever sees a sibling key's VALUE, so a field sitting DIRECTLY
	// on a top-level key ({"content":[...],"ssn":"…"}) was never tested against its
	// own name, while the nested spelling {"data":{"ssn":"…"}} redacted correctly.
	for _, p := range spec.paths {
		if envelopeRootExempt(p) {
			continue
		}
		if redactDotPathRec(result, p) {
			changed = true
		}
	}
	for key, val := range result {
		if key == "content" || key == "structuredContent" {
			continue
		}
		out, c, err := redactSiblingValue(key, val, spec)
		if err != nil {
			return false, err // fail closed
		}
		if c {
			// Containers are mutated in place, so this write only matters for a string
			// leaf (which is replaced by value); assigning to an already-present key
			// during the range is safe.
			result[key] = out
			changed = true
		}
	}
	return changed, nil
}

// redactSiblingValue applies the redaction paths to ONE unmodeled top-level key's
// value, under both anchorings, and reports whether anything changed. A string leaf is
// replaced by value; containers are mutated in place.
//
//   - Envelope-relative (prefix = key): a multi-segment path names a position relative
//     to the RESULT ENVELOPE, so "data.ssn" must reach an ssn a doubly-encoded blob at
//     key "data" carries — otherwise structuredContent holding an encoded blob masked
//     while a sibling key holding the identical shape forwarded it verbatim.
//   - Value-relative (empty prefix): keeps masking a container an upstream RELOCATED
//     under some other unmodeled key. Deliberate over-redaction: the safe direction
//     for a DLP obligation.
func redactSiblingValue(key string, val interface{}, spec redactSpec) (replacement interface{}, changed bool, err error) {
	// Envelope-relative first: a string leaf redacted under one anchoring is fed to the
	// next, so both apply to the same (possibly already re-serialized) blob.
	for _, prefix := range []string{key, ""} {
		switch v := val.(type) {
		case map[string]interface{}, []interface{}:
			c, cerr := redactStructuredContentValue(v, spec, prefix, 0)
			if cerr != nil {
				return nil, false, cerr // fail closed
			}
			if c {
				changed = true
			}
		case string:
			out, c, cerr := redactContainerString(v, spec, prefix, 0)
			if cerr != nil {
				return nil, false, cerr // fail closed
			}
			if c {
				val = out
				changed = true
			}
		default:
			// A scalar (number, bool, null) carries no named field and cannot hide one.
		}
	}
	return val, changed, nil
}

// redactStructuredContentField redacts the structuredContent key's own value under BOTH
// anchorings redactSiblingValue applies to an unmodeled sibling — envelope-relative and
// value-relative. Delegates to redactSiblingValue itself rather than re-deriving the
// walk: a hand-copied second implementation is exactly how this drifted once already —
// the container case got only the value-relative pass while the doubly-encoded-string
// case needed the envelope-relative one too, silently missing the manifest guide's
// recommended `structuredContent.ssn` spelling for an ssn smuggled as a string there.
//
// A scalar structuredContent carries no named field and nothing that could hide one —
// deliberately more lenient than the content-array path, which fails closed on
// structural anomalies a malformed item could conceal a body inside; a bare scalar cannot.
func redactStructuredContentField(result map[string]interface{}, spec redactSpec) (bool, error) {
	sc, ok := result["structuredContent"]
	if !ok {
		return false, nil
	}
	replacement, changed, err := redactSiblingValue("structuredContent", sc, spec)
	if err != nil {
		return false, err // depth-limit guard or an internal re-marshal error; fail closed
	}
	if changed {
		result["structuredContent"] = replacement
	}
	return changed, nil
}

// redactStructuredContentValue redacts an already-decoded structuredContent container
// (object or array) in place, at dot-prefix `prefix` from the structuredContent root: it
// masks the object keys the manifest paths address (rebased to prefix) AND recursively
// unwraps any doubly-encoded JSON-container string leaf at any depth. Reports whether
// anything changed. A string that is not a clean JSON container passes through
// unchanged; only the depth guard fails closed.
func redactStructuredContentValue(v interface{}, spec redactSpec, prefix string, depth int) (changed bool, err error) {
	keysChanged := redactJSONValue(v, rebaseLeafPaths(spec.paths, prefix))
	_, stringsChanged, serr := redactNestedJSONStrings(v, spec, prefix, depth)
	if serr != nil {
		return false, serr
	}
	return keysChanged || stringsChanged, nil
}

// redactNestedJSONStrings walks a decoded structuredContent value and redacts every
// string leaf that is a doubly-encoded JSON payload — a value an upstream can use to
// smuggle a named field past the structural-key redaction, which only addresses object
// keys and ignores string scalars (e.g. {"data":"{\"ssn\":\"x\"}"}). Each leaf gets the
// same treatment a top-level structuredContent string gets (redactContainerString); an
// unwrapped container recurses back through redactStructuredContentValue, so a field
// under MULTIPLE encoding layers is reached too.
//
// prefix is the dot-path from the structuredContent root to v; it rebases each leaf's
// paths (rebaseLeafPaths) so e.g. data.ssn reaches an ssn smuggled inside a string at
// key "data" — the same field the structural pass redacts in the honest, un-encoded
// shape. Maps/slices mutate in place; the string case returns its replacement.
func redactNestedJSONStrings(v interface{}, spec redactSpec, prefix string, depth int) (redacted interface{}, changed bool, err error) {
	if depth > maxRedactionDepth {
		return nil, false, fmt.Errorf("redactFields: nested JSON content exceeds the redaction depth limit %d; cannot verify redaction (fail closed)", maxRedactionDepth)
	}
	// This walk finds and unwraps doubly-encoded string leaves only; object-key
	// masking for the whole value is a separate pass (redactStructuredContentValue),
	// deliberately not fused into one traversal.
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			childPrefix := k
			if prefix != "" {
				childPrefix = prefix + "." + k
			}
			nv, c, cerr := redactNestedJSONStrings(child, spec, childPrefix, depth+1)
			if cerr != nil {
				return nil, false, cerr
			}
			if c {
				val[k] = nv
				changed = true
			}
		}
		return val, changed, nil
	case []interface{}:
		for i, child := range val {
			// Array elements are transparent to dot-paths (a path applies to every
			// element), so the prefix is inherited unchanged.
			nv, c, cerr := redactNestedJSONStrings(child, spec, prefix, depth+1)
			if cerr != nil {
				return nil, false, cerr
			}
			if c {
				val[i] = nv
				changed = true
			}
		}
		return val, changed, nil
	case string:
		out, c, cerr := redactContainerString(val, spec, prefix, depth+1)
		if cerr != nil {
			return nil, false, cerr
		}
		return out, c, nil
	}
	return v, false, nil
}

// rebaseLeafPaths returns the dot-paths to apply, at its own root, to a doubly-encoded
// JSON-container string unwrapped at dot-prefix `prefix` within structuredContent. A
// path may redact inside the blob only if the honest, un-encoded shape would redact a
// field at this same position:
//
//   - A BARE single-segment path (e.g. "ssn") applies at the blob root unchanged — the
//     doubly-encoded smuggling defense.
//   - A multi-segment path addressing a location UNDER `prefix` contributes the
//     remainder after the prefix ("data.ssn" -> "ssn").
//   - A multi-segment path anchored ELSEWHERE names nothing inside this blob and is
//     dropped, to avoid masking a field the manifest never named at this position.
//
// paths arrive already root-normalized (ApplyRedactObligs strips the "$."/"$" marker
// once up front), so this does NOT re-strip it.
func rebaseLeafPaths(paths []string, prefix string) []string {
	if prefix == "" {
		return paths
	}
	dotPrefix := prefix + "."
	// Single pass with lazy copy-on-write: alias the input while every path so far is kept
	// verbatim, and copy only when the first path is rebased or dropped — so an all-bare batch
	// (the common case, and any batch needing no rebasing) returns the input slice uncopied.
	out := paths
	rewritten := false
	for i, p := range paths {
		switch {
		case !strings.Contains(p, "."):
			// Bare single segment: applies at the blob root unchanged (smuggling defense).
			if rewritten {
				out = append(out, p)
			}
		case strings.HasPrefix(p, dotPrefix):
			// Addresses a location under this blob: rebase to the remainder after the prefix.
			if !rewritten {
				out = append([]string(nil), paths[:i]...)
				rewritten = true
			}
			out = append(out, p[len(dotPrefix):])
		default:
			// Anchored elsewhere: names nothing in this blob; drop it to avoid over-redaction.
			if !rewritten {
				out = append([]string(nil), paths[:i]...)
				rewritten = true
			}
		}
	}
	return out
}

// redactedSentinel is the placeholder a redacted field's value is replaced with.
// redactFields MASKS rather than strips: the matched key stays present and its
// value becomes this sentinel, so a host sees that the field existed but never its
// value. (Stripping the key instead would hide the field's very existence — a
// different disclosure trade-off; see docs/threat-model-mcp.md.)
const redactedSentinel = "[redacted]"

// normalizeDotPathRoot strips the optional JSONPath root marker from a dot-path EXACTLY
// once — only the two real spellings "$." and a lone "$" — leaving a real $-prefixed
// field name ("$schema", "$ref", …) intact. The single definition of the root-marker
// rule, shared by ApplyRedactObligs (applied once up front) and rebaseLeafPaths.
func normalizeDotPathRoot(dotPath string) string {
	switch {
	case strings.HasPrefix(dotPath, "$."):
		return dotPath[len("$."):]
	case dotPath == "$":
		return ""
	}
	return dotPath
}

// redactDotPathRec is the recursive worker for the redactFields walk. It does NOT
// strip the "$"/"$." root marker: ApplyRedactObligs normalizes that exactly once up
// front, so a $-prefixed nested field name here is matched literally. It reports
// whether a field was masked.
func redactDotPathRec(obj map[string]interface{}, dotPath string) bool {
	parts := strings.SplitN(dotPath, ".", 2)
	key := parts[0]
	if len(parts) == 1 {
		if _, present := obj[key]; !present {
			return false
		}
		// Mask in place: replace the value with the sentinel, keep the key. The
		// prior value (object, array, number, or string) is discarded wholesale.
		obj[key] = redactedSentinel
		return true
	}
	return redactValuePath(obj[key], parts[1])
}

// redactValuePath applies the remaining dot-path to a value that may be a nested
// object or an arbitrarily nested array of objects (so "results.ssn" works whether
// results is an object or an array of objects). Scalars and absent values are a
// no-op. Reports whether any field was masked.
func redactValuePath(val interface{}, dotPath string) bool {
	switch v := val.(type) {
	case map[string]interface{}:
		return redactDotPathRec(v, dotPath)
	case []interface{}:
		changed := false
		for _, item := range v {
			if redactValuePath(item, dotPath) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}
