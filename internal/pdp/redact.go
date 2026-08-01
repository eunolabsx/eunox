// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// redactFields directive: mask JSON paths in tool-call result text. Applied
// post-allow only, so nothing here participates in the allow/deny decision — it
// shapes a response the PDP has already permitted.
//
// Split out of pdp.go, which holds the PolicyDecisionPoint contract and the
// ManifestPDP that implements it. This engine shares no state with either: its entry
// point (ApplyRedactObligs) takes the upstream result bytes plus the obligations the
// engine already collected, and returns bytes. Keeping it here leaves pdp.go about the
// decision and this file about the transformation.

package pdp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ApplyRedactObligs applies redactFields obligations to a tools/call result,
// returning redacted bytes or an error. It MUST NOT return unredacted bytes when
// redact paths are non-empty and the response cannot be structurally verified
// (fail closed; see the capability-manifest guide § 5a).
//
// The result is decoded into a generic map so fields the proxy does not model
// (structuredContent, _meta, annotations, non-text content) survive the round-trip.
// Redaction applies to (1) each text content item whose body is clean JSON and (2)
// the structuredContent object. Content that is not a clean JSON container — free-form
// text, malformed JSON, JSON embedded in prose, a scalar — carries no addressable JSON
// object key and passes through unchanged; redactFields redacts cleanly-parseable JSON
// only and does NOT fail the response closed over string content it cannot parse. It
// fails closed on a structural/resource guard: an unparseable (or trailing-data)
// envelope, an envelope or unwrapped JSON leaf whose object keys duplicate or case-collide
// (so its decode may differ from what a host renders; see redactionKeysAmbiguous), a
// structurally unverifiable content array/item shape, the depth bound, or a
// resource/resource_link content item (whose embedded text/blob body this redactor
// cannot inspect) — the last so an upstream cannot evade a declared redactFields
// obligation by embedding the named field inside a resource. image/audio items, which
// carry no addressable JSON body, still pass through.
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
	// slice, so the manifest's own Paths are untouched). Every downstream consumer on this
	// path takes the already-normalized slice and does NOT re-strip: rebaseLeafPaths compares
	// the pre-normalized paths against blob prefixes without re-stripping, and redactJSONValue
	// masks via the raw worker redactDotPathRec. Stripping twice is not idempotent for an
	// original "$.$…" spelling (a field whose key is literally "$"), which would leak.
	for i := range paths {
		paths[i] = normalizeDotPathRoot(paths[i])
	}
	// Resolve the paths and their case-variant fold scope once, and thread the pair
	// through the whole walk: every leaf scan needs both, and re-deriving the fold set per
	// leaf would re-fold the same handful of names for every string in the response.
	spec := redactSpec{paths: paths, fold: redactionFoldKeys(paths)}

	// Preserve the original bytes so a response no path actually matches can be
	// returned verbatim (byte-for-byte), rather than re-marshaled — encoding/json
	// sorts map keys, so an unconditional re-marshal reorders the envelope (and any
	// JSON-object text item) even when nothing was redacted.
	original := resultBytes

	// Strip leading UTF-8 BOM(s) and JSON whitespace: encoding/json rejects a BOM, so
	// a BOM-prefixed envelope would otherwise fail the whole response closed.
	resultBytes = trimLeadingSpaceAndBOM(resultBytes)

	// Decode into a generic map so unknown fields survive the round-trip. UseNumber
	// so non-redacted integers above 2^53 round-trip byte-exact (marshalNoHTMLEscape
	// serializes json.Number verbatim).
	var result map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(resultBytes))
	dec.UseNumber()
	if err := dec.Decode(&result); err != nil {
		// Fail closed: never return unredacted data when we have paths to redact.
		return nil, fmt.Errorf("redactFields: failed to parse upstream response: %w", err)
	}
	// A JSON null envelope decodes into a nil map with no error — the one non-object
	// shape encoding/json accepts (arrays/scalars/bools all error above). It is not a
	// structurally valid tools/call result object, so fail closed like every sibling
	// non-object envelope rather than forwarding it with the obligation marked applied.
	if result == nil {
		return nil, fmt.Errorf("redactFields: response envelope is JSON null, not an object; cannot verify redaction (fail closed)")
	}
	// Decode stops after the first value; trailing tokens make the envelope a
	// malformed/ambiguous container that the documented contract refuses, mirroring
	// the per-text-item guard in redactJSONText — fail closed rather than silently
	// drop the trailing data on re-marshal.
	if dec.More() {
		return nil, fmt.Errorf("redactFields: trailing data after response envelope; cannot verify redaction (fail closed)")
	}
	// The decode above resolved every duplicate object key LAST-WINS, and a host is free
	// to resolve it first-wins. That divergence is a redaction bypass on its own:
	// {"content":[...],"data":{"ssn":"..."},"data":{}} decodes to an empty `data`, so no
	// path matches, `changed` stays false, and the ORIGINAL bytes — carrying the ssn — are
	// returned verbatim below while the audit record reports the obligation applied. The
	// same rule the request path (mcp.rejectDuplicateJSONKeys) and the list filters
	// (entryKeysAmbiguous) already apply closes it here: bytes whose decode cannot be
	// trusted to match what a host renders cannot verify a redaction, so they fail closed.
	if redactionKeysAmbiguous(resultBytes, spec.fold) {
		return nil, fmt.Errorf("redactFields: response envelope carries a duplicate or case-variant object key, so its decode may differ from what a host renders; cannot verify redaction (fail closed)")
	}

	// (1) Redact within each text content item. Any structurally unverifiable shape
	// — a non-array `content`, a non-object item, an item with no string `type`, an
	// unrecognized type, or a type=="text" item whose body is not a string — could
	// hide the named field, so each fails the whole response closed rather than
	// forward unredacted.
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
			t, ok := obj["type"].(string)
			if !ok || t == "" {
				return nil, fmt.Errorf("redactFields: response 'content' item has no string 'type'; cannot verify redaction (fail closed)")
			}
			if t != "text" {
				switch t {
				case "resource", "resource_link":
					// A resource / resource_link content item nests a `resource` object that
					// can carry a `text` or `blob` body holding arbitrary (possibly sensitive)
					// data this redactor does NOT walk. Silently forwarding it would let an
					// upstream evade a declared redactFields obligation by embedding the named
					// field inside a resource body. An active redaction obligation cannot be
					// satisfied over content the redactor cannot inspect, so fail the whole
					// response closed rather than forward it unredacted. See
					// docs/capability-manifest-guide.md.
					return nil, fmt.Errorf("redactFields: response 'content' item type %q carries an embedded resource body this redactor cannot inspect; cannot verify redaction (fail closed)", t)
				default:
					if !isRecognizedContentType(t) {
						return nil, fmt.Errorf("redactFields: response 'content' item has unrecognized type %q; cannot verify redaction (fail closed)", t)
					}
					// Recognized binary media (image/audio) carries no addressable JSON body a
					// redactFields dot-path could match, so it is preserved unchanged.
					continue
				}
			}
			text, ok := obj["text"].(string)
			if !ok {
				return nil, fmt.Errorf("redactFields: text content item has a non-string 'text' body (%T); cannot verify redaction (fail closed)", obj["text"])
			}
			redacted, err := redactJSONText(text, spec)
			if err != nil {
				return nil, err // fail closed
			}
			if redacted != text {
				changed = true
			}
			obj["text"] = redacted
		}
	}

	// (2) Redact within structuredContent (MCP 2025-06+ structured result), in place,
	// with the same fail-closed rigor as the content path above. See
	// redactStructuredContentField.
	scChanged, scErr := redactStructuredContentField(result, spec)
	if scErr != nil {
		return nil, scErr // fail closed
	}
	if scChanged {
		changed = true
	}

	// (3) Redact within every OTHER top-level result key. `content` and
	// `structuredContent` are the two shapes MCP defines, but a result envelope may
	// legally carry additional keys, and this function's own contract is that fields the
	// proxy does not model "survive the round-trip" — which meant a named field sitting in
	// any other top-level key was forwarded UNREDACTED even though the manifest declared
	// it redactable. An upstream returning {"content":[...],"data":{"ssn":"..."}} defeated
	// the obligation entirely.
	//
	// Redacting them (rather than failing the response closed on an unmodelled key) is the
	// right trade here: `_meta`, `annotations`, and vendor extensions are ordinary and
	// legitimate, so refusing them would break honest upstreams, while masking is exactly
	// what the operator asked for. The same container walk structuredContent uses is
	// reused, so a doubly-encoded JSON string leaf is unwrapped identically and the depth
	// bound applies the same way.
	sibChanged, sibErr := redactSiblingTopLevelKeys(result, spec)
	if sibErr != nil {
		return nil, sibErr // fail closed
	}
	if sibChanged {
		changed = true
	}

	// No path matched anything: return the original bytes verbatim so a response
	// the redaction did not touch is preserved byte-for-byte (key order, scalar
	// formatting, and any leading BOM/whitespace all intact). The re-marshal below
	// would otherwise reorder every envelope key via encoding/json's sorted-map
	// output even though nothing was redacted.
	if !changed {
		return original, nil
	}

	// Re-serialize WITHOUT HTML escaping: the default escaping of <, >, & (and
	// U+2028/U+2029) would rewrite passthrough values (URLs, HTML/XML, code) even in
	// fields no redaction path matched, breaking the "content not redacted is
	// preserved unchanged" guarantee for hosts that hash or diff the raw bytes.
	out, err := marshalNoHTMLEscape(result)
	if err != nil {
		return nil, fmt.Errorf("redactFields: failed to re-marshal redacted response: %w", err)
	}
	return out, nil
}

// redactionKeysAmbiguous reports whether raw — a result envelope, or a JSON container
// unwrapped from a string leaf — carries an object key whose decode this redactor cannot
// trust to match what a host renders. Either way the value the redaction walk inspected is
// not the value the host sees, so an active obligation cannot be verified over these bytes.
//
// Two rules, and unlike the */list entry gate the second is SCOPED (see spec.fold and
// redactionFoldKeys):
//
//   - An EXACT duplicate key, at any depth, is always untrustworthy: Go keeps the last and
//     a first-wins host parser renders the first. This is the whole of the bypass this gate
//     was added for — {"data":{"ssn":…},"data":{}} decodes to an empty `data`, so no path
//     matches, nothing is marked changed, and the ORIGINAL bytes carrying the ssn are
//     returned verbatim while the record reports the obligation applied.
//   - A CASE-VARIANT collision is untrustworthy only for a name this redaction actually
//     depends on resolving. The */list gate folds every root key because an entry is bound
//     to a STRUCT by encoding/json's case-insensitive field match; nothing on this path is.
//     Both the envelope and every unwrapped leaf decode into map[string]interface{}, whose
//     keys are exact — so {"Data":…,"data":…} yields two distinct entries here exactly as it
//     does for any host that renders JSON as data, with no divergence to refuse over.
//
// It runs the SAME scan as the */list entry gate (scanJSONKeys, shared with scanToolEntry),
// with array roots admitted: structuredContent, a sibling key's value, and any
// doubly-encoded leaf are all legally an array of objects, where a tools/list entry is not.
func redactionKeysAmbiguous(raw []byte, fold map[string]struct{}) bool {
	return scanJSONKeys(raw, jsonKeyScanOpts{allowArrayRoot: true, foldKeys: fold}).untrustworthy
}

// redactSpec is one redactFields obligation set, resolved once per response: the normalized
// dot-paths to mask, plus the folded key names whose case variants make a decode
// untrustworthy. They travel together because every leaf of the walk needs both, and
// deriving fold at each leaf would re-fold the same handful of names per string scanned.
type redactSpec struct {
	// paths are the dot-paths to mask, with the optional "$."/"$" JSONPath root marker
	// already stripped exactly once (see normalizeDotPathRoot). Downstream consumers take
	// them as-is and never re-strip.
	paths []string
	// fold is the scoped case-variant set redactionKeysAmbiguous applies; see
	// redactionFoldKeys.
	fold map[string]struct{}
}

// redactionFoldKeys returns the folded key names a case variant of which would change what
// this redaction resolves — the scope of redactionKeysAmbiguous's case-variant rule. Two
// sources, both about resolution rather than about case as such:
//
//   - Every SEGMENT of every redact path. The masking walk looks its segments up exactly
//     (redactDotPathRec does obj[key]), so with paths ["ssn"] a response carrying both
//     "ssn" and "SSN" has two candidate fields where the obligation named one. A host that
//     binds the result into a struct resolves that pair case-insensitively and may render
//     the sibling this walk did not mask, so the bytes cannot verify the obligation.
//   - The protocol-reserved envelope keys (mcpReservedRootKeys). ApplyRedactObligs
//     dispatches on them EXACTLY — result["content"] gets the content-array treatment, with
//     its fail-closed guards on resource items and anomalous shapes, while anything else
//     falls to the weaker generic sibling walk. So {"content":[],"Content":[{"type":
//     "resource",…}]} passes the strict pass over an empty array and the lenient one over
//     the payload, while a case-insensitive host binds the payload as its content. The
//     variant spelling has to be refused, not silently downgraded to the generic walk.
//
// Segments are collected from the whole path (not just its head) because a leaf scan sees
// the blob's own root, where "data.ssn" is looked up as "ssn". Folding at every depth costs
// only over-refusal on a nested case-variant pair, which is a denial, never a bypass.
func redactionFoldKeys(paths []string) map[string]struct{} {
	fold := make(map[string]struct{}, len(paths)+len(mcpReservedRootKeys))
	for k := range mcpReservedRootKeys {
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
// Redaction applies only to "text" items (and structuredContent). "image"/"audio"
// carry no top-level JSON object body a dot path could name, so they pass through
// unchanged. An unrecognized type fails the response closed.
//
// "resource"/"resource_link" are recognized here (so an unrecognized-type guard does
// not fire on them) but, unlike image/audio, they do NOT pass through when a
// redactFields obligation is active: they nest a "resource" object with a text/blob
// body this redactor cannot walk, so ApplyRedactObligs fails the response closed over
// them rather than let an upstream evade redaction by embedding the field there.
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

// utf8BOM is the UTF-8 byte-order mark (U+FEFF) as its three raw bytes, to keep
// the source ASCII-clean. encoding/json rejects a leading BOM and TrimSpace does
// not treat it as whitespace, so the redaction paths strip it explicitly —
// otherwise a BOM-prefixed JSON container evades redaction (fail open).
var utf8BOM = string([]byte{0xEF, 0xBB, 0xBF})

// trimLeadingSpaceAndBOM returns s with its entire leading run of UTF-8 BOMs and
// JSON whitespace removed, so the result begins at the first significant byte. It is
// generic over string and []byte so the two redaction paths share ONE implementation
// — the []byte envelope (ApplyRedactObligs) and the string leaf
// (classifyRedactableLeaf) — without a string twin AND without heap-copying a string
// leaf into a []byte just to trim it. The result is a reslice of s (no copy).
//
// The whole run (not just an offset-0 BOM) must go: a BOM anywhere in the leading
// run — behind a tab, doubled — would otherwise survive, keep encoding/json failing,
// and make classifyRedactableLeaf see 0xEF instead of '{', misclassifying a real JSON
// container as prose and forwarding it UNREDACTED.
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
// may be JSON. It is a thin wrapper over redactContainerString (the shared core): a string
// that parses cleanly as a JSON object/array is redacted and re-serialized (recursively,
// including doubly-encoded JSON-container string values nested inside it); anything else —
// prose, a scalar, malformed JSON, or JSON embedded in prose — is returned unchanged.
// redactFields never fails the response closed over string content it cannot parse.
func redactJSONText(text string, spec redactSpec) (string, error) {
	out, _, err := redactContainerString(text, spec, "", 0)
	return out, err
}

// redactContainerString redacts a string that is a (possibly multiply doubly-encoded) JSON
// container. It is the shared core of the text-content path (redactJSONText), the
// structuredContent string path (redactStructuredContentField), and the nested string-leaf
// walk (redactNestedJSONStrings), so the classify -> redact -> recurse -> re-serialize
// policy lives in one place. A string that parses cleanly as a JSON object/array is
// unwrapped, redacted (its object keys AND its own nested JSON-container string values, up
// to maxRedactionDepth), and re-serialized. A string that decodes to ANOTHER JSON string
// (a further string-encoding layer, e.g. a value double- or triple-JSON-encoded before
// delivery) recurses into that decoded string rather than passing it through, so a
// container hidden under any number of string layers is still reached — mirroring the
// coverage this function's callers document. Anything that is NOT a clean JSON container or
// string-encoded layer — prose, a genuine scalar, malformed JSON, or JSON embedded in
// surrounding prose — passes through byte-for-byte. redactFields does not fail the response
// closed over such content; data not modeled as clean JSON fields is redacted upstream (see
// the manifest guide and docs/threat-model-mcp.md). prefix rebases dot-paths to the string's
// position; depth bounds the recursion (both the container-key walk AND the string-layer
// unwrap share this one counter, so the total encoding depth an adversarial upstream can
// force is still capped at maxRedactionDepth).
func redactContainerString(s string, spec redactSpec, prefix string, depth int) (redacted string, changed bool, err error) {
	if depth > maxRedactionDepth {
		return "", false, fmt.Errorf("redactFields: nested JSON content exceeds the redaction depth limit %d; cannot verify redaction (fail closed)", maxRedactionDepth)
	}
	decoded, kind := classifyRedactableLeaf(s, spec.fold)
	switch kind {
	case leafKindString:
		// A further string-encoding layer: recurse into the decoded inner string so a
		// container hidden under multiple layers of JSON-string encoding is still
		// reached, instead of treating the one-decode-away scalar as terminal.
		inner, innerChanged, ierr := redactContainerString(decoded.(string), spec, prefix, depth+1)
		if ierr != nil {
			return "", false, ierr
		}
		if !innerChanged {
			return s, false, nil // nothing matched at any layer: preserve the original bytes
		}
		return finalizeRedactedLeaf(inner)
	case leafKindAmbiguous:
		// The leaf decodes to a container whose keys Go and a host can resolve differently
		// (see redactionKeysAmbiguous). The envelope-level gate cannot see this one: inside
		// the envelope the leaf is a single JSON string token, so its duplicate keys only
		// become keys when this function decodes them. Without the check here the identical
		// smuggle works one layer down — a text item carrying
		// "{\"data\":{\"ssn\":\"...\"},\"data\":{}}" leaves `changed` false, so the original
		// string, and then the original envelope, is forwarded verbatim.
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
		// Prose, a genuine scalar, malformed JSON, or JSON embedded in prose: no clean
		// JSON object to redact. Return the ORIGINAL string byte-for-byte (no
		// re-marshal/key reorder).
		return s, false, nil
	}
}

// finalizeRedactedLeaf re-marshals a redacted leaf value (an inner string from the
// leafKindString case, or a decoded container from the leafKindContainer case) back
// to JSON text, sharing the marshal-and-wrap-error tail both redactContainerString
// branches otherwise duplicate. Always reports changed=true: both callers already
// know something changed before calling this (that's why they're re-marshaling at
// all) and return their unmarshaled original directly on the unchanged path instead.
func finalizeRedactedLeaf(v interface{}) (redacted string, changed bool, err error) {
	out, merr := marshalNoHTMLEscape(v)
	if merr != nil {
		return "", false, fmt.Errorf("redactFields: failed to re-marshal redacted JSON content: %w", merr)
	}
	return string(out), true, nil
}

// maxRedactionDepth (256) is enforced in redactNestedJSONStrings, which walks EVERY
// structuredContent (and text) value — incrementing depth on each structural child and each
// doubly-encoded unwrap layer — and fails the WHOLE response closed past this limit. So 256
// is the operative bound on the redactable depth of ANY such value, plain or doubly-encoded,
// not just deeply-nested encoded payloads. It is a resource guard, not a content check,
// capping the worst-case re-marshal and dot-prefix-build cost against an adversarial input.
// The structural key-masking pass (redactJSONValue) carries no separate depth guard: it runs
// on the same value the string pass already depth-bounds (and only descends named paths plus
// array elements), so the response is denied at 256 regardless. encoding/json's own
// 10000-level decode cap is a far higher, separate bound — a response nested past it fails to
// decode and is rejected at the envelope — but 256 always fires first. No realistic tool
// result nests anywhere near this deep.
const maxRedactionDepth = 256

// leafRedactionKind classifies what a one-layer JSON decode of a redaction leaf yielded.
type leafRedactionKind int

const (
	// leafKindOther is prose, a genuine scalar (number/bool/null), malformed JSON, or
	// JSON embedded in surrounding prose: not redactable, passed through unchanged.
	leafKindOther leafRedactionKind = iota
	// leafKindContainer is a JSON object or array: the shape redactFields acts on directly.
	leafKindContainer
	// leafKindString is a JSON string scalar: a further string-encoding layer that may
	// itself decode to a container (or another string layer) and must be recursed into,
	// not treated as terminal — the fix for the double-encoding fail-open.
	leafKindString
	// leafKindAmbiguous is a JSON container whose object keys duplicate or case-collide, so
	// this redactor's decode of it may differ from what a host renders. It is NOT a
	// pass-through shape like leafKindOther: the caller fails the whole response closed,
	// because a container the redactor cannot read the way the host will could be hiding
	// the very field the obligation names.
	leafKindAmbiguous
)

// classifyRedactableLeaf decodes ONE JSON layer of the string s and reports what it found:
// a redactable container (leafKindContainer, the decoded object/array), a further
// string-encoding layer (leafKindString, the decoded inner string — the caller must decode
// it again to reach any container it wraps), a container whose duplicate/case-colliding
// keys make the decode untrustworthy (leafKindAmbiguous, which the caller fails closed on),
// or a terminal value (leafKindOther: prose, a genuine scalar, malformed JSON, or JSON
// embedded in prose) the caller passes through unchanged. redactFields never fails the response closed over string content it cannot
// parse — it redacts named fields of valid JSON only (see docs/threat-model-mcp.md).
//
// Fast-path guard: a string with no '{', no leading '"', and no leading '[' cannot name an
// object key, wrap one directly (as an object OR an array of objects), or wrap a further
// string-encoding layer that itself wraps one, so the decoder is skipped entirely (the
// common-leaf fast path); UseNumber preserves large-integer fidelity for the surviving
// fields on re-marshal. The envelope's first decode already resolves any "{" JSON escape to
// a literal '{' byte, so a directly-embedded leafKindContainer is always caught by the '{'
// check alone — the leading-'"'/leading-'[' arms exist only for a NESTED encoding layer or
// an array wrapper. Concretely: a doubly-encoded value can spell its INNER layer's braces
// as {/} unicode escapes, so the once-decoded Go string is a further JSON string (starts
// with '"') containing no literal '{' byte that still decodes to an object; the same
// evasion works one level further out via an array of escaped-brace string-encoded objects
// (`["{ssn...}"]`), which contains no literal '{' anywhere and starts with '[', not '"'.
// Bailing on '{' (or '{'-or-'"') alone would skip that layer and let the object it wraps
// pass through unredacted (see the redactNestedJSONStrings doc comment on doubly-encoded
// smuggling). A leading '"' or '[' that turns out to decode to plain prose, a scalar, or an
// array of non-container elements still terminates safely as leafKindOther after one
// bounded recursion (depth capped at maxRedactionDepth), so accepting these two extra
// prefixes costs no extra fail-closed risk.
func classifyRedactableLeaf(s string, fold map[string]struct{}) (decoded interface{}, kind leafRedactionKind) {
	trimmed := trimLeadingSpaceAndBOM(s)
	// '"' and '[' use HasPrefix (position-0 only) deliberately: under JSON grammar a
	// container's or a further string layer's start token must be the first
	// non-whitespace/BOM byte, so a '"' or '[' appearing later in the string cannot
	// itself open one. '{' intentionally stays ContainsRune (whole-string), broader
	// than strictly needed, because a bare embedded '{' not at position 0 is already
	// handled safely: it still has to pass the decode+dec.More() check below to be
	// treated as anything but leafKindOther, so widening it to HasPrefix would only
	// narrow coverage, not fix a bug. Do not "harmonize" the three checks to all use
	// HasPrefix without re-deriving this.
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
		// The decode above collapsed any duplicate key last-wins. Scan the leaf's own bytes
		// for that (and for a root-level case-variant collision) before the caller acts on
		// the decoded value: this is the only point where a string becomes a container, so
		// it is the one place the leaf's raw bytes and their decode are both in hand.
		if redactionKeysAmbiguous([]byte(trimmed), fold) {
			return nil, leafKindAmbiguous
		}
		return val, leafKindContainer
	case string:
		// A further string-encoding layer carries no keys of its own yet; the recursion
		// re-enters here with the decoded inner string and scans whatever container it
		// finally unwraps to.
		return v, leafKindString
	default:
		return nil, leafKindOther // a genuine JSON scalar (number/bool/null): no object key
	}
}

// redactJSONValue applies every dot-path redaction to a decoded JSON value,
// handling a top-level object or array of objects. It reports whether it actually
// masked a field. A value that matched no path (including any scalar) reports
// false, so the caller leaves the ORIGINAL bytes untouched — re-marshaling a map
// the redaction did not touch would reorder its keys (encoding/json sorts map
// keys) and could change scalar byte representation (1e308 -> 1e+308), breaking
// the "content not redacted is preserved unchanged" guarantee.
func redactJSONValue(val interface{}, paths []string) bool {
	switch v := val.(type) {
	case map[string]interface{}:
		changed := false
		for _, p := range paths {
			// paths arrive already root-normalized: ApplyRedactObligs strips the
			// optional "$."/"$" JSONPath marker once up front and threads the same
			// slice through the walk and rebaseLeafPaths. Redact via the raw worker
			// so the marker is NOT stripped a second time — a second strip is not
			// idempotent for a path that, after the first strip, still begins with
			// "$." or equals "$" (i.e. an original "$.$…" spelling targeting a field
			// whose key is literally "$"): it would over-strip and leak that field.
			// ApplyRedactObligs already normalized the marker once up front.
			if redactDotPathRec(v, p) {
				changed = true
			}
		}
		return changed
	case []interface{}:
		// Recurse into every element so objects at any nesting depth are redacted
		// (stopping at the first array level would leak nested fields).
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

// mcpReservedRootKeys are the MCP result-envelope keys that carry protocol STRUCTURE
// rather than tool data: the two content components, the CallToolResult error flag, the
// ReadResourceResult and GetPromptResult payload arrays, and the metadata sidecar.
//
// The envelope-root redaction pass masks a named key wholesale with the string sentinel,
// which is right for an unmodelled sibling carrying data but wrong for these: `isError` is
// a bool and `contents`/`messages` are arrays, so replacing one with "[redacted]" yields a
// result a spec-conformant host cannot decode at all — a hard protocol failure in place of
// the field-level masking the operator asked for. content/structuredContent additionally
// have their own shape-specific passes, which redact WITHIN them.
var mcpReservedRootKeys = map[string]struct{}{
	"content":           {},
	"structuredContent": {},
	"isError":           {},
	"contents":          {},
	"messages":          {},
	"_meta":             {},
}

// envelopeRootExempt reports whether a redact path must not be applied at the envelope
// root. Only a SINGLE-SEGMENT path naming a reserved component is exempt — that spelling
// would mask the whole component.
//
// A dotted path is deliberately NOT exempt, and the distinction is load-bearing: the
// manifest guide tells operators to "prefer the fully-qualified dotted path when the field
// is nested", so `structuredContent.ssn` is the recommended spelling for a field inside
// structuredContent. Anchored at the root it resolves exactly — result["structuredContent"]
// ["ssn"] — and masks that leaf alone. Exempting it by its HEAD instead would have made the
// recommended spelling redact nothing at all while the audit record still reported the
// obligation applied, which is the fail-open this whole pass exists to close.
func envelopeRootExempt(path string) bool {
	if strings.Contains(path, ".") {
		return false
	}
	_, reserved := mcpReservedRootKeys[path]
	return reserved
}

// redactSiblingTopLevelKeys applies the redaction paths to every top-level result key
// OTHER than content and structuredContent, which ApplyRedactObligs handles with their own
// shape-specific rigor.
//
// Split out of ApplyRedactObligs to keep that function within the cognitive-complexity
// budget, not because the walk is independent of it: it is the third of the three passes
// the doc there describes, and skipping it forwards a field the manifest declared
// redactable simply because the upstream put it under an unmodelled key.
//
// Redacting unmodelled keys rather than failing the response closed on their presence is
// deliberate: _meta, annotations, and vendor extensions are ordinary and legitimate, so
// refusing them would break honest upstreams, while masking is exactly what the operator
// asked for. Reuses structuredContent's container walk, so a doubly-encoded JSON string
// leaf is unwrapped identically and the depth bound applies the same way.
func redactSiblingTopLevelKeys(result map[string]interface{}, spec redactSpec) (bool, error) {
	changed := false
	// Match the paths against the ENVELOPE itself before descending into its values. The
	// descent below only ever sees a sibling key's VALUE, so a declared field sitting
	// DIRECTLY on a top-level key was never tested against its own name:
	// {"content":[...],"ssn":"123-45-6789"} with redactFields ["ssn"] forwarded the SSN
	// verbatim, while the nested spelling {"data":{"ssn":"..."}} redacted correctly. Same
	// obligation, same field name, opposite outcome depending on how deep the upstream
	// happened to put it.
	//
	// A path naming a protocol-reserved component OUTRIGHT is skipped: see
	// envelopeRootExempt. A DOTTED path through one is not — it names a leaf, and masking
	// that leaf is exactly what the operator asked for.
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

// redactSiblingValue applies the redaction paths to ONE unmodelled top-level key's value,
// under both anchorings, and reports whether anything changed. A string leaf is replaced by
// value (the caller writes the returned replacement back); containers are mutated in place.
//
// A dot-path is applied under TWO anchorings, and the union of the two is what gets masked:
//
//   - Envelope-relative (prefix = key). A multi-segment path names a position relative to
//     the RESULT ENVELOPE, so "data.ssn" must reach an ssn that a doubly-encoded blob at
//     key "data" carries: with the key as prefix, rebaseLeafPaths maps "data.ssn" to "ssn"
//     at the blob's own root, exactly as it already does for the identical shape under
//     structuredContent. Anchoring only at the value's root (as this walk once did) made
//     the two spellings of the same result disagree — structuredContent holding
//     {"data":"{\"ssn\":...}"} masked while a sibling key holding it forwarded the value
//     verbatim, defeating a declared obligation on the shape the envelope pass above
//     handles for the un-encoded spelling.
//   - Value-relative (empty prefix). Keeps masking a container an upstream RELOCATED under
//     some other unmodelled key: for "data.ssn", {"output":{"data":{"ssn":...}}} names
//     nothing envelope-relative, and rebaseLeafPaths drops paths anchored elsewhere, so the
//     first anchoring alone would forward it. Deliberate over-redaction: masking a field
//     the manifest named, at a position it did not name, is the safe direction for a DLP
//     obligation, whereas the reverse leaks.
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
// anchorings redactSiblingValue applies to an unmodelled sibling key — envelope-relative
// (prefix "structuredContent", so "structuredContent.ssn" reaches an ssn a doubly-encoded
// blob AT that key carries) and value-relative (empty prefix, treating the value as its
// own root). It delegates to redactSiblingValue itself rather than re-deriving the same
// two-anchoring walk: a hand-copied second implementation is exactly how this drifted once
// already — the container case (a direct structuredContent object) got only the
// value-relative pass here while the doubly-encoded-string case needed the envelope-relative
// one too, so "structuredContent.ssn" — the fully-qualified spelling the manifest guide
// recommends — silently failed to redact an ssn smuggled as a JSON string AT structuredContent
// itself, even though the identical shape under a sibling key already redacted correctly.
//
// The container case now also runs the envelope-relative anchoring, which is redundant with
// (but harmless alongside) redactSiblingTopLevelKeys' own top-level redactDotPathRec pass over
// the whole envelope — masking an already-masked leaf a second time changes nothing.
//
// A scalar structuredContent (JSON null, number, or bool) carries no named field, so there is
// nothing to redact and nothing that could hide one — redactSiblingValue's default case
// already passes it through unchanged. This is deliberately MORE lenient than the
// content-array path in ApplyRedactObligs, which fails closed on a structurally anomalous
// shape: a malformed content item can conceal a text body carrying the field, whereas a bare
// scalar cannot. Do not reconcile the two — failing closed here would needlessly block valid
// scalar results, and passing anomalous content shapes through there would fail open on a
// real hiding place.
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
// masks the object keys the manifest paths address (redactJSONValue, with paths rebased
// to prefix) AND recursively unwraps any doubly-encoded JSON-container string leaf at any
// depth (redactNestedJSONStrings, whose string case calls back here for each unwrapped
// layer). It reports whether anything changed. A string that is not a clean JSON container
// passes through unchanged; only the depth guard fails closed.
func redactStructuredContentValue(v interface{}, spec redactSpec, prefix string, depth int) (changed bool, err error) {
	keysChanged := redactJSONValue(v, rebaseLeafPaths(spec.paths, prefix))
	_, stringsChanged, serr := redactNestedJSONStrings(v, spec, prefix, depth)
	if serr != nil {
		return false, serr
	}
	return keysChanged || stringsChanged, nil
}

// redactNestedJSONStrings walks a decoded structuredContent value and applies redaction
// to every string leaf that is a doubly-encoded JSON payload — a value an upstream can
// use to smuggle a named field past the structural-key redaction (redactJSONValue),
// which only addresses object keys and ignores string scalars (e.g. {"data":"{\"ssn\":
// \"x\"}"} or ["{\"ssn\":\"x\"}"]). Each leaf is run through redactContainerString — the
// SAME treatment a top-level structuredContent string gets — so a leaf that parses cleanly
// as a JSON container is unwrapped, redacted, and re-serialized; anything that is not a
// clean JSON container (prose, a scalar, malformed JSON, or JSON embedded in prose) passes
// through unchanged. An unwrapped container is redacted via redactStructuredContentValue,
// which recurses back here, so a field hidden under MULTIPLE encoding layers is reached too.
//
// prefix is the dot-path from the structuredContent root to v; it rebases each leaf's
// paths (see rebaseLeafPaths) so a path like data.ssn reaches the ssn smuggled inside a
// string at key "data" — the same field the structural pass redacts in the honest,
// un-encoded {"data":{"ssn":...}} shape. Object keys extend the prefix; array elements
// are transparent to dot-paths and inherit it. Maps and slices are mutated in place; the
// string case returns its replacement (which the parent writes back), so the first
// return is load-bearing only for a leaf.
func redactNestedJSONStrings(v interface{}, spec redactSpec, prefix string, depth int) (redacted interface{}, changed bool, err error) {
	if depth > maxRedactionDepth {
		return nil, false, fmt.Errorf("redactFields: nested JSON content exceeds the redaction depth limit %d; cannot verify redaction (fail closed)", maxRedactionDepth)
	}
	// This walk finds and unwraps doubly-encoded string leaves only. Object-key masking for
	// the whole decoded value is done once, up front, by the redactJSONValue pass in
	// redactStructuredContentValue (redactDotPathRec descends named paths itself), so the two
	// passes are deliberately separate concerns, not a redundant double key-walk: fusing them
	// would re-thread the path-rebasing/array-descent logic through one traversal for a
	// marginal gain on size-bounded responses, at real risk to this DLP path.
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
		// A doubly-encoded JSON-container leaf gets the same redact / re-serialize treatment
		// as any container string; redactContainerString recurses back through
		// redactStructuredContentValue, so a field under a further encoding layer is reached
		// too. A non-container string (prose, malformed, embedded-in-prose) passes through.
		out, c, cerr := redactContainerString(val, spec, prefix, depth+1)
		if cerr != nil {
			return nil, false, cerr
		}
		return out, c, nil
	}
	return v, false, nil
}

// rebaseLeafPaths returns the dot-paths to apply, at its own root, to a doubly-encoded
// JSON-container string unwrapped at dot-prefix `prefix` within structuredContent. A path
// may redact inside the blob only if the honest, un-encoded shape would redact a field at
// this same position, so each input path maps as follows:
//
//   - A BARE single-segment path (e.g. "ssn") applies at the blob root unchanged: a bare
//     field name is redacted at the top level of every unwrapped container — the documented
//     doubly-encoded smuggling defense, where bare "ssn" catches an ssn smuggled at any layer.
//   - A multi-segment path addressing a location UNDER `prefix` (e.g. "data.ssn" reached via
//     key "data") contributes the remainder after the prefix ("ssn") — the same field the
//     structural pass redacts in the honest {"data":{"ssn":...}} shape.
//   - A multi-segment path anchored ELSEWHERE (it does not start with prefix+".") names
//     nothing inside this blob, so it is dropped. Retaining its absolute form and re-applying
//     it at the blob root would mask a differently-located field the manifest never named —
//     over-redaction that the honest, un-encoded shape does not perform.
//
// paths arrive already root-normalized — ApplyRedactObligs strips the optional "$."/"$"
// JSONPath marker once up front and threads the same slice through the walk — so this does
// NOT re-strip it; the comparisons below are against blob prefixes built from raw JSON keys
// (which carry no marker), and redactJSONValue applies them via redactDotPathRec without a
// second strip.
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
// once — only the two real spellings "$." and a lone "$" — leaving a real $-prefixed field
// name ("$schema", "$ref", …) intact and matched literally. It is the single definition of
// the root-marker rule, shared by ApplyRedactObligs (which applies it once up front so the
// rule is not re-evaluated at every node of the walk) and rebaseLeafPaths (nested-string
// rebasing).
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
// no-op. Calls redactDotPathRec (the root marker is normalized once up front by
// ApplyRedactObligs, not re-stripped at each level). Reports whether any field was masked.
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
