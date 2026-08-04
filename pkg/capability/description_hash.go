// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
)

// ComputeToolHash returns the "sha256:<lowercase-hex>" hash of a tool's model-facing
// instruction surface: its top-level description plus every input parameter description
// (at any nesting depth, via ParamDescriptions). Both are prompt content the host model
// reads, so both are pinned against an upstream that rewrites them to inject instructions
// (tool poisoning / rug-pull, FM-5); leaving nested descriptions unpinned would let an
// attacker move a payload one level down. Parameter STRUCTURE (names, types, required) is
// deliberately excluded — that's FM-6, at lower severity, and folding it in would make this
// always-fatal pin fire on benign schema evolution.
//
// Encoding is canonical (sorted, length-prefixed fields, so no two distinct inputs collide
// by concatenation) and matches the manifest's descriptionHash field. Pins generated before
// nested-description coverage must be regenerated with `eunox init --pin-descriptions`.
func ComputeToolHash(description string, paramDescriptions map[string]string) string {
	h := sha256.New()
	writeLenPrefixed(h, description)
	names := make([]string, 0, len(paramDescriptions))
	for name := range paramDescriptions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writeLenPrefixed(h, name)
		writeLenPrefixed(h, paramDescriptions[name])
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// ToolHashParams builds the paramDescriptions map to pass to ComputeToolHash, folding
// in a tool's model-facing top-level title, annotations, and outputSchema parameter
// descriptions (when present) under reserved keys alongside every inputSchema
// description. A tool that carries none of them yields exactly
// ParamDescriptions(inputSchema), so a description-only pin generated before this
// coverage still verifies unchanged — but an upstream that ADDS or rewrites a title,
// annotations, or an outputSchema description (all rendered to the host model by
// common clients) moves the hash, closing the FM-5 rug-pull those fields would
// otherwise hide behind. Annotations are serialized canonically (encoding/json sorts
// map keys), so an equivalent object always hashes identically. outputSchema's
// descriptions are namespaced under outputSchemaKeyPrefix before merging, so an
// outputSchema description can never collide with an inputSchema description at the
// same relative path. Shared by the drift check and `init` so they pin and verify
// identical input.
func ToolHashParams(title string, annotations, inputSchema, outputSchema map[string]interface{}) map[string]string {
	out := ParamDescriptions(inputSchema)
	if title != "" {
		out[toolTitleKey] = title
	}
	if len(annotations) > 0 {
		if b, err := json.Marshal(annotations); err == nil {
			out[toolAnnotationsKey] = string(b)
		} else {
			// A non-serializable annotations object (unexpected from a JSON-decoded
			// tools/list) forces a distinct, deterministic hash rather than silently
			// dropping the pinned surface — fail closed.
			out[toolAnnotationsKey] = "\x00unserializable-annotations"
		}
	}
	for k, v := range ParamDescriptions(outputSchema) {
		out[outputSchemaKeyPrefix+k] = v
	}
	return out
}

// writeLenPrefixed writes an 8-byte big-endian length prefix followed by s, so a
// concatenation of fields is unambiguous regardless of the bytes in s. The sink
// is the running hash (a hash.Hash satisfies io.Writer and never errors).
func writeLenPrefixed(w io.Writer, s string) {
	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(s)))
	_, _ = w.Write(lenbuf[:])
	_, _ = io.WriteString(w, s)
}

// maxParamDescriptionDepth bounds how deep ParamDescriptions recurses into a
// nested JSON Schema before it stops and fails closed. It guards against an
// adversarial, pathologically-deep upstream schema exhausting the stack, mirroring
// the redaction-depth guard pattern. Past the bound the walker records a sentinel
// key (paramDescriptionOverflowKey) so the computed hash deterministically differs
// from any honest schema rather than silently truncating the pinned surface.
const maxParamDescriptionDepth = 64

// paramDescriptionOverflowKey is the reserved key recorded when recursion exceeds
// maxParamDescriptionDepth. Its leading control byte cannot collide with a JSON
// Schema property name or pointer path, so an honest schema never produces it; its
// presence forces a distinct ComputeToolHash, failing closed on an over-deep schema.
const paramDescriptionOverflowKey = "\x00depth-exceeded"

// paramRootDescriptionKey is the reserved key under which the root inputSchema's own
// "description" is recorded. Like paramDescriptionOverflowKey it leads with a 0x00
// control byte, so it can never collide with a framed path (which always begins with a
// 'K'/'N'/'i' segment tag) nor with the overflow key (which trails "depth-exceeded").
// The root description is model-facing — hosts forward inputSchema to the model and a
// top-level "description" on it is rendered like any property description — so leaving
// it out of the hash would let an upstream rug-pull it (FM-5) without moving the pin.
const paramRootDescriptionKey = "\x00root-description"

// toolTitleKey and toolAnnotationsKey are the reserved keys under which a tool's
// model-facing top-level title and annotations object are folded into the hash by
// ToolHashParams. Like the other reserved keys they lead with a 0x00 control byte and
// carry a distinct suffix, so they can never collide with a framed param path (which
// begins with a 'K'/'N'/'i' tag) nor with the root/overflow keys. Both are rendered to
// the host model by common clients, so leaving them unpinned would let an upstream
// rug-pull them (FM-5) without moving the pin.
const (
	toolTitleKey       = "\x00tool-title"
	toolAnnotationsKey = "\x00tool-annotations"
)

// outputSchemaKeyPrefix namespaces every key ParamDescriptions returns for a tool's
// outputSchema before ToolHashParams folds it into the combined map, so an
// outputSchema description can never collide with an inputSchema description at the
// same relative path (e.g. both schemas independently having a top-level
// properties.foo) — a collision would let one silently mask the other in the map
// (Go map last-write-wins), hiding an FM-5 rug-pull in whichever schema lost the
// collision. Like the other reserved keys it leads with a 0x00 control byte (never
// producible by a framed path, which always begins with a 'K'/'N'/'i' tag) and a
// distinct literal suffix, so it cannot collide with paramRootDescriptionKey,
// paramDescriptionOverflowKey, toolTitleKey, or toolAnnotationsKey either. Prefixing
// (not just tagging) every outputSchema-derived key preserves ParamDescriptions'
// own injectivity guarantee: since the prefix is a fixed string, two distinct
// outputSchema keys remain distinct after prefixing.
const outputSchemaKeyPrefix = "\x00output-schema:"

// Segment kind tags for the framed path encoding (see frameSeg). They are distinct
// ASCII bytes and never 0x00, so a framed path can never collide with
// paramDescriptionOverflowKey (which leads with 0x00).
const (
	segKeyword = 'K' // a JSON Schema keyword that nests a subschema; payload = keyword name
	segName    = 'N' // a named entry within a map-valued keyword (e.g. a property name); payload = the name
	segIndex   = 'i' // an index within an array-valued keyword (tuple element / combinator branch); payload = decimal index
)

// JSON Schema keywords whose value nests one or more subschemas, grouped by shape. The
// walk visits EVERY subschema-valued keyword the spec defines, not a hand-picked few,
// so a model-facing "description" anywhere in the inputSchema enters the hash; a keyword
// omitted from this set would be a silent FM-5 rug-pull hiding place. "items" is handled
// separately because it has a dual shape (a single subschema, or a legacy tuple array).
var (
	// name -> subschema. "dependencies" is the draft-07 predecessor of
	// "dependentSchemas": its values are EITHER a subschema (schema dependency) OR an
	// array of property names (property dependency); the per-entry map type-assertion
	// in the walk recurses into the schema form and skips the array form, so a poisoned
	// description buried under a draft-07 schema dependency is still pinned.
	schemaMapKeywords = []string{"properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies"}
	// an ordered list of subschemas.
	schemaArrayKeywords = []string{"allOf", "anyOf", "oneOf", "prefixItems"}
	// a single subschema (a boolean form, e.g. additionalProperties:false, carries no
	// description and is skipped by the map type-assertion below).
	schemaSingleKeywords = []string{
		"additionalProperties", "unevaluatedProperties", "additionalItems", "unevaluatedItems",
		"propertyNames", "contains", "not", "if", "then", "else", "contentSchema",
	}
)

// frameSeg appends one unambiguously-framed segment to a path key: a 1-byte kind tag, an
// 8-byte big-endian length, then the segment bytes. Tag+length prefixing makes the
// concatenation INJECTIVE, so a property literally named "$defs" or "a.b" can never collide
// with a synthesized segment — load-bearing for FM-5, since a map-key collision would let
// one description silently overwrite another (Go map last-write-wins).
func frameSeg(prefix string, tag byte, seg string) string {
	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(seg)))
	return prefix + string(tag) + string(lenbuf[:]) + seg
}

// ParamDescriptions extracts every model-facing description string from a JSON Schema
// inputSchema, keyed by a canonical, collision-free path. It recurses through EVERY
// subschema-valued keyword the spec defines (see the schema*Keywords tables), plus the root
// schema's own "description" (under paramRootDescriptionKey), so nothing is left as an
// unwalked FM-5 rug-pull hiding place. Paths are built from frameSeg segments rather than a
// dotted string, so a property literally named "$defs" or "a.b" cannot collide with a
// synthesized path.
//
// Entries without a (string, non-empty) description are omitted; returns an empty, non-nil
// map when the schema carries none. Recursion is depth-bounded
// (maxParamDescriptionDepth); past it, records paramDescriptionOverflowKey and stops rather
// than silently dropping the unpinned tail. Shared by the drift check, the runtime PDP, and
// `init` so they pin and verify identical input.
func ParamDescriptions(inputSchema map[string]interface{}) map[string]string {
	out := map[string]string{}
	// The root inputSchema object has no keyword pointing at it, so collectParam-
	// Descriptions (which keys a description by the location that points at its node)
	// never records the root's own "description". Record it here under the reserved
	// root key so this top-level model-facing string is pinned like any nested one.
	if d, ok := inputSchema["description"].(string); ok && d != "" {
		out[paramRootDescriptionKey] = d
	}
	collectParamDescriptions(inputSchema, "", 0, out)
	return out
}

// collectParamDescriptions walks node, recording each description string under its
// canonical framed path. prefix is the path accumulated so far (empty at the root). It
// visits every subschema-valued JSON Schema keyword (the three schema*Keywords tables
// plus the dual-shaped "items"), keying each location by the keyword name (and the
// entry name or index within it) so two distinct locations never collide and every
// keyword is covered. The node's own "description" is NOT recorded here — a description
// belongs to the location that POINTS at the node, which the caller (recordChildSchema,
// or ParamDescriptions for the root via paramRootDescriptionKey) has already keyed;
// this avoids double-counting.
func collectParamDescriptions(node map[string]interface{}, prefix string, depth int, out map[string]string) {
	if depth > maxParamDescriptionDepth {
		// Fail closed: stop descending and force a distinct hash rather than silently
		// truncating the pinned description surface on a pathologically deep schema.
		out[paramDescriptionOverflowKey] = "depth-exceeded"
		return
	}

	// Map-valued keywords (name -> subschema): keyed by keyword then entry name. The
	// keyword frame keeps independent sections distinct — e.g. "$defs" and "definitions"
	// (legal aliases that may coexist), or a property literally named "$defs" vs the
	// real $defs section — so a poisoned description can never be masked by a benign
	// sibling under a colliding key (an FM-5 bypass).
	for _, kw := range schemaMapKeywords {
		m, ok := node[kw].(map[string]interface{})
		if !ok {
			continue
		}
		for name, raw := range m {
			if sub, ok := raw.(map[string]interface{}); ok {
				key := frameSeg(frameSeg(prefix, segKeyword, kw), segName, name)
				recordChildSchema(sub, key, depth+1, out)
			}
		}
	}

	// Array-valued keywords ([]subschema): keyed by keyword then index, so order is
	// preserved and branches stay distinct.
	for _, kw := range schemaArrayKeywords {
		arr, ok := node[kw].([]interface{})
		if !ok {
			continue
		}
		for i, raw := range arr {
			if sub, ok := raw.(map[string]interface{}); ok {
				key := frameSeg(frameSeg(prefix, segKeyword, kw), segIndex, strconv.Itoa(i))
				recordChildSchema(sub, key, depth+1, out)
			}
		}
	}

	// Single-subschema keywords (value is itself a schema; a boolean form has no
	// description and is skipped by the map type-assertion).
	for _, kw := range schemaSingleKeywords {
		if sub, ok := node[kw].(map[string]interface{}); ok {
			recordChildSchema(sub, frameSeg(prefix, segKeyword, kw), depth+1, out)
		}
	}

	// "items": either a single subschema (applies to all elements) or a legacy tuple
	// array. Handled here rather than in the tables because of its dual shape.
	switch items := node["items"].(type) {
	case map[string]interface{}:
		recordChildSchema(items, frameSeg(prefix, segKeyword, "items"), depth+1, out)
	case []interface{}:
		for i, raw := range items {
			if im, ok := raw.(map[string]interface{}); ok {
				key := frameSeg(frameSeg(prefix, segKeyword, "items"), segIndex, strconv.Itoa(i))
				recordChildSchema(im, key, depth+1, out)
			}
		}
	}
}

// recordChildSchema records a child schema's own "description" (keyed by path) and
// then recurses into it. Used for every subschema-valued keyword location, whose
// description belongs to the child schema the keyword points at.
func recordChildSchema(node map[string]interface{}, path string, depth int, out map[string]string) {
	if depth > maxParamDescriptionDepth {
		out[paramDescriptionOverflowKey] = "depth-exceeded"
		return
	}
	if d, ok := node["description"].(string); ok && d != "" {
		out[path] = d
	}
	collectParamDescriptions(node, path, depth, out)
}

// IsExactTool reports whether c targets a single, exact-name tool: a tool: target
// with no glob metacharacters. Per-tool pins that cannot represent a whole glob's
// fan-out — descriptionHash (FM-5) and structural argumentSchema drift (FM-6) —
// apply only to exact tools: a glob's single argumentSchema or hash cannot
// meaningfully stand for every tool the glob matches.
func (c *Constraint) IsExactTool() bool {
	if c == nil {
		return false
	}
	tt, name, err := ParseTarget(c.Target)
	if err != nil || tt != TargetTypeTool {
		return false
	}
	// A glob target (path.Match metacharacters) is not an exact tool name.
	return !ContainsGlobMeta(name)
}

// IsPinnedExactTool reports whether c is an exact-name tool: constraint carrying a
// non-empty descriptionHash — the only combination for which descriptionHash
// verification applies. It also guards constraints built programmatically, which
// bypass the loader's rejection of descriptionHash on glob and non-tool: targets.
func (c *Constraint) IsPinnedExactTool() bool {
	return c != nil && c.DescriptionHash != "" && c.IsExactTool()
}
