// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package config holds the binary's configuration and manifest loading layer: LocalManifest's
// load/validate/merge path, the GatewayConfig parser, and the schema-version negotiation both
// documents share. Depends only on pkg/*, gopkg.in/yaml.v3, and the stdlib — never on
// cmd/eunox — so the CLI subcommands and the transport layer can import from a non-main home.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	stdpath "path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// maxManifestFileBytes bounds a manifest file read against a misdirected path (a
// fat-fingered flag pointed at a data file or disk image) that would otherwise be
// buffered whole before the strict decode could reject it — an OOM where an error
// belongs. Generous relative to a real manifest (typically tens of KB even with hundreds
// of capability entries).
const maxManifestFileBytes = 32 << 20

// LocalManifest declares the capabilities an agent requires.
type LocalManifest struct {
	// SchemaVersion is the manifest grammar/dialect version (e.g. "0.1"), distinct from
	// the policy-content Version below. Required; refused at load if absent/unsupported.
	SchemaVersion string                  `json:"schemaVersion"`
	Name          string                  `json:"name"`
	Version       string                  `json:"version"`
	Description   string                  `json:"description,omitempty"`
	ServerVersion string                  `json:"serverVersion,omitempty"`
	Capabilities  []capability.Constraint `json:"capabilities"`
	// Audience, when set, pins the JWT 'aud' claim required on THIS route in gateway mode,
	// overriding the global --jwt-audience for the route. See WrapRoutesWithJWT and
	// internal/pdp/jwt.go. On a multi-file merge it is folded with a conflict check
	// (first non-empty wins; disagreeing files are rejected), like serverVersion.
	Audience string `json:"audience,omitempty"`
	// EffectCeiling is the tool-agnostic consequence bound EVERY allowed action is
	// additionally checked against, keyed on the action's effect properties rather than
	// which tool it is. It can only narrow (it runs after a constraint has already
	// allowed the call). Merged with the same conflict check as Audience/serverVersion.
	EffectCeiling *capability.EffectCeiling `json:"effectCeiling,omitempty"`
	// FlowLabelNamespaces declares the external sensitivity taxonomies this policy speaks —
	// the namespace half of an imported "namespace:value" flow label (Purview/MSIP/BigID).
	// eunox owns the algebra and never the taxonomy, so the VALUES stay open; declaring the
	// namespace is the closure it can still honestly own, which is what turns a misspelled
	// taxonomy name into a load error rather than a label that silently matches nothing.
	//
	// Merged as a UNION rather than with Audience's conflict check: declaring a namespace
	// grants nothing on its own (it only permits labels naming it), so two files each
	// declaring their own compose, where a conflict check would reject the composition.
	FlowLabelNamespaces []string `json:"flowLabelNamespaces,omitempty"`
}

// LoadManifest reads and validates a LocalManifest from a manifest file of any extension
// (YAML, JSON, or none). Every file is decoded through a yaml.Node first (YAML is a JSON
// superset) so the fail-closed hardening — duplicate-key rejection, multi-document rejection,
// timestamp guard, scalar-coercion guard — applies uniformly rather than an
// unrecognized/absent extension falling through to a guard-skipping bare json.Unmarshal. The
// node is then converted to JSON so capability.Constraint's polymorphic JSON unmarshalling is
// reused unchanged.
func LoadManifest(path string) (*LocalManifest, error) {
	data, err := ReadBoundedFile(BoundedRead{
		Path:      path,
		What:      "manifest",
		Max:       maxManifestFileBytes,
		OverLimit: "refusing to buffer it rather than parsing a manifest that cannot be one",
	})
	if err != nil {
		return nil, err
	}
	if err := errIfBinaryConfig("manifest", path, data); err != nil {
		return nil, err
	}

	lp := strings.ToLower(path)
	// Route EVERY manifest — YAML, JSON, or an unrecognized/absent extension — through the
	// yaml.Node decode below: node.Decode rejects DUPLICATE mapping keys and multi-document
	// streams where encoding/json silently keeps the last value, a fail-closed gap on a
	// security-critical surface. isJSON selects the numeric-coercion policy: JSON rejects only
	// a numerically lossy coercion, YAML rejects any auto-typing. Content detection (not just
	// extension) keeps an extensionless JSON manifest's non-canonical numbers accepted.
	isYAMLExt := strings.HasSuffix(lp, ".yaml") || strings.HasSuffix(lp, ".yml")
	isJSON := strings.HasSuffix(lp, ".json") || (!isYAMLExt && json.Valid(data))
	what := "YAML manifest"
	if isJSON {
		what = "JSON manifest"
	}
	// A .json-EXTENSION file must be valid JSON: yaml.v3 also accepts the YAML SUPERSET
	// (unquoted keys, single-quoted strings, # comments), which would silently admit a .json
	// file that strict JSON rejects. A content-detected JSON file needs no recheck.
	if strings.HasSuffix(lp, ".json") && !json.Valid(data) {
		return nil, fmt.Errorf("parsing JSON manifest %q: content is not valid JSON", path)
	}
	// Decode into a yaml.Node (not interface{}) so we can suppress yaml.v3's timestamp
	// inference before the JSON round-trip: an unquoted 2026-01-01 would otherwise become
	// "2026-01-01T00:00:00Z". See forceTimestampsToStrings.
	var node yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&node); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty document decodes to a zero node; leave it for the
			// Kind==0 branch below to treat as nil.
			node = yaml.Node{}
		} else {
			return nil, fmt.Errorf("parsing %s %q: %w", what, path, err)
		}
	}
	// Reject a multi-document stream: a second content-bearing "---" document would be
	// silently ignored. A trailing empty/null document is tolerated.
	if err := rejectExtraYAMLDocuments(dec, path, what); err != nil {
		return nil, err
	}
	// Flatten YAML merge keys before anything reads the document as WRITTEN: every walk below
	// scans a mapping for a LITERAL key, which a `<<:`-merged one does not have, while the
	// decode that produces the enforced policy sees it perfectly well. See resolveMergeKeys.
	resolveMergeKeys(&node)
	// Gate on the declared grammar version FIRST, before any guard that INTERPRETS the
	// content: the scalar-coercion guard below reads condition values under the 0.1 grammar,
	// so a manifest declaring a future version would otherwise be reported as a scalar that
	// must be quoted rather than an unsupported dialect.
	if v, ok := schemaVersionFromNode(&node); ok {
		if err := validateManifestSchemaVersion(v); err != nil {
			return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
		}
	}
	forceTimestampsToStrings(&node)
	forceSchemaVersionToString(&node)
	// Reject a scalar in a condition values:/enum: list that auto-typed away from its source
	// text (YAML: 010 -> 8 octal, 1.0 -> 1 float; JSON: a beyond-float64 integer rounds),
	// which would otherwise silently enforce a value the author did not write.
	if err := rejectCoercedScalarsForFormat(&node, isJSON, path); err != nil {
		return nil, err
	}
	var raw interface{}
	if node.Kind != 0 { // a zero Kind means an empty document; leave raw nil
		if err := node.Decode(&raw); err != nil {
			return nil, fmt.Errorf("parsing %s %q: %w", what, path, err)
		}
	}
	if data, err = json.Marshal(raw); err != nil {
		return nil, fmt.Errorf("converting manifest to JSON: %w", err)
	}

	// Gate on the declared grammar version FIRST, before interpreting any content: without
	// this, a manifest declaring a future version could be reported as carrying an "unknown
	// key" that is valid in the dialect it declares, burying the real diagnostic.
	var version struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(data, &version); err != nil {
		return nil, fmt.Errorf("parsing manifest %q: %w", path, err)
	}
	if err := validateManifestSchemaVersion(version.SchemaVersion); err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	// Then the recursive unknown-key check, BEFORE the typed decode: only this one names
	// the offending path and offers a "did you mean" suggestion.
	if err := checkManifestKeys(data); err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	var m LocalManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest %q: %w", path, err)
	}
	// Canonicalize to the trimmed form validation accepted: the padding of an explicitly
	// quoted " 0.1" would otherwise survive into MergeManifests' exact-string conflict check.
	m.SchemaVersion = strings.TrimSpace(m.SchemaVersion)
	if err := validateLocalManifest(&m); err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	return &m, nil
}

// rejectCoercedScalarsForFormat runs the scalar-coercion guard for both formats. YAML rejects
// any scalar whose canonical form differs textually from its source (010 -> 8, 1.0 -> 1); JSON
// rejects only a NUMERICALLY lossy coercion (an integer beyond float64 precision that
// node.Decode rounds), since a plain 1.0 -> 1 textual difference is harmless there.
func rejectCoercedScalarsForFormat(node *yaml.Node, isJSON bool, path string) error {
	if err := rejectCoercedValueScalars(node, isJSON); err != nil {
		return fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	return nil
}

// topLevelValueNode returns the value node of a top-level mapping key, unwrapping a
// DocumentNode wrapper first. Shared by schemaVersionFromNode and forceSchemaVersionToString.
//
// The value is resolved through its ALIAS, for the same reason the coercion guard resolves
// one: an `*ref` node carries no Value of its own, so both callers read it as absent. That
// made an aliased schemaVersion falsely "required" in the gateway loader, and made the
// manifest loader skip the pre-decode version gate entirely — producing exactly the coercion
// misdiagnosis the gate's ordering exists to prevent, for a document that declares its
// version perfectly well.
func topLevelValueNode(node *yaml.Node, key string) *yaml.Node {
	mapping, i := topLevelValueSlot(node, key)
	if mapping == nil {
		return nil
	}
	return resolveYAMLAlias(mapping.Content[i])
}

// topLevelValueSlot is topLevelValueNode's core, returning the mapping and the INDEX of key's
// value rather than the value itself — the position, not the node.
//
// The distinction is load-bearing for forceSchemaVersionToString: an alias node's target is
// SHARED with every other reference to that anchor, so a caller that means to change this one
// key's value has to replace what sits in this slot rather than mutate what the slot points
// at. A reader wants the resolved node and uses topLevelValueNode; a writer wants the slot.
func topLevelValueSlot(node *yaml.Node, key string) (mapping *yaml.Node, valueIdx int) {
	doc := resolveYAMLAlias(node)
	if doc == nil {
		return nil, -1
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = resolveYAMLAlias(doc.Content[0])
	}
	if doc == nil || doc.Kind != yaml.MappingNode {
		return nil, -1
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		k := resolveYAMLAlias(doc.Content[i])
		if k != nil && k.Kind == yaml.ScalarNode && k.Value == key {
			return doc, i + 1
		}
	}
	return nil, -1
}

// schemaVersionFromNode reads the top-level schemaVersion scalar's SOURCE TEXT off the parsed
// document, reporting whether the key was present as a scalar. Reads Value, so it is
// independent of the !!int/!!float retag forceSchemaVersionToString applies.
func schemaVersionFromNode(node *yaml.Node) (string, bool) {
	val := topLevelValueNode(node, "schemaVersion")
	if val == nil || val.Kind != yaml.ScalarNode {
		return "", false
	}
	return val.Value, true
}

// forceSchemaVersionToString retags an unquoted top-level `schemaVersion` scalar to !!str so
// the natural `schemaVersion: 0.1` (auto-typed as a float by yaml.v3) decodes as the string
// "0.1" instead of failing with an opaque "cannot unmarshal number into ... string" before
// validateManifestSchemaVersion can emit its friendly message. The gateway-config loader
// cannot do this (it decodes strictly from raw bytes for KnownFields) and instead rejects a
// bare-number schemaVersion outright. Retagging keeps the verbatim text, so "0.10" stays
// "0.10" rather than renormalizing to "0.1".
//
// An ALIASED `schemaVersion: *ver` is retagged by REPLACING this key's slot with a fresh string
// scalar, never by retagging the anchor. An anchor is shared with every other reference to it,
// so mutating it silently rewrites fields this function has no business touching — and one of
// them changes POLICY, not just type.
//
// With `values: [&ver 0.2]` beside `schemaVersion: *ver`, retagging the anchor decoded that
// condition's value as a Go string rather than the json.Number every other numeric spelling
// yields. MatchAllowedValue matches a string entry ONLY as a glob and only against a string
// argument, so the entry stopped matching the numeric argument it was written for: the
// capability silently denied every call it was meant to allow, with no load-time signal.
// Deny-side, but a policy change from a retag that had no business leaving this key.
//
// Copying also leaves the anchor's own tag intact for rejectCoercedScalarsForFormat, which runs
// after this and would otherwise skip a node this function had already rewritten.
func forceSchemaVersionToString(node *yaml.Node) {
	mapping, i := topLevelValueSlot(node, "schemaVersion")
	if mapping == nil {
		return
	}
	slot := mapping.Content[i]
	val := resolveYAMLAlias(slot)
	if val == nil || val.Kind != yaml.ScalarNode || (val.Tag != "!!int" && val.Tag != "!!float") {
		return
	}
	if slot == val {
		// Written directly under this key, so nothing else can be looking at it.
		val.Tag = "!!str"
		return
	}
	// Position from the ALIAS, so a later error about this value points at the reference the
	// author wrote rather than at the anchor's definition somewhere else in the file.
	mapping.Content[i] = &yaml.Node{
		Kind:   yaml.ScalarNode,
		Tag:    "!!str",
		Value:  val.Value,
		Line:   slot.Line,
		Column: slot.Column,
	}
}

// forceTimestampsToStrings retags every !!timestamp scalar to !!str so the subsequent
// node.Decode yields the literal text rather than a time.Time, stopping unquoted manifest
// dates from being rewritten to RFC3339 across the YAML->JSON conversion.
func forceTimestampsToStrings(n *yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!timestamp" {
		n.Tag = "!!str"
	}
	for _, child := range n.Content {
		forceTimestampsToStrings(child)
	}
}

// rejectCoercedValueScalars walks n and rejects any unquoted scalar in a condition "values:"
// (allowedValues) or argumentSchema "enum:" list that YAML auto-typed away from its written
// text (leading-zero octal, decimal-pointed float, …), making the manifest enforce a value
// that differs from its own source with no load-time signal. Rather than retag (which would
// turn a legitimately numeric allowlist entry into a string the engine could no longer
// match), this fails closed and forces the author to disambiguate.
// numericPolicyScalarKeys are policy fields holding a bare numeric scalar (not a values:/enum:
// list) with the identical coercion risk, e.g. `maxCalls: {windowSeconds: 0600}` silently
// loading as 384.
var numericPolicyScalarKeys = map[string]bool{
	"count":         true, // maxCalls
	"windowSeconds": true, // maxCalls
	"minimum":       true, // argumentSchema
	"maximum":       true, // argumentSchema
	"minLength":     true, // argumentSchema
	"maxLength":     true, // argumentSchema
	"minItems":      true, // argumentSchema
	"maxItems":      true, // argumentSchema
}

// scopedNumericPolicyScalarKeys are the effect layer's numeric bounds, which carry the
// identical coercion risk but whose SPELLINGS are generic ("max", "value"). Keyed by the
// block they must appear in, since a bare-name match would also reject an opaque
// `policy`/`custom` condition payload the engine does not itself enforce.
var scopedNumericPolicyScalarKeys = map[string]map[string]bool{
	"blastRadius":   {"value": true},                 // effect contract's / a byArgument case's magnitude
	"conditions":    {"max": true, "maxTotal": true}, // the blastRadius condition's per-call and cumulative bounds
	"effectCeiling": {"maxBlastRadius": true},        // the top-level ceiling's magnitude bound
}

// numericPolicyScalarKeyApplies reports whether key names an enforced number at this point in
// the document: an unscoped policy field, or a scoped one sitting in its own block.
func numericPolicyScalarKeyApplies(enclosingKey, key string) bool {
	if numericPolicyScalarKeys[key] {
		return true
	}
	return scopedNumericPolicyScalarKeys[enclosingKey][key]
}

func rejectCoercedValueScalars(n *yaml.Node, isJSON bool) error {
	return rejectCoercedScalarsUnder(n, isJSON, "", make(map[coercionVisit]bool))
}

// coercionVisit keys the walk's visited set. The KEY is part of it, not just the node: an
// anchored mapping is checked once per enclosing key it is referenced under, because the
// enclosing key is what decides whether a numeric field applies there. Keying on the node
// alone would check `&a {value: 010}` at whichever reference the walk reached first and skip
// it under `effect: {blastRadius: *a}`; keying on nothing (visit-and-forget) makes a
// billion-laughs alias graph expand exponentially. Node x key is bounded by the document.
type coercionVisit struct {
	node *yaml.Node
	key  string
}

// isYAMLMergeKey reports whether k merges another mapping's pairs into the enclosing one.
// It restates yaml.v3's own isMerge (value "<<" under a plain, "!" or "!!merge" tag) so this
// walk and the decode that produces the enforced policy agree about what a merge is: a quoted
// "<<" is a literal key there, and checking its pairs as merged ones would refuse a coerced
// number under a key the loader's own key check is what reports.
func isYAMLMergeKey(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.Value == "<<" &&
		(k.Tag == "" || k.Tag == "!" || k.Tag == "!!merge")
}

// rejectCoercedScalarsUnder is rejectCoercedValueScalars' walk, carrying the mapping key the
// current node hangs off so a scoped numeric key is recognized only inside its own block.
//
// An ALIAS is resolved here, not only at the pairwise checks below: an aliased MAPPING was
// otherwise descended into as an AliasNode, whose Content is empty, so its fields were
// checked only at the anchor's definition site — under whatever key sat there, which is not
// the key that decides whether they are numeric policy fields.
func rejectCoercedScalarsUnder(n *yaml.Node, isJSON bool, enclosingKey string, visited map[coercionVisit]bool) error {
	n = resolveYAMLAlias(n)
	if n == nil {
		return nil
	}
	if v := (coercionVisit{node: n, key: enclosingKey}); visited[v] {
		return nil
	} else {
		visited[v] = true
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			// Follow an alias on the key too (`&vk values` referenced as `*vk: [010]`) and
			// on the value, so `values: *ref` cannot smuggle a coerced scalar past the check.
			key = resolveYAMLAlias(key)
			val = resolveYAMLAlias(val)
			switch {
			case key.Kind == yaml.ScalarNode && (key.Value == "values" || key.Value == "enum") && val.Kind == yaml.SequenceNode:
				// One visited-set per list bounds a self-referential anchor (values: &loop
				// [*loop]) and collapses a billion-laughs-style alias graph to linear time.
				seen := make(map[*yaml.Node]bool)
				for _, item := range val.Content {
					if err := checkValueScalarNotCoerced(item, key.Value, isJSON, seen); err != nil {
						return err
					}
				}
			case key.Kind == yaml.ScalarNode && numericPolicyScalarKeyApplies(enclosingKey, key.Value) && val.Kind == yaml.ScalarNode:
				if err := checkNumericFieldNotCoerced(val, key.Value, isJSON); err != nil {
					return err
				}
			}
		}
		// Recurse pairwise so each value carries the key it hangs off; a key node is walked
		// too, with no enclosing key.
		for i := 0; i+1 < len(n.Content); i += 2 {
			if err := rejectCoercedScalarsUnder(n.Content[i], isJSON, "", visited); err != nil {
				return err
			}
			if err := rejectCoercedScalarsUnder(n.Content[i+1], isJSON, childKeyFor(n.Content[i], enclosingKey), visited); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range n.Content {
		if err := rejectCoercedScalarsUnder(child, isJSON, enclosingKey, visited); err != nil {
			return err
		}
	}
	return nil
}

// childKeyFor is the enclosing key rejectCoercedScalarsUnder walks a mapping value under.
//
// A merged mapping's pairs belong to the mapping that merges them, so they carry that
// mapping's own key: walked under "<<" they sat outside every scoped table, and
// `conditions: [{type: blastRadius, <<: &s {max: 010}}]` loaded enforcing 8 where the inline
// spelling is refused. The sequence form (`<<: [*a, *b]`) inherits it, that branch
// propagating the enclosing key on.
//
// resolveMergeKeys normally splices those pairs in before this walk runs, so what is left for
// this branch is the merge that pass deliberately does NOT flatten — one whose value or keys it
// cannot reproduce the decoder's precedence for. That document is refused a few lines later, but
// not by this guard, so the branch still has to check under the right key rather than under
// none.
//
// Every other key is canonicalized to "" unless it scopes a numeric field, because the key is
// half of the visited set: keeping the whole vocabulary re-walks a shared anchor once per key
// it is reachable under, which the merge inheritance turns from a fan-out into a chain — a
// 15 KB document of merged anchors took 126 ms. Sound because the key is read for nothing
// else: numericPolicyScalarKeyApplies indexes scopedNumericPolicyScalarKeys with it, and the
// values:/enum: branch ignores it.
func childKeyFor(keyNode *yaml.Node, enclosingKey string) string {
	k := resolveYAMLAlias(keyNode)
	if k == nil || k.Kind != yaml.ScalarNode {
		return ""
	}
	if isYAMLMergeKey(k) {
		return enclosingKey
	}
	if _, scoped := scopedNumericPolicyScalarKeys[k.Value]; !scoped {
		return ""
	}
	return k.Value
}

// resolveYAMLAlias returns the node an alias points at (its anchored target), or n
// unchanged when it is not an alias. The coercion guard must inspect the anchored scalar,
// not the AliasNode itself, so a value written as `*ref` cannot bypass the check.
func resolveYAMLAlias(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

// checkValueScalarNotCoerced rejects a single values:/enum: scalar that YAML auto-typed to a
// number whose canonical form differs from the author's source text. A quoted/block scalar is
// an explicit string and is left alone; only an unquoted !!int/!!float is at risk.
//
// seen is a visited set of *yaml.Node that guards the alias walk: a self-referential anchor
// (values: &loop [*loop]) previously recursed until the stack overflowed — an uncatchable
// fatal error. The same guard collapses a billion-laughs-style alias graph to linear time.
func checkValueScalarNotCoerced(item *yaml.Node, listKey string, isJSON bool, seen map[*yaml.Node]bool) error {
	if item == nil || seen[item] {
		return nil
	}
	seen[item] = true
	if item.Kind == yaml.AliasNode {
		// A list element written as an alias resolves to its anchored scalar, which is what
		// node.Decode enforces — check that. Gated on Kind == AliasNode rather than a bare
		// resolveYAMLAlias call, or every plain node would look "already seen" on first visit.
		item = resolveYAMLAlias(item)
		if item == nil || seen[item] {
			return nil
		}
		seen[item] = true
	}
	// A nested sequence or mapping element (e.g. `values: [[010]]`) is not itself a scalar,
	// but its children carry the same coercion risk one level down; the outer recursion
	// does not re-apply this check to them, so descend here. For a mapping this also walks
	// the keys, since a coerced numeric key is the same silent-drift class.
	if item.Kind == yaml.SequenceNode || item.Kind == yaml.MappingNode {
		for _, child := range item.Content {
			if err := checkValueScalarNotCoerced(child, listKey, isJSON, seen); err != nil {
				return err
			}
		}
		return nil
	}
	src, canonical, coerced, ok := scalarCoercion(item)
	if !ok || !coerced {
		return nil
	}
	// YAML: any textual difference is a silent auto-typing to reject. JSON: only a
	// numerically-lossy coercion is (coercionError/numericallyEqual).
	return coercionError("entry", listKey, false, item, src, canonical, isJSON)
}

// scalarCoercion reports whether item is a plain (unquoted) !!int/!!float scalar whose
// YAML-decoded value differs textually from its source text — the shared coercion-detection
// core for checkValueScalarNotCoerced and checkNumericFieldNotCoerced.
func scalarCoercion(item *yaml.Node) (src, canonical string, coerced, ok bool) {
	if item.Kind != yaml.ScalarNode || item.Style != 0 {
		return "", "", false, false
	}
	if item.Tag != "!!int" && item.Tag != "!!float" {
		return "", "", false, false
	}
	var v interface{}
	if err := item.Decode(&v); err != nil {
		return "", "", false, false
	}
	c, err := json.Marshal(v)
	if err != nil {
		return "", "", false, false
	}
	src = strings.TrimSpace(item.Value)
	canonical = string(c)
	return src, canonical, src != canonical, true
}

// CanonicalNumberLiteral returns the spelling a numeric literal ends up with after the
// manifest loader's YAML-node -> interface{} -> JSON renormalization above, whether that
// spelling denotes the SAME number, and whether lit is a number that pipeline reads as one
// at all.
//
// Exported because a REGISTRY corpus entry is copied into a manifest verbatim and pinned by
// the digest of its own bytes: the corpus loader decodes with UseNumber and keeps the
// literal, this loader re-marshals it, so a literal whose spelling does not survive the
// round trip (1.0 -> 1, 1e3 -> 1000) digests to two different values and the copy can never
// match its pin. The renormalization is this file's, so the answer about what survives it
// has to be this file's too — a second implementation elsewhere would be a place for the
// two to disagree about exactly the literals that matter.
//
// exact is reported separately because a renormalization that ROUNDS (an integer past
// float64's exact range) has no faithful spelling at all: naming its canonical form as the
// correction to write would hand the author a different magnitude than the one they
// declared, which for a blast radius is the input to the ceiling and the cumulative bound.
func CanonicalNumberLiteral(lit string) (canonical string, exact, ok bool) {
	var v interface{}
	if err := yaml.Unmarshal([]byte(lit), &v); err != nil {
		return "", false, false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", false, false
	}
	// The LAST step of the pipeline decides, not the yaml kind: the field is a json.Number,
	// and encoding/json accepts a quoted literal into one. So a scalar yaml.v3 declined to
	// resolve as a number (an exponent past float64's range, which its ParseFloat reports
	// out of range and it leaves a plain string) is re-marshaled quoted and reaches the
	// policy VERBATIM — pinnable, where reading the yaml kind alone called it unusable.
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return "", false, false
	}
	if n.String() == "" {
		// A JSON null unmarshals into a string kind by leaving it untouched rather than
		// failing, so an empty or null scalar arrives here looking like a canonical form.
		return "", false, false
	}
	if n.String() == lit {
		// Identical spelling needs no arbitrary-precision comparison, which is the only
		// expensive step here and is what a large literal would pay it on.
		return lit, true, true
	}
	return n.String(), numericallyEqual(lit, n.String()), true
}

// numericallyEqual reports whether src and canonical denote the same number, compared exactly
// via big.Rat so a beyond-float64-precision integer is judged correctly.
func numericallyEqual(src, canonical string) bool {
	srcRat, ok1 := new(big.Rat).SetString(src)
	canRat, ok2 := new(big.Rat).SetString(canonical)
	return ok1 && ok2 && srcRat.Cmp(canRat) == 0
}

// coercionError builds the "this literal number was silently coerced" error shared by
// checkValueScalarNotCoerced (kind "entry") and checkNumericFieldNotCoerced (kind "value"),
// so the two message shapes cannot drift. For JSON, only a numerically-lossy coercion is
// rejected; for YAML any textual difference is (scalarCoercion already confirmed one exists).
func coercionError(kind, label string, forField bool, item *yaml.Node, src, canonical string, isJSON bool) error {
	valueNoun, yamlSuffix := "the value", ""
	if forField {
		valueNoun, yamlSuffix = "the enforced value", " and would silently change the enforced policy"
	}
	if isJSON {
		if numericallyEqual(src, canonical) {
			return nil
		}
		return fmt.Errorf("%s %s %s is a number beyond float64 precision that decodes to %s, silently changing %s; write %s, or quote it (%q) to mean the string",
			label, kind, src, canonical, valueNoun, canonical, src)
	}
	return fmt.Errorf("%s %s %q is an unquoted YAML number that parses to %s, which differs from the text written%s; quote it (\"%s\") to mean the string, or write %s to mean the number",
		label, kind, item.Value, canonical, yamlSuffix, item.Value, canonical)
}

// checkNumericFieldNotCoerced rejects a bare numeric policy field (see
// numericPolicyScalarKeys) whose YAML auto-typed value differs textually from its source —
// the same coercion class checkValueScalarNotCoerced catches, but changing an enforced
// number rather than an allowlist entry.
func checkNumericFieldNotCoerced(item *yaml.Node, fieldName string, isJSON bool) error {
	item = resolveYAMLAlias(item)
	src, canonical, coerced, ok := scalarCoercion(item)
	if !ok || !coerced {
		return nil
	}
	return coercionError("value", fieldName, true, item, src, canonical, isJSON)
}

// MergeManifests combines the Capabilities lists from all manifests.
//
// Pure-metadata fields (name, version, description) are inherited from the first manifest,
// since none feeds enforcement or drift. Single-value fields that DO — serverVersion,
// schemaVersion, audience — are folded instead: first non-empty wins, two conflicting
// non-empty values are rejected, so a later file's pin cannot be silently dropped.
//
// The merge is likewise rejected when two capabilities from DIFFERENT files tie in the
// engine's equal-specificity selection, whose declaration-order tie-break would silently
// shadow the later one. See detectMergeConflicts.
func MergeManifests(ms []*LocalManifest) (*LocalManifest, error) {
	if len(ms) == 0 {
		// Zero capabilities ⟹ deny everything; the empty sentinel has no name, so it
		// skips validateLocalManifest.
		return &LocalManifest{}, nil
	}
	if len(ms) == 1 {
		return ms[0], nil
	}
	if err := detectMergeConflicts(ms); err != nil {
		return nil, err
	}
	// ServerVersion, SchemaVersion, and Audience are folded by the loop below WITH a
	// conflict check (first non-empty wins) and deliberately not pre-seeded here.
	merged := &LocalManifest{
		Name:        ms[0].Name,
		Version:     ms[0].Version,
		Description: ms[0].Description,
	}
	for _, m := range ms {
		merged.Capabilities = append(merged.Capabilities, m.Capabilities...)
		if err := mergeSingleValueField(&merged.ServerVersion, m.ServerVersion, "serverVersion"); err != nil {
			return nil, err
		}
		if err := mergeSingleValueField(&merged.SchemaVersion, m.SchemaVersion, "schemaVersion"); err != nil {
			return nil, err
		}
		if err := mergeSingleValueField(&merged.Audience, m.Audience, "audience"); err != nil {
			return nil, err
		}
		ceiling, err := mergeEffectCeiling(merged.EffectCeiling, m.EffectCeiling, m.Name)
		if err != nil {
			return nil, err
		}
		merged.EffectCeiling = ceiling
		merged.FlowLabelNamespaces = mergeFlowLabelNamespaces(merged.FlowLabelNamespaces, m.FlowLabelNamespaces)
	}
	// Re-validate the merged union: this is load-bearing, not defensive — two
	// individually-valid files can each pin the SAME tool to a DIFFERENT descriptionHash,
	// and only the merged whole is ambiguous. Do not drop it.
	if err := validateLocalManifest(merged); err != nil {
		return nil, fmt.Errorf("merged manifest is invalid: %w", err)
	}
	return merged, nil
}

// mergeSingleValueField folds one manifest's value for a single-valued top-level field into
// the accumulating merged value: first non-empty wins, a disagreeing non-empty value rejected.
func mergeSingleValueField(merged *string, next, field string) error {
	switch {
	case next == "":
		// nothing to contribute
	case *merged == "":
		*merged = next
	case *merged != next:
		return fmt.Errorf("conflicting %s across merged policy files: %q and %q; this field holds a single value and cannot be merged when files disagree — declare it in only one --policy file, or make the values match", field, *merged, next)
	}
	return nil
}

// detectMergeConflicts rejects a merge in which two capabilities from DIFFERENT manifests
// target the same resource with overlapping actions and principal scopes a single request
// can satisfy at once. The engine breaks such a tie by declaration order, which across files
// is just file-list order, so the effective policy would silently depend on it (fail-open) —
// surfaced at load instead. Two capabilities from the SAME manifest are left alone: within
// one file the first-in-order tie-break is documented and visible in one place. Ties are
// judged by SEMANTIC overlap (targetsCanTie, actionsOverlap, principalsConflict), not
// byte-equality, so a glob pair like `tool:read_*` / `tool:*_file` is still caught.
func detectMergeConflicts(ms []*LocalManifest) error {
	// prior records every capability seen and its manifest, so a later one can be compared
	// pairwise against every earlier cross-file one whose target could OVERLAP — catching
	// glob pairs like `read_*` / `*_file` that same-string keying would miss.
	type prior struct {
		manifestIdx int
		target      string
		principal   map[string][]string
		actions     []string
	}
	var seen []prior
	for mi := range ms {
		for ci := range ms[mi].Capabilities {
			c := &ms[mi].Capabilities[ci]
			for _, p := range seen {
				if p.manifestIdx == mi {
					continue // same file: documented first-wins, left alone
				}
				if targetsCanTie(p.target, c.Target) && actionsOverlap(p.actions, c.Actions) && principalsConflict(p.principal, c.Principal) {
					return fmt.Errorf("conflicting capabilities across policy files: targets %q and %q overlap (a single request can match both), with overlapping actions and principal scopes a single request can satisfy at once, so they tie in the enforcement engine, which breaks the tie by policy-file order — the entry in the file listed first silently wins and the later one is ignored (e.g. an earlier audit/permissive entry downgrades a later restrictive one to allow-and-log). Combine them into one capability, scope them to non-overlapping targets, or scope them to principals no single request can satisfy together (disjoint literal values on the same claim), so the effective policy does not depend on file order", p.target, c.Target)
				}
			}
			seen = append(seen, prior{manifestIdx: mi, target: c.Target, principal: c.Principal, actions: c.Actions})
		}
	}
	return nil
}

// targetsCanTie reports whether two targets could both match a single request and so tie.
// Different namespaces never tie; within a namespace it reduces to whether the bare patterns
// overlap. An unparseable target is treated as potentially tying (fail closed, defense-in-depth
// — validateLocalManifest already rejects such targets).
func targetsCanTie(a, b string) bool {
	aType, aBare, aErr := capability.ParseTarget(a)
	bType, bBare, bErr := capability.ParseTarget(b)
	if aErr != nil || bErr != nil {
		return true
	}
	if aType != bType {
		return false
	}
	return globTargetsOverlap(aBare, bBare)
}

// globTargetsOverlap reports whether two bare target patterns could TIE — the only case
// producing a silent file-order shadow. Identical targets tie; two distinct literals never
// tie; a literal and a glob covering it do NOT tie (the exact match outranks the glob). Two
// overlapping globs tie only when enforcement.ResourceSpecificity would rank them equally.
//
// Shares its equal/literal/glob skeleton with patternPairCanOverlap (principal-claim overlap)
// but answers a DIFFERENT question and is kept separate: target overlap uses
// enforcement.MatchesResource semantics while principal overlap uses stdpath.Match, and here
// two globs can be PROVEN disjoint and screened by specificity, where patternPairCanOverlap
// treats glob-vs-glob as always overlapping since principals carry no specificity ranking.
func globTargetsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	aGlob := capability.ContainsGlobMeta(a)
	bGlob := capability.ContainsGlobMeta(b)
	switch {
	case !aGlob && !bGlob:
		return false // two distinct literal targets never match the same name
	case aGlob && bGlob:
		if literalPrefixesDisjoint(a, b) {
			return false
		}
		// Overlapping globs of different specificity never tie: the engine deterministically
		// picks the more-specific one. toolName is "" so ResourceSpecificity always takes its
		// literal/wildcard-counting branch rather than its exact-match shortcut.
		return enforcement.ResourceSpecificity(a, "") == enforcement.ResourceSpecificity(b, "")
	default:
		return false // one literal, one glob: the literal's exact match outranks the glob
	}
}

// literalPrefix returns the leading run of pattern containing no glob metacharacter. Reads
// capability.GlobMetaChars so the set cannot drift from ContainsGlobMeta.
func literalPrefix(pattern string) string {
	if i := strings.IndexAny(pattern, capability.GlobMetaChars); i >= 0 {
		return pattern[:i]
	}
	return pattern
}

// literalPrefixesDisjoint reports whether two glob patterns can be PROVEN to share no
// matching name from their mandatory literal prefixes alone. Sound but incomplete — patterns
// it cannot separate are treated as overlapping by the caller (fail closed).
func literalPrefixesDisjoint(a, b string) bool {
	pa, pb := literalPrefix(a), literalPrefix(b)
	return !strings.HasPrefix(pa, pb) && !strings.HasPrefix(pb, pa)
}

// principalsConflict reports whether two constraints' principal scopes can be satisfied by a
// single request (the principal half of a positional tie): two general entries always
// conflict; a general and a scoped entry do NOT (the engine deterministically prefers the
// scoped one); two scoped entries conflict unless some claim named by BOTH pins the request to
// disjoint values (a claim named by only one cannot separate them). Mirrors PrincipalMatches,
// which ANDs a scope across its own claims.
func principalsConflict(a, b map[string][]string) bool {
	aScoped, bScoped := len(a) > 0, len(b) > 0
	if !aScoped || !bScoped {
		return !aScoped && !bScoped // a general/scoped pair is never a positional tie
	}
	for claim, aPats := range a {
		if bPats, ok := b[claim]; ok && !patternsCanOverlap(aPats, bPats) {
			return false // a shared claim is pinned to disjoint values
		}
	}
	return true
}

// patternsCanOverlap reports whether some single claim value matches at least one pattern in
// each list. Exact for literals and literal-vs-glob; two globs are conservatively treated as
// overlapping (fail closed).
func patternsCanOverlap(a, b []string) bool {
	for _, pa := range a {
		for _, pb := range b {
			if patternPairCanOverlap(pa, pb) {
				return true
			}
		}
	}
	return false
}

// patternPairCanOverlap reports whether a single claim value can satisfy both patterns. It
// mirrors globTargetsOverlap's equal/literal/glob skeleton for PRINCIPAL claims, with two
// deliberate differences (see globTargetsOverlap): stdpath.Match rather than
// enforcement.MatchesResource, and glob-vs-glob is always overlapping since principal scopes
// have no specificity ordering.
func patternPairCanOverlap(pa, pb string) bool {
	if pa == pb {
		return true
	}
	aGlob := capability.ContainsGlobMeta(pa)
	bGlob := capability.ContainsGlobMeta(pb)
	switch {
	case !aGlob && !bGlob:
		return false // two distinct literals never share a value
	case aGlob && bGlob:
		return true // glob vs glob is not cheaply decidable; assume they overlap
	case aGlob:
		// pa glob, pb literal: overlap iff the glob matches it. A malformed pattern
		// (ErrBadPattern) is treated as overlapping, not disjoint.
		m, err := stdpath.Match(pa, pb)
		return err != nil || m
	default:
		m, err := stdpath.Match(pb, pa)
		return err != nil || m
	}
}

// actionsOverlap reports whether two action lists share at least one action a single request
// could exercise. The "*" wildcard overlaps every action.
func actionsOverlap(a, b []string) bool {
	for _, x := range a {
		if x == "*" {
			return true
		}
		for _, y := range b {
			if y == "*" || x == y {
				return true
			}
		}
	}
	return false
}

// semverRe matches the strict three-part semver core (no leading zeros, no v prefix).
var semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

// serverVersionPinRe is the grammar matchServerVersion supports: a dot-separated version
// string of tokens or "*" wildcards. matchServerVersion does component-wise equality, NOT
// semver-range comparison, so a range like ">=2.0.0" would never match and block every
// session under strictDrift — validated here to turn that silent blackout into a load error.
var serverVersionPinRe = regexp.MustCompile(`^[0-9A-Za-z*][0-9A-Za-z.*+_-]*$`)

func validateLocalManifest(m *LocalManifest) error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("'name' must not be empty")
	}
	// Checked BEFORE the scope is built from it, so a per-label check is never made against
	// a declaration this manifest would have been rejected for.
	if err := validateFlowLabelNamespaces(m.FlowLabelNamespaces); err != nil {
		return err
	}
	// The manifest-level facts a per-token validator cannot see from the token's own value.
	// The grammar revision is consulted only by validateAllowedValues (the ${task.*} surface
	// is "0.2"-only); the authoritative version gate for discriminator tokens stays
	// checkTokenGrammarVersion below.
	scope := manifestScope{
		schemaVersion:  strings.TrimSpace(m.SchemaVersion),
		flowNamespaces: declaredFlowLabelNamespaces(m),
	}
	if err := validateEffectCeiling(m.EffectCeiling); err != nil {
		return err
	}
	if m.Version == "" {
		return fmt.Errorf("'version' must not be empty")
	}
	if !semverRe.MatchString(m.Version) {
		return fmt.Errorf("'version' must be a three-part semver (MAJOR.MINOR.PATCH), got %q", m.Version)
	}
	if m.ServerVersion != "" {
		if !serverVersionPinRe.MatchString(m.ServerVersion) {
			return fmt.Errorf("'serverVersion' is a dot-separated version pin with '*' wildcards (e.g. \"1.2.3\", \"1.2.*\", \"*\"), not a semver range; comparison/range operators (>=, >, <=, ~, ^, ||) are not supported and would never match, got %q", m.ServerVersion)
		}
		// matchServerVersion treats a '*' as a wildcard only when it is a WHOLE
		// dot-component; a mid-component form like "1.2*" would make FM-4 fire every
		// session (fatal under strictDrift). Reject it up front.
		for _, part := range strings.Split(m.ServerVersion, ".") {
			// An empty dot-component (a trailing '.', a doubled '..') passes the regex but can
			// never equal any real version component, so the pin never matches. Reject the typo.
			if part == "" {
				return fmt.Errorf("'serverVersion' has an empty dot-component (e.g. \"1.2.\" or \"1..2\"); it can never match a real server version, got %q", m.ServerVersion)
			}
			if strings.Contains(part, "*") && part != "*" {
				return fmt.Errorf("'serverVersion' wildcard must be a whole dot-component (e.g. \"1.2.*\", not \"1.2*\"); component %q mixes a literal with '*' and would never match, got %q", part, m.ServerVersion)
			}
		}
	}
	// Audience, when set, is compared VERBATIM against a token's 'aud' claim, so
	// surrounding whitespace would never match and would silently deny every call.
	if m.Audience != "" {
		if strings.TrimSpace(m.Audience) == "" {
			return fmt.Errorf("'audience' is whitespace-only; the audience is matched verbatim against a token's 'aud' claim, so it would never match and would silently deny every call — set a real audience or remove the field")
		}
		if m.Audience != strings.TrimSpace(m.Audience) {
			return fmt.Errorf("'audience' %q has leading or trailing whitespace; the audience is matched verbatim against a token's 'aud' claim, so this value would never match and would silently deny every call — remove the surrounding whitespace", m.Audience)
		}
	}
	// pinnedHashByTool tracks, per bare tool name, the descriptionHash the first pinned
	// exact-tool entry declared, so a second entry pinning the SAME tool to a DIFFERENT hash
	// is rejected as an ambiguous pin, caught here at load rather than the PDP's hot path.
	// MergeManifests re-runs this validator on the merged result, catching cross-file conflicts.
	pinnedHashByTool := map[string]string{}
	for i := range m.Capabilities {
		c := &m.Capabilities[i]
		if strings.TrimSpace(c.Target) == "" {
			return fmt.Errorf("capability at index %d: 'target' must not be empty", i)
		}
		if len(c.Actions) == 0 {
			return fmt.Errorf("capability at index %d: 'actions' must not be empty", i)
		}
		// Every resource must begin with a recognized namespace prefix.
		targetType, bare, err := capability.ParseTarget(c.Target)
		if err != nil {
			return fmt.Errorf("capability at index %d: %w", i, err)
		}
		// Enforcement mode, when set, must be recognized (fail-closed). It is
		// meaningful only for execution targets — a system: opt-in is binary, so
		// reject audit there rather than ignore it.
		switch c.Enforcement {
		case "", capability.EnforcementEnforce:
			// default — enforce normally
		case capability.EnforcementAudit:
			if targetType == capability.TargetTypeSystem {
				return fmt.Errorf("capability at index %d: enforcement %q is not supported on a system: target (the sampling opt-in is binary)", i, c.Enforcement)
			}
		default:
			return fmt.Errorf("capability at index %d: invalid enforcement %q — valid values are %q or %q", i, c.Enforcement, capability.EnforcementEnforce, capability.EnforcementAudit)
		}
		// Validate the glob pattern on the bare name (after prefix is stripped).
		if err := validateTargetPatternBreadth(targetType, bare, c.Target); err != nil {
			return fmt.Errorf("capability at index %d: %w", i, err)
		}
		if err := enforcement.ValidateResourcePattern(bare); err != nil {
			return fmt.Errorf("capability at index %d: %w", i, err)
		}
		// Validate action–namespace pairing.
		for _, action := range c.Actions {
			if err := capability.ValidateActionForTargetType(targetType, action); err != nil {
				return fmt.Errorf("capability at index %d: constraint %q has %w", i, c.Target, err)
			}
		}
		// FM-5 startup verification fetches tools/list only, so the pin is only meaningful on
		// tool: targets. Glob targets are rejected too, since a single hash cannot represent
		// every tool a glob might match.
		if c.DescriptionHash != "" {
			if targetType != capability.TargetTypeTool {
				return fmt.Errorf("capability at index %d: descriptionHash is only supported on tool: targets (FM-5 startup verification fetches tools/list; resource: and prompt: descriptions are not verified at startup)", i)
			}
			if capability.ContainsGlobMeta(bare) {
				return fmt.Errorf("capability at index %d: descriptionHash cannot be set on glob target %q — a single hash cannot represent the description of every tool the glob matches; use exact-name entries with --pin-descriptions", i, c.Target)
			}
			if err := validateDescriptionHashFormat(c.DescriptionHash); err != nil {
				return fmt.Errorf("capability at index %d: %w", i, err)
			}
			// If an earlier entry pinned the same bare name to a different hash, the manifest
			// is ambiguous — fail closed at load rather than let it reach the enforcement path.
			if prev, ok := pinnedHashByTool[bare]; ok && prev != c.DescriptionHash {
				return fmt.Errorf("capability at index %d: conflicting descriptionHash pins for tool %q — %q and %q; a tool cannot be pinned to two different descriptions, so remove or reconcile one of the entries", i, bare, prev, c.DescriptionHash)
			}
			pinnedHashByTool[bare] = c.DescriptionHash
		}
		if c.ArgumentSchema != nil {
			// argumentSchema validates a tool-call's argument map, scoped to tool: targets: a
			// resource:/prompt:/system: request carries no such map, so accepting one is a
			// fail-open guard with no runtime effect.
			if targetType != capability.TargetTypeTool {
				return fmt.Errorf("capability at index %d: constraint %q carries an argumentSchema, which applies only to tool: targets (the proxy validates tool-call arguments structurally; %s requests carry no tool-argument map to validate)", i, c.Target, targetType)
			}
			// Compile every `pattern` once at load: a malformed regex is rejected here
			// (fail closed) instead of denying the first live request, and each
			// valid pattern is primed into the enforcement regexp cache so the hot
			// path never recompiles it.
			if err := enforcement.CompileSchemaPatterns(fmt.Sprintf("capabilities[%d].argumentSchema", i), c.ArgumentSchema); err != nil {
				return err
			}
			// Reject an unsatisfiable schema: a `required` field absent from
			// `properties` while `additionalProperties` is false can never be
			// satisfied, denying every call with a misleading "additional property"
			// error.
			if err := validateArgumentSchemaConsistency(fmt.Sprintf("capabilities[%d].argumentSchema", i), c.ArgumentSchema); err != nil {
				return err
			}
		}
		// Validate principal scoping: only supported claims, each with a non-empty
		// pattern, so a typo'd claim (which would never match) is caught at load.
		if err := validatePrincipal(c.Principal); err != nil {
			return fmt.Errorf("capability at index %d: %w", i, err)
		}
		// The effect contract is the single input every effect check reads, so a malformed
		// one would make all three (effectClass, blastRadius, ceiling) wrong at once.
		if err := validateEffectContract(i, c.Effect); err != nil {
			return err
		}
		// Each directive type's rules live in directiveValidators, keyed by the same
		// discriminator pkg/capability's registry uses; the grammar-revision gate is separate
		// (checkTokenGrammarVersion). A null directive is rejected fail-closed like a null
		// condition.
		for j, dir := range c.Directives {
			if dir == nil {
				return fmt.Errorf("capability at index %d, directive %d: a null directive is not permitted; every directives entry must be a typed directive object", i, j)
			}
			// A typed-nil pointer is a non-nil interface, so it survives the dir==nil check
			// above but would panic when a case below dereferences it. Mirrors the engine's
			// collectObligations typed-nil guard.
			if capability.IsTypedNil(dir) {
				return fmt.Errorf("capability at index %d, directive %d: a typed-nil directive is not permitted; every directives entry must be a typed directive object", i, j)
			}
			// Dispatched off the directive's own DISCRIMINATOR through directiveValidators,
			// keyed the same as capability's directivePrototypes registry — not a type switch,
			// which would be a second hand-maintained mirror of that registry.
			validate, known := directiveValidators[dir.DirectiveType()]
			if !known {
				// Enumerate FROM the registry rather than a literal list, which would be a
				// third mirror. Reachable only for a programmatically built manifest.
				return fmt.Errorf("capability at index %d, directive %d: unrecognized directive type %q; the supported directives are %s",
					i, j, dir.DirectiveType(), strings.Join(capability.KnownDirectiveTypes(), ", "))
			}
			if err := validate(i, j, c.Target, targetType, dir, scope); err != nil {
				return err
			}
		}
		// Reject two quota-consuming conditions addressing the same counter bucket before
		// the per-condition pass, checked once per constraint rather than inside the
		// per-condition loop (which sees one entry at a time).
		if err := validateQuotaBucketsDistinct(i, c.Conditions); err != nil {
			return err
		}
		for j, cond := range c.Conditions {
			// A null conditions entry decodes to a nil Condition and would slip through this
			// type switch, then panic the engine at request time on the nil interface — a
			// whole-proxy DoS from one route manifest. Reject it at load, fail closed.
			if cond == nil {
				return fmt.Errorf("capability at index %d, condition %d: a null condition is not permitted; every conditions entry must be a typed condition object", i, j)
			}
			// A typed-nil pointer is a non-nil interface, so it survives the cond==nil check
			// above but would panic when a case below dereferences it, mirroring the
			// directive loop's typed-nil guard.
			if capability.IsTypedNil(cond) {
				return fmt.Errorf("capability at index %d, condition %d: a typed-nil condition is not permitted; every conditions entry must be a typed condition object", i, j)
			}
			// Dispatched off the condition's own DISCRIMINATOR through conditionValidators,
			// keyed the same as capability's conditionPrototypes registry — not a type switch,
			// under which a condition added to the registry without a switch arm loaded clean
			// with its Compile never run.
			validate, known := conditionValidators[cond.ConditionType()]
			if !known {
				return fmt.Errorf("capability at index %d, condition %d: unrecognized condition type %q; the supported conditions are %s",
					i, j, cond.ConditionType(), strings.Join(capability.KnownConditionTypes(), ", "))
			}
			if err := validate(i, j, cond, scope); err != nil {
				return err
			}
		}
	}
	// Single authoritative grammar-version gate, run after the per-capability loop (so
	// every condition/directive is non-nil and well-typed) rather than per-case, so a
	// future token cannot slip under an older revision by omitting one.
	if err := checkTokenGrammarVersion(m); err != nil {
		return err
	}
	return nil
}

// manifestScope carries the manifest-level facts a per-token validator needs but cannot read
// off the token it is handed: the declared grammar revision, and the sensitivity namespaces
// the policy declared. ONE struct rather than a parameter per fact, so the next
// manifest-level input is a field here instead of a re-thread of every validator signature.
type manifestScope struct {
	// schemaVersion is the manifest's declared grammar revision, which exactly one type's
	// rules turn on (${task.*} is "0.2"-only).
	schemaVersion string
	// flowNamespaces indexes flowLabelNamespaces — the imported-sensitivity taxonomies this
	// policy speaks. Nil when it declares none, which correctly admits no imported label.
	flowNamespaces map[string]bool
}

// conditionValidator is the per-type validation one condition needs: its own field checks
// plus the type's load-time Compile. cond is guaranteed non-nil, non-typed-nil by
// validateLocalManifest before dispatch.
type conditionValidator func(i, j int, cond capability.Condition, scope manifestScope) error

// conditionValidators is the manifest loader's per-condition validation, keyed by the SAME
// discriminator strings pkg/capability's conditionPrototypes registry holds — not a type
// switch, under which a condition added to the registry without a switch arm loaded clean with
// its Compile never run and its runtime state never built. A type missing here is now a test
// failure (TestConditionValidators_CoverEveryKnownCondition) rather than a silent gap.
//
// Each entry goes through typedCondition, which honours AsValueOrPointer's ok. Dispatch is on
// the discriminator the condition REPORTS, not its Go type, so a mismatched ConditionType()
// is reported rather than dereferenced as a type it is not.
var conditionValidators = map[string]conditionValidator{
	capability.ConditionTypeAllowedOperations: typedCondition(validateAllowedOperations),
	capability.ConditionTypeAllowedExtensions: typedCondition(validateAllowedExtensions),
	capability.ConditionTypeAllowedTables:     typedCondition(validateAllowedTables),
	capability.ConditionTypeRecipientDomain:   typedCondition(validateRecipientDomain),
	// The only per-type validator that needs the declared grammar revision: the ${task.*}
	// surface exists in "0.2" and not in "0.1", so what counts as a malformed reference
	// versus an ordinary literal differs between them.
	capability.ConditionTypeAllowedValues: typedScopedCondition(validateAllowedValues),
	capability.ConditionTypeMaxCalls:      typedCondition(validateMaxCalls),
	capability.ConditionTypeIPRange:       typedCondition(validateIPRange),
	capability.ConditionTypeTimeWindow:    typedCondition(validateTimeWindow),
	capability.ConditionTypeSequenceBlock: typedCondition(validateSequenceBlock),
	capability.ConditionTypeFlowLabel: typedScopedCondition(func(i, j int, c *capability.FlowLabelCondition, scope manifestScope) error {
		return validateFlowLabel(i, j, c.Allow, scope.flowNamespaces)
	}),
	capability.ConditionTypeEffectClass: typedCondition(func(i, j int, c *capability.EffectClassCondition) error {
		return validateEffectClass(i, j, c.Allow)
	}),
	capability.ConditionTypeBlastRadius: typedCondition(validateBlastRadius),
	capability.ConditionTypePolicy:      typedCondition(validatePolicyCondition),
	capability.ConditionTypeCustom:      typedCondition(validateCustomCondition),
}

// typedCondition adapts a per-type validator that needs nothing from the manifest around it.
// It is the common case; typedScopedCondition is for the types whose rules turn on a
// manifest-level fact.
func typedCondition[T any](check func(i, j int, v *T) error) conditionValidator {
	return typedScopedCondition(func(i, j int, v *T, _ manifestScope) error { return check(i, j, v) })
}

// typedScopedCondition folds one condition type's value and pointer decode forms into a
// single table entry: normalizes cond to *T, then runs the type's load-time Compile. The
// "Compile only on the POINTER form" rule is enforced by the type system — Compile has a
// pointer receiver, so the VALUE form does not satisfy the interface at all. The type mismatch
// is REPORTED rather than assumed away: under discriminator dispatch a programmatically built
// condition whose ConditionType() disagrees with its concrete type reaches here, where a
// discarded ok would be a nil dereference instead of a fail-closed load error.
func typedScopedCondition[T any](check func(i, j int, v *T, scope manifestScope) error) conditionValidator {
	return func(i, j int, cond capability.Condition, scope manifestScope) error {
		v, ok := capability.AsValueOrPointer[T](cond)
		if !ok || v == nil {
			return fmt.Errorf("capability at index %d, condition %d: condition reports type %q but is not one; refusing rather than validating it as a type it is not",
				i, j, cond.ConditionType())
		}
		if err := check(i, j, v, scope); err != nil {
			return err
		}
		if c, compilable := cond.(interface{ Compile() error }); compilable {
			// Compile cannot fail today (each validator already confirmed its inputs parse);
			// the error is still checked so a future normalization that CAN fail is caught.
			if err := c.Compile(); err != nil {
				return fmt.Errorf("capability at index %d, condition %d: %w", i, j, err)
			}
		}
		return nil
	}
}

func validateTargetPatternBreadth(targetType capability.TargetType, bare, target string) error {
	switch targetType {
	case capability.TargetTypeTool:
		if isBareWildcardTarget(bare) {
			return fmt.Errorf("target %q is too broad: a bare tool wildcard (tool:* or tool:**) is rejected; use a narrower tool glob or list tools explicitly", target)
		}
	case capability.TargetTypeResource:
		if isBareWildcardTarget(bare) {
			return fmt.Errorf("target %q is too broad: a bare resource wildcard (resource:* or resource:**) is rejected; scope the target to a concrete URI scheme, authority, or path", target)
		}
		if resourceWildcardsSchemeOrAuthority(bare) {
			return fmt.Errorf("target %q is too broad: resource wildcards are not allowed in the URI scheme or authority; use a concrete scheme and authority, then put globs in the path", target)
		}
		if resourceOpaqueURIWildcard(bare) {
			return fmt.Errorf("target %q is invalid: wildcards in an opaque (non-hierarchical) URI such as urn: or mailto: are rejected; opaque URIs match by exact equality only", target)
		}
	case capability.TargetTypeSystem:
		if capability.ContainsGlobMeta(bare) {
			return fmt.Errorf("target %q is invalid: system: targets are fixed identifiers and do not allow glob metacharacters", target)
		}
	}
	return nil
}

// isBareWildcardTarget reports whether the bare pattern is a match-everything target with
// nothing to scope it — a run of "*"/"?" including at least one "*". A run of ONLY "?" is NOT
// rejected: "??" matches only two-character names, a bounded and legitimately-scoped target.
// prompt:* is the documented exception and never routed here.
func isBareWildcardTarget(bare string) bool {
	return bare != "" && strings.Trim(bare, "*?") == "" && strings.Contains(bare, "*")
}

// resourceOpaqueURIWildcard reports whether bare is an opaque (non-hierarchical) resource URI
// (e.g. urn:…, mailto:…) carrying a glob metacharacter. Opaque URIs match by exact equality
// only, so any wildcard is rejected. Opaqueness is decided solely by the absence of a "//"
// authority component — a "/" in the scheme-specific part (e.g. a URN namespace string) does
// NOT make the URI hierarchical.
func resourceOpaqueURIWildcard(bare string) bool {
	colon := strings.Index(bare, ":")
	if colon <= 0 {
		return false // no scheme — not an opaque URI
	}
	rest := bare[colon+1:]
	if strings.HasPrefix(rest, "//") {
		return false // hierarchical: carries a "//" authority component
	}
	return capability.ContainsGlobMeta(rest)
}

func resourceWildcardsSchemeOrAuthority(pattern string) bool {
	schemeEnd := strings.Index(pattern, "://")
	if schemeEnd < 0 {
		colon := strings.Index(pattern, ":")
		return colon > 0 && capability.ContainsGlobMeta(pattern[:colon])
	}
	if capability.ContainsGlobMeta(pattern[:schemeEnd]) {
		return true
	}
	rest := pattern[schemeEnd+len("://"):]
	authorityEnd := strings.IndexAny(rest, "/?#")
	authority := rest
	if authorityEnd >= 0 {
		authority = rest[:authorityEnd]
	}
	return capability.ContainsGlobMeta(authority)
}

// validateArgumentRef rejects a condition 'argument' reference that fails closed at runtime:
// an empty reference, or a malformed nested "$." path — an empty body, an empty segment, or a
// trailing dot. Both cases silently deny every matching call with no load-time signal
// otherwise. emptyMsg is the condition-specific message for the empty case.
func validateArgumentRef(i, j int, argument, emptyMsg string) error {
	if argument == "" {
		return fmt.Errorf("capability at index %d, condition %d: %s", i, j, emptyMsg)
	}
	if capability.IsArgumentPath(argument) && capability.ArgumentPathSegments(argument) == nil {
		return fmt.Errorf("capability at index %d, condition %d: 'argument' %q is a malformed \"$.\" path (empty body, empty segment, or trailing dot); it would resolve to nothing and silently deny every call — write a well-formed path such as \"$.a.b\", or a bare top-level key", i, j, argument)
	}
	return nil
}

// validateAllowedTables rejects an allowedTables condition that fails closed or enforces
// non-deterministically: a missing 'argument', or two 'columns' keys differing only in case —
// the engine lowercases them into one key where which survives depends on map iteration order.
func validateAllowedTables(i, j int, v *capability.AllowedTablesCondition) error {
	if err := validateArgumentRef(i, j, v.Argument, "allowedTables requires an 'argument' field naming the tool parameter that carries the table name"); err != nil {
		return err
	}
	// An empty 'tables' list denies every call (column entries only apply to already-allowed
	// tables and cannot rescue it).
	if len(v.Tables) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: allowedTables requires a non-empty 'tables' list; an empty list matches no table and denies every call", i, j)
	}
	for k, table := range v.Tables {
		if strings.TrimSpace(table) == "" {
			return fmt.Errorf("capability at index %d, condition %d, table %d: allowedTables contains an empty or whitespace-only table entry; remove it or replace it with a real table name", i, j, k)
		}
		// Surrounding whitespace is the same footgun: request table names are trimmed
		// before matching, so " users" would never match and silently deny every call.
		if table != strings.TrimSpace(table) {
			return fmt.Errorf("capability at index %d, condition %d, table %d: allowedTables entry %q has leading or trailing whitespace; table names are trimmed before matching, so this entry would never match and would silently deny every call — remove the surrounding whitespace", i, j, k, table)
		}
	}
	seen := make(map[string]string, len(v.Columns))
	for table, cols := range v.Columns {
		// Normalize EXACTLY as the runtime compiler does (ToLower AFTER TrimSpace):
		// checking collisions on the untrimmed name let {"users", " users"} pass validation
		// then collapse onto one bucket at runtime, non-deterministically.
		key := strings.ToLower(strings.TrimSpace(table))
		if prior, dup := seen[key]; dup {
			return fmt.Errorf("capability at index %d, condition %d: allowedTables 'columns' has case-colliding keys %q and %q; table names are matched case-insensitively, so they address the same table and one column allowlist would non-deterministically overwrite the other — merge them under a single key", i, j, prior, table)
		}
		seen[key] = table
		// An empty column allowlist denies every access to the table unconditionally, even
		// though it is listed in 'tables'. To allow any column, OMIT the key instead.
		if len(cols) == 0 {
			return fmt.Errorf("capability at index %d, condition %d: allowedTables 'columns' has an empty column allowlist for table %q, which denies every access to that table unconditionally; to allow any column omit %q from 'columns', or to deny the table entirely remove it from 'tables'", i, j, table, table)
		}
	}
	return nil
}

// validateAllowedOperations rejects an allowedOperations condition that fails
// closed: a missing 'argument' or an empty 'operations' list (both deny every
// call, typically from an `operation:`/`operations:` typo).
func validateAllowedOperations(i, j int, v *capability.AllowedOperationsCondition) error {
	if err := validateArgumentRef(i, j, v.Argument, "allowedOperations requires an 'argument' field naming the tool parameter that carries the operation (e.g. argument: sql)"); err != nil {
		return err
	}
	if len(v.Operations) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: allowedOperations requires a non-empty 'operations' list; an empty list matches no operation and denies every call", i, j)
	}
	for k, op := range v.Operations {
		if strings.TrimSpace(op) == "*" {
			return fmt.Errorf("capability at index %d, condition %d: allowedOperations 'operations' list contains %q; the wildcard is not a valid operation verb and would allow any operation — list the permitted verbs explicitly (e.g. [\"SELECT\"])", i, j, "*")
		}
		// A blank/whitespace entry never EqualFold-matches a real operation verb, so
		// an all-blank list silently denies every call at runtime with no load-time
		// signal. Reject it, mirroring validateAllowedExtensions.
		if strings.TrimSpace(op) == "" {
			return fmt.Errorf("capability at index %d, condition %d, operation %d: allowedOperations contains an empty or whitespace-only entry; remove it or replace it with a real operation verb (e.g. \"SELECT\")", i, j, k)
		}
		// Surrounding whitespace is the same footgun: request verbs are trimmed before
		// matching, so "SELECT " would never match and would silently deny every call.
		if op != strings.TrimSpace(op) {
			return fmt.Errorf("capability at index %d, condition %d, operation %d: allowedOperations entry %q has leading or trailing whitespace; operation verbs are trimmed before matching, so this entry would never match and would silently deny every call — remove the surrounding whitespace", i, j, k, op)
		}
	}
	return nil
}

// validateAllowedExtensions rejects an allowedExtensions condition that fails
// closed: a missing 'argument' or an empty 'extensions' list (both deny every
// call, typically from an `extension:`/`extensions:` typo).
func validateAllowedExtensions(i, j int, v *capability.AllowedExtensionsCondition) error {
	if err := validateArgumentRef(i, j, v.Argument, "allowedExtensions requires an 'argument' field naming the tool parameter that carries the file path"); err != nil {
		return err
	}
	if len(v.Extensions) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: allowedExtensions requires a non-empty 'extensions' list; an empty list matches no file extension and denies every call", i, j)
	}
	// A blank/whitespace entry is dropped by the runtime's TrimSpace, so an
	// all-blank list collapses to an empty allowlist that denies every call. Reject
	// any blank entry.
	for k, ext := range v.Extensions {
		if strings.TrimSpace(ext) == "" {
			return fmt.Errorf("capability at index %d, condition %d, extension %d: allowedExtensions contains an empty or whitespace-only entry; remove it or replace it with a real extension (e.g. .pdf)", i, j, k)
		}
	}
	return nil
}

// validateAllowedValues rejects an allowedValues condition that fails closed: a
// missing 'argument' or an empty 'values' list (both deny every call, typically
// from an `arguments:`/`value:` typo), or a value that is a malformed glob.
func validateAllowedValues(i, j int, v *capability.AllowedValuesCondition, scope manifestScope) error {
	if err := validateArgumentRef(i, j, v.Argument, "allowedValues requires an 'argument' field naming the tool parameter to check (e.g. argument: path)"); err != nil {
		return err
	}
	if len(v.Values) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: allowedValues requires a non-empty 'values' list; an empty list matches nothing and denies every call", i, j)
	}
	// String values double as MatchValueGlob patterns at runtime; a malformed pattern is
	// silently treated as a non-match, quietly tightening the policy.
	for k, val := range v.Values {
		s, ok := val.(string)
		if !ok {
			continue
		}
		// A task-context variable is a REFERENCE, not a pattern: resolved from the validated
		// token and compared by exact equality, so it skips the glob check entirely. A
		// misspelled ${task.identifier} must not load as an inert literal that denies every
		// call. Gated on the revision that DEFINES the surface — under "0.1" a "${" is
		// ordinary literal text — with a recognized reference under "0.1" still refused by
		// checkTaskVarGrammarVersion.
		if revisionAdmits(scope.schemaVersion, ManifestSchemaVersion02) && capability.ContainsVariableRef(s) {
			if err := capability.ValidateVariableRef(s); err != nil {
				return fmt.Errorf("capability at index %d, condition %d, value %d: %w", i, j, k, err)
			}
			continue
		}
		if err := enforcement.ValidateValueGlob(s); err != nil {
			return fmt.Errorf("capability at index %d, condition %d, value %d: allowedValues contains invalid glob pattern %q: %w", i, j, k, s, err)
		}
	}
	return nil
}

// validateRedactFields rejects the structurally malformed redactFields paths the runtime
// redactor would silently no-op on — forwarding the field unredacted while the audit record
// reports redaction applied, a fail-open leak. The redactor splits on '.' and looks up each
// segment as a literal object key, so array-index notation, an empty segment, or surrounding
// whitespace never resolves. This catches malformed SYNTAX only; a FLAT upstream key literally
// named "a.b" is unaddressable and cannot be detected from the manifest alone — see
// docs/capability-manifest-guide.md.
func validateRedactFields(i, j int, fields []string) error {
	// An empty (or omitted) fields list declares a redaction that redacts nothing while
	// enforcedForwardCore still records the obligation as applied — a fail-open leak plus a
	// falsely "discharged" audit record.
	if len(fields) == 0 {
		return fmt.Errorf("capability at index %d, directive %d: redactFields requires a non-empty 'fields' list; an empty list declares a redaction that redacts nothing while the audit log reports it applied — list the field(s) to redact (e.g. fields: [\"users.ssn\"]) or remove the directive", i, j)
	}
	for _, field := range fields {
		if strings.ContainsAny(field, "[]") {
			return fmt.Errorf("capability at index %d, directive %d: redactFields path %q uses array-index notation ('[N]'), which is not supported and would silently redact nothing; use a dot path such as \"users.ssn\" to redact the field from every array element, or omit the index", i, j, field)
		}
		// Strip the leading root marker ("$." or a lone "$") before splitting, mirroring the
		// redactor. Any OTHER "$"-prefixed form is a likely typo (e.g. "$users.ssn" for
		// "$.users.ssn") that reaches the redactor unchanged and silently redacts nothing.
		var path string
		switch {
		case strings.HasPrefix(field, "$."):
			path = field[len("$."):]
		case field == "$":
			path = ""
		case strings.HasPrefix(field, "$"):
			return fmt.Errorf("capability at index %d, directive %d: redactFields path %q begins with '$' but is not the root marker \"$.\" or the lone \"$\" sentinel; it would silently redact nothing while the audit log reports it applied — write \"$.%s\" to anchor at the response root, or remove the leading '$' to target a field literally named without one", i, j, field, strings.TrimPrefix(field, "$"))
		default:
			path = field
		}
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("capability at index %d, directive %d: redactFields path %q is empty; provide a dot path naming the field(s) to redact (e.g. \"users.ssn\")", i, j, field)
		}
		for _, seg := range strings.Split(path, ".") {
			if seg == "" {
				return fmt.Errorf("capability at index %d, directive %d: redactFields path %q has an empty path segment (a leading, trailing, or doubled '.'), which would silently redact nothing; use a well-formed dot path such as \"users.ssn\"", i, j, field)
			}
			// The redactor matches each segment as a LITERAL key with no trimming, so a
			// whitespace segment never matches and silently redacts nothing.
			if strings.TrimSpace(seg) == "" {
				return fmt.Errorf("capability at index %d, directive %d: redactFields path %q has a whitespace-only path segment, which would silently redact nothing; use a well-formed dot path such as \"users.ssn\"", i, j, field)
			}
			if seg != strings.TrimSpace(seg) {
				return fmt.Errorf("capability at index %d, directive %d: redactFields path %q has a segment %q with leading or trailing whitespace; the redactor matches segments literally, so it would silently redact nothing — remove the whitespace", i, j, field, seg)
			}
		}
	}
	return nil
}

// validateMaxCalls rejects a maxCalls condition with a non-positive count or window. A
// windowSeconds past callcounter.MaxWindowSeconds overflows the duration arithmetic and would
// silently reset the quota (a fail-open bypass), so it is rejected too.
func validateMaxCalls(i, j int, v *capability.MaxCallsCondition) error {
	if v.Count < 1 {
		return fmt.Errorf("capability at index %d, condition %d: maxCalls requires 'count' >= 1 (the maximum calls permitted per window)", i, j)
	}
	if v.WindowSeconds < 1 {
		return fmt.Errorf("capability at index %d, condition %d: maxCalls requires 'windowSeconds' >= 1 (the rolling window length in seconds, e.g. windowSeconds: 3600); without it the limit never resets", i, j)
	}
	if int64(v.WindowSeconds) > callcounter.MaxWindowSeconds {
		return fmt.Errorf("capability at index %d, condition %d: maxCalls 'windowSeconds' %d exceeds the maximum %d; a larger window overflows the call-counter duration arithmetic and would silently reset the quota", i, j, v.WindowSeconds, callcounter.MaxWindowSeconds)
	}
	return nil
}

// validateQuotaBucketsDistinct rejects a capability whose quota-consuming conditions would
// address the SAME counter bucket (two maxCalls, or two cumulative blastRadius bounds,
// sharing a windowSeconds): the counter keys each bucket by namespace, so two such conditions
// share one physical bucket and halve the effective limit. Distinct windows are independent
// and left alone. Mixing the two TYPES is fine — they draw on separately-namespaced keys and
// the engine admits both together in ONE atomic backend call. The counter's own
// checkDistinctBuckets is the backstop for anything outside a manifest's closed condition set.
func validateQuotaBucketsDistinct(i int, conditions []capability.Condition) error {
	// Keyed by (namespace, window): only a collision WITHIN one namespace is a shared
	// bucket, because that is exactly how the counter keys them.
	type bucket struct {
		namespace string
		window    int
	}
	seen := make(map[bucket]int)
	for j, cond := range conditions {
		var b bucket
		switch v := cond.(type) {
		case capability.MaxCallsCondition:
			b = bucket{"maxCalls", v.WindowSeconds}
		case *capability.MaxCallsCondition:
			b = bucket{"maxCalls", v.WindowSeconds}
		case capability.BlastRadiusCondition:
			if !v.HasVelocity() {
				continue
			}
			b = bucket{"blastRadius", v.WindowSeconds}
		case *capability.BlastRadiusCondition:
			if !v.HasVelocity() {
				continue
			}
			b = bucket{"blastRadius", v.WindowSeconds}
		default:
			continue
		}
		if b.window < 1 {
			continue
		}
		if first, dup := seen[b]; dup {
			return fmt.Errorf("capability at index %d: conditions %d and %d are both %s with the same windowSeconds (%d); two equal windows share one counter bucket and would halve the effective limit — combine them into a single condition with the lower bound", i, first, j, b.namespace, b.window)
		}
		seen[b] = j
	}
	return nil
}

// validateIPRange rejects an ipRange condition with an empty CIDR list, a malformed CIDR,
// or a CIDR carrying host bits.
func validateIPRange(i, j int, v *capability.IPRangeCondition) error {
	if len(v.CIDRs) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: ipRange requires a non-empty 'cidrs' list; an empty list matches no source IP and denies every call", i, j)
	}
	for _, cidr := range v.CIDRs {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("capability at index %d, condition %d: ipRange contains an invalid CIDR %q (expected e.g. 10.0.0.0/8): %w", i, j, cidr, err)
		}
		// net.ParseCIDR silently masks host bits, so "10.0.0.5/8" behaves as "10.0.0.0/8" —
		// usually a /32-vs-network mistake that widens the allowlist.
		if !ip.Equal(network.IP) {
			return fmt.Errorf("capability at index %d, condition %d: ipRange CIDR %q has host bits set; use the network address %q, or /32 to allow just that host", i, j, cidr, network.String())
		}
	}
	return nil
}

// validateRecipientDomain rejects a recipientDomain condition that fails closed or ships a
// dead allowlist entry: a missing 'argument', empty/blank domains, or an entry beginning with
// '@' (an accidental full-address paste that could only match a malformed double-@ recipient).
func validateRecipientDomain(i, j int, v *capability.RecipientDomainCondition) error {
	if err := validateArgumentRef(i, j, v.Argument, "recipientDomain requires an 'argument' field naming the tool parameter that carries the recipient address"); err != nil {
		return err
	}
	if len(v.Domains) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: recipientDomain requires a non-empty 'domains' list; an empty list matches no recipient and denies every call", i, j)
	}
	for k, d := range v.Domains {
		trimmed := strings.TrimSpace(d)
		if trimmed == "" {
			return fmt.Errorf("capability at index %d, condition %d, domain %d: recipientDomain contains an empty or whitespace-only domain entry; remove it or replace it with a real domain (e.g. example.com)", i, j, k)
		}
		if d != trimmed {
			return fmt.Errorf("capability at index %d, condition %d, domain %d: recipientDomain entry %q has leading or trailing whitespace; recipient domains are trimmed before matching, so this entry would never match and would silently deny every call — remove the surrounding whitespace", i, j, k, d)
		}
		if strings.HasPrefix(trimmed, "@") {
			return fmt.Errorf("capability at index %d, condition %d, domain %d: recipientDomain entry %q must not start with '@'; use the bare domain (e.g. example.com)", i, j, k, d)
		}
	}
	return nil
}

// validateTimeWindow rejects a timeWindow condition that declares neither bound, carries a
// non-RFC3339 timestamp, or whose notBefore is at or after notAfter (an empty window).
func validateTimeWindow(i, j int, v *capability.TimeWindowCondition) error {
	if v.NotBefore == "" && v.NotAfter == "" {
		return fmt.Errorf("capability at index %d, condition %d: timeWindow requires at least one of 'notBefore' or 'notAfter'; a window with neither bound restricts nothing", i, j)
	}
	var notBefore, notAfter time.Time
	var err error
	if v.NotBefore != "" {
		if notBefore, err = time.Parse(time.RFC3339Nano, v.NotBefore); err != nil {
			return fmt.Errorf("capability at index %d, condition %d: timeWindow has an invalid notBefore %q (expected RFC3339, e.g. 2026-04-01T00:00:00Z or 2026-04-01T00:00:00.500Z): %w", i, j, v.NotBefore, err)
		}
	}
	if v.NotAfter != "" {
		if notAfter, err = time.Parse(time.RFC3339Nano, v.NotAfter); err != nil {
			return fmt.Errorf("capability at index %d, condition %d: timeWindow has an invalid notAfter %q (expected RFC3339, e.g. 2026-12-31T23:59:59Z or 2026-12-31T23:59:59.999Z): %w", i, j, v.NotAfter, err)
		}
	}
	if v.NotBefore != "" && v.NotAfter != "" && !notBefore.Before(notAfter) {
		return fmt.Errorf("capability at index %d, condition %d: timeWindow notBefore %q is not before notAfter %q; the window is empty and denies every call", i, j, v.NotBefore, v.NotAfter)
	}
	return nil
}

// validatePolicyCondition rejects a policy condition with no backend name. The engine
// resolves the evaluator by name at request time and denies (fail closed) when nothing is
// registered under it, so a blank backend is a silent deny-all with no load-time signal. The
// backend's EXISTENCE is deliberately not checked: evaluators may register after the manifest
// loads, so requiring registration would reject a legitimate wiring order — requiring a NAME
// does not.
func validatePolicyCondition(i, j int, v *capability.PolicyCondition) error {
	if strings.TrimSpace(v.Backend) == "" {
		return fmt.Errorf("capability at index %d, condition %d: policy requires a non-empty 'backend' naming the external policy evaluator (e.g. opa, cedar); an unnamed backend resolves to no evaluator and denies every matching call at request time", i, j)
	}
	return nil
}

// validateCustomCondition rejects a custom condition with no handler name, for the same
// reason as validatePolicyCondition: the name is the key the handler registry is looked up
// by, so a blank one denies every matching call at request time with nothing said at load.
func validateCustomCondition(i, j int, v *capability.CustomCondition) error {
	if strings.TrimSpace(v.Name) == "" {
		return fmt.Errorf("capability at index %d, condition %d: custom requires a non-empty 'name' naming the registered condition handler; an unnamed handler resolves to nothing and denies every matching call at request time", i, j)
	}
	return nil
}

// validateSequenceBlock rejects a sequenceBlock condition whose afterTools list would fail
// OPEN at runtime: an empty list, an entry naming no tool once stripped/trimmed, or an entry
// with an unrecognized namespace prefix (looked up under a key no call records). The
// colon-prefix check is conservative — it also rejects a bare resource URI like
// "file:///secrets", indistinguishable at load time from a prefix typo.
func validateSequenceBlock(i, j int, v *capability.SequenceBlockCondition) error {
	if len(v.AfterTools) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: sequenceBlock requires a non-empty 'afterTools' list naming the tools whose prior use in the session blocks this call; an empty list never fires and fails closed at runtime", i, j)
	}
	for k, entry := range v.AfterTools {
		stripped := enforcement.StripEnginePrefix(entry)
		if strings.TrimSpace(stripped) == "" {
			return fmt.Errorf("capability at index %d, condition %d, afterTools entry %d: sequenceBlock entry %q names no tool once its namespace prefix is stripped and surrounding whitespace is trimmed (e.g. \"\", a bare \"tool:\", or \"  \"); use a bare tool name (e.g. read_file) or a tool: prefix (e.g. tool:read_file)", i, j, k, entry)
		}
		// A colon-bearing entry stripEnginePrefix returns unchanged is ambiguous: the text
		// before ':' is not a recognized prefix, so the runtime matches the whole entry
		// literally and a namespace typo silently never fires. Require an explicit prefix.
		if strings.Contains(entry, ":") && stripped == entry {
			return fmt.Errorf("capability at index %d, condition %d, afterTools entry %d: sequenceBlock entry %q is ambiguous: the text before its first ':' is not a recognized namespace prefix (tool:, resource:, prompt:, system:), so the entry is matched literally — a namespace typo like 'mcp:read_file' then silently never fires, and a resource URI must carry the explicit resource: prefix (resource:file:///secrets). Add one of tool:, resource:, prompt:, or system: to disambiguate", i, j, k, entry)
		}
		// afterTools is matched LITERALLY against recorded call names, never glob-expanded,
		// so a wildcard like "read_*" silently fails OPEN. The rejected set is narrower for a
		// resource: entry, which legitimately contains '[' (IPv6 host) and '?' (query
		// string); '*' is still rejected since resource TARGETS legitimately glob.
		reject := capability.GlobMetaChars
		if strings.HasPrefix(entry, "resource:") {
			reject = "*"
		}
		if strings.ContainsAny(stripped, reject) {
			return fmt.Errorf("capability at index %d, condition %d, afterTools entry %d: sequenceBlock entry %q contains glob metacharacters (%s); afterTools is matched literally against recorded tool names, so a glob never fires and the block silently fails open — name the exact tool(s) instead", i, j, k, entry, reject)
		}
	}
	return nil
}

// directiveValidator is the per-type validation one directive needs: its target restriction
// and its own field checks. dir is guaranteed non-nil, non-typed-nil by validateLocalManifest
// before dispatch.
type directiveValidator func(i, j int, target string, targetType capability.TargetType, dir capability.Directive, scope manifestScope) error

// directiveValidators is the manifest loader's per-directive validation, keyed by the SAME
// discriminator strings pkg/capability's directivePrototypes registry holds — not a type
// switch, whose default-arm message hard-coded the directive list and would name three
// directives that were not the problem if a fourth were added and forgotten here.
//
// Each entry goes through typedDirective, which honours AsValueOrPointer's ok. Dispatch is on
// the discriminator the directive REPORTS, not its Go type, so a mismatched DirectiveType()
// is reported rather than dereferenced as a type it is not.
var directiveValidators = map[string]directiveValidator{
	capability.DirectiveTypeRedactFields: typedDirective(func(i, j int, target string, targetType capability.TargetType, d *capability.RedactFieldsDirective, _ manifestScope) error {
		// redactFields mutates the tools/call RESPONSE, so it applies only to tool: targets:
		// a directive that never applies is a fail-open leak plus a false "discharged" audit
		// record.
		if err := requireResponseDirectiveTarget(i, target, targetType); err != nil {
			return err
		}
		return validateRedactFields(i, j, d.Fields)
	}),
	capability.DirectiveTypeLabelOutput: typedDirective(func(i, j int, target string, targetType capability.TargetType, d *capability.LabelOutputDirective, scope manifestScope) error {
		// An enforce-time STATE directive rather than a response mutation, so it is valid on
		// any flow SOURCE target.
		if err := requireSourceDirectiveTarget(i, target, targetType, capability.DirectiveTypeLabelOutput); err != nil {
			return err
		}
		return validateLabelOutput(i, j, d.Labels, scope.flowNamespaces)
	}),
}

// typedDirective adapts a per-type validator to the discriminator-keyed table, normalizing the
// value and pointer decode forms to *T and REPORTING a type that does not match the
// discriminator it was filed under, rather than dereferencing nil — a programmatically built
// manifest (reachable through MergeManifests) can present a directive whose DirectiveType()
// lies about its concrete type.
func typedDirective[T any](check func(i, j int, target string, targetType capability.TargetType, d *T, scope manifestScope) error) directiveValidator {
	return func(i, j int, target string, targetType capability.TargetType, dir capability.Directive, scope manifestScope) error {
		d, ok := capability.AsValueOrPointer[T](dir)
		if !ok || d == nil {
			return fmt.Errorf("capability at index %d, directive %d: directive reports type %q but is not one; refusing rather than validating it as a type it is not",
				i, j, dir.DirectiveType())
		}
		return check(i, j, target, targetType, d, scope)
	}
}

// checkTokenGrammarVersion fails closed if any capability carries a token the declared
// schemaVersion does not admit (per capability.TokenSince) — the one authoritative
// grammar-version gate, so the per-type validation cases carry no version check and a new
// token cannot bypass it by omitting one. Runs after the per-capability structural
// validation, so ConditionType()/DirectiveType() cannot panic on a null or typed-nil entry.
func checkTokenGrammarVersion(m *LocalManifest) error {
	declared := strings.TrimSpace(m.SchemaVersion)
	// The effect layer's two non-condition tokens — effectCeiling and a constraint's effect
	// contract — are gated by the same rule here, since they have no registry entry of
	// their own. Through revisionAdmits, not an equality, so a semantics-only later
	// revision does not refuse its own token.
	if m.EffectCeiling != nil && !revisionAdmits(declared, ManifestSchemaVersion02) {
		return fmt.Errorf("the top-level effectCeiling was introduced in schemaVersion %q (the flow+effect grammar); this manifest declares schemaVersion %q, under which the key is not part of the grammar", ManifestSchemaVersion02, declared)
	}
	// The imported-sensitivity axis is part of the flow layer, so its namespace declaration
	// is gated with it: under "0.1" there is no flowLabel token to consume an imported label
	// in the first place, and admitting the key there would let a "0.1" manifest carry a
	// declaration whose only effect is to look enforced.
	if len(m.FlowLabelNamespaces) > 0 && !revisionAdmits(declared, ManifestSchemaVersion02) {
		return fmt.Errorf("the top-level flowLabelNamespaces was introduced in schemaVersion %q (the flow+effect grammar); this manifest declares schemaVersion %q, under which the key is not part of the grammar", ManifestSchemaVersion02, declared)
	}
	for i := range m.Capabilities {
		c := &m.Capabilities[i]
		if c.Effect != nil && !revisionAdmits(declared, ManifestSchemaVersion02) {
			return tokenGrammarVersionErr(i, "the effect contract block", ManifestSchemaVersion02, declared)
		}
		for _, cond := range c.Conditions {
			if err := checkTokenRevision(i, cond.ConditionType(), "condition", declared); err != nil {
				return err
			}
		}
		for _, dir := range c.Directives {
			if err := checkTokenRevision(i, dir.DirectiveType(), "directive", declared); err != nil {
				return err
			}
		}
		// Task-context variables are VALUES inside a condition that exists in both revisions,
		// so they carry no Since of their own either; gated here beside the other two.
		if err := checkTaskVarGrammarVersion(i, c, declared); err != nil {
			return err
		}
	}
	return nil
}

// checkTaskVarGrammarVersion rejects a ${task.*} reference under a revision that does not
// define it. Validation has already run, so this decides only whether the declared revision
// admits the surface at all.
func checkTaskVarGrammarVersion(i int, c *capability.Constraint, declared string) error {
	if revisionAdmits(declared, ManifestSchemaVersion02) {
		return nil
	}
	for _, cond := range c.Conditions {
		av, ok := capability.AsValueOrPointer[capability.AllowedValuesCondition](cond)
		if !ok || av == nil {
			continue
		}
		for _, val := range av.Values {
			s, isString := val.(string)
			if !isString || !capability.IsTaskVarRef(s) {
				// Only a RECOGNIZED reference is a "0.2" token; an unrecognized "${...}" under
				// "0.1" is a literal that revision has always accepted.
				continue
			}
			return tokenGrammarVersionErr(i, "the task-context variable "+s, ManifestSchemaVersion02, declared)
		}
	}
	return nil
}

// checkTokenRevision decides whether the declared revision admits one token, reading the
// introducing revision off pkg/capability's prototype registry (capability.TokenSince). A
// token this build cannot CLASSIFY is refused under every revision — the fail-closed reading
// of a gate with nothing to gate on, reachable only when a contributor adds a discriminator
// without declaring its Since. kind is "condition" or "directive", for the message only.
func checkTokenRevision(i int, token, kind, declared string) error {
	since, classified := capability.TokenSince(token)
	if !classified {
		return fmt.Errorf("capability at index %d: the %s %s is not classified into any published schemaVersion, so this build cannot decide whether schemaVersion %q admits it; refusing rather than guessing (a new token needs a Since on its pkg/capability prototype registry entry)",
			i, token, kind, declared)
	}
	if !revisionAdmits(declared, since) {
		return tokenGrammarVersionErr(i, "the "+token+" "+kind, since, declared)
	}
	return nil
}

// tokenGrammarVersionErr builds the fail-closed rejection for a token used under a
// schemaVersion that does not define it. Names the introducing revision and nothing else —
// naming it "the flow+effect grammar" would mislabel a token introduced by a later revision.
func tokenGrammarVersionErr(i int, feature, required, declared string) error {
	return fmt.Errorf("capability at index %d: %s was introduced in schemaVersion %q; this manifest declares schemaVersion %q, under which the token is not part of the grammar", i, feature, required, declared)
}

// requireResponseDirectiveTarget rejects a response-mutating directive (redactFields) on a
// non-tool target: the proxy redacts tools/call results only, so it would never apply — a
// fail-open leak plus a false "discharged" audit record.
func requireResponseDirectiveTarget(i int, target string, targetType capability.TargetType) error {
	if targetType != capability.TargetTypeTool {
		return fmt.Errorf("capability at index %d: constraint %q carries a redactFields directive; redactFields directives apply only to tool: targets (the proxy redacts tools/call results, not %s responses)", i, target, targetType)
	}
	return nil
}

// requireSourceDirectiveTarget restricts the flow-state directive labelOutput to tool: and
// resource: source targets. A prompt: or system: target is not a flow SOURCE (a
// sampling/createMessage request is an egress, a flowLabel SINK's place, not one that asserts
// taint) — this is why sampling can only ever be a flow sink.
func requireSourceDirectiveTarget(i int, target string, targetType capability.TargetType, directive string) error {
	if targetType != capability.TargetTypeTool && targetType != capability.TargetTypeResource {
		return fmt.Errorf("capability at index %d: constraint %q carries a %s directive, which is valid only on tool: or resource: source targets (a %s target is not a flow source)", i, target, directive, targetType)
	}
	return nil
}

// validateFlowLabelSet checks one authored label list against BOTH axes: a native class
// from the closed vocabulary, or an imported "namespace:value" whose namespace the manifest
// declared. It is the single label check the three flow tokens share, so a label legal in a
// labelOutput cannot be illegal in the flowLabel that reads it back.
//
// The declared-namespace half is what makes this the load-time closure the imported axis
// otherwise lacks: eunox cannot know the taxonomy's values, but it does know which
// taxonomies this policy said it speaks, so "purvew:confidential" fails here instead of
// becoming a label that taints where nothing admits it and reads as a mysterious denial.
func validateFlowLabelSet(where string, labels []string, declared map[string]bool) error {
	for _, l := range labels {
		if err := capability.ValidateFlowLabel(l); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		ns, _, imported := capability.SplitFlowLabel(l)
		if imported && !declared[ns] {
			return fmt.Errorf("%s: imported flow label %q names the sensitivity namespace %q, which this manifest does not declare — add it to the top-level 'flowLabelNamespaces' list (eunox does not own the taxonomy's values, so declaring the namespace is what makes a misspelled one a load error rather than a label that silently matches nothing)", where, l, ns)
		}
	}
	return nil
}

// validateFlowLabel checks a flowLabel condition's Allow set. An empty Allow is valid — it
// admits only an unlabeled, clean-context flow.
func validateFlowLabel(i, j int, allow []string, declared map[string]bool) error {
	return validateFlowLabelSet(fmt.Sprintf("capability at index %d, condition %d: flowLabel 'allow'", i, j), allow, declared)
}

// validateLabelOutput checks a labelOutput directive: a non-empty Labels list (an empty one
// records nothing and is an authoring mistake), every entry usable on one of the two axes.
func validateLabelOutput(i, j int, labels []string, declared map[string]bool) error {
	if len(labels) == 0 {
		return fmt.Errorf("capability at index %d, directive %d: labelOutput requires a non-empty 'labels' list naming the flow labels this call's output carries; an empty list records nothing", i, j)
	}
	return validateFlowLabelSet(fmt.Sprintf("capability at index %d, directive %d: labelOutput 'labels'", i, j), labels, declared)
}

// mergeFlowLabelNamespaces unions one file's declared sensitivity namespaces into the merged
// set, preserving first-seen order so the merged manifest renders deterministically.
//
// A UNION rather than mergeSingleValueField's conflict check, because a namespace
// declaration is a vocabulary the file's own capabilities draw on and not a bound over
// anyone else's: two files each declaring the taxonomy they use are composing, not
// disagreeing, and rejecting that would make the flow layer unusable across a split policy.
// Nothing widens — a namespace admits labels, and a label can only add taint or narrow an
// allow-set — so the union grants no capability either file did not already have.
func mergeFlowLabelNamespaces(merged, next []string) []string {
	if len(next) == 0 {
		return merged
	}
	// Capacity from the pre-populated side alone, not the two summed (CodeQL flags a
	// summed length as a potential allocation overflow); the map grows for the rest.
	seen := make(map[string]bool, len(merged))
	for _, ns := range merged {
		seen[ns] = true
	}
	for _, ns := range next {
		if !seen[ns] {
			seen[ns] = true
			merged = append(merged, ns)
		}
	}
	return merged
}

// validateFlowLabelNamespaces checks the top-level declaration itself: each entry
// well-formed, no duplicates. A duplicate is rejected rather than folded because a list that
// repeats an entry is an edit that went wrong, and silently accepting it is how the second
// spelling of a namespace survives review.
func validateFlowLabelNamespaces(namespaces []string) error {
	seen := make(map[string]bool, len(namespaces))
	for _, ns := range namespaces {
		if err := capability.ValidateFlowLabelNamespace(ns); err != nil {
			return fmt.Errorf("flowLabelNamespaces: %w", err)
		}
		if seen[ns] {
			return fmt.Errorf("flowLabelNamespaces declares %q twice", ns)
		}
		seen[ns] = true
	}
	return nil
}

// declaredFlowLabelNamespaces indexes the manifest's declaration for the per-label checks.
// Nil-safe and empty-safe: a policy declaring none simply admits no imported label, which is
// the correct reading of a manifest that never mentioned a taxonomy.
func declaredFlowLabelNamespaces(m *LocalManifest) map[string]bool {
	if m == nil || len(m.FlowLabelNamespaces) == 0 {
		return nil
	}
	set := make(map[string]bool, len(m.FlowLabelNamespaces))
	for _, ns := range m.FlowLabelNamespaces {
		set[ns] = true
	}
	return set
}

// validatePrincipal checks a constraint's principal scoping: every claim name must be one
// eunox can match on and must list at least one non-empty pattern, catching a typo at load.
func validatePrincipal(principal map[string][]string) error {
	if len(principal) == 0 {
		return nil
	}
	for claimName, patterns := range principal {
		if !capability.IsSupportedPrincipalClaim(claimName) {
			return fmt.Errorf("principal claim %q is not supported — valid claims are %s", claimName, strings.Join(capability.SupportedPrincipalClaimNames(), ", "))
		}
		if len(patterns) == 0 {
			return fmt.Errorf("principal claim %q must list at least one allowed value", claimName)
		}
		for _, p := range patterns {
			if strings.TrimSpace(p) == "" {
				return fmt.Errorf("principal claim %q has an empty value", claimName)
			}
			// PrincipalMatches skips an ErrBadPattern pattern, so an invalid glob would
			// silently never match; reject it at load instead.
			if _, err := stdpath.Match(p, ""); err != nil {
				return fmt.Errorf("principal claim %q has an invalid pattern %q: %w", claimName, p, err)
			}
		}
	}
	return nil
}

// checkManifestKeys rejects unknown keys anywhere in the manifest. The typed json.Unmarshal
// in LoadManifest is intentionally lenient at the struct level (those types are shared with
// IdP-issued JWT capability claims, which tolerate unknown fields), so without this a typo'd
// key would be silently dropped. This walk runs first because only it can name the offending
// path and suggest the intended key. argumentSchema keywords are checked by
// checkArgumentSchemaKeywords.
func checkManifestKeys(data []byte) error {
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		// Not a JSON object, so there are no keys to walk. NOT a judgement that the manifest
		// is acceptable — LoadManifest's typed decode, which runs immediately after this
		// check, rejects a non-object document.
		return nil //nolint:nilerr // a non-object document has no key structure to validate
	}
	if err := checkObjectKeys("", root, jsonFieldKeys(reflect.TypeOf(LocalManifest{}))); err != nil {
		return err
	}
	// The effect layer's nested objects are walked by their own checker: checkObjectKeys
	// above covers only the top-level key of each.
	if err := checkEffectKeys(root); err != nil {
		return err
	}
	caps, _ := root["capabilities"].([]interface{})
	capKeys := jsonFieldKeys(reflect.TypeOf(capability.Constraint{}))
	for i, raw := range caps {
		capObj, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		path := fmt.Sprintf("capabilities[%d]", i)
		if err := checkObjectKeys(path, capObj, capKeys); err != nil {
			return err
		}
		if as, ok := capObj["argumentSchema"]; ok {
			if err := checkArgumentSchemaKeywords(path+".argumentSchema", as); err != nil {
				return err
			}
		}
		if conds, ok := capObj["conditions"].([]interface{}); ok {
			for j, rc := range conds {
				condObj, ok := rc.(map[string]interface{})
				if !ok {
					continue
				}
				ct, _ := condObj["type"].(string)
				allowed, known := conditionKeysFor(ct)
				if !known {
					continue // unknown type is already rejected by the typed decode
				}
				if err := checkObjectKeys(fmt.Sprintf("%s.conditions[%d]", path, j), condObj, allowed); err != nil {
					return err
				}
			}
		}
		if dirs, ok := capObj["directives"].([]interface{}); ok {
			for j, rd := range dirs {
				dirObj, ok := rd.(map[string]interface{})
				if !ok {
					continue
				}
				dt, _ := dirObj["type"].(string)
				allowed, known := directiveKeysFor(dt)
				if !known {
					continue
				}
				if err := checkObjectKeys(fmt.Sprintf("%s.directives[%d]", path, j), dirObj, allowed); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// validJSONSchemaTypeNames is the set of `type` values argumentSchema accepts,
// matching schemaJSONTypeOf's classification (pkg/enforcement/schema.go) plus
// "integer", the numeric subtype schemaTypeCompatible special-cases.
var validJSONSchemaTypeNames = map[string]bool{
	"string":  true,
	"number":  true,
	"integer": true,
	"boolean": true,
	"object":  true,
	"array":   true,
	"null":    true,
}

// validateSchemaTypeValue checks a raw (not-yet-typed) `type` keyword value.
// capability.SchemaType.UnmarshalJSON normalizes an empty array the same as "no type
// declared", silently disabling the type check — this walks the RAW decoded value (which the
// typed SchemaType cannot distinguish from an absent key) and rejects the shapes that would
// silently weaken the declared policy. `type` is optional; an absent key or explicit `null`
// is valid.
func validateSchemaTypeValue(path string, raw interface{}) error {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		if v == "" {
			return fmt.Errorf("%s: type must not be an empty string — declare a JSON-Schema type name or omit type entirely", path)
		}
		if !validJSONSchemaTypeNames[v] {
			return fmt.Errorf("%s: unknown JSON-Schema type %q", path, v)
		}
		return nil
	case []interface{}:
		if len(v) == 0 {
			return fmt.Errorf("%s: type must not be an empty array — an empty array silently disables the type check rather than constraining it; declare at least one JSON-Schema type name or omit type entirely", path)
		}
		seen := make(map[string]bool, len(v))
		for _, elem := range v {
			s, ok := elem.(string)
			if !ok {
				return fmt.Errorf("%s: type array entries must be strings", path)
			}
			if s == "" {
				return fmt.Errorf("%s: type must not contain an empty string", path)
			}
			if !validJSONSchemaTypeNames[s] {
				return fmt.Errorf("%s: unknown JSON-Schema type %q", path, s)
			}
			if seen[s] {
				return fmt.Errorf("%s: duplicate type %q", path, s)
			}
			seen[s] = true
		}
		return nil
	default:
		// Unreachable via the typed decode (SchemaType.UnmarshalJSON already rejects
		// any shape other than string/array/null); fail closed defensively so a future
		// relaxation of that unmarshaler cannot silently slip an unchecked shape past
		// this validator too.
		return fmt.Errorf("%s: type must be a string, array of strings, or null", path)
	}
}

// argumentSchemaKeywords is the closed set of JSON-Schema keywords an argumentSchema may use.
// Anything outside it is rejected recursively (through properties and items). Keep in sync
// with capability.ArgumentSchema and pkg/enforcement/schema.go.
var argumentSchemaKeywords = map[string]bool{
	"type":                 true,
	"enum":                 true,
	"properties":           true,
	"required":             true,
	"additionalProperties": true,
	"items":                true,
	"minItems":             true,
	"maxItems":             true,
	"minLength":            true,
	"maxLength":            true,
	"pattern":              true,
	"minimum":              true,
	"maximum":              true,
	"description":          true,
}

// validateArgumentSchemaConsistency rejects a structurally unsatisfiable argumentSchema. When
// `additionalProperties` is false, every `required` name must appear in `properties`, or the
// field is both required and forbidden. Recurses through `properties` and `items`.
func validateArgumentSchemaConsistency(path string, s *capability.ArgumentSchema) error {
	if s == nil {
		return nil
	}
	if s.AdditionalProperties != nil && !*s.AdditionalProperties {
		for _, req := range s.Required {
			if _, ok := s.Properties[req]; !ok {
				return fmt.Errorf("%s: required field %q is not listed in properties, but additionalProperties is false — this schema is unsatisfiable; add %q to properties or drop it from required", path, req, req)
			}
		}
	}
	// Recurse into nested subschemas, visiting properties in a stable order for a
	// deterministic error.
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sub := s.Properties[name]
		// Reject an explicit null subschema (`properties: {x: null}`): it decodes to a nil
		// *ArgumentSchema, which the validator treats as "any" — a structural footgun. The
		// empty object `{}` is still accepted; only the anomalous null form is refused. The
		// sibling `items: null` is rejected in checkArgumentSchemaKeywords instead, since only
		// the raw layer can tell present-null from absent.
		if sub == nil {
			return fmt.Errorf("%s.properties.%s: property has a null schema, which would accept any value for the declared property — use an empty object {} for an explicit \"any\" subschema, or give the property a concrete schema", path, name)
		}
		if err := validateArgumentSchemaConsistency(path+".properties."+name, sub); err != nil {
			return err
		}
	}
	if s.Items != nil {
		if err := validateArgumentSchemaConsistency(path+".items", s.Items); err != nil {
			return err
		}
	}
	return nil
}

// checkArgumentSchemaKeywords walks an argumentSchema node (raw, as decoded from the
// manifest) and rejects the first keyword outside argumentSchemaKeywords, recursing into
// every subschema reachable through `properties` and `items`. It also rejects an explicit
// null `items` subschema — the array-element counterpart of the null-property rejection in
// validateArgumentSchemaConsistency, detectable only here since the typed Items pointer
// cannot distinguish present-null from absent.
func checkArgumentSchemaKeywords(path string, raw interface{}) error {
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !argumentSchemaKeywords[k] {
			if s := nearestKey(k, argumentSchemaKeywords); s != "" {
				return fmt.Errorf("%s: unknown keyword %q (did you mean %q?)", path, k, s)
			}
			return fmt.Errorf("%s: unknown keyword %q", path, k)
		}
	}
	if rawType, ok := obj["type"]; ok {
		if err := validateSchemaTypeValue(path+".type", rawType); err != nil {
			return err
		}
	}
	// properties is an object of name→subschema; items is a single subschema.
	if props, ok := obj["properties"].(map[string]interface{}); ok {
		names := make([]string, 0, len(props))
		for name := range props {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if err := checkArgumentSchemaKeywords(path+".properties."+name, props[name]); err != nil {
				return err
			}
		}
	}
	if items, ok := obj["items"]; ok {
		// Reject an explicit null items subschema (`items: null`): the typed Items pointer
		// cannot distinguish present-null from absent, so this raw layer catches it instead.
		// `items: {}` is the explicit "any element" and recurses cleanly.
		if items == nil {
			return fmt.Errorf("%s.items: array element schema is null, which would accept any element — use an empty object {} for an explicit \"any\" element schema, or give items a concrete schema", path)
		}
		if err := checkArgumentSchemaKeywords(path+".items", items); err != nil {
			return err
		}
	}
	return nil
}

// checkObjectKeys reports the first key in obj that is not in allowed, in deterministic
// (sorted) order. When a near match exists, it is offered as a "did you mean" hint.
func checkObjectKeys(path string, obj map[string]interface{}, allowed map[string]bool) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	where := path
	if where == "" {
		where = "manifest"
	}
	for _, k := range keys {
		if allowed[k] {
			continue
		}
		if s := nearestKey(k, allowed); s != "" {
			return fmt.Errorf("%s: unknown field %q (did you mean %q?)", where, k, s)
		}
		return fmt.Errorf("%s: unknown field %q", where, k)
	}
	return nil
}

// jsonFieldKeys returns the set of JSON object keys declared by struct type t, derived from
// its `json:"..."` field tags.
func jsonFieldKeys(t reflect.Type) map[string]bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		// An unexported, non-anonymous field is never a valid JSON key, so skip it — this
		// keeps a runtime-only field like IPRangeCondition.parsed from being mistaken for a
		// permitted manifest key.
		if !f.IsExported() && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := tag
		if comma := strings.IndexByte(tag, ','); comma >= 0 {
			name = tag[:comma]
		}
		// An untagged embedded struct promotes its JSON keys to the parent object, so its
		// own fields are the valid keys, not the embed's type name.
		if name == "" && f.Anonymous {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k := range jsonFieldKeys(ft) {
					out[k] = true
				}
				continue
			}
		}
		if name == "" {
			name = f.Name
		}
		out[name] = true
	}
	return out
}

// conditionKeysFor returns the permitted key set for a condition of the given discriminator
// type (always including "type"). The second result is false for a type this build does not
// model. The prototype comes from pkg/capability's ONE condition registry rather than a
// hand-mirrored switch, which failed silently by leaving a missing type's keys unchecked.
func conditionKeysFor(condType string) (map[string]bool, bool) {
	proto, known := capability.NewConditionPrototype(condType)
	if !known {
		return nil, false
	}
	keys := jsonFieldKeys(reflect.TypeOf(proto))
	keys["type"] = true
	return keys, true
}

// directiveKeysFor mirrors conditionKeysFor for directives — and, like it, reads the ONE
// registry rather than a hand-written type switch, which was a fail-open: a forgotten arm let
// a misspelled field load as an empty value.
func directiveKeysFor(dirType string) (map[string]bool, bool) {
	proto, known := capability.NewDirectivePrototype(dirType)
	if !known {
		return nil, false
	}
	keys := jsonFieldKeys(reflect.TypeOf(proto))
	keys["type"] = true
	return keys, true
}

// validateDescriptionHashFormat reports an error if s is not a valid
// "sha256:<64 lowercase hex chars>" description hash value. Delegates to
// capability.ValidateSHA256Pin, which the effect layer's ref pin also uses.
func validateDescriptionHashFormat(s string) error {
	return capability.ValidateSHA256Pin("descriptionHash", s)
}

// nearestKey returns the allowed key nearest to unknown, or "" if none is close
// enough. Candidates are sorted so ties resolve to the lexicographically first.
func nearestKey(unknown string, allowed map[string]bool) string {
	keys := make([]string, 0, len(allowed))
	for k := range allowed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return capability.NearestString(unknown, keys)
}
