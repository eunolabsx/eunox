// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package config holds the binary's configuration and manifest loading layer:
// the LocalManifest type with its load/validate/merge path (LoadManifest,
// MergeManifests), the GatewayConfig parser (LoadGatewayConfig), and the
// schema-version negotiation both documents share. It depends only on pkg/*,
// gopkg.in/yaml.v3 (config + manifest parsing), and the stdlib — never back on
// cmd/eunox — so the CLI subcommands and (soon) the transport layer can
// import the config types from a non-main home.
package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
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

// LocalManifest declares the capabilities an agent requires.
type LocalManifest struct {
	// SchemaVersion is the manifest grammar/dialect version (two-part, e.g.
	// "0.1"), distinct from the policy-content Version below. Required: a
	// manifest declaring an absent or unsupported schemaVersion is refused at
	// load (fail-closed). See schema_version.go.
	SchemaVersion string                  `json:"schemaVersion"`
	Name          string                  `json:"name"`
	Version       string                  `json:"version"`
	Description   string                  `json:"description,omitempty"`
	ServerVersion string                  `json:"serverVersion,omitempty"`
	Capabilities  []capability.Constraint `json:"capabilities"`
	DefaultTTL    int                     `json:"defaultTtl,omitempty"`
	// Audience, when set, pins the JWT 'aud' claim required on THIS route in gateway
	// mode: a token is authorized on the route only if its aud carries this value,
	// overriding the global --jwt-audience for the route (which stays the fallback for
	// routes that declare none). See WrapRoutesWithJWT in internal/transport/route.go and
	// the per-route check in internal/pdp/jwt.go; --jwt-allow-any-audience disables
	// audience pinning entirely. Single-upstream (non-gateway) mode does not consult this
	// field — its audience comes from --jwt-audience. On a multi-file merge it is folded
	// with a conflict check (first non-empty wins; two disagreeing files are rejected),
	// like serverVersion — never silently dropped. See docs/capability-manifest-guide.md.
	Audience string `json:"audience,omitempty"`
}

// LoadManifest reads and validates a LocalManifest from a manifest file of any
// extension (YAML, JSON, or none). Every file is decoded through a yaml.Node first
// (YAML is a JSON superset) so the fail-closed hardening — duplicate-key rejection,
// multi-document rejection, timestamp guard, scalar-coercion guard — applies
// uniformly; an unrecognized/absent extension no longer falls through to a bare
// json.Unmarshal that would skip those guards. The scalar-coercion guard runs for
// both formats but rejects a JSON number only when the coercion is numerically
// lossy (so valid JSON like values: [1.0] is still accepted). The node is then
// converted to JSON so the existing capability.Constraint JSON unmarshalling (with
// polymorphic conditions) is reused unchanged.
func LoadManifest(path string) (*LocalManifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a user-specified manifest file path (CLI argument)
	if err != nil {
		return nil, fmt.Errorf("reading manifest %q: %w", path, err)
	}
	if err := errIfBinaryConfig("manifest", path, data); err != nil {
		return nil, err
	}

	lp := strings.ToLower(path)
	// Route EVERY manifest — YAML, JSON, or an unrecognized/absent extension —
	// through the yaml.Node decode below. YAML is a JSON superset, so a .json file
	// parses cleanly here, and crucially node.Decode rejects DUPLICATE mapping keys
	// and multi-document streams. encoding/json silently keeps the last value for a
	// duplicated key, a fail-closed gap on a security-critical surface (e.g. two
	// `enforcement:` values), so an extensionless JSON-content file must NOT fall
	// through to a bare json.Unmarshal that skips these guards. errIfBinaryConfig
	// already screened binaries; genuine garbage fails the YAML parse loudly.
	// isJSON selects the numeric-coercion policy: a JSON number is unambiguous, so
	// the guard rejects only a NUMERICALLY lossy value (a beyond-float64 integer),
	// whereas YAML rejects any auto-typing (1.0 -> 1). Treat a file as JSON when it is
	// named .json OR has no recognized YAML extension but its content is valid JSON
	// (an extensionless or oddly-named JSON manifest). A .yaml/.yml file stays
	// YAML-strict even when it happens to be valid JSON — the operator chose YAML.
	// Content detection keeps an extensionless JSON manifest's non-canonical numbers
	// (e.g. values: [1.0]) accepted, matching the pre-hardening bare json.Unmarshal
	// path, while still routing every file through the yaml.Node hardening below.
	isYAMLExt := strings.HasSuffix(lp, ".yaml") || strings.HasSuffix(lp, ".yml")
	isJSON := strings.HasSuffix(lp, ".json") || (!isYAMLExt && json.Valid(data))
	what := "YAML manifest"
	if isJSON {
		what = "JSON manifest"
	}
	// A .json file must be valid JSON. The yaml.Node decode below gives us
	// duplicate-key rejection, but yaml.v3 also accepts the YAML SUPERSET (unquoted
	// keys, single-quoted strings, # comments, a bare non-object document), which would
	// silently admit a .json file that strict JSON rejects. Re-impose JSON strictness so
	// the .json extension still means JSON; the yaml.Node decode then layers duplicate-key
	// rejection on top. Only enforce it for a .json-EXTENSION file: a content-detected
	// JSON file (json.Valid already true) needs no recheck, and a .yaml file is exempt.
	if strings.HasSuffix(lp, ".json") && !json.Valid(data) {
		return nil, fmt.Errorf("parsing JSON manifest %q: content is not valid JSON", path)
	}
	// Decode into a yaml.Node (not interface{}) so we can suppress yaml.v3's
	// timestamp inference before the JSON round-trip: an unquoted date like
	// 2026-01-01 would otherwise become "2026-01-01T00:00:00Z", so an
	// allowedValues condition would silently enforce a different string than the
	// manifest text. See forceTimestampsToStrings.
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
	// Reject a multi-document stream: a second content-bearing "---" document
	// would be silently ignored, so an appended restrictive manifest would load
	// yet enforce none of it. A trailing empty/null document is tolerated, matching
	// the gateway-config loader.
	if err := rejectExtraYAMLDocuments(dec, path, what); err != nil {
		return nil, err
	}
	forceTimestampsToStrings(&node)
	// Reject a scalar in a condition values:/enum: list that auto-typed away from
	// its source text (YAML: 010 -> 8 octal, 1.0 -> 1 float; JSON: a beyond-float64
	// integer yaml.v3 rounds), which would otherwise silently enforce a value the
	// author did not write. The JSON path rejects only NUMERICALLY lossy coercions
	// (so valid JSON like values: [1.0] is still accepted); see
	// rejectCoercedScalarsForFormat.
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

	var m LocalManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest %q: %w", path, err)
	}
	// Gate on the declared grammar version before interpreting content: refuse an
	// unknown dialect rather than parse it under the wrong grammar.
	if err := validateManifestSchemaVersion(m.SchemaVersion); err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	// Canonicalize to the trimmed form validation accepted: an explicitly quoted
	// padded scalar (e.g. " 0.1") validates by trimming a copy, but the padding
	// otherwise survives into MergeManifests' exact-string conflict check and the
	// Digest(), causing spurious conflicts between " 0.1" and "0.1".
	m.SchemaVersion = strings.TrimSpace(m.SchemaVersion)
	// Reject unknown keys before required-field checks, so a typo (e.g.
	// `arguments` for `argument`) is reported as the typo rather than a downstream
	// "must not be empty".
	if err := checkManifestKeys(data); err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	if err := validateLocalManifest(&m); err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	return &m, nil
}

// rejectCoercedScalarsForFormat runs the scalar-coercion guard
// (rejectCoercedValueScalars) for both formats. For YAML it rejects any scalar
// whose canonical form differs textually from its source (010 -> 8, 1.0 -> 1).
// For JSON — whose numbers are unambiguous, so a 1.0 -> 1 textual difference is
// harmless — it rejects only a NUMERICALLY lossy coercion: an integer beyond
// float64 precision that yaml.v3's node.Decode rounds to a different value than
// written (the value pipeline is node.Decode -> json.Marshal, and yaml.v3 decodes
// an integer larger than uint64 to float64). Without this, a JSON allowlist value
// like 12345678901234567890123 loads rounded, silently widening the allowlist
// against a request arg that rounds to the same float64. Kept separate so
// LoadManifest's decode block stays flat.
func rejectCoercedScalarsForFormat(node *yaml.Node, isJSON bool, path string) error {
	if err := rejectCoercedValueScalars(node, isJSON); err != nil {
		return fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	return nil
}

// forceTimestampsToStrings retags every !!timestamp scalar to !!str so the
// subsequent node.Decode yields the literal text rather than a time.Time,
// stopping unquoted manifest dates from being rewritten to RFC3339 across the
// YAML->JSON conversion. Every other scalar type is left untouched.
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

// rejectCoercedValueScalars walks n and rejects any unquoted scalar in a condition
// "values:" (allowedValues) or argumentSchema "enum:" list that YAML auto-typed away
// from its written text — an unquoted leading-zero integer read as octal (010 -> 8),
// a decimal-pointed integer read as a float (1.0 -> 1), a sign/underscore/scientific
// form normalized on the way through. Such an entry makes the manifest enforce a
// value that differs from its own source (both an over-restriction — the intended
// literal is denied — and a widening — the coerced value is admitted), with no
// load-time signal.
//
// This closes the same class as the !!timestamp handling (forceTimestampsToStrings):
// yaml.v3 auto-types scalars the JSON/string model does not, and only !!timestamp
// was retagged. Rather than retag (which would turn a legitimately numeric allowlist
// entry into a string the engine's numericEqual could no longer match), this fails
// closed and forces the author to disambiguate: quote it ("010") to mean the string,
// or write the canonical number (8) to mean the number. Numbers whose text already
// round-trips (200, 1.5, -3) are untouched.
// numericPolicyScalarKeys are policy fields holding a bare numeric scalar (not a
// values:/enum: list) that carry the identical YAML auto-typing coercion risk: an
// unquoted leading-zero integer read as octal silently changes an enforced
// number, e.g. `maxCalls: {windowSeconds: 0600}` loads as 384 (a quietly
// shortened rate window) and `argumentSchema: {minimum: 010}` enforces 8, not
// 10. rejectCoercedValueScalars walks these the same way it walks values:/enum:
// list scalars.
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

func rejectCoercedValueScalars(n *yaml.Node, isJSON bool) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			// Follow an alias on the key too: `&vk values` anchored elsewhere and
			// referenced as `*vk: [010]` is a mapping key that is an AliasNode, not
			// a ScalarNode, so the switch below would silently skip it without this.
			key = resolveYAMLAlias(key)
			// Follow an alias so `values: *ref` (the whole list anchored elsewhere)
			// cannot smuggle a coerced scalar past the SequenceNode check below.
			val = resolveYAMLAlias(val)
			switch {
			case key.Kind == yaml.ScalarNode && (key.Value == "values" || key.Value == "enum") && val.Kind == yaml.SequenceNode:
				// One visited-set per list, shared across all its items: bounds a
				// self-referential anchor (values: &loop [*loop], which aliases back into
				// itself) and collapses an exponentially-branching (billion-laughs style)
				// alias graph to linear time. See checkValueScalarNotCoerced.
				seen := make(map[*yaml.Node]bool)
				for _, item := range val.Content {
					if err := checkValueScalarNotCoerced(item, key.Value, isJSON, seen); err != nil {
						return err
					}
				}
			case key.Kind == yaml.ScalarNode && numericPolicyScalarKeys[key.Value] && val.Kind == yaml.ScalarNode:
				if err := checkNumericFieldNotCoerced(val, key.Value, isJSON); err != nil {
					return err
				}
			}
		}
	}
	for _, child := range n.Content {
		if err := rejectCoercedValueScalars(child, isJSON); err != nil {
			return err
		}
	}
	return nil
}

// resolveYAMLAlias returns the node an alias points at (its anchored target), or n
// unchanged when it is not an alias. The coercion guard must inspect the anchored
// scalar, not the AliasNode (which has no Content and no Tag of its own), so a value
// written as `*ref` cannot bypass the check while node.Decode still resolves it to
// the coerced value.
func resolveYAMLAlias(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

// checkValueScalarNotCoerced rejects a single values:/enum: scalar that YAML
// auto-typed to a number whose canonical form differs from the author's source text.
// A quoted/block scalar (Style != 0) is an explicit string and is left alone; only an
// unquoted (plain) !!int/!!float is at risk, since !!str keeps the text verbatim and
// bool/null forms preserve their textual representation.
//
// seen is a visited set of *yaml.Node, one per top-level values:/enum: list (see
// rejectCoercedValueScalars), that guards the alias walk: a self-referential anchor
// (values: &loop [*loop], whose only element aliases back to the list itself) has no
// other cycle-breaking condition and previously recursed until the stack overflowed —
// an uncatchable fatal error that killed the whole process. The same guard collapses an
// exponentially-branching (billion-laughs style) alias graph to linear time, since each
// distinct anchor is only ever walked once.
func checkValueScalarNotCoerced(item *yaml.Node, listKey string, isJSON bool, seen map[*yaml.Node]bool) error {
	if item == nil || seen[item] {
		return nil
	}
	seen[item] = true
	if item.Kind == yaml.AliasNode {
		// A list element written as an alias (`*ref`) resolves to its anchored scalar,
		// which is what node.Decode will enforce — check that, not the AliasNode. Mark
		// the resolved target seen too (gated on Kind == AliasNode, not a bare
		// resolveYAMLAlias call: for a non-alias item, resolveYAMLAlias returns item
		// itself, and re-marking-and-checking the identical, already-just-marked pointer
		// would make every plain node look "already seen" on its first visit).
		item = resolveYAMLAlias(item)
		if item == nil || seen[item] {
			return nil
		}
		seen[item] = true
	}
	// A nested sequence or mapping element (e.g. `values: [[010]]`) is not itself a
	// scalar, but its children carry the same coercion risk one nesting level down.
	// The outer rejectCoercedValueScalars recursion does not re-apply this check to
	// them (they are not values:/enum:-keyed mappings), so descend here to keep the
	// guard depth-uniform. For a mapping this also walks the keys, since a coerced
	// numeric key is the same silent-drift class.
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
	// YAML: any textual difference (010 -> 8, 1.0 -> 1) is a silent auto-typing the
	// author did not write; fail closed and make them disambiguate. JSON: only a
	// numerically-lossy coercion is rejected (coercionError/numericallyEqual).
	return coercionError("entry", listKey, false, item, src, canonical, isJSON)
}

// scalarCoercion reports whether item is a plain (unquoted) !!int/!!float scalar
// whose YAML-decoded value differs textually from its source text — the shared
// coercion-detection core for both checkValueScalarNotCoerced (values:/enum: list
// entries) and checkNumericFieldNotCoerced (bare numeric policy fields). ok is
// false when item carries no coercion risk (not a plain numeric scalar, or a
// genuine decode failure that surfaces later at node.Decode instead).
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

// numericallyEqual reports whether src and canonical denote the same number,
// compared exactly via big.Rat so a beyond-float64-precision integer (which a
// naive float comparison could round to a false match) is judged correctly.
func numericallyEqual(src, canonical string) bool {
	srcRat, ok1 := new(big.Rat).SetString(src)
	canRat, ok2 := new(big.Rat).SetString(canonical)
	return ok1 && ok2 && srcRat.Cmp(canRat) == 0
}

// coercionError builds the "this literal number was silently coerced" error
// shared by checkValueScalarNotCoerced (a values:/enum: list entry, kind
// "entry") and checkNumericFieldNotCoerced (a bare numeric policy field, kind
// "value"), so the two message shapes cannot drift apart on a future wording
// tweak. label names the values:/enum: key or the policy field name; forField
// switches the two spots where a field's message additionally calls out that
// the coercion changes ENFORCED policy, not just an allowlist entry.
//
// For JSON, only a numerically-lossy coercion is rejected — JSON numbers are
// unambiguous, so a textual difference like 1.0 -> 1 is harmless — returning
// nil when src and canonical are numerically equal. For YAML, any textual
// difference is a silent auto-typing the author did not write, and is always
// rejected (scalarCoercion already confirmed src != canonical before this is
// called).
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

// checkNumericFieldNotCoerced rejects a bare numeric policy field (maxCalls'
// count/windowSeconds, argumentSchema's minimum/maximum/minLength/maxLength/
// minItems/maxItems — see numericPolicyScalarKeys) whose YAML auto-typed value
// differs textually from its source. This is the same coercion class
// checkValueScalarNotCoerced catches for values:/enum: list scalars, but here the
// coercion directly changes an enforced number (a rate-limit window, an argument
// bound) rather than an allowlist entry.
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
// Pure-metadata fields (name, version, description, defaultTtl) are inherited from
// the first manifest — none feeds enforcement or drift, so dropping the rest loses
// nothing.
//
// Single-value fields that DO drive enforcement or drift — serverVersion (FM-4),
// schemaVersion, and audience — are folded instead: the first non-empty value is adopted
// so a value set in any one file survives, and two files with *conflicting* non-empty
// values are rejected. Silently collapsing serverVersion would disable a later pin;
// audience pins the per-route JWT audience in gateway mode (see LocalManifest.Audience
// and WrapRoutesWithJWT), so dropping a later file's value would silently widen the
// route's accepted audience — the same fail-closed loss the fold prevents.
//
// The merge is likewise rejected when two capabilities from DIFFERENT files tie
// in the engine's equal-specificity selection, whose declaration-order tie-break
// would silently shadow the later one. See detectMergeConflicts.
func MergeManifests(ms []*LocalManifest) (*LocalManifest, error) {
	if len(ms) == 0 {
		// Empty input yields an empty manifest (zero capabilities ⟹ deny
		// everything). The empty sentinel has no name, so it skips
		// validateLocalManifest.
		return &LocalManifest{}, nil
	}
	if len(ms) == 1 {
		return ms[0], nil
	}
	if err := detectMergeConflicts(ms); err != nil {
		return nil, err
	}
	// ServerVersion, SchemaVersion, and Audience are enforcement/drift-bearing single
	// values, so they are folded by the loop below WITH a conflict check (first non-empty
	// wins; two disagreeing non-empty values are rejected) and deliberately not pre-seeded
	// here. Audience pins the per-route JWT audience in gateway mode, so silently keeping
	// only the first file's value would drop a pin declared in a later file — the same
	// fail-closed loss mergeSingleValueField prevents for serverVersion.
	merged := &LocalManifest{
		Name:        ms[0].Name,
		Version:     ms[0].Version,
		Description: ms[0].Description,
		DefaultTTL:  ms[0].DefaultTTL,
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
	}
	// Re-validate the merged union. This is load-bearing, not merely defensive: two
	// individually-valid files can each pin the SAME tool to a DIFFERENT descriptionHash,
	// and only the merged whole is ambiguous — validateLocalManifest's conflicting-pin
	// check catches that here (it cannot be seen on either file alone). It also guards a
	// future merge change from producing an otherwise-invalid manifest. Do not drop it.
	if err := validateLocalManifest(merged); err != nil {
		return nil, fmt.Errorf("merged manifest is invalid: %w", err)
	}
	return merged, nil
}

// mergeSingleValueField folds one manifest's value for a single-valued top-level
// field into the accumulating merged value: first non-empty wins (so a pin in any
// one file survives), and a second, disagreeing non-empty value is rejected
// rather than silently dropped.
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

// detectMergeConflicts rejects a merge in which two capabilities from DIFFERENT
// manifests target the same resource with overlapping actions and principal
// scopes a single request can satisfy at once. The engine scores such a pair
// identically and breaks the tie by declaration order; across files that is just
// the order the policy files are listed, so the effective policy silently depends
// on file order (appending a file to tighten could leave it inert, or downgrade a
// later restrictive entry to allow-and-log) — a fail-open. Surface it at load.
//
// Two capabilities from the SAME manifest are left alone: within one file the
// first-in-order tie-break is documented behavior and visible in one place.
//
// Whether a pair ties uses the engine's own rules — targetsCanTie, actionsOverlap,
// principalsConflict — which compare by SEMANTIC overlap, not byte-equality, so a
// glob pair like `tool:read_*` / `tool:*_file` (both matching `read_file`) or two
// co-satisfiable scopes keyed on different claims are still caught. Only pairs no
// single request can satisfy together are exempt.
func detectMergeConflicts(ms []*LocalManifest) error {
	// prior records every capability seen and its manifest, so a later one can be
	// compared pairwise (not via a string-keyed map) against every earlier
	// cross-file one whose target could OVERLAP — catching glob pairs like
	// `read_*` / `*_file` that same-string keying would miss.
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

// targetsCanTie reports whether two targets could both match a single request and
// so tie. Different namespaces never tie; within a namespace it reduces to whether
// the bare patterns overlap. An unparseable target is treated as potentially tying
// (fail closed); validateLocalManifest rejects such targets earlier, so this is
// defense-in-depth.
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

// globTargetsOverlap reports whether two bare target patterns could TIE — the
// only case producing a silent file-order shadow. Identical targets tie; two
// distinct literals never tie; a literal and a glob covering it do NOT tie (the
// exact match outranks the glob regardless of order). Two overlapping globs tie
// only when the engine's own specificity scoring (enforcement.ResourceSpecificity)
// would rank them equally — a different-specificity pair is resolved
// deterministically by the engine regardless of file order, so it is not a tie.
//
// This shares the equal/literal-vs-literal/glob skeleton with patternPairCanOverlap
// (principal-claim overlap) but answers a deliberately DIFFERENT question, so the
// two are kept separate rather than merged:
//   - matcher: target overlap uses enforcement.MatchesResource semantics (resource
//     segments, "**"); principal overlap uses stdpath.Match (claim values).
//   - glob-vs-glob: here two globs can be PROVEN disjoint via literalPrefixesDisjoint,
//     and are further screened by specificity — a literal-vs-glob pair does NOT tie
//     (the literal's exact match outranks the glob by specificity); patternPairCanOverlap
//     treats glob-vs-glob as always overlapping and a literal-vs-glob pair as
//     overlapping, because principals carry no specificity ranking to break a tie. A
//     change to glob semantics must be applied to whichever of the two it concerns,
//     NOT blindly mirrored.
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
		// Overlapping globs of different specificity never tie in the engine: it
		// deterministically picks the more-specific one (resourceSpecificity),
		// regardless of policy-file order, so only an equal-specificity pair is a
		// genuine file-order shadow. toolName is passed as "" (a value neither
		// pattern equals, since both contain glob metacharacters) so
		// ResourceSpecificity always takes its literal/wildcard-counting branch
		// rather than its exact-match shortcut.
		return enforcement.ResourceSpecificity(a, "") == enforcement.ResourceSpecificity(b, "")
	default:
		// One literal, one glob: the literal's exact match outranks the glob, so
		// the engine resolves the overlap deterministically — no order shadow.
		return false
	}
}

// literalPrefix returns the leading run of pattern containing no glob
// metacharacter — the bytes every matching name must begin with verbatim. It reads
// capability.GlobMetaChars so the set cannot drift from ContainsGlobMeta.
func literalPrefix(pattern string) string {
	if i := strings.IndexAny(pattern, capability.GlobMetaChars); i >= 0 {
		return pattern[:i]
	}
	return pattern
}

// literalPrefixesDisjoint reports whether two glob patterns can be PROVEN to share
// no matching name from their mandatory literal prefixes alone: a single name
// would have to begin with both prefixes verbatim, impossible unless one prefix is
// a prefix of the other. It is sound (never reports disjoint for patterns that
// actually overlap) but incomplete — patterns it cannot separate are treated as
// overlapping by the caller (fail closed).
func literalPrefixesDisjoint(a, b string) bool {
	pa, pb := literalPrefix(a), literalPrefix(b)
	return !strings.HasPrefix(pa, pb) && !strings.HasPrefix(pb, pa)
}

// principalsConflict reports whether two constraints' principal scopes can be
// satisfied by a single request (the principal half of a positional tie):
//
//   - Two general (unscoped) entries always both match, so they conflict.
//   - A general entry and a scoped one do NOT conflict: the engine prefers the
//     scoped entry when its principal matches, otherwise the general one,
//     deterministically.
//   - Two scoped entries conflict unless some claim named by BOTH pins the request
//     to disjoint values. A claim named by only one cannot separate them, so two
//     entries keyed on entirely DIFFERENT claims (sub vs iss) DO conflict. Mirrors
//     PrincipalMatches, which ANDs a scope across its own claims.
func principalsConflict(a, b map[string][]string) bool {
	aScoped, bScoped := len(a) > 0, len(b) > 0
	if !aScoped || !bScoped {
		// A general/scoped pair the engine resolves deterministically, so it is
		// never a positional tie; only two general entries always co-match.
		return !aScoped && !bScoped
	}
	for claim, aPats := range a {
		if bPats, ok := b[claim]; ok && !patternsCanOverlap(aPats, bPats) {
			return false // a shared claim is pinned to disjoint values
		}
	}
	return true
}

// patternsCanOverlap reports whether some single claim value matches at least one
// pattern in each list (i.e. the sets are not provably disjoint). Exact for
// literals and a literal-vs-glob; two globs are conservatively treated as
// overlapping (fail closed). Glob semantics are path.Match's, matching the engine.
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

// patternPairCanOverlap reports whether a single claim value can satisfy both
// patterns. It mirrors globTargetsOverlap's equal/literal/glob skeleton but for
// PRINCIPAL claims, with two deliberate differences (see globTargetsOverlap):
// principal matching uses stdpath.Match (not enforcement.MatchesResource), and two
// globs — and a literal-vs-glob pair — are treated as overlapping rather than
// specificity-ranked, because principal scopes have no specificity ordering to
// break a positional tie. Keep the divergence in mind before "unifying" the two.
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

// actionsOverlap reports whether two action lists share at least one action a
// single request could exercise. The "*" wildcard overlaps every action. The
// lists are tiny (one verb plus an optional wildcard per target type), so the
// nested scan is cheap.
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

// serverVersionPinRe is the grammar matchServerVersion supports: a dot-separated
// version string of version tokens or "*" wildcards. matchServerVersion does
// component-wise equality, NOT semver-range comparison, so a range like ">=2.0.0"
// or "1.2.* || 2.0.*" would split into components no version matches — a pin that
// can never be satisfied and blocks every session under strictDrift. Validating
// here turns that silent blackout into an up-front manifest error.
var serverVersionPinRe = regexp.MustCompile(`^[0-9A-Za-z*][0-9A-Za-z.*+_-]*$`)

func validateLocalManifest(m *LocalManifest) error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("'name' must not be empty")
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
		// dot-component; a mid-component form like "1.2*" splits into component "2*",
		// which equals no live version and makes FM-4 fire every session (fatal under
		// strictDrift). Reject it up front rather than ship a pin that can never match.
		for _, part := range strings.Split(m.ServerVersion, ".") {
			if strings.Contains(part, "*") && part != "*" {
				return fmt.Errorf("'serverVersion' wildcard must be a whole dot-component (e.g. \"1.2.*\", not \"1.2*\"); component %q mixes a literal with '*' and would never match, got %q", part, m.ServerVersion)
			}
		}
	}
	// Audience, when set, pins the JWT 'aud' claim compared VERBATIM against the
	// route's required audience; a normal token carries a whitespace-free aud, so
	// surrounding whitespace on the manifest value would never match and would
	// silently deny every call on the route. Reject it up front like the other
	// match-sensitive fields (allowedTables/allowedOperations/recipientDomain).
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
	// is rejected as an ambiguous pin. The ambiguity is a static property of the manifest
	// text (two exact-tool entries for one name are permitted — first-wins tie-break — but
	// two DIFFERENT hashes for one name cannot both be authoritative), so it is caught here at
	// load rather than carried into the PDP's hot enforcement path. MergeManifests re-runs this
	// validator on the merged result, so a conflict arising across separate --policy files is
	// caught too. See the per-entry accumulation in the descriptionHash block below.
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
		// Validate descriptionHash when present. FM-5 startup verification fetches
		// tools/list only, so the pin is only meaningful on tool: targets.
		// Glob targets are also rejected: a single hash cannot represent the
		// description of every tool the glob might match.
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
			// Reject a conflicting pin: this is a pinned exact tool (tool target, non-glob,
			// valid hash), so if an earlier entry pinned the same bare name to a different
			// hash the manifest is ambiguous — neither hash can be the authoritative
			// description for the same tool. Fail closed at load with a clear error rather
			// than let the ambiguity reach the enforcement path.
			if prev, ok := pinnedHashByTool[bare]; ok && prev != c.DescriptionHash {
				return fmt.Errorf("capability at index %d: conflicting descriptionHash pins for tool %q — %q and %q; a tool cannot be pinned to two different descriptions, so remove or reconcile one of the entries", i, bare, prev, c.DescriptionHash)
			}
			pinnedHashByTool[bare] = c.DescriptionHash
		}
		if c.ArgumentSchema != nil {
			// argumentSchema validates a tool-call's argument map and the spec
			// scopes it to tool: targets. A resource:/prompt:/system: request carries
			// no such map, so accepting one is a fail-open (a guard with no runtime
			// effect). Reject at load.
			if targetType != capability.TargetTypeTool {
				return fmt.Errorf("capability at index %d: constraint %q carries an argumentSchema, which applies only to tool: targets (the proxy validates tool-call arguments structurally; %s requests carry no tool-argument map to validate)", i, c.Target, targetType)
			}
			// Compile every `pattern` once at load: a malformed regex is rejected
			// here (fail closed) instead of denying the first live request, and each
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
		// Validate directives. redactFields mutates the tools/call RESPONSE and so
		// applies only to tool: targets (a directive that never applies is a fail-open
		// leak plus a false "discharged" audit record). labelOutput is different: it is
		// an enforce-time state directive that records flow labels on allow, not a
		// response mutation, so it is valid on any source target and is staged behind the
		// flow+effect draft schemaVersion. A null directive is rejected fail-closed like
		// a null condition.
		for j, dir := range c.Directives {
			if dir == nil {
				return fmt.Errorf("capability at index %d, directive %d: a null directive is not permitted; every directives entry must be a typed directive object", i, j)
			}
			// A typed-nil pointer (e.g. (*LabelOutputDirective)(nil)) is a non-nil
			// interface, so it survives the dir==nil check above but would panic when a
			// case below dereferences d.Fields/d.Labels. Reject it fail-closed, matching
			// the engine's collectObligations typed-nil guard (same capability.IsTypedNil).
			if capability.IsTypedNil(dir) {
				return fmt.Errorf("capability at index %d, directive %d: a typed-nil directive is not permitted; every directives entry must be a typed directive object", i, j)
			}
			// Each case pairs a directive's value and pointer decode forms and
			// re-normalizes to a pointer via AsValueOrPointer: the case types make that
			// assertion infallible and the typed-nil guard above makes the deref safe, so
			// the two logical directives need two arms, not four. An unrecognized directive
			// type hits the fail-closed default — the YAML/JSON loader only produces the two
			// known types (and rejects unknowns at decode), so this is defense in depth
			// against a programmatically built manifest, not a manifest-author hole.
			switch dir.(type) {
			case capability.RedactFieldsDirective, *capability.RedactFieldsDirective:
				d, _ := capability.AsValueOrPointer[capability.RedactFieldsDirective](dir)
				if err := requireResponseDirectiveTarget(i, c.Target, targetType); err != nil {
					return err
				}
				if err := validateRedactFields(i, j, d.Fields); err != nil {
					return err
				}
			case capability.LabelOutputDirective, *capability.LabelOutputDirective:
				d, _ := capability.AsValueOrPointer[capability.LabelOutputDirective](dir)
				if err := requireSourceDirectiveTarget(i, c.Target, targetType); err != nil {
					return err
				}
				if err := validateLabelOutput(i, j, d.Labels); err != nil {
					return err
				}
			default:
				return fmt.Errorf("capability at index %d, directive %d: unrecognized directive type %q; the only supported directives are redactFields and labelOutput", i, j, dir.DirectiveType())
			}
		}
		// Reject two maxCalls sharing a windowSeconds before the per-condition pass,
		// so the cross-condition collision is reported clearly. See
		// validateMaxCallsWindowsDistinct.
		if err := validateMaxCallsWindowsDistinct(i, c.Conditions); err != nil {
			return err
		}
		// Validate conditions. Conditions needing an explicit argument name fail
		// closed at runtime when it is empty; reject them here instead.
		for j, cond := range c.Conditions {
			// A null conditions entry (YAML `~`/JSON null) decodes to a nil Condition and
			// would slip through this type switch (no case matches nil), then panic the
			// engine at request time when it calls ConditionType() on the nil interface —
			// a whole-proxy DoS from one route manifest. Reject it at load, fail closed.
			if cond == nil {
				return fmt.Errorf("capability at index %d, condition %d: a null condition is not permitted; every conditions entry must be a typed condition object", i, j)
			}
			// A typed-nil pointer (e.g. (*FlowLabelCondition)(nil)) is a non-nil interface,
			// so it survives the cond==nil check above but would panic when a *Condition case
			// below dereferences v (e.g. v.Allow). Reject it fail-closed, mirroring the
			// directive loop's typed-nil guard (same capability.IsTypedNil).
			if capability.IsTypedNil(cond) {
				return fmt.Errorf("capability at index %d, condition %d: a typed-nil condition is not permitted; every conditions entry must be a typed condition object", i, j)
			}
			switch v := cond.(type) {
			case capability.AllowedOperationsCondition:
				if err := validateAllowedOperations(i, j, &v); err != nil {
					return err
				}
			case *capability.AllowedOperationsCondition:
				if err := validateAllowedOperations(i, j, v); err != nil {
					return err
				}
			case capability.AllowedExtensionsCondition:
				if err := validateAllowedExtensions(i, j, &v); err != nil {
					return err
				}
			case *capability.AllowedExtensionsCondition:
				if err := validateAllowedExtensions(i, j, v); err != nil {
					return err
				}
			case capability.AllowedTablesCondition:
				if err := validateAllowedTables(i, j, &v); err != nil {
					return err
				}
			case *capability.AllowedTablesCondition:
				if err := validateAllowedTables(i, j, v); err != nil {
					return err
				}
			case capability.RecipientDomainCondition:
				if err := validateRecipientDomain(i, j, &v); err != nil {
					return err
				}
			case *capability.RecipientDomainCondition:
				if err := validateRecipientDomain(i, j, v); err != nil {
					return err
				}
			case capability.AllowedValuesCondition:
				if err := validateAllowedValues(i, j, &v); err != nil {
					return err
				}
			case *capability.AllowedValuesCondition:
				if err := validateAllowedValues(i, j, v); err != nil {
					return err
				}
			case capability.MaxCallsCondition:
				if err := validateMaxCalls(i, j, &v); err != nil {
					return err
				}
			case *capability.MaxCallsCondition:
				if err := validateMaxCalls(i, j, v); err != nil {
					return err
				}
			case capability.IPRangeCondition:
				if err := validateIPRange(i, j, &v); err != nil {
					return err
				}
			case *capability.IPRangeCondition:
				if err := validateIPRange(i, j, v); err != nil {
					return err
				}
				// Pre-compile the CIDRs into *net.IPNet once at load so the hot path
				// never re-parses them. Only the pointer case is evaluated at runtime
				// (the value case is a copy). validateIPRange already confirmed they
				// parse; fail closed if Compile somehow errors.
				if err := v.Compile(); err != nil {
					return fmt.Errorf("capability at index %d, condition %d: %w", i, j, err)
				}
			case capability.TimeWindowCondition:
				if err := validateTimeWindow(i, j, &v); err != nil {
					return err
				}
			case *capability.TimeWindowCondition:
				if err := validateTimeWindow(i, j, v); err != nil {
					return err
				}
				// Pre-parse notBefore/notAfter into time.Time once at load so the hot
				// path never re-parses RFC3339 (mirrors the IPRange Compile above). Only
				// the pointer case is evaluated at runtime (the value case is a copy).
				// validateTimeWindow already confirmed they parse; fail closed if Compile
				// somehow errors.
				if err := v.Compile(); err != nil {
					return fmt.Errorf("capability at index %d, condition %d: %w", i, j, err)
				}
			case capability.SequenceBlockCondition:
				if err := validateSequenceBlock(i, j, &v); err != nil {
					return err
				}
			case *capability.SequenceBlockCondition:
				if err := validateSequenceBlock(i, j, v); err != nil {
					return err
				}
			case capability.FlowLabelCondition:
				if err := validateFlowLabel(i, j, v.Allow); err != nil {
					return err
				}
			case *capability.FlowLabelCondition:
				if err := validateFlowLabel(i, j, v.Allow); err != nil {
					return err
				}
			}
		}
	}
	// Single authoritative staging gate: reject any DRAFT-staged token the declared
	// schemaVersion does not admit. Runs after the per-capability loop (so every
	// condition/directive is non-nil and well-typed) rather than at each token's
	// validation case, so a future staged token cannot slip under the published grammar
	// by omitting a per-case gate.
	if err := checkExperimentalTokenStaging(m); err != nil {
		return err
	}
	return nil
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

// isBareWildcardTarget reports whether the bare pattern is a match-everything
// target with nothing to scope it — a run of "*"/"?" that includes at least one
// "*" ("*", "**", "*?", "?*", …). Rejected as too broad for tool: and resource:.
// A run of ONLY "?" (e.g. "?", "??") is NOT rejected here: path.Match's "?"
// matches exactly one character, so "??" matches only two-character names — a
// bounded, legitimately-scoped target, not match-everything. Requiring a "*" in
// the trimmed-to-empty pattern is what closes the tool:*? / tool:?* bypass
// (mixing in a "*" makes the run match any non-empty name) without also
// rejecting a pure fixed-length "?" pattern. prompt:* is the documented
// exception and never routed here.
func isBareWildcardTarget(bare string) bool {
	return bare != "" && strings.Trim(bare, "*?") == "" && strings.Contains(bare, "*")
}

// resourceOpaqueURIWildcard reports whether bare is an opaque (non-hierarchical)
// resource URI (e.g. urn:…, mailto:… — a scheme with no "//" authority) carrying a
// glob metacharacter. Opaque URIs match by exact equality only, so any wildcard in
// one is rejected at load.
//
// Opaqueness is decided solely by the absence of a "//" authority component: a "/"
// in the scheme-specific part does NOT make the URI hierarchical. A URN's
// namespace-specific string ("urn:example:foo/bar") or a path-like opaque value
// routinely contains "/", yet still matches by exact equality — so a glob in one
// must be rejected too. (Keying off any "/" let "urn:example:foo/bar*" slip past
// this guard, contradicting the stated invariant.)
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

// validateArgumentRef rejects a condition 'argument' reference that fails closed at
// runtime: an empty reference (every call denied for want of a named parameter), or
// a malformed nested "$." path — an empty body ("$."), an empty segment ("$.a..b"),
// or a trailing dot ("$.a."). ArgumentPathSegments returns nil for such a path, and
// ResolveArgument fails closed on a nil segment list (the same signal as a missing
// argument), so the condition silently denies every matching call with no load-time
// signal. Catch both at validate time. emptyMsg is the condition-specific message
// for the empty case (each validator already had a tailored one). Argument-bearing
// condition validators call this in place of their old `v.Argument == ""` check.
func validateArgumentRef(i, j int, argument, emptyMsg string) error {
	if argument == "" {
		return fmt.Errorf("capability at index %d, condition %d: %s", i, j, emptyMsg)
	}
	if capability.IsArgumentPath(argument) && capability.ArgumentPathSegments(argument) == nil {
		return fmt.Errorf("capability at index %d, condition %d: 'argument' %q is a malformed \"$.\" path (empty body, empty segment, or trailing dot); it would resolve to nothing and silently deny every call — write a well-formed path such as \"$.a.b\", or a bare top-level key", i, j, argument)
	}
	return nil
}

// validateAllowedTables rejects an allowedTables condition that fails closed or
// enforces non-deterministically: a missing 'argument' (every call denied), or
// two 'columns' keys differing only in case. Column-map keys are matched
// case-insensitively, so case variants like {users, Users} address one table and
// the engine lowercases them into a single key where one silently overwrites the
// other — and which survives depends on randomized map iteration order. Reject the
// contradiction at load (the 'tables' list tolerates case variants since it builds
// a plain membership set, losing nothing).
func validateAllowedTables(i, j int, v *capability.AllowedTablesCondition) error {
	if err := validateArgumentRef(i, j, v.Argument, "allowedTables requires an 'argument' field naming the tool parameter that carries the table name"); err != nil {
		return err
	}
	// An empty 'tables' list denies every call (column entries cannot rescue it —
	// they apply only to already-allowed tables). Reject so a `table:`/`tables:`
	// typo surfaces at validate-time.
	if len(v.Tables) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: allowedTables requires a non-empty 'tables' list; an empty list matches no table and denies every call", i, j)
	}
	// A blank/whitespace entry never matches a real table name, so an all-blank
	// list denies every call like an empty one. Reject any blank entry.
	for k, table := range v.Tables {
		if strings.TrimSpace(table) == "" {
			return fmt.Errorf("capability at index %d, condition %d, table %d: allowedTables contains an empty or whitespace-only table entry; remove it or replace it with a real table name", i, j, k)
		}
		// Surrounding whitespace is the same footgun as a blank entry: request table
		// names are trimmed before matching, so " users" would never match and would
		// silently deny every call. Reject it at load like the all-blank case.
		if table != strings.TrimSpace(table) {
			return fmt.Errorf("capability at index %d, condition %d, table %d: allowedTables entry %q has leading or trailing whitespace; table names are trimmed before matching, so this entry would never match and would silently deny every call — remove the surrounding whitespace", i, j, k, table)
		}
	}
	seen := make(map[string]string, len(v.Columns))
	for table, cols := range v.Columns {
		key := strings.ToLower(table)
		if prior, dup := seen[key]; dup {
			return fmt.Errorf("capability at index %d, condition %d: allowedTables 'columns' has case-colliding keys %q and %q; table names are matched case-insensitively, so they address the same table and one column allowlist would non-deterministically overwrite the other — merge them under a single key", i, j, prior, table)
		}
		seen[key] = table
		// An empty column allowlist denies every access to the table
		// unconditionally (the runtime treats it as a present-but-unsatisfiable
		// restriction), even though the table is listed in 'tables'. To allow any
		// column, OMIT the key; to deny the table, remove it from 'tables'. Reject at
		// load.
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
func validateAllowedValues(i, j int, v *capability.AllowedValuesCondition) error {
	if err := validateArgumentRef(i, j, v.Argument, "allowedValues requires an 'argument' field naming the tool parameter to check (e.g. argument: path)"); err != nil {
		return err
	}
	if len(v.Values) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: allowedValues requires a non-empty 'values' list; an empty list matches nothing and denies every call", i, j)
	}
	// String values double as MatchValueGlob patterns at runtime. A malformed
	// pattern (e.g. unclosed "[invalid") is silently treated as a non-match,
	// quietly tightening the policy. Validate through enforcement.ValidateValueGlob,
	// the same decomposition the runtime matcher uses, so a "**"-bearing pattern is
	// caught here too.
	for k, val := range v.Values {
		s, ok := val.(string)
		if !ok {
			continue
		}
		if err := enforcement.ValidateValueGlob(s); err != nil {
			return fmt.Errorf("capability at index %d, condition %d, value %d: allowedValues contains invalid glob pattern %q: %w", i, j, k, s, err)
		}
	}
	return nil
}

// validateRedactFields rejects the structurally malformed redactFields paths the
// runtime redactor (pdp.RedactDotPath) would silently no-op on — forwarding the
// field unredacted while the audit record reports redaction applied, a fail-open
// leak. The redactor splits on '.' and looks up each segment as a literal object
// key, so array-index notation ("users[0].ssn"), an empty segment ("a..b"), or a
// segment with surrounding whitespace never resolves. A plain dot path
// ("users.ssn") already redacts from every array element, so the index is unneeded.
//
// This catches malformed SYNTAX, not every possible no-op. The '.' separator is
// inherently ambiguous: a dot path "a.b" targets nested object a -> key b, so a
// FLAT upstream key literally named "a.b" (legal JSON) is unaddressable and is
// redacted by no path — a silent no-op this validator does not (and cannot, from
// the manifest alone) detect. Keys containing a literal '.' cannot be targeted; see
// docs/capability-manifest-guide.md.
func validateRedactFields(i, j int, fields []string) error {
	// An empty (or omitted) fields list declares a redaction that redacts nothing
	// while enforcedForwardCore still records the redactFields obligation as applied
	// — a fail-open leak of a declared DLP control plus a falsely "discharged" audit
	// record. The per-field loop below cannot catch this degenerate shape, so reject
	// it up front, mirroring the other fail-open guards in this function.
	if len(fields) == 0 {
		return fmt.Errorf("capability at index %d, directive %d: redactFields requires a non-empty 'fields' list; an empty list declares a redaction that redacts nothing while the audit log reports it applied — list the field(s) to redact (e.g. fields: [\"users.ssn\"]) or remove the directive", i, j)
	}
	for _, field := range fields {
		if strings.ContainsAny(field, "[]") {
			return fmt.Errorf("capability at index %d, directive %d: redactFields path %q uses array-index notation ('[N]'), which is not supported and would silently redact nothing; use a dot path such as \"users.ssn\" to redact the field from every array element, or omit the index", i, j, field)
		}
		// Strip the leading root marker ("$." or a lone "$") before splitting, mirroring
		// RedactDotPath. Any OTHER "$"-prefixed form is rejected below: the runtime
		// normalizeDotPathRoot strips only those two spellings, so a path like
		// "$users.ssn" (a likely typo for "$.users.ssn") would reach the redactor
		// unchanged, which then looks up a literal first key "$users", finds nothing, and
		// silently redacts nothing. Reserving a leading "$" for the root marker means a
		// field literally named with a leading "$" cannot be targeted with one; that is a
		// documented limitation (docs/capability-manifest-guide.md).
		var path string
		switch {
		case strings.HasPrefix(field, "$."):
			path = field[len("$."):]
		case field == "$":
			path = ""
		case strings.HasPrefix(field, "$"):
			// "$"-prefixed but neither "$." nor the lone "$": a fail-open trap. At runtime
			// it matches nothing while the audit record reports the redactFields obligation
			// applied — exactly what this validator exists to catch. Guide the operator to
			// the root-anchored form or to dropping the '$'.
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
			// The redactor matches each segment as a LITERAL key with no trimming,
			// so a segment with surrounding or all whitespace never matches and
			// silently redacts nothing. Reject it here.
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

// validateMaxCalls rejects a maxCalls condition with a non-positive count or
// window. A missing windowSeconds would silently become a never-resetting
// lifetime cap rather than a rolling limit, so require it. A windowSeconds past
// callcounter.MaxWindowSeconds is rejected too: it overflows the duration
// arithmetic and would silently reset the quota (a fail-open bypass).
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

// validateMaxCallsWindowsDistinct rejects a capability with two or more maxCalls
// conditions sharing a windowSeconds. The call counter keys each bucket by
// (session, targetType, name, windowSeconds), so they share one bucket: every call
// is counted once per condition, halving the effective limit. The combination adds
// no expressiveness (`count: min(a, b)` on one condition is the faithful rewrite),
// so reject it at load. Distinct windows are independent rate limits and left
// alone.
//
// A non-positive window is skipped and left to validateMaxCalls's sharper
// "windowSeconds >= 1" message, rather than reported here as a duplicate-window
// conflict that would misdirect the author.
func validateMaxCallsWindowsDistinct(i int, conditions []capability.Condition) error {
	seen := make(map[int]int) // windowSeconds -> index of the first maxCalls with it
	for j, cond := range conditions {
		var window int
		switch v := cond.(type) {
		case capability.MaxCallsCondition:
			window = v.WindowSeconds
		case *capability.MaxCallsCondition:
			window = v.WindowSeconds
		default:
			continue
		}
		if window < 1 {
			continue
		}
		if first, dup := seen[window]; dup {
			return fmt.Errorf("capability at index %d: conditions %d and %d are both maxCalls with the same windowSeconds (%d); two equal windows share one counter bucket and would halve the effective limit — combine them into a single maxCalls with the lower 'count'", i, first, j, window)
		}
		seen[window] = j
	}
	return nil
}

// validateIPRange rejects an ipRange condition with an empty CIDR list (denies
// every call), a malformed CIDR (a typo would otherwise only surface as a runtime
// denial), or a CIDR carrying host bits.
func validateIPRange(i, j int, v *capability.IPRangeCondition) error {
	if len(v.CIDRs) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: ipRange requires a non-empty 'cidrs' list; an empty list matches no source IP and denies every call", i, j)
	}
	for _, cidr := range v.CIDRs {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("capability at index %d, condition %d: ipRange contains an invalid CIDR %q (expected e.g. 10.0.0.0/8): %w", i, j, cidr, err)
		}
		// net.ParseCIDR silently masks host bits, so "10.0.0.5/8" behaves as
		// "10.0.0.0/8" — usually a /32-vs-network mistake that widens the allowlist.
		// The returned host IP differs from the masked network exactly when host bits
		// are set; reject that.
		if !ip.Equal(network.IP) {
			return fmt.Errorf("capability at index %d, condition %d: ipRange CIDR %q has host bits set; use the network address %q, or /32 to allow just that host", i, j, cidr, network.String())
		}
	}
	return nil
}

// validateRecipientDomain rejects a recipientDomain condition that fails closed
// or ships a dead allowlist entry: a missing 'argument' or empty 'domains' list
// (both deny every call), an empty/whitespace-only domain entry, or an entry
// beginning with '@' (an accidental full-address paste like "@example.com" that
// the runtime handler could only match against a malformed double-@ recipient).
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
		// Surrounding whitespace is the same footgun: recipient domains are trimmed
		// before matching, so "example.com " would never match and would silently deny
		// every call. Reject it at load like the all-blank case.
		if d != trimmed {
			return fmt.Errorf("capability at index %d, condition %d, domain %d: recipientDomain entry %q has leading or trailing whitespace; recipient domains are trimmed before matching, so this entry would never match and would silently deny every call — remove the surrounding whitespace", i, j, k, d)
		}
		// A leading "@" is an accidental full-address paste. The runtime extracts a
		// bare domain without an "@", so such an entry could only match a malformed
		// double-@ recipient. Reject it.
		if strings.HasPrefix(trimmed, "@") {
			return fmt.Errorf("capability at index %d, condition %d, domain %d: recipientDomain entry %q must not start with '@'; use the bare domain (e.g. example.com)", i, j, k, d)
		}
	}
	return nil
}

// validateTimeWindow rejects a timeWindow condition that declares neither bound
// (restricts nothing), carries a non-RFC3339 timestamp (a typo would otherwise
// only deny at runtime), or whose notBefore is at or after notAfter (an empty
// window that denies every call).
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

// validateSequenceBlock rejects a sequenceBlock condition whose afterTools list
// would fail OPEN at runtime. The handler keys session history by the bare tool
// name (stripped of its namespace prefix), so three authoring mistakes silently
// never match — an empty list, an entry naming no tool once stripped/trimmed (a
// list of such entries makes the whole block pass), and an entry with an
// unrecognized namespace prefix (e.g. mcp:read_file, looked up under a key no call
// records). The strip-then-trim check stays in lockstep with the engine's runtime
// guard.
//
// The colon-prefix check is conservative: it also rejects a bare resource URI like
// "file:///secrets" (which would fire at runtime), since at load time it is
// indistinguishable from a prefix typo. Requiring the explicit
// "resource:file:///secrets" keeps the policy unambiguous.
func validateSequenceBlock(i, j int, v *capability.SequenceBlockCondition) error {
	if len(v.AfterTools) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: sequenceBlock requires a non-empty 'afterTools' list naming the tools whose prior use in the session blocks this call; an empty list never fires and fails closed at runtime", i, j)
	}
	for k, entry := range v.AfterTools {
		stripped := enforcement.StripEnginePrefix(entry)
		if strings.TrimSpace(stripped) == "" {
			return fmt.Errorf("capability at index %d, condition %d, afterTools entry %d: sequenceBlock entry %q names no tool once its namespace prefix is stripped and surrounding whitespace is trimmed (e.g. \"\", a bare \"tool:\", or \"  \"); use a bare tool name (e.g. read_file) or a tool: prefix (e.g. tool:read_file)", i, j, k, entry)
		}
		// A colon-bearing entry stripEnginePrefix returns unchanged is ambiguous:
		// the text before ':' is not a recognized prefix, so the runtime matches the
		// whole entry literally. A namespace typo then silently never fires, and a
		// bare resource URI is indistinguishable from one at load. Require an explicit
		// prefix (see the doc comment).
		if strings.Contains(entry, ":") && stripped == entry {
			return fmt.Errorf("capability at index %d, condition %d, afterTools entry %d: sequenceBlock entry %q is ambiguous: the text before its first ':' is not a recognized namespace prefix (tool:, resource:, prompt:, system:), so the entry is matched literally — a namespace typo like 'mcp:read_file' then silently never fires, and a resource URI must carry the explicit resource: prefix (resource:file:///secrets). Add one of tool:, resource:, prompt:, or system: to disambiguate", i, j, k, entry)
		}
	}
	return nil
}

// experimentalTokenVersions maps a DRAFT-staged condition/directive discriminator to the
// manifest schemaVersion that admits it. A token absent from this map is part of the base
// published grammar and needs no gate. It is the single source of the staging invariant:
// a staged token is inert unless the manifest declares its introducing draft version, so
// adding a future staged token is one map entry — not a gate call threaded through each
// per-type validation case, which a contributor could forget, silently admitting the token
// under the published grammar (the fail-open this gate exists to prevent). A draft token
// requires its EXACT introducing version: a draft is a staging vehicle removed once it
// folds into a batched grammar bump, so no later version inherits it through this map.
var experimentalTokenVersions = map[string]string{
	capability.ConditionTypeFlowLabel:   ManifestSchemaVersionFlowEffectDraft,
	capability.DirectiveTypeLabelOutput: ManifestSchemaVersionFlowEffectDraft,
}

// checkExperimentalTokenStaging fails closed if any capability carries a DRAFT-staged token
// (per experimentalTokenVersions) the declared schemaVersion does not admit — so a published
// "0.1" manifest that uses one is rejected (the closed grammar stays closed) rather than
// silently enabling an experimental predicate. It is the one authoritative staging gate: the
// per-type validation cases carry no version check, so a new staged token cannot bypass the
// gate by omitting one. It runs after the per-capability structural validation, so every
// condition/directive is non-nil and well-typed and ConditionType()/DirectiveType() cannot
// panic on a null or typed-nil entry. SchemaVersion is compared trimmed so a quoted,
// whitespace-padded scalar is judged on its real value.
func checkExperimentalTokenStaging(m *LocalManifest) error {
	declared := strings.TrimSpace(m.SchemaVersion)
	for i := range m.Capabilities {
		c := &m.Capabilities[i]
		for _, cond := range c.Conditions {
			if req, staged := experimentalTokenVersions[cond.ConditionType()]; staged && declared != req {
				return experimentalTokenStagingErr(i, "the "+cond.ConditionType()+" condition", req, declared)
			}
		}
		for _, dir := range c.Directives {
			if req, staged := experimentalTokenVersions[dir.DirectiveType()]; staged && declared != req {
				return experimentalTokenStagingErr(i, "the "+dir.DirectiveType()+" directive", req, declared)
			}
		}
	}
	return nil
}

// experimentalTokenStagingErr builds the fail-closed rejection for a staged token used
// under a schemaVersion that does not admit it.
func experimentalTokenStagingErr(i int, feature, required, declared string) error {
	return fmt.Errorf("capability at index %d: %s is experimental and requires schemaVersion %q (the flow+effect draft); this manifest declares schemaVersion %q, under which the token is not part of the grammar", i, feature, required, declared)
}

// requireResponseDirectiveTarget rejects a response-mutating directive (redactFields)
// on a non-tool target: the proxy redacts tools/call results only, so such a directive
// would never apply — a fail-open leak plus a false "discharged" audit record.
// labelOutput does not go through here; it is an enforce-time state directive valid on
// any source target.
func requireResponseDirectiveTarget(i int, target string, targetType capability.TargetType) error {
	if targetType != capability.TargetTypeTool {
		return fmt.Errorf("capability at index %d: constraint %q carries a redactFields directive; redactFields directives apply only to tool: targets (the proxy redacts tools/call results, not %s responses)", i, target, targetType)
	}
	return nil
}

// requireSourceDirectiveTarget restricts labelOutput to tool: and resource: source
// targets — the boundaries a sensitive read sits at. A prompt: or system: target is not a
// flow SOURCE: a sampling/createMessage request is an egress the agent drives, a place a
// flowLabel SINK belongs, not a source that asserts new taint. (This restriction is why
// sampling can only ever be a flow sink, never a concurrent flow writer — see the
// per-session serialization in internal/transport.) Reject at load rather than admit a
// labelOutput on a non-source target.
func requireSourceDirectiveTarget(i int, target string, targetType capability.TargetType) error {
	if targetType != capability.TargetTypeTool && targetType != capability.TargetTypeResource {
		return fmt.Errorf("capability at index %d: constraint %q carries a labelOutput directive, which is valid only on tool: or resource: source targets (a %s target is not a flow source)", i, target, targetType)
	}
	return nil
}

// validateFlowLabel checks a flowLabel condition's Allow set against the closed native
// vocabulary, so a misspelled label is a load-time error rather than an inert entry
// (the closed grammar is a determinism invariant). An empty Allow is valid — it admits
// only an unlabeled, clean-context flow (the strictest, fail-closed sink).
func validateFlowLabel(i, j int, allow []string) error {
	for _, l := range allow {
		if !capability.IsFlowLabel(l) {
			return fmt.Errorf("capability at index %d, condition %d: flowLabel 'allow' contains unknown label %q — valid native flow labels are %s", i, j, l, strings.Join(capability.FlowLabelVocabulary(), ", "))
		}
	}
	return nil
}

// validateLabelOutput checks a labelOutput directive: a non-empty Labels list (an
// empty one records nothing and is an authoring mistake, like an empty sequenceBlock),
// every entry drawn from the closed native vocabulary.
func validateLabelOutput(i, j int, labels []string) error {
	if len(labels) == 0 {
		return fmt.Errorf("capability at index %d, directive %d: labelOutput requires a non-empty 'labels' list naming the native flow labels this call's output carries; an empty list records nothing", i, j)
	}
	for _, l := range labels {
		if !capability.IsFlowLabel(l) {
			return fmt.Errorf("capability at index %d, directive %d: labelOutput 'labels' contains unknown label %q — valid native flow labels are %s", i, j, l, strings.Join(capability.FlowLabelVocabulary(), ", "))
		}
	}
	return nil
}

// validatePrincipal checks a constraint's principal scoping: every claim name
// must be one eunox can match on (SupportedPrincipalClaims) and must list at least
// one non-empty pattern, so a typo'd claim name (which would silently never match)
// is caught at load.
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
			// Reject a malformed glob at load: PrincipalMatches skips an
			// ErrBadPattern pattern, so an invalid glob would silently never match.
			if _, err := stdpath.Match(p, ""); err != nil {
				return fmt.Errorf("principal claim %q has an invalid pattern %q: %w", claimName, p, err)
			}
		}
	}
	return nil
}

// checkManifestKeys rejects unknown keys anywhere in the manifest. The typed
// json.Unmarshal in LoadManifest is intentionally lenient (it is shared with
// IdP-issued JWT capability claims, which tolerate unknown fields), so without
// this a typo'd key (`arguments` for `argument`) would be silently dropped. The
// manifest is the security-critical surface, so fail closed on any unrecognized
// key. argumentSchema keywords are checked recursively by
// checkArgumentSchemaKeywords.
func checkManifestKeys(data []byte) error {
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		// Shape was already validated by the typed decode; nothing to walk.
		return nil //nolint:nilerr // a non-object manifest is caught upstream
	}
	if err := checkObjectKeys("", root, jsonFieldKeys(reflect.TypeOf(LocalManifest{}))); err != nil {
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
// capability.SchemaType.UnmarshalJSON accepts any string, array, or null and
// normalizes an empty array the same as "no type declared" (SchemaType.IsZero),
// which silently disables ValidateArgumentSchema's type check — a numeric argument
// then never reaches schemaValidateString, so a string-only `pattern` is silently
// bypassed. This walks the RAW decoded value (a map key present with an empty/
// invalid value is NOT the same as the key being absent, but the typed SchemaType
// cannot tell them apart) and rejects the shapes that would silently weaken the
// declared policy: an empty array, an empty string, an unrecognized type name, and
// a duplicate name within an array. `type` is optional — an absent key, or an
// explicit `null`, means no type constraint and is valid.
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

// argumentSchemaKeywords is the closed set of JSON-Schema keywords an
// argumentSchema may use. Anything outside it is rejected at load (recursively
// through properties and items), so an unsupported keyword (const, $ref, allOf,
// format, …) is flagged rather than silently unenforced. Keep in sync with
// capability.ArgumentSchema and the runtime validator in pkg/enforcement/schema.go.
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

// validateArgumentSchemaConsistency rejects a structurally unsatisfiable
// argumentSchema. When `additionalProperties` is false, every `required` name must
// appear in `properties`; otherwise the field is both required and forbidden, so
// every call is denied with a confusing "additional property" error. Recurses
// through `properties` and `items`.
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
	// Recurse into nested subschemas, visiting properties in a stable order so
	// the reported error is deterministic.
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sub := s.Properties[name]
		// Reject an explicit null subschema (`properties: {x: null}`): it decodes to
		// a nil *ArgumentSchema, which the validator treats as "any", so the declared
		// property silently accepts any value/type — a structural footgun where the
		// author meant to constrain x. The empty object `{}` is the correct
		// JSON-Schema "any" and decodes to a non-nil zero-value schema, so it is still
		// accepted; only the anomalous null form is refused, matching this file's
		// "reject ambiguous schema up front" posture. The sibling `items: null` is the
		// same footgun for array elements but is rejected in checkArgumentSchemaKeywords
		// instead — the typed Items pointer collapses present-null and absent to nil, so
		// only the raw layer (which still sees the key) can tell them apart.
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

// checkArgumentSchemaKeywords walks an argumentSchema node (raw, as decoded from
// the manifest) and rejects the first keyword outside argumentSchemaKeywords,
// with a path-qualified error such as
// `capabilities[2].argumentSchema.properties.path: unknown keyword "format"`.
// It recurses into every subschema reachable through `properties` (one per
// named property) and `items`. A non-object node (e.g. a `type` array element)
// is not a schema and is left to the typed decode. It also rejects an explicit
// null `items` subschema (the array-element counterpart of the null-property
// rejection in validateArgumentSchemaConsistency), which can only be detected here
// because the typed Items pointer cannot distinguish present-null from absent.
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
	// Recurse into nested subschemas. properties is an object of name→subschema;
	// items is a single subschema.
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
		// Reject an explicit null items subschema (`items: null`): like a null property
		// subschema it would accept any array element unchecked, the same footgun
		// validateArgumentSchemaConsistency rejects for `properties: {x: null}`. It is
		// caught HERE rather than there because the typed *ArgumentSchema cannot see it:
		// Items is a single pointer, so a present-but-null items decodes identically to an
		// absent one (both nil), whereas the typed Properties map distinguishes the two by
		// key membership. This raw layer still has the key present, so it can tell `items:
		// null` (reject) from an absent items (fine); `items: {}` is the explicit "any
		// element" and is a non-nil empty object that recurses cleanly.
		if items == nil {
			return fmt.Errorf("%s.items: array element schema is null, which would accept any element — use an empty object {} for an explicit \"any\" element schema, or give items a concrete schema", path)
		}
		if err := checkArgumentSchemaKeywords(path+".items", items); err != nil {
			return err
		}
	}
	return nil
}

// checkObjectKeys reports the first key in obj that is not in allowed, in
// deterministic (sorted) order so the error is stable. When a near match
// exists, it is offered as a "did you mean" hint.
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

// jsonFieldKeys returns the set of JSON object keys declared by struct type t,
// derived from its `json:"..."` field tags.
func jsonFieldKeys(t reflect.Type) map[string]bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		// An unexported, non-anonymous field is never a valid JSON key (encoding/json
		// ignores it), so skip it — this keeps a runtime-only field like
		// IPRangeCondition.parsed from being mistaken for a permitted manifest key.
		// Anonymous embeds fall through to the promotion handling below.
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
		// An untagged embedded struct promotes its JSON keys to the parent
		// object, so its own fields are the valid keys — not the embed's type
		// name. (A tagged embed nests under the tag and is treated as one key.)
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

// conditionKeysFor returns the permitted key set for a condition of the given
// discriminator type (always including "type"). The second result is false for a
// type this build does not model; the caller then skips key checking (the unknown
// type is already rejected by the typed decode).
func conditionKeysFor(condType string) (map[string]bool, bool) {
	var t reflect.Type
	switch condType {
	case capability.ConditionTypeTimeWindow:
		t = reflect.TypeOf(capability.TimeWindowCondition{})
	case capability.ConditionTypeIPRange:
		t = reflect.TypeOf(capability.IPRangeCondition{})
	case capability.ConditionTypeAllowedOperations:
		t = reflect.TypeOf(capability.AllowedOperationsCondition{})
	case capability.ConditionTypeAllowedExtensions:
		t = reflect.TypeOf(capability.AllowedExtensionsCondition{})
	case capability.ConditionTypeAllowedTables:
		t = reflect.TypeOf(capability.AllowedTablesCondition{})
	case capability.ConditionTypeMaxCalls:
		t = reflect.TypeOf(capability.MaxCallsCondition{})
	case capability.ConditionTypeRecipientDomain:
		t = reflect.TypeOf(capability.RecipientDomainCondition{})
	case capability.ConditionTypeAllowedValues:
		t = reflect.TypeOf(capability.AllowedValuesCondition{})
	case capability.ConditionTypeSequenceBlock:
		t = reflect.TypeOf(capability.SequenceBlockCondition{})
	case capability.ConditionTypeFlowLabel:
		t = reflect.TypeOf(capability.FlowLabelCondition{})
	case capability.ConditionTypePolicy:
		t = reflect.TypeOf(capability.PolicyCondition{})
	case capability.ConditionTypeCustom:
		t = reflect.TypeOf(capability.CustomCondition{})
	default:
		return nil, false
	}
	keys := jsonFieldKeys(t)
	keys["type"] = true
	return keys, true
}

// directiveKeysFor mirrors conditionKeysFor for response directives.
func directiveKeysFor(dirType string) (map[string]bool, bool) {
	switch dirType {
	case capability.DirectiveTypeRedactFields:
		keys := jsonFieldKeys(reflect.TypeOf(capability.RedactFieldsDirective{}))
		keys["type"] = true
		return keys, true
	case capability.DirectiveTypeLabelOutput:
		keys := jsonFieldKeys(reflect.TypeOf(capability.LabelOutputDirective{}))
		keys["type"] = true
		return keys, true
	}
	return nil, false
}

// validateDescriptionHashFormat reports an error if s is not a valid
// "sha256:<64 lowercase hex chars>" description hash value.
func validateDescriptionHashFormat(s string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return fmt.Errorf("descriptionHash %q must start with \"sha256:\"", s)
	}
	hexPart := s[len(prefix):]
	if len(hexPart) != 64 {
		return fmt.Errorf("descriptionHash %q: hex part must be exactly 64 characters (got %d)", s, len(hexPart))
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return fmt.Errorf("descriptionHash %q: hex part is not valid hex: %w", s, err)
	}
	if hexPart != strings.ToLower(hexPart) {
		return fmt.Errorf("descriptionHash %q: hex part must be lowercase", s)
	}
	return nil
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
