// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import "gopkg.in/yaml.v3"

// YAML merge keys, resolved once on the parsed document so nothing downstream has to know they
// exist.
//
// Every walk in this package that reads the document as WRITTEN — the schemaVersion pre-decode
// gates, the retag that keeps an unquoted version from producing an opaque unmarshal error, the
// numeric-coercion guards, the key-presence maps — scans a mapping for a LITERAL key. A key
// arriving through `<<:` has no slot of its own in the enclosing mapping, so it was invisible to
// all of them while being perfectly visible to the decode that produces the enforced policy.
// That split showed up as two things a merge could do that its inline spelling could not: a
// gateway config declaring its schemaVersion through a merge was refused as not declaring one at
// all, and a manifest declaring an unquoted one through a merge got
// "json: cannot unmarshal number into Go struct field .schemaVersion of type string" instead of
// the message validateManifestSchemaVersion exists to give.
//
// Teaching each walk to read through merges was the alternative, and it does not work for the
// WRITE half: retagging an aliased scalar means replacing the key's slot, never the anchor
// (which is shared with every other reference — retagging one silently changed a sibling
// `values:` entry from json.Number to a Go string, and a capability then denied every call it
// was written to allow), and a merged key has no slot to replace. Splicing the pairs in gives it
// one, and every future walk in this package inherits merge-correctness for nothing.

// resolveMergeKeys rewrites the document so no mapping carries a `<<` pair: each merge source's
// pairs are spliced into the mapping that merges them, the mapping's OWN keys winning, and the
// `<<` pair is dropped. Semantically identical to what yaml.v3's decoder does with the same
// document, which is the point — the pre-decode walks now see what the decode will.
//
// Splicing into the merging mapping (never the source) is what makes this safe for a shared
// anchor: `<<` is resolved at the mapping that contains it, so every reference to that mapping
// already saw the merged keys.
func resolveMergeKeys(node *yaml.Node) {
	resolveMergeKeysIn(node, map[*yaml.Node]bool{}, map[*yaml.Node]bool{})
}

// resolveMergeKeysIn walks children first, so a source that itself merges is already flat when
// the mapping merging it reads its pairs.
//
// done bounds an alias graph to linear time (a mapping referenced N times is resolved once, and
// resolution is idempotent); resolving breaks a cycle an anchor graph can form — a self-merging
// mapping recursed until the stack overflowed, which is an uncatchable fatal error rather than
// the load failure a bad document should produce.
func resolveMergeKeysIn(n *yaml.Node, done, resolving map[*yaml.Node]bool) {
	n = resolveYAMLAlias(n)
	if n == nil || done[n] || resolving[n] {
		return
	}
	resolving[n] = true
	for _, child := range n.Content {
		resolveMergeKeysIn(child, done, resolving)
	}
	if n.Kind == yaml.MappingNode {
		spliceMergeKeys(n, done, resolving)
	}
	delete(resolving, n)
	done[n] = true
}

// spliceMergeKeys replaces mapping's content with its own pairs followed by the pairs its `<<`
// keys contribute, first source winning and the mapping's own keys winning over all of them.
//
// It BAILS — leaving the mapping exactly as written — on anything it cannot reproduce the
// decoder's semantics for: a merge value that is not a mapping (or a sequence of them), or a key
// that is not a scalar. Both are then reported by the decode, which is the accurate place for
// them; appending pairs beside a key this function cannot compare would put a duplicate in the
// mapping and hand the merge the last-wins position, inverting the precedence it must have.
func spliceMergeKeys(mapping *yaml.Node, done, resolving map[*yaml.Node]bool) {
	var mergeValues []*yaml.Node
	own := make([]*yaml.Node, 0, len(mapping.Content))
	present := make(map[string]bool, len(mapping.Content)/2)
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key := resolveYAMLAlias(mapping.Content[i])
		if key == nil {
			return
		}
		if isYAMLMergeKey(key) {
			mergeValues = append(mergeValues, mapping.Content[i+1])
			continue
		}
		if key.Kind != yaml.ScalarNode {
			return
		}
		own = append(own, mapping.Content[i], mapping.Content[i+1])
		present[key.Value] = true
	}
	if len(mergeValues) == 0 {
		return
	}

	merged := make([]*yaml.Node, 0, len(mapping.Content))
	for _, value := range mergeValues {
		sources, ok := mergeSources(value)
		if !ok {
			return
		}
		for _, src := range sources {
			// Resolve the source's own merges first. Document order already guarantees an
			// anchor is walked before the alias referencing it, so this is normally a no-op —
			// asked anyway so the splice does not depend on that being true of every future
			// caller.
			resolveMergeKeysIn(src, done, resolving)
			for i := 0; i+1 < len(src.Content); i += 2 {
				key := resolveYAMLAlias(src.Content[i])
				if key == nil || key.Kind != yaml.ScalarNode {
					return
				}
				if present[key.Value] {
					continue
				}
				present[key.Value] = true
				merged = append(merged, src.Content[i], src.Content[i+1])
			}
		}
	}
	// A fresh slice rather than appending onto `own`: that shares mapping.Content's backing
	// array, so the append would write the merged pairs over pairs the walk above still
	// references when a merge sits before the mapping's own keys.
	content := make([]*yaml.Node, 0, len(own)+len(merged))
	content = append(content, own...)
	content = append(content, merged...)
	mapping.Content = content
}

// mergeSources resolves a `<<` value to the mappings it contributes, in precedence order. ok is
// false for anything the decoder itself refuses ("map merge requires map or sequence of maps as
// the value"), leaving that diagnosis to it rather than guessing at a repair.
func mergeSources(value *yaml.Node) ([]*yaml.Node, bool) {
	value = resolveYAMLAlias(value)
	if value == nil {
		return nil, false
	}
	switch value.Kind {
	case yaml.MappingNode:
		return []*yaml.Node{value}, true
	case yaml.SequenceNode:
		sources := make([]*yaml.Node, 0, len(value.Content))
		for _, item := range value.Content {
			item = resolveYAMLAlias(item)
			if item == nil || item.Kind != yaml.MappingNode {
				return nil, false
			}
			sources = append(sources, item)
		}
		return sources, true
	default:
		return nil, false
	}
}
