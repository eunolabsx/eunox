// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Grammar revisions of the manifest vocabulary, declared ON the prototype registries: each
// discriminator names the revision that introduced it, so the loader can refuse a token
// under a revision that doesn't define it instead of trusting a separate, driftable map.

package capability

import "slices"

// SchemaVersion01 is the base published grammar: deny-by-default capability authorization
// over the original closed condition/directive vocabulary. It remains CLOSED — none of the
// flow+effect tokens SchemaVersion02 introduces is part of it; using one under this revision
// is refused at load.
const SchemaVersion01 = "0.1"

// SchemaVersion02 is the published flow+effect grammar revision: the information-flow tokens,
// the effect layer, and the claim-populated ${task.*} variables — landed as ONE batched bump
// rather than one token at a time, so the grammar has two revisions rather than a version per
// predicate.
const SchemaVersion02 = "0.2"

// publishedSchemaVersions lists every published grammar revision in PUBLICATION ORDER — the
// one place the sequence is written down, so publishing a revision is an append here rather
// than an edit to a rule stated elsewhere.
//
// The ordering is DATA, not a comparison over version strings: "0.10" sorts before "0.2", and
// the index in this slice is the only rank there is — a version absent from it fails closed.
var publishedSchemaVersions = []string{SchemaVersion01, SchemaVersion02}

// PublishedSchemaVersions returns the published grammar revisions in publication order, as a
// fresh copy so a caller cannot reorder the sequence the loader's gates read from it (both
// which revisions it parses and, by index, which revision inherits which token).
func PublishedSchemaVersions() []string { return slices.Clone(publishedSchemaVersions) }

// tokenSpec is one entry of a prototype registry: how to instantiate the token's zero value,
// the grammar revision that introduced it, what cross-call state its enforcement accumulates,
// and which optional engine subsystems it depends on. The four travel together so a
// contributor cannot declare a token without classifying it on the same line as its
// constructor, rather than in a lookalike map elsewhere that can silently disagree.
type tokenSpec[T any] struct {
	// New builds a zero value of the token's Go type. Fresh per call, so a caller cannot
	// mutate the registry's idea of a type.
	New func() T
	// Since is the schemaVersion that introduced this discriminator. It must be one of the
	// published revisions above; an entry leaving it empty is refused at manifest load
	// (TokenSince reports it as unclassified) rather than admitted under a guess.
	Since string
	// State is the cross-call state this token's enforcement touches — drives the decision
	// turn and the multi-instance shared-state advisory. Empty is UNCLASSIFIED (treated as the
	// strongest class, not "accumulates nothing"). See tokenstate.go.
	State StateAccumulation
	// Uses names the optional engine subsystems this token depends on — drives the engine's
	// two subsystem skip gates. Declare SubsystemNone explicitly for "depends on none"; empty
	// is UNCLASSIFIED ("depends on all of them"). See subsystem.go.
	Uses []EngineSubsystem
}

// TokenSince reports the published schemaVersion that introduced the named condition or
// directive discriminator, and whether this build can classify it at all.
//
// ok is false both for a token in neither registry and for an entry declaring no revision;
// the caller must treat both as refusals (fail closed) — the inverse of the old behavior,
// where a token missing from the table was silently admitted under every revision.
func TokenSince(token string) (string, bool) {
	if spec, ok := conditionPrototypes[token]; ok {
		return spec.Since, spec.Since != ""
	}
	if spec, ok := directivePrototypes[token]; ok {
		return spec.Since, spec.Since != ""
	}
	return "", false
}
