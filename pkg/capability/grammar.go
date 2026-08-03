// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Grammar revisions of the manifest vocabulary, declared ON the prototype registries.
//
// A condition or directive discriminator belongs to exactly one published revision — the
// one that INTRODUCED it — and the manifest loader refuses a token under a revision that
// does not define it, so the closed grammar of an earlier revision stays closed. That
// classification used to live one package over as two hand-maintained maps, which made
// three states representable that must not be: a token in both, a token in neither, and a
// token in the wrong one. The first two were test-caught; the third was not, and it is the
// one that widens a "0.1" manifest with a later revision's predicate.
//
// Declaring the revision beside the constructor removes all three. The registry is the one
// place a token can be added at all, an entry with no revision is refused at load, and
// which revision a token belongs to is read from the same line that declares it exists.

package capability

import "slices"

// SchemaVersion01 is the base published grammar: deny-by-default capability authorization
// over the original closed condition/directive vocabulary. It remains supported and remains
// CLOSED — none of the flow+effect tokens introduced by SchemaVersion02 is part of it, and a
// manifest declaring this revision that uses one is refused at load.
const SchemaVersion01 = "0.1"

// SchemaVersion02 is the published flow+effect grammar revision: the information-flow tokens
// (the flowLabel condition, the labelOutput and declassify directives), the effect layer (the
// effectClass and blastRadius conditions, a constraint's effect contract, the top-level
// effectCeiling), and the claim-populated ${task.*} variables — landed as ONE batched bump
// rather than one token at a time, so the grammar has exactly two published revisions rather
// than a version per predicate.
const SchemaVersion02 = "0.2"

// publishedSchemaVersions lists every published grammar revision in PUBLICATION ORDER. It is
// the one place the sequence of revisions is written down: which revisions a build parses, and
// which of them admit a given token, are both read off this order, so publishing a revision is
// an append here rather than an edit to a rule stated somewhere else.
//
// The ordering is DATA rather than a comparison over the version strings. "0.10" sorts before
// "0.2" and a grammar gate that silently inverts on the tenth revision is the kind of defect
// that ships. The index in this slice is the only ordering there is, and a version absent from
// it has no rank at all — every consumer of the order fails closed on one.
var publishedSchemaVersions = []string{SchemaVersion01, SchemaVersion02}

// PublishedSchemaVersions returns the published grammar revisions in publication order, as a
// fresh copy so a caller cannot reorder the sequence the loader's gates read.
//
// The manifest loader derives BOTH of its version questions from this one sequence — the set
// of revisions it will parse at all, and (by index) which revision inherits which token — so
// the two cannot disagree about a revision that exists. Restating the list anywhere would be
// one more place for them to.
func PublishedSchemaVersions() []string { return slices.Clone(publishedSchemaVersions) }

// tokenSpec is one entry of a prototype registry: how to instantiate the token's zero value,
// the published grammar revision that introduced its discriminator, what cross-call state its
// enforcement accumulates, and which optional engine subsystems that enforcement depends on.
//
// The four travel together because they are added together. A contributor cannot declare a
// token without declaring when it entered the grammar, and cannot file it under the wrong
// revision by editing a lookalike map fifty lines from the one they meant — the classification
// is on the same line as the constructor.
type tokenSpec[T any] struct {
	// New builds a zero value of the token's Go type. Fresh per call, so a caller cannot
	// mutate the registry's idea of a type.
	New func() T
	// Since is the schemaVersion that introduced this discriminator. It must be one of the
	// published revisions above; an entry leaving it empty is refused at manifest load
	// (TokenSince reports it as unclassified) rather than admitted under a guess.
	Since string
	// State is the cross-call state this token's enforcement touches — the property the
	// transports' decision turn and the multi-instance shared-state advisory are both derived
	// from. It must be one of the classes in stateAccumulationOrder; an entry leaving it empty
	// is UNCLASSIFIED, which every consumer treats as the strongest class rather than as
	// "accumulates nothing". See tokenstate.go for the rule that sets it.
	State StateAccumulation
	// Uses names the optional engine subsystems this token's enforcement reads or writes — the
	// property the engine's two skip gates (WithoutAntecedentRecording, WithoutFlowLabels) are
	// derived from. Declare SubsystemNone explicitly for a token that depends on none; an
	// entry leaving it empty is UNCLASSIFIED, which every consumer treats as "depends on all
	// of them". See subsystem.go for the rule that sets it.
	Uses []EngineSubsystem
}

// TokenSince reports the published schemaVersion that introduced the named condition or
// directive discriminator, and whether this build can classify it at all.
//
// ok is false for a token in neither prototype registry AND for a registry entry that
// declares no revision. The caller must treat both as refusals: the manifest loader's gate
// exists to stop a later revision's predicate from widening an earlier one, and a token this
// build cannot place has to be refused rather than guessed at. That is the fail-closed
// direction, and it reverses how the classification failed before it was derived — a token
// missing from the (single, gated) table was silently admitted under every revision.
//
// It is the ONE classification lookup: the loader reads it instead of maintaining its own
// tables, so adding a token is an edit to the registry (plus a JSON Schema branch), not to a
// third map that can hold a different answer.
func TokenSince(token string) (string, bool) {
	if spec, ok := conditionPrototypes[token]; ok {
		return spec.Since, spec.Since != ""
	}
	if spec, ok := directivePrototypes[token]; ok {
		return spec.Since, spec.Since != ""
	}
	return "", false
}
