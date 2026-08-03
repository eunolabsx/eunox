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

// tokenSpec is one entry of a prototype registry: how to instantiate the token's zero value,
// and the published grammar revision that introduced its discriminator.
//
// The two travel together because they are added together. A contributor cannot declare a
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
