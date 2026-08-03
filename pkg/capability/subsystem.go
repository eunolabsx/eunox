// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Which OPTIONAL ENGINE SUBSYSTEM a token's enforcement depends on, declared ON the prototype
// registry entry beside the grammar revision and the state class.
//
// The engine builds two of its facilities conditionally: the per-call antecedent marker
// (WithoutAntecedentRecording) and the flow-label peek/record path (WithoutFlowLabels). Both
// skips are OPTIMIZATIONS — the marker exists only to be read by a later sequenceBlock, and
// the flow path only to be read by a flow token — so a policy carrying neither pays for
// neither.
//
// Whether to skip was a hand-written question per gate: one predicate naming sequenceBlock,
// another naming the three flow token types. That is the shape the state-accumulation axis
// already retired for the decision turn, and it fails the same way here, in the direction that
// matters: add a condition that READS the flow-label set, and a policy carrying only that
// condition reports "no flow token" — so the engine is built WithoutFlowLabels and the new
// handler runs against an engine holding no flow state. Depending on how it reaches the store
// that denies, allows, or (the plausible one) silently reads an empty set: a fail-open arriving
// through the gate rather than through the turn.
//
// Declaring the dependency on the registry entry removes that. The registry is the one place a
// token can be added at all, an entry declaring nothing is UNCLASSIFIED, and every consumer
// treats unclassified as "depends on every subsystem" — the skip is an optimization, so failing
// closed costs a per-call scan and nothing else. The completeness test in grammar_test.go fails
// the build when an entry declares none.
//
// The rule for setting it, stated once: ask which engine facility the token's HANDLER reads or
// writes. Nothing beyond the request, the clock, the call counter and its own configuration is
// SubsystemNone. Reading the antecedent history a prior call recorded is
// SubsystemAntecedentHistory. Reading or writing the flow-label set is SubsystemFlowLabels. A
// token whose enforcement is supplied from OUTSIDE this build (policy, custom) declares every
// subsystem: what an embedder's evaluator reads is not knowable here, and the conservative
// answer costs one per-call scan.

package capability

import "slices"

// EngineSubsystem names an optional engine facility a token's enforcement can depend on.
type EngineSubsystem string

const (
	// SubsystemNone is the explicit declaration that a token's enforcement depends on no
	// optional subsystem. It is a VALUE rather than an empty list because "declared nothing"
	// and "declared none" must not be the same thing: the first is an entry nobody has
	// reasoned about and fails closed, the second is a decision.
	SubsystemNone EngineSubsystem = "none"
	// SubsystemAntecedentHistory is the per-call marker the engine records so a later call's
	// sequenceBlock can ask what preceded it. Gated by WithoutAntecedentRecording.
	SubsystemAntecedentHistory EngineSubsystem = "antecedentHistory"
	// SubsystemFlowLabels is the session/task-scoped flow-label set: the labels a source
	// writes, a sink peeks, and a declassification clears. Gated by WithoutFlowLabels.
	SubsystemFlowLabels EngineSubsystem = "flowLabels"
)

// engineSubsystems lists every optional facility this build models. Like
// publishedSchemaVersions and stateAccumulationOrder it is DATA: membership is a lookup in
// this slice, so a subsystem this build does not model has no place in it at all and every
// consumer fails closed on one rather than comparing strings.
//
// SubsystemNone is deliberately absent — it is the "depends on nothing" marker, not a
// facility, and a token declaring it alongside a real one would be contradicting itself.
var engineSubsystems = []EngineSubsystem{SubsystemAntecedentHistory, SubsystemFlowLabels}

// EngineSubsystems returns the optional engine facilities this build models, as a fresh copy
// so a caller cannot reorder or extend the set the gates are derived from. A consumer that
// must be total over the subsystems (the completeness test, an operator report) enumerates
// this rather than restating the list.
func EngineSubsystems() []EngineSubsystem { return slices.Clone(engineSubsystems) }

// modelled reports whether s is a facility this build knows about.
func (s EngineSubsystem) modelled() bool { return slices.Contains(engineSubsystems, s) }

// validSubsystemDeclaration reports whether uses is a well-formed declaration: either exactly
// SubsystemNone, or a non-empty set of modelled subsystems. Anything else — empty, a mix of
// SubsystemNone with a real facility, a name this build does not model — is UNCLASSIFIED, and
// every consumer treats that as "depends on everything".
func validSubsystemDeclaration(uses []EngineSubsystem) bool {
	if len(uses) == 0 {
		return false
	}
	if slices.Contains(uses, SubsystemNone) {
		return len(uses) == 1
	}
	for _, s := range uses {
		if !s.modelled() {
			return false
		}
	}
	return true
}

// TokenEngineSubsystems reports the optional engine subsystems the named condition or
// directive discriminator declares, and whether this build can classify the token at all.
//
// ok is false for a token in neither prototype registry AND for an entry whose declaration is
// malformed (empty, or naming a facility this build does not model). Callers must treat both
// as "depends on every subsystem" — see TokenUsesEngineSubsystem, which applies that rule so
// each consumer does not have to.
func TokenEngineSubsystems(token string) ([]EngineSubsystem, bool) {
	if spec, ok := conditionPrototypes[token]; ok {
		return slices.Clone(spec.Uses), validSubsystemDeclaration(spec.Uses)
	}
	if spec, ok := directivePrototypes[token]; ok {
		return slices.Clone(spec.Uses), validSubsystemDeclaration(spec.Uses)
	}
	return nil, false
}

// TokenUsesEngineSubsystem reports whether the named token's enforcement depends on s.
//
// An UNCLASSIFIED token reports true for every subsystem. That is the fail-closed direction
// and it is cheap: the two gates it feeds are optimizations, so over-reporting builds an
// engine that does slightly more work per call, while under-reporting runs a handler against a
// facility that was never wired.
func TokenUsesEngineSubsystem(token string, s EngineSubsystem) bool {
	uses, ok := TokenEngineSubsystems(token)
	if !ok {
		return true
	}
	return slices.Contains(uses, s)
}

// ConditionUsesEngineSubsystem reports whether c's enforcement depends on s. A nil condition
// carries no enforcement and depends on nothing. Both the pointer form the JSON loader builds
// and the value form the JWT path builds are accepted, because the discriminator is read off
// the interface rather than off a Go type switch.
func ConditionUsesEngineSubsystem(c Condition, s EngineSubsystem) bool {
	if isNilToken(c) {
		return false
	}
	return TokenUsesEngineSubsystem(c.ConditionType(), s)
}

// DirectiveUsesEngineSubsystem is the directive-side twin of ConditionUsesEngineSubsystem.
func DirectiveUsesEngineSubsystem(d Directive, s EngineSubsystem) bool {
	if isNilToken(d) {
		return false
	}
	return TokenUsesEngineSubsystem(d.DirectiveType(), s)
}
