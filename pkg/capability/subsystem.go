// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Which OPTIONAL ENGINE SUBSYSTEM a token's enforcement depends on, declared ON the prototype
// registry entry. The engine skips two optional facilities (antecedent recording, the
// flow-label path) when no carried token needs them; declaring the dependency here — rather
// than a separate hand-written predicate per gate — means a new token that reads flow state
// can't silently fall through a gate that doesn't know about it. An entry declaring nothing
// is UNCLASSIFIED and treated as depending on every subsystem (enforced by
// subsystem_test.go). enforcement.WithConditionHandler can replace a token's handler, so a
// replacement is unclassified unless it self-declares via enforcement.SubsystemDependent.

package capability

import "slices"

// EngineSubsystem names an optional engine facility a token's enforcement can depend on.
type EngineSubsystem string

const (
	// SubsystemNone is the explicit declaration that a token depends on no optional
	// subsystem. It is a VALUE rather than an empty list: "declared nothing" (fails closed
	// as unclassified) and "declared none" (a decision) must not be the same thing.
	SubsystemNone EngineSubsystem = "none"
	// SubsystemAntecedentHistory is the per-call marker the engine records so a later call's
	// sequenceBlock can ask what preceded it. Gated by the engine's skipAntecedentRecording.
	SubsystemAntecedentHistory EngineSubsystem = "antecedentHistory"
	// SubsystemFlowLabels is the session/task-scoped flow-label set: the labels a source
	// writes, a sink peeks, and a declassification clears. Gated by the engine's skipFlow.
	SubsystemFlowLabels EngineSubsystem = "flowLabels"
)

// engineSubsystems lists every optional facility this build models. It is DATA: membership
// is a lookup in this slice, so a subsystem not modelled has no place in it and every
// consumer fails closed rather than comparing strings. SubsystemNone is deliberately absent
// — a "depends on nothing" marker, not a facility.
var engineSubsystems = []EngineSubsystem{SubsystemAntecedentHistory, SubsystemFlowLabels}

// EngineSubsystems returns the optional engine facilities this build models, as a fresh copy
// so a caller cannot reorder or extend the set the gates are derived from.
func EngineSubsystems() []EngineSubsystem { return slices.Clone(engineSubsystems) }

// modelled reports whether s is a facility this build knows about.
func (s EngineSubsystem) modelled() bool { return slices.Contains(engineSubsystems, s) }

// DeclarationUsesSubsystem reports whether a declaration depends on s, applying the
// unclassified rule: a MALFORMED declaration depends on EVERY subsystem. The one place that
// rule lives — both a registry entry's `Uses` and a handler's own
// enforcement.SubsystemDependent declaration read through it, so they can't silently diverge
// on what "empty" means.
func DeclarationUsesSubsystem(uses []EngineSubsystem, s EngineSubsystem) bool {
	if !validSubsystemDeclaration(uses) {
		return true
	}
	return slices.Contains(uses, s)
}

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
// ok is false for a token in neither registry AND for a malformed declaration; callers must
// treat both as "depends on every subsystem" — see TokenUsesEngineSubsystem.
func TokenEngineSubsystems(token string) ([]EngineSubsystem, bool) {
	uses, ok := tokenSubsystems(token)
	return slices.Clone(uses), ok
}

// tokenSubsystems is TokenEngineSubsystems without the defensive copy, for the in-package
// predicate below. The exported form clones because several entries share one backing array,
// and a caller that reordered it would reorder what the gates read.
func tokenSubsystems(token string) ([]EngineSubsystem, bool) {
	if spec, ok := conditionPrototypes[token]; ok {
		return spec.Uses, validSubsystemDeclaration(spec.Uses)
	}
	if spec, ok := directivePrototypes[token]; ok {
		return spec.Uses, validSubsystemDeclaration(spec.Uses)
	}
	return nil, false
}

// TokenUsesEngineSubsystem reports whether the named token's enforcement depends on s.
//
// An UNCLASSIFIED token reports true for every subsystem — the fail-closed direction: it
// costs extra work per call rather than running a handler against an unwired facility.
func TokenUsesEngineSubsystem(token string, s EngineSubsystem) bool {
	uses, ok := tokenSubsystems(token)
	if !ok {
		return true
	}
	return DeclarationUsesSubsystem(uses, s)
}

// Deliberately no per-INSTANCE form of the lookup above (unlike the state axis): the engine
// answers from its own handler registry, and a condition VALUE tells it nothing the
// discriminator doesn't.
