// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// What CROSS-CALL state a token accumulates, declared ON the prototype registry entry beside
// the grammar revision. Two questions about a whole policy are properties of the TOKENS it
// carries: must decisions be SERIALIZED on the state anchor (a non-atomic read-then-write has
// a source->sink race a host can pipeline into), and does the policy depend on state that is
// per-PROCESS under the in-memory backends (three replicas then enforce a budget three times
// over)? Both used to be hand-written disjunctions naming the tokens that happened to exist —
// silently wrong in the direction that matters, since a forgotten new token just reports "no
// turn needed" with no test to catch it. Declaring the class here instead means an entry
// declaring none is UNCLASSIFIED and treated as the strongest class (enforced by
// grammar_test.go). Rule for setting it: ask what the token's enforcement does to state that
// OUTLIVES the call — nothing is StateNone, an atomic AdmitAll budget is StateAtomic (needs no
// turn, the admission is indivisible), a read-then-write across calls is StateNonAtomic.

package capability

import "slices"

// StateAccumulation classifies the cross-call state a token's enforcement touches.
type StateAccumulation string

const (
	// StateNone is a token decided from the request alone (plus wall-clock or config): it
	// reads and writes nothing that outlives the call.
	StateNone StateAccumulation = "none"
	// StateAtomic is a budget consumed through one atomic admission per call — maxCalls'
	// slot, a cumulative blastRadius' weighted total. It accumulates (per-process under the
	// in-memory counter, so the multi-instance advisory covers it) but needs no decision
	// turn: AdmitAll admits or refuses a whole batch indivisibly.
	StateAtomic StateAccumulation = "atomic"
	// StateNonAtomic is a non-atomic read-then-write against shared state: one call commits
	// what a later call reads back, with a window in between (the flow-label set, the
	// antecedent history, a declassify's single-use ledger). What the decision turn exists for.
	StateNonAtomic StateAccumulation = "nonAtomic"
)

// stateAccumulationOrder lists the classes from weakest to strongest. It is DATA: a
// refinement is checked against this slice's index, and a class absent from it has no rank
// at all, so every consumer fails closed rather than comparing strings.
var stateAccumulationOrder = []StateAccumulation{StateNone, StateAtomic, StateNonAtomic}

// rank is the class's position in stateAccumulationOrder, or -1 for a class this build does
// not model.
func (s StateAccumulation) rank() int { return slices.Index(stateAccumulationOrder, s) }

// NeedsSerializedDecisions reports whether a policy carrying this token must run its
// decisions under the transports' decision turn.
//
// A class this build cannot place reports TRUE — the fail-closed direction: over-serializing
// costs decision parallelism, under-serializing reopens the source->sink race.
func (s StateAccumulation) NeedsSerializedDecisions() bool {
	switch s {
	case StateNone, StateAtomic:
		return false
	}
	return true
}

// AccumulatesSharedState reports whether this token's enforcement depends on state that
// outlives the call — the predicate behind the multi-instance advisory, which must fire for
// atomic budgets as much as non-atomic sets: a maxCalls of 20 enforced by three replicas
// with no shared backend is 60. A class this build cannot place reports TRUE, same reason.
func (s StateAccumulation) AccumulatesSharedState() bool { return s != StateNone }

// StateRefiner is implemented by a token whose accumulation depends on its VALUE and not only
// its type. blastRadius is the one today: a cumulative bound consumes a sliding-window
// budget, a per-call `max` compares one call's weight against a constant and stores nothing.
//
// A refinement may only NARROW: reporting more than the registry's declared class (or a
// class this build doesn't model) is ignored in favour of the declared one, so a mis-written
// refinement can cost precision, never the turn.
type StateRefiner interface {
	RefineStateAccumulation() StateAccumulation
}

// TokenStateAccumulation reports the class declared by the named condition or directive's
// prototype-registry entry, and whether this build can classify the token at all.
//
// ok is false for a token in neither registry AND for a malformed State. Callers must treat
// both as the strongest class — see NeedsSerializedDecisions.
func TokenStateAccumulation(token string) (StateAccumulation, bool) {
	if spec, ok := conditionPrototypes[token]; ok {
		return spec.State, spec.State.rank() >= 0
	}
	if spec, ok := directivePrototypes[token]; ok {
		return spec.State, spec.State.rank() >= 0
	}
	return "", false
}

// ConditionStateAccumulation reports what cross-call state c's enforcement touches: the class
// its registry entry declares, narrowed by the value itself when its type refines it. A nil
// condition accumulates nothing. Both the pointer form the JSON loader builds and the value
// form the JWT path builds are accepted, since the discriminator is read off the interface.
func ConditionStateAccumulation(c Condition) (StateAccumulation, bool) {
	// The discriminator methods have value receivers, so calling one on a typed nil
	// dereferences it — and a manifest is not the only source of these values
	// (MergeManifests builds constraints programmatically), so this path must not panic.
	if IsNilValue(c) {
		return StateNone, true
	}
	return refinedStateAccumulation(c.ConditionType(), c)
}

// DirectiveStateAccumulation is the directive-side twin of ConditionStateAccumulation.
func DirectiveStateAccumulation(d Directive) (StateAccumulation, bool) {
	if IsNilValue(d) {
		return StateNone, true
	}
	return refinedStateAccumulation(d.DirectiveType(), d)
}

// refinedStateAccumulation resolves a token's declared class and applies its instance
// refinement, if it has one.
func refinedStateAccumulation(token string, v any) (StateAccumulation, bool) {
	declared, ok := TokenStateAccumulation(token)
	if !ok {
		return declared, false
	}
	r, refines := v.(StateRefiner)
	if !refines {
		return declared, true
	}
	// Narrowing only: falling back to the declared class on an out-of-range refinement
	// costs precision at worst, never correctness.
	if refined := r.RefineStateAccumulation(); refined.rank() >= 0 && refined.rank() < declared.rank() {
		return refined, true
	}
	return declared, true
}
