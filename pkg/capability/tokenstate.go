// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// What CROSS-CALL state a token accumulates, declared ON the prototype registry entry beside
// the grammar revision.
//
// Two operational questions are asked about a whole policy, and both are properties of the
// TOKENS it carries rather than of the policy:
//
//   - Must this policy's decisions be SERIALIZED on the state anchor? A token whose
//     enforcement reads accumulated state in one call and writes it in another, NON-ATOMICALLY,
//     has a source->sink race a host can pipeline into: the sink's read runs before the
//     source's write commits and the taint is slipped. Both transports close that with a
//     decision turn, and both ask this to decide whether to take one.
//   - Does this policy depend on state that is per-PROCESS under the in-memory backends? Three
//     replicas without a shared Redis then enforce a budget three times over, and a source
//     recorded on one instance is invisible to a sink on another.
//
// Both used to be hand-written disjunctions naming the tokens that happened to exist. That is
// one place to forget per question, and forgetting is SILENT in the direction that matters: a
// new accumulating condition simply reports "no turn needed", both transports run its decisions
// unserialized, and every completeness test still passes because none of them asserts that a
// token declares anything here.
//
// Declaring the class on the registry entry removes that. The registry is the one place a token
// can be added at all, an entry declaring no class is UNCLASSIFIED (and every consumer treats
// that as the strongest class, not as "accumulates nothing"), and the completeness test in
// grammar_test.go fails the build when an entry declares none.
//
// The rule for setting it, stated once so the next contributor does not have to infer it from
// the existing entries: ask what the token's enforcement does to state that OUTLIVES the call.
// Nothing at all is StateNone. A budget admitted through the call counter's AdmitAll — one
// atomic admit-or-refuse per call — is StateAtomic: it accumulates, so it is per-process state
// the shared-state advisory must know about, but it needs no turn because the admission is
// indivisible. A read in one call and a write in another, with a window between them, is
// StateNonAtomic and needs the turn.

package capability

import "slices"

// StateAccumulation classifies the cross-call state a token's enforcement touches.
type StateAccumulation string

const (
	// StateNone is a token decided from the request alone (plus wall-clock or config): it
	// reads and writes nothing that outlives the call.
	StateNone StateAccumulation = "none"
	// StateAtomic is a budget consumed through one atomic admission per call — maxCalls'
	// slot, a cumulative blastRadius' weighted total. It is accumulated state (so it is
	// per-process under the in-memory counter, and the multi-instance advisory covers it) but
	// it needs no decision turn: AdmitAll admits or refuses a whole batch indivisibly, so
	// there is no window between a read and a write for a concurrent call to land in.
	StateAtomic StateAccumulation = "atomic"
	// StateNonAtomic is a non-atomic read-then-write against shared state: one call commits
	// what a later call reads back, with a window in between. The flow-label set a labelOutput
	// writes and a flowLabel sink peeks, the antecedent history sequenceBlock consults, the
	// single-use ledger a declassify burns. These are what the decision turn exists for.
	StateNonAtomic StateAccumulation = "nonAtomic"
)

// stateAccumulationOrder lists the classes from weakest to strongest. Like
// publishedSchemaVersions it is DATA: the ordering a refinement is checked against is an index
// into this slice, and a class absent from it has no rank at all, so every consumer fails
// closed on one rather than comparing strings.
var stateAccumulationOrder = []StateAccumulation{StateNone, StateAtomic, StateNonAtomic}

// rank is the class's position in stateAccumulationOrder, or -1 for a class this build does
// not model.
func (s StateAccumulation) rank() int { return slices.Index(stateAccumulationOrder, s) }

// NeedsSerializedDecisions reports whether a policy carrying this token must run its decisions
// under the transports' decision turn.
//
// A class this build cannot place reports TRUE. That is the fail-closed direction: an
// unclassified token is one nobody has reasoned about, and serializing a policy that did not
// need it costs decision parallelism, while not serializing one that did reopens the
// source->sink race.
func (s StateAccumulation) NeedsSerializedDecisions() bool {
	switch s {
	case StateNone, StateAtomic:
		return false
	}
	return true
}

// AccumulatesSharedState reports whether this token's enforcement depends on state that
// outlives the call — the predicate behind the multi-instance advisory, which must fire for
// the atomic budgets as much as for the non-atomic sets: a maxCalls of 20 enforced by three
// replicas with no shared backend is 60.
//
// A class this build cannot place reports TRUE, for the same reason as above: an unwarned
// operator running replicas is the failure this advisory exists to prevent.
func (s StateAccumulation) AccumulatesSharedState() bool { return s != StateNone }

// StateRefiner is implemented by a token whose accumulation depends on its VALUE and not only
// on its type. blastRadius is the one today: a cumulative bound consumes a sliding-window
// budget, a per-call `max` compares one call's weight against a constant and stores nothing.
//
// A refinement may only NARROW: the registry entry declares the strongest class any instance
// of the token can reach, and a refinement reporting more than that (or reporting a class this
// build does not model) is ignored in favour of the declared one. So a mis-written refinement
// can cost precision, never the turn.
type StateRefiner interface {
	RefineStateAccumulation() StateAccumulation
}

// TokenStateAccumulation reports the class declared by the named condition or directive's
// prototype-registry entry, and whether this build can classify the token at all.
//
// ok is false for a token in neither registry AND for an entry whose State is empty or names a
// class this build does not model. Callers must treat both as the strongest class — see
// NeedsSerializedDecisions.
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
// its registry entry declares, narrowed by the value itself when its type refines it.
//
// A nil condition carries no enforcement and accumulates nothing. Both the pointer form the
// JSON loader builds and the value form the JWT path builds are accepted, because the
// discriminator is read off the interface rather than off a Go type switch.
func ConditionStateAccumulation(c Condition) (StateAccumulation, bool) {
	if isNilToken(c) {
		return StateNone, true
	}
	return refinedStateAccumulation(c.ConditionType(), c)
}

// DirectiveStateAccumulation is the directive-side twin of ConditionStateAccumulation.
func DirectiveStateAccumulation(d Directive) (StateAccumulation, bool) {
	if isNilToken(d) {
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
	// Narrowing only, and never to a class this build cannot place: the declared class is the
	// answer every consumer would have used, so falling back to it costs precision at worst.
	if refined := r.RefineStateAccumulation(); refined.rank() >= 0 && refined.rank() < declared.rank() {
		return refined, true
	}
	return declared, true
}

// isNilToken reports whether v is a nil interface or a typed nil pointer, through the
// package's one typed-nil predicate. The discriminator methods have value receivers, so calling
// one on a typed nil pointer dereferences it; a manifest is not the only source of these values
// (MergeManifests takes programmatically built constraints), so the classification path must
// not panic on one.
func isNilToken(v any) bool { return v == nil || IsTypedNil(v) }
