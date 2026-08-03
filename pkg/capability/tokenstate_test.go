// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenStateAccumulation_EveryRegisteredTokenDeclaresAClass is the completeness gate the
// property lacked, and the reason this whole classification moved onto the registry entry.
//
// "Which tokens accumulate cross-call state" decides whether both transports serialize their
// decisions. Asked as a hand-written disjunction of the tokens that happened to exist, a new
// accumulating condition is simply absent from it: the decision turn is not taken, the
// source->sink race is open, and every other completeness test still passes because none of
// them asserts that a token declares this. It mirrors
// TestTokenSince_EveryRegisteredTokenDeclaresAPublishedRevision exactly, for exactly that
// reason — the grammar revision already had this gate and this property did not.
func TestTokenStateAccumulation_EveryRegisteredTokenDeclaresAClass(t *testing.T) {
	t.Parallel()
	for _, token := range append(KnownConditionTypes(), KnownDirectiveTypes()...) {
		t.Run(token, func(t *testing.T) {
			class, ok := TokenStateAccumulation(token)
			require.True(t, ok,
				"%q declares no State on its prototype-registry entry, so every consumer must treat it as "+
					"the strongest class. Declare what cross-call state its enforcement touches: StateNone, "+
					"StateAtomic (one atomic AdmitAll admission) or StateNonAtomic (a read in one call, a "+
					"write in another)", token)
			assert.True(t, slices.Contains(stateAccumulationOrder, class),
				"%q declares State %q, which is not a class this build models", token, class)
		})
	}
}

// TestTokenStateAccumulation_UnclassifiedIsNotStateNone pins the fail-closed direction. An
// entry with no State must read as "cannot classify" rather than as the zero class it
// resembles — reporting an unreasoned-about token as StateNone is exactly the silent fail-open
// the declaration exists to reverse.
func TestTokenStateAccumulation_UnclassifiedIsNotStateNone(t *testing.T) {
	const token = "unclassifiedStateForTest"
	conditionPrototypes[token] = tokenSpec[Condition]{New: func() Condition { return &MaxCallsCondition{} }, Since: SchemaVersion01}
	t.Cleanup(func() { delete(conditionPrototypes, token) })

	class, ok := TokenStateAccumulation(token)
	assert.False(t, ok, "an entry with no State must not be classified")
	assert.NotEqual(t, StateNone, class)

	// And the two derived predicates both fail CLOSED on it: serialize, and warn.
	assert.True(t, class.NeedsSerializedDecisions(), "an unclassified token must still take the decision turn")
	assert.True(t, class.AccumulatesSharedState(), "and must still trip the multi-instance advisory")
}

func TestTokenStateAccumulation_UnknownTokenIsUnclassified(t *testing.T) {
	t.Parallel()
	for _, token := range []string{"", "no-such-token", "MAXCALLS", "maxCall"} {
		_, ok := TokenStateAccumulation(token)
		assert.False(t, ok, "%q is in neither registry", token)
	}
}

// TestStateAccumulation_PredicatesMatchTheClasses pins what each class means to its two
// consumers. The distinction that matters is StateAtomic: maxCalls and a cumulative
// blastRadius DO accumulate state a later call reads back — so the shared-state advisory must
// fire — and deliberately need NO decision turn, because AdmitAll admits or refuses a whole
// batch of buckets indivisibly. A predicate written as "accumulates anything ⟹ serialize"
// would serialize every quota policy in existence.
func TestStateAccumulation_PredicatesMatchTheClasses(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		class          StateAccumulation
		wantSerialized bool
		wantShared     bool
	}{
		"none":       {StateNone, false, false},
		"atomic":     {StateAtomic, false, true},
		"non-atomic": {StateNonAtomic, true, true},
		"a class we cannot place fails closed on both": {StateAccumulation("no-such-class"), true, true},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.wantSerialized, tc.class.NeedsSerializedDecisions())
			assert.Equal(t, tc.wantShared, tc.class.AccumulatesSharedState())
		})
	}
}

// TestStateAccumulation_TheFlowTokensAreTheNonAtomicOnes reads the classification back off the
// registry for the tokens whose class the decision turn's correctness rests on. It is the
// state-side twin of TestTokenSince_FlowAndEffectTokensAreTheLaterRevision: the classification
// is derived now, so what is left to assert is that the derivation lands on the right answers.
func TestStateAccumulation_TheFlowTokensAreTheNonAtomicOnes(t *testing.T) {
	t.Parallel()
	for _, token := range []string{
		ConditionTypeFlowLabel, ConditionTypeSequenceBlock,
		DirectiveTypeLabelOutput, DirectiveTypeDeclassify,
	} {
		class, ok := TokenStateAccumulation(token)
		require.True(t, ok)
		assert.Equal(t, StateNonAtomic, class, "%q commits in one call what a later call reads back", token)
	}
	for _, token := range []string{ConditionTypeMaxCalls} {
		class, ok := TokenStateAccumulation(token)
		require.True(t, ok)
		assert.Equal(t, StateAtomic, class, "%q is admitted atomically and needs no turn", token)
	}
	for _, token := range []string{
		ConditionTypeTimeWindow, ConditionTypeIPRange, ConditionTypeAllowedValues,
		ConditionTypeEffectClass, DirectiveTypeRedactFields,
	} {
		class, ok := TokenStateAccumulation(token)
		require.True(t, ok)
		assert.Equal(t, StateNone, class, "%q decides from the request alone", token)
	}
}

// TestConditionStateAccumulation_RefinesPerInstance covers the one token whose accumulation is
// a property of its VALUE: a cumulative blastRadius consumes a sliding-window budget, a
// per-call `max` compares one magnitude against a constant and stores nothing. Without the
// refinement the multi-instance advisory would fire for every per-call bound, telling an
// operator their replicas need a shared backend for state that does not exist.
func TestConditionStateAccumulation_RefinesPerInstance(t *testing.T) {
	t.Parallel()
	total := json.Number("2000")
	per := json.Number("500")
	for name, tc := range map[string]struct {
		cond Condition
		want StateAccumulation
	}{
		"cumulative bound consumes a window budget": {
			&BlastRadiusCondition{MaxTotal: &total, WindowSeconds: 3600}, StateAtomic},
		"per-call bound stores nothing": {
			&BlastRadiusCondition{Max: &per}, StateNone},
		"value form refines identically": {
			BlastRadiusCondition{Max: &per}, StateNone},
		"half a cumulative bound bounds nothing and stores nothing": {
			&BlastRadiusCondition{MaxTotal: &total}, StateNone},
	} {
		t.Run(name, func(t *testing.T) {
			class, ok := ConditionStateAccumulation(tc.cond)
			require.True(t, ok)
			assert.Equal(t, tc.want, class)
		})
	}
}

// TestDirectiveStateAccumulation_ReadsTheDirectiveRegistry: the directive side resolves
// through its own registry, in both the pointer form the loader builds and the value form a
// programmatic manifest carries.
func TestDirectiveStateAccumulation_ReadsTheDirectiveRegistry(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		dir  Directive
		want StateAccumulation
	}{
		"labelOutput writes what a sink reads back": {&LabelOutputDirective{Labels: []string{FlowLabelPII}}, StateNonAtomic},
		"value form resolves identically":           {LabelOutputDirective{Labels: []string{FlowLabelPII}}, StateNonAtomic},
		"declassify clears it and burns a grant":    {&DeclassifyDirective{Labels: []string{FlowLabelPII}}, StateNonAtomic},
		"redactFields masks one response":           {&RedactFieldsDirective{Fields: []string{"a.b"}}, StateNone},
	} {
		t.Run(name, func(t *testing.T) {
			class, ok := DirectiveStateAccumulation(tc.dir)
			require.True(t, ok)
			assert.Equal(t, tc.want, class)
		})
	}
}

// TestStateAccumulation_RefinementCanOnlyNarrow is the guard on the escape hatch. The registry
// entry declares the strongest class an instance can reach; a refinement reporting MORE than
// that, or a class this build cannot place, is ignored in favour of the declared one — so a
// mis-written refinement costs precision and can never drop a token below what its type
// declared.
func TestStateAccumulation_RefinementCanOnlyNarrow(t *testing.T) {
	t.Parallel()
	assertDeclared := func(t *testing.T, c Condition, want StateAccumulation) {
		t.Helper()
		class, ok := ConditionStateAccumulation(c)
		require.True(t, ok)
		assert.Equal(t, want, class)
	}
	// maxCalls declares StateAtomic; a refinement claiming MORE is ignored.
	assertDeclared(t, refiningCondition{ConditionTypeMaxCalls, StateNonAtomic}, StateAtomic)
	// ...and one naming a class this build does not model is ignored too.
	assertDeclared(t, refiningCondition{ConditionTypeMaxCalls, StateAccumulation("invented")}, StateAtomic)
	// Narrowing is honoured.
	assertDeclared(t, refiningCondition{ConditionTypeMaxCalls, StateNone}, StateNone)
}

// TestStateAccumulation_NilTokensAccumulateNothing: the discriminator methods have value
// receivers, so a typed nil would be dereferenced. A programmatically built manifest
// (MergeManifests) can carry one, and the classification path must classify rather than panic.
func TestStateAccumulation_NilTokensAccumulateNothing(t *testing.T) {
	t.Parallel()
	require.NotPanics(t, func() {
		class, ok := ConditionStateAccumulation(nil)
		assert.True(t, ok)
		assert.Equal(t, StateNone, class)

		class, ok = ConditionStateAccumulation((*FlowLabelCondition)(nil))
		assert.True(t, ok)
		assert.Equal(t, StateNone, class)

		class, ok = DirectiveStateAccumulation(nil)
		assert.True(t, ok)
		assert.Equal(t, StateNone, class)

		class, ok = DirectiveStateAccumulation((*LabelOutputDirective)(nil))
		assert.True(t, ok)
		assert.Equal(t, StateNone, class)
	})
}

// TestStateAccumulation_UnmodelledDiscriminatorIsUnclassified: a token whose discriminator is
// in neither registry cannot be placed, so the classification reports that rather than
// guessing — the caller is what turns it into "the strongest class".
func TestStateAccumulation_UnmodelledDiscriminatorIsUnclassified(t *testing.T) {
	t.Parallel()
	_, ok := ConditionStateAccumulation(refiningCondition{"no-such-condition", StateNone})
	assert.False(t, ok)
}

// refiningCondition is a condition that reports an arbitrary discriminator and an arbitrary
// refinement, for driving the narrowing rule against classes real tokens do not produce.
type refiningCondition struct {
	discriminator string
	refined       StateAccumulation
}

func (c refiningCondition) ConditionType() string                      { return c.discriminator }
func (c refiningCondition) RefineStateAccumulation() StateAccumulation { return c.refined }
