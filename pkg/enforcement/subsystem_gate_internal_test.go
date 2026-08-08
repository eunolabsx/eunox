// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// White-box (package enforcement) tests for the optional-subsystem gates: which of the engine's
// two conditional facilities — the antecedent history and the flow-label set — get wired for a
// given policy, and who decides.
//
// The decision moved here from the manifest layer, and the reason is the override case below.
// A manifest-side derivation is a statement about TOKEN TYPES, while the thing that reads a
// store is the HANDLER, and those are the same object only for the handlers this build ships.

package enforcement

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flowReadingHandler is the shape the subsystem declaration exists for: an embedder's
// replacement for a stock condition whose enforcement reads the flow-label set the stock one
// never touched.
type flowReadingHandler struct {
	declares []capability.EngineSubsystem
}

func (flowReadingHandler) Handle(context.Context, capability.Condition, *capability.EnforceRequest) *ConditionError {
	return nil
}

func (h flowReadingHandler) UsesEngineSubsystems() []capability.EngineSubsystem { return h.declares }

// TestSubsystemGates_AnOverriddenStockHandlerKeepsItsFacilityWired is the regression, and the
// reason the gates are the engine's business rather than the manifest's.
//
// WithConditionHandler can replace ANY registered type, not just the extension points. An
// embedder registering a handler for allowedValues — declared as depending on nothing, which is
// correct for the handler this build ships — that closes over the FlowLabelStore they also
// passed to WithFlowLabelStore gets, from a policy of nothing but allowedValues, an engine that
// never populates the flow set. The handler then reads an empty set: the fail-open the flow
// layer exists to prevent, arriving through the gate rather than through the turn.
func TestSubsystemGates_AnOverriddenStockHandlerKeepsItsFacilityWired(t *testing.T) {
	t.Parallel()
	allowedValuesOnly := []string{capability.ConditionTypeAllowedValues}

	stock := New(WithPolicyTokens(allowedValuesOnly))
	require.True(t, stock.skipFlow,
		"the shipped allowedValues handler touches no flow state, so the skip must still be available")

	// An override that says nothing about itself is UNCLASSIFIED — the conservative default,
	// so an embedder gets the safe answer by doing nothing at all.
	silent := New(
		WithPolicyTokens(allowedValuesOnly),
		WithConditionHandler(capability.ConditionTypeAllowedValues, ConditionHandlerFunc(
			func(context.Context, capability.Condition, *capability.EnforceRequest) *ConditionError { return nil })),
	)
	assert.False(t, silent.skipFlow,
		"a replacement handler is not described by the declaration the token it replaced carries")
	assert.False(t, silent.skipAntecedentRecording, "and the same for the other facility")

	// And one that declares honestly gets exactly what it declared.
	declared := New(
		WithPolicyTokens(allowedValuesOnly),
		WithConditionHandler(capability.ConditionTypeAllowedValues,
			flowReadingHandler{declares: []capability.EngineSubsystem{capability.SubsystemFlowLabels}}),
	)
	assert.False(t, declared.skipFlow, "the handler reads the flow set, so the flow path stays wired")
	assert.True(t, declared.skipAntecedentRecording, "and only what it declared stays wired")

	// A handler declaring SubsystemNone is taken at its word — the whole reason "declared
	// none" is a value rather than an empty slice.
	none := New(
		WithPolicyTokens(allowedValuesOnly),
		WithConditionHandler(capability.ConditionTypeAllowedValues,
			flowReadingHandler{declares: []capability.EngineSubsystem{capability.SubsystemNone}}),
	)
	assert.True(t, none.skipFlow)
	assert.True(t, none.skipAntecedentRecording)
}

// TestSubsystemGates_DeriveFromEveryTokenInTheVocabulary walks the whole condition/directive
// vocabulary and pins that each token's declaration is what the gates turn on — the consumer
// half of pkg/capability's completeness test. A gate written as a hand-listed set of token
// types passes today and fails here the moment a token is added, which is the point.
func TestSubsystemGates_DeriveFromEveryTokenInTheVocabulary(t *testing.T) {
	t.Parallel()
	seen := map[capability.EngineSubsystem]bool{}
	for _, token := range append(capability.KnownConditionTypes(), capability.KnownDirectiveTypes()...) {
		t.Run(token, func(t *testing.T) {
			e := New(WithPolicyTokens([]string{token}))
			for _, s := range capability.EngineSubsystems() {
				want := capability.TokenUsesEngineSubsystem(token, s)
				seen[s] = seen[s] || want
				assert.Equal(t, want, e.policyUses(s),
					"the gate for %q must follow what %q declares, not a list of token types", s, token)
			}
		})
	}
	// Not vacuous: some token really does depend on each facility, so a build where every
	// declaration collapsed to SubsystemNone — skipping both for every policy — fails here.
	for _, s := range capability.EngineSubsystems() {
		assert.True(t, seen[s], "no token in the vocabulary declares %q, so its gate is never exercised", s)
	}
}

// TestSubsystemGates_UndeclaredPolicyWiresEverything separates the two statements a caller can
// make, because only one of them may skip anything. An engine nobody told about its policy —
// every embedder using pkg/enforcement directly, and every test — must wire both facilities;
// an engine told the policy carries no tokens may skip both.
func TestSubsystemGates_UndeclaredPolicyWiresEverything(t *testing.T) {
	t.Parallel()
	silent := New()
	assert.False(t, silent.skipFlow, "an engine told nothing about its policy must wire everything")
	assert.False(t, silent.skipAntecedentRecording)

	empty := New(WithPolicyTokens(nil))
	assert.True(t, empty.skipFlow, "a policy that carries no token needs neither facility")
	assert.True(t, empty.skipAntecedentRecording)

	// A token this build has no handler for is unclassifiable, so it depends on everything —
	// it fails closed at decision time anyway, and the skip must not be taken on its account
	// in the meantime.
	unknown := New(WithPolicyTokens([]string{"someFutureCondition"}))
	assert.False(t, unknown.skipFlow)
	assert.False(t, unknown.skipAntecedentRecording)
}

// declaringEvaluator is a PolicyEvaluator that states which facilities it reads.
type declaringEvaluator struct{ declares []capability.EngineSubsystem }

func (declaringEvaluator) Evaluate(context.Context, string, interface{}, interface{}, *capability.EnforceRequest) *ConditionError {
	return nil
}
func (e declaringEvaluator) UsesEngineSubsystems() []capability.EngineSubsystem { return e.declares }

// silentEvaluator is one that does not.
type silentEvaluator struct{}

func (silentEvaluator) Evaluate(context.Context, string, interface{}, interface{}, *capability.EnforceRequest) *ConditionError {
	return nil
}

// TestSubsystemGates_ExtensionPointsAskTheirEvaluator covers `policy`, whose enforcement is
// supplied from outside this build. Its registry entry declares EVERY subsystem, and must — a
// token type cannot know what an embedder's evaluator reads. The evaluator can, and the cost of
// not asking it lands on the policy's OTHER capabilities: a manifest mixing `policy` with a
// plain maxCalls keeps antecedent recording wired for the whole engine, so every maxCalls call
// pays a counter round-trip and re-arms a fail-closed deny path on a counter-write fault.
//
// It also covers the token that must NOT follow the evaluator — see the `custom` case below.
func TestSubsystemGates_ExtensionPointsAskTheirEvaluator(t *testing.T) {
	t.Parallel()
	mixed := []string{capability.ConditionTypePolicy, capability.ConditionTypeMaxCalls}

	conservative := New(WithPolicyTokens(mixed), WithPolicyEvaluator(silentEvaluator{}))
	assert.False(t, conservative.skipFlow, "an evaluator that declares nothing is unclassified")
	assert.False(t, conservative.skipAntecedentRecording)

	// Not wired at all is the same answer: the token still cannot be classified from here.
	assert.False(t, New(WithPolicyTokens(mixed)).skipAntecedentRecording)

	honest := New(WithPolicyTokens(mixed),
		WithPolicyEvaluator(declaringEvaluator{declares: []capability.EngineSubsystem{capability.SubsystemFlowLabels}}))
	assert.False(t, honest.skipFlow, "the evaluator reads the flow set")
	assert.True(t, honest.skipAntecedentRecording,
		"and the sibling maxCalls no longer pays for a facility nothing reads")

	// `custom` must NOT follow the evaluator: handleCustom consults no evaluator at all, so
	// an evaluator wired for `policy` would be declaring on behalf of a token it has nothing
	// to do with — the defect the registry lookup exists to remove, arriving through the
	// forwarding. Its registry entry (every subsystem) stands until an embedder supplies the
	// real handler and declares for that.
	withCustom := New(WithPolicyTokens([]string{capability.ConditionTypeCustom, capability.ConditionTypeMaxCalls}),
		WithPolicyEvaluator(declaringEvaluator{declares: []capability.EngineSubsystem{capability.SubsystemNone}}))
	assert.False(t, withCustom.skipFlow,
		"a `policy` evaluator must not answer for `custom`, whose handler never calls it")
	assert.False(t, withCustom.skipAntecedentRecording)

	// The order options are applied in must not matter: the gates are derived after ALL of
	// them, so an evaluator passed before or after the tokens is seen either way.
	reversed := New(
		WithPolicyEvaluator(declaringEvaluator{declares: []capability.EngineSubsystem{capability.SubsystemNone}}),
		WithPolicyTokens(mixed))
	assert.True(t, reversed.skipFlow)
	assert.True(t, reversed.skipAntecedentRecording)
}

// TestRegisteredHandler_OverrideReplacesTheDeclarationToo pins the pairing at the registry
// level: installing a handler for a type must replace that type's subsystem declaration in the
// same write, or the engine keeps skipping a facility on the strength of what the handler that
// is no longer there used to do.
func TestRegisteredHandler_OverrideReplacesTheDeclarationToo(t *testing.T) {
	t.Parallel()
	e := New(WithConditionHandler(capability.ConditionTypeFlowLabel, ConditionHandlerFunc(
		func(context.Context, capability.Condition, *capability.EnforceRequest) *ConditionError { return nil })))
	entry, ok := e.handlers[capability.ConditionTypeFlowLabel]
	require.True(t, ok)
	assert.Nil(t, entry.uses,
		"the replaced token's declaration must not survive the handler it described")
	assert.True(t, entry.dependsOn(capability.SubsystemFlowLabels), "so the override is unclassified")
	assert.True(t, entry.dependsOn(capability.SubsystemAntecedentHistory))

	// A built-in keeps the declaration from its prototype-registry entry.
	builtin := New().handlers[capability.ConditionTypeFlowLabel]
	assert.True(t, builtin.dependsOn(capability.SubsystemFlowLabels))
	assert.False(t, builtin.dependsOn(capability.SubsystemAntecedentHistory))
}

// unsetPureHandler and unsetCommittingHandler are an embedder's handlers that declare their own
// subsystems by dereferencing themselves — the ordinary shape — so a nil pointer of either (an
// unset config field, boxed into a non-nil interface) panics if anything calls that method. They
// are deliberately separate types: a fixture implementing BOTH registers as committing whichever
// option installs it, and would exercise only one of the two arms below.
type unsetPureHandler struct{ declares []capability.EngineSubsystem }

func (h *unsetPureHandler) Handle(context.Context, capability.Condition, *capability.EnforceRequest) *ConditionError {
	return nil
}

func (h *unsetPureHandler) UsesEngineSubsystems() []capability.EngineSubsystem { return h.declares }

type unsetCommittingHandler struct{ declares []capability.EngineSubsystem }

func (h *unsetCommittingHandler) PrepareCommit(context.Context, capability.Condition, *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	return DeferredCommit{}, false, nil
}

func (h *unsetCommittingHandler) UsesEngineSubsystems() []capability.EngineSubsystem {
	return h.declares
}

// TestRegisteredHandler_TypedNilDeclarationDoesNotPanicNew pins that the typed-nil rule
// registeredHandler.commits states is applied by the OTHER reader of the same two fields. The
// SubsystemDependent assertion succeeds for a typed nil — the itab belongs to the type, not the
// value — so asking it to declare crashed New, i.e. the proxy never started and the fail-closed
// CONDITION_FAILED the decision path promises for this handler was never reached.
//
// WithPolicyTokens is required to reproduce: without it policyUses short-circuits on
// "the policy is unknown, wire everything" before any entry is asked.
func TestRegisteredHandler_TypedNilDeclarationDoesNotPanicNew(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		opt  Option
	}{
		{"committing", WithCommittingConditionHandler(capability.ConditionTypeMaxCalls, (*unsetCommittingHandler)(nil))},
		{"pure", WithConditionHandler(capability.ConditionTypeAllowedValues, (*unsetPureHandler)(nil))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var e *Engine
			require.NotPanics(t, func() {
				e = New(WithPolicyTokens([]string{capability.ConditionTypeMaxCalls, capability.ConditionTypeAllowedValues}), tc.opt)
			})
			// Unclassified, so every facility stays wired: an entry that cannot declare must not
			// be read as declaring nothing.
			assert.False(t, e.skipFlow, "an undeclarable handler leaves the flow facility wired")
			assert.False(t, e.skipAntecedentRecording, "and the antecedent facility too")
		})
	}
}

// TestRegisterBuiltins_CoversEveryDiscriminatorInTheVocabulary closes the in-tree half of the
// unknown-condition-type refusal: a token in pkg/capability's prototype registry whose
// registerBuiltins line was forgotten loads clean from a manifest (the loader checks the
// prototype registry) and then hits "unknown condition type" on every call carrying it.
//
// Nothing caught that before. The subsystem-gate test above still passes for such a token,
// because policyUses falls back to the declaration when the type is absent from e.handlers —
// so the two registries could disagree with every test green.
func TestRegisterBuiltins_CoversEveryDiscriminatorInTheVocabulary(t *testing.T) {
	t.Parallel()
	e := New()
	for _, condType := range capability.KnownConditionTypes() {
		handler, ok := e.handlers[condType]
		if !ok {
			t.Errorf("condition type %q is in the grammar but has no handler: a manifest carrying it loads clean and then refuses every call as an unknown type", condType)
			continue
		}
		// An entry holding neither shape is the same gap one level in: registered, and still
		// unable to evaluate anything.
		if handler.pure == nil && handler.committing == nil {
			t.Errorf("condition type %q has a registry entry with no handler in either field", condType)
		}
	}
	// The other direction. A handler for a type the grammar does not model can never be
	// reached through a manifest, so it is dead code that reads as coverage.
	for condType := range e.handlers {
		if _, known := capability.NewConditionPrototype(condType); !known {
			t.Errorf("handler registered for %q, which is not a condition discriminator this build models", condType)
		}
	}
}
