// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenEngineSubsystems_EveryRegisteredTokenDeclaresOne is the completeness gate for the
// third axis, mirroring the Since and State gates for the same reason each of those exists.
//
// "Which engine subsystems does this policy need" decides whether the route builder skips the
// antecedent marker and the flow peek/record path. Asked as a hand-written list of token types
// — which it was — a new condition that READS the flow-label set is simply absent from it: the
// engine is built WithoutFlowLabels, the handler runs against an engine holding no flow state,
// and every other completeness test still passes because none of them asserts that a token
// declares this.
func TestTokenEngineSubsystems_EveryRegisteredTokenDeclaresOne(t *testing.T) {
	t.Parallel()
	for _, token := range append(KnownConditionTypes(), KnownDirectiveTypes()...) {
		t.Run(token, func(t *testing.T) {
			uses, ok := TokenEngineSubsystems(token)
			require.True(t, ok,
				"%q declares no usable Uses on its prototype-registry entry, so every consumer must treat it "+
					"as depending on every subsystem. Declare which optional engine facility its enforcement "+
					"reads: SubsystemNone, SubsystemAntecedentHistory, SubsystemFlowLabels", token)
			for _, s := range uses {
				assert.True(t, s == SubsystemNone || s.modelled(),
					"%q declares Uses %q, which is not a subsystem this build models", token, s)
			}
		})
	}
}

// TestTokenEngineSubsystems_TheFlowTokensDeclareTheFlowStore pins the declarations the gates
// actually turn on, so a token silently losing its subsystem is a failure here rather than a
// skipped facility at runtime. The negative half is what makes the gate worth having: a
// policy of nothing but maxCalls must still skip both.
func TestTokenEngineSubsystems_TheFlowTokensDeclareTheFlowStore(t *testing.T) {
	t.Parallel()
	for _, token := range []string{ConditionTypeFlowLabel, DirectiveTypeLabelOutput, DirectiveTypeDeclassify} {
		assert.True(t, TokenUsesEngineSubsystem(token, SubsystemFlowLabels), "%q reads or writes the flow-label set", token)
		assert.False(t, TokenUsesEngineSubsystem(token, SubsystemAntecedentHistory), "%q does not read the antecedent history", token)
	}
	assert.True(t, TokenUsesEngineSubsystem(ConditionTypeSequenceBlock, SubsystemAntecedentHistory))
	assert.False(t, TokenUsesEngineSubsystem(ConditionTypeSequenceBlock, SubsystemFlowLabels))
	for _, s := range EngineSubsystems() {
		assert.False(t, TokenUsesEngineSubsystem(ConditionTypeMaxCalls, s),
			"a quota lives in the call counter, which is wired unconditionally, not in %q", s)
	}
}

// TestTokenEngineSubsystems_ExtensionPointsDeclareEverything covers the two tokens whose
// enforcement is supplied from outside this build. An embedder's evaluator or custom handler
// can close over the very FlowLabelStore the engine was given, so this build cannot say what
// it reads — and skipping a facility out from under it is the silent direction.
func TestTokenEngineSubsystems_ExtensionPointsDeclareEverything(t *testing.T) {
	t.Parallel()
	for _, token := range []string{ConditionTypePolicy, ConditionTypeCustom} {
		for _, s := range EngineSubsystems() {
			assert.True(t, TokenUsesEngineSubsystem(token, s),
				"%q is an extension point: what it reads is not knowable here, so it must not disable %q", token, s)
		}
	}
}

// TestTokenEngineSubsystems_UnclassifiedDependsOnEverything pins the fail-closed direction:
// an entry that declares nothing must not read as "depends on nothing", which is the zero
// value it resembles and the fail-open the declaration exists to reverse. A malformed
// declaration — a facility this build does not model, or SubsystemNone mixed with a real one —
// is treated the same way.
func TestTokenEngineSubsystems_UnclassifiedDependsOnEverything(t *testing.T) {
	for name, uses := range map[string][]EngineSubsystem{
		"declares nothing":           nil,
		"declares an unknown one":    {EngineSubsystem("no-such-subsystem")},
		"mixes none with a real one": {SubsystemNone, SubsystemFlowLabels},
	} {
		t.Run(name, func(t *testing.T) {
			const token = "unclassifiedSubsystemForTest"
			conditionPrototypes[token] = tokenSpec[Condition]{
				New: func() Condition { return &MaxCallsCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: uses,
			}
			t.Cleanup(func() { delete(conditionPrototypes, token) })

			_, ok := TokenEngineSubsystems(token)
			assert.False(t, ok, "a malformed declaration must not be classified")
			for _, s := range EngineSubsystems() {
				assert.True(t, TokenUsesEngineSubsystem(token, s),
					"an unclassified token must keep %q wired rather than have it skipped", s)
			}
		})
	}
}

// TestTokenEngineSubsystems_UnknownTokenDependsOnEverything is the same rule for a token in
// neither registry: unclassifiable, so nothing is skipped on its account.
func TestTokenEngineSubsystems_UnknownTokenDependsOnEverything(t *testing.T) {
	t.Parallel()
	for _, token := range []string{"", "no-such-token", "FLOWLABEL", "flowlabel"} {
		_, ok := TokenEngineSubsystems(token)
		assert.False(t, ok, "%q is in neither registry", token)
		assert.True(t, TokenUsesEngineSubsystem(token, SubsystemFlowLabels))
	}
}

// TestEngineSubsystems_ReturnsACopy keeps the modelled set from being reordered or extended
// through the accessor: the registry entries reference the same slice, and the two gates are
// derived from it.
func TestEngineSubsystems_ReturnsACopy(t *testing.T) {
	t.Parallel()
	got := EngineSubsystems()
	require.NotEmpty(t, got)
	got[0] = EngineSubsystem("tampered")
	assert.True(t, slices.Contains(EngineSubsystems(), SubsystemAntecedentHistory))
	assert.True(t, slices.Contains(EngineSubsystems(), SubsystemFlowLabels))
	assert.False(t, slices.Contains(EngineSubsystems(), SubsystemNone),
		"SubsystemNone is the declares-nothing marker, not a facility a policy can need")
}

// TestConditionAndDirectiveUsesEngineSubsystem_AreNilSafe covers the two forms a token can
// take (the loader's pointer, a programmatically built value) and the typed nil a
// programmatic build can produce, which must not panic on a value-receiver discriminator.
func TestConditionAndDirectiveUsesEngineSubsystem_AreNilSafe(t *testing.T) {
	t.Parallel()
	assert.True(t, ConditionUsesEngineSubsystem(&FlowLabelCondition{}, SubsystemFlowLabels))
	assert.True(t, ConditionUsesEngineSubsystem(FlowLabelCondition{}, SubsystemFlowLabels))
	assert.True(t, DirectiveUsesEngineSubsystem(&LabelOutputDirective{}, SubsystemFlowLabels))
	assert.True(t, DirectiveUsesEngineSubsystem(LabelOutputDirective{}, SubsystemFlowLabels))

	assert.False(t, ConditionUsesEngineSubsystem(nil, SubsystemFlowLabels))
	assert.False(t, DirectiveUsesEngineSubsystem(nil, SubsystemFlowLabels))
	assert.False(t, ConditionUsesEngineSubsystem((*FlowLabelCondition)(nil), SubsystemFlowLabels),
		"a typed nil carries no enforcement and must not panic")
	assert.False(t, DirectiveUsesEngineSubsystem((*LabelOutputDirective)(nil), SubsystemFlowLabels))
}
