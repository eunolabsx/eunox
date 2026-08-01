// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// effNum builds a *json.Number for a manifest numeric literal.
func effNum(s string) *json.Number {
	n := json.Number(s)
	return &n
}

// effectReq builds a tools/call enforce request with the given arguments.
func effectReq(name string, args map[string]interface{}) *capability.EnforceRequest {
	return &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: name,
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: name},
		Arguments:  args,
	}
}

// effectEngine builds an engine with a counter wired and an optional ceiling.
func effectEngine(ceiling *capability.EffectCeiling) *enforcement.Engine {
	opts := []enforcement.Option{enforcement.WithCallCounter(callcounter.NewInMemory())}
	if ceiling != nil {
		opts = append(opts, enforcement.WithEffectCeiling(ceiling))
	}
	return enforcement.New(opts...)
}

// TestEffectClassCondition covers the per-target class gate: allow, deny, and the
// malformed/unevaluable inputs that must fail closed rather than fall open.
func TestEffectClassCondition(t *testing.T) {
	cases := []struct {
		name       string
		contract   *capability.EffectContract
		allow      []string
		wantDecide capability.Decision
	}{
		{
			name:       "a permitted class allows",
			contract:   &capability.EffectContract{Class: capability.EffectReversible},
			allow:      []string{capability.EffectReversible, capability.EffectCompensable},
			wantDecide: capability.DecisionAllow,
		},
		{
			name:       "a class outside the allow set denies",
			contract:   &capability.EffectContract{Class: capability.EffectIrreversible},
			allow:      []string{capability.EffectReversible, capability.EffectCompensable},
			wantDecide: capability.DecisionDeny,
		},
		{
			name:       "an unannotated target denies — it resolves to irreversible",
			contract:   nil,
			allow:      []string{capability.EffectReversible},
			wantDecide: capability.DecisionDeny,
		},
		{
			name:       "an empty allow set admits nothing",
			contract:   &capability.EffectContract{Class: capability.EffectReversible},
			allow:      nil,
			wantDecide: capability.DecisionDeny,
		},
		{
			name:       "an unknown class in the allow set denies rather than being ignored",
			contract:   &capability.EffectContract{Class: capability.EffectReversible},
			allow:      []string{"mostly-harmless"},
			wantDecide: capability.DecisionDeny,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			caps := []capability.Constraint{{
				Target:     "tool:act",
				Actions:    []string{"call"},
				Effect:     c.contract,
				Conditions: []capability.Condition{capability.EffectClassCondition{Allow: c.allow}},
			}}
			resp := effectEngine(nil).ValidateAction(context.Background(), effectReq("act", nil), caps)
			assert.Equal(t, c.wantDecide, resp.Decision)
			if c.wantDecide == capability.DecisionDeny {
				require.NotNil(t, resp.Denial)
				assert.Equal(t, capability.ConditionTypeEffectClass, resp.Denial.ConditionType)
				assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
			}
		})
	}
}

// TestBlastRadiusCondition covers the quantitative gate, including the case the whole
// condition exists for: the argument is legal at every value and only its SIZE is wrong.
func TestBlastRadiusCondition(t *testing.T) {
	contract := &capability.EffectContract{
		Class:              capability.EffectCompensable,
		CompensatingAction: "tool:reverse_refund",
		BlastRadius:        &capability.BlastRadiusSpec{Argument: "amount", Unit: "usd"},
	}
	caps := []capability.Constraint{{
		Target:     "tool:refund",
		Actions:    []string{"call"},
		Effect:     contract,
		Conditions: []capability.Condition{capability.BlastRadiusCondition{Max: effNum("500")}},
	}}
	eng := effectEngine(nil)

	t.Run("a small refund allows", func(t *testing.T) {
		resp := eng.ValidateAction(context.Background(), effectReq("refund", map[string]interface{}{"amount": json.Number("50")}), caps)
		assert.Equal(t, capability.DecisionAllow, resp.Decision)
	})
	t.Run("a refund at the bound allows", func(t *testing.T) {
		resp := eng.ValidateAction(context.Background(), effectReq("refund", map[string]interface{}{"amount": json.Number("500")}), caps)
		assert.Equal(t, capability.DecisionAllow, resp.Decision)
	})
	t.Run("a $5,000 refund is denied by blastRadius", func(t *testing.T) {
		resp := eng.ValidateAction(context.Background(), effectReq("refund", map[string]interface{}{"amount": json.Number("5000")}), caps)
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ConditionTypeBlastRadius, resp.Denial.ConditionType)
		assert.Equal(t, "5000", resp.Denial.Details["blast_radius"])
		assert.Equal(t, "500", resp.Denial.Details["blast_radius_max"])
	})
	t.Run("an unquantifiable call denies rather than being read as zero", func(t *testing.T) {
		resp := eng.ValidateAction(context.Background(), effectReq("refund", map[string]interface{}{}), caps)
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Contains(t, resp.Denial.Message, "could not be quantified")
	})
	t.Run("an exact comparison above 2^53 is not lost to float rounding", func(t *testing.T) {
		big := []capability.Constraint{{
			Target:     "tool:refund",
			Actions:    []string{"call"},
			Effect:     contract,
			Conditions: []capability.Condition{capability.BlastRadiusCondition{Max: effNum("9007199254740993")}},
		}}
		over := eng.ValidateAction(context.Background(), effectReq("refund", map[string]interface{}{"amount": json.Number("9007199254740994")}), big)
		assert.Equal(t, capability.DecisionDeny, over.Decision)
		at := eng.ValidateAction(context.Background(), effectReq("refund", map[string]interface{}{"amount": json.Number("9007199254740993")}), big)
		assert.Equal(t, capability.DecisionAllow, at.Decision)
	})
}

// TestEffectCeiling_EscalatesConsequentialActions is the consequence gate: approval is
// triggered by irreversibility plus blast radius plus the absence of a compensating
// action — never by which tool it is.
func TestEffectCeiling_EscalatesConsequentialActions(t *testing.T) {
	ceiling := &capability.EffectCeiling{MaxEffectClass: capability.EffectCompensable, MaxBlastRadius: effNum("1000")}
	eng := effectEngine(ceiling)

	compensable := []capability.Constraint{{
		Target:  "tool:refund",
		Actions: []string{"call"},
		Effect: &capability.EffectContract{
			Class:              capability.EffectCompensable,
			CompensatingAction: "tool:reverse_refund",
			BlastRadius:        &capability.BlastRadiusSpec{Argument: "amount", Unit: "usd"},
		},
	}}

	t.Run("an action under the ceiling passes untouched", func(t *testing.T) {
		resp := eng.ValidateAction(context.Background(), effectReq("refund", map[string]interface{}{"amount": json.Number("40")}), compensable)
		assert.Equal(t, capability.DecisionAllow, resp.Decision)
	})

	t.Run("an over-magnitude action escalates with the reason on the record", func(t *testing.T) {
		resp := eng.ValidateAction(context.Background(), effectReq("refund", map[string]interface{}{"amount": json.Number("4000")}), compensable)
		require.Equal(t, capability.DecisionEscalate, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ErrCodeEscalationRequired, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Details["ceiling_exceeded"], "blast_radius")
		// An escalation must not be downgradable to a forward: performing the action and
		// logging it is precisely what the ceiling exists to stop.
		assert.True(t, resp.Denial.HardDeny)
		assert.False(t, resp.AuditOnly)
	})

	t.Run("an unannotated tool escalates by default — the registry flywheel", func(t *testing.T) {
		bare := []capability.Constraint{{Target: "tool:anything", Actions: []string{"call"}}}
		resp := eng.ValidateAction(context.Background(), effectReq("anything", nil), bare)
		require.Equal(t, capability.DecisionEscalate, resp.Decision)
		assert.Equal(t, false, resp.Denial.Details["annotated"])
		assert.Contains(t, resp.Denial.Message, "declares no effect contract")
	})

	t.Run("the ceiling is keyed on effect, not tool identity", func(t *testing.T) {
		// Two differently-named tools with the SAME contract get the same verdict; the
		// ceiling never consults the name.
		for _, name := range []string{"wire_transfer", "delete_everything"} {
			caps := []capability.Constraint{{
				Target:  "tool:" + name,
				Actions: []string{"call"},
				Effect:  &capability.EffectContract{Class: capability.EffectReversible, BlastRadius: &capability.BlastRadiusSpec{Value: effNum("1")}},
			}}
			resp := eng.ValidateAction(context.Background(), effectReq(name, nil), caps)
			assert.Equal(t, capability.DecisionAllow, resp.Decision, name)
		}
	})
}

// TestEffectCeiling_OnExceedDeny pins the alternative outcome: an operator who wants a
// refusal rather than an approval queue gets a plain CONDITION_FAILED deny.
func TestEffectCeiling_OnExceedDeny(t *testing.T) {
	eng := effectEngine(&capability.EffectCeiling{MaxEffectClass: capability.EffectReversible, OnExceed: capability.OnExceedDeny})
	caps := []capability.Constraint{{Target: "tool:send_email", Actions: []string{"call"},
		Effect: &capability.EffectContract{Class: capability.EffectIrreversible}}}

	resp := eng.ValidateAction(context.Background(), effectReq("send_email", nil), caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
}

// TestEffectCeiling_RequiresCompensationIsTheThirdGateInput pins the third input of the
// consequence gate: the same irreversible action escalates without a compensating action
// and passes with one, when the ceiling admits its class.
func TestEffectCeiling_RequiresCompensationIsTheThirdGateInput(t *testing.T) {
	eng := effectEngine(&capability.EffectCeiling{MaxEffectClass: capability.EffectIrreversible, RequireCompensation: true})

	uncompensated := []capability.Constraint{{Target: "tool:wire", Actions: []string{"call"},
		Effect: &capability.EffectContract{Class: capability.EffectIrreversible}}}
	assert.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(context.Background(), effectReq("wire", nil), uncompensated).Decision,
		"an action at (not above) the class bound is not subject to the compensation leg")

	tighter := effectEngine(&capability.EffectCeiling{MaxEffectClass: capability.EffectCompensable, RequireCompensation: true})
	resp := tighter.ValidateAction(context.Background(), effectReq("wire", nil), uncompensated)
	require.Equal(t, capability.DecisionEscalate, resp.Decision)
	assert.Contains(t, resp.Denial.Details["ceiling_exceeded"], "no_compensating_action")
}

// TestEffectCeiling_RunsAfterConditionsAndBeforeTheStateCommit pins the ordering: an
// over-ceiling call is never forwarded, so it must leave no sequenceBlock antecedent
// behind for a later condition to read as "this already ran".
func TestEffectCeiling_RunsAfterConditionsAndBeforeTheStateCommit(t *testing.T) {
	eng := effectEngine(&capability.EffectCeiling{MaxEffectClass: capability.EffectReversible})
	caps := []capability.Constraint{
		{Target: "tool:read_secrets", Actions: []string{"call"},
			Effect: &capability.EffectContract{Class: capability.EffectIrreversible}},
		{Target: "tool:post", Actions: []string{"call"},
			Effect:     &capability.EffectContract{Class: capability.EffectReversible},
			Conditions: []capability.Condition{capability.SequenceBlockCondition{AfterTools: []string{"read_secrets"}}}},
	}

	escalated := eng.ValidateAction(context.Background(), effectReq("read_secrets", nil), caps)
	require.Equal(t, capability.DecisionEscalate, escalated.Decision)

	// read_secrets never ran, so the sequenceBlock antecedent must not have been recorded.
	after := eng.ValidateAction(context.Background(), effectReq("post", nil), caps)
	assert.Equal(t, capability.DecisionAllow, after.Decision,
		"an escalated call must not leave a phantom sequenceBlock antecedent")
}

// TestEffectConditionsFailClosedWithoutAResolvedContract pins that a direct caller of a
// handler with no resolved effect on the context is refused rather than judged against a
// guessed default.
func TestEffectConditionsFailClosedWithoutAResolvedContract(t *testing.T) {
	eng := effectEngine(nil)
	// EvaluateConditions goes through evaluateMatched, which resolves the contract — so
	// to reach the unresolved path the condition has to be evaluated with a bare context.
	// The public surface that does that is a custom handler registry lookup, which tests
	// cannot reach; instead assert the equivalent observable: a constraint whose contract
	// is absent resolves to the fail-closed default and is denied by a class gate.
	caps := []capability.Constraint{{
		Target:     "tool:act",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.EffectClassCondition{Allow: []string{capability.EffectReversible}}},
	}}
	resp := eng.EvaluateConditions(context.Background(), effectReq("act", nil), &caps[0])
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, false, resp.Denial.Details["annotated"])
}

// TestEffectCeilingSkippedWhenUnset pins that a policy with no ceiling pays nothing and
// changes nothing: every allow stays an allow, including for an unannotated target.
func TestEffectCeilingSkippedWhenUnset(t *testing.T) {
	caps := []capability.Constraint{{Target: "tool:anything", Actions: []string{"call"}}}
	resp := effectEngine(nil).ValidateAction(context.Background(), effectReq("anything", nil), caps)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}
