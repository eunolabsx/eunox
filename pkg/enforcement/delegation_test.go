// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strs(v ...string) *[]string { return &v }

// delegatedReq is a request presented by a delegate at the end of the given chain.
func delegatedReq(session, name string, grants ...capability.DelegationGrant) *capability.EnforceRequest {
	r := req(session, name)
	actors := make([]string, len(grants))
	for i := range grants {
		actors[i] = grants[i].Subject
	}
	r.Delegation = &capability.DelegationChain{Actors: actors, Grants: grants}
	return r
}

// TestDelegation_TargetOutsideTheGrantDenies is the authority axis: the manifest permits the
// tool and no condition refuses it, and the call is still one this delegate was never handed.
func TestDelegation_TargetOutsideTheGrantDenies(t *testing.T) {
	eng := declassifyEngine()
	caps := []capability.Constraint{{Target: "tool:*", Actions: []string{"call"}}}
	ctx := context.Background()

	allowed := eng.ValidateAction(ctx,
		delegatedReq("s", "read_file", capability.DelegationGrant{Subject: "agent-a", Targets: strs("tool:read_file")}), caps)
	require.Equal(t, capability.DecisionAllow, allowed.Decision)

	denied := eng.ValidateAction(ctx,
		delegatedReq("s", "write_file", capability.DelegationGrant{Subject: "agent-a", Targets: strs("tool:read_file")}), caps)
	require.Equal(t, capability.DecisionDeny, denied.Decision)
	require.NotNil(t, denied.Denial)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, denied.Denial.Code)
	assert.Equal(t, "delegation", denied.Denial.ConditionType)
	assert.Equal(t, true, denied.Denial.Details["delegation"])
	assert.Equal(t, "target_not_delegated", denied.Denial.Details["reason"])
	assert.Equal(t, "agent-a", denied.Denial.Details["delegate"], "the refusal must name the hop that blocked it")
}

// TestDelegation_EveryHopApplies pins that the decision path applies EVERY hop rather than
// only the most attenuated one, so the enforcement does not rest on the monotonicity
// assertion being right.
func TestDelegation_EveryHopApplies(t *testing.T) {
	eng := declassifyEngine()
	caps := []capability.Constraint{{Target: "tool:*", Actions: []string{"call"}}}

	// A hand-built chain whose second hop is BROADER than its first — the shape
	// ValidateDelegationChain refuses at the token boundary. Even so, hop 1 must still bind.
	widening := delegatedReq("s", "write_file",
		capability.DelegationGrant{Subject: "agent-a", Targets: strs("tool:read_file")},
		capability.DelegationGrant{Subject: "agent-b", Targets: strs("tool:read_file", "tool:write_file")},
	)
	resp := eng.ValidateAction(context.Background(), widening, caps)
	assert.Equal(t, capability.DecisionDeny, resp.Decision, "a later hop must not be able to reach past an earlier one")
	assert.Equal(t, "agent-a", resp.Denial.Details["delegate"])
}

// TestDelegation_EmptyTargetsIsDenyAll covers the absent/present-empty distinction: an omitted
// targets list restricts nothing, while a present-empty one reaches nothing.
func TestDelegation_EmptyTargetsIsDenyAll(t *testing.T) {
	eng := declassifyEngine()
	caps := []capability.Constraint{{Target: "tool:*", Actions: []string{"call"}}}
	ctx := context.Background()

	unrestricted := eng.ValidateAction(ctx, delegatedReq("s", "read_file", capability.DelegationGrant{Subject: "agent-a"}), caps)
	assert.Equal(t, capability.DecisionAllow, unrestricted.Decision, "an omitted targets list narrows nothing")

	denyAll := eng.ValidateAction(ctx,
		delegatedReq("s", "read_file", capability.DelegationGrant{Subject: "agent-a", Targets: strs()}), caps)
	assert.Equal(t, capability.DecisionDeny, denyAll.Decision, "a present-empty targets list reaches nothing")
}

// TestDelegation_ForcedLabelsTaintTheDelegatesCalls is the quarantine's taint half: the
// sub-agent's calls carry `untrusted` because its delegator decided so, whatever the tool says
// and whatever the agent would prefer.
func TestDelegation_ForcedLabelsTaintTheDelegatesCalls(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	// A clean anchor. Without the chain, this sink allows.
	clean := eng.ValidateAction(ctx, req("s", "publish"), sinkCaps("publish", capability.FlowLabelPublic))
	require.Equal(t, capability.DecisionAllow, clean.Decision)

	quarantined := delegatedReq("s", "publish",
		capability.DelegationGrant{Subject: "scraper", Labels: []string{capability.FlowLabelUntrusted}})
	resp := eng.ValidateAction(ctx, quarantined, sinkCaps("publish", capability.FlowLabelPublic))
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, []string{capability.FlowLabelUntrusted}, resp.Denial.Details["blockedLabels"])
	assert.Equal(t, []string{capability.FlowLabelUntrusted}, resp.Denial.Details["delegated_labels"],
		"the tape must distinguish taint the chain imposed from taint the proxy observed")
}

// TestDelegation_AllowLabelCapQuarantinesEveryLabeledSink is the full quarantine: a sub-agent
// sharing a tainted task reaches NO sink, however it is injected — because its hop capped the
// sink allow-set to empty, and the intersection of anything with empty is empty.
func TestDelegation_AllowLabelCapQuarantinesEveryLabeledSink(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	// The task is tainted by a legitimate source read.
	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_customer"), sourceCaps("read_customer", capability.FlowLabelPII)).Decision)

	// A sink that explicitly permits pii: without the chain the delegate reaches it.
	permissive := sinkCaps("publish", capability.FlowLabelPII)
	require.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, req("s", "publish"), permissive).Decision)

	quarantined := delegatedReq("s", "publish",
		capability.DelegationGrant{Subject: "sub-agent", AllowLabels: strs()})
	resp := eng.ValidateAction(ctx, quarantined, permissive)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, []string{}, resp.Denial.Details["allowLabels"],
		"the recorded allow-set must be the EFFECTIVE one, not the manifest's — the manifest's was never what refused the call")
}

// TestDelegation_RedactFieldsCompose covers the directive-composition axis: a hop's
// redactFields is applied on top of the constraint's own, including on a constraint that
// declares none.
func TestDelegation_RedactFieldsCompose(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()

	caps := []capability.Constraint{{
		Target:     "tool:read_customer",
		Actions:    []string{"call"},
		Directives: []capability.Directive{capability.RedactFieldsDirective{Fields: []string{"email"}}},
	}}
	resp := eng.ValidateAction(ctx,
		delegatedReq("s", "read_customer", capability.DelegationGrant{Subject: "agent-a", RedactFields: []string{"ssn"}}), caps)
	require.Equal(t, capability.DecisionAllow, resp.Decision)

	var paths []string
	for _, ob := range resp.Obligations {
		require.Equal(t, capability.DirectiveTypeRedactFields, ob.Type)
		paths = append(paths, ob.Paths...)
	}
	assert.ElementsMatch(t, []string{"ssn", "email"}, paths, "the delegate must see at least as much redacted as its delegator")

	// A constraint with no directives of its own still gets the chain's redaction.
	bare := []capability.Constraint{{Target: "tool:read_customer", Actions: []string{"call"}}}
	resp = eng.ValidateAction(ctx,
		delegatedReq("s", "read_customer", capability.DelegationGrant{Subject: "agent-a", RedactFields: []string{"ssn"}}), bare)
	require.Equal(t, capability.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 1)
	assert.Equal(t, []string{"ssn"}, resp.Obligations[0].Paths)
}

// TestDelegation_EffectClassCapDenies covers the consequence axis, and that it DENIES rather
// than escalating: no human is in a position to grant, at this point in the call, authority
// the delegator itself chose not to pass on.
func TestDelegation_EffectClassCapDenies(t *testing.T) {
	eng := declassifyEngine()
	caps := []capability.Constraint{{
		Target:  "tool:delete_everything",
		Actions: []string{"call"},
		Effect:  &capability.EffectContract{Class: capability.EffectIrreversible},
	}}
	resp := eng.ValidateAction(context.Background(),
		delegatedReq("s", "delete_everything",
			capability.DelegationGrant{Subject: "agent-a", MaxEffectClass: capability.EffectReversible}), caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, "effect_class", resp.Denial.Details["reason"])
	assert.Equal(t, capability.EffectIrreversible, resp.Denial.Details["effect_class"])
	assert.Equal(t, capability.EffectReversible, resp.Denial.Details["delegated_max_effect_class"])
}

// TestDelegation_RefusalLeavesNoState pins the ordering the whole file depends on: a call
// refused for exceeding its delegation spends no quota, so a delegate cannot drain its own
// (or its task's) budget by making calls it was never allowed to make.
func TestDelegation_RefusalLeavesNoState(t *testing.T) {
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
	caps := []capability.Constraint{{
		Target:     "tool:refund",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.MaxCallsCondition{Count: 1, WindowSeconds: 3600}},
	}}
	ctx := context.Background()

	refused := eng.ValidateAction(ctx,
		delegatedReq("s", "refund", capability.DelegationGrant{Subject: "agent-a", Targets: strs("tool:read_file")}), caps)
	require.Equal(t, capability.DecisionDeny, refused.Decision)

	// The undelegated caller's own quota is untouched.
	assert.Equal(t, capability.DecisionAllow, eng.ValidateAction(ctx, req("s", "refund"), caps).Decision)
}

// TestDelegation_NoChainChangesNothing is the "costs a nil check" property: nearly every token
// carries no chain, and those requests must behave exactly as they did.
func TestDelegation_NoChainChangesNothing(t *testing.T) {
	eng := declassifyEngine()
	caps := []capability.Constraint{{
		Target:     "tool:read_customer",
		Actions:    []string{"call"},
		Directives: []capability.Directive{capability.RedactFieldsDirective{Fields: []string{"email"}}},
	}}
	resp := eng.ValidateAction(context.Background(), req("s", "read_customer"), caps)
	require.Equal(t, capability.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 1)
	assert.Equal(t, []string{"email"}, resp.Obligations[0].Paths)
}

// TestDelegation_UnknownForcedLabelDeniesRatherThanNormalizingAway is the fail-open this
// closes.
//
// A forced label is the delegators' DECISION about what this delegate is, not a cooperating
// client's voluntary attribution — and the two were run through the same normalizer, which
// drops anything outside the vocabulary. Dropping a voluntary declaration is safe (an unknown
// label there could only ever have added denials). Dropping a FORCED one removes taint, so a
// sink that should have refused the delegate's call allows it.
//
// Both token-boundary entry points refuse such a grant — ParseDelegationGrants as it decodes
// the claim, ValidateDelegationChain as it assembles the chain — so this fires only for an
// embedder that reached the engine through neither, which is exactly the population a silent
// normalization leaves unprotected, and the reason the sibling checks in this package surface
// against the RAW authored values too.
func TestDelegation_UnknownForcedLabelDeniesRatherThanNormalizingAway(t *testing.T) {
	eng := declassifyEngine()
	ctx := context.Background()
	// A sink that permits only public-provenance flows. Nothing has tainted the session, so it
	// is the forced label — and only the forced label — that decides.
	caps := []capability.Constraint{{
		Target:     "tool:*",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}},
	}}

	t.Run("a known forced label still denies on its own merits", func(t *testing.T) {
		resp := eng.ValidateAction(ctx, delegatedReq("s", "publish",
			capability.DelegationGrant{Subject: "agent-a", Labels: []string{capability.FlowLabelUntrusted}}), caps)
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	})

	t.Run("an unknown forced label denies rather than being dropped", func(t *testing.T) {
		resp := eng.ValidateAction(ctx, delegatedReq("s", "publish",
			capability.DelegationGrant{Subject: "agent-a", Labels: []string{"quarantined"}}), caps)
		require.Equal(t, capability.DecisionDeny, resp.Decision, "normalizing the label away lets the call through as untainted")
		require.NotNil(t, resp.Denial)
		// The FAULT code, not a policy verdict: the chain is malformed, so there is no verdict
		// an observing route may downgrade into a forward.
		assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
		assert.False(t, resp.Denial.Downgradable())
		assert.Contains(t, resp.Denial.Message, "quarantined", "the refusal must name the label it could not honor")
	})

	t.Run("the token boundary refuses the same grant outright", func(t *testing.T) {
		// Both halves of the boundary, because a caller may reach either: ParseDelegationGrants
		// asserts the grant as it decodes the claim, and ValidateDelegationChain re-asserts it
		// for a chain assembled any other way. That is what makes the decision-path check above
		// a backstop rather than the only check — it fires for an embedder that skips both.
		_, err := capability.ParseDelegationGrants([]byte(`[{"subject":"agent-a","labels":["quarantined"]}]`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "quarantined")

		_, err = capability.ValidateDelegationChain(nil, []capability.DelegationGrant{
			{Subject: "agent-a", Labels: []string{"quarantined"}},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "quarantined")
	})
}
