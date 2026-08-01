// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// DecideResourceCancel is the resources/unsubscribe authority question. It exists as its
// own entry point because routing a cancel through DecideResourceRead — the READ decision,
// which is a committing one — charged the cancellation for policy state it does not use:
// the URI's maxCalls quota, a sequenceBlock antecedent, and the entry's labelOutput taint.
// Once that quota was spent the cancel was itself denied, so a host could not stop a stream
// it had legitimately started. The tests below pin both halves: what a cancel still
// requires (a permitting manifest entry, a live session, the caller's principal scope) and
// what it must no longer consume.

const cancelSess = "cancel-sess-1"

// cancelURI is the resource both the read and the cancel name.
const cancelURI = "file:///data/live/metrics"

// newCancelPDP builds a ManifestPDP whose engine carries the stateful backends a
// metered decision would touch — a call counter (maxCalls, sequenceBlock history) and a
// flow-label store (labelOutput taint) — so a cancel that wrongly commits any of them is
// observable rather than silently absorbed by a nil backend.
func newCancelPDP(caps ...capability.Constraint) *ManifestPDP {
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
	return NewManifestPDP(caps, eng, killswitch.NewInMemory())
}

// TestDecideResourceCancel_SurvivesAnExhaustedQuota is the headline regression: a
// one-call budget spent by the subscribe must not leave the host unable to cancel.
func TestDecideResourceCancel_SurvivesAnExhaustedQuota(t *testing.T) {
	t.Parallel()

	p := newCancelPDP(capability.Constraint{
		Target:     "resource:file:///data/live/*",
		Actions:    []string{"read"},
		Conditions: []capability.Condition{capability.MaxCallsCondition{Count: 1, WindowSeconds: 3600}},
	})
	ctx := context.Background()

	// The subscribe spends the single slot.
	sub := p.DecideResourceRead(ctx, cancelSess, cancelURI, "")
	require.Equal(t, capability.DecisionAllow, sub.Decision, "the first read/subscribe must be allowed")

	// A second READ is correctly rate limited — the budget really is spent.
	second := p.DecideResourceRead(ctx, cancelSess, cancelURI, "")
	require.Equal(t, capability.DecisionDeny, second.Decision)
	require.NotNil(t, second.Denial)
	require.Equal(t, capability.ErrCodeRateLimited, second.Denial.Code)

	// The cancel must still be authorized: it moves no data, so a spent read budget is
	// not a reason to strand the subscription open.
	cancel := p.DecideResourceCancel(ctx, cancelSess, cancelURI, "")
	assert.Equal(t, capability.DecisionAllow, cancel.Decision,
		"an exhausted maxCalls budget must not deny the unsubscribe that closes the stream it opened")
	assert.Nil(t, cancel.Denial)
}

// A cancel must also not SPEND the budget: cancelling first must leave the resource's
// full quota available to the read that follows.
func TestDecideResourceCancel_ConsumesNoQuota(t *testing.T) {
	t.Parallel()

	p := newCancelPDP(capability.Constraint{
		Target:     "resource:file:///data/live/*",
		Actions:    []string{"read"},
		Conditions: []capability.Condition{capability.MaxCallsCondition{Count: 1, WindowSeconds: 3600}},
	})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.Equal(t, capability.DecisionAllow,
			p.DecideResourceCancel(ctx, cancelSess, cancelURI, "").Decision,
			"cancel %d must be allowed; a cancel evaluates no condition", i+1)
	}

	// The 1-call budget is untouched, so the read still gets its slot. (Asserted through
	// the decision rather than by reading the counter: the bucket key is an internal
	// composite of the engine's, and a test that rebuilt it would pass on a key the
	// engine no longer writes.)
	assert.Equal(t, capability.DecisionAllow, p.DecideResourceRead(ctx, cancelSess, cancelURI, "").Decision,
		"three cancels must not have spent the resource's single maxCalls slot")
}

// A cancel must record no sequenceBlock antecedent. sequenceBlock BLOCKS a target once
// its antecedent has run, so a cancel that recorded one would arm an exfiltration gate
// against a session that never read the resource at all.
func TestDecideResourceCancel_RecordsNoSequenceAntecedent(t *testing.T) {
	t.Parallel()

	// exfiltrate is blocked once the live-metrics resource has been READ. Naming the
	// resource in afterTools is also what puts a sequenceBlock in the policy at all,
	// which is what arms antecedent recording.
	p := newCancelPDP(
		capability.Constraint{Target: "resource:file:///data/live/*", Actions: []string{"read"}},
		capability.Constraint{
			Target:     "tool:exfiltrate",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.SequenceBlockCondition{AfterTools: []string{"resource:" + cancelURI}}},
		},
	)
	ctx := context.Background()
	sink := func() capability.EnforceResponse {
		return p.Decide(ctx, cancelSess, EnforceTarget{Type: capability.TargetTypeTool, Name: "exfiltrate"}, nil, "")
	}

	require.Equal(t, capability.DecisionAllow, p.DecideResourceCancel(ctx, cancelSess, cancelURI, "").Decision)
	assert.Equal(t, capability.DecisionAllow, sink().Decision,
		"a cancel must not record a sequenceBlock antecedent — the resource was never read")

	// The read DOES record it, so this pins the cancel's behavior rather than a
	// generally-dead antecedent path.
	require.Equal(t, capability.DecisionAllow, p.DecideResourceRead(ctx, cancelSess, cancelURI, "").Decision)
	blocked := sink()
	require.Equal(t, capability.DecisionDeny, blocked.Decision,
		"the read must still record the antecedent the cancel does not")
	require.NotNil(t, blocked.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, blocked.Denial.ConditionType)
}

// A cancel must apply no labelOutput taint: it returns no data, so tainting the session
// for it would deny an unrelated sink for a request that carried nothing.
func TestDecideResourceCancel_AppliesNoFlowTaint(t *testing.T) {
	t.Parallel()

	p := newCancelPDP(
		capability.Constraint{
			Target:     "resource:file:///data/live/*",
			Actions:    []string{"read"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
		},
		capability.Constraint{
			Target:     "tool:send_email",
			Actions:    []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic, capability.FlowLabelInternal}}},
		},
	)
	ctx := context.Background()

	cancel := p.DecideResourceCancel(ctx, cancelSess, cancelURI, "")
	require.Equal(t, capability.DecisionAllow, cancel.Decision)
	assert.Empty(t, cancel.LabelsOut, "a cancel transfers no data, so it emits no labels")

	sink := p.Decide(ctx, cancelSess, EnforceTarget{Type: capability.TargetTypeTool, Name: "send_email"}, nil, "")
	assert.Equal(t, capability.DecisionAllow, sink.Decision,
		"a cancel must not taint the session — the sink was never fed confidential data")

	// The read does taint, so the sink denial below proves the taint path is live and
	// the assertion above is about the cancel specifically.
	require.Equal(t, capability.DecisionAllow, p.DecideResourceRead(ctx, cancelSess, cancelURI, "").Decision)
	tainted := p.Decide(ctx, cancelSess, EnforceTarget{Type: capability.TargetTypeTool, Name: "send_email"}, nil, "")
	require.Equal(t, capability.DecisionDeny, tainted.Decision)
	require.NotNil(t, tainted.Denial)
	assert.Equal(t, capability.ConditionTypeFlowLabel, tainted.Denial.ConditionType)
}

// Dropping the metering does not drop the MATCH: a URI outside the manifest was never
// subscribable, so an unsubscribe naming it is a host talking about a channel it does not
// have, and is denied AUTHORIZATION_FAILED like every other unlisted target.
func TestDecideResourceCancel_DeniesUnlistedURI(t *testing.T) {
	t.Parallel()

	p := newCancelPDP(capability.Constraint{Target: "resource:file:///data/live/*", Actions: []string{"read"}})

	resp := p.DecideResourceCancel(context.Background(), cancelSess, "file:///etc/shadow", "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
}

// A name match whose actions do not include "read" gets the more precise
// CAPABILITY_DENIED ("listed, but not for this action"), the same distinction
// DecideResourceRead draws.
func TestDecideResourceCancel_DeniesNameMatchWithoutReadAction(t *testing.T) {
	t.Parallel()

	p := newCancelPDP(capability.Constraint{Target: "resource:file:///data/live/*", Actions: []string{"write"}})

	resp := p.DecideResourceCancel(context.Background(), cancelSess, cancelURI, "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeCapabilityDenied, resp.Denial.Code)
}

// The kill switch outranks everything: a revoked session gets KILL_SWITCH, not an allow.
// Cancelling reduces flow, but a killed session must not reach the upstream at all.
func TestDecideResourceCancel_KilledSessionDenied(t *testing.T) {
	t.Parallel()

	ks := killswitch.NewInMemory()
	p := NewManifestPDP(
		[]capability.Constraint{{Target: "resource:file:///data/live/*", Actions: []string{"read"}}},
		enforcement.New(), ks)
	require.NoError(t, ks.KillSession(context.Background(), cancelSess))

	resp := p.DecideResourceCancel(context.Background(), cancelSess, cancelURI, "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeKillSwitch, resp.Denial.Code)
}

// Principal scoping still applies: the entry that permits the resource is scoped to one
// agent, so another agent's cancel finds no entry at all.
func TestDecideResourceCancel_HonorsPrincipalScoping(t *testing.T) {
	t.Parallel()

	p := newCancelPDP(capability.Constraint{
		Target:    "resource:file:///data/live/*",
		Actions:   []string{"read"},
		Principal: map[string][]string{"agent_id": {"admin-bot"}},
	})

	allowed := p.DecideResourceCancel(ctxWithAgent("admin-bot"), cancelSess, cancelURI, "")
	assert.Equal(t, capability.DecisionAllow, allowed.Decision, "the scoped agent may cancel")

	denied := p.DecideResourceCancel(ctxWithAgent("other-bot"), cancelSess, cancelURI, "")
	require.Equal(t, capability.DecisionDeny, denied.Decision,
		"an agent the principal scope excludes holds no subscription to cancel")
	require.NotNil(t, denied.Denial)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, denied.Denial.Code)
}

// AlwaysAllowPDP (the --audit wiretap) allows every cancel, and DenyAllPDP (the
// no-policy fail-closed default) denies every one — the same postures they take for
// every other enforced method, so the new entry point cannot become a hole in either.
func TestDecideResourceCancel_WiretapAndNoPolicyPostures(t *testing.T) {
	t.Parallel()

	allow := AlwaysAllowPDP{}.DecideResourceCancel(context.Background(), cancelSess, cancelURI, "")
	assert.Equal(t, capability.DecisionAllow, allow.Decision, "a wiretap route allows every cancel")

	deny := DenyAllPDP{}.DecideResourceCancel(context.Background(), cancelSess, cancelURI, "")
	require.Equal(t, capability.DecisionDeny, deny.Decision, "a no-policy route denies every cancel")
	require.NotNil(t, deny.Denial)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, deny.Denial.Code)
}

// -----------------------------------------------------------------
// The JWT layer's own cancel decision
// -----------------------------------------------------------------

// The JWT wrapper does not route a cancel into Decide (which is the READ decision and
// therefore metered), but it must still apply everything a token can RESTRICT with. These
// pin that the separate path did not become a way around the token.

// A request with no validated claims is an authentication failure, not a policy one, and
// must HARD deny — a hard deny is the one verdict an --audit route may not downgrade to a
// logged forward.
func TestJWTPDP_DecideResourceCancel_NoClaims_HardDenied(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "cancel-noclaims")
	p, cleanup := makeJWTPDPWithInner(t, key, AlwaysAllowPDP{})
	defer cleanup()

	resp := p.DecideResourceCancel(context.Background(), cancelSess, cancelURI, "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeNoJWTClaims, resp.Denial.Code)
	assert.True(t, resp.Denial.HardDeny,
		"an unvalidated token must not be downgradable to a logged forward by an audit-mode route")
}

// An mcp.capabilities claim is an exhaustive allowlist, so a resource it does not name is
// not cancellable through that token either — the token can still only restrict.
func TestJWTPDP_DecideResourceCancel_ExhaustiveClaimsNarrowTheManifest(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "cancel-caps")
	inner := newCancelPDP(capability.Constraint{Target: "resource:file:///data/live/*", Actions: []string{"read"}})
	p, cleanup := makeJWTPDPWithInner(t, key, inner)
	defer cleanup()

	t.Run("claim omits the resource", func(t *testing.T) {
		ctx, err := p.ValidateToken(context.Background(), "Bearer "+makeJWTToken(t, key, []string{"tool:read_file"}))
		require.NoError(t, err)

		resp := p.DecideResourceCancel(ctx, cancelSess, cancelURI, "")
		require.Equal(t, capability.DecisionDeny, resp.Decision,
			"the manifest permits the resource, but this token does not name it")
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
	})

	t.Run("claim covers the resource", func(t *testing.T) {
		ctx, err := p.ValidateToken(context.Background(), "Bearer "+makeJWTToken(t, key, []string{"resource:file:///data/live/*"}))
		require.NoError(t, err)

		assert.Equal(t, capability.DecisionAllow, p.DecideResourceCancel(ctx, cancelSess, cancelURI, "").Decision,
			"a token naming the resource cancels through to the inner match-only decision")
	})
}

// An identity-only token on a route with no capability policy authenticates but does not
// authorize — the same fail-closed posture Decide takes, so the cancel path cannot become
// the one place an unpoliced JWT route forwards.
func TestJWTPDP_DecideResourceCancel_IdentityOnlyTokenUnpolicedRouteDenied(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "cancel-identity")
	p, cleanup := makeJWTPDPWithInner(t, key, nil)
	defer cleanup()

	ctx, err := p.ValidateToken(context.Background(), "Bearer "+makeJWTToken(t, key, nil))
	require.NoError(t, err)

	resp := p.DecideResourceCancel(ctx, cancelSess, cancelURI, "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
}
