// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func list(v ...string) *[]string { return &v }

// TestParseActorChain_ReversesRFC8693Nesting pins the ordering conversion. RFC 8693 §4.1
// nests the chain most-recent-actor-outermost; every comparison in this package reads it
// delegator-first, and getting the direction backwards would compare each hop against its own
// delegate and report every correct chain as a widening.
func TestParseActorChain_ReversesRFC8693Nesting(t *testing.T) {
	raw := json.RawMessage(`{"sub":"agent-c","act":{"sub":"agent-b","act":{"sub":"agent-a"}}}`)
	actors, err := capability.ParseActorChain(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{"agent-a", "agent-b", "agent-c"}, actors)
}

func TestParseActorChain_RejectsMalformed(t *testing.T) {
	for name, raw := range map[string]string{
		"no sub":        `{"act":{"sub":"b"}}`,
		"blank sub":     `{"sub":"   "}`,
		"not an object": `"agent-a"`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := capability.ParseActorChain(json.RawMessage(raw))
			assert.Error(t, err, "a chain this build cannot read is a token making a claim it cannot honor")
		})
	}
}

func TestParseActorChain_AbsentIsNotAnError(t *testing.T) {
	actors, err := capability.ParseActorChain(nil)
	require.NoError(t, err)
	assert.Empty(t, actors)

	actors, err = capability.ParseActorChain(json.RawMessage(`null`))
	require.NoError(t, err)
	assert.Empty(t, actors)
}

// TestParseActorChain_DepthCapped bounds attacker-influenced input the decision path walks
// once per enforced call.
func TestParseActorChain_DepthCapped(t *testing.T) {
	raw := `{"sub":"a"}`
	for i := 0; i < capability.MaxDelegationDepth+1; i++ {
		raw = `{"sub":"a","act":` + raw + `}`
	}
	_, err := capability.ParseActorChain(json.RawMessage(raw))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unbounded delegation chain")
}

func TestParseDelegationGrants_RejectsUnknownFieldAndBadValues(t *testing.T) {
	for name, tc := range map[string]struct{ raw, want string }{
		"misspelled field": {`[{"subject":"a","targts":["tool:x"]}]`, "unknown"},
		"no subject":       {`[{"targets":["tool:x"]}]`, "subject"},
		"star target":      {`[{"subject":"a","targets":["tool:read_*"]}]`, "contains '*'"},
		"unknown label":    {`[{"subject":"a","labels":["secret-ish"]}]`, "unknown flow label"},
		"unknown allow":    {`[{"subject":"a","allowLabels":["nope"]}]`, "unknown flow label"},
		"bad class":        {`[{"subject":"a","maxEffectClass":"safe"}]`, "maxEffectClass"},
		"empty redact":     {`[{"subject":"a","redactFields":["  "]}]`, "redactFields"},
		// '?' and '[' are ordinary characters in a resource URI, and delegated targets are
		// matched literally, so refusing them made an entire class of target unexpressible —
		// and because a malformed grant rejects the TOKEN, one such entry refused every
		// request the caller made.
		"unknown act field": {`[{"subject":"a","bogus":1}]`, "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := capability.ParseDelegationGrants(json.RawMessage(tc.raw))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestParseDelegationGrants_AcceptsLiteralURIMetacharacters pins that only '*' is refused.
// Delegated targets are matched literally, so nothing else can widen a grant — and refusing
// the whole glob-metacharacter set made a resource URI with a query string unexpressible,
// which (since a malformed grant rejects the token) refused every request the caller made.
func TestParseDelegationGrants_AcceptsLiteralURIMetacharacters(t *testing.T) {
	grants, err := capability.ParseDelegationGrants(json.RawMessage(
		`[{"subject":"a","targets":["resource:https://api.example.com/search?q=x","resource:file:///c[1]/x"]}]`))
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.NotNil(t, grants[0].Targets)
	assert.Len(t, *grants[0].Targets, 2)
}

// TestParseActorChain_RejectsUnknownField keeps a misspelled "acts" from silently truncating
// the chain: with an act-only token nothing downstream would detect it, because the hop-for-hop
// agreement check is skipped when there are no grants.
func TestParseActorChain_RejectsUnknownField(t *testing.T) {
	_, err := capability.ParseActorChain(json.RawMessage(`{"sub":"b","acts":{"sub":"a"}}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

// TestValidateDelegationChain_AccumulatesTheFloor is the assertion an adjacent-pairs comparison
// could not make: an intervening hop that omits an axis must not erase the constraint an
// earlier hop placed on it.
func TestValidateDelegationChain_AccumulatesTheFloor(t *testing.T) {
	_, err := capability.ValidateDelegationChain(nil, []capability.DelegationGrant{
		{Subject: "a", Targets: list("tool:x")},
		{Subject: "b"},
		{Subject: "c", Targets: list("tool:x", "tool:wipe_db")},
	})
	require.Error(t, err, "hop c declares authority hop a never held; the omitted middle hop must not launder it")
	assert.Contains(t, err.Error(), "does not hold")

	// The same shape that genuinely narrows still passes.
	_, err = capability.ValidateDelegationChain(nil, []capability.DelegationGrant{
		{Subject: "a", Targets: list("tool:x", "tool:y")},
		{Subject: "b"},
		{Subject: "c", Targets: list("tool:x")},
	})
	assert.NoError(t, err)
}

// TestParseDelegationGrants_PreservesPresentEmpty is the load-bearing decode property: a
// present-empty targets list is the deny-all grant a quarantine mints, and collapsing it to
// "absent" would turn the strictest grant expressible into no grant at all.
func TestParseDelegationGrants_PreservesPresentEmpty(t *testing.T) {
	grants, err := capability.ParseDelegationGrants(json.RawMessage(`[{"subject":"a","targets":[],"allowLabels":[]}]`))
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.NotNil(t, grants[0].Targets)
	assert.Empty(t, *grants[0].Targets)
	require.NotNil(t, grants[0].AllowLabels)
	assert.Empty(t, *grants[0].AllowLabels)
}

// TestValidateDelegationChain_RefusesEveryWideningDirection is the monotonicity assertion,
// one case per ASSERTED axis. Each narrows in its OWN direction, so a single "is a subset" test
// would be wrong for one of the three.
func TestValidateDelegationChain_RefusesEveryWideningDirection(t *testing.T) {
	for name, tc := range map[string]struct {
		prior, next capability.DelegationGrant
		want        string
	}{
		"reaches a target its delegator lacks": {
			capability.DelegationGrant{Subject: "a", Targets: list("tool:read")},
			capability.DelegationGrant{Subject: "b", Targets: list("tool:read", "tool:write")},
			"does not hold",
		},
		"admits taint at a sink its delegator cannot": {
			capability.DelegationGrant{Subject: "a", AllowLabels: list(capability.FlowLabelPublic)},
			capability.DelegationGrant{Subject: "b", AllowLabels: list(capability.FlowLabelPublic, capability.FlowLabelPII)},
			"admits flow label",
		},
		"caps effect class above its delegator": {
			capability.DelegationGrant{Subject: "a", MaxEffectClass: capability.EffectReversible},
			capability.DelegationGrant{Subject: "b", MaxEffectClass: capability.EffectIrreversible},
			"above its delegator",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := capability.ValidateDelegationChain(nil, []capability.DelegationGrant{tc.prior, tc.next})
			require.Error(t, err, "a widening hop must reject the token, not be clamped")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestValidateDelegationChain_UnionAxesAreNotAsserted pins the other half of the split: a hop
// that names none of its delegator's labels or redactions is ACCEPTED, because the decision path
// unions both across every hop and so the delegate carries them anyway. Rejecting the shape
// demanded that every hop restate every ancestor's values, and the whole TOKEN was denied when
// one did not — a monotonicity check denying a monotone chain.
func TestValidateDelegationChain_UnionAxesAreNotAsserted(t *testing.T) {
	chain, err := capability.ValidateDelegationChain(nil, []capability.DelegationGrant{
		{Subject: "a", Labels: []string{capability.FlowLabelUntrusted}, RedactFields: []string{"ssn"}},
		{Subject: "b", Labels: []string{capability.FlowLabelPII}, RedactFields: []string{"dob"}},
		{Subject: "c"},
	})
	require.NoError(t, err)
	require.NotNil(t, chain)
	// Both hops' declarations survive to the decision path, so nothing hop c omitted was lost.
	assert.ElementsMatch(t, []string{capability.FlowLabelUntrusted, capability.FlowLabelPII}, chain.ForcedLabels())
	assert.Equal(t, []string{"dob", "ssn"}, chain.RedactFields())
}

// TestValidateDelegationChain_AcceptsNarrowing is the positive case for every axis at once.
func TestValidateDelegationChain_AcceptsNarrowing(t *testing.T) {
	chain, err := capability.ValidateDelegationChain(
		[]string{"agent-a", "agent-b"},
		[]capability.DelegationGrant{
			{Subject: "agent-a", Targets: list("tool:read", "tool:write"), AllowLabels: list(capability.FlowLabelPublic, capability.FlowLabelPII), RedactFields: []string{"ssn"}, MaxEffectClass: capability.EffectCompensable},
			{Subject: "agent-b", Targets: list("tool:read"), Labels: []string{capability.FlowLabelUntrusted}, AllowLabels: list(capability.FlowLabelPublic), RedactFields: []string{"ssn", "email"}, MaxEffectClass: capability.EffectReversible},
		})
	require.NoError(t, err)
	require.NotNil(t, chain)
	assert.Equal(t, "agent-b", chain.Delegate())

	ok, _ := chain.PermitsTarget("tool:read")
	assert.True(t, ok)
	ok, blocked := chain.PermitsTarget("tool:write")
	assert.False(t, ok, "the delegate narrowed away tool:write even though its delegator holds it")
	assert.Equal(t, "agent-b", blocked)

	assert.Equal(t, []string{capability.FlowLabelUntrusted}, chain.ForcedLabels())
	allowed, capped := chain.AllowedLabelCap()
	assert.True(t, capped)
	assert.Equal(t, []string{capability.FlowLabelPublic}, allowed)
	assert.Equal(t, []string{"email", "ssn"}, chain.RedactFields())
	class, subject, hasCap := chain.EffectClassCap()
	assert.True(t, hasCap)
	assert.Equal(t, capability.EffectReversible, class)
	assert.Equal(t, "agent-b", subject)
}

// TestValidateDelegationChain_ActorsAndGrantsMustAgree refuses a token whose two halves
// describe different delegations; picking either would be guessing which one was meant.
func TestValidateDelegationChain_ActorsAndGrantsMustAgree(t *testing.T) {
	_, err := capability.ValidateDelegationChain([]string{"a", "b"}, []capability.DelegationGrant{{Subject: "a"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hop for hop")

	_, err = capability.ValidateDelegationChain([]string{"a", "b"}, []capability.DelegationGrant{{Subject: "a"}, {Subject: "z"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain names")
}

// TestValidateDelegationChain_ReassertsGrantsDepthCap pins a defense-in-depth gap:
// ValidateDelegationChain re-asserts the actors cap independently of
// ParseActorChain's own, but did not do the same for grants. ParseDelegationGrants already
// caps a real token's claim before it reaches here, but ValidateDelegationChain is itself
// an exported boundary a caller can reach directly with a pre-built []DelegationGrant (no
// actors at all, so the hop-agreement check that would otherwise compare lengths never
// runs) — the narrowing loop below must not walk an unbounded slice before either cap
// fires.
func TestValidateDelegationChain_ReassertsGrantsDepthCap(t *testing.T) {
	grants := make([]capability.DelegationGrant, capability.MaxDelegationDepth+1)
	for i := range grants {
		grants[i] = capability.DelegationGrant{Subject: fmt.Sprintf("hop-%d", i)}
	}
	_, err := capability.ValidateDelegationChain(nil, grants)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than the maximum")
}

// TestValidateDelegationChain_PresentEmptyGrantsDisagreeWithActors is the mis-mint most likely
// to come out of an IdP template: the act chain is right and the grant array came out empty.
// Zero hops beside two actors is a disagreement like any other, and collapsing present-empty
// into absent made it the one that passed silently — leaving the operator believing an
// attenuation is in force that the token does not carry.
func TestValidateDelegationChain_PresentEmptyGrantsDisagreeWithActors(t *testing.T) {
	grants, err := capability.ParseDelegationGrants(json.RawMessage(`[]`))
	require.NoError(t, err)
	require.NotNil(t, grants, "a present-empty claim must stay distinguishable from an absent one")

	_, err = capability.ValidateDelegationChain([]string{"a", "b"}, grants)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hop for hop")

	// The genuinely act-only token — no delegation claim at all — is still well-formed: it
	// carries the chain's identities and states no narrowing.
	absent, err := capability.ParseDelegationGrants(nil)
	require.NoError(t, err)
	require.Nil(t, absent)
	chain, err := capability.ValidateDelegationChain([]string{"a", "b"}, absent)
	require.NoError(t, err)
	require.NotNil(t, chain)
	assert.Equal(t, "b", chain.Delegate())
}

// TestValidateDelegationChain_EmptyIsNoChain keeps the common path free: no act, no grants, no
// chain object at all.
func TestValidateDelegationChain_EmptyIsNoChain(t *testing.T) {
	chain, err := capability.ValidateDelegationChain(nil, nil)
	require.NoError(t, err)
	assert.Nil(t, chain)
	assert.True(t, chain.IsEmpty())

	// Every accessor is nil-safe, because the decision path calls them on a nil chain for
	// nearly every request in a deployment that never mints one.
	ok, _ := chain.PermitsTarget("tool:anything")
	assert.True(t, ok)
	assert.Nil(t, chain.ForcedLabels())
	assert.Nil(t, chain.RedactFields())
	_, capped := chain.AllowedLabelCap()
	assert.False(t, capped)
	_, _, hasCap := chain.EffectClassCap()
	assert.False(t, hasCap)
	assert.Empty(t, chain.Delegate())
}

// TestDelegationChain_AllowLabelCapIntersectsAcrossHops covers composition rather than
// last-hop-wins: two hops each capping the sink allow-set compose to their intersection.
func TestDelegationChain_AllowLabelCapIntersectsAcrossHops(t *testing.T) {
	chain := &capability.DelegationChain{Grants: []capability.DelegationGrant{
		{Subject: "a", AllowLabels: list(capability.FlowLabelPublic, capability.FlowLabelPII)},
		{Subject: "b", AllowLabels: list(capability.FlowLabelPublic)},
	}}
	allowed, capped := chain.AllowedLabelCap()
	require.True(t, capped)
	assert.Equal(t, []string{capability.FlowLabelPublic}, allowed)
}

// TestDelegationGrant_LabelCountIsBounded pins the per-hop label bound. MaxDelegationDepth
// bounds the hops on the argument that the chain is attacker-influenced input the decision
// path walks once per enforced call; once a label may be an operator-open "namespace:value"
// rather than one of five closed classes, each hop's own label lists need the same treatment
// or the per-call work is unbounded again one level down. See MaxExternalFlowLabels.
func TestDelegationGrant_LabelCountIsBounded(t *testing.T) {
	labels := func(n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("purview:c-%d", i))
		}
		return out
	}

	atBound := capability.DelegationGrant{Subject: "agent", Labels: labels(capability.MaxExternalFlowLabels)}
	assert.NoError(t, atBound.Validate(), "a hop exactly at the bound is admitted")

	over := capability.DelegationGrant{Subject: "agent", Labels: labels(capability.MaxExternalFlowLabels + 1)}
	err := over.Validate()
	require.Error(t, err, "one over the bound is refused at the token boundary")
	assert.Contains(t, err.Error(), "more than the maximum")

	// The allow-cap takes the same bound: it is intersected per call the same way.
	allowCap := labels(capability.MaxExternalFlowLabels + 1)
	overCap := capability.DelegationGrant{Subject: "agent", AllowLabels: &allowCap}
	err = overCap.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowLabels")
}
