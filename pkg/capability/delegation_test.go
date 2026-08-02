// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"encoding/json"
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
		"glob target":      {`[{"subject":"a","targets":["tool:read_*"]}]`, "glob metacharacter"},
		"unknown label":    {`[{"subject":"a","labels":["secret-ish"]}]`, "unknown flow label"},
		"unknown allow":    {`[{"subject":"a","allowLabels":["nope"]}]`, "unknown flow label"},
		"bad class":        {`[{"subject":"a","maxEffectClass":"safe"}]`, "maxEffectClass"},
		"empty redact":     {`[{"subject":"a","redactFields":["  "]}]`, "redactFields"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := capability.ParseDelegationGrants(json.RawMessage(tc.raw))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
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
// one case per axis. Each axis narrows in its OWN direction, so a single "is a subset" test
// would be wrong for three of the five.
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
		"drops taint its delegator carries": {
			capability.DelegationGrant{Subject: "a", Labels: []string{capability.FlowLabelUntrusted}},
			capability.DelegationGrant{Subject: "b"},
			"drops flow label",
		},
		"admits taint at a sink its delegator cannot": {
			capability.DelegationGrant{Subject: "a", AllowLabels: list(capability.FlowLabelPublic)},
			capability.DelegationGrant{Subject: "b", AllowLabels: list(capability.FlowLabelPublic, capability.FlowLabelPII)},
			"admits flow label",
		},
		"unmasks a field its delegator redacts": {
			capability.DelegationGrant{Subject: "a", RedactFields: []string{"ssn"}},
			capability.DelegationGrant{Subject: "b"},
			"unmasks field",
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
