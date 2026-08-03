// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// The harden path applied a delegation chain to its OBLIGATIONS and not to its VERDICT: the
// forwarded response was masked by the chain's composed redactFields while the refusal itself
// was taken as if the caller held no delegation at all. Not an authority hole — the call was
// refused either way — but the tape carried the wrapping layer's generic authorization failure
// instead of the axis and the hop, so no delegation filter found the event.

// cappedDelegationCtx returns a context carrying a validated token whose single hop caps the
// effect class at `class` — the shape a control plane mints for a sub-agent it wants unable to
// cause anything more consequential than that.
func cappedDelegationCtx(class string) context.Context {
	return WithJWTClaims(context.Background(), &JWTClaims{
		Subject: "user@example.com",
		Delegation: &capability.DelegationChain{
			Actors: []string{"agent-a", "agent-b"},
			Grants: []capability.DelegationGrant{{Subject: "agent-b", MaxEffectClass: class}},
		},
	})
}

// delegatedEffectPDP permits one irreversible tool with no ceiling of its own, so the ONLY
// bound on the call's effect class is whatever the chain declares.
func delegatedEffectPDP() *ManifestPDP {
	return NewManifestPDP(
		[]capability.Constraint{{
			Target:  "tool:wire_transfer",
			Actions: []string{"call"},
			Effect:  &capability.EffectContract{Class: capability.EffectIrreversible},
		}},
		enforcement.New(),
		nil,
	)
}

// softRefusal is the downgradable AUTHORIZATION_FAILED a wrapping layer (the JWT PDP) produces
// when it short-circuits above the inner PDP.
func softRefusal() capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    capability.ErrCodeAuthorizationFailed,
			Message: "tool \"wire_transfer\" is not in the JWT capability claims",
		},
	}
}

// The regression: a delegated caller over its hop's cap must be refused ON THAT AXIS, naming
// the hop, rather than under the wrapping layer's generic verdict.
func TestHardenRefusal_ComposesTheDelegatedEffectClassCap(t *testing.T) {
	t.Parallel()
	p := delegatedEffectPDP()
	target := EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}

	// Control: the full path refuses this call on the delegation axis, so the composed one
	// must reach the same statement rather than a weaker one.
	ctrl := p.Decide(cappedDelegationCtx(capability.EffectReversible), "s", target, nil, "")
	if ctrl.Decision == capability.DecisionAllow {
		t.Fatalf("control: the full path must refuse an over-cap delegated call, got %+v", ctrl)
	}

	hardened := p.HardenRefusal(cappedDelegationCtx(capability.EffectReversible), "s", softRefusal(), target, nil)
	if hardened.Denial == nil {
		t.Fatal("the composed response dropped the refusal entirely")
	}
	if hardened.Denial.ConditionType != "delegation" {
		t.Fatalf("condition_type = %q, want delegation: the record must name the axis that refused the call, got %+v",
			hardened.Denial.ConditionType, hardened.Denial)
	}
	if got := hardened.Denial.Details["delegate"]; got != "agent-b" {
		t.Fatalf("details.delegate = %v, want agent-b: a multi-hop chain's refusal is only actionable when it names the hop", got)
	}
	if got := hardened.Denial.Details["reason"]; got != "effect_class" {
		t.Fatalf("details.reason = %v, want effect_class", got)
	}
	if got := hardened.Denial.Details["delegation"]; got != true {
		t.Fatalf("details.delegation = %v, want true: it is the discriminator every attenuation event carries", got)
	}
	// The wrapping layer's own reason survives in the message, so an operator fixing the
	// token still sees why authorization failed.
	if hardened.Denial.Message == "" {
		t.Fatal("the composed refusal carries no message")
	}
}

// A chain whose cap ADMITS the action contributes nothing: the seam only ever speaks for a
// bound that would actually have refused.
func TestHardenRefusal_DelegationCapWithinBoundLeavesTheVerdictAlone(t *testing.T) {
	t.Parallel()
	p := delegatedEffectPDP()
	target := EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}

	hardened := p.HardenRefusal(cappedDelegationCtx(capability.EffectIrreversible), "s", softRefusal(), target, nil)
	if hardened.Denial == nil || hardened.Denial.Code != capability.ErrCodeAuthorizationFailed {
		t.Fatalf("an in-bounds cap must leave the wrapping layer's verdict untouched, got %+v", hardened.Denial)
	}
}

// An undelegated refusal takes the same path and must be unchanged — the overwhelmingly common
// case, and the one where a new leg would be noticed only as a regression.
func TestHardenRefusal_UndelegatedRefusalUnchanged(t *testing.T) {
	t.Parallel()
	p := delegatedEffectPDP()
	target := EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}

	hardened := p.HardenRefusal(context.Background(), "s", softRefusal(), target, nil)
	if hardened.Denial == nil || hardened.Denial.Code != capability.ErrCodeAuthorizationFailed {
		t.Fatalf("an undelegated refusal must pass through, got %+v", hardened.Denial)
	}
}

// The composed delegation verdict must never preempt a HARDER one. The declassify escalation
// and the ceiling escalation are both hard and both run ahead of this leg, which inverts the
// full path's order deliberately: a harden-only seam may not replace a hard refusal with the
// downgradable one a delegation bound produces.
func TestHardenRefusal_DelegationCapDoesNotPreemptTheEscalation(t *testing.T) {
	t.Parallel()
	ceiling := &capability.EffectCeiling{
		MaxEffectClass: capability.EffectReversible,
		OnExceed:       capability.OnExceedEscalate,
	}
	p := NewManifestPDP(
		[]capability.Constraint{{
			Target:  "tool:wire_transfer",
			Actions: []string{"call"},
			Effect:  &capability.EffectContract{Class: capability.EffectIrreversible},
		}},
		enforcement.New(enforcement.WithEffectCeiling(ceiling)),
		nil,
	)
	target := EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}

	hardened := p.HardenRefusal(cappedDelegationCtx(capability.EffectReversible), "s", softRefusal(), target, nil)
	if hardened.Decision != capability.DecisionEscalate {
		t.Fatalf("decision = %v, want escalate: the ceiling's HARD verdict must win over the delegation cap's downgradable one", hardened.Decision)
	}
	if hardened.Denial == nil || !hardened.Denial.HardDeny {
		t.Fatalf("the composed refusal must stay hard: %+v", hardened.Denial)
	}
}
