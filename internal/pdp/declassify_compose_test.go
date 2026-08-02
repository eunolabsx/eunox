// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
)

// declassifyPDP builds a ManifestPDP over caps with a real flow store.
func declassifyPDP(t *testing.T, caps []capability.Constraint) *ManifestPDP {
	t.Helper()
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
	return NewManifestPDP(caps, eng, nil)
}

// TestDeclassify_UnionDoesNotTaintADeclassifyingConstraint pins that the labelOutput union
// scan leaves a declassifying entry alone.
//
// The union exists so a sibling entry cannot SHADOW a source's taint. Applied to a
// declassify entry it rebuilt, at runtime, the labelOutput+declassify constraint the loader
// refuses — out of two entries that are each individually coherent, so nothing rejects
// them. The observable damage was that a capability written as "this action clears pii"
// instead ASSERTED pii on a clean session, silently, with no approver recorded.
func TestDeclassify_UnionDoesNotTaintADeclassifyingConstraint(t *testing.T) {
	caps := []capability.Constraint{
		{
			Target:     "tool:*",
			Actions:    []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelPII}}},
		},
		{
			Target:     "tool:sanitize",
			Actions:    []string{"call"},
			Directives: []capability.Directive{capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}},
		},
	}
	p := declassifyPDP(t, caps)
	ctx := WithJWTClaims(context.Background(), &JWTClaims{
		Subject: "svc",
		Declassify: []capability.DeclassifyApproval{{
			Labels: []string{capability.FlowLabelPII}, Target: "tool:sanitize", Approver: "alice",
		}},
	})

	resp := p.Decide(ctx, "s", EnforceTarget{Type: capability.TargetTypeTool, Name: "sanitize"}, map[string]interface{}{}, "")
	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("decision = %v, want allow (denial: %+v)", resp.Decision, resp.Denial)
	}
	if len(resp.LabelsOut) != 0 {
		t.Fatalf("a declassifying capability must not be handed a synthesized labelOutput; labels_out = %v", resp.LabelsOut)
	}
}

// TestDeclassify_ComposedRefusalStaysHard is the composed-verdict guarantee: a wrapping
// layer's refusal is HARDENED to the declassify escalation, so adding a JWT can never make
// a call run that the same manifest hard-refuses without one.
//
// Without the hardening the JWT layer's soft AUTHORIZATION_FAILED was downgraded on an
// --audit route and the call was FORWARDED — performing the action and clearing nothing,
// while the tokenless path hard-escalated the identical request. That inverts the rule
// that a token may only ever restrict.
func TestDeclassify_ComposedRefusalStaysHard(t *testing.T) {
	caps := []capability.Constraint{{
		Target:     "tool:sanitize",
		Actions:    []string{"call"},
		Directives: []capability.Directive{capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}},
	}}
	p := declassifyPDP(t, caps)

	// A soft refusal such as an outer authorization layer produces.
	soft := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    capability.ErrCodeAuthorizationFailed,
			Message: "tool \"sanitize\" is not in the JWT capability claims",
		},
	}
	target := EnforceTarget{Type: capability.TargetTypeTool, Name: "sanitize"}

	hardened := p.HardenRefusal(context.Background(), "s", soft, target, map[string]interface{}{})
	if hardened.Decision != capability.DecisionEscalate {
		t.Fatalf("decision = %v, want escalate", hardened.Decision)
	}
	if hardened.Denial == nil || !hardened.Denial.HardDeny {
		t.Fatalf("the composed refusal must be hard so --audit cannot forward it: %+v", hardened.Denial)
	}
	if hardened.Denial.Code != capability.ErrCodeEscalationRequired {
		t.Fatalf("code = %q, want %q", hardened.Denial.Code, capability.ErrCodeEscalationRequired)
	}
	if hardened.Denial.ConditionType != capability.DirectiveTypeDeclassify {
		t.Fatalf("condition_type = %q, want declassify", hardened.Denial.ConditionType)
	}

	// With a covering approval the declassification is not what makes the call refusable,
	// so the outer layer's own verdict stands unchanged.
	approved := WithJWTClaims(context.Background(), &JWTClaims{
		Subject: "svc",
		Declassify: []capability.DeclassifyApproval{{
			Labels: []string{capability.FlowLabelPII}, Target: "tool:sanitize", Approver: "alice",
		}},
	})
	unchanged := p.HardenRefusal(approved, "s", soft, target, map[string]interface{}{})
	if unchanged.Decision == capability.DecisionEscalate {
		t.Fatal("an approved declassification must not harden the wrapping layer's verdict into an escalation")
	}
}
