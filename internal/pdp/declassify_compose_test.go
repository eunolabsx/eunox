// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
)

// faultyPeekCounter is a call counter whose ledger read always faults, so a test can put the
// declassify ledger in the one state the hardening path has to answer for: "cannot tell a live
// single-use grant from a spent one".
type faultyPeekCounter struct{}

func (faultyPeekCounter) IncrementAndGet(_ context.Context, _ string, _, _ int) (int64, error) {
	return 0, nil
}

func (faultyPeekCounter) Peek(_ context.Context, _ string, _ int) (int64, error) {
	return 0, errors.New("ledger backend unreachable")
}

func (faultyPeekCounter) AdmitAll(_ context.Context, _ []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return true, -1, 0, 0, nil
}

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

// TestDeclassify_ComposedRefusalHardensOnAnUnreadableLedger closes the same inversion from the
// other direction. checkDeclassify raises a HARD `ledger_unavailable` escalation when it cannot
// tell a live single-use grant from a spent one; leaving the wrapping layer's SOFT refusal in
// place on the identical fault meant an --audit route FORWARDED the call, so an unreachable
// ledger became the way to run a declassification the same manifest blocks without a token.
func TestDeclassify_ComposedRefusalHardensOnAnUnreadableLedger(t *testing.T) {
	eng := enforcement.New(
		enforcement.WithCallCounter(faultyPeekCounter{}),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
	p := NewManifestPDP([]capability.Constraint{{
		Target:     "tool:sanitize",
		Actions:    []string{"call"},
		Directives: []capability.Directive{capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}},
	}}, eng, nil)

	// A covering, single-use grant — so the answer turns entirely on the ledger read.
	ctx := WithJWTClaims(context.Background(), &JWTClaims{
		Subject: "svc",
		Declassify: []capability.DeclassifyApproval{{
			Labels: []string{capability.FlowLabelPII}, Target: "tool:sanitize",
			Approver: "alice", ID: "apr-1", Once: true,
		}},
	})
	soft := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    capability.ErrCodeAuthorizationFailed,
			Message: "tool \"sanitize\" is not in the JWT capability claims",
		},
	}
	hardened := p.HardenRefusal(ctx, "s", soft, EnforceTarget{Type: capability.TargetTypeTool, Name: "sanitize"}, map[string]interface{}{})
	if hardened.Denial == nil || !hardened.Denial.HardDeny {
		t.Fatalf("an unreadable ledger must leave a non-downgradable refusal: %+v", hardened.Denial)
	}
	if got := hardened.Denial.Details["reason"]; got != "ledger_unavailable" {
		t.Fatalf("reason = %v, want ledger_unavailable so the tape names the fault rather than a missing approval", got)
	}
}

// TestDeclassify_ComposedRefusalUsesTheCanonicalTarget is the padded-name divergence. The
// composed path derived the approval target itself as `type + ":" + name`, which does not
// trim — while the engine resolves it through resolveRequestTarget, which does. A request
// whose target name carried surrounding whitespace therefore resolved to "tool:sanitize "
// here and "tool:sanitize" there, and an approval (already trimmed at the token boundary)
// could never match it: a permanent ESCALATION_REQUIRED on a grant the operator scoped
// correctly, with nothing they could change to satisfy it.
//
// It fails closed, which is why it is a usability defect rather than a widening — but an
// unsatisfiable escalation is exactly the failure the centralized resolver exists to prevent.
//
// The constraint is a WILDCARD on purpose: an exactly-named entry does not match a padded
// name in findConstraint at all, so the request never reaches the approval check and the
// divergence is unobservable. A "tool:*" entry does match, which is how a padded name a host
// sends in tools/call params reaches the target resolver in the first place.
func TestDeclassify_ComposedRefusalUsesTheCanonicalTarget(t *testing.T) {
	p := declassifyPDP(t, []capability.Constraint{{
		Target:     "tool:*",
		Actions:    []string{"call"},
		Directives: []capability.Directive{capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}},
	}})
	ctx := WithJWTClaims(context.Background(), &JWTClaims{
		Subject: "svc",
		Declassify: []capability.DeclassifyApproval{{
			Labels: []string{capability.FlowLabelPII}, Target: "tool:sanitize", Approver: "alice",
		}},
	})
	soft := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    capability.ErrCodeAuthorizationFailed,
			Message: "tool \"sanitize\" is not in the JWT capability claims",
		},
	}

	hardened := p.HardenRefusal(ctx, "s", soft,
		EnforceTarget{Type: capability.TargetTypeTool, Name: "  sanitize  "}, map[string]interface{}{})
	if hardened.Decision == capability.DecisionEscalate {
		t.Fatalf("a padded target name must resolve to the canonical target the approval names, "+
			"not to an escalation no approval can satisfy: %+v", hardened.Denial)
	}
}

// TestDeclassify_ComposedRefusalCarriesTheSessionsLabels pins the record shape. The engine's
// own refusal sets both details.carried_labels and the top-level CarriedLabels, because "what
// is this session already carrying" is the first thing an approver needs in order to decide
// whether the declassification should be approved at all. The composed refusal built its own
// DenialInfo and set neither, so the same logical refusal landed on the tape two different
// ways depending on whether a JWT layer wrapped the call — and the wrapped one dropped the
// field the approver acts on.
func TestDeclassify_ComposedRefusalCarriesTheSessionsLabels(t *testing.T) {
	p := declassifyPDP(t, []capability.Constraint{
		{
			Target:     "tool:read_customer",
			Actions:    []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelPII}}},
		},
		{
			Target:     "tool:sanitize",
			Actions:    []string{"call"},
			Directives: []capability.Directive{capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}},
		},
	})
	ctx := context.Background()
	if got := p.Decide(ctx, "s", EnforceTarget{Type: capability.TargetTypeTool, Name: "read_customer"},
		map[string]interface{}{}, ""); got.Decision != capability.DecisionAllow {
		t.Fatalf("source read = %v, want allow", got.Decision)
	}

	soft := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    capability.ErrCodeAuthorizationFailed,
			Message: "tool \"sanitize\" is not in the JWT capability claims",
		},
	}
	hardened := p.HardenRefusal(ctx, "s", soft,
		EnforceTarget{Type: capability.TargetTypeTool, Name: "sanitize"}, map[string]interface{}{})
	if hardened.Decision != capability.DecisionEscalate || hardened.Denial == nil {
		t.Fatalf("decision = %v, want escalate (%+v)", hardened.Decision, hardened.Denial)
	}
	if len(hardened.CarriedLabels) != 1 || hardened.CarriedLabels[0] != capability.FlowLabelPII {
		t.Fatalf("carried_labels = %v, want [pii] — the approver reads this to decide", hardened.CarriedLabels)
	}
	got, ok := hardened.Denial.Details["carried_labels"].([]string)
	if !ok || len(got) != 1 || got[0] != capability.FlowLabelPII {
		t.Fatalf("details.carried_labels = %v, want [pii]; the composed record must match the documented shape", hardened.Denial.Details["carried_labels"])
	}
}
