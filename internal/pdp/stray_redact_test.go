// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// INVARIANT: a redactFields directive on a non-tool target is a HARD deny, the sibling of the
// stray-argumentSchema guard beside it.
//
// redactFields is tool-only (the proxy redacts tools/call results) and the loader refuses one
// on a resource:/prompt:/system: target, so this is the in-process / defense-in-depth path — a
// library consumer building constraints directly. Without the guard the directive is collected
// (enforcement.CollectObligations is target-type-blind) and the redactor runs over an envelope
// it does not understand: a resources/read `contents[].blob` body is not the `content` shape it
// inspects, so it passes uninspected while the tape records the obligation as APPLIED — the
// embedded-body evasion the tools/call path fails closed on.
func TestStrayRedactFields_OnANonToolTarget_HardDenies(t *testing.T) {
	t.Parallel()
	redact := []capability.Directive{&capability.RedactFieldsDirective{Fields: []string{"users.ssn"}}}

	for _, tc := range []struct {
		name   string
		decide func(*ManifestPDP) capability.EnforceResponse
		entry  capability.Constraint
	}{
		{
			name:  "resources/read",
			entry: capability.Constraint{Target: "resource:secrets/*", Actions: []string{"read"}, Directives: redact},
			decide: func(p *ManifestPDP) capability.EnforceResponse {
				return p.DecideResourceRead(context.Background(), "s", "secrets/db", "")
			},
		},
		{
			name:  "prompts/get",
			entry: capability.Constraint{Target: "prompt:review", Actions: []string{"get"}, Directives: redact},
			decide: func(p *ManifestPDP) capability.EnforceResponse {
				return p.DecidePromptGet(context.Background(), "s", "review", "")
			},
		},
		{
			name: "sampling/createMessage",
			entry: capability.Constraint{
				Target: "system:" + capability.MethodSamplingCreateMessage, Actions: []string{"allow"}, Directives: redact,
			},
			decide: func(p *ManifestPDP) capability.EnforceResponse {
				return p.DecideSampling(context.Background(), "s", "")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := tc.decide(newTestManifestPDP(tc.entry))

			if resp.Decision != capability.DecisionDeny {
				t.Fatalf("decision = %q, want deny", resp.Decision)
			}
			if resp.Denial == nil {
				t.Fatal("Denial = nil, want a populated DenialInfo")
			}
			if resp.Denial.Code != capability.ErrCodeEnforcementError {
				t.Errorf("denial code = %q, want %q (an engine/wiring fault, not a policy verdict)",
					resp.Denial.Code, capability.ErrCodeEnforcementError)
			}
			if !resp.Denial.BlockOverride {
				t.Error("the deny must be BlockOverride so a route running under --audit cannot downgrade it to a forward")
			}
			if len(resp.Obligations) != 0 {
				t.Errorf("a refused constraint must carry no obligations, got %v", resp.Obligations)
			}
		})
	}
}

// TestStrayRedactFields_AuditOnlyStillDenies is the schema guard's companion invariant on this
// one: the check runs ABOVE the audit-mode stamp, so an enforcement: audit entry cannot turn it
// into an observed allow that log-and-forwards an unapplied redaction.
func TestStrayRedactFields_AuditOnlyStillDenies(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:      "resource:secrets/*",
		Actions:     []string{"read"},
		Enforcement: capability.EnforcementAudit,
		Directives:  []capability.Directive{&capability.RedactFieldsDirective{Fields: []string{"users.ssn"}}},
	})

	resp := p.DecideResourceRead(context.Background(), "s", "secrets/db", "")
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny", resp.Decision)
	}
	if resp.AuditOnly {
		t.Error("AuditOnly = true: the stray-redactFields deny must not be downgraded to an observed allow")
	}
}

// TestRedactFields_OnAToolTargetStillApplies is the control: the guard refuses the stray case,
// not the surface. A tool entry keeps its obligation.
func TestRedactFields_OnAToolTargetStillApplies(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:     "tool:read_record",
		Actions:    []string{"call"},
		Directives: []capability.Directive{&capability.RedactFieldsDirective{Fields: []string{"users.ssn"}}},
	})

	resp := p.Decide(context.Background(), "s",
		EnforceTarget{Type: capability.TargetTypeTool, Name: "read_record"}, map[string]interface{}{}, "")
	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("decision = %q, want allow", resp.Decision)
	}
	if len(resp.Obligations) != 1 || resp.Obligations[0].Type != capability.DirectiveTypeRedactFields {
		t.Fatalf("a tool entry must still carry its redactFields obligation, got %+v", resp.Obligations)
	}
}

// TestStrayRedactFields_TypedNilDirectiveDoesNotPanic: DirectiveType has a VALUE receiver, so
// a typed-nil directive pointer boxed in the interface survives a bare `d != nil` check and
// panics on the auto-generated dereference. A decision point that crashes produces no decision
// at all, which is this package's fail-OPEN reading — and the population that can carry a
// typed nil is exactly the in-process consumer these guards exist for.
func TestStrayRedactFields_TypedNilDirectiveDoesNotPanic(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:     "resource:secrets/*",
		Actions:    []string{"read"},
		Directives: []capability.Directive{(*capability.RedactFieldsDirective)(nil)},
	})

	resp := p.DecideResourceRead(context.Background(), "s", "secrets/db", "")
	if resp.Decision == "" {
		t.Fatal("a typed-nil directive must still produce a decision")
	}
}

// TestStrayRedactFields_NoMatchForwardCarriesNoRedaction is the path the matched-constraint
// guard sits BELOW and therefore cannot cover: no entry is selected, so the forwarded refusal
// fills its obligations from every entry NAMING the target — a deliberately wider,
// principal-blind union — and that fill used to pick a stray resource-entry redactFields up
// and hand it to the tools/call-shaped redactor. The obligation is now dropped where it is
// collected, so the tape stops claiming a redaction nothing performed.
func TestStrayRedactFields_NoMatchForwardCarriesNoRedaction(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		// Principal-scoped away from this caller, so findConstraint selects nothing.
		Target:     "resource:secrets/*",
		Actions:    []string{"read"},
		Principal:  map[string][]string{"agent_id": {"someone-else"}},
		Directives: []capability.Directive{&capability.RedactFieldsDirective{Fields: []string{"users.ssn"}}},
	})

	// --audit: the no-match deny is downgradable, so this is the posture that forwards it.
	resp := p.DecideResourceRead(enforcement.WithSkipQuota(context.Background()), "s", "secrets/db", "")
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (nothing matched)", resp.Decision)
	}
	if len(resp.Obligations) != 0 {
		t.Fatalf("a forwarded resources/read refusal must carry no redactFields obligation the redactor cannot discharge, got %v", resp.Obligations)
	}
}

// TestRedactFields_ToolNoMatchForwardStillCarriesIt is the control for the guard above: the
// same wider fill on a TOOL target is the case it exists for, and must be untouched.
func TestRedactFields_ToolNoMatchForwardStillCarriesIt(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:     "tool:read_record",
		Actions:    []string{"call"},
		Principal:  map[string][]string{"agent_id": {"someone-else"}},
		Directives: []capability.Directive{&capability.RedactFieldsDirective{Fields: []string{"users.ssn"}}},
	})

	resp := p.Decide(enforcement.WithSkipQuota(context.Background()), "s",
		EnforceTarget{Type: capability.TargetTypeTool, Name: "read_record"}, map[string]interface{}{}, "")
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (principal-scoped away)", resp.Decision)
	}
	if len(resp.Obligations) != 1 {
		t.Fatalf("a forwarded tools/call refusal must still be masked by an entry naming the tool, got %v", resp.Obligations)
	}
}
