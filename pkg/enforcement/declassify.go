// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// declassifyConditionType is the condition_type stamped on a declassification refusal.
// It is the directive's own discriminator rather than a condition name: no condition
// failed, and labelling the refusal "flowLabel" would make an operator grep for a sink
// rule that does not exist. The audit field is a taxonomy slot, not a claim that a
// condition ran — the effect ceiling uses it the same way.
const declassifyConditionType = capability.DirectiveTypeDeclassify

// declassifyOutcome is what checkDeclassify resolved for a call: the labels an approved
// directive will clear plus the approval that authorized them, or nothing at all when the
// constraint carries no declassify directive. It is computed BEFORE any state is
// committed and applied inside the atomic source commit, so an unapproved call never
// reaches the commit and an approved one clears exactly what was authorized.
type declassifyOutcome struct {
	// Labels are the labels to remove, canonical vocabulary order. Empty means "no
	// declassification on this call".
	Labels []string
	// Approver and ApprovalID come from the grant that covered Labels.
	Approver   string
	ApprovalID string
}

// checkDeclassify resolves the constraint's declassify directive against the request's
// approvals. It returns the outcome to apply on commit and, when the call is not
// authorized, the refusal that REPLACES the allow.
//
// It runs on the allow tail — after the conditions and after the effect ceiling, before
// the deferred-condition commit and the flow/antecedent write — for the same reason the
// ceiling does: an unapproved declassification is NOT forwarded, so it must leave neither
// a spent quota slot, nor a phantom sequenceBlock antecedent, nor any change to the
// session's label set.
//
// Why the refusal is an ESCALATION and not a deny: "no human has approved dropping this
// label here" is precisely the condition `escalate` was introduced to name. It is a hard
// refusal with AuditOnly unset (escalateResponse), so a route running --audit cannot turn
// it into a forward — the same non-negotiable that keeps an over-ceiling action from being
// performed-anyway-and-logged. A declassification is if anything the stronger case: the
// forward would not merely perform the action, it would perform it while ALSO clearing the
// taint that would have stopped the next one.
func (e *Engine) checkDeclassify(req *capability.EnforceRequest, matched *capability.Constraint, carriedLabels []string, requestID, now string) (declassifyOutcome, *capability.EnforceResponse) {
	want := capability.DeclassifyLabelsOf(matched)
	if len(want) == 0 {
		return declassifyOutcome{}, nil
	}

	// Fail closed on an unknown label the same way recordLabels and handleFlowLabel do.
	// A loaded manifest cannot reach here with one (validation rejects it); a
	// programmatically built constraint can, and a label this build cannot interpret must
	// not be quietly removed from a set the sink check reads.
	for _, l := range want {
		if !capability.IsFlowLabel(l) {
			return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want, nil,
				fmt.Sprintf("declassify names unknown flow label %q; valid native labels are %v", l, flowLabelVocab),
				"unknown_label")
		}
	}

	// The store and session guards mirror recordLabels': without both, the Remove cannot
	// be performed, and forwarding the call while the clear silently did not happen would
	// leave the operator believing a label was dropped.
	if e.flowStore == nil {
		return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want, nil,
			"flow-label store not configured; a declassification cannot be applied", "no_store")
	}
	if req.SessionID == "" {
		return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want, nil,
			"sessionId is required to apply a declassification", "no_session")
	}

	target := canonicalApprovalTarget(req)
	if target == "" {
		return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want, nil,
			"the request carries no resolvable target, so no approval can be scoped to it", "no_target")
	}

	approval := capability.FindDeclassifyApproval(req.DeclassifyApprovals, target, want)
	if approval == nil {
		// One message for "no grant at all" and "a grant that does not cover this",
		// because the distinction is not one the caller may act on differently and
		// enumerating which labels a presented grant was missing would echo the token's
		// contents back to it. The count is safe and is the operator's first diagnostic.
		return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want, approvalCountDetail(req),
			fmt.Sprintf("clearing flow label(s) %v at %s requires a human approval covering all of them; the request carries none", want, target),
			"no_approval")
	}

	return declassifyOutcome{
		Labels:     want,
		Approver:   approval.Approver,
		ApprovalID: approval.ID,
	}, nil
}

// declassifyRefusal builds the ESCALATION_REQUIRED refusal that replaces the allow for an
// unauthorized declassification. Every arm goes through it (rather than building an
// EnforceResponse literal) so the boundDenialDetails pass and the details shape are
// single-sourced — details here carries manifest-authored and request-derived values, and
// the one refusal a human is expected to read is exactly the one that must not carry an
// unbounded value onto the signed tape.
func (e *Engine) declassifyRefusal(requestID, now string, carriedLabels, want []string, extra map[string]interface{}, message, reason string) *capability.EnforceResponse {
	details := map[string]interface{}{
		// "flow": true marks this a flow-layer refusal, the same discriminator a
		// flowLabel sink denial carries, so one filter finds every information-flow
		// event on the tape.
		"flow":              true,
		"declassify_labels": want,
		"reason":            reason,
	}
	for k, v := range extra {
		details[k] = v
	}
	// The session's accumulated labels, for the same reason the ceiling's escalation
	// carries them: this is a refusal a human is expected to act on, and "what is this
	// session already carrying" is the first thing they need in order to decide whether
	// the declassification should be approved at all.
	if len(carriedLabels) > 0 {
		details["carried_labels"] = carriedLabels
	}
	resp := escalateResponse(requestID, now, capability.DenialInfo{
		Code:          capability.ErrCodeEscalationRequired,
		ConditionType: declassifyConditionType,
		Message:       message,
		Details:       details,
		// Hard, for the same reason the ceiling's escalation is: --audit downgrades a
		// policy verdict being staged, and this is not one.
		HardDeny: true,
	})
	if resp.CarriedLabels == nil {
		resp.CarriedLabels = carriedLabels
	}
	return &resp
}

// approvalCountDetail reports how many approvals the request presented, so an operator can
// tell "the token carried no declassify claim at all" (an integration that was never wired)
// from "it carried grants, none covering this action" (a scoping mistake). Only the count
// is recorded — the grants' contents are the token's, and echoing them onto the tape would
// put an IdP's claim payload into the audit record for a call that was refused.
func approvalCountDetail(req *capability.EnforceRequest) map[string]interface{} {
	if len(req.DeclassifyApprovals) == 0 {
		return nil
	}
	return map[string]interface{}{"approvals_presented": len(req.DeclassifyApprovals)}
}

// canonicalApprovalTarget renders the request's target in the "<type>:<bare>" spelling an
// approval names. It prefers the split Target the PDP populates and falls back to parsing
// the caller-supplied TargetName, so a direct engine caller that set only the latter is
// still scoped rather than silently unscoped. An unparseable target yields "", which
// checkDeclassify turns into a refusal — never into an approval that matches everything.
func canonicalApprovalTarget(req *capability.EnforceRequest) string {
	if req.Target != nil && req.Target.Type != "" && req.Target.Name != "" {
		return req.Target.Type + ":" + req.Target.Name
	}
	name := strings.TrimSpace(req.TargetName)
	if name == "" {
		return ""
	}
	tt, bare, err := capability.ParseTarget(name)
	if err != nil {
		// A bare name defaults to the tool namespace, matching EnforceRequest.TargetName's
		// documented spelling rule. Anything else (an unknown prefix) stays unresolvable.
		if strings.Contains(name, ":") {
			return ""
		}
		return string(capability.TargetTypeTool) + ":" + name
	}
	return string(tt) + ":" + bare
}

// clearLabels applies an approved declassification: it removes the granted labels from
// the session's accumulated set. It returns the labels actually removed — the intersection
// with what the session was carrying — so the audit record reports what CHANGED rather
// than what was authorized.
//
// Reporting the intersection is deliberate. An approval to clear `pii` on a session that
// never carried it is not an error (the action is permitted and the end state is the one
// the policy asked for), but recording labels_cleared: ["pii"] would put a declassification
// that did not happen on the tape, and the tape is the artifact an auditor reconstructs the
// flow from. A no-op clear records no labels_cleared and no approver.
func (e *Engine) clearLabels(ctx context.Context, req *capability.EnforceRequest, out declassifyOutcome, carriedLabels []string) ([]string, error) {
	if len(out.Labels) == 0 {
		return nil, nil
	}
	if e.flowStore == nil {
		return nil, fmt.Errorf("flow label store not configured; flow labels cannot be cleared")
	}
	if req.SessionID == "" {
		return nil, fmt.Errorf("sessionId is required to clear flow labels")
	}
	present := make(map[string]bool, len(carriedLabels))
	for _, l := range carriedLabels {
		present[l] = true
	}
	var removed []string
	for _, l := range out.Labels {
		if present[l] {
			removed = append(removed, l)
		}
	}
	if len(removed) == 0 {
		return nil, nil
	}
	if err := e.flowStore.Remove(ctx, e.flowSessionKey(req.SessionID), removed...); err != nil {
		return nil, err
	}
	return removed, nil
}

// declassifyRecordFailureDenial is the fail-closed response when an approved
// declassification cannot be applied. It is a HARD deny for the mirror of
// labelRecordFailureDenial's reason: forwarding the call while the Remove failed would
// perform the action AND leave the taint the policy said this action clears, so the next
// call in the session hits a sink rule the operator believes no longer applies. Over-
// blocking is the safe direction; the operator retries once the store is reachable.
func declassifyRecordFailureDenial(requestID, now string, auditOnly bool) capability.EnforceResponse {
	return denyResponse(requestID, now, auditOnly, nil, capability.DenialInfo{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: declassifyConditionType,
		Message:       "declassification could not be applied; session flow state is unreliable",
		HardDeny:      true,
		Details:       map[string]interface{}{"flow": true, "phase": "record"},
	})
}
