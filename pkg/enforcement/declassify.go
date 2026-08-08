// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// declassifyConditionType is the taxonomy slot stamped on a declassification refusal — not a
// condition name, since no condition ran (mirrors the effect ceiling's own slot).
const declassifyConditionType = capability.DirectiveTypeDeclassify

// declassifyOutcome is what checkDeclassify resolved for a call: the labels an approved
// directive will clear plus the approval that authorized them, computed BEFORE any state is
// committed so an unapproved call never reaches the commit.
type declassifyOutcome struct {
	// Labels are the labels to remove, canonical vocabulary order; empty means no
	// declassification.
	Labels []string
	// Approver and ApprovalID come from the grant that covered Labels.
	Approver   string
	ApprovalID string
	// LedgerID is the ledger member to burn for a single-use grant, empty for a standing one —
	// resolved here with the grant so the commit burns exactly what this check authorized.
	LedgerID string
}

// handle mints the commit handle for this outcome: the approved labels intersected with what
// the anchor is carrying as of this decision. nil when nothing was authorized.
//
// It computes the intersection itself rather than taking one, since a second call site
// passing anything other than this intersection could mint a handle authorizing more than the
// approval covered.
func (d declassifyOutcome) handle(carriedLabels, labelsOut []string) *capability.Declassification {
	if len(d.Labels) == 0 {
		return nil
	}
	pendingClear := intersectLabels(d.Labels, unionLabels(carriedLabels, labelsOut))
	return capability.NewDeclassification(pendingClear, d.Approver, d.ApprovalID, d.LedgerID != "")
}

// declassifyLedgerWindowSec bounds how long a burned single-use approval is remembered.
//
// The other half of the guarantee is enforced at the token boundary: a token whose remaining
// lifetime exceeds this window is refused outright, so a burn always outlives the token that
// could replay it.
const declassifyLedgerWindowSec = capability.DeclassifyLedgerWindowSec

// declassifyLedgerKey addresses ONE single-use grant's burn: route namespace plus the grant's
// ledger id, deliberately carrying no session and no task — "approve clearing this once" means
// once, and anchoring it made it once-per-session/task instead (see the file-level exception).
//
// Lives in the CallCounter rather than the FlowLabelStore because the counter's AdmitAll is
// the codebase's one atomic admission primitive; the flow store's Get-then-Add would let two
// concurrent callers both win, double-spending the grant.
func (e *Engine) declassifyLedgerKey(ledgerID string) string {
	return compositeCounterKey("declassify", e.counterKeyNamespace, ledgerID)
}

// declassifyLedgerBucket is the one-slot quota a single-use grant draws on: the first
// AdmitAll admits, every later one is refused having recorded nothing.
func (e *Engine) declassifyLedgerBucket(ledgerID string) capability.QuotaBucket {
	return capability.QuotaBucket{
		Key:       e.declassifyLedgerKey(ledgerID),
		WindowSec: declassifyLedgerWindowSec,
		Counted:   true,
		Limit:     1,
	}
}

// approvalSpent reports whether a single-use grant looks already burned. It is a PEEK — it
// records nothing — because it runs during selection, before the ceiling and quota commits
// have had their chance to refuse the call, and spending the grant here would burn a human
// approval for a call that never ran. The race this leaves open is closed at burnApproval's
// atomic commit.
func (e *Engine) approvalSpent(ctx context.Context, ledgerID string) (bool, error) {
	if ledgerID == "" {
		return false, nil
	}
	if e.counter == nil {
		return false, fmt.Errorf("call counter not configured, so a single-use declassify approval cannot be checked")
	}
	n, err := e.counter.Peek(ctx, e.declassifyLedgerKey(ledgerID), declassifyLedgerWindowSec)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// There is deliberately no exported "is there a usable approval for this?" predicate:
// DeclassifyVerdictFor answers the whole question (target, selection, refusal shape) through
// checkDeclassify, so a caller needing only the boolean tests its result for nil instead of
// hand-rolling target resolution and refusal construction that can drift from the decision path.

// approvalSelection is what one walk of the covering grants found: the first still-live grant
// (nil if all spent or none cover), its ledger member, and how many were passed over as
// burned — which distinguishes "no approval covers this" from "it was spent", different
// operator actions.
type approvalSelection struct {
	approval *capability.DeclassifyApproval
	ledgerID string
	covering []*capability.DeclassifyApproval
	consumed int
}

// selectLiveApproval is the ONE walk over covering grants; checkDeclassify (and, through it,
// the wrapping-PDP hardening path via DeclassifyVerdictFor) is its only caller, so a hardening
// check cannot be looser than the decision.
//
// It walks rather than taking the first covering grant because a single-use grant already
// burned still covers the call on paper and must be passed over for a later live one.
func (e *Engine) selectLiveApproval(ctx context.Context, approvals []capability.DeclassifyApproval, target string, want []string) (approvalSelection, error) {
	sel := approvalSelection{covering: capability.CoveringDeclassifyApprovals(approvals, target, want)}
	for _, cand := range sel.covering {
		id := cand.LedgerID()
		spent, err := e.approvalSpent(ctx, id)
		if err != nil {
			return approvalSelection{}, err
		}
		if spent {
			sel.consumed++
			continue
		}
		sel.approval, sel.ledgerID = cand, id
		break
	}
	return sel, nil
}

// checkDeclassify resolves the constraint's declassify directive against the request's
// approvals, returning the outcome to apply on commit and, when unauthorized, the refusal
// that REPLACES the allow.
//
// It runs on the allow tail, after conditions and the effect ceiling and before any commit,
// so an unapproved declassification leaves no spent quota slot, no phantom antecedent, no
// label change.
//
// The refusal is an ESCALATION rather than a deny — "no human approved dropping this label"
// is what `escalate` exists to name — and it is HARD (AuditOnly unset), so --audit cannot
// turn it into a forward: that would perform the action while also clearing the taint meant
// to stop it.
func (e *Engine) checkDeclassify(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, carriedLabels []string, requestID, now string) (declassifyOutcome, *capability.EnforceResponse) {
	if e.skipFlow {
		// No flow state to read or clear; the config layer keeps this unreachable in-tree by
		// counting declassify as flow-relevant, and this is defense in depth for that.
		return declassifyOutcome{}, nil
	}
	want := capability.DeclassifyLabelsOf(matched)
	if len(want) == 0 {
		return declassifyOutcome{}, nil
	}

	// Fail closed on an unknown label, matching recordLabels and handleFlowLabel: a loaded
	// manifest cannot reach here with one, but a programmatically built constraint can.
	for _, l := range want {
		if !capability.IsFlowLabel(l) {
			return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want, nil,
				fmt.Sprintf("declassify names unknown flow label %q; valid native labels are %v", l, flowLabelVocab),
				"unknown_label")
		}
	}

	// The store and session guards mirror recordLabels': without both, the Remove cannot be
	// performed, and forwarding while a clear silently failed would mislead the operator.
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

	// First still-live grant among those scoped to this call; DeclassifyVerdictFor reaches
	// this same walk, so hardening can't answer more loosely than the decision.
	sel, err := e.selectLiveApproval(ctx, req.DeclassifyApprovals, target, want)
	if err != nil {
		// Unreadable ledger means "already used" can't be distinguished from "never used";
		// escalating is the only answer that doesn't make an unreachable backend a replay
		// vector.
		return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want, nil,
			fmt.Sprintf("single-use declassify approval state could not be read: %v", err),
			"ledger_unavailable")
	}
	approval, ledgerID, covering, consumed := sel.approval, sel.ledgerID, sel.covering, sel.consumed
	if approval == nil {
		if consumed > 0 {
			// Distinct reason from "no approval": the grant was scoped correctly and has been
			// spent, a different operator action than widening scope. consumed_approval_id
			// (not approval_id, reserved for a signed successful clear) joins this refusal to
			// the allow that spent it.
			return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want,
				map[string]interface{}{"approvals_consumed": consumed, "consumed_approval_id": covering[0].ID},
				fmt.Sprintf("the human approval covering flow label(s) %v at %s is single-use and has already been consumed; a new approval is required", want, target),
				"approval_consumed")
		}
		// One message for "no grant" and "a grant that doesn't cover this" — the distinction
		// isn't actionable differently, and enumerating missing labels would echo the token
		// back to it.
		return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want, approvalCountDetail(req),
			fmt.Sprintf("clearing flow label(s) %v at %s requires a human approval covering all of them; the request carries none", want, target),
			"no_approval")
	}

	return declassifyOutcome{
		Labels:     want,
		Approver:   approval.Approver,
		ApprovalID: approval.ID,
		LedgerID:   ledgerID,
	}, nil
}

// DeclassifyVerdictFor answers ONE question — "would this constraint's declassification have
// been authorized?" — for an already-selected constraint, WITHOUT evaluating conditions or
// committing state. Returns the ESCALATION_REQUIRED refusal checkDeclassify would produce, or
// nil.
//
// It exists for the COMPOSED case: a wrapping PDP (the JWT layer) can refuse a call on its own
// terms before checkDeclassify ever runs, and a bare wrapping refusal is soft — downgradable by
// --audit — which would let the forward perform the action AND clear the taint it should have
// stopped. Routing through checkDeclassify (rather than a hand-rolled target/refusal, which
// previously diverged on untrimmed names and a missing CarriedLabels field) gives one
// canonical resolver and one refusal shape.
//
// Non-committing is inherited from checkDeclassify itself; its only backend touch is the
// ledger PEEK, which records nothing.
//
// Use ONLY to HARDEN an already-refused call, never to produce an allow. The flow-label peek's
// failure is swallowed, matching CeilingVerdictFor: the refusal being hardened must not
// weaken.
func (e *Engine) DeclassifyVerdictFor(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) *capability.EnforceResponse {
	// e == nil first: an exported method on unexported fields, so an embedder can legitimately
	// hold an unwired *Engine. Dereferencing would panic a request goroutine on a refusal path
	// — fail-open-via-crash. Mirrors CommitDeclassification's same guard.
	if e == nil || req == nil || matched == nil || e.skipFlow {
		return nil
	}
	if len(capability.DeclassifyLabelsOf(matched)) == 0 {
		return nil
	}
	requestID := NewRequestID()
	now := e.clock.Now().UTC().Format(time.RFC3339Nano)

	var carriedLabels []string
	// Skip the peek for an unanchorable request, mirroring evaluateMatched's ordering: with
	// no task id the anchor falls back to the SESSION key, and the snapshot would come from
	// the very bucket the full path's refusal exists to reject — wrong-bucket evidence on
	// the hardened record.
	if !e.anchorUnresolved(req) {
		if labels, err := e.peekSessionLabels(ctx, req); err == nil {
			carriedLabels = labels
		}
	}
	// Outcome discarded: it describes what a COMMIT would apply, and this commits nothing.
	_, refusal := e.checkDeclassify(ctx, req, matched, carriedLabels, requestID, now)
	return refusal
}

// declassifyRefusal builds the ESCALATION_REQUIRED refusal for an unauthorized
// declassification. Every arm routes through it so BoundDenialDetails and the details shape
// are single-sourced.
func (e *Engine) declassifyRefusal(requestID, now string, carriedLabels, want []string, extra map[string]interface{}, message, reason string) *capability.EnforceResponse {
	details := map[string]interface{}{
		// Marks this a flow-layer refusal, same discriminator a flowLabel sink denial carries.
		capability.FlowAuditDetailKey: true,
		"declassify_labels":           want,
		"reason":                      reason,
	}
	for k, v := range extra {
		details[k] = v
	}
	// The session's accumulated labels: this refusal is meant for a human to act on, and what
	// the session already carries is the first thing they need.
	if len(carriedLabels) > 0 {
		details["carried_labels"] = carriedLabels
	}
	resp := escalateResponse(requestID, now, capability.DenialInfo{
		Code:          capability.ErrCodeEscalationRequired,
		ConditionType: declassifyConditionType,
		Message:       message,
		Details:       details,
		// Hard, same reason the ceiling's escalation is: --audit must not downgrade this to a
		// forward.
		HardDeny: true,
	})
	resp.CarriedLabels = carriedLabels
	return &resp
}

// approvalCountDetail reports how many approvals the request presented, so an operator can
// tell "no declassify claim at all" from "grants presented, none covering this" — only the
// count, not the grants' contents, since those are the token's and echoing them onto the tape
// would leak it.
func approvalCountDetail(req *capability.EnforceRequest) map[string]interface{} {
	if len(req.DeclassifyApprovals) == 0 {
		return nil
	}
	return map[string]interface{}{"approvals_presented": len(req.DeclassifyApprovals)}
}

// canonicalApprovalTarget renders the request's target in the "<type>:<bare>" spelling an
// approval names, delegating to resolveRequestTarget — the same resolver
// FindMatchingCapability uses to select the constraint — so an approval is scoped against the
// target that selected it.
//
// A hand-rolled resolver previously diverged (whole-Target preference, no trimming, rejecting
// unrecognized prefixes) in ways that made correctly-scoped approvals unsatisfiable.
func canonicalApprovalTarget(req *capability.EnforceRequest) string {
	reqType, bare := resolveRequestTarget(req)
	if bare == "" || reqType == "" {
		return ""
	}
	return reqType + ":" + bare
}

// burnApproval spends a single-use grant via one atomic admission against its one-slot
// bucket — the ONLY authoritative test (approvalSpent's peek is advisory); the loser of a
// concurrent race is hard-denied. A standing grant (empty ledgerID) burns nothing.
//
// Runs inside the DECISION's commit, not the deferred clear it authorizes, because it is the
// atomic test that makes "once" mean once. That leaves a grant possibly spent by a call whose
// clear never lands (a later fault); the response's SpentApprovalID names it for
// reconciliation.
//
// Burns on EVERY commit of an approved single-use declassification, even a no-op clear — the
// approval turned an escalation into an allow, so it was spent regardless of whether a label
// moved. Burning only on an effective clear would make the grant replayable by ordering.
//
// No un-burn by design: a call refused after its burn over-refuses (mint another approval)
// rather than handing the use back to a route that already forwarded it once (the fail-open
// the old un-burn had on an --audit route).
//
// NOT skipped under SkipQuota: observe mode skips budget spend, but the label clear this
// grant authorizes still runs for real, so the burn that guards its single-use property must
// too.
func (e *Engine) burnApproval(ctx context.Context, ledgerID string) error {
	if ledgerID == "" {
		return nil
	}
	if e.counter == nil {
		return fmt.Errorf("call counter not configured; a single-use declassify approval cannot be burned")
	}
	admitted, _, _, _, err := e.counter.AdmitAll(ctx, []capability.QuotaBucket{e.declassifyLedgerBucket(ledgerID)})
	if err != nil {
		return err
	}
	if !admitted {
		return fmt.Errorf("single-use declassify approval was consumed concurrently by another call")
	}
	return nil
}

// declassifyRecordFailureDenial is the fail-closed response when the declassify leg of the
// source commit faulted. HARD deny: the soft antecedent-fault deny beside it is downgradable
// by --audit, and forwarding a call whose one-shot approval was just spent burns the approval
// with nothing performed to show for it.
//
// Nothing was cleared on this path (the clear is phase two and never ran). spentApprovalID
// names a single-use grant this commit burned before faulting, so an operator reconciling
// one-shot approvals doesn't believe it's still live; it rides the response field rather than
// a detail key so the audit layer stamps it identically on allow and refusal.
func declassifyRecordFailureDenial(requestID, now string, auditOnly bool, spentApprovalID string) capability.EnforceResponse {
	resp := denyResponse(requestID, now, auditOnly, nil, capability.DenialInfo{
		Code:          capability.ErrCodeEnforcementError,
		ConditionType: declassifyConditionType,
		Message:       "the declassification leg of this call's state commit failed; the approved clear was not applied and the call is refused",
		Details:       map[string]interface{}{capability.FlowAuditDetailKey: true, "phase": "record"},
	})
	if spentApprovalID != "" {
		// Carries no labels and no authorizing approval — its only job is to name the burned
		// grant. The dedicated constructor keeps the id off ApprovalID(), reserved for a
		// declassification that actually took effect.
		resp.Declassification = capability.NewSpentGrantOnly(spentApprovalID)
	}
	return resp
}
