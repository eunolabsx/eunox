// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"

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
	// LedgerID is the ledger member to burn when the grant is single-use, empty for a
	// standing one. It is resolved here, with the grant, rather than re-derived at commit
	// time: the commit must burn EXACTLY the approval this check authorized, and a second
	// derivation is a place for the two to pick different grants.
	LedgerID string
}

// declassifyLedgerWindowSec bounds how long a burned single-use approval is remembered. It
// is a REAL bound on the guarantee, not a storage detail, and it is stated in the same terms
// sequenceHistoryWindowSec states its own: after this long with no further presentation of
// that grant, the burn is gone and the grant is live again.
//
// Seven days is chosen against what the burn has to outlive — the TOKEN carrying the grant.
// A control plane minting a short-lived token per approval (the practice the docs recommend
// regardless) is orders of magnitude inside it; a deployment issuing week-long tokens with
// standing single-use grants embedded is at the edge of what any local ledger can promise,
// and shortening the token is the fix, not lengthening this.
const declassifyLedgerWindowSec = 7 * 86400

// declassifyLedgerKey addresses ONE single-use grant's burn. The key is the route namespace
// plus the grant's ledger id, and deliberately carries no session and no task:
//
//   - "Approve clearing this once" means once. Anchoring the ledger made it once-per-session
//     by default — session teardown reclaimed it and two concurrent sessions held two
//     independent ledgers — so the property the grant advertises held in no default
//     deployment. Anchoring it to the task merely moved the boundary.
//   - A per-grant key rather than one set per anchor also bounds the state: each burn is
//     reclaimed on its own window instead of accumulating in a set that is never pruned.
//
// It lives in the CallCounter rather than the FlowLabelStore, which reverses the original
// choice, and the reason is atomicity. The flow store offers no test-and-set: a Get-then-Add
// burn is a check-then-act that two concurrent callers both win, which double-spends exactly
// the approval this mechanism exists to make single-use. The counter's AdmitAll is the
// codebase's ONE atomic admission primitive, and a counted bucket with a limit of 1 is
// precisely "admit once, ever". The cost is that the counter is windowed — see
// declassifyLedgerWindowSec, where that bound is stated rather than wished away.
func (e *Engine) declassifyLedgerKey(ledgerID string) string {
	return compositeCounterKey("declassify", e.counterKeyNamespace, ledgerID)
}

// declassifyLedgerBucket is the one-slot quota a single-use grant draws on. Counted with a
// limit of 1: the first AdmitAll records the entry and admits, every later one is refused
// having recorded nothing.
func (e *Engine) declassifyLedgerBucket(ledgerID string) capability.QuotaBucket {
	return capability.QuotaBucket{
		Key:       e.declassifyLedgerKey(ledgerID),
		WindowSec: declassifyLedgerWindowSec,
		Counted:   true,
		Limit:     1,
	}
}

// approvalSpent reports whether a single-use grant looks already burned. It is a PEEK — it
// records nothing — because it runs during selection, before the ceiling and the quota
// commits have had their chance to refuse the call, and a check that spent the grant would
// consume a human approval for a call that never ran.
//
// It is therefore advisory: two concurrent callers can both peek clean. That race is closed at
// the commit, where burnApproval's atomic admission lets exactly one through and the loser
// hard-denies. The error is NOT swallowed — a fault means the proxy cannot tell a fresh
// approval from a spent one, and treating that as fresh would make an unreachable backend the
// way to replay every one-shot grant in a token.
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

// UsableDeclassifyApproval reports whether any of the presented approvals both COVERS
// (labels + target) and is still LIVE (not a burned single-use grant) — the same two-part
// test checkDeclassify applies when it selects one.
//
// It is exported for the wrapping-PDP hardening path, which has to answer "would the
// declassification have been authorized?" without running a decision. That path used the
// scope-only test, so a burned grant read as authorization and left a wrapping layer's SOFT
// refusal intact for an --audit route to downgrade and forward — while the same call without
// the wrapper met the hard `approval_consumed` escalation. Adding a token must never make the
// proxy allow more, so the two paths ask the same question here.
func (e *Engine) UsableDeclassifyApproval(ctx context.Context, approvals []capability.DeclassifyApproval, target string, want []string) (bool, error) {
	// Exported, so a caller can reach it with no engine configured. Report the fault rather
	// than dereferencing: every caller treats an error as "cannot tell live from spent" and
	// fails closed, which is the right reading of "there is no ledger here".
	if e == nil {
		return false, fmt.Errorf("no enforcement engine configured, so a single-use declassify approval cannot be checked")
	}
	sel, err := e.selectLiveApproval(ctx, approvals, target, want)
	if err != nil {
		return false, err
	}
	return sel.approval != nil, nil
}

// approvalSelection is what one walk of the covering grants found: the first still-live grant
// (nil when every covering grant is spent, or none covers), its ledger member, and how many
// covering grants were passed over as already burned — the count that separates "no approval
// covers this" from "the approval was real and has been spent", which are different operator
// actions.
type approvalSelection struct {
	approval *capability.DeclassifyApproval
	ledgerID string
	covering []*capability.DeclassifyApproval
	consumed int
}

// selectLiveApproval is the ONE walk over the covering grants, shared by the decision path
// (checkDeclassify, which needs the selected grant to stamp and burn) and by the wrapping-PDP
// hardening path (UsableDeclassifyApproval, which needs only whether one exists). The two must
// agree — a hardening check looser than the decision means adding a token makes the proxy allow
// more — and a second copy of "walk, peek, take the first live one" is exactly where that
// divergence had already happened once.
//
// It walks rather than taking the first covering grant, because scope is not the whole test: a
// single-use grant already burned covers the call on paper and must be passed over in favour of
// a later grant that is still live. One Peek per covering grant, bounded by
// MaxDeclassifyApprovals.
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
func (e *Engine) checkDeclassify(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, carriedLabels []string, requestID, now string) (declassifyOutcome, *capability.EnforceResponse) {
	if e.skipFlow {
		// An engine built WithoutFlowLabels holds no flow state, so it can neither read
		// what a session carries nor clear it. Returning the zero outcome means such a
		// constraint neither escalates nor pretends to declassify; the config layer keeps
		// this unreachable in-tree by counting declassify as flow-relevant, and this is
		// the same defense in depth its two siblings carry.
		return declassifyOutcome{}, nil
	}
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

	// The first still-live grant among those whose scope covers this call, through the walk
	// UsableDeclassifyApproval shares — so the hardening path cannot answer this question more
	// loosely than the decision does.
	sel, err := e.selectLiveApproval(ctx, req.DeclassifyApprovals, target, want)
	if err != nil {
		// The ledger is unreadable, so "already used" cannot be distinguished from "never
		// used". Escalating is the only answer that does not make an unreachable backend the
		// way to replay every one-shot grant in a token — the same fail-closed posture every
		// other flow-state read fault takes.
		return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want, nil,
			fmt.Sprintf("single-use declassify approval state could not be read: %v", err),
			"ledger_unavailable")
	}
	approval, ledgerID, covering, consumed := sel.approval, sel.ledgerID, sel.covering, sel.consumed
	if approval == nil {
		if consumed > 0 {
			// A distinct reason from "no approval", because it is a distinct operator
			// action: the grant was real and scoped correctly, and it has been spent. Told
			// "no approval covers this", an operator re-checks the scope they already got
			// right; told "consumed", they mint a new one. The approval id is safe to name
			// (it is the control plane's own record identifier, and it is already stamped
			// on the allow that spent it) and is what joins this refusal to that record.
			//
			// Spelled consumed_approval_id rather than approval_id: the latter is a
			// top-level SIGNED field on the allow that performed a declassification, and
			// reusing the name inside a refusal's details would put the same key in two
			// places with two provenances on one tape.
			return declassifyOutcome{}, e.declassifyRefusal(requestID, now, carriedLabels, want,
				map[string]interface{}{"approvals_consumed": consumed, "consumed_approval_id": covering[0].ID},
				fmt.Sprintf("the human approval covering flow label(s) %v at %s is single-use and has already been consumed; a new approval is required", want, target),
				"approval_consumed")
		}
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
		LedgerID:   ledgerID,
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
	resp.CarriedLabels = carriedLabels
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
// approval names. It delegates to resolveRequestTarget — the ONE resolver
// FindMatchingCapability uses to select the constraint in the first place — so the target
// an approval is scoped against is by construction the target that selected the entry.
//
// A second, hand-rolled resolver here diverged from it in three ways that each made a
// correctly-written approval unsatisfiable: it preferred req.Target wholesale rather than
// per-field, it did not trim a padded name, and it rejected an unrecognized prefix where
// splitEnginePrefix defaults one to the tool namespace. Every one of those produced a
// permanent escalation on a grant the operator had scoped correctly.
//
// An empty bare name yields "", which checkDeclassify turns into a refusal — never into an
// approval that matches everything.
func canonicalApprovalTarget(req *capability.EnforceRequest) string {
	reqType, bare := resolveRequestTarget(req)
	if bare == "" || reqType == "" {
		return ""
	}
	return reqType + ":" + bare
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
//
// present is the set as it stands AFTER this call's own labelOutput write, not the pre-call
// snapshot. The distinction only bites for a constraint carrying both directives — which
// the loader refuses and the PDP no longer synthesizes, but which an embedder of this
// package can still build — and getting it wrong there meant the clear could not remove a
// label the same call had just asserted, i.e. assert silently won over clear. Ordering the
// commit add-then-clear and reading the post-add state is what makes "clear wins"
// deterministic rather than a claim the code did not honor.
func (e *Engine) clearLabels(ctx context.Context, req *capability.EnforceRequest, out declassifyOutcome, present []string) ([]string, error) {
	if len(out.Labels) == 0 || e.skipFlow {
		// skipFlow means the engine holds no flow state at all, so there is nothing to
		// clear. It short-circuits here for the same defense-in-depth reason recordLabels
		// and peekSessionLabels do: the caller derives flow-relevance separately, and a
		// clear that silently removed nothing would leave the operator believing a label
		// was dropped.
		return nil, nil
	}
	if e.flowStore == nil {
		return nil, fmt.Errorf("flow label store not configured; flow labels cannot be cleared")
	}
	if req.SessionID == "" {
		return nil, fmt.Errorf("sessionId is required to clear flow labels")
	}
	held := make(map[string]bool, len(present))
	for _, l := range present {
		held[l] = true
	}
	var removed []string
	for _, l := range out.Labels {
		if held[l] {
			removed = append(removed, l)
		}
	}
	if len(removed) == 0 {
		return nil, nil
	}
	if err := e.flowStore.Remove(ctx, e.flowKey(req), removed...); err != nil {
		return nil, err
	}
	return removed, nil
}

// burnApproval spends a single-use grant: one atomic admission against the grant's one-slot
// bucket. It is the ONLY authoritative test — approvalSpent's peek is advisory, so two
// concurrent callers can both reach here believing the grant is live, and exactly one of them
// is admitted. The loser gets admitted=false and an error, which the caller turns into a hard
// deny: over-refusing one of two racing calls is the only outcome that keeps "once" meaning
// once. A standing grant (empty ledgerID) burns nothing and costs no round trip.
//
// It runs on EVERY commit of an approved single-use declassification, including one whose
// clear turns out to be a no-op because the anchor was not carrying the labels. That is the
// property, not an oversight: the approval is what turned an escalation into an allow, so it
// was spent whether or not a label moved. Burning only on a clear that changed something
// would make the grant trivially replayable by ordering — present it once while clean (no
// burn), acquire the taint, present it again to the clear that matters.
//
// There is deliberately no un-burn. The counter has no delete, and that is the right shape
// here: a call refused AFTER its burn leaves the grant spent, which over-refuses (the operator
// mints another approval) rather than handing a use back. The un-burn this replaced was a
// fail-OPEN on one path — a soft antecedent-fault deny is downgraded and FORWARDED by an
// --audit route, so the action ran while the grant was handed back.
//
// It is also NOT skipped under SkipQuota, which makes it the one thing on the commit path that
// an --audit route still spends. That asymmetry is deliberate and follows from what observe
// mode actually does: a maxCalls bucket is skipped because observe consumes no BUDGET, but the
// label clear this grant authorizes is performed for real on an observe route (flow state has
// to stay accurate or the predictions are worthless). Skipping only the burn would leave a real
// clear behind a grant still marked live — the replay this ledger exists to close, reachable by
// putting the route in observe mode. The burn and the clear are one transaction; observe either
// does both or neither, and it does both.
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
