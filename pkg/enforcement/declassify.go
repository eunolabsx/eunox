// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"
	"time"

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

// There is deliberately no exported "is there a usable approval for this?" predicate.
//
// One existed (UsableDeclassifyApproval), for the wrapping-PDP hardening path, and answering
// only THAT question is what left the rest of the answer to be hand-rolled at the call site —
// which is where the caller re-derived the canonical approval target without trimming a padded
// name, and built its own refusal without CarriedLabels. Scoping a seam to the boolean and
// leaving the target resolution and the record shape to the caller reproduces, one layer up,
// exactly the divergence canonicalApprovalTarget was centralized to prevent.
//
// DeclassifyVerdictFor is the seam instead: it answers the whole question — resolve the target,
// select a live grant, and build the refusal — through the same checkDeclassify the decision
// path runs, so the composed verdict cannot be looser than, or shaped differently from, the
// unwrapped one. A caller that needs only the boolean can test its result for nil.

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

// selectLiveApproval is the ONE walk over the covering grants. checkDeclassify is its only
// caller now, and so — through checkDeclassify — is the wrapping-PDP hardening path, which
// reaches it via DeclassifyVerdictFor rather than through a predicate of its own. A hardening
// check looser than the decision means adding a token makes the proxy allow more, and a second
// copy of "walk, peek, take the first live one" is exactly where that divergence had already
// happened once.
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

	// The first still-live grant among those whose scope covers this call. The wrapping-PDP
	// hardening path reaches this same walk through DeclassifyVerdictFor, so it cannot answer
	// the question more loosely than the decision does.
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

// DeclassifyVerdictFor answers ONE question — "would this constraint's declassification
// have been authorized?" — for a constraint that has already been selected, WITHOUT
// evaluating a single condition and WITHOUT committing any state. It returns the refusal
// checkDeclassify would produce (an ESCALATION_REQUIRED escalate), or nil when the
// constraint clears nothing, the engine holds no flow state, or the request carries a live
// covering approval.
//
// It is the declassify twin of CeilingVerdictFor and exists for the same COMPOSED case: a
// PDP wrapping this engine's PDP — the JWT layer — can refuse a call on its own terms and
// short-circuit above the inner PDP, so evaluateMatched never runs and checkDeclassify
// never fires. The call is still refused, but that refusal is a SOFT deny an --audit route
// downgrades to a FORWARD, which would perform the action AND leave the taint the policy
// says the action clears. Adding a token must never make the proxy allow more.
//
// What makes this a SEAM rather than a convenience is that the wrapping path used to
// answer the question itself, and a hand-rolled answer diverges. It resolved the approval
// target as `string(target.Type) + ":" + target.Name` — reintroducing one of the three
// divergences canonicalApprovalTarget's doc records as already paid for, so a request
// whose target name carried surrounding whitespace resolved to a target no
// already-trimmed grant could ever match, and a correctly-scoped approval became a
// permanent, unsatisfiable escalation. It also built its own DenialInfo and omitted
// CarriedLabels, so the same logical refusal had two record shapes depending on whether a
// JWT layer wrapped the call — and the JWT-wrapped one dropped the field an approver acts
// on first. Routing through checkDeclassify gives one canonical-target resolver, one
// refusal builder, and one record shape, and means a future change to checkDeclassify
// needs no hand-mirroring.
//
// Non-committing is a property of checkDeclassify itself, not something reproduced here:
// it runs before any commit precisely so an unapproved declassification spends no quota
// slot, writes no antecedent, and changes no label. Its only backend touch is the ledger
// PEEK behind selectLiveApproval, which records nothing.
//
// Like CeilingVerdictFor, the caller may use this ONLY to HARDEN a refusal — never to
// produce an allow, and never on a path that would otherwise forward. When a condition
// would have denied first, the full path reports that condition and never reaches the
// declassify check, while this reports the declassification; the call is refused either
// way, so the difference is a harder refusal rather than a wrong one.
//
// The flow-label peek is a pure Get and its failure is swallowed, matching
// CeilingVerdictFor: this is asked about a call that is ALREADY refused, so a label-store
// fault must not weaken (or replace) the refusal being hardened. The peeked set is only
// evidence on the record; the authorization test itself does not read it.
func (e *Engine) DeclassifyVerdictFor(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) *capability.EnforceResponse {
	// e == nil first, and it is not defensive noise. This is an exported method on an
	// exported type whose fields are unexported, so an embedder legitimately holds an
	// unwired *Engine — and the predicate this replaced (UsableDeclassifyApproval) guarded
	// exactly that, with a test pinning it. Dereferencing instead would panic a request
	// goroutine on a refusal path, which is fail-open-via-crash: the connection drops with
	// no denial and no audit record for the refusal being hardened. The sibling
	// CommitDeclassification guards the same way for the same reason. nil means "no
	// engine, so no checkDeclassify on the unwrapped path either" — there is no verdict
	// this could be weaker than.
	if e == nil || req == nil || matched == nil || e.skipFlow {
		return nil
	}
	if len(capability.DeclassifyLabelsOf(matched)) == 0 {
		return nil
	}
	requestID := NewRequestID()
	now := e.clock.Now().UTC().Format(time.RFC3339Nano)

	var carriedLabels []string
	if labels, err := e.peekSessionLabels(ctx, req); err == nil {
		carriedLabels = labels
	}
	// The outcome is discarded on purpose: it describes what a COMMIT would apply, and
	// this path commits nothing. Only the refusal is the answer.
	_, refusal := e.checkDeclassify(ctx, req, matched, carriedLabels, requestID, now)
	return refusal
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

// burnApproval spends a single-use grant: one atomic admission against the grant's one-slot
// bucket. It is the ONLY authoritative test — approvalSpent's peek is advisory, so two
// concurrent callers can both reach here believing the grant is live, and exactly one of them
// is admitted. The loser gets admitted=false and an error, which the caller turns into a hard
// deny: over-refusing one of two racing calls is the only outcome that keeps "once" meaning
// once. A standing grant (empty ledgerID) burns nothing and costs no round trip.
//
// It runs inside the DECISION's commit — not with the deferred clear it authorizes — because
// it is the atomic test that makes "once" mean once, and two callers must not both be able to
// reach it. That leaves it possible for a grant to be spent by a call whose clear is never
// committed (a refusal below the decision, a fault at the commit); the response carries a
// SpentApprovalID for exactly that case, so the tape names the grant an operator must replace.
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

// declassifyRecordFailureDenial is the fail-closed response when the declassify leg of the
// source commit faulted. It is a HARD deny: the soft antecedent-fault deny beside it is
// downgraded and FORWARDED by an --audit route, and forwarding a call whose one-shot
// approval was just spent runs the action while the operator's single approval is gone with
// nothing to show for it.
//
// Nothing was cleared on this path — the clear is the caller's second phase and never ran —
// so the session's flow state is exactly as accurate as before the call. What may have
// changed is the LEDGER: spentApprovalID names a single-use grant this commit burned before
// faulting, empty when nothing was spent. It rides the refusal because this is the only
// record the grant will ever appear on, and an operator reconciling one-shot approvals would
// otherwise believe it was still live.
// The id rides the RESPONSE field rather than being stamped into details here: the detail
// key belongs to the audit layer, and one producer of it — the transport, which stamps it
// identically on the allow and on every refusal — is what keeps a single spelling and a
// single provenance on the tape.
func declassifyRecordFailureDenial(requestID, now string, auditOnly bool, spentApprovalID string) capability.EnforceResponse {
	resp := denyResponse(requestID, now, auditOnly, nil, capability.DenialInfo{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: declassifyConditionType,
		Message:       "the declassification leg of this call's state commit failed; the approved clear was not applied and the call is refused",
		HardDeny:      true,
		Details:       map[string]interface{}{"flow": true, "phase": "record"},
	})
	resp.SpentApprovalID = spentApprovalID
	return resp
}
