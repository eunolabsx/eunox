// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"errors"
	"fmt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Flow labels are per-session provenance state in the FlowLabelStore seam (distinct from the
// CallCounter): a labelOutput directive on an allowed source call Adds labels to the session's
// accumulated SET, and a flowLabel condition at a sink Gets the set and denies when a class
// outside its Allow is present. A SET, not a count — the store holds one entry per
// (session,label).
//
// Unlike sequenceBlock's 24h sliding window, flow state has NO wall-clock expiry: it's a
// monotonic, session-lifetime fact, reclaimed only by the transport's Clear on session end (a
// windowed marker would age a taint out mid-session, a fail-open the "for all flows" claim
// can't tolerate).
//
// Under WithTaskAnchoredState the same set is keyed on the validated task instead, so taint
// crosses a hop between enforcement points rather than restarting clean. See anchor.go.

// flowLabelVocab is the native flow-label vocabulary, cached once from
// capability.FlowLabelVocabulary so the subset check and the accumulated-set peek do not
// re-allocate it per request. Read-only.
var flowLabelVocab = capability.FlowLabelVocabulary()

// flowKey builds the flow-label store key for a request's anchor. No per-label component: the
// store holds the whole accumulated SET under one key (Add unions, Get returns the set).
func (e *Engine) flowKey(req *capability.EnforceRequest) string {
	return e.anchoredKey("flow", req)
}

// flowSessionKey is the SESSION-anchored flow key, for the transport's teardown Clear — the
// one caller with a session id and nothing else. Equals flowKey without task anchoring; under
// task anchoring it addresses only the key a task-less request on that session would have
// written, which is exactly what teardown should reclaim.
func (e *Engine) flowSessionKey(sessionID string) string {
	return compositeCounterKey("flow", e.counterKeyNamespace, sessionID)
}

// handleFlowLabel enforces the sink half of information-flow control: denies when the
// session's accumulated flow labels are not a subset of the condition's Allow set. Reads only
// eunox's own label state, never the payload, so it is deterministic with no model in the
// decision path.
//
// Reports ALL present-and-not-allowed classes, not just the first, so an integrity signal is
// never hidden behind a benign one. An empty Allow admits only an unlabeled flow; the closed
// vocabulary means a label the sink didn't enumerate is denied by construction.
//
// Prefers the engine's already-peeked snapshot (threaded via ctx) over its own Peek, keeping
// the audited carried_labels and the enforced set one atomic snapshot.
//
// Concurrency: the source's label write and this sink's read are two independent requests. The
// transport serializes the per-session decision phase for a flow-relevant session, so a source
// read commits its label before a later sink read runs, deterministically. A direct engine
// caller that doesn't serialize owns that ordering itself, as with sequenceBlock.
func (e *Engine) handleFlowLabel(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	fl, condErr := castCondition[capability.FlowLabelCondition](cond)
	if condErr != nil {
		return condErr
	}
	if fl == nil {
		// Defense in depth against a typed-nil *FlowLabelCondition (runConditions already
		// rejects this before dispatch): an unevaluable condition must fail closed, never
		// panic.
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       "flowLabel condition is nil and cannot be evaluated",
		}
	}

	// Compose the delegation chain's allow-set cap into the condition's own: intersection is
	// the only safe composition, since the sink rule is "present and not allowed => deny", so
	// a hop's cap can only remove entries. An empty capped set is the full quarantine.
	effectiveAllow := delegatedAllowLabels(fl.Allow, req.Delegation)

	// Defense in depth: the loader rejects an unknown label, but a programmatically built
	// condition can carry one — surfaced against the AUTHORED set so a manifest typo is still
	// caught even if a delegation cap happened to remove the entry.
	for _, l := range fl.Allow {
		if !capability.IsFlowLabel(l) {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeFlowLabel,
				Message:       fmt.Sprintf("flowLabel 'allow' contains unknown label %q; valid native labels are %v", l, flowLabelVocab),
			}
		}
	}
	allow := make(map[string]bool, len(effectiveAllow))
	for _, l := range effectiveAllow {
		allow[l] = true
	}

	// Fail closed when label state can't be read: no store, or no session (which would merge
	// state across anonymous callers). Runs before the threaded set is used so a nil threaded
	// set can't be mistaken for "clean context".
	if e.flowStore == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       "flow-label store not configured; flow-label state is unavailable",
		}
	}
	if req.SessionID == "" {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       "sessionId is required for flowLabel condition",
		}
	}

	// Prefer the engine's already-peeked snapshot (a real Peek error already made the engine
	// fail closed before this handler runs, so a threaded set is trustworthy); fall back to
	// peekSessionLabels for a direct caller that didn't thread one.
	present, threaded := carriedLabelsFromContext(ctx)
	if !threaded {
		peeked, err := e.peekSessionLabels(ctx, req)
		if err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeFlowLabel,
				Message:       fmt.Sprintf("flow-label state lookup failed: %v", err),
			}
		}
		present = peeked
	}

	// Union in a cooperating client's per-call attribution — one-directional by design: a
	// client may declare MORE labels than the session join knew about, never fewer, so an
	// untrusted declaration can only produce more denials and needs no trust decision. Used
	// for THIS check only, never written into session state.
	declared := capability.NormalizeDeclaredLabels(req.DeclaredLabels)
	present = unionLabels(present, declared)

	// Union in the taint every hop of the delegation chain forces onto this delegate's calls
	// — the same one-directional rule as the client attribution above, but different
	// provenance: this is what the delegators DECIDED this delegate is, on a verified token
	// the delegate can't edit, vs. a cooperating agent describing its own inputs. Used for
	// THIS check only, never persisted.
	forced := req.Delegation.ForcedLabels()
	present = unionLabels(present, forced)

	// blocked = present labels not permitted here. present is vocabulary-ordered, so blocked
	// is too.
	var blocked []string
	for _, label := range present {
		if !allow[label] {
			blocked = append(blocked, label)
		}
	}
	if len(blocked) > 0 {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       fmt.Sprintf("flow label(s) %v present in this session but not permitted at this sink", blocked),
			Details: func() map[string]interface{} {
				d := map[string]interface{}{
					// Distinguishes a source->sink flow denial from a plain
					// capability/argument denial.
					capability.FlowAuditDetailKey: true,
					"blockedLabel":                blocked[len(blocked)-1],
					"blockedLabels":               blocked,
					// The EFFECTIVE allow-set (post-delegation-cap), not the authored one —
					// recording the manifest's own list would send an operator to widen a
					// rule that never refused the call.
					"allowLabels": effectiveAllow,
				}
				if len(declared) > 0 {
					// Separate from the proxy's observed state, so an auditor can tell what
					// was OBSERVED from what the client claimed.
					d["declared_labels"] = declared
				}
				if len(forced) > 0 {
					// Separate again: an auditor must be able to tell observed,
					// client-declared, and delegation-imposed taint apart.
					d["delegated_labels"] = forced
				}
				return d
			}(),
		}
	}
	return nil
}

// unionLabels merges declared into present, deduplicated, in fixed vocabulary order. Returns
// present unchanged when there's nothing to add.
//
// Delegates to capability.NormalizeDeclaredLabels rather than a second dedupe-and-order copy,
// since the ordering here is what both the subset check and the audit record rely on — a
// divergence wouldn't show up as an error, only as a differently-ordered label set on the tape.
func unionLabels(present, declared []string) []string {
	if len(declared) == 0 {
		return present
	}
	all := make([]string, 0, len(present)+len(declared))
	all = append(all, present...)
	all = append(all, declared...)
	return capability.NormalizeDeclaredLabels(all)
}

// peekSessionLabels reports the session's accumulated flow-label set (vocabulary order) for
// the audit record's carried_labels and handleFlowLabel's threaded snapshot. Fails closed on
// a store error rather than dropping it silently, so a source-only constraint can't
// under-report the accumulated set on the signed tape.
//
// A stored label OUTSIDE the closed vocabulary is an ERROR, not something to reorder past:
// dropping it would silently suppress a denial the sink rule ("present and not allowed =>
// deny") depends on — e.g. two proxy versions with different vocabularies sharing one Redis
// flow store. Every sibling path already fails closed on an unknown label; this makes the read
// agree with them, over-denying during a mixed-version rollout rather than enforcing against a
// blind spot.
func (e *Engine) peekSessionLabels(ctx context.Context, req *capability.EnforceRequest) ([]string, error) {
	if e.skipFlow || e.flowStore == nil || req.SessionID == "" {
		// skipFlow short-circuits here too, mirroring evaluateMatched's own gate, so the
		// engine stays consistent even if a caller derives flow-relevance independently
		// (e.g. the PDP audit path via ConstraintHasFlow alone).
		return nil, nil
	}
	present, err := e.flowStore.Get(ctx, e.flowKey(req))
	if err != nil {
		return nil, err
	}
	if len(present) == 0 {
		return nil, nil
	}
	inSet := make(map[string]bool, len(present))
	for _, l := range present {
		if !capability.IsFlowLabel(l) {
			return nil, fmt.Errorf("session flow-label store holds %q, which is not in this build's flow-label vocabulary; refusing to evaluate an information-flow policy against a label set this build cannot interpret", l)
		}
		inSet[l] = true
	}
	var out []string
	for _, label := range flowLabelVocab {
		if inSet[label] {
			out = append(out, label)
		}
	}
	return out, nil
}

// PeekSessionLabels is the exported form of peekSessionLabels, for the audit-mode antecedent
// path to back-fill carried_labels onto a downgraded-and-forwarded deny that never went
// through evaluateMatched's own peek.
func (e *Engine) PeekSessionLabels(ctx context.Context, req *capability.EnforceRequest) ([]string, error) {
	return e.peekSessionLabels(ctx, req)
}

// recordLabels performs the source half of information-flow control: unions an allowed call's
// labelOutput labels into the session's accumulated set (one atomic Add), returning the
// recorded labels (canonical order) for the audit record's labels_out field.
//
// Runs regardless of audit/observe mode, like sequenceBlock's antecedent recording: flow
// provenance is history that must stay accurate for a later ENFORCED sink — unlike maxCalls,
// which skips its commit under --audit because observing a quota would consume it.
//
// A constraint with labelOutput but no session or store can't persist the label, which would
// let a later sink Get empty and fail OPEN; returns an error instead and the caller denies
// fail-closed.
//
// The write is a single Add of the whole set, so there's no mid-write partial commit to order
// defensively (unlike the old per-label counter loop).
func (e *Engine) recordLabels(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) ([]string, error) {
	if e.skipFlow {
		// Mirrors peekSessionLabels; defense in depth since skipFlow implies no labelOutput
		// to record anyway.
		return nil, nil
	}
	set := map[string]bool{}
	for _, dir := range matched.Directives {
		lo, ok := capability.AsValueOrPointer[capability.LabelOutputDirective](dir)
		if !ok || lo == nil {
			// !ok: not a labelOutput. lo == nil: a typed-nil pointer AsValueOrPointer
			// returns as (nil, true); dereferencing would panic.
			continue
		}
		for _, l := range lo.Labels {
			if !capability.IsFlowLabel(l) {
				// Fail closed rather than silently drop, matching handleFlowLabel's Allow
				// check.
				return nil, fmt.Errorf("labelOutput contains unknown flow label %q; valid native labels are %v", l, flowLabelVocab)
			}
			set[l] = true
		}
	}
	if len(set) == 0 {
		return nil, nil
	}
	if e.flowStore == nil {
		return nil, fmt.Errorf("flow label store not configured; flow labels cannot be recorded")
	}
	if req.SessionID == "" {
		return nil, fmt.Errorf("sessionId is required to record flow labels")
	}
	// Canonical vocabulary order for labels_out; the store's Add commits the whole set
	// atomically, so order matters only for the deterministic audit field.
	out := make([]string, 0, len(set))
	for _, label := range flowLabelVocab {
		if set[label] {
			out = append(out, label)
		}
	}
	if err := e.flowStore.Add(ctx, e.flowKey(req), out...); err != nil {
		return nil, err
	}
	return out, nil
}

// RecordLabels is the exported form of recordLabels for the audit-mode antecedent path: when
// a downgraded audit-mode source's read is forwarded, its labelOutput labels must still be
// recorded (or a later ENFORCED sink Gets empty and fails open) and surfaced as labels_out.
func (e *Engine) RecordLabels(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) ([]string, error) {
	return e.recordLabels(ctx, req, matched)
}

// intersectLabels returns the members of want present in held, in want's order.
//
// Bounds an approved declassification's clear to the taint the decision actually OBSERVED —
// intersecting at commit time instead, against whatever the anchor holds a round trip later,
// would silently widen the clear to cover a label a concurrent source added in between.
func intersectLabels(want, held []string) []string {
	if len(want) == 0 || len(held) == 0 {
		return nil
	}
	var out []string
	for _, w := range want {
		for _, h := range held {
			if w == h {
				out = append(out, w)
				break
			}
		}
	}
	return out
}

// SourceCommitError classifies which leg of the atomic source-call commit (recordSourceCall)
// faulted, so the caller builds the matching deny: a flow-label write fault (Flow=true) is
// HARD (an unlabeled forward would fail a later sink open), a declassify leg fault
// (Declassify=true) is HARD via declassifyRecordFailureDenial, a sequenceBlock fault (both
// false) is the plain antecedent deny.
//
// The declassify leg's fault is a BURN fault (a CallCounter write), not a clear fault — the
// clear is phase two and doesn't run inside this commit. It sets Flow too, so a caller
// checking Flow alone (the audit-mode antecedent path, which never declassifies) still routes
// to a hard deny; Declassify is checked first so the two never disagree.
type SourceCommitError struct {
	Err        error
	Flow       bool
	Declassify bool
	// SpentApprovalID names a single-use grant this commit BURNED before faulting, empty if
	// nothing was spent — without it, a grant spent by a call that never ran would reach the
	// tape named by nothing at all.
	SpentApprovalID string
}

// Error implements error.
func (e *SourceCommitError) Error() string { return e.Err.Error() }

// recordSourceCall commits an allowed call's flow labels and its sequenceBlock antecedent as
// a single all-or-nothing unit, closing the cross-namespace half-commit: the two live in
// disjoint backends (FlowLabelStore "flow:", CallCounter "seq:"), so a fault between the
// writes could otherwise strand one.
//
// Writes flow FIRST (the store supports targeted Remove), then the antecedent; if the
// antecedent write faults, rolls back the flow labels THIS call added so a hard-denied call
// leaves NEITHER committed. A transport serializing its decision phase makes the rollback
// race-free; the engine itself takes no such guarantee for granted (see rollbackLabels).
//
// An APPROVED declassification contributes only the BURN of a single-use grant here — the
// label clear is deferred to CommitDeclassification, run after the call actually completes
// (see EnforceResponse.Declassification: a clear applied here would be invisible to every
// concurrent decision for the whole upstream round trip). labelOutput's add stays here for the
// mirror reason: a call that taints and then fails should leave EXTRA taint, which
// over-blocks rather than under-blocks.
//
// Every write fails closed on its own fault, mapped to a SourceCommitError. recordLabels and
// RecordSessionCall each self-guard when the policy doesn't need them, so a flow-only or
// seq-only policy does exactly one write and needs no rollback.
func (e *Engine) recordSourceCall(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, flowRelevant bool, carriedLabels []string, decl declassifyOutcome) (labelsOut []string, cerr *SourceCommitError) {
	if e.anchorUnresolved(req) {
		// evaluateMatched already refuses this well before the allow tail; this is a
		// backstop, and also the entry point the PDP's audit-mode antecedent path uses for
		// a deny that never ran the decision at all. Falling back to session keying here
		// would silently write the split anchorUnresolved exists to refuse.
		return nil, &SourceCommitError{Err: errUnanchorableStateWrite, Flow: flowRelevant}
	}
	var added []string
	if flowRelevant {
		var err error
		labelsOut, err = e.recordLabels(ctx, req, matched)
		if err != nil {
			return nil, &SourceCommitError{Err: err, Flow: true}
		}
		added = labelsAdded(labelsOut, carriedLabels)
	}
	if len(decl.Labels) > 0 {
		// A standing grant burns nothing; a single-use one is spent here atomically, and the
		// loser of a concurrent race hard-denies.
		if err := e.burnApproval(ctx, decl.LedgerID); err != nil {
			e.rollbackLabels(ctx, req, added)
			return nil, &SourceCommitError{Err: err, Flow: true, Declassify: true}
		}
	}
	if err := e.RecordSessionCall(ctx, req); err != nil {
		// Take the label add back out so the hard-denied call leaves no taint. Best-effort —
		// a rollback fault leaves a stranded label, the accepted fail-closed residual
		// (over-blocks, never leaks). Runs before the branch below since both arms need it.
		e.rollbackLabels(ctx, req, added)
		if decl.LedgerID != "" {
			// A HARD deny: the plain antecedent-fault deny is SOFT (downgradable by
			// --audit), and forwarding a call whose one-shot approval was just spent burns
			// the approval for nothing.
			return nil, &SourceCommitError{Err: err, Flow: true, Declassify: true, SpentApprovalID: decl.ApprovalID}
		}
		return nil, &SourceCommitError{Err: err, Flow: false}
	}
	return labelsOut, nil
}

// errUnanchorableStateWrite is the fault recordSourceCall reports for a request this engine
// can't anchor (see anchorUnresolved). Travels as a SourceCommitError so every caller maps it
// to a hard, non-downgradable deny — an --audit route forwarding the call is exactly how the
// un-anchored write would happen.
var errUnanchorableStateWrite = errors.New("this route anchors enforcement state on the task, but the presented token carries no mcp.task_id; refusing to record this call against a second, session-keyed bucket (fail closed)")

// RecordSourceCall is the exported form of recordSourceCall for the audit-mode antecedent
// path: when a downgraded audit-mode source's deny is forwarded, its flow labels and
// sequenceBlock antecedent must still be recorded atomically and surfaced on the forwarded
// record.
//
// Commits NO declassification: that path forwards a call whose verdict was a DENY, and the
// approval check that authorizes a clear runs only on the allow tail — a downgraded observe
// deny must never untaint a session.
func (e *Engine) RecordSourceCall(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, flowRelevant bool, carriedLabels []string) ([]string, *SourceCommitError) {
	return e.recordSourceCall(ctx, req, matched, flowRelevant, carriedLabels, declassifyOutcome{})
}

// labelsAdded returns the labels in out not already in the pre-call carried set — the ones
// this call's Add introduced — so a rollback preserves a label a prior source already
// asserted.
func labelsAdded(out, carried []string) []string {
	if len(out) == 0 {
		return nil
	}
	var added []string
	for _, l := range out {
		pre := false
		for _, c := range carried {
			if c == l {
				pre = true
				break
			}
		}
		if !pre {
			added = append(added, l)
		}
	}
	return added
}

// rollbackLabels best-effort removes the labels a faulted source call added, so a hard-denied
// call leaves no flow taint. No-op for a nil store, empty session, or empty set; a Remove
// fault is swallowed (the fail-closed residual — a stranded label over-blocks, never leaks).
func (e *Engine) rollbackLabels(ctx context.Context, req *capability.EnforceRequest, added []string) {
	if e.flowStore == nil || req.SessionID == "" || len(added) == 0 {
		return
	}
	if e.anchoredOnTask(req) {
		// Not for a task-keyed request: nothing the engine can see guarantees no other
		// writer touched the task's set between the pre-call snapshot and here, so a
		// compensating Remove could delete a label a concurrent writer legitimately just
		// added — a fail-open on the same "for all flows" claim the anchor exists to extend.
		// Stranding this call's own label instead over-blocks, the direction the rollback
		// path already accepts elsewhere.
		//
		// The in-tree transports DO serialize a task's decisions in-process, closing the
		// window for one proxy — but this is an exported package an embedder can drive with
		// no serialization at all, and two eunox instances sharing one Redis backend hold
		// independent turns for the same task regardless. A session-keyed token-less caller
		// has no such hazard: no other caller can write to its bucket at all.
		return
	}
	_ = e.flowStore.Remove(ctx, e.flowKey(req), added...)
}

// CommitDeclassification applies an approved declassification's label clear, for a call the
// decision AUTHORIZED and the caller has now actually performed — the second half of a
// two-phase clear (the decision authorizes and burns a single-use grant; this removes the
// labels once the sanitizing call has run).
//
// The split matters under concurrency: clearing inside the decision would leave the label
// absent for the whole upstream round trip (unbounded when --upstream-timeout is 0), letting a
// concurrent sink the taint existed to stop be allowed and forwarded before the sanitizing
// call even returned. Deferring removes the window rather than narrowing it, with no
// dependency on any serialization — which is what makes it hold for a second eunox instance
// on shared Redis, or an embedder with no turn of its own.
//
// It is also why nothing above the engine needs an undo any more: every refusal below the
// decision now simply never calls this, so there's nothing to put back.
//
// A caller that never commits (crash, store fault, forgetful embedder) leaves the session as
// tainted as it found it — over-blocking, resolved with another approval, the fail-closed
// mirror of the burn's own accepted over-refusal.
//
// Clears decl's authorized set and NOTHING else — that set was already intersected against
// what the anchor was carrying INSIDE the decision's critical section, and this does NOT
// re-read the anchor. Re-reading would widen the clear to whatever the anchor holds a round
// trip later, laundering a source read decided while the sanitizing call was still in flight
// through an approval granted before that read existed — a set store can't tell one occurrence
// of a label from another, so nothing downstream could catch it.
//
// Takes the decision's HANDLE, not a label slice: the old []string signature let any embedder
// holding an *Engine clear any label with no approval, no burn, no escalation, nothing on the
// tape. A handle is minted only by an authorizing decision, carries its set unexported, and is
// single-use, so a wider clear can't be expressed and an authorization can't be replayed.
//
// A nil handle clears nothing without error — the no-declassification case, and also a handle
// whose intersection came back empty.
//
// Anchoring follows the request (flowKey): the caller MUST hand a context that still carries
// the request's validated claims, or the anchor resolves the SESSION key instead of the task
// key — clearing the wrong bucket and reporting success. Detach cancellation only
// (context.WithoutCancel), never the values.
func (e *Engine) CommitDeclassification(ctx context.Context, req *capability.EnforceRequest, decl *capability.Declassification) (cleared []string, err error) {
	if !decl.PendingClear() {
		return nil, nil
	}
	if e == nil || e.skipFlow || e.flowStore == nil || req == nil || req.SessionID == "" {
		// Reachable on an engine holding no flow state, or a PDP whose commit chain is a
		// no-op — none of those may report a clear. Checked BEFORE the claim, so an engine
		// that can't clear doesn't consume the handle, or a correctly-wired retry would
		// find it already spent.
		return nil, errNoFlowStateToClear
	}
	// One authorization, one clear — reporting a double-commit as a caller fault keeps it
	// from looking like a healthy one, since the grant behind it was burned exactly once.
	//
	// Claimed BEFORE the store write: a Remove that faults leaves the authorization spent, so
	// a retry is refused (over-refuses; the operator mints another approval) rather than
	// re-applying a clear that may have already landed and deleting a label twice from a set
	// store that can't tell the occurrences apart.
	labels, err := decl.Claim()
	if err != nil {
		return nil, err
	}
	if err := e.flowStore.Remove(ctx, e.flowKey(req), labels...); err != nil {
		// labels, not nil: the Remove may have taken effect before the error surfaced, so
		// the caller reports which labels MAY have gone rather than claiming they did.
		return labels, err
	}
	return labels, nil
}

// errNoFlowStateToClear is what an engine holding no flow state returns from a commit it was
// asked to perform. An ERROR, not a silent empty result: a no-op clear is decided at decision
// time (the handle's set comes back empty and the caller never commits), so reaching here with
// labels in hand and no store is a wiring fault the caller must record as a failed commit.
var errNoFlowStateToClear = fmt.Errorf("this decision point holds no flow-label state, so an approved declassification cannot be applied (wiring fault, not a store failure)")

// ClearSessionLabels releases a session's accumulated flow-label set, called from the
// transport's session teardown so an ended session retains no state. No-op with no store
// wired, no flow control in the policy, or an empty session id.
//
// Clears the SESSION-anchored key only: under WithTaskAnchoredState, labels a request wrote
// under a TASK key are meant to outlive this session, and clearing them here would let an
// agent launder a task's taint by disconnecting. Abandoned task state is reclaimed by the
// store's own idle TTL or flowlabelstore.WithMaxKeys.
func (e *Engine) ClearSessionLabels(ctx context.Context, sessionID string) error {
	if e.flowStore == nil || e.skipFlow || sessionID == "" {
		return nil
	}
	return e.flowStore.Clear(ctx, e.flowSessionKey(sessionID))
}

// constraintHasFlow reports whether matched participates in information-flow control.
// Delegates to the single-sourced capability.ConstraintHasFlow so the engine's allow-path
// gate, the PDP's audit-mode gate, and the config-level subsystem gate can't drift on what
// counts as flow.
func constraintHasFlow(matched *capability.Constraint) bool {
	return capability.ConstraintHasFlow(matched)
}

// labelRecordFailureDenial is the fail-closed response when recordLabels can't persist a
// marker. HARD deny — forwarding the source read while its label failed to persist leaves it
// unlabeled and a later sink fails open, mirroring recordAuditModeAntecedent's
// hardDenyResponse for the analogous sequenceBlock case.
func labelRecordFailureDenial(requestID, now string, auditOnly bool, obligations []capability.Obligation) capability.EnforceResponse {
	return denyResponse(requestID, now, auditOnly, obligations, capability.DenialInfo{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeFlowLabel,
		Message:       "flow-label recording failed; source->sink flow state is unreliable",
		HardDeny:      true,
		Details: map[string]interface{}{
			// Without this, a filter keyed on the flow discriminator missed the one flow
			// event an operator most needs: the hard deny raised when a source's label
			// write faulted.
			capability.FlowAuditDetailKey: true, "phase": "record",
		},
	})
}
