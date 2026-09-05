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

// Labels span two axes (see capability/flowlabel.go): the closed native provenance set, and
// imported "namespace:value" sensitivity classes whose taxonomy eunox does not own. The
// algebra here is indifferent to which — a label is an opaque set member to the join and the
// subset check — which is what lets the engine enforce a value set it cannot enumerate. The
// axes are told apart in exactly two places, neither of them a decision: the canonical
// ordering (capability.NormalizeFlowLabels) and the wording of a validation error.

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
	return capability.CompositeKey("flow", e.counterKeyNamespace, sessionID)
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

	effectiveAllow := fl.Allow

	// Defense in depth: the loader rejects an unknown label, but a programmatically built
	// condition can carry one.
	for _, l := range fl.Allow {
		if err := capability.ValidateFlowLabel(l); err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeFlowLabel,
				Message:       fmt.Sprintf("flowLabel 'allow' is unusable: %v", err),
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
		return conditionFault(capability.ConditionTypeFlowLabel, "flow-label store not configured; flow-label state is unavailable")
	}
	// The ANCHOR's id, not req.SessionID: flowKey is anchoredKey("flow", req), so gating on the
	// session refused a task-anchored request whose flow bucket keys perfectly well — the same
	// disagreement between a namespace's guard and its key that counterSubjectGuards closes for
	// the quota and history namespaces.
	if e.resolveAnchor(req).ID == "" {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeFlowLabel,
			// BlockOverride for counterSubjectGuards' reason, and this is the namespace where the
			// downgrade does the most damage: an observing route forwards the call with the SINK
			// never evaluated, which is the check that stops tainted data reaching this target.
			BlockOverride: true,
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
			return conditionFault(capability.ConditionTypeFlowLabel, fmt.Sprintf("flow-label state lookup failed: %v", err))
		}
		present = peeked
	}

	// Union in a cooperating client's per-call attribution — one-directional by design: a
	// client may declare MORE labels than the session join knew about, never fewer, so an
	// untrusted declaration can only produce more denials and needs no trust decision. Used
	// for THIS check only, never written into session state.
	declared := capability.NormalizeDeclaredLabels(req.DeclaredLabels)
	present = unionLabels(present, declared)

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
					"allowLabels":                 effectiveAllow,
				}
				if len(declared) > 0 {
					// Separate from the proxy's observed state, so an auditor can tell what
					// was OBSERVED from what the client claimed.
					d["declared_labels"] = declared
				}
				return d
			}(),
		}
	}
	return nil
}

// unionLabels merges declared into present, deduplicated, in canonical order (native classes
// in vocabulary order, then imported sorted — see NormalizeFlowLabels). Returns
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

// peekSessionLabels reports the session's accumulated flow-label set (canonical order) for
// the audit record's carried_labels and handleFlowLabel's threaded snapshot. Fails closed on
// a store error rather than dropping it silently, so a source-only constraint can't
// under-report the accumulated set on the signed tape.
//
// A stored label belonging to NEITHER axis is an ERROR, not something to reorder past:
// dropping it would silently suppress a denial the sink rule ("present and not allowed =>
// deny") depends on — e.g. two proxy versions with different NATIVE vocabularies sharing one
// Redis flow store, where the older build wrote a bare token this one cannot place. Every
// sibling path already fails closed on such a label; this makes the read agree with them,
// over-denying during a mixed-version rollout rather than enforcing against a blind spot.
//
// An imported label needs no such agreement: the axis has no closed value set to disagree
// about, and the subset check treats it as an opaque set member, so any build that can parse
// it enforces it identically.
func (e *Engine) peekSessionLabels(ctx context.Context, req *capability.EnforceRequest) ([]string, error) {
	// The anchor's id, not req.SessionID, for flowKey's reason: a task-anchored request with no
	// session read as "no labels carried" for a task bucket that may hold them — a silent
	// fail-OPEN at the sink, since the rule is "present and not in Allow => deny".
	if e.skipFlow || e.flowStore == nil || e.resolveAnchor(req).ID == "" {
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
	for _, l := range present {
		// Structural, not declaration-based: the imported axis has no closed value set to
		// check against, so what this can still catch is a label belonging to NEITHER axis
		// — which is the mixed-version case it exists for, since a build that predates a
		// native class writes a bare token this one does not know. An imported label is
		// interpretable by any build that can parse it: the subset check treats it as an
		// opaque set member, so two versions cannot disagree about what it means.
		if err := capability.ValidateFlowLabel(l); err != nil {
			return nil, fmt.Errorf("session flow-label store holds a label this build cannot interpret (%w); refusing to evaluate an information-flow policy against it", err)
		}
	}
	return capability.NormalizeFlowLabels(present), nil
}

// PeekSessionLabels is the exported form of peekSessionLabels, for the audit-mode antecedent
// path to back-fill carried_labels onto a downgraded-and-forwarded deny that never went
// through evaluateMatched's own peek.
//
// A nil engine or request is refused rather than dereferenced, for nilRequestDenial's reason.
// The receiver too, because a ManifestPDP may legitimately hold none (as CeilingVerdictFor and
// NonCommittingConditionVerdict already allow), and this seam runs on its forwarded-observe leg.
func (e *Engine) PeekSessionLabels(ctx context.Context, req *capability.EnforceRequest) ([]string, error) {
	if e == nil || req == nil {
		return nil, errors.New(nilSeamRefusal("PeekSessionLabels", "a nil engine or request"))
	}
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
	// Below skipFlow, never above: this is the one leg that dereferences matched, and refusing
	// higher up turned an antecedent-only commit on a flow-skipping engine — which never reads
	// it — into a hard deny, the fail-shut inversion this seam must not cause.
	if matched == nil {
		return nil, errors.New(nilSeamRefusal("recordLabels", "a nil constraint"))
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
			if err := capability.ValidateFlowLabel(l); err != nil {
				// Fail closed rather than silently drop, matching handleFlowLabel's Allow
				// check.
				return nil, fmt.Errorf("labelOutput: %w", err)
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
	if e.resolveAnchor(req).ID == "" {
		return nil, fmt.Errorf("sessionId is required to record flow labels")
	}
	// Canonical order for labels_out; the store's Add commits the whole set atomically, so
	// order matters only for the deterministic audit field.
	keys := make([]string, 0, len(set))
	for l := range set {
		keys = append(keys, l)
	}
	out := capability.NormalizeFlowLabels(keys)
	if err := e.flowStore.Add(ctx, e.flowKey(req), out...); err != nil {
		return nil, err
	}
	return out, nil
}

// SourceCommitError classifies which leg of the atomic source-call commit (recordSourceCall)
// faulted, so the caller builds the matching deny: a flow-label write fault (Flow=true) is
// HARD (an unlabeled forward would fail a later sink open), while a sequenceBlock fault
// (Flow=false) is the plain antecedent deny.
type SourceCommitError struct {
	Err  error
	Flow bool
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
// labelOutput's add stays here rather than after the call: a call that taints and then fails
// should leave EXTRA taint, which over-blocks rather than under-blocks.
//
// Every write fails closed on its own fault, mapped to a SourceCommitError. recordLabels and
// RecordSessionCall each self-guard when the policy doesn't need them, so a flow-only or
// seq-only policy does exactly one write and needs no rollback.
func (e *Engine) recordSourceCall(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, scope SourceCommitScope, carriedLabels []string) (labelsOut []string, cerr *SourceCommitError) {
	if e.anchorUnresolved(req) {
		// evaluateMatched already refuses this well before the allow tail; this is a
		// backstop, and also the entry point the PDP's audit-mode antecedent path uses for
		// a deny that never ran the decision at all. Falling back to session keying here
		// would silently write the split anchorUnresolved exists to refuse.
		return nil, &SourceCommitError{Err: errUnanchorableStateWrite, Flow: scope.Flow}
	}
	var added []string
	if scope.Flow {
		var err error
		labelsOut, err = e.recordLabels(ctx, req, matched)
		if err != nil {
			return nil, &SourceCommitError{Err: err, Flow: true}
		}
		added = labelsAdded(labelsOut, carriedLabels)
	}
	if err := e.recordAntecedentIn(ctx, scope, req); err != nil {
		// Take the label add back out so the hard-denied call leaves no taint. Best-effort —
		// a rollback fault leaves a stranded label, the accepted fail-closed residual
		// (over-blocks, never leaks). Runs before the branch below since both arms need it.
		e.rollbackLabels(ctx, req, added)
		return nil, &SourceCommitError{Err: err, Flow: false}
	}
	return labelsOut, nil
}

// errUnanchorableStateWrite is the fault recordSourceCall reports for a request this engine
// can't anchor (see anchorUnresolved). Travels as a SourceCommitError so every caller maps it
// to a hard, non-downgradable deny — an --audit route forwarding the call is exactly how the
// un-anchored write would happen.
var errUnanchorableStateWrite = errors.New("this route anchors enforcement state on the task, but the presented token carries no mcp.task_id; refusing to record this call against a second, session-keyed bucket (fail closed)")

// SourceCommitScope names which of recordSourceCall's two namespaces this commit writes.
//
// Both halves are the CALLER's question, and they are asked separately because the two
// namespaces are bounded by different things. Flow is per-constraint (does this entry declare
// a labelOutput). The antecedent is bounded policy-wide inside RecordSessionCall, but a caller
// may hold a NARROWER bound the engine cannot see: the PDP's forwarded no-match deny knows
// which target names some sequenceBlock actually queries, and recording an unqueryable name
// mints a counter key per made-up target. A single flag for both would force that caller to
// choose between committing the taint of a forwarded read and minting those keys.
//
// A struct rather than two adjacent bools: the two are independent and a transposition would
// silently swap which namespace a commit writes.
type SourceCommitScope struct {
	Flow       bool
	Antecedent bool
}

// recordAntecedentIn is RecordSessionCall under the caller's scope, so the skip is a
// documented no-write rather than a nil error from a write that was never attempted.
func (e *Engine) recordAntecedentIn(ctx context.Context, scope SourceCommitScope, req *capability.EnforceRequest) error {
	if !scope.Antecedent {
		return nil
	}
	return e.RecordSessionCall(ctx, req)
}

// RecordSourceCall is the exported form of recordSourceCall for the audit-mode antecedent
// path: when a downgraded audit-mode source's deny is forwarded, its flow labels and
// sequenceBlock antecedent must still be recorded atomically and surfaced on the forwarded
// record. scope names which of the two this caller wants (see SourceCommitScope).
//
// A nil engine or request is refused here, for PeekSessionLabels' reason; a nil matched is
// refused by recordLabels, the only leg that reads it. Travels as a SourceCommitError like every
// other fault on this path, so the caller's existing hard ENFORCEMENT_ERROR deny covers it with
// no new branch.
func (e *Engine) RecordSourceCall(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, scope SourceCommitScope, carriedLabels []string) ([]string, *SourceCommitError) {
	if e == nil || req == nil {
		return nil, &SourceCommitError{Err: errors.New(nilSeamRefusal("RecordSourceCall", "a nil engine or request")), Flow: scope.Flow}
	}
	return e.recordSourceCall(ctx, req, matched, scope, carriedLabels)
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
	if e.flowStore == nil || e.resolveAnchor(req).ID == "" || len(added) == 0 {
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
		Code:          capability.ErrCodeEnforcementError,
		ConditionType: capability.ConditionTypeFlowLabel,
		Message:       "flow-label recording failed; source->sink flow state is unreliable",
		Details: map[string]interface{}{
			// Without this, a filter keyed on the flow discriminator missed the one flow
			// event an operator most needs: the hard deny raised when a source's label
			// write faulted.
			capability.FlowAuditDetailKey: true, "phase": "record",
		},
	})
}
