// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Flow labels are per-session provenance state in the FlowLabelStore seam (distinct
// from the CallCounter): a labelOutput directive on an allowed source call Adds its
// labels to the session's accumulated SET, and a flowLabel condition at a sink Gets the
// set and denies when a class outside its Allow is present. Presence is the only bit
// that matters — a SET, not a count — so the store holds one entry per (session,label).
//
// The "flow" key prefix and the engine's counterKeyNamespace (route name) lead the
// store key so routes sharing one backend address disjoint label state, exactly as
// sequenceHistoryKey namespaces its history. Unlike sequenceBlock's 24h sliding window,
// flow state has NO wall-clock expiry: it is a monotonic, session-lifetime fact,
// reclaimed by the transport's Clear on session end (a windowed marker aged a taint out
// mid-session, a fail-open the "for all flows" claim cannot tolerate). See
// docs/flow-label-hardening.md and pkg/flowlabelstore.

// flowLabelVocab is the native flow-label vocabulary, cached once from
// capability.FlowLabelVocabulary so the subset check and the accumulated-set peek do
// not re-allocate it per request. Read-only.
var flowLabelVocab = capability.FlowLabelVocabulary()

// flowSessionKey builds the per-session flow-label store key. namespace (the engine's
// counterKeyNamespace) leads so routes sharing one FlowLabelStore address disjoint
// label state, mirroring sequenceHistoryKey. There is no per-label component: the store
// holds the whole accumulated SET under this one key (Add unions, Get returns the set),
// where the old windowed counter needed one marker key per label.
func (e *Engine) flowSessionKey(sessionID string) string {
	return compositeCounterKey("flow", e.counterKeyNamespace, sessionID)
}

// handleFlowLabel enforces the sink half of information-flow control: it denies when
// the session's accumulated flow labels are not a subset of the condition's Allow set
// — i.e. when a source class that flowed into this session is not permitted here. The
// check reads only eunox's per-session label state (never the payload), so it is
// deterministic with no model in the decision path.
//
// It reports ALL present-and-not-allowed classes (not only the first), so an integrity
// (untrusted) signal is never hidden behind a benign class; the single-value
// blockedLabel is the highest-vocabulary-order class present (untrusted-preferring),
// while blockedLabels carries the full set. Because the check covers the whole closed
// vocabulary, a label the sink does not explicitly permit is denied by construction —
// the allowlist survives a label the author never enumerated (fail closed). An empty
// Allow admits only an unlabeled (clean-context) flow.
//
// To avoid Peeking the vocabulary twice per sink call (once here, once in the engine's
// peekSessionLabels for the audit field) and to keep the audited carried_labels and the
// enforced set a single atomic snapshot, it prefers the accumulated set the engine
// already peeked and threaded via ctx, falling back to its own Peek only for a direct
// caller that did not thread one.
//
// Concurrency: the source's label write (recordLabels' Add) and this sink's read happen
// in two independent requests. The transport serializes the per-session decision phase
// for a flow-relevant session (docs/flow-label-hardening.md piece B), so a source read
// received before an egress commits its label before the egress's sink read runs —
// deterministically, even under a client that pipelines both without waiting. (On a
// direct engine caller that does not serialize, the ordering is the caller's
// responsibility, as with sequenceBlock.)
func (e *Engine) handleFlowLabel(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	fl, condErr := castCondition[capability.FlowLabelCondition](cond)
	if condErr != nil {
		return condErr
	}

	// Defense in depth: the loader rejects an unknown label in Allow, but a
	// programmatically built condition can carry one. Surface it rather than silently
	// ignore (matching recordLabels, which also errors on an unknown label).
	allow := make(map[string]bool, len(fl.Allow))
	for _, l := range fl.Allow {
		if !capability.IsFlowLabel(l) {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeFlowLabel,
				Message:       fmt.Sprintf("flowLabel 'allow' contains unknown label %q; valid native labels are %v", l, flowLabelVocab),
			}
		}
		allow[l] = true
	}

	// Fail closed when label state cannot be read: no store, or no session (which
	// would merge label state across anonymous callers). These guards run before the
	// threaded set is used, so a nil threaded set (which peekSessionLabels also returns
	// for these cases) can never be mistaken for "clean context".
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

	// Prefer the engine's already-peeked snapshot (threaded via ctx). A real Peek error
	// makes the engine fail closed before this handler runs, so a threaded set is
	// trustworthy; the fallback reuses peekSessionLabels (the same vocab scan the audit
	// path runs, single-sourced so the two cannot drift) for a direct caller that did not
	// thread one. The counter==nil / empty-session guards above already fired, so
	// peekSessionLabels' own short-circuit is unreachable here — it runs the full scan.
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

	// blocked = present labels not permitted here. present is vocabulary-ordered (both
	// the threaded snapshot and the fallback append in vocab order), so blocked is too.
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
			Details: map[string]interface{}{
				// "flow": true distinguishes a source->sink flow denial from a plain
				// capability/argument denial. blockedLabels lists every offending class;
				// blockedLabel is the highest-vocabulary-order one (untrusted-preferring),
				// so a single-value consumer keyed on the integrity signal still sees it.
				"flow":          true,
				"blockedLabel":  blocked[len(blocked)-1],
				"blockedLabels": blocked,
				"allowLabels":   fl.Allow,
			},
		}
	}
	return nil
}

// peekSessionLabels reports the session's accumulated flow-label set (vocabulary order)
// for the audit record's carried_labels field and for handleFlowLabel's threaded
// snapshot. It fails closed: a store error is returned rather than silently dropped, so a
// source-only constraint (which runs no flowLabel condition to fail-closed first) cannot
// under-report the accumulated set on the signed tape — the caller denies instead.
// Returns (nil, nil) when there is nothing to read. The store returns the set in
// unspecified order, so this reorders it into the fixed vocabulary order (public..
// untrusted) — the single ordering both the enforced subset check and the audit field
// rely on — dropping any member outside the closed vocabulary (fail-safe; recordLabels
// rejects such a label at the source, so this only guards a directly-poked store).
func (e *Engine) peekSessionLabels(ctx context.Context, req *capability.EnforceRequest) ([]string, error) {
	if e.flowStore == nil || req.SessionID == "" {
		return nil, nil
	}
	present, err := e.flowStore.Get(ctx, e.flowSessionKey(req.SessionID))
	if err != nil {
		return nil, err
	}
	if len(present) == 0 {
		return nil, nil
	}
	inSet := make(map[string]bool, len(present))
	for _, l := range present {
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

// PeekSessionLabels is the exported form of peekSessionLabels, for the audit-mode
// antecedent path to back-fill carried_labels onto a downgraded-and-forwarded deny that
// never went through evaluateMatched's own peek.
func (e *Engine) PeekSessionLabels(ctx context.Context, req *capability.EnforceRequest) ([]string, error) {
	return e.peekSessionLabels(ctx, req)
}

// recordLabels performs the source half of information-flow control: it unions the
// labelOutput labels of an allowed call into the session's accumulated set (one atomic
// store Add), so a later flowLabel sink observes them. It returns the recorded labels
// (canonical vocabulary order) for the audit record's labels_out field.
//
// It runs regardless of audit/observe mode: like sequenceBlock's antecedent recording
// (recordSessionCall / recordAuditModeAntecedent), flow provenance is history that must
// stay accurate for a later ENFORCED sink, so an observed source still records its
// labels. This differs from maxCalls, which skips its commit under --audit only because
// observing a quota would consume it; recording provenance consumes nothing.
//
// A constraint carrying labelOutput but lacking a session or store cannot persist the
// label, which would let a later sink Get empty and fail OPEN; recordLabels returns an
// error in that case (and on an unknown label, or a backend write fault) and the caller
// denies the source read fail-closed. A constraint with no labelOutput records nothing
// and returns (nil, nil).
//
// The write is a single Add of the whole label set, so — unlike the old per-label
// counter loop — there is no mid-write partial-commit to order defensively; the store
// commits the set atomically. The ordering of this write relative to recordSessionCall
// (and the atomic-commit rollback across the two namespaces) lives in recordSourceCall.
func (e *Engine) recordLabels(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) ([]string, error) {
	set := map[string]bool{}
	for _, dir := range matched.Directives {
		lo, ok := capability.AsValueOrPointer[capability.LabelOutputDirective](dir)
		if !ok || lo == nil {
			// !ok: not a labelOutput. lo == nil: a typed-nil *LabelOutputDirective, which
			// AsValueOrPointer returns as (nil, true); dereferencing lo.Labels would panic.
			continue
		}
		for _, l := range lo.Labels {
			// Fail closed on an unknown label rather than silently drop it (matching
			// handleFlowLabel's Allow check): a typo'd label on a non-manifest code path
			// must not let a source assert NO taint while declaring one.
			if !capability.IsFlowLabel(l) {
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
	// out is canonical vocabulary order (public..untrusted) for labels_out. The store
	// commits the whole set in one Add, so order is immaterial to the write; it matters
	// only for the deterministic audit field.
	out := make([]string, 0, len(set))
	for _, label := range flowLabelVocab {
		if set[label] {
			out = append(out, label)
		}
	}
	if err := e.flowStore.Add(ctx, e.flowSessionKey(req.SessionID), out...); err != nil {
		return nil, err
	}
	return out, nil
}

// RecordLabels is the exported form of recordLabels for the audit-mode antecedent path:
// when an audit-mode source's deny is downgraded and the read forwarded, the labels its
// output carries must still be recorded (or a later ENFORCED sink Gets empty and fails
// open) AND surfaced on the forwarded call's audit record. It returns the recorded
// labels so the caller can stamp labels_out, mirroring the genuine-allow path. Returns
// an error on a record fault, which the caller turns into a hard deny.
func (e *Engine) RecordLabels(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) ([]string, error) {
	return e.recordLabels(ctx, req, matched)
}

// SourceCommitError classifies which half of the atomic source-call commit
// (recordSourceCall) faulted, so the caller builds the matching fail-closed deny: a
// flow-label write fault (Flow=true) is a HARD deny (labelRecordFailureDenial /
// hardDenyResponse — an unlabeled forward would fail a later sink open), a sequenceBlock
// antecedent write fault (Flow=false) denies via recordFailureDenial.
type SourceCommitError struct {
	Err  error
	Flow bool
}

// Error implements error.
func (e *SourceCommitError) Error() string { return e.Err.Error() }

// recordSourceCall commits an allowed call's flow labels and its sequenceBlock
// antecedent as a single all-or-nothing unit, closing the cross-namespace half-commit
// (docs/flow-label-hardening.md defect D3/FR-H5). The two live in disjoint backends (the
// FlowLabelStore holds "flow:", the CallCounter holds "seq:"), so a fault between the two
// writes could otherwise strand one: a phantom seq antecedent for a call that hard-denied
// and never ran, or a stranded flow label.
//
// It writes flow FIRST (the FlowLabelStore supports targeted Remove), then the seq
// antecedent; if the seq write faults, it rolls back the flow labels THIS call added
// (out minus the pre-call carried set) so the hard-denied call leaves NEITHER committed.
// This reverses the old seq-first order, which could not clean up a stranded write at
// all. The per-session decision lock (piece B) serializes this critical section, so the
// rollback removes exactly this call's additions with no concurrent writer to race.
//
// Both writes still fail closed on their own fault (returned as a SourceCommitError the
// caller maps to the right deny). recordLabels is skipped when the constraint is not
// flow-relevant; recordSessionCall self-guards when the policy has no sequenceBlock
// (skipAntecedentRecording) — so a flow-only or seq-only policy does exactly one write
// and needs no rollback. carriedLabels is the pre-call accumulated set (peeked by the
// caller before this commit), used to compute the rollback delta.
func (e *Engine) recordSourceCall(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, flowRelevant bool, carriedLabels []string) ([]string, *SourceCommitError) {
	var labelsOut, added []string
	if flowRelevant {
		var err error
		labelsOut, err = e.recordLabels(ctx, req, matched)
		if err != nil {
			return nil, &SourceCommitError{Err: err, Flow: true}
		}
		added = labelsAdded(labelsOut, carriedLabels)
	}
	if err := e.recordSessionCall(ctx, req); err != nil {
		// The seq write faulted after the flow write committed: roll the flow labels this
		// call added back out so the hard-denied call taints nothing. Best-effort — a
		// rollback fault leaves a stranded label (fail-closed: over-blocks a later sink,
		// never a leak), the narrow residual documented in docs/flow-label-hardening.md.
		e.rollbackLabels(ctx, req, added)
		return nil, &SourceCommitError{Err: err, Flow: false}
	}
	return labelsOut, nil
}

// RecordSourceCall is the exported form of recordSourceCall for the audit-mode
// antecedent path (recordAuditModeAntecedent): when an audit-mode source's deny is
// downgraded and the read forwarded, its flow labels and sequenceBlock antecedent must
// still be recorded — atomically, so a fault leaves neither stranded — and the labels
// surfaced on the forwarded call's record. It returns labelsOut for that back-fill and a
// SourceCommitError the caller maps to a hard deny.
func (e *Engine) RecordSourceCall(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, flowRelevant bool, carriedLabels []string) ([]string, *SourceCommitError) {
	return e.recordSourceCall(ctx, req, matched, flowRelevant, carriedLabels)
}

// labelsAdded returns the labels in out that were NOT already in the pre-call carried
// set — i.e. the ones this call's Add introduced. Rolling back only these preserves a
// label a prior source in the same session already asserted. Both slices are small
// (bounded by the closed vocabulary), so a linear scan is cheaper than a map.
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

// rollbackLabels best-effort removes the labels a faulted source call added, so a
// hard-denied call leaves no flow taint (see recordSourceCall). A nil store, empty
// session, or empty set is a no-op; a Remove fault is swallowed (the fail-closed residual
// documented in docs/flow-label-hardening.md — a stranded label over-blocks, never leaks).
func (e *Engine) rollbackLabels(ctx context.Context, req *capability.EnforceRequest, added []string) {
	if e.flowStore == nil || req.SessionID == "" || len(added) == 0 {
		return
	}
	_ = e.flowStore.Remove(ctx, e.flowSessionKey(req.SessionID), added...)
}

// ClearSessionLabels releases a session's accumulated flow-label set, called from the
// transport's session teardown so an ended session retains no state and a reused session
// id starts clean (docs/flow-label-hardening.md FR-H2). It is a no-op when no store is
// wired, the policy uses no flow control (skipFlow), or the session id is empty — the
// same guards recordLabels/peekSessionLabels apply, so a non-flow deployment pays
// nothing on teardown.
func (e *Engine) ClearSessionLabels(ctx context.Context, sessionID string) error {
	if e.flowStore == nil || e.skipFlow || sessionID == "" {
		return nil
	}
	return e.flowStore.Clear(ctx, e.flowSessionKey(sessionID))
}

// constraintHasFlow reports whether matched participates in information-flow control
// (carries a flowLabel condition or a labelOutput directive), so the engine peeks and
// records label state only for flow-relevant constraints. Delegates to the single-sourced,
// nil-safe capability.ConstraintHasFlow so the engine's allow-path gate, the PDP's
// audit-mode antecedent gate, and the config-level HasFlowLabel cannot drift on what
// counts as flow.
func constraintHasFlow(matched *capability.Constraint) bool {
	return capability.ConstraintHasFlow(matched)
}

// labelRecordFailureDenial is the fail-closed response when recordLabels cannot persist
// a marker. It is a HARD deny: unlike a plain audit-mode denial, a record fault must NOT
// be downgraded to a forwarded (observe) allow, because forwarding the source read while
// its label failed to persist leaves the read unlabeled and a later sink fails open
// (the exfil this backs). This mirrors recordAuditModeAntecedent's hardDenyResponse for
// the analogous sequenceBlock record-fault case. The "phase":"record" detail
// distinguishes it from an actual flowLabel sink denial (which carries blockedLabel).
func labelRecordFailureDenial(requestID, now string, auditOnly bool, obligations []capability.Obligation) capability.EnforceResponse {
	return denyResponse(requestID, now, auditOnly, obligations, capability.DenialInfo{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeFlowLabel,
		Message:       "flow-label recording failed; source->sink flow state is unreliable",
		HardDeny:      true,
		Details:       map[string]interface{}{"phase": "record"},
	})
}
