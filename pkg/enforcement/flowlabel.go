// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Flow labels reuse the sequenceBlock history seam: a label present in a session is a
// per-(session, label) marker in the CallCounter backend, set by a labelOutput
// directive on an allowed call and read (Peek) by a flowLabel condition at a sink.
// Presence is the only bit that matters, so one marker per key (maxEntries=1) suffices.
// The "flow" key prefix keeps the label namespace disjoint from the "seq" and
// "maxcalls" namespaces on a shared backend, exactly as sequenceHistoryKey /
// maxCallsBucket keep theirs disjoint.
//
// flowLabelWindowSec is a large reclamation bound, NOT a security-relevant lifetime.
// Flow-label provenance is a monotonic per-session fact, but it is stored here in a
// sliding-window counter whose marker is written once at the source read and refreshed
// only if that same label is re-emitted. So the taint is NOT truly session-lifetime: a
// session active (or idle) past the window without re-emitting a label loses it and a
// sink then fails open. The window is set far above any realistic session to make that
// unlikely, but it does not eliminate it — a session-lifetime store is the real fix, and
// this data-structure/lifetime mismatch (and the source-write vs sink-Peek concurrency
// race) is tracked in docs/flow-label-hardening.md.
const (
	flowLabelWindowSec         = 30 * 24 * 3600 // 30-day reclamation bound; see the note above and docs/flow-label-hardening.md
	flowLabelHistoryMaxEntries = sequenceHistoryMaxEntries
)

// flowLabelVocab is the native flow-label vocabulary, cached once from
// capability.FlowLabelVocabulary so the subset check and the accumulated-set peek do
// not re-allocate it per request. Read-only.
var flowLabelVocab = capability.FlowLabelVocabulary()

// flowLabelKey builds the per-session, per-label marker key. namespace (the engine's
// counterKeyNamespace) leads so routes sharing one CallCounter address disjoint label
// state, mirroring sequenceHistoryKey.
func flowLabelKey(namespace, sessionID, label string) string {
	return compositeCounterKey("flow", namespace, sessionID, label)
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
// Concurrency limitation (intrinsic, mirrors sequenceBlock): the source's label write
// (recordLabels' IncrementAndGet) and this sink's read happen in two independent
// requests, so a host that issues the source read and the sink call CONCURRENTLY on one
// session can let the sink read before the source's marker commits — the sink then sees
// an empty set and allows the flow. MCP's per-session request model is serial, so a
// compliant client never triggers it; a full fix (per-session serialization) is tracked
// in docs/flow-label-hardening.md. Documented, like the identical sequenceBlock race.
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

	// Fail closed when label state cannot be read: no counter, or no session (which
	// would merge label state across anonymous callers). These guards run before the
	// threaded set is used, so a nil threaded set (which peekSessionLabels also returns
	// for these cases) can never be mistaken for "clean context".
	if e.counter == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       "call counter not configured; flow-label state is unavailable",
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
// snapshot. It fails closed: a Peek error is returned rather than silently dropped, so a
// source-only constraint (which runs no flowLabel condition to fail-closed first) cannot
// under-report the accumulated set on the signed tape — the caller denies instead.
// Returns (nil, nil) when there is nothing to read. Appends directly in vocabulary
// order (no intermediate map), so the result is canonical and allocation-light.
func (e *Engine) peekSessionLabels(ctx context.Context, req *capability.EnforceRequest) ([]string, error) {
	if e.counter == nil || req.SessionID == "" {
		return nil, nil
	}
	var out []string
	for _, label := range flowLabelVocab {
		count, err := e.counter.Peek(ctx, flowLabelKey(e.counterKeyNamespace, req.SessionID, label), flowLabelWindowSec)
		if err != nil {
			return nil, err
		}
		if count > 0 {
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
// labelOutput labels of an allowed call into the session's accumulated set, so a later
// flowLabel sink observes them. It returns the recorded labels (canonical vocabulary
// order) for the audit record's labels_out field.
//
// It runs regardless of audit/observe mode: like sequenceBlock's antecedent recording
// (recordSessionCall / recordAuditModeAntecedent), flow provenance is history that must
// stay accurate for a later ENFORCED sink, so an observed source still records its
// labels. This differs from maxCalls, which skips its commit under --audit only because
// observing a quota would consume it; recording provenance consumes nothing.
//
// A constraint carrying labelOutput but lacking a session or counter cannot persist the
// label, which would let a later sink Peek empty and fail OPEN; recordLabels returns an
// error in that case (and on an unknown label, or a backend write fault) and the caller
// denies the source read fail-closed. A constraint with no labelOutput records nothing
// and returns (nil, nil).
//
// Markers are written most-restrictive-first (reverse vocabulary order) so a mid-loop
// backend fault leaves the MORE protective prefix persisted (fail-safe). The ordering of
// this write relative to recordSessionCall — and the non-atomic residual across the two
// namespaces — is documented at the call site (evaluateMatched).
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
	if e.counter == nil {
		return nil, fmt.Errorf("call counter not configured; flow labels cannot be recorded")
	}
	if req.SessionID == "" {
		return nil, fmt.Errorf("sessionId is required to record flow labels")
	}
	// out is canonical vocabulary order (public..untrusted) for labels_out; the WRITE
	// loop below walks it in reverse (most-restrictive-first).
	out := make([]string, 0, len(set))
	for _, label := range flowLabelVocab {
		if set[label] {
			out = append(out, label)
		}
	}
	for i := len(out) - 1; i >= 0; i-- {
		if _, err := e.counter.IncrementAndGet(ctx, flowLabelKey(e.counterKeyNamespace, req.SessionID, out[i]), flowLabelWindowSec, flowLabelHistoryMaxEntries); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RecordLabels is the exported form of recordLabels for the audit-mode antecedent path:
// when an audit-mode source's deny is downgraded and the read forwarded, the labels its
// output carries must still be recorded (or a later ENFORCED sink Peeks empty and fails
// open) AND surfaced on the forwarded call's audit record. It returns the recorded
// labels so the caller can stamp labels_out, mirroring the genuine-allow path. Returns
// an error on a record fault, which the caller turns into a hard deny.
func (e *Engine) RecordLabels(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) ([]string, error) {
	return e.recordLabels(ctx, req, matched)
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
