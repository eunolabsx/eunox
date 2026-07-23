// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Flow labels reuse the sequenceBlock history seam: a label present in a session is
// a per-(session, label) marker in the CallCounter backend, set by a labelOutput
// directive on an allowed call and read (Peek) by a flowLabel condition at a sink.
// Presence is the only bit that matters, so the window and max-entries mirror the
// sequence-history markers (24h; one marker per key). The "flow" key prefix keeps
// the label namespace disjoint from the "seq" and "maxcalls" namespaces on a shared
// backend, exactly as sequenceHistoryKey / maxCallsBucket keep theirs disjoint.
const (
	flowLabelWindowSec         = sequenceHistoryWindowSec
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

// flowLabelsPresent returns the vocabulary-ordered subset of labels for which
// set[label] is true. Ordering is fixed (the vocabulary order) so a derived audit
// field is deterministic run to run; unknown labels in set are dropped (the closed
// vocabulary is the single source of truth).
func flowLabelsPresent(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	var out []string
	for _, label := range flowLabelVocab {
		if set[label] {
			out = append(out, label)
		}
	}
	return out
}

// handleFlowLabel enforces the sink half of information-flow control: it denies when
// the session's accumulated flow labels are not a subset of the condition's Allow set
// — i.e. when a source class that flowed into this session is not permitted here. The
// check reads only eunox's per-session label state (never the payload), so it is
// deterministic with no model in the decision path.
//
// It Peeks each vocabulary label NOT in Allow; the first one present denies. Because
// the check enumerates the closed vocabulary complement rather than a caller-named
// block list, a label the sink does not explicitly permit is denied by construction —
// the allowlist survives a label the author never enumerated (fail closed), the same
// property that makes the manifest an allowlist rather than a blocklist. An empty
// Allow admits only an unlabeled (clean-context) flow.
func (e *Engine) handleFlowLabel(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	fl, condErr := castCondition[capability.FlowLabelCondition](cond)
	if condErr != nil {
		return condErr
	}

	// Defense in depth: the loader rejects an unknown label in Allow, but a
	// programmatically built condition can carry one. An unknown entry is inert here
	// (it matches no vocabulary label), so this only sharpens the error rather than
	// guarding a fail-open; still, surface it rather than silently ignore.
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
	// would merge label state across anonymous callers). Mirrors sequenceBlock.
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

	for _, label := range flowLabelVocab {
		if allow[label] {
			continue
		}
		count, err := e.counter.Peek(ctx, flowLabelKey(e.counterKeyNamespace, req.SessionID, label), flowLabelWindowSec)
		if err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeFlowLabel,
				Message:       fmt.Sprintf("flow-label state lookup failed: %v", err),
			}
		}
		if count > 0 {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeFlowLabel,
				Message:       fmt.Sprintf("flow label %q is present in this session but not permitted at this sink", label),
				Details: map[string]interface{}{
					// "flow": true distinguishes a source->sink flow denial from a plain
					// capability/argument denial for SIEM rules and the audit tape.
					"flow":         true,
					"blockedLabel": label,
					"allowLabels":  fl.Allow,
				},
			}
		}
	}
	return nil
}

// peekSessionLabels reports the session's accumulated flow-label set (vocabulary
// order) for the audit record's carried_labels field. Best-effort: a Peek error is
// left out of the reported set rather than failing the (already-made) decision —
// this runs only after conditions have passed, so a flowLabel sink has already
// fail-closed on any real state-read fault. Returns nil when there is nothing to read.
func (e *Engine) peekSessionLabels(ctx context.Context, req *capability.EnforceRequest) []string {
	if e.counter == nil || req.SessionID == "" {
		return nil
	}
	present := make(map[string]bool, len(flowLabelVocab))
	for _, label := range flowLabelVocab {
		if count, err := e.counter.Peek(ctx, flowLabelKey(e.counterKeyNamespace, req.SessionID, label), flowLabelWindowSec); err == nil && count > 0 {
			present[label] = true
		}
	}
	return flowLabelsPresent(present)
}

// recordLabels performs the source half of information-flow control: it unions the
// labelOutput labels of an allowed call into the session's accumulated set, so a
// later flowLabel sink observes them. It returns the recorded labels (vocabulary
// order) for the audit record's labels_out field.
//
// A constraint carrying labelOutput but lacking a session or counter cannot persist
// the label, which would let a later sink Peek empty and fail OPEN; recordLabels
// returns an error in that case and the caller denies the (benign) source read fail-
// closed, exactly as maxCalls/sequenceBlock require a session. A constraint with no
// labelOutput records nothing and returns (nil, nil).
func (e *Engine) recordLabels(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) ([]string, error) {
	set := map[string]bool{}
	for _, dir := range matched.Directives {
		if dir == nil || isTypedNil(dir) {
			continue
		}
		lo, ok := asLabelOutput(dir)
		if !ok {
			continue
		}
		for _, l := range lo.Labels {
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
	out := flowLabelsPresent(set) // known labels only, vocabulary order
	for _, label := range out {
		if _, err := e.counter.IncrementAndGet(ctx, flowLabelKey(e.counterKeyNamespace, req.SessionID, label), flowLabelWindowSec, flowLabelHistoryMaxEntries); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// asLabelOutput returns dir as *LabelOutputDirective, accepting either the value or
// pointer form a manifest directive may decode into (mirrors asCondition).
func asLabelOutput(dir capability.Directive) (*capability.LabelOutputDirective, bool) {
	switch t := dir.(type) {
	case *capability.LabelOutputDirective:
		return t, true
	case capability.LabelOutputDirective:
		return &t, true
	default:
		return nil, false
	}
}

// constraintHasFlow reports whether matched participates in information-flow control
// (carries a flowLabel condition or a labelOutput directive), so the engine peeks and
// records label state only for flow-relevant constraints rather than on every call.
func constraintHasFlow(matched *capability.Constraint) bool {
	for _, cond := range matched.Conditions {
		if cond != nil && !isTypedNil(cond) && cond.ConditionType() == capability.ConditionTypeFlowLabel {
			return true
		}
	}
	for _, dir := range matched.Directives {
		if dir != nil && !isTypedNil(dir) && dir.DirectiveType() == capability.DirectiveTypeLabelOutput {
			return true
		}
	}
	return false
}

// labelRecordFailureDenial is the fail-closed response when recordLabels cannot
// persist a marker, mirroring recordFailureDenial but attributed to flowLabel (the
// only feature the marker backs). The "phase":"record" detail distinguishes it from
// an actual flowLabel sink denial (which carries blockedLabel).
func labelRecordFailureDenial(requestID, now string, auditOnly bool, obligations []capability.Obligation) capability.EnforceResponse {
	return denyResponse(requestID, now, auditOnly, obligations, capability.DenialInfo{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeFlowLabel,
		Message:       "flow-label recording failed; source->sink flow state is unreliable",
		Details:       map[string]interface{}{"phase": "record"},
	})
}
