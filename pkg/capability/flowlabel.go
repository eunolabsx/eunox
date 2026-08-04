// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

// ConditionTypeFlowLabel is the discriminator for flowLabel conditions — the sink
// half of information-flow control.
const ConditionTypeFlowLabel = "flowLabel"

// DirectiveTypeLabelOutput is the discriminator for labelOutput directives — the
// source half of information-flow control.
const DirectiveTypeLabelOutput = "labelOutput"

// FlowAuditDetailKey is the audit `details` key every information-flow event shares (across
// pkg/enforcement and internal/transport), so one filter finds them all on the tape. A rename
// or typo on either producer silently splits the filter rather than failing anything.
const FlowAuditDetailKey = "flow"

// The native flow-label vocabulary: a closed, flat set of provenance/integrity source
// classes — an opaque tag the policy asserts, never inferred from content. The set is
// closed: a misspelled label is a load-time error, not a silently-never-matching one.
const (
	// FlowLabelPublic marks data of public provenance (openly shareable).
	FlowLabelPublic = "public"
	// FlowLabelInternal marks data of internal-only provenance.
	FlowLabelInternal = "internal"
	// FlowLabelConfidential marks confidential-business provenance.
	FlowLabelConfidential = "confidential"
	// FlowLabelPII marks data carrying personal information.
	FlowLabelPII = "pii"
	// FlowLabelUntrusted marks data of untrusted provenance (the integrity class: input
	// that may be attacker-influenced, e.g. prompt injection). A control path carrying
	// it blocks/escalates regardless of held permission.
	FlowLabelUntrusted = "untrusted"
)

// flowLabelVocabulary is the ordered closed set. Order is fixed so any derived
// report (e.g. the accumulated-set audit field) is deterministic.
var flowLabelVocabulary = []string{
	FlowLabelPublic,
	FlowLabelInternal,
	FlowLabelConfidential,
	FlowLabelPII,
	FlowLabelUntrusted,
}

var flowLabelSet = func() map[string]bool {
	m := make(map[string]bool, len(flowLabelVocabulary))
	for _, l := range flowLabelVocabulary {
		m[l] = true
	}
	return m
}()

// FlowLabelVocabulary returns a fresh copy of the ordered native flow-label set, so
// callers (the engine's accumulated-set peek, validation error messages) enumerate
// the same closed vocabulary without being able to mutate it.
func FlowLabelVocabulary() []string {
	return append([]string(nil), flowLabelVocabulary...)
}

// IsFlowLabel reports whether s is a recognized native flow label. Validation and
// the engine both consult it, so the closed set is enforced identically at load and
// at runtime.
func IsFlowLabel(s string) bool {
	return flowLabelSet[s]
}

// AsValueOrPointer normalizes a polymorphic value that may be stored as either T or *T
// (as manifest conditions/directives are, depending on decode path) to *T — the single
// normalizer, so the type-switch isn't re-copied per concrete type. Returns (nil, false)
// when v is neither; a typed-nil *T is returned as-is (no dereference).
func AsValueOrPointer[T any](v any) (*T, bool) {
	switch t := v.(type) {
	case *T:
		return t, true
	case T:
		return &t, true
	default:
		return nil, false
	}
}

// IsFlowLabelCondition reports whether c is a flowLabel condition (value or pointer form).
// Single-sourced so the engine's flow-relevance check and the config-level multi-instance
// advisory cannot drift on what counts as flow. Nil-safe.
func IsFlowLabelCondition(c Condition) bool {
	_, ok := AsValueOrPointer[FlowLabelCondition](c)
	return ok
}

// IsLabelOutputDirective reports whether d is a labelOutput directive (value or
// pointer form). Single-sourced alongside IsFlowLabelCondition. Nil-safe.
func IsLabelOutputDirective(d Directive) bool {
	_, ok := AsValueOrPointer[LabelOutputDirective](d)
	return ok
}

// ConstraintHasFlow reports whether c participates in information-flow control: a flowLabel
// condition (sink), a labelOutput directive (source), or a declassify directive (the
// verdict depends on session label state too). Single-sourced so the engine's allow-path
// gate and the PDP's audit-mode antecedent gate can't drift on what counts as flow. Nil-safe.
func ConstraintHasFlow(c *Constraint) bool {
	if c == nil {
		return false
	}
	for _, cond := range c.Conditions {
		if IsFlowLabelCondition(cond) {
			return true
		}
	}
	for _, dir := range c.Directives {
		if IsLabelOutputDirective(dir) || IsDeclassifyDirective(dir) {
			return true
		}
	}
	return false
}

// FlowLabelCondition denies a call when the session's accumulated flow labels (the
// set-union of every labelOutput asserted earlier in session) are not a subset of Allow —
// the sink half of the source->sink invariant. An empty Allow admits only an unlabeled
// (clean-context) flow, the strictest fail-closed default; a violation is a flowLabel
// CONDITION_FAILED, distinct from a capability denial. Reads eunox's own state, never the
// payload, so it stays deterministic with no model in the decision path.
type FlowLabelCondition struct {
	Allow []string `json:"allow"`
}

// ConditionType returns the flowLabel discriminator.
func (FlowLabelCondition) ConditionType() string { return ConditionTypeFlowLabel }

// MarshalJSON serializes FlowLabelCondition with its discriminator.
func (c FlowLabelCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// LabelOutputDirective asserts — by policy, never by content inference — that the output
// of an allowed call carries the named native flow Labels into the session's accumulated
// set, where a later flowLabel condition checks them (the source half of the source->sink
// invariant). Unlike redactFields it does not mutate the response: its effect is a
// per-session state write on allow, so it produces no response obligation and is valid on
// any source target (tool: or resource:), not only tool: targets.
type LabelOutputDirective struct {
	Labels []string `json:"labels"`
}

// DirectiveType returns the labelOutput discriminator.
func (LabelOutputDirective) DirectiveType() string { return DirectiveTypeLabelOutput }

// ToObligation satisfies the Directive interface. labelOutput carries no response
// obligation — its effect is the engine's session-state write, so the engine skips this
// before it would be emitted — hence the returned sentinel is never marshaled.
func (d LabelOutputDirective) ToObligation() Obligation {
	return Obligation{Type: DirectiveTypeLabelOutput}
}
