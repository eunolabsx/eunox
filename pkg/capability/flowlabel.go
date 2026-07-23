// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

// ConditionTypeFlowLabel is the discriminator for flowLabel conditions — the sink
// half of information-flow control.
const ConditionTypeFlowLabel = "flowLabel"

// DirectiveTypeLabelOutput is the discriminator for labelOutput directives — the
// source half of information-flow control.
const DirectiveTypeLabelOutput = "labelOutput"

// The native flow-label vocabulary: a closed, flat set of provenance/integrity
// source classes. It is deliberately small (no partial order, no lattice) — a flow
// label is an opaque tag the policy asserts, never a value the engine infers from
// content. eunox owns this algebra; it does not own a sensitivity taxonomy, so the
// imported-sensitivity axis (mapping to external classifiers) is a separate surface,
// not part of this set. The set is closed: a misspelled label is a load-time error,
// keeping the grammar falsifiable rather than evaluate-to-know.
const (
	// FlowLabelPublic marks data of public provenance (openly shareable).
	FlowLabelPublic = "public"
	// FlowLabelInternal marks data of internal-only provenance.
	FlowLabelInternal = "internal"
	// FlowLabelConfidential marks confidential-business provenance.
	FlowLabelConfidential = "confidential"
	// FlowLabelPII marks data carrying personal information.
	FlowLabelPII = "pii"
	// FlowLabelUntrusted marks data of untrusted provenance — the integrity class:
	// input that may be attacker-influenced (a prompt-injection carrier). A control
	// path carrying it blocks/escalates an action regardless of held permission.
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

// flowLabelSet is the membership index over flowLabelVocabulary.
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

// FlowLabelCondition denies a call when the session's accumulated flow labels are
// not a subset of Allow — i.e. when any source class that flowed into this session
// is not permitted at this sink. It is the sink half of the source->sink invariant:
// for all flows, a class outside Allow never reaches this sink.
//
// Allow lists the native source classes this sink tolerates. The accumulated set is
// the set-union of every labelOutput asserted on an allowed call earlier in the same
// session (conservative task-level join; see the engine). An empty Allow admits only
// an unlabeled (clean-context) flow — the strictest, fail-closed default. A call
// whose accumulated set carries a label outside Allow is denied with a flowLabel
// CONDITION_FAILED naming the offending label, distinct from a capability denial.
//
// The check reads eunox's own per-session state, never the payload, so it stays
// deterministic with no model in the decision path.
type FlowLabelCondition struct {
	Allow []string `json:"allow"`
}

// ConditionType returns the flowLabel discriminator.
func (FlowLabelCondition) ConditionType() string { return ConditionTypeFlowLabel }

// MarshalJSON serializes FlowLabelCondition with its discriminator.
func (c FlowLabelCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// LabelOutputDirective asserts — by policy, never by content inference — that the
// output of an allowed call carries the named native flow Labels into the session's
// accumulated set, where a later flowLabel condition checks them. It is the source
// half of the source->sink invariant.
//
// Unlike redactFields, labelOutput does not mutate the response: its effect is the
// per-session state write the engine performs on allow (see the engine's recordLabels
// / collectObligations handling). It therefore produces no post-allow response
// obligation and is valid on any source target a sensitive read can sit at (tool: or
// resource:), not only tool: targets.
type LabelOutputDirective struct {
	Labels []string `json:"labels"`
}

// DirectiveType returns the labelOutput discriminator.
func (LabelOutputDirective) DirectiveType() string { return DirectiveTypeLabelOutput }

// ToObligation is required by the Directive interface. labelOutput carries no
// response obligation — its effect is the engine's session-state write — so the
// engine skips it before this would be emitted (see collectObligations). The
// labelOutput-typed sentinel returned here is never marshaled onto a response, so
// it carries no payload and Obligation gains no labelOutput case.
func (d LabelOutputDirective) ToObligation() Obligation {
	return Obligation{Type: DirectiveTypeLabelOutput}
}
