// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"fmt"
	"sort"
	"strings"
)

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

// Flow labels have TWO AXES, and the difference between them is who owns the vocabulary:
//
//   - NATIVE provenance/integrity — a bare token from the closed set below. eunox owns it
//     end to end, so a misspelled one is a load-time error rather than a
//     silently-never-matching entry.
//   - IMPORTED sensitivity — "namespace:value", where the namespace names an external
//     taxonomy (Purview/MSIP/BigID) and the value is that taxonomy's own class. eunox owns
//     the ALGEBRA (the join, the subset check, the canonical order) and never the taxonomy
//     or the classifier: it consumes a classification some incumbent already produced and
//     cannot enumerate, let alone derive, the value set.
//
// The axes are disjoint by SHAPE — a label carrying the separator is imported, one without
// it is native — so neither can spell the other and no `eunox:pii` alias exists.
//
// What the open value set costs is nothing on the decision path, because the sink rule is
// "present and not allowed => deny": a typo'd value taints where no sink admits it
// (over-blocks) and, in a sink's allow list, admits nothing (over-blocks again). Both
// directions fail closed, which is what makes an operator-owned value space safe here and
// would not make it safe in a rule that GRANTED on a match. The closure eunox can still
// honestly own is the NAMESPACE: a manifest declares the taxonomies it speaks
// (LocalManifest.FlowLabelNamespaces), so a misspelled namespace is caught at load, where
// the native axis catches a misspelled label. The value half is irreducibly the incumbent's.
//
// Both axes stay FLAT — a label is a tag, and there is no partial order between
// "purview:confidential" and "purview:public" any more than between two native classes.
// Adding a lattice waits on a partner forcing one.

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

// nativeFlowLabelVocabulary is the ordered closed set. Order is fixed so any derived
// report (e.g. the accumulated-set audit field) is deterministic.
var nativeFlowLabelVocabulary = []string{
	FlowLabelPublic,
	FlowLabelInternal,
	FlowLabelConfidential,
	FlowLabelPII,
	FlowLabelUntrusted,
}

var nativeFlowLabelSet = func() map[string]bool {
	m := make(map[string]bool, len(nativeFlowLabelVocabulary))
	for _, l := range nativeFlowLabelVocabulary {
		m[l] = true
	}
	return m
}()

// NativeFlowLabelVocabulary returns a fresh copy of the ordered native flow-label set, so
// callers (the engine's accumulated-set peek, validation error messages) enumerate
// the same closed vocabulary without being able to mutate it.
//
// Named for its AXIS: it is not "the flow labels", only the half of them eunox owns, and a
// caller rendering it as the complete vocabulary would tell an operator their imported
// label was a typo.
func NativeFlowLabelVocabulary() []string {
	return append([]string(nil), nativeFlowLabelVocabulary...)
}

// IsNativeFlowLabel reports whether s is a recognized native flow label. Validation and
// the engine both consult it, so the closed set is enforced identically at load and
// at runtime.
//
// This answers about the NATIVE axis alone: an imported label is not one, and a caller
// asking "may this label be used here" wants ValidateFlowLabel instead.
func IsNativeFlowLabel(s string) bool {
	return nativeFlowLabelSet[s]
}

// FlowLabelNamespaceSep separates an imported label's namespace from its value. Splitting
// on the FIRST occurrence is what lets a taxonomy whose own classes contain a colon
// ("purview:eu:pii") round-trip without an escape rule.
const FlowLabelNamespaceSep = ":"

// Bounds on an imported label's two halves. Generous against any real taxonomy and small
// enough that a label cannot become an unbounded string on the audit tape or in the flow
// store, which holds one set entry per label.
const (
	maxFlowLabelNamespaceLen = 32
	maxFlowLabelValueLen     = 96
)

// SplitFlowLabel splits an imported label into its namespace and value; imported reports
// whether label carries the separator at all. A native label returns ("", label, false).
//
// It SPLITS and does not validate — ValidateFlowLabel is the judgement — so a caller that
// has already validated (the canonical sort, the namespace-declaration check) needs no
// second error path.
func SplitFlowLabel(label string) (namespace, value string, imported bool) {
	i := strings.Index(label, FlowLabelNamespaceSep)
	if i < 0 {
		return "", label, false
	}
	return label[:i], label[i+len(FlowLabelNamespaceSep):], true
}

// ValidateFlowLabel reports whether label is usable on either axis: a member of the closed
// native set, or a structurally well-formed "namespace:value" imported label.
//
// It deliberately does NOT check that the namespace is one the policy declared. That
// closure is the manifest loader's (validateFlowLabelNamespaceUse), because it is the one
// layer holding the declaration — and the layers that cannot see a manifest at all are
// exactly the ones where an undeclared namespace is provably harmless: a client's attribution
// block only ever ADDS taint. That direction over-blocks on a typo, so refusing it here would buy no safety and
// would reject a legitimately-issued token naming a taxonomy this manifest happens not to
// use.
func ValidateFlowLabel(label string) error {
	namespace, value, imported := SplitFlowLabel(label)
	if !imported {
		if IsNativeFlowLabel(label) {
			return nil
		}
		return fmt.Errorf("unknown flow label %q: it names no native class (%s) and carries no %q namespace separator, so it belongs to neither axis",
			label, strings.Join(nativeFlowLabelVocabulary, ", "), FlowLabelNamespaceSep)
	}
	if err := ValidateFlowLabelNamespace(namespace); err != nil {
		return fmt.Errorf("imported flow label %q: %w", label, err)
	}
	switch {
	case value == "":
		return fmt.Errorf("imported flow label %q: the value after %q is empty; an imported label names a class in its taxonomy, not the taxonomy alone", label, FlowLabelNamespaceSep)
	case len(value) > maxFlowLabelValueLen:
		return fmt.Errorf("imported flow label %q: the value is %d bytes, over the %d-byte bound", label, len(value), maxFlowLabelValueLen)
	}
	for _, r := range value {
		// Printable ASCII only, and no space: a set store cannot tell "confidential" from
		// "confidential ", so whitespace would let two labels that read identically taint
		// two different buckets. Non-ASCII is refused for the homoglyph version of the same
		// hazard on a value that gates data egress. Operators slugify ("Highly
		// Confidential" -> "highly-confidential"), which is what the crosswalk a taxonomy
		// mapping produces anyway.
		if r < '!' || r > '~' {
			return fmt.Errorf("imported flow label %q: the value contains %q; imported label values are printable ASCII with no spaces (slugify the taxonomy's own spelling, e.g. %q -> %q)",
				label, r, "Highly Confidential", "highly-confidential")
		}
	}
	return nil
}

// MaxExternalFlowLabels bounds how many labels ONE externally-supplied list may carry — a
// client's attribution block.
//
// The native axis bounded these implicitly at five: the vocabulary was closed, so a list of
// 300,000 labels was rejected at its first entry. Opening the imported axis removed that
// ceiling — every entry is now well-formed — and these lists are normalized (deduped and
// SORTED), unioned into the carried set, re-normalized, and walked, all on the decision path,
// once per enforced call.
//
// Unbounded, that is a CPU amplifier a peer drives from one `_meta` block: measured on the
// flowLabel sink, a decision costs ~20us at five declared labels, 8ms at ten thousand, and
// ~440ms at three hundred thousand — the last still fitting a single request under the 4 MiB
// body cap. Roughly 22,000x for bytes the caller chooses, which is a denial-of-service lever
// rather than untidiness, and it is why the bound is a COUNT rather than a byte budget.
//
// It is NOT what keeps the audit record legible: a deny's details are already bounded whole
// by enforcement.BoundDenialDetails (8 KiB, at the denyResponse funnel), which elides the
// oversized array and leaves the `flow` discriminator and the record intact — verified at
// 300,000 labels, ~4 KB of details. Elision of a long blocked-label list is that bound's
// designed behavior at any count and is not this constant's business.
//
// Sixty-four is far above any real attribution (a call's inputs carry a handful of classes
// across one or two taxonomies) and low enough to keep the decision in the tens of
// microseconds.
//
// It bounds the EXTERNAL surfaces only; the operator-authored lists carry their own count
// bound (MaxAuthoredFlowLabels), for a different reason.
const MaxExternalFlowLabels = 64

// MaxAuthoredFlowLabels bounds how many labels ONE manifest-authored list may carry — a
// labelOutput directive's `labels`, a flowLabel condition's `allow`.
//
// Not a DoS bound: these lists are operator-authored config, so a bad one is an authoring
// mistake rather than a lever a caller pulls. What it buys differs per token, which is why
// the load error states the bound rather than one consequence. A labelOutput's list is what
// the audit record's labels_out/carried_labels are built from, and the manifest file cap
// (32 MiB) admits tens of thousands of distinct labels on one directive. A flowLabel's
// `allow` reaches neither field — it is the sink's subset set, rebuilt and walked once per
// decision, so the bound there is on per-call work.
//
// It bounds ONE LIST, and NEITHER record field is one list: labels_out unions every
// labelOutput on the matched constraint (and, on the principal-blind legs, across every
// capability naming the target), and carried_labels unions everything the anchor has
// accrued. A manifest whose every list sits exactly at this cap can still produce either
// field arbitrarily large, which is why the record carries its own byte backstop beside
// this rather than because of it. Sixty-four mirrors MaxExternalFlowLabels because a
// policy declaring dozens of classes on one target is already past anything real.
const MaxAuthoredFlowLabels = 64

// checkExternalFlowLabels validates one externally-supplied label list: bounded in COUNT,
// every entry usable on one of the two axes. The single checker for every such boundary, so
// a surface added later cannot pick up the per-label rule while missing the count bound —
// which is exactly the pairing the closed vocabulary used to provide for free.
func checkExternalFlowLabels(labels []string, what string) error {
	if len(labels) > MaxExternalFlowLabels {
		return fmt.Errorf("%s declares %d flow labels, more than the maximum of %d", what, len(labels), MaxExternalFlowLabels)
	}
	for _, l := range labels {
		if err := ValidateFlowLabel(l); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
	}
	return nil
}

// ValidateFlowLabelNamespace reports whether ns is a well-formed imported-label namespace:
// lowercase, alphanumeric-with-hyphens, leading letter, bounded.
//
// Lowercase is enforced rather than folded because a label is compared as a whole string
// everywhere it matters (the store's set membership, the sink's subset check), so
// "Purview:x" and "purview:x" would otherwise be two axes that print the same.
func ValidateFlowLabelNamespace(ns string) error {
	switch {
	case ns == "":
		return fmt.Errorf("the namespace before %q is empty; an imported label is %q", FlowLabelNamespaceSep, "namespace"+FlowLabelNamespaceSep+"value")
	case len(ns) > maxFlowLabelNamespaceLen:
		return fmt.Errorf("namespace %q is %d bytes, over the %d-byte bound", ns, len(ns), maxFlowLabelNamespaceLen)
	case ns[0] < 'a' || ns[0] > 'z':
		return fmt.Errorf("namespace %q must start with a lowercase letter", ns)
	}
	for _, r := range ns {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("namespace %q contains %q; a namespace is lowercase letters, digits and hyphens (it is eunox's name for the taxonomy, not the taxonomy's own spelling)", ns, r)
		}
	}
	return nil
}

// NormalizeFlowLabels returns labels in canonical order with duplicates collapsed, so an
// effective set and the audit field derived from it are deterministic regardless of the
// order they arrived in. It is the ONE renderer of a label set; a second copy would not
// fail anything, it would just put a differently-ordered set on the tape.
//
// Canonical order is native-first in vocabulary order, then imported sorted as plain
// strings. Native-first is what keeps a policy that uses only the native axis producing
// byte-identical audit fields to before the second axis existed.
//
// Malformed entries are DROPPED rather than surfaced, and the boundaries that parse untrusted
// input (ParseContextManifest, the token claims) reject a malformed label before it reaches
// here, so on the shipped path there is nothing to drop. A caller that reaches this with one
// anyway owns the direction: unioning taint IN (the declared and forced sets) cannot
// manufacture an allowance by dropping an entry. The paths where a dropped label WOULD shrink an obligation —
// the engine's own store read and label record — validate explicitly and fail closed instead.
func NormalizeFlowLabels(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	in := make(map[string]bool, len(labels))
	for _, l := range labels {
		in[l] = true
	}
	var out []string
	for _, l := range nativeFlowLabelVocabulary {
		if in[l] {
			out = append(out, l)
			delete(in, l)
		}
	}
	imported := make([]string, 0, len(in))
	for l := range in {
		if _, _, ok := SplitFlowLabel(l); ok && ValidateFlowLabel(l) == nil {
			imported = append(imported, l)
		}
	}
	sort.Strings(imported)
	return append(out, imported...)
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
// condition (sink) or a labelOutput directive (source). Single-sourced so the engine's allow-path
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
		if IsLabelOutputDirective(dir) {
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

// LabelOutputDirective asserts — by policy, never by content inference — that the output of
// an allowed call carries the named Labels into the session's accumulated set, where a later
// flowLabel condition checks them (the source half of the source->sink
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
