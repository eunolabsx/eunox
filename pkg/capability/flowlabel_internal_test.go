// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFlowLabelVocabulary_PinnedFlatSet pins the native flow-label vocabulary: a
// closed, flat set of at most five source classes with no partial order. The exact
// membership is asserted so a future edit that grows the set past five, adds a
// lattice, or renames a class is a deliberate, reviewed change rather than a silent
// drift — the small flat vocabulary is a load-bearing stop-line, not an accident.
func TestFlowLabelVocabulary_PinnedFlatSet(t *testing.T) {
	got := NativeFlowLabelVocabulary()

	// Exactly these five, in this fixed order (the order backs deterministic audit
	// fields and the subset-check enumeration).
	want := []string{"public", "internal", "confidential", "pii", "untrusted"}
	assert.Equal(t, want, got, "the native flow-label vocabulary is pinned")

	// Flat and small: at most five classes, no lattice (there is no ordering type —
	// the vocabulary is a plain string set).
	assert.LessOrEqual(t, len(got), 5, "vocabulary stays flat and small (<=5 classes)")

	// Constants and membership agree with the slice.
	assert.Equal(t, []string{
		FlowLabelPublic, FlowLabelInternal, FlowLabelConfidential, FlowLabelPII, FlowLabelUntrusted,
	}, got)
	for _, l := range got {
		assert.True(t, IsNativeFlowLabel(l), "%q is a recognized flow label", l)
	}

	// A label outside the closed set is rejected — the property that makes a misspelled
	// label a load-time error rather than an inert entry.
	assert.False(t, IsNativeFlowLabel("secret"))
	assert.False(t, IsNativeFlowLabel("PUBLIC"), "labels are case-sensitive")
	assert.False(t, IsNativeFlowLabel(""))

	// The returned slice is a copy: a caller cannot mutate the package's set.
	got[0] = "tampered"
	assert.Equal(t, "public", NativeFlowLabelVocabulary()[0], "vocabulary is defensively copied")
}

// TestValidateFlowLabel_TwoAxes covers the label grammar across both axes: which labels are
// usable, and — for the imported axis, whose values eunox deliberately does not enumerate —
// exactly which structural rules stand in for a closed vocabulary.
func TestValidateFlowLabel_TwoAxes(t *testing.T) {
	longNS := "a" + string(make([]byte, maxFlowLabelNamespaceLen))
	for _, tc := range []struct {
		name, label string
		wantErr     string
	}{
		{name: "native class", label: "pii"},
		{name: "native integrity class", label: "untrusted"},
		{name: "imported label", label: "purview:confidential"},
		{name: "imported with hyphens both halves", label: "ms-info:highly-confidential"},
		{name: "imported with digits in namespace", label: "bigid2:pci"},
		// Splitting on the FIRST separator is what lets a taxonomy whose own classes
		// contain a colon round-trip with no escape rule.
		{name: "value may contain the separator", label: "purview:eu:gdpr-pii"},

		{name: "misspelled native", label: "untrused", wantErr: "belongs to neither axis"},
		{name: "native is case-sensitive", label: "PII", wantErr: "belongs to neither axis"},
		{name: "empty", label: "", wantErr: "belongs to neither axis"},
		{name: "namespace absent", label: ":confidential", wantErr: "namespace before"},
		{name: "value absent", label: "purview:", wantErr: "value after"},
		{name: "uppercase namespace", label: "Purview:x", wantErr: "must start with a lowercase letter"},
		{name: "namespace leading digit", label: "9purview:x", wantErr: "must start with a lowercase letter"},
		{name: "namespace underscore", label: "ms_info:x", wantErr: "lowercase letters, digits and hyphens"},
		{name: "namespace over bound", label: longNS + ":x", wantErr: "over the"},
		// A set store cannot tell "confidential" from "confidential ", so whitespace would
		// let two labels that read identically taint two different buckets.
		{name: "value with a space", label: "purview:highly confidential", wantErr: "printable ASCII with no spaces"},
		{name: "value with a tab", label: "purview:a\tb", wantErr: "printable ASCII with no spaces"},
		{name: "value non-ASCII", label: "purview:confidentiaIİ", wantErr: "printable ASCII with no spaces"},
		{name: "value over bound", label: "purview:" + string(make([]byte, maxFlowLabelValueLen+1)), wantErr: "over the"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFlowLabel(tc.label)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestSplitFlowLabel_AxisIsShape pins that the axes are told apart by SHAPE alone, so
// neither can spell the other and no native-label alias under a namespace exists.
func TestSplitFlowLabel_AxisIsShape(t *testing.T) {
	ns, value, imported := SplitFlowLabel("purview:eu:pii")
	assert.True(t, imported)
	assert.Equal(t, "purview", ns)
	assert.Equal(t, "eu:pii", value, "split on the FIRST separator only")

	ns, value, imported = SplitFlowLabel("pii")
	assert.False(t, imported)
	assert.Empty(t, ns)
	assert.Equal(t, "pii", value)

	// A native class under a namespace is an IMPORTED label that merely looks native: it is
	// a distinct set member, and nothing folds the two together.
	assert.False(t, IsNativeFlowLabel("eunox:pii"))
	assert.NoError(t, ValidateFlowLabel("eunox:pii"))
}

// TestNormalizeFlowLabels_CanonicalOrder pins the canonical order both axes share, and the
// property that keeps it safe to have added a second axis at all: a native-only set renders
// byte-identically to how it did before the imported axis existed, so no existing policy's
// audit fields move.
func TestNormalizeFlowLabels_CanonicalOrder(t *testing.T) {
	// Native-first in VOCABULARY order (not alphabetical), then imported sorted as strings.
	got := NormalizeFlowLabels([]string{
		"purview:secret", "pii", "msip:confidential", "public", "purview:general", "untrusted",
	})
	assert.Equal(t, []string{
		"public", "pii", "untrusted",
		"msip:confidential", "purview:general", "purview:secret",
	}, got)

	// Order-independent and duplicate-collapsing: the same set in any arrival order renders
	// identically, which is what makes the audit field deterministic.
	assert.Equal(t, got, NormalizeFlowLabels([]string{
		"untrusted", "purview:general", "msip:confidential", "public", "purview:secret", "pii", "pii",
	}))

	// Native-only sets are untouched by the second axis.
	assert.Equal(t, []string{"public", "confidential", "untrusted"},
		NormalizeFlowLabels([]string{"untrusted", "confidential", "public"}))
	assert.Nil(t, NormalizeFlowLabels(nil))

	// Malformed entries are dropped; every caller here is unioning taint IN, so a drop
	// cannot manufacture an allowance.
	assert.Equal(t, []string{"pii"}, NormalizeFlowLabels([]string{"pii", "not a label", "purview:"}))
}

// TestFlowLabelCondition_RoundTrip round-trips a flowLabel condition through the
// polymorphic ConditionWrapper (value and empty-allow forms).
func TestFlowLabelCondition_RoundTrip(t *testing.T) {
	cond := FlowLabelCondition{Allow: []string{FlowLabelPublic, FlowLabelInternal}}

	data, err := json.Marshal(ConditionWrapper{Condition: cond})
	require.NoError(t, err)
	assert.Contains(t, string(data), `"type":"flowLabel"`)
	assert.Contains(t, string(data), `"allow"`)

	var decoded ConditionWrapper
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, ConditionTypeFlowLabel, decoded.ConditionType())
	fl := decoded.Condition.(*FlowLabelCondition)
	assert.Equal(t, []string{FlowLabelPublic, FlowLabelInternal}, fl.Allow)

	// An empty allow (the strictest sink: clean-context flows only) round-trips too.
	empty := FlowLabelCondition{Allow: []string{}}
	data, err = json.Marshal(ConditionWrapper{Condition: empty})
	require.NoError(t, err)
	var decodedEmpty ConditionWrapper
	require.NoError(t, json.Unmarshal(data, &decodedEmpty))
	assert.Empty(t, decodedEmpty.Condition.(*FlowLabelCondition).Allow)
}

// TestLabelOutputDirective_RoundTrip round-trips a labelOutput directive through the
// polymorphic DirectiveWrapper in value and pointer forms.
func TestLabelOutputDirective_RoundTrip(t *testing.T) {
	dir := LabelOutputDirective{Labels: []string{FlowLabelConfidential, FlowLabelPII}}

	data, err := json.Marshal(DirectiveWrapper{Directive: dir})
	require.NoError(t, err)
	assert.Contains(t, string(data), `"type":"labelOutput"`)
	assert.Contains(t, string(data), `"labels"`)

	var decoded DirectiveWrapper
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, DirectiveTypeLabelOutput, decoded.DirectiveType())
	assert.Equal(t, []string{FlowLabelConfidential, FlowLabelPII}, decoded.Directive.(*LabelOutputDirective).Labels)

	// Pointer form.
	ptr := &LabelOutputDirective{Labels: []string{FlowLabelUntrusted}}
	data, err = json.Marshal(DirectiveWrapper{Directive: ptr})
	require.NoError(t, err)
	var decodedPtr DirectiveWrapper
	require.NoError(t, json.Unmarshal(data, &decodedPtr))
	assert.Equal(t, []string{FlowLabelUntrusted}, decodedPtr.Directive.(*LabelOutputDirective).Labels)
}

// TestLabelOutputDirective_Sentinel documents that labelOutput's ToObligation is a
// pure interface requirement: it returns a payloadless labelOutput-typed sentinel
// that is never emitted as a response obligation (the engine records the labels as
// session state and skips the directive before it becomes an obligation).
func TestLabelOutputDirective_Sentinel(t *testing.T) {
	ob := LabelOutputDirective{Labels: []string{FlowLabelPublic}}.ToObligation()
	assert.Equal(t, DirectiveTypeLabelOutput, ob.Type)
	assert.Nil(t, ob.Paths, "labelOutput carries no response paths")
}

// TestUnknownDirectiveType_ListsLabelOutput confirms labelOutput joined the closed
// directive grammar: the unknown-type error enumerates it as valid.
func TestUnknownDirectiveType_ListsLabelOutput(t *testing.T) {
	var w DirectiveWrapper
	err := json.Unmarshal([]byte(`{"type":"noSuchDirective"}`), &w)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "labelOutput")
}
