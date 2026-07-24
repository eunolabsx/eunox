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
	got := FlowLabelVocabulary()

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
		assert.True(t, IsFlowLabel(l), "%q is a recognized flow label", l)
	}

	// A label outside the closed set is rejected — the property that makes a misspelled
	// label a load-time error rather than an inert entry.
	assert.False(t, IsFlowLabel("secret"))
	assert.False(t, IsFlowLabel("PUBLIC"), "labels are case-sensitive")
	assert.False(t, IsFlowLabel(""))

	// The returned slice is a copy: a caller cannot mutate the package's set.
	got[0] = "tampered"
	assert.Equal(t, "public", FlowLabelVocabulary()[0], "vocabulary is defensively copied")
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
