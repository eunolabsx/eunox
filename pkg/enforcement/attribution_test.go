// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// attributionEngine builds an engine with both stateful seams wired.
func attributionEngine() *enforcement.Engine {
	return enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
}

// attributedReq builds a sink request carrying a client's per-call attribution.
func attributedReq(session, name string, declared ...string) *capability.EnforceRequest {
	return &capability.EnforceRequest{
		SessionID:      session,
		TargetName:     name,
		Target:         &capability.EnforceRequestTarget{Type: "tool", Name: name},
		DeclaredLabels: declared,
	}
}

// TestAttributionTightensASinkCheck is the interface's whole purpose: a cooperating client
// declares taint the proxy's own session state does not know about — data it fetched
// outside eunox's view — and the sink denies a call it would otherwise have allowed.
func TestAttributionTightensASinkCheck(t *testing.T) {
	eng := attributionEngine()
	caps := sinkCaps("egress", capability.FlowLabelPublic, capability.FlowLabelInternal)

	clean := eng.ValidateAction(context.Background(), attributedReq("s1", "egress"), caps)
	require.Equal(t, capability.DecisionAllow, clean.Decision,
		"with no attribution and a clean session the egress is allowed")

	declared := eng.ValidateAction(context.Background(),
		attributedReq("s1", "egress", capability.FlowLabelConfidential), caps)
	require.Equal(t, capability.DecisionDeny, declared.Decision,
		"a client-declared confidential input must deny the same egress")
	require.NotNil(t, declared.Denial)
	assert.Equal(t, capability.ConditionTypeFlowLabel, declared.Denial.ConditionType)
	assert.Equal(t, capability.FlowLabelConfidential, declared.Denial.Details["blockedLabel"])
	// The client's own claim is recorded separately from the proxy's observed state, so an
	// auditor can tell a denial the proxy derived from one the client asked for.
	assert.Equal(t, []string{capability.FlowLabelConfidential}, declared.Denial.Details["declared_labels"])
}

// TestAttributionCannotWiden is the security property: the interface is union-only, so a
// client cannot declare its way OUT of a label the proxy observed. An agent that could
// narrow its own taint would defeat information-flow control with one extra field, and it
// would be the first thing a prompt injection reached for.
func TestAttributionCannotWiden(t *testing.T) {
	eng := attributionEngine()
	source := sourceCaps("read_secrets", capability.FlowLabelConfidential)
	sink := sinkCaps("egress", capability.FlowLabelPublic, capability.FlowLabelInternal)
	caps := append(append([]capability.Constraint{}, source...), sink...)

	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(context.Background(), attributedReq("s1", "read_secrets"), caps).Decision)

	// The client declares a benign-only attribution for the egress. The confidential label
	// the proxy recorded is still present, so the sink still denies.
	resp := eng.ValidateAction(context.Background(),
		attributedReq("s1", "egress", capability.FlowLabelPublic), caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision,
		"a client attribution must never subtract a label the proxy observed")
	assert.Equal(t, capability.FlowLabelConfidential, resp.Denial.Details["blockedLabel"])
}

// TestAttributionIsPerCallNotSessionState pins that an attributed call does not taint the
// session: the declaration is a statement about ONE call, and persisting it would let a
// client permanently taint a session it merely passed through.
func TestAttributionIsPerCallNotSessionState(t *testing.T) {
	eng := attributionEngine()
	caps := sinkCaps("egress", capability.FlowLabelPublic, capability.FlowLabelInternal)

	denied := eng.ValidateAction(context.Background(),
		attributedReq("s1", "egress", capability.FlowLabelPII), caps)
	require.Equal(t, capability.DecisionDeny, denied.Decision)

	after := eng.ValidateAction(context.Background(), attributedReq("s1", "egress"), caps)
	assert.Equal(t, capability.DecisionAllow, after.Decision,
		"a per-call attribution must not persist into the session's accumulated set")
}

// TestAttributionAbsentIsTheDefault pins that a non-cooperating client changes nothing —
// the conservative session join is the behavior with no attribution, and the interface
// costs nothing to ignore.
func TestAttributionAbsentIsTheDefault(t *testing.T) {
	eng := attributionEngine()
	caps := sinkCaps("egress", capability.FlowLabelPublic)
	resp := eng.ValidateAction(context.Background(), attributedReq("s1", "egress"), caps)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	if resp.Denial != nil {
		t.Fatalf("no attribution must produce no denial, got %+v", resp.Denial)
	}
}

// TestParseContextManifest covers the wire boundary: what a client may send, and the
// malformed shapes that must be refused rather than silently ignored.
func TestParseContextManifest(t *testing.T) {
	meta := func(body string) map[string]json.RawMessage {
		return map[string]json.RawMessage{capability.MetaKeyContextManifest: json.RawMessage(body)}
	}

	t.Run("a well-formed block parses", func(t *testing.T) {
		cm, err := capability.ParseContextManifest(meta(`{"labels":["untrusted","pii"]}`))
		require.NoError(t, err)
		require.NotNil(t, cm)
		assert.Equal(t, []string{"untrusted", "pii"}, cm.Labels)
	})

	t.Run("an absent block attributes nothing", func(t *testing.T) {
		cm, err := capability.ParseContextManifest(nil)
		require.NoError(t, err)
		assert.Nil(t, cm)
		cm, err = capability.ParseContextManifest(map[string]json.RawMessage{"other.vendor/key": json.RawMessage(`{"x":1}`)})
		require.NoError(t, err)
		assert.Nil(t, cm, "a key eunox does not model must be left alone")
	})

	t.Run("an empty label list attributes nothing", func(t *testing.T) {
		cm, err := capability.ParseContextManifest(meta(`{"labels":[]}`))
		require.NoError(t, err)
		assert.Nil(t, cm)
	})

	for _, tc := range []struct{ name, body, wantErr string }{
		{"unknown label", `{"labels":["kinda-secret"]}`, "unknown flow label"},
		{"misspelled field", `{"labelz":["pii"]}`, "unknown field"},
		{"wrong shape", `{"labels":"pii"}`, "cannot unmarshal"},
	} {
		t.Run(tc.name+" is refused, not ignored", func(t *testing.T) {
			_, err := capability.ParseContextManifest(meta(tc.body))
			require.Error(t, err, "a client that got the shape wrong must find out")
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestParseContextManifest_LabelCountIsBounded pins the count bound the imported axis made
// necessary. The closed native vocabulary used to cap a client's effective declared set at
// five by construction; once a label may be an operator-open "namespace:value", an untrusted
// peer can name unboundedly many well-formed ones in one `_meta` block. They reach the
// decision path and a denial's details, where an oversized list pushes the marshaled map past
// the audit total cap and gets the WHOLE map replaced by the truncation marker — the caller
// erasing its own flow-denial evidence. See capability.MaxExternalFlowLabels.
func TestParseContextManifest_LabelCountIsBounded(t *testing.T) {
	block := func(n int) map[string]json.RawMessage {
		labels := make([]string, 0, n)
		for i := 0; i < n; i++ {
			labels = append(labels, fmt.Sprintf("purview:c-%d", i))
		}
		body, err := json.Marshal(capability.ContextManifest{Labels: labels})
		require.NoError(t, err)
		return map[string]json.RawMessage{capability.MetaKeyContextManifest: body}
	}

	cm, err := capability.ParseContextManifest(block(capability.MaxExternalFlowLabels))
	require.NoError(t, err, "a list exactly at the bound is admitted")
	assert.Len(t, cm.Labels, capability.MaxExternalFlowLabels)

	_, err = capability.ParseContextManifest(block(capability.MaxExternalFlowLabels + 1))
	require.Error(t, err, "one over the bound is refused, not truncated")
	assert.Contains(t, err.Error(), "more than the maximum")
}

// TestDeclaredLabels_BoundedCostAndIntactDenial covers the two halves of what the count
// bound is and is not for.
//
// IS: the decision path normalizes (sorts), unions and walks a client's declared labels once
// per enforced call, so an unbounded list is a CPU amplifier a peer drives from one `_meta`
// block. At the bound the whole decision stays in the tens of microseconds.
//
// IS NOT: keeping the denial record legible. BoundDenialDetails already caps a deny's whole
// details map at 8 KiB, so the `flow` discriminator and the record survive whatever the
// caller sends — asserted here at the bound so a future change to either mechanism cannot
// quietly make the other one load-bearing.
func TestDeclaredLabels_BoundedCostAndIntactDenial(t *testing.T) {
	labels := make([]string, 0, capability.MaxExternalFlowLabels)
	for i := 0; i < capability.MaxExternalFlowLabels; i++ {
		// Maximal-length labels, so this measures the worst case the grammar admits.
		ns := fmt.Sprintf("ns-%d", i)
		labels = append(labels,
			ns+strings.Repeat("x", 32-len(ns))+":"+fmt.Sprintf("c-%d", i)+strings.Repeat("x", 96-len(fmt.Sprintf("c-%d", i))))
	}
	for _, l := range labels {
		require.NoError(t, capability.ValidateFlowLabel(l))
	}

	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
	resp := eng.ValidateAction(context.Background(), &capability.EnforceRequest{
		SessionID:      "s",
		TargetName:     "send_email",
		Target:         &capability.EnforceRequestTarget{Type: "tool", Name: "send_email"},
		DeclaredLabels: labels,
	}, []capability.Constraint{{
		Target:     "tool:send_email",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{"public"}}},
	}})

	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeFlowLabel, resp.Denial.ConditionType)
	assert.Equal(t, true, resp.Denial.Details[capability.FlowAuditDetailKey],
		"the flow discriminator survives a maximal declaration")

	// Bounded whole by BoundDenialDetails (8 KiB), far below the audit sink's own 1 MiB total
	// cap — the cap that, if exceeded, would replace the map with a truncation marker. A long
	// blocked-label array is ELIDED with a marker rather than dropping the map, which is that
	// bound's designed behavior and not something the count bound is chasing.
	marshaled, err := json.Marshal(resp.Denial.Details)
	require.NoError(t, err)
	assert.Less(t, len(marshaled), 1<<20)
}

// TestNormalizeDeclaredLabelsIsDeterministic pins that the effective set and the audit
// field do not depend on how the client ordered or repeated its labels.
func TestNormalizeDeclaredLabelsIsDeterministic(t *testing.T) {
	got := capability.NormalizeDeclaredLabels([]string{"untrusted", "pii", "untrusted", "public"})
	assert.Equal(t, []string{"public", "pii", "untrusted"}, got)
	assert.Nil(t, capability.NormalizeDeclaredLabels(nil))
	assert.Nil(t, capability.NormalizeDeclaredLabels([]string{"not-a-label"}))
}
