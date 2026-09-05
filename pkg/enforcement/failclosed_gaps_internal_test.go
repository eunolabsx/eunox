// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
)

// -----------------------------------------------------------------
// peekSessionLabels: an out-of-vocabulary stored label fails closed
// -----------------------------------------------------------------

// The sink rule is "present and not in Allow => deny", so DROPPING a present label can
// only suppress a denial. A store holding a label this build's vocabulary does not contain
// — two proxy versions sharing one Redis flow store, or a store written out-of-band — must
// therefore fail closed, not be quietly filtered out on the way to the sink check.
func TestPeekSessionLabels_UnknownStoredLabelFailsClosed(t *testing.T) {
	ctx := context.Background()
	store := flowlabelstore.NewInMemory()
	eng := New(WithCallCounter(callcounter.NewInMemory()), WithFlowLabelStore(store))

	// Poke a label from a hypothetical newer vocabulary straight into the store, as a
	// peer proxy running a different build would.
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "send_email"}
	require.NoError(t, store.Add(ctx, eng.flowSessionKey("s"), "regulated-phi"))

	present, err := eng.peekSessionLabels(ctx, req)
	require.Error(t, err, "an out-of-vocabulary stored label must be an error, not silently dropped")
	assert.Nil(t, present)
	assert.Contains(t, err.Error(), "regulated-phi", "the error must name the label an operator has to act on")
}

// The whole point of the error: the sink DENIES rather than allowing a call whose session
// carries a label this build cannot interpret (and so could never have allowlisted).
func TestPeekSessionLabels_UnknownStoredLabelDeniesAtSink(t *testing.T) {
	ctx := context.Background()
	store := flowlabelstore.NewInMemory()
	eng := New(WithCallCounter(callcounter.NewInMemory()), WithFlowLabelStore(store))
	require.NoError(t, store.Add(ctx, eng.flowSessionKey("s"), "regulated-phi"))

	resp := eng.ValidateAction(ctx, &capability.EnforceRequest{
		SessionID:  "s",
		TargetName: "send_email",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "send_email"},
	}, []capability.Constraint{{
		Target:     "tool:send_email",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}},
	}})

	assert.Equal(t, capability.DecisionDeny, resp.Decision,
		"a sink must deny when the session carries a label outside this build's vocabulary")
}

// Known labels are unaffected: they still come back in vocabulary order.
func TestPeekSessionLabels_KnownLabelsStillOrdered(t *testing.T) {
	ctx := context.Background()
	store := flowlabelstore.NewInMemory()
	eng := New(WithCallCounter(callcounter.NewInMemory()), WithFlowLabelStore(store))
	require.NoError(t, store.Add(ctx, eng.flowSessionKey("s"),
		capability.FlowLabelUntrusted, capability.FlowLabelConfidential))

	present, err := eng.peekSessionLabels(ctx, &capability.EnforceRequest{SessionID: "s"})
	require.NoError(t, err)
	want := []string{}
	for _, l := range capability.NativeFlowLabelVocabulary() {
		if l == capability.FlowLabelUntrusted || l == capability.FlowLabelConfidential {
			want = append(want, l)
		}
	}
	assert.Equal(t, want, present, "known labels must still be returned in fixed vocabulary order")
}

// -----------------------------------------------------------------
// quotaBucketKey: one guard sequence for every counter-backed bucket
// -----------------------------------------------------------------

// The observe half is the original regression: --audit skips the COUNTER, not the guards in
// front of it, so honoring the skip first hid exactly the misconfigurations an audit run exists
// to surface — the record said ALLOW where enforce mode writes MISSING_CONTEXT.
//
// The class column is the second: blastRadius classified an unwired counter a POLICY code, which
// an observing posture downgrades and FORWARDS with the budget neither checked nor counted,
// while its siblings called it a fault. Asserted as a literal per row rather than derived from
// the code under test, so it can actually fail.
func TestQuotaBucketKey_GuardsAreIdenticalAcrossEverySpec(t *testing.T) {
	specs := []quotaBucketSpec{maxCallsBucketSpec, blastRadiusBucketSpec}

	cases := []struct {
		name      string
		engine    *Engine
		req       *capability.EnforceRequest
		wantCode  string
		wantClass capability.DenialClass
		wantMsg   string
	}{
		{
			// A fault, not a verdict: the counter is the engine's own state and the budget it
			// was asked about was never evaluated, so no posture may forward past it.
			name:      "nil counter",
			engine:    New(),
			req:       &capability.EnforceRequest{SessionID: "s", TargetName: "read_file"},
			wantCode:  capability.ErrCodeEnforcementError,
			wantClass: capability.DenialClassFault,
			wantMsg:   "call counter not configured",
		},
		{
			// A caller-contract fault too, so it takes the same code rather than blaming a
			// sessionId the call never carried.
			name:      "nil request",
			engine:    New(WithCallCounter(callcounter.NewInMemory())),
			req:       nil,
			wantCode:  capability.ErrCodeEnforcementError,
			wantClass: capability.DenialClassFault,
			wantMsg:   "called with a nil request",
		},
		{
			// DenialClassPolicy, recorded rather than asserted as safe: this refusal IS
			// downgradable, so an observing route forwards a call whose bucket was never
			// derived. It pre-dates the shared guard and is not this seam's to change — pinned
			// so a future correction is a visible edit rather than a silent one.
			name:      "empty session",
			engine:    New(WithCallCounter(callcounter.NewInMemory())),
			req:       &capability.EnforceRequest{SessionID: "", TargetName: "read_file"},
			wantCode:  capability.ErrCodeMissingContext,
			wantClass: capability.DenialClassPolicy,
			wantMsg:   "sessionId is required",
		},
		{
			name:      "empty target name",
			engine:    New(WithCallCounter(callcounter.NewInMemory())),
			req:       &capability.EnforceRequest{SessionID: "s", TargetName: ""},
			wantCode:  capability.ErrCodeMissingContext,
			wantClass: capability.DenialClassPolicy,
			wantMsg:   "tool or resource name is required",
		},
	}

	for _, spec := range specs {
		for _, tc := range cases {
			t.Run(spec.condType+"/"+tc.name, func(t *testing.T) {
				for _, posture := range []struct {
					name string
					ctx  context.Context
				}{
					{"enforce", context.Background()},
					{"observe", WithSkipQuota(context.Background())},
				} {
					key, skip, condErr := tc.engine.quotaBucketKey(posture.ctx, tc.req, spec)
					require.NotNil(t, condErr, "%s must deny this misconfiguration", posture.name)
					assert.False(t, skip, "%s: skip must not be reported for a failed structural guard", posture.name)
					assert.Empty(t, key)
					assert.Equal(t, tc.wantCode, condErr.Code,
						"%s: the code must not depend on the condition or the posture", posture.name)
					assert.Equal(t, tc.wantClass, capability.ClassifyDenialCode(condErr.Code),
						"%s: whether this refusal is downgradable must not depend on the condition", posture.name)
					assert.Equal(t, spec.condType, condErr.ConditionType)
					assert.True(t, strings.Contains(condErr.Message, tc.wantMsg),
						"%s: message = %q, want it to mention %q", posture.name, condErr.Message, tc.wantMsg)
				}
			})
		}
	}
}

// The skip itself is intact for a well-formed request: no quota is consumed under --audit.
func TestMaxCallsBucket_SkipQuotaStillSkipsAValidRequest(t *testing.T) {
	counter := callcounter.NewInMemory()
	eng := New(WithCallCounter(counter))
	cond := capability.MaxCallsCondition{Count: 5, WindowSeconds: 60}
	req := &capability.EnforceRequest{
		SessionID:  "s",
		TargetName: "read_file",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_file"},
	}

	mc, key, skip, condErr := eng.maxCallsBucket(WithSkipQuota(context.Background()), cond, req)
	require.Nil(t, condErr)
	assert.True(t, skip, "a well-formed request must still skip quota under --audit")
	assert.Nil(t, mc)
	assert.Empty(t, key)
}
