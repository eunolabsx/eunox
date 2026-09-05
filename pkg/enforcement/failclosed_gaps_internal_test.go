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
// maxCallsBucket: --audit must not hide misconfigurations
// -----------------------------------------------------------------

// Observe mode (--audit) exists to predict what enforcement would do. Only the counter
// INCREMENT must be suppressed; a nil counter, an empty session, or an unidentifiable
// target deny in enforce mode regardless of any quota, so honoring the skip before those
// guards hid exactly the misconfigurations the audit run is meant to surface — the record
// said ALLOW where enforce mode writes MISSING_CONTEXT.
func TestMaxCallsBucket_SkipQuotaDoesNotBypassStructuralValidation(t *testing.T) {
	cond := capability.MaxCallsCondition{Count: 5, WindowSeconds: 60}

	cases := []struct {
		name     string
		engine   *Engine
		req      *capability.EnforceRequest
		wantCode string
		wantMsg  string
	}{
		{
			name:   "nil counter",
			engine: New(),
			req:    &capability.EnforceRequest{SessionID: "s", TargetName: "read_file"},
			// A fault, not a verdict: an unwired counter is the engine's own state, and the
			// budget it was asked about was never evaluated.
			wantCode: capability.ErrCodeEnforcementError,
			wantMsg:  "call counter not configured",
		},
		{
			name:     "empty session",
			engine:   New(WithCallCounter(callcounter.NewInMemory())),
			req:      &capability.EnforceRequest{SessionID: "", TargetName: "read_file"},
			wantCode: capability.ErrCodeMissingContext,
			wantMsg:  "sessionId is required",
		},
		{
			name:     "empty target name",
			engine:   New(WithCallCounter(callcounter.NewInMemory())),
			req:      &capability.EnforceRequest{SessionID: "s", TargetName: ""},
			wantCode: capability.ErrCodeMissingContext,
			wantMsg:  "tool or resource name is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Enforce mode establishes the expected verdict...
			_, _, skip, condErr := tc.engine.maxCallsBucket(context.Background(), cond, tc.req)
			require.NotNil(t, condErr, "enforce mode must deny this misconfiguration")
			require.False(t, skip)
			assert.Equal(t, tc.wantCode, condErr.Code)

			// ...and observe mode must report the SAME thing rather than skipping past it.
			_, _, skip, condErr = tc.engine.maxCallsBucket(WithSkipQuota(context.Background()), cond, tc.req)
			require.NotNil(t, condErr, "--audit must not hide a misconfiguration enforce mode denies")
			assert.False(t, skip, "skip must not be reported for a request that fails structural validation")
			assert.Equal(t, tc.wantCode, condErr.Code, "the observed code must match what enforce mode would record")
			assert.True(t, strings.Contains(condErr.Message, tc.wantMsg),
				"message = %q, want it to mention %q", condErr.Message, tc.wantMsg)
		})
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

// -----------------------------------------------------------------
// quotaBucketKey: one guard sequence for every counter-backed bucket
// -----------------------------------------------------------------

// The guards are shared rather than mirrored because the family had drifted: blastRadius
// classified an unwired counter CONDITION_FAILED — DenialClassPolicy, which an observing
// posture downgrades and FORWARDS — while maxCalls, sequenceBlock and the commit backstop all
// classified it a fault. This runs the table against every spec, in both postures, so a bucket
// added later cannot reintroduce the split: a misconfiguration must produce the same code
// whatever the condition and whatever the posture.
func TestQuotaBucketKey_GuardsAreIdenticalAcrossEverySpec(t *testing.T) {
	specs := []quotaBucketSpec{maxCallsBucketSpec, blastRadiusBucketSpec}

	cases := []struct {
		name      string
		engine    *Engine
		req       *capability.EnforceRequest
		wantCode  string
		wantClass capability.DenialClass
	}{
		{
			// A fault, not a verdict: the counter is the engine's own state, and the budget it
			// was asked about was never evaluated. DenialClassFault is what stops an --audit
			// route forwarding the call with the budget neither checked nor counted.
			name:      "nil counter",
			engine:    New(),
			req:       &capability.EnforceRequest{SessionID: "s", TargetName: "read_file"},
			wantCode:  capability.ErrCodeEnforcementError,
			wantClass: capability.DenialClassFault,
		},
		{
			name:      "empty session",
			engine:    New(WithCallCounter(callcounter.NewInMemory())),
			req:       &capability.EnforceRequest{SessionID: "", TargetName: "read_file"},
			wantCode:  capability.ErrCodeMissingContext,
			wantClass: capability.ClassifyDenialCode(capability.ErrCodeMissingContext),
		},
		{
			// Not reachable from the decision path, but maxCallsBucket dereferenced req here
			// before the guard was shared; blastRadiusBucket already refused it.
			name:      "nil request",
			engine:    New(WithCallCounter(callcounter.NewInMemory())),
			req:       nil,
			wantCode:  capability.ErrCodeMissingContext,
			wantClass: capability.ClassifyDenialCode(capability.ErrCodeMissingContext),
		},
		{
			name:      "empty target name",
			engine:    New(WithCallCounter(callcounter.NewInMemory())),
			req:       &capability.EnforceRequest{SessionID: "s", TargetName: ""},
			wantCode:  capability.ErrCodeMissingContext,
			wantClass: capability.ClassifyDenialCode(capability.ErrCodeMissingContext),
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
					assert.Equal(t, spec.condType, condErr.ConditionType)
					assert.Equal(t, tc.wantClass, capability.ClassifyDenialCode(condErr.Code),
						"%s: an observing posture must not be able to downgrade and forward this", posture.name)
				}
			})
		}
	}
}

// Each spec still keys its own namespace, so a velocity budget and a maxCalls quota on one
// target cannot share a bucket and corrupt each other's accounting.
func TestQuotaBucketKey_SpecsKeyDisjointNamespaces(t *testing.T) {
	eng := New(WithCallCounter(callcounter.NewInMemory()))
	req := &capability.EnforceRequest{
		SessionID:  "s",
		TargetName: "refund",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "refund"},
	}

	maxCallsKey, _, condErr := eng.quotaBucketKey(context.Background(), req, maxCallsBucketSpec)
	require.Nil(t, condErr)
	blastRadiusKey, _, condErr := eng.quotaBucketKey(context.Background(), req, blastRadiusBucketSpec)
	require.Nil(t, condErr)

	assert.NotEqual(t, maxCallsKey, blastRadiusKey)
	assert.True(t, strings.HasPrefix(maxCallsKey, "maxcalls"), "key = %q", maxCallsKey)
	assert.True(t, strings.HasPrefix(blastRadiusKey, "blastradius"), "key = %q", blastRadiusKey)
}
