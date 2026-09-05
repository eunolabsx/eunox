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
// The downgradable column is the second: blastRadius classified an unwired counter a POLICY
// code, which an observing posture downgrades and FORWARDS with the budget neither checked nor
// counted, while its siblings called it a fault. Asserted as a literal per row rather than
// derived from the code under test, so it can actually fail — and asked as Downgradable()
// rather than as the class alone, since the two structural guards keep the MISSING_CONTEXT code
// an operator's SIEM rules are keyed on and block through the producer's override instead.
func TestCounterSubjectGuards_AreIdenticalAcrossEverySpec(t *testing.T) {
	specs := []counterKeySpec{maxCallsBucketSpec, blastRadiusBucketSpec, sequenceHistorySpec}

	cases := []struct {
		name     string
		engine   *Engine
		req      *capability.EnforceRequest
		wantCode string
		wantMsg  string
	}{
		{
			// A fault, not a verdict: the counter is the engine's own state and the budget it
			// was asked about was never evaluated, so no posture may forward past it.
			name:     "nil counter",
			engine:   New(),
			req:      &capability.EnforceRequest{SessionID: "s", TargetName: "read_file"},
			wantCode: capability.ErrCodeEnforcementError,
			wantMsg:  "call counter not configured",
		},
		{
			// A caller-contract fault too, so it takes the same code rather than blaming a
			// sessionId the call never carried. sequenceBlock had no arm for this at all.
			name:     "nil request",
			engine:   New(WithCallCounter(callcounter.NewInMemory())),
			req:      nil,
			wantCode: capability.ErrCodeEnforcementError,
			wantMsg:  "called with a nil request",
		},
		{
			// Keeps MISSING_CONTEXT — an operator's rules are keyed on it, and the code is a
			// genuine policy verdict everywhere else it is minted — and blocks anyway through
			// the producer's override: no subject means the bound was never evaluated, so
			// there is no verdict for an observing route to stand in for.
			name:     "empty anchor",
			engine:   New(WithCallCounter(callcounter.NewInMemory())),
			req:      &capability.EnforceRequest{SessionID: "", TargetName: "read_file"},
			wantCode: capability.ErrCodeMissingContext,
			wantMsg:  "sessionId is required",
		},
	}

	for _, spec := range specs {
		for _, tc := range cases {
			t.Run(spec.condType+"/"+tc.name, func(t *testing.T) {
				condErr := tc.engine.counterSubjectGuards(tc.req, spec)
				require.NotNil(t, condErr, "this misconfiguration must be refused")
				assert.Equal(t, tc.wantCode, condErr.Code,
					"the code must not depend on which counter-backed state this is")
				assert.False(t, denialFor(condErr).Downgradable(),
					"no observing route may forward past a guard that found no subject to evaluate against")
				assert.Equal(t, spec.condType, condErr.ConditionType)
				assert.True(t, strings.Contains(condErr.Message, tc.wantMsg),
					"message = %q, want it to mention %q", condErr.Message, tc.wantMsg)
			})
		}
	}
}

// denialFor asks the refusal the ONE question every layer asks of it, rather than reading the
// class or the override alone — either half on its own is how a fault-shaped refusal comes to be
// forwarded.
func denialFor(condErr *ConditionError) *capability.DenialInfo {
	return &capability.DenialInfo{Code: condErr.Code, BlockOverride: condErr.BlockOverride}
}

// quotaBucketKey's own two additions on top of the shared guards: the target-name guard (which
// sequenceBlock does not take — it keys history on a target it resolves itself) and the observe
// skip, which must sit BELOW every structural guard.
func TestQuotaBucketKey_TargetGuardAndSkipOrder(t *testing.T) {
	for _, spec := range []counterKeySpec{maxCallsBucketSpec, blastRadiusBucketSpec} {
		for _, posture := range []struct {
			name string
			ctx  context.Context
		}{
			{"enforce", context.Background()},
			{"observe", WithSkipQuota(context.Background())},
		} {
			t.Run(spec.condType+"/"+posture.name, func(t *testing.T) {
				eng := New(WithCallCounter(callcounter.NewInMemory()))
				req := &capability.EnforceRequest{SessionID: "s", TargetName: ""}
				key, skip, condErr := eng.quotaBucketKey(posture.ctx, req, spec)
				require.NotNil(t, condErr, "%s must deny an unidentifiable target", posture.name)
				assert.False(t, skip, "%s: skip must not be reported for a failed structural guard", posture.name)
				assert.Empty(t, key)
				assert.Equal(t, capability.ErrCodeMissingContext, condErr.Code)
				assert.False(t, denialFor(condErr).Downgradable(),
					"%s: a bucket that was never derived has no verdict to forward in its place", posture.name)
				assert.Contains(t, condErr.Message, "tool or resource name is required")
			})
		}
	}
}

// The anchor half of the guard: a task-anchored engine keys on the validated task id, so a
// request carrying one and no session must reach the same bucket anchoredKey would build for
// it — the namespace-disagreement C2 records, where the antecedent recorder wrote fine for a
// request the quota guard refused for having no subject.
func TestCounterSubjectGuards_TaskAnchoredRequestNeedsNoSession(t *testing.T) {
	eng := New(WithCallCounter(callcounter.NewInMemory()), WithTaskAnchoredState())
	req := &capability.EnforceRequest{
		TargetName: "read_file",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_file"},
		Claims:     map[string]interface{}{"task_id": "t-1"},
	}
	require.Nil(t, eng.counterSubjectGuards(req, maxCallsBucketSpec),
		"a task-anchored request carrying a task id has a subject to key on")

	key, skip, condErr := eng.quotaBucketKey(context.Background(), req, maxCallsBucketSpec)
	require.Nil(t, condErr)
	assert.False(t, skip)
	assert.Equal(t, eng.anchoredKey(maxCallsBucketSpec.namespace, req, "tool", "read_file"), key,
		"the guard and the key must agree about which subject the bucket belongs to")

	// The same engine still refuses a request with neither, and names the subject the KEY would
	// have used rather than always naming sessionId.
	condErr = eng.counterSubjectGuards(&capability.EnforceRequest{TargetName: "read_file"}, maxCallsBucketSpec)
	require.NotNil(t, condErr)
	assert.Contains(t, condErr.Message, "sessionId is required")
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
