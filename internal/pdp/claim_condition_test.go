// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// overrideAllowedValues is an embedder's replacement for a built-in condition type — the
// documented use of enforcement.WithConditionHandler. It inverts the built-in's verdict on
// a sentinel value so a test can tell WHICH implementation ran, rather than only that some
// implementation agreed.
type overrideAllowedValues struct{ deniedValue string }

func (o overrideAllowedValues) Handle(_ context.Context, _ capability.Condition, req *capability.EnforceRequest) *enforcement.ConditionError {
	if v, _ := req.Arguments["path"].(string); v == o.deniedValue {
		return &enforcement.ConditionError{
			Code:          capability.ErrCodeValueNotPermitted,
			ConditionType: capability.ConditionTypeAllowedValues,
			Message:       "override refused this value",
		}
	}
	return nil
}

// committingOverride is the other shape WithConditionHandler admits: a replacement that
// CONSUMES state on admit. It cannot be run ahead of the deciding PDP without charging the
// call twice, so the claim-condition seam must refuse to run it rather than double-count.
type committingOverride struct{ overrideAllowedValues }

func (committingOverride) PrepareCommit(context.Context, capability.Condition, *capability.EnforceRequest) (enforcement.DeferredCommit, bool, *enforcement.ConditionError) {
	return enforcement.DeferredCommit{}, false, nil
}

// TestJWTPath_HonorsAConditionHandlerOverride is the composition defect a shared predicate
// could not close. WithConditionHandler redefines what a condition TYPE means for an
// embedder's engine; the manifest path dispatches through that registry and the JWT
// capability-claim path used to call the package-level built-in directly. One engine wired
// into both a ManifestPDP and the JWTPDP intersecting against it therefore enforced two
// different rules for the same condition on the same call — neither failing, neither
// logging, and only wrong together.
func TestJWTPath_HonorsAConditionHandlerOverride(t *testing.T) {
	engine := enforcement.New(enforcement.WithConditionHandler(
		capability.ConditionTypeAllowedValues, overrideAllowedValues{deniedValue: "/tmp/blocked"}))
	inner := NewManifestPDP(nil, engine, killswitch.NewInMemory())

	// The built-in would ALLOW this (the value matches the claim's allowed set) and the
	// operator's override refuses it. The JWT path must report the override's refusal.
	cond := capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}
	req := jwtCondReq("read_file", map[string]interface{}{"path": "/tmp/blocked"}, nil)

	viaBuiltin := evaluateJWTConditions(context.Background(), nil, nil, []capability.Condition{cond}, req)
	require.Nil(t, viaBuiltin, "the built-in predicate allows this value; the test would prove nothing otherwise")

	viaOverride := evaluateJWTConditions(context.Background(), nil, inner, []capability.Condition{cond}, req)
	require.NotNil(t, viaOverride, "an operator's allowedValues override must reach the JWT capability-claim path")
	require.NotNil(t, viaOverride.Denial)
	assert.Equal(t, capability.ErrCodeValueNotPermitted, viaOverride.Denial.Code)
	assert.Contains(t, viaOverride.Denial.Message, "override refused this value")

	// And the converse: a value the override permits is not refused just because it went
	// through the seam. The override is the semantics, in both directions.
	allowed := jwtCondReq("read_file", map[string]interface{}{"path": "/etc/shadow"}, nil)
	assert.Nil(t, evaluateJWTConditions(context.Background(), nil, inner, []capability.Condition{cond}, allowed),
		"the override's verdict governs, including where it is looser than the built-in")
}

// TestJWTPath_FailsClosedOnACommittingOverride pins the one narrowing the seam introduces.
// The claim path runs BEFORE the deciding PDP, so a handler that consumes a quota slot (or
// writes a label) on admit would charge the call here and again when that PDP runs. The
// seam refuses instead — visibly, naming the condition type — rather than silently running
// the built-in in its place, which would be the same two-semantics defect one layer down.
func TestJWTPath_FailsClosedOnACommittingOverride(t *testing.T) {
	engine := enforcement.New(enforcement.WithConditionHandler(
		capability.ConditionTypeAllowedValues, committingOverride{}))
	inner := NewManifestPDP(nil, engine, killswitch.NewInMemory())

	cond := capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}
	resp := evaluateJWTConditions(context.Background(), nil, inner, []capability.Condition{cond},
		jwtCondReq("read_file", map[string]interface{}{"path": "/tmp/ok"}, nil))

	require.NotNil(t, resp, "a committing handler cannot be evaluated ahead of the decision; deny")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType)
	assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.Details["conditionType"])
}

// TestJWTClaimConditions_UnevaluatedConditionsAreFaultsNotPolicyVerdicts is the property the
// two codes above carry, stated where it bites rather than left implicit in a constant.
//
// A refusal's CLASS is read off its code at every layer that asks, and the one thing a policy
// verdict permits that a fault does not is an observing route downgrading it to a forward. Both
// of these arms mean the condition guarding the call was never evaluated once, so there is no
// verdict to stand in for the one that never ran — an --audit route minting the policy code here
// forwarded the call to the upstream and reported "would be allowed" for a call enforce mode
// denies.
func TestJWTClaimConditions_UnevaluatedConditionsAreFaultsNotPolicyVerdicts(t *testing.T) {
	engine := enforcement.New(enforcement.WithConditionHandler(
		capability.ConditionTypeAllowedValues, committingOverride{}))
	inner := NewManifestPDP(nil, engine, killswitch.NewInMemory())

	for name, resp := range map[string]*capability.EnforceResponse{
		"handler cannot be evaluated ahead of the decision": evaluateJWTConditions(context.Background(), nil, inner,
			[]capability.Condition{capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}},
			jwtCondReq("read_file", map[string]interface{}{"path": "/tmp/ok"}, nil)),
		"condition type has no evaluator": evaluateJWTConditions(context.Background(), nil, nil,
			[]capability.Condition{capability.TimeWindowCondition{NotAfter: "2099-01-01T00:00:00Z"}},
			jwtCondReq("storage_access", map[string]interface{}{}, nil)),
	} {
		require.NotNil(t, resp, "%s: must deny", name)
		require.NotNil(t, resp.Denial, "%s: must carry a denial", name)
		assert.Equal(t, capability.DenialClassFault, capability.ClassifyDenialCode(resp.Denial.Code),
			"%s: the class vocabulary calls this a fault; the code is its only encoding", name)
		assert.False(t, resp.Denial.Downgradable(),
			"%s: an observing route must BLOCK a call whose condition nothing evaluated, not forward it", name)
	}
}

// unregisteredCondition names a discriminator no engine registers a handler for — the
// shape a condition type added to the grammar without a handler would have.
type unregisteredCondition struct{}

func (unregisteredCondition) ConditionType() string { return "not-a-registered-type" }

// TestNonCommittingConditionVerdict_UnknownTypeFailsClosed covers the seam's other
// ok=false arm at the engine. An unregistered type is denied by the engine on its own path,
// so a composing layer must not read "no handler" as "the condition passed".
func TestNonCommittingConditionVerdict_UnknownTypeFailsClosed(t *testing.T) {
	cerr, ok := enforcement.NonCommittingConditionVerdict(context.Background(),
		unregisteredCondition{}, &capability.EnforceRequest{})
	assert.Nil(t, cerr)
	assert.False(t, ok, "an unregistered condition type must not read as a pass")

	// A nil condition is the same answer: there is nothing to dispatch on, and reading it
	// as a pass would be the fail-open direction.
	_, ok = enforcement.NonCommittingConditionVerdict(context.Background(), nil, &capability.EnforceRequest{})
	assert.False(t, ok)
}

// TestJWTPDP_EvaluateClaimConditionDelegatesToItsInner pins that a stack of wrappers
// resolves to whatever is actually deciding, and that a JWT-only route (no inner) answers
// from the built-ins — the only case where the built-in IS the deployment's semantics,
// because there is no engine to have overridden it.
func TestJWTPDP_EvaluateClaimConditionDelegatesToItsInner(t *testing.T) {
	engine := enforcement.New(enforcement.WithConditionHandler(
		capability.ConditionTypeAllowedValues, overrideAllowedValues{deniedValue: "/tmp/blocked"}))
	inner := NewManifestPDP(nil, engine, killswitch.NewInMemory())

	cond := capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}
	req := jwtCondReq("read_file", map[string]interface{}{"path": "/tmp/blocked"}, nil)

	wrapped := &JWTPDP{inner: inner}
	cerr, ok := wrapped.EvaluateClaimCondition(context.Background(), cond, req)
	require.True(t, ok)
	require.NotNil(t, cerr, "the wrapper must resolve to the inner PDP's semantics")

	bare := &JWTPDP{}
	cerr, ok = bare.EvaluateClaimCondition(context.Background(), cond, req)
	require.True(t, ok)
	assert.Nil(t, cerr, "with no wrapped PDP the built-ins are the route's semantics")
}

// TestJWTClaimEnforceRequest_PopulatesTheCallIdentity is the first half of the
// partial-request fix: the claim path used to build a two-field literal, so a semantic
// added to the shared predicate that read the target or the session would have seen the
// zero value here and the real one on the manifest path.
func TestJWTClaimEnforceRequest_PopulatesTheCallIdentity(t *testing.T) {
	req := jwtClaimEnforceRequest("sess-7",
		EnforceTarget{Type: capability.TargetTypeResource, Name: "file:///data/x"},
		map[string]interface{}{"uri": "file:///data/x"},
		map[string]interface{}{"task_id": "t-1"})

	assert.Equal(t, "sess-7", req.SessionID)
	assert.Equal(t, "file:///data/x", req.TargetName)
	require.NotNil(t, req.Target)
	assert.Equal(t, "resource", req.Target.Type)
	assert.Equal(t, "file:///data/x", req.Target.Name)
	assert.Equal(t, "file:///data/x", req.Arguments["uri"])
	assert.Equal(t, "t-1", req.Claims["task_id"])
}

// TestEnforceRequestFields_ClaimPathPopulationIsDeliberate turns the silent-divergence risk
// into a build-time signal.
//
// The claim path feeds a PARTIALLY populated request to a predicate shared with the
// manifest path. That is sound only for a predicate reading the fields it populates — and
// a field added to capability.EnforceRequest later, read by a semantic added to the
// predicate later, would diverge with no compile error and no test failure, because there
// is no longer a second hand-written implementation whose incompleteness a reviewer would
// notice by diffing it against the first.
//
// So the decision is recorded here, per field, and this test fails when a field is added:
// whoever adds one has to say whether the claim-side request must carry it. It asserts the
// "populated" set is genuinely non-zero on a real request, so the table cannot drift into
// claiming something the builder does not do.
func TestEnforceRequestFields_ClaimPathPopulationIsDeliberate(t *testing.T) {
	// true  — the claim path populates it, and this test proves it is non-zero.
	// false — deliberately left zero; see jwtClaimEnforceRequest for the reason per field.
	populated := map[string]bool{
		"SessionID":  true,
		"TargetName": true,
		"Arguments":  true,
		"Target":     true,
		"Claims":     true,

		"Context":        false, // the manifest path decides on network position, one frame later
		"Directives":     false, // come from the matched manifest constraint; none is selected yet
		"DeclaredLabels": false, // the flow layer evaluates these over the full request
	}

	req := jwtClaimEnforceRequest("sess-1",
		EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"},
		map[string]interface{}{"path": "/tmp/x"},
		map[string]interface{}{"sub": "agent-1"})

	rv := reflect.ValueOf(*req)
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		want, listed := populated[name]
		if !listed {
			t.Fatalf("capability.EnforceRequest gained field %q: decide whether the JWT "+
				"capability-claim path must populate it (see jwtClaimEnforceRequest), then add it "+
				"to this table. A field left zero here is read as the zero value by any semantic "+
				"the shared predicate gains later, while the manifest path sees the real one.", name)
		}
		isZero := rv.Field(i).IsZero()
		if want && isZero {
			t.Errorf("field %q is recorded as populated but the builder leaves it zero", name)
		}
		if !want && !isZero {
			t.Errorf("field %q is recorded as deliberately zero but the builder populates it", name)
		}
	}
	assert.Equal(t, rt.NumField(), len(populated),
		"every EnforceRequest field must have a recorded decision")
}
