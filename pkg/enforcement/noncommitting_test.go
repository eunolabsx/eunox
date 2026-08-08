// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// TestNonCommittingConditionVerdict_DispatchesThroughTheRegistry is the property the seam
// exists for: a composing layer asking THIS engine gets the handler THIS engine would run,
// including one an embedder registered over a built-in. Calling the package-level predicate
// instead would enforce the shipped semantics on one path and the override on another.
func TestNonCommittingConditionVerdict_DispatchesThroughTheRegistry(t *testing.T) {
	cond := capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}
	req := &capability.EnforceRequest{Arguments: map[string]interface{}{"path": "/tmp/ok"}}

	// The built-in permits this value.
	cerr, ok := enforcement.New().NonCommittingConditionVerdict(context.Background(), cond, req)
	require.True(t, ok)
	assert.Nil(t, cerr)

	// An override is what actually runs.
	overridden := enforcement.New(enforcement.WithConditionHandler(
		capability.ConditionTypeAllowedValues,
		enforcement.ConditionHandlerFunc(func(context.Context, capability.Condition, *capability.EnforceRequest) *enforcement.ConditionError {
			return &enforcement.ConditionError{Code: capability.ErrCodeValueNotPermitted, Message: "override"}
		})))
	cerr, ok = overridden.NonCommittingConditionVerdict(context.Background(), cond, req)
	require.True(t, ok)
	require.NotNil(t, cerr)
	assert.Equal(t, "override", cerr.Message)
}

// TestNonCommittingConditionVerdict_RefusesToRunACommittingHandler pins the narrowing. A
// committing handler consumes state on admit, and this seam runs AHEAD of the engine's own
// decision — so evaluating one here would charge the call's quota twice. ok=false is the
// caller's signal to fail closed; running it, or silently substituting the built-in, would
// each be worse.
func TestNonCommittingConditionVerdict_RefusesToRunACommittingHandler(t *testing.T) {
	e := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	cond := capability.MaxCallsCondition{Count: 1, WindowSeconds: 60}
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "tool:x"}

	cerr, ok := e.NonCommittingConditionVerdict(context.Background(), cond, req)
	assert.Nil(t, cerr)
	assert.False(t, ok, "maxCalls commits a window slot on admit; it must not run ahead of the decision")

	// And the quota really was untouched: the one slot is still available to a real decision.
	resp := e.EvaluateConditions(context.Background(), req, &capability.Constraint{
		Target:     "tool:x",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{cond},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision,
		"the refused evaluation must have consumed nothing")
}

// TestNonCommittingConditionVerdict_FailsClosedWithoutAHandler covers the other ok=false
// arm plus the nil guards. None of them may read as "the condition passed".
func TestNonCommittingConditionVerdict_FailsClosedWithoutAHandler(t *testing.T) {
	req := &capability.EnforceRequest{}

	_, ok := enforcement.New().NonCommittingConditionVerdict(context.Background(), unregisteredCondition{}, req)
	assert.False(t, ok, "an unregistered condition type has no semantics to report")

	_, ok = enforcement.New().NonCommittingConditionVerdict(context.Background(), nil, req)
	assert.False(t, ok, "a nil condition has nothing to dispatch on")

	// A nil engine is a legitimate state for an embedder (the fields are unexported), and it
	// answers from the built-ins rather than panicking on what is a refusal path.
	var nilEngine *enforcement.Engine
	cerr, ok := nilEngine.NonCommittingConditionVerdict(context.Background(),
		capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}},
		&capability.EnforceRequest{Arguments: map[string]interface{}{"path": "/etc/shadow"}})
	require.True(t, ok)
	require.NotNil(t, cerr)
	assert.Equal(t, capability.ErrCodeValueNotPermitted, cerr.Code)
}

// TestNonCommittingConditionVerdict_PackageFunctionIsTheBuiltins covers the entry point a
// caller with no engine at all uses — a JWT-only or wiretap route, where the shipped
// predicate IS the deployment's semantics because there is no engine to have overridden it.
func TestNonCommittingConditionVerdict_PackageFunctionIsTheBuiltins(t *testing.T) {
	cond := capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}

	cerr, ok := enforcement.NonCommittingConditionVerdict(context.Background(), cond,
		&capability.EnforceRequest{Arguments: map[string]interface{}{"path": "/tmp/ok"}})
	require.True(t, ok)
	assert.Nil(t, cerr)

	cerr, ok = enforcement.NonCommittingConditionVerdict(context.Background(), cond,
		&capability.EnforceRequest{Arguments: map[string]interface{}{"path": "/etc/shadow"}})
	require.True(t, ok)
	require.NotNil(t, cerr)
	assert.Equal(t, capability.ErrCodeValueNotPermitted, cerr.Code)
	assert.Equal(t, capability.ConditionTypeAllowedValues, cerr.ConditionType)
}

// nilPureHandler implements only the pure interface, so a typed nil of it registers through
// registerPure and reaches every reader of registeredHandler.pure.
type nilPureHandler struct{}

func (h *nilPureHandler) Handle(context.Context, capability.Condition, *capability.EnforceRequest) *enforcement.ConditionError {
	// Nil-receiver SAFE on purpose: the panic is the loud failure, and this fixture pins the
	// quiet one underneath it — an entry the composing layer would otherwise report as passed.
	return nil
}

// TestNonCommittingConditionVerdict_TypedNilHandlerIsNotUsable pins that this entry point and
// the decision path agree about an unusable handler. The engine denies it CONDITION_FAILED
// (hard); reporting ok=true here would have the JWT capability-claim path read the condition as
// SATISFIED for the same registration — a fail-open reachable through a claim, not a manifest.
func TestNonCommittingConditionVerdict_TypedNilHandlerIsNotUsable(t *testing.T) {
	t.Parallel()
	e := enforcement.New(enforcement.WithConditionHandler(capability.ConditionTypeAllowedValues, (*nilPureHandler)(nil)))
	cond := &capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp"}}
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "tool", Arguments: map[string]interface{}{"path": "/etc"}}

	condErr, ok := e.NonCommittingConditionVerdict(context.Background(), cond, req)
	assert.False(t, ok, "an unusable handler must not report a verdict the caller can trust")
	assert.Nil(t, condErr)

	// The decision path's answer for the same registration, which this must not contradict.
	caps := []capability.Constraint{{Target: "tool", Actions: []string{"*"}, Conditions: []capability.Condition{cond}}}
	resp := e.ValidateAction(context.Background(), req, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.True(t, resp.Denial.HardDeny)
}
