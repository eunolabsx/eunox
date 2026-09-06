// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// A subsystem handed over as a TYPED nil is a non-nil interface, so it walks straight past the
// `x == nil` reads that route to each subsystem's fail-closed absent case and panics on the
// first method call that dereferences the receiver. The engine is exported with no
// requireUsableOptions wall in front of it (the transport's own guard covers the proxy's
// options struct, not a library caller's), so these are the shapes an embedder reaches
// directly. Every case here asserts the REFUSAL the absent case already promises — never a
// panic, since a decision point that crashes produces no decision at all and the supervisor,
// not the policy, then decides the traffic.

// nilEvaluator's methods dereference the receiver, which is what makes the typed nil fatal
// rather than merely odd — the shape any evaluator holding configuration has.
type nilEvaluator struct{ backend string }

func (e *nilEvaluator) Evaluate(context.Context, string, interface{}, interface{}, *capability.EnforceRequest) *enforcement.ConditionError {
	_ = e.backend
	return nil
}

// UsesEngineSubsystems makes this the SubsystemDependent shape New itself calls through, so a
// typed nil crashes the constructor and not only the request.
func (e *nilEvaluator) UsesEngineSubsystems() []capability.EngineSubsystem {
	_ = e.backend
	return nil
}

type nilCounter struct{ prefix string }

func (c *nilCounter) IncrementAndGet(context.Context, string, int, int) (int64, error) {
	_ = c.prefix
	return 0, nil
}

func (c *nilCounter) Peek(context.Context, string, int) (int64, error) { _ = c.prefix; return 0, nil }

func (c *nilCounter) AdmitAll(context.Context, []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	_ = c.prefix
	return true, 0, 0, 0, nil
}

type nilFlowStore struct{ prefix string }

func (s *nilFlowStore) Add(context.Context, string, ...string) error { _ = s.prefix; return nil }

func (s *nilFlowStore) Get(context.Context, string) ([]string, error) {
	_ = s.prefix
	return nil, nil
}

func (s *nilFlowStore) Remove(context.Context, string, ...string) error { _ = s.prefix; return nil }

func (s *nilFlowStore) Clear(context.Context, string) error { _ = s.prefix; return nil }

type nilClock struct{ at time.Time }

func (c *nilClock) Now() time.Time { return c.at }

func policyRequest() *capability.EnforceRequest {
	return &capability.EnforceRequest{
		SessionID:  "s-1",
		TargetName: "send_email",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "send_email"},
	}
}

func TestTypedNilPolicyEvaluator_DeniesRatherThanPanics(t *testing.T) {
	t.Parallel()

	caps := []capability.Constraint{{
		Target:     "tool:send_email",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.PolicyCondition{Backend: "opa", Config: map[string]interface{}{"path": "x"}}},
	}}

	// WithPolicyTokens naming "policy" is what makes New ask the evaluator which subsystems it
	// reads — the constructor half of the same defect.
	eng := enforcement.New(
		enforcement.WithPolicyEvaluator((*nilEvaluator)(nil)),
		enforcement.WithPolicyTokens([]string{capability.ConditionTypePolicy}),
	)

	resp := eng.ValidateAction(context.Background(), policyRequest(), caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code,
		"an evaluator that cannot be called reached no verdict, so the refusal must not be downgradable")
	assert.False(t, resp.Denial.Downgradable(), "an observing route must not forward a call nothing evaluated")
}

func TestTypedNilCallCounter_DeniesRatherThanPanics(t *testing.T) {
	t.Parallel()

	caps := []capability.Constraint{{
		Target:     "tool:send_email",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.MaxCallsCondition{Count: 1, WindowSeconds: 60}},
	}}

	eng := enforcement.New(enforcement.WithCallCounter((*nilCounter)(nil)))

	resp := eng.ValidateAction(context.Background(), policyRequest(), caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.False(t, resp.Denial.Downgradable(), "an unwired counter means the budget was neither checked nor counted")
}

func TestTypedNilFlowLabelStore_DeniesRatherThanPanics(t *testing.T) {
	t.Parallel()

	caps := []capability.Constraint{{
		Target:     "tool:send_email",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}},
	}}

	eng := enforcement.New(enforcement.WithFlowLabelStore((*nilFlowStore)(nil)))

	resp := eng.ValidateAction(context.Background(), policyRequest(), caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
}

// The clock has no fail-closed absent case to route to — every read is a bare e.clock.Now() —
// so absent means the DEFAULT here, not nil.
func TestWithClock_ValuelessClockLeavesTheSystemClock(t *testing.T) {
	t.Parallel()

	for name, opt := range map[string]enforcement.Option{
		"plain nil": enforcement.WithClock(nil),
		"typed nil": enforcement.WithClock((*nilClock)(nil)),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			eng := enforcement.New(opt)
			require.NotNil(t, eng.Clock())
			assert.WithinDuration(t, time.Now(), eng.Clock().Now(), time.Minute)

			// The decision path stamps DecidedAt from that clock; before the fix this panicked
			// on the first timeWindow evaluation.
			caps := []capability.Constraint{{
				Target:     "tool:send_email",
				Actions:    []string{"call"},
				Conditions: []capability.Condition{capability.TimeWindowCondition{NotBefore: "00:00", NotAfter: "23:59"}},
			}}
			assert.NotEmpty(t, eng.ValidateAction(context.Background(), policyRequest(), caps).DecidedAt)
		})
	}
}

// A REAL clock still wins, so the normalization cannot be read as "options are advisory".
func TestWithClock_RealClockStillWins(t *testing.T) {
	t.Parallel()

	frozen := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	eng := enforcement.New(enforcement.WithClock(&nilClock{at: frozen}))
	assert.Equal(t, frozen, eng.Clock().Now())
}
