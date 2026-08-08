// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// overCommittingHandler ignores SkipQuota and hands back a bucket — the contract violation the
// engine repairs by dropping the bucket and naming the type in HandlerFaults.
type overCommittingHandler struct{}

func (overCommittingHandler) PrepareCommit(context.Context, capability.Condition, *capability.EnforceRequest) (enforcement.DeferredCommit, bool, *enforcement.ConditionError) {
	return enforcement.DeferredCommit{
		Bucket: capability.QuotaBucket{Key: "fault-bucket", WindowSec: 60, Counted: true, Limit: 5},
		Deny: func(float64, time.Duration) *enforcement.ConditionError {
			return &enforcement.ConditionError{Code: capability.ErrCodeConditionFailed, Message: "over limit"}
		},
	}, false, nil
}

// TestManifestPDP_HandlerFaultSurvivesTheDecision pins the field's passage through THIS layer.
// A repaired handler fault is reported by exactly one thing — the annotation the transport
// stamps from the decision — so a PDP that rebuilds an allow field by field silently turns
// repair-and-report back into repair-and-ignore, and no engine-level or transport-level test
// would notice: both build their decision straight from an Engine.
func TestManifestPDP_HandlerFaultSurvivesTheDecision(t *testing.T) {
	t.Parallel()
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithCommittingConditionHandler(capability.ConditionTypeMaxCalls, overCommittingHandler{}),
	)
	caps := []capability.Constraint{{
		Target:     "tool:read_file",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60}},
	}}
	p := NewManifestPDP(caps, eng, nil)

	// The route posture that produces a fault at all: whole-route observe mode.
	ctx := enforcement.WithSkipQuota(context.Background())
	resp := p.Decide(ctx, "sess-1", EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, nil, "")

	require.Equal(t, capability.DecisionAllow, resp.Decision, "denial: %+v", resp.Denial)
	assert.Equal(t, []string{capability.ConditionTypeMaxCalls}, resp.HandlerFaults,
		"the PDP must hand the engine's fault report on; nothing else reports it")
}
