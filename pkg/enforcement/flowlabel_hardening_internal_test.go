// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"errors"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
)

// faultOnIncrementCounter fails every IncrementAndGet — the sequenceBlock antecedent write
// recordSessionCall performs — so the atomic source-call commit's SECOND write faults after
// the flow-label write has already committed. The other methods are inert (unused on this
// path). It is the fault injector for the atomic-commit rollback test.
type faultOnIncrementCounter struct{}

func (faultOnIncrementCounter) IncrementAndGet(context.Context, string, int, int) (int64, error) {
	return 0, errors.New("injected seq-write fault")
}
func (faultOnIncrementCounter) Peek(context.Context, string, int) (int64, error) { return 0, nil }
func (faultOnIncrementCounter) IncrementIfBelow(context.Context, string, int, int64) (count int64, admitted bool, retryAfter time.Duration, err error) {
	return 0, false, 0, nil
}
func (faultOnIncrementCounter) IncrementIfAllBelow(context.Context, []string, []int, []int64) (admitted bool, deniedIndex int, count int64, retryAfter time.Duration, err error) {
	return false, 0, 0, 0, nil
}

// TestFlowHardening_AtomicCommitRollsBackOnSeqFault is the atomic-cross-namespace-commit
// acceptance test: a single allowed source call whose constraint carries BOTH a
// labelOutput directive and a sequenceBlock-relevant antecedent write commits both or
// neither. A fault injected between the two writes (the flow write commits, then the seq
// antecedent write faults) must leave NEITHER committed — no stranded flow label, so a
// later flowLabel sink sees clean state. Runs against the in-memory and miniredis stores.
func TestFlowHardening_AtomicCommitRollsBackOnSeqFault(t *testing.T) {
	t.Parallel()
	newRedisStore := func(t *testing.T) capability.FlowLabelStore {
		mr := miniredis.RunT(t)
		client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		return flowlabelstore.NewRedis(client)
	}
	for _, tc := range []struct {
		name  string
		store func(*testing.T) capability.FlowLabelStore
	}{
		{"memory", func(*testing.T) capability.FlowLabelStore { return flowlabelstore.NewInMemory() }},
		{"redis", newRedisStore},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.store(t)

			// A source that labels its output (the flow write). recordSessionCall is NOT
			// skipped (no WithoutAntecedentRecording), so the seq antecedent write runs after
			// the flow write and faults on the injected counter.
			eng := New(WithCallCounter(faultOnIncrementCounter{}), WithFlowLabelStore(store))
			source := capability.Constraint{
				Target:     "tool:read_secret",
				Actions:    []string{"call"},
				Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
			}
			req := &capability.EnforceRequest{
				SessionID: "s",
				ToolName:  "read_secret",
				Target:    &capability.EnforceRequestTarget{Type: "tool", Name: "read_secret"},
			}
			resp := eng.ValidateAction(ctx, req, []capability.Constraint{source})

			// The call fails closed, attributed to the sequenceBlock record fault.
			require.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
			assert.Equal(t, "record", resp.Denial.Details["phase"])

			// Atomicity: the flow label this call added was rolled back, so the store holds
			// nothing for the session — the seq antecedent never committed either (its write
			// is the one that faulted), so NEITHER namespace is left half-recorded.
			present, err := eng.peekSessionLabels(ctx, &capability.EnforceRequest{SessionID: "s"})
			require.NoError(t, err)
			assert.Empty(t, present, "the flow write must be rolled back when its paired seq write faults (neither committed)")

			// And a later flowLabel sink — evaluated on a WORKING counter but the SAME store —
			// sees clean state and is allowed, the concrete downstream guarantee the atomic commit makes.
			verifier := New(WithCallCounter(callcounter.NewInMemory()), WithFlowLabelStore(store))
			sink := verifier.ValidateAction(ctx, &capability.EnforceRequest{
				SessionID: "s",
				ToolName:  "send_email",
				Target:    &capability.EnforceRequestTarget{Type: "tool", Name: "send_email"},
			}, []capability.Constraint{{
				Target:     "tool:send_email",
				Actions:    []string{"call"},
				Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}},
			}})
			assert.Equal(t, capability.DecisionAllow, sink.Decision, "a later sink must see clean state after the rolled-back commit")
		})
	}
}
