// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
)

// TestFlowHardening_TaintOutlivesAnyWindow is the FR-H1 (session-lifetime taint)
// acceptance test: a flow label set by a source read is visible to every later sink in
// the same session with NO wall-clock expiry. It ties BOTH the engine clock and the call
// counter's clock to one fake clock and advances it far past the retired 30-day
// flow-label window; the taint must still deny a later sink. On the old windowed-counter
// implementation the taint would age out and the sink would fail OPEN — this is red there,
// green on the session-lifetime FlowLabelStore.
func TestFlowHardening_TaintOutlivesAnyWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	// The counter tracks the same fake clock, so if flow state still lived in the
	// counter's window (the old design) advancing the clock would expire it.
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(clock.Now))
	eng := enforcement.New(
		enforcement.WithCallCounter(counter),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
		enforcement.WithClock(clock),
	)

	src := eng.ValidateAction(ctx, req("s", "read_secret"), sourceCaps("read_secret", capability.FlowLabelConfidential))
	require.Equal(t, capability.DecisionAllow, src.Decision)
	require.Equal(t, []string{capability.FlowLabelConfidential}, src.LabelsOut)

	// Advance the clock ninety days — three times the retired window, and far beyond any
	// realistic session — without re-emitting the label.
	clock.now = clock.now.Add(90 * 24 * time.Hour)

	sink := eng.ValidateAction(ctx, req("s", "send_email"),
		sinkCaps("send_email", capability.FlowLabelPublic, capability.FlowLabelInternal))
	require.Equal(t, capability.DecisionDeny, sink.Decision, "the taint must persist for the session lifetime, with no wall-clock expiry")
	require.NotNil(t, sink.Denial)
	assert.Equal(t, capability.ConditionTypeFlowLabel, sink.Denial.ConditionType)
	assert.Equal(t, capability.FlowLabelConfidential, sink.Denial.Details["blockedLabel"])
}

// TestFlowHardening_ClearReclaimsSession is the FR-H2 (session-end reclamation) acceptance
// test: when a session ends, ClearSessionLabels releases its flow-label state, so the
// SAME session id (were it reused) starts clean and a later sink sees no taint.
func TestFlowHardening_ClearReclaimsSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	eng := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)

	// Taint the session, and confirm a sink denies while the taint is live.
	require.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, req("s", "read_secret"), sourceCaps("read_secret", capability.FlowLabelConfidential)).Decision)
	tainted := eng.ValidateAction(ctx, req("s", "send_email"), sinkCaps("send_email", capability.FlowLabelPublic))
	require.Equal(t, capability.DecisionDeny, tainted.Decision, "precondition: the live taint denies the sink")

	// End the session.
	require.NoError(t, eng.ClearSessionLabels(ctx, "s"))

	// The reused session id now starts clean: the identical sink is allowed.
	clean := eng.ValidateAction(ctx, req("s", "send_email"), sinkCaps("send_email", capability.FlowLabelPublic))
	assert.Equal(t, capability.DecisionAllow, clean.Decision, "after Clear, the session's taint must be gone")
	assert.Empty(t, clean.CarriedLabels)

	// Clearing a session with no state, or with no store wired, is a safe no-op.
	require.NoError(t, eng.ClearSessionLabels(ctx, "never-seen"))
	require.NoError(t, enforcement.New().ClearSessionLabels(ctx, "s"))
}

// TestFlowHardening_MultiInstanceSharesTaint is the FR-H4 (multi-instance parity)
// acceptance test: a source labeling its output on one engine/instance and a sink reading
// it on another must agree, when both share one Redis-backed FlowLabelStore. This is the
// deployment the shared backend exists for (a source on proxy A, an egress on proxy B);
// without it, the two fail open silently.
func TestFlowHardening_MultiInstanceSharesTaint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	shared := flowlabelstore.NewRedis(client)

	// Two independent engines (proxy instances), each with its own counter, sharing one
	// flow store and the default (empty) counter-key namespace so the session key matches.
	instanceA := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(shared))
	instanceB := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(shared))

	// Source read lands on instance A.
	src := instanceA.ValidateAction(ctx, req("s", "read_secret"), sourceCaps("read_secret", capability.FlowLabelPII))
	require.Equal(t, capability.DecisionAllow, src.Decision)

	// The egress lands on instance B — it must see the taint recorded on A and deny.
	sink := instanceB.ValidateAction(ctx, req("s", "send_email"),
		sinkCaps("send_email", capability.FlowLabelPublic, capability.FlowLabelInternal))
	require.Equal(t, capability.DecisionDeny, sink.Decision, "instance B must observe the taint instance A recorded (shared backend)")
	assert.Equal(t, capability.FlowLabelPII, sink.Denial.Details["blockedLabel"])

	// And a clean egress on B in a DIFFERENT session is unaffected — the taint is
	// per-session, not global.
	other := instanceB.ValidateAction(ctx, req("other", "send_email"),
		sinkCaps("send_email", capability.FlowLabelPublic, capability.FlowLabelInternal))
	assert.Equal(t, capability.DecisionAllow, other.Decision)
}
