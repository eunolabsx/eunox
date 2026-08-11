// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The audit sink's arrival at the health seam, and the guard that stops a typed nil turning a
// scrape into a panic.
//
// The sink was the one degradable subsystem whose degradation predicate the transport hand-coded,
// which is the duplication the seam exists to remove — and it was the copy with the most
// consequence, since the predicate beside it is the one --require-audit=strict denies live traffic
// on.

package transport

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// The sink answers the seam with a SAMPLE, the same half of the rule the JWT layer follows: the
// counters /healthz renders and the verdict beside them come from one reading, so a record dropped
// mid-scrape cannot put a zero count next to a degraded verdict.
var _ healthReporter = audit.Health{}

// TestHealthSnapshot_AuditVerdictComesFromTheSink pins the fold rather than a predicate of the
// transport's own: what flips the summary is whatever audit.Health.HealthStatus answers.
func TestHealthSnapshot_AuditVerdictComesFromTheSink(t *testing.T) {
	t.Parallel()
	t.Run("coverage loss degrades", func(t *testing.T) {
		t.Parallel()
		snap := healthSnapshot{Status: statusOK, AuditConfigured: true, AuditHealthy: true}
		snap.fold(audit.Health{Dropped: 1}, &snap.AuditHealthy)
		assert.False(t, snap.AuditHealthy)
		assert.Equal(t, statusDegraded, snap.Status)
	})

	// The carve-out, which the transport used to have to remember: a stalled rotation has lost no
	// record, so it must never reach the gate that denies traffic — and it IS a readiness
	// regression, so it must reach this one. Both halves now live on the sink's own verdict.
	t.Run("a maintenance stall degrades readiness alone", func(t *testing.T) {
		t.Parallel()
		h := audit.Health{MaintenanceStalled: true, MaintenanceReason: "rotation deferred: no free name"}
		require.Zero(t, h.Dropped+h.WriteFailures, "a stall is not coverage loss; --require-audit=strict must not deny on it")
		require.Error(t, h.HealthStatus(), "and it is still a readiness regression: the disk bound is unenforced")

		snap := healthSnapshot{Status: statusOK, AuditConfigured: true, AuditHealthy: true}
		snap.fold(h, &snap.AuditHealthy)
		assert.False(t, snap.AuditHealthy)
		assert.Equal(t, statusDegraded, snap.Status)
	})

	t.Run("a healthy sink touches nothing", func(t *testing.T) {
		t.Parallel()
		snap := healthSnapshot{Status: statusOK, AuditConfigured: true, AuditHealthy: true}
		snap.fold(audit.Health{}, &snap.AuditHealthy)
		assert.True(t, snap.AuditHealthy)
		assert.Equal(t, statusOK, snap.Status)
	})
}

// TestHealthSnapshot_AbsentSinkIsDegraded pins where absence is answered, and the answer.
//
// It used to be the transport's own: a `p.sink == nil` arm set both fields by hand while the sink's
// documented verdict for a nil receiver said healthy — two answers to one question, disagreeing.
// The sample carries it now (audit.Health.Absent), so this file holds no audit predicate at all,
// and the answer is DEGRADED: a trail that does not exist is not one an incident responder can read.
func TestHealthSnapshot_AbsentSinkIsDegraded(t *testing.T) {
	t.Parallel()
	p := newHTTPProxy(httpProxyOptions{})
	snap := p.snapshot()
	assert.False(t, snap.AuditConfigured)
	assert.False(t, snap.AuditHealthy, "a trail that does not exist is not one an incident responder can read")
	assert.Equal(t, statusDegraded, snap.Status)

	sink, _ := newTempAuditSink(t)
	healthy := newHTTPProxy(httpProxyOptions{Sink: sink}).snapshot()
	assert.True(t, healthy.AuditConfigured)
	assert.True(t, healthy.AuditHealthy)
	assert.Equal(t, statusOK, healthy.Status)
}

// TestHealthMetrics_AuditVerdictIsOneSeries pins the gauge beside the three counters: alerting on
// "the audit trail is not operating normally" must not be an OR a reader assembles themselves, since
// assembling it means re-deriving the maintenance carve-out at the far end.
func TestHealthMetrics_AuditVerdictIsOneSeries(t *testing.T) {
	t.Parallel()
	sink, _ := newTempAuditSink(t)
	body := metricsBody(t, newHTTPProxy(httpProxyOptions{Sink: sink}))
	assert.Contains(t, body, "eunox_audit_healthy 1\n")
	assert.Contains(t, body, "# TYPE eunox_audit_healthy gauge\n")

	assert.Contains(t, metricsBody(t, newHTTPProxy(httpProxyOptions{})), "eunox_audit_healthy 0\n",
		"and it answers for an absent sink too, which is the state an operator most needs a single series for")
}

// TestHealthFold_WiredButNilSubsystemDegrades pins the ANSWER, which is the part of this guard that
// is a decision rather than a mechanism.
//
// `h == nil` compares the INTERFACE, so an interface holding a `(*killswitch.Redis)(nil)` passed it
// and the call behind it dereferenced a nil receiver — on the endpoints an operator reaches for when
// something is already wrong. Reporting it HEALTHY was the first fix and is worse than the panic for
// this subsystem: a green readiness signal over an emergency stop that cannot answer, against
// killswitch.Manager's rule that a backend which cannot confirm its kill set never serves a silent
// all-clear. A wired-but-nil subsystem therefore degrades — which is also what the audit arm already
// does for a sink it could not open.
func TestHealthFold_WiredButNilSubsystemDegrades(t *testing.T) {
	t.Parallel()
	for name, reporter := range map[string]healthReporter{
		"typed nil pointer":   (*killswitch.Redis)(nil),
		"typed nil in-memory": (*killswitch.InMemory)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snap := healthSnapshot{Status: statusOK, KillSwitchHealthy: true}
			require.NotPanics(t, func() { snap.fold(reporter, &snap.KillSwitchHealthy) })
			assert.False(t, snap.KillSwitchHealthy, "a kill switch that cannot answer is not a healthy one")
			assert.Equal(t, statusDegraded, snap.Status)
		})
	}

	// A nil INTERFACE is the other fact and still reports nothing: nothing was wired, which is the
	// caller's own business — a proxy with no JWT layer folds no JWKS verdict.
	snap := healthSnapshot{Status: statusOK, KillSwitchHealthy: true}
	require.NotPanics(t, func() { snap.fold(nil, &snap.KillSwitchHealthy) })
	assert.True(t, snap.KillSwitchHealthy)
	assert.Equal(t, statusOK, snap.Status)

	// And a struct-valued sample is never nil, so its verdict must still be read — the failure a
	// kind-blind check would introduce while fixing the pointer one.
	healthy := healthSnapshot{Status: statusOK, AuditHealthy: true}
	healthy.fold(audit.Health{}, &healthy.AuditHealthy)
	assert.True(t, healthy.AuditHealthy)
	degraded := healthSnapshot{Status: statusOK, AuditHealthy: true}
	degraded.fold(audit.Health{Dropped: 1}, &degraded.AuditHealthy)
	assert.False(t, degraded.AuditHealthy)
}

// TestHealthSnapshot_TypedNilKillSwitchDegradesRatherThanPanics is the reachable end of the same
// hazard: the type assertion in snapshot() succeeds for a typed nil exactly as the old guard did.
func TestHealthSnapshot_TypedNilKillSwitchDegradesRatherThanPanics(t *testing.T) {
	t.Parallel()
	p := &HTTPProxy{ks: (*killswitch.Redis)(nil)}
	var snap healthSnapshot
	require.NotPanics(t, func() { snap = p.snapshot() })
	assert.False(t, snap.KillSwitchHealthy)
	assert.Equal(t, statusDegraded, snap.Status)
	assert.Contains(t, metricsBody(t, p), "eunox_kill_switch_healthy 0\n")
}
