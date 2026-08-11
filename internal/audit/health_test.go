// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openHealthSink(t *testing.T) *Sink {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestHealth_ReadinessIsWiderThanTheEnforcementGate is the reconciliation the seam needed before the
// sink could answer it: the two predicates differ by exactly the maintenance stall, and this is
// where that difference is stated.
//
// A stalled rotation has lost no record — every decision is still written and signed — so it must
// NEVER reach AuditDegraded, which --require-audit=strict consults to deny live traffic. It is still
// a readiness regression, because the configured disk bound is unenforced and the log grows until
// writes themselves fail. A consumer's health endpoint used to hold that carve-out by hand.
func TestHealth_ReadinessIsWiderThanTheEnforcementGate(t *testing.T) {
	t.Parallel()
	s := openHealthSink(t)

	require.NoError(t, s.Health().HealthStatus(), "a fresh sink is operating normally")

	s.setRotationStalled("sibling directory unreadable")
	h := s.Health()
	assert.True(t, h.MaintenanceStalled)
	assert.Zero(t, h.Dropped+h.WriteFailures, "a stalled rotation loses no record, so it may not deny traffic")
	degraded, _, _ := s.AuditDegraded()
	assert.False(t, degraded, "and the enforcement gate must agree, since it is the same fact")
	require.Error(t, h.HealthStatus(), "readiness is the wider question: the disk bound is unenforced")
	assert.Contains(t, h.HealthStatus().Error(), "sibling directory unreadable",
		"and it names the cause, which is what an operator acts on")

	s.setRotationStalled("")
	assert.NoError(t, s.Health().HealthStatus(), "a rotation that next succeeds clears it")
}

// TestHealth_CoverageLossIsOnePredicate pins the enforcement gate and the readiness verdict to the
// same function over the same counters. Two conditions that agree today diverge the first time
// either moves, and nothing fails when they do: one drives a denial, the other a probe.
func TestHealth_CoverageLossIsOnePredicate(t *testing.T) {
	t.Parallel()
	s := openHealthSink(t)
	s.dropped.Store(3)
	s.writeFailures.Store(2)

	degraded, reason, detail := s.AuditDegraded()
	require.True(t, degraded)
	h := s.Health()
	require.Error(t, h.HealthStatus())
	assert.Contains(t, h.HealthStatus().Error(), reason,
		"one predicate, one reason: the readiness verdict states the enforcement gate's own cause rather than a second copy of it")

	// The sample carries the same numbers the reason was built from, which is the whole point of it
	// being a sample: a consumer rendering the counters and folding the verdict takes one reading.
	assert.Equal(t, int64(3), h.Dropped)
	assert.Equal(t, int64(2), h.WriteFailures)
	assert.Equal(t, int64(3), detail["dropped_count"])
	assert.Equal(t, int64(2), detail["write_failure_count"])
}

// TestHealth_NilSinkIsHealthyBecauseAbsenceIsTheCallersFact pins the nil answer and the reason for
// it: a sink that never opened cannot report on itself, and folding "absent" into "degraded" here
// would report every legitimately optional sink (--require-audit=off) as broken.
func TestHealth_NilSinkIsHealthyBecauseAbsenceIsTheCallersFact(t *testing.T) {
	t.Parallel()
	var s *Sink
	assert.Equal(t, Health{}, s.Health())
	assert.NoError(t, s.Health().HealthStatus())
}
