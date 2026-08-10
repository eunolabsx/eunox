// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The sink's answer to the readiness question asked with no request in hand: one sample carrying
// the coverage counters, the maintenance status, and the verdict over both.
//
// It lives in this package because the predicate does. A consumer's health endpoint used to
// hand-code "no sink, or a dropped record, or a write failure, or a stalled rotation" over the
// three getters below, which is one predicate written twice in two packages — the copy that drives
// a readiness probe beside the copy that denies live traffic — and the deliberate carve-out between
// them (a stalled rotation is a readiness regression and must NEVER deny traffic) had to be
// remembered by hand at the far end.

package audit

import "errors"

// Health is the audit sink's operational state as ONE reading: the coverage counters, the log
// maintenance status, and — through HealthStatus — the readiness verdict over them.
//
// A SAMPLE rather than a live queryable, because the consumer needs both the numbers and the
// verdict and must not take two readings to get them: a record dropped between the two emits a
// healthy verdict beside a non-zero count, or the reverse, in one body that then contradicts
// itself. The counters here and the verdict below are derived from the same load.
//
// The zero value is a healthy reading, which is what a nil sink answers. That is deliberate rather
// than convenient: a sink that never opened cannot report on itself, and its ABSENCE is a fact
// about the proxy that wired it — the caller knows it, this package cannot, and folding "absent"
// into "degraded" here would report a healthy sink as broken every time one is legitimately
// optional (--require-audit=off).
type Health struct {
	// Dropped and WriteFailures are the two coverage counters, sampled together. The enforcement
	// verdict is DERIVED from them rather than carried beside them: they are the same reading, so
	// deriving it is not a second one — and a field would make a Health whose verdict contradicts
	// its own counters representable, which is the self-contradicting body this type exists to
	// prevent.
	Dropped       int64
	WriteFailures int64
	// MaintenanceStalled reports rotation or retention pruning making no progress. Deliberately
	// NOT part of Degraded: no record has been lost, so it must not deny traffic under
	// --require-audit=strict. It IS part of HealthStatus, since an unenforced disk bound is a
	// readiness regression an operator has to act on before the filesystem fills.
	MaintenanceStalled bool
	MaintenanceReason  string
}

// Health samples this sink's operational state. A nil sink answers the zero value (healthy), for
// the reason stated on the type.
//
// The counters are loaded once and every verdict derived from that load, rather than each caller
// asking DroppedRecords/WriteFailures/AuditDegraded in sequence and reconciling three readings.
func (s *Sink) Health() Health {
	if s == nil {
		return Health{}
	}
	h := Health{Dropped: s.dropped.Load(), WriteFailures: s.writeFailures.Load()}
	h.MaintenanceStalled, h.MaintenanceReason = s.MaintenanceStalled()
	return h
}

// HealthStatus reports whether the audit trail is operating normally: nil when it is, the cause
// otherwise. It is the readiness verdict — strictly wider than the enforcement one, and this is the
// one place the difference is written down.
//
// Wider by exactly the maintenance stall. A deferred rotation or a stalled prune has lost no
// record — every decision is still written and signed — so it is not audit-integrity loss and must
// not reach the gate that denies live traffic. It is still a readiness regression: the configured
// size/retention bound is unenforced, and the log grows until the filesystem fills, at which point
// writes DO fail and strict mode denies everything. Reporting it early is the whole point.
//
// The two causes are joined rather than concatenated, so a consumer that grows past rendering the
// string can still tell them apart — which is the whole content of the carve-out.
func (h Health) HealthStatus() error {
	var causes []error
	if degraded, reason := coverageLost(h.Dropped, h.WriteFailures); degraded {
		causes = append(causes, errors.New(reason))
	}
	if h.MaintenanceStalled {
		causes = append(causes, errors.New("audit log maintenance stalled: "+h.MaintenanceReason))
	}
	return errors.Join(causes...)
}
