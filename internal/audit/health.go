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

// Health is the audit sink's operational state as ONE reading: whether there is a trail at all,
// the coverage counters, the log maintenance status, and — through HealthStatus — the readiness
// verdict over them.
//
// A SAMPLE rather than a live queryable, because the consumer needs both the numbers and the
// verdict and must not take two readings to get them: a record dropped between the two emits a
// healthy verdict beside a non-zero count, or the reverse, in one body that then contradicts
// itself. The counters here and the verdict below are derived from the same load.
//
// ABSENCE is part of the sample rather than a fact the caller keeps beside it. It was the caller's:
// a nil sink answered the zero value (healthy) on the argument that only the wiring knows whether
// it expected one, and the single production consumer then overrode that verdict by hand — so the
// documented answer and the shipped one disagreed, and the next consumer to follow the documented
// one would report a proxy writing no audit trail at all as operating normally. "There is no trail
// to read" is a statement about audit coverage like the two counters are, so it is answered here,
// once, and a consumer for which a missing sink is EXPECTED (--require-audit=off wires none) reads
// Absent and decides for itself rather than re-deriving the fact.
type Health struct {
	// Absent reports that there is no sink: this is a reading taken of nothing. The counters below
	// are zero because nothing was measured, not because nothing was lost, which is the distinction
	// a consumer rendering them needs — and the reason this is a field rather than a nil sample.
	Absent bool
	// Dropped and WriteFailures are the two coverage counters, sampled together. They are distinct
	// findings for an operator: Dropped is back-pressure on a healthy file (the write queue could
	// not keep up), WriteFailures is the backing file itself refusing (full disk, EIO, a file lost
	// to a failed rotation), so a non-zero WriteFailures means the tape is unwritable even where
	// the queue kept up.
	//
	// The enforcement verdict is DERIVED from them rather than carried beside them: they are the
	// same reading, so deriving it is not a second one — and a field would make a Health whose
	// verdict contradicts its own counters representable, which is the self-contradicting body this
	// type exists to prevent.
	Dropped       int64
	WriteFailures int64
	// MaintenanceStalled reports rotation or retention pruning making no progress. Deliberately
	// NOT part of Degraded: no record has been lost, so it must not deny traffic under
	// --require-audit=strict. It IS part of HealthStatus, since an unenforced disk bound is a
	// readiness regression an operator has to act on before the filesystem fills.
	MaintenanceStalled bool
	MaintenanceReason  string
}

// Health samples this sink's operational state. A nil sink answers Absent, for the reason stated on
// the type — nil-safe deliberately, so a consumer holding an optional sink takes one reading
// through the same call rather than branching before it and answering for absence itself.
//
// The counters are loaded once and every verdict derived from that load, rather than each caller
// asking for them in sequence and reconciling several readings — which is why this is the only way
// to read them.
func (s *Sink) Health() Health {
	if s == nil {
		return Health{Absent: true}
	}
	h := Health{Dropped: s.dropped.Load(), WriteFailures: s.writeFailures.Load()}
	h.MaintenanceStalled, h.MaintenanceReason = s.MaintenanceStalled()
	return h
}

// HealthStatus reports whether the audit trail is operating normally: nil when it is, the cause
// otherwise. It is the readiness verdict — strictly wider than the enforcement one, and this is the
// one place the difference is written down.
//
// Wider by exactly the maintenance stall and the absent sink, and for the same reason in both
// cases: neither is audit-integrity LOSS, and both are things an operator has to act on. A deferred
// rotation or a stalled prune has lost no record — every decision is still written and signed — so
// it must not reach the gate that denies live traffic, but the configured size/retention bound is
// unenforced and the log grows until the filesystem fills, at which point writes DO fail and strict
// mode denies everything. A sink that never opened has lost no record either, because it has
// recorded none: there is nothing to deny traffic OVER, and nothing to read afterwards.
//
// The causes are joined rather than concatenated, so a consumer that grows past rendering the
// string can still tell them apart — which is the whole content of the carve-out.
func (h Health) HealthStatus() error {
	var causes []error
	if h.Absent {
		causes = append(causes, errors.New("no audit sink: this proxy writes no audit trail"))
	}
	if degraded, reason := coverageLost(h.Dropped, h.WriteFailures); degraded {
		causes = append(causes, errors.New(reason))
	}
	if h.MaintenanceStalled {
		causes = append(causes, errors.New("audit log maintenance stalled: "+h.MaintenanceReason))
	}
	return errors.Join(causes...)
}
