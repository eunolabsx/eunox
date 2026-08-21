// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The sink's answer to the readiness question asked with no request in hand: one sample carrying
// the coverage counters, the maintenance status, and the verdict over both.
//
// It lives in this package because the predicate does. A consumer's health endpoint used to
// hand-code "no sink, or a dropped record, or a write failure, or a stalled rotation" over one
// accessor per counter, which is one predicate written twice in two packages — the copy that drives
// a readiness probe beside the copy that denies live traffic — and the deliberate carve-out between
// them (a stalled rotation is a readiness regression and must NEVER deny traffic) had to be
// remembered by hand at the far end. Those accessors are gone: this sample is the only way to READ
// the counters, so there is no second reading to reconcile. AuditDegraded loads them too, but for
// the enforcement gate and to stamp its own denial record — evidence beside a verdict rather than a
// health reading, which is why it must not acquire the maintenance lock this sample does.

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
// once. The verdict below therefore reports a sink that is not present, which is what the one
// production consumer already did by hand; a consumer that wants the OPPOSITE for a deployment
// where no sink is expected (--require-audit=off wires none) reads the Present field rather than
// re-deriving the fact from wiring it holds separately.
//
// The ZERO value is therefore a DEGRADED reading, not a healthy one, and that is the fail-safe
// direction the health seam requires of every sample that satisfies it (see the rule stated on
// internal/transport's healthReporter). Stated as Present rather than Absent for exactly that: with
// the polarity the other way a Health{} that reached a consumer before being filled in — a future
// second sink, a sample built by a test double — reported a healthy audit trail, while the sibling
// subsystem answering the same seam reported an outage from ITS zero value. One seam whose two
// implementations fail in opposite directions is a seam with no rule.
type Health struct {
	// Present reports that there IS a sink behind this reading. False means the sample was taken of
	// nothing: the counters below are zero because nothing was measured, not because nothing was
	// lost, which is the distinction a consumer rendering them needs — and the reason this is a
	// field rather than a nil sample.
	//
	// Not the kind of field the doc below refuses. That argument is about carrying a VERDICT beside
	// the counters it should be derived from; this is an input to the verdict, and the only
	// constructor is Sink.Health, which sets it exactly when there is a sink to read the counters
	// from — so an absent sample with non-zero counters is unreachable rather than merely unwritten.
	Present bool
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

// Health samples this sink's operational state. A nil sink answers the zero value — not present,
// and therefore degraded — for the reason stated on
// the type — nil-safe deliberately, so a consumer holding an optional sink takes one reading
// through the same call rather than branching before it and answering for absence itself.
//
// The counters are loaded once and every verdict derived from that load, rather than each caller
// asking for them in sequence and reconciling several readings — which is why this is the only way
// to read them.
func (s *Sink) Health() Health {
	if s == nil {
		return Health{}
	}
	h := Health{Present: true, Dropped: s.dropped.Load(), WriteFailures: s.writeFailures.Load()}
	h.MaintenanceStalled, h.MaintenanceReason = s.maintenanceStalled()
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
	if !h.Present {
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
