// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Loopback-only operational endpoints for the HTTP transport: /healthz (a JSON
// health snapshot) and /metrics (Prometheus text exposition). Both share the
// loopback guard used by /control/kill, so neither is reachable from off-host; a
// scraper runs as a sidecar or via the loopback interface.

package transport

import (
	"fmt"
	"net/http"

	"github.com/eunolabs/eunox/pkg/circuitbreaker"
)

// healthReporter is the readiness question asked of a kill-switch backend with no request in
// hand. Every killswitch.Manager answers it (in-memory always nil: an in-process kill set is
// always confirmable), but the proxy holds killActivator — narrow to keep the kill's UNDO path
// shut — which carries no reader at all, so the assertion stays. A value satisfying that
// interface without HealthStatus is reported healthy, which is why the one the binary wires is
// a full Manager.
type healthReporter interface {
	HealthStatus() error
}

// healthSnapshot is the live operational state surfaced by /healthz and /metrics.
type healthSnapshot struct {
	Status            string `json:"status"` // "ok" | "degraded"
	Sessions          int    `json:"sessions"`
	MaxSessions       int    `json:"maxSessions"` // 0 = unlimited
	Routes            int    `json:"routes"`
	AuditDropped      int64  `json:"auditDropped"`      // records dropped because the write queue was full
	AuditWriteFailed  int64  `json:"auditWriteFailed"`  // records that reached the drainer but failed to write to disk
	AuditConfigured   bool   `json:"auditConfigured"`   // false when the audit sink failed to open
	KillSwitchHealthy bool   `json:"killSwitchHealthy"` // false when a Redis backend is degraded
	// AuditMaintenanceStalled is true when rotation/retention pruning has stopped making
	// progress. Records are still written and signed (not an audit-integrity loss, does not
	// gate traffic) — the size/retention bound is just unenforced until the fault is fixed.
	AuditMaintenanceStalled bool   `json:"auditMaintenanceStalled"`
	AuditMaintenanceReason  string `json:"auditMaintenanceReason,omitempty"`
	// JWKS is absent when no JWT layer reports a key-fetch breaker. Nested rather than three
	// flat fields so presence is ONE fact: a per-field `omitempty` drops a legitimate zero
	// counter, and a zeroed state on a proxy that fetches no keys reads as healthy key
	// fetching rather than as none.
	JWKS *jwksHealth `json:"jwks,omitempty"`
}

// jwksHealth is the JWT layer's key-fetch state, as reported by the circuit breaker guarding
// IdP fetches. Its fields carry no omitempty: within the block a zero is a measurement.
type jwksHealth struct {
	BreakerState   circuitbreaker.State `json:"breakerState"`
	FetchFailures  int64                `json:"fetchFailures"`
	FetchSuccesses int64                `json:"fetchSuccesses"`
}

// keyFetchImpeded reports whether the breaker is refusing, or has tripped and not yet proved
// recovery. Anything but closed counts, including a state this build does not recognize.
//
// Half-open is NOT a recovering state: it is entered only from open and closes only once a
// probe SUCCEEDS, so it means "tripped, retry outstanding" — and at the shipped
// HalfOpenMaxProbes=1 a probe in flight refuses every other fetch exactly as open does, while
// a cooldown that merely lapsed with no traffic reports half-open forever. Reading only
// StateOpen therefore went quiet for most of a sustained outage.
func (j *jwksHealth) keyFetchImpeded() bool {
	return j != nil && j.BreakerState != circuitbreaker.StateClosed
}

// snapshot gathers the current operational state (locked map reads plus atomic
// counter loads).
func (p *HTTPProxy) snapshot() healthSnapshot {
	snap := healthSnapshot{
		Status:            "ok",
		Sessions:          p.sessionCount(),
		MaxSessions:       p.maxSessions,
		Routes:            len(p.routes),
		AuditConfigured:   p.sink != nil,
		KillSwitchHealthy: true,
	}
	if p.sink != nil {
		snap.AuditDropped = p.sink.DroppedRecords()
		snap.AuditWriteFailed = p.sink.WriteFailures()
		snap.AuditMaintenanceStalled, snap.AuditMaintenanceReason = p.sink.MaintenanceStalled()
	}
	// A degraded kill switch (e.g. a Redis partition) flips status to "degraded". The
	// operational consequence depends on the configured degraded mode (fail-closed by
	// default, fail-open opt-in) — either way it's not operating normally.
	if hr, ok := p.ks.(healthReporter); ok && hr.HealthStatus() != nil {
		snap.KillSwitchHealthy = false
		snap.Status = "degraded"
	}
	// Asked of the shared validator rather than per route: WrapRoutesWithJWT gives every
	// route wrapper this one validator's cache, so the routes share a single breaker.
	if p.jwtPDP != nil {
		if st, ok := p.jwtPDP.Cache().BreakerStats(); ok {
			snap.JWKS = &jwksHealth{
				BreakerState:   st.State,
				FetchFailures:  st.TotalFailures,
				FetchSuccesses: st.TotalSuccesses,
			}
		}
	}
	// An impeded breaker means key refreshes are being refused: an unknown-kid token fails
	// closed now and every token does once the cached set passes its TTL. Degraded here means
	// what it means for the kill switch — not operating normally — not "already rejecting".
	if snap.JWKS.keyFetchImpeded() {
		snap.Status = "degraded"
	}
	// Audit-integrity loss also flips status to "degraded": no sink, dropped records, or
	// failed writes each mean the tamper-evident audit trail is incomplete.
	if !snap.AuditConfigured || snap.AuditDropped > 0 || snap.AuditWriteFailed > 0 {
		snap.Status = "degraded"
	}
	// A stalled rotation/prune is a readiness regression too, even though no record was lost.
	// NOT part of AuditDegraded, so it never denies live traffic under --require-audit=strict.
	if snap.AuditMaintenanceStalled {
		snap.Status = "degraded"
	}
	return snap
}

// handleHealth serves GET /healthz (loopback only): a JSON health snapshot. It
// always returns 200 for liveness — the Status field ("ok"/"degraded") carries
// the readiness signal, so liveness probes do not flap on degradation.
func (p *HTTPProxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !p.loopbackOnly(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSONMsg(w, p.snapshot())
}

// handleMetrics serves GET /metrics (loopback only) in Prometheus text exposition
// format. The metric set is intentionally small and stable: the values an operator
// alerts on (audit loss, session pressure, kill-switch health).
func (p *HTTPProxy) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !p.loopbackOnly(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := p.snapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	// wf discards write errors: a broken scrape connection is not actionable here.
	wf := func(format string, args ...interface{}) { _, _ = fmt.Fprintf(w, format, args...) }
	wf("# HELP eunox_active_sessions Current number of active client sessions.\n")
	wf("# TYPE eunox_active_sessions gauge\n")
	wf("eunox_active_sessions %d\n", snap.Sessions)
	wf("# HELP eunox_max_sessions Configured maximum concurrent sessions (0 = unlimited).\n")
	wf("# TYPE eunox_max_sessions gauge\n")
	wf("eunox_max_sessions %d\n", snap.MaxSessions)
	wf("# HELP eunox_routes Configured upstream routes.\n")
	wf("# TYPE eunox_routes gauge\n")
	wf("eunox_routes %d\n", snap.Routes)
	wf("# HELP eunox_audit_dropped_records_total Audit records discarded because the write queue was full.\n")
	wf("# TYPE eunox_audit_dropped_records_total counter\n")
	wf("eunox_audit_dropped_records_total %d\n", snap.AuditDropped)
	wf("# HELP eunox_audit_write_failures_total Audit records that reached the drainer but failed to write to disk (full disk, EIO, ...). A non-zero value means the audit trail is incomplete.\n")
	wf("# TYPE eunox_audit_write_failures_total counter\n")
	wf("eunox_audit_write_failures_total %d\n", snap.AuditWriteFailed)
	wf("# HELP eunox_audit_sink_up Whether the audit sink opened successfully (1 = up).\n")
	wf("# TYPE eunox_audit_sink_up gauge\n")
	wf("eunox_audit_sink_up %d\n", gaugeBool(snap.AuditConfigured))
	wf("# HELP eunox_kill_switch_healthy Kill-switch backend health (1 = healthy, 0 = degraded).\n")
	wf("# TYPE eunox_kill_switch_healthy gauge\n")
	wf("eunox_kill_switch_healthy %d\n", gaugeBool(snap.KillSwitchHealthy))
	wf("# HELP eunox_audit_maintenance_stalled Audit rotation or retention pruning is not making progress (1 = stalled). No records are lost, but the configured size/retention bound is unenforced and the log will grow until the fault is fixed.\n")
	wf("# TYPE eunox_audit_maintenance_stalled gauge\n")
	wf("eunox_audit_maintenance_stalled %d\n", gaugeBool(snap.AuditMaintenanceStalled))
	// Absent without a JWT layer rather than emitted as zeros: a permanently-healthy gauge on
	// a proxy that fetches no keys is indistinguishable from healthy key fetching, and an
	// absent series is what a scraper already knows how to read.
	if snap.JWKS != nil {
		wf("# HELP eunox_jwks_fetch_healthy IdP key fetching is unimpeded (1 = breaker closed). 0 means refreshes are refused or the breaker has tripped and not yet proved recovery: a token whose kid the cached key set does not carry fails closed now, and every token fails once that set passes its TTL.\n")
		wf("# TYPE eunox_jwks_fetch_healthy gauge\n")
		wf("eunox_jwks_fetch_healthy %d\n", gaugeBool(!snap.JWKS.keyFetchImpeded()))
		// The state as a labelled set, the Prometheus spelling for an enum: a single boolean
		// could not name half-open, which is the state a sustained outage sits in longest.
		wf("# HELP eunox_jwks_breaker_state IdP key-fetch circuit breaker state (1 on the active state).\n")
		wf("# TYPE eunox_jwks_breaker_state gauge\n")
		for _, st := range []circuitbreaker.State{circuitbreaker.StateClosed, circuitbreaker.StateHalfOpen, circuitbreaker.StateOpen} {
			wf("eunox_jwks_breaker_state{state=%q} %d\n", string(st), gaugeBool(snap.JWKS.BreakerState == st))
		}
		wf("# HELP eunox_jwks_fetch_failures_total JWKS fetches the breaker admitted and saw fail. Fetches it REFUSED are not counted here -- watch eunox_jwks_fetch_healthy for those.\n")
		wf("# TYPE eunox_jwks_fetch_failures_total counter\n")
		wf("eunox_jwks_fetch_failures_total %d\n", snap.JWKS.FetchFailures)
		wf("# HELP eunox_jwks_fetch_successes_total JWKS fetches reported successful to the breaker, including outcomes it then discarded as stale. Observability only -- do not read a rising value as recovery; eunox_jwks_fetch_healthy is the recovery signal.\n")
		wf("# TYPE eunox_jwks_fetch_successes_total counter\n")
		wf("eunox_jwks_fetch_successes_total %d\n", snap.JWKS.FetchSuccesses)
	}
}

// gaugeBool renders a boolean as a Prometheus gauge sample. One spelling, so a new gauge
// cannot invert the conversion in its own copy of the three-line idiom.
func gaugeBool(b bool) int {
	if b {
		return 1
	}
	return 0
}
