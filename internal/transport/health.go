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
)

// healthReporter is the subset of a kill-switch backend that can report its own
// health. The Redis kill switch implements it (it tracks the last pub/sub refresh
// error); the in-memory backend does not and is treated as always healthy.
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
	}
	// A degraded kill switch (e.g. a Redis partition) flips status to "degraded".
	// The operational consequence depends on the configured degraded mode, NOT a
	// fixed "fails open": the shipped default is fail-closed (deny all traffic until
	// the backend recovers), and fail-open (serve the last-known cache, so a fresh
	// revocation may be missed) is opt-in. Either way the kill switch is not
	// operating normally, so surface it for incident response.
	if hr, ok := p.ks.(healthReporter); ok && hr.HealthStatus() != nil {
		snap.KillSwitchHealthy = false
		snap.Status = "degraded"
	}
	// Audit-integrity loss also flips status to "degraded": no sink configured,
	// dropped records, or failed writes each mean the tamper-evident audit trail is
	// incomplete — a readiness regression to alert on.
	if !snap.AuditConfigured || snap.AuditDropped > 0 || snap.AuditWriteFailed > 0 {
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
	killHealthy := 0
	if snap.KillSwitchHealthy {
		killHealthy = 1
	}
	auditUp := 0
	if snap.AuditConfigured {
		auditUp = 1
	}
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
	wf("eunox_audit_sink_up %d\n", auditUp)
	wf("# HELP eunox_kill_switch_healthy Kill-switch backend health (1 = healthy, 0 = degraded).\n")
	wf("# TYPE eunox_kill_switch_healthy gauge\n")
	wf("eunox_kill_switch_healthy %d\n", killHealthy)
}
