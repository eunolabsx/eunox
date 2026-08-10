// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Loopback-only operational endpoints for the HTTP transport: /healthz (a JSON
// health snapshot) and /metrics (Prometheus text exposition). Both share the
// loopback guard used by /control/kill, so neither is reachable from off-host; a
// scraper runs as a sidecar or via the loopback interface.

package transport

import (
	"fmt"
	"io"
	"net/http"
	"reflect"

	"github.com/eunolabs/eunox/pkg/circuitbreaker"
)

// healthReporter is the readiness question asked of a degradable subsystem with no request in
// hand: nil while it is operating normally, the cause otherwise.
//
// It is the RULE, not one subsystem's precedent. Every degradable subsystem answers the verdict
// through this seam, from the package that owns its state machine, and the transport only folds
// verdicts — it never encodes a degradation predicate of its own, which is how the copy of "which
// breaker states are impeded" that lived here got the half-open case wrong and could only be fixed
// and tested by standing up an HTTPProxy.
//
// A subsystem with DETAIL to report answers with a SAMPLE that implements this seam
// (capability.KeyFetchHealth is one), rather than with a live queryable. That is the second half of
// the rule and it is what stops one /healthz body contradicting itself: the transport renders the
// sample's fields and folds that same sample's verdict, where re-asking the subsystem takes an
// independent reading and can report a servable key set beside a verdict saying every token fails
// closed. Splitting verdict from detail this way is also what lets ONE seam serve subsystems whose
// details have nothing in common — an `error` has no room for a breaker state plus two counters.
//
// What differs per subsystem is only how the proxy REACHES it, which is a property of what it
// holds rather than a second pattern: every killswitch.Manager answers the seam live (in-memory
// always nil — an in-process kill set is always confirmable), but the proxy holds killActivator,
// narrowed to keep the kill's UNDO path shut, which carries no reader at all, so that one arrives
// through a type assertion. A value satisfying killActivator without HealthStatus is reported
// healthy, which is why the one the binary wires is a full Manager.
type healthReporter interface {
	HealthStatus() error
}

// healthSnapshot is the live operational state surfaced by /healthz and /metrics.
type healthSnapshot struct {
	Status           string `json:"status"` // "ok" | "degraded"
	Sessions         int    `json:"sessions"`
	MaxSessions      int    `json:"maxSessions"` // 0 = unlimited
	Routes           int    `json:"routes"`
	AuditDropped     int64  `json:"auditDropped"`     // records dropped because the write queue was full
	AuditWriteFailed int64  `json:"auditWriteFailed"` // records that reached the drainer but failed to write to disk
	AuditConfigured  bool   `json:"auditConfigured"`  // false when the audit sink failed to open
	// AuditHealthy is the sink's OWN verdict, folded through the health seam rather than
	// recomputed here. False for a trail that has lost coverage (a dropped record or a failed
	// write, the same predicate --require-audit=strict denies on) or whose log maintenance has
	// stalled — and for a sink that never opened, which is the one part of the answer the sink
	// cannot give: absence is the proxy's own fact.
	AuditHealthy      bool `json:"auditHealthy"`
	KillSwitchHealthy bool `json:"killSwitchHealthy"` // false when a Redis backend is degraded
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

// jwksHealth is the JWT layer's key-fetch state: the circuit breaker guarding IdP fetches, and
// whether the cached key set can still serve. Its fields carry no omitempty: within the block a
// zero is a measurement.
//
// Two booleans rather than one because they answer different questions and an operator alerts
// on them differently. KeysServable false with an impeded breaker is a READINESS regression —
// every token now fails closed — while an impeded breaker over a servable set is an ALERT with
// no rejections behind it yet: key rotation is blocked and a token carrying a `kid` the cached
// set does not hold fails closed at once, but everything else validates.
type jwksHealth struct {
	BreakerState   circuitbreaker.State `json:"breakerState"`
	FetchFailures  int64                `json:"fetchFailures"`
	FetchSuccesses int64                `json:"fetchSuccesses"`
	// KeysServable: a fetched key set is installed and still inside its TTL.
	KeysServable bool `json:"keysServable"`
	// Healthy: this layer can still validate tokens. False is what flips the summary, and it is
	// the verdict pkg/capability reached, never one recomputed from the two fields above.
	Healthy bool `json:"healthy"`
}

// fold applies one subsystem's verdict to the snapshot: healthy is its own field (a scraper
// reads the field, not the aggregate) and a non-nil verdict also flips the summary.
//
// A pointer to the field rather than a returned bool, so a subsystem cannot be folded into the
// summary while its own field silently stays true — the discrepancy nothing downstream could
// detect.
func (s *healthSnapshot) fold(h healthReporter, healthy *bool) {
	if absentReporter(h) || h.HealthStatus() == nil {
		return
	}
	*healthy = false
	s.Status = statusDegraded
}

// absentReporter reports whether h holds no subsystem at all — the interface itself nil, or a typed
// nil inside a non-nil interface.
//
// `h == nil` compares the INTERFACE, so it passes for an interface holding a `(*killswitch.Redis)(nil)`
// and the call behind it dereferences a nil receiver. The guard read as a nil check and was not one,
// which is worse than no guard: every later subsystem folded through this seam inherits the
// appearance of coverage. Nothing in cmd/eunox produces a typed nil, but the seam is reached through
// the EXPORTED API — a consumer wiring `var ks *killswitch.Redis` into HTTPGatewayOptions.KS — and
// healthReporter's own doc invites more subsystems through it, so the ways to arrive here grow.
//
// Reflection over the nilable kinds, the treatment redisutil.IsNilClient carries for the same
// question one layer down; a second copy rather than an import because that one is reached through a
// `redis.Cmdable` signature this seam cannot satisfy, and exporting its half from a package that
// exists to answer the go-redis TOPOLOGY question would widen that package to serve a caller with no
// Redis in it. IsNil PANICS on any other kind, which is why the kinds are named rather than tried —
// the guard must not become the crash it prevents — and a subsystem answering with a struct VALUE
// (audit.Health, capability.KeyFetchHealth) lands in the default arm as present, which is correct: a
// value sample is never absent.
func absentReporter(h healthReporter) bool {
	if h == nil {
		return true
	}
	switch rv := reflect.ValueOf(h); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}

// The two values the summary takes. Named because handleHealth designates it the READINESS
// signal, so an operator wires a probe to it and every write of the string is load-bearing.
const (
	statusOK       = "ok"
	statusDegraded = "degraded"
)

// snapshot gathers the current operational state (locked map reads plus atomic
// counter loads).
func (p *HTTPProxy) snapshot() healthSnapshot {
	snap := healthSnapshot{
		Status:            statusOK,
		Sessions:          p.sessionCount(),
		MaxSessions:       p.maxSessions,
		Routes:            len(p.routes),
		AuditConfigured:   p.sink != nil,
		AuditHealthy:      p.sink != nil,
		KillSwitchHealthy: true,
	}
	if p.sink == nil {
		// ABSENCE, not degradation, and the one part of the audit answer that stays here: a sink
		// that never opened cannot report on itself, and only the proxy knows it wired none. It
		// still flips the summary — a trail that does not exist is not a trail an incident
		// responder can read — but it is a different fact from the sink's own verdict below, which
		// is why it is not folded through the seam.
		snap.Status = statusDegraded
	} else {
		// ONE sample, and its own verdict folded from it: the counters below and the health seam's
		// answer come from the same reading, so a record dropped mid-scrape cannot put a zero count
		// beside a degraded verdict in one body. The predicate itself belongs to the package that
		// owns the state — including the carve-out that keeps a stalled rotation out of the gate
		// that denies traffic while keeping it in this one (see audit.Health.HealthStatus), which
		// the copy that used to live here had to remember by hand.
		h := p.sink.Health()
		snap.AuditDropped = h.Dropped
		snap.AuditWriteFailed = h.WriteFailures
		snap.AuditMaintenanceStalled, snap.AuditMaintenanceReason = h.MaintenanceStalled, h.MaintenanceReason
		snap.fold(h, &snap.AuditHealthy)
	}
	// A degraded kill switch (e.g. a Redis partition) flips status to "degraded". The
	// operational consequence depends on the configured degraded mode (fail-closed by
	// default, fail-open opt-in) — either way it's not operating normally.
	if hr, ok := p.ks.(healthReporter); ok {
		snap.fold(hr, &snap.KillSwitchHealthy)
	}
	// Asked of the shared validator rather than per route: WrapRoutesWithJWT gives every
	// route wrapper this one validator's cache, so the routes share a single breaker.
	//
	// The verdict comes back through the same seam the kill switch answers, and it degrades on
	// IMPACT rather than on the breaker tripping: the breaker's cooldown is tens of seconds
	// against a five-minute default key TTL, so degrading on the trip alone reports a fleet-wide
	// readiness regression — every replica shares the IdP and trips in the same window — through
	// a window in which every token still validates. The impediment itself is still reported, in
	// the block below and as eunox_jwks_fetch_healthy, since it blocks rotation and fails an
	// unknown-kid token now.
	if p.jwtPDP != nil {
		if h, ok := p.jwtPDP.KeyFetchHealth(); ok {
			snap.JWKS = &jwksHealth{
				BreakerState:   h.Breaker.State,
				FetchFailures:  h.Breaker.TotalFailures,
				FetchSuccesses: h.Breaker.TotalSuccesses,
				KeysServable:   h.KeysServable,
				Healthy:        true,
			}
			// The SAMPLE is folded, not the validator: re-asking it would read the breaker and the
			// cache's freshness a second time, and a TTL lapsing between the two reads is enough to
			// emit a servable key set beside a verdict saying every token fails closed.
			snap.fold(h, &snap.JWKS.Healthy)
		}
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
	// Every series goes through one of these three, so the name cannot be spelled differently
	// in a metric's own HELP, TYPE and sample lines, and the TYPE word cannot contradict the
	// suffix. Hand-transcribing the trio per metric is what made that possible.
	m := metricWriter{w: w}
	m.gauge("eunox_active_sessions", "Current number of active client sessions.", int64(snap.Sessions))
	m.gauge("eunox_max_sessions", "Configured maximum concurrent sessions (0 = unlimited).", int64(snap.MaxSessions))
	m.gauge("eunox_routes", "Configured upstream routes.", int64(snap.Routes))
	m.counter("eunox_audit_dropped_records_total", "Audit records discarded because the write queue was full.", snap.AuditDropped)
	m.counter("eunox_audit_write_failures_total", "Audit records that reached the drainer but failed to write to disk (full disk, EIO, ...). A non-zero value means the audit trail is incomplete.", snap.AuditWriteFailed)
	m.gauge("eunox_audit_sink_up", "Whether the audit sink opened successfully (1 = up).", gaugeBool(snap.AuditConfigured))
	// The sink's own verdict as one series, so alerting on "the audit trail is not operating
	// normally" is one rule rather than an OR over the three series around it — and so a reader
	// cannot reconstruct it from those three and get the maintenance carve-out wrong.
	m.gauge("eunox_audit_healthy", "Audit trail health as the sink itself reports it (1 = healthy). 0 means the trail has lost coverage (see eunox_audit_dropped_records_total and eunox_audit_write_failures_total, the losses --require-audit=strict denies on), its log maintenance has stalled (eunox_audit_maintenance_stalled, which does NOT deny traffic), or no sink opened at all (eunox_audit_sink_up).", gaugeBool(snap.AuditHealthy))
	m.gauge("eunox_kill_switch_healthy", "Kill-switch backend health (1 = healthy, 0 = degraded).", gaugeBool(snap.KillSwitchHealthy))
	m.gauge("eunox_audit_maintenance_stalled", "Audit rotation or retention pruning is not making progress (1 = stalled). No records are lost, but the configured size/retention bound is unenforced and the log will grow until the fault is fixed.", gaugeBool(snap.AuditMaintenanceStalled))
	// Absent without a JWT layer rather than emitted as zeros: a permanently-healthy gauge on
	// a proxy that fetches no keys is indistinguishable from healthy key fetching, and an
	// absent series is what a scraper already knows how to read.
	if snap.JWKS != nil {
		m.gauge("eunox_jwks_fetch_healthy", "IdP key fetching is unimpeded (1 = breaker closed). 0 means refreshes are refused or the breaker has tripped and not yet proved recovery: key rotation is blocked and a token whose kid the cached key set does not carry fails closed now. Alert on it; it does NOT by itself flip /healthz status, since a warm cache keeps validating -- pair it with eunox_jwks_keys_servable for that.", gaugeBool(!snap.JWKS.BreakerState.Impeded()))
		// The second half of the readiness question, and the reason the gauge above is an alert
		// rather than a drain signal: 0 on BOTH is the window in which every token fails closed.
		m.gauge("eunox_jwks_keys_servable", "A fetched key set is installed and still within its cache TTL (1 = tokens carrying a kid it holds keep validating). 0 alongside eunox_jwks_fetch_healthy 0 is the window in which every token fails closed, and is what flips /healthz status to degraded.", gaugeBool(snap.JWKS.KeysServable))
		// The state as a labelled set, the Prometheus spelling for an enum: a single boolean
		// could not name half-open, which is the state a sustained outage sits in longest.
		states := make([]labelledSample, 0, 3)
		for _, st := range []circuitbreaker.State{circuitbreaker.StateClosed, circuitbreaker.StateHalfOpen, circuitbreaker.StateOpen} {
			states = append(states, labelledSample{
				labels: fmt.Sprintf("{state=%q}", string(st)),
				value:  gaugeBool(snap.JWKS.BreakerState == st),
			})
		}
		m.gaugeSet("eunox_jwks_breaker_state", "IdP key-fetch circuit breaker state (1 on the active state).", states)
		m.counter("eunox_jwks_fetch_failures_total", "JWKS fetches the breaker admitted and saw fail. Fetches it REFUSED are not counted here -- watch eunox_jwks_fetch_healthy for those.", snap.JWKS.FetchFailures)
		m.counter("eunox_jwks_fetch_successes_total", "JWKS fetches reported successful to the breaker, including outcomes it then discarded as stale. Observability only -- do not read a rising value as recovery; eunox_jwks_fetch_healthy is the recovery signal.", snap.JWKS.FetchSuccesses)
	}
}

// metricWriter renders Prometheus text exposition groups. Write errors are discarded: a broken
// scrape connection is not actionable here.
type metricWriter struct{ w io.Writer }

// labelledSample is one sample of a multi-series metric: the rendered label set (including
// braces) and its value.
type labelledSample struct {
	labels string
	value  int64
}

func (m metricWriter) emit(name, help, kind string, samples []labelledSample) {
	_, _ = fmt.Fprintf(m.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	for _, s := range samples {
		_, _ = fmt.Fprintf(m.w, "%s%s %d\n", name, s.labels, s.value)
	}
}

func (m metricWriter) gauge(name, help string, v int64) {
	m.emit(name, help, "gauge", []labelledSample{{value: v}})
}

func (m metricWriter) counter(name, help string, v int64) {
	m.emit(name, help, "counter", []labelledSample{{value: v}})
}

// gaugeSet renders an enum as the Prometheus idiom: one HELP/TYPE for the family, one sample
// per member.
func (m metricWriter) gaugeSet(name, help string, samples []labelledSample) {
	m.emit(name, help, "gauge", samples)
}

// gaugeBool renders a boolean as a gauge value. One spelling, so a new gauge cannot invert the
// conversion in its own copy of the three-line idiom.
func gaugeBool(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
