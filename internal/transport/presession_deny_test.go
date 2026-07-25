// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestPreSessionDenyLimiter_BoundsBurstAndCountsSuppressed pins the property that closes
// the unauthenticated audit-flood vector: a caller who can trigger refusals at an arbitrary
// rate must not be able to enqueue audit records at that rate. Without the bound, the queue
// overflows, the sink's monotonic drop counter latches AuditDegraded(), and
// --require-audit=strict then denies every legitimate request for the process lifetime.
func TestPreSessionDenyLimiter_BoundsBurstAndCountsSuppressed(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	l := newPreSessionDenyLimiter()
	l.now = func() time.Time { return now }

	admitted := 0
	const attempts = 5000
	for i := 0; i < attempts; i++ {
		if ok, _ := l.admit(); ok {
			admitted++
		}
	}
	if admitted != preSessionDenyBurst {
		t.Fatalf("a burst with no clock movement must admit exactly the burst size; admitted %d, want %d", admitted, preSessionDenyBurst)
	}

	// The suppressed refusals are not lost: the next admitted record carries the count, so
	// an operator sees both that the attack happened and its scale.
	now = base.Add(time.Second)
	ok, suppressed := l.admit()
	if !ok {
		t.Fatal("a refill second must admit again")
	}
	if want := uint64(attempts - preSessionDenyBurst); suppressed != want {
		t.Fatalf("suppressed = %d, want %d — every suppressed refusal must be folded into the next admitted record", suppressed, want)
	}

	// And the count resets, so the following record does not double-report.
	if ok, s := l.admit(); !ok || s != 0 {
		t.Fatalf("after reporting, the suppressed counter must reset; ok=%v suppressed=%d", ok, s)
	}
}

// TestPreSessionDenyLimiter_RefillIsRateBounded pins that sustained pressure is served at
// the configured rate rather than the caller's rate.
func TestPreSessionDenyLimiter_RefillIsRateBounded(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	l := newPreSessionDenyLimiter()
	l.now = func() time.Time { return now }

	// Drain the burst.
	for i := 0; i < preSessionDenyBurst; i++ {
		if ok, _ := l.admit(); !ok {
			t.Fatalf("burst token %d should have been admitted", i)
		}
	}
	if ok, _ := l.admit(); ok {
		t.Fatal("the bucket must be empty after the burst is drained")
	}

	// One second of refill yields exactly the per-second rate, not more.
	now = base.Add(time.Second)
	admitted := 0
	for i := 0; i < preSessionDenyRatePerSec*10; i++ {
		if ok, _ := l.admit(); ok {
			admitted++
		}
	}
	if admitted != preSessionDenyRatePerSec {
		t.Fatalf("one second of refill admitted %d, want %d", admitted, preSessionDenyRatePerSec)
	}
}

// TestPreSessionDenyLimiter_BackwardsClockDoesNotGrantTokens pins that a clock step
// backwards cannot mint refill (which would hand an attacker the rate they were denied).
func TestPreSessionDenyLimiter_BackwardsClockDoesNotGrantTokens(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	l := newPreSessionDenyLimiter()
	l.now = func() time.Time { return now }
	for i := 0; i < preSessionDenyBurst; i++ {
		l.admit()
	}
	now = base.Add(-time.Hour)
	if ok, _ := l.admit(); ok {
		t.Fatal("a backwards clock step must not refill the bucket")
	}
}

// TestHostAllowedForLoopbackEndpoint_PresentButHostlessIsRefused pins the DNS-rebinding
// pin's absent-Host carve-out to the header being genuinely ABSENT.
//
// normalizeHost reduces a PRESENT but host-less value to "" — net.SplitHostPort succeeds on
// ":8080" and returns an empty host, and "[]" reduces the same way — so keying the
// allowance off the normalized value let `Host: :8080` skip the entire rebinding pin on
// /control/kill, /healthz and /metrics. The carve-out's own rationale ("HTTP/1.1 requires
// the header, so no value means a non-browser local caller") does not hold for a header
// that was sent.
func TestHostAllowedForLoopbackEndpoint_PresentButHostlessIsRefused(t *testing.T) {
	t.Parallel()
	p := &HTTPProxy{allowedOriginHosts: map[string]bool{"localhost": true}}

	if !p.hostAllowedForLoopbackEndpoint("", "") {
		t.Error("a genuinely absent Host must still be admitted (HTTP/1.0 probe, hand-rolled client)")
	}
	for _, raw := range []string{":8080", "[]", ":", "[]:9000"} {
		if p.hostAllowedForLoopbackEndpoint(raw, normalizeHost(raw)) {
			t.Errorf("Host %q is present but carries no host part; it must not satisfy the rebinding pin", raw)
		}
	}
	if !p.hostAllowedForLoopbackEndpoint("localhost:3000", "localhost") {
		t.Error("a trusted name must still be admitted")
	}
	if p.hostAllowedForLoopbackEndpoint("attacker.com", "attacker.com") {
		t.Error("a foreign name is the rebinding case and must be refused")
	}
}

// TestAddClaimedSessionID_NilMapAndOversizedHeader pins the two hazards in the shared
// pre-session detail helper: a nil details map (which recordResourceExhausted passes) must
// not panic inside an HTTP handler on a security-refusal path, and the attacker-controlled
// header must be bounded so a single unauthenticated request cannot append most of a 1 MiB
// header to the tamper-evident tape.
func TestAddClaimedSessionID_NilMapAndOversizedHeader(t *testing.T) {
	t.Parallel()
	r := newTestRequestWithSession("abc")
	got := addClaimedSessionID(nil, r)
	if got["claimed_session_id"] != "abc" {
		t.Fatalf("a nil details map must be allocated, not panicked on; got %+v", got)
	}

	huge := make([]byte, 4096)
	for i := range huge {
		huge[i] = 'A'
	}
	r = newTestRequestWithSession(string(huge))
	got = addClaimedSessionID(map[string]interface{}{}, r)
	claimed, _ := got["claimed_session_id"].(string)
	if len(claimed) != maxClaimedSessionIDLen {
		t.Fatalf("claimed session id length = %d, want it bounded to %d", len(claimed), maxClaimedSessionIDLen)
	}
	if got["claimed_session_id_truncated"] != true {
		t.Error("truncation must be marked so the record is not read as a complete value")
	}
}

// newTestRequestWithSession builds a request carrying the given Mcp-Session-Id header.
func newTestRequestWithSession(id string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	r.Header.Set(SessionHeader, id)
	return r
}
