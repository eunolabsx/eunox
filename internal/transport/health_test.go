// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/circuitbreaker"
)

// newJWKSHealthProxy builds a proxy through the real gateway constructor, so the wiring the
// health endpoint depends on (HTTPGatewayOptions.JWTPDP reaching p.jwtPDP) is exercised rather
// than hand-assigned. A real audit sink keeps every other input to snapshot() healthy, so a
// "degraded" verdict can only have come from the breaker.
func newJWKSHealthProxy(t *testing.T, br *circuitbreaker.Breaker) *HTTPProxy {
	t.Helper()
	sink, _ := newTempAuditSink(t)
	opts := httpProxyOptions{Sink: sink}
	if br != nil {
		opts.JWTPDP = pdp.NewJWTPDP(pdp.JWTPDPOptions{
			JWKSURI: "https://idp.example/.well-known/jwks.json",
			// Pinning neither audience nor issuer only silences the constructor's
			// misconfiguration warnings; no token is validated here.
			AllowAnyAudience: true,
			AllowAnyIssuer:   true,
			Breaker:          br,
		})
	}
	return newHTTPProxy(opts)
}

// testClock is a manually advanced clock, so the breaker's cooldown projection is driven by
// the test rather than by however finely the host's wall clock happens to tick.
type testClock struct{ ns atomic.Int64 }

func newTestClock() *testClock {
	c := &testClock{}
	c.ns.Store(time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC).UnixNano())
	return c
}
func (c *testClock) Now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// trippedBreaker returns a breaker driven to StateOpen by one failed call, on clk.
func trippedBreaker(t *testing.T, clk *testClock, cooldown time.Duration) *circuitbreaker.Breaker {
	t.Helper()
	br := circuitbreaker.New(circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  cooldown,
		HalfOpenMaxProbes: 1,
	}, circuitbreaker.WithClock(clk.Now))
	_, err := circuitbreaker.Do(context.Background(), br, func(context.Context) (struct{}, error) {
		return struct{}{}, errors.New("JWKS endpoint down")
	})
	if err == nil {
		t.Fatal("the seeding call must fail so the breaker trips")
	}
	if got := br.State(); got != circuitbreaker.StateOpen {
		t.Fatalf("breaker state = %q, want open", got)
	}
	return br
}

// metricsBody renders /metrics through the real handler and returns the whole exposition.
// Both halves of the loopback guard have to be satisfied: a loopback source AND a loopback
// Host, the latter being the DNS-rebinding check.
func metricsBody(t *testing.T, p *HTTPProxy) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Host = "127.0.0.1:3000"
	rec := httptest.NewRecorder()
	p.handleMetrics(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// TestHealthSnapshot_JWKSBreaker pins the operator-visible consequence of a JWKS outage. An
// impeded breaker refuses key refreshes, so an unknown-kid token fails closed at once and
// every token fails when the cached set passes its TTL; before this was surfaced, token
// validation could be entirely down with /healthz reporting "ok".
func TestHealthSnapshot_JWKSBreaker(t *testing.T) {
	t.Run("no JWT layer reports no key-fetch state at all", func(t *testing.T) {
		p := newJWKSHealthProxy(t, nil)
		snap := p.snapshot()
		if snap.JWKS != nil {
			t.Errorf("jwks = %+v, want absent with no JWT layer configured", snap.JWKS)
		}
		if snap.Status != "ok" {
			t.Errorf("status = %q, want ok", snap.Status)
		}
		// The block must be ABSENT on the wire: a scraper has to be able to tell "this proxy
		// fetches no keys" from "its key fetching is healthy".
		body, err := json.Marshal(snap)
		if err != nil {
			t.Fatalf("marshal snapshot: %v", err)
		}
		if strings.Contains(string(body), "jwks") {
			t.Errorf("snapshot JSON must omit the jwks block with no JWT layer: %s", body)
		}
		if got := metricsBody(t, p); strings.Contains(got, "eunox_jwks_") {
			t.Errorf("metrics must emit no eunox_jwks_* series with no JWT layer:\n%s", got)
		}
	})

	t.Run("closed breaker is reported in full and stays ok", func(t *testing.T) {
		p := newJWKSHealthProxy(t, circuitbreaker.New(circuitbreaker.DefaultConfig()))
		snap := p.snapshot()
		if snap.JWKS == nil {
			t.Fatal("jwks block must be present with a JWT layer configured")
		}
		if snap.JWKS.BreakerState != circuitbreaker.StateClosed {
			t.Errorf("breakerState = %q, want closed", snap.JWKS.BreakerState)
		}
		if snap.Status != "ok" {
			t.Errorf("status = %q, want ok for a closed breaker", snap.Status)
		}
		// Both counters must survive marshalling at zero: within the block a zero is a
		// measurement ("never fetched"), not an absence.
		body, err := json.Marshal(snap)
		if err != nil {
			t.Fatalf("marshal snapshot: %v", err)
		}
		for _, want := range []string{`"fetchFailures":0`, `"fetchSuccesses":0`} {
			if !strings.Contains(string(body), want) {
				t.Errorf("snapshot JSON missing %s (a zero counter must not be omitted): %s", want, body)
			}
		}
		got := metricsBody(t, p)
		for _, want := range []string{
			"eunox_jwks_fetch_healthy 1\n",
			`eunox_jwks_breaker_state{state="closed"} 1`,
			`eunox_jwks_breaker_state{state="open"} 0`,
		} {
			if !strings.Contains(got, want) {
				t.Errorf("metrics missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("open breaker degrades the snapshot", func(t *testing.T) {
		p := newJWKSHealthProxy(t, trippedBreaker(t, newTestClock(), time.Hour))
		snap := p.snapshot()
		if snap.JWKS == nil {
			t.Fatal("jwks block must be present")
		}
		if snap.JWKS.BreakerState != circuitbreaker.StateOpen {
			t.Errorf("breakerState = %q, want open", snap.JWKS.BreakerState)
		}
		if snap.JWKS.FetchFailures != 1 {
			t.Errorf("fetchFailures = %d, want 1", snap.JWKS.FetchFailures)
		}
		if snap.Status != "degraded" {
			t.Errorf("status = %q, want degraded: an open breaker means token validation is failing closed", snap.Status)
		}
		got := metricsBody(t, p)
		for _, want := range []string{
			"eunox_jwks_fetch_healthy 0\n",
			`eunox_jwks_breaker_state{state="open"} 1`,
			`eunox_jwks_breaker_state{state="closed"} 0`,
			"eunox_jwks_fetch_failures_total 1\n",
			"eunox_jwks_fetch_successes_total 0\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("metrics missing %q:\n%s", want, got)
			}
		}
	})

	// The regression this test exists for: a breaker whose cooldown lapsed reports half-open
	// forever until some fetch drives it, and at HalfOpenMaxProbes=1 a probe in flight refuses
	// every other fetch. Reading only StateOpen made a sustained outage report "ok" for most
	// of its duration, so the page the feature exists to enable never fired.
	t.Run("half-open degrades too", func(t *testing.T) {
		clk := newTestClock()
		br := trippedBreaker(t, clk, 30*time.Second)
		clk.advance(31 * time.Second)

		p := newJWKSHealthProxy(t, br)
		snap := p.snapshot()
		if snap.JWKS == nil {
			t.Fatal("jwks block must be present")
		}
		if snap.JWKS.BreakerState != circuitbreaker.StateHalfOpen {
			t.Fatalf("breakerState = %q, want half-open after the cooldown lapsed", snap.JWKS.BreakerState)
		}
		if snap.Status != "degraded" {
			t.Errorf("status = %q, want degraded: half-open means tripped with the retry outstanding, not recovered", snap.Status)
		}
		got := metricsBody(t, p)
		for _, want := range []string{
			"eunox_jwks_fetch_healthy 0\n",
			`eunox_jwks_breaker_state{state="half-open"} 1`,
		} {
			if !strings.Contains(got, want) {
				t.Errorf("metrics missing %q:\n%s", want, got)
			}
		}

		// Reading health must not spend the single recovery probe. Asserting the reported
		// state is not enough — it projects identically whether or not the budget was
		// consumed — so demand that a real fetch is still admitted afterwards.
		admitted := false
		_, _ = circuitbreaker.Do(context.Background(), br, func(context.Context) (struct{}, error) {
			admitted = true
			return struct{}{}, nil
		})
		if !admitted {
			t.Error("the health reads consumed the half-open probe budget; a real key fetch was refused")
		}
	})

	t.Run("an unrecognized breaker state is not reported healthy", func(t *testing.T) {
		// A Breaker not built through New has the zero State. It must fail safe rather than
		// read as closed, and must not make a configured JWT layer look unconfigured.
		p := newJWKSHealthProxy(t, &circuitbreaker.Breaker{})
		snap := p.snapshot()
		if snap.JWKS == nil {
			t.Fatal("jwks block must be present: the JWT layer is configured")
		}
		if snap.Status != "degraded" {
			t.Errorf("status = %q, want degraded for a state this build does not recognize", snap.Status)
		}
		got := metricsBody(t, p)
		if !strings.Contains(got, "eunox_jwks_fetch_healthy 0\n") {
			t.Errorf("an unrecognized state must not report healthy:\n%s", got)
		}
		if strings.Contains(got, `eunox_jwks_breaker_state{state="closed"} 1`) {
			t.Errorf("an unrecognized state must not claim any named state:\n%s", got)
		}
	})
}
