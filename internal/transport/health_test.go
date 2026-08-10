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
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/circuitbreaker"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// newJWKSHealthProxy builds a proxy whose only degradable subsystem is the JWT layer: a real
// audit sink and an in-memory kill switch keep every other input to snapshot() healthy, so a
// "degraded" verdict can only have come from the breaker.
func newJWKSHealthProxy(t *testing.T, br *circuitbreaker.Breaker) *HTTPProxy {
	t.Helper()
	sink, _ := newTempAuditSink(t)
	p := &HTTPProxy{ks: killswitch.NewInMemory(), sink: sink, sessions: map[string]*httpSession{}}
	if br != nil {
		p.jwtPDP = pdp.NewJWTPDP(pdp.JWTPDPOptions{
			JWKSURI: "https://idp.example/.well-known/jwks.json",
			// Pinning neither audience nor issuer only silences the constructor's
			// misconfiguration warnings; no token is validated here.
			AllowAnyAudience: true,
			AllowAnyIssuer:   true,
			Breaker:          br,
		})
	}
	return p
}

// trippedBreaker returns a breaker driven to StateOpen by one failed call. The long cooldown
// keeps it open rather than projecting half-open the instant the cooldown lapses.
func trippedBreaker(t *testing.T) *circuitbreaker.Breaker {
	t.Helper()
	br := circuitbreaker.New(circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Hour,
		HalfOpenMaxProbes: 1,
	})
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
// open breaker refuses key refreshes, so an unknown-kid token fails closed at once and every
// token fails when the cached set passes its TTL; before this was surfaced, token validation
// could be entirely down with /healthz reporting "ok".
func TestHealthSnapshot_JWKSBreaker(t *testing.T) {
	t.Run("no JWT layer reports no key-fetch state at all", func(t *testing.T) {
		p := newJWKSHealthProxy(t, nil)
		snap := p.snapshot()
		if snap.JWKSFetchState != "" {
			t.Errorf("jwksFetchState = %q, want empty with no JWT layer configured", snap.JWKSFetchState)
		}
		if snap.Status != "ok" {
			t.Errorf("status = %q, want ok", snap.Status)
		}
		// The field must be ABSENT on the wire, not "": a scraper has to be able to tell
		// "this proxy fetches no keys" from "its key fetching is healthy".
		body, err := json.Marshal(snap)
		if err != nil {
			t.Fatalf("marshal snapshot: %v", err)
		}
		if strings.Contains(string(body), "jwksFetchState") {
			t.Errorf("snapshot JSON must omit jwksFetchState with no JWT layer: %s", body)
		}
		if got := metricsBody(t, p); strings.Contains(got, "eunox_jwks_") {
			t.Errorf("metrics must emit no eunox_jwks_* series with no JWT layer:\n%s", got)
		}
	})

	t.Run("closed breaker is reported and stays ok", func(t *testing.T) {
		p := newJWKSHealthProxy(t, circuitbreaker.New(circuitbreaker.DefaultConfig()))
		snap := p.snapshot()
		if snap.JWKSFetchState != string(circuitbreaker.StateClosed) {
			t.Errorf("jwksFetchState = %q, want closed", snap.JWKSFetchState)
		}
		if snap.Status != "ok" {
			t.Errorf("status = %q, want ok for a closed breaker", snap.Status)
		}
		if got := metricsBody(t, p); !strings.Contains(got, "eunox_jwks_breaker_open 0\n") {
			t.Errorf("metrics missing eunox_jwks_breaker_open 0:\n%s", got)
		}
	})

	t.Run("open breaker degrades the snapshot", func(t *testing.T) {
		p := newJWKSHealthProxy(t, trippedBreaker(t))
		snap := p.snapshot()
		if snap.JWKSFetchState != string(circuitbreaker.StateOpen) {
			t.Errorf("jwksFetchState = %q, want open", snap.JWKSFetchState)
		}
		if snap.JWKSFetchFailures != 1 {
			t.Errorf("jwksFetchFailures = %d, want 1", snap.JWKSFetchFailures)
		}
		if snap.Status != "degraded" {
			t.Errorf("status = %q, want degraded: an open breaker means token validation is failing closed", snap.Status)
		}
		got := metricsBody(t, p)
		for _, want := range []string{
			"eunox_jwks_breaker_open 1\n",
			"eunox_jwks_fetch_failures_total 1\n",
			"eunox_jwks_fetch_successes_total 0\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("metrics missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("a half-open breaker is reported without degrading", func(t *testing.T) {
		// Cooldown already elapsed: Stats projects half-open, meaning the next fetch is
		// admitted. That is recovering, not refusing, so it must not read as degraded --
		// and the projection must not be consumed by the read.
		br := circuitbreaker.New(circuitbreaker.Config{
			FailureThreshold:  1,
			CooldownDuration:  time.Nanosecond,
			HalfOpenMaxProbes: 1,
		})
		if _, err := circuitbreaker.Do(context.Background(), br, func(context.Context) (struct{}, error) {
			return struct{}{}, errors.New("JWKS endpoint down")
		}); err == nil {
			t.Fatal("the seeding call must fail so the breaker trips")
		}
		p := newJWKSHealthProxy(t, br)
		snap := p.snapshot()
		if snap.JWKSFetchState != string(circuitbreaker.StateHalfOpen) {
			t.Fatalf("jwksFetchState = %q, want half-open", snap.JWKSFetchState)
		}
		if snap.Status != "ok" {
			t.Errorf("status = %q, want ok: a half-open breaker admits the next fetch", snap.Status)
		}
		if got := metricsBody(t, p); !strings.Contains(got, "eunox_jwks_breaker_open 0\n") {
			t.Errorf("half-open must not raise the open gauge:\n%s", got)
		}
		// The two reads above must not have advanced anything the next verification needs.
		if got := br.State(); got != circuitbreaker.StateHalfOpen {
			t.Errorf("breaker state after two health reads = %q, want half-open still", got)
		}
	})
}
