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
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/circuitbreaker"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// Whether the cache behind the JWT layer holds a key set inside its TTL. Named at the call
// site because it is the whole difference between an impediment and an impact: the breaker
// tripping is not by itself a readiness regression while the cached set still serves.
const (
	warmCache = true
	coldCache = false
)

// newJWKSHealthProxy builds a proxy through the real gateway constructor, so the wiring the
// health endpoint depends on (HTTPGatewayOptions.JWTPDP reaching p.jwtPDP) is exercised rather
// than hand-assigned. A real audit sink keeps every other input to snapshot() healthy, so a
// "degraded" verdict can only have come from the JWT layer.
func newJWKSHealthProxy(t *testing.T, br *circuitbreaker.Breaker, warm bool) *HTTPProxy {
	t.Helper()
	sink, _ := newTempAuditSink(t)
	opts := httpProxyOptions{Sink: sink}
	if br != nil {
		opts.JWTPDP = newJWKSHealthPDP(t, br, warm, time.Hour, nil)
	}
	return newHTTPProxy(opts)
}

// newJWKSHealthPDP builds the validator the health endpoint reads, over a cache this test
// controls: warm installs a real key set through a live JWKS server (the only way to make
// freshAt true), ttl and now drive its expiry.
//
// The warm fetch runs BEFORE the caller trips the breaker, since a fetch through an open
// breaker is refused and would leave the cache cold whatever the test asked for.
func newJWKSHealthPDP(t *testing.T, br *circuitbreaker.Breaker, warm bool, ttl time.Duration, now func() time.Time) *pdp.JWTPDP {
	t.Helper()
	cfg := capability.JWKSCacheConfig{
		JWKSURL:  "https://idp.example/.well-known/jwks.json",
		CacheTTL: ttl,
		Breaker:  br,
		Now:      now,
	}
	if warm {
		srv := makeJWKSServer(t, newTestKey(t, "k1"))
		t.Cleanup(srv.Close)
		cfg.JWKSURL = srv.URL
		cfg.Client = srv.Client()
	}
	cache := capability.NewJWKSCache(cfg)
	if warm {
		if _, err := cache.GetKeys(context.Background()); err != nil {
			t.Fatalf("warm the JWKS cache: %v", err)
		}
	}
	return pdp.NewJWTPDPWithCache(pdp.JWTPDPOptions{
		JWKSURI: cfg.JWKSURL,
		// Pinning neither audience nor issuer only silences the constructor's
		// misconfiguration warnings; no token is validated here.
		AllowAnyAudience: true,
		AllowAnyIssuer:   true,
	}, cache)
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

// newHealthBreaker returns a CLOSED breaker on clk that trips on one failure. Closed, because
// a warm cache has to be filled through it before the test trips it — a fetch through an open
// breaker is refused.
func newHealthBreaker(clk *testClock, cooldown time.Duration) *circuitbreaker.Breaker {
	return circuitbreaker.New(circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  cooldown,
		HalfOpenMaxProbes: 1,
	}, circuitbreaker.WithClock(clk.Now))
}

// tripBreaker drives br to StateOpen with one failed call.
func tripBreaker(t *testing.T, br *circuitbreaker.Breaker) *circuitbreaker.Breaker {
	t.Helper()
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

// trippedBreaker returns a breaker already driven to StateOpen, on clk.
func trippedBreaker(t *testing.T, clk *testClock, cooldown time.Duration) *circuitbreaker.Breaker {
	t.Helper()
	return tripBreaker(t, newHealthBreaker(clk, cooldown))
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

// TestHealthSnapshot_JWKSBreaker pins the operator-visible consequence of a JWKS outage, and
// the line between the two things it can mean. An impeded breaker refuses key refreshes, so
// rotation is blocked and an unknown-kid token fails closed at once — reported, and alertable,
// as eunox_jwks_fetch_healthy 0. It becomes a READINESS regression only once the cached set can
// no longer serve, which is when every token fails closed; before this was surfaced at all,
// token validation could be entirely down with /healthz reporting "ok".
func TestHealthSnapshot_JWKSBreaker(t *testing.T) {
	t.Run("no JWT layer reports no key-fetch state at all", func(t *testing.T) {
		p := newJWKSHealthProxy(t, nil, coldCache)
		snap := p.snapshot()
		if snap.JWKS != nil {
			t.Errorf("jwks = %+v, want absent with no JWT layer configured", snap.JWKS)
		}
		if snap.Status != statusOK {
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
		p := newJWKSHealthProxy(t, circuitbreaker.New(circuitbreaker.DefaultConfig()), coldCache)
		snap := p.snapshot()
		if snap.JWKS == nil {
			t.Fatal("jwks block must be present with a JWT layer configured")
		}
		if snap.JWKS.BreakerState != circuitbreaker.StateClosed {
			t.Errorf("breakerState = %q, want closed", snap.JWKS.BreakerState)
		}
		if !snap.JWKS.Healthy {
			t.Error("jwks.healthy must be true: a closed breaker can fetch whatever it needs")
		}
		if snap.Status != statusOK {
			t.Errorf("status = %q, want ok for a closed breaker", snap.Status)
		}
		// Both counters must survive marshalling at zero: within the block a zero is a
		// measurement ("never fetched"), not an absence.
		body, err := json.Marshal(snap)
		if err != nil {
			t.Fatalf("marshal snapshot: %v", err)
		}
		for _, want := range []string{`"fetchFailures":0`, `"fetchSuccesses":0`, `"keysServable":false`} {
			if !strings.Contains(string(body), want) {
				t.Errorf("snapshot JSON missing %s (a zero measurement must not be omitted): %s", want, body)
			}
		}
		got := metricsBody(t, p)
		for _, want := range []string{
			"eunox_jwks_fetch_healthy 1\n",
			"eunox_jwks_keys_servable 0\n",
			`eunox_jwks_breaker_state{state="closed"} 1`,
			`eunox_jwks_breaker_state{state="open"} 0`,
		} {
			if !strings.Contains(got, want) {
				t.Errorf("metrics missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("open breaker with no servable key set degrades the snapshot", func(t *testing.T) {
		p := newJWKSHealthProxy(t, trippedBreaker(t, newTestClock(), time.Hour), coldCache)
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
		if snap.JWKS.KeysServable {
			t.Error("keysServable must be false: no fetch ever succeeded")
		}
		if snap.JWKS.Healthy {
			t.Error("jwks.healthy must be false: with no servable set every token fails closed")
		}
		if snap.Status != statusDegraded {
			t.Errorf("status = %q, want degraded: refreshes refused with no servable key set means every token fails closed", snap.Status)
		}
		got := metricsBody(t, p)
		for _, want := range []string{
			"eunox_jwks_fetch_healthy 0\n",
			"eunox_jwks_keys_servable 0\n",
			`eunox_jwks_breaker_state{state="open"} 1`,
			`eunox_jwks_breaker_state{state="closed"} 0`,
			"eunox_jwks_fetch_failures_total 1\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("metrics missing %q:\n%s", want, got)
			}
		}
	})

	// The regression this case exists for: an IdP blip that fails enough refreshes to trip the
	// breaker does so while the cached set is seconds old (30s cooldown against a 5-minute
	// default TTL), and every replica shares the IdP, so degrading on the trip alone takes the
	// whole fleet out of rotation over a window in which 100% of tokens validate.
	t.Run("open breaker over a warm cache alerts but stays ready", func(t *testing.T) {
		br := newHealthBreaker(newTestClock(), time.Hour)
		p := newJWKSHealthProxy(t, br, warmCache)
		tripBreaker(t, br)

		snap := p.snapshot()
		if snap.JWKS == nil {
			t.Fatal("jwks block must be present")
		}
		if snap.JWKS.BreakerState != circuitbreaker.StateOpen {
			t.Fatalf("breakerState = %q, want open", snap.JWKS.BreakerState)
		}
		if !snap.JWKS.KeysServable {
			t.Fatal("the warm fetch must have installed a key set inside its TTL")
		}
		if !snap.JWKS.Healthy {
			t.Error("jwks.healthy must stay true while the cached set serves every token")
		}
		if snap.Status != statusOK {
			t.Errorf("status = %q, want ok: a readiness probe must not drain a replica whose cache absorbs the blip", snap.Status)
		}
		got := metricsBody(t, p)
		// The impediment is still reported and still alertable: rotation is blocked and a
		// token whose kid the cached set does not hold is rejected now.
		for _, want := range []string{
			"eunox_jwks_fetch_healthy 0\n",
			"eunox_jwks_keys_servable 1\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("metrics missing %q:\n%s", want, got)
			}
		}
	})

	// The moment the impediment becomes an impact: the cached set the case above was ready on
	// passes its TTL with refreshes still refused.
	t.Run("a warm cache passing its TTL degrades", func(t *testing.T) {
		clk := newTestClock()
		br := newHealthBreaker(clk, time.Hour)
		sink, _ := newTempAuditSink(t)
		p := newHTTPProxy(httpProxyOptions{
			Sink:   sink,
			JWTPDP: newJWKSHealthPDP(t, br, warmCache, time.Minute, clk.Now),
		})
		tripBreaker(t, br)

		if snap := p.snapshot(); snap.Status != statusOK || !snap.JWKS.KeysServable {
			t.Fatalf("status = %q, keysServable = %v: the set is still inside its TTL", snap.Status, snap.JWKS.KeysServable)
		}
		clk.advance(2 * time.Minute)
		snap := p.snapshot()
		if snap.JWKS.KeysServable {
			t.Error("keysServable must be false once the cached set passes its TTL")
		}
		if snap.Status != statusDegraded {
			t.Errorf("status = %q, want degraded: refreshes refused and the cached set stale is when every token fails closed", snap.Status)
		}
	})

	// The regression #347 fixed, kept pinned: a breaker whose cooldown lapsed reports half-open
	// forever until some fetch drives it, and at HalfOpenMaxProbes=1 a probe in flight refuses
	// every other fetch. Reading only StateOpen made a sustained outage report "ok" for most of
	// its duration, so the page the feature exists to enable never fired.
	t.Run("half-open counts as impeded", func(t *testing.T) {
		clk := newTestClock()
		br := trippedBreaker(t, clk, 30*time.Second)
		clk.advance(31 * time.Second)

		p := newJWKSHealthProxy(t, br, coldCache)
		snap := p.snapshot()
		if snap.JWKS == nil {
			t.Fatal("jwks block must be present")
		}
		if snap.JWKS.BreakerState != circuitbreaker.StateHalfOpen {
			t.Fatalf("breakerState = %q, want half-open after the cooldown lapsed", snap.JWKS.BreakerState)
		}
		if snap.Status != statusDegraded {
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
		p := newJWKSHealthProxy(t, &circuitbreaker.Breaker{}, coldCache)
		snap := p.snapshot()
		if snap.JWKS == nil {
			t.Fatal("jwks block must be present: the JWT layer is configured")
		}
		if snap.Status != statusDegraded {
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

// Every degradable subsystem answers the readiness verdict through ONE seam. Asserted as a
// compile-time constraint rather than left to whichever pattern a new subsystem's author reads
// first: the alternative was two precedents eight lines apart in snapshot(), one asserting an
// interface and one reaching through concrete types across three packages, with nothing failing
// when a third subsystem picked between them arbitrarily.
var (
	_ healthReporter = (*pdp.JWTPDP)(nil)
	_ healthReporter = (*killswitch.InMemory)(nil)
)

// TestHealthSnapshot_SubsystemVerdictsFoldTheSameWay pins the fold: a degraded subsystem sets
// its OWN field and the summary, and never one without the other — the discrepancy a scraper
// reading the field could not detect.
func TestHealthSnapshot_SubsystemVerdictsFoldTheSameWay(t *testing.T) {
	t.Run("jwks", func(t *testing.T) {
		p := newJWKSHealthProxy(t, trippedBreaker(t, newTestClock(), time.Hour), coldCache)
		snap := p.snapshot()
		if snap.JWKS.Healthy || snap.Status != statusDegraded {
			t.Errorf("healthy = %v, status = %q: a degraded subsystem must set both", snap.JWKS.Healthy, snap.Status)
		}
		if !snap.KillSwitchHealthy {
			t.Error("one subsystem's verdict must not touch another's field")
		}
	})

	t.Run("kill switch", func(t *testing.T) {
		sink, _ := newTempAuditSink(t)
		p := newHTTPProxy(httpProxyOptions{Sink: sink, KS: unconfirmableKillSwitch{killswitch.NewInMemory()}})
		snap := p.snapshot()
		if snap.KillSwitchHealthy || snap.Status != statusDegraded {
			t.Errorf("killSwitchHealthy = %v, status = %q: a degraded subsystem must set both", snap.KillSwitchHealthy, snap.Status)
		}
		if snap.JWKS != nil {
			t.Error("no JWT layer is configured, so no jwks block may appear")
		}
	})
}

// unconfirmableKillSwitch is a working backend that cannot confirm its kill set — the shape a
// partitioned Redis reports, and the only thing snapshot() asks of it. A real manager is
// embedded rather than a nil one: the proxy subscribes to revocations at construction.
type unconfirmableKillSwitch struct{ *killswitch.InMemory }

func (unconfirmableKillSwitch) HealthStatus() error { return errors.New("redis: connection refused") }

// TestHealthSnapshot_JWKSReportsTheCacheEveryRouteFetchesThrough pins the invariant snapshot()
// states in prose and relies on: it reads ONE validator's breaker and calls the answer
// proxy-wide. That is only true because WrapRoutesWithJWT hands every route wrapper the
// validator's own cache, and because the gateway is handed that same validator — two
// independent inputs to NewHTTPProxyGateway that nothing else ties together. Split them and
// /healthz reports a breaker no route fetches through, permanently healthy.
func TestHealthSnapshot_JWKSReportsTheCacheEveryRouteFetchesThrough(t *testing.T) {
	sink, _ := newTempAuditSink(t)
	routes := map[string]*UpstreamRoute{
		"alpha": {name: "alpha", pdp: pdp.AlwaysAllowPDP{}},
		"beta":  {name: "beta", pdp: pdp.AlwaysAllowPDP{}},
	}
	validator, err := WrapRoutesWithJWT(routes, pdp.JWTPDPOptions{
		JWKSURI:          "https://idp.example/.well-known/jwks.json",
		AllowAnyAudience: true,
		AllowAnyIssuer:   true,
	})
	if err != nil {
		t.Fatalf("WrapRoutesWithJWT: %v", err)
	}
	p := NewHTTPProxyGateway(HTTPGatewayOptions{
		Routes: routes,
		JWTPDP: validator,
		KS:     killswitch.NewInMemory(),
		Sink:   sink,
	})

	reported := p.jwtPDP.Cache()
	if reported == nil {
		t.Fatal("the proxy must hold the validator whose cache /healthz reports")
	}
	for name, rt := range routes {
		wrapper, ok := rt.pdp.(*pdp.JWTPDP)
		if !ok {
			t.Fatalf("route %q was not wrapped: %T", name, rt.pdp)
		}
		if wrapper.Cache() != reported {
			t.Errorf("route %q fetches keys through a different cache than /healthz reports; the proxy-wide reading would be wrong for it", name)
		}
	}
	if p.snapshot().JWKS == nil {
		t.Error("a wrapped gateway must report a jwks block: absence is documented to mean no JWT layer")
	}
}
