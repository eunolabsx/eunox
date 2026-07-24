// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/circuitbreaker"
)

// TestIsLoopbackHost pins the single source of truth cmd/eunox's
// validateJWKSURIScheme and this package's own plaintext-http warning both
// consult, so the two call sites cannot silently re-diverge on which hosts
// count as loopback (case-insensitivity and a trailing FQDN dot in particular).
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"Localhost", true},
		{"localhost.", true},
		{"LOCALHOST.", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"example.com", false},
		{"127.0.0.1.nip.io", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsLoopbackHost(tc.host); got != tc.want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestJWKSCache_ForceRefresh_BypassesTTL verifies the force-refresh path that
// fixes the kid-miss-during-rotation gap: GetKeys and Refresh
// serve from cache while within the TTL, but ForceRefresh always issues an HTTP
// fetch regardless of the TTL.
func TestJWKSCache_ForceRefresh_BypassesTTL(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})

	// Prime the cache.
	_, err = cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	// Within the TTL, GetKeys and Refresh both serve from cache — no new fetch.
	_, err = cache.GetKeys(context.Background())
	require.NoError(t, err)
	_, err = cache.Refresh(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load(), "within TTL, GetKeys/Refresh must not re-fetch")

	// A forced refresh ignores the TTL and always fetches.
	_, _, err = cache.refresh(context.Background(), true)
	require.NoError(t, err)
	require.Equal(t, int32(2), hits.Load(), "ForceRefresh must bypass the TTL and fetch")
}

// TestJWKSCache_NegativeCacheTTL_NormalizesToDefault is the regression for a
// negative CacheTTL: it must normalize to the 5-minute default (matching
// NewPayloadCache's <= 0 normalization) rather than being treated as
// always-stale, which would silently disable caching and re-fetch the JWKS on
// every call.
func TestJWKSCache_NegativeCacheTTL_NormalizesToDefault(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: -1})
	require.Equal(t, 5*time.Minute, cache.cacheTTL, "negative CacheTTL should normalize to the 5-minute default")

	_, err = cache.GetKeys(context.Background())
	require.NoError(t, err)
	_, err = cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load(), "a normalized (non-zero) TTL must still serve the second call from cache")
}

// TestJWKSCache_ForceRefresh_DoesNotJoinInFlightNonForced pins that forced and
// non-forced refreshes use SEPARATE singleflight keys: a forced
// refresh arriving while a non-forced fetch is in flight must start its own HTTP
// round-trip rather than join the non-forced leader and inherit its TTL fast-path.
// Sharing one key let a forced caller silently receive a cached/stale key set
// during a rotation, after which ForceRefreshForKID marked the kid absent for 30s
// and denied valid tokens.
func TestJWKSCache_ForceRefresh_DoesNotJoinInFlightNonForced(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			close(entered)
			<-release // hold the leader (non-forced) fetch open so the forced caller must decide whether to queue behind it
		}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})

	// Leader: a non-forced refresh that blocks mid-fetch.
	leaderDone := make(chan error, 1)
	go func() {
		_, e := cache.Refresh(context.Background())
		leaderDone <- e
	}()
	<-entered

	// A forced refresh arriving now must NOT join the in-flight non-forced fetch:
	// with separate keys it issues its own request, which (being the second hit)
	// returns immediately without blocking on release.
	forcedDone := make(chan error, 1)
	go func() {
		_, _, e := cache.refresh(context.Background(), true)
		forcedDone <- e
	}()
	require.NoError(t, <-forcedDone, "forced refresh must complete on its own fetch without waiting for the held non-forced leader")
	require.Equal(t, int32(2), hits.Load(), "forced refresh must start its own HTTP round-trip, not join the in-flight non-forced fetch")

	close(release)
	require.NoError(t, <-leaderDone)
}

// TestJWKSCache_ForceRefreshForKID_EmptyKID_RateLimited is the regression:
// ForceRefreshForKID("") must delegate to the rate-limited kid-less
// path (ForceRefreshForVerify) rather than fetching unconditionally. The old code
// gated its suppression block on kid != "", so an empty kid skipped all
// rate-limiting and hit the IdP's JWKS endpoint on every call. Here the endpoint
// returns the SAME (single, kid-less) key set on every fetch, so the first forced
// refresh charges the shared sentinel; subsequent ForceRefreshForKID("") calls must
// be suppressed and serve the cache instead of re-fetching.
func TestJWKSCache_ForceRefreshForKID_EmptyKID_RateLimited(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		// A single key with NO kid header: an empty-kid lookup selects it, so the
		// fetched set never resolves a "missing" kid and the set is unchanging.
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})

	// Prime the cache so the next fetch observes an UNCHANGED set (a cold-cache first
	// fetch counts as a change and would not charge the sentinel).
	_, err = cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	// First empty-kid forced refresh: delegates to ForceRefreshForVerify, fetches,
	// and — because the set is unchanged relative to the primed cache — charges the
	// shared sentinel.
	_, err = cache.ForceRefreshForKID(context.Background(), "")
	require.NoError(t, err)
	require.Equal(t, int32(2), hits.Load())

	// Subsequent empty-kid forced refreshes must be rate-limited: the charged shared
	// sentinel suppresses the fetch and the cached set is served. The old (buggy)
	// code skipped all rate-limiting for the empty kid and fetched on every call.
	for i := 0; i < 5; i++ {
		_, err = cache.ForceRefreshForKID(context.Background(), "")
		require.NoError(t, err)
	}
	require.Equal(t, int32(2), hits.Load(), "empty-kid ForceRefreshForKID must be rate-limited via ForceRefreshForVerify, not fetch every call")
}

// TestJWKSCache_kidRecentlyAbsent_ReinsertedFreshReturnsTrue is the regression:
// when the entry is found expired under the read lock but a concurrent
// markKIDAbsent re-inserts it with a fresh timestamp before the write lock is
// acquired (the RWMutex has no atomic upgrade), the write-lock re-check must return
// true — the kid IS recently absent again. The old code's re-check only deleted on
// re-confirmed expiry and ALWAYS returned false, so a freshly re-charged entry was
// reported as not-absent, letting a suppressed fetch through.
//
// We drive the upgrade gap deterministically with a clock whose returned time
// depends on a flag we flip between the two now() reads inside kidRecentlyAbsent:
// the read-lock read sees the entry as expired, the write-lock re-read sees it as
// fresh (as if it had just been re-inserted).
func TestJWKSCache_kidRecentlyAbsent_ReinsertedFreshReturnsTrue(t *testing.T) {
	t.Parallel()
	const kid = "k-absent"

	base := time.Unix(1_000_000, 0)
	var firstReadDone atomic.Bool
	now := func() time.Time {
		if firstReadDone.CompareAndSwap(false, true) {
			// First now() call: the read-lock expiry check. Report a time far past
			// the TTL so the entry (stamped at base) reads as expired and the code
			// falls through to the write-lock re-check.
			return base.Add(negativeKIDTTL * 2)
		}
		// Subsequent now() calls: the write-lock re-check. Report a time within the
		// TTL of base, as if a concurrent markKIDAbsent had re-stamped the entry
		// fresh in the upgrade gap. The re-check must then return true.
		return base.Add(negativeKIDTTL / 2)
	}
	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: "http://example.invalid/jwks", Now: now})
	cache.negMu.Lock()
	cache.negKIDs[kid] = base
	cache.negMu.Unlock()

	require.True(t, cache.kidRecentlyAbsent(kid),
		"an entry re-stamped fresh between the read-unlock and write-lock must report recently-absent")
	cache.negMu.RLock()
	_, stillThere := cache.negKIDs[kid]
	cache.negMu.RUnlock()
	require.True(t, stillThere, "a re-stamped-fresh entry must NOT be pruned")
}

// TestJWKSCache_kidRecentlyAbsent_ExpiredIsPruned pins the complementary path: an
// entry that is genuinely expired at both the read-lock and write-lock checks must
// be pruned and reported not-absent.
func TestJWKSCache_kidRecentlyAbsent_ExpiredIsPruned(t *testing.T) {
	t.Parallel()
	const kid = "k-stale"
	base := time.Unix(1_000_000, 0)
	clk := base
	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: "http://example.invalid/jwks", Now: func() time.Time { return clk }})
	cache.negMu.Lock()
	cache.negKIDs[kid] = base
	cache.negMu.Unlock()

	clk = base.Add(negativeKIDTTL * 2)
	require.False(t, cache.kidRecentlyAbsent(kid), "a genuinely-expired entry must report not-absent")
	cache.negMu.RLock()
	_, stillThere := cache.negKIDs[kid]
	cache.negMu.RUnlock()
	require.False(t, stillThere, "a genuinely-expired entry must be pruned by the write-lock branch")
}

// TestJWKSCache_refresh_SkippedInstallReturnsInstalledSet is the regression:
// when a refresh closure does NOT install its fetched set
// (because a newer-generation refresh already committed a fresher one), it must
// return the currently-installed set — what GetKeys() will serve — rather than its
// own discarded fetch, and compute "changed" against that returned set.
//
// We force the install-skip branch deterministically: pre-load the cache with a
// known set and bump installedFetchGen above what the next single fetch's ticket
// will reach, so the fetched set is computed but never installed.
func TestJWKSCache_refresh_SkippedInstallReturnsInstalledSet(t *testing.T) {
	t.Parallel()
	installedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	fetchedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		// The endpoint serves a DIFFERENT key than the pre-installed set, so if the
		// closure wrongly returned its own fetch we would observe the fetched key.
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &fetchedKey.PublicKey, KeyID: "fetched", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})

	// Pre-install a known set and pin installedFetchGen high so the upcoming forced
	// fetch (which takes a strictly-lower generation) is computed but its install is
	// skipped — exactly the supersede race the fix addresses.
	installed := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &installedKey.PublicKey, KeyID: "installed", Use: "sig"}}}
	cache.mu.Lock()
	cache.jwks = installed
	cache.fetchedAt = cache.now()
	cache.installedFetchGen = 1_000_000 // higher than any ticket this single fetch will take
	cache.mu.Unlock()

	keys, changed, err := cache.refresh(context.Background(), true)
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load(), "a forced refresh must fetch")

	// The fetch was discarded (its generation was stale), so the closure must return
	// the currently-installed set, not its own fetched set.
	require.Same(t, installed, keys, "skipped-install refresh must return the installed set, not its discarded fetch")
	require.Len(t, FindKeys(keys, "installed"), 1, "returned set must be the installed one")
	require.Len(t, FindKeys(keys, "fetched"), 0, "returned set must not be the discarded fetch")

	// "changed" is computed against the returned (installed) set, which equals the
	// set present before this fetch, so it must report no change.
	require.False(t, changed, "changed must be computed against the returned installed set (no change)")

	// And GetKeys continues to serve the installed set, confirming coherence.
	served, err := cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Same(t, installed, served)
}

// jwksJSONWithNKeys returns a marshaled JWKS carrying n keys, all reusing one
// public key with distinct key IDs. Reusing a single key avoids n keygens while
// still producing a structurally valid set of n entries.
func jwksJSONWithNKeys(t *testing.T, n int) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	entries := make([]jose.JSONWebKey, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, jose.JSONWebKey{Key: &key.PublicKey, KeyID: fmt.Sprintf("k%d", i), Use: "sig"})
	}
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: entries})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

// TestJWKSCache_RejectsOversizedKeySet asserts the maxJWKSKeys cap: a set above
// the cap is rejected wholesale (fail closed) so a kid-less token cannot be made
// to trial an unbounded number of keys, while a set at the cap is accepted.
func TestJWKSCache_RejectsOversizedKeySet(t *testing.T) {
	t.Run("above cap is rejected", func(t *testing.T) {
		body := jwksJSONWithNKeys(t, maxJWKSKeys+1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})
		if _, err := cache.GetKeys(context.Background()); err == nil {
			t.Fatal("expected an oversized key set to be rejected, got nil error")
		}
	})

	t.Run("at cap is accepted", func(t *testing.T) {
		body := jwksJSONWithNKeys(t, maxJWKSKeys)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})
		got, err := cache.GetKeys(context.Background())
		if err != nil {
			t.Fatalf("expected a key set at the cap to be accepted, got error: %v", err)
		}
		if len(got.Keys) != maxJWKSKeys {
			t.Fatalf("expected %d keys, got %d", maxJWKSKeys, len(got.Keys))
		}
	})
}

// TestJWKSCache_FetchFailuresTaggedUnavailable pins that every failure to obtain a
// usable key set carries ErrJWKSUnavailable, so a caller (and the audit layer above
// it) can tell a JWKS-infrastructure outage apart from a forged token: the token was
// never checked against a key. It covers each origin — network error, non-200,
// empty set, oversized set, and an open circuit breaker — through the exported
// GetKeys, and confirms a healthy fetch is NOT tagged.
func TestJWKSCache_FetchFailuresTaggedUnavailable(t *testing.T) {
	t.Run("network error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(jwksJSONWithNKeys(t, 1))
		}))
		url := srv.URL
		srv.Close() // close before fetch so Do() returns a connection error
		cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: url, CacheTTL: time.Hour})
		_, err := cache.GetKeys(context.Background())
		if err == nil || !errors.Is(err, ErrJWKSUnavailable) {
			t.Fatalf("GetKeys err = %v, want it to wrap ErrJWKSUnavailable", err)
		}
	})

	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})
		_, err := cache.GetKeys(context.Background())
		if err == nil || !errors.Is(err, ErrJWKSUnavailable) {
			t.Fatalf("GetKeys err = %v, want it to wrap ErrJWKSUnavailable", err)
		}
	})

	t.Run("empty key set", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}))
		defer srv.Close()
		cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})
		_, err := cache.GetKeys(context.Background())
		if err == nil || !errors.Is(err, ErrJWKSUnavailable) {
			t.Fatalf("GetKeys err = %v, want it to wrap ErrJWKSUnavailable", err)
		}
	})

	t.Run("oversized key set", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(jwksJSONWithNKeys(t, maxJWKSKeys+1))
		}))
		defer srv.Close()
		cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})
		_, err := cache.GetKeys(context.Background())
		if err == nil || !errors.Is(err, ErrJWKSUnavailable) {
			t.Fatalf("GetKeys err = %v, want it to wrap ErrJWKSUnavailable", err)
		}
	})

	t.Run("open circuit breaker", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		// Threshold 1 trips the breaker on the first failed fetch; the long cooldown
		// keeps it open for the second call, which is rejected as ErrOpen — the branch
		// that must also carry ErrJWKSUnavailable.
		br := circuitbreaker.New(circuitbreaker.Config{
			FailureThreshold:  1,
			CooldownDuration:  time.Hour,
			HalfOpenMaxProbes: 1,
		})
		cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour, Breaker: br})
		if _, err := cache.GetKeys(context.Background()); err == nil {
			t.Fatal("first GetKeys should fail (503) and trip the breaker")
		}
		_, err := cache.GetKeys(context.Background())
		if err == nil || !errors.Is(err, circuitbreaker.ErrOpen) {
			t.Fatalf("second GetKeys err = %v, want it to wrap circuitbreaker.ErrOpen (breaker should be open)", err)
		}
		if !errors.Is(err, ErrJWKSUnavailable) {
			t.Fatalf("breaker-open err = %v, want it to also wrap ErrJWKSUnavailable", err)
		}
	})

	t.Run("healthy fetch is not tagged", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(jwksJSONWithNKeys(t, 1))
		}))
		defer srv.Close()
		cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})
		if _, err := cache.GetKeys(context.Background()); err != nil {
			t.Fatalf("a healthy fetch must succeed, got %v", err)
		}
	})
}

// TestJWKSCache_DefaultClientRefusesRedirect asserts the default client built by
// NewJWKSCache does not follow a redirect away from the configured JWKS endpoint:
// the redirect target is never contacted and the fetch fails closed.
func TestJWKSCache_DefaultClientRefusesRedirect(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write(jwksJSONWithNKeys(t, 1))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// Client is nil, so NewJWKSCache builds the default client whose CheckRedirect
	// refuses to follow the 30x.
	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: redirector.URL, CacheTTL: time.Hour})
	if _, err := cache.GetKeys(context.Background()); err == nil {
		t.Fatal("expected the refused redirect to surface as a fetch error, got nil")
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("redirect target was contacted %d time(s); the default client must not follow JWKS redirects", n)
	}
}

// blockingRoundTripper never responds until released, simulating a stalled
// transport. It honors request-context cancellation so the bounded fetch can
// unblock it.
type blockingRoundTripper struct {
	released chan struct{}
}

func (b *blockingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-b.released:
		return nil, context.Canceled
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

// TestJWKSCache_BoundedFetch_NoClientTimeout guards against: the shared
// fetch strips the caller's deadline (context.WithoutCancel) on the assumption
// that the HTTP client's Timeout bounds it, but a custom client may have
// Timeout == 0. Without an internal ceiling a stalled transport would hang
// forever and, because refreshes share one singleflight call, every later
// verification would join the stuck fetch. The cache must impose its own maxFetch
// ceiling so the operation always terminates.
func TestJWKSCache_BoundedFetch_NoClientTimeout(t *testing.T) {
	t.Parallel()

	rt := &blockingRoundTripper{released: make(chan struct{})}
	defer close(rt.released)

	// Zero-value timeout: the exact misconfiguration the fix must tolerate.
	cache := NewJWKSCache(JWKSCacheConfig{
		JWKSURL:  "https://idp.example/.well-known/jwks.json",
		Client:   &http.Client{Transport: rt},
		CacheTTL: time.Hour,
	})
	cache.maxFetch = 50 * time.Millisecond // shrink the real ceiling for the test

	// Caller passes a short deadline; the fetch deliberately ignores it, so the
	// internal ceiling is what must rescue us.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := cache.GetKeys(ctx)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from a stalled fetch, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GetKeys did not return: fetch was not bounded by maxFetch")
	}
}

// TestFindKeys_NilSet verifies that FindKeys does not panic on a nil JWKS — an
// exported caller that forgot to check a fetch error (and so passes a nil set)
// must get an empty result, not a nil-pointer dereference.
func TestFindKeys_NilSet(t *testing.T) {
	t.Parallel()
	require.Nil(t, FindKeys(nil, "some-kid"), "FindKeys(nil, kid) must return nil, not panic")
	require.Nil(t, FindKeys(nil, ""), "FindKeys(nil, \"\") must return nil, not panic")
}

// TestJWKSCache_ForceRefreshForKID_SuppressesUnknownKIDFlood verifies the
// negative-cache gate: a kid that a forced refetch fails to resolve is not
// refetched again until negativeKIDTTL elapses, so a stream of distinct
// unknown-kid tokens cannot drive one upstream JWKS round-trip each. The caller
// still fails closed in the suppressed window because the returned set does not
// contain the kid.
func TestJWKSCache_ForceRefreshForKID_SuppressesUnknownKIDFlood(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	now := time.Now()
	cache := NewJWKSCache(JWKSCacheConfig{
		JWKSURL:  srv.URL,
		Client:   srv.Client(),
		CacheTTL: time.Hour,
		Now:      func() time.Time { return now },
	})

	// Prime the cache with one fetch.
	_, err = cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	// First unknown-kid lookup forces a fresh fetch (rotation-handling path) and,
	// finding no match, records the kid as absent.
	set, err := cache.ForceRefreshForKID(context.Background(), "ghost")
	require.NoError(t, err)
	require.Equal(t, int32(2), hits.Load(), "first unknown-kid lookup must force one fetch")
	require.Empty(t, FindKeys(set, "ghost"), "the returned set must not contain the unknown kid (caller fails closed)")

	// Repeated unknown-kid lookups within negativeKIDTTL are suppressed: the
	// cached set is returned with no further upstream fetch.
	for i := 0; i < 50; i++ {
		set, err = cache.ForceRefreshForKID(context.Background(), "ghost")
		require.NoError(t, err)
		require.Empty(t, FindKeys(set, "ghost"))
	}
	require.Equal(t, int32(2), hits.Load(), "an unknown-kid flood must not amplify into one fetch per token")

	// Once negativeKIDTTL elapses, the kid is retried exactly once more.
	now = now.Add(negativeKIDTTL + time.Second)
	_, err = cache.ForceRefreshForKID(context.Background(), "ghost")
	require.NoError(t, err)
	require.Equal(t, int32(3), hits.Load(), "after the negative-cache TTL the kid must be retried")
}

// TestJWKSCache_ForceRefreshForKID_SharedBudgetAcrossDistinctKIDs is the core of
// the shared-refresh-budget fix: a flood of DISTINCT unknown kids must not drive
// one upstream JWKS round-trip each. The per-kid negative cache only suppresses a
// repeat of the SAME kid, so without a shared budget N distinct unknown kids cost N
// forced fetches. Once a forced fetch returns the same key set the cache already
// held, the shared sentinel is charged and every subsequent distinct unknown kid is
// served from cache (failing closed) until the budget's TTL elapses.
func TestJWKSCache_ForceRefreshForKID_SharedBudgetAcrossDistinctKIDs(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	now := time.Now()
	cache := NewJWKSCache(JWKSCacheConfig{
		JWKSURL:  srv.URL,
		Client:   srv.Client(),
		CacheTTL: time.Hour,
		Now:      func() time.Time { return now },
	})

	// Prime the cache with one fetch.
	_, err = cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	// The first unknown kid forces a fetch; the set is unchanged, so it charges the
	// shared budget.
	set, err := cache.ForceRefreshForKID(context.Background(), "ghost-0")
	require.NoError(t, err)
	require.Equal(t, int32(2), hits.Load(), "the first unknown kid must force one fetch")
	require.Empty(t, FindKeys(set, "ghost-0"), "the returned set must not contain the unknown kid (fail closed)")

	// Subsequent DISTINCT unknown kids must be suppressed by the shared budget — no
	// per-kid entry exists for any of them, yet none forces a fetch.
	for i := 1; i <= 50; i++ {
		kid := "ghost-" + strconv.Itoa(i)
		set, err = cache.ForceRefreshForKID(context.Background(), kid)
		require.NoError(t, err)
		require.Empty(t, FindKeys(set, kid), "a distinct unknown kid must still fail closed while suppressed")
	}
	require.Equal(t, int32(2), hits.Load(),
		"a flood of DISTINCT unknown kids must not amplify into one fetch per kid (shared budget)")

	// After the budget's TTL elapses, exactly one more forced fetch is allowed.
	now = now.Add(negativeKIDTTL + time.Second)
	_, err = cache.ForceRefreshForKID(context.Background(), "ghost-after-ttl")
	require.NoError(t, err)
	require.Equal(t, int32(3), hits.Load(), "after the shared-budget TTL a forced fetch must be allowed again")
}

// TestJWKSCache_ForceRefreshForKID_ChangedSetLeavesBudgetOpen pins the rotation
// safety of the shared budget: a forced fetch that pulls in a CHANGED key set must
// NOT charge the shared sentinel, so a genuinely rotated-in kid presented right
// after is still resolved immediately rather than being suppressed for the window.
func TestJWKSCache_ForceRefreshForKID_ChangedSetLeavesBudgetOpen(t *testing.T) {
	t.Parallel()
	keyA, keyB := mustECDSAKey(t), mustECDSAKey(t)
	jwk := func(k *ecdsa.PrivateKey, id string) jose.JSONWebKey {
		return jose.JSONWebKey{Key: &k.PublicKey, KeyID: id, Use: "sig"}
	}

	var mu sync.Mutex
	current := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk(keyA, "a")}}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		mu.Lock()
		ks := current
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	defer srv.Close()

	now := time.Now()
	cache := NewJWKSCache(JWKSCacheConfig{
		JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour,
		Now: func() time.Time { return now },
	})

	_, err := cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	// A rotation lands: key "b" appears. An unknown kid forces a fetch that pulls the
	// new set in (CHANGED), so the shared budget is left clear.
	mu.Lock()
	current = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk(keyA, "a"), jwk(keyB, "b")}}
	mu.Unlock()
	set, err := cache.ForceRefreshForKID(context.Background(), "ghost")
	require.NoError(t, err)
	require.Equal(t, int32(2), hits.Load(), "the unknown kid must force a fetch")
	require.Empty(t, FindKeys(set, "ghost"), "the unknown kid stays absent (fail closed)")

	// The rotated-in kid "b" is presented within negativeKIDTTL (clock not advanced).
	// Because the previous fetch CHANGED the set, the shared budget did not engage, so
	// this forced refresh runs and resolves "b" immediately.
	set, err = cache.ForceRefreshForKID(context.Background(), "b")
	require.NoError(t, err)
	require.Equal(t, int32(3), hits.Load(), "a changed set must not suppress a following forced refresh")
	require.NotEmpty(t, FindKeys(set, "b"), "the rotated-in kid must be resolved, not suppressed by the shared budget")
}

// TestJWKSCache_ForceRefreshForKID_ChargedBudgetDelaysRotatedKidUntilTTL pins the
// accepted tradeoff of the shared budget for the charged -> rotation -> new-kid
// ordering (the converse of ChangedSetLeavesBudgetOpen, which covers
// rotation-before-charge). When the sentinel is charged BEFORE a rotation lands, a
// genuinely rotated-in kid is suppressed and fails closed for up to negativeKIDTTL,
// then resolves on the first probe fetch after the budget expires. The delay is
// bounded and self-healing, and far below CacheTTL.
func TestJWKSCache_ForceRefreshForKID_ChargedBudgetDelaysRotatedKidUntilTTL(t *testing.T) {
	t.Parallel()
	keyA, keyNew := mustECDSAKey(t), mustECDSAKey(t)
	jwk := func(k *ecdsa.PrivateKey, id string) jose.JSONWebKey {
		return jose.JSONWebKey{Key: &k.PublicKey, KeyID: id, Use: "sig"}
	}

	var mu sync.Mutex
	current := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk(keyA, "a")}}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		mu.Lock()
		ks := current
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	defer srv.Close()

	now := time.Now()
	cache := NewJWKSCache(JWKSCacheConfig{
		JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour,
		Now: func() time.Time { return now },
	})

	_, err := cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	// 1) An unknown kid charges the shared budget via an unchanged fetch.
	_, err = cache.ForceRefreshForKID(context.Background(), "ghost")
	require.NoError(t, err)
	require.Equal(t, int32(2), hits.Load(), "the unknown kid must force one fetch and charge the budget")

	// 2) The issuer rotates in "knew" AFTER the budget is charged (clock not advanced).
	mu.Lock()
	current = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk(keyA, "a"), jwk(keyNew, "knew")}}
	mu.Unlock()

	// 3) A valid token carrying "knew" arrives within the window: the charged budget
	// suppresses the forced fetch, so "knew" is not yet observed and the caller fails
	// closed. No upstream fetch happens — this is the bounded delay the doc comment
	// describes.
	set, err := cache.ForceRefreshForKID(context.Background(), "knew")
	require.NoError(t, err)
	require.Equal(t, int32(2), hits.Load(), "while the budget is charged the rotated-in kid must not force a fetch")
	require.Empty(t, FindKeys(set, "knew"), "the rotated-in kid is suppressed (fails closed) until the budget expires")

	// 4) After negativeKIDTTL the budget expires; the next lookup fetches, observes the
	// rotation, and resolves "knew" — bounded and self-healing.
	now = now.Add(negativeKIDTTL + time.Second)
	set, err = cache.ForceRefreshForKID(context.Background(), "knew")
	require.NoError(t, err)
	require.Equal(t, int32(3), hits.Load(), "after the budget TTL one probe fetch must run")
	require.NotEmpty(t, FindKeys(set, "knew"), "the rotated-in kid resolves once the budget expires (self-healing)")
}

// TestJWKSCache_ForceRefreshForKID_DoesNotSuppressKnownOrEmptyKID verifies that a
// PRESENT kid forces a fetch every time and is never negatively cached. The empty
// kid is handled separately (see below): it delegates to the
// rate-limited ForceRefreshForVerify rather than fetching unconditionally, so it
// is NOT exempt from the shared sentinel.
func TestJWKSCache_ForceRefreshForKID_DoesNotSuppressKnownOrEmptyKID(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})

	// A present kid forces a fetch every time and is never negatively cached.
	for i := int32(1); i <= 3; i++ {
		set, ferr := cache.ForceRefreshForKID(context.Background(), "k1")
		require.NoError(t, ferr)
		require.NotEmpty(t, FindKeys(set, "k1"))
		require.Equal(t, i, hits.Load(), "a known kid must always fetch (never suppressed)")
	}

	// The empty kid must NOT bypass rate-limiting: ForceRefreshForKID("")
	// delegates to the rate-limited ForceRefreshForVerify. The endpoint here serves
	// an unchanging key set, so the first empty-kid forced refresh fetches and
	// charges the shared sentinel (the set is unchanged relative to the installed
	// one); subsequent empty-kid calls are then suppressed and serve the cache. The
	// old code skipped all rate-limiting for the empty kid, letting it hammer the
	// IdP on every call.
	base := hits.Load()
	_, ferr := cache.ForceRefreshForKID(context.Background(), "")
	require.NoError(t, ferr)
	require.Equal(t, base+1, hits.Load(), "first empty-kid forced refresh fetches")
	for i := 0; i < 3; i++ {
		_, ferr = cache.ForceRefreshForKID(context.Background(), "")
		require.NoError(t, ferr)
	}
	require.Equal(t, base+1, hits.Load(), "empty-kid forced refresh is rate-limited (delegates to ForceRefreshForVerify), not fetched every call")
}

// TestJWKSCache_MarkKIDAbsent_AnchorsToFirstObservation is the regression:
// re-marking an already-known-absent kid must NOT slide its negativeKIDTTL window
// forward. The suppress window is anchored to the FIRST absent observation, so a
// client that keeps presenting a stale kid cannot pin it in the negative cache —
// once the TTL measured from the first observation elapses, a forced refresh is
// allowed again and a JWKS update that re-adds the kid can resolve it.
func TestJWKSCache_MarkKIDAbsent_AnchorsToFirstObservation(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cache := NewJWKSCache(JWKSCacheConfig{
		JWKSURL: "https://example.invalid/jwks",
		Now:     func() time.Time { return now },
	})

	// First observation anchors the window at t0.
	cache.markKIDAbsent("k1")
	require.True(t, cache.kidRecentlyAbsent("k1"), "a freshly marked kid must be suppressed")

	// Advance to just before the TTL boundary and re-mark the SAME kid. Pre-fix,
	// this re-mark reset the timestamp to "now", extending the window by another
	// full TTL; with the fix it is ignored and the original timestamp stands.
	now = now.Add(negativeKIDTTL - time.Second)
	cache.markKIDAbsent("k1")
	require.True(t, cache.kidRecentlyAbsent("k1"), "still within one TTL of the first observation")

	// Advance just past the TTL measured from the FIRST observation. Anchored to
	// the first observation, the entry has now expired despite the recent re-mark.
	now = now.Add(2 * time.Second)
	require.False(t, cache.kidRecentlyAbsent("k1"),
		"window must be anchored to the first observation; a re-mark must not slide it forward")
}

// TestJWKSCache_MarkKIDAbsent_SentinelExemptFromCap is the regression: the
// shared refresh sentinel must remain insertable even when a flood of distinct
// unknown kids has filled the negative cache to capacity. Otherwise the kid-less
// (ForceRefreshForVerify) and unknown-kid (ForceRefreshForKID) paths lose their
// shared rate-limit and an attacker can drive unbounded JWKS fetches.
func TestJWKSCache_MarkKIDAbsent_SentinelExemptFromCap(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cache := NewJWKSCache(JWKSCacheConfig{
		JWKSURL: "https://example.invalid/jwks",
		Now:     func() time.Time { return now },
	})

	// Fill the negative cache to capacity with distinct unknown kids, as an
	// attacker flooding the proxy with unique-kid tokens would.
	for i := 0; i < negativeKIDMaxLen; i++ {
		cache.markKIDAbsent("kid-" + strconv.Itoa(i))
	}

	// A real kid past the cap is dropped, so the map stays bounded.
	cache.markKIDAbsent("overflow-kid")
	require.False(t, cache.kidRecentlyAbsent("overflow-kid"),
		"a real kid past the cap must be dropped so the negative cache stays bounded")

	// The sentinel must still be recorded despite the full map.
	cache.markKIDAbsent(sharedRefreshSentinel)
	require.True(t, cache.kidRecentlyAbsent(sharedRefreshSentinel),
		"the shared refresh sentinel must be reserved even when the negative cache is full")
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

// TestJWKSCache_ForceRefreshForVerify_DoesNotSuppressAfterRotation is the
// regression: when a verify-triggered forced refresh actually pulls in a rotated
// key (the set CHANGED), the negative sentinel must NOT be marked, so a second
// rotation within negativeKIDTTL is still fetched immediately. The previous code
// marked the sentinel unconditionally, suppressing the whole kid-less path for the
// window and rejecting tokens signed by an emergency re-rotated key.
func TestJWKSCache_ForceRefreshForVerify_DoesNotSuppressAfterRotation(t *testing.T) {
	t.Parallel()
	keyA, keyB, keyC := mustECDSAKey(t), mustECDSAKey(t), mustECDSAKey(t)
	jwk := func(k *ecdsa.PrivateKey, id string) jose.JSONWebKey {
		return jose.JSONWebKey{Key: &k.PublicKey, KeyID: id, Use: "sig"}
	}

	var mu sync.Mutex
	current := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk(keyA, "a")}}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		mu.Lock()
		ks := current
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	defer srv.Close()

	now := time.Now()
	cache := NewJWKSCache(JWKSCacheConfig{
		JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour,
		Now: func() time.Time { return now },
	})

	_, err := cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	// Rotation R1: a new key B appears. The forced refresh fetches and pulls it in;
	// because the set changed, the sentinel is left clear.
	mu.Lock()
	current = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk(keyA, "a"), jwk(keyB, "b")}}
	mu.Unlock()
	set, err := cache.ForceRefreshForVerify(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(2), hits.Load(), "R1 must force a fetch")
	require.NotEmpty(t, FindKeys(set, "b"), "rotated-in key B must be present")

	// Rotation R2 within negativeKIDTTL (clock not advanced): a key C appears. Since
	// R1 changed the set and did not suppress, this forced refresh must still fetch
	// and pull C in immediately.
	mu.Lock()
	current = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk(keyA, "a"), jwk(keyB, "b"), jwk(keyC, "c")}}
	mu.Unlock()
	set, err = cache.ForceRefreshForVerify(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(3), hits.Load(), "a second rotation within the window must not be suppressed")
	require.NotEmpty(t, FindKeys(set, "c"), "emergency re-rotated key C must be pulled in immediately")
}

// TestJWKSCache_ForceRefreshForVerify_SuppressesWhenUnchanged verifies the DoS
// guard is preserved: when a forced refresh returns the SAME key set (no
// rotation), the sentinel is marked so a flood of bad-signature kid-less tokens
// within negativeKIDTTL reuses the cached set instead of forcing a fetch each.
func TestJWKSCache_ForceRefreshForVerify_SuppressesWhenUnchanged(t *testing.T) {
	t.Parallel()
	keyA := mustECDSAKey(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &keyA.PublicKey, KeyID: "a", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	now := time.Now()
	cache := NewJWKSCache(JWKSCacheConfig{
		JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour,
		Now: func() time.Time { return now },
	})

	_, err := cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	// First verify refresh: set unchanged, so it fetches once and marks the sentinel.
	_, err = cache.ForceRefreshForVerify(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(2), hits.Load())

	// A flood within the window is suppressed: no further fetches.
	for i := 0; i < 50; i++ {
		_, err = cache.ForceRefreshForVerify(context.Background())
		require.NoError(t, err)
	}
	require.Equal(t, int32(2), hits.Load(), "an unchanged-set flood must not amplify into one fetch per token")

	// After the TTL elapses, exactly one more fetch is allowed.
	now = now.Add(negativeKIDTTL + time.Second)
	_, err = cache.ForceRefreshForVerify(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(3), hits.Load(), "after the negative-cache TTL a verify refresh must be retried")
}

// TestJWKSCache_Refresh_DoubleCheckSkipsRedundantFetch pins: the non-forced
// TTL check runs outside the singleflight, so a goroutine can pass it while stale,
// and if a concurrent refresh makes the cache fresh before this goroutine enters
// the singleflight closure as a new leader, it would issue a redundant HTTP fetch.
// The closure now re-checks staleness under the lock and returns the freshly-cached
// set without a round-trip. The concurrent refresh is modeled with a clock that
// reports the cache as stale at the outer check and fresh at the inner check (i.e.
// the observed cache age dropped below the TTL because fetchedAt advanced).
func TestJWKSCache_Refresh_DoubleCheckSkipsRedundantFetch(t *testing.T) {
	key := mustECDSAKey(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "a", Use: "sig"}}})
	}))
	defer srv.Close()

	const ttl = 10 * time.Second
	base := time.Now()
	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: ttl})

	// Warm the cache with a real set whose fetch time is fixed an hour in the past.
	cache.mu.Lock()
	cache.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "a", Use: "sig"}}}
	cache.fetchedAt = base.Add(-time.Hour)
	cache.mu.Unlock()

	// now() is read once at the outer check and once at the inner double-check. With
	// fetchedAt fixed at base-1h: the outer read (base) makes the cache look an hour
	// old (stale); the inner read (base-1h+1s) makes it look one second old (fresh),
	// modeling a concurrent refresh that advanced fetchedAt while we waited.
	var calls atomic.Int32
	cache.now = func() time.Time {
		if calls.Add(1) == 1 {
			return base // outer check: stale
		}
		return base.Add(-time.Hour).Add(time.Second) // inner check: fresh
	}

	keys, _, err := cache.refresh(context.Background(), false)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(FindKeys(keys, "a")) == 0 {
		t.Fatal("expected the cached key set returned")
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("inner double-check should have skipped the fetch; got %d HTTP hits", got)
	}
}

// TestJWKSCache_SlowBackgroundRefreshDoesNotClobberForcedRotation is the
// regression: a non-forced (background) refresh that STARTED first but
// FINISHES last must not overwrite the newer key set installed by a forced
// rotation that started later. Forced and background refreshes use separate
// singleflight keys and run concurrently, so completion order is not start order;
// the fetch-generation guard ensures the older-started fetch's stale result is
// dropped at install time.
func TestJWKSCache_SlowBackgroundRefreshDoesNotClobberForcedRotation(t *testing.T) {
	t.Parallel()
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if hits.Add(1) == 1 {
			// First (background) fetch: serve the OLD set A, but hold the response
			// open until the forced rotation has installed set B.
			close(entered)
			<-release
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &keyA.PublicKey, KeyID: "kA", Use: "sig"}}})
			return
		}
		// Second (forced) fetch: serve the NEW set B immediately.
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &keyB.PublicKey, KeyID: "kB", Use: "sig"}}})
	}))
	defer srv.Close()

	cache := NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, Client: srv.Client(), CacheTTL: time.Hour})

	// Background refresh starts first (takes the earlier fetch generation) and
	// blocks mid-fetch.
	bgDone := make(chan error, 1)
	go func() {
		_, e := cache.Refresh(context.Background())
		bgDone <- e
	}()
	<-entered

	// Forced rotation starts later, fetches set B, and installs it (newer
	// generation).
	forced, _, err := cache.refresh(context.Background(), true)
	require.NoError(t, err)
	require.Equal(t, "kB", forced.Keys[0].KeyID, "forced refresh should fetch set B")

	// Release the slow background fetch; its older-generation result (set A) must
	// be discarded at install rather than clobbering set B.
	close(release)
	require.NoError(t, <-bgDone)

	keys, err := cache.GetKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys.Keys, 1)
	require.Equal(t, "kB", keys.Keys[0].KeyID,
		"the newer forced rotation (set B) must survive; the slower background fetch (set A) must not clobber it")
}
