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
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCandidateKIDs covers the shared kid-extraction helper that both the
// capability-token and IdP-JWT paths use: distinct first-seen ordering, the
// requireKID policy (drop the "" try-all sentinel, require at least one explicit
// kid), and the empty-header error. jwt.ParseSigned is compact-only so a parsed
// token yields a single header in practice, but the helper's contract is exercised
// directly here so the multi-header guard cannot silently regress.
func TestCandidateKIDs(t *testing.T) {
	hdr := func(kids ...string) []jose.Header {
		h := make([]jose.Header, len(kids))
		for i, k := range kids {
			h[i] = jose.Header{KeyID: k}
		}
		return h
	}
	cases := []struct {
		name       string
		headers    []jose.Header
		requireKID bool
		want       []string
		wantErr    bool
	}{
		{"single kid", hdr("k1"), false, []string{"k1"}, false},
		{"distinct ordered", hdr("a", "b"), false, []string{"a", "b"}, false},
		{"dedup", hdr("a", "a", "b"), false, []string{"a", "b"}, false},
		{"empty kid preserved without requireKID", hdr(""), false, []string{""}, false},
		{"valid kid after empty without requireKID", hdr("", "valid"), false, []string{"", "valid"}, false},
		{"requireKID drops empty, keeps explicit", hdr("", "valid"), true, []string{"valid"}, false},
		{"requireKID all empty errors", hdr("", ""), true, nil, true},
		{"no headers errors", nil, false, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CandidateKIDs(tc.headers, tc.requireKID)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestVerifyWithKeyRotation_Contract pins the contract of the shared
// VerifyWithKeyRotation skeleton directly, with a fake per-key verifier, so the
// terminal-vs-retryable distinction and the single forced-refresh retry are
// guarded independently of the two real callers (VerifyToken / ValidateToken).
// The fake verifier scripts results by KeyID and ignores the crypto, so no real
// signatures are needed — this exercises the choreography, not jose.
func TestVerifyWithKeyRotation_Contract(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	newCache := func(t *testing.T, handler http.HandlerFunc) *JWKSCache {
		t.Helper()
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		return NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, CacheTTL: time.Hour, Client: srv.Client()})
	}
	writeKey := func(w http.ResponseWriter, pub interface{}, kid string) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Use: "sig"}}})
	}

	t.Run("terminal failure is surfaced as-is and not retried", func(t *testing.T) {
		var fetches atomic.Int32
		cache := newCache(t, func(w http.ResponseWriter, _ *http.Request) {
			fetches.Add(1)
			writeKey(w, keyA.Public(), "k")
		})
		sentinel := errors.New("claims invalid")
		calls := 0
		got, err := VerifyWithKeyRotation[string](context.Background(), cache, "k", func(_ *jose.JSONWebKey, _ bool) (*string, error) {
			calls++
			return nil, Terminal(sentinel)
		})
		require.Nil(t, got)
		require.ErrorIs(t, err, sentinel) // surfaced as-is, unwrapped from the Terminal marker
		require.Equal(t, 1, calls)        // never retried against a refreshed key set
		// Only the initial GetKeys fetch; a terminal failure must not force a refresh.
		require.Equal(t, int32(1), fetches.Load())
	})

	t.Run("signature failure retries exactly once against a refreshed key set", func(t *testing.T) {
		var fetches atomic.Int32
		cache := newCache(t, func(w http.ResponseWriter, _ *http.Request) {
			// First fetch serves keyA (rejected); the forced refresh serves keyB (accepted).
			if fetches.Add(1) >= 2 {
				writeKey(w, keyB.Public(), "B")
				return
			}
			writeKey(w, keyA.Public(), "A")
		})
		var seen []string
		got, err := VerifyWithKeyRotation[string](context.Background(), cache, "", func(key *jose.JSONWebKey, _ bool) (*string, error) {
			seen = append(seen, key.KeyID)
			if key.KeyID == "B" {
				s := "ok"
				return &s, nil
			}
			return nil, fmt.Errorf("bad signature for %s", key.KeyID) // plain -> retryable
		})
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, "ok", *got)
		require.Equal(t, []string{"A", "B"}, seen) // keyA failed, keyB (refreshed) succeeded
		require.Equal(t, int32(2), fetches.Load()) // initial fetch + exactly one forced refresh
	})

	t.Run("unchanged refreshed set is not re-verified", func(t *testing.T) {
		var fetches atomic.Int32
		cache := newCache(t, func(w http.ResponseWriter, _ *http.Request) {
			// Every fetch serves the identical keyA: the forced refresh returns exactly
			// the keys already tried, so the rotation the retry exists to catch did not
			// happen.
			fetches.Add(1)
			writeKey(w, keyA.Public(), "A")
		})
		var calls int
		got, err := VerifyWithKeyRotation[string](context.Background(), cache, "", func(_ *jose.JSONWebKey, _ bool) (*string, error) {
			calls++
			return nil, fmt.Errorf("bad signature") // plain -> retryable
		})
		require.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verify signature", "an exhausted unchanged set is a signature failure, not a refresh failure")
		// The forced refresh still fires (a rotation MIGHT have happened), but because it
		// returned the identical key set, the per-key verifier is NOT run a second time:
		// re-verifying the same key against the same token can only burn CPU. One verify
		// call, not two.
		require.Equal(t, 1, calls, "an unchanged refreshed set must not be re-verified (2x CPU amplification)")
		require.Equal(t, int32(2), fetches.Load(), "the forced refresh still runs; only the pointless re-verify is skipped")
	})

	t.Run("cached-key signature failure is not masked as an outage when the refresh also fails", func(t *testing.T) {
		var fetches atomic.Int32
		cache := newCache(t, func(w http.ResponseWriter, _ *http.Request) {
			if fetches.Add(1) >= 2 {
				http.Error(w, "jwks down", http.StatusServiceUnavailable)
				return
			}
			writeKey(w, keyA.Public(), "A")
		})
		got, err := VerifyWithKeyRotation[string](context.Background(), cache, "", func(_ *jose.JSONWebKey, _ bool) (*string, error) {
			return nil, errors.New("bad signature") // plain -> retryable, exhausts the cached set
		})
		require.Nil(t, got)
		require.Error(t, err)
		// The token WAS checked against a key we held (the cached set) and failed, so this
		// is a signature failure, not a "never checked against a key" outage. The failed
		// rotation refresh is only best-effort context: it must NOT wrap ErrJWKSUnavailable,
		// or the audit layer would record a forged token presented during a JWKS blip as an
		// infrastructure outage and hide it from a SIEM keyed on invalid_signature.
		assert.Contains(t, err.Error(), "verify signature", "a failed signature against a cached key stays a signature failure")
		assert.False(t, errors.Is(err, ErrJWKSUnavailable), "the failed rotation refresh must not mask the signature failure as a JWKS outage")
	})

	t.Run("a verifier returning neither result nor error fails closed", func(t *testing.T) {
		cache := newCache(t, func(w http.ResponseWriter, _ *http.Request) {
			writeKey(w, keyA.Public(), "k")
		})
		got, err := VerifyWithKeyRotation[string](context.Background(), cache, "k", func(_ *jose.JSONWebKey, _ bool) (*string, error) {
			return nil, nil // contract violation: neither a result nor an error
		})
		require.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "neither a result nor an error")
	})
}

// TestVerifyWithKeyRotationMultiKID pins the kid fan-out wrapper's contract directly:
// the empty-candidate guard (fail closed, verifier never run), single-kid success,
// the multi-header fan-out (a kid with no matching key is skipped and a later kid
// succeeds), and the all-fail surface (a non-nil error, never (nil, nil)). The
// fan-out is unreachable today — jwt.ParseSigned is compact-only, so a parsed token
// carries exactly one header — but VerifyWithKeyRotationMultiKID is exported API on
// the verification path, so its contract is locked here against a silent regression.
func TestVerifyWithKeyRotationMultiKID(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// serveKeys returns a cache backed by a JWKS endpoint serving exactly the given keys.
	serveKeys := func(t *testing.T, keys ...jose.JSONWebKey) *JWKSCache {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(&jose.JSONWebKeySet{Keys: keys})
		}))
		t.Cleanup(srv.Close)
		return NewJWKSCache(JWKSCacheConfig{JWKSURL: srv.URL, CacheTTL: time.Hour, Client: srv.Client()})
	}
	sigKey := func(pub interface{}, kid string) jose.JSONWebKey {
		return jose.JSONWebKey{Key: pub, KeyID: kid, Use: "sig"}
	}

	t.Run("empty kids fails closed without calling the verifier", func(t *testing.T) {
		cache := serveKeys(t, sigKey(keyA.Public(), "A"))
		got, err := VerifyWithKeyRotationMultiKID[string](context.Background(), cache, nil, func(*jose.JSONWebKey, bool) (*string, error) {
			t.Fatal("verifier must not run when there are no candidate kids")
			return nil, nil
		})
		require.Nil(t, got)
		require.Error(t, err)
	})

	t.Run("single kid success", func(t *testing.T) {
		cache := serveKeys(t, sigKey(keyA.Public(), "A"))
		got, err := VerifyWithKeyRotationMultiKID[string](context.Background(), cache, []string{"A"}, func(*jose.JSONWebKey, bool) (*string, error) {
			s := "ok"
			return &s, nil
		})
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, "ok", *got)
	})

	t.Run("fan-out: a kid with no matching key is skipped, a later kid succeeds", func(t *testing.T) {
		cache := serveKeys(t, sigKey(keyB.Public(), "B"))
		var seen []string
		got, err := VerifyWithKeyRotationMultiKID[string](context.Background(), cache, []string{"A", "B"}, func(key *jose.JSONWebKey, _ bool) (*string, error) {
			seen = append(seen, key.KeyID)
			s := "ok"
			return &s, nil
		})
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, "ok", *got)
		require.Equal(t, []string{"B"}, seen) // kid "A" matched no key, so the verifier ran only for "B"
	})

	t.Run("all kids fail surfaces a non-nil error (fail closed)", func(t *testing.T) {
		cache := serveKeys(t, sigKey(keyA.Public(), "A"))
		got, err := VerifyWithKeyRotationMultiKID[string](context.Background(), cache, []string{"X", "Y"}, func(*jose.JSONWebKey, bool) (*string, error) {
			t.Fatal("no candidate kid matches a served key, so the verifier must never run")
			return nil, nil
		})
		require.Nil(t, got)
		require.Error(t, err)
	})
}

// TestFindKeys_KidlessReturnsCopy pins that the kid-less branch of FindKeys returns
// a fresh copy, not a live alias into the cached *JSONWebKeySet. The cache serves the
// same set to every concurrent verification, so a caller mutating the returned slice
// must not corrupt the shared root-of-trust set.
func TestFindKeys_KidlessReturnsCopy(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: keyA.Public(), KeyID: "a", Use: "sig"},
		{Key: keyB.Public(), KeyID: "b", Use: "sig"},
	}}

	got := FindKeys(set, "") // kid-less: all keys
	require.Len(t, got, 2)

	// Reorder/overwrite and append on the returned slice must not touch the cache.
	got[0] = jose.JSONWebKey{KeyID: "tampered"}
	_ = append(got, jose.JSONWebKey{KeyID: "injected"}) //nolint:staticcheck // intentional: prove the append cannot reach set.Keys

	require.Len(t, set.Keys, 2, "append/overwrite of the returned slice leaked into the cached set")
	assert.Equal(t, "a", set.Keys[0].KeyID, "overwrite of the returned slice leaked into the cached set")
	assert.Equal(t, "b", set.Keys[1].KeyID)

	again := FindKeys(set, "")
	require.Len(t, again, 2)
	assert.Equal(t, "a", again[0].KeyID, "a later call must still see the original keys")
}
