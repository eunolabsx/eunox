// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestClassifyJWTError_JWKSUnavailable pins that a JWKS-infrastructure outage is
// classified as jwks_unavailable, not "invalid": a valid token presented while the
// key endpoint is down was never checked against a key, so recording it identically
// to a forged token would poison the fail-closed audit trail. Each sub-test drives a
// different fetch-failure origin through ValidateToken and asserts the category.
func TestClassifyJWTError_JWKSUnavailable(t *testing.T) {
	key := newTestKey(t, "c-unavail")
	const iss = "https://idp.example"
	const aud = "svc-test"
	authHeader := "Bearer " + makeIDPToken(t, key, nil, iss, aud, "user-1", time.Now().Add(time.Hour))

	newPDP := func(url string) *JWTPDP {
		return NewJWTPDP(JWTPDPOptions{
			JWKSURI:  url + "/",
			Issuer:   iss,
			Audience: aud,
			CacheTTL: 5 * time.Second,
		})
	}

	assertUnavailable := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected ValidateToken to fail during a JWKS outage, got nil")
		}
		if got := ClassifyJWTError(err); got != jwtErrJWKSUnavailable {
			t.Errorf("ClassifyJWTError(%v) = %q, want %q", err, got, jwtErrJWKSUnavailable)
		}
	}

	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		_, err := newPDP(srv.URL).ValidateToken(context.Background(), authHeader)
		assertUnavailable(t, err)
	})

	t.Run("empty key set", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}))
		defer srv.Close()
		_, err := newPDP(srv.URL).ValidateToken(context.Background(), authHeader)
		assertUnavailable(t, err)
	})

	t.Run("network error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		url := srv.URL
		srv.Close() // closed before the fetch → connection error
		_, err := newPDP(url).ValidateToken(context.Background(), authHeader)
		assertUnavailable(t, err)
	})

	// Negative control: a healthy JWKS with a signature mismatch still classifies as
	// invalid_signature, so the new category does not swallow genuine token failures.
	t.Run("signature failure stays invalid_signature", func(t *testing.T) {
		srv := makeJWKSServer(t, key)
		defer srv.Close()
		otherKey := newTestKey(t, "c-unavail") // same kid, different key
		bad := "Bearer " + makeIDPToken(t, otherKey, nil, iss, aud, "user-1", time.Now().Add(time.Hour))
		_, err := newPDP(srv.URL).ValidateToken(context.Background(), bad)
		if err == nil {
			t.Fatal("expected a signature failure")
		}
		if got := ClassifyJWTError(err); got != jwtErrSignature {
			t.Errorf("ClassifyJWTError = %q, want %q", got, jwtErrSignature)
		}
	})
}

// TestParseV2Claim_MalformedTargetGlobRejected pins that a malformed target-name glob
// is rejected at token validation, mirroring the manifest loader
// (enforcement.ValidateResourcePattern). Without it the claim passes, then path.Match
// swallows the ErrBadPattern to a silent non-match at enforce time — an inert grant
// that surfaces only as an opaque AUTHORIZATION_FAILED, indistinguishable from a
// target the token never listed.
func TestParseV2Claim_MalformedTargetGlobRejected(t *testing.T) {
	for _, tc := range []struct{ name, claim string }{
		{"tool unclosed class", "tool:read_[file"},
		{"prompt unclosed class", "prompt:re[view"},
		{"non-http resource unclosed class", "resource:file:///data[/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := parseV2Claim(tc.claim); err == nil {
				t.Fatalf("parseV2Claim(%q) = nil error, want rejection of the malformed target glob", tc.claim)
			} else if !strings.Contains(err.Error(), "invalid target pattern") {
				t.Errorf("error = %q, want it to name the invalid target pattern", err.Error())
			}
		})
	}

	// The http(s)-resource query is compared LITERALLY, not globbed (see matchClaimBare),
	// so a '[' in the query must NOT be rejected as a bad glob — only the path before
	// '?' is validated. These must parse cleanly.
	for _, claim := range []string{
		"resource:https://api.example.com/data?filter[]=x",
		"resource:http://up/search?q=a[b",
	} {
		if _, _, _, err := parseV2Claim(claim); err != nil {
			t.Errorf("parseV2Claim(%q) = %v, want the literal-query '[' accepted (the query is not a glob)", claim, err)
		}
	}

	// Valid target globs (the common case) still parse.
	for _, claim := range []string{
		"tool:read_*", "tool:read_file", "resource:file:///data/*", "prompt:code_review",
		"resource:https://api.example.com/data?q=1",
	} {
		if _, _, _, err := parseV2Claim(claim); err != nil {
			t.Errorf("parseV2Claim(%q) = %v, want a valid target glob to parse", claim, err)
		}
	}
}

// TestNormalizeAudience pins that only a whitespace-only audience collapses to "",
// while a real audience (including one with surrounding spaces) is left unchanged.
func TestNormalizeAudience(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"\t\n", ""},
		{"svc-a", "svc-a"},
		{" svc-a ", " svc-a "}, // non-empty after trim → unchanged
	} {
		if got := normalizeAudience(tc.in); got != tc.want {
			t.Errorf("normalizeAudience(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSanitizeAudiences pins that empty and whitespace-only entries are dropped while
// real audiences are preserved in order and byte-for-byte.
func TestSanitizeAudiences(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"all empty", []string{"", "  ", "\t"}, []string{}},
		{"mixed", []string{"", "svc-a", "  ", "svc-b"}, []string{"svc-a", "svc-b"}},
		{"clean", []string{"svc-a", "svc-b"}, []string{"svc-a", "svc-b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeAudiences(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("sanitizeAudiences(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("sanitizeAudiences(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestJWTPDP_EmptyAcceptedAudienceRejectsEmptyAud is the finding-E regression: a
// JWTPDP built (via the exported options) with an accepted-audience list holding only
// an empty entry must NOT admit a token whose own aud is the literal empty string.
// go-jose matches audiences by set intersection, so an expected AnyAudience of [""]
// would otherwise ACCEPT an aud:"" token; sanitizeAudiences drops the empty entry,
// leaving no pinned audience, so validation fails closed. A whitespace entry alongside
// a real one is likewise dropped without disturbing the real audience.
func TestJWTPDP_EmptyAcceptedAudienceRejectsEmptyAud(t *testing.T) {
	key := newTestKey(t, "e-aud")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	const iss = "https://idp.example"
	future := time.Now().Add(time.Hour)

	t.Run("empty-only accepted list rejects aud empty-string", func(t *testing.T) {
		emptyAudToken := "Bearer " + makeIDPToken(t, key, nil, iss, "", "user-1", future)
		p := NewJWTPDP(JWTPDPOptions{
			JWKSURI:           srv.URL + "/",
			AllowAnyIssuer:    true,
			AcceptedAudiences: []string{""}, // the only "pin" — must be dropped, not honored
			CacheTTL:          5 * time.Second,
		})
		if _, err := p.ValidateToken(context.Background(), emptyAudToken); err == nil {
			t.Fatal("a token with aud:\"\" must be rejected when the only accepted audience is empty (fail closed)")
		} else if got := ClassifyJWTError(err); got != jwtErrInvalidAudience {
			t.Errorf("ClassifyJWTError = %q, want %q", got, jwtErrInvalidAudience)
		}
	})

	t.Run("whitespace entry dropped, real audience still accepted", func(t *testing.T) {
		realToken := "Bearer " + makeIDPToken(t, key, nil, iss, "svc-a", "user-1", future)
		p := NewJWTPDP(JWTPDPOptions{
			JWKSURI:           srv.URL + "/",
			AllowAnyIssuer:    true,
			AcceptedAudiences: []string{"  ", "svc-a"},
			CacheTTL:          5 * time.Second,
		})
		if _, err := p.ValidateToken(context.Background(), realToken); err != nil {
			t.Fatalf("a token for the real audience must still validate: %v", err)
		}
	})
}
