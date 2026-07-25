// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestJWKSCache_CrossHostRedirectRefusedWithCallerSuppliedClient pins the floor that must
// hold no matter which HTTP client the consumer injects.
//
// The redirect refusal installed by NewJWKSCache applies only to the DEFAULT client, so a
// consumer supplying its own *http.Client — the natural way to set a proxy, a custom
// transport, or a different timeout — silently got Go's default redirect-following back.
// An IdP open redirect (a far more common vulnerability than key-file injection) could then
// serve an attacker key set over valid TLS and forge every token the proxy accepts. The
// same-origin check therefore lives on the RESPONSE, where no client can weaken it.
func TestJWKSCache_CrossHostRedirectRefusedWithCallerSuppliedClient(t *testing.T) {
	t.Parallel()

	const attackerKeys = `{"keys":[{"kty":"oct","kid":"attacker","k":"AAAA"}]}`
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(attackerKeys))
	}))
	defer attacker.Close()

	// The "IdP": answers the JWKS path with a 302 to the attacker host.
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://attacker.example.com/keys", http.StatusFound)
	}))
	defer idp.Close()

	// Both servers listen on loopback, and a loopback->loopback hop is deliberately
	// exempt (it never leaves the machine). Give them distinct NON-loopback names so the
	// hop under test is the cross-host one the check exists for.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: hostRewritingTransport(map[string]string{
			"idp.example.com":      strings.TrimPrefix(idp.URL, "http://"),
			"attacker.example.com": strings.TrimPrefix(attacker.URL, "http://"),
		}),
	}

	// A caller-supplied client with Go's DEFAULT redirect policy — i.e. it follows.
	c := NewJWKSCache(JWKSCacheConfig{
		JWKSURL: "http://idp.example.com/.well-known/jwks.json",
		Client:  client,
	})

	_, err := c.fetchKeys(context.Background())
	if err == nil {
		t.Fatal("a cross-host JWKS redirect must fail closed even when the caller supplies its own client")
	}
	if !strings.Contains(err.Error(), "not the configured JWKS host") {
		t.Fatalf("error should name the origin mismatch, got: %v", err)
	}
}

// hostRewritingTransport returns a Transport that dials the mapped test-server address for
// each fake hostname, so a test can exercise real redirect following between two hosts that
// are not both loopback (which the same-origin check deliberately exempts).
func hostRewritingTransport(hosts map[string]string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			target, ok := hosts[host]
			if !ok {
				return nil, &net.AddrError{Err: "no test server mapped", Addr: addr}
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
}

// TestJWKSCache_SameHostRedirectAllowed is the negative control: an IdP relocating its key
// set within its OWN host is legitimate, so path changes must still work.
func TestJWKSCache_SameHostRedirectAllowed(t *testing.T) {
	t.Parallel()

	const keys = `{"keys":[{"kty":"oct","kid":"real","k":"AAAA"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" {
			http.Redirect(w, r, "http://idp.example.com/keys", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(keys))
	}))
	defer srv.Close()

	c := NewJWKSCache(JWKSCacheConfig{
		JWKSURL: "http://idp.example.com/.well-known/jwks.json",
		Client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: hostRewritingTransport(map[string]string{"idp.example.com": strings.TrimPrefix(srv.URL, "http://")}),
		},
	})
	set, err := c.fetchKeys(context.Background())
	if err != nil {
		t.Fatalf("a same-host redirect must be followed: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "real" {
		t.Fatalf("expected the real key set, got %+v", set.Keys)
	}
}

// TestRedactURLForLog_StripsEveryCredentialBearingComponent pins that the log-safe redactor
// leaks neither the secret nor its length, on both the parseable and unparseable paths.
func TestRedactURLForLog_StripsEveryCredentialBearingComponent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, in string
		mustNot  []string
	}{
		{"userinfo and query", "https://svc:s3cr3t@idp.internal/keys?api_key=AKIA123", []string{"s3cr3t", "AKIA123", "api_key"}},
		{"query only", "https://idp.internal/keys?token=abcdef", []string{"abcdef", "token"}},
		{"fragment", "https://idp.internal/keys#frag-secret", []string{"frag-secret"}},
		{"unparseable with credentials", "ht tp://svc:s3cr3t@idp.internal/keys?api_key=AKIA123", []string{"s3cr3t", "AKIA123"}},
		{"opaque", "mailto:svc:s3cr3t@example.com", []string{"s3cr3t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := RedactURLForLog(tc.in)
			for _, bad := range tc.mustNot {
				if strings.Contains(got, bad) {
					t.Errorf("RedactURLForLog(%q) = %q, must not contain %q", tc.in, got, bad)
				}
			}
		})
	}
	// The host and path are operational context an operator needs, so they survive.
	if got := RedactURLForLog("https://svc:pw@idp.internal:8443/keys?k=v"); got != "https://idp.internal:8443/keys" {
		t.Errorf("host and path must survive redaction; got %q", got)
	}
}
