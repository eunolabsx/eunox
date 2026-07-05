// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// BenchmarkJWTPDP measures JWTPDP overhead in two sub-scenarios:
//
//   - Decide_CachedClaims: claims already in context; measures constraint
//     building + condition evaluation only (no crypto).
//   - ValidateToken_CachedJWKS: full JWT validation including ECDSA P-256
//     signature verification; JWKS is cached so no network I/O.
//
// Target: p99 < 3 ms added overhead (JWT PDP mode, JWKS cached).
func BenchmarkJWTPDP(b *testing.B) {
	b.Run("Decide_CachedClaims_Allow", func(b *testing.B) {

		jwtPDP, ctx, _ := benchJWTPDPContext(b, nil)
		allowArgs := map[string]interface{}{"path": "/reports/q3.pdf"}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = jwtPDP.Decide(ctx, "sess-bench", EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, allowArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_CachedClaims_Deny", func(b *testing.B) {
		jwtPDP, ctx, _ := benchJWTPDPContext(b, nil)
		absentArgs := map[string]interface{}{}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = jwtPDP.Decide(ctx, "sess-bench", EnforceTarget{Type: capability.TargetTypeTool, Name: "write_file"}, absentArgs, "127.0.0.1")
		}
	})

	b.Run("ValidateToken_CachedJWKS", func(b *testing.B) {

		jwtPDP, _, token := benchJWTPDPContext(b, nil)
		baseCtx := context.Background()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = jwtPDP.ValidateToken(baseCtx, token)
		}
	})
}

// BenchmarkListFilter measures the cost of filtering a tools/list response
// against a manifest — the work done on every tools/list passing through the
// proxy. Sized at 50 upstream tools with a 25-entry allowlist (half permitted).
func BenchmarkListFilter(b *testing.B) {
	caps := make([]capability.Constraint, 25)
	tools := make([]mcp.ToolEntry, 50)
	for i := range tools {
		tools[i] = mcp.ToolEntry{Name: fmt.Sprintf("tool_%02d", i)}
	}
	for i := range caps {
		caps[i] = capability.Constraint{Target: fmt.Sprintf("tool:tool_%02d", i), Actions: []string{"call"}}
	}
	mpdp := newTestManifestPDP(caps...)
	raw, _ := json.Marshal(mcp.ToolsListResult{Tools: tools})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = filterToolsListResult(raw, mpdp, nil)
	}
}

// benchJWTPDPContext builds a JWTPDP backed by an in-process JWKS server, mints a
// valid v0.2 token, warms the cache, and returns the PDP, a claims-populated
// context, and the bearer header. It is a package-pdp copy of the same-named
// helper in cmd/eunox (which backs the transport benchmark); the copies are
// independent because this one builds the claim block with the package-private
// claim types, which the main-package helper cannot reach.
func benchJWTPDPContext(b *testing.B, inner PolicyDecisionPoint) (*JWTPDP, context.Context, string) {
	b.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("generate ECDSA key: %v", err)
	}
	const kid = "bench-k1"

	jwksSet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: priv.Public(), KeyID: kid, Use: "sig"},
	}}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksSet)
	}))
	b.Cleanup(jwksSrv.Close)

	jwtPDP := NewJWTPDP(JWTPDPOptions{
		JWKSURI:                  jwksSrv.URL + "/",
		Issuer:                   "https://idp.bench",
		Audience:                 "eunox",
		Inner:                    inner,
		CacheTTL:                 5 * time.Minute,
		ExperimentalCapabilities: true,
	})

	// Mint a token valid for the benchmark run.
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		b.Fatalf("new signer: %v", err)
	}
	stdClaims := josejwt.Claims{
		Issuer:   "https://idp.bench",
		Subject:  "bench-agent",
		Audience: josejwt.Audience{"eunox"},
		IssuedAt: josejwt.NewNumericDate(time.Now()),
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	// Use valid v0.2 shorthand (namespace-prefixed) so ValidateToken accepts them.
	benchCaps := []string{"tool:read_file?path=/reports/*", "tool:query_db?op=SELECT"}
	payload := idpJWTPayload{
		MCP: mcpClaimSet{
			Version:      mcpClaimVersion,
			Capabilities: &benchCaps,
			AgentID:      "bench-agent",
			TaskID:       "bench-task",
		},
	}
	token, err := josejwt.Signed(sig).Claims(stdClaims).Claims(payload).Serialize()
	if err != nil {
		b.Fatalf("sign bench token: %v", err)
	}

	// Warm the JWKS cache and get a pre-populated context.
	ctx, err := jwtPDP.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		b.Fatalf("ValidateToken warmup: %v", err)
	}

	return jwtPDP, ctx, "Bearer " + token
}
