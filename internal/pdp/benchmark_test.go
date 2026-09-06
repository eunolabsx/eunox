// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"

	"github.com/eunolabs/eunox/pkg/capability"
)

// BenchmarkJWTPDP measures JWTPDP overhead. ValidateToken runs on EVERY request through the
// HTTP transport, not once per session, so what it costs is the per-request figure:
//
//   - Decide_CachedClaims: claims already in context; measures constraint
//     building + condition evaluation only (no crypto).
//   - ValidateToken_Memoized / ValidateToken_Verified: the SAME call on either side of the
//     verified-token cache. The two differ by roughly the ECDSA P-256 verification plus the
//     payload decodes, which is the whole reason the cache exists — so a single figure
//     covering both measures neither. A benchmark reusing one token measures only the first,
//     which is how a cache-hit number came to be recorded as a signature-verification cost.
//   - ValidateToken_Refused_Memoized / ValidateToken_Refused_Verified: the same split for a
//     token the validator REFUSES for a reason no elapsed time can change (an IdP emitting
//     one mis-spelled watched claim). Before the refusal cache only the second existed, so a
//     single mis-minted claim template put a full verification on every request, fleet-wide.
//
// The _Verified arms disarm the caches rather than cycling more tokens than the caches hold: a
// cycle large enough to evict reliably would cost thousands of ECDSA signatures in the fixture
// alone. What that trades away is the Put a genuine miss also pays, so they measure the
// verification and not quite the whole miss. Each arm still cycles a modest set of distinct
// tokens, so no measurement is one token's bytes.
//
// Target: p99 < 3 ms added overhead (JWT PDP mode, JWKS cached).
func BenchmarkJWTPDP(b *testing.B) {
	b.Run("Decide_CachedClaims_Allow", func(b *testing.B) {

		fx := benchJWTPDPContext(b, nil)
		allowArgs := map[string]interface{}{"path": "/reports/q3.pdf"}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = fx.pdp.Decide(fx.ctx, "sess-bench", EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, allowArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_CachedClaims_Deny", func(b *testing.B) {
		fx := benchJWTPDPContext(b, nil)
		absentArgs := map[string]interface{}{}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = fx.pdp.Decide(fx.ctx, "sess-bench", EnforceTarget{Type: capability.TargetTypeTool, Name: "write_file"}, absentArgs, "127.0.0.1")
		}
	})

	// benchValidate cycles headers minted by this arm's OWN fixture — the tokens carry that
	// fixture's signature, so a shared header set would fail verification against another
	// PDP's key set and measure the wrong refusal.
	benchValidate := func(b *testing.B, arm benchValidateArm, cached bool) {
		fx := benchJWTPDPContext(b, nil)
		headers := arm.mint(fx)
		if !cached {
			fx.pdp.tokenCache, fx.pdp.refusalCache = nil, nil
		}
		baseCtx := context.Background()
		if cached {
			// Warm the arm so it measures hits from the first iteration rather than
			// amortizing len(headers) cold validations across b.N — and assert the warm-up
			// landed. Without that assertion an arm that stopped hitting its cache (a changed
			// key derivation, a category dropped from the memoizable table, a -benchtime past
			// the entry TTL) silently reports a full verification under a "Memoized" name,
			// which is the mislabelling this whole split exists to correct.
			for _, h := range headers {
				_, err := fx.pdp.ValidateToken(baseCtx, h)
				arm.check(b, err)
			}
			// At LEAST the warmed set: the fixture validates one token of its own on the way
			// in, which lands in the positive cache too.
			if n := arm.cache(fx).Len(); n < len(headers) {
				b.Fatalf("%s: cache holds %d of %d warmed tokens; this arm would measure misses", arm.name, n, len(headers))
			}
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := fx.pdp.ValidateToken(baseCtx, headers[i%len(headers)])
			if err != nil != arm.refused {
				b.Fatalf("%s: ValidateToken err = %v, refused = %v", arm.name, err, arm.refused)
			}
		}
	}

	for _, arm := range []benchValidateArm{
		{
			name:  "ValidateToken",
			mint:  benchJWTFixture.validHeaders,
			cache: func(fx benchJWTFixture) cacheLen { return fx.pdp.tokenCache },
		},
		{
			name:    "ValidateToken_Refused",
			mint:    benchJWTFixture.refusedHeaders,
			cache:   func(fx benchJWTFixture) cacheLen { return fx.pdp.refusalCache },
			refused: true,
			want:    jwtErrNonCanonicalClaim,
		},
	} {
		b.Run(arm.name+"_Memoized", func(b *testing.B) { benchValidate(b, arm, true) })
		b.Run(arm.name+"_Verified", func(b *testing.B) { benchValidate(b, arm, false) })
	}
}

// cacheLen is the one thing benchValidate asks of either token cache, so the two concrete
// PayloadCache instantiations can be named by one field.
type cacheLen interface{ Len() int }

// benchValidateArm is one side of the ValidateToken split: how its tokens are minted, which
// cache is supposed to hold them, and what ValidateToken must answer for them.
type benchValidateArm struct {
	name    string
	mint    func(benchJWTFixture) []string
	cache   func(benchJWTFixture) cacheLen
	refused bool
	want    string
}

// check fails the benchmark unless err is the verdict this arm is written around — the guard
// that keeps an arm from silently measuring the other path.
func (a benchValidateArm) check(b *testing.B, err error) {
	b.Helper()
	if !a.refused {
		if err != nil {
			b.Fatalf("%s: ValidateToken: %v", a.name, err)
		}
		return
	}
	if got := ClassifyJWTError(err); got != a.want {
		b.Fatalf("%s: category = %q, want %q (%v)", a.name, got, a.want, err)
	}
}

// benchDistinctTokens is how many distinct tokens each ValidateToken arm cycles. Enough that
// the measurement is not one token's bytes, small enough that the fixture's ECDSA signing
// stays a rounding error beside the run itself.
const benchDistinctTokens = 64

// BenchmarkListFilter measures the cost of filtering a tools/list response against a
// manifest — the work done on every tools/list passing through the proxy. Sized at 50
// upstream tools with a 25-entry allowlist (half permitted).
//
// The catalog carries a description and a populated inputSchema per entry, because that
// is what the path actually costs: the per-entry decode into toolListEntry deep-parses
// inputSchema, and it dominates every envelope-level pass. A catalog of bare
// mcp.ToolEntry{Name: ...} values measures almost none of the real work and made a
// whole-envelope decode on the unpinned path look free.
//
// The two sub-benchmarks split on the one thing that changes the shape of the path: an
// unpinned manifest skips pin-arming entirely, while a pinned one walks the catalog a
// second time to hash the pinned entries.
func BenchmarkListFilter(b *testing.B) {
	tools := benchToolCatalog(50)
	caps := make([]capability.Constraint, 25)
	for i := range caps {
		caps[i] = capability.Constraint{Target: fmt.Sprintf("tool:tool_%02d", i), Actions: []string{"call"}}
	}
	raw, err := json.Marshal(mcp.ToolsListResult{Tools: tools})
	if err != nil {
		b.Fatalf("marshal catalog: %v", err)
	}

	b.Run("Unpinned", func(b *testing.B) {
		mpdp := newTestManifestPDP(caps...)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = filterToolsListResult(raw, mpdp, nil, "", true)
		}
	})

	b.Run("Pinned", func(b *testing.B) {
		pinned := make([]capability.Constraint, len(caps))
		copy(pinned, caps)
		// One pin is enough to arm the whole pass: the gate is len(pinnedTools) > 0.
		pinned[0].DescriptionHash = "sha256:" + strings.Repeat("00", 32)
		mpdp := newTestManifestPDP(pinned...)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = filterToolsListResult(raw, mpdp, nil, "", true)
		}
	})
}

// benchToolCatalog builds n tools shaped like a real upstream catalog: a prose
// description plus an 8-property inputSchema carrying enums, so the per-entry decode
// the filter path performs is measured rather than skipped.
func benchToolCatalog(n int) []mcp.ToolEntry {
	tools := make([]mcp.ToolEntry, n)
	for i := range tools {
		props := make(map[string]interface{}, 8)
		for p := 0; p < 8; p++ {
			props[fmt.Sprintf("param_%d", p)] = map[string]interface{}{
				"type":        "string",
				"description": fmt.Sprintf("The %d%s parameter, supplied by the caller and validated upstream.", p, "th"),
				"enum":        []string{"alpha", "beta", "gamma", "delta"},
			}
		}
		tools[i] = mcp.ToolEntry{
			Name:        fmt.Sprintf("tool_%02d", i),
			Description: "Performs a bounded operation against the upstream service and returns a structured result. Arguments are validated before dispatch.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": props,
				"required":   []string{"param_0", "param_1"},
			},
		}
	}
	return tools
}

// benchJWTFixture is a JWTPDP backed by an in-process JWKS server, together with the signer
// that minted its tokens — so an arm can mint MORE of them (distinct valid tokens, or a
// payload the validator refuses) under the same key rather than validating one token's bytes
// forever.
type benchJWTFixture struct {
	// tb is held so a mint helper shared with the tests can report through the benchmark.
	tb  testing.TB
	pdp *JWTPDP
	// ctx carries the claims of an already-validated token, for the Decide arms.
	ctx context.Context
	// sign serializes exactly the claim members it is handed and returns the Authorization
	// header value.
	sign func(claims map[string]interface{}) string
}

// validHeaders mints benchDistinctTokens tokens the validator ACCEPTS. Distinct by `sub`, which is
// carried into the claims every arm below reads, so the tokens differ in payload bytes and
// therefore in cache key.
func (f benchJWTFixture) validHeaders() []string {
	out := make([]string, benchDistinctTokens)
	for i := range out {
		out[i] = f.sign(benchTokenClaims(fmt.Sprintf("bench-agent-%d", i)))
	}
	return out
}

// refusedHeaders mints benchDistinctTokens tokens the validator REFUSES for a reason no elapsed time
// can change: the `mcp` claim spelled a way no decoder on this path binds, which is refused
// only after the signature has verified. The shape a claim template with one mis-cased entry
// produces for every token an IdP mints.
func (f benchJWTFixture) refusedHeaders() []string {
	out := make([]string, benchDistinctTokens)
	for i := range out {
		out[i] = f.sign(misspellMCPClaim(f.tb, benchTokenClaims(fmt.Sprintf("bench-agent-%d", i))))
	}
	return out
}

// benchTokenClaims is the payload the fixture's tokens carry, spelled as the claim members
// themselves rather than through the struct types: the refused arm has to write a member name
// no struct tag can express. Valid v0.2 shorthand capabilities, so ValidateToken accepts it.
func benchTokenClaims(sub string) map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"mcp": map[string]interface{}{
			"v":            mcpClaimVersion,
			"capabilities": []string{"tool:read_file?path=/reports/*", "tool:query_db?op=SELECT"},
			"agent_id":     sub,
			"task_id":      "bench-task",
		},
		"iss": "https://idp.bench",
		"sub": sub,
		"aud": []string{"eunox"},
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

// benchJWTPDPContext builds the fixture, warming its JWKS cache with one validated token.
//
// It stays a package-pdp helper rather than merging with the same-named one in
// internal/transport because the arms above reach what only this package can: mcpClaimVersion,
// and the unexported cache fields a _Verified arm disarms.
func benchJWTPDPContext(b *testing.B, inner PolicyDecisionPoint) benchJWTFixture {
	b.Helper()

	key := newTestKey(b, "bench-k1")
	jwksSrv := makeJWKSServer(b, key)
	b.Cleanup(jwksSrv.Close)

	jwtPDP := NewJWTPDP(JWTPDPOptions{
		JWKSURI:                  jwksSrv.URL + "/",
		Issuer:                   "https://idp.bench",
		Audience:                 "eunox",
		Inner:                    inner,
		CacheTTL:                 5 * time.Minute,
		ExperimentalCapabilities: true,
	})
	sign := func(claims map[string]interface{}) string {
		return "Bearer " + signClaimsMapToken(b, key, claims)
	}

	// Warm the JWKS cache and get a pre-populated context.
	ctx, err := jwtPDP.ValidateToken(context.Background(), sign(benchTokenClaims("bench-agent")))
	if err != nil {
		b.Fatalf("ValidateToken warmup: %v", err)
	}

	return benchJWTFixture{tb: b, pdp: jwtPDP, ctx: ctx, sign: sign}
}
