// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// settableClock is an enforcement.Clock a test can advance. fixedClock cannot move, and the
// two properties below are about what happens as time passes with the token bytes unchanged.
// Guarded because the JWKS cache reads the same clock from its own goroutines.
type settableClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *settableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *settableClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// misspelledClaimToken is the shape the refusal cache exists for: a signed, unexpired,
// otherwise-valid token whose `mcp` claim is spelled a way no decoder on this path binds, so
// every request carrying it is refused after a full ECDSA verification. Its refusal is
// reached before validateStandardClaims, so it carries no exp for the entry to be capped at.
func misspelledClaimToken(t *testing.T, key testKey) string {
	t.Helper()
	claims := liveTokenClaims()
	delete(claims, topLevelClaimMCP)
	claims["Mcp"] = map[string]interface{}{"v": mcpClaimVersion}
	return signClaimsMapToken(t, key, claims)
}

// TestJWTRefusalMemoization_EveryCategoryDeclaresOne derives the category set from jwt.go's
// own constants rather than from a list written beside the table, so a category added without
// a memoization verdict fails the build instead of inheriting the map's zero value silently.
// Absence IS the fail-closed answer, which is exactly why it must not be reachable by
// forgetting: the omission would look identical to a deliberate "not memoizable" until the
// day a genuinely replayable refusal started re-running a verify per request.
func TestJWTRefusalMemoization_EveryCategoryDeclaresOne(t *testing.T) {
	t.Parallel()
	file, err := parser.ParseFile(token.NewFileSet(), "jwt.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing the validator's source: %v", err)
	}
	declared := make(map[string]bool, len(memoizableJWTRefusals))
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "jwtErr") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				code, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					t.Fatalf("%s: unquoting %s: %v", name.Name, lit.Value, uerr)
				}
				declared[code] = true
				if _, covered := memoizableJWTRefusals[code]; !covered {
					t.Errorf("%s (%q) has no row in memoizableJWTRefusals: an undeclared category reads as not memoizable, which is indistinguishable from having decided that", name.Name, code)
				}
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("no jwtErr* category constants found: the walk has stopped seeing the declarations it derives from")
	}
	for code := range memoizableJWTRefusals {
		if !declared[code] {
			t.Errorf("memoizableJWTRefusals declares %q, which no jwtErr* constant spells: a row no refusal can carry answers nothing", code)
		}
	}
}

// TestValidateToken_MemoizesTheClaimSpellingRefusal is the issue's own case: an IdP emitting
// one mis-spelled watched claim moved a whole class of tokens onto the uncached path, where
// each request re-ran ParseSigned plus the ECDSA verify plus both payload decodes. The
// assertion is IDENTITY of the returned error, not merely its category — only a replayed
// entry can hand back the same value the first refusal produced.
func TestValidateToken_MemoizesTheClaimSpellingRefusal(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	p := makeJWTPDP(t, srv, "", "", nil)

	header := "Bearer " + misspelledClaimToken(t, key)
	_, first := p.ValidateToken(context.Background(), header)
	if got := ClassifyJWTError(first); got != jwtErrNonCanonicalClaim {
		t.Fatalf("first refusal category = %q, want %q (%v)", got, jwtErrNonCanonicalClaim, first)
	}
	if n := p.refusalCache.Len(); n != 1 {
		t.Fatalf("refusal cache holds %d entries, want 1", n)
	}
	_, second := p.ValidateToken(context.Background(), header)
	if second != first {
		t.Fatalf("second refusal = %v, want the memoized %v", second, first)
	}
	if n := p.tokenCache.Len(); n != 0 {
		t.Fatalf("verified-token cache holds %d entries; a refusal must never populate it", n)
	}
}

// TestValidateToken_MemoizesMalformedTokenOnlyAfterVerification pins the half of the rule the
// category table cannot express: `malformed_token` is reached both BEFORE the signature is
// checked (ParseSigned, the kid scan) and after it (the payload decodes), and only the second
// may be cached. That gate is what keeps the refusal cache unpollutable — an unauthenticated
// peer spraying distinct garbage cannot place a single entry in it.
func TestValidateToken_MemoizesMalformedTokenOnlyAfterVerification(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	// A payload whose `mcp` claim is not an object at all: the scan refuses its SHAPE, which
	// is neither minting mistake and so classifies as malformed_token — after the signature
	// has verified.
	verified := liveTokenClaims()
	verified[topLevelClaimMCP] = nil

	for _, tc := range []struct {
		name       string
		header     func() string
		wantCached int
	}{
		{"before verification", func() string { return "Bearer not.a.jwt" }, 0},
		{"after verification", func() string { return "Bearer " + signClaimsMapToken(t, key, verified) }, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := makeJWTPDP(t, srv, "", "", nil)
			_, err := p.ValidateToken(context.Background(), tc.header())
			if got := ClassifyJWTError(err); got != jwtErrMalformedToken {
				t.Fatalf("category = %q, want %q (%v)", got, jwtErrMalformedToken, err)
			}
			if n := p.refusalCache.Len(); n != tc.wantCached {
				t.Fatalf("refusal cache holds %d entries, want %d", n, tc.wantCached)
			}
		})
	}
}

// TestValidateToken_DoesNotMemoizeVerdictsThatCanChange covers the other half: a refusal that
// verified the signature and still must not be replayed, because the state it read can change
// while the bytes do not. Both rows would be memoized by the signature gate alone, so they
// pin the category table rather than the gate.
func TestValidateToken_DoesNotMemoizeVerdictsThatCanChange(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	other := newTestKey(t, "k1") // same kid, different key material: a rotation can heal it
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	for _, tc := range []struct {
		name  string
		token string
		want  string
	}{
		{
			// The clock moves, and a token refused for its exp today is not a fact about
			// the bytes.
			name:  "expired",
			token: makeIDPToken(t, key, []string{"tool:read_file"}, "", "", "agent-1", time.Now().Add(-time.Hour)),
			want:  jwtErrExpired,
		},
		{
			// A JWKS rotation makes previously unverifiable bytes verify.
			name:  "invalid signature",
			token: makeIDPToken(t, other, []string{"tool:read_file"}, "", "", "agent-1", time.Now().Add(time.Hour)),
			want:  jwtErrSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := makeJWTPDP(t, srv, "", "", nil)
			_, err := p.ValidateToken(context.Background(), "Bearer "+tc.token)
			if got := ClassifyJWTError(err); got != tc.want {
				t.Fatalf("category = %q, want %q (%v)", got, tc.want, err)
			}
			if n := p.refusalCache.Len(); n != 0 {
				t.Fatalf("refusal cache holds %d entries; %s must be re-derived every request", n, tc.want)
			}
		})
	}
}

// TestValidateToken_RefusalEntryNeverOutlivesTheToken pins the exp cap: a refusal reached past
// the standard-claim read carries the token's own exp, so the memoized CATEGORY cannot keep
// naming a payload fault after expiry has overtaken it. Without the cap the entry would answer
// unsupported_version for the rest of the TTL on a token that is no longer live.
func TestValidateToken_RefusalEntryNeverOutlivesTheToken(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	base := time.Now()
	clk := &settableClock{t: base}
	p := NewJWTPDP(JWTPDPOptions{
		JWKSURI:                  srv.URL + "/",
		AllowAnyIssuer:           true,
		AllowAnyAudience:         true,
		CacheTTL:                 time.Hour,
		Clock:                    clk,
		ExperimentalCapabilities: true,
	})

	tokenStr := makeIDPTokenVersion(t, key, []string{"tool:read_file"}, "9.9", "", "", "agent-1", base.Add(5*time.Second))
	if _, err := p.ValidateToken(context.Background(), "Bearer "+tokenStr); ClassifyJWTError(err) != jwtErrUnsupportedVersion {
		t.Fatalf("category = %q, want %q", ClassifyJWTError(err), jwtErrUnsupportedVersion)
	}
	if _, ok := p.refusalCache.Get(capability.HashTokenKey(tokenStr)); !ok {
		t.Fatal("a version refusal past the standard-claim read must be memoized")
	}

	// Past exp AND past the leeway that still admits it, so the re-derived verdict is the
	// expiry rather than the version.
	clk.advance(5*time.Second + capability.DefaultTokenLeeway + time.Second)
	if _, ok := p.refusalCache.Get(capability.HashTokenKey(tokenStr)); ok {
		t.Fatal("the entry outlived the token's own exp")
	}
	if _, err := p.ValidateToken(context.Background(), "Bearer "+tokenStr); ClassifyJWTError(err) != jwtErrExpired {
		t.Fatalf("category after expiry = %q, want %q", ClassifyJWTError(err), jwtErrExpired)
	}
}

// TestValidateToken_RefusalWithNoExpFallsBackToTheTTL covers the other branch of the cap: a
// refusal reached BEFORE the standard-claim read has no exp to cap with, so the flat TTL is
// what bounds it.
func TestValidateToken_RefusalWithNoExpFallsBackToTheTTL(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	clk := &settableClock{t: time.Now()}
	p := NewJWTPDP(JWTPDPOptions{
		JWKSURI:                  srv.URL + "/",
		AllowAnyIssuer:           true,
		AllowAnyAudience:         true,
		CacheTTL:                 time.Hour,
		Clock:                    clk,
		ExperimentalCapabilities: true,
	})

	tokenStr := misspelledClaimToken(t, key)
	if _, err := p.ValidateToken(context.Background(), "Bearer "+tokenStr); ClassifyJWTError(err) != jwtErrNonCanonicalClaim {
		t.Fatalf("category = %q, want %q", ClassifyJWTError(err), jwtErrNonCanonicalClaim)
	}
	if _, ok := p.refusalCache.Get(capability.HashTokenKey(tokenStr)); !ok {
		t.Fatal("the claim-spelling refusal must be memoized")
	}
	clk.advance(jwtRefusalCacheTTL + time.Second)
	if _, ok := p.refusalCache.Get(capability.HashTokenKey(tokenStr)); ok {
		t.Fatal("the entry outlived the refusal-cache TTL")
	}
}

// TestJWTRouteWrapper_HoldsNoRefusalCache is the structural half of the audience/issuer
// argument in memoizableJWTRefusals: those categories are replayable only because
// ValidateToken answers the SHARED validator's union question, with the per-route narrowing
// happening later in Decide. A route wrapper that held a refusal cache could answer a
// route-scoped question from an entry minted for the union, so it holds neither cache.
func TestJWTRouteWrapper_HoldsNoRefusalCache(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	validator := makeJWTPDP(t, srv, "", "", nil)

	wrapper := NewJWTPDPWithCache(JWTPDPOptions{
		AllowAnyIssuer:           true,
		AllowAnyAudience:         true,
		RouteAudience:            "route-a",
		ExperimentalCapabilities: true,
	}, validator.Cache())
	if wrapper.refusalCache != nil || wrapper.tokenCache != nil {
		t.Fatal("a route wrapper must hold neither token cache")
	}

	// Nil-receiver safe on both legs: the refusal is still produced, just never memoized.
	header := "Bearer " + misspelledClaimToken(t, key)
	if _, err := wrapper.ValidateToken(context.Background(), header); ClassifyJWTError(err) != jwtErrNonCanonicalClaim {
		t.Fatalf("category = %q, want %q", ClassifyJWTError(err), jwtErrNonCanonicalClaim)
	}
	if n := wrapper.refusalCache.Len(); n != 0 {
		t.Fatalf("route wrapper memoized %d refusals", n)
	}
}
