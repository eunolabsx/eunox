// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// misspelledClaimToken is the shape the refusal cache exists for: a signed, unexpired,
// otherwise-valid token whose `mcp` claim is spelled a way no decoder on this path binds, so
// every request carrying it is refused after a full ECDSA verification. Its refusal is
// reached before validateStandardClaims, so it carries no exp for the entry to be capped at.
func misspelledClaimToken(t testing.TB, key testKey) string {
	t.Helper()
	return signClaimsMapToken(t, key, misspellMCPClaim(t, liveTokenClaims()))
}

// misspellMCPClaim rewrites claims' `mcp` member under a spelling that folds to it but that no
// decoder on this path binds. Through variantSpelling rather than a literal, so a change to
// what the scan treats as a variant reaches every fixture built on this shape — a hardcoded
// spelling the scan stopped refusing would leave a "refused" fixture the validator ACCEPTS,
// with the assertions around it still green.
func misspellMCPClaim(t testing.TB, claims map[string]interface{}) map[string]interface{} {
	t.Helper()
	variant, ok := variantSpelling(topLevelClaimMCP)
	if !ok {
		t.Fatalf("%q has no case-variant spelling, so this fixture cannot carry the refusal", topLevelClaimMCP)
	}
	claims[variant] = claims[topLevelClaimMCP]
	delete(claims, topLevelClaimMCP)
	return claims
}

// refusalFixture is the key + JWKS server every test below needs.
func refusalFixture(t *testing.T) (testKey, *JWTPDP) {
	t.Helper()
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	t.Cleanup(srv.Close)
	return key, makeJWTPDP(t, srv, "", "", nil)
}

// TestJWTRefusalMemoization_EveryCategoryDeclaresOne derives the category set from package
// pdp's own constants rather than from a list written beside the table, so a category added
// without a memoization verdict fails the build instead of inheriting the map's zero value
// silently. Absence IS the fail-closed answer, which is exactly why it must not be reachable
// by forgetting: the omission would look identical to a deliberate "not memoizable" until the
// day a genuinely replayable refusal started re-running a verify per request.
//
// Every non-test file in the package, not one named file: the constants and the table already
// live in different files, so a walk pinned to jwt.go would stop covering a category the
// moment one was declared beside the code that raises it.
func TestJWTRefusalMemoization_EveryCategoryDeclaresOne(t *testing.T) {
	t.Parallel()
	declared := make(map[string]bool, len(memoizableJWTRefusals))
	for _, name := range packageGoFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
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
				for i, ident := range vs.Names {
					if !strings.HasPrefix(ident.Name, "jwtErr") {
						continue
					}
					// A category that is not a plain string literal cannot be read here, and
					// skipping it silently would reopen the hole this walk closes.
					if i >= len(vs.Values) {
						t.Fatalf("%s (%s) has no value of its own; the walk cannot read its category", ident.Name, name)
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s (%s) is not a plain string literal; the walk cannot read its category", ident.Name, name)
					}
					code, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						t.Fatalf("%s: unquoting %s: %v", ident.Name, lit.Value, uerr)
					}
					declared[code] = true
					if _, covered := memoizableJWTRefusals[code]; !covered {
						t.Errorf("%s (%q) has no row in memoizableJWTRefusals: an undeclared category reads as not memoizable, which is indistinguishable from having decided that", ident.Name, code)
					}
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

// packageGoFiles lists the package's non-test sources, so a source guard derives its subject
// from the package rather than from a filename it has to be told about.
func packageGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Clean(name))
	}
	return out
}

// TestMemoizableRefusal_SignatureGateRefusesEveryCategory drives the gate DIRECTLY, because
// no request can: every refusal reachable without a verified signature already carries a
// category the table answers false for, so the two guards agree today and a behavioural test
// cannot tell which one answered. The gate is what keeps them agreeing — it is what makes the
// refusal cache unpollutable by an unauthenticated peer, so a pre-verification refusal that
// ever came to carry a memoizable category is refused by construction rather than by having
// been thought about.
func TestMemoizableRefusal_SignatureGateRefusesEveryCategory(t *testing.T) {
	t.Parallel()
	for code, memoizable := range memoizableJWTRefusals {
		err := jwtErr(code, errors.New("refusal under test"))
		if got := memoizableRefusal(err, false); got {
			t.Errorf("memoizableRefusal(%q, signatureVerified=false) = true; an unverified refusal is never replayable", code)
		}
		if got := memoizableRefusal(err, true); got != memoizable {
			t.Errorf("memoizableRefusal(%q, signatureVerified=true) = %v, want %v (the table's row)", code, got, memoizable)
		}
	}
}

// TestValidateToken_MemoizesTheClaimSpellingRefusal is the case the memoization exists for: an
// IdP emitting one mis-spelled watched claim moves a whole class of tokens onto the uncached
// path, where each request re-runs ParseSigned plus the ECDSA verify plus both payload
// decodes. The assertion is IDENTITY of the returned error, not merely its category — only a
// replayed entry can hand back the same value the first refusal produced.
func TestValidateToken_MemoizesTheClaimSpellingRefusal(t *testing.T) {
	t.Parallel()
	key, p := refusalFixture(t)

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

// TestValidateToken_MemoizationByCategory covers both halves of the admission rule against a
// live validator: which refusals are replayed, and which are re-derived every request because
// the state behind them can change while the bytes do not. Every row here VERIFIES its
// signature first, so what separates them is the category table alone.
//
// not_yet_valid and issued_in_future are here for the same reason as expired: all three heal
// with the clock, so memoizing one would deny a token for the rest of the TTL after it became
// valid — a self-inflicted authentication outage that nothing else in the package would catch.
func TestValidateToken_MemoizationByCategory(t *testing.T) {
	t.Parallel()
	now := time.Now()
	for _, tc := range []struct {
		name       string
		token      func(t *testing.T, key testKey) string
		want       string
		wantCached int
	}{
		{
			name:       "claim spelled a way nothing binds",
			token:      func(t *testing.T, key testKey) string { return misspelledClaimToken(t, key) },
			want:       jwtErrNonCanonicalClaim,
			wantCached: 1,
		},
		{
			// The scan refuses the mcp claim's SHAPE, which is neither minting mistake and so
			// classifies as malformed_token — after the signature has verified. Its pre-verify
			// twin is the row below.
			name: "malformed payload after verification",
			token: func(t *testing.T, key testKey) string {
				claims := liveTokenClaims()
				claims[topLevelClaimMCP] = nil
				return signClaimsMapToken(t, key, claims)
			},
			want:       jwtErrMalformedToken,
			wantCached: 1,
		},
		{
			name: "unsupported mcp version",
			token: func(t *testing.T, key testKey) string {
				return makeIDPTokenVersion(t, key, nil, "9.9", "", "", "agent-1", now.Add(time.Hour))
			},
			want:       jwtErrUnsupportedVersion,
			wantCached: 1,
		},
		{
			// Not a JWS at all: refused before any key is consulted, so it never reaches the
			// memoization at all — which is what keeps an unauthenticated peer from placing an
			// entry, since malformed_token is otherwise a replayable category.
			name:       "malformed token before verification",
			token:      func(t *testing.T, _ testKey) string { return "not.a.jwt" },
			want:       jwtErrMalformedToken,
			wantCached: 0,
		},
		{
			name: "expired",
			token: func(t *testing.T, key testKey) string {
				return makeIDPToken(t, key, nil, "", "", "agent-1", now.Add(-time.Hour))
			},
			want:       jwtErrExpired,
			wantCached: 0,
		},
		{
			name: "not yet valid",
			token: func(t *testing.T, key testKey) string {
				claims := liveTokenClaims()
				claims["nbf"] = now.Add(time.Hour).Unix()
				return signClaimsMapToken(t, key, claims)
			},
			want:       jwtErrNotYetValid,
			wantCached: 0,
		},
		{
			name: "issued in the future",
			token: func(t *testing.T, key testKey) string {
				claims := liveTokenClaims()
				claims["iat"] = now.Add(time.Hour).Unix()
				return signClaimsMapToken(t, key, claims)
			},
			want:       jwtErrIssuedInFuture,
			wantCached: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key, p := refusalFixture(t)
			_, err := p.ValidateToken(context.Background(), "Bearer "+tc.token(t, key))
			if got := ClassifyJWTError(err); got != tc.want {
				t.Fatalf("category = %q, want %q (%v)", got, tc.want, err)
			}
			if n := p.refusalCache.Len(); n != tc.wantCached {
				t.Fatalf("refusal cache holds %d entries, want %d", n, tc.wantCached)
			}
		})
	}
}

// TestValidateToken_DoesNotMemoizeSignatureFailure is the key-set half of the rule, kept apart
// because it needs a second key: a JWKS rotation makes previously unverifiable bytes verify,
// so this verdict is not a fact about the bytes even though it looks like one.
func TestValidateToken_DoesNotMemoizeSignatureFailure(t *testing.T) {
	t.Parallel()
	key, p := refusalFixture(t)
	other := newTestKey(t, key.kid) // same kid, different key material

	_, err := p.ValidateToken(context.Background(), "Bearer "+makeIDPToken(t, other, nil, "", "", "agent-1", time.Now().Add(time.Hour)))
	if got := ClassifyJWTError(err); got != jwtErrSignature {
		t.Fatalf("category = %q, want %q (%v)", got, jwtErrSignature, err)
	}
	if n := p.refusalCache.Len(); n != 0 {
		t.Fatalf("refusal cache holds %d entries; a signature failure must be re-derived every request", n)
	}
}

// TestValidateToken_RefusalEntryNeverOutlivesTheToken pins the exp cap on the two refusals
// that reach it by different routes: unsupported_version, which is refused AFTER the standard
// claims validated, and invalid_issuer, which is refused DURING that read — past
// ValidateWithLeeway, so with the token proven live and its exp in hand. The issuer case is
// the one the cap exists for: without it a validator keeps naming an issuer fault on a token
// that has since expired, on the closed-set audit field a SIEM keys expiry alerting on.
func TestValidateToken_RefusalEntryNeverOutlivesTheToken(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		iss   string
		pin   string
		token func(t *testing.T, key testKey, exp time.Time) string
		want  string
	}{
		{
			name: "refused after the standard-claim read",
			token: func(t *testing.T, key testKey, exp time.Time) string {
				return makeIDPTokenVersion(t, key, nil, "9.9", "https://idp.test", "eunox", "agent-1", exp)
			},
			want: jwtErrUnsupportedVersion,
		},
		{
			name: "refused during it, with the exp already validated",
			token: func(t *testing.T, key testKey, exp time.Time) string {
				return makeIDPToken(t, key, nil, "https://idp.other", "eunox", "agent-1", exp)
			},
			want: jwtErrInvalidIssuer,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := newTestKey(t, "k1")
			srv := makeJWKSServer(t, key)
			t.Cleanup(srv.Close)

			base := time.Now()
			clk := &advancingClock{now: base}
			p := NewJWTPDP(JWTPDPOptions{
				JWKSURI:                  srv.URL + "/",
				Issuer:                   "https://idp.test",
				Audience:                 "eunox",
				CacheTTL:                 time.Hour,
				Clock:                    clk,
				ExperimentalCapabilities: true,
			})

			tokenStr := tc.token(t, key, base.Add(5*time.Second))
			if _, err := p.ValidateToken(context.Background(), "Bearer "+tokenStr); ClassifyJWTError(err) != tc.want {
				t.Fatalf("category = %q, want %q", ClassifyJWTError(err), tc.want)
			}
			if _, ok := p.refusalCache.Get(capability.HashTokenKey(tokenStr)); !ok {
				t.Fatal("a refusal carrying the token's exp must be memoized")
			}

			// Past exp AND past the leeway that still admits it, so the re-derived verdict is
			// the expiry rather than the payload fault.
			clk.advance(5*time.Second + capability.DefaultTokenLeeway + time.Second)
			if _, ok := p.refusalCache.Get(capability.HashTokenKey(tokenStr)); ok {
				t.Fatal("the entry outlived the token's own exp")
			}
			if _, err := p.ValidateToken(context.Background(), "Bearer "+tokenStr); ClassifyJWTError(err) != jwtErrExpired {
				t.Fatalf("category after expiry = %q, want %q", ClassifyJWTError(err), jwtErrExpired)
			}
		})
	}
}

// TestValidateToken_RefusalWithNoExpFallsBackToTheTTL covers the other branch of the cap: a
// refusal reached before the exp was read has none to cap with, so the flat TTL bounds it.
func TestValidateToken_RefusalWithNoExpFallsBackToTheTTL(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	t.Cleanup(srv.Close)

	clk := &advancingClock{now: time.Now()}
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

// TestValidateToken_MemoizesTheAudienceRefusal covers the two rows whose safety rests on the
// longest argument: an audience or issuer mismatch is a fact about the bytes only because
// ValidateToken answers the SHARED validator's UNION question, with the per-route narrowing
// happening later in Decide. Both are driven here, and the wrapper below is the structural
// half — it holds no cache, so a route-scoped question cannot be answered from a union-scoped
// entry.
func TestValidateToken_MemoizesTheAudienceRefusal(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	t.Cleanup(srv.Close)

	p := NewJWTPDP(JWTPDPOptions{
		JWKSURI:                  srv.URL + "/",
		Issuer:                   "https://idp.test",
		AcceptedAudiences:        []string{"route-a", "route-b"},
		CacheTTL:                 time.Hour,
		ExperimentalCapabilities: true,
	})

	tokenStr := makeIDPToken(t, key, nil, "https://idp.test", "route-z", "agent-1", time.Now().Add(time.Hour))
	_, first := p.ValidateToken(context.Background(), "Bearer "+tokenStr)
	if got := ClassifyJWTError(first); got != jwtErrInvalidAudience {
		t.Fatalf("category = %q, want %q (%v)", got, jwtErrInvalidAudience, first)
	}
	_, second := p.ValidateToken(context.Background(), "Bearer "+tokenStr)
	if second != first {
		t.Fatalf("second refusal = %v, want the memoized %v", second, first)
	}
}

// TestJWTRouteWrapper_HoldsNoRefusalCache is the structural half of that argument: a route
// wrapper that held a refusal cache could answer a route-scoped question from an entry minted
// for the union, so it holds neither cache.
func TestJWTRouteWrapper_HoldsNoRefusalCache(t *testing.T) {
	t.Parallel()
	key, validator := refusalFixture(t)

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

// TestValidateToken_BoundsRetainedRefusalDetail pins the bound on the IdP-controlled text a
// memoized refusal carries. Before the cache existed the message was returned and dropped;
// now it is held for the TTL, so an unbounded value is memory the token's author chooses.
func TestValidateToken_BoundsRetainedRefusalDetail(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	t.Cleanup(srv.Close)

	p := NewJWTPDP(JWTPDPOptions{
		JWKSURI:                  srv.URL + "/",
		Issuer:                   "https://idp.test",
		AllowAnyAudience:         true,
		CacheTTL:                 time.Hour,
		ExperimentalCapabilities: true,
	})

	huge := strings.Repeat("i", 256*1024)
	_, err := p.ValidateToken(context.Background(), "Bearer "+makeIDPToken(t, key, nil, huge, "", "agent-1", time.Now().Add(time.Hour)))
	if got := ClassifyJWTError(err); got != jwtErrInvalidIssuer {
		t.Fatalf("category = %q, want %q", got, jwtErrInvalidIssuer)
	}
	// The whole message, not just the interpolated value: what the cache retains is the error.
	if n := len(err.Error()); n > 4*maxRefusalDetailBytes {
		t.Fatalf("retained refusal message is %d bytes for a %d-byte issuer; the bound is not applied", n, len(huge))
	}
}
