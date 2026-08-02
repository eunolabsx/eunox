// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"
	"time"
)

// TestJWT_AmbiguousStandardClaimRejected extends the act/Act regression to the RFC 7519
// registered claims, which go-jose decodes through the SAME bare
// encoding/json.Unmarshal: jwt.Claims has no custom UnmarshalJSON and plain `iss`/`sub`/
// `aud`/`exp`/`nbf`/`iat`/`jti` tags, so a payload naming one of them twice binds
// whichever spelling sorts last in the payload bytes, silently.
//
// These decide more than the custom claims do. `sub` is what a manifest's `principal:`
// scoping reads, so the collision picks which constraints govern the call — up to
// resolving a narrowly-scoped agent's token to a broader identity. `exp`/`nbf` decide
// whether the token is live at all, and `aud`/`iss` whether it was minted for this proxy.
//
// Not third-party forgeable (the signature covers the whole payload), which is exactly
// why the test signs the ambiguous payload with a real key: the realistic producer is the
// operator's own minting pipeline emitting a validly-signed but internally ambiguous
// token, the same "IdP template mistake" class the mcp/act gate already refuses.
func TestJWT_AmbiguousStandardClaimRejected(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	pdp := makeJWTPDP(t, srv, "", "", nil)
	exp := time.Now().Add(time.Hour)

	// signRawClaimsToken's own stdClaims contribute "sub", "iat" and "exp"; each case
	// below adds a second spelling of one of them (or of a claim stdClaims does not set)
	// as a distinct Go map key, so both survive into the signed payload verbatim.
	for name, raw := range map[string]map[string]interface{}{
		"sub case variant": {"Sub": "admin-svc"},
		"exp case variant": {"Exp": time.Now().Add(100 * time.Hour).Unix()},
		"iat case variant": {"Iat": time.Now().Add(-time.Hour).Unix()},
		"nbf pair":         {"nbf": time.Now().Add(-time.Hour).Unix(), "NBF": time.Now().Add(time.Hour).Unix()},
		"iss pair":         {"iss": "https://idp.example.com", "Iss": "https://evil.example.com"},
		"aud pair":         {"aud": "eunox", "Aud": "other"},
		"jti pair":         {"jti": "a", "JTI": "b"},
	} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]interface{}{"mcp": map[string]interface{}{"v": mcpClaimVersion}}
			for k, v := range raw {
				claims[k] = v
			}
			token := signRawClaimsToken(t, key, "low-priv-agent", exp, claims)
			_, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
			if err == nil {
				t.Fatalf("ValidateToken accepted a token whose payload names one standard claim twice (%v); want a terminal rejection", raw)
			}
			if got := ClassifyJWTError(err); got != "ambiguous_claims" {
				t.Fatalf("error category = %q, want ambiguous_claims", got)
			}
		})
	}
}

// TestJWT_UnambiguousStandardClaimsAccepted is the other half: watching the standard
// claims must not make an ordinary token — one naming each of them exactly once, beside
// unrelated claims minted for other audiences — fail to validate.
func TestJWT_UnambiguousStandardClaimsAccepted(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	pdp := makeJWTPDP(t, srv, "", "", nil)

	token := signRawClaimsToken(t, key, "agent-1", time.Now().Add(time.Hour), map[string]interface{}{
		"mcp": map[string]interface{}{"v": mcpClaimVersion},
		"jti": "token-1",
		"nbf": time.Now().Add(-time.Minute).Unix(),
		// An ambiguity among claims this build never reads stays none of its business,
		// exactly as for the mcp/act gate.
		"email": "a@example.com",
		"Email": "b@example.com",
	})
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("a token naming each standard claim once must validate: %v", err)
	}
	if got := JWTClaimsPtr(ctx); got == nil || got.Subject != "agent-1" {
		t.Fatalf("subject = %v, want agent-1", got)
	}
}
