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
// whether the token is live at all, `aud`/`iss` whether it was minted for this proxy, and
// `jti` whether the credential has been revoked — the one where the party who benefits from
// the ambiguity is the one holding the revoked token.
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
		// cnf is not one of go-jose's std claims — eunox reads it out of the raw claim map
		// for the RFC 7800 sender-constrained check — and it is the one watched claim whose
		// ambiguity fails OPEN rather than merely picking wrong. See the cnf-specific test
		// below for why that makes it the sharpest entry in the list.
		"cnf pair": {"cnf": map[string]interface{}{"jkt": "abc"}, "Cnf": map[string]interface{}{"jkt": "def"}},
		// jti is the sharpest entry after cnf, and for the same shape of reason: its
		// ambiguity is not a mis-pick, it is a BYPASS. Per-token revocation is keyed on jti,
		// so a token naming it twice binds whichever spelling sorts last — and the holder of
		// a revoked credential controls the payload. `{"jti":"revoked","JTI":"clean"}` is a
		// revoked token that keeps serving, with the revocation still listed as active.
		"jti pair": {"jti": "revoked-token", "JTI": "clean-token"},
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
		"nbf": time.Now().Add(-time.Minute).Unix(),
		// An ambiguity among claims this build never reads stays none of its business,
		// exactly as for the mcp/act gate. `email` is the standing example: a registered
		// claim is not what qualifies one for the watch list, being READ is.
		"email": "a@example.com",
		"Email": "b@example.com",
		// jti used to sit here for exactly that reason, and it MOVED to the rejected table
		// when revocation started reading it. That is the watch list's criterion working:
		// membership follows what this build decodes, and jti now decides whether a
		// credential is revoked.
		"jti": "token-1",
	})
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("a token naming each standard claim once must validate: %v", err)
	}
	if got := JWTClaimsPtr(ctx); got == nil || got.Subject != "agent-1" {
		t.Fatalf("subject = %v, want agent-1", got)
	}
}

// TestJWT_AmbiguousCnfRejected is the one entry in the watch list whose ambiguity fails
// OPEN, which is why it is watched even though it is not a claim go-jose decodes.
//
// eunox reads `cnf` from the RAW claim map (a plain map decode — last member wins) to
// detect an RFC 7800 sender-constrained token, which it must refuse because it verifies no
// proof of possession. `CnfIsSenderConstrained(nil)` reads an explicit null as ABSENT, not
// malformed — so `{"cnf":{"jkt":…},"cnf":null}` resolves to null, the constraint
// evaporates, and a PoP-bound token is accepted as a plain bearer token. Anyone who
// captures it can then replay it: the exact downgrade the rejection exists to prevent,
// reached through the ambiguity class the rest of this gate closes.
func TestJWT_AmbiguousCnfRejected(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	p := makeJWTPDP(t, srv, "", "", nil)

	// A single, unambiguous cnf is still refused on its own terms (sender-constrained),
	// which is the behavior this test must not be confused with.
	constrained := signRawClaimsToken(t, key, "agent-1", time.Now().Add(time.Hour), map[string]interface{}{
		"mcp": map[string]interface{}{"v": mcpClaimVersion},
		"cnf": map[string]interface{}{"jkt": "abc"},
	})
	if _, err := p.ValidateToken(context.Background(), "Bearer "+constrained); err == nil {
		t.Fatal("a sender-constrained token must be refused")
	} else if got := ClassifyJWTError(err); got != "sender_constrained" {
		t.Fatalf("error category = %q, want sender_constrained", got)
	}

	// The fail-open shape: a real cnf plus a null one. Before the gate watched cnf this
	// validated cleanly and downgraded to a bearer token.
	ambiguous := signRawClaimsToken(t, key, "agent-1", time.Now().Add(time.Hour), map[string]interface{}{
		"mcp": map[string]interface{}{"v": mcpClaimVersion},
		"cnf": map[string]interface{}{"jkt": "abc"},
		"Cnf": nil,
	})
	if _, err := p.ValidateToken(context.Background(), "Bearer "+ambiguous); err == nil {
		t.Fatal("an ambiguous cnf must reject the token, not resolve to whichever member sorts last")
	} else if got := ClassifyJWTError(err); got != "ambiguous_claims" && got != "sender_constrained" {
		t.Fatalf("error category = %q, want the token refused (ambiguous_claims or sender_constrained)", got)
	}
}
