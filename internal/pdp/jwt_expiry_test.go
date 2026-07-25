// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"
	"time"
)

// TestJWTPDP_ValidateToken_CapturesExpiresAt pins that a validated JWTClaims carries the
// verified exp as a wall-clock time. A long-lived SSE stream, validated only once at
// open, arms a timer at this instant so it does not outlive the token; without the field
// there is nothing for the transport to bound the stream on.
func TestJWTPDP_ValidateToken_CapturesExpiresAt(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "https://idp.example.com", "eunox", nil)
	exp := time.Now().Add(37 * time.Minute)
	token := makeIDPToken(t, key, []string{"tool:read_file"}, "https://idp.example.com", "eunox", "agent-1", exp)

	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	claims, ok := jwtClaimsFromContext(ctx)
	if !ok {
		t.Fatal("no claims in context")
	}
	if claims.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt must be populated so an SSE stream can bound itself to the token lifetime")
	}
	// JWT exp is Unix-second precision, so compare seconds.
	if claims.ExpiresAt.Unix() != exp.Unix() {
		t.Errorf("ExpiresAt = %d (unix), want %d (the verified exp)", claims.ExpiresAt.Unix(), exp.Unix())
	}
}
