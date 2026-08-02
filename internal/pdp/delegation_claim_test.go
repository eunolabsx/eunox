// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// makeDelegationToken signs an identity-only IdP JWT carrying a top-level RFC 8693 `act`
// chain and an mcp.delegation grant array, exactly as a token-exchange endpoint would emit
// them, so a malformed or WIDENING chain is presented the way a real one would be.
func makeDelegationToken(t *testing.T, key testKey, actJSON, grantsJSON string, exp time.Time) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	now := time.Now()
	std := jwt.Claims{Subject: "user@example.com", IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(exp)}
	mcp := map[string]interface{}{"v": mcpClaimVersion}
	if grantsJSON != "" {
		var v interface{}
		if err := json.Unmarshal([]byte(grantsJSON), &v); err != nil {
			t.Fatalf("grants fixture is not JSON: %v", err)
		}
		mcp[capability.ClaimDelegation] = v
	}
	custom := map[string]interface{}{"mcp": mcp}
	if actJSON != "" {
		var v interface{}
		if err := json.Unmarshal([]byte(actJSON), &v); err != nil {
			t.Fatalf("act fixture is not JSON: %v", err)
		}
		custom[capability.ClaimActor] = v
	}
	token, err := jwt.Signed(sig).Claims(std).Claims(custom).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

// TestValidateToken_DelegationChain pins where a delegation chain is checked: at the TOKEN
// boundary. The operator's whole reason for minting a chain is that "the delegate is no
// broader than its delegator" is checkable, and rejecting the token is what makes it
// checkable — clamping a widening hop would leave the token working while meaning something
// other than what it says.
func TestValidateToken_DelegationChain(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	p := makeJWTPDP(t, srv, "", "", nil)
	exp := time.Now().Add(time.Hour)

	cases := []struct {
		name, act, grants, wantErr string
		wantHops                   int
		wantDelegate               string
	}{
		{
			name:         "a narrowing two-hop chain is carried on the validated claims",
			act:          `{"sub":"agent-b","act":{"sub":"agent-a"}}`,
			grants:       `[{"subject":"agent-a","targets":["tool:read","tool:write"]},{"subject":"agent-b","targets":["tool:read"],"labels":["untrusted"]}]`,
			wantHops:     2,
			wantDelegate: "agent-b",
		},
		{
			name:     "no delegation at all is the common case",
			wantHops: 0,
		},
		{
			name:         "an act chain with no grants still names the delegate",
			act:          `{"sub":"agent-a"}`,
			wantHops:     0,
			wantDelegate: "agent-a",
		},
		{
			name:    "a widening hop rejects the token",
			act:     `{"sub":"agent-b","act":{"sub":"agent-a"}}`,
			grants:  `[{"subject":"agent-a","targets":["tool:read"]},{"subject":"agent-b","targets":["tool:read","tool:write"]}]`,
			wantErr: "does not hold",
		},
		{
			name:    "a chain whose halves disagree rejects the token",
			act:     `{"sub":"agent-b","act":{"sub":"agent-a"}}`,
			grants:  `[{"subject":"agent-a"}]`,
			wantErr: "hop for hop",
		},
		{
			name:    "a grant naming the wrong actor rejects the token",
			act:     `{"sub":"agent-b","act":{"sub":"agent-a"}}`,
			grants:  `[{"subject":"agent-a"},{"subject":"agent-z"}]`,
			wantErr: "chain names",
		},
		{
			name:    "a star in a delegated target rejects the token",
			grants:  `[{"subject":"agent-a","targets":["tool:read_*"]}]`,
			wantErr: "contains '*'",
		},
		{
			name:    "a misspelled act nesting rejects the token",
			act:     `{"sub":"agent-b","acts":{"sub":"agent-a"}}`,
			wantErr: "unknown",
		},
		{
			name:    "an actor with no sub rejects the token",
			act:     `{"act":{"sub":"agent-a"}}`,
			wantErr: "carries no 'sub'",
		},
		{
			name:    "a misspelled grant field rejects the token",
			grants:  `[{"subject":"agent-a","targts":["tool:read"]}]`,
			wantErr: "unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := makeDelegationToken(t, key, tc.act, tc.grants, exp)
			ctx, err := p.ValidateToken(context.Background(), "Bearer "+token)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			chain := delegationFromContext(ctx)
			if tc.wantHops == 0 && tc.wantDelegate == "" {
				if !chain.IsEmpty() {
					t.Fatalf("want no chain, got %+v", chain)
				}
				return
			}
			if len(chain.Grants) != tc.wantHops {
				t.Fatalf("got %d hops, want %d", len(chain.Grants), tc.wantHops)
			}
			if got := chain.Delegate(); got != tc.wantDelegate {
				t.Fatalf("delegate = %q, want %q", got, tc.wantDelegate)
			}
		})
	}
}

// TestDelegationFromContext_NoToken pins the default: a request with no verified token
// carries no chain, so a deployment with no delegation integration decides exactly as it does
// today.
func TestDelegationFromContext_NoToken(t *testing.T) {
	if got := delegationFromContext(context.Background()); got != nil {
		t.Fatalf("a tokenless request must carry no delegation chain, got %+v", got)
	}
}
