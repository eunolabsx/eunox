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

// makeDeclassifyToken signs an identity-only IdP JWT whose mcp block carries the raw
// declassify claim value, so a malformed grant can be presented exactly as an IdP would
// emit it.
func makeDeclassifyToken(t *testing.T, key testKey, declassifyJSON, sub string, exp time.Time) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	now := time.Now()
	std := jwt.Claims{
		Subject:  sub,
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(exp),
	}
	mcp := map[string]interface{}{"v": mcpClaimVersion}
	if declassifyJSON != "" {
		var v interface{}
		if err := json.Unmarshal([]byte(declassifyJSON), &v); err != nil {
			t.Fatalf("fixture is not JSON: %v", err)
		}
		mcp[capability.ClaimDeclassify] = v
	}
	token, err := jwt.Signed(sig).Claims(std).Claims(map[string]interface{}{"mcp": mcp}).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

// TestValidateToken_DeclassifyClaim pins where the approval grant is validated: at the
// TOKEN boundary. A grant this build cannot enforce rejects the token, rather than
// evaluating later to "covers nothing" — which would turn an IdP template mistake into a
// permanent, invisible escalation loop with no error for an operator to grep for.
func TestValidateToken_DeclassifyClaim(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	p := makeJWTPDP(t, srv, "", "", nil)
	exp := time.Now().Add(time.Hour)

	cases := []struct {
		name, claim, wantErr string
		wantGrants           int
	}{
		{
			name:       "a well-formed grant is carried on the validated claims",
			claim:      `[{"labels":["pii"],"target":"tool:sanitize","approver":"alice@example.com","id":"apr-1"}]`,
			wantGrants: 1,
		},
		{
			name:       "no claim at all is the common case and grants nothing",
			claim:      "",
			wantGrants: 0,
		},
		{
			name:       "an explicitly empty array grants nothing",
			claim:      `[]`,
			wantGrants: 0,
		},
		{
			name:    "a glob target rejects the token",
			claim:   `[{"labels":["pii"],"target":"tool:*","approver":"alice"}]`,
			wantErr: "glob metacharacter",
		},
		{
			name:    "an unknown label rejects the token",
			claim:   `[{"labels":["secret"],"target":"tool:sanitize","approver":"alice"}]`,
			wantErr: "unknown flow label",
		},
		{
			name:    "a grant with no approver rejects the token",
			claim:   `[{"labels":["pii"],"target":"tool:sanitize"}]`,
			wantErr: "must name the human who approved",
		},
		{
			name:    "a non-array claim rejects the token",
			claim:   `{"labels":["pii"]}`,
			wantErr: "must be an array",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := makeDeclassifyToken(t, key, tc.claim, "svc", exp)
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
			got := declassifyApprovalsFromContext(ctx)
			if len(got) != tc.wantGrants {
				t.Fatalf("got %d approvals, want %d", len(got), tc.wantGrants)
			}
			if tc.wantGrants > 0 {
				if got[0].Approver != "alice@example.com" || got[0].Target != "tool:sanitize" {
					t.Fatalf("grant did not survive validation intact: %+v", got[0])
				}
			}
		})
	}
}

// TestDeclassifyApprovalsFromContext_NoToken pins the default: a request with no verified
// token carries no approvals, which is what makes a deployment with no approval
// integration ESCALATE a declassify directive rather than silently performing it.
func TestDeclassifyApprovalsFromContext_NoToken(t *testing.T) {
	if got := declassifyApprovalsFromContext(context.Background()); got != nil {
		t.Fatalf("a tokenless request must carry no approvals, got %v", got)
	}
}
