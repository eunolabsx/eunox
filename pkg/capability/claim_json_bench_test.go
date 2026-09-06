// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// benchClaimWatch is a watch list shaped like the one a JWT payload is scanned against: the
// registered claims plus a proxy-owned block. Deliberately NOT described as a copy of any
// consumer's list — that one is package-private and would drift from this silently — since
// what the cost depends on is the SIZE of the fold map and the number of members that hit it,
// not which names are in it.
var benchClaimWatch = capability.NewClaimWatch("mcp", "sub", "iss", "aud", "jti", "exp", "nbf", "iat", "cnf")

// BenchmarkClaimMembers isolates the claim-name scan: the pass a JWT payload takes on top of
// its own decodes — once over the payload, and again over the `mcp` block when the token
// carries one. It is the guard that makes the fold-space scan and the byte-exact decoders
// under it agree about which claims a token carries, so it runs on every validation that
// reaches the payload: a cache hit of either kind returns above it.
//
// Three shapes, splitting on what changes the work:
//
//   - Clean is the ordinary token: watched claims spelled canonically, beside the unwatched
//     claims a real enterprise IdP emits. Every member is still tokenized, folded and looked
//     up, because a claim named the wrong way has to be proven absent.
//   - Unwatched holds the same watched claims under a payload of mostly foreign claims, so
//     the part of the cost that scales with members this build never reads is visible on its
//     own — that is the half an IdP grows without eunox changing.
//   - Variant is the refusal path: one watched claim spelled a way nothing binds, where the
//     scan also builds its report.
//
// Decode is the same bytes through a plain map unmarshal, which is the comparison worth having
// — the scan exists because that decode cannot see what it collapses.
func BenchmarkClaimMembers(b *testing.B) {
	run := func(b *testing.B, payload []byte, wantErr bool) {
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := capability.ClaimMembers(payload, "jwt payload", benchClaimWatch)
			if (err != nil) != wantErr {
				b.Fatalf("ClaimMembers err = %v, wantErr = %v", err, wantErr)
			}
		}
	}

	b.Run("Clean", func(b *testing.B) { run(b, benchClaimPayload(8, ""), false) })
	b.Run("Unwatched", func(b *testing.B) { run(b, benchClaimPayload(40, ""), false) })
	b.Run("Variant", func(b *testing.B) { run(b, benchClaimPayload(8, "Mcp"), true) })

	b.Run("Decode", func(b *testing.B) {
		payload := benchClaimPayload(8, "")
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var v map[string]json.RawMessage
			if err := json.Unmarshal(payload, &v); err != nil {
				b.Fatalf("unmarshal: %v", err)
			}
		}
	})
}

// benchClaimPayload renders a JWT payload with the watched claims plus extra unwatched ones,
// as literal bytes rather than through a map marshal so the member ORDER (which the scan walks
// in) is fixed run to run. mcpKey names the `mcp` claim: pass a variant spelling to build the
// payload the scan refuses.
func benchClaimPayload(unwatched int, mcpKey string) []byte {
	if mcpKey == "" {
		mcpKey = "mcp"
	}
	members := []string{
		fmt.Sprintf(`%q:{"v":"0.2","capabilities":["tool:read_file?path=/reports/*","tool:query_db?op=SELECT"],"task_id":"task-7f3a","agent_id":"agent-1"}`, mcpKey),
		`"iss":"https://idp.example.com/tenants/acme"`,
		`"sub":"agent-1"`,
		`"aud":["eunox"]`,
		`"jti":"01J9Q4T2ZR8VQ0X6N3B7C5D1E2"`,
		`"iat":1767225600`,
		`"nbf":1767225600`,
		`"exp":1767229200`,
	}
	for i := 0; i < unwatched; i++ {
		members = append(members, fmt.Sprintf(`"https://claims.example.com/%02d":%q`, i, strings.Repeat("v", 24)))
	}
	return []byte("{" + strings.Join(members, ",") + "}")
}
