// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// Revoking a token must RECLAIM the sessions holding it, not merely deny their next request.
//
// This is the half of a kill that has no request to hang off. A session whose credential was
// revoked still holds an upstream subprocess, a maxSessions slot and an SSE stream; denying its
// traffic frees none of them, and with sessionIdleTimeoutMs: 0 there is no reaper to find them
// later. That is precisely the configuration the on-delivery reclaim exists for.
//
// Nothing in the reclaim path was written for the token dimension — sessionKilled rebuilds the
// context from the session's own claims and re-asks ShouldBlock, which now reads the token id
// out of them. That is the Subject struct paying off, and it is worth a test rather than an
// assumption: "no code change was needed" is a claim about behavior, and the only way to know
// it holds is to drive it.
func TestRevocationReclaim_RevokedTokenReclaimsItsSession(t *testing.T) {
	ks := killswitch.NewInMemory()
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)
	sink, _ := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{
		UpstreamURL:   upSrv.URL,
		PDP:           newTestManifestPDPWithKS(ks),
		KS:            ks,
		SessionIdleMs: 0, // no idle reaper: the on-delivery sweep is the only reclaim
		Sink:          sink,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	require.NotNil(t, sess, "session not found")
	// The session carries the credential it was established with, which is where the reclaim
	// path reads the token id from — a session with no claims has no token dimension to match.
	sess.claims = &pdp.JWTClaims{AgentID: "agent-1", TokenID: "jti-leaked"}

	// A revocation naming a DIFFERENT credential must leave it alone. Asserted first, so a
	// sweep that tears down indiscriminately fails here rather than passing the real case.
	require.NoError(t, ks.RevokeJTI(context.Background(), "jti-other"))
	proxy.sweepKilledSessions()
	assert.Equal(t, 1, proxy.sessionCount(),
		"revoking another credential must not reclaim this session; the dimension is per-token by design")

	require.NoError(t, ks.RevokeJTI(context.Background(), "jti-leaked"))
	proxy.sweepKilledSessions()
	waitForSessions(t, proxy, 0)
}

// The same fact one layer down: the kill CHECK matches on the token dimension, so the next
// request on a revoked credential is denied even though its agent and session are untouched.
//
// Separate from the reclaim above because they fail independently — a sweep could reclaim
// while the check let a racing in-flight request through, or the check could match while the
// sweep spared the session forever.
func TestKillCheck_RevokedTokenDeniesWhileAgentAndSessionAreClean(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	ctx := context.Background()
	require.NoError(t, ks.RevokeJTI(ctx, "jti-leaked"))

	p := newTestManifestPDPWithKS(ks)

	revoked := pdp.WithJWTClaims(ctx, &pdp.JWTClaims{AgentID: "agent-1", TokenID: "jti-leaked"})
	deny := p.CheckKill(revoked, "sess-1")
	require.NotNil(t, deny, "a request presenting a revoked credential must be denied")
	require.NotNil(t, deny.Denial)
	assert.Equal(t, "KILL_SWITCH", deny.Denial.Code,
		"a revoked token is a revocation, not a policy verdict; the code is what an observing route may not downgrade")

	// The same agent on a different credential still serves, which is the property that makes
	// this the finest dimension rather than a differently-spelled agent kill.
	clean := pdp.WithJWTClaims(ctx, &pdp.JWTClaims{AgentID: "agent-1", TokenID: "jti-clean"})
	assert.Nil(t, p.CheckKill(clean, "sess-1"),
		"revoking one credential must leave the same agent's other tokens serving")

	// And a request with no token at all is unaffected: an absent dimension is not evaluated,
	// which is a narrowing rather than a bypass — the session and global dimensions still apply.
	assert.Nil(t, p.CheckKill(ctx, "sess-1"),
		"a request with no token has no token dimension to match; it must not inherit another's revocation")
}
