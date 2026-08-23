// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// A 2026-07-28 host is SERVED over HTTP, with no `initialize` anywhere in the exchange.
//
// This is the property the whole D3 sequence exists for, and it is the first time it holds: the
// revision has no handshake, so the first enforced request is what mints the worker that owns the
// upstream. Driven end to end through the real handler, real PDP and real upstream, because every
// layer below has been exercised only against 2025-11-25 peers until now.
func TestFirstRequestCreation_ADeclaringHostIsServedWithNoHandshake(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarness(t)

	resp := h.call(t, "agent-1", capability.MethodToolsCall, `{"name":"read_file","arguments":{"path":"/tmp/x"}}`)
	require.Equal(t, http.StatusOK, resp.status, "body: %s", resp.body)
	assert.Contains(t, resp.body, `"result"`, "a declaring host's first request must be served, not refused")

	assert.NotNil(t, h.upstreamSaw(capability.MethodToolsCall), "the call never reached the upstream")

	// The worker was minted by the CALL, not by a handshake: its id is the anchor-derived key
	// rather than a UUID. (The upstream leg still opens with `initialize` — that is its own
	// revision's business, pinned per route, and independent of what the host speaks.)
	sess := h.proxy.getSession(workerKey("", enforcement.ResolveStateAnchor(false, false, "", "agent-1")))
	require.NotNil(t, sess, "no worker was minted under the request's resolved state anchor")

	// And the retired header is neither required nor returned.
	assert.Empty(t, resp.sessionHeader, "a 2026-07-28 response must not carry Mcp-Session-Id")
	assert.Equal(t, 1, h.proxy.sessionCount(), "exactly one worker for one identity")
}

// The second request from the same identity JOINS the worker rather than minting another.
//
// This is what the anchor keying buys, and it is the difference between a session model and a
// fork-per-request: a minted-id worker would spawn a new upstream every time and accumulate each
// request's policy state in a bucket nothing else ever reaches — quotas that never bind,
// antecedents that never correlate.
func TestFirstRequestCreation_TheSameIdentityJoinsOneWorker(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarness(t)

	for i := 0; i < 3; i++ {
		resp := h.call(t, "agent-1", capability.MethodToolsCall, `{"name":"read_file","arguments":{"path":"/tmp/x"}}`)
		require.Equal(t, http.StatusOK, resp.status, "call %d body: %s", i, resp.body)
	}
	assert.Equal(t, 1, h.proxy.sessionCount(), "three requests from one identity minted more than one worker")
	// Counting the map is not enough on its own: registering a duplicate id used to OVERWRITE,
	// so three workers could come and go leaving a count of one and two orphaned upstreams.
	// Counting the opens is what sees that.
	assert.Equal(t, 1, h.upstreamOpens(), "the upstream was opened more than once for one identity")

	// A DIFFERENT identity gets its own, which is what makes the first assertion about keying
	// rather than about a single global worker.
	resp := h.call(t, "agent-2", capability.MethodToolsCall, `{"name":"read_file","arguments":{"path":"/tmp/x"}}`)
	require.Equal(t, http.StatusOK, resp.status, "body: %s", resp.body)
	assert.Equal(t, 2, h.proxy.sessionCount(), "a second identity must not share the first's worker")
}

// The worker key is the anchor the ENGINE keys its state on, resolved through the one shared
// resolver rather than restated here.
//
// Asserted directly because the consequence of drift is silent: a worker keyed on one subject
// while policy accumulates against another gives quotas that never bind and antecedents that
// never correlate — no error, no refusal, just enforcement that quietly does nothing.
func TestFirstRequestCreation_TheWorkerKeyIsTheStateAnchor(t *testing.T) {
	t.Parallel()
	route := &UpstreamRoute{name: "r1"}
	ctx := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{AgentID: "agent-1", TokenID: "jti-a"})

	key, ok := firstRequestWorkerKey(route, ctx)
	require.True(t, ok)
	assert.Equal(t, workerKey("r1", enforcement.ResolveStateAnchor(false, false, "", "agent-1")), key,
		"the worker key must be the resolved state anchor, or the worker map and the policy state disagree about a request")
	// Printable throughout: this string becomes the worker's id and is signed into the audit
	// record's session_id, which is sanitized on the way — a control rune would be recorded as
	// something other than itself, and two workers could collapse onto one recorded id.
	assert.Equal(t, key, audit.SanitizeAuditField(key),
		"the worker key must survive audit-field sanitization unchanged")

	// jti is revocation-only: a rotated credential must land on the SAME worker, or every token
	// refresh forks a new upstream and restarts the identity's accumulated state.
	rotated := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{AgentID: "agent-1", TokenID: "jti-b"})
	rotatedKey, ok := firstRequestWorkerKey(route, rotated)
	require.True(t, ok)
	assert.Equal(t, key, rotatedKey, "the worker key must survive token rotation")

	// Route-namespaced: p.sessions is one flat map across a gateway's upstreams, and
	// handleSessionPost answers 409 on a route mismatch, so one identity reaching two routes
	// must not collide on a key a UUID could never have collided on.
	other, ok := firstRequestWorkerKey(&UpstreamRoute{name: "r2"}, ctx)
	require.True(t, ok)
	assert.NotEqual(t, key, other, "one identity on two routes must get two workers")
}

// Note on the unidentified case: a request presenting no stable identity is refused, and that is
// asserted in first_request_negotiation_test.go against a proxy with NO JWT validator configured
// — which is the only shape that reaches this gate. With a validator wired, a token carrying no
// `agent_id` is rejected one layer earlier by handleMCP's own JWT pre-validation, so a cell here
// would pass whatever this gate did. It was written that way first; the mutation run is what
// showed it proving nothing.

// A revoked credential is refused BEFORE the worker is created, so a kill lands ahead of the
// privileged side effect rather than after it.
func TestFirstRequestCreation_KillGateRunsBeforeTheUpstreamIsSpawned(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarness(t)
	require.NoError(t, h.ks.KillAgent(context.Background(), "agent-1"))

	resp := h.call(t, "agent-1", capability.MethodToolsCall, `{"name":"read_file","arguments":{"path":"/tmp/x"}}`)
	assert.Contains(t, resp.body, capability.ErrCodeKillSwitch)
	assert.Zero(t, h.proxy.sessionCount(), "a killed identity must not hold a worker")
	// The sharp assertion: the upstream was never CONTACTED AT ALL. A kill caught one gate later
	// still denies the call, so asserting only on the denial would pass with the gate moved below
	// creation — having already spawned the subprocess the emergency stop exists to prevent.
	assert.Nil(t, h.upstreamSaw(mcp.MethodInitialize),
		"an upstream was opened for a killed identity; the kill gate must run before the spawn")
	assert.Nil(t, h.upstreamSaw(capability.MethodToolsCall), "the call reached the upstream past an active kill")
}

// The loser of a creation race ADOPTS the winner rather than being published over it.
//
// Driven deterministically, by asking the creation path for the same key twice, rather than by
// spawning goroutines and hoping one lands inside the window: a racing test that usually takes
// the fast path passes for the wrong reason, which is exactly what the first version of this
// did. The branch under test is reached on every second call here.
//
// What must not happen is two workers SURVIVING. Registering a duplicate id used to overwrite,
// which left the first worker's upstream outside the registry — nothing to reap it, and
// sessionCount unchanged, so the leak was invisible from every counter an operator has.
func TestFirstRequestCreation_TheLoserOfACreationRaceAdoptsTheWinner(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarness(t)
	route := h.proxy.routes[""]
	ctx := pdp.WithJWTClaims(capability.WithProtocolRevision(context.Background(), capability.Revision20260728),
		&pdp.JWTClaims{AgentID: "agent-1"})
	key, ok := firstRequestWorkerKey(route, ctx)
	require.True(t, ok)

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	first := h.proxy.createFirstRequestSession(ctx, httptest.NewRecorder(), req, route, key, capability.Revision20260728, h.proxy.currentReapGen())
	require.NotNil(t, first)
	second := h.proxy.createFirstRequestSession(ctx, httptest.NewRecorder(), req, route, key, capability.Revision20260728, h.proxy.currentReapGen())
	require.NotNil(t, second, "the loser must adopt the winner, not fail the request")

	assert.Same(t, first, second, "the second creation published a rival worker over the first")
	assert.Equal(t, 1, h.proxy.sessionCount())
	// The loser's own upstream is gone: it was opened and then torn down by the failed
	// registration, leaving exactly the winner's.
	assert.Equal(t, 1, h.liveUpstreams(), "a losing first request orphaned its upstream")
}

// And concurrently, end to end: whatever interleaving the scheduler picks, one worker survives.
func TestFirstRequestCreation_ConcurrentFirstRequestsConvergeOnOneWorker(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarness(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.call(t, "agent-1", capability.MethodToolsCall, `{"name":"read_file","arguments":{"path":"/tmp/x"}}`)
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, h.proxy.sessionCount(), "concurrent first requests left more than one worker for one identity")
	assert.LessOrEqual(t, h.liveUpstreams(), 1, "a losing first request orphaned its upstream")
}

// ── harness ─────────────────────────────────────────────────────────────────

type declaringResponse struct {
	status          int
	body            string
	sessionHeader   string
	wwwAuthenticate string
}

type declaringHostHarness struct {
	srv   *httptest.Server
	proxy *HTTPProxy
	ks    killswitch.Manager
	key   testKey

	mu     sync.Mutex
	seen   map[string]mcp.RPCMsg
	opens  int
	closes int
}

// newDeclaringHostHarness stands up a JWT-authenticated proxy over a remote upstream, which is
// what a 2026-07-28 host needs to be served: the revision has no handshake, so identity comes
// from the bearer alone.
func newDeclaringHostHarness(t *testing.T) *declaringHostHarness {
	t.Helper()
	h := &declaringHostHarness{seen: map[string]mcp.RPCMsg{}, key: newTestKey(t, "k1")}

	fake := newFakeUpstream()
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, err := body.ReadFrom(r.Body)
		require.NoError(t, err)
		var msg mcp.RPCMsg
		_ = json.Unmarshal(body.Bytes(), &msg)
		r.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
		h.mu.Lock()
		h.seen[msg.Method] = msg
		switch {
		case msg.Method == mcp.MethodInitialize:
			h.opens++
		case r.Method == http.MethodDelete:
			h.closes++
		}
		h.mu.Unlock()
		fake.ServeHTTP(w, r)
	})
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", capture))
	t.Cleanup(upSrv.Close)

	h.ks = killswitch.NewInMemory()
	inner := newTestManifestPDPWithKS(h.ks, capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}})
	jwtPDP, cleanup := makeJWTPDPWithInner(t, h.key, inner)
	t.Cleanup(cleanup)

	sink, _ := newTempAuditSink(t)
	h.proxy = newHTTPProxy(httpProxyOptions{
		UpstreamURL: upSrv.URL,
		PDP:         jwtPDP,
		JWTPDP:      jwtPDP,
		KS:          h.ks,
		Sink:        sink,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", h.proxy.handleMCP)
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

// upstreamOpens counts how many times an upstream leg was OPENED, which is what a worker owning
// one means. The map count alone cannot see a worker that was created and then displaced.
func (h *declaringHostHarness) upstreamOpens() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.opens
}

// liveUpstreams is opens minus the closes the proxy has performed, so an orphaned upstream — one
// created, displaced out of the registry, and therefore never torn down — is visible.
func (h *declaringHostHarness) liveUpstreams() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.opens - h.closes
}

func (h *declaringHostHarness) upstreamSaw(method string) *mcp.RPCMsg {
	h.mu.Lock()
	defer h.mu.Unlock()
	msg, ok := h.seen[method]
	if !ok {
		return nil
	}
	return &msg
}

// call makes one declaring request bearing a token for agentID.
func (h *declaringHostHarness) call(t *testing.T, agentID, method, params string) declaringResponse {
	t.Helper()
	return h.callWithToken(t, h.tokenFor(t, agentID), method, params)
}

func (h *declaringHostHarness) callWithToken(t *testing.T, token, method, params string) declaringResponse {
	t.Helper()
	declared := params[:len(params)-1] + `,"_meta":{"` + capability.MetaKeyProtocolVersion + `":"` + capability.Revision20260728.String() + `"}}`
	body, err := json.Marshal(mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method, Params: json.RawMessage(declared),
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(RoutingHeaderMethod, method)
	if name := gjsonName(declared); name != "" {
		req.Header.Set(RoutingHeaderName, name)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return declaringResponse{
		status:          resp.StatusCode,
		body:            buf.String(),
		sessionHeader:   resp.Header.Get(SessionHeader),
		wwwAuthenticate: resp.Header.Get("WWW-Authenticate"),
	}
}

// tokenFor mints a bearer carrying the mcp.agent_id claim the worker key is derived from.
func (h *declaringHostHarness) tokenFor(t *testing.T, agentID string) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: h.key.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", h.key.kid),
	)
	require.NoError(t, err)
	now := time.Now()
	token, err := jwt.Signed(sig).
		Claims(jwt.Claims{Subject: agentID, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}).
		Claims(idpJWTPayloadForTest{MCP: mcpClaimSetForTest{Version: mcpClaimVersionForTest, AgentID: agentID}}).
		Serialize()
	require.NoError(t, err)
	return token
}

// gjsonName pulls the tool/prompt name out of a params blob for the routing header, so the cells
// exercise W3's check rather than tripping it.
func gjsonName(params string) string {
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal([]byte(params), &p)
	return p.Name
}
