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
	"strings"
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
	identity, ok := stableCallerIdentity(&pdp.JWTClaims{Subject: "agent-1", AgentID: "agent-1"})
	require.True(t, ok)
	sess := h.proxy.getSession(workerKey("", enforcement.ResolveStateAnchor(false, false, "", identity)))
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
	base := &pdp.JWTClaims{Issuer: "https://idp", Subject: "alice", AgentID: "agent-1", TokenID: "jti-a"}
	ctx := pdp.WithJWTClaims(context.Background(), base)

	key, ok := firstRequestWorkerKey(route, ctx)
	require.True(t, ok)
	identity, ok := stableCallerIdentity(base)
	require.True(t, ok)
	assert.Equal(t, workerKey("r1", enforcement.ResolveStateAnchor(false, false, "", identity)), key,
		"the worker key must be the resolved state anchor, or the worker map and the policy state disagree about a request")
	// Printable throughout: this string becomes the worker's id and is signed into the audit
	// record's session_id, which is sanitized on the way — a control rune would be recorded as
	// something other than itself, and two workers could collapse onto one recorded id.
	assert.Equal(t, key, audit.SanitizeAuditField(key),
		"the worker key must survive audit-field sanitization unchanged")

	// jti is revocation-only: a rotated credential must land on the SAME worker, or every token
	// refresh forks a new upstream and restarts the identity's accumulated state.
	rotated := pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "https://idp", Subject: "alice", AgentID: "agent-1", TokenID: "jti-b"})
	rotatedKey, ok := firstRequestWorkerKey(route, rotated)
	require.True(t, ok)
	assert.Equal(t, key, rotatedKey, "the worker key must survive token rotation")

	// At least as fine as the OWNER BINDING, which compares (iss, sub). A coarser key hands the
	// first caller a worker every other caller sharing its agent id is then permanently refused
	// on — AUTHORIZATION_FAILED per attempt, forever, for legitimate traffic.
	otherSubject := pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "https://idp", Subject: "bob", AgentID: "agent-1"})
	bobKey, ok := firstRequestWorkerKey(route, otherSubject)
	require.True(t, ok)
	assert.NotEqual(t, key, bobKey, "two subjects sharing an agent id must not share a worker the owner binding then refuses")

	otherIssuer := pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "https://other-idp", Subject: "alice", AgentID: "agent-1"})
	issuerKey, ok := firstRequestWorkerKey(route, otherIssuer)
	require.True(t, ok)
	assert.NotEqual(t, key, issuerKey, "the owner binding compares the issuer too")

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

	sink    *audit.Sink
	logPath string

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
	return newDeclaringHostHarnessWithTape(t)
}

// newDeclaringHostHarnessWithTape is the same harness with its audit log readable, for the cells
// that assert on what a refusal RECORDED rather than on what it answered.
func newDeclaringHostHarnessWithTape(t *testing.T) *declaringHostHarness {
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

	sink, logPath := newTempAuditSink(t)
	h.sink, h.logPath = sink, logPath
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
// tape closes the sink and returns every record written, so a cell can count what a flood left
// behind. Closed rather than synced: the sink drains on a background goroutine, and Close is what
// this package's other tape-reading tests use to make the writes observable.
func (h *declaringHostHarness) tape(t *testing.T) []map[string]interface{} {
	t.Helper()
	_ = h.sink.Close()
	return readAuditRecords(t, h.logPath)
}

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

// ── the review findings, as cells ───────────────────────────────────────────

// Only a REQUEST may mint a worker.
//
// The `initialize` arm has always guarded this — a notification must never start an upstream or
// consume a session slot — and the declaring path is the same hazard with no handshake to hang
// the guard off. A sessionless notification, host response or unframed message would otherwise
// fork an upstream for a message that can never be answered and whose sender it does not
// identify, at one subprocess per frame.
func TestFirstRequestCreation_OnlyARequestMintsAWorker(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarness(t)
	resp := h.postDeclaring(t, h.tokenFor(t, "agent-1"), mcp.RPCMsg{
		JSONRPC: "2.0", Method: "notifications/cancelled", Params: json.RawMessage(`{"requestId":1}`),
	})

	assert.Equal(t, http.StatusAccepted, resp.status,
		"JSON-RPC forbids replying to a notification; it must be acked bodyless")
	assert.NotContains(t, resp.body, `"jsonrpc"`,
		"a framing that cannot be answered must not receive a JSON-RPC body")
	assert.Zero(t, h.proxy.sessionCount(), "a notification minted a worker")
	assert.Zero(t, h.upstreamOpens(), "a notification forked an upstream")

	// The notification is the only non-request framing that REACHES this arm, and the reason is
	// worth recording: a declaration rides in `params`, and neither a host response nor a frame
	// that is neither request nor notification carries any — so both resolve to the default
	// revision and are answered by the old-revision 400 well above session creation. Asserted so
	// that stays true rather than being assumed.
	for _, msg := range []mcp.RPCMsg{
		{JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Result: json.RawMessage(`{}`)},
		{JSONRPC: "2.0"},
	} {
		other := h.postDeclaring(t, h.tokenFor(t, "agent-1"), msg)
		assert.Equal(t, http.StatusBadRequest, other.status,
			"a framing that can carry no declaration must not reach the declaring path at all")
	}
	assert.Zero(t, h.proxy.sessionCount())
	assert.Zero(t, h.upstreamOpens())
}

// A refusal on the creation path respects the framing it is answering.
//
// Reached with a revoked identity, which refuses at the kill gate. A request gets the JSON-RPC
// denial; anything else is acked bodyless — never a denial body for a message JSON-RPC forbids
// answering, and never the malformed `{"jsonrpc":""}` frame a zero RPCMsg becomes if it is
// written unconditionally.
func TestFirstRequestCreation_RefusalsRespectTheFraming(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarness(t)
	require.NoError(t, h.ks.KillAgent(context.Background(), "agent-1"))

	req := h.postDeclaring(t, h.tokenFor(t, "agent-1"), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"read_file"}`),
	})
	assert.Contains(t, req.body, capability.ErrCodeKillSwitch, "a request must be told why it was refused")

	// The notification never reaches the kill gate — the framing gate is above it — so what this
	// half pins is that being dropped is also answered bodyless. Both paths out of this arm have
	// to respect the framing, and they are different code.
	notif := h.postDeclaring(t, h.tokenFor(t, "agent-1"), mcp.RPCMsg{
		JSONRPC: "2.0", Method: "notifications/cancelled", Params: json.RawMessage(`{"requestId":1}`),
	})
	assert.Equal(t, http.StatusAccepted, notif.status)
	assert.NotContains(t, notif.body, `"jsonrpc"`,
		"a notification received a JSON-RPC error body for a message it may not be sent one for")
}

// The worker id is safe to print and safe to sign.
//
// It is built from claims an IdP signed, which says the IdP vouched for them — not that it
// bounded or sanitized them. The id reaches an operator's console through a %s and the audit
// record's session_id through a sanitizer that maps every control rune to a space, so a raw claim
// would be both a log-injection primitive and a way for two distinct workers to be recorded under
// one id.
func TestFirstRequestCreation_TheWorkerIDIsPrintableAndInjective(t *testing.T) {
	t.Parallel()
	route := &UpstreamRoute{name: "r1"}

	forged := "x\n[eunox] FORGED LOG LINE"
	key, ok := firstRequestWorkerKey(route, pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "https://idp", Subject: "alice", AgentID: forged}))
	require.True(t, ok)
	assert.NotContains(t, key, "\n", "a claim forged a console line into the worker id")
	assert.Equal(t, key, audit.SanitizeAuditField(key),
		"the worker id must survive audit-field sanitization unchanged, or session_id names something else")

	// Injective where sanitization is LOSSY: these two collapse to the same string under
	// SanitizeAuditField, so a key that relied on sanitizing would let two callers share one
	// worker, its quota and its upstream.
	tab, ok := firstRequestWorkerKey(route, pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "https://idp", Subject: "alice", AgentID: "a\tb"}))
	require.True(t, ok)
	soh, ok := firstRequestWorkerKey(route, pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "https://idp", Subject: "alice", AgentID: "a\x01b"}))
	require.True(t, ok)
	require.Equal(t, audit.SanitizeAuditField("a\tb"), audit.SanitizeAuditField("a\x01b"),
		"premise: these are the pair sanitization collapses")
	assert.NotEqual(t, tab, soh, "two identities sanitization cannot tell apart became one worker")

	// Bounded, and still injective past the bound: a validated claim is not a bounded one, and
	// the id becomes a map key, an audit field and a log line.
	long := strings.Repeat("a", 4096)
	longKey, ok := firstRequestWorkerKey(route, pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "https://idp", Subject: "alice", AgentID: long}))
	require.True(t, ok)
	assert.Less(t, len(longKey), 1024, "an unbounded claim produced an unbounded worker id")
	otherLong, ok := firstRequestWorkerKey(route, pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "https://idp", Subject: "alice", AgentID: long + "b"}))
	require.True(t, ok)
	assert.NotEqual(t, longKey, otherLong, "truncation made two identities one worker")
}

// The task-anchored arm encodes too.
//
// It is the arm that does NOT come through stableCallerIdentity: a task-anchored route resolves
// to the validated `task_id` claim verbatim, which is as caller-supplied as the rest. Encoding at
// workerKey is what makes this a property of every worker id rather than of remembering which
// arm produced it.
func TestFirstRequestCreation_TheTaskAnchoredKeyIsEncodedToo(t *testing.T) {
	t.Parallel()
	route := &UpstreamRoute{name: "r1", taskAnchored: true}
	key, ok := firstRequestWorkerKey(route, pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Issuer: "https://idp", Subject: "alice", AgentID: "agent-1", TaskID: "t\n[eunox] FORGED"}))
	require.True(t, ok)
	assert.NotContains(t, key, "\n", "a task id forged a console line into the worker id")
	assert.Equal(t, key, audit.SanitizeAuditField(key))
}

// A second request must not be served on a worker whose startup drift check has not finished.
//
// registerSession PUBLISHES before runDriftCheckOrTeardown, which was safe while ids were minted
// UUIDs no second request could name. A derived id can be named, so without the wait a request
// could run against an upstream whose tool list FM-5 has not compared to the manifest, and whose
// Tier-2 surface baseline is unset.
func TestFirstRequestCreation_AJoinerWaitsForEstablishment(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarness(t)
	sess := &httpSession{id: "w1", route: h.proxy.routes[""], established: make(chan struct{})}
	sess.initInProgress.Store(true)
	require.NoError(t, h.proxy.registerSession(sess, h.proxy.currentReapGen()))

	// While establishing, a joiner blocks rather than proceeding.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	assert.False(t, h.proxy.awaitEstablished(ctx, sess),
		"a joiner was released while the worker was still coming up")

	// Once established it is joinable — and only because it is still registered.
	h.proxy.finishEstablishing(sess)
	assert.True(t, h.proxy.awaitEstablished(context.Background(), sess))

	// A worker whose establishment ENDED IN TEARDOWN must not be joined: the signal means "no
	// longer coming up", never "came up".
	h.proxy.mu.Lock()
	delete(h.proxy.sessions, sess.id)
	h.proxy.mu.Unlock()
	assert.False(t, h.proxy.awaitEstablished(context.Background(), sess),
		"a joiner adopted a worker that was torn down while coming up")
}

// And the resolve path actually WAITS — asserted by driving firstRequestSession, not the helper.
//
// A cell that only exercises awaitEstablished proves the primitive works while the caller could
// have stopped calling it; that is exactly what the first version of the cell above did, and a
// mutation removing the wait from the resolve path left it green.
func TestFirstRequestCreation_TheResolvePathWaitsForEstablishment(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarness(t)
	route := h.proxy.routes[""]
	ctx := pdp.WithJWTClaims(capability.WithProtocolRevision(context.Background(), capability.Revision20260728),
		&pdp.JWTClaims{Issuer: "https://idp", Subject: "alice", AgentID: "agent-1"})
	key, ok := firstRequestWorkerKey(route, ctx)
	require.True(t, ok)

	// A worker for this key, registered but still coming up — the window registerSession opens
	// by publishing before the startup drift check runs.
	sess := &httpSession{id: key, route: route, established: make(chan struct{})}
	sess.initInProgress.Store(true)
	require.NoError(t, h.proxy.registerSession(sess, h.proxy.currentReapGen()))

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"read_file"}`)}
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	resolved := make(chan *httpSession, 1)
	go func() {
		resolved <- h.proxy.firstRequestSession(httptest.NewRecorder(), req.WithContext(ctx), route, capability.Revision20260728, msg)
	}()

	select {
	case got := <-resolved:
		t.Fatalf("firstRequestSession returned %v while the worker was still coming up; a request would run against an upstream whose drift check has not passed", got)
	case <-time.After(100 * time.Millisecond):
	}

	h.proxy.finishEstablishing(sess)
	select {
	case got := <-resolved:
		assert.Same(t, sess, got, "the waiter joined a different worker than the one it waited for")
	case <-time.After(2 * time.Second):
		t.Fatal("firstRequestSession never returned after establishment finished")
	}
}

// postDeclaring sends one arbitrary message from a declaring host, so a cell can choose the
// framing rather than always sending a well-formed request.
func (h *declaringHostHarness) postDeclaring(t *testing.T, token string, msg mcp.RPCMsg) declaringResponse {
	t.Helper()
	// The declaration rides in `params`, so a framing that carries none cannot declare — which is
	// itself the subject of one cell above. Left alone rather than given an empty object, so the
	// message stays the shape the caller asked for.
	if len(msg.Params) > 2 {
		msg.Params = json.RawMessage(string(msg.Params[:len(msg.Params)-1]) +
			`,"_meta":{"` + capability.MetaKeyProtocolVersion + `":"` + capability.Revision20260728.String() + `"}}`)
	}
	body, err := json.Marshal(msg)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", CTJSON)
	if msg.Method != "" {
		req.Header.Set(RoutingHeaderMethod, msg.Method)
	}
	if name := gjsonName(string(msg.Params)); name != "" {
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
	return declaringResponse{status: resp.StatusCode, body: buf.String(), sessionHeader: resp.Header.Get(SessionHeader)}
}

// The session-gate refusal is rate-limited, which it did not used to be.
//
// The old exemption rested on session ids being unguessable per-session UUIDs handed only to
// their creator, so driving this record needed a live victim id — a materially higher bar than
// the zero-session flood catAudience closes. Derived worker ids ended that: an attacker who can
// name a victim's issuer, subject and agent id can address that victim's worker directly, be
// refused by the owner binding, and drive one audit record per attempt holding no session at all.
//
// Driven the way an attacker would — by putting the victim's derived id in the session header —
// rather than by calling the recorder, since what is under test is whether the reachable path is
// bounded.
func TestFirstRequestCreation_TheSessionGateRefusalIsMetered(t *testing.T) {
	t.Parallel()
	h := newDeclaringHostHarnessWithTape(t)

	// A victim worker, established the ordinary way.
	require.Equal(t, http.StatusOK,
		h.call(t, "victim", capability.MethodToolsCall, `{"name":"read_file","arguments":{"path":"/tmp/x"}}`).status)
	victimKey, ok := firstRequestWorkerKey(h.proxy.routes[""], pdp.WithJWTClaims(context.Background(),
		&pdp.JWTClaims{Subject: "victim", AgentID: "victim"}))
	require.True(t, ok)
	require.NotNil(t, h.proxy.getSession(victimKey), "the victim worker's id is derivable, which is the premise")

	// An attacker naming it, refused by the owner binding, over and over.
	const attempts = 40
	for i := 0; i < attempts; i++ {
		h.postToSession(t, h.tokenFor(t, "attacker"), victimKey, mcp.RPCMsg{
			JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
			Params: json.RawMessage(`{"name":"read_file"}`),
		})
	}

	var gateDenies int
	for _, rec := range h.tape(t) {
		if d, ok := rec["details"].(map[string]interface{}); ok {
			if reason, _ := d["reason"].(string); reason == "session_owner_mismatch" {
				gateDenies++
			}
		}
	}
	require.NotZero(t, gateDenies, "no session-gate refusal was recorded; the attack path is not being exercised")
	assert.Less(t, gateDenies, attempts,
		"every attempt wrote a record: the session-gate refusal is an unbounded audit-flood primitive now that worker ids are derivable")
}

// postToSession addresses an EXISTING worker by id, which is how an attacker reaches another
// identity's session gate once ids are derivable.
func (h *declaringHostHarness) postToSession(t *testing.T, token, sessionID string, msg mcp.RPCMsg) declaringResponse {
	t.Helper()
	body, err := json.Marshal(msg)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(SessionHeader, sessionID)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return declaringResponse{status: resp.StatusCode, body: buf.String()}
}

// The SESSION-HEADER POST takes the same wait.
//
// A derived worker id is not confined to the path that derives it: a caller who computes it from
// their own claims can present it in Mcp-Session-Id, and that spelling reached the same
// mid-establishment worker through handleSessionPost with no wait at all — negotiation resolves
// fine, since omission inherits the pinned revision. Driven through the real handler for
// TheResolvePathWaitsForEstablishment's reason: a cell that exercises awaitEstablished alone
// proves the primitive works while this caller could have stopped calling it.
//
// The message is a SWALLOWED notification so the cell measures the wait rather than a forward:
// it runs the whole prologue and is answered 202 with no upstream involved.
func TestFirstRequestCreation_TheSessionHeaderPathWaitsForEstablishment(t *testing.T) {
	t.Parallel()
	proxy := newTestHTTPProxy()
	route := newBareTestRoute()
	sess := newTestSession(&httpSession{
		id: "w1", route: route, done: make(chan struct{}), established: make(chan struct{}),
	})
	sess.initInProgress.Store(true)
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, sess.id)
	w := httptest.NewRecorder()
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		proxy.handleSessionPost(w, req, route, sess.id,
			mcp.RPCMsg{JSONRPC: "2.0", Method: mcp.MethodNotificationsInitialized})
	}()

	select {
	case <-answered:
		t.Fatal("the POST was answered while the worker was still coming up; it ran against an upstream whose startup drift check had not passed")
	case <-time.After(100 * time.Millisecond):
	}

	proxy.finishEstablishing(sess)
	select {
	case <-answered:
	case <-time.After(2 * time.Second):
		t.Fatal("the POST never returned after establishment finished")
	}
	assert.Equal(t, http.StatusAccepted, w.Code, "body: %s", w.Body.String())
}

// So does the SSE GET, which is the one that gets served without asking for anything.
//
// newSession starts readUpstream BEFORE runDriftCheckOrTeardown, so the upstream is already
// broadcasting by the time the drift check runs. A subscriber registered in that window receives
// the not-yet-vetted upstream's notifications — the FM-5 rug-pull this proxy exists to catch,
// delivered to a host as though it had been checked.
func TestFirstRequestCreation_TheSSEGetPathWaitsForEstablishment(t *testing.T) {
	t.Parallel()
	proxy := newTestHTTPProxy()
	route := newBareTestRoute()
	done := make(chan struct{})
	sess := newTestSession(&httpSession{
		id: "w1", route: route, done: done, established: make(chan struct{}),
	})
	sess.initInProgress.Store(true)
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, sess.id)
	w := httptest.NewRecorder()
	streaming := make(chan struct{})
	go func() {
		defer close(streaming)
		proxy.handleMCPGet(w, req, route)
	}()

	select {
	case <-streaming:
		t.Fatal("the SSE GET returned while the worker was still coming up")
	case <-time.After(100 * time.Millisecond):
	}
	// The assertion that names the harm: no stream is attached to the unvetted upstream's
	// broadcast while it is unvetted.
	assert.False(t, sess.hasSubscribers(),
		"an SSE subscriber was registered on a worker whose startup drift check had not passed")

	proxy.finishEstablishing(sess)
	require.Eventually(t, sess.hasSubscribers, 2*time.Second, 5*time.Millisecond,
		"the stream never opened after establishment finished")

	close(done) // the upstream exits; the stream loop returns
	select {
	case <-streaming:
	case <-time.After(2 * time.Second):
		t.Fatal("the SSE GET never returned after its session ended")
	}
	assert.Equal(t, http.StatusOK, w.Code)
}

// A worker torn down WHILE coming up is served by neither leg.
//
// The wait's signal means "no longer coming up", never "came up" — a failed startup drift check
// ends establishment by tearing the session down. Each leg then gives the answer it ALREADY gives
// for a worker that is gone rather than a new one, which is what keeps an old-revision client's
// handling of this race unchanged: the POST the retryable JSON-RPC error its teardown race
// produces one gate further on, the GET resolveSessionForRoute's 404.
func TestFirstRequestCreation_AWorkerTornDownWhileComingUpIsNotServed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		msg        mcp.RPCMsg
		wantStatus int
		wantBody   string
	}{{
		name:       "session-header POST, request",
		msg:        mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: capability.MethodToolsCall},
		wantStatus: http.StatusOK, // a JSON-RPC error rides a 200; the code is the verdict
		wantBody:   `"code":-32000`,
	}, {
		// A framing JSON-RPC forbids answering is acked bodyless, as every other drop on this
		// leg is — never a denial body, and never the malformed {"jsonrpc":""} frame.
		name:       "session-header POST, notification",
		msg:        mcp.RPCMsg{JSONRPC: "2.0", Method: mcp.MethodNotificationsInitialized},
		wantStatus: http.StatusAccepted,
	}, {
		name:       "SSE GET",
		wantStatus: http.StatusNotFound,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newTornDownWorkerHarness(t, nil)

			w, answered := h.driveParked(t, tc.msg)
			h.tearDownWhileComingUp()
			awaitAnswer(t, answered)

			assert.Equal(t, tc.wantStatus, w.Code,
				"a worker torn down while coming up was served anyway; body: %s", w.Body.String())
			if tc.wantBody != "" {
				assert.Contains(t, w.Body.String(), tc.wantBody, "the answer must be retryable and correlatable to the caller's own request id")
			}
			if tc.msg.IsZero() {
				assert.False(t, h.sess.hasSubscribers(), "a stream was attached to a torn-down worker")
			}
		})
	}
}

// And a worker the kill store still names is answered KILL_SWITCH, on the tape, on BOTH legs.
//
// This is the half that decides where the failed-wait refusal lives. Reusing the unresolved-id
// answer would have recorded the kill under an EMPTY signed session_id (that helper's subject is
// claimedSession, since its id resolved nothing) — and on the declaring re-entry, which carries
// no session header at all, under nothing. Routing the GET's failed wait to a bare status would
// have dropped the leg's only kill record outright, since its own kill check sits below the wait.
func TestFirstRequestCreation_AKilledWorkerTornDownWhileComingUpRecordsTheKill(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		msg        mcp.RPCMsg
		wantStatus int
	}{{
		name:       "session-header POST",
		msg:        mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: capability.MethodToolsCall},
		wantStatus: http.StatusOK,
	}, {
		name:       "SSE GET",
		wantStatus: http.StatusForbidden,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ks := killswitch.NewInMemory()
			h := newTornDownWorkerHarness(t, ks)

			w, answered := h.driveParked(t, tc.msg)
			require.NoError(t, ks.KillSession(context.Background(), h.sess.id))
			h.tearDownWhileComingUp()
			awaitAnswer(t, answered)

			assert.Equal(t, tc.wantStatus, w.Code, "body: %s", w.Body.String())

			var killRecords []map[string]interface{}
			for _, rec := range h.tape(t) {
				if rec["denial_code"] == capability.ErrCodeKillSwitch {
					killRecords = append(killRecords, rec)
				}
			}
			require.Len(t, killRecords, 1,
				"a kill reaping a worker mid-establishment left no KILL_SWITCH record; the leg's own kill check sits below the wait")
			// The subject is the whole point: this id RESOLVED a live registration and cleared
			// both session gates, so it is fact. Left as a claim it lands in details only, and an
			// operator cannot join this refusal to the traffic that preceded it.
			assert.Equal(t, h.sess.id, killRecords[0]["session_id"],
				"the kill was recorded against an unverified id for a worker this proxy established")
		})
	}
}

// ── the torn-down-worker harness ────────────────────────────────────────────

// tornDownWorkerHarness is the mid-establishment fixture the two tables above share: a worker
// registered but still coming up, on a route whose sink is readable. ks may be nil for the cells
// that arm no kill.
type tornDownWorkerHarness struct {
	proxy   *HTTPProxy
	route   *UpstreamRoute
	sess    *httpSession
	sink    *audit.Sink
	logPath string
}

func newTornDownWorkerHarness(t *testing.T, ks killswitch.Manager) *tornDownWorkerHarness {
	t.Helper()
	sink, logPath := newTempAuditSink(t)
	h := &tornDownWorkerHarness{proxy: newTestHTTPProxy(), sink: sink, logPath: logPath}
	h.route = &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{sink: sink, upstream: "up1"}}
	if ks != nil {
		h.route.pdp = newTestManifestPDPWithKS(ks)
	}
	h.sess = newTestSession(&httpSession{
		id: "w1", route: h.route, done: make(chan struct{}), established: make(chan struct{}),
	})
	h.sess.initInProgress.Store(true)
	h.proxy.mu.Lock()
	h.proxy.sessions[h.sess.id] = h.sess
	h.proxy.mu.Unlock()
	return h
}

// driveParked launches the leg msg selects — a zero message is the SSE GET, which carries no
// JSON-RPC envelope — and asserts it is still parked while the worker is coming up.
func (h *tornDownWorkerHarness) driveParked(t *testing.T, msg mcp.RPCMsg) (w *httptest.ResponseRecorder, answered chan struct{}) {
	t.Helper()
	method := http.MethodGet
	if !msg.IsZero() {
		method = http.MethodPost
	}
	req := httptest.NewRequest(method, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, h.sess.id)
	w, answered = httptest.NewRecorder(), make(chan struct{})
	go func() {
		defer close(answered)
		if msg.IsZero() {
			h.proxy.handleMCPGet(w, req, h.route)
			return
		}
		h.proxy.handleSessionPost(w, req, h.route, h.sess.id, msg)
	}()
	select {
	case <-answered:
		t.Fatal("answered while the worker was still coming up")
	case <-time.After(parkedWorkerSettle):
	}
	return w, answered
}

// tearDownWhileComingUp does what a failed startup drift check does: tear the worker out of the
// registry, then end its establishing window.
func (h *tornDownWorkerHarness) tearDownWhileComingUp() {
	h.proxy.mu.Lock()
	delete(h.proxy.sessions, h.sess.id)
	h.proxy.mu.Unlock()
	h.proxy.finishEstablishing(h.sess)
}

func (h *tornDownWorkerHarness) tape(t *testing.T) []map[string]interface{} {
	t.Helper()
	_ = h.sink.Close()
	return readAuditRecords(t, h.logPath)
}

// parkedWorkerSettle is how long a cell watches a leg stay parked before releasing it. Long
// enough that a leg which does not wait has certainly answered, short enough to pay per cell.
const parkedWorkerSettle = 50 * time.Millisecond

func awaitAnswer(t *testing.T, answered chan struct{}) {
	t.Helper()
	select {
	case <-answered:
	case <-time.After(2 * time.Second):
		t.Fatal("never returned after establishment ended in teardown")
	}
}
