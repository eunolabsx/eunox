// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPUpstream_BoundsInflightPosts verifies the bridge caps concurrent POST
// goroutines at maxInflightPosts: a host firing many notifications cannot push
// more than maxInflightPosts requests into the upstream at once (the rest block on
// the semaphore until a slot frees), so the in-flight goroutine/connection
// footprint stays bounded.
func TestHTTPUpstream_BoundsInflightPosts(t *testing.T) {
	var inflight, peak atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inflight.Add(1)
		for { // record the high-water mark of concurrent in-flight requests
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release // hold the request open until the test releases it
		inflight.Add(-1)
		w.WriteHeader(http.StatusAccepted) // notification ack
	}))
	defer srv.Close()

	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer h.close()

	// Fire 2x the cap of notifications (ID nil, so post() returns after the POST
	// with no response correlation). Each Write spawns a semaphore-bounded post().
	for i := 0; i < 2*maxInflightPosts; i++ {
		go func() { _ = h.Write(mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/test"}) }()
	}

	// Exactly maxInflightPosts reach the blocked handler; the rest wait on the sem.
	require.Eventually(t, func() bool {
		return inflight.Load() == int64(maxInflightPosts)
	}, 3*time.Second, 5*time.Millisecond)

	// Give any over-cap goroutine a chance to (incorrectly) slip through.
	time.Sleep(50 * time.Millisecond)
	assert.LessOrEqual(t, peak.Load(), int64(maxInflightPosts),
		"in-flight POSTs must never exceed maxInflightPosts")

	close(release) // let them all drain
}

// TestStdioProxy_HTTPUpstream_CallRoundTrip drives a StdioProxy whose upstream is
// a remote HTTP MCP server (transport: stdio host → http upstream), exercising the
// httpUpstream bridge end to end: connectUpstream, the initialize handshake, the
// readUpstream loop, and callUpstream's pending/response routing — all over HTTP
// rather than a subprocess pipe.
func TestStdioProxy_HTTPUpstream_CallRoundTrip(t *testing.T) {
	up := newFakeUpstreamForJWT(t)
	defer up.srv.Close()

	p := &StdioProxy{
		sessionID:   "s1",
		upstreamURL: up.srv.URL,
	}

	// Mirror Start's upstream sequence: connect, initialize, then start the
	// background read loop.
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	if err := p.initUpstream(context.Background()); err != nil {
		t.Fatalf("initUpstream: %v", err)
	}
	if p.upHTTP == nil {
		t.Fatal("expected HTTP upstream bridge to be set")
	}
	if p.upHTTP.sessID == "" {
		t.Error("expected upstream session id captured from initialize response")
	}

	p.upstreamDone = make(chan struct{})
	go func() {
		defer close(p.upstreamDone)
		p.readUpstream(context.Background())
	}()
	defer p.closeUpstreamInput()

	req := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`7`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file","arguments":{}}`),
	}
	resp, err := p.callUpstream(context.Background(), req)
	if err != nil {
		t.Fatalf("callUpstream: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}
	// callUpstream rewrites the outbound id to a proxy-generated upstream nonce
	// and routes the response back by that nonce, so a late response for a
	// timed-out call cannot be misrouted into a later request reusing the host id.
	// The host-facing id is restored by the shared forward core (enforcedForwardCore
	// / dispatchList), not by callUpstream — so the response here legitimately
	// carries the nonce, not the original 7.
	if mcp.MsgKey(resp.ID) == mcp.MsgKey(mcp.RawJSON(`7`)) {
		t.Errorf("response ID = %s; callUpstream should route by the proxy nonce, not echo the host id", mcp.MsgKey(resp.ID))
	}
	if resp.Result == nil {
		t.Error("expected a result from the upstream tool call")
	}
}

// TestHTTPUpstream_Post_MismatchedResponseIDRejected is the regression for the
// bridge silently rebinding a mismatched upstream response id to the caller's
// request id. A spec-violating upstream that answers request id 7 with a response
// carrying id 99 must surface an internal error keyed to the request id — never a
// result falsely labeled as belonging to request 7.
func TestHTTPUpstream_Post_MismatchedResponseIDRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Echo a deliberately wrong id regardless of the request's id.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":99,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer srv.Close()

	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer h.close()

	req := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`7`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"x","arguments":{}}`),
	}
	// incoming is buffered, so post can run synchronously before Read drains it.
	h.post(context.Background(), req)

	got, err := h.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Error == nil {
		t.Fatalf("expected an error response for a mismatched upstream id, got result: %+v", got)
	}
	if mcp.MsgKey(got.ID) != mcp.MsgKey(mcp.RawJSON(`7`)) {
		t.Errorf("error response id = %s, want 7 (the caller's request id)", mcp.MsgKey(got.ID))
	}
	if got.Result != nil {
		t.Errorf("a mismatched result must not be bound to the request, got result %s", got.Result)
	}
}

// TestHTTPUpstream_Post_MismatchedErrorIDPreserved verifies the error-shape half
// of the fail-closed id-mismatch handling: when the upstream returns an error
// response whose id does not echo the request (here a null id), the bridge REFUSES it
// rather than re-stamping the request id and delivering the upstream's crafted error —
// re-stamping would let an adversarial upstream inject one caller's error into
// another's reply (cross-call leakage). The caller receives a generic internal error
// bound to its OWN request id (7), not the upstream's -32601.
func TestHTTPUpstream_Post_RejectsMismatchedErrorID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"Method not found"}}`))
	}))
	defer srv.Close()

	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer h.close()

	req := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`7`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"x","arguments":{}}`),
	}
	h.post(context.Background(), req)

	got, err := h.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Error == nil {
		t.Fatal("expected an error response delivered to the caller")
	}
	// The upstream's crafted -32601 "Method not found" must NOT be forwarded verbatim;
	// the caller gets a generic internal error instead.
	if got.Error.Code == -32601 || got.Error.Message == "Method not found" {
		t.Errorf("a mismatched upstream error must be refused, not forwarded; got code=%d msg=%q",
			got.Error.Code, got.Error.Message)
	}
	// The delivered error is still bound to THIS caller's request id (7), never the
	// upstream's null id.
	if mcp.MsgKey(got.ID) != mcp.MsgKey(mcp.RawJSON(`7`)) {
		t.Errorf("error response id = %s, want 7 (the caller's request id)", mcp.MsgKey(got.ID))
	}
}

// TestHTTPUpstream_Post_EmptyBodySurfacesObservedError verifies that a 200 OK whose
// body is {} (no jsonrpc/result/error fields) is surfaced to the host as an error
// that describes what was actually observed — an empty/non-JSON-RPC response — and
// NOT as a misleading "202 Accepted" (a real 202-to-a-request is turned into an
// error by DoMCPHTTP and never reaches this arm).
func TestHTTPUpstream_Post_EmptyBodySurfacesObservedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer h.close()

	req := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`7`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"x","arguments":{}}`),
	}
	h.post(context.Background(), req)

	got, err := h.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Error == nil {
		t.Fatalf("expected an error response for an empty 200-OK body, got result: %+v", got)
	}
	if got.Result != nil {
		t.Errorf("an empty/non-JSON-RPC body must not forward a result, got %s", got.Result)
	}
	if strings.Contains(got.Error.Message, "202") {
		t.Errorf("error message must not claim a 202 was returned, got: %q", got.Error.Message)
	}
	if !strings.Contains(got.Error.Message, "empty or non-JSON-RPC") {
		t.Errorf("error message should describe the observed empty/non-JSON-RPC response, got: %q", got.Error.Message)
	}
	if mcp.MsgKey(got.ID) != mcp.MsgKey(mcp.RawJSON(`7`)) {
		t.Errorf("error response id = %s, want 7 (the caller's request id)", mcp.MsgKey(got.ID))
	}
}

// TestHTTPUpstream_Post_MethodBearingReplyRejected verifies the bridge fails closed
// on a reply that echoes the request's id but ALSO carries a `method` field. Such a
// reply is request/notification shape, not a response; if queued onto `incoming`,
// readUpstream would classify it as a server-initiated request and route it to the
// host — a forged server-initiated request the bridge is documented never to deliver.
// The upstream knows the proxy-generated id (it was just sent it), so id-equality
// alone cannot catch this: the fix gates on shape (IsResponse) and fails closed.
func TestHTTPUpstream_Post_MethodBearingReplyRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Echo the request's id (7) but smuggle a method: a forged sampling request.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage","params":{}}`))
	}))
	defer srv.Close()

	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer h.close()

	req := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`7`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"x","arguments":{}}`),
	}
	h.post(context.Background(), req)

	got, err := h.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Method != "" {
		t.Fatalf("a method-bearing reply must NOT be delivered verbatim (it would be routed as a server-initiated request), got method %q", got.Method)
	}
	if got.Error == nil {
		t.Fatalf("expected an error response for a method-bearing reply, got: %+v", got)
	}
	if !strings.Contains(got.Error.Message, "non-response reply") {
		t.Errorf("error message should describe the rejected non-response reply, got: %q", got.Error.Message)
	}
	if mcp.MsgKey(got.ID) != mcp.MsgKey(mcp.RawJSON(`7`)) {
		t.Errorf("error response id = %s, want 7 (the caller's request id)", mcp.MsgKey(got.ID))
	}
}

// TestHTTPUpstream_Post_ErrorReasonIsHostSafe pins the disclosure fix: when the
// upstream POST fails (here a non-2xx status whose body carries internal detail),
// the synthesized error the host receives must be classified through the shared
// upstreamErrInfo helper — a generic "upstream error" — never the raw err.Error(),
// which for a remote HTTP upstream can embed the endpoint URL and up to 64 KiB of
// upstream body. Previously the arm forwarded "upstream error: "+err.Error()
// verbatim, leaking both to the host.
func TestHTTPUpstream_Post_ErrorReasonIsHostSafe(t *testing.T) {
	const secret = "SECRET-INTERNAL-HOSTNAME-db.internal.corp:5432"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(secret)) // upstream body DoMCPHTTP folds into its error text
	}))
	defer srv.Close()

	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer h.close()

	req := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`7`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"x","arguments":{}}`),
	}
	h.post(context.Background(), req)

	got, err := h.Read()
	require.NoError(t, err)
	require.NotNil(t, got.Error, "expected a synthesized error response for a failed upstream POST")
	assert.NotContains(t, got.Error.Message, secret, "raw upstream body must never reach the host")
	assert.NotContains(t, got.Error.Message, srv.URL, "upstream endpoint URL must never reach the host")
	assert.Equal(t, "upstream error", got.Error.Message, "host sees only the generic failure class")
	assert.Equal(t, jsonRPCCodeInternalError, got.Error.Code)
	assert.Equal(t, mcp.MsgKey(mcp.RawJSON(`7`)), mcp.MsgKey(got.ID), "error must be bound to the caller's request id")
}

// TestStdioProxy_HTTPUpstream_UnreachableSurfacesError verifies that a call to an
// unreachable HTTP upstream surfaces the transport failure as callUpstream's ERROR
// (not a nil-error synthesized response), rather than hanging until the per-call
// timeout. Returning the error is what makes enforcedForwardCore record a
// deny/UPSTREAM_ERROR — matching the gateway's callRemoteUpstream path — instead of
// an allow carrying upstream_error_code. upstreamErrInfo must classify it as an infra
// denial so the two transports agree on the record shape.
func TestStdioProxy_HTTPUpstream_UnreachableSurfacesError(t *testing.T) {
	p := &StdioProxy{
		sessionID:   "s1",
		upstreamURL: "http://127.0.0.1:1", // nothing listening
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	p.upstreamDone = make(chan struct{})
	go func() {
		defer close(p.upstreamDone)
		p.readUpstream(context.Background())
	}()
	defer p.closeUpstreamInput()

	_, err := p.callUpstream(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"x","arguments":{}}`),
	})
	if err == nil {
		t.Fatal("expected callUpstream to return a transport error for an unreachable upstream (records deny/UPSTREAM_ERROR)")
	}
	// The same classifier both transports feed into enforcedForwardCore must bucket
	// this as an infra denial, so the stdio bridge and the gateway agree on the code.
	code, reason, _ := upstreamErrInfo(err, p.upstreamTimeMs)
	if !IsInfraDenialCode(code) {
		t.Fatalf("upstreamErrInfo(%v) = %q, want an infra denial code", err, code)
	}
	if strings.Contains(reason, p.upstreamURL) {
		t.Fatalf("host-facing reason %q must not leak the upstream endpoint", reason)
	}
}

// TestStdioProxy_HTTPUpstream_InfraFailureRecordsDeny is the record-shape assertion
// for the stdio-to-HTTP bridge: an unreachable upstream, driven through the shared
// enforcedForwardCore exactly as a real tools/call would be, must record a
// deny/UPSTREAM_ERROR (not an allow carrying upstream_error_code) so the stdio
// transport and the gateway agree on how an infra failure appears on the tape.
func TestStdioProxy_HTTPUpstream_InfraFailureRecordsDeny(t *testing.T) {
	p := &StdioProxy{
		sessionID:   "s1",
		upstreamURL: "http://127.0.0.1:1", // nothing listening
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	p.upstreamDone = make(chan struct{})
	go func() {
		defer close(p.upstreamDone)
		p.readUpstream(context.Background())
	}()
	defer p.closeUpstreamInput()

	rec := &fwdRecorder{}
	fp := forwardParams{rec: rec, sessionID: "s1", callUpstream: p.callUpstream}
	resp := enforcedForwardCore(context.Background(), fp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	require.NotNil(t, resp.Error, "host must receive an upstream-error response")
	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision, "an infra failure must record a deny, matching the gateway")
	assert.True(t, IsInfraDenialCode(rec.records[0].code), "deny must carry an infra denial code, got %q", rec.records[0].code)
}

// TestHTTPUpstream_CloseTerminatesUpstreamSession regression for the
// stdio-to-HTTP bridge: close() previously only canceled local work and never
// sent MCP's session-termination DELETE, so the upstream session leaked until
// the remote independently expired it. close() must now issue a bounded DELETE
// carrying the captured upstream session ID.
func TestHTTPUpstream_CloseTerminatesUpstreamSession(t *testing.T) {
	t.Parallel()
	var deletes int32
	var gotSID atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			atomic.AddInt32(&deletes, 1)
			gotSID.Store(r.Header.Get(SessionHeader))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	h.sessID = "up-sess-123" // captured during initialize in production

	h.close() // close runs the DELETE synchronously before returning

	require.Equal(t, int32(1), atomic.LoadInt32(&deletes), "close must send exactly one upstream session DELETE")
	assert.Equal(t, "up-sess-123", gotSID.Load(), "DELETE must carry the captured upstream session id")
}

// TestHTTPUpstream_CloseNoSessionNoDelete verifies a bridge that never captured
// an upstream session id (initialize never completed) sends no DELETE — there is
// nothing to terminate.
func TestHTTPUpstream_CloseNoSessionNoDelete(t *testing.T) {
	t.Parallel()
	var deletes int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			atomic.AddInt32(&deletes, 1)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	h.close()

	assert.Equal(t, int32(0), atomic.LoadInt32(&deletes), "no upstream session id ⟹ no DELETE")
}

// TestHTTPUpstream_WriteSyncIsSynchronous regression: the handshake's
// notifications/initialized was sent via the fire-and-forget Write, which returns
// before the POST completes, so the first host request could reach the upstream
// before the notification. writeSync must not return until the POST has been
// delivered.
func TestHTTPUpstream_WriteSyncIsSynchronous(t *testing.T) {
	t.Parallel()
	received := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m mcp.RPCMsg
		_ = json.NewDecoder(r.Body).Decode(&m)
		received <- m.Method
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	notif, err := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	require.NoError(t, err)

	require.NoError(t, h.writeSync(context.Background(), notif))

	// The notification must already have reached the upstream by the time
	// writeSync returns (a non-blocking read succeeds). The async Write would not
	// guarantee this.
	select {
	case m := <-received:
		assert.Equal(t, "notifications/initialized", m)
	default:
		t.Fatal("writeSync returned before notifications/initialized reached the upstream")
	}
}

// TestHTTPUpstream_BoundedPostReleasesSlotOnStall is the regression for the
// notification-path wedge: a fire-and-forget POST to an upstream that accepts the
// connection but never sends response headers must release its maxInflightPosts
// slot via its own deadline, even when --upstream-timeout is disabled (so the
// shared transport carries no ResponseHeaderTimeout). The Write path passes
// notifyPostTimeout; here a short bound exercises the same mechanism so the test
// runs fast. Without the bound the slot would be pinned until close() and the read
// loop would eventually wedge on a full semaphore.
func TestHTTPUpstream_BoundedPostReleasesSlotOnStall(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block // never send response headers — simulate a stalling upstream
	}))
	defer srv.Close()
	defer close(block)

	// timeout disabled (0): no transport ResponseHeaderTimeout, the regression's config.
	h := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	defer h.close()

	// Fire a bounded fire-and-forget POST; the slot must free when the bound fires.
	h.spawnPost(h.ctx, mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/progress"}, 50*time.Millisecond)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.sem) == 0 { // slot released
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("bounded notification POST did not release its semaphore slot against a stalling upstream; the slot would be pinned and the read loop could wedge")
}
