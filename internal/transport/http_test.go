// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// ── msgKey ────────────────────────────────────────────────────────────────

func TestMsgKey_NilID(t *testing.T) {
	t.Parallel()
	if got := mcp.MsgKey(nil); got != "" {
		t.Errorf("msgKey(nil) = %q, want \"\"", got)
	}
}

func TestMsgKey_StringID(t *testing.T) {
	t.Parallel()
	// MsgKey canonicalizes a string ID by its decoded value under an "s:" type
	// prefix, so equivalent encodings of the same string correlate.
	id := mcp.RawJSON(`"req-1"`)
	if got := mcp.MsgKey(id); got != "s:req-1" {
		t.Errorf("msgKey = %q, want %q", got, "s:req-1")
	}
}

// newTestSession wires the session-scoped teardown context (sessCtx/sessCancel) onto a
// directly-constructed test session, so a test-built httpSession carries the same
// always-live sessCtx that newSession/newRemoteSession establish in production. It
// returns s so a struct literal can be wrapped inline: newTestSession(&httpSession{ ... }).
// Production code can then rely on sessCtx being non-nil and drop the nil-guards that only
// existed for the old directly-constructed literals. The cancel is not registered with a
// cleanup: a leaked cancelCtx spawns no goroutine and is reclaimed at process exit, and
// tests exercising teardown call sess.close (which cancels it) themselves.
func newTestSession(s *httpSession) *httpSession {
	ctx, cancel := context.WithCancel(context.Background())
	s.sessCtx, s.sessCancel = ctx, cancel
	return s
}

// newClosedTestSession builds a test session whose teardown has already fired: sessCtx is
// wired and immediately canceled, so an in-flight subprocess call (awaitNonced selecting on
// teardownDone) returns errUpstreamExited at once. This is the production-faithful successor
// to the older "pre-close the done channel" idiom — production signals a torn-down upstream
// by canceling sessCtx (readUpstream's defer), not by the done channel alone, which no longer
// backs teardownDone. Use it for the "session already closed / upstream gone" tests.
func newClosedTestSession(s *httpSession) *httpSession {
	newTestSession(s)
	s.sessCancel()
	return s
}

// noFlushWriter is an http.ResponseWriter that does NOT implement http.Flusher.
type noFlushWriter struct {
	code   int
	header http.Header
	body   bytes.Buffer
}

func newNoFlushWriter() *noFlushWriter               { return &noFlushWriter{header: make(http.Header), code: 200} }
func (w *noFlushWriter) Header() http.Header         { return w.header }
func (w *noFlushWriter) Write(p []byte) (int, error) { return w.body.Write(p) }
func (w *noFlushWriter) WriteHeader(code int)        { w.code = code }

// ── handleMCPGet: session found but no Flusher ───────────────────────────

func TestHTTPHandleMCPGet_NoFlusher(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:   "known-sess",
		done: make(chan struct{}),
	})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "known-sess")
	// noFlushWriter does NOT implement http.Flusher → should return 500.
	w := newNoFlushWriter()
	proxy.handleMCPGet(w, req, nil)
	if w.code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-Flusher ResponseWriter, got %d", w.code)
	}
}

// TestHTTPHandleMCPGet_KnownSession covers the SSE path when sess.done is closed.
func TestHTTPHandleMCPGet_KnownSession_Done(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	done := make(chan struct{})
	close(done) // immediately done → select picks <-sess.done
	sess := newTestSession(&httpSession{
		id:   "done-sess",
		done: done,
	})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "done-sess")
	w := httptest.NewRecorder() // implements Flusher → SSE path
	proxy.handleMCPGet(w, req, nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for SSE stream, got %d", w.Code)
	}
}

// ── handleMCPDelete: known session ────────────────────────────────────────

func TestHTTPHandleMCPDelete_KnownSession(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions:   make(map[string]*httpSession),
		shutdownMs: 50,
	}
	sess := newTestSession(&httpSession{
		id:           "del-sess",
		done:         make(chan struct{}),
		upHTTPClient: &http.Client{}, // remote mode → close() just closes done
	})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "del-sess")
	w := httptest.NewRecorder()
	proxy.handleMCPDelete(w, req, nil)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	proxy.mu.Lock()
	_, exists := proxy.sessions["del-sess"]
	proxy.mu.Unlock()
	if exists {
		t.Error("session should have been removed")
	}
}

// ── handleKill ────────────────────────────────────────────────────────────

func TestHTTPHandleKill_NonPOST(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	req := httptest.NewRequest(http.MethodGet, "/control/kill", http.NoBody)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	proxy.handleKill(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTPHandleKill_InvalidJSON(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession), controlToken: testControlToken}
	req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString("bad json"))
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set(ControlTokenHeader, testControlToken)
	w := httptest.NewRecorder()
	proxy.handleKill(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTPHandleKill_NoSessionIDOrAll(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession), controlToken: testControlToken}
	body := `{"sessionId":"","all":false}`
	req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(body))
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set(ControlTokenHeader, testControlToken)
	w := httptest.NewRecorder()
	proxy.handleKill(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHTTPHandleKill_RejectsTrailingJSONTokens pins the fail-closed fix: a
// /control/kill body is exactly one JSON value, so a legitimate {"sessionId":"s1"}
// followed by a smuggled second value (e.g. {"all":true}) must be rejected with 400
// before either object is acted on — never silently executing the first value while
// dropping the second.
func TestHTTPHandleKill_RejectsTrailingJSONTokens(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession), controlToken: testControlToken, ks: killswitch.NewInMemory()}
	body := `{"sessionId":"s1"} {"all":true}`
	req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(body))
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set(ControlTokenHeader, testControlToken)
	w := httptest.NewRecorder()
	proxy.handleKill(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("trailing JSON token: status = %d, want 400 (body=%q)", w.Code, w.Body.String())
	}
	status, err := proxy.ks.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.GlobalActive {
		t.Error("malformed body with a smuggled {\"all\":true} must not activate the global kill")
	}
}

// killWriteErrSwitch is a kill-switch double whose write operations
// (ActivateGlobal / KillSession) fail, modeling a Redis backend that is
// unreachable when an operator issues an emergency stop.
type killWriteErrSwitch struct{}

func (killWriteErrSwitch) ShouldBlock(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (killWriteErrSwitch) ActivateGlobal(_ context.Context) error   { return errKillSwitchFailed }
func (killWriteErrSwitch) DeactivateGlobal(_ context.Context) error { return nil }
func (killWriteErrSwitch) KillAgent(_ context.Context, _ string) error {
	return errKillSwitchFailed
}
func (killWriteErrSwitch) ReviveAgent(_ context.Context, _ string) error { return nil }
func (killWriteErrSwitch) KillSession(_ context.Context, _ string) error {
	return errKillSwitchFailed
}
func (killWriteErrSwitch) ReviveSession(_ context.Context, _ string) error { return nil }
func (killWriteErrSwitch) Reset(_ context.Context) error                   { return nil }
func (killWriteErrSwitch) Status(_ context.Context) (*killswitch.Status, error) {
	return &killswitch.Status{}, nil
}

// TestHTTPHandleKill_ActivateGlobalErrorPropagated pins that a kill-store
// write failure on `{"all":true}` must surface as a 500, not a misleading
// {"ok":true}. Returning success on a failed emergency stop would leave the
// operator believing the proxy is halted while it keeps serving requests.
func TestHTTPHandleKill_ActivateGlobalErrorPropagated(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession), ks: killWriteErrSwitch{}, controlToken: testControlToken}
	req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(`{"all":true}`))
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set(ControlTokenHeader, testControlToken)
	w := httptest.NewRecorder()
	proxy.handleKill(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on kill-store failure, got %d (body=%q)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"ok":true`) {
		t.Errorf("must not report ok:true on a failed kill, got %q", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "kill switch backend unavailable") {
		t.Errorf("500 body must not leak the raw backend error, got %q", w.Body.String())
	}
}

// TestHTTPHandleKill_KillSessionErrorPropagated is the per-session counterpart of
// the above.
func TestHTTPHandleKill_KillSessionErrorPropagated(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession), ks: killWriteErrSwitch{}, controlToken: testControlToken}
	req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(`{"sessionId":"s1"}`))
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set(ControlTokenHeader, testControlToken)
	w := httptest.NewRecorder()
	proxy.handleKill(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on kill-store failure, got %d (body=%q)", w.Code, w.Body.String())
	}
}

// TestHTTPHandleKill_GlobalKill_NoWiretapCaveat pins that the kill response no
// longer carries a wiretap_routes_unaffected caveat: the wiretap PDP is now wired
// to the kill switch (NewAlwaysAllowPDP), so a global kill stops every route,
// including a policyless wiretap one, and there is no partial-coverage to flag.
func TestHTTPHandleKill_GlobalKill_NoWiretapCaveat(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	proxy := &HTTPProxy{
		sessions:     make(map[string]*httpSession),
		ks:           ks,
		controlToken: testControlToken,
		routes:       map[string]*UpstreamRoute{"wiretap": {name: "wiretap", pdp: pdp.NewAlwaysAllowPDP(ks)}},
	}
	req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(`{"all":true}`))
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set(ControlTokenHeader, testControlToken)
	w := httptest.NewRecorder()
	proxy.handleKill(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v (body=%q)", err, w.Body.String())
	}
	if _, present := resp["wiretap_routes_unaffected"]; present {
		t.Errorf("kill response must not carry wiretap_routes_unaffected anymore, got %q", w.Body.String())
	}
	if resp["killed"] != "all" {
		t.Errorf("expected killed:all, got %v", resp["killed"])
	}
}

// TestHTTPHandleKill_ReclaimsSlotWithIdleReapingDisabled is the regression for the
// kill-triggered session-exhaustion DoS: with sessionIdleTimeoutMs == 0 (a documented,
// valid config) the idle reaper never runs, so a kill that relied solely on it left the
// session's upstream and its maxSessions slot pinned until process exit. handleKill must
// tear the session down itself, freeing the slot.
func TestHTTPHandleKill_ReclaimsSlotWithIdleReapingDisabled(t *testing.T) {
	t.Parallel()
	newRemoteSess := func(id string) *httpSession {
		// Remote-mode session: close() takes the upHTTPClient branch (no subprocess) and,
		// with an empty upstreamSessID, skips the upstream DELETE — a safe, non-blocking
		// teardown for the test.
		return newTestSession(&httpSession{id: id, upHTTPClient: &http.Client{}, done: make(chan struct{})})
	}

	t.Run("per-session kill frees the slot", func(t *testing.T) {
		ks := killswitch.NewInMemory()
		proxy := &HTTPProxy{
			sessions:      map[string]*httpSession{"s1": newRemoteSess("s1")},
			ks:            ks,
			controlToken:  testControlToken,
			sessionIdleMs: 0, // idle reaping disabled
			maxSessions:   1,
		}
		req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(`{"sessionId":"s1"}`))
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set(ControlTokenHeader, testControlToken)
		w := httptest.NewRecorder()
		proxy.handleKill(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
		}
		if proxy.getSession("s1") != nil || proxy.sessionCount() != 0 {
			t.Fatalf("killed session must be reaped from the registry (count=%d) even with idle reaping disabled", proxy.sessionCount())
		}
	})

	t.Run("global kill frees every slot", func(t *testing.T) {
		ks := killswitch.NewInMemory()
		proxy := &HTTPProxy{
			sessions:      map[string]*httpSession{"s1": newRemoteSess("s1"), "s2": newRemoteSess("s2")},
			ks:            ks,
			controlToken:  testControlToken,
			sessionIdleMs: 0,
		}
		req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(`{"all":true}`))
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set(ControlTokenHeader, testControlToken)
		w := httptest.NewRecorder()
		proxy.handleKill(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
		}
		if proxy.sessionCount() != 0 {
			t.Fatalf("a global kill must reap all sessions; count=%d", proxy.sessionCount())
		}
	})
}

// TestHTTPHandleKill_PerSession_NoWiretapCaveat is the per-session companion: the
// caveat is gone on both the global and per-session branches.
func TestHTTPHandleKill_PerSession_NoWiretapCaveat(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	proxy := &HTTPProxy{
		sessions:     make(map[string]*httpSession),
		ks:           ks,
		controlToken: testControlToken,
		routes:       map[string]*UpstreamRoute{"wiretap": {name: "wiretap", pdp: pdp.NewAlwaysAllowPDP(ks)}},
	}
	req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(`{"sessionId":"sess-7"}`))
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set(ControlTokenHeader, testControlToken)
	w := httptest.NewRecorder()
	proxy.handleKill(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v (body=%q)", err, w.Body.String())
	}
	if _, present := resp["wiretap_routes_unaffected"]; present {
		t.Errorf("per-session kill response must not carry wiretap_routes_unaffected, got %q", w.Body.String())
	}
	if resp["killed"] != "sess-7" {
		t.Errorf("expected killed:sess-7, got %v", resp["killed"])
	}
}

// ── forwardNotification remote mode ───────────────────────────────────────

func TestHTTPForwardNotification_RemoteMode(t *testing.T) {
	t.Parallel()
	// Set up a fake upstream that accepts POST notifications (returns 202).
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		done:         make(chan struct{}),
		route:        &UpstreamRoute{transport: "http", upstreamURL: srv.URL},
		pending:      make(map[string]chan upstreamResult),
		upHTTPClient: &http.Client{Timeout: 5 * time.Second},
		proxy:        proxy,
	})

	msg := mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/initialized"}
	sess.forwardNotification(context.Background(), msg)
	// Remote mode: callRemoteUpstream sends the notification; any error is ignored.
	// Coverage goal: the `s.upHTTPClient != nil` branch in forwardNotification is taken.
}

// ── callSubprocessUpstream: write error ──────────────────────────────────

func TestCallSubprocessUpstream_WriteError(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{
		pending:  make(map[string]chan upstreamResult),
		done:     make(chan struct{}),                // NOT closed so done doesn't interfere
		upWriter: mcp.NewMsgWriter(&failingWriter{}), // fails on write
	})
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`13`), Method: "tools/call"}
	_, err := sess.callSubprocessUpstream(context.Background(), msg)
	if err == nil {
		t.Error("expected error from failing upstream writer")
	}
}

// ── callSubprocessUpstream (session done) ────────────────────────────────

func TestCallSubprocessUpstream_SessionDone(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	close(done)
	sess := newClosedTestSession(&httpSession{
		pending:  make(map[string]chan upstreamResult),
		done:     done,
		upWriter: mcp.NewMsgWriter(io.Discard),
	})
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`11`), Method: "tools/call"}
	_, err := sess.callSubprocessUpstream(context.Background(), msg)
	if err == nil {
		t.Error("expected error when session done is closed")
	}
}

// ── runInitHandshake captures the upstream serverInfo.version ──────

// TestRunInitHandshake_CapturesServerVersion pins that the local-
// subprocess HTTP init path must extract serverInfo.version into
// upstreamServerVersion (like http_remote.go and stdio.go), so the FM-4 drift
// check can compare it against the manifest's serverVersion pin. Before the fix
// only Capabilities was captured and the version stayed "".
func TestRunInitHandshake_CapturesServerVersion(t *testing.T) {
	t.Parallel()
	// runInitHandshake increments idCounter to 1 for the first request, so the
	// matching response must carry id 1.
	resp, err := mcp.SuccessResponse(mcp.RawJSON("1"), mcp.InitResult{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
		ServerInfo:      map[string]interface{}{"name": "upstream", "version": "9.9.9"},
	})
	if err != nil {
		t.Fatalf("successResponse: %v", err)
	}
	line, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	sess := newTestSession(&httpSession{
		pending:  make(map[string]chan upstreamResult),
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(io.Discard),
		upReader: mcp.NewMsgReader(bytes.NewReader(append(line, '\n'))),
	})
	if err := sess.runInitHandshake(); err != nil {
		t.Fatalf("runInitHandshake: %v", err)
	}
	if sess.upstreamServerVersion != "9.9.9" {
		t.Fatalf("upstreamServerVersion = %q, want %q", sess.upstreamServerVersion, "9.9.9")
	}
	if sess.upstreamCaps == nil {
		t.Error("upstreamCaps should also be captured")
	}
}

// TestRunInitHandshake_RejectsUpstreamErrorResponse regression: when
// the upstream returns a JSON-RPC error to initialize, the handshake must fail
// (so session creation aborts) rather than silently falling through to
// notifications/initialized and handing the client a session backed by an
// un-initialized upstream.
func TestRunInitHandshake_RejectsUpstreamErrorResponse(t *testing.T) {
	t.Parallel()
	// runInitHandshake uses id 1 for the first request, so the error response must
	// carry id 1 to be matched.
	errResp := mcp.ErrorResponse(mcp.RawJSON("1"), -32600, "unsupported protocol version")
	line, err := json.Marshal(errResp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var hostOut bytes.Buffer // captures what the proxy writes to the upstream
	sess := newTestSession(&httpSession{
		pending:  make(map[string]chan upstreamResult),
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&hostOut),
		upReader: mcp.NewMsgReader(bytes.NewReader(append(line, '\n'))),
	})

	err = sess.runInitHandshake()
	if err == nil {
		t.Fatal("runInitHandshake must fail when the upstream rejects initialize")
	}
	if !strings.Contains(err.Error(), "initialize rejected") {
		t.Errorf("error = %q, want it to report the upstream rejection", err.Error())
	}
	// The handshake sent the initialize request, but must NOT have proceeded to
	// notifications/initialized after the error.
	if strings.Contains(hostOut.String(), "notifications/initialized") {
		t.Error("notifications/initialized must not be sent after an init rejection")
	}
	if sess.upstreamCaps != nil {
		t.Error("upstreamCaps must not be populated from a rejected initialize")
	}
}

// ── callUpstream dispatcher (local mode) ──────────────────────────────────

func TestHTTPCallUpstream_LocalMode_SessionDone(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	close(done)
	sess := newClosedTestSession(&httpSession{
		pending:  make(map[string]chan upstreamResult),
		done:     done,
		upWriter: mcp.NewMsgWriter(io.Discard),
		// upHTTPClient nil → local mode → routes to callSubprocessUpstream
	})
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`12`), Method: "tools/list"}
	_, err := sess.callUpstream(context.Background(), msg)
	if err == nil {
		t.Error("expected error when session done is closed (local mode)")
	}
}

// ── handleHTTPToolsCall ───────────────────────────────────────────────────

func TestHTTPHandleToolsCall_InvalidParams(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": "not-an-object",
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected error for invalid params")
	}
}

// ── handleHTTPResourcesSubscribe ─────────────────────────────────────────

func TestHTTPHandleResourcesSubscribe_Deny(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe",
		"params": map[string]interface{}{"uri": "file:///secret.txt"},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected denial error")
	}
}

func TestHTTPHandleResourcesSubscribe_InvalidParams(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe",
		"params": "not-an-object",
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected error for invalid params")
	}
}

func TestHTTPHandleResourcesSubscribe_EmptyURI(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe",
		"params": map[string]interface{}{"uri": ""},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected error for empty URI")
	}
}

// ── handleHTTPPromptsGet ──────────────────────────────────────────────────

func TestHTTPHandlePromptsGet_InvalidParams(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "prompts/get",
		"params": "bad",
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected error for invalid params")
	}
}

// ── handleKill: non-loopback ──────────────────────────────────────────────

func TestHTTPHandleKill_NonLoopback(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	body := `{"all":true}`
	req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(body))
	req.RemoteAddr = "192.168.1.100:9999" // non-loopback → forbidden
	w := httptest.NewRecorder()
	proxy.handleKill(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-loopback, got %d", w.Code)
	}
}

// ── handleHTTPResourcesRead ───────────────────────────────────────────────

func TestHTTPHandleResourcesRead_InvalidParams(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "resources/read",
		"params": "bad",
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected error for invalid params")
	}
}

func TestHTTPHandleResourcesRead_EmptyURI(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "resources/read",
		"params": map[string]interface{}{"uri": ""},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected error for empty URI")
	}
}

func TestHTTPHandleResourcesRead_Deny(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "resources/read",
		"params": map[string]interface{}{"uri": "file:///secret.txt"},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected denial error")
	}
}

// ── handleHTTPToolsCall: deny ─────────────────────────────────────────────

func TestHTTPHandleToolsCall_Deny(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/secret"},
		},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected denial error")
	}
}

// ── handleHTTPResourcesRead: dry-run deny ────────────────────────────────

func TestHTTPHandleResourcesRead_DryRunDeny(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		Audit:       true,
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "resources/read",
		"params": map[string]interface{}{"uri": "file:///secret.txt"},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()
	// dry-run: should forward despite denial
	_ = resp
}

// ── handleHTTPResourcesSubscribe: dry-run deny ────────────────────────────

func TestHTTPHandleResourcesSubscribe_DryRunDeny(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		Audit:       true,
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe",
		"params": map[string]interface{}{"uri": "file:///secret.txt"},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()
	_ = resp
}

// ── handleHTTPPromptsGet: deny ────────────────────────────────────────────

func TestHTTPHandlePromptsGet_Deny(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "prompts/get",
		"params": map[string]interface{}{"name": "my-prompt"},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected denial error")
	}
}

func TestHTTPHandlePromptsGet_DryRunDeny(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		Audit:       true,
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "prompts/get",
		"params": map[string]interface{}{"name": "my-prompt"},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()
	// dry-run: should forward despite denial
	_ = resp
}

func TestHTTPHandlePromptsGet_EmptyName(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	dp := newTestManifestPDPWithPrompt(t, "my-prompt")
	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         dp,
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "prompts/get",
		"params": map[string]interface{}{"name": ""},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error == nil {
		t.Error("expected error for empty prompt name")
	}
}

// ── handleHTTPToolsCall: dry-run deny ────────────────────────────────────

func TestHTTPHandleToolsCall_DryRunDeny(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		Audit:       true,
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/ok"},
		},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// dry-run: should forward despite denial
	if result.Error != nil {
		t.Errorf("dry-run: expected forwarded response, got error: %+v", result.Error)
	}
}

// ── handleHTTPToolsCall: audit-only deny ──────────────────────────────────

func TestHTTPHandleToolsCall_AuditOnlyDeny(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		Audit:       true,
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/ok"},
		},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// audit-only: should forward despite denial
	if result.Error != nil {
		t.Errorf("audit-only: expected forwarded response, got error: %+v", result.Error)
	}
}

// ── handleHTTPToolsCall: upstream timeout path ────────────────────────────

func TestHTTPHandleToolsCall_WithUpstreamTimeout(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:            pdp.AlwaysAllowPDP{},
		UpstreamURL:    srv.URL,
		UpstreamTimeMs: 5000, // generous timeout so the call succeeds
		Port:           0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initHTTPSession(t, proxySrv)

	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/ok"},
		},
	}
	resp := postMCPJSON(t, proxySrv, body, sid)
	defer resp.Body.Close()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Should succeed within the generous timeout
	if result.Error != nil {
		t.Errorf("unexpected error: %+v", result.Error)
	}
}

// ── handleMCP: method not allowed ────────────────────────────────────────

func TestHTTPHandleMCP_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
		routes:   map[string]*UpstreamRoute{"": {pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}}},
	}
	req := httptest.NewRequest(http.MethodPut, "/mcp", http.NoBody)
	w := httptest.NewRecorder()
	proxy.handleMCP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for PUT, got %d", w.Code)
	}
}

// ── msgReader: scan error ─────────────────────────────────────────────────

type errReader struct {
	after int
	n     int
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.n >= e.after {
		return 0, fmt.Errorf("forced read error")
	}
	e.n++
	p[0] = '\n'
	return 1, nil
}

func TestMsgReader_ScanError(t *testing.T) {
	t.Parallel()
	// Reader that returns an error after 0 bytes → scanner.Err() != nil
	reader := mcp.NewMsgReader(&errReader{after: 0})
	_, err := reader.Read()
	if err == nil {
		t.Error("expected error from reader that always fails")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

// initHTTPSession initializes an MCP session through the proxy and returns
// the session ID.
func initHTTPSession(t *testing.T, proxySrv *httptest.Server) string {
	t.Helper()
	body := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": MCPProtocolVersion,
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test", "version": "0.1"},
		},
	}
	resp := postMCPJSON(t, proxySrv, body, "")
	defer resp.Body.Close()
	sid := resp.Header.Get(SessionHeader)
	if sid == "" {
		t.Fatal("expected session ID in response header")
	}
	return sid
}

// postMCPJSON sends a POST /mcp with a JSON body and returns the response.
func postMCPJSON(t *testing.T, srv *httptest.Server, body interface{}, sessionID string) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set(SessionHeader, sessionID)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	return resp
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

// capturedRecord captures an audit decision for assertions.
type capturedRecord struct {
	SessionID string
	ToolName  string
	Method    string
	Decision  string
	Code      string
	Details   map[string]interface{}
	Audit     bool
}

// newAuditProxy returns an HTTPProxy in audit (observe) mode, backed by the
// given upstream server, using a deny-all PDP so that every tools/call would be
// denied under normal enforcement.
func newAuditProxy(t *testing.T, upstreamSrv *httptest.Server) *HTTPProxy {
	t.Helper()
	return newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: upstreamSrv.URL,
		Audit:       true,
		Port:        0,
	})
}

// postMCPWithBody sends a POST /mcp with the given JSON body and optional session header.
func postMCPWithBody(t *testing.T, proxySrv *httptest.Server, body interface{}, sessionID string) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, proxySrv.URL+"/mcp", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	return resp
}

// initSessionDryRun creates a new session against proxy with fake upstream.
// Returns the session ID.
func initSessionDryRun(t *testing.T, proxySrv *httptest.Server) string {
	t.Helper()
	initMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test", "version": "0"},
		},
	}
	resp := postMCPWithBody(t, proxySrv, initMsg, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize: status %d", resp.StatusCode)
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("no Mcp-Session-Id in initialize response")
	}
	return sid
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

func TestDryRun_ToolCallForwardedDespiteDeny(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t) // reuse the stub from JWT tests
	defer upstream.srv.Close()

	proxy := newAuditProxy(t, upstream.srv)
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initSessionDryRun(t, proxySrv)

	// Call a tool. The denyAllPDP would normally block it, but in dry-run mode
	// the call must be forwarded and succeed.
	toolMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/secret/data"},
		},
	}
	resp := postMCPWithBody(t, proxySrv, toolMsg, sid)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Result should be non-nil (upstream responded) not an error.
	if result.Error != nil {
		t.Errorf("unexpected error in response: %+v", result.Error)
	}
	if result.Result == nil {
		t.Error("expected a result from upstream, got nil")
	}
}

func TestAudit_RecordsObserveFlag(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	// Use a custom proxy that routes to our capture sink.
	proxyWithSink := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: upstream.srv.URL,
		Audit:       true,
		Port:        0,
	})

	// Swap the sink for our capture sink via a wrapper PDP that also records.
	var recorded []capturedRecord
	recordingPDP := recordingDecisionPoint{
		inner: denyAllPDP{},
		onDecide: func(sessionID, toolName string, resp capability.EnforceResponse) {
			recorded = append(recorded, capturedRecord{
				SessionID: sessionID,
				ToolName:  toolName,
				Decision:  string(resp.Decision),
				Audit:     proxyWithSink.routes[""].audit,
			})
		},
	}
	proxyWithSink.routes[""].pdp = recordingPDP

	proxySrv := httptest.NewServer(http.HandlerFunc(proxyWithSink.handleMCP))
	defer proxySrv.Close()

	sid := initSessionDryRun(t, proxySrv)

	toolMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "write_file",
			"arguments": map[string]interface{}{},
		},
	}
	resp := postMCPWithBody(t, proxySrv, toolMsg, sid)
	defer func() { _ = resp.Body.Close() }()

	if len(recorded) == 0 {
		t.Fatal("no PDP decision recorded")
	}
	if !recorded[0].Audit {
		t.Errorf("expected audit observe flag set in recorded decision, got false")
	}
	if recorded[0].Decision != string(capability.DecisionDeny) {
		t.Errorf("expected deny decision, got %q", recorded[0].Decision)
	}
}

func TestDryRun_NormalMode_DenyBlocks(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	// Normal mode (no dry-run): denyAll should block the call.
	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: upstream.srv.URL,
		Audit:       false,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initSessionDryRun(t, proxySrv)

	toolMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{},
		},
	}
	resp := postMCPWithBody(t, proxySrv, toolMsg, sid)
	defer func() { _ = resp.Body.Close() }()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Denial is a JSON-RPC error, not a tool result.
	if result.Error == nil {
		t.Fatal("expected JSON-RPC error for denied tools/call, got nil error")
	}
	if result.Error.Code != capability.JSONRPCCodeCapabilityDenied {
		t.Errorf("error.code = %d, want %d (CAPABILITY_DENIED)", result.Error.Code, capability.JSONRPCCodeCapabilityDenied)
	}
}

func TestDryRun_AllowedCall_NotAffected(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	// Allow-all PDP with dry-run: should still forward normally.
	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: upstream.srv.URL,
		Audit:       true,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initSessionDryRun(t, proxySrv)

	toolMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/ok"},
		},
	}
	resp := postMCPWithBody(t, proxySrv, toolMsg, sid)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error != nil {
		t.Errorf("unexpected error: %+v", result.Error)
	}
}

// -------------------------------------------------------------------------
// Helpers for recording decisions
// -------------------------------------------------------------------------

type recordingDecisionPoint struct {
	inner    pdp.PolicyDecisionPoint
	onDecide func(sessionID, toolName string, resp capability.EnforceResponse)
}

func (r recordingDecisionPoint) Decide(ctx context.Context, sessionID string, target pdp.EnforceTarget, args map[string]interface{}, sourceIP string) capability.EnforceResponse {
	resp := r.inner.Decide(ctx, sessionID, target, args, sourceIP)
	r.onDecide(sessionID, target.Name, resp)
	return resp
}

func (r recordingDecisionPoint) DecideResourceRead(ctx context.Context, sessionID, uri, sourceIP string) capability.EnforceResponse {
	return r.inner.DecideResourceRead(ctx, sessionID, uri, sourceIP)
}

func (r recordingDecisionPoint) DecidePromptGet(ctx context.Context, sessionID, promptName, sourceIP string) capability.EnforceResponse {
	return r.inner.DecidePromptGet(ctx, sessionID, promptName, sourceIP)
}

func (r recordingDecisionPoint) DecideSampling(ctx context.Context, sessionID, sourceIP string) capability.EnforceResponse {
	return r.inner.DecideSampling(ctx, sessionID, sourceIP)
}
func (r recordingDecisionPoint) CheckKill(ctx context.Context, sessionID string) *capability.EnforceResponse {
	return r.inner.CheckKill(ctx, sessionID)
}
func (r recordingDecisionPoint) CheckAudience(ctx context.Context) *capability.EnforceResponse {
	return r.inner.CheckAudience(ctx)
}
func (r recordingDecisionPoint) RecordObservedToolHashes(ctx context.Context, result json.RawMessage) int {
	return r.inner.RecordObservedToolHashes(ctx, result)
}
func (r recordingDecisionPoint) FilterToolsList(ctx context.Context, result json.RawMessage) pdp.ListFilterResult {
	return r.inner.FilterToolsList(ctx, result)
}
func (r recordingDecisionPoint) FilterResourcesList(ctx context.Context, result json.RawMessage) pdp.ListFilterResult {
	return r.inner.FilterResourcesList(ctx, result)
}
func (r recordingDecisionPoint) FilterPromptsList(ctx context.Context, result json.RawMessage) pdp.ListFilterResult {
	return r.inner.FilterPromptsList(ctx, result)
}

// mcpHelperSentinel is the argv marker that turns a re-exec of the test binary
// into a minimal MCP stdio upstream (see TestHelperMCPProcess).
const mcpHelperSentinel = "eunox-helper-mcp-process"

// TestHelperMCPProcess is a re-exec entry point. When the test binary is invoked
// with mcpHelperSentinel in its arguments (by TestHTTPProxy_SubprocessSessions_NoLeak),
// it serves a minimal MCP stdio session and then lets the process exit normally.
// During an ordinary `go test` run the sentinel is absent and this is a no-op.
func TestHelperMCPProcess(t *testing.T) {
	if !slices.Contains(os.Args, mcpHelperSentinel) {
		return
	}
	mcpHelperServe()
	// Return (do not os.Exit) so we don't trip -test.paniconexit0; once stdin is
	// closed by the proxy the binary finishes and exits cleanly.
}

// mcpHelperServe reads newline-delimited JSON-RPC from stdin and answers every
// request, replying to initialize with a minimal server result. It returns when
// stdin is closed (the proxy tearing the session down).
func mcpHelperServe() {
	reader := mcp.NewMsgReader(os.Stdin)
	writer := mcp.NewMsgWriter(os.Stdout)
	for {
		msg, err := reader.Read()
		if err != nil {
			return // EOF: proxy closed our stdin.
		}
		if msg.ID == nil {
			continue // notification: no response expected
		}
		var result interface{}
		if msg.Method == "initialize" {
			result = mcp.InitResult{
				ProtocolVersion: MCPProtocolVersion,
				Capabilities:    map[string]interface{}{},
				ServerInfo:      map[string]interface{}{"name": "leak-helper", "version": "1.0"},
			}
		} else {
			result = map[string]interface{}{}
		}
		resp, _ := mcp.SuccessResponse(msg.ID, result)
		_ = writer.Write(resp)
	}
}

func TestHTTPProxy_SubprocessSessions_NoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	proxy := newHTTPProxy(httpProxyOptions{
		Command:    os.Args[0],
		Args:       []string{"-test.run=^TestHelperMCPProcess$", "--", mcpHelperSentinel},
		PDP:        pdp.AlwaysAllowPDP{},
		ShutdownMs: 2000,
	})

	// Warm up so lazily-created goroutines/pools exist before we sample baseline.
	for i := 0; i < 3; i++ {
		sid := leakInitSession(t, proxy)
		leakDeleteSession(t, proxy, sid)
	}
	settleGoroutines()
	base := runtime.NumGoroutine()

	const cycles = 20
	for i := 0; i < cycles; i++ {
		sid := leakInitSession(t, proxy)
		leakDeleteSession(t, proxy, sid)
	}

	// DELETE removes the entry synchronously, so the map must already be empty.
	if n := proxy.liveSessionCount(); n != 0 {
		t.Fatalf("session map leak: %d live sessions after %d init/delete cycles", n, cycles)
	}

	const tolerance = 4
	if got := waitForGoroutineCount(base + tolerance); got > base+tolerance {
		t.Fatalf("goroutine leak: baseline %d, after %d subprocess sessions %d (tolerance %d)",
			base, cycles, got, tolerance)
	}
}

// mcpHangAfterInitSentinel is the argv marker that turns a re-exec of the test
// binary into a subprocess that answers initialize, then closes its own stdout
// while staying alive and never reading stdin again (see TestHelperMCPHangAfterInitProcess).
const mcpHangAfterInitSentinel = "eunox-helper-mcp-hang-after-init"

// TestHelperMCPHangAfterInitProcess is a re-exec entry point used by
// TestHTTPProxy_SessionCleanup_ReapsHungSubprocess to reproduce the cleanup-goroutine
// deadlock: readUpstream exits on a non-EOF-clean condition (here, the upstream tearing
// down only its stdout) while the subprocess itself keeps running and ignores stdin, so
// only SIGKILL can end it.
func TestHelperMCPHangAfterInitProcess(t *testing.T) {
	if !slices.Contains(os.Args, mcpHangAfterInitSentinel) {
		return
	}
	mcpHangAfterInitServe()
}

// mcpHangAfterInitServe answers a single initialize request, then closes stdout
// (so the proxy's readUpstream loop observes EOF and exits, closing sess.done, while
// this process is still running) and blocks forever without reading stdin again — so
// closing the proxy's write end never causes it to exit on its own.
func mcpHangAfterInitServe() {
	reader := mcp.NewMsgReader(os.Stdin)
	writer := mcp.NewMsgWriter(os.Stdout)
	msg, err := reader.Read()
	if err != nil || msg.ID == nil {
		return
	}
	result := mcp.InitResult{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    map[string]interface{}{},
		ServerInfo:      map[string]interface{}{"name": "hang-after-init-helper", "version": "1.0"},
	}
	resp, _ := mcp.SuccessResponse(msg.ID, result)
	_ = writer.Write(resp)
	_ = os.Stdout.Close()
	select {} // never read stdin again; only SIGKILL ends this process
}

// TestHTTPProxy_SessionCleanup_ReapsHungSubprocess is the regression for the cleanup
// goroutine deadlock: sess.done closes on ANY readUpstream exit, not only a clean
// process exit. Here the upstream tears down only its stdout right after answering
// initialize and then hangs, ignoring stdin — so the naive `<-sess.done;
// sess.upCmd.Wait()` cleanup would block forever, leaking the session slot, the
// subprocess, its FDs, and the cleanup goroutine itself. The fixed cleanup goroutine
// must close stdin and, when that alone does not end the process, escalate to SIGKILL
// after a bounded grace period so the session is reaped.
func TestHTTPProxy_SessionCleanup_ReapsHungSubprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	proxy := newHTTPProxy(httpProxyOptions{
		Command:    os.Args[0],
		Args:       []string{"-test.run=^TestHelperMCPHangAfterInitProcess$", "--", mcpHangAfterInitSentinel},
		PDP:        pdp.AlwaysAllowPDP{},
		ShutdownMs: 300,
	})

	sid := leakInitSession(t, proxy)
	if proxy.liveSessionCount() != 1 {
		t.Fatalf("session %q was not registered", sid)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && proxy.liveSessionCount() != 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if n := proxy.liveSessionCount(); n != 0 {
		t.Fatalf("session not reaped after the upstream hung with only stdout torn down: %d still live (cleanup goroutine likely wedged in upCmd.Wait())", n)
	}
}

func TestHTTPProxy_RemoteSessions_NoLeak(t *testing.T) {
	fu := newFullFakeUpstream()
	upURL := startFakeUpstream(t, fu)

	proxy := newHTTPProxy(httpProxyOptions{
		UpstreamURL: upURL,
		PDP:         pdp.AlwaysAllowPDP{},
		ShutdownMs:  2000,
	})

	for i := 0; i < 3; i++ {
		sid := leakInitSession(t, proxy)
		leakDeleteSession(t, proxy, sid)
	}
	settleGoroutines()
	base := runtime.NumGoroutine()

	const cycles = 25
	for i := 0; i < cycles; i++ {
		sid := leakInitSession(t, proxy)
		leakDeleteSession(t, proxy, sid)
	}

	if n := proxy.liveSessionCount(); n != 0 {
		t.Fatalf("session map leak: %d live sessions after %d init/delete cycles", n, cycles)
	}

	// Each remote session owns its connection pool, released on close() via
	// CloseIdleConnections — so the per-session upstream-connection goroutines
	// must not accumulate across churn.
	const tolerance = 4
	if got := waitForGoroutineCount(base + tolerance); got > base+tolerance {
		t.Fatalf("goroutine/connection leak: baseline %d, after %d remote sessions %d (tolerance %d)",
			base, cycles, got, tolerance)
	}
}

// liveSessionCount returns the number of sessions currently in the proxy map.
func (p *HTTPProxy) liveSessionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

// settleGoroutines gives transient goroutines a chance to exit before a baseline
// sample.
func settleGoroutines() {
	for i := 0; i < 10; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
}

// waitForGoroutineCount polls until the goroutine count drops to limit (or a
// timeout elapses), returning the final observed count. Cleanup is asynchronous,
// so this absorbs the brief settling window after a session closes.
func waitForGoroutineCount(limit int) int {
	n := runtime.NumGoroutine()
	for i := 0; i < 150 && n > limit; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	return n
}

func leakInitSession(t *testing.T, p *HTTPProxy) string {
	t.Helper()
	body, _ := json.Marshal(mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON("1"),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"leak","version":"1.0"}}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", CTJSON)
	w := httptest.NewRecorder()
	p.handleMCP(w, req)
	sid := w.Header().Get(SessionHeader)
	if sid == "" {
		t.Fatalf("initialize failed: status %d, body %s", w.Code, w.Body.String())
	}
	return sid
}

func leakDeleteSession(t *testing.T, p *HTTPProxy, sid string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, sid)
	w := httptest.NewRecorder()
	p.handleMCP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete failed: status %d, body %s", w.Code, w.Body.String())
	}
}

// newOriginTestServer wraps a trivial 200-OK handler in the same
// requireValidOrigin middleware the real server uses, so the test exercises the
// production choke point rather than a handler-local copy.
func newOriginTestServer(t *testing.T, opts httpProxyOptions) *httptest.Server {
	t.Helper()
	proxy := newHTTPProxy(opts)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(proxy.requireValidOrigin(ok))
	t.Cleanup(srv.Close)
	return srv
}

func getWithOrigin(t *testing.T, url, origin string, setOrigin bool) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody) //nolint:noctx // short-lived test request
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if setOrigin {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestOriginValidation_DefaultAllowlist verifies the built-in allowlist: loopback
// origins (and the absence of an Origin header) are accepted, while a foreign
// Origin is rejected with 403.
func TestOriginValidation_DefaultAllowlist(t *testing.T) {
	srv := newOriginTestServer(t, httpProxyOptions{Bind: "127.0.0.1"})

	cases := []struct {
		name      string
		origin    string
		setOrigin bool
		want      int
	}{
		{"no origin header", "", false, http.StatusOK},
		{"present empty origin rejected", "", true, http.StatusForbidden},
		{"null origin rejected", "null", true, http.StatusForbidden},
		{"localhost", "http://localhost", true, http.StatusOK},
		{"localhost with port", "http://localhost:3000", true, http.StatusOK},
		{"127.0.0.1", "http://127.0.0.1:8080", true, http.StatusOK},
		{"ipv6 loopback", "http://[::1]:3000", true, http.StatusOK},
		{"foreign https origin", "https://evil.example.com", true, http.StatusForbidden},
		{"rebinding lookalike", "http://attacker.localhost.evil.com", true, http.StatusForbidden},
		{"unparseable origin", "::::not a url", true, http.StatusForbidden},
		{"hostless origin", "file://", true, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := getWithOrigin(t, srv.URL+"/mcp", tc.origin, tc.setOrigin)
			if got != tc.want {
				t.Errorf("Origin %q (set=%v): got status %d, want %d", tc.origin, tc.setOrigin, got, tc.want)
			}
		})
	}
}

// TestOriginValidation_ConfiguredAllowlist verifies that operator-configured
// origins are accepted (case-insensitively) while others are still rejected.
func TestOriginValidation_ConfiguredAllowlist(t *testing.T) {
	srv := newOriginTestServer(t, httpProxyOptions{
		Bind:           "127.0.0.1",
		AllowedOrigins: []string{"https://app.example.com"},
	})

	cases := []struct {
		name   string
		origin string
		want   int
	}{
		{"configured origin", "https://app.example.com", http.StatusOK},
		{"configured origin different case", "https://APP.EXAMPLE.COM", http.StatusOK},
		{"loopback still allowed", "http://localhost", http.StatusOK},
		{"other origin rejected", "https://other.example.com", http.StatusForbidden},
		{"configured host wrong scheme", "http://app.example.com", http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := getWithOrigin(t, srv.URL+"/mcp", tc.origin, true)
			if got != tc.want {
				t.Errorf("Origin %q: got status %d, want %d", tc.origin, got, tc.want)
			}
		})
	}
}

// TestOriginValidation_NullOptIn verifies that "null" is rejected by default but
// can be explicitly allowed via listen.allowedOrigins for trusted file:/sandboxed
// front-ends — it is never on the built-in allowlist.
func TestOriginValidation_NullOptIn(t *testing.T) {
	srv := newOriginTestServer(t, httpProxyOptions{
		Bind:           "127.0.0.1",
		AllowedOrigins: []string{"null"},
	})
	if got := getWithOrigin(t, srv.URL+"/mcp", "null", true); got != http.StatusOK {
		t.Errorf("explicitly allowed null origin: got %d, want 200", got)
	}
}

// TestOriginValidation_BindHost verifies that the configured bind host is added
// to the allowlist, while a wildcard bind does not widen it.
func TestOriginValidation_BindHost(t *testing.T) {
	t.Run("bind host accepted", func(t *testing.T) {
		srv := newOriginTestServer(t, httpProxyOptions{Bind: "192.168.1.10"})
		if got := getWithOrigin(t, srv.URL+"/mcp", "http://192.168.1.10:3000", true); got != http.StatusOK {
			t.Errorf("bind host origin: got %d, want 200", got)
		}
	})

	t.Run("wildcard bind does not allow arbitrary host", func(t *testing.T) {
		srv := newOriginTestServer(t, httpProxyOptions{Bind: "0.0.0.0"})
		if got := getWithOrigin(t, srv.URL+"/mcp", "http://0.0.0.0", true); got != http.StatusForbidden {
			t.Errorf("wildcard bind origin should be rejected: got %d, want 403", got)
		}
		// Loopback still works under a wildcard bind.
		if got := getWithOrigin(t, srv.URL+"/mcp", "http://localhost", true); got != http.StatusOK {
			t.Errorf("loopback under wildcard bind: got %d, want 200", got)
		}
	})
}

// TestOriginValidation_AppliesToControlKill verifies the guard covers every
// endpoint, not just /mcp — a mismatched Origin on /control/kill is rejected.
func TestOriginValidation_AppliesToControlKill(t *testing.T) {
	srv := newOriginTestServer(t, httpProxyOptions{Bind: "127.0.0.1"})
	if got := getWithOrigin(t, srv.URL+"/control/kill", "https://evil.example.com", true); got != http.StatusForbidden {
		t.Errorf("/control/kill with foreign Origin: got %d, want 403", got)
	}
}

// TestOriginRejection_AuditRecordSeparatesClaimedSessionID pins that a pre-session
// origin denial does not stamp the unverified Mcp-Session-Id header into the
// structured session_id (which would let anyone forge ORIGIN_REJECTED records
// attributed to a victim's session). session_id stays empty; the claimed id is
// preserved only as the unverified claimed_session_id detail.
func TestOriginRejection_AuditRecordSeparatesClaimedSessionID(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{Bind: "127.0.0.1", Sink: sink})

	const claimedSessionID = "client-claimed-session-123"
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set(SessionHeader, claimedSessionID)
	rec := httptest.NewRecorder()

	if proxy.checkOrigin(rec, req) {
		t.Fatal("checkOrigin allowed a foreign Origin; expected rejection")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	_ = sink.Close()
	r := findAuditRecordByMethod(readAuditRecords(t, logPath), "", "deny")
	if r == nil {
		t.Fatal("no ORIGIN_REJECTED deny record written")
	}
	if code, _ := r["denial_code"].(string); code != "ORIGIN_REJECTED" {
		t.Fatalf("denial_code = %q, want ORIGIN_REJECTED", code)
	}
	// The structured session_id must NOT carry the unverified client-claimed value.
	if got, _ := r["session_id"].(string); got != "" {
		t.Errorf("session_id = %q, want empty (unauthenticated Mcp-Session-Id must not be stamped as a real session)", got)
	}
	// The claimed id is preserved as an unverified detail for correlation.
	details, ok := r["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("details = %v, want a map carrying claimed_session_id", r["details"])
	}
	if got, _ := details["claimed_session_id"].(string); got != claimedSessionID {
		t.Errorf("details.claimed_session_id = %q, want %q", got, claimedSessionID)
	}
}

// TestJWTInvalid_AuditRecordSeparatesClaimedSessionID pins that a JWT-validation
// denial does not stamp the unverified Mcp-Session-Id header into the structured
// session_id (which would let an unauthenticated caller forge JWT_INVALID records
// attributed to a victim's session). JWT pre-validation runs before any session
// lookup, so the header is attacker-controlled: session_id stays empty and the
// claimed id is preserved only as the unverified claimed_session_id detail, the
// same separation checkOrigin applies.
func TestJWTInvalid_AuditRecordSeparatesClaimedSessionID(t *testing.T) {
	// A real JWTPDP backed by an empty JWKS rejects any presented token.
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()
	jwtPDP := pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:                  jwksServer.URL,
		Audience:                 "test-aud",
		ExperimentalCapabilities: true,
	})

	sink, logPath := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{Bind: "127.0.0.1", JWTPDP: jwtPDP, Sink: sink})

	const claimedSessionID = "client-claimed-session-456"
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer not-a-valid-token")
	req.Header.Set(SessionHeader, claimedSessionID)
	rec := httptest.NewRecorder()

	proxy.handleMCP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	_ = sink.Close()
	r := findAuditRecordByMethod(readAuditRecords(t, logPath), "", "deny")
	if r == nil {
		t.Fatal("no JWT_INVALID deny record written")
	}
	if code, _ := r["denial_code"].(string); code != "JWT_INVALID" {
		t.Fatalf("denial_code = %q, want JWT_INVALID", code)
	}
	// The structured session_id must NOT carry the unverified client-claimed value.
	if got, _ := r["session_id"].(string); got != "" {
		t.Errorf("session_id = %q, want empty (unauthenticated Mcp-Session-Id must not be stamped as a real session)", got)
	}
	// The claimed id is preserved as an unverified detail for correlation.
	details, ok := r["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("details = %v, want a map carrying claimed_session_id", r["details"])
	}
	if got, _ := details["claimed_session_id"].(string); got != claimedSessionID {
		t.Errorf("details.claimed_session_id = %q, want %q", got, claimedSessionID)
	}
}

// TestHTTPJWT_ExperimentalCapabilitiesGate_RejectsCapabilityTokenWhenOff is the
// HTTP-layer counterpart to the PDP-level gate test: a fully valid, signed token that
// carries mcp.capabilities must be rejected with 401 at the HTTP boundary when
// --jwt-experimental-capabilities is off (the default), recorded as a JWT_INVALID
// deny. The same token validating under a flag-on validator proves the 401 is the
// experimental gate rejecting a valid token, not a malformed/invalid one.
func TestHTTPJWT_ExperimentalCapabilitiesGate_RejectsCapabilityTokenWhenOff(t *testing.T) {
	key := newTestKey(t, "exp-cap-http")
	jwksServer := makeJWKSServer(t, key)
	defer jwksServer.Close()

	capToken := makeIDPToken(t, key, []string{"tool:read_file"}, "", "", "agent-1", time.Now().Add(time.Hour))

	// Gate OFF (default): the HTTP layer must reject the capability-bearing token.
	validatorOff := pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:          jwksServer.URL + "/",
		AllowAnyIssuer:   true,
		AllowAnyAudience: true,
		CacheTTL:         5 * time.Second,
		// ExperimentalCapabilities defaults to false.
	})
	sink, logPath := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{Bind: "127.0.0.1", JWTPDP: validatorOff, Sink: sink})

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+capToken)
	rec := httptest.NewRecorder()

	proxy.handleMCP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a capability-bearing token must be rejected with 401 when --jwt-experimental-capabilities is off; got %d", rec.Code)
	}

	_ = sink.Close()
	r := findAuditRecordByMethod(readAuditRecords(t, logPath), "", "deny")
	if r == nil {
		t.Fatal("no JWT_INVALID deny record written for the gated capability token")
	}
	if code, _ := r["denial_code"].(string); code != "JWT_INVALID" {
		t.Fatalf("denial_code = %q, want JWT_INVALID", code)
	}

	// Contrast: the SAME token validates cleanly when the gate is on, proving the 401
	// above is the experimental gate rejecting a valid token, not a signature/claim failure.
	validatorOn := pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:                  jwksServer.URL + "/",
		AllowAnyIssuer:           true,
		AllowAnyAudience:         true,
		CacheTTL:                 5 * time.Second,
		ExperimentalCapabilities: true,
	})
	if _, err := validatorOn.ValidateToken(context.Background(), "Bearer "+capToken); err != nil {
		t.Fatalf("the same token must validate when the gate is on (proves the 401 is the gate, not an invalid token): %v", err)
	}
}

// TestJWTInvalid_AuditRecordCarriesStableErrorType pins the disclosure fix: the
// JWT_INVALID audit record must carry a stable error_type CATEGORY, never the raw
// go-jose / validation message (which can disclose claim values, the accepted
// algorithm, the configured issuer, or key-rotation state to a downstream SIEM).
// The audit tape applies the same non-disclosure posture as the opaque-401 response.
func TestJWTInvalid_AuditRecordCarriesStableErrorType(t *testing.T) {
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()
	jwtPDP := pdp.NewJWTPDP(pdp.JWTPDPOptions{JWKSURI: jwksServer.URL, Audience: "test-aud"})

	sink, logPath := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{Bind: "127.0.0.1", JWTPDP: jwtPDP, Sink: sink})

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer not-a-valid-token")
	rec := httptest.NewRecorder()
	proxy.handleMCP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	_ = sink.Close()
	r := findAuditRecordByMethod(readAuditRecords(t, logPath), "", "deny")
	if r == nil {
		t.Fatal("no JWT_INVALID deny record written")
	}
	details, ok := r["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("details = %v, want a map", r["details"])
	}
	// The raw library message must be gone.
	if raw, present := details["error"]; present {
		t.Errorf("details still carries the raw error message under \"error\": %v", raw)
	}
	// A stable category must be present. "not-a-valid-token" is not a parseable JWS.
	et, _ := details["error_type"].(string)
	if et != "malformed_token" {
		t.Errorf("details.error_type = %q, want %q", et, "malformed_token")
	}
}

// TestHandleMCPPost_RejectsTrailingJSONTokens pins the fail-closed fix: a single
// JSON-RPC POST body is exactly one JSON value, so a body with a second token after
// the first must be rejected with 400 before any dispatch — never 202-acking an
// invalid initialize notification or allocating a session off a malformed body.
func TestHandleMCPPost_RejectsTrailingJSONTokens(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()
	proxy := newAuditProxy(t, upstream.srv)
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	// First value is a valid initialize; a second JSON-RPC token follows it.
	body := `{"jsonrpc":"2.0","method":"initialize","params":{}} {"jsonrpc":"2.0","method":"tools/list","id":1}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, proxySrv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing JSON token: status = %d, want 400", resp.StatusCode)
	}
	// A malformed body must not create a session.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.Errorf("malformed body allocated a session: Mcp-Session-Id = %q", sid)
	}
}

// TestCheckOrigin_MultipleHeadersRejected pins the DNS-rebinding-guard fix: a
// request carrying more than one Origin header is rejected even when the first
// value is an allowed loopback origin, so a non-browser client cannot smuggle a
// disallowed Origin past a guard that validated only vals[0].
func TestCheckOrigin_MultipleHeadersRejected(t *testing.T) {
	proxy := newHTTPProxy(httpProxyOptions{Bind: "127.0.0.1"})

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Add("Origin", "http://localhost") // allowed on its own
	req.Header.Add("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()

	if proxy.checkOrigin(rec, req) {
		t.Fatal("checkOrigin admitted a request with two Origin headers; must reject (RFC 6454 forbids multiple)")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	// A single allowed Origin still passes (the guard did not become over-strict).
	req2 := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req2.Header.Set("Origin", "http://localhost")
	if !proxy.checkOrigin(httptest.NewRecorder(), req2) {
		t.Fatal("checkOrigin rejected a single allowed Origin; want pass")
	}
}

// ── sampling round-trip: host response routed to upstream ────────────

// TestHTTPSamplingRoundTrip_HostResponseRoutedToUpstream pins for the HTTP
// transport: a server-initiated request is broadcast to the host over SSE; the
// host POSTs its response back to /mcp. handleMCPPost must forward that response
// to the upstream subprocess instead of dropping it with a bare 202 (which hangs
// the upstream).
func TestHTTPSamplingRoundTrip_HostResponseRoutedToUpstream(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	rt := &UpstreamRoute{pdp: pdp.AlwaysAllowPDP{}}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{
		id:       "rt-sess",
		route:    rt,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	// The host holds an open SSE stream (as it does in production), so the
	// server-initiated request is delivered and its ID tracked for the response
	// route-back below.
	ch := make(chan mcp.RPCMsg, 16)
	sess.addSub(ch)

	// Upstream initiated a request with ID 5 that was broadcast to the host.
	sess.broadcastServerRequest(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`5`), Method: "sampling/createMessage"})

	// Host POSTs its response (same ID) back to /mcp.
	body := `{"jsonrpc":"2.0","id":5,"result":{"role":"assistant","content":{"type":"text","text":"hi"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set(SessionHeader, "rt-sess")
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, rt)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202 for a host response POST, got %d", w.Code)
	}
	var routed mcp.RPCMsg
	if err := json.Unmarshal(bytes.TrimSpace(up.Bytes()), &routed); err != nil {
		t.Fatalf("host response was not routed to the upstream (%v); upstream bytes: %q", err, up.String())
	}
	if mcp.MsgKey(routed.ID) != "n:5" || routed.Result == nil {
		t.Errorf("routed upstream message = %+v, want the id-5 result", routed)
	}
}

// TestHTTPReadUpstream_KilledSessionDropsNotificationRelay is the regression for
// the HTTP SSE relay continuing to stream upstream->host notifications to a session
// killed via a shared (Redis-style) backend: the local /control/kill path evicts SSE
// streams, but a backend kill only updates the kill store, so readUpstream must gate
// the broadcast on CheckKill. A killed session drops (does not broadcast) upstream
// notifications; a live session forwards them.
func TestHTTPReadUpstream_KilledSessionDropsNotificationRelay(t *testing.T) {
	t.Parallel()

	newSess := func(id string, ks killswitch.Manager, input string) (*httpSession, chan mcp.RPCMsg) {
		rt := &UpstreamRoute{name: "r", pdp: pdp.NewAlwaysAllowPDP(ks), sink: &routeSink{}}
		s := newTestSession(&httpSession{
			id:       id,
			route:    rt,
			done:     make(chan struct{}),
			pending:  make(map[string]chan upstreamResult),
			upWriter: mcp.NewMsgWriter(io.Discard),
			upReader: mcp.NewMsgReader(strings.NewReader(input)),
		})
		ch := make(chan mcp.RPCMsg, 4)
		s.addSub(ch)
		return s, ch
	}

	notif := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"p":1}}` + "\n"

	// Killed session: the notification must NOT reach the subscriber.
	ksKilled := killswitch.NewInMemory()
	_ = ksKilled.KillSession(context.Background(), "killed-sess")
	sKilled, chKilled := newSess("killed-sess", ksKilled, notif)
	sKilled.readUpstream(context.Background()) // returns at EOF
	select {
	case m := <-chKilled:
		t.Fatalf("killed session must not relay upstream notifications, got %+v", m)
	default:
	}

	// Live session: the notification is delivered.
	ksLive := killswitch.NewInMemory()
	sLive, chLive := newSess("live-sess", ksLive, notif)
	sLive.readUpstream(context.Background())
	select {
	case m := <-chLive:
		if m.Method != "notifications/progress" {
			t.Fatalf("live session delivered wrong message: %+v", m)
		}
	default:
		t.Fatal("live session must relay the upstream notification to the subscriber")
	}
}

// TestHTTPBroadcastServerRequest_NoSubscriberFailsClosed verifies that a
// server-initiated request with no SSE subscriber to receive it does not hang the
// upstream: broadcastServerRequest must reply a JSON-RPC error to the upstream,
// untrack the ID, and report a non-delivery. There is no replay buffer, so a
// dropped server request would otherwise block the upstream forever.
func TestHTTPBroadcastServerRequest_NoSubscriberFailsClosed(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	sess := newTestSession(&httpSession{
		id:       "no-sub",
		route:    &UpstreamRoute{},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})

	delivered := sess.broadcastServerRequest(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`5`), Method: "sampling/createMessage"})
	if delivered {
		t.Fatalf("broadcastServerRequest reported delivered with no subscriber")
	}

	// The upstream must receive an error response for ID 5 so it unblocks.
	var routed mcp.RPCMsg
	if err := json.Unmarshal(bytes.TrimSpace(up.Bytes()), &routed); err != nil {
		t.Fatalf("no error response written to upstream (%v); bytes: %q", err, up.String())
	}
	if mcp.MsgKey(routed.ID) != "n:5" || routed.Error == nil {
		t.Errorf("upstream message = %+v, want an error response for id 5", routed)
	}

	// The ID must be untracked so a (never-arriving) host response cannot later be
	// mis-routed, and so the tracker is not leaked.
	if sess.serverReqs.take(mcp.MsgKey(mcp.RawJSON(`5`))) {
		t.Errorf("id 5 is still tracked after a fail-closed broadcast; want untracked")
	}
}

// TestHTTPHandleMCPPost_UntrackedResponseIgnored verifies the route-back is
// bounded: a host response POST whose ID was never broadcast as a server-initiated
// request is acknowledged (202) but NOT written to the upstream.
func TestHTTPHandleMCPPost_UntrackedResponseIgnored(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	rt := &UpstreamRoute{pdp: pdp.AlwaysAllowPDP{}}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{
		id:       "rt-sess2",
		route:    rt,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	body := `{"jsonrpc":"2.0","id":999,"result":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set(SessionHeader, "rt-sess2")
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, rt)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", w.Code)
	}
	if up.Len() != 0 {
		t.Errorf("untracked host response must not be forwarded to the upstream; got %q", up.String())
	}
}

// TestHTTPHandleSessionPost_KilledServerResponseRecordsDeny pins the fix for the
// silently-dropped host reply to a server-initiated request on a killed session: the
// reply must NOT be routed to the upstream (kill semantics), and the drop must be
// RECORDED so a killed session's suppressed server-response is visible on the tape
// (mirroring the notification kill record). A response carries no method, so the
// record uses a fixed "server-response" identifier.
func TestHTTPHandleSessionPost_KilledServerResponseRecordsDeny(t *testing.T) {
	t.Parallel()

	sink, logPath := newTempAuditSink(t)
	ks := killswitch.NewInMemory()
	if err := ks.KillSession(context.Background(), "kill-sess"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	policy := newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}})

	var up bytes.Buffer
	rt := &UpstreamRoute{pdp: policy, sink: &routeSink{sink: sink, upstream: "up1"}}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{
		id:       "kill-sess",
		route:    rt,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	// A tracked server-initiated request ID (as if one had been broadcast to the host).
	sess.serverReqs.track(mcp.MsgKey(mcp.RawJSON(`5`)))
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	body := `{"jsonrpc":"2.0","id":5,"result":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set(SessionHeader, "kill-sess")
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, rt)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", w.Code)
	}
	if up.Len() != 0 {
		t.Errorf("a killed session's host reply must NOT be routed to the upstream; got %q", up.String())
	}
	if err := sink.Close(); err != nil { // flush the drainer to disk
		t.Fatalf("sink.Close: %v", err)
	}
	recs := readAuditRecords(t, logPath)
	rec := findAuditRecordByMethod(recs, "server-response", "deny")
	if rec == nil {
		t.Fatalf("no deny record for the dropped server-response; records: %+v", recs)
	}
	details, _ := rec["details"].(map[string]interface{})
	if got, _ := details["transport"].(string); got != "http-server-response" {
		t.Errorf("deny record transport marker = %q, want http-server-response; record: %+v", got, rec)
	}
}

// TestHTTPRemoveSubAndDrain_RepliesErrorForBufferedServerRequest pins the SSE
// teardown path: a server-initiated request broadcast into an SSE subscriber's
// buffer that the stream loop never read (the client disconnected) must, on
// removeSubAndDrain, get an error reply routed to the upstream and have its ID
// untracked — otherwise the upstream hangs awaiting a response the departed client
// will never send.
func TestHTTPRemoveSubAndDrain_RepliesErrorForBufferedServerRequest(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	sess := newTestSession(&httpSession{
		id:       "drain-sess",
		route:    &UpstreamRoute{},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	ch := make(chan mcp.RPCMsg, 16)
	if !sess.addSub(ch) {
		t.Fatalf("addSub failed")
	}
	// The upstream broadcasts a server-initiated request; deliverToOne buffers it in
	// ch and the ID is tracked. The SSE loop never reads it (simulating a client that
	// disconnected with the request still buffered).
	if !sess.broadcastServerRequest(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}) {
		t.Fatalf("broadcastServerRequest reported not delivered; want delivered to the buffered sub")
	}

	sess.removeSubAndDrain(context.Background(), ch)

	// The buffered request must have produced an error reply to the upstream.
	var routed mcp.RPCMsg
	if err := json.Unmarshal(bytes.TrimSpace(up.Bytes()), &routed); err != nil {
		t.Fatalf("no error response written to upstream on drain (%v); bytes: %q", err, up.String())
	}
	if mcp.MsgKey(routed.ID) != "n:7" || routed.Error == nil {
		t.Errorf("upstream message = %+v, want an error response for id 7", routed)
	}
	// The ID must be untracked so a (never-arriving) host response cannot later be
	// misrouted and the tracker is not leaked.
	if sess.serverReqs.take(mcp.MsgKey(mcp.RawJSON(`7`))) {
		t.Errorf("id 7 still tracked after drain; want untracked")
	}
	// The subscription must be gone so no further messages are delivered to ch.
	sess.notifMu.Lock()
	n := len(sess.notifSubs)
	sess.notifMu.Unlock()
	if n != 0 {
		t.Errorf("removeSubAndDrain left %d subscriber(s); want 0", n)
	}
}

// TestHTTPFailServerRequestDelivery_RepliesErrorUpstream covers when a
// server-initiated request is delivered to an SSE subscriber but cannot be relayed
// to the host (e.g. json.Marshal fails on the SSE write path), the shared rescue
// must untrack the ID and reply an error to the upstream so it does not hang. A
// notification (no ID) is a no-op.
func TestHTTPFailServerRequestDelivery_RepliesErrorUpstream(t *testing.T) {
	t.Parallel()
	var up bytes.Buffer
	sess := newTestSession(&httpSession{
		id:       "marshalfail-sess",
		route:    &UpstreamRoute{},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	// Track the server-initiated request ID as broadcastServerRequest would, then
	// simulate the SSE write loop failing to deliver it.
	sess.serverReqs.track(mcp.MsgKey(mcp.RawJSON(`9`)))
	sess.failServerRequestDelivery(
		context.Background(),
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Method: "sampling/createMessage"},
		"proxy: failed to serialize server-initiated request for SSE delivery",
	)

	var routed mcp.RPCMsg
	if err := json.Unmarshal(bytes.TrimSpace(up.Bytes()), &routed); err != nil {
		t.Fatalf("no error response written to upstream (%v); bytes: %q", err, up.String())
	}
	if mcp.MsgKey(routed.ID) != "n:9" || routed.Error == nil {
		t.Errorf("upstream message = %+v, want an error response for id 9", routed)
	}
	if sess.serverReqs.take(mcp.MsgKey(mcp.RawJSON(`9`))) {
		t.Error("id 9 still tracked after delivery failure; want untracked")
	}

	// A notification (no ID) expects no response: nothing is written upstream.
	up.Reset()
	sess.failServerRequestDelivery(
		context.Background(),
		mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/progress"},
		"unused",
	)
	if up.Len() != 0 {
		t.Errorf("a notification delivery failure must not write upstream; got %q", up.String())
	}
}

// TestHTTPFailServerRequestDelivery_WritesCorrectionRecord pins that a delivery
// failure appends an audit record. The request was recorded as an allow when it was
// buffered onto a subscriber channel, so the tamper-evident tape must not stand as
// claiming the host received a request that never reached it.
func TestHTTPFailServerRequestDelivery_WritesCorrectionRecord(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	var up bytes.Buffer
	sess := newTestSession(&httpSession{
		id:       "correction-sess",
		route:    &UpstreamRoute{sink: &routeSink{sink: sink, upstream: "up1"}},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	sess.serverReqs.track(mcp.MsgKey(mcp.RawJSON(`9`)))
	sess.failServerRequestDelivery(
		context.Background(),
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Method: "sampling/createMessage"},
		"proxy: SSE write failed before delivering server-initiated request",
	)
	if err := sink.Close(); err != nil { // flush the drainer to disk
		t.Fatalf("sink.Close: %v", err)
	}

	recs := readAuditRecords(t, logPath)
	rec := findAuditRecord(recs, "sampling/createMessage", "deny")
	if rec == nil {
		t.Fatalf("no correction deny record for the undelivered server-initiated request; records: %+v", recs)
	}
	details, _ := rec["details"].(map[string]interface{})
	if got, _ := details["transport"].(string); got != "http-server-request-undelivered" {
		t.Errorf("correction record transport marker = %q, want http-server-request-undelivered; record: %+v", got, rec)
	}
}

// TestHTTPHandleMCPPost_RemoteModeServerResponseWarnsAndUntracks pins the
// remote-upstream mitigation: a host response whose ID matches a tracked
// server-initiated request, received on a session with no upWriter (remote mode),
// must be untracked and a warning logged rather than silently dropped.
func TestHTTPHandleMCPPost_RemoteModeServerResponseWarnsAndUntracks(t *testing.T) {
	// Mutates os.Stderr; must not run in parallel with other stderr-capturing tests.
	rt := &UpstreamRoute{pdp: pdp.AlwaysAllowPDP{}}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{
		id:    "remote-sess",
		route: rt,
		done:  make(chan struct{}),
		// upWriter intentionally nil: remote-upstream mode has no subprocess pipe.
	})
	// Simulate a tracked server-initiated request ID (as if one had been forwarded).
	sess.serverReqs.track(mcp.MsgKey(mcp.RawJSON(`42`)))
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	body := `{"jsonrpc":"2.0","id":42,"result":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set(SessionHeader, "remote-sess")
	rec := httptest.NewRecorder()
	proxy.handleMCPPost(rec, req, rt)

	_ = w.Close()
	os.Stderr = old
	var logbuf bytes.Buffer
	_, _ = io.Copy(&logbuf, r)

	if rec.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rec.Code)
	}
	// The tracked ID must be removed even though it could not be delivered.
	if sess.serverReqs.take(mcp.MsgKey(mcp.RawJSON(`42`))) {
		t.Errorf("id 42 still tracked after a remote-mode drop; want untracked")
	}
	if logged := logbuf.String(); !strings.Contains(logged, "no upstream writer in remote-upstream mode") {
		t.Errorf("expected a stderr warning about the dropped remote-mode response; got %q", logged)
	}
}

// TestHTTPInitializeNotificationDoesNotCreateSession is the regression: the
// production HTTP handler created a session (and started an upstream) whenever
// method == "initialize" with no session header, before checking isRequest(). A
// JSON-RPC initialize *notification* (no id) therefore spawned a real upstream
// and consumed a session slot; repeated notifications could exhaust the cap or
// spawn unbounded upstreams. An initialize notification must be accepted without
// allocating any session/upstream state.
func TestHTTPInitializeNotificationDoesNotCreateSession(t *testing.T) {
	t.Parallel()
	fake := newFakeUpstream()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	for i := 0; i < 5; i++ {
		resp := postMCPJSON(t, proxySrv, map[string]interface{}{
			"jsonrpc": "2.0", "method": "initialize", "params": map[string]interface{}{},
		}, "")
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("initialize notification: status %d, want %d", resp.StatusCode, http.StatusAccepted)
		}
		if sid := resp.Header.Get(SessionHeader); sid != "" {
			t.Fatalf("initialize notification assigned a session id %q", sid)
		}
		resp.Body.Close()
		if n := proxy.sessionCount(); n != 0 {
			t.Fatalf("after %d initialize notification(s), sessionCount = %d, want 0", i+1, n)
		}
	}

	// A real initialize request (with id) must still create exactly one session.
	sid := initHTTPSession(t, proxySrv)
	if sid == "" {
		t.Fatal("initialize request did not return a session id")
	}
	if n := proxy.sessionCount(); n != 1 {
		t.Fatalf("after one initialize request, sessionCount = %d, want 1", n)
	}
}

// ── handleInitialize ─────────────────────────────────────────────────────

func TestHandleInitialize_NoCaps(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{sessionID: "sess-1"}
	resp := p.buildInitResponse(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "initialize"})

	if resp.Error != nil {
		t.Errorf("unexpected error: %+v", resp.Error)
	}
	if resp.Result == nil {
		t.Error("expected result")
	}
}

func TestHandleInitialize_WithCaps(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{
		sessionID:    "sess-caps",
		upstreamCaps: map[string]interface{}{"tools": map[string]interface{}{"listChanged": true}},
	}
	resp := p.buildInitResponse(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "initialize"})

	var result mcp.InitResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if result.Capabilities == nil {
		t.Error("capabilities should not be nil when upstreamCaps is set")
	}
}

// ── handleHostRequest ─────────────────────────────────────────────────────

func TestHandleHostRequest_Initialize(t *testing.T) {
	t.Parallel()
	hw := &mockHostWriter{}
	p := &StdioProxy{
		sessionID:  "sess-init",
		hostWriter: mcp.NewMsgWriter(&writerAdapter{hw}),
		pdp:        pdp.AlwaysAllowPDP{}, // non-nil PDP invariant; CheckKill clears the way for initialize
	}
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "initialize",
	})
	if len(hw.messages) == 0 {
		t.Error("expected initialize response")
	}
}

func TestHandleHostRequest_Default_UnmappedMethod(t *testing.T) {
	t.Parallel()
	p, hw := closedUpstream(t)
	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "unknown/method",
	})
	if len(hw.messages) != 1 {
		t.Fatalf("expected 1 message for unmapped method, got %d", len(hw.messages))
	}
	if hw.messages[0].Error == nil {
		t.Error("expected error for unmapped method")
	}
}

func TestHandleHostRequest_AllMethods(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method string
		params json.RawMessage
	}{
		{"tools/call", json.RawMessage(`{"name":"read_file","arguments":{"path":"/x"}}`)},
		{"resources/read", json.RawMessage(`{"uri":"file:///test"}`)},
		{"tools/list", nil},
		{"resources/list", nil},
		{"prompts/list", nil},
		{"resources/subscribe", json.RawMessage(`{"uri":"file:///sub"}`)},
		{"prompts/get", json.RawMessage(`{"name":"my-prompt"}`)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()
			p, hw := closedUpstream(t)
			p.handleHostRequest(context.Background(), mcp.RPCMsg{
				JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: tc.method, Params: tc.params,
			})
			if len(hw.messages) == 0 {
				t.Errorf("method %s: expected at least one response", tc.method)
			}
		})
	}
}

// TestDecodeParams_PreservesLargeIntegerPrecision pins the root-cause fix: an
// integer argument above 2^53 must decode to a json.Number carrying its exact
// text, not a float64 that has already rounded it. The default json.Unmarshal
// path yields float64 and loses the distinction.
func TestDecodeParams_PreservesLargeIntegerPrecision(t *testing.T) {
	t.Parallel()
	var params mcp.ToolCallParams
	if err := mcp.DecodeParams(json.RawMessage(`{"name":"t","arguments":{"id":9007199254740993}}`), &params); err != nil {
		t.Fatalf("decodeParams: %v", err)
	}
	num, ok := params.Arguments["id"].(json.Number)
	if !ok {
		t.Fatalf("id type = %T, want json.Number (large ints must survive decode without a lossy float64 round-trip)", params.Arguments["id"])
	}
	if num.String() != "9007199254740993" {
		t.Errorf("id = %q, want %q (exact text preserved)", num.String(), "9007199254740993")
	}
}

// TestMsToDuration_SaturatesInsteadOfOverflowing verifies the timeout/idle
// conversion saturates rather than wrapping. A millisecond value above
// config.MaxDurationMs would otherwise overflow time.Duration to a negative value,
// turning a "very long" timeout into an instant one (expiring upstream calls and
// reaping sessions on sight).
func TestMsToDuration_SaturatesInsteadOfOverflowing(t *testing.T) {
	t.Parallel()
	if got := msToDuration(30000); got != 30*time.Second {
		t.Errorf("msToDuration(30000) = %v, want 30s", got)
	}
	if got := msToDuration(int(config.MaxDurationMs)); got != time.Duration(config.MaxDurationMs)*time.Millisecond {
		t.Errorf("msToDuration(config.MaxDurationMs) = %v, want the exact in-range product", got)
	}
	if got := msToDuration(int(config.MaxDurationMs) + 1); got != time.Duration(math.MaxInt64) {
		t.Errorf("msToDuration(overflow) = %v, want saturated MaxInt64; a wrapped negative would expire timers instantly", got)
	}
}

// ── handleHTTPUpstreamRequest ─────────────────────────────────────────────

func TestHTTPHandleUpstreamRequest_NonSampling(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-x",
		route:    &UpstreamRoute{pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(io.Discard),
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "roots/list"}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case got := <-ch:
		if got.Method != "roots/list" {
			t.Errorf("broadcast method: want roots/list, got %s", got.Method)
		}
	default:
		t.Error("expected message to be broadcast to subscriber")
	}
}

// addSub caps the number of concurrent SSE subscribers on one session at
// maxSubsPerSession, so a client cannot open an unbounded number of GET streams on
// a single session. A removeSub frees a slot again.
func TestHTTPSession_AddSubCapsSubscribers(t *testing.T) {
	t.Parallel()
	s := newTestSession(&httpSession{})
	chs := make([]chan mcp.RPCMsg, 0, maxSubsPerSession)
	for i := 0; i < maxSubsPerSession; i++ {
		ch := make(chan mcp.RPCMsg, 1)
		if !s.addSub(ch) {
			t.Fatalf("addSub %d should succeed below the cap", i)
		}
		chs = append(chs, ch)
	}
	if s.addSub(make(chan mcp.RPCMsg, 1)) {
		t.Fatalf("addSub past maxSubsPerSession (%d) must be rejected", maxSubsPerSession)
	}
	s.removeSub(chs[0])
	if !s.addSub(make(chan mcp.RPCMsg, 1)) {
		t.Fatal("addSub after a removeSub should be accepted again")
	}
}

// A server-initiated request must be delivered to a single SSE subscriber, not
// fanned out to every open stream on the session: broadcasting a
// sampling/createMessage payload would disclose it to unintended streams and let
// multiple clients race to answer the same JSON-RPC id (only the first reaches the
// upstream). With two subscribers, exactly one receives the request.
func TestHTTPHandleUpstreamRequest_ServerRequestDeliveredToOneSubscriber(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-fanout",
		route:    &UpstreamRoute{pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(io.Discard),
	})
	ch1 := make(chan mcp.RPCMsg, 1)
	ch2 := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch1)
	sess.addSub(ch2)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "roots/list"}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	delivered := 0
	for _, ch := range []chan mcp.RPCMsg{ch1, ch2} {
		select {
		case <-ch:
			delivered++
		default:
		}
	}
	if delivered != 1 {
		t.Errorf("server-initiated request must reach exactly one subscriber, reached %d", delivered)
	}
}

func TestHTTPHandleUpstreamRequest_SamplingDeny(t *testing.T) {
	t.Parallel()
	uw := &mockUpstreamWriter{}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	// A ManifestPDP with no system:sampling/createMessage opt-in denies sampling
	// (fail closed). alwaysAllowPDP can no longer be used to exercise the deny
	// path: wiretap mode now OBSERVES sampling rather than hard-blocking it
	// so a real manifest-without-opt-in is what denies.
	denyPDP := newTestManifestPDP(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	sess := newTestSession(&httpSession{
		id:       "sess-deny",
		route:    &UpstreamRoute{pdp: denyPDP, sink: &routeSink{}},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
	})
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	if len(uw.messages) != 1 {
		t.Fatalf("expected 1 upstream error response, got %d", len(uw.messages))
	}
	if uw.messages[0].Error == nil {
		t.Error("expected error response for denied sampling")
	}
}

func TestHTTPHandleUpstreamRequest_SamplingDenyDryRun(t *testing.T) {
	t.Parallel()
	uw := &mockUpstreamWriter{}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-dr",
		route:    &UpstreamRoute{pdp: pdp.AlwaysAllowPDP{}, audit: true, sink: &routeSink{}},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	// dry-run: should broadcast despite denial
	select {
	case <-ch:
	default:
		t.Error("dry-run: expected sampling/createMessage to be broadcast to subscribers")
	}
}

func TestHTTPHandleUpstreamRequest_SamplingDenyAuditOnly(t *testing.T) {
	t.Parallel()
	uw := &mockUpstreamWriter{}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-ao",
		route:    &UpstreamRoute{pdp: pdp.AlwaysAllowPDP{}, audit: true, sink: &routeSink{}},
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case <-ch:
	default:
		t.Error("audit-only: expected sampling/createMessage to be broadcast")
	}
}

func TestHTTPHandleUpstreamRequest_SamplingThroughJWTWrapper(t *testing.T) {
	t.Parallel()
	// With --jwks-uri every route PDP is wrapped in a JWTPDP. The
	// manifest's system:sampling/createMessage opt-in must keep working through
	// the wrapper instead of being denied because the PDP is no longer a
	// *ManifestPDP.
	route := &UpstreamRoute{
		name: "up1",
		pdp: newTestManifestPDP(
			capability.Constraint{Target: "system:sampling/createMessage", Actions: []string{"allow"}},
		),
		sink: &routeSink{},
	}
	_, _ = WrapRoutesWithJWT(map[string]*UpstreamRoute{"up1": route}, pdp.JWTPDPOptions{AllowAnyAudience: true})
	if _, ok := route.pdp.(*pdp.JWTPDP); !ok {
		t.Fatalf("route PDP not wrapped by JWT: %T", route.pdp)
	}

	uw := &mockUpstreamWriter{}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-jwt-sampling",
		route:    route,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case got := <-ch:
		if got.Method != "sampling/createMessage" {
			t.Errorf("broadcast method: want sampling/createMessage, got %s", got.Method)
		}
	default:
		t.Error("expected sampling/createMessage to be broadcast when the manifest opts in behind the JWT wrapper")
	}
	if len(uw.messages) != 0 {
		t.Errorf("expected no error response to upstream, got %d: %+v", len(uw.messages), uw.messages)
	}
}

func TestHTTPHandleUpstreamRequest_SamplingDeniedThroughJWTWrapper_NoOptIn(t *testing.T) {
	t.Parallel()
	// The wrapper must not widen access: a JWT-wrapped manifest without the
	// system: opt-in still denies sampling.
	route := &UpstreamRoute{
		name: "up1",
		pdp: newTestManifestPDP(
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		),
		sink: &routeSink{},
	}
	_, _ = WrapRoutesWithJWT(map[string]*UpstreamRoute{"up1": route}, pdp.JWTPDPOptions{AllowAnyAudience: true})

	uw := &mockUpstreamWriter{}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-jwt-sampling-deny",
		route:    route,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case <-ch:
		t.Error("sampling must not be broadcast when the manifest lacks the system: opt-in")
	default:
	}
	if len(uw.messages) != 1 || uw.messages[0].Error == nil {
		t.Fatalf("expected 1 error response to upstream, got %+v", uw.messages)
	}
}

// killSamplingRoute builds a JWT-wrapped, manifest-opted route sharing the
// given kill-switch manager, mirroring the gateway wiring (LoadUpstreamPDP +
// WrapRoutesWithJWT) so kill state reaches both the wrapper and the inner PDP.
func killSamplingRoute(ks killswitch.Manager) *UpstreamRoute {
	route := &UpstreamRoute{
		name: "up1",
		pdp: newTestManifestPDPWithKS(ks,
			capability.Constraint{Target: "system:sampling/createMessage", Actions: []string{"allow"}},
		),
		sink: &routeSink{},
	}
	_, _ = WrapRoutesWithJWT(map[string]*UpstreamRoute{"up1": route}, pdp.JWTPDPOptions{KillSwitch: ks, AllowAnyAudience: true})
	return route
}

func TestHTTPHandleUpstreamRequest_SamplingKilledSession_Denied(t *testing.T) {
	t.Parallel()
	// Regression for the kill-switch bypass: a killed session must not keep
	// forwarding manifest-opted sampling, JWT wrapping or not.
	ks := killswitch.NewInMemory()
	if err := ks.KillSession(context.Background(), "sess-killed"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}

	uw := &mockUpstreamWriter{}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-killed",
		route:    killSamplingRoute(ks),
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case <-ch:
		t.Error("sampling must not be broadcast for a killed session")
	default:
	}
	if len(uw.messages) != 1 || uw.messages[0].Error == nil {
		t.Fatalf("expected 1 error response to upstream for killed session, got %+v", uw.messages)
	}
}

// TestHTTPInitialize_GlobalKill_RefusesSessionCreation is a regression test:
// a global kill is an emergency stop that blocks ALL requests, so a
// session-creating initialize must be refused (no upstream subprocess/remote
// session spawned, no session id issued) while a global kill is active.
func TestHTTPInitialize_GlobalKill_RefusesSessionCreation(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	if err := ks.ActivateGlobal(context.Background()); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}
	route := &UpstreamRoute{
		name:      "up1",
		transport: "stdio",
		pdp:       newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink:      &routeSink{},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, route)

	if n := proxy.sessionCount(); n != 0 {
		t.Errorf("global kill must refuse session creation; sessionCount=%d", n)
	}
	if sid := w.Header().Get(SessionHeader); sid != "" {
		t.Errorf("no session id should be issued under global kill, got %q", sid)
	}
	var resp mcp.RPCMsg
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	if resp.Error == nil {
		t.Fatalf("expected a JSON-RPC error under global kill, got %s", w.Body.String())
	}
	if want := denialToJSONRPCCode(capability.ErrCodeKillSwitch); resp.Error.Code != want {
		t.Errorf("error code = %d, want %d (KILL_SWITCH)", resp.Error.Code, want)
	}
}

// TestHTTPHandleGet_KilledSession_RefusesStream pins that a killed session cannot
// open or hold the SSE GET notification stream: the GET path now consults the kill
// switch (like the POST methods), so an emergency-stopped session is refused (HTTP
// 403) instead of keeping a live stream receiving upstream notifications until the
// idle reaper fires.
func TestHTTPHandleGet_KilledSession_RefusesStream(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	if err := ks.KillSession(context.Background(), "sess-killed"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	proxy.sessions["sess-killed"] = newTestSession(&httpSession{id: "sess-killed", route: route, done: make(chan struct{})})

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "sess-killed")
	w := httptest.NewRecorder()
	proxy.handleMCPGet(w, req, route)

	if w.Code != http.StatusForbidden {
		t.Errorf("killed-session SSE GET status = %d, want %d (Forbidden)", w.Code, http.StatusForbidden)
	}
	if ct := w.Header().Get("Content-Type"); strings.HasPrefix(ct, ctSSE) {
		t.Errorf("killed-session SSE GET must not open an event stream (Content-Type=%q)", ct)
	}
}

// TestHTTPHandleGet_GlobalKill_RefusesStream mirrors the per-session case for a
// global (kill-all) emergency stop: a session must not be able to open the SSE
// notification stream while a global kill is active, pinning the "(or globally
// killed)" claim in the handler comment and threat model.
func TestHTTPHandleGet_GlobalKill_RefusesStream(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	if err := ks.ActivateGlobal(context.Background()); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	proxy.sessions["sess-any"] = newTestSession(&httpSession{id: "sess-any", route: route, done: make(chan struct{})})

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "sess-any")
	w := httptest.NewRecorder()
	proxy.handleMCPGet(w, req, route)

	if w.Code != http.StatusForbidden {
		t.Errorf("global-kill SSE GET status = %d, want %d (Forbidden)", w.Code, http.StatusForbidden)
	}
	if ct := w.Header().Get("Content-Type"); strings.HasPrefix(ct, ctSSE) {
		t.Errorf("global-kill SSE GET must not open an event stream (Content-Type=%q)", ct)
	}
}

// TestHTTPHandleGet_LiveSession_OpensStream is the control for the kill test: a
// live (un-killed) session still opens the SSE stream, so the kill gate does not
// regress the normal path. The request context is cancelled up front so the
// handler's stream loop returns immediately instead of blocking.
func TestHTTPHandleGet_LiveSession_OpensStream(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	proxy.sessions["sess-live"] = newTestSession(&httpSession{id: "sess-live", route: route, done: make(chan struct{})})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // close the stream immediately so handleMCPGet's loop returns
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody).WithContext(ctx)
	req.Header.Set(SessionHeader, "sess-live")
	w := httptest.NewRecorder()
	proxy.handleMCPGet(w, req, route)

	if w.Code != http.StatusOK {
		t.Errorf("live-session SSE GET status = %d, want %d (OK)", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, ctSSE) {
		t.Errorf("live-session SSE GET must open an event stream, Content-Type=%q", ct)
	}
}

// TestHTTPHandleGet_EvictedSession_ClosesOpenStream pins the kill-eviction half of
// the SSE coverage: a stream that is ALREADY OPEN when the session is killed is torn
// down promptly, not left receiving upstream notifications until the idle ceiling
// closes it. The GET refusal alone only stops a killed session from (re)opening a
// stream; evictStreams (driven by /control/kill) closes the one already held.
func TestHTTPHandleGet_EvictedSession_ClosesOpenStream(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{id: "sess-evict", route: route, done: make(chan struct{}), evicted: make(chan struct{})})
	proxy.sessions["sess-evict"] = sess

	// Background context (never cancelled) so the stream loop blocks until eviction,
	// not on a client disconnect.
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "sess-evict")
	w := httptest.NewRecorder()

	returned := make(chan struct{})
	go func() {
		proxy.handleMCPGet(w, req, route)
		close(returned)
	}()

	// Wait until the stream is actually open (subscriber registered) so the eviction
	// races a live stream, not the handler's setup.
	deadline := time.Now().Add(2 * time.Second)
	for !sess.hasSubscribers() {
		if time.Now().After(deadline) {
			t.Fatal("SSE stream never opened")
		}
		time.Sleep(time.Millisecond)
	}

	// Evict exactly as the kill path does; the open stream must return promptly.
	proxy.evictSessionStreams("sess-evict")

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("evicted SSE stream did not close")
	}

	// The stream did open (200 + SSE) and then unsubscribed on exit.
	if w.Code != http.StatusOK {
		t.Errorf("SSE GET status = %d, want %d (OK)", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, ctSSE) {
		t.Errorf("SSE GET must have opened an event stream, Content-Type=%q", ct)
	}
	if sess.hasSubscribers() {
		t.Error("evicted stream must unsubscribe on exit; session still has subscribers")
	}
}

// TestHandleSessionPost_OwnerMismatchNotification_Acks202 is the regression for a
// denied initialize NOTIFICATION (no id) on the session-owner-mismatch branch getting a
// JSON-RPC error body under an implicit HTTP 200. An id-less initialize carrying a
// victim's Mcp-Session-Id reaches handleSessionPost (the session-creating branch requires
// msg.IsRequest()), passes the audience pin, and hits the owner-mismatch branch. Like the
// sibling audience/kill deny branches it must ack the fire-and-forget notification with a
// bodyless 202 — a JSON-RPC error with the id omitted (RPCMsg.ID is json:"id,omitempty")
// is not a valid response to a notification and is indistinguishable from a readiness ack.
func TestHandleSessionPost_OwnerMismatchNotification_Acks202(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	// A session BOUND to a creating identity, so a request from a different (here: no)
	// identity is an owner mismatch.
	sess := newTestSession(&httpSession{
		id:     "victim",
		route:  route,
		done:   make(chan struct{}),
		claims: &pdp.JWTClaims{Issuer: "iss-a", Subject: "sub-a"},
	})
	proxy.sessions["victim"] = sess

	// initialize NOTIFICATION: method set, no id. The request context carries no JWT
	// identity, so ownerMismatch is true.
	msg := mcp.RPCMsg{JSONRPC: "2.0", Method: "initialize"}
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "victim")
	w := httptest.NewRecorder()

	proxy.handleSessionPost(w, req, route, "victim", msg)

	if w.Code != http.StatusAccepted {
		t.Fatalf("owner-mismatch initialize notification status = %d, want %d (Accepted)", w.Code, http.StatusAccepted)
	}
	if body := strings.TrimSpace(w.Body.String()); body != "" {
		t.Fatalf("owner-mismatch notification must be acked with an EMPTY 202 body, got %q", body)
	}
}

// TestHandleSessionPost_KilledReapedSession_DeniesWithKillSwitch is the regression for
// the interaction between the kill-triggered session teardown (reapKilledSession removes
// the session from the registry) and the documented kill contract (a killed session's
// requests are denied with KILL_SWITCH). Because the reap removes the session, a
// subsequent POST to its id no longer resolves — but it must still return a JSON-RPC
// KILL_SWITCH deny, not a bare 404 (which the demo e2e "post-kill read_file -> DENY
// (KILL_SWITCH)" assertion, and any client relying on the kill contract, would see as a
// transport error). The kill store outlives the reaped registry entry, so the POST path
// consults it on a not-found and renders the deny.
func TestHandleSessionPost_KilledReapedSession_DeniesWithKillSwitch(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	// The session has been killed AND reaped out of the registry (its subprocess/slot
	// reclaimed) — exactly the post-kill state reapKilledSession leaves behind — but the
	// kill store still records the id.
	if err := ks.KillSession(context.Background(), "gone"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}

	t.Run("request gets a KILL_SWITCH JSON-RPC deny, not 404", func(t *testing.T) {
		msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "tools/call"}
		req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
		req.Header.Set(SessionHeader, "gone")
		w := httptest.NewRecorder()

		proxy.handleSessionPost(w, req, route, "gone", msg)

		if w.Code == http.StatusNotFound {
			t.Fatalf("a killed+reaped session's request must not 404; it must deny with KILL_SWITCH")
		}
		var resp mcp.RPCMsg
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response is not JSON-RPC: %v (body=%q, status=%d)", err, w.Body.String(), w.Code)
		}
		if resp.Error == nil {
			t.Fatalf("expected a JSON-RPC error, got %s", w.Body.String())
		}
		if want := denialToJSONRPCCode(capability.ErrCodeKillSwitch); resp.Error.Code != want {
			t.Errorf("error code = %d, want %d (KILL_SWITCH)", resp.Error.Code, want)
		}
	})

	t.Run("genuinely unknown session still 404s", func(t *testing.T) {
		msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`8`), Method: "tools/call"}
		req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
		req.Header.Set(SessionHeader, "never-existed")
		w := httptest.NewRecorder()

		proxy.handleSessionPost(w, req, route, "never-existed", msg)

		if w.Code != http.StatusNotFound {
			t.Errorf("an unkilled, unknown session must still 404; got %d (%s)", w.Code, w.Body.String())
		}
	})
}

// TestRegisterSession_FailsClosedAfterShutdown is the regression for a slow
// in-flight initialize registering its session AFTER closeAllSessions has emptied the
// registry and the reaper was canceled — a leaked upstream subprocess + goroutines that
// nothing would ever reap. closeAllSessions latches shuttingDown under the lock before
// the snapshot/swap, so any registerSession that lands afterward fails closed;
// newSession/newRemoteSession then tear down the upstream they just started.
func TestRegisterSession_FailsClosedAfterShutdown(t *testing.T) {
	t.Parallel()
	p := newHTTPProxy(httpProxyOptions{})

	// closeAllSessions runs during Serve teardown; it latches shuttingDown.
	p.closeAllSessions()

	sess := newTestSession(&httpSession{id: "late", done: make(chan struct{})})
	err := p.registerSession(sess, p.currentReapGen())
	if !errors.Is(err, errShuttingDown) {
		t.Fatalf("registerSession after shutdown must fail closed with errShuttingDown, got %v", err)
	}
	if p.getSession("late") != nil {
		t.Fatal("a session registering after shutdown must not leak into the registry")
	}
}

// TestRegisterSession_FailsClosedAfterConcurrentGlobalReap is the regression for the
// kill-triggered slot leak: a session-creating initialize that captured its reap
// generation BEFORE a global kill's reapAllKilledSessions swept the registry must not
// register into the fresh (post-sweep) map with a live upstream the sweep never saw.
// Unlike TestRegisterSession_FailsClosedAfterShutdown, the registry must stay usable
// AFTER the race is rejected — a fresh registerSession (with the current generation)
// must still succeed, since reapAllKilledSessions (unlike closeAllSessions) does not
// latch shuttingDown.
func TestRegisterSession_FailsClosedAfterConcurrentGlobalReap(t *testing.T) {
	t.Parallel()
	p := newHTTPProxy(httpProxyOptions{})

	// Simulates newSession/newRemoteSession capturing the generation before starting a
	// (possibly slow) upstream handshake.
	staleGen := p.currentReapGen()

	// A global kill fires and reapAllKilledSessions sweeps the registry while the
	// simulated handshake above is still "in flight" (nothing registered yet, matching
	// an empty registry mid-handshake).
	p.reapAllKilledSessions()

	// The handshake "finishes" and registers using the generation it captured before
	// the sweep: must be rejected, and must not leak into the registry.
	late := newTestSession(&httpSession{id: "raced", done: make(chan struct{})})
	if err := p.registerSession(late, staleGen); !errors.Is(err, errRacedReap) {
		t.Fatalf("registerSession racing a global reap must fail closed with errRacedReap, got %v", err)
	}
	if p.getSession("raced") != nil {
		t.Fatal("a session racing a global reap must not leak into the registry")
	}

	// The registry must still be usable afterward (reapAllKilledSessions does not latch
	// shuttingDown): a session that captures the CURRENT generation registers normally.
	fresh := newTestSession(&httpSession{id: "fresh", done: make(chan struct{})})
	if err := p.registerSession(fresh, p.currentReapGen()); err != nil {
		t.Fatalf("registerSession after a global reap (fresh generation) must succeed, got %v", err)
	}
	if p.getSession("fresh") == nil {
		t.Fatal("a session registering with the current generation after a reap must be present in the registry")
	}
}

// TestEvictAllSessionStreams_ClosesOpenStream pins the shutdown-latency fix: the
// teardown evicts every open SSE GET stream BEFORE srv.Shutdown so an in-flight SSE
// handler (which Shutdown does not cancel) returns immediately and Shutdown drains
// promptly, instead of pinning the full shutdownMs. This exercises evictAllSessionStreams
// directly — the call the teardown defer now makes first.
func TestEvictAllSessionStreams_ClosesOpenStream(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{id: "sess-a", route: route, done: make(chan struct{}), evicted: make(chan struct{})})
	proxy.sessions["sess-a"] = sess

	// Background context (never cancelled) so the SSE loop blocks until eviction, exactly
	// as a long-lived client stream would during shutdown.
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "sess-a")
	w := httptest.NewRecorder()

	returned := make(chan struct{})
	go func() {
		proxy.handleMCPGet(w, req, route)
		close(returned)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !sess.hasSubscribers() {
		if time.Now().After(deadline) {
			t.Fatal("SSE stream never opened")
		}
		time.Sleep(time.Millisecond)
	}

	// The teardown's first step: evict every open stream so Shutdown does not block on it.
	proxy.evictAllSessionStreams()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("regression: evictAllSessionStreams did not close the open SSE stream; srv.Shutdown would block the full shutdownMs")
	}
}

// flushWriterFailingAfter is an http.ResponseWriter that supports flushing but
// starts returning an error from Write after the first failAfter successful
// writes, so a test can let the initial keepalive frame succeed and then force the
// next frame's write to fail.
type flushWriterFailingAfter struct {
	hdr       http.Header
	writes    int
	failAfter int
}

func (f *flushWriterFailingAfter) Header() http.Header {
	if f.hdr == nil {
		f.hdr = make(http.Header)
	}
	return f.hdr
}
func (f *flushWriterFailingAfter) WriteHeader(int) {}
func (f *flushWriterFailingAfter) Flush()          {}
func (f *flushWriterFailingAfter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes > f.failAfter {
		return 0, errors.New("simulated SSE write failure")
	}
	return len(p), nil
}

// TestHTTPHandleGet_WriteErrorUnblocksInflightServerRequest pins the fix for an
// SSE-delivery leak: when the loop has already consumed a server-initiated request
// from the subscriber channel and the frame write then fails (stuck reader /
// disconnect), the request must be unblocked with an error reply to the upstream —
// not left tracked until the idle reaper. removeSubAndDrain only recovers requests
// STILL buffered in the channel, so the consumed-then-failed one needs the explicit
// failServerRequestDelivery in the write-error path.
func TestHTTPHandleGet_WriteErrorUnblocksInflightServerRequest(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{},
	}
	var up bytes.Buffer
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{
		id:       "sess-werr",
		route:    route,
		done:     make(chan struct{}),
		evicted:  make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	proxy.sessions[sess.id] = sess

	// Let the initial keepalive frame (write #1) succeed, then fail the data frame.
	w := &flushWriterFailingAfter{failAfter: 1}
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, sess.id)

	returned := make(chan struct{})
	go func() {
		proxy.handleMCPGet(w, req, route)
		close(returned)
	}()

	// Wait until the stream registered its subscriber, then broadcast a
	// server-initiated request so the loop consumes it and the next write fails.
	deadline := time.Now().Add(2 * time.Second)
	for !sess.hasSubscribers() {
		if time.Now().After(deadline) {
			t.Fatal("SSE stream never opened")
		}
		time.Sleep(time.Millisecond)
	}
	if !sess.broadcastServerRequest(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Method: "sampling/createMessage"}) {
		t.Fatal("broadcastServerRequest reported not delivered; want delivered to the open stream")
	}

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return after the SSE write error")
	}

	// The consumed-then-failed request must have been unblocked with an error reply,
	// and its ID untracked — exactly as the buffered-drain path does.
	var routed mcp.RPCMsg
	if err := json.Unmarshal(bytes.TrimSpace(up.Bytes()), &routed); err != nil {
		t.Fatalf("no error reply written to upstream for the in-flight request (%v); bytes=%q", err, up.String())
	}
	if mcp.MsgKey(routed.ID) != "n:9" || routed.Error == nil {
		t.Errorf("upstream message = %+v, want an error reply for id 9", routed)
	}
	if sess.serverReqs.take(mcp.MsgKey(mcp.RawJSON(`9`))) {
		t.Error("id 9 still tracked after the write-error teardown; want untracked")
	}
}

// TestHTTPInitialize_StrictAuditDegraded_RefusesSessionCreation pins that, under
// --require-audit=strict, a session-creating initialize is refused once the audit
// trail has degraded: spawning/contacting an upstream is a privileged side effect,
// so it must not happen while records cannot be trusted to be written. A real sink
// is forced degraded by recording after Close (a post-close record counts as a
// drop), so AuditDegraded() reports true without racing the drainer.
func TestHTTPInitialize_StrictAuditDegraded_RefusesSessionCreation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("audit.Close: %v", err)
	}
	// A post-close record is counted as a drop, so the sink reports degraded.
	sink.RecordDeny(context.Background(), "", "x", "x", capability.ErrCodeAuthorizationFailed, "", nil, false)
	if degraded, _, _ := sink.AuditDegraded(); !degraded {
		t.Fatal("precondition: sink must report degraded after a post-close drop")
	}

	route := &UpstreamRoute{
		name:      "up1",
		transport: "stdio",
		pdp:       newTestManifestPDPWithKS(killswitch.NewInMemory(), capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink:      &routeSink{sink: sink},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession), requireAuditStrict: true}

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, route)

	if n := proxy.sessionCount(); n != 0 {
		t.Errorf("a degraded strict-audit trail must refuse session creation; sessionCount=%d", n)
	}
	if sid := w.Header().Get(SessionHeader); sid != "" {
		t.Errorf("no session id should be issued under a degraded strict-audit trail, got %q", sid)
	}
	var resp mcp.RPCMsg
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	if resp.Error == nil {
		t.Fatalf("expected a JSON-RPC error under a degraded strict-audit trail, got %s", w.Body.String())
	}
	if want := denialToJSONRPCCode(capability.ErrCodeAuditUnavailable); resp.Error.Code != want {
		t.Errorf("error code = %d, want %d (AUDIT_UNAVAILABLE)", resp.Error.Code, want)
	}
}

func TestHTTPHandleUpstreamRequest_SamplingGlobalKill_Denied(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	if err := ks.ActivateGlobal(context.Background()); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}

	uw := &mockUpstreamWriter{}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-any",
		route:    killSamplingRoute(ks),
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case <-ch:
		t.Error("sampling must not be broadcast under a global kill")
	default:
	}
	if len(uw.messages) != 1 || uw.messages[0].Error == nil {
		t.Fatalf("expected 1 error response to upstream under global kill, got %+v", uw.messages)
	}
}

func TestHTTPHandleUpstreamRequest_SamplingKilledAgent_Denied(t *testing.T) {
	t.Parallel()
	// Per-agent kills must cover server-initiated sampling: the request carries
	// no token, so the handler attributes the session's last-validated agent
	// identity to the kill check.
	ks := killswitch.NewInMemory()
	if err := ks.KillAgent(context.Background(), "agent-x"); err != nil {
		t.Fatalf("KillAgent: %v", err)
	}

	uw := &mockUpstreamWriter{}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-agent",
		route:    killSamplingRoute(ks),
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
		claims:   &pdp.JWTClaims{AgentID: "agent-x"},
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case <-ch:
		t.Error("sampling must not be broadcast for a session whose agent is killed")
	default:
	}
	if len(uw.messages) != 1 || uw.messages[0].Error == nil {
		t.Fatalf("expected 1 error response to upstream for killed agent, got %+v", uw.messages)
	}
}

func TestHTTPHandleUpstreamRequest_NonSamplingKilledAgent_Denied(t *testing.T) {
	t.Parallel()
	// Per-agent kills must also cover NON-sampling server-initiated requests
	// (roots/list, elicitation/create), not just sampling. The request carries no
	// token, so the handler attributes the session's last-validated agent identity
	// to the kill check — which only reaches the agent dimension if the claims are
	// attached to the context before the non-sampling kill check, not solely inside
	// the sampling branch.
	ks := killswitch.NewInMemory()
	if err := ks.KillAgent(context.Background(), "agent-x"); err != nil {
		t.Fatalf("KillAgent: %v", err)
	}

	uw := &mockUpstreamWriter{}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-agent",
		route:    killSamplingRoute(ks),
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
		claims:   &pdp.JWTClaims{AgentID: "agent-x"},
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "roots/list"}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case <-ch:
		t.Error("roots/list must not be broadcast for a session whose agent is killed")
	default:
	}
	if len(uw.messages) != 1 || uw.messages[0].Error == nil {
		t.Fatalf("expected 1 error response to upstream for killed agent, got %+v", uw.messages)
	}
}

func TestHTTPHandleUpstreamRequest_SamplingAuditMode_RecordsDeny(t *testing.T) {
	t.Parallel()
	// Audit mode must record the would-be sampling denial (with its real code),
	// not just an allow — mirroring the stdio handler and stats' OBSERVED bucket.
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	route := &UpstreamRoute{
		name: "up1",
		pdp: newTestManifestPDP(
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		),
		audit: true,
		sink:  &routeSink{sink: sink, upstream: "up1"},
	}
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "sess-audit",
		route:    route,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(io.Discard),
	})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case <-ch:
	default:
		t.Error("audit mode: expected sampling/createMessage to be broadcast")
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("closing sink: %v", err)
	}
	recs := readAuditRecords(t, dir+"/audit.jsonl")
	found := false
	for _, rec := range recs {
		if rec["decision"] == "deny" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an observed deny record for audit-mode sampling; got %+v", recs)
	}
}

func TestHTTPHandleUpstreamRequest_NonSampling_WritesAuditRecord(t *testing.T) {
	t.Parallel()
	// A forwarded server-initiated request that is NOT sampling (roots/list,
	// elicitation/create, …) must still produce an audit record like every other
	// forwarded request, so the OCSF tape shows the host received and executed it.
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	route := &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{sink: sink, upstream: "up1"}}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{id: "sess-roots", route: route, done: make(chan struct{}), upWriter: mcp.NewMsgWriter(io.Discard)})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "roots/list"}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case got := <-ch:
		if got.Method != "roots/list" {
			t.Errorf("broadcast method: want roots/list, got %s", got.Method)
		}
	default:
		t.Error("expected roots/list to be broadcast to subscriber")
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("closing sink: %v", err)
	}
	recs := readAuditRecords(t, dir+"/audit.jsonl")
	if len(recs) != 1 {
		t.Fatalf("want 1 audit record for the forwarded roots/list, got %d: %+v", len(recs), recs)
	}
	if recs[0]["decision"] != "allow" || recs[0]["method"] != "roots/list" {
		t.Errorf("record = decision %v method %v, want allow roots/list", recs[0]["decision"], recs[0]["method"])
	}
}

func TestHTTPHandleUpstreamRequest_SamplingAuditMode_RecordsDenyThenAllow(t *testing.T) {
	t.Parallel()
	// In route audit mode a would-be-denied sampling request is forwarded,
	// and the tape must carry BOTH the observed deny AND a following allow that
	// confirms the forward, mirroring enforcedForward's two-record pattern.
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	route := &UpstreamRoute{
		name: "up1",
		pdp: newTestManifestPDP( // no sampling opt-in → would deny under enforcement
			capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		),
		audit: true,
		sink:  &routeSink{sink: sink, upstream: "up1"},
	}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{id: "sess-audit2", route: route, done: make(chan struct{}), upWriter: mcp.NewMsgWriter(io.Discard)})
	ch := make(chan mcp.RPCMsg, 1)
	sess.addSub(ch)

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage", Params: json.RawMessage(`{}`)}
	proxy.handleHTTPUpstreamRequest(context.Background(), sess, msg)

	select {
	case <-ch:
	default:
		t.Error("audit mode: expected sampling/createMessage to be broadcast")
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("closing sink: %v", err)
	}
	recs := readAuditRecords(t, dir+"/audit.jsonl")
	if len(recs) != 2 {
		t.Fatalf("want 2 records (deny then allow), got %d: %+v", len(recs), recs)
	}
	if recs[0]["decision"] != "deny" {
		t.Errorf("first record decision = %v, want deny", recs[0]["decision"])
	}
	if recs[1]["decision"] != "allow" {
		t.Errorf("second record decision = %v, want allow", recs[1]["decision"])
	}
}

func TestHTTPSession_AgentClaimsCapturedAtInitialize(t *testing.T) {
	t.Parallel()
	// The session captures the initialize request's validated claims; the
	// upstream-initiated sampling path attributes them to the kill check and
	// audit record (see handleHTTPUpstreamRequest).
	ctx := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{AgentID: "agent-x"})
	sess := newTestSession(&httpSession{claims: pdp.JWTClaimsPtr(ctx)})
	if sess.claims == nil || sess.claims.AgentID != "agent-x" {
		t.Fatalf("claims not captured from ctx: %+v", sess.claims)
	}
}

// ── broadcast ─────────────────────────────────────────────────────────────

func TestHTTPBroadcast_WithSubscribers(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{done: make(chan struct{})})

	ch1 := make(chan mcp.RPCMsg, 2)
	ch2 := make(chan mcp.RPCMsg, 2)
	sess.addSub(ch1)
	sess.addSub(ch2)

	msg := mcp.RPCMsg{JSONRPC: "2.0", Method: "notification/test"}
	sess.broadcast(msg)

	for i, ch := range []chan mcp.RPCMsg{ch1, ch2} {
		select {
		case got := <-ch:
			if got.Method != "notification/test" {
				t.Errorf("sub %d: wrong method %s", i, got.Method)
			}
		default:
			t.Errorf("sub %d: expected message", i)
		}
	}
}

func TestHTTPBroadcast_SlowSubscriberDropped(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{done: make(chan struct{})})

	// Unbuffered channel — any send would block; the default branch must fire.
	slow := make(chan mcp.RPCMsg)
	sess.addSub(slow)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.broadcast(mcp.RPCMsg{JSONRPC: "2.0", Method: "notify"})
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("broadcast blocked on slow subscriber")
	}
}

// ── forwardNotification (httpSession) ────────────────────────────────────

func TestHTTPForwardNotification_LocalMode(t *testing.T) {
	t.Parallel()
	uw := &mockUpstreamWriter{}
	sess := newTestSession(&httpSession{
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
	})
	msg := mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/initialized"}
	sess.forwardNotification(context.Background(), msg)

	if len(uw.messages) != 1 {
		t.Fatalf("expected 1 upstream message, got %d", len(uw.messages))
	}
	if uw.messages[0].Method != "notifications/initialized" {
		t.Errorf("wrong method: %s", uw.messages[0].Method)
	}
}

// TestHTTPHandleSessionPost_EnforcedMethodNotificationDenied is the regression
// for each enforced method (tools/call, resources/read, resources/subscribe,
// prompts/get) framed as a POST notification (no id): IsNotification's
// classification is purely structural, so before the fix nothing stopped a
// notification-shaped enforced call from being forwarded to the upstream
// verbatim via forwardNotification, bypassing both the PDP decision and the
// audit log. Each must instead be denied and recorded, and never reach the
// upstream — mirroring the stdio transport's forwardHostNotification guard.
func TestHTTPHandleSessionPost_EnforcedMethodNotificationDenied(t *testing.T) {
	methods := []string{
		capability.MethodToolsCall,
		capability.MethodResourcesRead,
		capability.MethodResourcesSubscribe,
		capability.MethodPromptsGet,
	}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			sink, logPath := newTempAuditSink(t)
			policy := newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}})

			var up bytes.Buffer
			rt := &UpstreamRoute{pdp: policy, sink: &routeSink{sink: sink, upstream: "up1"}}
			proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
			sess := newTestSession(&httpSession{
				id:       "notif-bypass-sess",
				route:    rt,
				done:     make(chan struct{}),
				upWriter: mcp.NewMsgWriter(&up),
			})
			proxy.mu.Lock()
			proxy.sessions[sess.id] = sess
			proxy.mu.Unlock()

			body := fmt.Sprintf(`{"jsonrpc":"2.0","method":%q,"params":{"name":"delete_all","arguments":{},"uri":"file:///x"}}`, method)
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			req.Header.Set(SessionHeader, "notif-bypass-sess")
			w := httptest.NewRecorder()
			proxy.handleMCPPost(w, req, rt)

			if w.Code != http.StatusAccepted {
				t.Errorf("expected 202, got %d", w.Code)
			}
			if up.Len() != 0 {
				t.Errorf("a notification-framed %s must never reach the upstream; got %q", method, up.String())
			}
			if err := sink.Close(); err != nil { // flush the drainer to disk
				t.Fatalf("sink.Close: %v", err)
			}
			recs := readAuditRecords(t, logPath)
			rec := findAuditRecordByMethod(recs, method, "deny")
			if rec == nil {
				t.Fatalf("no deny record for the notification-framed %s; records: %+v", method, recs)
			}
			if code, _ := rec["denial_code"].(string); code != codeInvalidRequest {
				t.Errorf("denial_code = %q, want %q; record: %+v", code, codeInvalidRequest, rec)
			}
		})
	}
}

// TestHTTPHandleSessionPost_UnmappedNotificationDeniedAndRecorded is the HTTP
// analogue of TestStdioForwardHostNotification_UnmappedNotificationDeniedAndRecorded:
// a notification method that is neither swallowed nor one of the four enforced
// Decide* methods — e.g. a novel or unrecognized method like "tools/uninstall" —
// must be dropped and recorded like any other unmapped method, not forwarded to
// the upstream verbatim.
func TestHTTPHandleSessionPost_UnmappedNotificationDeniedAndRecorded(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	policy := newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}})

	var up bytes.Buffer
	rt := &UpstreamRoute{pdp: policy, sink: &routeSink{sink: sink, upstream: "up1"}}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{
		id:       "unmapped-notif-sess",
		route:    rt,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	const method = "tools/uninstall"
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":%q,"params":{}}`, method)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set(SessionHeader, "unmapped-notif-sess")
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, rt)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", w.Code)
	}
	if up.Len() != 0 {
		t.Errorf("an unmapped notification-framed method must never reach the upstream; got %q", up.String())
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}
	recs := readAuditRecords(t, logPath)
	rec := findAuditRecordByMethod(recs, method, "deny")
	if rec == nil {
		t.Fatalf("no deny record for the unmapped notification %q; records: %+v", method, recs)
	}
	if code, _ := rec["denial_code"].(string); code != capability.ErrCodeAuthorizationFailed {
		t.Errorf("denial_code = %q, want %q; record: %+v", code, capability.ErrCodeAuthorizationFailed, rec)
	}
}

// TestHTTPHandleSessionPost_MidSessionInitializeSwallowed is a regression: an
// id-less "initialize" POSTed on an existing session (IsNotification's
// classification is purely structural, so a client can send "initialize" with no
// id and have it counted as a notification even though the method is ordinarily a
// request) must be swallowed exactly like notifications/initialized, not forwarded
// verbatim to the upstream via forwardNotification — which would let a client
// re-trigger the upstream's handshake outside dispatchRequest's kill gate and
// audit trail. Mirrors the sessionless path's existing drop of the same message.
func TestHTTPHandleSessionPost_MidSessionInitializeSwallowed(t *testing.T) {
	t.Parallel()

	sink, _ := newTempAuditSink(t)
	policy := newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}})
	var up bytes.Buffer
	rt := &UpstreamRoute{pdp: policy, sink: &routeSink{sink: sink}}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession)}
	sess := newTestSession(&httpSession{
		id:       "mid-session-init-sess",
		route:    rt,
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(&up),
	})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	body := `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set(SessionHeader, "mid-session-init-sess")
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, rt)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", w.Code)
	}
	if up.Len() != 0 {
		t.Errorf("a mid-session initialize notification must never reach the upstream; got %q", up.String())
	}
}

// ── closeAllSessions ──────────────────────────────────────────────────────

func TestHTTPCloseAllSessions(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions:   make(map[string]*httpSession),
		shutdownMs: 100,
	}

	// Two remote-mode sessions (upHTTPClient set → close() just closes done channel)
	for _, id := range []string{"s1", "s2"} {
		sess := newTestSession(&httpSession{
			id:           id,
			done:         make(chan struct{}),
			upHTTPClient: &http.Client{},
		})
		proxy.sessions[id] = sess
	}

	proxy.closeAllSessions()

	proxy.mu.Lock()
	remaining := len(proxy.sessions)
	proxy.mu.Unlock()

	if remaining != 0 {
		t.Errorf("sessions map should be empty after closeAllSessions, got %d", remaining)
	}
}

// ── httpSession.close (remote mode) ──────────────────────────────────────

func TestHTTPSessionClose_RemoteMode(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	sess := newTestSession(&httpSession{
		done:         done,
		upHTTPClient: &http.Client{},
	})
	sess.close(100)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("remote-mode close did not close done channel")
	}

	// Second close should be idempotent.
	sess.close(100)
}

// ── HTTPProxy.Serve ───────────────────────────────────────────────────────

func TestHTTPProxy_Serve_CancelContext(t *testing.T) {
	proxy := &HTTPProxy{
		bind:       "127.0.0.1",
		port:       0, // OS chooses a free port
		shutdownMs: 50,
		sessions:   make(map[string]*httpSession),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- proxy.Serve(ctx) }()

	// Wait briefly for the server to start.
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Serve returned unexpected error after context cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

// TestHTTPProxy_Serve_IPv6Bind is the regression for the listen-address builder:
// a bare IPv6 bind ("::1") must be bracketed before ":port" (net.JoinHostPort), or
// net.Listen rejects it ("too many colons in address") and the proxy never serves.
// The pre-fix fmt.Sprintf("%s:%d") produced "::1:0", breaking every IPv6 bind.
func TestHTTPProxy_Serve_IPv6Bind(t *testing.T) {
	// Skip where the environment has no IPv6 loopback rather than fail spuriously.
	if l, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	} else {
		_ = l.Close()
	}

	proxy := &HTTPProxy{
		bind:       "::1", // bare IPv6 literal, the natural YAML form
		port:       0,     // OS chooses a free port
		shutdownMs: 50,
		sessions:   make(map[string]*httpSession),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- proxy.Serve(ctx) }()

	// A malformed listen address fails fast on errCh; a healthy listener keeps
	// serving until the context is cancelled.
	select {
	case err := <-errCh:
		t.Fatalf("Serve failed to bind IPv6 (::1): %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Serve returned unexpected error after context cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

// ── cmdVersion / printUsage ───────────────────────────────────────────────

// ── readUpstream (httpSession) ────────────────────────────────────────────

func TestHTTPReadUpstream_Paths(t *testing.T) {
	t.Parallel()
	pr, pw := io.Pipe()

	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	sess := newTestSession(&httpSession{
		id:       "ru-sess",
		proxy:    proxy,
		route:    &UpstreamRoute{pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}},
		done:     make(chan struct{}),
		upReader: mcp.NewMsgReader(pr),
		upWriter: mcp.NewMsgWriter(io.Discard),
		pending:  make(map[string]chan upstreamResult),
	})
	ch := make(chan mcp.RPCMsg, 4)
	sess.addSub(ch)

	// Start readUpstream in a goroutine first (io.Pipe is unbuffered).
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		sess.readUpstream(context.Background())
	}()

	writer := mcp.NewMsgWriter(pw)
	// Notification → broadcast
	_ = writer.Write(mcp.RPCMsg{JSONRPC: "2.0", Method: "server/notification"})
	// Server-initiated request (sampling → denied, error written to upstream)
	_ = writer.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`5`), Method: "sampling/createMessage",
		Params: json.RawMessage(`{}`)})
	// Response with no matching pending → dropped
	_ = writer.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`99`)})
	// Close pipe → EOF → readUpstream returns (also closes sess.done)
	pw.Close()

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("readUpstream did not return after pipe was closed")
	}

	select {
	case <-sess.done:
	default:
		t.Error("readUpstream must close sess.done when it returns")
	}

	// Notification should have been broadcast
	select {
	case got := <-ch:
		if got.Method != "server/notification" {
			t.Errorf("broadcast method: want server/notification, got %s", got.Method)
		}
	default:
		t.Error("expected notification to be broadcast")
	}
}

// ── httpSession.initUpstream ──────────────────────────────────────────────

func TestHTTPSession_initUpstream_Success(t *testing.T) {
	t.Parallel()

	// Build a proper two-pipe setup simulating a fake MCP upstream.
	upstreamR, upstreamW := io.Pipe()     // session writes here; fake upstream reads
	downstreamR, downstreamW := io.Pipe() // fake upstream writes here; session reads

	sess := newTestSession(&httpSession{
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(upstreamW),
		upReader: mcp.NewMsgReader(downstreamR),
	})

	// Fake upstream goroutine: respond to initialize, then return.
	go func() {
		defer func() {
			downstreamW.Close()
			upstreamR.Close()
		}()
		r := mcp.NewMsgReader(upstreamR)
		w := mcp.NewMsgWriter(downstreamW)
		for {
			msg, err := r.Read()
			if err != nil {
				return
			}
			switch msg.Method {
			case "initialize":
				result := mcp.InitResult{
					ProtocolVersion: MCPProtocolVersion,
					Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
					ServerInfo:      map[string]interface{}{"name": "fake", "version": "0.1"},
				}
				resp, _ := mcp.SuccessResponse(msg.ID, result)
				_ = w.Write(resp)
			case "notifications/initialized":
				return
			}
		}
	}()

	t.Cleanup(func() {
		upstreamW.Close()
		downstreamW.Close()
	})

	if err := sess.initUpstream(context.Background()); err != nil {
		t.Errorf("initUpstream failed: %v", err)
	}
}

func TestHTTPSession_initUpstream_WriteError(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(io.Discard),           // write succeeds but...
		upReader: mcp.NewMsgReader(bytes.NewReader(nil)), // EOF immediately
	})
	// upReader returns EOF immediately → initUpstream fails reading response
	err := sess.initUpstream(context.Background())
	if err == nil {
		t.Error("expected error when upstream closes before responding")
	}
}

// TestNewHTTPProxyGateway_MalformedTrustedProxyCIDREntryWarns is a regression test:
// GatewayConfig.Validate rejects a malformed listen.trustedProxyCIDRs entry before
// the CLI ever reaches NewHTTPProxyGateway, but the constructor is exported and a
// caller that bypasses Validate must still be warned rather than have the entry
// silently dropped with no signal. Valid entries alongside the malformed one must
// still compile and take effect.
func TestNewHTTPProxyGateway_MalformedTrustedProxyCIDREntryWarns(t *testing.T) {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	proxy := NewHTTPProxyGateway(HTTPGatewayOptions{
		Routes:            map[string]*UpstreamRoute{},
		TrustFwdFor:       true,
		TrustedProxyCIDRs: []string{"10.0.0.0/8", "not-a-cidr"},
	})
	_ = w.Close()
	os.Stderr = oldStderr
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if !strings.Contains(string(captured), "not-a-cidr") {
		t.Errorf("a malformed entry must be logged, not silently dropped; got stderr: %s", captured)
	}
	if len(proxy.trustedProxyNets) != 1 {
		t.Fatalf("the one valid entry must still compile; got %v", proxy.trustedProxyNets)
	}
	if got := proxy.trustedProxyNets[0].String(); got != "10.0.0.0/8" {
		t.Errorf("trustedProxyNets[0] = %q, want \"10.0.0.0/8\"", got)
	}
}

// ── sourceIP ──────────────────────────────────────────────────────────────

// trustedProxyNetsForTest compiles CIDRs into the []*net.IPNet shape sourceIP
// consults, mirroring what NewHTTPProxyGateway builds from
// HTTPGatewayOptions.TrustedProxyCIDRs.
func trustedProxyNetsForTest(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("invalid test CIDR %q: %v", c, err)
		}
		nets = append(nets, n)
	}
	return nets
}

func TestSourceIP_TrustXFF(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{trustFwdFor: true, trustedProxyNets: trustedProxyNetsForTest(t, "127.0.0.1/32")}
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.RemoteAddr = "127.0.0.1:1234"
	ip := proxy.sourceIP(req)
	if !strings.Contains(ip, "10.0.0.1") {
		t.Errorf("sourceIP with trustFwdFor: want 10.0.0.1, got %q", ip)
	}
}

// TestSourceIP_TrustXFF_UntrustedPeerFallsBackToRemoteAddr verifies the fix for the
// spoofing gap: trustFwdFor alone is not enough to honor X-Forwarded-For — the
// immediate peer (RemoteAddr) must also match a configured listen.trustedProxyCIDRs
// entry. A peer outside that allowlist gets its own RemoteAddr as the source IP, so it
// cannot forge an ipRange source purely by setting the header.
func TestSourceIP_TrustXFF_UntrustedPeerFallsBackToRemoteAddr(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{trustFwdFor: true, trustedProxyNets: trustedProxyNetsForTest(t, "10.0.0.0/8")}
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.RemoteAddr = "203.0.113.9:1234" // not in 10.0.0.0/8
	ip := proxy.sourceIP(req)
	if ip != "203.0.113.9" {
		t.Errorf("sourceIP: untrusted peer must fall back to its own RemoteAddr, got %q", ip)
	}
}

// TestSourceIP_TrustXFF_EmptyAllowlistNeverTrusts verifies that
// --trust-forwarded-for with no listen.trustedProxyCIDRs configured never trusts
// X-Forwarded-For, regardless of peer — an empty allowlist matches nothing, so the
// flag alone has no effect until CIDRs are configured.
func TestSourceIP_TrustXFF_EmptyAllowlistNeverTrusts(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{trustFwdFor: true} // no trustedProxyNets configured
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.RemoteAddr = "127.0.0.1:1234"
	ip := proxy.sourceIP(req)
	if ip != "127.0.0.1" {
		t.Errorf("sourceIP: empty trustedProxyCIDRs must never trust XFF, got %q", ip)
	}
}

func TestSourceIP_NoXFF(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{trustFwdFor: false}
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.RemoteAddr = "192.168.1.2:5678"
	ip := proxy.sourceIP(req)
	if ip != "192.168.1.2" {
		t.Errorf("sourceIP: want 192.168.1.2, got %q", ip)
	}
}

// TestSourceIP_TrustXFF_RightmostHop verifies the proxy reads the right-most
// X-Forwarded-For entry (the address appended by the trusted immediate proxy),
// not the left-most one (which a client can forge). A client sending
// "X-Forwarded-For: 10.0.0.1" to spoof a trusted source for an ipRange condition
// must not win over the real address the trusted proxy appends.
func TestSourceIP_TrustXFF_RightmostHop(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{trustFwdFor: true, trustedProxyNets: trustedProxyNetsForTest(t, "127.0.0.1/32")}
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	// Left entry is attacker-injected; right entry is appended by the trusted hop.
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.7")
	req.RemoteAddr = "127.0.0.1:1234"
	ip := proxy.sourceIP(req)
	if ip != "203.0.113.7" {
		t.Errorf("sourceIP: want right-most trusted hop 203.0.113.7, got %q (left-most is client-spoofable)", ip)
	}
}

// TestSourceIP_TrustXFF_MultipleHeaderLines verifies that a second
// X-Forwarded-For header line cannot shadow the trusted right-most hop. An
// intermediary that adds its own line rather than appending leaves an
// attacker-controlled first line; sourceIP must flatten ALL lines and return the
// right-most entry across the whole chain, not just the first line's.
func TestSourceIP_TrustXFF_MultipleHeaderLines(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{trustFwdFor: true, trustedProxyNets: trustedProxyNetsForTest(t, "127.0.0.1/32")}
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	// First line is attacker-injected; second line is the trusted proxy's real
	// client IP. Header.Get would return the first line; we must use the last.
	req.Header.Add("X-Forwarded-For", "10.0.0.1")
	req.Header.Add("X-Forwarded-For", "203.0.113.7")
	req.RemoteAddr = "127.0.0.1:1234"
	ip := proxy.sourceIP(req)
	if ip != "203.0.113.7" {
		t.Errorf("sourceIP: want right-most trusted hop 203.0.113.7, got %q (first line is client-spoofable)", ip)
	}
}

// TestSourceIP_TrustXFF_StripsPort verifies the right-most X-Forwarded-For entry is
// normalized like the RemoteAddr path: some proxies append the client as IP:port (or
// an IPv6 literal). The returned value must be a bare IP so the downstream ipRange
// condition's net.ParseIP succeeds; a port-suffixed value parses as nil and would
// wrongly deny every request with CONDITION_FAILED.
func TestSourceIP_TrustXFF_StripsPort(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{trustFwdFor: true, trustedProxyNets: trustedProxyNetsForTest(t, "127.0.0.1/32")}

	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.7:5678")
	req.RemoteAddr = "127.0.0.1:1234"
	if ip := proxy.sourceIP(req); ip != "203.0.113.7" {
		t.Errorf("sourceIP: want port-stripped 203.0.113.7, got %q", ip)
	}

	// IPv6 with a port (bracketed) must also normalize to the bare address.
	req6 := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req6.Header.Set("X-Forwarded-For", "[2001:db8::1]:5678")
	req6.RemoteAddr = "127.0.0.1:1234"
	if ip := proxy.sourceIP(req6); ip != "2001:db8::1" {
		t.Errorf("sourceIP: want port-stripped 2001:db8::1, got %q", ip)
	}

	// A bare IP (no port) is returned unchanged — the common nginx/envoy default.
	reqBare := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	reqBare.Header.Set("X-Forwarded-For", "203.0.113.7")
	reqBare.RemoteAddr = "127.0.0.1:1234"
	if ip := proxy.sourceIP(reqBare); ip != "203.0.113.7" {
		t.Errorf("sourceIP: bare IP must pass through, got %q", ip)
	}

	// A bracketed IPv6 literal WITHOUT a port ("[2001:db8::1]") fails SplitHostPort
	// (no port), so the brackets must be stripped — net.ParseIP rejects the bracketed
	// form and would otherwise deny every request with CONDITION_FAILED.
	req6NoPort := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req6NoPort.Header.Set("X-Forwarded-For", "[2001:db8::1]")
	req6NoPort.RemoteAddr = "127.0.0.1:1234"
	if ip := proxy.sourceIP(req6NoPort); ip != "2001:db8::1" {
		t.Errorf("sourceIP: want unbracketed 2001:db8::1, got %q", ip)
	}

	// A bare (unbracketed) IPv6 with no port passes through unchanged — the common
	// X-Forwarded-For form, which net.ParseIP already accepts.
	reqBare6 := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	reqBare6.Header.Set("X-Forwarded-For", "2001:db8::1")
	reqBare6.RemoteAddr = "127.0.0.1:1234"
	if ip := proxy.sourceIP(reqBare6); ip != "2001:db8::1" {
		t.Errorf("sourceIP: bare IPv6 must pass through, got %q", ip)
	}
}

// ── notificationMsg ───────────────────────────────────────────────────────

func TestNotificationMsg(t *testing.T) {
	t.Parallel()
	msg, err := mcp.NotificationMsg("tools/list_changed", map[string]interface{}{"delta": 3})
	if err != nil {
		t.Fatalf("notificationMsg: %v", err)
	}
	if msg.Method != "tools/list_changed" {
		t.Errorf("wrong method: %s", msg.Method)
	}
	if msg.ID != nil {
		t.Error("notification should have nil ID")
	}
	if msg.Params == nil {
		t.Error("expected params")
	}
}

// ── handleMCPGet (SSE path) ───────────────────────────────────────────────

func TestHTTPHandleMCPGet_NoSessionHeader(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	w := httptest.NewRecorder()
	proxy.handleMCPGet(w, req, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing session header, got %d", w.Code)
	}
}

func TestHTTPHandleMCPGet_UnknownSession(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "no-such-session")
	w := httptest.NewRecorder()
	proxy.handleMCPGet(w, req, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown session, got %d", w.Code)
	}
}

// ── handleMCPDelete ───────────────────────────────────────────────────────

func TestHTTPHandleMCPDelete_NoSessionHeader(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	req := httptest.NewRequest(http.MethodDelete, "/mcp", http.NoBody)
	w := httptest.NewRecorder()
	proxy.handleMCPDelete(w, req, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing session, got %d", w.Code)
	}
}

func TestHTTPHandleMCPDelete_UnknownSession(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	req := httptest.NewRequest(http.MethodDelete, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "no-such")
	w := httptest.NewRecorder()
	proxy.handleMCPDelete(w, req, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown session, got %d", w.Code)
	}
}

// ── upstreamErrInfo classification ────────────────────────────────────────

// headerTimeoutErr mimics the net.Error a remote upstream's transport-level
// ResponseHeaderTimeout produces (the *url.Error wrapping "net/http: timeout awaiting
// response headers"): Timeout()==true, but it does NOT wrap context.DeadlineExceeded, so
// only the net.Error branch — not errors.Is(context.DeadlineExceeded) — classifies it.
type headerTimeoutErr struct{ msg string }

func (e headerTimeoutErr) Error() string   { return e.msg }
func (e headerTimeoutErr) Timeout() bool   { return true }
func (e headerTimeoutErr) Temporary() bool { return false }

func TestUpstreamErrInfo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		err         error
		timeMs      int
		wantCode    string
		wantReason  string
		wantRPCCode int
	}{
		{"deadline with configured timeout", context.DeadlineExceeded, 100, "UPSTREAM_TIMEOUT", "upstream did not respond within 100 ms", -32603},
		{"wrapped deadline", fmt.Errorf("upstream HTTP: %w", context.DeadlineExceeded), 250, "UPSTREAM_TIMEOUT", "upstream did not respond within 250 ms", -32603},
		{"deadline inherited from caller", context.DeadlineExceeded, 0, "UPSTREAM_TIMEOUT", "upstream did not respond before the request deadline", -32603},
		{"host canceled", context.Canceled, 100, "REQUEST_CANCELED", "request canceled before the upstream responded", -32603},
		// A duplicate in-flight JSON-RPC id is a HOST protocol fault: it must be an
		// invalid-request (-32600) with a non-infra code, not blamed on the upstream.
		{"duplicate host id", fmt.Errorf("%w \"n:7\": request already pending", errDuplicateID), 100, "INVALID_REQUEST", "duplicate JSON-RPC request id already in flight", -32600},
		// A net.Error timeout that does NOT wrap context.DeadlineExceeded (the remote
		// upstream's ResponseHeaderTimeout) must still be classified UPSTREAM_TIMEOUT,
		// not UPSTREAM_ERROR, so the same physical failure is never recorded under two
		// codes depending on which timer wins — and its raw text is not dumped to stderr.
		{"net.Error header timeout, configured", headerTimeoutErr{msg: `Post "https://internal.svc:8443/mcp": net/http: timeout awaiting response headers`}, 30000, "UPSTREAM_TIMEOUT", "upstream did not respond within 30000 ms", -32603},
		{"net.Error header timeout wrapped, inherited deadline", fmt.Errorf("tools/list: %w", headerTimeoutErr{msg: "net/http: timeout awaiting response headers"}), 0, "UPSTREAM_TIMEOUT", "upstream did not respond before the request deadline", -32603},
		// The host-facing reason must NOT embed the underlying error text: for a
		// remote HTTP upstream it can carry the upstream's hostname/path or raw
		// response body, which must not be disclosed to the MCP host.
		{"generic upstream failure", errors.New("pipe broke"), 100, "UPSTREAM_ERROR", "upstream error", -32603},
		{"upstream url in error", errors.New(`Post "https://internal.svc:8443/mcp": dial tcp: refused`), 100, "UPSTREAM_ERROR", "upstream error", -32603},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code, reason, rpcCode := upstreamErrInfo(tc.err, tc.timeMs)
			if code != tc.wantCode || reason != tc.wantReason || rpcCode != tc.wantRPCCode {
				t.Errorf("upstreamErrInfo(%v, %d) = (%q, %q, %d), want (%q, %q, %d)",
					tc.err, tc.timeMs, code, reason, rpcCode, tc.wantCode, tc.wantReason, tc.wantRPCCode)
			}
			// Defense in depth: the host reason must never leak upstream internals
			// regardless of error class.
			if strings.Contains(reason, "internal.svc") || strings.Contains(reason, "pipe broke") {
				t.Errorf("host-facing reason %q leaked underlying error text", reason)
			}
		})
	}
}

func TestIsInfraDenialCode(t *testing.T) {
	t.Parallel()
	// INVALID_REQUEST covers the malformed / empty-target enforced-request deny
	// (malformedDeny) as well as the duplicate-in-flight-id fault: a host protocol fault
	// suggest must skip, not mine into a phantom method-named target.
	for _, code := range []string{"UPSTREAM_ERROR", "UPSTREAM_TIMEOUT", "REQUEST_CANCELED", "INVALID_REQUEST"} {
		if !IsInfraDenialCode(code) {
			t.Errorf("IsInfraDenialCode(%q) = false, want true", code)
		}
	}
	// Operator/infra denials, not policy decisions: KILL_SWITCH[_ERROR] is an operator
	// emergency stop and AUDIT_UNAVAILABLE is the --require-audit=strict gate tripping.
	// suggest must skip these so it does not fabricate a deny-only allowlist suggestion
	// for a target policy never actually denied.
	for _, code := range []string{"KILL_SWITCH", "KILL_SWITCH_ERROR", "AUDIT_UNAVAILABLE"} {
		if !IsInfraDenialCode(code) {
			t.Errorf("IsInfraDenialCode(%q) = false, want true", code)
		}
	}
	// INVALID_PARAMS is NOT infra: the manifest argumentSchema check emits it as a real
	// policy denial against a real target, which suggest must keep mining.
	for _, code := range []string{"", "CAPABILITY_DENIED", "AUTHORIZATION_FAILED", "CONDITION_FAILED", "INVALID_PARAMS"} {
		if IsInfraDenialCode(code) {
			t.Errorf("IsInfraDenialCode(%q) = true, want false", code)
		}
	}
}

// ── newSession initialize deadline ────────────────────────────────────────

// TestHTTPProxy_NewSessionInitializeHonorsContext verifies that the local
// subprocess initialize handshake is bounded by the caller's context: a
// subprocess that never answers initialize must fail session start when the
// per-initialize deadline expires instead of blocking the handler goroutine
// on an unbounded pipe read and leaving an unkillable orphan process.
func TestHTTPProxy_NewSessionInitializeHonorsContext(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{
		Command: "sleep",
		Args:    []string{"60"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := proxy.newSession(ctx, proxy.routes[""], "")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from a subprocess that never completes initialize")
	}
	if elapsed > 5*time.Second {
		t.Errorf("newSession took %v; initialize handshake not bounded by ctx", elapsed)
	}
}

// ── Upstream timeout propagation ─────────────────────────────────

// TestWithUpstreamTimeout_HTTPProxy verifies that withUpstreamTimeout returns a
// canceled context after the configured deadline elapses.
func TestWithUpstreamTimeout_HTTPProxy(t *testing.T) {
	t.Parallel()
	p := &HTTPProxy{upstreamTimeMs: 50}
	ctx, cancel := p.withUpstreamTimeout(context.Background())
	defer cancel()

	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("expected DeadlineExceeded, got %v", ctx.Err())
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("regression: HTTPProxy.withUpstreamTimeout did not fire")
	}
}

func TestWithUpstreamTimeout_HTTPProxy_NoTimeout(t *testing.T) {
	t.Parallel()
	p := &HTTPProxy{upstreamTimeMs: 0}
	ctx, cancel := p.withUpstreamTimeout(context.Background())
	defer cancel()

	select {
	case <-ctx.Done():
		t.Error("regression: context must not be canceled when no timeout is set")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestWithUpstreamTimeout_MarkerBypasses verifies that a context marked
// withoutUpstreamTimeout is NOT bounded by --upstream-timeout, so session-start
// work (the drift probe) keeps its own session-start budget.
func TestWithUpstreamTimeout_MarkerBypasses(t *testing.T) {
	t.Parallel()
	p := &HTTPProxy{upstreamTimeMs: 50}

	// Unmarked: the per-request deadline is applied.
	ctx, cancel := p.withUpstreamTimeout(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("expected a deadline when upstreamTimeMs > 0 and context is unmarked")
	}

	// Marked: the per-request deadline is suppressed.
	mctx, mcancel := p.withUpstreamTimeout(withoutUpstreamTimeout(context.Background()))
	defer mcancel()
	if _, ok := mctx.Deadline(); ok {
		t.Error("withoutUpstreamTimeout context must not be bounded by --upstream-timeout")
	}
}

// ── Duplicate JSON-RPC ID protection ────────────────────────────

// TestCallSubprocessUpstream_DuplicateID_HTTP verifies that registering a second
// pending entry with the same JSON-RPC message ID returns an error instead of
// silently overwriting the first goroutine's channel.
func TestCallSubprocessUpstream_DuplicateID_HTTP(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{
		pending:  make(map[string]chan upstreamResult),
		done:     make(chan struct{}),
		upWriter: mcp.NewMsgWriter(io.Discard),
		// upHTTPClient nil → local mode
	})

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`42`), Method: "tools/call"}
	key := mcp.MsgKey(msg.ID)

	firstCh := make(chan upstreamResult, 1)
	sess.pendingMu.Lock()
	sess.pending[key] = firstCh
	sess.pendingMu.Unlock()

	_, err := sess.callSubprocessUpstream(context.Background(), msg)
	if err == nil {
		t.Error("regression: duplicate ID must return an error, not overwrite the pending entry")
	}

	sess.pendingMu.Lock()
	remaining := sess.pending[key]
	sess.pendingMu.Unlock()
	if remaining != firstCh {
		t.Error("regression: duplicate ID request must not overwrite the existing pending channel")
	}
}

// TestDeliverUpstreamResponse_DuplicateDoesNotWedgeReader verifies the
// non-blocking send in deliverUpstreamResponse: when a misbehaving upstream emits
// a second response for an ID whose buffered(1) channel is already full and whose
// caller has left without draining, the duplicate is dropped instead of wedging
// the reader goroutine forever on a full channel.
func TestDeliverUpstreamResponse_DuplicateDoesNotWedgeReader(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	pending := make(map[string]chan upstreamResult)
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`)}

	// Caller registered a buffered(1) channel but never drains it, modelling a
	// caller that already left via ctx.Done()/done before the response arrived.
	ch := make(chan upstreamResult, 1)
	mu.Lock()
	pending[mcp.MsgKey(msg.ID)] = ch
	mu.Unlock()

	// First delivery fills the one-slot buffer.
	deliverUpstreamResponse(&mu, pending, msg)

	// A duplicate response for the same ID must be dropped, not block the reader.
	done := make(chan struct{})
	go func() {
		deliverUpstreamResponse(&mu, pending, msg)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("regression: deliverUpstreamResponse blocked on a duplicate response; reader goroutine would be wedged")
	}
}

// ── HTTP session startup deadline ───────────────────────────────

// TestHTTPProxy_InitializeDeadline verifies that the HTTP handler applies a
// per-initialize deadline that fires before the global write timeout.
func TestHTTPProxy_InitializeDeadline(t *testing.T) {
	t.Parallel()

	stallSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	defer stallSrv.Close()

	proxy := &HTTPProxy{
		sessions: make(map[string]*httpSession),
	}
	route := &UpstreamRoute{transport: "http", upstreamURL: stallSrv.URL, pdp: pdp.AlwaysAllowPDP{}}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := proxy.newRemoteSession(ctx, route, "")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("regression: newRemoteSession must fail when upstream stalls")
	}
	if elapsed > 2*time.Second {
		t.Errorf("regression: newRemoteSession took %v; per-initialize deadline not applied", elapsed)
	}
}

// -----------------------------------------------------------------
// ResolveUpstreamTimeout
// -----------------------------------------------------------------

func TestResolveUpstreamTimeout(t *testing.T) {
	tests := []struct {
		name      string
		flag, cfg int
		want      int
	}{
		{"unset flag, no config → built-in default", UpstreamTimeoutUnset, 0, defaultUpstreamTimeoutMs},
		{"explicit flag 0 → disabled", 0, 0, 0},
		{"explicit flag value", 8000, 0, 8000},
		{"config overrides unset flag", UpstreamTimeoutUnset, 5000, 5000},
		{"explicit flag overrides config", 8000, 5000, 8000},
		{"explicit flag 0 overrides config", 0, 5000, 0},
		{"config 0 does not override flag", 8000, 0, 8000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveUpstreamTimeout(tc.flag, tc.cfg); got != tc.want {
				t.Errorf("ResolveUpstreamTimeout(%d, %d) = %d, want %d", tc.flag, tc.cfg, got, tc.want)
			}
		})
	}
}

// newCappedProxy builds a single-route remote proxy against a fake upstream with
// the given session controls, returning the proxy and a loopback test server that
// routes /mcp, /healthz, and /metrics through it.
func newCappedProxy(t *testing.T, maxSessions, idleMs int) (*HTTPProxy, *httptest.Server) {
	t.Helper()
	fake := newFakeUpstream()
	upSrv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(upSrv.Close)

	sink, _ := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{
		UpstreamURL:   upSrv.URL,
		PDP:           pdp.AlwaysAllowPDP{},
		MaxSessions:   maxSessions,
		SessionIdleMs: idleMs,
		Sink:          sink,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", proxy.handleMCP)
	mux.HandleFunc("/healthz", proxy.handleHealth)
	mux.HandleFunc("/metrics", proxy.handleMetrics)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return proxy, srv
}

func TestSessionCap_RefusesBeyondLimit(t *testing.T) {
	proxy, srv := newCappedProxy(t, 2, 0)

	// Two sessions fit under the cap of 2.
	_ = initSession(t, srv)
	_ = initSession(t, srv)
	if got := proxy.sessionCount(); got != 2 {
		t.Fatalf("expected 2 active sessions, got %d", got)
	}

	// The third initialize is refused with 503 and spawns no session.
	initMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, srv, initMsg, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("third initialize: want 503, got %d", resp.StatusCode)
	}
	if got := proxy.sessionCount(); got != 2 {
		t.Fatalf("session count must stay at the cap, got %d", got)
	}
}

func TestSessionCap_FreesSlotAfterDelete(t *testing.T) {
	proxy, srv := newCappedProxy(t, 1, 0)
	sid := initSession(t, srv)

	// At cap: a second initialize is refused.
	resp := postMCP(t, srv, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "initialize", Params: json.RawMessage(`{}`)}, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("want 503 at cap, got %d", resp.StatusCode)
	}

	// DELETE frees the slot; a new initialize then succeeds.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, srv.URL+"/mcp", http.NoBody)
	req.Header.Set(SessionHeader, sid)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = delResp.Body.Close()
	waitForSessions(t, proxy, 0)

	if newSID := initSession(t, srv); newSID == "" {
		t.Fatal("expected a fresh session after the slot was freed")
	}
}

func TestIdleReaper_ClosesIdleSession(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 60000)
	sid := initSession(t, srv)
	if proxy.sessionCount() != 1 {
		t.Fatalf("expected 1 session after init")
	}

	// Force the session past the idle horizon and run one reap sweep.
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}
	sess.lastActive.Store(time.Now().Add(-time.Hour).UnixNano())
	proxy.reapOnce(time.Minute)
	waitForSessions(t, proxy, 0)
}

// TestIdleReaper_SparesInitInProgressSession covers a session still
// initializing — registered, no subscribers, stale lastActive while the startup
// drift check blocks — must not be reaped. reapOnce skips it while initInProgress
// is set (overriding both the normal idle rule and the hard ceiling); once cleared
// the normal idle rule applies again.
func TestIdleReaper_SparesInitInProgressSession(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 60000)
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}

	// Idle by every normal measure: stale lastActive and lastRequest, no subscribers.
	sess.lastActive.Store(time.Now().Add(-time.Hour).UnixNano())
	sess.lastRequest.Store(time.Now().Add(-time.Hour).UnixNano())

	// Still initializing: the reaper must skip it even though it looks idle.
	sess.initInProgress.Store(true)
	proxy.reapOnce(time.Minute)
	if proxy.sessionCount() != 1 {
		t.Fatalf("an initializing session must not be reaped, count=%d", proxy.sessionCount())
	}

	// Initialization complete: the normal idle rule now reaps it.
	sess.initInProgress.Store(false)
	proxy.reapOnce(time.Minute)
	waitForSessions(t, proxy, 0)
}

// TestIdleReaper_SparesInFlightRequest covers a session with an enforced request in
// flight past the NORMAL idle window: lastActive is not refreshed while the upstream
// call blocks, so a call outliving --session-idle would otherwise be torn down
// mid-flight (killing the upstream out from under callUpstream). reapOnce's normal arm
// must skip a session while inFlight > 0 (mirroring the initInProgress spare); once
// the call completes the normal idle rule applies again. lastRequest is kept RECENT so
// only the normal arm is exercised here (the hard ceiling is covered separately).
func TestIdleReaper_SparesInFlightRequest(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 60000)
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}

	// Stale by the normal idle measure (lastActive), but recent by the hard ceiling
	// (lastRequest) so only the normal arm is in play. No subscribers.
	sess.lastActive.Store(time.Now().Add(-time.Hour).UnixNano())
	sess.lastRequest.Store(time.Now().UnixNano())

	// A request is in flight (blocked on the upstream): the normal arm must skip it.
	sess.inFlight.Add(1)
	proxy.reapOnce(time.Minute)
	if proxy.sessionCount() != 1 {
		t.Fatalf("a session with an in-flight request must not be reaped by the normal arm, count=%d", proxy.sessionCount())
	}

	// Request completed: the normal idle rule now reaps it.
	sess.inFlight.Add(-1)
	proxy.reapOnce(time.Minute)
	waitForSessions(t, proxy, 0)
}

// TestIdleReaper_HardCeilingReapsInFlightRequest pins that the in-flight spare is
// scoped to the NORMAL arm only: the hard idle ceiling still reaps a session whose
// enforced call never returns (a silent upstream under --upstream-timeout=0), so a
// stuck request cannot pin the session and its subprocess forever.
func TestIdleReaper_HardCeilingReapsInFlightRequest(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 60000)
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}

	// Past the hard ceiling: no host request for well over hardIdleMultiplier x idle.
	sess.lastActive.Store(time.Now().Add(-time.Hour).UnixNano())
	sess.lastRequest.Store(time.Now().Add(-time.Hour).UnixNano())

	// A request is stuck in flight; the hard arm must reap regardless. The proxy's
	// upstreamTimeMs is 0 here (newCappedProxy leaves it unset), i.e. the per-call
	// budget is DISABLED, so the call is unbounded and the ceiling is its only backstop.
	sess.inFlight.Add(1)
	proxy.reapOnce(time.Minute)
	waitForSessions(t, proxy, 0)
}

// TestIdleReaper_HardCeilingSparesInFlightWhenBudgetFinite pins that the hard ceiling
// does NOT tear down an in-flight call that is bounded by a finite --upstream-timeout:
// the call ends on its own within its budget, so killing it mid-flight would fail a
// legal request whenever upstreamTimeout >= hardIdleMultiplier x idle. Once the call
// completes (inFlight == 0) the ceiling reaps the now-idle session.
func TestIdleReaper_HardCeilingSparesInFlightWhenBudgetFinite(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 60000)
	proxy.upstreamTimeMs = 30000 // finite per-call budget bounds any in-flight call
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}

	// Past the hard ceiling, but a call is in flight and bounded by the finite budget.
	sess.lastActive.Store(time.Now().Add(-time.Hour).UnixNano())
	sess.lastRequest.Store(time.Now().Add(-time.Hour).UnixNano())
	sess.inFlight.Add(1)
	proxy.reapOnce(time.Minute)
	if proxy.sessionCount() != 1 {
		t.Fatalf("hard ceiling must spare an in-flight call bounded by a finite upstream timeout, count=%d", proxy.sessionCount())
	}

	// Call completed: the hard ceiling now reaps the idle session.
	sess.inFlight.Add(-1)
	proxy.reapOnce(time.Minute)
	waitForSessions(t, proxy, 0)
}

// TestSessionRequestSlot_CapRejectsOverflow pins the per-session concurrent-request
// cap: once maxConcurrentSessionRequests slots are held, a further acquire is
// rejected (the caller returns a retryable busy error) rather than dispatching an
// unbounded handler. Releasing a slot admits the next request.
func TestSessionRequestSlot_CapRejectsOverflow(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{})
	for i := 0; i < maxConcurrentSessionRequests; i++ {
		if !sess.tryAcquireRequestSlot() {
			t.Fatalf("acquire %d must succeed within the cap", i)
		}
	}
	if sess.tryAcquireRequestSlot() {
		t.Fatal("acquire past the cap must be rejected")
	}
	sess.releaseRequestSlot()
	if !sess.tryAcquireRequestSlot() {
		t.Fatal("a freed slot must admit the next request")
	}
}

// TestIdleReaper_SparesJustReadySession is the regression for the activity clocks
// being seeded at init START: registerSession stamps lastActive/lastRequest before
// the handshake + drift probe run, and the initInProgress guard spares the session
// only DURING init — so a session whose startup outlasts a short --session-idle was
// eligible for reaping the instant init completed, before the client sent its first
// post-init request. newSession now re-stamps the clocks at readiness; this
// simulates the stale init-start timestamps + that re-stamp and confirms the reaper
// spares the just-ready session.
func TestIdleReaper_SparesJustReadySession(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 5000) // 5s idle window
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}

	// Simulate registration that happened long before establishment finished (the
	// startup took longer than the idle window), so the clocks hold the init-start time.
	old := time.Now().Add(-time.Hour).UnixNano()
	sess.lastActive.Store(old)
	sess.lastRequest.Store(old)
	sess.initInProgress.Store(false) // init is complete

	// The readiness re-stamp newSession now performs at the end of establishment.
	sess.touchRequest()

	// No SSE subscriber yet (the client just received the init response and has not
	// opened GET /mcp). The reaper must still spare the just-ready session.
	proxy.reapOnce(msToDuration(5000))
	if proxy.sessionCount() != 1 {
		t.Fatalf("a just-ready session must not be reaped before its first post-init request, count=%d", proxy.sessionCount())
	}
}

func TestIdleReaper_SparesActiveSession(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 60000)
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)

	// Recently touched: a sweep must leave it alone.
	sess.touch()
	proxy.reapOnce(time.Minute)
	if proxy.sessionCount() != 1 {
		t.Fatalf("a recently active session must not be reaped, count=%d", proxy.sessionCount())
	}
}

func TestIdleReaper_SparesSubscribedSessionWithRecentRequest(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 60000)
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}

	// Open SSE stream: an active subscriber spares the session from the normal
	// idle reaper.
	sess.addSub(make(chan mcp.RPCMsg, 1))

	// Drive it well past the normal idle horizon but keep lastRequest recent: the
	// host is silent on the request channel but has POSTed within the hard ceiling.
	sess.lastActive.Store(time.Now().Add(-time.Hour).UnixNano())
	sess.lastRequest.Store(time.Now().UnixNano())

	proxy.reapOnce(time.Minute)
	if proxy.sessionCount() != 1 {
		t.Fatalf("an SSE-subscribed session with a recent host request must not be reaped, count=%d", proxy.sessionCount())
	}
}

func TestIdleReaper_ReapsSubscribedSessionPastHardCeiling(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 60000)
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}

	// Open SSE stream, then go fully silent on the request channel for longer than
	// the hard ceiling (hardIdleMultiplier x the idle window). The session must be
	// reaped despite the open SSE stream so it cannot pin its upstream forever.
	sess.addSub(make(chan mcp.RPCMsg, 1))
	idle := time.Minute
	past := time.Now().Add(-idle * (hardIdleMultiplier + 1)).UnixNano()
	sess.lastActive.Store(past)
	sess.lastRequest.Store(past)

	proxy.reapOnce(idle)
	waitForSessions(t, proxy, 0)
}

// TestIdleReaper_HugeIdleWindow_DoesNotReapEverySession is a regression for the
// hard-ceiling overflow: a validator-accepted but very large idle window
// (config.MaxDurationMs, "effectively unlimited") must not be multiplied into an
// int64 overflow that wraps hardCutoff into the future and reaps every session on
// the first sweep. A freshly-active session must survive.
func TestIdleReaper_HugeIdleWindow_DoesNotReapEverySession(t *testing.T) {
	proxy, srv := newCappedProxy(t, 0, 60000)
	sid := initSession(t, srv)
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found")
	}
	// Freshly active: a host request and activity right now.
	now := time.Now().UnixNano()
	sess.lastActive.Store(now)
	sess.lastRequest.Store(now)

	// Effectively-unlimited idle window (the validator's documented max). idle*4
	// overflows int64 without the saturation guard.
	proxy.reapOnce(msToDuration(int(config.MaxDurationMs)))

	if proxy.sessionCount() != 1 {
		t.Fatalf("a huge idle window must not reap a freshly-active session; count=%d", proxy.sessionCount())
	}
}

// waitForSessions polls until the proxy reports want active sessions or fails.
func waitForSessions(t *testing.T, proxy *HTTPProxy, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if proxy.sessionCount() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session count did not reach %d (still %d)", want, proxy.sessionCount())
}

// TestCloseAllSessions_ReapsLiveSessions covers the closeAllSessions reap primitive
// that HTTPProxy.Serve's single teardown defer invokes on every return path —
// graceful ctx cancel AND the srv.Serve error path (the error arm previously
// returned without reaping, leaking each live session's upstream connection plus
// the idle reaper goroutine). Driving a real srv.Serve error requires refactoring
// Serve's internal listener ownership, so this test exercises the primitive
// directly rather than through Serve: closeAllSessions drains the registry and
// closes every live session.
func TestCloseAllSessions_ReapsLiveSessions(t *testing.T) {
	proxy, srv := newCappedProxy(t, 5, 0)
	_ = initSession(t, srv)
	_ = initSession(t, srv)
	waitForSessions(t, proxy, 2)

	proxy.closeAllSessions()

	if n := proxy.sessionCount(); n != 0 {
		t.Fatalf("closeAllSessions must drain the registry; still %d session(s)", n)
	}
}

func TestHealthAndMetricsEndpoints(t *testing.T) {
	_, srv := newCappedProxy(t, 5, 0)
	_ = initSession(t, srv)

	t.Run("healthz returns a JSON snapshot", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("get /healthz: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("healthz status = %d", resp.StatusCode)
		}
		var snap healthSnapshot
		if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
			t.Fatalf("decode snapshot: %v", err)
		}
		if snap.Status != "ok" {
			t.Errorf("status = %q, want ok", snap.Status)
		}
		if snap.Sessions != 1 {
			t.Errorf("sessions = %d, want 1", snap.Sessions)
		}
		if snap.MaxSessions != 5 {
			t.Errorf("maxSessions = %d, want 5", snap.MaxSessions)
		}
	})

	t.Run("snapshot is degraded when no audit sink is configured", func(t *testing.T) {
		p := &HTTPProxy{ks: killswitch.NewInMemory(), sessions: map[string]*httpSession{}}
		snap := p.snapshot()
		if snap.AuditConfigured {
			t.Fatalf("expected AuditConfigured=false for nil sink")
		}
		if snap.Status != "degraded" {
			t.Errorf("status = %q, want degraded (nil audit sink)", snap.Status)
		}
	})

	t.Run("snapshot is degraded when audit writes have failed", func(t *testing.T) {
		// Drive the drainer's marshal-error path (which bumps WriteFailures, see
		// audit.go) by recording details that cannot be JSON-marshaled, so the
		// record reaches the drainer but cannot be durably written. A configured
		// sink with AuditWriteFailed > 0 must still flip Status to degraded.
		sink, _ := newTempAuditSink(t)
		for i := 0; i < 50 && sink.WriteFailures() == 0; i++ {
			sink.RecordAllow(context.Background(), "sess", "tool", "tools/call",
				map[string]interface{}{"bad": math.Inf(1)}, nil, false, nil, nil)
			time.Sleep(5 * time.Millisecond)
		}
		if sink.WriteFailures() == 0 {
			t.Skip("could not provoke an audit write failure on this platform; nil-sink case covers the verdict")
		}
		p := &HTTPProxy{ks: killswitch.NewInMemory(), sink: sink, sessions: map[string]*httpSession{}}
		snap := p.snapshot()
		if snap.AuditWriteFailed <= 0 {
			t.Fatalf("expected AuditWriteFailed > 0, got %d", snap.AuditWriteFailed)
		}
		if snap.Status != "degraded" {
			t.Errorf("status = %q, want degraded (audit write failures)", snap.Status)
		}
	})

	t.Run("metrics returns Prometheus text", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/metrics")
		if err != nil {
			t.Fatalf("get /metrics: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("metrics status = %d", resp.StatusCode)
		}
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		body := string(buf[:n])
		for _, want := range []string{
			"eunox_active_sessions 1",
			"eunox_max_sessions 5",
			"eunox_audit_dropped_records_total",
			"eunox_kill_switch_healthy 1",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("metrics body missing %q\n---\n%s", want, body)
			}
		}
	})
}

// TestAddSlack_SaturatesInsteadOfOverflowing pins that addSlack saturates at
// math.MaxInt64 rather than wrapping past it into a negative (past) deadline. At
// the documented-max upstream timeout (config.MaxDurationMs) the in-range
// ms->Duration product sits within a few hundred microseconds of math.MaxInt64,
// so a bare d+writeSlack would overflow to a write deadline in the PAST that fails
// every response write.
func TestAddSlack_SaturatesInsteadOfOverflowing(t *testing.T) {
	t.Parallel()

	// Ordinary case: well within range, writeSlack is simply added.
	if got := addSlack(30 * time.Second); got != 35*time.Second {
		t.Errorf("addSlack(30s) = %v, want 35s", got)
	}

	// Already at the ceiling: adding the slack must stay at the ceiling.
	if got := addSlack(time.Duration(math.MaxInt64)); got != time.Duration(math.MaxInt64) {
		t.Errorf("addSlack(MaxInt64) = %v, want MaxInt64", got)
	}

	// The documented-max upstream timeout: the saturated ms->Duration product is
	// just under MaxInt64, so a bare d+writeSlack would wrap negative. addSlack must
	// clamp to MaxInt64 — a future deadline, never the past.
	d := msToDuration(int(config.MaxDurationMs))
	got := addSlack(d)
	if got != time.Duration(math.MaxInt64) {
		t.Errorf("addSlack(msToDuration(MaxDurationMs)) = %v, want MaxInt64", got)
	}
	if got < d {
		t.Errorf("addSlack returned %v < d (%v); the sum wrapped negative instead of saturating", got, d)
	}
	if !time.Now().Add(got).After(time.Now()) {
		t.Errorf("addSlack(...)=%v yields a non-future deadline; a bare d+writeSlack would be in the past", got)
	}

	// Exactly at the overflow boundary: (MaxInt64-writeSlack) + writeSlack == MaxInt64 (no wrap).
	if got := addSlack(time.Duration(math.MaxInt64) - writeSlack); got != time.Duration(math.MaxInt64) {
		t.Errorf("addSlack(MaxInt64-writeSlack) = %v, want MaxInt64", got)
	}
}
