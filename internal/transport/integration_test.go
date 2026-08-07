// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// End-to-end integration tests for the stdio proxy lifecycle. These tests
// re-exec the test binary as a real MCP stdio upstream subprocess and drive
// StdioProxy.Start through its full path: connect → initialize handshake →
// (optional) drift check → serve host → drain. They exercise the subprocess
// wiring (connectUpstream, killUpstream, signalUpstream, waitUpstream,
// upstreamLabel, serveHost) that the in-memory unit tests cannot reach.

// End-to-end coverage for `validate --live`: a mock upstream returning a known
// tool list is introspected over the same handshake the CLI uses
// (fetchLiveTools), then the live tool set is diffed against a manifest and the
// full drift report is rendered (runValidateLive). This exercises the whole
// pipeline — handshake, classification, formatting, exit code — against a real
// HTTP server, rather than the pure-function units covered in
// validate_live_test.go.

package transport

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// stdioUpstreamSentinel is the argv marker that turns a re-exec of the test
// binary into a full MCP stdio upstream (see TestHelperStdioUpstream).
const stdioUpstreamSentinel = "eunox-stdio-upstream-process"

// TestHelperStdioUpstream is a re-exec entry point. When the test binary is
// invoked with stdioUpstreamSentinel in its arguments, it serves a minimal but
// complete MCP stdio session — initialize, tools/list (two tools), tools/call
// (echo), and a generic empty result for anything else — then exits when its
// stdin is closed. During an ordinary `go test` run the sentinel is absent and
// this is a no-op.
func TestHelperStdioUpstream(t *testing.T) {
	if !slices.Contains(os.Args, stdioUpstreamSentinel) {
		return
	}
	stdioUpstreamServe()
}

const stdioHangSentinel = "eunox-stdio-hang-process"

// TestHelperStdioHangUpstream is a re-exec entry point that consumes stdin but
// never writes a response, so an introspector blocks waiting for the initialize
// reply until its context deadline kills this subprocess. Used to prove the
// live-introspection timeout actually unwedges a non-answering stdio upstream.
func TestHelperStdioHangUpstream(t *testing.T) {
	if !slices.Contains(os.Args, stdioHangSentinel) {
		return
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func stdioUpstreamServe() {
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
		switch msg.Method {
		case "initialize":
			result = mcp.InitResult{
				ProtocolVersion: capability.Revision20251125.String(),
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "stdio-integ", "version": "1.0.0"},
			}
		case "tools/list":
			result = map[string]interface{}{
				"tools": []map[string]interface{}{
					{"name": "read_file", "description": "reads a file"},
					{"name": "write_file", "description": "writes a file"},
				},
			}
		case "tools/call":
			result = map[string]interface{}{
				"content": []map[string]interface{}{{"type": "text", "text": "ok"}},
			}
		default:
			result = map[string]interface{}{}
		}
		resp, _ := mcp.SuccessResponse(msg.ID, result)
		_ = writer.Write(resp)
	}
}

// helperUpstreamArgs returns the command + args that re-exec the test binary as
// the stdio upstream defined by TestHelperStdioUpstream.
func helperUpstreamArgs() (command string, args []string) {
	return os.Args[0], []string{"-test.run=^TestHelperStdioUpstream$", "--", stdioUpstreamSentinel}
}

// stdioHostHarness wires a StdioProxy's host side to in-memory pipes so a test
// can write requests and read responses while Start runs against a real
// subprocess upstream.
type stdioHostHarness struct {
	proxy   *StdioProxy
	hostIn  *mcp.MsgWriter // test → proxy (host requests)
	hostOut *mcp.MsgReader // proxy → test (host responses)
	done    chan error     // receives the result of Start
	inW     *io.PipeWriter
}

// newStdioHostHarness builds a StdioProxy from opts (overriding only the host
// stdin/stdout with pipes) and starts it in the background.
func newStdioHostHarness(t *testing.T, opts StdioProxyOptions) *stdioHostHarness {
	t.Helper()
	cmd, args := helperUpstreamArgs()
	opts.Command = cmd
	opts.Args = args

	p := NewStdioProxy(opts)

	inR, inW := io.Pipe()   // host → proxy
	outR, outW := io.Pipe() // proxy → host
	p.hostReader = mcp.NewMsgReader(inR)
	p.hostWriter = mcp.NewMsgWriter(outW)

	h := &stdioHostHarness{
		proxy:   p,
		hostIn:  mcp.NewMsgWriter(inW),
		hostOut: mcp.NewMsgReader(outR),
		done:    make(chan error, 1),
		inW:     inW,
	}

	go func() {
		h.done <- p.Start(context.Background())
	}()
	return h
}

// roundTrip writes req to the proxy and reads the next response.
func (h *stdioHostHarness) roundTrip(t *testing.T, req mcp.RPCMsg) mcp.RPCMsg {
	t.Helper()
	if err := h.hostIn.Write(req); err != nil {
		t.Fatalf("write host request: %v", err)
	}
	resp, err := h.hostOut.Read()
	if err != nil {
		t.Fatalf("read host response: %v", err)
	}
	return resp
}

// shutdown closes the host stdin (EOF) and waits for Start to return.
func (h *stdioHostHarness) shutdown(t *testing.T) error {
	t.Helper()
	_ = h.inW.Close()
	select {
	case err := <-h.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after host stdin closed")
		return nil
	}
}

// TestStdioProxy_FullLifecycle drives the entire Start path against a real
// subprocess upstream: initialize, tools/list, tools/call, then graceful
// shutdown on host EOF.
func TestStdioProxy_FullLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	h := newStdioHostHarness(t, StdioProxyOptions{
		PDP:        pdp.AlwaysAllowPDP{},
		SessionID:  "integ-lifecycle",
		ShutdownMs: 2000,
	})

	// upstreamLabel must report the subprocess command once connected.
	if got := h.proxy.upstreamLabel(); got != os.Args[0] {
		t.Errorf("upstreamLabel: got %q, want %q", got, os.Args[0])
	}

	// initialize
	initResp := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "initialize",
		Params: json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}`),
	})
	if initResp.Error != nil {
		t.Fatalf("initialize errored: %+v", initResp.Error)
	}
	var initRes mcp.InitResult
	if err := json.Unmarshal(initResp.Result, &initRes); err != nil {
		t.Fatalf("initialize result unmarshal: %v", err)
	}
	if initRes.ServerInfo["name"] != proxyName {
		t.Errorf("initialize serverInfo.name: got %v, want %q", initRes.ServerInfo["name"], proxyName)
	}

	// tools/list (no manifest → forwarded verbatim, both tools present)
	listResp := h.roundTrip(t, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "tools/list"})
	tools, err := drift.ParseToolsListResult(listResp.Result)
	if err != nil {
		t.Fatalf("parse tools/list: %v", err)
	}
	if len(tools) != 2 {
		t.Errorf("tools/list: got %d tools, want 2", len(tools))
	}

	// tools/call (allowed by alwaysAllowPDP)
	callResp := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`3`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/hosts"}}`),
	})
	if callResp.Error != nil {
		t.Fatalf("tools/call errored: %+v", callResp.Error)
	}

	// A host notification should be forwarded without a response.
	if err := h.hostIn.Write(mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/cancelled"}); err != nil {
		t.Fatalf("write notification: %v", err)
	}

	if err := h.shutdown(t); err != nil {
		t.Errorf("Start returned error: %v", err)
	}
}

// TestStdioProxy_InFlightRequestSurvivesHostEOF pins the shutdown-race fix: an
// ALLOWED request still being forwarded when the host closes stdin must complete
// and return its upstream result, not get cut off mid-write with a -32603
// "upstream error". The trigger is closing host stdin immediately after a
// tools/call, without first draining its response (exactly what the stdio demo's
// pipe-all-then-EOF harness does). The earlier teardown closed the upstream input
// before in-flight handlers finished, yanking the pipe out from under the forward;
// serveHost now waits (bounded) for handlers before closing.
func TestStdioProxy_InFlightRequestSurvivesHostEOF(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	h := newStdioHostHarness(t, StdioProxyOptions{
		PDP:        pdp.AlwaysAllowPDP{},
		SessionID:  "integ-inflight-eof",
		ShutdownMs: 2000,
	})

	// Complete the handshake so the upstream is ready to answer.
	initResp := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "initialize",
		Params: json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}`),
	})
	if initResp.Error != nil {
		t.Fatalf("initialize errored: %+v", initResp.Error)
	}

	// Send a tools/call and close host stdin immediately, WITHOUT reading the
	// response first — so the request is still in flight in its handler goroutine
	// when serveHost observes EOF.
	if err := h.hostIn.Write(mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/hosts"}}`),
	}); err != nil {
		t.Fatalf("write tools/call: %v", err)
	}
	_ = h.inW.Close() // host EOF while tools/call is in flight

	callResp, err := h.hostOut.Read()
	if err != nil {
		t.Fatalf("read tools/call response: %v", err)
	}
	if callResp.Error != nil {
		t.Fatalf("in-flight tools/call was cut off at host EOF: %+v", callResp.Error)
	}
	if mcp.MsgKey(callResp.ID) != "n:2" {
		t.Errorf("response ID: got %s, want 2", mcp.MsgKey(callResp.ID))
	}

	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after host stdin closed")
	}
}

// TestStdioProxy_LifecycleWithManifestDriftClean drives Start with a manifest
// whose tools match the upstream, so the stdio drift check runs and passes.
func TestStdioProxy_LifecycleWithManifestDriftClean(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	manifest := &config.LocalManifest{
		Name:    "integ",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Actions: []string{"call"}},
			{Target: "tool:write_file", Actions: []string{"call"}},
		},
	}
	dp := pdp.NewManifestPDP(manifest.Capabilities, enforcement.New(), killswitch.NewInMemory())

	h := newStdioHostHarness(t, StdioProxyOptions{
		PDP:        dp,
		SessionID:  "integ-drift",
		ShutdownMs: 2000,
		// drift.MakeDriftCheck is the shared drift policy in internal/drift; this
		// integration test drives the transport's session-start path with the real
		// hook and asserts the end-to-end session outcome.
		DriftCheck: drift.MakeDriftCheck(manifest, true),
	})

	initResp := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "initialize",
		Params: json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}`),
	})
	if initResp.Error != nil {
		t.Fatalf("initialize errored: %+v", initResp.Error)
	}

	// tools/list should now be filtered through the manifest (both tools allowed).
	listResp := h.roundTrip(t, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "tools/list"})
	tools, err := drift.ParseToolsListResult(listResp.Result)
	if err != nil {
		t.Fatalf("parse tools/list: %v", err)
	}
	if len(tools) != 2 {
		t.Errorf("filtered tools/list: got %d, want 2", len(tools))
	}

	if err := h.shutdown(t); err != nil {
		t.Errorf("Start returned error: %v", err)
	}
}

// TestStdioProxy_StrictDriftAbortsStart asserts that a manifest pinning a
// descriptionHash that does not match the live tool description (FM-5
// description drift) aborts Start — unconditionally, not gated on
// --strict-drift — and the upstream is killed.
func TestStdioProxy_StrictDriftAbortsStart(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	// Pin a descriptionHash that cannot match the live description → FM-5 drift,
	// which aborts Start unconditionally (fail closed).
	manifest := &config.LocalManifest{
		Name:    "integ",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{
				Target:          "tool:read_file",
				Actions:         []string{"call"},
				DescriptionHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}
	dp := pdp.NewManifestPDP(manifest.Capabilities, enforcement.New(), killswitch.NewInMemory())

	cmd, args := helperUpstreamArgs()
	p := NewStdioProxy(StdioProxyOptions{
		Command:    cmd,
		Args:       args,
		PDP:        dp,
		SessionID:  "integ-drift-abort",
		ShutdownMs: 2000,
		// drift.MakeDriftCheck is the shared drift policy in internal/drift; the
		// descriptionHash pin below trips FM-5, which is unconditionally fatal, so
		// Start must abort.
		DriftCheck: drift.MakeDriftCheck(manifest, true),
	})
	// Host side is never exercised; give it a closed stdin so Start cannot block
	// on serveHost even if drift unexpectedly passes.
	inR, _ := io.Pipe()
	p.hostReader = mcp.NewMsgReader(inR)
	outR, outW := io.Pipe()
	go func() { _, _ = io.Copy(io.Discard, outR) }()
	p.hostWriter = mcp.NewMsgWriter(outW)

	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("expected Start to abort on descriptionHash drift, got nil")
	}
	// The startup-failure path must REAP the subprocess, not just signal it: without
	// cmd.Wait the killed child stays a zombie and os/exec never closes the stdin/
	// stdout pipe FDs. ProcessState is set only by Wait, so its presence confirms the
	// reap (Start calls killUpstream+waitUpstream synchronously before returning).
	if p.upCmd == nil || p.upCmd.ProcessState == nil {
		t.Error("Start must reap the upstream subprocess on a startup failure (ProcessState nil => no cmd.Wait => zombie + leaked pipe FDs)")
	}
}

// TestStdioProxy_ConnectUpstream_SubprocessLifecycle exercises connectUpstream,
// signalUpstream, and waitUpstream for a local subprocess without driving the
// full Start path.
func TestStdioProxy_ConnectUpstream_SubprocessLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess; skipped in -short")
	}

	p := &StdioProxy{
		command:    "sleep",
		args:       []string{"30"},
		shutdownMs: 200,
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	if p.upCmd == nil || p.upCmd.Process == nil {
		t.Fatal("expected a started subprocess")
	}
	if got := p.upstreamLabel(); got != "sleep" {
		t.Errorf("upstreamLabel: got %q, want %q", got, "sleep")
	}

	// SIGTERM should terminate `sleep`; waitUpstream then reaps it.
	p.signalUpstream(syscall.SIGTERM)
	p.waitUpstream()
	// Perform the same teardown Start does once the upstream has exited. Skipping it
	// left signalUpstream's AfterFunc armed with nothing to cancel it, so its goroutine
	// fired shutdownMs after this test returned and read os.Stderr while an unrelated
	// test was swapping that process-global through captureStderr — a data race the
	// detector then attributed to whatever test happened to be running.
	if !p.stopKillTimer() {
		t.Error("the SIGKILL fallback fired before teardown could cancel it; its goroutine outlives this test")
	}
}

// TestStdioProxy_SignalUpstream_KillTimerStoppable pins the fix: the
// SIGKILL fallback timer armed by signalUpstream is captured on the proxy so
// Start's teardown can stop it once the upstream has exited — suppressing a
// spurious "sending SIGKILL" log line on clean shutdown and freeing the timer.
// With a long shutdownMs the timer cannot have fired yet, so Stop() must report
// it was cancelled in time. If signalUpstream stopped capturing the timer
// (p.killTimer left nil) this test fails immediately.
func TestStdioProxy_SignalUpstream_KillTimerStoppable(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess; skipped in -short")
	}

	p := &StdioProxy{
		command:    "sleep",
		args:       []string{"30"},
		shutdownMs: 60000, // 60s: far longer than the test, so the timer never fires
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}

	// SIGTERM kills `sleep` immediately and arms the SIGKILL fallback timer.
	p.signalUpstream(syscall.SIGTERM)

	p.killMu.Lock()
	timer := p.killTimer
	p.killMu.Unlock()
	if timer == nil {
		t.Fatal("signalUpstream did not capture the SIGKILL fallback timer (regression)")
	}
	// Through stopKillTimer, the same call Start's teardown makes: a true return is the
	// timer being cancelled in time, which is what suppresses the spurious SIGKILL log
	// path and keeps the fallback goroutine from outliving the shutdown.
	if !p.stopKillTimer() {
		t.Error("kill timer already fired or was stopped; teardown cannot suppress the spurious SIGKILL log path")
	}

	p.waitUpstream() // reap the terminated subprocess
}

// TestStdioProxy_KillUpstream_Subprocess covers the killUpstream subprocess
// branch directly.
func TestStdioProxy_KillUpstream_Subprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess; skipped in -short")
	}

	p := &StdioProxy{
		command: "sleep",
		args:    []string{"30"},
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	p.killUpstream()
	p.waitUpstream() // reap the killed process
}

// TestStdioProxy_ConnectUpstream_BadCommand asserts connectUpstream surfaces a
// start error for a nonexistent command.
func TestStdioProxy_ConnectUpstream_BadCommand(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{
		command: "this-command-does-not-exist-eunox",
	}
	if err := p.connectUpstream(context.Background()); err == nil {
		t.Fatal("expected connectUpstream to fail for a nonexistent command")
	}
}

// TestStdioProxy_HTTPUpstreamWiring covers the HTTP-upstream branch of
// connectUpstream/upstreamLabel/killUpstream/signalUpstream/closeUpstreamInput,
// which route through the httpUpstream bridge rather than a subprocess.
func TestStdioProxy_HTTPUpstreamWiring(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{
		upstreamURL: "https://upstream.example.com",
		shutdownMs:  200,
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream (http): %v", err)
	}
	if p.upHTTP == nil {
		t.Fatal("expected upHTTP to be wired for a URL upstream")
	}
	if got := p.upstreamLabel(); got != "https://upstream.example.com" {
		t.Errorf("upstreamLabel: got %q, want the URL", got)
	}
	// All teardown paths for an HTTP upstream funnel through upHTTP.close();
	// calling them must be safe (idempotent close).
	p.signalUpstream(syscall.SIGTERM)
	p.closeUpstreamInput()
	p.killUpstream()
	p.waitUpstream() // no-op for HTTP, must not panic
}

// TestStdioProxy_ConnectUpstream_HTTPEmitsServerInitiatedNotice pins the stdio-host
// half of the remote-HTTP-upstream limitation: connecting a remote HTTP upstream
// emits the server-initiated-not-serviced NOTICE so an operator is not left
// debugging a silent hang. The gateway half is covered by
// TestBuildRoutes_RemoteUpstreamServerInitiatedNotice. The NOTICE is captured through the
// proxy's own stderr field rather than the process-global os.Stderr (issue 215), so this can
// run in parallel like any other test.
func TestStdioProxy_ConnectUpstream_HTTPEmitsServerInitiatedNotice(t *testing.T) {
	t.Parallel()
	var buf syncBuffer
	p := &StdioProxy{
		upstreamURL: "https://upstream.example.com",
		shutdownMs:  200,
		stderr:      &buf,
	}
	connErr := p.connectUpstream(context.Background())
	if connErr != nil {
		t.Fatalf("connectUpstream (http): %v", connErr)
	}
	s := buf.String()
	if !strings.Contains(s, "is a remote HTTP upstream") || !strings.Contains(s, "server-initiated requests") {
		t.Errorf("expected the stdio host to emit a server-initiated-not-serviced NOTICE, got:\n%s", s)
	}
	if !strings.Contains(s, `"https://upstream.example.com"`) {
		t.Errorf("the NOTICE must name the upstream URL, got:\n%s", s)
	}
	// Teardown funnels through upHTTP.close(); must stay safe/idempotent.
	p.killUpstream()
	p.waitUpstream() // no-op for HTTP, must not panic
}

// TestRunStdioDriftCheck_SkippedWhenNoPins asserts that a tools/list failure is
// non-fatal (best-effort) in non-strict mode when the manifest pins no description
// hashes. Under --strict-drift the same failure is fatal — see
// TestRunStdioDriftCheck_StrictFatalWhenNoPins.
func TestRunStdioDriftCheck_SkippedWhenNoPins(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess; skipped in -short")
	}
	// `true` exits immediately, so its stdout closes before answering tools/list
	// → fetchUpstreamToolsRaw fails → drift check is skipped (no pins, non-strict).
	p := &StdioProxy{
		command: "true",
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	defer func() { p.killUpstream(); p.waitUpstream() }()

	manifest := &config.LocalManifest{
		Name:         "nopins",
		Version:      "1.0.0",
		Capabilities: []capability.Constraint{{Target: "tool:read_file", Actions: []string{"call"}}},
	}
	raw, probeErr := p.fetchUpstreamToolsRaw(context.Background())
	// drift.MakeDriftCheck is the shared drift policy in internal/drift; with no
	// descriptionHash pins and strict off, a tools/list probe failure is a
	// best-effort skip.
	if err := drift.MakeDriftCheck(manifest, false)(raw, p.upstreamServerVersion, probeErr); err != nil {
		t.Errorf("expected drift check to be skipped (no pins, non-strict), got %v", err)
	}
}

// TestRunStdioDriftCheck_StrictFatalWhenNoPins asserts that under
// --strict-drift a tools/list probe failure is fatal even with no descriptionHash
// pins: an upstream we cannot inspect must not silently bypass the fatal-on-drift
// guarantee by withholding tools/list.
func TestRunStdioDriftCheck_StrictFatalWhenNoPins(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess; skipped in -short")
	}
	p := &StdioProxy{
		command: "true",
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	defer func() { p.killUpstream(); p.waitUpstream() }()

	manifest := &config.LocalManifest{
		Name:         "nopins",
		Version:      "1.0.0",
		Capabilities: []capability.Constraint{{Target: "tool:read_*", Actions: []string{"call"}}},
	}
	raw, probeErr := p.fetchUpstreamToolsRaw(context.Background())
	if err := drift.MakeDriftCheck(manifest, true)(raw, p.upstreamServerVersion, probeErr); err == nil {
		t.Error("expected fatal drift error under --strict-drift when tools/list unavailable")
	}
}

// TestRunStdioDriftCheck_FatalWhenPinsAndNoToolsList asserts that a tools/list
// failure is fatal when the manifest pins a description hash (cannot verify
// integrity → fail closed).
func TestRunStdioDriftCheck_FatalWhenPinsAndNoToolsList(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess; skipped in -short")
	}
	p := &StdioProxy{
		command: "true",
	}
	if err := p.connectUpstream(context.Background()); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	defer func() { p.killUpstream(); p.waitUpstream() }()

	manifest := &config.LocalManifest{
		Name:    "pins",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{
				Target:          "tool:read_file",
				Actions:         []string{"call"},
				DescriptionHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}
	raw, probeErr := p.fetchUpstreamToolsRaw(context.Background())
	// drift.MakeDriftCheck is the shared drift policy in internal/drift; with a
	// descriptionHash pin a tools/list probe failure fails closed (cannot verify
	// description integrity without the live list).
	if err := drift.MakeDriftCheck(manifest, true)(raw, p.upstreamServerVersion, probeErr); err == nil {
		t.Error("expected fatal drift error when pins set and tools/list unavailable")
	}
}

// ── OnReady ordering ──────────────────────────────────────────────────────

// TestStdioProxy_OnReadyNotRunWhenStartupFails pins the ordering the session-kill TTL
// publish depends on, the stdio analogue of TestServe_AfterListenNotRunWhenBindFails. The
// hook overwrites shared, last-writer-wins Redis state that `eunox kill` then trusts, so a
// proxy that never comes up must not run it — otherwise starting a second, doomed proxy
// leaves the RUNNING one's advertised lifetime replaced by one nothing enforces.
//
// The stdio host has no bind step, so the steps it has to clear instead are its own, inside
// Start: spawning the upstream, the initialize handshake, and the drift check.
func TestStdioProxy_OnReadyNotRunWhenStartupFails(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	// An FM-5 descriptionHash pin that cannot match, so the drift check refuses the
	// session — the LAST of Start's fallible steps, and the one furthest from the
	// constructor, so clearing it means the hook cleared all three.
	manifest := &config.LocalManifest{
		Name:    "integ",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{{
			Target:          "tool:read_file",
			Actions:         []string{"call"},
			DescriptionHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		}},
	}

	for _, tc := range []struct {
		name    string
		command string
		args    []string
		drift   drift.CheckFunc
	}{
		{
			name:    "upstream binary does not exist",
			command: filepath.Join(t.TempDir(), "no-such-upstream"),
		},
		{
			name:    "drift check refuses the session",
			command: os.Args[0],
			args:    []string{"-test.run=^TestHelperStdioUpstream$", "--", stdioUpstreamSentinel},
			drift:   drift.MakeDriftCheck(manifest, true),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ready atomic.Bool
			p := NewStdioProxy(StdioProxyOptions{
				Command:    tc.command,
				Args:       tc.args,
				PDP:        pdp.NewManifestPDP(manifest.Capabilities, enforcement.New(), killswitch.NewInMemory()),
				SessionID:  "integ-onready-fail",
				ShutdownMs: 2000,
				DriftCheck: tc.drift,
				OnReady:    func(context.Context) { ready.Store(true) },
			})
			// Genuinely CLOSED stdin, so Start cannot block in serveHost if startup
			// unexpectedly succeeds. Discarding the write end instead leaves the read end
			// blocking forever (a GC'd *io.PipeWriter closes nothing), which would turn a
			// regression in the ordering this test pins into a package-wide timeout rather
			// than a failed assertion.
			inR, inW := io.Pipe()
			_ = inW.Close()
			p.hostReader = mcp.NewMsgReader(inR)
			outR, outW := io.Pipe()
			go func() { _, _ = io.Copy(io.Discard, outR) }()
			p.hostWriter = mcp.NewMsgWriter(outW)

			if err := p.Start(context.Background()); err == nil {
				t.Fatal("Start must fail for this case; the test's premise is a failed startup")
			}
			if ready.Load() {
				t.Error("OnReady must not run when startup fails: it would clobber a running proxy's published state")
			}
		})
	}
}

// The companion: on a session that does come up, the hook must actually run — before the
// host serve loop, so a proxy standing and serving has published its state.
func TestStdioProxy_OnReadyRunsOnceSessionIsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	var ready atomic.Bool
	h := newStdioHostHarness(t, StdioProxyOptions{
		PDP:        pdp.AlwaysAllowPDP{},
		SessionID:  "integ-onready-ok",
		ShutdownMs: 2000,
		OnReady:    func(context.Context) { ready.Store(true) },
	})
	// Drive one request through so the serve loop has demonstrably started, which places
	// the hook strictly before it rather than merely somewhere inside Start.
	h.roundTrip(t, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/list"})
	if !ready.Load() {
		t.Error("OnReady must run once the session is live, before the host serve loop")
	}
	if err := h.shutdown(t); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// TestStdioProxy_RevisionNegotiationEndToEnd drives the whole seam through a real proxy and
// a real upstream subprocess: an ordinary 2025-11-25 session is byte-unchanged, a request
// declaring the newer revision inside that context is refused -32022, and a method the
// newer revision removed is refused for a peer that declares it.
//
// End-to-end rather than at the resolver, because the property that matters is that the
// serve loop resolves the revision BEFORE anything routes on the method — a unit test on
// resolveHostRevision cannot see a call site that looked the method up first.
func TestStdioProxy_RevisionNegotiationEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	h := newStdioHostHarness(t, StdioProxyOptions{
		PDP:        pdp.AlwaysAllowPDP{},
		SessionID:  "integ-revision",
		ShutdownMs: 2000,
	})

	initResp := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "initialize",
		Params: json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}`),
	})
	if initResp.Error != nil {
		t.Fatalf("initialize errored: %+v", initResp.Error)
	}
	if got := h.proxy.hostRevision(); got != capability.Revision20251125 {
		t.Fatalf("host context revision = %q, want %q — answering initialize IS the negotiation", got, capability.Revision20251125)
	}

	// The regression guard: an ordinary request of the negotiated revision carries no
	// declaration and must behave exactly as before the seam existed.
	if resp := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/hosts"}}`),
	}); resp.Error != nil {
		t.Fatalf("an undeclared request in a negotiated context must serve unchanged, got %+v", resp.Error)
	}

	// A declaration disagreeing with the context is enforcement confusion, not negotiation.
	flip := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`3`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/hosts"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
	})
	if flip.Error == nil || flip.Error.Code != capability.JSONRPCCodeUnsupportedProtocolVersion {
		t.Fatalf("a mid-context revision flip must be refused -32022, got %+v (result %s)", flip.Error, flip.Result)
	}

	// An unknown revision is refused the same way, whatever the context.
	unknown := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`4`), Method: "tools/list",
		Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}`),
	})
	if unknown.Error == nil || unknown.Error.Code != capability.JSONRPCCodeUnsupportedProtocolVersion {
		t.Fatalf("an unknown declared revision must be refused -32022, got %+v", unknown.Error)
	}

	if err := h.shutdown(t); err != nil {
		t.Errorf("Start returned error: %v", err)
	}
}

// TestStdioProxy_NewRevisionPeerLosesRemovedMethods: a peer that declares 2026-07-28 before
// any handshake gets that revision's tables — so ping, a method the revision removed, is
// denied by the same fail-closed default an unknown method hits, while tools/call (which
// both revisions have) still serves.
func TestStdioProxy_NewRevisionPeerLosesRemovedMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}

	h := newStdioHostHarness(t, StdioProxyOptions{
		PDP:        pdp.AlwaysAllowPDP{},
		SessionID:  "integ-revision-new",
		ShutdownMs: 2000,
	})

	ping := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "ping",
		Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
	})
	if ping.Error == nil {
		t.Fatalf("ping must be denied for a peer on a revision that removed it, got result %s", ping.Result)
	}
	if ping.Error.Code != capability.JSONRPCCodeAuthorizationFailed {
		t.Errorf("ping denial code = %d, want %d — removal is expressed by absence from the table, so it hits the ordinary unmapped default",
			ping.Error.Code, capability.JSONRPCCodeAuthorizationFailed)
	}

	call := h.roundTrip(t, mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/hosts"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
	})
	if call.Error != nil {
		t.Fatalf("tools/call exists in both revisions and must serve, got %+v", call.Error)
	}

	if err := h.shutdown(t); err != nil {
		t.Errorf("Start returned error: %v", err)
	}
}
