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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
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

// stdioNoisySentinel is the argv marker that turns a re-exec of the test binary
// into an MCP stdio upstream that also prints non-JSON chatter to its stdout (see
// TestHelperStdioNoisyUpstream).
const stdioNoisySentinel = "eunox-stdio-noisy-process"

// TestHelperStdioNoisyUpstream is a re-exec entry point serving the same minimal
// MCP session as TestHelperStdioUpstream, but with stray non-JSON lines written to
// STDOUT — the shape an npx-launched server produces when a dependency prints a
// banner or a debug line onto the protocol stream. Each stray line is newline
// terminated, so the JSON-RPC framing stays intact and every one of them surfaces
// as a recoverable mcp.ErrParse to a reader.
func TestHelperStdioNoisyUpstream(t *testing.T) {
	if !slices.Contains(os.Args, stdioNoisySentinel) {
		return
	}
	// A banner ahead of the handshake, the common real-world case.
	fmt.Fprintln(os.Stdout, "my-mcp-server v1.2.3 — starting up")
	stdioUpstreamServeNoisy()
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

// stdioUpstreamServeNoisy serves the same session as stdioUpstreamServe but emits a
// stray non-JSON line to stdout before each response, so a reader must skip garbage
// interleaved with the protocol stream, not only a leading banner.
func stdioUpstreamServeNoisy() {
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
				ServerInfo:      map[string]interface{}{"name": "stdio-noisy", "version": "1.0.0"},
			}
		case "tools/list":
			result = map[string]interface{}{
				"tools": []map[string]interface{}{
					{"name": "read_file", "description": "reads a file"},
					{"name": "write_file", "description": "writes a file"},
				},
			}
		default:
			result = map[string]interface{}{}
		}
		// Chatter immediately before the real reply: the reader must skip this line
		// and go on to read the response that follows it on the same stream.
		fmt.Fprintf(os.Stdout, "[debug] handled %s\n", msg.Method)
		resp, _ := mcp.SuccessResponse(msg.ID, result)
		_ = writer.Write(resp)
	}
}

// helperUpstreamArgs returns the command + args that re-exec the test binary as
// the stdio upstream defined by TestHelperStdioUpstream.
func helperUpstreamArgs() (command string, args []string) {
	return os.Args[0], []string{"-test.run=^TestHelperStdioUpstream$", "--", stdioUpstreamSentinel}
}

// noisyUpstreamArgs returns the command + args that re-exec the test binary as the
// banner-printing stdio upstream defined by TestHelperStdioNoisyUpstream.
func noisyUpstreamArgs() (command string, args []string) {
	return os.Args[0], []string{"-test.run=^TestHelperStdioNoisyUpstream$", "--", stdioNoisySentinel}
}

// TestFetchLiveToolsStdio_NonJSONLineIsTerminal pins that the CLI probe and the
// RUNTIME agree about a stray non-JSON line on a stdio upstream's stdout.
//
// It is tempting to make the probe skip mcp.ErrParse so `init` / `validate --live` /
// `doctor --live` tolerate an npx-launched server that prints a banner. That is a
// fail-open in the reporting direction: both transports' upstream readers
// (StdioProxy.readUpstream, httpSession.readUpstream) and the shared initialize
// handshake (awaitStartupReply) end the session on any non-EOF read error, ErrParse
// included — only the HOST-side reader skips one and answers -32700. A lenient probe
// would therefore emit a manifest for, and report healthy, an upstream that
// `eunox proxy` kills at the handshake.
//
// So this asserts the probe FAILS, and it is the tripwire for that coupling: if the
// runtime upstream readers are ever made lenient, this test should be inverted in the
// same change, never on its own.
func TestFetchLiveToolsStdio_NonJSONLineIsTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess; skipped in -short")
	}
	cmd, args := noisyUpstreamArgs()
	_, err := fetchLiveToolsStdio(context.Background(), cmd, args)
	if err == nil {
		t.Fatal("expected a banner-printing upstream to fail the probe, matching how the runtime treats it")
	}
	if !errors.Is(err, mcp.ErrParse) {
		t.Errorf("probe error should identify the malformed line (mcp.ErrParse), got: %v", err)
	}
}

// TestFetchLiveToolsStdio_Subprocess drives the one-shot introspection client
// used by `init` and `validate --live --config` against a real subprocess.
func TestFetchLiveToolsStdio_Subprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess; skipped in -short")
	}
	cmd, args := helperUpstreamArgs()
	info, err := fetchLiveToolsStdio(context.Background(), cmd, args)
	if err != nil {
		t.Fatalf("fetchLiveToolsStdio: %v", err)
	}
	if len(info.Tools) != 2 {
		t.Errorf("got %d tools, want 2", len(info.Tools))
	}
	if info.ServerVersion != "1.0.0" {
		t.Errorf("server version: got %q, want %q", info.ServerVersion, "1.0.0")
	}
}

// TestFetchLiveToolsStdio_BadCommand asserts the start error is surfaced.
func TestFetchLiveToolsStdio_BadCommand(t *testing.T) {
	t.Parallel()
	_, err := fetchLiveToolsStdio(context.Background(), "this-command-does-not-exist-eunox", nil)
	if err == nil {
		t.Fatal("expected fetchLiveToolsStdio to fail for a nonexistent command")
	}
}

// TestFetchLiveToolsStdio_ContextTimeout asserts that a stdio upstream which
// never answers the handshake is bounded by the context deadline rather than
// hanging forever — the mechanism the validate/doctor/init --live timeouts rely
// on. The deadline kills the bound subprocess, closing its stdout so the blocked
// read returns, and the surfaced error is the deadline itself.
func TestFetchLiveToolsStdio_ContextTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess; skipped in -short")
	}
	cmd := os.Args[0]
	args := []string{"-test.run=^TestHelperStdioHangUpstream$", "--", stdioHangSentinel}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := fetchLiveToolsStdio(ctx, cmd, args)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a non-answering upstream under a context deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error: got %v, want context.DeadlineExceeded surfaced", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("fetchLiveToolsStdio did not honor the context deadline (took %v)", elapsed)
	}
}

// TestValidateLive_EndToEnd_MockUpstream drives the complete validate --live
// flow against a mock MCP server returning a fixed tool list that hits every
// report section: exact-covered, glob-matched (FM-1), uncovered, and a stale
// manifest entry (FM-2). It asserts both the rendered report and the exit code.
func TestValidateLive_EndToEnd_MockUpstream(t *testing.T) {
	// Known live tool list returned by the mock upstream.
	tools := []mcp.ToolEntry{
		{Name: "read_file", InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string"},
			},
		}},
		{Name: "get_customer"},       // matched by the get_* glob → FM-1
		{Name: "delete_all_records"}, // no manifest entry → uncovered
	}
	fake := newFakeUpstreamWithTools(tools)
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},     // exact
		capability.Constraint{Target: "tool:get_*", Actions: []string{"call"}},         // glob → FM-1
		capability.Constraint{Target: "tool:legacy_search", Actions: []string{"call"}}, // stale → FM-2
	)

	info, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}
	if len(info.Tools) != 3 {
		t.Fatalf("expected 3 live tools, got %d", len(info.Tools))
	}

	var out bytes.Buffer
	code := runValidateLive(manifest, info.Tools, info.ServerVersion, &out)
	if code != 1 {
		t.Errorf("exit code: want 1 (glob match + stale entry), got %d", code)
	}

	report := out.String()
	for _, want := range []string{
		"COVERED",
		"read_file",
		"WARNINGS",
		"get_customer",
		"NOT COVERED (denied by default)",
		"delete_all_records",
		"STALE MANIFEST ENTRIES",
		"tool:legacy_search",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q\n--- report ---\n%s", want, report)
		}
	}
}

// TestValidateLive_EndToEnd_CleanManifest_Exit0 verifies that an exact-only
// manifest covering every live tool produces a clean report and exit 0.
func TestValidateLive_EndToEnd_CleanManifest_Exit0(t *testing.T) {
	tools := []mcp.ToolEntry{{Name: "read_file"}, {Name: "query_db"}}
	fake := newFakeUpstreamWithTools(tools)
	srv := httptest.NewServer(http.StripPrefix("/mcp", fake))
	t.Cleanup(srv.Close)

	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:query_db", Actions: []string{"call"}},
	)

	info, err := fetchLiveTools(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("fetchLiveTools: %v", err)
	}

	var out bytes.Buffer
	code := runValidateLive(manifest, info.Tools, info.ServerVersion, &out)
	if code != 0 {
		t.Errorf("exit code: want 0 for clean manifest, got %d\n%s", code, out.String())
	}
}

// TestValidateLive_EndToEnd_Stdio drives the same pipeline over the stdio
// transport: runStdioHandshake against an in-memory mock server, then
// runValidateLive. This covers the `--transport stdio` path end to end.
func TestValidateLive_EndToEnd_Stdio(t *testing.T) {
	srv := newStdioMockServer(happyPathHandler(t, "1.0.0", []map[string]interface{}{
		{"name": "read_file"},
		{"name": "get_customer"}, // matched by get_* glob → FM-1
	}))

	info, err := runStdioHandshake(context.Background(), srv.clientW, srv.clientR)
	srv.close()
	if err != nil {
		t.Fatalf("runStdioHandshake: %v", err)
	}

	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:get_*", Actions: []string{"call"}},
	)

	var out bytes.Buffer
	code := runValidateLive(manifest, info.Tools, info.ServerVersion, &out)
	if code != 1 {
		t.Errorf("exit code: want 1 (glob match), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "get_customer") {
		t.Errorf("report should flag get_customer as a glob match\n%s", out.String())
	}
}
