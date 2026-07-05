// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Lightweight one-shot MCP client for the validate --live and init subcommands:
// no session management or proxy machinery, just the initialize handshake
// followed by tools/list.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/transport"
)

// LiveUpstreamInfo holds the tool list and server metadata fetched from a
// live MCP HTTP server during the validate --live and init handshake.
type LiveUpstreamInfo struct {
	Tools         []drift.UpstreamTool
	ServerVersion string // version field from initialize serverInfo; empty if absent
}

// fetchLiveTools connects to the remote MCP HTTP server at baseURL, performs
// the initialize handshake, sends tools/list, and returns the live tool set
// together with the server version reported in the initialize response.
//
// baseURL is the server's base URL (e.g. "https://mcp.example.com"); "/mcp"
// is appended automatically, matching the proxy convention.
func fetchLiveTools(ctx context.Context, baseURL, authHeader string, tlsSkipVerify bool) (LiveUpstreamInfo, error) {
	// The probe is bounded by the caller's liveUpstreamTimeout context, so no
	// separate header cap is needed (0 = unset).
	client := transport.BuildUpstreamClient(tlsSkipVerify, 0)
	endpoint := transport.UpstreamMCPEndpoint(baseURL)

	initResp, respHdr, err := transport.DoMCPHTTP(ctx, client, endpoint,
		transport.BuildInitializeRequestWithID(mcp.RawJSON(`1`)), "", authHeader)
	// Capture the upstream session id and arm the terminating DELETE the instant the
	// response headers arrive, BEFORE the err gate. A lenient remote upstream may have
	// already ALLOCATED a server-side session (stamped Mcp-Session-Id) even on a
	// transport-level / non-2xx initialize failure, so the session must be closed on
	// every error path below — not only the success path. DeleteMCPHTTPSession no-ops on
	// an empty sessID, so the success path still issues a single DELETE. Mirrors
	// initRemoteUpstream in internal/transport/http_remote.go, which captures before any
	// correlation/validation gate for the same reason. The helper is best-effort/bounded
	// — the HTTP peer of fetchLiveToolsStdio's teardown.
	var sessID string
	if respHdr != nil {
		if sessID = respHdr.Get(transport.SessionHeader); sessID != "" {
			//nolint:contextcheck // teardown deliberately uses the helper's own bounded background context: it runs from the defer as the probe's request context is being canceled.
			defer transport.DeleteMCPHTTPSession(client, endpoint, sessID, authHeader)
		}
	}
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: %w", err)
	}

	// Validate through the same checker the proxy uses, so the CLI and proxy cannot
	// diverge on what counts as a valid initialize result (e.g. a `null` result must
	// be rejected, not accepted with an empty server version).
	_, serverVersion, _, err := transport.ApplyInitializeResult(initResp)
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: %w", err)
	}

	notif, _ := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	if _, _, err := transport.DoMCPHTTP(ctx, client, endpoint, notif, sessID, authHeader); err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("notifications/initialized: %w", err)
	}

	// Page tools/list to exhaustion via the shared paginator, mirroring the stdio
	// path and both transport drift probes, so the full tool catalog is observed.
	merged, err := drift.FetchAllToolPages(func(cursor string) (json.RawMessage, error) {
		req := drift.ToolsListRequest(mcp.RawJSON(`2`), cursor)
		listResp, _, err := transport.DoMCPHTTP(ctx, client, endpoint, req, sessID, authHeader)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		if listResp.Error != nil {
			return nil, fmt.Errorf("tools/list: server error %d: %s", listResp.Error.Code, listResp.Error.Message)
		}
		return listResp.Result, nil
	})
	if err != nil {
		return LiveUpstreamInfo{}, err
	}
	tools, err := drift.ParseToolsListResult(merged)
	if err != nil {
		return LiveUpstreamInfo{}, err
	}
	return LiveUpstreamInfo{Tools: tools, ServerVersion: serverVersion}, nil
}

// stdioIntrospectShutdownMs caps the post-tools/list wait before SIGKILL — the
// subprocess sees stdin EOF and most servers exit immediately; this is the
// safety net for ones that don't.
const stdioIntrospectShutdownMs = 2000

// liveUpstreamTimeout bounds a single live introspection for the validate,
// doctor, and init subcommands. Without it, a stdio upstream that completes
// initialize but never answers tools/list would block forever. A var only so
// tests can shorten it; production never reassigns it.
var liveUpstreamTimeout = 30 * time.Second

// fetchLiveToolsStdio spawns the subprocess, runs the initialize + tools/list
// handshake over its stdin/stdout, returns the tool set and server version, and
// shuts it down. The stdio peer of fetchLiveTools, used by `init` and
// `validate --live --config`.
func fetchLiveToolsStdio(ctx context.Context, command string, args []string) (LiveUpstreamInfo, error) {
	// Bind the subprocess to a cancelable context; the shutdown backstop cancels it
	// rather than calling cmd.Process.Kill() directly. os/exec serializes the
	// context-driven kill with cmd.Wait, so a SIGKILL can never reach a PID Wait
	// already reaped (and the OS may have recycled) — a raw timer + Kill would race.
	procCtx, cancel := context.WithCancel(ctx)
	defer cancel()                                        // always release the context (covers the early-return error paths)
	cmd := exec.CommandContext(procCtx, command, args...) //nolint:gosec // G204: command and args are user-supplied CLI arguments
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("upstream stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		// StdinPipe already succeeded, allocating an os.Pipe() pair on cmd's
		// childIOFiles/parentIOPipes. Those are closed only inside cmd.Start() or
		// cmd.Wait(), neither of which has run on this path (the teardown defer below
		// is registered only after Start succeeds), so close the parent write end here
		// to avoid leaking its fds.
		_ = stdin.Close()
		return LiveUpstreamInfo{}, fmt.Errorf("upstream stdout: %w", err)
	}
	w := mcp.NewMsgWriter(stdin)
	r := mcp.NewMsgReader(stdout)

	if err := cmd.Start(); err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("starting upstream %q: %w", command, err)
	}

	// Always tear the subprocess down: stdin close signals EOF, cmd.Wait reaps, an
	// AfterFunc backstops with SIGKILL. Deferred so a panic in runStdioHandshake
	// still reaps it (init's parent ctx is Background, so exec alone never cancels).
	defer func() {
		_ = stdin.Close()
		// Backstop: cancel procCtx if the subprocess does not exit shortly after
		// stdin close. Runs before the top-level cancel (LIFO), reaping here first.
		killTimer := time.AfterFunc(stdioIntrospectShutdownMs*time.Millisecond, cancel)
		_ = cmd.Wait()
		killTimer.Stop()
	}()

	info, err := runStdioHandshake(ctx, w, r)
	if err != nil {
		return LiveUpstreamInfo{}, err
	}
	return info, nil
}

// runStdioHandshake drives initialize → notifications/initialized → tools/list
// over the supplied write/read pair. Factored out of fetchLiveToolsStdio so it
// can be unit-tested against an in-memory pipe pair without spawning a real
// subprocess.
func runStdioHandshake(ctx context.Context, w *mcp.MsgWriter, r *mcp.MsgReader) (LiveUpstreamInfo, error) {
	const initID = `"_init"`
	if err := w.Write(transport.BuildInitializeRequestWithID(mcp.RawJSON(initID))); err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: write: %w", err)
	}
	initResp, err := readResponseWithID(ctx, w, r, initID)
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: %w", err)
	}
	// Same checker as the HTTP probe, so the stdio path fails closed on a
	// null/missing-field result. ApplyInitializeResult also surfaces an upstream error.
	_, serverVersion, _, err := transport.ApplyInitializeResult(initResp)
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: %w", err)
	}

	notif, _ := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	if err := w.Write(notif); err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("notifications/initialized: write: %w", err)
	}

	const listID = `"_tools_list"`
	// Follow nextCursor to exhaustion, merging all pages. FetchAllToolPages bounds
	// the page/tool counts and rejects a repeated cursor.
	merged, err := drift.FetchAllToolPages(func(cursor string) (json.RawMessage, error) {
		req := drift.ToolsListRequest(mcp.RawJSON(listID), cursor)
		if err := w.Write(req); err != nil {
			return nil, fmt.Errorf("tools/list: write: %w", err)
		}
		listResp, err := readResponseWithID(ctx, w, r, listID)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		if listResp.Error != nil {
			return nil, fmt.Errorf("tools/list: server error %d: %s", listResp.Error.Code, listResp.Error.Message)
		}
		return listResp.Result, nil
	})
	if err != nil {
		return LiveUpstreamInfo{}, err
	}
	tools, err := drift.ParseToolsListResult(merged)
	if err != nil {
		return LiveUpstreamInfo{}, err
	}
	return LiveUpstreamInfo{Tools: tools, ServerVersion: serverVersion}, nil
}

// readResponseWithID reads messages from r until it sees a response whose id
// matches wantID, discarding any notifications that arrive first. Returns the
// matched response, or an error if the stream ends or ctx is canceled first.
// An unsolicited response with a different id is treated as a protocol error.
func readResponseWithID(ctx context.Context, w *mcp.MsgWriter, r *mcp.MsgReader, wantID string) (mcp.RPCMsg, error) {
	// wantID is a raw JSON id literal (e.g. `"_init"`); canonicalize it through
	// MsgKey so the comparison matches MsgKey's value-based keys rather than the
	// raw byte spelling.
	wantKey := mcp.MsgKey(mcp.RawJSON(wantID))
	for {
		if err := ctx.Err(); err != nil {
			return mcp.RPCMsg{}, err
		}
		msg, err := r.Read()
		if err != nil {
			// A context deadline kills the subprocess, whose stdout close surfaces
			// here as a read error; report the deadline rather than the consequent
			// "file already closed" so the caller sees why the probe ended.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return mcp.RPCMsg{}, ctxErr
			}
			return mcp.RPCMsg{}, err
		}
		if msg.IsNotification() {
			continue
		}
		if msg.IsResponse() {
			if mcp.MsgKey(msg.ID) == wantKey {
				return msg, nil
			}
			return mcp.RPCMsg{}, fmt.Errorf("unexpected response id %q (wanted %q)", mcp.MsgKey(msg.ID), wantID)
		}
		// An unsolicited server-initiated request (roots/list, sampling/createMessage,
		// …) blocks the upstream until answered. Silently ignoring it would wedge the
		// probe until the deadline, so reply a structured error — the same fail-closed
		// handling the transports' startup read loops apply.
		transport.RejectPreInitServerRequest(w, msg)
	}
}
