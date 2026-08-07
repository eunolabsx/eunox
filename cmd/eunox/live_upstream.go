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
	"os/signal"
	"syscall"
	"time"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/capability"
)

// LiveUpstreamInfo holds the tool list and server metadata fetched from a live MCP HTTP
// server during the validate --live and init handshake.
type LiveUpstreamInfo struct {
	Tools         []drift.UpstreamTool
	ServerVersion string // version field from initialize serverInfo; empty if absent
}

// fetchLiveTools connects to the remote MCP HTTP server at baseURL, performs the initialize
// handshake, sends tools/list, and returns the live tool set with the server version.
// baseURL is the server's base URL; "/mcp" is appended automatically.
func fetchLiveTools(ctx context.Context, baseURL, authHeader string, tlsSkipVerify bool) (LiveUpstreamInfo, error) {
	// Bounded by the caller's liveUpstreamTimeout context, so no separate header cap needed.
	client := transport.BuildUpstreamClient(tlsSkipVerify, 0)
	endpoint := transport.UpstreamMCPEndpoint(baseURL)

	// The probe opens with `initialize`, which exists only in the handshake-bearing
	// revision — so that is the revision this leg speaks, and what its post-handshake
	// requests declare. A discover-first opener is the CLI-probe workstream's.
	initResp, respHdr, err := transport.DoMCPHTTP(ctx, client, endpoint,
		transport.BuildInitializeRequestWithID(mcp.RawJSON(`1`)), "", authHeader, capability.Revision20251125)
	// Capture the session id and arm the terminating DELETE BEFORE the err gate: a lenient
	// upstream may have already allocated a server-side session even on a failed initialize,
	// so it must be closed on every error path, not only success.
	var sessID string
	if respHdr != nil {
		if sessID = respHdr.Get(transport.SessionHeader); sessID != "" {
			//nolint:contextcheck // teardown deliberately uses the helper's own bounded background context: it runs from the defer as the probe's request context is being canceled.
			defer transport.DeleteMCPHTTPSession(client, endpoint, sessID, authHeader, capability.Revision20251125)
		}
	}
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: %w", err)
	}

	// Same checker the proxy uses, so the CLI and proxy can't diverge on what counts as a
	// valid initialize result (e.g. a `null` result must be rejected).
	hs, err := transport.ApplyInitializeResult(initResp)
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: %w", err)
	}
	serverVersion := hs.ServerVersion

	notif, _ := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	if _, _, err := transport.DoMCPHTTP(ctx, client, endpoint, notif, sessID, authHeader, capability.Revision20251125); err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("notifications/initialized: %w", err)
	}

	// Page tools/list to exhaustion so the full tool catalog is observed.
	merged, err := drift.FetchAllToolPages(func(cursor string) (json.RawMessage, error) {
		req := drift.ToolsListRequest(mcp.RawJSON(`2`), cursor)
		listResp, _, err := transport.DoMCPHTTP(ctx, client, endpoint, req, sessID, authHeader, capability.Revision20251125)
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

// stdioIntrospectShutdownMs caps the post-tools/list wait before SIGKILL — most servers
// exit immediately on stdin EOF; this is the safety net for ones that don't.
const stdioIntrospectShutdownMs = 2000

// liveUpstreamTimeout bounds a single live introspection; without it a stdio upstream that
// completes initialize but never answers tools/list would block forever. A var only so
// tests can shorten it.
var liveUpstreamTimeout = 30 * time.Second

// fetchLiveToolsStdio spawns the subprocess, runs the initialize + tools/list handshake
// over its stdin/stdout, and shuts it down. The stdio peer of fetchLiveTools.
func fetchLiveToolsStdio(ctx context.Context, command string, args []string) (LiveUpstreamInfo, error) {
	// Cancel rather than call cmd.Process.Kill() directly: os/exec serializes the
	// context-driven kill with cmd.Wait, so SIGKILL can never race a reaped/recycled PID.
	procCtx, cancel := context.WithCancel(ctx)
	defer cancel()                                        // release the context on every early-return path
	cmd := exec.CommandContext(procCtx, command, args...) //nolint:gosec // G204: command and args are user-supplied CLI arguments
	transport.ConfigureUpstreamCmd(cmd)
	// Tear down the whole process group on cancel, not just the direct child — os/exec's
	// default Cancel (Process.Kill() on the wrapper alone) orphans the real server an
	// `npx`/`uvx` wrapper spawns.
	cmd.Cancel = func() error {
		transport.KillUpstreamProcess(cmd.Process)
		return nil
	}

	// Forward an operator's Ctrl-C to the probe subprocess. ConfigureUpstreamCmd's own
	// process group detaches it from the terminal's SIGINT delivery; without a handler
	// here the CLI would die on the default disposition and orphan a daemon-style server.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	stopSigWatch := make(chan struct{})
	defer close(stopSigWatch)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-stopSigWatch:
		}
	}()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("upstream stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		// StdinPipe already allocated its pipe pair, closed only by Start/Wait — neither
		// of which has run yet on this path — so close it here to avoid leaking fds.
		_ = stdin.Close()
		return LiveUpstreamInfo{}, fmt.Errorf("upstream stdout: %w", err)
	}
	w := mcp.NewMsgWriter(stdin)
	r := mcp.NewMsgReader(stdout)

	if err := cmd.Start(); err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("starting upstream %q: %w", command, err)
	}

	// Always tear the subprocess down: stdin close signals EOF, cmd.Wait reaps, an
	// AfterFunc backstops with SIGKILL. Deferred so a panic in runStdioHandshake still reaps.
	defer func() {
		_ = stdin.Close()
		killTimer := time.AfterFunc(stdioIntrospectShutdownMs*time.Millisecond, cancel)
		_ = cmd.Wait()
		killTimer.Stop()
	}()

	// procCtx, not the outer ctx: the handshake must observe the same cancellation as the
	// subprocess, or an operator's Ctrl-C would surface as a misleading read EOF.
	info, err := runStdioHandshake(procCtx, w, r)
	if err != nil {
		return LiveUpstreamInfo{}, err
	}
	return info, nil
}

// runStdioHandshake drives initialize -> notifications/initialized -> tools/list over the
// supplied write/read pair. Factored out so it can be unit-tested without a real subprocess.
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
	hs, err := transport.ApplyInitializeResult(initResp)
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("initialize: %w", err)
	}
	serverVersion := hs.ServerVersion

	notif, _ := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	if err := w.Write(notif); err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("notifications/initialized: write: %w", err)
	}

	const listID = `"_tools_list"`
	// FetchAllToolPages follows nextCursor to exhaustion, bounding page/tool counts and
	// rejecting a repeated cursor.
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

// readResponseWithID reads messages from r until it sees a response whose id matches
// wantID, discarding notifications that arrive first. An unsolicited response with a
// different id is treated as a protocol error.
func readResponseWithID(ctx context.Context, w *mcp.MsgWriter, r *mcp.MsgReader, wantID string) (mcp.RPCMsg, error) {
	// Canonicalize through MsgKey so the comparison matches its value-based keys rather
	// than the raw byte spelling.
	wantKey := mcp.MsgKey(mcp.RawJSON(wantID))
	for {
		if err := ctx.Err(); err != nil {
			return mcp.RPCMsg{}, err
		}
		msg, err := r.Read()
		if err != nil {
			// A context deadline kills the subprocess, whose stdout close surfaces as a
			// read error; report the deadline instead of the consequent "file already closed".
			if ctxErr := ctx.Err(); ctxErr != nil {
				return mcp.RPCMsg{}, ctxErr
			}
			// A malformed line is TERMINAL here deliberately, matching the runtime (both
			// transports' upstream readers end the session on any non-EOF read error,
			// mcp.ErrParse included) — skipping it would let this probe certify a stdio
			// server that `eunox proxy` then kills at the handshake.
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
		// An unsolicited server-initiated request blocks the upstream until answered;
		// silently ignoring it would wedge the probe until the deadline.
		transport.RejectPreInitServerRequest(w, msg)
	}
}

// fetchSpecLive introspects the upstream an initUpstreamSpec points at, dispatching on its
// transport. Shared by `validate --live` and `init`; fetchRouteLive is the gateway-config
// sibling for a *config.UpstreamConfig.
func fetchSpecLive(ctx context.Context, spec initUpstreamSpec) (LiveUpstreamInfo, error) {
	switch spec.Transport {
	case config.HostTransportStdio:
		return fetchLiveToolsStdio(ctx, spec.Command, spec.Args)
	case config.HostTransportHTTP:
		return fetchLiveTools(ctx, spec.URL, spec.AuthHeader, spec.TLSSkipVerify)
	default:
		// Fail closed rather than probing an unrecognized transport as HTTP; the structural
		// guard against a future third transport silently inheriting the HTTP probe.
		return LiveUpstreamInfo{}, fmt.Errorf("unknown upstream transport %q", spec.Transport)
	}
}

// fetchRouteLive introspects one route's declared upstream. A fresh liveUpstreamTimeout is
// applied PER route so a slow early route cannot exhaust a shared budget. Delegates the
// actual transport dispatch to fetchSpecLive via an adapted initUpstreamSpec, so the two
// don't hand-mirror the same stdio/http switch; the route name is added as an error prefix
// here, since fetchSpecLive's caller-agnostic spec has none to give.
func fetchRouteLive(ctx context.Context, u *config.UpstreamConfig) (LiveUpstreamInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, liveUpstreamTimeout)
	defer cancel()
	info, err := fetchSpecLive(ctx, initUpstreamSpec{
		Transport:     u.Transport,
		URL:           u.UpstreamURL,
		AuthHeader:    u.UpstreamAuthHeader,
		TLSSkipVerify: u.UpstreamTLSSkipVerify,
		Command:       u.Command,
		Args:          u.Args,
	})
	if err != nil {
		return LiveUpstreamInfo{}, fmt.Errorf("upstream %q: %w", u.Name, err)
	}
	return info, nil
}
