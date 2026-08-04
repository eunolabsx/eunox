// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
)

// fetchUpstreamToolsRaw sends a tools/list probe over the HTTP session's callUpstream and
// returns the raw JSON result. Marked withoutUpstreamTimeout since it's session-start work,
// bounded by sessionStartTimeout instead — a tight --upstream-timeout must not fail session
// establishment when the manifest pins descriptionHash (fetch failure is fatal then).
func (sess *httpSession) fetchUpstreamToolsRaw(ctx context.Context) (json.RawMessage, error) {
	return drift.FetchAllToolPages(func(cursor string) (json.RawMessage, error) {
		req := drift.ToolsListRequest(mcp.RawJSON(`"_drift"`), cursor)
		resp, err := sess.callUpstream(withoutUpstreamTimeout(ctx), req)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("tools/list: upstream error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	})
}

// fetchUpstreamToolsRaw sends tools/list to the configured upstream before the background
// readUpstream goroutine starts, dispatching on the upstream transport (subprocess pipe or,
// when p.upHTTP is set, the remote HTTP bridge). Returns the raw JSON result.
//
// Bounded by the session-start budget, NOT --upstream-timeout in either direction (mirroring
// the httpSession probe's initCtx), so the same upstream/manifest/flags establishes a session
// identically behind a stdio host and an HTTP host.
//
// On the remote-HTTP bridge that budget bounds the ENTIRE multi-page probe once, not each
// page — a fresh per-page deadline would let a slow upstream stretch startup to
// pages*budget. The single deadline also makes the bridge read honor cancellation (readCtx).
//
// Termination is guaranteed on the subprocess path by the pipe closing on process exit (EOF),
// bounded by runBoundedStartup's watchdog; on the HTTP bridge by the probe-wide deadline.
func (p *StdioProxy) fetchUpstreamToolsRaw(ctx context.Context) (json.RawMessage, error) {
	// Derive one deadline for the whole HTTP-bridge probe (all pages share it), bounding it
	// by the session-start budget exactly as runBoundedStartup bounds the subprocess path
	// and as the httpSession probe bounds its own initCtx — so the two transports reach the
	// same start success/failure for a given upstream, independent of --upstream-timeout in
	// both directions. The subprocess path keeps the parent ctx unchanged (its overall bound
	// is runBoundedStartup's child-kill watchdog, which EOFs the pipe to unblock Read).
	probeCtx, cancel := p.httpBridgeStartCtx(ctx)
	defer cancel()
	return drift.FetchAllToolPages(func(cursor string) (json.RawMessage, error) {
		req := drift.ToolsListRequest(mcp.RawJSON(`"_drift"`), cursor)
		if p.upHTTP != nil {
			p.upHTTP.postWithCtx(probeCtx, req)
		} else if err := p.upWriter.Write(req); err != nil {
			return nil, fmt.Errorf("tools/list write: %w", err)
		}
		msg, err := awaitStartupReply(
			func() (mcp.RPCMsg, error) { return p.readProbeReply(probeCtx) },
			mcp.RawJSON(`"_drift"`),
			p.upWriter,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("tools/list read: %w", err)
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("tools/list: upstream error %d: %s", msg.Error.Code, msg.Error.Message)
		}
		return msg.Result, nil
	})
}

// readProbeReply reads the next upstream message during startup (the initialize handshake and
// the tools/list drift probe). On the remote-HTTP bridge it honors ctx (readCtx) so a
// canceled/timed-out startup returns promptly rather than blocking until teardown. The
// subprocess path keeps the plain Read, bounded by runBoundedStartup's child-kill watchdog.
func (p *StdioProxy) readProbeReply(ctx context.Context) (mcp.RPCMsg, error) {
	if p.upHTTP != nil {
		return p.upHTTP.readCtx(ctx)
	}
	return p.upReader.Read()
}
