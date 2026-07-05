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

// fetchUpstreamToolsRaw sends a tools/list probe over the HTTP session's
// callUpstream and returns the raw JSON result. As session-start work it is marked
// withoutUpstreamTimeout: bounded by sessionStartTimeout, not --upstream-timeout.
// Binding it to the per-request knob would let a tight --upstream-timeout fail
// session establishment when the manifest pins descriptionHash (fetch failure is
// fatal then), even though the upstream answers within the session-start budget.
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

// fetchUpstreamToolsRaw sends tools/list to the configured upstream before the
// background readUpstream goroutine starts, dispatching on the upstream transport:
// a subprocess stdin/stdout pipe, or — when p.upHTTP is set — the remote HTTP
// bridge. It returns the raw JSON result.
//
// As session-start work the bridge bounds it by the session-start budget, NOT
// --upstream-timeout (mirroring the httpSession probe's initCtx): a tight
// --upstream-timeout would otherwise fail startup when the manifest pins
// descriptionHash (fetch failure is fatal then) even though the upstream answers in
// time. It is bounded by --upstream-timeout in NEITHER direction: a generous
// --upstream-timeout does not widen it either, so the same upstream/manifest/flags
// establishes a session identically behind a stdio host and an HTTP host.
//
// On the remote-HTTP bridge that budget bounds the ENTIRE multi-page probe once,
// not each page: a fresh per-page deadline would let a slow upstream answering each
// of up to maxToolsListPages pages just under the budget stretch startup to
// pages*budget. The single deadline also makes the bridge read honor cancellation
// (readCtx), so a parent-context cancel during startup — or an expired deadline —
// returns an error instead of blocking forever (spawnPost can drop a POST on an
// already-canceled ctx, leaving nothing in-flight for the plain Read to receive).
//
// It discards any number of notifications arriving before the response.
// Termination is guaranteed on the subprocess path by the pipe closing on process
// exit (EOF → Read error) bounded by runBoundedStartup's watchdog, and on the HTTP
// bridge by the probe-wide deadline plus readCtx honoring it.
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
		for {
			msg, err := p.readProbeReply(probeCtx)
			if err != nil {
				return nil, fmt.Errorf("tools/list read: %w", err)
			}
			if msg.IsResponse() && mcp.MsgKey(msg.ID) == mcp.MsgKey(mcp.RawJSON(`"_drift"`)) {
				if msg.Error != nil {
					return nil, fmt.Errorf("tools/list: upstream error %d: %s", msg.Error.Code, msg.Error.Message)
				}
				return msg.Result, nil
			}
			// Discard notifications arriving before the response. A discarded
			// server-initiated REQUEST (sampling/createMessage, roots/list,
			// elicitation/create), however, would leave the upstream blocked awaiting a
			// response: this probe runs inline before readUpstream starts, so nothing
			// else will answer it.
			RejectPreInitServerRequest(p.upWriter, msg)
		}
	})
}

// readProbeReply reads the next upstream message during startup — the initialize
// handshake (initUpstream) and the tools/list drift probe. On the remote-HTTP bridge it
// honors ctx (readCtx) so a canceled or timed-out startup returns promptly rather than
// blocking until session teardown — the plain Read is not context-aware and done is
// closed only by close(), which the stuck startup never reaches. The subprocess path
// keeps the plain Read, whose overall bound is runBoundedStartup's child-kill watchdog
// (pipe EOF unblocks it).
func (p *StdioProxy) readProbeReply(ctx context.Context) (mcp.RPCMsg, error) {
	if p.upHTTP != nil {
		return p.upHTTP.readCtx(ctx)
	}
	return p.upReader.Read()
}
