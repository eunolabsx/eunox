// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Remote HTTP upstream for the stdio host (transport: stdio with an upstream whose own
// transport is http).
//
// httpUpstream bridges the StdioProxy's message-level upstream I/O (a Write of an rpcMsg
// and a Read of the next) onto a remote MCP HTTP server: a Write POSTs the message and,
// for a request, queues the response for a later Read. This lets the StdioProxy's async
// machinery (the handshakes, callUpstream's pending map, the readUpstream loop) drive a
// remote HTTP upstream unchanged.
//
// KNOWN LIMITATION: like the HTTP gateway's remote-upstream path, this bridge is strictly
// request/response — one POST per host request, reading only that POST's own response
// body. No persistent inbound stream (no SSE GET) is opened, so a server-initiated request
// (sampling/createMessage, roots/list, elicitation/create) is never seen, enforced,
// audited, or forwarded. A system:sampling/createMessage opt-in for an HTTP upstream is
// therefore rejected at startup (route.go) rather than loaded as a silently inert grant.
// Reach the upstream over stdio if server-initiated requests must be enforced.

package transport

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// initializedNotifyTimeout bounds the synchronous notifications/initialized POST
// sent during the handshake (writeSync). It must complete before the proxy
// starts forwarding host requests, so it is bounded independently of any
// per-call timeout.
const initializedNotifyTimeout = 10 * time.Second

// maxInflightPosts caps concurrent POST goroutines. Write and postWithCtx are
// fire-and-forget, so without a bound a pipelining host could spawn unbounded
// in-flight POSTs. The cap turns that into backpressure: the next spawn blocks
// until a slot frees (or the bridge closes). 64 matches the incoming-response
// buffer so the two limits do not fight.
const maxInflightPosts = 64

// httpUpstream is a request/response bridge to a remote MCP HTTP server that
// satisfies the StdioProxy's upstream sink (Write) and source (Read).
type httpUpstream struct {
	endpoint   string // full MCP endpoint URL (base + /mcp)
	authHeader string // "Name: Value" header injected on every request, or ""
	client     *http.Client

	// ctx bounds every POST and is canceled by close(), so a shutdown promptly
	// aborts in-flight requests to an unresponsive upstream.
	ctx    context.Context
	cancel context.CancelFunc

	// incoming carries responses (and synthesized upstream-error responses) from
	// in-flight POSTs back to Read, which the proxy's readUpstream loop drains.
	incoming chan mcp.RPCMsg

	// sem bounds concurrent post() goroutines to maxInflightPosts: a token is
	// acquired before each spawn and released when it returns.
	sem chan struct{}

	// reportErr, when set, delivers a request POST's TRANSPORT failure directly to the
	// waiting caller keyed by the upstream nonce (msg.ID) and reports whether one was
	// found, so callUpstream returns an error and the decision is recorded as a
	// deny/UPSTREAM_ERROR (matching the gateway) rather than an allow. Wired to
	// reportUpstreamErr, which delivers only while the caller is still in flight; a nil
	// reportErr, a false return (handshake/probe POST, or one already abandoned), or a
	// POST with no id leaves the in-band synthesized-error fallback unchanged.
	reportErr func(upKey string, err error) bool

	mu     sync.Mutex
	sessID string // upstream Mcp-Session-Id, captured from the initialize response
	// rev is the protocol revision this leg speaks — decided from the operator's pin before the
	// leg is opened, not captured from a reply. Guarded by mu because it is written once at
	// construction and read by every later POST, including the opener's own. See setRevision.
	rev capability.Revision

	// notices is this bridge's diagnostic CHANNEL: where its lines go AND what bounds them, as one
	// value. It needs a bound because a notification-POST failure is written once per notification
	// a host sends against an unreachable upstream. The zero value (every test call site) writes
	// every line, to os.Stderr — the same fallback errOutOrStderr has always applied.
	notices noticeWriter

	closeOnce sync.Once
	done      chan struct{}
}

// newHTTPUpstream builds a bridge to baseURL (the upstream MCP server). authHeader
// is an optional "Name: Value" line injected on every request; tlsSkipVerify
// disables TLS verification (dev only); upstreamTimeoutMs bounds the transport's
// response-header wait (0 = disabled). The bridge POSTs under a context derived
// from parent that close() cancels.
//
// The bridge's diagnostic CHANNEL is NOT a parameter: it is set by the caller as one whole
// noticeWriter afterwards (see StdioProxy.connectUpstream). A writer parameter here built half of
// one — destination set, bucket nil, i.e. unbounded — which production only survived because the
// single call site overwrote the whole field on the next line. Half a channel is exactly what
// noticeWriter exists to make unrepresentable; leaving the zero value writes to os.Stderr
// unbounded, which is the disposition every test call site already had.
func newHTTPUpstream(parent context.Context, baseURL, authHeader string, tlsSkipVerify bool, upstreamTimeoutMs int) *httpUpstream {
	ctx, cancel := context.WithCancel(parent)
	h := &httpUpstream{
		endpoint:   UpstreamMCPEndpoint(baseURL),
		authHeader: authHeader,
		client:     BuildUpstreamClient(tlsSkipVerify, upstreamTimeoutMs),
		ctx:        ctx,
		cancel:     cancel,
		incoming:   make(chan mcp.RPCMsg, 64),
		sem:        make(chan struct{}, maxInflightPosts),
		done:       make(chan struct{}),
	}
	return h
}

// notifyPostTimeout bounds a fire-and-forget POST (the Write path) so a stalling
// upstream cannot pin a maxInflightPosts slot indefinitely and wedge the read loop
// on a full semaphore. Deliberately INDEPENDENT of --upstream-timeout: even when
// that's disabled, a notification must still release its slot.
const notifyPostTimeout = 30 * time.Second

// spawnPost runs h.post under the in-flight semaphore (maxInflightPosts). When the cap is
// reached the caller blocks until a slot frees (backpressure) or the bridge closes, at
// which point the message is dropped, matching the fire-and-forget contract. The slot is
// released when post() returns, on an independent goroutine that completes as readUpstream
// drains `incoming`, so a blocked spawn never deadlocks against its own release.
//
// bound, when > 0, caps the POST's own duration. The Write path passes notifyPostTimeout
// so a slot always frees even with the per-call timeout disabled; postWithCtx passes 0
// because its ctx already carries the per-call deadline.
func (h *httpUpstream) spawnPost(ctx context.Context, msg mcp.RPCMsg, bound time.Duration) {
	select {
	case h.sem <- struct{}{}:
	case <-ctx.Done():
		return
	case <-h.done:
		return
	}
	go func() {
		defer func() { <-h.sem }()
		pctx := ctx
		if bound > 0 {
			var cancel context.CancelFunc
			pctx, cancel = context.WithTimeout(ctx, bound)
			defer cancel()
		}
		h.post(pctx, msg)
	}()
}

// Write POSTs msg to the upstream using the bridge-lifetime context. Used for
// fire-and-forget paths (init handshake, forwarded host notifications, sampling
// denial responses) where no per-call timeout applies. Satisfies msgSink.
//
// Write can block on the maxInflightPosts semaphore; serveHost (stdio.go) forwards host
// notifications through it on its read-loop goroutine, which can block here under load.
// Deadlock-free only because this bridge never delivers server-initiated requests (KNOWN
// LIMITATION above): incoming carries responses only, so the read loop has no
// upstream-request reply to route and cannot wedge against a blocked Write. Opening an
// upstream SSE stream here would reintroduce that reply path and must revisit this coupling.
func (h *httpUpstream) Write(msg mcp.RPCMsg) error {
	h.spawnPost(h.ctx, msg, notifyPostTimeout)
	return nil
}

// writeSync POSTs msg synchronously and returns the upstream error, unlike the
// fire-and-forget Write. The handshake's notifications/initialized must reach the
// upstream before the proxy forwards host requests, or strict upstreams reject the
// first request that races ahead of it. Captures the upstream session ID from the
// response header if one is returned, mirroring post().
func (h *httpUpstream) writeSync(ctx context.Context, msg mcp.RPCMsg) error {
	ctx, cancel := context.WithTimeout(ctx, initializedNotifyTimeout)
	defer cancel()
	_, hdr, err := h.do(ctx, msg)
	h.captureUpstreamSessID(hdr)
	return err
}

// captureUpstreamSessID records the upstream Mcp-Session-Id from the first response
// header that carries one (the initialize response); a later header is ignored so a
// mid-session id never overwrites the established one. Goroutine-safe; a nil or
// header without the session field is a no-op. Shared by writeSync and post.
func (h *httpUpstream) captureUpstreamSessID(hdr http.Header) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Under the lock: the leg's revision is what decides whether there is a session to hold at
	// all (UpstreamSessionID), and reading it outside would race setRevision.
	sid := UpstreamSessionID(h.rev, hdr)
	if sid == "" {
		return
	}
	if h.sessID == "" {
		h.sessID = sid
	}
}

// postWithCtx POSTs msg using a caller-supplied context so per-call timeouts
// cancel the HTTP request. Used by callUpstream, which holds the per-call deadline
// ctx. Like Write it can block on the maxInflightPosts semaphore; callUpstream
// waits under the same ctx (awaitNonced selects on ctx.Done()), so a slot that
// never frees surfaces as the per-call timeout rather than a hang.
func (h *httpUpstream) postWithCtx(ctx context.Context, msg mcp.RPCMsg) {
	// bound=0: ctx already carries the per-call --upstream-timeout deadline.
	h.spawnPost(ctx, msg, 0)
}

// post performs one POST and, for a request, queues the response for Read.
func (h *httpUpstream) post(ctx context.Context, msg mcp.RPCMsg) {
	resp, hdr, err := h.do(ctx, msg)
	h.captureUpstreamSessID(hdr)
	if msg.ID == nil {
		// Notification: no response to deliver. Log POST failures so dropped
		// notifications/initialized and notifications/cancelled are not silent.
		// Pre-gated for the reason its HTTP-transport twin is: a down upstream fails every POST,
		// so the arguments are built per frame for a line the bucket discards (see admitNotice) —
		// and this transport has no route tier, so the bucket is the whole budget.
		if err != nil {
			if line, ok := h.notices.admitNotice(siteUpstreamPostFailed); ok {
				line.writef("[eunox] upstream notification %q POST failed: %v\n",
					audit.BoundEnvelopeField(msg.Method), err)
			}
		}
		return
	}
	switch {
	case err != nil:
		// Surface the TRANSPORT failure to the waiting caller as an ERROR, delivered
		// directly through the shared byUpstreamID routing channel, so
		// enforcedForwardCore/dispatch record a deny/UPSTREAM_ERROR matching the
		// gateway's callRemoteUpstream path rather than an allow with an
		// upstream_error_code. Once delivered the routing channel IS the delivery, so
		// return without touching incoming.
		//
		// reportErr reports false when there's no live caller to deliver to (a
		// handshake/probe POST, or one already abandoned), in which case fall through
		// to the synthesized in-band response below. That response is still classified
		// through upstreamErrInfo so the host sees only the failure CLASS: raw
		// err.Error() must never be forwarded, since for a remote HTTP upstream it can
		// carry the endpoint URL and upstream body text. bound=0: the POST already
		// carried the per-call deadline, so a deadline expiry is attributed to the
		// request deadline.
		if h.reportErr != nil && h.reportErr(mcp.MsgKey(msg.ID), err) {
			return
		}
		_, reason, rpcCode := upstreamErrInfo(h.notices, err, 0)
		resp = mcp.ErrorResponse(msg.ID, rpcCode, reason)
	case resp.JSONRPC == "" && resp.Result == nil && resp.Error == nil:
		// Deliberately LOOSER than mcp.RPCMsg.IsZero, which also requires id/method/params empty:
		// a 200 OK body of `{"id":1}` carries nothing to deliver and must be caught here, while
		// IsZero answers "this message was never built" for a proxy layer deciding whether to send.
		// Two questions, two predicates.
		//
		// An empty/zero RPCMsg here is a 200 OK whose body is {}, null, or any JSON
		// object lacking jsonrpc/result/error: DoMCPHTTP's plain-JSON path decodes such
		// a body to a zero-value RPCMsg with a nil error. (A real 202 Accepted to a
		// request becomes a non-nil error, taken by the err != nil arm above.) Surface
		// what was actually observed instead of forwarding an empty result to the host.
		resp = mcp.ErrorResponse(msg.ID, jsonRPCCodeInternalError, "upstream returned an empty or non-JSON-RPC response for request "+msg.Method+" (expected a JSON-RPC result or error)")
	default:
		// Correlate by shape via the shared rule. A non-response reply — e.g. one
		// carrying a `method` field — must NEVER enter `incoming`: readUpstream would
		// reclassify it as a server-initiated request and route it to the host, but
		// this bridge is documented to deliver responses only (the Write-path
		// deadlock-freedom argument depends on it). A malicious upstream knows the
		// nonce id, so id-equality alone is insufficient; a mismatched id is refused
		// (fail closed) whether it rides a result or an error — re-stamping a
		// mismatched error would let an adversarial upstream inject one caller's error
		// into another's reply.
		if correlated, cerr := correlateUpstreamReply(msg, resp); cerr != nil {
			resp = mcp.ErrorResponse(msg.ID, jsonRPCCodeInternalError, cerr.Error())
		} else {
			resp = correlated
		}
	}
	select {
	case h.incoming <- resp:
	case <-h.done:
	}
}

// do POSTs msg to the upstream MCP endpoint under ctx and returns the decoded
// response and headers. Delegates to DoMCPHTTP, the shared implementation.
func (h *httpUpstream) do(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, http.Header, error) {
	h.mu.Lock()
	sid, rev := h.sessID, h.rev
	h.mu.Unlock()
	return DoMCPHTTP(ctx, h.client, h.endpoint, msg, sid, h.authHeader, rev)
}

// setRevision pins the protocol revision this leg speaks. Called from connectUpstream, BEFORE
// the opener runs — the opener of a declaring revision is an ordinary request and carries the
// MCP-Protocol-Version header like any other, so a bridge still holding the empty revision
// would open the leg naming a version this proxy is not speaking. Do not move it after the
// open.
func (h *httpUpstream) setRevision(rev capability.Revision) {
	h.mu.Lock()
	h.rev = rev
	h.mu.Unlock()
}

// Read returns the next queued upstream message, blocking until one arrives or
// the upstream is closed (returning io.EOF). Satisfies the proxy's upstream
// message source.
func (h *httpUpstream) Read() (mcp.RPCMsg, error) {
	select {
	case msg := <-h.incoming:
		return msg, nil
	case <-h.done:
		return mcp.RPCMsg{}, io.EOF
	}
}

// readCtx is Read with caller cancellation: it also returns when ctx is canceled
// (surfacing ctx.Err()). The plain Read selects only on incoming/done, and done is closed
// only by close(), which a startup probe stuck before the background reader runs never
// reaches — so a probe whose context is canceled or exceeds its deadline would otherwise
// block forever. Used by the stdio bridge's tools/list drift probe.
func (h *httpUpstream) readCtx(ctx context.Context) (mcp.RPCMsg, error) {
	select {
	case msg := <-h.incoming:
		return msg, nil
	case <-h.done:
		return mcp.RPCMsg{}, io.EOF
	case <-ctx.Done():
		return mcp.RPCMsg{}, ctx.Err()
	}
}

// close terminates the upstream MCP session, stops Read, and cancels any
// in-flight POSTs. Idempotent.
func (h *httpUpstream) close() {
	h.closeOnce.Do(func() {
		// Terminate the upstream session with a bounded DELETE before canceling the
		// bridge context, so the remote frees its session state rather than leaking it
		// until its own (often absent) expiry. DeleteMCPHTTPSession uses its own
		// background context, so h.cancel() below does not abort it.
		h.mu.Lock()
		sid, rev := h.sessID, h.rev
		h.mu.Unlock()
		DeleteMCPHTTPSession(h.client, h.endpoint, sid, h.authHeader, rev, h.notices.errOut())
		close(h.done)
		h.cancel()
	})
}

// splitHeaderLine parses a "Name: Value" header line, returning the trimmed name
// and value. ok is false when the line is empty or has no colon separator.
func splitHeaderLine(line string) (name, value string, ok bool) {
	if line == "" {
		return "", "", false
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}
