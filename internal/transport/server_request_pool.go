// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// maxConcurrentServerRequests bounds the in-flight handler goroutines an upstream reader
// spawns for SERVER-initiated requests (sampling/createMessage, roots/list, elicitation).
// The upstream-facing twin of maxConcurrentHostRequests / maxConcurrentSessionRequests:
// those handlers no longer run inline on the read loop, so without a cap an upstream
// emitting requests faster than the host answers them grows goroutines unbounded.
//
// Far smaller than either host cap, since a server-initiated request needs a HUMAN-facing
// round trip (an LLM completion, a roots prompt) — double-digit concurrency is already
// well past anything an honest upstream produces. On saturation the request is refused
// with a structured, retryable error and the refusal is recorded.
//
// The bound is per POOL, scoped to each transport's own upstream connection: proxy-wide
// for stdio (one upstream), per session for HTTP (one upstream subprocess each), so one
// session's flood cannot consume another's slots.
const maxConcurrentServerRequests = 32

// serverRequestPool is the admission control and off-reader dispatch for one upstream
// connection's SERVER-initiated request handlers. Both transports own one.
//
// The handler must not run inline on the read loop — that used to be a cycle, not a slow
// path: the reader is the only goroutine delivering upstream responses; a declassifying
// host call holds the decision turn across its whole upstream round trip; and the sampling
// leg used to take that turn BEFORE DecideSampling ran. A sampling/createMessage arriving
// mid-clear parked the reader on a turn whose holder was waiting for a response only that
// reader could deliver. Off the read loop, a blocked handler blocks only itself.
//
// ORDERING, stated rather than left to be inferred: server-initiated requests used to
// arrive in receipt order purely because they ran inline, and no longer do — two requests
// the upstream emits back to back may now reach the host in either order. Nothing depends
// on that order (JSON-RPC correlates by id; MCP defines no ordering between independent
// server-initiated requests), but a future request kind that DID need ordering would have
// to establish it here. Host-initiated traffic keeps every ordering guarantee it had.
//
// One pool rather than a copy per transport, since the parts that must not diverge — the
// refusal being both answered AND recorded, the in-flight count taken before the goroutine
// starts, teardown having something to wait on — are exactly what a copy gets wrong. Zero
// value usable; the semaphore is sized on first dispatch so a struct-literal session (as
// tests build) is bounded too.
type serverRequestPool struct {
	semOnce sync.Once
	sem     chan struct{}

	// saturation gates the RESOURCE_EXHAUSTED record this pool writes on refusal,
	// collapsing an episode into one record carrying the elided count. Its own gate, not
	// shared with the host-facing pools: an upstream flood must not elide a host pool's
	// saturation record or the reverse.
	saturation saturationGate

	// inFlight counts dispatched handlers that have not returned, so teardown can wait
	// for them (drain). They run off the read loop, so draining the reader no longer
	// implies they're done — one still running would otherwise have its audit record
	// dropped by an already-closed sink, or have its flow-state read raced by
	// ReleaseSession.
	inFlight atomic.Int64
}

// serverRequestDispatch is what a transport supplies for one dispatch: where a refusal is
// written, who records it, and the handler itself. Named fields rather than positional
// parameters, for the reason the audit RecordParams struct has them: a transposition of
// two same-typed arguments is otherwise silent.
type serverRequestDispatch struct {
	// rec receives the saturation refusal record; nil (no sink configured) skips it.
	rec auditRecorder
	// sessionID identifies the session on that record.
	sessionID string
	// unblocker answers the upstream initiator, on the CALLER's goroutine (the reader) for a
	// refusal, since no handler is spawned — and RECORDS an answer that did not land. ONE field
	// rather than the writer, the limits and the leg threaded separately: those three are one
	// obligation, and a sixth thing this leg needs is then declared once instead of at both
	// transports' literals, where a keyed literal zero-fills whichever is missed.
	unblocker serverRequestUnblocker
	// errOut is where the seam writes that report; nil means os.Stderr.
	errOut io.Writer
	// handle is the server-initiated request's handler, run on its own goroutine.
	handle func(context.Context, mcp.RPCMsg)
	// revision is the session's negotiated host revision, stamped onto ctx BEFORE the admission
	// gate. The handler's own leg stamps it too, but the saturation refusal returns above that,
	// so without this an established session's refusals recorded no revision at all — which on
	// this tape means "written before one could be resolved".
	revision capability.Revision
}

// dispatchServerRequest is the ENTRY both transports take for one server-initiated request: refuse
// an id no reply could ever be routed back to, then hand the request to the pool.
//
// One function rather than the same three-step sequence hand-mirrored per transport, in the mould
// hostNotificationGate.admit set for the four checks each used to hand-place: the pair took the same
// edit twice the last two times this leg changed, and the per-transport delta is now the dispatch
// struct alone.
func dispatchServerRequest(ctx context.Context, pool *serverRequestPool, msg mcp.RPCMsg, d serverRequestDispatch) {
	// Refused at the ENTRY, above the pool and above any decision: a request whose reply could
	// never be routed back must not consume a handler slot, a policy quota, or the host's
	// attention. See admitServerRequestID.
	if !admitServerRequestID(ctx, d.unblocker, msg) {
		return
	}
	pool.dispatch(ctx, msg, d)
}

// dispatch runs d.handle for msg on its own goroutine, or refuses msg when the pool is at
// maxConcurrentServerRequests.
//
// On saturation the request is refused to the upstream with a retryable server-busy error
// and the refusal is RECORDED, mirroring the host-side caps — an upstream that floods this
// leg leaves a trace on the tamper-evident tape rather than only a stream of error replies.
func (p *serverRequestPool) dispatch(ctx context.Context, msg mcp.RPCMsg, d serverRequestDispatch) {
	p.semOnce.Do(func() { p.sem = make(chan struct{}, maxConcurrentServerRequests) })
	ctx = capability.WithProtocolRevision(ctx, resolveRevision(d.revision))
	select {
	case p.sem <- struct{}{}:
		// A free slot means any saturation episode is over: re-arm the gate so the next
		// refusal is recorded as a new episode rather than folded into the last one.
		p.saturation.clear()
	default:
		recordResourceExhausted(ctx, d.rec, &p.saturation, d.sessionID, msg.Method)
		// Record-before-act, so the answer below is the one that may be lost rather than the
		// record. Through the shared seam because it runs AFTER that record: a nil concrete writer
		// would panic here and leave a tape reporting a refusal the process died delivering — and
		// an answer that is merely DESTROYED leaves the initiator blocked with the saturation
		// record describing the refusal but not the delivery, which is why the seam appends its own.
		d.unblocker.answer(ctx, mcp.ErrorResponse(msg.ID, jsonRPCCodeServerBusy,
			"eunox: too many concurrent server-initiated requests in flight; retry"), answerPoolSaturated, msg.Method)
		return
	}
	// Counted before the goroutine starts, so teardown's drain cannot observe zero for a
	// request that has been admitted but not yet begun.
	p.inFlight.Add(1)
	go func() {
		defer p.inFlight.Add(-1)
		defer func() { <-p.sem }()
		d.handle(ctx, msg)
	}()
}

// drain blocks until every dispatched handler has returned, or until timeout elapses. Both
// transports call it from teardown before releasing per-session enforcement state: draining
// the reader no longer implies these handlers are finished, and one still running past that
// point would write its audit record into a closed sink (dropped) or read flow state
// ReleaseSession has just cleared.
//
// Unlike the host-decision drains it is NOT gated on the policy using flow control: a
// server-initiated handler writes an audit record on every path, serialized or not.
func (p *serverRequestPool) drain(timeout time.Duration) { awaitDrained(&p.inFlight, timeout) }
