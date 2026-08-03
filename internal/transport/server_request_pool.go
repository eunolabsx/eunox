// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
)

// maxConcurrentServerRequests bounds the in-flight handler goroutines an upstream reader
// spawns for SERVER-initiated requests (sampling/createMessage, roots/list, elicitation). It
// is the upstream-facing twin of maxConcurrentHostRequests / maxConcurrentSessionRequests and
// exists for the same hazard from the other direction: those handlers no longer run inline on
// the read loop, so without a cap an upstream that emits requests faster than the host answers
// them grows goroutines without bound — which is exactly the pressure moving them off the
// reader relieved the reader of.
//
// It is far smaller than either host cap, because the traffic is: a server-initiated request
// needs a HUMAN-facing round trip on the host side (an LLM completion, a roots prompt), so
// double-digit concurrency is already well past anything an honest upstream produces, while a
// host cap has to absorb an agent pipelining tool calls. On saturation the request is refused
// to the upstream with a structured, retryable error and the refusal is recorded.
//
// The bound is per POOL, and each transport scopes its pool to its own upstream connection:
// proxy-wide for stdio (one upstream), per session for HTTP (one upstream subprocess each), so
// one session's flood cannot consume another's slots.
const maxConcurrentServerRequests = 32

// serverRequestPool is the admission control and off-reader dispatch for one upstream
// connection's SERVER-initiated request handlers. Both transports own one.
//
// The handler must not run inline on the read loop, and the reason is a cycle rather than a
// slow path. The reader is the only goroutine that delivers upstream responses to waiting host
// handlers; a declassifying host call holds the decision turn across its whole upstream round
// trip; and the sampling leg takes that turn BEFORE DecideSampling runs. A
// sampling/createMessage arriving mid-clear therefore parked the reader on a turn whose holder
// was waiting for a response only that reader could deliver. Bounding the wait
// (samplingTurnWait) turned the deadlock into a stall, but nothing bounded how OFTEN: an
// upstream emitting one such request per in-flight clear costs that reader's whole response
// delivery the bound each time, and sampling need not even be permitted, since the turn is
// taken before the decision that would refuse it. Off the read loop, a blocked handler blocks
// itself and nothing else, and the bound stays as the backstop.
//
// ORDERING, stated rather than left to be inferred: server-initiated requests were handled in
// receipt order purely because they ran inline, and they no longer are. Two requests the
// upstream emits back to back may reach the host in either order, and one may now be overtaken
// by a notification received after it. Nothing depends on that order — JSON-RPC correlates a
// response to its request by id, and MCP defines no ordering between independent
// server-initiated requests — but a future request kind that DID need ordering would have to
// establish it here rather than inherit it from where this happens to run. Host-initiated
// traffic keeps every ordering guarantee it had; nothing on this path touches it.
//
// One pool rather than a copy per transport: the two differ only in what they hand `dispatch`,
// and the parts that must not diverge are the parts a copy gets wrong — the refusal being both
// answered AND recorded, the in-flight count being taken before the goroutine starts, and
// teardown having something to wait on. The zero value is usable; the semaphore is sized on
// first dispatch so a pool inside a struct-literal session (as tests build) is bounded too.
type serverRequestPool struct {
	semOnce sync.Once
	sem     chan struct{}

	// saturation gates the RESOURCE_EXHAUSTED record this pool writes when it refuses,
	// collapsing an episode of saturation into a single record carrying the count of refusals
	// elided since (see saturationGate). Its own gate, not shared with the host-facing pools:
	// an upstream flood must not elide a host pool's saturation record or the reverse.
	saturation saturationGate

	// inFlight counts dispatched handlers that have not returned, so teardown can wait for
	// them (drain). They run off the read loop, so draining the reader no longer implies they
	// are done — and one still running would otherwise have its audit record dropped by an
	// already-closed sink, or have its flow-state read raced by ReleaseSession.
	inFlight atomic.Int64
}

// serverRequestDispatch is what a transport supplies for one dispatch: where a refusal is
// written, who records it, and the handler itself. Named fields rather than positional
// parameters, for the reason the audit RecordParams struct has them: a transposition of two
// same-typed arguments is otherwise silent.
type serverRequestDispatch struct {
	// rec receives the saturation refusal record; nil (no sink configured) skips it.
	rec auditRecorder
	// sessionID identifies the session on that record.
	sessionID string
	// writeUpstream answers the upstream initiator. Called on the CALLER's goroutine (the
	// reader) for a refusal, since no handler is spawned.
	writeUpstream func(mcp.RPCMsg)
	// handle is the server-initiated request's handler, run on its own goroutine.
	handle func(context.Context, mcp.RPCMsg)
}

// dispatch runs d.handle for msg on its own goroutine, or refuses msg when the pool is at
// maxConcurrentServerRequests.
//
// On saturation the request is refused to the upstream with a retryable server-busy error and
// the refusal is RECORDED, mirroring the host-side caps through the same helper — an upstream
// that floods this leg leaves a trace on the tamper-evident tape rather than only a stream of
// error replies.
func (p *serverRequestPool) dispatch(ctx context.Context, msg mcp.RPCMsg, d serverRequestDispatch) {
	p.semOnce.Do(func() { p.sem = make(chan struct{}, maxConcurrentServerRequests) })
	select {
	case p.sem <- struct{}{}:
		// A free slot means any saturation episode is over: re-arm the gate so the next
		// refusal is recorded as a new episode rather than folded into the last one.
		p.saturation.clear()
	default:
		recordResourceExhausted(ctx, d.rec, &p.saturation, d.sessionID, msg.Method)
		d.writeUpstream(mcp.ErrorResponse(msg.ID, jsonRPCCodeServerBusy,
			"eunox: too many concurrent server-initiated requests in flight; retry"))
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
// transports call it from teardown before releasing per-session enforcement state, because
// draining the reader no longer implies these handlers are finished: one still running past
// that point would write its audit record into a closed sink (dropped, not recorded) or read
// flow state ReleaseSession has just cleared.
//
// Unlike the host-decision drains it is NOT gated on the policy using flow control: a
// server-initiated handler writes an audit record on every path, serialized or not, so the
// record is what is being protected here rather than the flow state alone.
func (p *serverRequestPool) drain(timeout time.Duration) { awaitDrained(&p.inFlight, timeout) }
