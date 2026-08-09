// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The server-initiated leg's one rule for a request this proxy can no longer deliver, and for a
// host reply it can no longer route.
//
// Such a request blocks its upstream until something answers it — on HTTP until the hard idle
// ceiling reclaims the session, on stdio until the host disconnects, since that transport has no
// reaper at all. eunox ANSWERS the initiator with an error of its own wherever it can do so
// without acting on a second identity's behalf: the answer carries a fixed string and an id this
// proxy itself issued, so nothing the host said is relayed and no refusal is undone.
//
// The two deliberate exceptions, each stated where it is taken rather than here:
//
//   - A REVOCATION drop is an emergency stop, not an error to report. The session is being torn
//     down around it and its blocked request is left to be reclaimed with the rest (see
//     routeHostServerResponse and stdio's IsResponse arm).
//   - A reply refused because of WHO SENT IT leaves the real owner's reply still possible, and
//     answering the initiator completes its request either way — so answering on an unauthorized
//     sender's message would hand any second identity that learned a session id a way to abort the
//     owner's pending reply (see httpSession.unblockGateRefusedServerReply).
//
// Every other site answers, through the one seam below: a protocol refusal, a request no
// subscriber could receive, a delivery that failed after buffering, and a request the bounded
// tracker had to evict. Before this existed the sequence was written out at four sites with three
// different dispositions for the same nil-writer condition, so "reported rather than dropped" was
// the rule on one transport and not the other for an identical case.
//
// Answering is only half of it: a request this proxy accepted and then FAILED also owes the tape a
// record, since a stderr line is not something a SIEM sees. recordServerRequestDropped is that
// record, shared by every disposition here that produces one.

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// serverRequestUnblocker is the per-transport wiring every site that answers a blocked
// server-initiated initiator needs.
//
// writeUpstream is a func rather than an mcp.MsgSink because the two transports' upstream sinks
// differ in type, and a nil CONCRETE writer handed to a shared interface parameter is a non-nil
// interface that panics on use rather than the "no upstream to answer" case each caller tests
// for. Both transports already build this shape for serverRequestDispatch, so the seam is one
// they have rather than one this adds; nil means there is genuinely nothing to answer through.
type serverRequestUnblocker struct {
	reqs          *serverReqTracker
	writeUpstream func(mcp.RPCMsg)
	errOut        io.Writer
}

// unblock consumes id from the tracker and answers its blocked initiator with eunox's own error
// carrying reason, so the upstream is not left waiting on a request nothing will ever complete.
// It reports whether the id was one this proxy still held — which is also the question a caller's
// own tail turns on, since only a request that was actually consumed here was failed here.
//
// The id is consumed even when there is no upstream sink to answer through. That case is
// unreachable today (see writeToInitiator) and the alternative is worse: leaving the entry means it
// can never be reclaimed — no host reply to a request that was never delivered will ever arrive —
// so it occupies one of the bounded set's slots for the session's life and eventually displaces a
// LIVE request, which is now an outcome that actively answers an initiator rather than a silent one.
func (u serverRequestUnblocker) unblock(id *json.RawMessage, reason string) bool {
	if id == nil || !u.reqs.take(mcp.MsgKey(id)) {
		return false
	}
	u.write(mcp.ErrorResponse(id, capability.JSONRPCCodeEnforcementError, reason), reason)
	return true
}

// relay writes the host's OWN reply to the blocked initiator, reporting whether it reached the
// upstream. It consumes nothing: a caller that routes a genuine reply has already taken the id it
// matched, and the take is what decided the reply was routable at all.
//
// A false is the one drop on this leg that destroys a reply the host actually PRODUCED — the take
// above it is what makes that reply unroutable by any later path — so the caller owes the tape a
// record (recordServerRequestDropped, tagged dropHTTPReplyUndeliverable / dropStdioReplyUndeliverable).
// Every sibling disposition here appends one; this was the only one whose entire account was a
// stderr line, which no SIEM sees.
func (u serverRequestUnblocker) relay(reply mcp.RPCMsg) bool {
	// The reply WAS routable — the caller's take proved it — so what failed is the sink, not the
	// routing. Naming remote-upstream mode is the one operational fact that sends an operator to
	// the configuration rather than to the host's id matching.
	return u.write(reply, "no upstream writer in remote-upstream mode")
}

// write applies the shared nil-writer disposition to reply.
//
// It consumes nothing. Whether the tracked id should be taken is each caller's own question and
// the three answers genuinely differ — unblock takes it, relay's caller already did, and an
// eviction removed it as the very act that created the debt.
func (u serverRequestUnblocker) write(reply mcp.RPCMsg, what string) bool {
	return writeToInitiator(u.writeUpstream, u.errOut, reply, what)
}

// writeToInitiator is the ONE nil-writer disposition every site that answers a blocked
// server-initiated initiator shares: send reply through write, or report that there was no upstream
// sink to send it through. what names the situation for that report; it reports whether the reply
// was delivered.
//
// A package function rather than a method on the unblocker because THREE shapes carry this wiring —
// the unblocker, the sampling leg's serverRequestParams, and the pool's serverRequestDispatch — and
// only the first went through the seam. The other two called a concrete writer straight from a
// closure, which does not merely skip the report: (*mcp.MsgWriter).Write takes its mutex on a nil
// receiver, so those sites PANIC where this reports, and on the denial arms the panic lands AFTER
// the audit record — leaving a tape recording a denial the process died delivering.
//
// The writerless case is unreachable today on every caller: remote-upstream mode is the only shape
// without a sink and those sessions issue no server-initiated requests, so no id could have been
// tracked, and stdio's writer is nil only before connectUpstream runs. Reported rather than dropped
// because the alternative is an upstream wedged with nothing on stderr or the tape saying why.
func writeToInitiator(write func(mcp.RPCMsg), errOut io.Writer, reply mcp.RPCMsg, what string) bool {
	if write == nil {
		_, _ = fmt.Fprintf(resolvedErrOut(errOut),
			"[eunox] WARNING: a server-initiated request was left blocked: no upstream writer to answer it (%s)\n", what)
		return false
	}
	write(reply)
	return true
}

// How the sites that answer a blocked initiator with an error of eunox's own name their situation
// for writeToInitiator's report. Constants rather than literals at each site, so the report reads
// the same whichever leg produced it.
const (
	answerRevokedServerRequest = "denying a revoked session's server-initiated request"
	answerStrictAuditRefusal   = "refusing a server-initiated request: the audit trail has degraded under --require-audit=strict"
	answerPolicyRefusal        = "denying a server-initiated request the policy refused"
	answerPoolSaturated        = "refusing a server-initiated request: the in-flight pool is saturated"
)

// The server-request drop legs: WHY a server-initiated request this proxy had already accepted was
// failed rather than delivered, and on which transport. Values of the shared transportLeg type, so
// one closed vocabulary reaches the `transport` detail rather than one enum per producer — see
// transportLeg.
const (
	// dropHTTPUndelivered: buffered onto a subscriber channel that never reached the host (the
	// client disconnected, or the SSE write failed).
	dropHTTPUndelivered transportLeg = "http-server-request-undelivered"
	// dropHTTPDisplaced / dropStdioDisplaced: the tracker made room, or an id collided. Distinct
	// from undelivered because the request may well have reached the host — what failed is eunox's
	// ability to route the answer back.
	dropHTTPDisplaced  transportLeg = "http-server-request-displaced"
	dropStdioDisplaced transportLeg = "stdio-server-request-displaced"
	// dropHTTPUnroutableID / dropStdioUnroutableID: the request's own JSON-RPC id is larger than
	// the tracker will retain (maxTrackedServerReqIDBytes), so no reply to it could ever be routed
	// back. Refused up front rather than after the host has answered — see trackServerRequest.
	dropHTTPUnroutableID  transportLeg = "http-server-request-id-unroutable"
	dropStdioUnroutableID transportLeg = "stdio-server-request-id-unroutable"
	// dropHTTPReplyUndeliverable / dropStdioReplyUndeliverable: the HOST's own reply was consumed
	// from the tracker — which is what made it unroutable by any later path — and there was no
	// upstream sink to relay it through. The one drop that destroys a reply the host actually
	// produced.
	dropHTTPReplyUndeliverable  transportLeg = "http-server-reply-undeliverable"
	dropStdioReplyUndeliverable transportLeg = "stdio-server-reply-undeliverable"
)

// serverRequestDrops is ONE leg's pair of tags for the two ways the tracker refuses to keep a
// server-initiated request routable: it displaced an entry to make room, or the request's own id is
// larger than the tracker retains. Both are the same event to the initiator — nothing can route a
// reply to it — and differ only in which leg and which cause the tape names, so they travel
// together rather than as two parameters a caller could pair wrongly.
type serverRequestDrops struct {
	displaced    transportLeg
	unroutableID transportLeg
}

var (
	httpServerRequestDrops  = serverRequestDrops{displaced: dropHTTPDisplaced, unroutableID: dropHTTPUnroutableID}
	stdioServerRequestDrops = serverRequestDrops{displaced: dropStdioDisplaced, unroutableID: dropStdioUnroutableID}
)

// displacedServerRequestError is what eunox answers a displaced request's initiator with. It names
// the proxy's own bookkeeping rather than anything about the host: a displacement is eunox running
// out of room (or an upstream reusing an id), which is exactly the case where it owes the upstream
// an answer it can produce without relaying anything the host said.
const displacedServerRequestError = "eunox: this server-initiated request was displaced from the proxy's in-flight tracker (its capacity limit, or a reused request id); no reply to it can be routed"

// unroutableIDServerRequestError is what eunox answers a request whose id it will not retain with.
// Same shape as a displacement and for the same reason — the proxy cannot route a reply to it — but
// said BEFORE the host is troubled with a request whose answer would be dropped.
const unroutableIDServerRequestError = "eunox: this server-initiated request carries a JSON-RPC id larger than the proxy's in-flight tracker retains; no reply to it could be routed, so it was not forwarded"

// recordServerRequestDropped appends the tape's account of a server-initiated request the proxy
// accepted and then failed. Shared by every disposition that produces one, so their record shape
// cannot drift; rec may be nil (skipped).
//
// A DENY rather than a correction of a specific earlier record: the tape is append-only, and what
// this states is that the named request did not complete through this proxy.
//
// The subject is a killSubject rather than a bare id for the reason refusalForwardParams gives: the
// value lands in the signed session_id field, and auditSessionID is the one function that decides
// whether a leg's id may be claimed as fact.
func recordServerRequestDropped(ctx context.Context, rec auditRecorder, subj killSubject, method string, drop transportLeg) {
	if rec == nil {
		return
	}
	rec.RecordDeny(ctx, subj.auditSessionID(), method, method, capability.ErrCodeEnforcementError, "",
		subj.auditDetails(map[string]interface{}{detailTransport: string(drop)}), false)
}

// trackServerRequest records msg as an outstanding server-initiated request on this leg, disposes
// of whatever the tracker DISPLACED to make room for it, and reports whether the request is
// ROUTABLE — whether a host reply to it could be routed back at all. A false means the caller must
// not forward it: the initiator has already been answered and the tape already carries the refusal.
//
// A displacement is neither of the leg's two exceptions: it is not a refusal of the peer and not
// an emergency stop, but eunox running out of bookkeeping space — the case where it most clearly
// owes the upstream an answer it can produce on its own. Answering has to happen HERE rather than
// when a reply eventually arrives, because by then the entry is gone and the reply is dropped as
// untracked by both transports' routing arms. An id the tracker will not retain
// (maxTrackedServerReqIDBytes) is the same debt one step earlier, and is refused up front rather
// than after the host has done the work of answering it.
//
// Recorded as well as answered: a displaced request is a call the proxy actively failed, and
// nothing on the tape said so — only a one-shot stderr warning that says a displacement happened,
// not which request it cost. The record is METERED (catDisplaced): once the bounded set is full,
// every further server-initiated request displaces one, so an upstream that outruns a slow host
// turns an unbounded audit-write rate loose on the tape — under --require-audit=strict, enough
// dropped writes latch AuditDegraded and deny every route. The refusal itself is never suppressed;
// only the tape write is bounded, and a suppressed one folds into the next admitted record.
//
// The context is the DISPLACING request's, while the record names the DISPLACED request's method.
// Sound because everything the sink derives from it is per-SESSION rather than per-request — the
// claims captured at initialize and the session's pinned revision, both read-only after the
// handshake — so the two requests share every fact the record carries but the method.
//
// It is the ONLY caller of serverReqTracker.track, which is the invariant that keeps an entry from
// leaving the tracker with its initiator unanswered — asserted by a source guard, since Go does not
// require a return value to be consumed.
func trackServerRequest(ctx context.Context, u serverRequestUnblocker, rec auditRecorder, limiter *categoryRecordLimiter, subj killSubject, drops serverRequestDrops, msg mcp.RPCMsg) bool {
	if msg.ID == nil {
		// Unreachable: forwardServerRequest's caller contract is a REQUEST, which by
		// mcp.RPCMsg.IsRequest carries an id. There is nothing to key and nothing to answer with,
		// so the caller simply does not forward it.
		return false
	}
	if !trackableServerRequestID(msg.ID) {
		u.write(mcp.ErrorResponse(msg.ID, capability.JSONRPCCodeEnforcementError, unroutableIDServerRequestError), unroutableIDServerRequestError)
		recordServerRequestDropped(ctx, meteredDropRecorder(rec, limiter), subj, msg.Method, drops.unroutableID)
		return false
	}
	displaced, ok := u.reqs.track(msg, u.errOut)
	if !ok {
		return true
	}
	// Written directly rather than through unblock: the displacement has already removed the
	// entry — that removal IS what leaves the initiator with nothing to answer it — so there is no
	// id left to take and a take-first path would answer nothing at all.
	u.write(mcp.ErrorResponse(displaced.id, capability.JSONRPCCodeEnforcementError, displacedServerRequestError), displacedServerRequestError)
	recordServerRequestDropped(ctx, meteredDropRecorder(rec, limiter), subj, displaced.method, drops.displaced)
	return true
}

// meteredDropRecorder charges catDisplaced for one tracker-refusal record, or returns rec unchanged
// for a caller that holds no limiter (a proxy assembled by a bare struct literal in a test).
func meteredDropRecorder(rec auditRecorder, limiter *categoryRecordLimiter) auditRecorder {
	if limiter == nil {
		return rec
	}
	return admitRefusalRecord(rec, limiter, catDisplaced)
}
