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
	writeUpstream func(mcp.RPCMsg) error
	errOut        io.Writer
}

// unblock consumes id from the tracker and answers its blocked initiator with eunox's own error
// carrying reason, so the upstream is not left waiting on a request nothing will ever complete.
// It reports whether the id was one this proxy still HELD, not whether the answer landed:
// failServerRequestDelivery's correction record is exactly-once precisely because only one take
// succeeds, so consumption is the question its caller turns on. A destroyed answer matters where
// nothing else records the failure, which is relay's case and not this one — every caller here is
// already writing, or has already written, a record for the refusal that brought it.
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
	u.answerUntracked(id, reason)
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
//
// It covers a FAILED write as well as an absent sink, which is what makes the record reachable at
// all: the absent sink is unreachable today on both transports, while a dead subprocess EPIPE-ing
// mid-reply is the case that actually happens.
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

// answerUntracked sends eunox's own error to an initiator whose request this proxy never tracked,
// or removed before the reply could be matched. It takes nothing: the id is already gone (a
// displacement) or was never stored (an id the tracker refuses), so there is nothing to consume and
// a take-first path would answer nothing at all.
func (u serverRequestUnblocker) answerUntracked(id *json.RawMessage, reason string) bool {
	return u.write(mcp.ErrorResponse(id, capability.JSONRPCCodeEnforcementError, reason), reason)
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
// It reports a FAILED write as well as an absent sink, because to every caller they are the same
// event — the initiator is blocked and eunox could not say so — and only the failed write is
// reachable in a running deployment. A sink that swallowed its own error made the absent-sink branch
// the only one a caller could ever observe, which is the branch this doc calls unreachable.
//
// The writerless case is unreachable today on every caller: remote-upstream mode is the only shape
// without a sink and those sessions issue no server-initiated requests, so no id could have been
// tracked, and stdio's writer is nil only before connectUpstream runs. Reported rather than dropped
// because the alternative is an upstream wedged with nothing on stderr or the tape saying why.
func writeToInitiator(write func(mcp.RPCMsg) error, errOut io.Writer, reply mcp.RPCMsg, what string) bool {
	if write == nil {
		_, _ = fmt.Fprintf(resolvedErrOut(errOut),
			"[eunox] WARNING: a server-initiated request was left blocked: no upstream writer to answer it (%s)\n", what)
		return false
	}
	if err := write(reply); err != nil {
		_, _ = fmt.Fprintf(resolvedErrOut(errOut),
			"[eunox] WARNING: a server-initiated request was left blocked: answering its initiator failed (%s): %v\n", what, err)
		return false
	}
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
	// Through auditIdentity, the rule EVERY refusal with no policy decision behind it shares: the
	// sink derives target_type/target from the identifier, so naming a target-resolving method here
	// would stamp a policy target onto the signed tape for a request the PDP never saw — and
	// sampling/createMessage, the method most likely to be dropped on this leg, resolves one.
	identifier, name := auditIdentity(mcp.RPCMsg{Method: method})
	rec.RecordDeny(ctx, subj.auditSessionID(), identifier, name, capability.ErrCodeEnforcementError, "",
		subj.auditDetails(map[string]interface{}{detailTransport: string(drop)}), false)
}

// trackServerRequest records msg as an outstanding server-initiated request on this leg and
// disposes of whatever the tracker DISPLACED to make room for it.
//
// A displacement is neither of the leg's two exceptions: it is not a refusal of the peer and not
// an emergency stop, but eunox running out of bookkeeping space — the case where it most clearly
// owes the upstream an answer it can produce on its own. Answering has to happen HERE rather than
// when a reply eventually arrives, because by then the entry is gone and the reply is dropped as
// untracked by both transports' routing arms.
//
// Recorded as well as answered, and recorded FIRST: a displaced request is a call the proxy
// actively failed, and a crash between the two must lose the answer rather than the tape entry —
// the rule every denial arm on this leg follows. The record is METERED (catDisplaced): once the
// bounded set is full, every further server-initiated request displaces one, so an upstream that
// outruns a slow host turns an unbounded audit-write rate loose on the tape — under
// --require-audit=strict, enough dropped writes latch AuditDegraded and deny every route. The
// refusal itself is never suppressed; only the tape write is bounded.
//
// The context is the DISPLACING request's, while the record names the DISPLACED request's method.
// Sound because everything the sink derives from it is per-SESSION rather than per-request — the
// claims captured at initialize and the session's pinned revision, both read-only after the
// handshake — so the two requests share every fact the record carries but the method.
//
// It is the ONLY caller of serverReqTracker.track, which is the invariant that keeps an entry from
// leaving the tracker with its initiator unanswered — asserted by a source guard, since Go does not
// require a return value to be consumed.
func trackServerRequest(ctx context.Context, u serverRequestUnblocker, recs refusalRecorders, subj killSubject, drop transportLeg, msg mcp.RPCMsg) {
	displaced, ok := u.reqs.track(msg, u.errOut)
	if !ok {
		return
	}
	recordServerRequestDropped(ctx, recs.forCategory(catDisplaced), subj, displaced.method, drop)
	u.answerUntracked(displaced.id, displacedServerRequestError)
}

// admitServerRequestID refuses a server-initiated request whose own JSON-RPC id is larger than the
// tracker will retain (maxTrackedServerReqIDBytes), reporting whether the request may proceed.
//
// It runs at each transport's ENTRY to this leg — before the pool, before any decision — because
// everything below it would be work spent on a request whose reply could never be routed back: the
// host would answer it and both routing arms would drop that answer as untracked, and on the
// sampling path the decision would have committed a maxCalls slot for a call the host never saw.
// The bound is enforced by refusing rather than truncating, since a truncated id can neither answer
// the initiator it was kept for nor index the reply it was kept to match.
//
// Record-before-act, and exactly ONE record: the leg below writes its own not-delivered deny for a
// request it was asked to forward, so refusing here rather than there is also what keeps a single
// refusal from producing two contradictory entries.
func admitServerRequestID(ctx context.Context, u serverRequestUnblocker, recs refusalRecorders, subj killSubject, drop transportLeg, msg mcp.RPCMsg) bool {
	if trackableServerRequestID(msg.ID) {
		return true
	}
	recordServerRequestDropped(ctx, recs.forCategory(catUnroutableID), subj, msg.Method, drop)
	// A nil id is not answerable — there is nothing to stamp a response with — but it is still
	// refused, and mcp.RPCMsg.IsRequest makes it unreachable from either transport's entry.
	if msg.ID != nil {
		u.answerUntracked(msg.ID, unroutableIDServerRequestError)
	}
	return false
}
