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
//     sender's message would hand any second identity that learned a session id a way to abort
//     the owner's pending reply (see httpSession.unblockGateRefusedServerReply).
//
// Every other site answers, through the one seam below: a protocol refusal, a request no
// subscriber could receive, a delivery that failed after buffering, and a request the bounded
// tracker had to evict. Before this existed the sequence was written out at four sites with three
// different dispositions for the same nil-writer condition, so "reported rather than dropped" was
// the rule on one transport and not the other for an identical case.

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
// unreachable today (see write) and the alternative is worse: leaving the entry means it can never
// be reclaimed — no host reply to a request that was never delivered will ever arrive — so it
// occupies one of the bounded set's slots for the session's life and eventually displaces a LIVE
// request, which is now an outcome that actively answers an initiator rather than a silent one.
func (u serverRequestUnblocker) unblock(id *json.RawMessage, reason string) bool {
	if id == nil || !u.reqs.take(mcp.MsgKey(id)) {
		return false
	}
	u.write(mcp.ErrorResponse(id, capability.JSONRPCCodeEnforcementError, reason), reason)
	return true
}

// relay writes the host's OWN reply to the blocked initiator. It consumes nothing: a caller that
// routes a genuine reply has already taken the id it matched, and the take is what decided the
// reply was routable at all.
func (u serverRequestUnblocker) relay(reply mcp.RPCMsg) {
	// The reply WAS routable — the caller's take proved it — so what failed is the sink, not the
	// routing. Naming remote-upstream mode is the one operational fact that sends an operator to
	// the configuration rather than to the host's id matching.
	u.write(reply, "no upstream writer in remote-upstream mode")
}

// write is the ONE nil-writer disposition every site on this leg shares: send reply to the blocked
// initiator, or report that there was no upstream sink to send it through. what names the
// situation for that report.
//
// It consumes nothing. Whether the tracked id should be taken is each caller's own question and
// the three answers genuinely differ — unblock takes it, relay's caller already did, and an
// eviction removed it as the very act that created the debt.
//
// The writerless case is unreachable today on every caller: remote-upstream mode is the only shape
// without a sink and those sessions issue no server-initiated requests, so no id could have been
// tracked. Reported rather than dropped because the alternative is an upstream wedged with nothing
// on stderr or the tape saying why.
func (u serverRequestUnblocker) write(reply mcp.RPCMsg, what string) {
	if u.writeUpstream == nil {
		_, _ = fmt.Fprintf(resolvedErrOut(u.errOut),
			"[eunox] WARNING: a server-initiated request was left blocked: no upstream writer to answer it (%s)\n", what)
		return
	}
	u.writeUpstream(reply)
}

// serverRequestDrop names, in a record's `transport` detail, WHY a server-initiated request this
// proxy had already accepted was failed rather than delivered. A typed enum so a new drop site
// cannot spell an existing one's tag slightly differently.
type serverRequestDrop string

const (
	// dropHTTPUndelivered: buffered onto a subscriber channel that never reached the host (the
	// client disconnected, or the SSE write failed).
	dropHTTPUndelivered serverRequestDrop = "http-server-request-undelivered"
	// dropHTTPDisplaced / dropStdioDisplaced: the tracker made room, or an id collided. Distinct
	// from undelivered because the request may well have reached the host — what failed is eunox's
	// ability to route the answer back.
	dropHTTPDisplaced  serverRequestDrop = "http-server-request-displaced"
	dropStdioDisplaced serverRequestDrop = "stdio-server-request-displaced"
)

// displacedServerRequestError is what eunox answers a displaced request's initiator with. It names
// the proxy's own bookkeeping rather than anything about the host: a displacement is eunox running
// out of room (or an upstream reusing an id), which is exactly the case where it owes the upstream
// an answer it can produce without relaying anything the host said.
const displacedServerRequestError = "eunox: this server-initiated request was displaced from the proxy's in-flight tracker (its capacity limit, or a reused request id); no reply to it can be routed"

// recordServerRequestDropped appends the tape's account of a server-initiated request the proxy
// accepted and then failed. Shared by the two dispositions that produce one, so their record
// shape cannot drift; rec may be nil (skipped).
//
// A DENY rather than a correction of a specific earlier record: the tape is append-only, and what
// this states is that the named request did not complete through this proxy.
//
// The subject is a killSubject rather than a bare id for the reason refusalForwardParams gives: the
// value lands in the signed session_id field, and auditSessionID is the one function that decides
// whether a leg's id may be claimed as fact.
func recordServerRequestDropped(ctx context.Context, rec auditRecorder, subj killSubject, method string, drop serverRequestDrop) {
	if rec == nil {
		return
	}
	rec.RecordDeny(ctx, subj.auditSessionID(), method, method, capability.ErrCodeEnforcementError, "",
		subj.auditDetails(map[string]interface{}{"transport": string(drop)}), false)
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
func trackServerRequest(ctx context.Context, u serverRequestUnblocker, rec auditRecorder, limiter *categoryRecordLimiter, subj killSubject, drop serverRequestDrop, msg mcp.RPCMsg) {
	displaced, ok := u.reqs.track(msg, u.errOut)
	if !ok {
		return
	}
	// Written directly rather than through unblock: the displacement has already removed the
	// entry — that removal IS what leaves the initiator with nothing to answer it — so there is no
	// id left to take and a take-first path would answer nothing at all.
	u.write(mcp.ErrorResponse(displaced.id, capability.JSONRPCCodeEnforcementError, displacedServerRequestError), displacedServerRequestError)
	if limiter != nil {
		rec = admitRefusalRecord(rec, limiter, catDisplaced)
	}
	recordServerRequestDropped(ctx, rec, subj, displaced.method, drop)
}
