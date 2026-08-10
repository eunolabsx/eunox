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
// record, and every disposition here reaches it through the unblocker's own dropReport — so the
// obligation travels with the seam rather than with whoever remembered it. Three sites used to
// turn on unblock's return value (which reports whether the id was HELD, not whether the answer
// LANDED) and threw the delivery report away, leaving the upstream blocked with only a stderr line
// — now rate-limited, so under a flood not even that.

package transport

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// serverRequestLegs is ONE transport's drop-leg vocabulary for this seam: which site a record names
// for each of the four ways a server-initiated request can be failed here.
//
// One value per transport rather than four leg parameters threaded through the helpers: the four
// dispositions are the same four on both transports, and a call site that carries only one of them
// is how a displacement came to be recordable under the refusal leg.
type serverRequestLegs struct {
	// displaced: the bounded tracker made room, or an upstream reused an id.
	displaced transportLeg
	// unroutableID: the request's own JSON-RPC id is larger than the tracker retains.
	unroutableID transportLeg
	// refusal: an answer eunox produced ITSELF — a refusal, a displacement, an unroutable id —
	// that never reached the initiator.
	refusal transportLeg
	// reply: a host reply DESTROYED because there was nothing to relay it through. A different
	// fact from refusal, carrying a different category (the host actually produced that work),
	// which is why one leg field cannot serve both.
	reply transportLeg
}

// The two transports' leg sets.
var (
	httpServerRequestLegs = serverRequestLegs{
		displaced:    dropHTTPDisplaced,
		unroutableID: dropHTTPUnroutableID,
		refusal:      dropHTTPRefusalUndeliverable,
		reply:        dropHTTPReplyUndeliverable,
	}
	stdioServerRequestLegs = serverRequestLegs{
		displaced:    dropStdioDisplaced,
		unroutableID: dropStdioUnroutableID,
		refusal:      dropStdioRefusalUndeliverable,
		reply:        dropStdioReplyUndeliverable,
	}
)

// dropReport is what an answering site needs to put a destroyed answer on the tape: whose session
// the record describes, the wiring that resolves its recorder per category, and this transport's
// leg vocabulary.
//
// It lives on the unblocker rather than at each call site because "answer the initiator" and
// "record the answer that did not land" are one obligation, and splitting them is what left
// unblock's three callers reporting neither. See this file's package comment.
type dropReport struct {
	// recs resolves each drop record's recorder against the category's own declaration.
	recs refusalRecorders
	// subj names whose session the record describes. See killSubject.
	subj killSubject
	legs serverRequestLegs
}

// recordDrop appends the tape's account of one failed server-initiated request. A nil recorder (no
// sink, or a bucket that suppressed this one) is a no-op inside recordServerRequestDropped.
func (d dropReport) recordDrop(ctx context.Context, category refusalCategory, leg transportLeg, method string) {
	recordServerRequestDropped(ctx, d.recs.forCategory(category), d.subj, method, leg)
}

// serverRequestUnblocker is the per-transport wiring every site that answers a blocked
// server-initiated initiator needs — the answer AND its report.
//
// The sink is resolved into a writer LAZILY, at the moment something is answered: most holders want
// only the tracker (every forwarded request), and resolving eagerly cost them a method-value closure
// for a writer nothing called.
//
// writeUpstream() hands out a func rather than the interface because a nil CONCRETE writer in a
// shared interface parameter is a non-nil interface that panics on use; initiatorWriter decides that
// once.
type serverRequestUnblocker struct {
	reqs *serverReqTracker
	// sink is the upstream's message sink, possibly a typed nil (HTTP holds a concrete
	// *mcp.MsgWriter) — which is exactly what initiatorWriter resolves and why nothing here may
	// test it with a bare != nil.
	sink mcp.MsgSink
	// notices is this leg's diagnostic CHANNEL — where a line goes and what bounds it, as ONE
	// field. It used to be a writer here beside a bucket reached through report, two independently
	// zeroable things feeding one line: a leg that set the writer and not the bucket wrote
	// unbounded with every guard still green. See noticeWriter.
	notices noticeWriter
	// report is where a destroyed answer lands. Held here rather than passed per call because the
	// seam below is what every answering site funnels through, and an obligation placed on one
	// caller is one the next site added does not inherit.
	report dropReport
}

// writeUpstream resolves this unblocker's sink into the writer the answering seam takes, or nil when
// there is genuinely nothing to answer through. Nothing outside this file holds a raw writer any
// more — the two shapes that used to (the sampling leg's params, the pool's dispatch) carry the whole
// unblocker — so the nil answer is decided here and only here; see initiatorWriter.
func (u serverRequestUnblocker) writeUpstream() func(mcp.RPCMsg) error {
	return initiatorWriter(u.sink)
}

// unblock consumes id from the tracker and answers its blocked initiator with eunox's own error
// carrying reason, so the upstream is not left waiting on a request nothing will ever complete.
// It reports whether the id was one this proxy still HELD, not whether the answer landed:
// failServerRequestDelivery's correction record is exactly-once precisely because only one take
// succeeds, so consumption is the question its caller turns on. A DESTROYED answer is recorded
// here rather than returned, which is what the three callers turning on that bool used to lose —
// each ends up with an upstream blocked and, under a notice flood, nothing at all on either channel.
//
// The record names the method of the TAKEN entry, not of the message that brought us here: this
// arm's commonest caller holds a host RESPONSE, which carries no method at all, so a method
// parameter would have had one caller passing the empty string for the request it just failed.
//
// The id is consumed even when there is no upstream sink to answer through. That case is
// unreachable today (see writeToInitiator) and the alternative is worse: leaving the entry means it
// can never be reclaimed — no host reply to a request that was never delivered will ever arrive —
// so it occupies one of the bounded set's slots for the session's life and eventually displaces a
// LIVE request, which is now an outcome that actively answers an initiator rather than a silent one.
func (u serverRequestUnblocker) unblock(ctx context.Context, id *json.RawMessage, reason string) bool {
	if id == nil {
		return false
	}
	req, held := u.reqs.take(mcp.MsgKey(id))
	if !held {
		return false
	}
	u.answerUntracked(ctx, id, reason, req.method)
	return true
}

// relay writes the host's OWN reply to the blocked initiator and records a reply it destroyed.
//
// It consumes nothing: a caller that routes a genuine reply has already taken the id it matched, and
// the take is what decided the reply was routable at all.
//
// A failed write is the one drop on this leg that destroys a reply the host actually PRODUCED — the
// take above it is what makes that reply unroutable by any later path — so it carries its own category
// (catServerRequestFailed) and its own leg, which is why one leg field on the unblocker cannot
// serve this and a refused answer alike.
//
// It covers a FAILED write as well as an absent sink, which is what makes the record reachable at
// all: the absent sink is unreachable today on both transports, while a dead subprocess EPIPE-ing
// mid-reply is the case that actually happens.
func (u serverRequestUnblocker) relay(ctx context.Context, reply mcp.RPCMsg) {
	// The reply WAS routable — the caller's take proved it — so what failed is the sink, not the
	// routing. Naming remote-upstream mode is the one operational fact that sends an operator to
	// the configuration rather than to the host's id matching.
	if u.write(reply, "no upstream writer in remote-upstream mode") {
		return
	}
	// methodLabelServerResponse rather than the taken entry's method: the message destroyed here is
	// the host's response, which carries no method of its own, and both transports' hand-written
	// predecessors of this record named it that way.
	u.report.recordDrop(ctx, catServerRequestFailed, u.report.legs.reply, methodLabelServerResponse)
}

// write applies the shared nil-writer disposition to reply, with no record either way.
//
// It consumes nothing. Whether the tracked id should be taken is each caller's own question and
// the three answers genuinely differ — unblock takes it, relay's caller already did, and an
// eviction removed it as the very act that created the debt.
func (u serverRequestUnblocker) write(reply mcp.RPCMsg, what string) bool {
	return writeToInitiator(u.writeUpstream(), u.notices, reply, what)
}

// answer sends an error of eunox's OWN making to a blocked initiator and records one that did not
// land. It reports nothing: the tape entry IS the report, and a bool for a caller to forget is how
// three of unblock's callers came to discard it.
//
// Record-AFTER-act, unlike every refusal arm that calls it: the fact recorded is the write's own
// outcome.
//
// The earlier reading — that every caller has already recorded the refusal that brought it here, so
// a destroyed answer is not the only thing on the tape — is the one this rejects: that record
// describes the REFUSAL, not the delivery, and an operator reconstructing a wedged upstream cannot
// tell "refused and told so" from "refused and the upstream never heard" from it.
//
// method names the REQUEST left blocked, not the refusal; see recordServerRequestDropped for why it
// is not turned into a policy target.
func (u serverRequestUnblocker) answer(ctx context.Context, reply mcp.RPCMsg, what, method string) {
	if u.write(reply, what) {
		return
	}
	u.report.recordDrop(ctx, catRefusalUndeliverable, u.report.legs.refusal, method)
}

// answerUntracked sends eunox's own error to an initiator whose request this proxy never tracked,
// or removed before the reply could be matched. It takes nothing: the id is already gone (a
// displacement) or was never stored (an id the tracker refuses), so there is nothing to consume and
// a take-first path would answer nothing at all.
func (u serverRequestUnblocker) answerUntracked(ctx context.Context, id *json.RawMessage, reason, method string) {
	u.answer(ctx, mcp.ErrorResponse(id, capability.JSONRPCCodeEnforcementError, reason), reason, method)
}

// initiatorWriter turns an upstream sink into the writer this leg answers through, or nil when
// there is genuinely nothing to answer through.
//
// It exists because one transport holds its sink as an INTERFACE (mcp.MsgSink) and the other as a
// concrete pointer: a bare `!= nil` on the interface is the typed-nil trap asRecorder documents —
// an interface holding a nil *mcp.MsgWriter is non-nil, builds a writer, and panics inside a mutex
// take on the nil receiver, which is exactly what this seam was added to report instead.
//
// That one type is answered by NAME, above the reflection: it is the sink both in-tree transports
// hold, so the relay path — every answered initiator — no longer reaches reflect at all.
func initiatorWriter(sink mcp.MsgSink) func(mcp.RPCMsg) error {
	if sink == nil {
		return nil
	}
	if w, isWriter := sink.(*mcp.MsgWriter); isWriter {
		if w == nil {
			return nil
		}
		return w.Write
	}
	if nilSink(sink) {
		return nil
	}
	return sink.Write
}

// nilSink reports whether sink is an interface holding a nil value. Kind-checked before IsNil,
// which panics for a non-nilable kind — a sink implemented on a struct VALUE is legitimate and must
// answer false rather than crash the check that exists to prevent a crash.
//
// EVERY nil-able kind answers true, deliberately, including the value-receiver kinds. The tempting
// narrowing — refuse only the kinds whose nil IS a dereferenced receiver — reads as closing a false
// refusal and instead reopens the crash this seam exists to report: for the ordinary func adapter
// (`type sinkFunc func(mcp.RPCMsg) error; func (f sinkFunc) Write(m) error { return f(m) }`, this
// package's own test helper) a nil value dispatches the method and then panics calling the nil func,
// and a nil chan-backed one blocks forever. Both land AFTER the refusal's audit record, which is the
// tape-records-a-denial-the-process-died-delivering outcome writeToInitiator was written to replace.
//
// So the two errors are not symmetric: refusing a usable sink costs one lost answer plus a record
// saying so, and calling an unusable one costs the process. The residual false refusal is a nil map
// or slice whose Write happens to work on a nil receiver — a shape no in-tree sink has, and one an
// out-of-tree consumer resolves by not holding a nil sink.
func nilSink(sink mcp.MsgSink) bool {
	v := reflect.ValueOf(sink)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
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
//
// The report is BOUNDED here rather than at any one caller, because this is the seam every answering
// site funnels through and a dead sink fails every one of them at the peer's rate: an upstream that
// closes its stdin and keeps emitting requests takes a refusal arm per request, and an unbounded
// line here is one write syscall per frame — the record beside it metered while the syscall was not.
// Residual: a blocked stderr (a pipe to a stalled collector) still blocks the writer; the bound
// lowers the rate, it does not make the write non-blocking.
func writeToInitiator(write func(mcp.RPCMsg) error, notices noticeWriter, reply mcp.RPCMsg, what string) bool {
	if write == nil {
		if line, ok := notices.admitNotice(siteInitiatorUnanswerable); ok {
			line.writef(
				"[eunox] WARNING: a server-initiated request was left blocked: no upstream writer to answer it (%s)\n", what)
		}
		return false
	}
	if err := write(reply); err != nil {
		if line, ok := notices.admitNotice(siteInitiatorUnanswerable); ok {
			line.writef(
				"[eunox] WARNING: a server-initiated request was left blocked: answering its initiator failed (%s): %v\n", what, err)
		}
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
	// dropHTTPRefusalUndeliverable / dropStdioRefusalUndeliverable: eunox REFUSED a
	// server-initiated request (revoked session, degraded trail under --require-audit=strict, a
	// policy deny, or a saturated pool) and the answer saying so never reached the initiator. See
	// serverRequestUnblocker.answer for why the refusal's own record does not cover this.
	dropHTTPRefusalUndeliverable  transportLeg = "http-server-refusal-undeliverable"
	dropStdioRefusalUndeliverable transportLeg = "stdio-server-refusal-undeliverable"
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
	details := subj.auditDetails(nil)
	// An UNSET leg names no site, and an empty member of a closed vocabulary is worse on a signed
	// tape than an absent key: it matches no SIEM filter and reads like a record written before the
	// vocabulary existed. Every production caller passes a constant; this is what keeps a future one
	// that forgets from stamping a blank.
	if drop != "" {
		details = subj.auditDetails(map[string]interface{}{detailTransport: string(drop)})
	}
	rec.RecordDeny(ctx, subj.auditSessionID(), identifier, name, capability.ErrCodeEnforcementError, "",
		details, false)
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
func trackServerRequest(ctx context.Context, u serverRequestUnblocker, msg mcp.RPCMsg) {
	displaced, ok := u.reqs.track(msg, u.notices.errOut())
	if !ok {
		return
	}
	u.report.recordDrop(ctx, catDisplaced, u.report.legs.displaced, displaced.method)
	// The record above says the request was dropped; answer appends a second one if its initiator
	// was never told, which is what an operator needs to tell a wedged upstream from a merely
	// evicted one.
	u.answerUntracked(ctx, displaced.id, displacedServerRequestError, displaced.method)
}

// admitAndTrackServerRequest is the prologue BOTH forward paths share: refuse an id no reply could
// be routed back to, then record the request as outstanding and dispose of whatever that displaced.
// It reports whether the caller may deliver msg.
//
// One function for the reason dispatchServerRequest is one: the pair was hand-mirrored, and the two
// halves are not independent — the refusal must not degrade into a silent untracked forward, so a
// caller that ran the second without the first would hand the host a request whose answer both
// routing arms drop.
func admitAndTrackServerRequest(ctx context.Context, u serverRequestUnblocker, msg mcp.RPCMsg) bool {
	if !admitServerRequestID(ctx, u, msg) {
		return false
	}
	trackServerRequest(ctx, u, msg)
	return true
}

// admitServerRequestID refuses a server-initiated request whose own JSON-RPC id is larger than the
// tracker will retain (maxTrackedServerReqIDBytes), reporting whether the request may proceed.
//
// The REFUSAL is this gate's; the BOUND is the tracker's own (track refuses such an id too, so the
// retention argument is backed by the type that does the retaining). What is here rather than there
// is the answer to the peer, and it runs at each transport's ENTRY to this leg — before the pool,
// before any decision — because
// everything below it would be work spent on a request whose reply could never be routed back: the
// host would answer it and both routing arms would drop that answer as untracked, and on the
// sampling path the decision would have committed a maxCalls slot for a call the host never saw.
// The bound is enforced by refusing rather than truncating, since a truncated id can neither answer
// the initiator it was kept for nor index the reply it was kept to match.
//
// Record-before-act, and exactly ONE record: the leg below writes its own not-delivered deny for a
// request it was asked to forward, so refusing here rather than there is also what keeps a single
// refusal from producing two contradictory entries.
func admitServerRequestID(ctx context.Context, u serverRequestUnblocker, msg mcp.RPCMsg) bool {
	if trackableServerRequestID(msg.ID) {
		return true
	}
	u.report.recordDrop(ctx, catUnroutableID, u.report.legs.unroutableID, msg.Method)
	// A nil id is not answerable — there is nothing to stamp a response with — but it is still
	// refused, and mcp.RPCMsg.IsRequest makes it unreachable from either transport's entry.
	if msg.ID != nil {
		u.answerUntracked(ctx, msg.ID, unroutableIDServerRequestError, msg.Method)
	}
	return false
}
