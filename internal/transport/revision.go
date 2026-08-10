// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Protocol-revision negotiation, host side and upstream side.
//
// The two are tracked independently on purpose: a proxy exists to stand between peers that
// disagree, and the common migration deployment is a current host in front of a lagging
// upstream (or the reverse). The host-side result is established per context and CHECKED per
// request; the upstream-side result is DECIDED once, before the leg opens, and pinned for the
// route's life (see upstream_open.go — it selects the opener, so it cannot be a conclusion
// drawn from the opener's own reply).

package transport

import (
	"context"
	"errors"
	"fmt"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// errRevisionMismatch marks a request declaring a revision other than the one its context
// was opened at. It is a refusal rather than a re-negotiation: each revision has its own
// method table, so a mid-context flip is indistinguishable from a probe for the more
// permissive one — the same family of enforcement confusion as a header disagreeing with the
// body it describes.
var errRevisionMismatch = errors.New("protocol revision disagrees with the context it arrived in")

// errUnhonorableUpstreamRevision marks a message this proxy cannot forward at the revision it
// resolved under.
//
// Params are forwarded VERBATIM into a conversation eunox itself opened with `initialize`, so
// dispatching under one revision and addressing the upstream as another does not relay a
// mismatched pair, it MANUFACTURES one — the same family of enforcement confusion
// errRevisionMismatch refuses on the host leg. The handshake is the carrier both legs have; a
// remote HTTP upstream reads a second one, the MCP-Protocol-Version header, which names the
// same revision. Rewriting the request to match is translation, which the mismatched-pair
// boundary governs and this build does not do.
var errUnhonorableUpstreamRevision = errors.New("request revision cannot be honored by the upstream leg")

// hostLeg is what revision negotiation needs to know about the connection a message arrived on.
//
// A struct rather than three parameters because the SESSIONLESS arms supply mostly zero values,
// and three bare arguments at those call sites read as an oversight rather than as the fact
// they are: no session established, and no upstream leg their message could reach.
type hostLeg struct {
	contextRev  capability.Revision
	upstreamRev capability.Revision
	sessionID   string
}

// hostMessageGate is the shared prologue every host message passes before its framing is
// dispatched — the head of the gate order (see dispatch.go), with the three per-transport
// facts injected rather than restated.
//
// It exists for the reason hostNotificationGate does one framing over. Before it, each
// transport spelled the sequence out: resolve, build the refusal, write it in whatever shape
// this peer takes, and — on the one transport that remembered — answer the upstream request a
// refused host RESPONSE would have completed. That last step lived at HTTP's CALL SITE rather
// than in its negotiation helper, so a third HTTP entry point that negotiated would have
// inherited the refusal and not the unblock, which is the same shape as the arm that inherited
// neither.
//
// The two transports still hold their own negotiateHostRevision, because their SHAPES differ
// for a reason that is not a preference: stdio returns the stamped context (its reader owns the
// pin and nothing may route a message without giving its records the revision it routed by),
// while contextcheck requires HTTP's derivation from r.Context() to be visible at the site. The
// prologue below is what is common underneath both — negotiation, its refusal, and its debt to
// a blocked initiator.
//
// It COSTS three heap allocations per host message, measured rather than assumed: `negotiate`
// calls its three fields indirectly, so the receiver leaks (`-gcflags=-m`: "leaking param: g")
// and every closure spills. BenchmarkHTTPProxy moves +3 allocs/op and ~+65 B/op on each proxied
// subtest — around 1% of a request that already allocates ~330 times. Accepted rather than
// optimized away, because the two shapes that would remove it both undo the point: hoisting the
// resolve out of `negotiate` puts the sequence back at the call sites, and boxing the three
// hooks into an interface only moves the allocation to the transport that cannot supply a
// long-lived receiver. BenchmarkStdioProxy cannot see any of this — it drives handleHostRequest
// directly, below serveHost, which is the only caller of stdio's negotiateHostRevision.
//
// Revocation is deliberately NOT part of this prologue, though the gate order places it next.
// For the REQUEST framing the kill check must be taken AFTER the decision turn, freshly, so a
// kill landing during an unbounded wait is recorded as KILL_SWITCH rather than as the method's
// own refusal; a prologue-level answer would be the stale one. That is why the request framing
// takes it inside dispatchRequest and enforcedForwardCore, and why the notification framing —
// which waits for nothing — can and does take it here-adjacent, in hostNotificationGate.
type hostMessageGate struct {
	// leg is the connection's own answer to what negotiation needs to know.
	leg hostLeg
	// recorder resolves the refusal's audit recorder, LAZILY: it is drawn from a rate-limit
	// bucket, so resolving it for a message that is about to be admitted spends a token on
	// nothing — and an unauthenticated peer can send those at will. Nil resolves to no
	// recorder, which refuseHostRevision reads as "record nothing"; the wire refusal is
	// unaffected either way.
	recorder func() auditRecorder
	// refuse writes the refusal to THIS peer. It is handed the response refuseHostRevision
	// built, which is the zero message for any framing JSON-RPC forbids replying to — each
	// transport decides what it sends instead (stdio nothing, HTTP a bodyless 202).
	//
	// Never nil, like hostNotificationGate.checkKill: every gate has a peer to answer, and the
	// refusal path is reachable by any peer sending a bad version, so there is nothing a
	// fallback here could do that a caller with no writer has not already got wrong.
	refuse func(mcp.RPCMsg)
	// unblock answers the upstream request a refused host RESPONSE would have completed, so it
	// does not hang until the connection ends. Nil on a leg that has no upstream to unblock —
	// the pre-session arms, whose messages reach none. See server_request_unblock.go for the
	// leg's one rule and its two exceptions.
	unblock func(context.Context, mcp.RPCMsg)
}

// negotiate resolves the revision one host message is dispatched under, disposing of it
// entirely when it cannot be established: ok=false means the record is written, this peer has
// its refusal in whatever shape it takes, and any upstream request the message would have
// answered has been unblocked.
//
// The revision is returned rather than stamped onto a context here, because which context it is
// stamped onto is exactly the part that differs between the transports — see the type's doc.
func (g hostMessageGate) negotiate(ctx context.Context, msg mcp.RPCMsg) (capability.Revision, bool) {
	rev, err := resolveHostRevision(g.leg.contextRev, g.leg.upstreamRev, msg)
	if err == nil {
		return rev, true
	}
	var rec auditRecorder
	if g.recorder != nil {
		rec = g.recorder()
	}
	// Rate-limited like every other caller-driven refusal: a suppressed record still gets its
	// refusal on the wire, so the peer is refused either way — what the bucket bounds is the
	// tape write, which is the part a flood turns into an availability problem.
	g.refuse(refuseHostRevision(ctx, rec, g.leg.sessionID, g.leg.contextRev, msg, err))
	if g.unblock != nil {
		g.unblock(ctx, msg)
	}
	return "", false
}

// resolveHostRevision decides which revision one host message is dispatched under.
//
// contextRev is the revision the peer's context was opened at, or "" for a context that
// never negotiated one. An undeclared revision inherits the context's, and an unnegotiated
// context falls back to capability.DefaultRevision — the surface eunox already shipped, so
// nothing reaches a different method table by omitting a declaration. (Session creation
// without a handshake, where "no context and no declaration" becomes a decision rather than
// a default, is ADR-0004's session-creation half and not this seam's to make.)
//
// legRev is the revision this proxy's UPSTREAM leg negotiated, or "" for a caller with no
// upstream leg yet (the sessionless arms, whose messages reach no upstream). See
// checkUpstreamHonorable for what it gates.
func resolveHostRevision(contextRev, legRev capability.Revision, msg mcp.RPCMsg) (capability.Revision, error) {
	declared, present, err := mcp.DeclaredRevisionOf(msg)
	if err != nil {
		return "", err
	}
	resolved := declared
	switch {
	case !present:
		// resolveRevision, not a second spelling of it: an unnegotiated context resolves to the
		// surface eunox already shipped, and that rule has exactly one home.
		resolved = resolveRevision(contextRev)
	case contextRev != "" && declared != contextRev:
		return "", fmt.Errorf("%w: context negotiated %s, request declares %s", errRevisionMismatch, contextRev, declared)
	}
	// Only for a message whose params actually travel: one answered without contacting the
	// upstream contradicts nothing there, so refusing it would deny a message on the strength of
	// a forward that never happens. Asked per FRAMING — a host RESPONSE has no method to look up
	// and is relayed verbatim, so a method-keyed gate skipped exactly the class whose bytes reach
	// the upstream unconditionally.
	if paramsReachUpstream(msg) {
		if err := checkUpstreamHonorable(resolved, legRev); err != nil {
			return "", err
		}
	}
	return resolved, nil
}

// upstreamAddressedRevision is the revision this proxy PRESENTS to an upstream leg: the one
// the leg was OPENED at (UpstreamOpenRevision), which is what the leg's own field already
// holds. True of a subprocess upstream, which reads bare JSON-RPC and no header at all, as
// much as of a remote HTTP one — the opener's method differs either way.
//
// It used to be the handshake revision unconditionally, because every leg was opened with
// `initialize` whatever an operator pinned. That is no longer so, and the identity here is the
// point rather than an accident: what is SENT (the MCP-Protocol-Version header, the opener's
// method, eunox's own `_meta` declaration) and what is CHECKED (checkUpstreamHonorable) read
// this one expression, so a pinned leg cannot be addressed as one revision and held to another.
//
// An unset (or unspeakable) leg revision resolves through UpstreamOpenRevision, the SAME
// resolver that decided what to open with — not through resolveRevision, which answers the
// HOST-side empty-carrier question and lands on capability.DefaultRevision. The two agree only
// while DefaultRevision and the handshake revision are the same value, and the day the default
// advances they would open a leg with `initialize` while heading and checking it as something
// else. One resolver is what keeps that from being two.
func upstreamAddressedRevision(legRev capability.Revision) capability.Revision {
	return UpstreamOpenRevision(legRev)
}

// checkUpstreamHonorable refuses a message this proxy cannot forward without contradicting
// itself: one whose RESOLVED revision is not the one the upstream leg is addressed as.
//
// Resolved, not declared. A declaration is only half of how a message acquires its revision —
// the other half is inheriting the context, which a peer pins by declaring once on a method
// that forwards nothing. Checking the declaration alone let that peer be dispatched under the
// newer method table and forwarded anyway, on every later request that simply omitted it.
//
// Which messages reach it is paramsReachUpstream's question, not this one's; it deliberately
// covers a framing (the host response) that carries no method and is never dispatched at all,
// because "its bytes reach the upstream" is the whole trigger.
//
// A leg with no revision yet ("") is not checked: there is nothing to contradict, and refusing
// would deny a message on the strength of a fact nobody has established. Every leg the proxy
// opens now pins its revision at construction, so this covers the legs a test builds by
// literal rather than a window a live one passes through.
func checkUpstreamHonorable(resolved, legRev capability.Revision) error {
	if legRev == "" {
		return nil
	}
	if addressed := upstreamAddressedRevision(legRev); resolved != addressed {
		return fmt.Errorf("%w: this proxy addresses its upstream leg as %s, request resolves to %s",
			errUnhonorableUpstreamRevision, addressed, resolved)
	}
	return nil
}

// revisionRefusalReason turns a resolveHostRevision error into the host-facing message for
// the -32022 refusal. It names the failure class and the revision the peer declared (which
// the peer sent and which is bounded by having been matched against a closed set), never any
// other caller-supplied value.
func revisionRefusalReason(err error) string {
	// One condition, not an arm per sentinel: what this function protects is the ALLOWLIST of
	// errors whose text is safe to echo, and all of these are (each names only the failure
	// class and version strings — the peer's own, already matched against a closed set, and
	// this proxy's own leg revisions). Anything else collapses to a fixed string rather than
	// leaking an unreviewed message.
	if errors.Is(err, errRevisionMismatch) || errors.Is(err, mcp.ErrUnknownRevision) ||
		errors.Is(err, mcp.ErrConflictingRevision) || errors.Is(err, errUnhonorableUpstreamRevision) {
		return err.Error()
	}
	return "protocol revision could not be established"
}

// refuseHostRevision records the refusal and builds the -32022 response for a request whose
// revision cannot be established. Shared by both transports so the record and the wire reply
// are minted together — a refusal the tape does not carry is exactly the blind spot the
// notification-framing guards exist to close.
//
// This refusal precedes the kill check on both transports, because a message whose revision
// is unresolved has no method table to be looked up in. It performs nothing and contacts no
// upstream, so a revoked session gains nothing by taking this path; what it costs is that
// such a probe is recorded under this code rather than KILL_SWITCH.
//
// A NOTIFICATION gets the record and a zero RPCMsg: JSON-RPC forbids replying to one, and
// stamping the response with a null id would read as a reply to a different request. A host
// RESPONSE — reachable since the honorability gate became framing-aware — gets the record and no
// host-facing reply for the same reason, but its INITIATOR is answered separately by each
// transport's negotiation arm through the one serverRequestUnblocker (see
// server_request_unblock.go for the leg's rule). What the record may name is
// auditIdentity's.
func refuseHostRevision(ctx context.Context, rec auditRecorder, sessionID string, contextRev capability.Revision, msg mcp.RPCMsg, err error) mcp.RPCMsg {
	reason := revisionRefusalReason(err)
	// The message resolved no revision — that is why it is here — but its CONTEXT may have one,
	// and that is what the record should name: a mid-context flip is refused on a session whose
	// surface is established. Absence stays reserved for a refusal taken before anything could
	// be resolved, which is the only reading the tape's convention allows it.
	if contextRev != "" {
		ctx = capability.WithProtocolRevision(ctx, contextRev)
	}
	if rec != nil {
		identifier, method := auditIdentity(msg)
		rec.RecordDeny(ctx, sessionID, identifier, method, capability.ErrCodeUnsupportedProtocolVersion, "", nil, false)
	}
	if !msg.IsRequest() {
		return mcp.RPCMsg{}
	}
	return mcp.UnsupportedProtocolVersionResponse(msg.ID, reason)
}

// The two reasons eunox answers a blocked upstream with when it refuses the host's reply to that
// upstream's own request. Fixed text of eunox's own: the reply was refused, so nothing the host
// said may be relayed, and the id each is stamped with is one this proxy itself issued.
//
// Which refusals answer at all — and the two that deliberately do not — is the leg's one rule,
// stated in server_request_unblock.go.
const (
	refusedReplyUpstreamError     = "eunox: the host's reply declared an MCP protocol revision that could not be established; the reply was refused and cannot be relayed"
	gateRefusedReplyUpstreamError = "eunox: the host's reply was refused by this session's security gates; the reply was refused and cannot be relayed"
)
