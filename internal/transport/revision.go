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

// A message this proxy cannot forward at the revision it resolved under used to have a
// sentinel of its own here, because dispatching under one revision while addressing the
// upstream as another does not relay a mismatched pair, it MANUFACTURES one. That is still
// true, and it is now errUntranslatableAcrossRevisions' to say: rewriting the request so the
// two agree is TRANSLATION, and the boundary that decides which messages get it is the one
// place the refusal belongs. See translate.go.

// errUndeclaredOnDeclaringLeg marks a message that resolved to a declaring revision by
// INHERITING its context rather than by stating a version, on a leg whose revision requires the
// declaration on every request.
//
// eunox forwards a host's params verbatim and declares only on the requests it originates, so
// there is nothing to add on the way through — the member would simply be absent at the
// upstream, which refuses it one layer away from the cause. Refusing here names the cause: the
// peer inherited a revision whose own rule is that inheritance is not enough.
var errUndeclaredOnDeclaringLeg = errors.New("request inherited a revision that requires a per-request declaration, and carries none")

// errUndecodableForwardedParams marks a message this build refused whole — a duplicate object
// key, the one rejection a conforming peer does not share — whose bytes nevertheless travel to
// the upstream with nothing re-reading them.
//
// mcp.DeclaredRevision cannot say what such a body declares, and "eunox could not read it" is
// not "it declares nothing": a peer adds a throwaway duplicate key to make this proxy's decoder
// bail while leaving a clean io.modelcontextprotocol/protocolVersion in `_meta` for the
// upstream's last-wins parser to read. Every gate downstream then compares an INHERITED revision the forwarded bytes
// contradict — errRevisionMismatch and checkUpstreamHonorable both pass, and on a remote leg
// eunox stamps an MCP-Protocol-Version header naming a revision other than the one the body it
// is carrying declares. That is the enforcement-versus-upstream parser differential
// mcp.DecodeParams exists to close, so the framing-blind fallback must not reopen it for the
// framings DecodeParams never gets a second look at.
var errUndecodableForwardedParams = errors.New("params this proxy forwards verbatim could not be decoded, so the protocol revision they declare to the upstream cannot be established")

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
// It costs an admitted host message NOTHING, which took two shapes to reach and is the reason
// the wiring below looks as it does. As three injected closures it cost three heap allocations
// per message: `negotiate` calls a func field indirectly, so the compiler cannot keep the
// receiver local (`-gcflags=-m`: "leaking param: g") and every closure built to fill one spills
// — paid on every message, including the admitted ones the resolve returns early for. The two
// hooks whose receiver OUTLIVES the message are now an interface each transport satisfies from a
// value it already holds (hostGatePeer), and the one that genuinely captured per-message state
// (HTTP's ResponseWriter) is gone: the refusal is RETURNED for the caller to write. What did not
// move is the sequence, which is what this type is for.
//
// Revocation is deliberately NOT part of this prologue, though the gate order places it next.
// For the REQUEST framing the kill check must be taken AFTER the decision turn, freshly, so a
// kill landing during an unbounded wait is recorded as KILL_SWITCH rather than as the method's
// own refusal; a prologue-level answer would be the stale one. That is why the request framing
// takes it inside dispatchRequest and enforcedForwardCore, and why the notification framing
// takes it here-adjacent, in hostNotificationGate — which suffices only where nothing waits
// after it. stdio's ordering barrier does, so that leg re-checks past it.
type hostMessageGate struct {
	// leg is the connection's own answer to what negotiation needs to know.
	leg hostLeg
	// peer is the connection itself, as the two hooks the refusal path needs from it.
	//
	// Never nil, like hostNotificationGate.checkKill: every gate has a peer to answer, and the
	// refusal path is reachable by any peer sending a bad version, so there is nothing a
	// fallback here could do that a caller with no wiring has not already got wrong.
	peer hostGatePeer
}

// hostGatePeer is the half of the prologue's wiring whose receiver OUTLIVES the message: where a
// refusal's record goes, and how the upstream request a refused host RESPONSE would have
// completed is answered.
//
// An INTERFACE rather than two closure fields, for a reason that is measured rather than
// stylistic. negotiate calls a hook indirectly, so filling one with a closure allocates it on
// every message — including the admitted ones, which is every message on a healthy connection.
// Both transports answer both questions from a value they already hold for the length of the
// connection (*StdioProxy, *httpSession), so boxing one costs nothing. The single caller with no
// such value is HTTP's pre-session arm, which builds a sessionlessGatePeer per message: once per
// session establishment rather than once per request.
type hostGatePeer interface {
	// revisionRefusalRecorder resolves the refusal's audit recorder, and is called only on the
	// refusal path: the recorder is drawn from a rate-limit bucket, so resolving it for a message
	// about to be admitted would spend a token on nothing — and an unauthenticated peer can send
	// those at will. A nil recorder is what refuseHostRevision reads as "record nothing"; the
	// wire refusal is unaffected either way.
	revisionRefusalRecorder() auditRecorder
	// unblockRefusedServerReply answers the upstream request a refused host RESPONSE would have
	// completed, so it does not hang until the connection ends. A no-op on a leg with no upstream
	// to unblock — the pre-session arms, whose messages reach none. See server_request_unblock.go
	// for the leg's one rule and its two exceptions.
	unblockRefusedServerReply(context.Context, mcp.RPCMsg)
}

// negotiate resolves the revision one host message is dispatched under, disposing of it
// entirely when it cannot be established: ok=false means the record is written, any upstream
// request the message would have answered has been unblocked, and the returned message is the
// refusal this peer is OWED — the zero message for any framing JSON-RPC forbids replying to, so
// each transport writes what it is handed in the shape its peer takes (stdio nothing, HTTP a
// bodyless 202).
//
// The refusal travels back rather than through an injected writer because that hook is the one
// piece of this wiring that genuinely captures per-message state, so a closure for it is built
// and spilled on every ADMITTED message to serve the refused ones. What stays inside is the part
// the type exists for: the sequence — resolve, then record, then unblock — which no caller can
// reorder or forget. Writing the refusal is not part of that sequence; each transport already
// owns what its peer is sent when JSON-RPC forbids a reply.
//
// So the unblock now runs BEFORE the caller's write rather than after. Immaterial rather than
// tolerated: it acts on the RESPONSE framing alone, and JSON-RPC forbids replying to a response,
// so the message returned for that framing is the zero one — there is no content whose ordering
// against the upstream's answer any peer could observe.
//
// The revision is returned rather than stamped onto a context here, because which context it is
// stamped onto is exactly the part that differs between the transports — see the type's doc.
func (g hostMessageGate) negotiate(ctx context.Context, msg mcp.RPCMsg) (capability.Revision, mcp.RPCMsg, bool) {
	rev, err := resolveHostRevision(g.leg.contextRev, g.leg.upstreamRev, msg)
	if err == nil {
		return rev, mcp.RPCMsg{}, true
	}
	// Rate-limited like every other caller-driven refusal: a suppressed record still gets its
	// refusal on the wire, so the peer is refused either way — what the bucket bounds is the
	// tape write, which is the part a flood turns into an availability problem.
	refusal := refuseHostRevision(ctx, g.peer.revisionRefusalRecorder(), g.leg.sessionID, g.leg.contextRev, msg, err)
	g.peer.unblockRefusedServerReply(ctx, msg)
	return "", refusal, false
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
	// UNREADABLE is a third answer, not an absence: this build refused a body a conforming peer
	// reads fine, so what it declares is unknown. Refused outright where those bytes travel
	// unread (checkUndecodableForwarded); otherwise the message is on its way to a handler that
	// re-decodes and denies it, so it resolves as an undeclared one does — the malformed body
	// chooses no table, and the target-bearing INVALID_REQUEST its handler writes is not
	// replaced by a version failure.
	unreadable := errors.Is(err, mcp.ErrUndecodableDeclaration)
	if unreadable {
		if fwdErr := checkUndecodableForwarded(legRev, msg); fwdErr != nil {
			return "", fwdErr
		}
		declared, present, err = "", false, nil
	}
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
	if paramsReachUpstream(msg) && reachesUpstreamUnderRevision(resolved, msg) {
		if err := checkUpstreamHonorable(resolved, legRev, msg); err != nil {
			return "", err
		}
		// present || unreadable, not present: that check refuses a message for carrying NO
		// declaration, and an unreadable body has not been established to carry none — the
		// absence above is this decoder's, not the peer's. Passing the manufactured one made a
		// malformed tools/call on a declaring leg refuse -32022 as errUndeclaredOnDeclaringLeg,
		// which is the exact relabelling the unreadable arm exists to avoid, on the one leg
		// revision the tests for it did not cover. Nothing is lost by skipping: the handler
		// denies these bytes before they reach the upstream that would have wanted the member.
		if err := checkDeclarationReachesUpstream(resolved, legRev, msg, present || unreadable); err != nil {
			return "", err
		}
	}
	return resolved, nil
}

// reachesUpstreamUnderRevision narrows paramsReachUpstream by the peer's own routing tables:
// a method resolved does not DISPATCH is refused by the fail-closed routing default and
// forwards nothing, so neither upstream-facing check has anything to judge.
//
// paramsReachUpstream stays revision-INDEPENDENT — it answers a question about the method, and
// deriving it from the tables would make a per-method fact depend on who is asking. What is
// revision-dependent is whether THIS message gets that far, and that is this predicate.
//
// It exists because of gate ORDER. Negotiation runs before routing (a message whose revision is
// unresolved has no table to be looked up in), so the upstream-facing checks see messages
// routing is about to refuse. That was harmless while they only ever produced the same answer
// routing would; it stopped being harmless when the translation boundary started producing a
// DIFFERENT one, reporting a method the peer's own revision removed as two revisions that
// cannot bridge it — a diagnosis pointing an operator at their migration for a call a matched
// pair would refuse just as flatly.
//
// A message with no METHOD is exempt rather than refused. A host RESPONSE is dispatched by
// neither table by construction, so asking this of one answers no for every response and would
// hand the verbatim-relayed framing — the one whose bytes reach the upstream with no dispatch
// decision at all — straight past both checks.
func reachesUpstreamUnderRevision(resolved capability.Revision, msg mcp.RPCMsg) bool {
	return msg.Method == "" || dispatchesMessage(resolved, msg)
}

// checkUndecodableForwarded refuses a message whose members this build alone refused and whose
// bytes reach the upstream unread. See errUndecodableForwardedParams for what such a
// message can otherwise smuggle past enforcement, and unreadParamsReachUpstream for why the
// question is asked of three framings rather than of every message whose params travel.
//
// A leg with no revision ("") has no upstream for the bytes to reach — the sessionless arms —
// which is the same window checkUpstreamHonorable declines to judge, and for the same reason:
// refusing there would deny a message on the strength of a forward that never happens.
func checkUndecodableForwarded(legRev capability.Revision, msg mcp.RPCMsg) error {
	if legRev == "" || !unreadParamsReachUpstream(msg) {
		return nil
	}
	return errUndecodableForwardedParams
}

// checkDeclarationReachesUpstream refuses a message that would arrive at a declaring upstream
// without the per-request version member that revision requires.
//
// The gap it closes is the seam between two rules that are each correct alone. Host-side,
// omission INHERITS the context — so a peer may declare once and omit forever after. Upstream-
// side, eunox declares only on the requests it ORIGINATES, because adding a member to a host's
// params is translation. Put together, an inherited request crosses to a declaring upstream with
// no declaration at all and is refused there, by a peer that cannot say which of eunox's two
// rules produced it.
//
// Scoped to a message that carries a METHOD: the revision requires the declaration on requests
// and notifications, and a host RESPONSE — the one framing relayed verbatim with no method — is
// an answer to something the upstream already declared for itself.
//
// Not applied when the message declared its own revision, which is the matched-pair case and
// the normal one: a conforming peer on a declaring revision states its version every time.
//
// Nor when the pair is MISMATCHED and the message translates. The gap this closes is a host on
// the SAME declaring revision as the leg that inherited its declaration from the context
// instead of restating it — eunox forwards those params verbatim, so nothing supplies the
// member. On a mismatched pair translateRequest adds it, so refusing here would refuse a
// message eunox is about to make conforming, and would do it under a code that tells the host
// to add a member its own revision does not have.
func checkDeclarationReachesUpstream(resolved, legRev capability.Revision, msg mcp.RPCMsg, declared bool) error {
	if declared || legRev == "" || msg.Method == "" {
		return nil
	}
	if !declaresPerRequestRevision(resolved) {
		return nil
	}
	if resolved != upstreamAddressedRevision(legRev) && boundaryDisposition(msg).translates {
		return nil
	}
	// The key is named from capability's own constant rather than spelled out: this text is
	// echoed to the peer verbatim (revisionRefusalReason allowlists it), and a message telling a
	// host which member to add is worthless if the spelling drifts from the one the decoder reads.
	return fmt.Errorf("%w: %s requires %s in every request's _meta, and eunox forwards params verbatim rather than adding one",
		errUndeclaredOnDeclaringLeg, resolved, capability.MetaKeyProtocolVersion)
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
//
// A MISMATCHED pair is no longer refused wholesale. Which messages such a pair may carry is
// the translation boundary's question (translate.go), asked per message because the answer is
// per method; what stays here is the refusal for the ones it will not carry, so a message that
// cannot cross is stopped at negotiation rather than at the upstream call it would otherwise
// reach. The call seam re-asks the same question, and deliberately: that is where the bytes
// actually cross, and a gate that runs only at negotiation would be one refactor away from
// being bypassed by a path that reaches the upstream another way.
func checkUpstreamHonorable(resolved, legRev capability.Revision, msg mcp.RPCMsg) error {
	if legRev == "" {
		return nil
	}
	addressed := upstreamAddressedRevision(legRev)
	if resolved == addressed {
		return nil
	}
	if decl := boundaryDisposition(msg); !decl.translates {
		return refuseAcrossRevisions(msg.Method, resolved, addressed, decl.why)
	}
	return nil
}

// revisionRefusalReason turns a resolveHostRevision error into the host-facing message for
// the -32022 refusal. It names the failure class and the revision the peer declared (which
// the peer sent and which is bounded by having been matched against a closed set), never any
// other caller-supplied value.
func revisionRefusalReason(err error) string {
	// One condition, not an arm per sentinel: what this function protects is the ALLOWLIST of
	// errors whose text is safe to echo, and all of these are (each names the failure class and
	// at most version strings — the peer's own, already matched against a closed set, and this
	// proxy's own leg revisions). Anything else collapses to a fixed string rather than leaking
	// an unreviewed message.
	if errors.Is(err, errRevisionMismatch) || errors.Is(err, mcp.ErrUnknownRevision) ||
		errors.Is(err, mcp.ErrConflictingRevision) || errors.Is(err, errUntranslatableAcrossRevisions) ||
		errors.Is(err, errUndecodableForwardedParams) || errors.Is(err, errUndeclaredOnDeclaringLeg) {
		return err.Error()
	}
	return "protocol revision could not be established"
}

// revisionRefusalCode picks the symbolic code a revision refusal is recorded under.
//
// Two codes, because the tape has to separate two different operator problems that share one
// wire integer: a revision that could not be ESTABLISHED for one peer, and a PAIR of
// established revisions that cannot carry this message. The first is a misconfigured or
// probing client; the second is a deployment mid-migration hitting the translation boundary,
// and it is the one an operator greps for when deciding whether an upgrade is safe to finish.
//
// Keyed on the sentinel rather than on the text, so the two cannot drift as the messages are
// reworded. Anything else keeps the establish-a-revision code, which is what every refusal
// here meant before the boundary existed.
func revisionRefusalCode(err error) string {
	if errors.Is(err, errUntranslatableAcrossRevisions) {
		return capability.ErrCodeUntranslatableAcrossRevisions
	}
	return capability.ErrCodeUnsupportedProtocolVersion
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
		rec.RecordDeny(ctx, sessionID, identifier, method, revisionRefusalCode(err), "", nil, false)
	}
	if !msg.IsRequest() {
		return mcp.RPCMsg{}
	}
	// The same code the record carries: a host branching on `data.code` and a SIEM rule reading
	// the tape must not be told two different things about one refusal.
	return mcp.RevisionRefusalResponse(msg.ID, revisionRefusalCode(err), reason)
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
