// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Shared request dispatch: the single method→handler mapping and fail-closed
// default both transports route enforced MCP requests through.
//
// # Gate order
//
// The cross-cutting gates every host message passes are ordered ONCE, here, rather than
// re-derived at each transport's prologue. Both transports inherit it: the head of the order
// by calling hostMessageGate.negotiate (in revision.go), the notification framing by
// hostNotificationGate.admit, the request framing by dispatchRequest.
//
// The head and the tail are shared; the MIDDLE is deliberately not one prologue. Revocation
// cannot be hoisted beside negotiation for the request framing, because that check must be
// taken FRESH after the decision turn — a kill landing during an unbounded wait has to be
// recorded as KILL_SWITCH rather than as the method's own refusal, and a prologue-level answer
// would be the stale one. So the request framing takes it inside dispatchRequest and
// enforcedForwardCore, and the notification framing — which waits for nothing — takes it in
// hostNotificationGate. See hostMessageGate's doc for what the two transports still hold of
// their own, and why.
//
//  1. REVISION negotiation (resolveHostRevision / refuseHostRevision). First, because every
//     table below is revision-scoped: a message whose revision cannot be established has no
//     table to be looked up in. Its one cost is a labelling exception — a revoked session's
//     bad-version probe is recorded as UNSUPPORTED_PROTOCOL_VERSION rather than KILL_SWITCH,
//     on a message refused either way that contacts no upstream and mutates no state.
//     Negotiation is also what stamps the revision onto the context every later gate records
//     under, so a gate placed ahead of it would write a record naming no revision at all. ONE
//     gate is deliberately ahead of it and therefore records no revision: HTTP's session-owner
//     binding, which decides whether the caller may act on this session at all and so must not
//     read the session's negotiated state first (see enforceSessionGates).
//  2. The SWALLOWED set (notification framing only): a method the proxy has already handled
//     is neither an error nor an event, so it is dropped before anything that would record it.
//     "Already handled" is a property of the LEG, not of the method: a pre-session arm has
//     completed no handshake, so nothing is swallowed there and the gates below still see the
//     message (hostNotificationGate.established).
//  3. REVOCATION (kill switch). Locally-answered requests share dispatchRequest's boundary
//     gate; Decide* requests carry their own richer record inside enforcedForwardCore;
//     notifications take it from hostNotificationGate.
//  4. FAIL-CLOSED routing: enforced-method-as-notification smuggling, then the unmapped
//     default (dispatchUnmapped / notifyUnmapped).
//
// The order and its exception are pinned by TestGateOrder_* in gate_order_test.go, so a
// reordered prologue fails a test rather than silently changing which code a revoked
// session's probes are recorded under.

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// dispatchParams bundles everything the per-method enforced handlers need, independent of
// transport (HTTP fills it from sess.route + session; stdio from the proxy itself).
//
// pdp is never nil: every production constructor substitutes a concrete PDP (DenyAllPDP is the
// fail-closed "no policy" default), so every handler may dereference d.pdp directly.
type dispatchParams struct {
	forwardParams
	// pdp is the decision point every handler decides with AND the committer handed to
	// enforcedForwardCore for a declassification's clear — one field, not two kept in sync.
	pdp      pdp.PolicyDecisionPoint
	sourceIP string
	// buildInit answers a host `initialize` locally, injected per-transport so initialize can
	// flow through dispatchRequest like every other method — the response differs, the kill
	// gate does not. nil only in tests; fails closed if unset.
	buildInit func(mcp.RPCMsg) mcp.RPCMsg

	// receipts verifies a tool result's signed effect receipt against this upstream's
	// configured key domain. nil (the default) skips the whole surface entirely.
	receipts *capability.EffectReceiptVerifier

	// honorAttribution admits the client-supplied attribution interface (_meta's
	// io.eunolabs.context-manifest block), gated on the route's schemaVersion since the
	// manifest-side grammar gate can't cover a token that arrives on a REQUEST. False means
	// ignored (union-only, so falling back to the session join is the stricter reading).
	honorAttribution bool
}

// finishDecision closes the decision critical section (if open) right after the PDP decision
// and before the forward. One exception: a declassifying call keeps the turn until the
// handler returns, because its flow-state write splits across the decision (resolves what to
// clear) and the post-forward commit (removes it) — releasing early would let a concurrent
// source land between the two and commit a fresh taint the commit then wrongly clears.
//
// Cost: head-of-line blocking on the anchor for one declassifying call, bounded by
// --upstream-timeout (unbounded at 0). Paid only by calls that actually declassify; both
// transports also defer this same idempotent release as a backstop.
func (d dispatchParams) finishDecision(dec capability.EnforceResponse) {
	if d.endDecision == nil || dec.Declassification.PendingClear() {
		return
	}
	d.endDecision()
}

// killDenied runs the kill-switch check for a locally-answered method (Decide* methods embed
// their own richer kill record via enforcedForwardCore). Applied once at the dispatchRequest
// boundary so a new locally-answered method inherits revocation by construction; malformedDeny
// is the one other caller, reached before the PDP.
//
// The lookup is FRESH, never a value the transport leg resolved earlier for the same message:
// this gate can be reached after an unbounded wait for the decision turn, and the whole point
// of it is that a kill landing during that wait is recorded as KILL_SWITCH rather than as the
// method's own refusal.
func (d dispatchParams) killDenied(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, bool) {
	if deny := d.pdp.CheckKill(ctx, d.sessionID); deny != nil {
		return recordKillDenial(ctx, d.rec, deny, msg.ID, verifiedSession(d.sessionID), msg.Method), true
	}
	return mcp.RPCMsg{}, false
}

// decideCtx applies the audit-mode quota skip: in observe mode MaxCalls is skipped
// (WithSkipQuota) so the observed call consumes none; sequenceBlock/history are unaffected.
func (d dispatchParams) decideCtx(ctx context.Context) context.Context {
	if d.audit {
		return enforcement.WithSkipQuota(ctx)
	}
	return ctx
}

// methodHandler is the shape every dispatched request handler shares.
type methodHandler func(context.Context, dispatchParams, mcp.RPCMsg) mcp.RPCMsg

// notificationDisposition is what a transport does with the NOTIFICATION framing of a
// method. The zero value is the fail-closed one: dropped and recorded.
type notificationDisposition int

const (
	// notifyUnmapped drops and records the notification (denyUnmappedHostNotification), the
	// notification-framed analogue of dispatchUnmapped's default.
	notifyUnmapped notificationDisposition = iota
	// notifyForward forwards the notification to the upstream verbatim.
	notifyForward
	// notifySwallow drops the notification silently, with no record: the proxy already
	// handled the thing it announces, so it is neither an error nor an event.
	notifySwallow
)

// methodSpec is ONE method's whole declaration: the revisions it exists in, how its request
// framing is dispatched, and what happens to its notification framing. The four routing
// tables are DERIVED from these (buildRevisionDispatch), so a method's revision membership
// is stated once rather than mirrored into four maps that can silently disagree — the
// pattern pkg/capability's tokenSpec already uses for grammar revisions.
//
// Removal across revisions is expressed by ABSENCE from In: a method outside the requesting
// peer's tables falls to dispatchUnmapped exactly as an unknown method does, so there is no
// second removal mechanism to keep in step with the first.
// The request handler is declared as one of TWO typed fields rather than a handler paired
// with an "is it enforced" flag: the flag made `enforced, no handler` representable, an
// invalid state a registry test had to reject by hand. Which field carries the handler IS
// the classification, so isEnforcedMethod and "which handler runs" cannot diverge.
type methodSpec struct {
	// In lists the revisions this method exists in. An entry declaring none is refused by
	// buildRevisionDispatch (dispatched under no revision) and fails
	// TestMethodRegistry_EveryMethodDeclaresRevisionMembership.
	In []capability.Revision
	// Decide answers the request framing through the PDP: it carries its own richer kill
	// record inside enforcedForwardCore and takes the decision turn.
	Decide methodHandler
	// Local answers the request framing inside the proxy, under dispatchRequest's boundary
	// kill gate. Setting it alongside Decide is refused by
	// TestMethodRegistry_EveryMethodDeclaresRevisionMembership.
	Local methodHandler
	// Notification is the disposition of this method's notification framing.
	Notification notificationDisposition
	// LocalForwards declares that this method's LOCAL handler sends the host's own params to
	// the upstream — the */list methods, whose handler forwards the request and filters the
	// reply. The only half of forwardsHostParams the other fields cannot answer.
	LocalForwards bool
}

// paramsReachUpstream reports whether msg's own params travel to the upstream verbatim — the
// fact the message's revision has to be honorable for, since a declaration only manufactures a
// mismatched pair when it actually rides beside the MCP-Protocol-Version header this proxy
// stamps.
//
// Asked per FRAMING, with the method lookup as only one of its arms. A host RESPONSE carries no
// method, so a method-keyed gate misses it entirely — and a response is the one framing whose
// bytes are relayed to the upstream with no dispatch decision at all (the serve loops write it
// straight through), `_meta` declaration included. That is the same per-method vs per-framing
// split dispatchesMessage draws for the pin.
//
// A response is therefore allowed to CARRY a declaration and is held to it, rather than having
// one forbidden outright. Forbidding it would be a second rule to keep in step with the
// mismatch check that already governs every other framing — and it is that check, not a ban,
// that a reply to a proxy-issued request needs: the revision it declares must be the one its
// context negotiated, and one this proxy can honor on the leg the bytes are about to enter.
func paramsReachUpstream(msg mcp.RPCMsg) bool {
	if msg.IsResponse() {
		return true
	}
	return forwardsHostParams(msg.Method)
}

// unreadParamsReachUpstream narrows paramsReachUpstream to the messages whose bytes travel on
// with NOTHING in this proxy re-decoding them first — the exact class for which
// mcp.DeclaredRevision's "the method handler denies these bytes moments later" argument does
// not hold, and therefore the class an unreadable body may not be read as an undeclared one.
//
// A request routed to a Decide handler is the one message that argument covers: the handler
// runs mcp.DecodeParams over the same bytes and answers a target-bearing malformedDeny. Three
// shapes it does not, and the registry cannot merge them because two are not per-method facts
// at all: a host RESPONSE (relayed verbatim, never dispatched), a notifyForward NOTIFICATION,
// and a LocalForwards REQUEST — the */list methods, whose handler hands msg to the upstream
// untouched and filters only the reply.
//
// DERIVED from paramsReachUpstream so it can never claim a message that gate does not, then
// narrowed by FRAMING within it. The narrowing is load-bearing rather than tidiness: that gate
// asks its per-method half as one OR over the three handler fields, so it reports true for a
// Decide method in notification framing and for a notifyForward method in request framing —
// two pairings this proxy REFUSES rather than forwards, whose bytes therefore reach nobody to
// disagree with.
func unreadParamsReachUpstream(msg mcp.RPCMsg) bool {
	if !paramsReachUpstream(msg) {
		return false
	}
	if msg.IsResponse() {
		return true
	}
	spec := methodRegistry[msg.Method]
	if msg.IsRequest() {
		return spec.Decide == nil && spec.LocalForwards
	}
	return spec.Notification == notifyForward
}

// forwardsHostParams reports whether method's own params reach the upstream, in either
// framing — the per-METHOD half of paramsReachUpstream, which is the question a request or a
// notification answers and the wrong shape for a message with no method.
//
// DERIVED from the handler fields rather than declared per method: a Decide entry added
// without a hand-set flag would still dispatch and still forward with this gate silently off,
// caught only by a registry test someone had to remember to write.
//
// Revision-independent on purpose: a method outside the peer's revision is denied before it
// could forward anything, so the question is about the METHOD, not the table.
func forwardsHostParams(method string) bool {
	spec, known := methodRegistry[method]
	if !known {
		return false
	}
	return spec.Decide != nil || spec.LocalForwards || spec.Notification == notifyForward
}

// handler returns the method's request handler and whether it is the enforced (Decide*) one.
// Nil for a notification-only method.
func (s methodSpec) handler() (methodHandler, bool) {
	if s.Decide != nil {
		return s.Decide, true
	}
	return s.Local, false
}

// methodNotificationsProgress and methodNotificationsRootsListChanged are notification
// methods with no request framing; defined here since nothing else in the package
// references them.
const (
	methodNotificationsProgress         = "notifications/progress"
	methodNotificationsRootsListChanged = "notifications/roots/list_changed"
)

// methodRegistry is the single source of truth for what eunox dispatches, per revision.
//
// The 2026-07-28 entries describe that revision's method set as the spec defines it; the
// methods it ADDS (server/discover, subscriptions/listen, tasks/*) are deliberately absent
// until each one's responder is implemented, so they deny fail-closed meanwhile rather than
// routing to a handler that does not exist.
var methodRegistry = map[string]methodSpec{
	// Enforced (Decide*) methods. The resources/subscribe pair is 2025-11-25 only:
	// 2026-07-28 replaces it with subscriptions/listen, which is not implemented yet.
	capability.MethodToolsCall: {
		In:     []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Decide: dispatchToolsCall,
	},
	capability.MethodResourcesRead: {
		In:     []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Decide: dispatchResourcesRead,
	},
	capability.MethodResourcesSubscribe: {
		In:     []capability.Revision{capability.Revision20251125},
		Decide: dispatchResourcesSubscribe,
	},
	capability.MethodResourcesUnsubscribe: {
		In:     []capability.Revision{capability.Revision20251125},
		Decide: dispatchResourcesUnsubscribe,
	},
	capability.MethodPromptsGet: {
		In:     []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Decide: dispatchPromptsGet,
	},

	// Locally answered methods. initialize and ping are handshake/utility methods
	// 2026-07-28 removes; the three */list methods exist in both revisions.
	mcp.MethodInitialize: {
		In:    []capability.Revision{capability.Revision20251125},
		Local: dispatchInitialize,
		// "initialize" can arrive with no id (a notification by IsNotification's structural
		// classification); forwarding it verbatim would re-trigger the upstream handshake
		// outside the kill gate, so the notification framing is swallowed.
		Notification: notifySwallow,
	},
	methodPing: {
		In: []capability.Revision{capability.Revision20251125},
		Local: func(_ context.Context, _ dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
			return dispatchPing(msg)
		},
	},
	capability.MethodResourcesList: {
		In: []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Local: func(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
			return dispatchList(ctx, d, msg, pdp.ListFilterer.FilterResourcesList)
		},
		LocalForwards: true,
	},
	capability.MethodToolsList: {
		In: []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Local: func(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
			return dispatchList(ctx, d, msg, pdp.ListFilterer.FilterToolsList)
		},
		LocalForwards: true,
	},
	capability.MethodPromptsList: {
		In: []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Local: func(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
			return dispatchList(ctx, d, msg, pdp.ListFilterer.FilterPromptsList)
		},
		LocalForwards: true,
	},

	// Notification-only methods. notifications/initialized closes a handshake 2026-07-28
	// does not have; roots/list_changed announces a capability it deprecates.
	mcp.MethodNotificationsInitialized: {
		In: []capability.Revision{capability.Revision20251125},
		// The proxy already sent its own during its upstream handshake.
		Notification: notifySwallow,
	},
	methodNotificationsCancelled: {
		In:           []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Notification: notifyForward,
	},
	methodNotificationsProgress: {
		In:           []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Notification: notifyForward,
	},
	methodNotificationsRootsListChanged: {
		In:           []capability.Revision{capability.Revision20251125},
		Notification: notifyForward,
	},
}

// revisionTables is one revision's derived routing tables — the shape the dispatcher and the
// two transports actually consult.
//
// The notification dispositions are ONE map rather than a set-map per disposition: two
// mutually-exclusive sets could both claim a method, and the fail-closed notifyUnmapped came
// from neither of them. As a single map it is the zero value, so a method with no entry
// falls to it by construction.
type revisionTables struct {
	decide        map[string]methodHandler
	local         map[string]methodHandler
	notifications map[string]notificationDisposition
}

// request resolves method's REQUEST framing: the handler these tables hold for it, whether that
// handler is the enforced (Decide*) one, and whether either table holds it at all.
//
// THE walk, in one place. dispatchRequest, isEnforcedMethod and the stdio pin's predicate each
// used to spell it out, so "the proxy acted on this message" and "this message decided which
// revision the connection speaks" agreed by review — the shape a third table or a new fallback
// silently breaks.
//
// It returns the enforced FLAG rather than dispatching, because dispatchRequest interposes the
// kill gate BETWEEN the two tables: an enforced method carries its own richer kill record inside
// enforcedForwardCore, a locally-answered one takes the boundary gate first. A helper that
// returned just "the handler" could not preserve that placement.
//
// A nil handler IS the not-found answer — buildRevisionDispatch never stores one — so there is
// no third return to get out of step with the first, the same shape methodSpec.handler uses.
func (t revisionTables) request(method string) (handler methodHandler, enforced bool) {
	if decided, found := t.decide[method]; found {
		return decided, true
	}
	return t.local[method], false
}

// enforces reports whether method's REQUEST framing is PDP-decided under these tables. A direct
// probe of the ONE table that answers it, not a call to request: this is a single-table
// question, and routing it through the two-table walk cost every notification the gate admits a
// second lookup for a method the first table already said nothing about.
func (t revisionTables) enforces(method string) bool {
	_, ok := t.decide[method]
	return ok
}

// notification resolves method's NOTIFICATION framing: its disposition and whether one is
// stored. Presence IS the "the proxy acts on it" test — notifyUnmapped is the map's zero value
// and is never stored, so an entry exists exactly for a disposition the proxy acts on, by
// forwarding it or by swallowing something it has already handled.
func (t revisionTables) notification(method string) (notificationDisposition, bool) {
	disposition, ok := t.notifications[method]
	return disposition, ok
}

// revisionDispatch holds the per-revision tables derived from methodRegistry at init.
var revisionDispatch = buildRevisionDispatch(methodRegistry)

// buildRevisionDispatch derives each published revision's four routing tables from the
// declarations. An entry that declares no revision, or names one this build does not speak,
// contributes to no table at all — it is dispatched nowhere and falls to the fail-closed
// default, the same outcome as never having been declared. That silence is intentional
// (production must not panic on a data slip) and is what the derivation test converts into a
// build failure.
func buildRevisionDispatch(registry map[string]methodSpec) map[capability.Revision]revisionTables {
	out := make(map[capability.Revision]revisionTables, len(capability.PublishedRevisions()))
	for _, rev := range capability.PublishedRevisions() {
		out[rev] = revisionTables{
			decide:        map[string]methodHandler{},
			local:         map[string]methodHandler{},
			notifications: map[string]notificationDisposition{},
		}
	}
	for method, spec := range registry {
		for _, rev := range spec.In {
			tables, ok := out[rev]
			if !ok {
				continue // a revision this build does not speak: contribute nothing
			}
			if handler, enforced := spec.handler(); handler != nil {
				if enforced {
					tables.decide[method] = handler
				} else {
					tables.local[method] = handler
				}
			}
			// notifyUnmapped is left absent deliberately: it is the map's zero value, so the
			// fail-closed default needs no entry to be reached.
			if spec.Notification != notifyUnmapped {
				tables.notifications[method] = spec.Notification
			}
		}
	}
	return out
}

// handshakeRevision is the revision whose method set contains `initialize` — the one place
// "the handshake exists only in the older revision" is written down for this package, DERIVED
// from methodRegistry rather than restated at each site that opens, answers, or version-stamps
// a handshake. A registry that stops declaring exactly one revision for `initialize` falls back
// to the shipped default here (production must not panic on a data slip) and fails
// TestHandshakeRevision_DerivedFromTheRegistry.
//
// capability.HandshakeRevision() is the same fact for the layers that may not import this
// package (the config loader refusing an unmatchable pin). The derivation stays here so the
// registry remains the operational source; the test asserts the two agree.
var handshakeRevision = deriveHandshakeRevision(methodRegistry)

func deriveHandshakeRevision(registry map[string]methodSpec) capability.Revision {
	if spec, ok := registry[mcp.MethodInitialize]; ok && len(spec.In) == 1 {
		return spec.In[0]
	}
	return capability.DefaultRevision
}

// unroutableReason classifies WHY nothing could route a message the fail-closed default is
// about to drop. Per METHOD crossed with the framing, deliberately: a method the peer's revision
// has is not "removed" merely because it arrived in a framing that revision does not dispatch,
// and an operator reading a wiretap tape needs those apart. What the record may NAME is a
// separate question, answered by auditIdentity for every no-policy-decision refusal alike.
func unroutableReason(rev capability.Revision, method string) string {
	spec, known := methodRegistry[method]
	switch {
	case !known:
		return audit.UnroutableUnknownMethod
	case !slices.Contains(spec.In, rev):
		return audit.UnroutableRemovedInRevision
	default:
		return audit.UnroutableFramingUnmapped
	}
}

// unroutableDetail builds the reserved marker naming a routing refusal as eunox's own.
//
// The refusal's own code (UNROUTABLE_METHOD) is what says WHOSE refusal it is, and its class is
// what keeps an observing route from downgrading it; the marker adds the part a code cannot
// carry — WHICH of the three ways the message was unroutable, and the revision the tables were
// consulted for. It rides every one of these records rather than only an --audit route's,
// because "the peer's revision removed this method" is the same diagnosis either way.
func unroutableDetail(rev capability.Revision, reason string) map[string]interface{} {
	return map[string]interface{}{
		audit.UnroutableKey: map[string]interface{}{"reason": reason, "revision": rev.String()},
	}
}

// dispatchesMessage reports whether rev's routing tables hold a handler for msg IN THE FRAMING
// IT ARRIVED IN — through the SAME lookup methods dispatchRequest and hostNotificationGate.admit
// call one gate later, so "the proxy acted on this message" and whatever this predicate is used
// to conclude cannot disagree. Sharing the lookup is what makes that structural rather than a
// claim; TestDispatchesMessage_MatchesWhatTheDispatcherActuallyDoes drives both and compares.
//
// It is the stdio context PIN's predicate. A message about to be dropped by the fail-closed
// default says nothing about which revision a conversation is on, and latching from one wedges
// the connection for the process's life; the same fact, phrased per METHOD instead, does not
// close that class. `notifications/progress` exists in both revisions with a forwarding
// disposition and NO request handler, so a REQUEST-framed one satisfies "the revision has this
// method", pins from it, and is then discarded by dispatchUnmapped — a message nothing acted on
// deciding what the peer speaks.
//
// Framings are answered exhaustively rather than by falling through: a message that is neither
// framing (a RESPONSE to a request this proxy issued) is dispatched by neither table and carries
// no method to look up, so it pins nothing.
func dispatchesMessage(rev capability.Revision, msg mcp.RPCMsg) bool {
	tables := tablesFor(rev)
	switch {
	case msg.IsRequest():
		handler, _ := tables.request(msg.Method)
		return handler != nil
	case msg.IsNotification():
		_, ok := tables.notification(msg.Method)
		return ok
	default:
		return false
	}
}

// requestRevision returns the revision this request is dispatched under, read from the ONE
// carrier: the context the transports stamp at negotiation, which is also where the audit
// sink reads protocol_revision from.
//
// It is deliberately not ALSO a field on dispatchParams. Two carriers threaded by hand from
// the same local variable had opposite zero-value semantics — the field resolved to
// DefaultRevision, the context omitted the field entirely — so any entry point that threaded
// one and forgot the other wrote a record claiming no revision was decided for a request the
// dispatcher decided under 2025-11-25. That is the same argument
// enforcement.ResolveStateAnchor makes for the state anchor: a second reading of the same
// question is where the two silently diverge.
//
// A context that carries no revision resolves to capability.DefaultRevision — the surface
// eunox already shipped, so omission can never reach a different method set. Every dispatch
// decision reads that fallback HERE, so no two of them can resolve the empty carrier
// differently. The audit sink's omission is not a third reading of the same question: it
// records what was negotiated, and "nothing was" is a fact a pre-negotiation refusal needs to
// be able to state.
//
// Refusing here instead — turning "an entry point forgot to negotiate" into a runtime denial —
// was weighed and declined: the gate-order source guard already holds that at build time, and a
// refusal would need a distinguished "no peer to negotiate with" value for the legitimately
// non-negotiating arms, which is the second carrier of one fact this seam exists to remove.
func requestRevision(ctx context.Context) capability.Revision {
	return resolveRevision(capability.ProtocolRevisionFromContext(ctx))
}

// resolveRevision applies the empty-carrier rule ONCE, for every leg that has to decide what an
// unresolved revision means: the surface eunox already shipped.
//
// Named rather than inlined into requestRevision because the server-initiated leg asks it of a
// value rather than of a context — it has no host request in scope, so it is handed the
// session's pin as a fact. Answering it there by hand is how that leg came to record "nothing
// was negotiated" for a session whose host-leg records name a revision: the two are the same
// question, and a second reading of it is where they diverge.
func resolveRevision(rev capability.Revision) capability.Revision {
	if rev != "" {
		return rev
	}
	return capability.DefaultRevision
}

// tablesFromContext returns the routing tables for the revision the request was negotiated
// under. Re-derived from the single carrier at each lookup rather than resolved once and
// passed alongside it: a carried copy is exactly the second carrier this seam exists to
// remove. The cost is one map lookup per dispatch decision — two per enforced request, since
// the transports ask isEnforcedMethod before dispatching one.
func tablesFromContext(ctx context.Context) revisionTables {
	return tablesFor(requestRevision(ctx))
}

// tablesFor returns the routing tables for rev.
//
// The zero Revision resolves to capability.DefaultRevision: a dispatchParams built without
// an explicit revision is a caller that never negotiated one, and the old revision is the
// surface eunox already shipped. An unknown non-empty revision resolves to EMPTY tables
// instead — it was declared and cannot be honored, so every method falls to the fail-closed
// default rather than borrowing another revision's set.
func tablesFor(rev capability.Revision) revisionTables {
	return revisionDispatch[resolveRevision(rev)]
}

// isEnforcedMethod reports whether method is one of the request's revision's Decide* methods,
// derived from the same declarations dispatchRequest routes by so the two cannot drift.
func isEnforcedMethod(ctx context.Context, method string) bool {
	return tablesFromContext(ctx).enforces(method)
}

// hostNotificationGate is the per-transport wiring the shared notification gate needs. The
// gate itself — which checks run, and in what order — is not per-transport; see the package
// gate order at the top of this file.
type hostNotificationGate struct {
	// recorders resolves the recorder for a refusal in ONE category, lazily — for the reason a
	// thunk was needed at all (a pre-session leg's recorder is drawn from a rate-limit bucket, so
	// resolving it for a message that records nothing spends a token on nothing, and an
	// unauthenticated peer sends those at will), and per CATEGORY because this gate's three
	// recording arms disagree about metering. A single per-leg thunk handed the metered kill
	// recorder to the two arms whose categories are DECLARED exempt, so an exemption on the record
	// charged a bucket anyway — and charged catKill, the one bounding the records an emergency
	// stop depends on. See refusalRecorders.
	recorders refusalRecorders
	// subject names WHOSE session a record describes and whether this proxy can vouch for the
	// name: a leg with a session supplies the id it established, a pre-session one the id the
	// client claimed. See killSubject.
	subject killSubject
	// established says this leg has completed its handshake, which is what makes the
	// swallowed set apply to it. Its zero value costs a revocation lookup on a message that
	// would otherwise be dropped for free — the direction that records more, not less.
	established bool
	// audit is this leg's route posture (--audit / a route with no policy), carried so the
	// routing refusal reaches the shared deny path with the real posture rather than a constant.
	// It changes nothing today — that refusal's code classifies as a fault, so it is not
	// downgradable whoever asks — which is exactly why it must be the real value: a hardcoded
	// false would make the notification-framed observe-mode regression pass by construction
	// instead of by the property it exists to hold.
	audit bool
	// strictAudit is the --require-audit=strict state this leg's transport holds, carried for the
	// same reason `audit` is: the routing refusal reaches the shared deny path through this gate,
	// and a zero value here would give the notification framing a different audit posture from the
	// identical bytes in request framing.
	strictAudit strictAuditState
	// checkKill is a thunk, not a value, so the swallowed set costs no revocation lookup: on
	// a Redis-backed kill switch that lookup can be a network round trip, and a swallowed
	// notification is dropped before revocation is even a question.
	//
	// A thunk only saves what its supplier has not already spent, and the HTTP session leg used
	// to resolve the answer eagerly and hand over a constant — so this saving was real on stdio
	// alone. Both legs now supply a lazy lookup, and
	// TestSessionLeg_RevocationIsLookedUpAtMostOncePerPost counts it rather than leaving the
	// claim to the comment. Never nil: every gate below calls it unconditionally.
	checkKill func() *capability.EnforceResponse
	// leg names this transport's notification leg in a kill-drop record.
	leg transportLeg
}

// notificationOutcome is what the shared gate DID with a notification. Three outcomes, not a
// bool, because a transport needs more than "may I forward it": whether the proxy ENGAGED with
// the message at all is a separate question, and the answer differs for the two ways a
// notification is dropped. The swallowed set is dropped for free — no record, no revocation
// lookup — while a refusal writes to the tamper-evident tape, which is work done on the
// session's behalf.
type notificationOutcome int

const (
	// notificationSwallowed: dropped for free. The proxy had already handled what it announces,
	// so it is neither an error nor an event, and nothing about the session's liveness follows.
	notificationSwallowed notificationOutcome = iota
	// notificationRefused: dropped WITH its record — revoked, an enforced method smuggled as a
	// notification, or unmapped.
	notificationRefused
	// notificationForward: admitted for verbatim forwarding to the upstream.
	notificationForward
)

// admit applies every cross-cutting gate a host->upstream notification passes, in the one
// canonical order, and reports what it did with it. Anything but notificationForward means the
// gate has already disposed of the notification and the caller need only ack.
//
// Shared by both transports so the checks, their order, and their audit records cannot drift
// between them; before it existed each transport hand-placed the same four steps. It also
// resolves the revision's tables ONCE, where the three separate predicates it replaces each
// resolved their own.
func (g hostNotificationGate) admit(ctx context.Context, msg mcp.RPCMsg) notificationOutcome {
	tables := tablesFromContext(ctx)
	disposition, _ := tables.notification(msg.Method)
	swallowed := disposition == notifySwallow
	// The swallowed set is what the proxy has ALREADY handled, so it is neither an error nor
	// an event and is dropped before anything that would record it. That reasoning needs the
	// proxy to have handled it: on a leg with no session it has not, and an id-less
	// `initialize` arriving during an emergency stop is precisely the attempt an operator
	// needs on the tape rather than a silent readiness ack.
	if swallowed && g.established {
		return notificationSwallowed
	}
	if kill := g.checkKill(); kill != nil {
		recordKillDrop(ctx, g.recorders.forCategory(catKill), kill, g.subject, msg.Method, msg.Method, g.leg)
		return notificationRefused
	}
	if swallowed {
		// Pre-session, and revocation had nothing to say: there is no upstream to forward to
		// and nothing the later arms could add, so the drop is the whole disposition.
		return notificationSwallowed
	}
	// An enforced method framed as a notification (no id) is a fail-closed reject: forwarding
	// it verbatim would bypass both the PDP decision and the audit record.
	if tables.enforces(msg.Method) {
		// Unmetered by DECLARATION (catSmuggled), not by omission — and named to the resolver, so
		// the declaration is what decides rather than whichever recorder this leg happened to
		// build. See refusalDeclarations and refusalRecorders.
		if rec := g.recorders.forCategory(catSmuggled); rec != nil {
			// auditIdentity for the same reason its siblings use it: every enforced method
			// resolves a target type, so naming one here fabricates a policy target for a
			// message the PDP never saw.
			identifier, method := auditIdentity(msg)
			rec.RecordDeny(ctx, g.subject.auditSessionID(), identifier, method, codeInvalidRequest, "", g.subject.auditDetails(nil), false)
		}
		return notificationRefused
	}
	if disposition == notifyForward {
		return notificationForward
	}
	// notifyUnmapped, the notification-framed analogue of dispatchUnmapped — the SAME producer
	// now, not an analogue of it. Before either existed, an unrecognized notification-framed
	// method reached the upstream invisibly while its request-framed twin was denied and logged.
	//
	// The framing carries the fact that there is no reply channel here, so the core builds no
	// denial message to throw away (JSON-RPC forbids replying to a notification, and the caller
	// acks). What is not skipped is everything else the shared path owns — the observe gate, the
	// strict-audit gate and the record shape.
	refuseUnroutable(ctx, refusalForwardParams(g.subject, g.audit, g.strictAudit), g.recorders, g.subject, msg, unroutableFramingNotification)
	return notificationRefused
}

// dispatchRequest routes an enforced MCP request to its handler and returns the JSON-RPC
// message to deliver to the host — the single source of truth for the method→handler mapping
// and the fail-closed default both transports share.
//
// The kill gate is applied STRUCTURALLY: Decide* methods embed their own richer kill record
// inside enforcedForwardCore and skip the boundary gate; every other (locally-answered) method
// shares one simple gate applied here, so a new locally-answered method inherits revocation by
// construction rather than needing killDenied re-placed inside its handler. Its position
// relative to revision negotiation is the package gate order at the top of this file.
func dispatchRequest(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) (reply mcp.RPCMsg) {
	// The same no-reply-channel rule enforcedForwardCore applies at its own boundary, applied at
	// THIS one too, because the two boundaries cover different exits: the core is also reached from
	// the notification gate (refuseUnroutable), which never passes through here, while the
	// locally-answered set below never passes through the core — and `ID` carries `omitempty`, so
	// an id-less ping or re-initialize returns `{"jsonrpc":"2.0","result":{}}`, a response to a
	// message JSON-RPC forbids answering. Unreachable while both transports gate on IsRequest.
	defer func() {
		if msg.ID == nil {
			reply = mcp.RPCMsg{}
		}
	}()
	handler, enforced := tablesFromContext(ctx).request(msg.Method)
	if enforced {
		return handler(ctx, d, msg)
	}

	// Locally-answered set shares one simple kill gate applied once here. A killed session is
	// recorded as KILL_SWITCH (not the method's own code) and never contacts the upstream. It
	// sits BETWEEN the two tables, which is why revisionTables.request reports which one hit
	// rather than just dispatching.
	if resp, killed := d.killDenied(ctx, msg); killed {
		return resp
	}
	if handler != nil {
		return handler(ctx, d, msg)
	}
	return dispatchUnmapped(ctx, d, msg)
}

// methodPing is the MCP liveness probe, answered locally without contacting the upstream.
const methodPing = "ping"

// enforcedMethodSummary is the subset the audit-mode banner may claim as "forwarded and
// logged": only Decide* methods reach the upstream AND leave a decision record — initialize,
// ping, and */list do not (no record, or an enumeration event rather than a decision).
//
// Derived across ALL revisions, not one: the banner prints once at startup, before any peer
// has negotiated, so the honest claim is every method this build may enforce.
var enforcedMethodSummary = enforcedMethodNames()

// enforcedMethodNames joins every method this build may enforce under ANY revision, sorted so
// a map's iteration order cannot make the banner text unstable. Read straight off the
// declarations — the derived tables would give the same answer through an extra map.
func enforcedMethodNames() string {
	methods := make([]string, 0, len(methodRegistry))
	for method, spec := range methodRegistry {
		if spec.Decide != nil {
			methods = append(methods, method)
		}
	}
	sort.Strings(methods)
	return strings.Join(methods, ", ")
}

// unmappedMethodExamples names MCP methods this build does NOT dispatch, so the banner's
// caveat is concrete rather than abstract. They are examples, not an exhaustive list:
// anything outside the two routing tables is denied the same way.
const unmappedMethodExamples = "e.g. completion/complete, logging/setLevel, resources/templates/list"

// dispatchInitialize answers a host initialize by delegating to the per-transport buildInit
// responder. The shared kill gate runs at the dispatchRequest boundary (buildInit echoes
// capabilities without consulting the PDP), so this handler no longer self-gates. A missing
// buildInit (test misconfiguration) fails closed rather than nil-call panicking.
func dispatchInitialize(_ context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	if d.buildInit == nil {
		return mcp.ErrorResponse(msg.ID, jsonRPCCodeInternalError, "internal error: initialize responder not configured")
	}
	return d.buildInit(msg)
}

// dispatchPing answers the MCP utility ping locally with the spec's empty result: ping
// authorizes nothing, so falling through to dispatchUnmapped's refusal broke a liveness probe
// every host is entitled to send. Answered locally (not forwarded) so a ping
// can't probe upstream liveness through the proxy; the shared kill gate still applies, so a
// killed session gets KILL_SWITCH, not a pong. No audit record — a heartbeat, not a guarded
// action.
func dispatchPing(msg mcp.RPCMsg) mcp.RPCMsg {
	return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{}`)}
}

// malformedDeny records a fail-closed audit deny for an enforced request rejected BEFORE the
// PDP (unparseable params, empty target), so a probe with malformed input isn't invisible to
// an auditor. Uses codeInvalidRequest, not capability.ErrCodeInvalidParams — the real target
// never parsed, so IsInfraDenialCode lets suggest skip it rather than fabricate a phantom
// target like "tool:tools/call".
func (d dispatchParams) malformedDeny(ctx context.Context, msg mcp.RPCMsg, reason string) mcp.RPCMsg {
	// Kill gate FIRST: the malformed path is a Decide* method (skips the boundary gate) that's
	// rejected before the PDP (never reaches enforcedForwardCore's own check), so without this
	// a revoked session's malformed probe would be recorded as INVALID_REQUEST rather than
	// KILL_SWITCH.
	if resp, killed := d.killDenied(ctx, msg); killed {
		return resp
	}
	if d.rec != nil {
		d.rec.RecordDeny(ctx, d.sessionID, msg.Method, msg.Method, codeInvalidRequest, "", nil, false)
	}
	return mcp.ErrorResponse(msg.ID, jsonRPCCodeInvalidParams, reason)
}

// dispatchToolsCall applies the PDP to a tools/call request and either forwards
// to the upstream or returns a denial result.
func dispatchToolsCall(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	var params mcp.ToolCallParams
	if err := mcp.DecodeParams(msg.Params, &params); err != nil {
		return d.malformedDeny(ctx, msg, "invalid tools/call params")
	}
	if params.Name == "" {
		return d.malformedDeny(ctx, msg, "tools/call: name must not be empty")
	}
	if params.Arguments == nil {
		params.Arguments = map[string]interface{}{}
	}
	// The attribution interface: `_meta`'s labels union into the session's accumulated set.
	// A malformed block is a malformed REQUEST, not a silently ignored hint. Gated on
	// honorAttribution (the draft-schema staging discipline) so a 0.1 operator sees no change.
	decideCtx := d.decideCtx(ctx)
	if d.honorAttribution {
		declared, metaErr := capability.ParseContextManifest(params.Meta)
		if metaErr != nil {
			return d.malformedDeny(ctx, msg, "tools/call: "+metaErr.Error())
		}
		if declared != nil {
			decideCtx = pdp.WithDeclaredLabels(decideCtx, declared.Labels)
		}
	}
	dec := d.pdp.Decide(decideCtx, d.sessionID, pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: params.Name}, params.Arguments, d.sourceIP)
	// Close the decision critical section here so the forward below runs concurrently.
	// A declassification-authorizing decision keeps the turn instead; see finishDecision.
	d.finishDecision(dec)

	// In audit mode the allow record logs the full tool arguments; unlike resources/prompts,
	// tools/call's details slot holds that argument map rather than an upstream_error_code note.
	var toolDetails map[string]interface{}
	// Log arguments under route-level --audit OR a per-constraint enforcement:audit decision
	// (dec.AuditOnly) — guarding only on d.audit dropped the map for observe-mode constraints.
	if (d.audit || dec.AuditOnly) && len(params.Arguments) > 0 {
		toolDetails = quarantineReservedArgs(params.Arguments)
	}
	out := enforcedForwardCore(ctx, d.forwardParams, d.pdp, msg, dec, capability.MethodToolsCall, params.Name, params.Name, "tool", true,
		func(upResp mcp.RPCMsg) map[string]interface{} {
			// Record the upstream's forwarded error code so a rejected call isn't identical to
			// a clean success on the tape. Merges into a COPY of toolDetails — never mutates
			// the caller's live params.Arguments map. quarantineReservedArgs has already moved
			// every reserved name out, so nothing here can shadow a real argument.
			extra := upstreamErrorDetail(upResp)
			// The signed effect receipt, verified here so its verdict rides the SAME allow record
			// rather than a second one — a separate record double-counted allows in `eunox stats`
			// and let `eunox suggest` mine it as a fake argument map. nil costs nothing.
			receipt := d.effectReceiptDetail(upResp, dec, params.Name)
			if receipt != nil {
				if extra == nil {
					extra = make(map[string]interface{}, 1)
				}
				// One reserved, underscore-prefixed key so the verdict never flattens into the
				// argument map a miner reads. Written into the ANNOTATION map this closure owns,
				// never into mergeAuditDetails' return (whose contract is that it's the caller's).
				extra[audit.EffectReceiptKey] = receipt
			}
			return mergeAuditDetails(toolDetails, extra)
		})
	return out
}

// quarantineReservedArgs moves any key in eunox's reserved details namespace under a nested
// holder, so a caller-supplied argument can never forge a proxy annotation on the tape — e.g.
// spoofing the ATTENTION alert `eunox stats` prints for details._eunox_declassify_commit_failed.
// Quarantining (not dropping) keeps the record faithful: the argument was really sent.
func quarantineReservedArgs(args map[string]interface{}) map[string]interface{} {
	reserved := false
	for k := range args {
		if audit.IsReservedDetailKey(k) {
			reserved = true
			break
		}
	}
	if !reserved {
		return args
	}
	out := make(map[string]interface{}, len(args))
	quarantined := make(map[string]interface{})
	for k, v := range args {
		if audit.IsReservedDetailKey(k) {
			quarantined[k] = v
			continue
		}
		out[k] = v
	}
	out[audit.ReservedArgumentsKey] = quarantined
	return out
}

// effectReceiptDetail verifies the signed effect receipt an upstream published in the tool
// result's `_meta` and returns the structured verdict, or nil when there's nothing to record.
//
// POST-HOC by construction: the call has already run, so an inconsistency is evidence on the
// tape, never a late denial. Verification only — no server-egress watching or inference.
func (d dispatchParams) effectReceiptDetail(upResp mcp.RPCMsg, dec capability.EnforceResponse, tool string) map[string]interface{} {
	if d.receipts == nil || upResp.Result == nil {
		return nil
	}
	// A substring probe before the full decode: a tool result is the largest body on the wire
	// and almost none carry a receipt, so this avoids a whole JSON scan per call. A miss is
	// safe — it just reads as "no receipt".
	if !bytes.Contains(upResp.Result, []byte(capability.MetaKeyEffectReceipt)) {
		return nil
	}
	var meta struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(upResp.Result, &meta); err != nil || len(meta.Meta) == 0 {
		return nil
	}
	raw, present := capability.ParseEffectReceipt(meta.Meta)
	if !present {
		return nil
	}
	// Only an allow carries a resolved contract to check against. Observe-mode forwards are
	// included deliberately — the call ran, so it's worth the same scrutiny — Verify handles
	// having no declaration to compare against.
	result := d.receipts.Verify(raw, tool, dec.Effect, time.Now())
	if result == nil {
		return nil
	}
	if result.Verdict == capability.ReceiptInconsistent {
		// The one verdict that is a finding rather than bookkeeping: the server's own signed
		// account contradicts the contract policy was written against. Admitted before the
		// arguments are built — an upstream returning an inconsistent receipt per call drives one
		// of these per frame, and a discarded line still costs the join over its reason list, the
		// sanitizing walk, and the variadic boxing of both (see admitNotice). The admission also
		// collapses this site to one line per window per route, since the commonest cause is a
		// stale effect.ref pin, which makes EVERY receipt on this route inconsistent until an
		// operator fixes it; the per-call evidence stays on the tape either way.
		if line, ok := d.limits.notices.admitNotice(siteReceiptInconsistent); ok {
			line.writef("[eunox] WARN effect-receipt tool=%q — the upstream's signed receipt contradicts the effect contract this policy declares (%s); the call already ran, so this is evidence, not a refusal\n",
				audit.SanitizeAuditField(tool), strings.Join(result.Reasons, ", "))
		}
	}
	return result.AuditDetails()
}

// dispatchResourcesRead applies the PDP to a resources/read request and either
// forwards it to the upstream or returns a denial result.
func dispatchResourcesRead(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	var params mcp.ResourceReadParams
	if err := mcp.DecodeParams(msg.Params, &params); err != nil {
		return d.malformedDeny(ctx, msg, "invalid resources/read params")
	}
	if params.URI == "" {
		return d.malformedDeny(ctx, msg, "resources/read: uri must not be empty")
	}
	// Interface method (not a type-assert to *pdp.ManifestPDP) so JWT-only PDPs
	// also enforce resource reads.
	dec := d.pdp.DecideResourceRead(d.decideCtx(ctx), d.sessionID, params.URI, d.sourceIP)
	d.finishDecision(dec) // release the decision turn before the forward
	return enforcedForwardCore(ctx, d.forwardParams, d.pdp, msg, dec, capability.MethodResourcesRead, params.URI, params.URI, "resource", true, upstreamErrorDetail)
}

// dispatchResourcesSubscribe enforces resources/subscribe under the same
// read-access policy as resources/read: a subscription that would be denied at
// read time is denied before the channel is established.
func dispatchResourcesSubscribe(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	var params mcp.ResourceReadParams
	if err := mcp.DecodeParams(msg.Params, &params); err != nil {
		return d.malformedDeny(ctx, msg, "invalid resources/subscribe params")
	}
	if params.URI == "" {
		return d.malformedDeny(ctx, msg, "resources/subscribe: uri must not be empty")
	}
	dec := d.pdp.DecideResourceRead(d.decideCtx(ctx), d.sessionID, params.URI, d.sourceIP)
	d.finishDecision(dec) // release the decision turn before the forward
	// recordObligations is false: a subscription does not log obligation names.
	return enforcedForwardCore(ctx, d.forwardParams, d.pdp, msg, dec, capability.MethodResourcesSubscribe, params.URI, params.URI, "resource subscription", false, upstreamErrorDetail)
}

// dispatchResourcesUnsubscribe enforces resources/unsubscribe against the SAME manifest entry
// as resources/read/subscribe, but through DecideResourceCancel rather than DecideResourceRead
// — the URI must still be permitted, but no policy state is charged for cancelling.
//
// Mapped rather than left to the fail-closed default deliberately: unsubscribe only ever
// REDUCES data flow, so denying it protects nothing while costing the host its one way to
// stop a stream it already established. Using the cancel (not read) decision avoids charging
// maxCalls/sequenceBlock/labelOutput for a call that transfers no data — a metered read would
// let a one-call subscribe budget block the matching unsubscribe forever.
func dispatchResourcesUnsubscribe(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	var params mcp.ResourceReadParams
	if err := mcp.DecodeParams(msg.Params, &params); err != nil {
		return d.malformedDeny(ctx, msg, "invalid resources/unsubscribe params")
	}
	if params.URI == "" {
		return d.malformedDeny(ctx, msg, "resources/unsubscribe: uri must not be empty")
	}
	dec := d.pdp.DecideResourceCancel(ctx, d.sessionID, params.URI, d.sourceIP)
	d.finishDecision(dec) // release the decision turn before the forward
	// recordObligations is false: cancelling a subscription does not log obligation names.
	return enforcedForwardCore(ctx, d.forwardParams, d.pdp, msg, dec, capability.MethodResourcesUnsubscribe, params.URI, params.URI, "resource subscription", false, upstreamErrorDetail)
}

// dispatchPromptsGet enforces the capability manifest for prompts/get requests.
// Manifest entries must use namespaced prompt targets of the form "prompt:<name>"
// (e.g. "prompt:code_review", "prompt:*") with action "get" or "*".
func dispatchPromptsGet(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	var params mcp.PromptGetParams
	if err := mcp.DecodeParams(msg.Params, &params); err != nil {
		return d.malformedDeny(ctx, msg, "invalid prompts/get params")
	}
	if params.Name == "" {
		return d.malformedDeny(ctx, msg, "prompts/get: name must not be empty")
	}
	// Interface method (not a type-assert to *pdp.ManifestPDP).
	dec := d.pdp.DecidePromptGet(d.decideCtx(ctx), d.sessionID, params.Name, d.sourceIP)
	d.finishDecision(dec) // release the decision turn before the forward
	// auditID carries the "prompts/" display prefix; denialTarget is the bare name.
	return enforcedForwardCore(ctx, d.forwardParams, d.pdp, msg, dec, capability.MethodPromptsGet, "prompts/"+params.Name, params.Name, "prompt", true, upstreamErrorDetail)
}

// dispatchList forwards a */list request to the upstream and prunes the result to permitted
// entries. No policy configured uses DenyAllPDP, filtering to empty (fail closed); only an
// audit-mode wiretap route returns the catalog unfiltered. The enumeration is recorded, since
// listing is a common reconnaissance step.
func dispatchList(ctx context.Context, d dispatchParams, msg mcp.RPCMsg, filter func(pdp.ListFilterer, context.Context, json.RawMessage) pdp.ListFilterResult) mcp.RPCMsg {
	// The kill-switch check runs at the dispatchRequest boundary (a killed session must not
	// enumerate the catalog), so this handler no longer self-gates.

	// --require-audit=strict: fail the enumeration closed rather than forward an unrecorded
	// one. The three string args collapse to the method name: a */list has no sub-target.
	if denied, blocked := d.strictAuditDenial(ctx, msg, msg.Method, msg.Method, msg.Method, capability.EnforceResponse{}); blocked {
		return denied
	}

	// ListFilterer/RecordObservedToolHashes take (ctx, result), no session param, so the
	// session id rides the context (the per-session Tier-2 baseline needs it).
	ctx = pdp.WithSessionID(ctx, d.sessionID)

	if d.callUpstream == nil {
		// The same mode enforcedForwardCore reads (see forwardParams.callUpstream): a leg with no
		// upstream cannot enumerate one, and a nil call here would be a crash where the honest
		// answer is a fail-closed refusal naming the wiring fault.
		return d.refuseUpstreamless(ctx, msg, msg.Method, msg.Method, msg.Method, capability.EnforceResponse{})
	}
	upResp, err := d.callUpstream(ctx, msg)
	if err != nil {
		return d.recordUpstreamFailure(ctx, msg, err, msg.Method, msg.Method, nil)
	}

	// Defense-in-depth: a neither-result-nor-error reply is malformed, and forwarding it
	// would bypass list filtering. callUpstream now rejects this before returning, so it's
	// no longer reachable live — kept as a backstop against a future bypass.
	if upResp.Error == nil && upResp.Result == nil {
		warnIfStrictAuditJustDegraded(d.errOutOrStderr(), d.requireAuditStrict, d.rec, msg.Method, msg.Method, func() {
			if d.rec != nil {
				d.rec.RecordDeny(ctx, d.sessionID, msg.Method, msg.Method, capability.ErrCodeEnforcementError, "", nil, false)
			}
		})
		return mcp.ErrorResponse(msg.ID, jsonRPCCodeInternalError, "upstream returned a malformed list response (no result and no error)")
	}

	// Mark a tools/list observation that covers the WHOLE surface, so Tier-2 can report a tool
	// appearing/disappearing mid-session — without this, the only complete observation was the
	// session-start probe, which has nothing to compare against. See completeToolsListing.
	if msg.Method == capability.MethodToolsList && upResp.Result != nil && completeToolsListing(msg.Params, upResp.Result) {
		ctx = pdp.WithCompleteToolListing(ctx)
	}

	// In audit mode the enumeration must return the full catalog: filtering would hide tools
	// the host can still CALL (deny downgraded to observe).
	//
	// The upstream and filtered entry counts feed only the allow record below.
	var upstreamCount, filteredCount int
	switch {
	case upResp.Result != nil && !d.audit:
		// d.pdp is always non-nil (see dispatchParams), so "no policy" uses DenyAllPDP,
		// filtering to empty rather than forwarding verbatim.
		fr := filter(d.pdp, ctx, upResp.Result)
		upResp.Result = fr.Result
		upstreamCount, filteredCount = fr.Upstream, fr.Kept()
	case msg.Method == capability.MethodToolsList && upResp.Result != nil:
		// Audit mode tools/list: filter bypassed, but this arms the descriptionHash pin
		// (must hold EVEN under --audit) — runs unconditionally, never gated on d.rec.
		upstreamCount = d.pdp.RecordObservedToolHashes(ctx, upResp.Result)
		filteredCount = upstreamCount
	case d.rec != nil:
		// Audit mode on resources/prompts, or a nil result: verbatim, no filtering. Count
		// only when a recorder will read it, so a route with no sink pays no decode cost.
		upstreamCount = pdp.CountListEntries(msg.Method, upResp.Result)
		filteredCount = upstreamCount
	}

	// AuditOnly never applies to list methods, so d.audit alone carries the observe posture.
	// Details carry filter statistics so an auditor can tell filtering from a genuinely empty
	// upstream apart.
	warnIfStrictAuditJustDegraded(d.errOutOrStderr(), d.requireAuditStrict, d.rec, msg.Method, msg.Method, func() {
		if d.rec != nil {
			d.rec.RecordAllow(ctx, d.sessionID, msg.Method, msg.Method, listAllowDetails(upResp, upstreamCount, filteredCount, d.audit), nil, d.audit, nil, nil)
		}
	})

	upResp.ID = msg.ID
	return upResp
}

// listAllowDetails builds the structured audit details for a */list allow: filter statistics
// plus, when present, the forwarded upstream JSON-RPC error code. observeMode marks the
// audit/observe posture so a reader can distinguish a policy-filtered 0 from an all-permitting
// manifest.
func listAllowDetails(upResp mcp.RPCMsg, upstreamCount, filteredCount int, observeMode bool) map[string]interface{} {
	details := map[string]interface{}{
		"upstream_count":   upstreamCount,
		"filtered_count":   filteredCount,
		"suppressed_count": upstreamCount - filteredCount,
	}
	// In observe mode suppressed_count is 0 because filtering is bypassed, not because the
	// manifest permits everything. Stamp observe_mode so an auditor doesn't misread that.
	if observeMode {
		details["observe_mode"] = true
	}
	// A forwarded upstream error is noted by code (never message), mirroring
	// upstreamErrorDetail.
	if upResp.Error != nil {
		details[audit.UpstreamErrorCodeKey] = upResp.Error.Code
	}
	return details
}

// completeToolsListing reports whether a request/response pair together cover the WHOLE
// advertised tool set — the precondition Tier-2 needs before concluding a tool is missing
// rather than merely on another page. A cursored request or a nextCursor response means
// false; every ambiguous input reports false too (the conservative direction).
func completeToolsListing(params, result json.RawMessage) bool {
	if len(params) > 0 {
		// Cursor as a *string, not a string: `"cursor": null` asks for the first page, exactly
		// as an absent key does, and must not be read as a paginated fetch.
		var req struct {
			Cursor *string `json:"cursor"`
		}
		// mcp.DecodeParams, not json.Unmarshal: it rejects a duplicate key before decoding, so
		// `{"cursor":"page2","cursor":null}` can't decode to "no cursor" and falsely mark a
		// single-page fetch COMPLETE.
		if err := mcp.DecodeParams(params, &req); err != nil {
			return false
		}
		if req.Cursor != nil && *req.Cursor != "" {
			return false
		}
	}
	var res struct {
		NextCursor string `json:"nextCursor"`
	}
	// mcp.DecodeParams here too: a plain json.Unmarshal keeps the LAST of a duplicate
	// "nextCursor" key, so `{"nextCursor":"page2","nextCursor":""}` would decode to "" and
	// mark a truncated page COMPLETE — the exact ambiguity this function's own doc says it
	// reports false on, and the params side above is already hardened against.
	if err := mcp.DecodeParams(result, &res); err != nil {
		return false
	}
	return res.NextCursor == ""
}

// dispatchUnmapped is the request-framed entry to the fail-closed routing default. Its refusal
// wiring is this leg's sink paired with this leg's limits, so the request framing is governed by
// refusalDeclarations exactly as the notification framing is — it used to be handed an
// already-resolved recorder that never met the declaration at all.
func dispatchUnmapped(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	return refuseUnroutable(ctx, d.forwardParams, d.limits.recorders(d.rec), verifiedSession(d.sessionID), msg, unroutableFramingRequest)
}
