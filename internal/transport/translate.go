// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The cross-revision translation boundary: what a MISMATCHED host/upstream revision pair may
// carry, and what it may not.
//
// A matched pair does not reach this file at all. Everything here is scoped to the case where
// the host resolved one revision and the upstream leg is addressed as another, which before
// this file was refused wholesale by checkUpstreamHonorable.
//
// # The rule
//
// ADR-0006: translate only what is stateless and lossless in both directions; never fabricate
// statefulness on a peer's behalf. Two consequences worth stating because they are what the
// declaration table encodes:
//
//   - A method that carries no per-exchange state translates. `tools/call`, `resources/read`,
//     `prompts/get` and the three `*/list` methods are request-response with the whole exchange
//     in one round trip, so bridging them costs eunox no memory of anything.
//   - A method whose meaning DEPENDS on state one side cannot hold is refused, even though
//     nothing about the individual message is hard to forward. The subscribe pair is the clear
//     case: forwarding `resources/subscribe` to an upstream whose revision replaced it with
//     `subscriptions/listen` would open a stream one side believes exists and the other has
//     never heard of, and eunox would have to hold the correspondence for the connection's life.
//
// # Why the disposition is DECLARED rather than derived
//
// It cannot be derived from the method's revision membership: every method here is in BOTH
// revisions' tables (a method outside the peer's table never gets this far — it hits
// dispatchUnmapped first), so membership says nothing about whether the PAIR can carry it.
// It is a fact about the semantics, so it is written down per method, and a method whose params
// reach an upstream with no declaration fails the build rather than inheriting either answer.
//
// # Direction matters, and the two directions do different work
//
// Host to upstream, the translation is a DECLARATION: a 2026-07-28 upstream requires
// `io.modelcontextprotocol/protocolVersion` on every request, and an old host sends none.
// Upstream to host, it is a RESULT SHAPE: a 2026-07-28 host requires `resultType` on every
// result, and an old upstream sends none.
//
// The refusals are not symmetric either, and the asymmetry is the point: what cannot cross
// toward a stateless host (`input_required`) is different from what cannot cross toward one
// that has no per-request declaration.

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// errUntranslatableAcrossRevisions marks a message a mismatched pair cannot carry. It reaches
// the tape and the wire through upstreamErrInfo, which maps it to
// capability.ErrCodeUntranslatableAcrossRevisions and the spec's -32022 — the same path the
// duplicate-id fault takes, and for the same reason: it is a refusal produced AT the upstream
// call that is not an upstream failure, and recording it as one would report an outage against
// a healthy server.
var errUntranslatableAcrossRevisions = errors.New("message cannot be translated across the host/upstream revision boundary")

// crossRevisionDeclaration is one method's disposition on a mismatched pair, with the reason
// it holds. Both answers carry a `why`: a refusal an operator hits mid-migration needs to say
// what it protects, and a translation needs to say what makes it lossless.
type crossRevisionDeclaration struct {
	// translates is true when the message may cross a mismatched pair, with whatever
	// per-direction adjustment translateRequest/translateResult applies.
	translates bool
	why        string
}

// crossRevisionRegistry declares every method whose params reach an upstream. Keyed the way
// methodRegistry is, and held to the same completeness rule by
// TestCrossRevisionRegistry_CoversEveryForwardingMethod: a method that forwards host params
// with no entry here fails the build rather than defaulting to either answer.
//
// A host RESPONSE has no method and is handled separately (see boundaryDisposition), because
// the only reason a response exists on a mismatched pair is a server-initiated request that
// this boundary already refused on the way out.
var crossRevisionRegistry = map[string]crossRevisionDeclaration{
	capability.MethodToolsCall: {
		translates: true,
		why:        "request-response in one round trip; the whole exchange crosses at once, so bridging it holds no state",
	},
	capability.MethodResourcesRead: {
		translates: true,
		why:        "request-response in one round trip; a read carries no subscription and no continuation",
	},
	capability.MethodPromptsGet: {
		translates: true,
		why:        "request-response in one round trip",
	},
	capability.MethodToolsList: {
		translates: true,
		why:        "enumeration is stateless; the reply is filtered per identity either way, and the result-shape members the newer revision requires are addable without inventing anything",
	},
	capability.MethodResourcesList: {
		translates: true,
		why:        "enumeration is stateless, as for tools/list",
	},
	capability.MethodPromptsList: {
		translates: true,
		why:        "enumeration is stateless, as for tools/list",
	},
	capability.MethodResourcesSubscribe: {
		why: "opening a stream against an upstream whose revision replaced this pair with subscriptions/listen would require eunox to hold the subscription correspondence for the connection's life — the statefulness ADR-0006 refuses to fabricate",
	},
	capability.MethodResourcesUnsubscribe: {
		why: "the close half of a pair whose open is refused; translating it alone would acknowledge tearing down a stream that was never opened",
	},
	methodNotificationsCancelled: {
		translates: true,
		why:        "pairs with a request that crossed; refusing it would leave a translated request the host cannot cancel, which is worse than forwarding a notification that names an id the upstream already knows",
	},
	methodNotificationsProgress: {
		translates: true,
		why:        "carries a progress token for an exchange already in flight and commits nothing",
	},
	methodNotificationsRootsListChanged: {
		why: "announces a capability the newer revision deprecates, so it can only travel old-host-to-new-upstream, where it names a surface the upstream has no way to read",
	},
}

// boundaryDisposition answers whether msg may cross a mismatched pair.
//
// A message with no method — a host RESPONSE — is refused. On a mismatched pair the only
// request it could be answering is a server-initiated one, which this boundary refuses at the
// upstream leg before it ever reaches the host, so a response arriving here means either a
// reply to a request eunox never relayed or a peer probing the seam. Neither is forwardable.
func boundaryDisposition(msg mcp.RPCMsg) crossRevisionDeclaration {
	if msg.Method == "" {
		return crossRevisionDeclaration{
			why: "a host response on a mismatched pair answers a server-initiated request this boundary refuses at the leg, so no reply of this shape was ever asked for",
		}
	}
	// The zero value refuses, which is what makes an unlisted method fail closed at runtime
	// even though the registry test is what should have caught it at build time.
	return crossRevisionRegistry[msg.Method]
}

// refuseAcrossRevisions builds the boundary error for a message that may not cross, naming
// both revisions and the method.
//
// Every part of the message is from a closed set — two published revisions and a method this
// build routes — so it is safe to surface to the host verbatim, which revisionRefusalReason
// relies on for the sibling revision errors.
func refuseAcrossRevisions(method string, hostRev, legRev capability.Revision, why string) error {
	subject := method
	if subject == "" {
		subject = "a response"
	}
	return fmt.Errorf("%w: %s cannot cross a host %s / upstream %s pair (%s)",
		errUntranslatableAcrossRevisions, subject, hostRev, legRev, why)
}

// translateRequest adapts a host message for an upstream leg addressed at a different
// revision, or returns it unchanged when the pair is matched.
//
// The two adjustments are mirror images, and each is the thing the RECEIVING revision requires
// of a client that speaks it:
//
//   - Toward a DECLARING upstream, the per-request revision declaration is ADDED. This is the
//     one place a host's own `_meta` is written to, and it is exactly the translation the
//     matched-pair rule forbids (see DeclareUpstreamRevision, which does the merge and is
//     otherwise reserved for requests eunox originates). Without it the upstream refuses every
//     forwarded request for a member the host had no way to know it needed.
//   - Toward a NON-declaring upstream, a declaration the host sent is REMOVED. eunox is
//     presenting itself to that upstream as a client of ITS revision, and such a client sends
//     no such member; leaving it there would hand an upstream a version claim about a leg it is
//     not on. Lossless in the sense that matters: the member describes the host-to-eunox leg,
//     which the upstream has no stake in.
//
// Notifications take the same treatment as requests. A declaring upstream requires the member
// on every message a client sends it, and a notification is not exempt.
func translateRequest(msg mcp.RPCMsg, hostRev, legRev capability.Revision) (mcp.RPCMsg, error) {
	addressed := upstreamAddressedRevision(legRev)
	if hostRev == addressed {
		return msg, nil
	}
	if declaresPerRequestRevision(legRev) {
		return DeclareUpstreamRevision(msg, legRev)
	}
	return stripRevisionDeclaration(msg)
}

// stripRevisionDeclaration removes the per-request revision members from msg's params, and
// removes an emptied `_meta` with them so the upstream sees the shape a client of its own
// revision would send rather than a vestigial empty object.
//
// Fails closed on every malformed shape, for DeclareUpstreamRevision's reasons: params that
// decode to JSON `null` (which nils the map with no error) and params carrying a duplicate key
// (which mcp.DecodeParams refuses where a plain Unmarshal would silently resolve one).
func stripRevisionDeclaration(msg mcp.RPCMsg) (mcp.RPCMsg, error) {
	if len(msg.Params) == 0 {
		return msg, nil
	}
	fail := func(err error) (mcp.RPCMsg, error) {
		return mcp.RPCMsg{}, fmt.Errorf("stripping the revision declaration from %s: %w", msg.Method, err)
	}
	fields := map[string]json.RawMessage{}
	if err := mcp.DecodeParams(msg.Params, &fields); err != nil {
		return fail(fmt.Errorf("params are not a JSON object: %w", err))
	}
	raw, ok := fields[metaMember]
	if !ok || len(raw) == 0 {
		return msg, nil
	}
	meta := map[string]json.RawMessage{}
	if err := mcp.DecodeParams(raw, &meta); err != nil {
		return fail(fmt.Errorf("existing %s is not a JSON object: %w", metaMember, err))
	}
	before := len(meta)
	delete(meta, capability.MetaKeyProtocolVersion)
	delete(meta, capability.MetaKeyClientCapabilities)
	if len(meta) == before {
		return msg, nil
	}
	if len(meta) == 0 {
		delete(fields, metaMember)
	} else {
		encoded, err := json.Marshal(meta)
		if err != nil {
			return fail(err)
		}
		fields[metaMember] = encoded
	}
	params, err := json.Marshal(fields)
	if err != nil {
		return fail(err)
	}
	msg.Params = params
	return msg, nil
}

// translateResult adapts an upstream reply for a host on a different revision, or returns it
// unchanged when the pair is matched or the reply carries no result to adapt.
//
// This step never rewrites bytes, in EITHER direction. Toward a declaring host the members that
// revision requires do have to be added — but a matched 2026-07-28 pair needs exactly the same
// thing, so supplying them is not a property of the boundary and does not belong here: it is
// applied once for every declaring host by the shape pass this wrapper sits inside
// (result_shape.go), which is also the pass that refuses a variant eunox cannot enforce. Toward
// a non-declaring host nothing is stripped either: the extra members a newer upstream sends are
// inert for a host that does not read them, and rewriting a result to remove members nobody
// looks at would put eunox's hands on payload bytes for no gain.
//
// What is left is the one thing only the boundary can say: a variant an old host would MISREAD
// (see resultCrossesToHost). The shape pass cannot make that call, because it is a fact about
// the peer's revision rather than about the result.
func translateResult(method string, resp mcp.RPCMsg, hostRev, legRev capability.Revision) (mcp.RPCMsg, error) {
	addressed := upstreamAddressedRevision(legRev)
	if hostRev == addressed || len(resp.Result) == 0 || declaresPerRequestRevision(hostRev) {
		return resp, nil
	}
	return resp, resultCrossesToHost(method, resp, hostRev, legRev)
}

// upstreamCodeRewrite carries, for one request, the error code the UPSTREAM actually sent when
// the boundary re-spelled it for the host.
//
// # Why the audit tape needs this at all
//
// The rewrite happens at the upstream call, which is BELOW the audit record — the same response
// object the host receives is the one upstreamErrorDetail reads. So the tape recorded the
// translated integer under `_eunox_upstream_error_code`, a field whose name promises what the
// upstream sent. On a signed, tamper-evident log that is a false statement, and it is not
// recoverable after the fact: a translated -32602 and an upstream that genuinely sent -32602 are
// the same bytes.
//
// # Why only the ORIGINAL is recorded
//
// The forward direction is deterministic — method, the two revisions and the upstream's code
// decide the host's code — and the record already carries the revision. So the original is
// strictly more informative than the translated value, and recording it costs no second detail
// key, no new reserved name, and no threat-model addition.
//
// # Why a context holder
//
// The translation cannot move above the audit: it must stay at the upstream call, because that
// is what guarantees every code it sees came from the upstream. Applied any later it would also
// rewrite eunox's OWN denials — CAPABILITY_DENIED is -32002 under the same revision — and turn a
// policy refusal into invalid-params. So the fact has to travel UP from the seam, and the context
// is the only channel the wrapper has: it is built at construction and sees nothing but ctx and
// the message.
//
// Installed once, by dispatchRequest, which is the single entry both audit-writing paths (the
// enforced forward core, and the `*/list` dispatcher) are reached through. A path that somehow
// missed the install degrades to recording the forwarded code — today's behavior rather than a
// new failure — and a source guard pins the install.
type upstreamCodeRewrite struct {
	original  int
	rewritten bool
}

type upstreamCodeRewriteKey struct{}

// withUpstreamCodeRewrite installs the per-request slot the boundary reports a rewrite into.
func withUpstreamCodeRewrite(ctx context.Context) context.Context {
	return context.WithValue(ctx, upstreamCodeRewriteKey{}, &upstreamCodeRewrite{})
}

// noteUpstreamCodeRewrite records the code the upstream sent, before the boundary re-spelled it.
// A no-op when no slot was installed.
func noteUpstreamCodeRewrite(ctx context.Context, original int) {
	if slot, ok := ctx.Value(upstreamCodeRewriteKey{}).(*upstreamCodeRewrite); ok {
		slot.original, slot.rewritten = original, true
	}
}

// upstreamCodeBeforeRewrite returns the upstream's own error code when the boundary rewrote it.
//
// Written by the wrapper's goroutine and read by the same one after it returns — the slot is per
// request, and a request is handled start to finish on one goroutine.
func upstreamCodeBeforeRewrite(ctx context.Context) (int, bool) {
	slot, ok := ctx.Value(upstreamCodeRewriteKey{}).(*upstreamCodeRewrite)
	if !ok || !slot.rewritten {
		return 0, false
	}
	return slot.original, true
}

// translateReply is the boundary's one entry point for whatever the upstream answered, routing a
// result to translateResult and an ERROR to translateErrorCode.
//
// It exists because a reply is one of two shapes and only one of them was being looked at: every
// gate in translateResult tests `resp.Result`, so an error response — which carries none —
// matched the "nothing to do" branch and crossed with its code untouched. An error is not the
// quiet case here; it is the one carrying an integer whose MEANING the two revisions disagree
// about.
//
// Routing on `resp.Error != nil` is exact because a reply carrying BOTH is refused before it
// gets here — awaitNonced on the subprocess path and correlateUpstreamReply on the HTTP bridges
// both reject one violating JSON-RPC's exactly-one-of invariant. That is a dependency rather
// than an observation: a fourth upstream path skipping those guards would take the error branch
// and with it skip the result-side REFUSAL, which is the fail-open direction.
func translateReply(ctx context.Context, method string, resp mcp.RPCMsg, hostRev, legRev capability.Revision) (mcp.RPCMsg, error) {
	if resp.Error != nil {
		return translateErrorCode(ctx, method, resp, hostRev, legRev), nil
	}
	return translateResult(method, resp, hostRev, legRev)
}

// translateErrorCode rewrites an upstream error's integer into the receiving host's spelling,
// for the one code whose meaning moved between the revisions.
//
// # What moved
//
// 2025-11-25 assigns -32002 to resource-not-found. 2026-07-28 moves that meaning to -32602 and
// frees -32002 into the implementation-defined band. So the same integer means different things
// to the two peers, and a proxy that forwards it verbatim hands one peer a code from the other's
// dictionary — a 2026-07-28 host reads -32002 as some implementation's private code and loses
// the one fact the upstream was reporting.
//
// # Why only one direction
//
// Old to new is a WIDENING and safe: under 2025-11-25 the spec assigns -32002 exactly one
// meaning, so reading it as resource-not-found is the conforming reading and the new spelling
// says the same thing.
//
// New to old is a NARROWING and is deliberately NOT performed. Under 2026-07-28 the same -32602
// carries both resource-not-found and JSON-RPC's own invalid-params, so the integer no longer
// distinguishes them; remapping it to -32002 would assert "the resource does not exist" about
// what may well have been a malformed request. Left alone, -32602 is still a code the old host
// understands (invalid params) — less precise than the truth, but never a claim eunox invented.
// Never fabricate on a peer's behalf is the boundary's rule, and this is the same rule applied to
// an integer.
//
// # Why it is scoped to the methods that address a resource
//
// A -32002 arriving from `tools/call` is an upstream using the implementation-defined band as
// 2025-11-25 permitted, not a missing resource, and rewriting it would be eunox inventing a
// meaning. The scope is DERIVED from capability.MethodTargetType — the same mapping the audit
// layer stamps `target_type` from — so a resource-addressing method added later is covered
// without this being remembered.
//
// eunox's OWN denials never reach here: this wrapper sits at the upstream call, so every code it
// sees came from the upstream. That is what makes reading -32002 as the spec's meaning safe
// despite eunox spelling CAPABILITY_DENIED with the same integer.
func translateErrorCode(ctx context.Context, method string, resp mcp.RPCMsg, hostRev, legRev capability.Revision) mcp.RPCMsg {
	if hostRev == upstreamAddressedRevision(legRev) || !declaresPerRequestRevision(hostRev) {
		return resp
	}
	if target, ok := capability.MethodTargetType(method); !ok || target != capability.TargetTypeResource {
		return resp
	}
	if resp.Error.Code != capability.ResourceNotFoundWireCode(upstreamAddressedRevision(legRev)) {
		return resp
	}
	// Copied rather than mutated in place: resp.Error is a pointer into the decoded upstream
	// message, and the caller's copy of that message is the one the reader may still hold.
	// Reported UP before the code is replaced: the audit record must name what the upstream
	// sent, and after this assignment nothing can recover it (a translated -32602 and a genuine
	// one are the same bytes).
	noteUpstreamCodeRewrite(ctx, resp.Error.Code)
	rewritten := *resp.Error
	rewritten.Code = capability.ResourceNotFoundWireCode(hostRev)
	resp.Error = &rewritten
	return resp
}

// resultCrossesToHost refuses an upstream result whose variant a non-declaring host cannot
// read.
//
// `input_required` is the whole of it, and it is refused rather than passed through because
// passing it through is SILENT: an old host has no `resultType` in its vocabulary, so it reads
// the result as a completed call, drops the `inputRequests` the upstream is waiting on, and the
// exchange desynchronizes with both sides believing they are done. A refusal costs the caller
// one failed call; the pass-through costs them a wrong answer they cannot detect.
//
// Any other unrecognized variant is refused for the same reason, which is also why the check is
// "not complete" rather than "is input_required": a variant this build has never heard of is
// exactly the case where eunox cannot know what a host would lose by reading it as complete.
// An ABSENT resultType is complete by the spec's rule for earlier-revision servers, and is the
// shape every 2025-11-25 upstream produces, so it crosses.
//
// The member is read through the shape pass's SHALLOW top-level scan rather than a strict
// decode of the whole body. A deep decode refuses fold-equal duplicate keys at every nesting
// depth, which is right for host params bound into an upstream's struct and wrong for a result:
// an upstream answering `{"structuredContent":{"id":1,"ID":2}}` is carrying two legal sibling
// fields of its OWN payload, and hard-refusing that after the tool has already run makes a
// mismatched pair a compatibility hazard rather than a translation. The differential that
// matters is at the top level, in the member both sides read, and that is where the scan checks.
func resultCrossesToHost(method string, resp mcp.RPCMsg, hostRev, legRev capability.Revision) error {
	members, err := scanResultMembers(resp.Result)
	if err != nil {
		return refuseAcrossRevisions(method, hostRev, legRev,
			"the upstream result could not be read well enough to establish whether its variant is one this host's revision understands")
	}
	variant, present, err := members.resultType()
	if err != nil {
		return refuseAcrossRevisions(method, hostRev, legRev,
			"the upstream result states a variant that is not a JSON string, so whether this host's revision understands it cannot be established")
	}
	if capability.ResultTypeForwardable(variant, present) {
		return nil
	}
	return refuseAcrossRevisions(method, hostRev, legRev, fmt.Sprintf(
		"the upstream answered resultType %q, which a host on %s has no way to read; forwarding it would be read as a completed call and the exchange would desynchronize silently",
		capability.BoundResultType(variant), hostRev))
}

// withCrossRevisionTranslation wraps a leg's upstream call so every enforced forward crosses
// the boundary through one seam.
//
// Wrapped at CONSTRUCTION rather than applied per call site, because the alternative is asking
// each of the forward core, the `*/list` dispatcher, and whatever calls the upstream next to
// remember — and the one that forgets is a message crossing a mismatched pair untranslated,
// which fails at the far peer with an error naming eunox's own bug as the upstream's.
//
// The host revision comes from the CONTEXT, not from a field, because it is decided per request
// (capability.WithProtocolRevision, stamped by each transport's negotiation) while the leg
// revision is fixed for the leg's life. resolveRevision handles the empty carrier the same way
// every other reader of it does.
//
// A matched pair returns inner untouched at the first branch of each translate step, so nothing
// about the byte stream a matched pair produces changes — the release's own regression
// invariant, held structurally rather than by test.
func withCrossRevisionTranslation(legRev capability.Revision, inner func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error)) func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
	if inner == nil {
		// nil is a MODE the forward core and dispatchList both read (a leg with no upstream), so
		// it must survive wrapping rather than becoming a non-nil func that fails on use.
		return nil
	}
	return func(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
		hostRev := resolveRevision(capability.ProtocolRevisionFromContext(ctx))
		if hostRev == upstreamAddressedRevision(legRev) {
			return inner(ctx, msg)
		}
		// The disposition is re-asked here rather than trusted from the honorability gate:
		// that gate runs at negotiation, and this is the seam the bytes actually cross.
		if decl := boundaryDisposition(msg); !decl.translates {
			return mcp.RPCMsg{}, refuseAcrossRevisions(msg.Method, hostRev, legRev, decl.why)
		}
		outbound, err := translateRequest(msg, hostRev, legRev)
		if err != nil {
			return mcp.RPCMsg{}, fmt.Errorf("%w: %w", errUntranslatableAcrossRevisions, err)
		}
		resp, err := inner(ctx, outbound)
		if err != nil {
			return resp, err
		}
		return translateReply(ctx, msg.Method, resp, hostRev, legRev)
	}
}

// refuseServerRequestAcrossRevisions refuses an upstream's server-initiated request when the
// host it would be relayed to is on a revision that has no server-initiated requests, or nil
// when the leg may proceed.
//
// This is the one boundary check with no host message in scope — the request originates at the
// upstream — so it reads the session's pinned revision as a fact rather than resolving one, the
// same way every other decision on this leg does.
//
// Keyed on the HOST's revision alone. The upstream's is implied: a leg addressed at a revision
// with no server-initiated mechanism cannot produce one of these in the first place, so a pair
// that reaches here with a declaring host is a mismatched pair by construction, and asking
// about the upstream again would be asking a question the message itself already answered.
func refuseServerRequestAcrossRevisions(method string, hostRev capability.Revision) error {
	if !declaresPerRequestRevision(hostRev) {
		return nil
	}
	return refuseAcrossRevisions(method, hostRev, handshakeRevision,
		"the host's revision replaced server-initiated requests with a client-driven exchange, so there is no way to ask it and no honest answer eunox could give on its behalf")
}

// translateNotificationForLeg adapts a host notification for an upstream leg addressed at a
// different revision, reporting false when it must be dropped instead.
//
// Notifications need this for the same reason requests do — a declaring upstream requires the
// per-request declaration on every message a client sends it, not only on the ones carrying an
// id — but they cannot get it from withCrossRevisionTranslation, because a forwarded
// notification never goes through the upstream CALL: there is no reply to correlate, so each
// transport writes it straight out (stdio to its subprocess writer, HTTP through
// forwardNotification). Wrapping the call seam therefore covered every enforced request and
// none of these.
//
// A drop rather than a refusal, because JSON-RPC forbids answering a notification and the
// boundary already ADMITTED this one at negotiation: reaching a translation failure here means
// the params are malformed in a way the gate could not see, which is the same disposition every
// other unforwardable notification takes.
func translateNotificationForLeg(msg mcp.RPCMsg, hostRev, legRev capability.Revision) (mcp.RPCMsg, error) {
	if hostRev == upstreamAddressedRevision(legRev) {
		return msg, nil
	}
	translated, err := translateRequest(msg, hostRev, legRev)
	if err != nil {
		// The CAUSE travels with the drop rather than being flattened to "no": this is the one
		// unforwardable-notification disposition whose reason is eunox's own translation layer
		// rather than the peer's message, so the leg dropping it is the only place that can say
		// which notification was lost and why.
		return mcp.RPCMsg{}, err
	}
	return translated, nil
}
