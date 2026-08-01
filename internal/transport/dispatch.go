// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Shared request dispatch: the single method→handler mapping and fail-closed
// default both transports route enforced MCP requests through.

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// dispatchParams bundles everything the per-method enforced handlers need,
// independent of transport. HTTP fills these from sess.route + the session;
// stdio from the proxy itself (with an empty source IP — stdio has no
// per-request client address). It embeds forwardParams (consumed verbatim by the
// shared enforced-forward core) and adds only the parse→decide bits (pdp,
// sourceIP), so handlers pass d.forwardParams straight through.
// pdp is never nil: every production constructor (NewStdioProxy; and, for HTTP,
// NewHTTPProxyGateway fed by BuildRoutes) substitutes a concrete PDP (DenyAllPDP /
// AlwaysAllowPDP) for an omitted one, so
// the invariant is established at construction and every dispatch path may
// dereference d.pdp directly. A nil here is a wiring bug, not a runtime condition to
// tolerate — DenyAllPDP, not a nil-forwards-verbatim special case, is the
// fail-closed "no policy" default.
type dispatchParams struct {
	forwardParams
	pdp      pdp.PolicyDecisionPoint
	sourceIP string
	// buildInit answers a host `initialize` locally from the upstream capabilities
	// captured at session start (HTTP: the session's; stdio: the proxy's). It is
	// injected per-transport so `initialize` can flow through dispatchRequest like
	// every other enforced method — the response differs per transport, the
	// cross-cutting gate (the kill check) does not. nil only in tests that never send
	// initialize through the dispatcher; the initialize case fails closed if unset.
	buildInit func(mcp.RPCMsg) mcp.RPCMsg

	// endDecision closes the per-session decision critical section a serialize-relevant
	// transport opened around this enforced request. The four Decide* handlers call it (via
	// finishDecision) IMMEDIATELY after the PDP
	// decision so the upstream forward runs OUTSIDE the lock — only the decision + state
	// write serialize, not the slow round-trip. It is idempotent, so the transport also
	// defers it as a backstop for the malformed-params path (which returns before the
	// decision). nil for a non-serialized request (a non-flow/non-sequenceBlock policy, or
	// a locally-answered method), where finishDecision is a no-op.
	endDecision func()

	// honorAttribution admits the client-supplied attribution interface (the
	// io.eunolabs.context-manifest block in a request's _meta). It is the runtime staging
	// gate for a DRAFT wire token — set only when the route's policy declares the
	// flow+effect draft schemaVersion — because the manifest-side gate
	// (checkExperimentalTokenStaging) structurally cannot cover a token that arrives on a
	// REQUEST rather than in the policy. False means the block is IGNORED, not rejected:
	// the interface is union-only, so ignoring it falls back to the conservative session
	// join, which is the stricter reading.
	honorAttribution bool
}

// finishDecision closes the per-session decision critical section, if one is open (see
// dispatchParams.endDecision). The Decide* handlers call it right after the PDP decision
// and before enforcedForwardCore, so the upstream forward is never held under the
// per-session lock. A no-op when the request is not serialized.
func (d dispatchParams) finishDecision() {
	if d.endDecision != nil {
		d.endDecision()
	}
}

// killDenied runs the session kill-switch check for a locally-answered method that
// does NOT flow through a Decide* path (which embeds its own richer kill record via
// enforcedForwardCore). If the session is killed it returns the recordKillDenial
// response and true. dispatchRequest applies this once, at the boundary, for the whole
// locally-answered set (initialize, */list, the unmapped default), so those handlers no
// longer self-gate and a new locally-answered method inherits revocation by construction.
// The one remaining direct caller is malformedDeny — the malformed-params sub-path of a
// Decide* method, reached before the PDP and so not covered by the boundary gate. A
// kill-store error fails closed inside CheckKill.
func (d dispatchParams) killDenied(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, bool) {
	if deny := d.pdp.CheckKill(ctx, d.sessionID); deny != nil {
		return recordKillDenial(ctx, d.rec, deny, msg.ID, verifiedSession(d.sessionID), msg.Method), true
	}
	return mcp.RPCMsg{}, false
}

// decideCtx applies the audit-mode quota skip: in observe mode the MaxCalls quota
// is skipped (WithSkipQuota) so the observed call consumes none, while
// sequenceBlock evaluation and session history are unaffected.
func (d dispatchParams) decideCtx(ctx context.Context) context.Context {
	if d.audit {
		return enforcement.WithSkipQuota(ctx)
	}
	return ctx
}

// decideMethodHandlers maps each Decide*-method (tools/call, resources/read,
// resources/subscribe, resources/unsubscribe, prompts/get) to its dispatch handler.
// It is the single source of truth for "is this an enforced method requiring a PDP decision":
// dispatchRequest routes through it below, and isEnforcedMethod (consulted by
// both transports' notification paths, since IsNotification's classification
// is purely structural with no method allowlist) derives its answer from the
// SAME map, so the two questions — "which handler does this method route to"
// and "is this method enforced" — cannot silently diverge the way two
// independently-maintained case lists could.
var decideMethodHandlers = map[string]func(context.Context, dispatchParams, mcp.RPCMsg) mcp.RPCMsg{
	capability.MethodToolsCall:            dispatchToolsCall,
	capability.MethodResourcesRead:        dispatchResourcesRead,
	capability.MethodResourcesSubscribe:   dispatchResourcesSubscribe,
	capability.MethodResourcesUnsubscribe: dispatchResourcesUnsubscribe,
	capability.MethodPromptsGet:           dispatchPromptsGet,
}

// isEnforcedMethod reports whether method is one of the Decide* methods above,
// derived from decideMethodHandlers so it cannot drift from dispatchRequest's
// own routing table.
func isEnforcedMethod(method string) bool {
	_, ok := decideMethodHandlers[method]
	return ok
}

// swallowedHostNotifications is the set of host->upstream notification methods
// both transports drop rather than forward verbatim:
//
//   - "notifications/initialized": the proxy already sent its own to the upstream
//     during its client handshake, so re-forwarding the host's would double it.
//   - "initialize": IsNotification()'s classification is purely structural, so a
//     client can send "initialize" with no id and have it counted as a notification
//     even though the method is ordinarily a request. Forwarding that verbatim would
//     let it re-trigger the upstream's handshake outside dispatchRequest's kill gate
//     and audit trail, so it is swallowed on the notification path.
//
// It is the single source of truth for this set so the stdio and HTTP transports
// (forwardHostNotification and handleSessionPost) provably agree — the "enforced
// identically on both transports" property their comments assert is mechanical
// rather than two hand-mirrored literal lists that could silently diverge.
var swallowedHostNotifications = map[string]struct{}{
	mcp.MethodNotificationsInitialized: {},
	mcp.MethodInitialize:               {},
}

// isSwallowedHostNotification reports whether a host->upstream notification of this
// method must be dropped rather than forwarded (see swallowedHostNotifications).
func isSwallowedHostNotification(method string) bool {
	_, ok := swallowedHostNotifications[method]
	return ok
}

// methodNotificationsProgress and methodNotificationsRootsListChanged are
// host->upstream notification methods the proxy forwards verbatim (see
// forwardableHostNotifications). Neither has any other reference in this package
// (unlike methodNotificationsCancelled, which rewriteCancelToNonce also consults),
// so they are defined here rather than in stdio.go.
const (
	methodNotificationsProgress         = "notifications/progress"
	methodNotificationsRootsListChanged = "notifications/roots/list_changed"
)

// forwardableHostNotifications is the allowlist of host->upstream notification
// methods forwarded to the upstream verbatim once the swallowed set
// (isSwallowedHostNotification) and the enforced-method fail-closed reject
// (denyEnforcedMethodNotification) have already passed. Before this allowlist
// existed, every method reaching this point — regardless of what it was — was
// forwarded with no policy check and no audit record: a notification-framed
// "tools/uninstall" (or any other unrecognized method) reached the upstream
// invisibly, while its request-framed twin was denied and logged by
// dispatchUnmapped. isForwardableHostNotification closes that gap; anything not
// in this set is dropped and recorded by denyUnmappedHostNotification instead,
// mirroring dispatchUnmapped's fail-closed default for the request-framed case.
var forwardableHostNotifications = map[string]struct{}{
	methodNotificationsCancelled:        {},
	methodNotificationsProgress:         {},
	methodNotificationsRootsListChanged: {},
}

// isForwardableHostNotification reports whether a host->upstream notification of
// this method is allowlisted for verbatim forwarding (see
// forwardableHostNotifications).
func isForwardableHostNotification(method string) bool {
	_, ok := forwardableHostNotifications[method]
	return ok
}

// denyUnmappedHostNotification checks whether msg's method is outside the
// forwardable allowlist and, if so, records a fail-closed deny for it rather than
// letting the caller forward it verbatim — the notification-framed analogue of
// dispatchUnmapped's fail-closed default for request-framed calls. Shared by both
// transports' notification paths so the check and its audit record live once,
// matching denyEnforcedMethodNotification's "single source of truth" pattern.
// Returns true when msg was denied; the caller must not forward it in that case.
func denyUnmappedHostNotification(ctx context.Context, rec auditRecorder, sessionID string, msg mcp.RPCMsg) bool {
	if isForwardableHostNotification(msg.Method) {
		return false
	}
	if rec != nil {
		rec.RecordDeny(ctx, sessionID, msg.Method, msg.Method, capability.ErrCodeAuthorizationFailed, "", nil, false)
	}
	fmt.Fprintf(os.Stderr,
		"[eunox] SECURITY: unmapped notification method %q denied (AUTHORIZATION_FAILED) — not forwarded\n",
		audit.SanitizeAuditField(msg.Method))
	return true
}

// denyEnforcedMethodNotification checks whether msg's method is an enforced
// Decide* method and, if so, records the fail-closed deny for it having been
// smuggled in via notification framing (no id) instead of the request framing
// a legitimate MCP host always uses for these methods — forwarding it verbatim
// would bypass both the PDP decision and the audit record the request-framed
// equivalent gets. Shared by both transports' notification paths (stdio's
// forwardHostNotification, HTTP's handleSessionPost) so the check and its
// audit record live once instead of being hand-mirrored per transport, the
// same "single source of truth" principle dispatchRequest upholds for
// request-framed calls. Returns true when msg was denied; the caller must not
// forward it to the upstream in that case.
func denyEnforcedMethodNotification(ctx context.Context, rec auditRecorder, sessionID string, msg mcp.RPCMsg) bool {
	if !isEnforcedMethod(msg.Method) {
		return false
	}
	if rec != nil {
		rec.RecordDeny(ctx, sessionID, msg.Method, msg.Method, codeInvalidRequest, "", nil, false)
	}
	return true
}

// dispatchRequest routes an enforced MCP request to its handler and returns the
// JSON-RPC message to deliver to the host. It is the single source of truth for
// the method→handler mapping and the fail-closed default both transports share.
// initialize routes through here too (via dispatchInitialize) so its cross-cutting
// kill gate cannot drift from the other locally-answered paths; only the response
// body differs per transport, supplied by the injected d.buildInit. The HTTP
// session-CREATING initialize (which spawns/contacts an upstream and carries the
// strict-audit gate) stays in the HTTP transport — no session/dispatchParams exist
// yet on that path.
//
// The kill gate is applied STRUCTURALLY, by which arm of the split a method lands in,
// rather than per-handler:
//
//   - Decide* methods (tools/call, resources/read, resources/subscribe,
//     resources/unsubscribe, prompts/get)
//     embed a richer kill record inside enforcedForwardCore, so they are dispatched
//     WITHOUT the boundary gate. Their malformed-params sub-path — reached before the
//     PDP — gates separately inside malformedDeny.
//   - Every other method is locally answered (initialize, the */list family, and the
//     fail-closed unmapped default) and shares ONE simple kill gate applied here, at the
//     dispatch boundary. A newly-added locally-answered method inherits revocation by
//     construction — it need only be added to the second switch — instead of re-placing
//     killDenied inside its handler (the per-site pattern that previously leaked the gate
//     across every such method).
func dispatchRequest(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	if handler, ok := decideMethodHandlers[msg.Method]; ok {
		return handler(ctx, d, msg)
	}

	// Locally-answered set: none of these flow through a Decide* path, so they share the
	// one simple kill gate, applied once here before routing. A killed session is recorded
	// as KILL_SWITCH (not the method's own denial code) and never contacts the upstream.
	if resp, killed := d.killDenied(ctx, msg); killed {
		return resp
	}
	if handler, ok := locallyAnsweredHandlers[msg.Method]; ok {
		return handler(ctx, d, msg)
	}
	return dispatchUnmapped(ctx, d, msg)
}

// methodPing is the MCP liveness probe, answered locally without contacting the upstream.
const methodPing = "ping"

// locallyAnsweredHandlers maps each method dispatchRequest answers WITHOUT a PDP Decide*
// call — the handshake, the liveness probe, and the three */list flavors — to its handler.
// It is a table rather than a switch for the same reason decideMethodHandlers is: routing
// and "is this method dispatched at all" are then one fact rather than two hand-maintained
// lists that can disagree. The audit-mode banner asks the SECOND question — it names the
// enforced set (enforcedMethodSummary) and says an undispatched method is still denied — and
// this table is what makes that claim checkable instead of prose.
//
// Everything NOT in this table or in decideMethodHandlers falls to dispatchUnmapped's
// fail-closed deny, in every mode.
var locallyAnsweredHandlers = map[string]func(context.Context, dispatchParams, mcp.RPCMsg) mcp.RPCMsg{
	mcp.MethodInitialize: dispatchInitialize,
	methodPing: func(_ context.Context, _ dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
		return dispatchPing(msg)
	},
	capability.MethodResourcesList: func(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
		return dispatchList(ctx, d, msg, pdp.ListFilterer.FilterResourcesList)
	},
	capability.MethodToolsList: func(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
		return dispatchList(ctx, d, msg, pdp.ListFilterer.FilterToolsList)
	},
	capability.MethodPromptsList: func(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
		return dispatchList(ctx, d, msg, pdp.ListFilterer.FilterPromptsList)
	},
}

// enforcedMethodSummary is the subset the audit-mode banner's "forwarded and logged"
// sentence may name: only the Decide* methods actually reach the upstream AND leave a
// decision record. The locally-answered half of the dispatch table does not — initialize
// and ping never touch the upstream and write no record, and the …/list flavors forward
// the catalog unfiltered and are recorded as enumeration events, not decisions — so
// sweeping them into one "every dispatched call is forwarded and logged" claim replaced
// the old "ALL calls" over-claim with a narrower false one.
var enforcedMethodSummary = sortedMethods(decideMethodHandlers)

// unmappedMethodExamples names MCP methods this build does NOT dispatch, so the banner's
// caveat is concrete rather than abstract. They are examples, not an exhaustive list:
// anything outside the two routing tables is denied the same way.
const unmappedMethodExamples = "e.g. completion/complete, logging/setLevel, resources/templates/list"

// sortedMethods joins the given routing tables' keys in sorted order, so a banner derived
// from a table cannot drift from what the dispatcher does (and a map's iteration order
// cannot make the text unstable). Variadic because it once joined both tables for a
// whole-dispatch-table summary; the banner now names only the enforced half, and the tests
// still exercise the multi-table form.
func sortedMethods(tables ...map[string]func(context.Context, dispatchParams, mcp.RPCMsg) mcp.RPCMsg) string {
	var methods []string
	for _, t := range tables {
		for m := range t {
			methods = append(methods, m)
		}
	}
	sort.Strings(methods)
	return strings.Join(methods, ", ")
}

// dispatchInitialize answers a host initialize request by delegating to the
// per-transport buildInit responder. The shared kill gate runs at the dispatchRequest
// boundary (a killed session must not receive the upstream capability set — buildInit
// echoes them without consulting the PDP), so this handler no longer self-gates. Routing
// initialize through the shared dispatcher keeps its kill gate from being copy-maintained
// across the stdio and HTTP re-initialize sites. A missing buildInit (a misconfigured
// dispatchParams, only reachable in tests) fails closed with an internal error rather
// than a nil-call panic.
func dispatchInitialize(_ context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	if d.buildInit == nil {
		return mcp.ErrorResponse(msg.ID, jsonRPCCodeInternalError, "internal error: initialize responder not configured")
	}
	return d.buildInit(msg)
}

// dispatchPing answers the MCP utility ping locally with the spec's empty result.
//
// ping carries no arguments, names no target, and reaches no upstream, so there is
// nothing for a manifest to authorize — but falling through to dispatchUnmapped denied it
// with AUTHORIZATION_FAILED, which breaks the liveness probe every MCP host is entitled to
// send and writes a policy-denial record for a call that was never a policy question. That
// is a fail-closed default doing the wrong thing rather than a security property: nothing
// is protected by refusing to say "I am here".
//
// It is answered locally rather than forwarded so a ping cannot be used to probe upstream
// liveness through the proxy, and it sits inside the locally-answered set so the shared
// kill gate at the dispatchRequest boundary still applies: a killed session gets
// KILL_SWITCH, not a pong. No audit record — like initialize, this is a handshake-level
// utility that is not a guarded action, and recording every host heartbeat would bury the
// tape in noise.
func dispatchPing(msg mcp.RPCMsg) mcp.RPCMsg {
	return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{}`)}
}

// malformedDeny records a fail-closed audit deny for an enforced request rejected
// BEFORE the PDP is consulted — unparseable params or an empty required target — then
// returns the -32602 host response. Without the record these denials would leave no
// trace on the tamper-evident tape, unlike every PDP deny and dispatchUnmapped, so a
// probe of an enforced method with malformed input would be invisible to an auditor
// (the "deny AND log" invariant). The method fills both the method and target audit
// fields: the real target failed to parse or was empty, and the method is the only
// stable identifier (mirroring dispatchList, where the method IS the target).
//
// The audit code is codeInvalidRequest (a host protocol fault), NOT
// capability.ErrCodeInvalidParams: the target here is the METHOD name (the real target
// could not be parsed), so a policy-mining consumer must skip it — IsInfraDenialCode
// covers codeInvalidRequest, and suggest would otherwise fabricate a phantom target like
// "tool:tools/call". ErrCodeInvalidParams is reserved for the manifest argumentSchema
// denial, which carries a real target suggest must keep seeing. The host still gets the
// standard -32602 (invalid params) JSON-RPC code, independent of the audit classification.
func (d dispatchParams) malformedDeny(ctx context.Context, msg mcp.RPCMsg, reason string) mcp.RPCMsg {
	// Kill gate FIRST, so it uniformly precedes both malformed and well-formed enforced
	// handling. The well-formed Decide* path consults the kill switch inside
	// enforcedForwardCore, and the locally-answered set is gated at the dispatchRequest
	// boundary — but the malformed path sits between them: it is a Decide* method (so it
	// skips the boundary gate) yet is rejected BEFORE the PDP (so it never reaches
	// enforcedForwardCore). Without this call a revoked session probing an enforced method
	// with malformed params would be recorded as a request-shape fault (INVALID_REQUEST)
	// rather than KILL_SWITCH — invisible to KILL_SWITCH-keyed triage of the continued
	// activity. The request never reaches the upstream either way (the security property
	// is intact); this corrects which signal the tamper-evident record carries. This is
	// the one killDenied site the structural boundary gate cannot absorb.
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
	// The attribution interface: a cooperating client may attribute this call's inputs in
	// `_meta`, and those labels are unioned into the session's accumulated set for this
	// call's sink check. A malformed block is a malformed REQUEST, not a silently ignored
	// hint — a client that tried to attribute a call and got the shape wrong must find
	// out, rather than proceed believing a tightening is in force when it is not.
	//
	// Gated on honorAttribution, which is the DRAFT staging discipline: under the
	// published grammar the whole block — including that malformed-request rejection — is
	// skipped, so a `0.1` operator sees no behavior change from a token their grammar does
	// not contain. Ignoring rather than rejecting is the conservative direction here
	// because the interface is union-only and can only ever tighten.
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
	// Close the per-session decision critical section here — the decision and its flow/
	// sequence state write are done — so the upstream forward below runs concurrently.
	// Everything after this reads the settled dec.
	d.finishDecision()

	// In audit mode the allow record logs the full tool arguments; otherwise none.
	// Unlike resources/prompts, tools/call's details slot holds that argument map
	// rather than an upstream_error_code note.
	var toolDetails map[string]interface{}
	// Log arguments under route-level --audit OR a per-constraint enforcement:audit
	// decision (dec.AuditOnly). Guarding only on d.audit dropped the argument map for
	// an observe-mode constraint, leaving its allow records without the very detail
	// the operator attached audit mode to capture.
	if (d.audit || dec.AuditOnly) && len(params.Arguments) > 0 {
		toolDetails = params.Arguments
	}
	return enforcedForwardCore(ctx, d.forwardParams, msg, dec, capability.MethodToolsCall, params.Name, params.Name, "tool", true,
		func(upResp mcp.RPCMsg) map[string]interface{} {
			// Record the forwarded upstream's error code, as every other enforced method
			// does, so a tools/call the upstream rejected is not byte-for-byte identical
			// to a clean success on the tamper-evident tape. Reuse upstreamErrorDetail
			// (the shared source of the field name and the never-record-the-message rule)
			// and merge it into a COPY of toolDetails so the caller's live
			// params.Arguments map is never mutated. audit.UpstreamErrorCodeKey is
			// underscore-prefixed and reserved, so a host argument literally named
			// "upstream_error_code" (bare, no prefix) cannot collide with it in practice —
			// but the underscore-prefixed name itself is still just a caller-supplied
			// string, not something pkg/capability rejects as a tool argument name, so
			// keep the same collision guard the bare key used to need, just re-keyed onto
			// the new reserved name: on the vanishingly rare call whose real argument is
			// literally named "_eunox_upstream_error_code", nest instead of overwriting it.
			extra := upstreamErrorDetail(upResp)
			if extra == nil {
				return toolDetails
			}
			if _, collide := toolDetails[audit.UpstreamErrorCodeKey]; collide {
				return map[string]interface{}{
					"arguments":                toolDetails,
					audit.UpstreamErrorCodeKey: extra[audit.UpstreamErrorCodeKey],
				}
			}
			details := make(map[string]interface{}, len(toolDetails)+len(extra))
			for k, v := range toolDetails {
				details[k] = v
			}
			for k, v := range extra {
				details[k] = v
			}
			return details
		})
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
	d.finishDecision() // release the per-session decision lock before the forward
	return enforcedForwardCore(ctx, d.forwardParams, msg, dec, capability.MethodResourcesRead, params.URI, params.URI, "resource", true, upstreamErrorDetail)
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
	d.finishDecision() // release the per-session decision lock before the forward
	// recordObligations is false: a subscription does not log obligation names.
	return enforcedForwardCore(ctx, d.forwardParams, msg, dec, capability.MethodResourcesSubscribe, params.URI, params.URI, "resource subscription", false, upstreamErrorDetail)
}

// dispatchResourcesUnsubscribe enforces resources/unsubscribe against the SAME manifest
// entry as resources/read and resources/subscribe (identical wire shape: a single uri), but
// through DecideResourceCancel rather than DecideResourceRead — the URI must still be
// permitted, and no consumable policy state is charged for cancelling.
//
// It is mapped rather than left to the fail-closed default deliberately. Unmapped is the
// right default for a method whose effect the proxy cannot reason about, but this one is
// the exact inverse of a method that IS enforced and forwarded: a host that subscribed to
// a permitted resource could never cancel through the proxy, so the upstream kept pushing
// resource-updated notifications for the rest of the session. Denying it protected
// nothing — it only ever REDUCES data flow — while costing the host the one way to stop a
// stream it already established.
//
// Routing it through the cancel decision instead of the read decision is what makes that
// argument hold in practice. A read decision is metered: it spends the URI's maxCalls
// budget, records a sequenceBlock antecedent, and applies the entry's labelOutput taint.
// Charging a cancellation that way reintroduces the very failure this handler exists to
// remove — a one-call budget spent by the subscribe leaves the unsubscribe denied
// RATE_LIMITED, so the stream can never be stopped — and taints the session for a request
// that transfers no data. DecideResourceCancel keeps the match requirement (a URI the
// manifest never permitted was never subscribable, so an unsubscribe naming it is a host
// talking about a channel it does not have) and drops the metering, which also keeps the
// audit trail symmetric: every subscribe on the tape has its matching unsubscribe.
//
// d.decideCtx is deliberately NOT applied: its only effect is the observe-mode quota skip,
// and this path consumes no quota in either mode.
func dispatchResourcesUnsubscribe(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	var params mcp.ResourceReadParams
	if err := mcp.DecodeParams(msg.Params, &params); err != nil {
		return d.malformedDeny(ctx, msg, "invalid resources/unsubscribe params")
	}
	if params.URI == "" {
		return d.malformedDeny(ctx, msg, "resources/unsubscribe: uri must not be empty")
	}
	dec := d.pdp.DecideResourceCancel(ctx, d.sessionID, params.URI, d.sourceIP)
	d.finishDecision() // release the per-session decision lock before the forward
	// recordObligations is false: cancelling a subscription does not log obligation names.
	return enforcedForwardCore(ctx, d.forwardParams, msg, dec, capability.MethodResourcesUnsubscribe, params.URI, params.URI, "resource subscription", false, upstreamErrorDetail)
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
	d.finishDecision() // release the per-session decision lock before the forward
	// auditID carries the "prompts/" display prefix; denialTarget is the bare name.
	return enforcedForwardCore(ctx, d.forwardParams, msg, dec, capability.MethodPromptsGet, "prompts/"+params.Name, params.Name, "prompt", true, upstreamErrorDetail)
}

// dispatchList forwards a */list request to the upstream and prunes the result
// to permitted entries (filter selects the ListFilterer method for the flavor).
// When no policy is configured an enforce route uses DenyAllPDP and the list is
// filtered to empty (fail closed); only an audit-mode (AlwaysAllowPDP) wiretap
// route returns the upstream catalog unfiltered. The enumeration is recorded —
// listing is a common reconnaissance step — and upstreamErrorDetail distinguishes
// a forwarded upstream error from a clean enumeration.
func dispatchList(ctx context.Context, d dispatchParams, msg mcp.RPCMsg, filter func(pdp.ListFilterer, context.Context, json.RawMessage) pdp.ListFilterResult) mcp.RPCMsg {
	// The kill-switch check runs at the dispatchRequest boundary for the whole
	// locally-answered set (a killed session must not enumerate the catalog), so this
	// handler no longer self-gates. The enforced Decide* paths embed their own check;
	// */list does not flow through them, hence its place in the boundary-gated set.

	// --require-audit=strict: once the audit trail has degraded, fail the
	// enumeration closed rather than forward an unrecorded one (mirroring
	// enforcedForwardCore). strictAuditDenial's three string args (audit id, method,
	// denial target) all collapse to the method name here: a */list request
	// addresses no sub-target, so the method IS the target. The repetition is
	// intentional.
	if denied, blocked := d.strictAuditDenial(ctx, msg, msg.Method, msg.Method, msg.Method); blocked {
		return denied
	}

	// The ListFilterer/RecordObservedToolHashes seams take (ctx, result) and no session —
	// unlike the enforced Decide* paths, which receive it as a parameter — so the session
	// id rides the context, as JWT claims already do. The Tier-2 interface baseline is
	// per-session (see pdp.SurfaceBaseline), so both paths below need it.
	ctx = pdp.WithSessionID(ctx, d.sessionID)

	upResp, err := d.callUpstream(ctx, msg)
	if err != nil {
		return d.recordUpstreamFailure(ctx, msg, err, msg.Method, msg.Method)
	}

	// Defense-in-depth: a non-error response carrying no result is malformed, and
	// forwarding it verbatim would bypass list filtering (filtering operates on the
	// result). callUpstream now rejects a neither-result-nor-error reply before it
	// returns (awaitNonced's isMalformedResponse check, shared with the HTTP-upstream
	// bridge), so this is no longer reachable via a live upstream — but it is kept as
	// a cheap fail-closed backstop against a future path that bypasses that check.
	// (An upstream ERROR response — Error != nil, Result nil — is a legitimate
	// diagnostic and is forwarded below.)
	if upResp.Error == nil && upResp.Result == nil {
		warnIfStrictAuditJustDegraded(d.requireAuditStrict, d.rec, msg.Method, msg.Method, func() {
			if d.rec != nil {
				d.rec.RecordDeny(ctx, d.sessionID, msg.Method, msg.Method, capability.ErrCodeEnforcementError, "", nil, false)
			}
		})
		return mcp.ErrorResponse(msg.ID, jsonRPCCodeInternalError, "upstream returned a malformed list response (no result and no error)")
	}

	// In audit (observe/wiretap) mode the enumeration must return the full upstream
	// catalog: filtering here would hide tools the host can still CALL (deny
	// downgraded to observe), contradicting "observe everything, block nothing".
	//
	// The upstream and filtered entry counts feed only the allow record below.
	var upstreamCount, filteredCount int
	switch {
	case upResp.Result != nil && !d.audit:
		// Only the manifest filter is bypassed in audit mode; the kill-switch check
		// above stays unconditional (a kill hard-blocks even in audit mode). d.pdp is
		// always non-nil (see dispatchParams), so a "no policy" route uses DenyAllPDP —
		// which filters the catalog to empty — rather than forwarding it verbatim. The
		// filter computes both entry counts while pruning, so the record reads them
		// directly rather than re-parsing the catalog.
		fr := filter(d.pdp, ctx, upResp.Result)
		upResp.Result = fr.Result
		upstreamCount, filteredCount = fr.Upstream, fr.Kept()
	case msg.Method == capability.MethodToolsList && upResp.Result != nil:
		// Audit mode tools/list (the enforce-mode case above already handled a non-audit
		// non-nil result, so reaching here means audit mode; the filter is bypassed, so
		// upstream == filtered — the full catalog is forwarded verbatim). This is what
		// lets the call-leg descriptionHash pin fire on a mid-session description
		// rotation, a hard deny that must hold EVEN under --audit — so it runs
		// UNCONDITIONALLY, never gated on d.rec: an audit-mode route with no sink
		// configured must still have that defense armed, not silently disarmed for lack
		// of a configured recorder. Its return value is this decode's entry count, so no
		// second decode of the same bytes is needed for the audit record below.
		upstreamCount = d.pdp.RecordObservedToolHashes(ctx, upResp.Result)
		filteredCount = upstreamCount
	case d.rec != nil:
		// Audit mode on resources/prompts (no descriptionHash pin to arm), or a nil
		// result: the verbatim upstream catalog is returned with no filtering, so
		// upstream == filtered. Count only when a recorder will actually read it, so a
		// route with no sink pays no decode cost here.
		upstreamCount = pdp.CountListEntries(msg.Method, upResp.Result)
		filteredCount = upstreamCount
	}

	// AuditOnly never applies to list methods (no per-entry deny to downgrade), so
	// d.audit alone carries the observe posture. The allow details carry filter
	// statistics so an auditor can tell an empty client view caused by policy
	// filtering from a genuinely empty upstream. This *list enumeration follows the
	// same gate-before/record-after shape as enforcedForwardCore, so it gets the
	// same immediate boundary-call diagnostic under strict mode.
	warnIfStrictAuditJustDegraded(d.requireAuditStrict, d.rec, msg.Method, msg.Method, func() {
		if d.rec != nil {
			d.rec.RecordAllow(ctx, d.sessionID, msg.Method, msg.Method, listAllowDetails(upResp, upstreamCount, filteredCount, d.audit), nil, d.audit, nil, nil)
		}
	})

	upResp.ID = msg.ID
	return upResp
}

// listAllowDetails builds the structured audit details for a */list allow:
// filter statistics (upstream/filtered/suppressed counts) plus, when present, the
// forwarded upstream JSON-RPC error code. The counts live in the existing details
// map (no new top-level audit field) and show how much the manifest pruned.
// observeMode marks the audit/observe posture so a reader can tell a 0 suppressed
// count caused by bypassed filtering from one caused by an all-permitting manifest.
func listAllowDetails(upResp mcp.RPCMsg, upstreamCount, filteredCount int, observeMode bool) map[string]interface{} {
	details := map[string]interface{}{
		"upstream_count":   upstreamCount,
		"filtered_count":   filteredCount,
		"suppressed_count": upstreamCount - filteredCount,
	}
	// In audit (observe) mode the manifest filter is bypassed, so suppressed_count is 0
	// because nothing was filtered — NOT because the manifest permits every entry. Stamp
	// observe_mode so an auditor comparing an enforce-mode log to an observe-mode one
	// does not misread "suppressed_count: 0" as "policy allows all". Only set when true,
	// so enforce-mode records keep their existing shape.
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

// dispatchUnmapped is the fail-closed default: an unmapped MCP method is denied
// with AUTHORIZATION_FAILED and never forwarded to the upstream. The method name
// is logged so operators can detect protocol drift or novel MCP extensions.
func dispatchUnmapped(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	// The kill-switch check runs at the dispatchRequest boundary for the whole
	// locally-answered set, so a killed session is reported as KILL_SWITCH (not
	// AUTHORIZATION_FAILED) before ever reaching this handler — triage and
	// KILL_SWITCH-keyed alerting see the revocation. This handler is the fail-closed
	// default for a live session's unmapped method.
	// msg.Method is attacker-controlled (it arrives in the host JSON-RPC envelope).
	// %q already escapes control runes, but sanitize first for defense in depth and
	// consistency with the audit log's own diagnostic output, so a method name
	// carrying control characters cannot shape this line for a downstream log parser.
	// Sanitize once and reuse for the host-facing denial too: the method also flows
	// into denialResult's error message, so the two host/log surfaces stay symmetric.
	// The structured audit field stays the raw method — the record is JSON-encoded,
	// which escapes control runes, and RecordDeny owns its own fields.
	sanitizedMethod := audit.SanitizeAuditField(msg.Method)
	// Record-before-act: write the tamper-evident audit record before the stderr
	// notice, so a crash between the two never leaves a SIEM alert with no
	// corresponding audit trail entry.
	if d.rec != nil {
		d.rec.RecordDeny(ctx, d.sessionID, msg.Method, msg.Method, capability.ErrCodeAuthorizationFailed, "", nil, false)
	}
	fmt.Fprintf(os.Stderr,
		"[eunox] SECURITY: unmapped MCP method %q denied (AUTHORIZATION_FAILED) — not forwarded\n",
		sanitizedMethod,
	)
	return denialResult(msg.ID, capability.ErrCodeAuthorizationFailed, "", sanitizedMethod, "")
}
