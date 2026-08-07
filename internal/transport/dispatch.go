// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Shared request dispatch: the single method→handler mapping and fail-closed
// default both transports route enforced MCP requests through.

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	// revision is the MCP protocol revision this request was negotiated under; it selects
	// the dispatch tables. The zero value means the caller never negotiated one and resolves
	// to capability.DefaultRevision (see tablesFor) — the surface eunox already shipped, so
	// omission can never reach a different method set.
	revision capability.Revision

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
type methodSpec struct {
	// In lists the revisions this method exists in. An entry declaring none is refused by
	// buildRevisionDispatch (dispatched under no revision) and fails
	// TestMethodRegistry_EveryMethodDeclaresRevisionMembership.
	In []capability.Revision
	// Handler answers the request framing; nil for a notification-only method.
	Handler methodHandler
	// Enforced marks Handler as a Decide* handler — the one that carries its own kill
	// record and takes the decision turn. It is what isEnforcedMethod derives from, so
	// "is this enforced" and "which handler runs" cannot diverge.
	Enforced bool
	// Notification is the disposition of this method's notification framing.
	Notification notificationDisposition
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
// until the workstreams that implement them land, so they deny fail-closed meanwhile rather
// than routing to a handler that does not exist.
var methodRegistry = map[string]methodSpec{
	// Enforced (Decide*) methods. The resources/subscribe pair is 2025-11-25 only:
	// 2026-07-28 replaces it with subscriptions/listen, which is not implemented yet.
	capability.MethodToolsCall: {
		In:       []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Handler:  dispatchToolsCall,
		Enforced: true,
	},
	capability.MethodResourcesRead: {
		In:       []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Handler:  dispatchResourcesRead,
		Enforced: true,
	},
	capability.MethodResourcesSubscribe: {
		In:       []capability.Revision{capability.Revision20251125},
		Handler:  dispatchResourcesSubscribe,
		Enforced: true,
	},
	capability.MethodResourcesUnsubscribe: {
		In:       []capability.Revision{capability.Revision20251125},
		Handler:  dispatchResourcesUnsubscribe,
		Enforced: true,
	},
	capability.MethodPromptsGet: {
		In:       []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Handler:  dispatchPromptsGet,
		Enforced: true,
	},

	// Locally answered methods. initialize and ping are handshake/utility methods
	// 2026-07-28 removes; the three */list methods exist in both revisions.
	mcp.MethodInitialize: {
		In:      []capability.Revision{capability.Revision20251125},
		Handler: dispatchInitialize,
		// "initialize" can arrive with no id (a notification by IsNotification's structural
		// classification); forwarding it verbatim would re-trigger the upstream handshake
		// outside the kill gate, so the notification framing is swallowed.
		Notification: notifySwallow,
	},
	methodPing: {
		In: []capability.Revision{capability.Revision20251125},
		Handler: func(_ context.Context, _ dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
			return dispatchPing(msg)
		},
	},
	capability.MethodResourcesList: {
		In: []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Handler: func(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
			return dispatchList(ctx, d, msg, pdp.ListFilterer.FilterResourcesList)
		},
	},
	capability.MethodToolsList: {
		In: []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Handler: func(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
			return dispatchList(ctx, d, msg, pdp.ListFilterer.FilterToolsList)
		},
	},
	capability.MethodPromptsList: {
		In: []capability.Revision{capability.Revision20251125, capability.Revision20260728},
		Handler: func(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
			return dispatchList(ctx, d, msg, pdp.ListFilterer.FilterPromptsList)
		},
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

// revisionTables is one revision's four derived routing tables — the shape the dispatcher
// and the two transports actually consult.
type revisionTables struct {
	decide               map[string]methodHandler
	local                map[string]methodHandler
	forwardNotifications map[string]struct{}
	swallowNotifications map[string]struct{}
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
			decide:               map[string]methodHandler{},
			local:                map[string]methodHandler{},
			forwardNotifications: map[string]struct{}{},
			swallowNotifications: map[string]struct{}{},
		}
	}
	for method, spec := range registry {
		for _, rev := range spec.In {
			tables, ok := out[rev]
			if !ok {
				continue // a revision this build does not speak: contribute nothing
			}
			if spec.Handler != nil {
				if spec.Enforced {
					tables.decide[method] = spec.Handler
				} else {
					tables.local[method] = spec.Handler
				}
			}
			switch spec.Notification {
			case notifyForward:
				tables.forwardNotifications[method] = struct{}{}
			case notifySwallow:
				tables.swallowNotifications[method] = struct{}{}
			case notifyUnmapped:
				// The fail-closed default: recorded and dropped, no table entry.
			}
		}
	}
	return out
}

// tablesFor returns the routing tables for rev.
//
// The zero Revision resolves to capability.DefaultRevision: a dispatchParams built without
// an explicit revision is a caller that never negotiated one, and the old revision is the
// surface eunox already shipped. An unknown non-empty revision resolves to EMPTY tables
// instead — it was declared and cannot be honored, so every method falls to the fail-closed
// default rather than borrowing another revision's set.
func tablesFor(rev capability.Revision) revisionTables {
	if rev == "" {
		rev = capability.DefaultRevision
	}
	return revisionDispatch[rev]
}

// isEnforcedMethod reports whether method is one of rev's Decide* methods, derived from the
// same declarations dispatchRequest routes by so the two cannot drift.
func isEnforcedMethod(rev capability.Revision, method string) bool {
	_, ok := tablesFor(rev).decide[method]
	return ok
}

// isSwallowedHostNotification reports whether a host->upstream notification of this method
// must be dropped silently under rev rather than forwarded or recorded.
func isSwallowedHostNotification(rev capability.Revision, method string) bool {
	_, ok := tablesFor(rev).swallowNotifications[method]
	return ok
}

// isForwardableHostNotification reports whether a host->upstream notification of this
// method is allowlisted for verbatim forwarding under rev.
func isForwardableHostNotification(rev capability.Revision, method string) bool {
	_, ok := tablesFor(rev).forwardNotifications[method]
	return ok
}

// denyUnmappedHostNotification denies (and records) a notification outside the requesting
// peer's forwardable allowlist — the notification-framed analogue of dispatchUnmapped.
// Shared by both transports so the check and record live once. Returns true when msg was
// denied. Before this existed, an unrecognized notification-framed method reached the
// upstream invisibly while its request-framed twin was denied and logged.
func denyUnmappedHostNotification(ctx context.Context, w io.Writer, rec auditRecorder, sessionID string, rev capability.Revision, msg mcp.RPCMsg) bool {
	if isForwardableHostNotification(rev, msg.Method) {
		return false
	}
	if rec != nil {
		rec.RecordDeny(ctx, sessionID, msg.Method, msg.Method, capability.ErrCodeAuthorizationFailed, "", nil, false)
	}
	_, _ = fmt.Fprintf(resolvedErrOut(w),
		"[eunox] SECURITY: unmapped notification method %q denied (AUTHORIZATION_FAILED) — not forwarded\n",
		audit.SanitizeAuditField(msg.Method))
	return true
}

// denyEnforcedMethodNotification denies (and records) an enforced Decide* method smuggled in
// via notification framing (no id) rather than request framing — forwarding it verbatim would
// bypass both the PDP decision and the audit record. Shared by both transports; returns true
// when msg was denied.
func denyEnforcedMethodNotification(ctx context.Context, rec auditRecorder, sessionID string, rev capability.Revision, msg mcp.RPCMsg) bool {
	if !isEnforcedMethod(rev, msg.Method) {
		return false
	}
	if rec != nil {
		rec.RecordDeny(ctx, sessionID, msg.Method, msg.Method, codeInvalidRequest, "", nil, false)
	}
	return true
}

// dispatchRequest routes an enforced MCP request to its handler and returns the JSON-RPC
// message to deliver to the host — the single source of truth for the method→handler mapping
// and the fail-closed default both transports share.
//
// The kill gate is applied STRUCTURALLY: Decide* methods embed their own richer kill record
// inside enforcedForwardCore and skip the boundary gate; every other (locally-answered) method
// shares one simple gate applied here, so a new locally-answered method inherits revocation by
// construction rather than needing killDenied re-placed inside its handler.
func dispatchRequest(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	tables := tablesFor(d.revision)
	if handler, ok := tables.decide[msg.Method]; ok {
		return handler(ctx, d, msg)
	}

	// Locally-answered set shares one simple kill gate applied once here. A killed session is
	// recorded as KILL_SWITCH (not the method's own code) and never contacts the upstream.
	if resp, killed := d.killDenied(ctx, msg); killed {
		return resp
	}
	if handler, ok := tables.local[msg.Method]; ok {
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
var enforcedMethodSummary = sortedMethods(func() map[string]methodHandler {
	all := map[string]methodHandler{}
	for _, tables := range revisionDispatch {
		for method, handler := range tables.decide {
			all[method] = handler
		}
	}
	return all
}())

// unmappedMethodExamples names MCP methods this build does NOT dispatch, so the banner's
// caveat is concrete rather than abstract. They are examples, not an exhaustive list:
// anything outside the two routing tables is denied the same way.
const unmappedMethodExamples = "e.g. completion/complete, logging/setLevel, resources/templates/list"

// sortedMethods joins a routing table's keys in sorted order, so a banner derived from a
// table cannot drift from what the dispatcher does, and a map's iteration order cannot make
// the text unstable.
func sortedMethods(table map[string]methodHandler) string {
	methods := make([]string, 0, len(table))
	for m := range table {
		methods = append(methods, m)
	}
	sort.Strings(methods)
	return strings.Join(methods, ", ")
}

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
// authorizes nothing, so falling through to dispatchUnmapped's AUTHORIZATION_FAILED broke a
// liveness probe every host is entitled to send. Answered locally (not forwarded) so a ping
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
		// account contradicts the contract policy was written against.
		_, _ = fmt.Fprintf(d.errOutOrStderr(),
			"[eunox] WARN effect-receipt tool=%q — the upstream's signed receipt contradicts the effect contract this policy declares (%s); the call already ran, so this is evidence, not a refusal\n",
			audit.SanitizeAuditField(tool), strings.Join(result.Reasons, ", "))
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

// dispatchUnmapped is the fail-closed default: an unmapped MCP method is denied
// with AUTHORIZATION_FAILED and never forwarded to the upstream. The method name
// is logged so operators can detect protocol drift or novel MCP extensions.
func dispatchUnmapped(ctx context.Context, d dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg {
	// Kill-switch check runs at the dispatchRequest boundary, so a killed session is reported
	// as KILL_SWITCH before reaching this handler. msg.Method is attacker-controlled; sanitize
	// once and reuse for both the stderr line and the host-facing denial. The structured audit
	// field stays raw (JSON-encoding already escapes control runes).
	sanitizedMethod := audit.SanitizeAuditField(msg.Method)
	// Record-before-act: write the audit record before the stderr notice, so a crash between
	// the two never leaves a SIEM alert with no corresponding audit trail entry.
	if d.rec != nil {
		d.rec.RecordDeny(ctx, d.sessionID, msg.Method, msg.Method, capability.ErrCodeAuthorizationFailed, "", nil, false)
	}
	_, _ = fmt.Fprintf(d.errOutOrStderr(),
		"[eunox] SECURITY: unmapped MCP method %q denied (AUTHORIZATION_FAILED) — not forwarded\n",
		sanitizedMethod,
	)
	return denialResult(msg.ID, capability.ErrCodeAuthorizationFailed, "", sanitizedMethod, "")
}
