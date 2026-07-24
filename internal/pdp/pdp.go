// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package pdp holds the policy-decision-point layer: the PolicyDecisionPoint
// contract and its implementations (ManifestPDP, JWTPDP, AlwaysAllowPDP) that
// decide whether an MCP request is permitted, filter */list responses to the
// permitted entries, and authorize sampling. It depends on pkg/* (capability,
// enforcement, killswitch, and — for JWT verification — circuitbreaker) plus
// go-jose; the transports in cmd/eunox consume it through these exported types.
package pdp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// EnforceTarget identifies the namespace type and bare name of the resource
// being enforced. Type is the namespace prefix (tool, resource, prompt,
// system); Name is the unprefixed name supplied by the MCP caller.
type EnforceTarget struct {
	Type capability.TargetType
	Name string
}

// PolicyDecisionPoint evaluates whether an MCP request should be permitted,
// returning the same capability.EnforceResponse the enforcement engine uses.
// Every implementation must decide every method explicitly — no silent
// fall-through to "forward verbatim".
type PolicyDecisionPoint interface {
	Decide(ctx context.Context, sessionID string, target EnforceTarget, args map[string]interface{}, sourceIP string) capability.EnforceResponse
	DecideResourceRead(ctx context.Context, sessionID, uri, sourceIP string) capability.EnforceResponse
	DecidePromptGet(ctx context.Context, sessionID, promptName, sourceIP string) capability.EnforceResponse

	// Folded into the contract so every PDP implements them and the transport
	// calls them directly (no optional-interface type assertion).
	ListFilterer
	SamplingAuthorizer

	// CheckKill returns a non-nil deny when the session is killed (or the kill
	// store errors, fail closed), nil otherwise. The */list handlers call it
	// BEFORE contacting the upstream — the Decide* paths embed the same check, but
	// */list does not flow through them, so without it a killed session could still
	// enumerate the catalog. A PDP with no kill switch wired returns nil.
	CheckKill(ctx context.Context, sessionID string) *capability.EnforceResponse

	// CheckAudience returns a non-nil deny when the session's validated token does not
	// carry this route's required audience (the per-route JWT audience pin), nil
	// otherwise. The session-creating initialize path calls it BEFORE spawning/contacting
	// the route's upstream — the Decide*/list/sampling paths embed the same pin, but
	// initialize does not flow through them, so without it a token valid only for ANOTHER
	// route's audience (accepted by the gateway's shared union validator) could spin up
	// THIS route's upstream and read its serverInfo. Mirrors CheckKill's pre-spawn role.
	// A PDP that pins no token audience (every non-JWT PDP, or a JWT route with no
	// audience pinned / --jwt-allow-any-audience) returns nil.
	CheckAudience(ctx context.Context) *capability.EnforceResponse

	// RecordObservedToolHashes records the live description hash of each pinned tool in a
	// tools/list result WITHOUT filtering the catalog, and returns the number of tool
	// entries in result (mirroring CountListEntries, computed as a byproduct of the same
	// decode rather than a second one). The enforce-mode list filter (FilterToolsList)
	// already records these as a side effect of pruning, but audit-mode (observe) routes
	// forward tools/list VERBATIM and skip the filter — so without this pass the
	// observed-hash map stays empty and the call-leg descriptionHash pin (a hard deny that
	// must fire even under --audit) can never trip on a mid-session description rotation.
	//
	// The caller (dispatchList) must invoke this UNCONDITIONALLY on the audit-mode
	// tools/list path — never gated on whether an audit recorder is configured. The pin
	// this feeds is a security control, not audit-logging bookkeeping: an audit-mode route
	// running with no sink configured must still have the poisoning defense armed.
	RecordObservedToolHashes(ctx context.Context, result json.RawMessage) (entryCount int)

	// ReleaseSession releases per-session enforcement state when the transport tears a
	// session down (idle reap, client DELETE, kill, shutdown, or natural upstream exit),
	// so an ended session retains no state and a reused session id starts clean. Today
	// that is the session's accumulated flow-label set; it is the one teardown seam any
	// future per-session state reuses. It must be
	// a safe no-op for a PDP with no such state (AlwaysAllowPDP, DenyAllPDP) and for a
	// session that recorded none, and must never block on the upstream — teardown paths
	// call it with a detached, bounded context.
	ReleaseSession(ctx context.Context, sessionID string)
}

// ListFilterer filters tools/resources/prompts list results down to the entries
// the PDP would permit; AlwaysAllowPDP (wiretap) passes them through unchanged.
// The context carries any JWT claims attached by the HTTP layer; PDPs that do
// not need them (e.g. ManifestPDP) ignore the context.
//
// Each method returns a ListFilterResult: the pruned result plus the pre- and
// post-filter entry counts the filter already computed while pruning. The
// transport records those counts directly instead of re-parsing the catalog, so
// a large */list payload is parsed once per call rather than three times.
type ListFilterer interface {
	FilterToolsList(ctx context.Context, result json.RawMessage) ListFilterResult
	FilterResourcesList(ctx context.Context, result json.RawMessage) ListFilterResult
	FilterPromptsList(ctx context.Context, result json.RawMessage) ListFilterResult
}

// ListFilterResult is the outcome of filtering a */list result: the pruned
// result envelope plus the entry counts a recorder needs, so the transport need
// not re-parse the (potentially large) catalog to audit how much was suppressed.
//
// Upstream is the entry count BEFORE filtering; Kept() is the count AFTER,
// derived from len(Entries) so it is definitionally consistent with the survivor
// set rather than a separately-maintained field a producer could set inconsistently.
// On a fail-closed parse error the result is an empty list, Entries is nil, and both
// Upstream and Kept() are 0 — best-effort audit accounting, never an enforcement input.
//
// Entries is the surviving entries pre-parsed (the same json.RawMessage slice the
// filter just produced), exposed so a layered filter — the JWT PDP intersecting
// with an inner PDP — applies its second pass to these in memory instead of
// re-parsing Result. nil when the result could not be parsed (fail closed).
//
// CONTRACT: Entries MUST mirror the entries in Result's list field. The JWT
// intersection treats Entries as the authoritative survivor set (it re-splices a
// claim-filtered subset of Entries back into Result), so a ListFilterer that
// returns Entries inconsistent with Result would corrupt the intersection. Every
// in-tree producer (filterListResult, passThroughList) upholds this; a fail-closed
// return reports nil Entries, which the intersection treats as an empty listing.
type ListFilterResult struct {
	Result   json.RawMessage
	Entries  []json.RawMessage
	Upstream int
	// unexported: intra-package reuse in the JWT intersection to avoid re-parsing Result.
	envKeys   []string
	envValues map[string]json.RawMessage
	entryIDs  []string // decoded identifier (name/uri) per Entries[i]; "" when the keep func decoded none; nil slice when unavailable
}

// Kept returns the count of entries that survived filtering. It is len(Entries) by
// definition — the surviving set IS the kept entries — so it cannot drift from
// Entries the way a separately-stored field could. filtered_count in the audit
// record is therefore always consistent with the emitted catalog.
func (r ListFilterResult) Kept() int { return len(r.Entries) }

// List result envelope array keys — aliases of the pkg/capability single source
// of truth (shared with the transport dispatch map via capability.ListResultKey)
// so the filter helpers here and the transport layer cannot disagree on where a
// */list flavor carries its entries.
const (
	listKeyTools     = capability.ListKeyTools
	listKeyResources = capability.ListKeyResources
	listKeyPrompts   = capability.ListKeyPrompts
)

// CountListEntries returns the number of entries in a */list method's result
// array, or 0 for a non-list method or an empty/absent/unparseable result.
//
// It is the audit-accounting counterpart to the ListFilterer methods, which
// return the counts as a by-product of filtering. The transport uses it only on
// the audit (observe/wiretap) path, where the full upstream catalog is forwarded
// UNFILTERED — the filter, and its free counts, are deliberately skipped — so the
// upstream count must be obtained without applying policy. Best-effort, never an
// enforcement input.
func CountListEntries(method string, result json.RawMessage) int {
	key := capability.ListResultKey(method)
	if key == "" {
		return 0
	}
	return countListEntries(result, key)
}

// countListEntries returns the number of entries in the fieldName array of a
// */list result envelope, or 0 for an empty/absent/unparseable result. It backs
// the exported CountListEntries (the audit/wiretap best-effort entry count); the
// filter paths (passThroughList, filterListResult) decode entries from their own
// key-ordered envelope decode instead, so they preserve sibling fields and key
// order, so this stays a length-only helper.
func countListEntries(result json.RawMessage, fieldName string) int {
	if len(result) == 0 {
		return 0
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(result, &envelope); err != nil {
		return 0
	}
	rawArray, ok := envelope[fieldName]
	if !ok {
		return 0
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(rawArray, &entries); err != nil {
		return 0
	}
	return len(entries)
}

// passThroughList wraps an unfiltered */list result as a ListFilterResult,
// counting its entries once so Upstream == Kept() reflects the catalog the host
// will see. Used by the wiretap passthrough (AlwaysAllowPDP) and the JWT
// nil-inner delegate, neither of which prunes anything — so the deliberate
// pass-through is stated once: each call site is a pass-through by design, not a
// copy-paste oversight, and a fourth list method added later inherits the intent
// (and the count) from a single place.
func passThroughList(result json.RawMessage, fieldName string) ListFilterResult {
	keys, values, err := decodeOrderedObject(result)
	if err != nil {
		// Envelope malformed (non-object): no entries to expose, nothing to carry.
		return ListFilterResult{Result: result, Upstream: 0}
	}
	// Read entries straight from the already-decoded envelope value (one parse, not a
	// second whole-envelope unmarshal). Entries is populated (not just counted) so a
	// JWT intersection layered over this passthrough applies its claim filter to the
	// pre-parsed slice without re-parsing.
	var entries []json.RawMessage
	if raw, ok := values[fieldName]; ok {
		_ = json.Unmarshal(raw, &entries) // nil on a non-array value, matching countListEntries
	}
	return ListFilterResult{Result: result, Entries: entries, Upstream: len(entries),
		envKeys: keys, envValues: values}
}

// SamplingAuthorizer decides whether server-initiated sampling
// (sampling/createMessage from the upstream) is permitted. Sampling is
// deny-by-default: a PDP whose policy carries no explicit opt-in denies.
// Implementations must check the kill switch and fail closed on a kill-store
// error — this is the only enforcement point on the upstream-initiated path.
//
// sourceIP is the session's originating client IP (empty on stdio, which has no
// network client), threaded through so an ipRange condition on the opt-in
// evaluates against a real address instead of failing closed with MISSING_CONTEXT.
type SamplingAuthorizer interface {
	DecideSampling(ctx context.Context, sessionID, sourceIP string) capability.EnforceResponse
}

// killCheck consults the kill switch and returns a non-nil deny response when
// the call must be blocked: an active kill matching the agent/session/global
// dimension, or a kill-store error (fail closed).  A nil ks imposes no check
// (JWT-only mode).  The agent dimension is taken from JWT claims in ctx.
func killCheck(ctx context.Context, ks killswitch.Checker, sessionID string) *capability.EnforceResponse {
	if ks == nil {
		return nil
	}
	blocked, err := ks.ShouldBlock(ctx, agentIDFromContext(ctx), sessionID)
	if err != nil {
		deny := denyResponse(nil, capability.ErrCodeKillSwitchError, "", "kill switch check failed: "+err.Error())
		return &deny
	}
	if blocked {
		deny := denyResponse(nil, capability.ErrCodeKillSwitch, "", "session has been terminated by a kill-switch command")
		return &deny
	}
	return nil
}

// IsKillSwitchDenial reports whether a denial originated from the kill switch
// (an active kill or a kill-store error). These are an operator emergency stop
// and must hard-block even in audit (observe) mode, unlike policy denials, which
// audit mode logs and forwards.
func IsKillSwitchDenial(d *capability.DenialInfo) bool {
	return d != nil && (d.Code == capability.ErrCodeKillSwitch || d.Code == capability.ErrCodeKillSwitchError)
}

// denyResponse builds a deny EnforceResponse. Like newAllowResponse it stamps a
// fresh RequestID and RFC3339Nano DecidedAt — the audit-correlation fields the
// engine stamps on every deny — so a PDP-layer deny is never structurally
// incomplete. now comes from clockNow (a nil clock falls back to the wall clock),
// so a frozen test clock is honored on the deny path identically to the allow path.
func denyResponse(clock enforcement.Clock, code, condType, message string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision:  capability.DecisionDeny,
		RequestID: enforcement.NewRequestID(),
		DecidedAt: clockNow(clock).UTC().Format(time.RFC3339Nano),
		Denial: &capability.DenialInfo{
			Code:          code,
			ConditionType: condType,
			Message:       message,
		},
	}
}

// hardDenyResponse builds a deny that must never be downgraded to an audit-mode
// forward — neither by decideTarget's stamp() (a per-constraint enforcement:audit
// downgrade) nor by the transport's isObserveDeny gate (a route running under
// --audit). Use it for any deny that is an engine bug or a non-negotiable security
// gate rather than a downgradable policy verdict (e.g. an unenforceable stray
// argumentSchema, a tool-poisoning descriptionHash mismatch, an engine-evaluation
// error, an unhandled target type, or an antecedent-record failure). Analogous to
// the kill-switch treatment.
func hardDenyResponse(clock enforcement.Clock, code, message string) capability.EnforceResponse {
	resp := denyResponse(clock, code, "", message)
	resp.Denial.HardDeny = true
	return resp
}

// -----------------------------------------------------------------
// AlwaysAllowPDP — transparent passthrough
// -----------------------------------------------------------------

// AlwaysAllowPDP is the transparent passthrough used by audit/wiretap mode:
// every method forwards and logs the call, applying no policy. The optional clock
// supplies the wiretap-allow DecidedAt (nil falls back to the wall clock, so a
// test can freeze time).
//
// The optional kill switch (ks) is the one thing a wiretap route still enforces:
// when wired (NewAlwaysAllowPDP) a global or session-targeted /control/kill
// hard-blocks even this policyless route. A zero-value AlwaysAllowPDP{} carries no
// kill switch and never blocks — the pure-passthrough form tests use.
type AlwaysAllowPDP struct {
	clock enforcement.Clock
	ks    killswitch.Checker
}

// NewAlwaysAllowPDP builds a wiretap PDP wired to the shared kill switch, so an
// operator's emergency stop halts even a policyless audit/wiretap route. ks may be
// nil, in which case the route never blocks (bare AlwaysAllowPDP{} behavior).
func NewAlwaysAllowPDP(ks killswitch.Checker) AlwaysAllowPDP {
	return AlwaysAllowPDP{ks: ks}
}

// wiretapAllow builds the allow response audit-only (wiretap) mode returns.
func (p AlwaysAllowPDP) wiretapAllow() capability.EnforceResponse {
	return newAllowResponse(p.clock)
}

// clockNow returns the current instant from c when non-nil, falling back to the
// real wall clock. Centralizing the nil-check keeps the injected-clock fallback
// identical across every PDP allow path.
func clockNow(c enforcement.Clock) time.Time {
	if c != nil {
		return c.Now()
	}
	return time.Now()
}

// newAllowResponse builds the allow response shared by the PDP paths that decide
// allow without the enforcement engine (AlwaysAllowPDP wiretap, JWTPDP's JWT-only
// grant). It stamps a fresh RequestID and RFC3339Nano DecidedAt — the
// audit-correlation fields the engine generates for every decision — so these
// records are never structurally incomplete. now comes from clockNow.
func newAllowResponse(clock enforcement.Clock) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision:  capability.DecisionAllow,
		RequestID: enforcement.NewRequestID(),
		DecidedAt: clockNow(clock).UTC().Format(time.RFC3339Nano),
	}
}

// Decide returns a wiretap allow for every tools/call: audit/wiretap mode applies
// no policy and forwards the call after logging it — unless the kill switch is
// active, which hard-blocks even a wiretap route.
func (p AlwaysAllowPDP) Decide(ctx context.Context, sessionID string, _ EnforceTarget, _ map[string]interface{}, _ string) capability.EnforceResponse {
	if deny := p.CheckKill(ctx, sessionID); deny != nil {
		return *deny
	}
	return p.wiretapAllow()
}

// DecideResourceRead returns a wiretap allow for every resources/read, unless a
// kill is active.
func (p AlwaysAllowPDP) DecideResourceRead(ctx context.Context, sessionID, _, _ string) capability.EnforceResponse {
	if deny := p.CheckKill(ctx, sessionID); deny != nil {
		return *deny
	}
	return p.wiretapAllow()
}

// DecidePromptGet returns a wiretap allow for every prompts/get, unless a kill is
// active.
func (p AlwaysAllowPDP) DecidePromptGet(ctx context.Context, sessionID, _, _ string) capability.EnforceResponse {
	if deny := p.CheckKill(ctx, sessionID); deny != nil {
		return *deny
	}
	return p.wiretapAllow()
}

// DecideSampling lets audit/wiretap mode observe server-initiated sampling
// instead of hard-blocking it: it returns an explicit wiretap allow rather than a
// deny that the transport observe gate would hard-block even under --audit. Still
// consults the kill switch when one is wired (NewAlwaysAllowPDP); a bare
// AlwaysAllowPDP{} keeps observing.
func (p AlwaysAllowPDP) DecideSampling(ctx context.Context, sessionID, _ string) capability.EnforceResponse {
	if deny := p.CheckKill(ctx, sessionID); deny != nil {
		return *deny
	}
	return p.wiretapAllow()
}

// CheckKill consults the kill switch when one is wired (NewAlwaysAllowPDP), so an
// operator's /control/kill stops even a policyless wiretap route — its */list
// enumeration included. A zero-value AlwaysAllowPDP{} has no kill switch (nil ks),
// and killCheck returns nil for a nil checker, preserving pure-passthrough.
func (p AlwaysAllowPDP) CheckKill(ctx context.Context, sessionID string) *capability.EnforceResponse {
	return killCheck(ctx, p.ks, sessionID)
}

// CheckAudience pins no token audience: a wiretap/audit-mode route forwards every call,
// so it imposes no per-route audience requirement.
func (AlwaysAllowPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}

// RecordObservedToolHashes records no hashes — a wiretap PDP pins no tool
// descriptions — but still reports an accurate entry count via the same
// passThroughList decode FilterToolsList uses, so the caller need not decode result a
// second time just to count entries (see CountListEntries).
func (AlwaysAllowPDP) RecordObservedToolHashes(_ context.Context, result json.RawMessage) int {
	return passThroughList(result, listKeyTools).Upstream
}

// ReleaseSession is a no-op: a wiretap PDP enforces no policy and holds no per-session
// flow state to release.
func (AlwaysAllowPDP) ReleaseSession(_ context.Context, _ string) {}

// FilterToolsList passes the tools/list result through unchanged: wiretap/audit
// mode applies no policy. It still reports an accurate entry count (Upstream ==
// Kept) so a JWT route layered over a wiretap inner audits the right numbers.
// FilterResourcesList and FilterPromptsList do the same.
func (p AlwaysAllowPDP) FilterToolsList(_ context.Context, result json.RawMessage) ListFilterResult {
	return passThroughList(result, listKeyTools)
}

// FilterResourcesList passes the resources/list result through unchanged (wiretap mode).
func (p AlwaysAllowPDP) FilterResourcesList(_ context.Context, result json.RawMessage) ListFilterResult {
	return passThroughList(result, listKeyResources)
}

// FilterPromptsList passes the prompts/list result through unchanged (wiretap mode).
func (p AlwaysAllowPDP) FilterPromptsList(_ context.Context, result json.RawMessage) ListFilterResult {
	return passThroughList(result, listKeyPrompts)
}

// -----------------------------------------------------------------
// DenyAllPDP — fail-closed safety net
// -----------------------------------------------------------------

// DenyAllPDP denies every enforced method with AUTHORIZATION_FAILED and filters
// every */list result to empty. It is the fail-closed default the transport
// constructors substitute when no PDP is wired, so a caller that forgets to set
// one denies rather than forwards verbatim. The shipped binary always wires a
// concrete PDP, so this is a defense-in-depth backstop for the library seam, never
// a runtime path.
type DenyAllPDP struct{}

// Compile-time guarantee that DenyAllPDP implements the full contract — its whole
// purpose is to be a complete fail-closed implementation.
var _ PolicyDecisionPoint = DenyAllPDP{}

// deny is the single structured deny every DenyAllPDP method returns.
func (DenyAllPDP) deny() capability.EnforceResponse {
	return denyResponse(nil, capability.ErrCodeAuthorizationFailed, "", "no policy configured: denying by default")
}

// Decide denies every tools/call.
func (p DenyAllPDP) Decide(_ context.Context, _ string, _ EnforceTarget, _ map[string]interface{}, _ string) capability.EnforceResponse {
	return p.deny()
}

// DecideResourceRead denies every resources/read and resources/subscribe.
func (p DenyAllPDP) DecideResourceRead(_ context.Context, _, _, _ string) capability.EnforceResponse {
	return p.deny()
}

// DecidePromptGet denies every prompts/get.
func (p DenyAllPDP) DecidePromptGet(_ context.Context, _, _, _ string) capability.EnforceResponse {
	return p.deny()
}

// DecideSampling denies every server-initiated sampling/createMessage.
func (p DenyAllPDP) DecideSampling(_ context.Context, _, _ string) capability.EnforceResponse {
	return p.deny()
}

// CheckKill fails closed like every other DenyAllPDP method. The transports call
// CheckKill as an explicit gate on exactly the paths that do NOT flow through Decide —
// */list forwarding, session-creating initialize, and notification relay. Returning nil
// would let those gates proceed (spawn an upstream, forward tools/list, relay a
// notification) even though DenyAllPDP authorizes nothing — the one hole in an otherwise
// total deny. DenyAllPDP holds no kill switch, so the block is unconditional; the code
// mirrors deny() rather than a kill-switch code because the cause is "no policy", not an
// operator stop.
func (p DenyAllPDP) CheckKill(_ context.Context, _ string) *capability.EnforceResponse {
	d := p.deny()
	return &d
}

// CheckAudience pins no token audience: DenyAllPDP already denies every enforced action.
func (DenyAllPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}

// RecordObservedToolHashes records no hashes — the "no policy" default pins no tool
// descriptions (and denies every call regardless) — but still reports an accurate
// entry count, matching AlwaysAllowPDP, so a caller need not decode result again.
func (DenyAllPDP) RecordObservedToolHashes(_ context.Context, result json.RawMessage) int {
	return passThroughList(result, listKeyTools).Upstream
}

// ReleaseSession is a no-op: the fail-closed default holds no per-session flow state.
func (DenyAllPDP) ReleaseSession(_ context.Context, _ string) {}

// FilterToolsList filters the tools/list result down to nothing (keep == false
// for every entry), reusing the shared fail-closed envelope round-trip.
func (DenyAllPDP) FilterToolsList(_ context.Context, result json.RawMessage) ListFilterResult {
	return emptyListing(result, listKeyTools)
}

// FilterResourcesList filters the resources/list result down to nothing.
func (DenyAllPDP) FilterResourcesList(_ context.Context, result json.RawMessage) ListFilterResult {
	return emptyListing(result, listKeyResources)
}

// FilterPromptsList filters the prompts/list result down to nothing.
func (DenyAllPDP) FilterPromptsList(_ context.Context, result json.RawMessage) ListFilterResult {
	return emptyListing(result, listKeyPrompts)
}

// -----------------------------------------------------------------
// ManifestPDP — enforces the manifest capabilities using the Go enforcement engine
// -----------------------------------------------------------------

// ManifestPDP applies the local capability manifest to every tool call.
//
// Matching semantics:
//   - The manifest is an allowlist: only tools with an explicit capability entry
//     are permitted.  A tool absent from the manifest is denied by default.
//   - The actions list must contain "call" or "*" to permit the call.
//   - If a constraint matches, conditions are evaluated.  A failure denies.
type ManifestPDP struct {
	caps   []capability.Constraint
	engine *enforcement.Engine
	ks     killswitch.Checker

	// parsedTargets is the once-parsed form of each caps[i].Target, computed at
	// construction and indexed parallel to caps. findConstraint runs for
	// every enforced request and previously re-ran capability.ParseTarget over the
	// static c.Target for every constraint; caching the (type, bare, parseErr) here
	// removes that per-request string scan. A malformed target is recorded with
	// parseErr=true so the runtime skips it exactly as the inline error check did
	// (fail closed).
	parsedTargets []parsedTarget

	// descMu guards observedToolHash, the SHA-256 of each tool's most recently
	// observed model-facing surface (description + parameter descriptions, via
	// capability.ComputeToolHash), keyed by tool name. Recorded when a tools/list
	// response is filtered (the only place the proxy sees the live description and
	// inputSchema) and read at tools/call time so a pinned descriptionHash is
	// enforced on the call leg too. Only tools matched to a pinned exact-tool
	// constraint are recorded (see filterToolsListResult), so the map is bounded by
	// the manifest's pinned set, not by what the upstream advertises — a
	// name-rotating upstream cannot flood it.
	descMu           sync.RWMutex
	observedToolHash map[string]string
	// poisonedTools is a sticky set of pinned tool names whose live description was
	// EVER observed to differ from the pin. observedToolHash is last-write-wins and
	// per-name, but in HTTP mode one per-route ManifestPDP is shared across N
	// per-session upstream subprocesses: an honest session serving the clean
	// description would overwrite observedToolHash back to the pin and re-open the
	// call-leg pin for a concurrent session whose upstream instance is still
	// poisoned. A mismatch recorded here is never cleared by a later clean
	// observation, so the call leg denies for every session while the tool is in
	// the set. The fail-closed trade-off (a legitimately changed-then-reverted
	// pinned description stays blocked until restart) is appropriate for a pin.
	poisonedTools map[string]struct{}

	// pinnedTools maps a pinned exact-tool name to its descriptionHash, built at
	// construction over EVERY IsPinnedExactTool constraint — not just the one findConstraint
	// selects. filterToolsListResult and decideTarget consult this map so the pin is enforced
	// whenever the tool name is pinned by ANY entry, even when a duplicate non-pinned sibling
	// (or a pinned sibling lacking the "call" action) wins selection and would otherwise
	// shadow the pin on both legs. Read-only after construction, so it needs no lock. A tool
	// pinned by two entries to DIFFERENT hashes is an ambiguous manifest, rejected at load by
	// validateLocalManifest (config layer), so this map never carries a conflicting pin and a
	// plain hash string suffices — no in-band conflict sentinel is threaded into the hot path.
	pinnedTools map[string]string

	// anyLabelOutput is true when at least one capability carries a labelOutput directive.
	// It gates the union scan (constraintWithUnionLabelOutput): a source read's taint is
	// the union of labelOutput across ALL entries matching the request, not only the one
	// findConstraint scores highest — so a sibling without labelOutput cannot shadow one
	// that has it (mirrors pinnedTools' "enforce off any matching entry"). Computed once at
	// construction; false skips the scan entirely, so a policy with no sources pays nothing.
	anyLabelOutput bool
}

// parsedTarget is the once-parsed form of a constraint's Target (see
// ManifestPDP.parsedTargets). parseErr flags a malformed target so the hot path
// skips it, fail closed, without re-deriving the error.
type parsedTarget struct {
	typ      capability.TargetType
	bare     string
	parseErr bool
}

// NewManifestPDP creates a PDP backed by the given capabilities.
// engine must have a CallCounter configured to support maxCalls conditions.
func NewManifestPDP(caps []capability.Constraint, engine *enforcement.Engine, ks killswitch.Checker) *ManifestPDP {
	parsed := make([]parsedTarget, len(caps))
	var pinned map[string]string
	for i := range caps {
		tt, bare, err := capability.ParseTarget(caps[i].Target)
		if err != nil {
			parsed[i] = parsedTarget{parseErr: true}
			continue
		}
		parsed[i] = parsedTarget{typ: tt, bare: bare}
		// Record every pinned exact-tool's hash keyed by bare name, so both legs enforce the
		// pin independent of which constraint wins selection. validateLocalManifest rejects a
		// tool pinned to two DIFFERENT hashes at load, so a production PDP never sees a
		// conflict; keep first-declared-wins here for determinism if a direct (test) caller
		// constructs one anyway.
		if caps[i].IsPinnedExactTool() {
			if pinned == nil {
				pinned = make(map[string]string)
			}
			if _, ok := pinned[bare]; !ok {
				pinned[bare] = caps[i].DescriptionHash
			}
		}
	}
	anyLabelOutput := false
	for i := range caps {
		for _, dir := range caps[i].Directives {
			if capability.IsLabelOutputDirective(dir) {
				anyLabelOutput = true
				break
			}
		}
		if anyLabelOutput {
			break
		}
	}
	return &ManifestPDP{caps: caps, parsedTargets: parsed, engine: engine, ks: ks, observedToolHash: make(map[string]string), pinnedTools: pinned, anyLabelOutput: anyLabelOutput}
}

// engineClock returns the engine's clock so decideTarget's hand-built denies
// stamp DecidedAt from the same source the engine uses, honoring a frozen test
// clock on every deny path. nil-safe: a nil engine falls back to the wall clock.
func (p *ManifestPDP) engineClock() enforcement.Clock {
	if p.engine == nil {
		return nil
	}
	return p.engine.Clock()
}

// recordObservedToolHash stores the hash of a tool's live model-facing surface
// (description + title + annotations + input/output parameter descriptions) seen in
// a tools/list response, so
// decideTarget can enforce a pinned descriptionHash on the call leg against the
// same surface the host was shown. Callers must gate this on a pinned exact-tool
// constraint match (see filterToolsListResult) and pass that constraint's pinned
// hash as pin.
//
// Recording the observed hash and marking a mismatch as poisoned happen under a
// SINGLE lock, so the two updates are atomic: a concurrent call-leg reader
// (pinViolated, also single-locked) can never observe the hash updated but the
// poison mark not yet set, which would let an interleaving honest-session
// overwrite re-open the pin. pin is the constraint's DescriptionHash ("" only for
// a non-pinned caller, in which case no poison is possible).
func (p *ManifestPDP) recordObservedToolHash(name, description, title string, annotations, inputSchema, outputSchema map[string]interface{}, pin string) {
	h := capability.ComputeToolHash(description, capability.ToolHashParams(title, annotations, inputSchema, outputSchema))
	// Sticky poison mark: set when the live hash differs from the pin, never cleared by a
	// later clean observation, so a concurrent honest session cannot re-open the call-leg pin
	// for a session whose upstream instance is still poisoned. The `pin != ""` guard keeps a
	// non-pinned direct caller (empty pin) from poisoning.
	needsPoison := pin != "" && h != pin
	// Fast path: the observed surface is unchanged and no new poison mark is required
	// (the common case — a tool's description is stable across tools/list responses).
	// Read under the shared RLock so concurrent tools/list responses and the tools/call
	// pinViolated reader do not serialize on the exclusive lock. One ManifestPDP is
	// shared across all of a route's sessions, so this contention is real under load.
	p.descMu.RLock()
	observed, ok := p.observedToolHash[name]
	_, poisoned := p.poisonedTools[name]
	p.descMu.RUnlock()
	if ok && observed == h && (!needsPoison || poisoned) {
		return
	}
	// Slow path: the hash changed, or a poison mark must be set. Take the exclusive
	// lock and (re-)apply state under it — the RLock snapshot may be stale, so the
	// write path is unconditional. Recording the hash and the poison mark under this
	// SINGLE lock keeps them atomic: a concurrent pinViolated reader can never observe
	// the hash updated but the poison mark not yet set, which would let an interleaving
	// honest-session overwrite re-open the pin.
	p.descMu.Lock()
	if p.observedToolHash == nil {
		p.observedToolHash = make(map[string]string)
	}
	p.observedToolHash[name] = h
	if needsPoison {
		if p.poisonedTools == nil {
			p.poisonedTools = make(map[string]struct{})
		}
		p.poisonedTools[name] = struct{}{}
	}
	p.descMu.Unlock()
}

// isToolPoisoned reports whether a pinned tool was ever observed poisoned.
func (p *ManifestPDP) isToolPoisoned(name string) bool {
	p.descMu.RLock()
	_, ok := p.poisonedTools[name]
	p.descMu.RUnlock()
	return ok
}

// pinViolated reports whether a pinned tool's call leg must be denied: it was ever
// observed poisoned (sticky), OR its most recently observed hash differs from the
// pin. BOTH are read under a single RLock so the call leg cannot observe a torn
// state (poison not yet set AND a just-overwritten clean hash) that would let a
// poisoned call through. With recordObservedToolHash marking poison atomically on a
// mismatch, the poison check alone is authoritative; the observed-hash comparison
// is retained as defense-in-depth for a direct (non-filter) caller that recorded a
// hash without a pin.
//
// The observed-hash comparison is a plain `observed != pin`. In the shipped proxy
// pinnedTools only ever holds a non-empty hash (IsPinnedExactTool requires a
// DescriptionHash) and validateLocalManifest rejects a conflicting pin at load, so pin is
// always a single non-empty hash here; a hypothetical direct caller passing an empty pin
// would deny once any hash was observed (the defense-in-depth backstop).
func (p *ManifestPDP) pinViolated(name, pin string) bool {
	p.descMu.RLock()
	defer p.descMu.RUnlock()
	if _, poisoned := p.poisonedTools[name]; poisoned {
		return true
	}
	observed, ok := p.observedToolHash[name]
	return ok && observed != pin
}

// CheckKill consults the manifest PDP's kill switch, returning a non-nil deny when
// the session is killed (or the kill store errors, fail closed). It shares
// killCheck with the Decide* paths so the */list handlers enforce it identically.
func (p *ManifestPDP) CheckKill(ctx context.Context, sessionID string) *capability.EnforceResponse {
	return killCheck(ctx, p.ks, sessionID)
}

// CheckAudience pins no token audience: the manifest layer enforces capabilities, not
// the JWT aud claim. Per-route token-audience pinning lives in the JWTPDP wrapper.
func (*ManifestPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}

// ReleaseSession releases the session's accumulated flow-label state on teardown, via
// the engine (which namespaces the store key by route). A no-op when the policy uses no
// flow control or no store is wired (see Engine.ClearSessionLabels). Best-effort: a
// store fault on teardown is swallowed rather than surfaced — the session is already
// gone, and a Redis-backed store reclaims an orphaned key by idle TTL regardless.
func (p *ManifestPDP) ReleaseSession(ctx context.Context, sessionID string) {
	if p.engine == nil {
		return
	}
	_ = p.engine.ClearSessionLabels(ctx, sessionID)
}

// Decide evaluates a tools/call against the manifest: it selects the
// best-matching constraint, runs its conditions through the enforcement engine,
// and returns the allow/deny decision (with any obligations).
func (p *ManifestPDP) Decide(ctx context.Context, sessionID string, target EnforceTarget, args map[string]interface{}, sourceIP string) capability.EnforceResponse {
	return p.decideTarget(ctx, sessionID, target, args, sourceIP, validateSchema)
}

// schemaMode tells decideTarget how to treat a constraint's argumentSchema.
// argumentSchema is tool-only by spec (§ 3.2.2), so tools/call validates a present
// schema while the non-tool targets treat one as a fail-closed error.
type schemaMode bool

const (
	validateSchema schemaMode = true  // tools/call: run ValidateArgumentSchema
	rejectSchema   schemaMode = false // resources/read, prompts/get: a present schema fails closed
)

// decideTarget is the shared decision path for the three manifest target types
// of the same shape — tools/call, resources/read, prompts/get. The one helper is
// what keeps an enforcement change from landing on one method and silently
// missing the others.
//
// Sequence: kill-switch check -> findConstraint (allowlist; a "tool:" entry can
// never satisfy a "resource:"/"prompt:" lookup) -> audit-mode stamp -> action
// check -> argumentSchema handling -> condition evaluation. The schema mode
// distinguishes tools/call (validate a present schema) from the non-tool targets
// (a present argumentSchema is tool-only by spec, so finding one is a fail-closed
// ENFORCEMENT_ERROR).
func (p *ManifestPDP) decideTarget(ctx context.Context, sessionID string, target EnforceTarget, args map[string]interface{}, sourceIP string, schema schemaMode) capability.EnforceResponse {
	// Kill switch check: per-agent (JWT agent_id from ctx), per-session, and
	// global kills are honored; a kill-store error fails closed.
	if deny := killCheck(ctx, p.ks, sessionID); deny != nil {
		return *deny
	}

	// Find the most specific matching constraint, scoped to the target type and the
	// caller's principal. The manifest is an allowlist: only listed targets pass.
	claims := jwtClaimsAsMap(ctx)
	matched := p.findConstraint(target, claims)
	if matched == nil {
		return denyResponse(p.engineClock(), capability.ErrCodeAuthorizationFailed, "",
			fmt.Sprintf("%s %q is not listed in the capability manifest", target.Type, target.Name))
	}
	// Union labelOutput across every entry matching this request, so a source read carries
	// its taint even when the entry findConstraint scored highest (a more-specific or
	// principal-scoped sibling) lacks labelOutput while another matching entry has it —
	// otherwise the taint is silently dropped and a later sink fails open. A no-op for a
	// policy with no sources, and for the common single-source case. Only the recorded
	// labelOutput changes; conditions, actions, argumentSchema, and the descriptionHash pin
	// below all read matched's own (unchanged) properties, and obligations skip labelOutput.
	matched = p.constraintWithUnionLabelOutput(matched, target, claims)

	// Stray-argumentSchema fail-closed guard. argumentSchema is tool-only by spec
	// (§ 3.2.2) and the loader rejects it on resource:/prompt: targets, but a
	// manifest built in-process could carry one. EvaluateConditions does not run
	// ValidateArgumentSchema, so a stray schema on a non-tool target would be a
	// declared guard with no runtime effect (fail-open). Refuse instead.
	//
	// This guard MUST run BEFORE the audit-mode defer below; it is an
	// ENFORCEMENT_ERROR (an engine bug, not a downgradable policy verdict), so it
	// returns hardDenyResponse to stay non-downgradable even under audit (see that
	// helper for how HardDeny survives stamp() and isObserveDeny).
	if matched.ArgumentSchema != nil && schema != validateSchema {
		return hardDenyResponse(p.engineClock(), capability.ErrCodeEnforcementError,
			fmt.Sprintf("constraint %q carries an argumentSchema, which is tool-only and not enforced on %s; refusing to forward a request guarded by an unenforced schema (fail closed)", matched.Target, targetOperationPhrase(target.Type)))
	}

	// descriptionHash pin (tools/call leg). A constraint may pin a tool's
	// description hash to defend against an upstream that rewrites the description to
	// inject a prompt (tool poisoning, FM-5). filterToolsListResult hides a
	// description-changed tool from tools/list, but a host calling by name (a cached
	// tool) would otherwise bypass the pin on the call leg. Enforce it here against
	// the most recently observed description.
	//
	// Like the stray-argumentSchema guard, this MUST run BEFORE the audit-mode defer
	// and returns hardDenyResponse: a tool-poisoning deny is not downgradable even
	// under audit (see that helper). It denies only when the description HAS been
	// re-observed and no
	// longer matches — the mid-session change the session-start drift probe cannot
	// catch. An as-yet-unobserved description is not denied (the probe already
	// verified every pin at establishment).
	//
	// The pin fires on an OBSERVED description mismatch alone, independent of whether
	// the SELECTED constraint permits the action OR is itself the pinned entry. It is
	// keyed off pinnedTools (every pinned entry for this name), not matched: when
	// findConstraint selects a name-only match lacking the "call" action, or a
	// duplicate non-pinned sibling that shadows the pinned entry, an action-gated or
	// matched-gated pin would be skipped and the request would fall through to the
	// CAPABILITY_DENIED action check below -- which an audit-mode constraint downgrades
	// to a forwarded allow, letting the call reach the poisoned upstream and violating
	// the invariant that a tool-poisoning deny is never downgradable. Firing here off
	// the name keeps a genuine poisoning (an observed mismatch) a hard
	// AUTHORIZATION_FAILED; a matching or as-yet-unobserved description does not deny
	// here and still reaches the accurate action check below.
	if pin, isPinned := p.pinnedTools[target.Name]; schema == validateSchema && isPinned {
		// pinViolated reads the sticky poison mark and the observed hash under one lock
		// (see its doc): a sticky poison from any earlier observation in any concurrent
		// session sharing this per-route PDP, or a currently-observed mismatch, denies.
		// The single-locked read cannot observe a torn state that an honest session's
		// overwrite would otherwise open.
		if p.pinViolated(target.Name, pin) {
			return hardDenyResponse(p.engineClock(), capability.ErrCodeAuthorizationFailed,
				fmt.Sprintf("tool %q description no longer matches the pinned descriptionHash (the upstream description changed after the session started); refusing to forward (fail closed)", target.Name))
		}
	}

	// A constraint in audit (observe) mode downgrades its own denial to a
	// logged-but-forwarded allow. stamp applies that downgrade only to the verdicts
	// returned BELOW this point: the kill-switch, no-match, stray-schema, and
	// descriptionHash returns above never pass through it and stay hard-deny.
	// Stamping explicitly at each return site (rather than via a deferred mutation
	// of a named return) keeps which verdicts are downgradable visible in the
	// control flow, so a future early return added below cannot silently inherit it.
	stamp := func(r capability.EnforceResponse) capability.EnforceResponse {
		// Never stamp a hard deny as AuditOnly: it must block even on an audit-only
		// constraint or a route running under --audit (e.g. antecedent record failure).
		if matched.IsAuditOnly() && (r.Denial == nil || !r.Denial.HardDeny) {
			r.AuditOnly = true
		}
		return r
	}

	// Build the enforce request up front so every early-return deny an audit-mode
	// constraint downgrades to a forwarded allow can still record the antecedent in
	// session history — otherwise a later sequenceBlock naming this target in
	// afterTools Peeks an empty history and fails OPEN though the tool ran.
	// ToolName/Target carry target.Name (for input.target.* and the audit record);
	// Claims back input.claims.agent_id/task_id/etc.
	req := &capability.EnforceRequest{
		SessionID: sessionID,
		ToolName:  target.Name,
		Arguments: args,
		Context:   capability.EnforceRequestContext{SourceIP: sourceIP},
		Target: &capability.EnforceRequestTarget{
			Type: string(target.Type),
			Name: target.Name,
		},
		Claims: claims,
	}

	// The constraint's actions list must contain the required action for this
	// target type, or the wildcard "*".
	required := requiredActionFor(target.Type)
	if !containsAction(matched.Actions, required) {
		resp := denyResponse(p.engineClock(), capability.ErrCodeCapabilityDenied, "",
			fmt.Sprintf("constraint %q does not permit %s (actions must include %q or '*'; got: %s)", matched.Target, targetOperationPhrase(target.Type), required, strings.Join(matched.Actions, ", ")))
		if override := recordAuditModeAntecedent(ctx, p.engine, p.engineClock(), req, matched, &resp); override != nil {
			return *override
		}
		return stamp(resp)
	}

	// Structural argument validation runs before conditions so INVALID_PARAMS wins
	// over any condition failure when the request is both malformed and
	// policy-violating. Unlike the stray-schema guard, an INVALID_PARAMS denial IS a
	// policy verdict and is correctly downgraded by an audit-mode constraint.
	if matched.ArgumentSchema != nil && schema == validateSchema {
		if err := enforcement.ValidateArgumentSchema(args, matched.ArgumentSchema); err != nil {
			resp := denyResponse(p.engineClock(), capability.ErrCodeInvalidParams, "argumentSchema", err.Error())
			if override := recordAuditModeAntecedent(ctx, p.engine, p.engineClock(), req, matched, &resp); override != nil {
				return *override
			}
			return stamp(resp)
		}
	}

	resp := p.evaluateAndRecord(ctx, req, matched)
	return stamp(resp)
}

// evaluateAndRecord runs the matched constraint's conditions through the engine
// and records the audit-mode antecedent — the tail shared by every Decide* path,
// so a new enforcement point cannot regress to forwarding without evaluating
// conditions. EvaluateConditions carries every outcome (including a rejection, which
// resolves to a CONDITION_FAILED deny) in the response itself, so there is no error
// channel to branch on here — a deny is always a structured EnforceResponse.
func (p *ManifestPDP) evaluateAndRecord(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) capability.EnforceResponse {
	resp := p.engine.EvaluateConditions(ctx, req, matched)
	if override := recordAuditModeAntecedent(ctx, p.engine, p.engineClock(), req, matched, &resp); override != nil {
		return *override
	}
	return resp
}

// targetOperationPhrase renders the human-readable operation name used in
// CAPABILITY_DENIED and stray-argumentSchema denials, preserving the wording each
// Decide* path historically emitted: "resource reads" for resources/read,
// "prompts/get" for prompts/get, and the bare target type ("tool") otherwise.
func targetOperationPhrase(t capability.TargetType) string {
	switch t {
	case capability.TargetTypeResource:
		return "resource reads"
	case capability.TargetTypePrompt:
		return "prompts/get"
	default:
		return string(t)
	}
}

// recordAuditModeAntecedent records session state when an audit-mode constraint
// DOWNGRADES a deny to a forwarded call. On that path EvaluateConditions returns the
// deny before its allow-tail state writes run, but the transport still forwards and the
// tool runs, so two guarantees would otherwise be broken: a later sequenceBlock naming
// this target Peeks an empty history and fails OPEN (RecordSessionCall closes this), and
// a later flowLabel sink Peeks the labelOutput labels this forwarded read actually
// carried and fails OPEN (RecordLabels closes this — the data was produced, so it must
// be labeled). The genuine-allow path already records both inside EvaluateConditions,
// and an enforced deny means the tool never ran, so neither needs this — and neither
// does a HardDeny audit-mode deny: it is NOT downgraded, so recording would attribute
// state to a call that never ran (the bug the HardDeny check below prevents).
//
// When either record fails the corresponding integrity guarantee cannot be upheld, so
// the call returns a hardDenyResponse CONDITION_FAILED deny — non-downgradable even
// under audit (see hardDenyResponse), so the read is not forwarded with unreliable
// state. RecordSourceCall commits the two namespaces atomically — flow labels first,
// then the seq antecedent, rolling the flow write back on a seq fault (see
// recordSourceCall) — so a fault in either leaves NEITHER committed.
//
// On the downgrade the labels this forwarded read carries in and asserts out are
// stamped back onto resp (LabelsOut from RecordLabels, CarriedLabels from a pre-write
// Peek) so the audit record of the forwarded observe-allow reflects the same flow the
// genuine-allow path records inside EvaluateConditions — otherwise an audit-mode source
// read would log with empty labels though it produced labeled data. The structural
// early-return denies (action mismatch, INVALID_PARAMS) never ran conditions, so resp
// arrives with CarriedLabels nil; a flow-relevant condition deny arrives already
// stamped by evaluateMatched, so the Peek is skipped to avoid a redundant read. The
// back-fill mutates resp through the pointer, so callers see the stamped labels.
//
// The flow peek/record and the label back-fill are gated on the SAME per-constraint
// predicate the genuine-allow path uses (evaluateMatched's flowRelevant =
// !skipFlow && constraintHasFlow), so a non-flow constraint's forwarded observe record
// stays label-free — matching the record a genuine allow of that constraint writes,
// rather than over-reporting the session's accumulated labels on a call that is neither a
// flow source nor a sink — and pays none of the vocabulary Peek cost, honoring the
// WithoutFlowLabels optimization on this path too. RecordSessionCall stays ungated: the
// sequenceBlock antecedent must be recorded for every downgraded deny regardless of flow.
//
// clock is p.engineClock() at every call site so the frozen test clock is honored
// and a nil engine never reaches engine.Clock() directly.
func recordAuditModeAntecedent(ctx context.Context, engine *enforcement.Engine, clock enforcement.Clock, req *capability.EnforceRequest, matched *capability.Constraint, resp *capability.EnforceResponse) *capability.EnforceResponse {
	if matched.IsAuditOnly() && resp.Decision == capability.DecisionDeny && (resp.Denial == nil || !resp.Denial.HardDeny) {
		flowRelevant := capability.ConstraintHasFlow(matched)
		// Capture the carried set before any write, only for a flow-relevant constraint
		// whose deny did not already stamp it (a condition deny routed through
		// evaluateMatched has). This peek fails CLOSED, exactly like the genuine-allow path
		// (evaluateMatched denies on a peek error): the captured set is not only the tape's
		// carried_labels for this forwarded observe record — where a swallowed error would
		// silently under-report the flow — but ALSO the rollback-delta baseline handed to
		// RecordSourceCall, where a nil-from-error baseline would let a paired seq-write fault
		// roll back a PRIOR source's label (a fail-open). So a peek fault here hard-denies
		// (non-downgradable even under audit) rather than forward with unreliable state.
		var incoming []string
		if flowRelevant && resp.CarriedLabels == nil {
			var perr error
			incoming, perr = engine.PeekSessionLabels(ctx, req)
			if perr != nil {
				deny := hardDenyResponse(clock, capability.ErrCodeConditionFailed,
					"audit-mode flow-label peek failed: "+perr.Error())
				return &deny
			}
		}
		// Commit the seq antecedent and the flow labels atomically (RecordSourceCall), so
		// a fault between the two leaves neither stranded on this forwarded observe record —
		// the same all-or-nothing the genuine-allow
		// path uses. carried is the pre-write accumulated set for the rollback delta:
		// resp.CarriedLabels when a flow-condition deny already stamped it, else the peek.
		carried := resp.CarriedLabels
		if carried == nil {
			carried = incoming
		}
		labels, cerr := engine.RecordSourceCall(ctx, req, matched, flowRelevant, carried)
		if cerr != nil {
			msg := "audit-mode antecedent record failed: "
			if cerr.Flow {
				msg = "audit-mode flow-label record failed: "
			}
			deny := hardDenyResponse(clock, capability.ErrCodeConditionFailed, msg+cerr.Error())
			return &deny
		}
		if flowRelevant {
			if len(labels) > 0 {
				resp.LabelsOut = labels
			}
			if resp.CarriedLabels == nil {
				resp.CarriedLabels = incoming
			}
		}
	}
	return nil
}

// requiredActionFor returns the canonical action keyword for a target type — the
// action that must appear in a constraint's actions list (or "*") to permit it.
func requiredActionFor(t capability.TargetType) string {
	switch t {
	case capability.TargetTypeResource:
		return "read"
	case capability.TargetTypePrompt:
		return "get"
	case capability.TargetTypeSystem:
		return "allow"
	default: // TargetTypeTool
		return "call"
	}
}

// findConstraint returns the most specific constraint whose namespace type and
// bare-name pattern match target AND whose principal scoping (if any) is satisfied
// by claims, or nil. A principal-scoped entry the claims do not satisfy is skipped
// like a target mismatch (fail closed); claims is nil with no validated token, so
// a principal-scoped entry can never match then.
//
// Tiebreak: higher target specificity wins; at equal specificity a
// principal-scoped entry beats a general one, regardless of manifest order.
//
// Selection is action-aware: an entry whose actions permit the required operation
// wins over a sibling that shares only the name. Without this two entries for the
// same target differing only by action could resolve to the wrong one by
// specificity/order and CAPABILITY_DENY a request a sibling permits.
//
// When NO entry permits the action, the best name match is returned anyway (the
// fallback phase) so the caller emits the precise CAPABILITY_DENIED ("exists but
// does not permit this action") rather than AUTHORIZATION_FAILED ("not listed").
// The fallback scan runs only when the action-aware scan finds nothing.
func (p *ManifestPDP) findConstraint(target EnforceTarget, claims map[string]interface{}) *capability.Constraint {
	required := requiredActionFor(target.Type)

	// Single pass tracking two bests at once: the PRIMARY (an entry whose actions
	// permit the required operation) and the name-only FALLBACK (any name match,
	// returned so the caller emits CAPABILITY_DENIED rather than AUTHORIZATION_FAILED
	// when nothing permits the action). This yields the same result as the old
	// two-phase scan — primary if any, else fallback — while scanning the constraint
	// list once. findConstraint runs per catalog entry in filterToolsListResult, so on
	// a large upstream catalog against a mostly-denying manifest this halves the
	// per-tools/list matchBare/path.Match evaluations.
	primary := newConstraintScorer()
	fallback := newConstraintScorer()
	// parsedTargets is built parallel to caps by NewManifestPDP, so the hot path
	// reads the once-parsed (type, bare) instead of re-scanning the static Target.
	// A ManifestPDP built directly (a struct literal, as some tests do) leaves it
	// unpopulated; fall back to inline ParseTarget then, mirroring how handleIPRange
	// parses when Networks() reports the condition was not pre-compiled.
	useCache := len(p.parsedTargets) == len(p.caps)
	for i := range p.caps {
		var pt parsedTarget
		if useCache {
			pt = p.parsedTargets[i]
		} else {
			tt, bare, err := capability.ParseTarget(p.caps[i].Target)
			pt = parsedTarget{typ: tt, bare: bare, parseErr: err != nil}
		}
		if pt.parseErr || pt.typ != target.Type {
			continue
		}
		if !matchBare(pt.bare, target.Name) {
			continue
		}
		c := &p.caps[i]
		if !c.PrincipalMatches(claims) {
			continue
		}
		s := bareSpecificity(pt.bare, target.Name)
		hasPrincipal := c.HasPrincipal()
		fallback.offer(i, s, hasPrincipal)
		if containsAction(c.Actions, required) {
			primary.offer(i, s, hasPrincipal)
		}
	}
	if primary.best >= 0 {
		return &p.caps[primary.best]
	}
	if fallback.best >= 0 {
		return &p.caps[fallback.best]
	}
	return nil
}

// constraintScorer tracks the best-scoring constraint index seen so far under
// findConstraint's tiebreak: higher target specificity wins, and at equal
// specificity a principal-scoped entry beats a general one, regardless of manifest
// order. Shared by findConstraint's primary and fallback trackers so the tiebreak
// lives in one place across a single scan.
type constraintScorer struct {
	best      int
	bestScore int
	bestPrin  bool
}

func newConstraintScorer() constraintScorer {
	return constraintScorer{best: -1, bestScore: -(1 << 30)}
}

func (cs *constraintScorer) offer(i, score int, hasPrincipal bool) {
	if score > cs.bestScore || (score == cs.bestScore && hasPrincipal && !cs.bestPrin) {
		cs.bestScore, cs.best, cs.bestPrin = score, i, hasPrincipal
	}
}

// matchBare reports whether the bare pattern (namespace prefix stripped) matches
// the bare target name. Delegates to enforcement.MatchesResource so the proxy and
// engine share one implementation.
func matchBare(pattern, name string) bool {
	return enforcement.MatchesResource(pattern, name)
}

// bareSpecificity scores how specific a bare pattern is against name, via
// enforcement.ResourceSpecificity (shared with the engine, like matchBare).
func bareSpecificity(pattern, name string) int {
	return enforcement.ResourceSpecificity(pattern, name)
}

// StripNamespacePrefix removes the leading "type:" prefix from a resource field,
// returning the bare name/pattern (unchanged if no recognized prefix is present,
// so bare wildcards like "*" pass through). Delegates to
// enforcement.StripEnginePrefix so the proxy and engine recognize the same
// namespace set and cannot diverge.
func StripNamespacePrefix(s string) string {
	return enforcement.StripEnginePrefix(s)
}

// containsAction reports whether actions contains act or the wildcard "*".
func containsAction(actions []string, act string) bool {
	for _, a := range actions {
		if a == act || a == "*" {
			return true
		}
	}
	return false
}

// constraintWithUnionLabelOutput returns matched augmented so its labelOutput carries the
// UNION of labelOutput labels across every entry matching this request — so a source read's
// taint is not dropped when a sibling (a more-specific or principal-scoped entry) lacking
// labelOutput wins selection over one that has it (mirrors the
// pinnedTools "enforce off any matching entry" rule). It returns matched UNCHANGED when the
// policy declares no labelOutput, when no matching entry adds a label matched lacks, or when
// matched already asserts the full union — so the common single-source case allocates
// nothing. Only labelOutput changes; the shallow copy shares matched's conditions, actions,
// argumentSchema, principal, and every other property, so selection, condition evaluation,
// the descriptionHash pin, and obligations (which skip labelOutput) are all unaffected.
func (p *ManifestPDP) constraintWithUnionLabelOutput(matched *capability.Constraint, target EnforceTarget, claims map[string]interface{}) *capability.Constraint {
	if !p.anyLabelOutput {
		return matched
	}
	union := p.matchingLabelOutputUnion(target, claims)
	if len(union) == 0 || labelSetContainsAll(labelOutputLabels(matched), union) {
		return matched
	}
	cp := *matched
	cp.Directives = replaceLabelOutputDirective(matched.Directives, union)
	return &cp
}

// matchingLabelOutputUnion collects the union of labelOutput labels from every capability
// whose target type + pattern match target AND whose principal scoping the caller's claims
// satisfy — the same "applies to this request" test findConstraint uses, minus the
// specificity/action tie-break, because ANY matching source entry's taint applies. Order is
// unspecified (the engine reorders into the canonical vocabulary). nil when nothing matches.
func (p *ManifestPDP) matchingLabelOutputUnion(target EnforceTarget, claims map[string]interface{}) []string {
	var set map[string]struct{}
	useCache := len(p.parsedTargets) == len(p.caps)
	for i := range p.caps {
		var pt parsedTarget
		if useCache {
			pt = p.parsedTargets[i]
		} else {
			tt, bare, err := capability.ParseTarget(p.caps[i].Target)
			pt = parsedTarget{typ: tt, bare: bare, parseErr: err != nil}
		}
		if pt.parseErr || pt.typ != target.Type || !matchBare(pt.bare, target.Name) {
			continue
		}
		if !p.caps[i].PrincipalMatches(claims) {
			continue
		}
		for _, l := range labelOutputLabels(&p.caps[i]) {
			if set == nil {
				set = make(map[string]struct{})
			}
			set[l] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	return out
}

// labelOutputLabels returns the flow labels a constraint's labelOutput directives assert
// (across all of them; nil-safe on a typed-nil directive), or nil.
func labelOutputLabels(c *capability.Constraint) []string {
	var out []string
	for _, dir := range c.Directives {
		if lo, ok := capability.AsValueOrPointer[capability.LabelOutputDirective](dir); ok && lo != nil {
			out = append(out, lo.Labels...)
		}
	}
	return out
}

// labelSetContainsAll reports whether every element of want is present in have (small
// closed-vocabulary slices, so a linear scan beats building a set).
func labelSetContainsAll(have, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// replaceLabelOutputDirective returns dirs with every labelOutput directive dropped and one
// LabelOutputDirective carrying labels appended, so the constraint asserts exactly the
// union. Non-labelOutput directives (e.g. redactFields) are preserved in order.
func replaceLabelOutputDirective(dirs []capability.Directive, labels []string) []capability.Directive {
	out := make([]capability.Directive, 0, len(dirs)+1)
	for _, dir := range dirs {
		if capability.IsLabelOutputDirective(dir) {
			continue
		}
		out = append(out, dir)
	}
	return append(out, capability.LabelOutputDirective{Labels: labels})
}

// DecideResourceRead evaluates a resources/read against the manifest. The URI is
// matched against resource entries with the same glob semantics as tool names;
// entries must include "read" or "*".
func (p *ManifestPDP) DecideResourceRead(ctx context.Context, sessionID, uri, sourceIP string) capability.EnforceResponse {
	// Conditions evaluate against the synthesised {"uri": uri} map. rejectSchema:
	// argumentSchema is tool-only, so one on a resource entry fails closed.
	return p.decideTarget(ctx, sessionID,
		EnforceTarget{Type: capability.TargetTypeResource, Name: uri},
		map[string]interface{}{"uri": uri}, sourceIP, rejectSchema)
}

// DecideSampling implements SamplingAuthorizer. The kill switch is checked first
// (fail closed). The capability decision requires the manifest's explicit
// system:sampling/createMessage opt-in AND that every condition on that entry
// passes — evaluated through EvaluateConditions like the other paths, so a
// timeWindow/maxCalls/ipRange guard is enforced, not skipped.
//
// sourceIP is the session's originating client IP (empty on stdio), threaded into
// the request so an ipRange condition on the opt-in sees a real address rather
// than failing closed with MISSING_CONTEXT.
func (p *ManifestPDP) DecideSampling(ctx context.Context, sessionID, sourceIP string) capability.EnforceResponse {
	if deny := killCheck(ctx, p.ks, sessionID); deny != nil {
		return *deny
	}

	// Resolve the explicit system:sampling/createMessage opt-in; without a matching
	// "allow"/"*" constraint sampling stays denied (fail closed).
	claims := jwtClaimsAsMap(ctx)
	matched := p.findConstraint(EnforceTarget{
		Type: capability.TargetTypeSystem,
		Name: capability.MethodSamplingCreateMessage,
	}, claims)
	// Distinguish "no opt-in entry at all" from "an entry exists but withholds the
	// allow action": findConstraint's fallback phase returns a name-matching entry
	// regardless of action, so a non-nil match without "allow" means the operator
	// DID declare a system:sampling/createMessage entry but gave it the wrong action.
	// Emitting the same "no opt-in" message for both led operators to add a duplicate
	// entry rather than fix the action, and gave SIEM no way to tell the two apart.
	switch {
	case matched == nil:
		return denyResponse(p.engineClock(), capability.ErrCodeSamplingDenied, "",
			"server-initiated sampling requires an explicit system:sampling/createMessage opt-in in the manifest")
	case !containsAction(matched.Actions, "allow"):
		return denyResponse(p.engineClock(), capability.ErrCodeSamplingDenied, "",
			"a system:sampling/createMessage entry exists but does not include the \"allow\" action; add \"allow\" to its actions to permit server-initiated sampling")
	}

	// Stray-argumentSchema fail-closed guard, mirroring decideTarget. argumentSchema is
	// tool-only by spec and the loader rejects it on system: targets, but a manifest
	// built in-process could carry one. evaluateAndRecord never runs
	// ValidateArgumentSchema, so a stray schema here would be a declared guard with no
	// runtime effect (fail-open). Refuse with a non-downgradable ENFORCEMENT_ERROR.
	if matched.ArgumentSchema != nil {
		return hardDenyResponse(p.engineClock(), capability.ErrCodeEnforcementError,
			fmt.Sprintf("constraint %q carries an argumentSchema, which is tool-only and not enforced on sampling; refusing to forward a request guarded by an unenforced schema (fail closed)", matched.Target))
	}

	// Sampling has no per-entry audit (observe) mode: enforcement: audit is rejected
	// on system: targets at manifest load, so a matched sampling constraint is never
	// audit-only. Route-level --audit still forwards sampling, but that is the
	// transport's call, not here.

	// Conditions on the opt-in entry MUST be evaluated — skipping them is a
	// fail-open on the only enforcement point for server-initiated sampling.
	// sampling/createMessage carries no tool args, so the request uses an empty set.
	// Sampling keeps its own constraint-resolution head but shares evaluateAndRecord
	// so its condition tail cannot drift from the other paths.
	req := &capability.EnforceRequest{
		SessionID: sessionID,
		ToolName:  capability.MethodSamplingCreateMessage,
		Arguments: map[string]interface{}{},
		Context:   capability.EnforceRequestContext{SourceIP: sourceIP},
		Target: &capability.EnforceRequestTarget{
			Type: string(capability.TargetTypeSystem),
			Name: capability.MethodSamplingCreateMessage,
		},
		Claims: claims,
	}

	return p.evaluateAndRecord(ctx, req, matched)
}

// DecidePromptGet evaluates a prompts/get against the manifest. Entries use
// namespaced targets "prompt:<name>" (e.g. "prompt:code_review", "prompt:*") with
// action "get" or "*".
func (p *ManifestPDP) DecidePromptGet(ctx context.Context, sessionID, promptName, sourceIP string) capability.EnforceResponse {
	// Conditions evaluate against {"name": promptName}; rejectSchema as for resources.
	return p.decideTarget(ctx, sessionID,
		EnforceTarget{Type: capability.TargetTypePrompt, Name: promptName},
		map[string]interface{}{"name": promptName}, sourceIP, rejectSchema)
}

// FilterToolsList implements ListFilterer for the manifest PDP. JWT claims are
// read from ctx so a principal-scoped entry is hidden from an identity that does
// not match it, keeping the visible list aligned with what the caller can invoke.
func (p *ManifestPDP) FilterToolsList(ctx context.Context, result json.RawMessage) ListFilterResult {
	return filterToolsListResult(result, p, jwtClaimsAsMap(ctx))
}

// FilterResourcesList implements ListFilterer for the manifest PDP.
func (p *ManifestPDP) FilterResourcesList(ctx context.Context, result json.RawMessage) ListFilterResult {
	return filterResourcesListResult(result, p, jwtClaimsAsMap(ctx))
}

// FilterPromptsList implements ListFilterer for the manifest PDP.
func (p *ManifestPDP) FilterPromptsList(ctx context.Context, result json.RawMessage) ListFilterResult {
	return filterPromptsListResult(result, p, jwtClaimsAsMap(ctx))
}

// emptyListEnvelope holds precomputed fail-closed envelopes keyed by list field
// name, used by filterListResult to avoid marshalling a fresh map on every parse failure.
var emptyListEnvelope = func() map[string]json.RawMessage {
	m := make(map[string]json.RawMessage, 3)
	for _, key := range []string{listKeyTools, listKeyResources, listKeyPrompts} {
		b, _ := json.Marshal(map[string]interface{}{key: []interface{}{}})
		m[key] = b
	}
	return m
}()

// filterListResult filters the named array field in a JSON result envelope,
// keeping only entries for which keep returns true. The full envelope, its
// original top-level key ORDER, and each kept entry's JSON all survive — only the
// list field's value changes. Fails closed to {"fieldName":[]} on any
// parse/marshal error — never the original bytes.
//
// It returns a ListFilterResult carrying the pruned envelope, the surviving
// entries pre-parsed (Entries), and the pre-filter (Upstream) and post-filter
// (Kept) counts it computes while iterating, so the transport audits them and a
// layered JWT filter re-filters them without a second parse. A fail-closed return
// reports both counts as 0 and nil Entries (the body could not be parsed).
//
// Filtering is per-entry: a single malformed entry is dropped on its own (keep
// fails closed to false on a decode error) rather than fail-closing the whole
// list. Key order is preserved by splicing only the list field back into the
// decoded ordered object — a map round-trip would emit top-level keys sorted,
// silently diverging the response from the upstream's field order.
func filterListResult(resultBytes json.RawMessage, fieldName string, keep func(json.RawMessage) (bool, string)) ListFilterResult {
	// failClosed returns the canonical empty listing {fieldName:[]}, dropping any
	// sibling fields: on a body the proxy could not parse as a list, the minimal
	// well-formed response is safer than echoing the rest of an unexpected envelope.
	failClosed := func() ListFilterResult {
		b := emptyListEnvelope[fieldName]
		if b == nil {
			b, _ = json.Marshal(map[string]interface{}{fieldName: []interface{}{}})
		}
		return ListFilterResult{Result: b, Upstream: 0}
	}
	// An empty/absent body carries no entries; fail closed rather than forward bytes.
	if len(resultBytes) == 0 {
		return failClosed()
	}
	// Decode preserving key order so sibling fields and their order survive verbatim.
	keys, values, err := decodeOrderedObject(resultBytes)
	if err != nil {
		return failClosed()
	}
	rawArray, ok := values[fieldName]
	if !ok {
		return failClosed()
	}
	var rawEntries []json.RawMessage
	if err := json.Unmarshal(rawArray, &rawEntries); err != nil {
		return failClosed()
	}
	kept := make([]json.RawMessage, 0, len(rawEntries))
	keptIDs := make([]string, 0, len(rawEntries))
	for _, raw := range rawEntries {
		pass, id := keep(raw)
		if pass {
			kept = append(kept, raw)
			keptIDs = append(keptIDs, id)
		}
	}
	out, err := encodeOrderedObjectWithList(keys, values, fieldName, kept)
	if err != nil {
		return failClosed()
	}
	return ListFilterResult{Result: out, Entries: kept, Upstream: len(rawEntries),
		envKeys: keys, envValues: values, entryIDs: keptIDs}
}

// decodeOrderedObject decodes a JSON object into its key order plus a key→value
// map, capturing each value's bytes verbatim. A plain map[string]json.RawMessage
// loses the order (Go marshals map keys sorted), which would silently reorder a
// filtered */list response away from the upstream's field order. Returns an error
// unless b is exactly one JSON object (matching json.Unmarshal, trailing data is
// rejected) so callers fail closed on anything else.
func decodeOrderedObject(b []byte) (keys []string, values map[string]json.RawMessage, err error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil, fmt.Errorf("list result is not a JSON object")
	}
	values = make(map[string]json.RawMessage)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, nil, fmt.Errorf("non-string object key")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, err
		}
		if _, dup := values[key]; !dup {
			keys = append(keys, key)
		}
		values[key] = raw // last value wins on a duplicate key, matching encoding/json
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, nil, err
	}
	// Reject trailing data after the object (json.Unmarshal does too): only EOF
	// (whitespace skipped) is acceptable here.
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, fmt.Errorf("trailing data after JSON object")
	}
	return keys, values, nil
}

// isSafeJSONKey reports whether s can be emitted as a JSON key using "s" without
// escaping. True for strings that contain only printable ASCII excluding '"', '\',
// and the runes encoding/json HTML-escapes ('<', '>', '&'), so a key the fast path
// accepts encodes byte-identically to json.Marshal(k) rather than emitting those
// runes raw.
func isSafeJSONKey(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b > 0x7E || b == '"' || b == '\\' || b == '<' || b == '>' || b == '&' {
			return false
		}
	}
	return true
}

// encodeOrderedObjectWithList re-emits a JSON object in keys order, substituting
// the marshaled entries array for the value of fieldName while every other field
// keeps its original bytes verbatim. For a conformant (unique-key) object the only
// change versus the upstream is the pruned list — field order and sibling fields
// are byte-faithful. A pathological duplicate-key object is collapsed to one entry
// per key (last value wins), exactly as encoding/json and the prior map round-trip
// did, so the output is the standard parse, not the original byte sequence. A
// nil/empty entries slice is emitted as [] (never null) so the list field stays an array.
// If fieldName is not among keys it is appended, so the encoded object always carries
// the list field (an envelope is never returned with the list silently dropped).
func encodeOrderedObjectWithList(keys []string, values map[string]json.RawMessage, fieldName string, entries []json.RawMessage) ([]byte, error) {
	if entries == nil {
		entries = []json.RawMessage{}
	}
	filtered, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	writeKey := func(buf *bytes.Buffer, k string) error {
		// fast path: most MCP envelope keys are safe ASCII needing no escaping.
		if isSafeJSONKey(k) {
			buf.WriteByte('"')
			buf.WriteString(k)
			buf.WriteByte('"')
			return nil
		}
		keyBytes, err := json.Marshal(k) // proper escaping of the key
		if err != nil {
			return err
		}
		buf.Write(keyBytes)
		return nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	wroteField := false
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeKey(&buf, k); err != nil {
			return nil, err
		}
		buf.WriteByte(':')
		if k == fieldName {
			buf.Write(filtered)
			wroteField = true
		} else {
			buf.Write(values[k])
		}
	}
	// The list field was absent from keys (e.g. a passthrough envelope that omitted
	// it): append it so the result is always a well-formed */list envelope carrying
	// the (possibly empty) array, never a body with the list field dropped.
	if !wroteField {
		if len(keys) > 0 {
			buf.WriteByte(',')
		}
		if err := writeKey(&buf, fieldName); err != nil {
			return nil, err
		}
		buf.WriteByte(':')
		buf.Write(filtered)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// replaceOrderedListField parses envelope as a JSON object (preserving key order)
// and re-emits it with fieldName's value replaced by the marshaled entries array.
// The JWT intersection path uses it to splice its in-memory claim-filtered entries
// back into the inner PDP's already-ordered envelope without re-parsing entries.
// Returns an error only if envelope is not an object; a missing fieldName is
// appended by encodeOrderedObjectWithList, so the result always carries the list
// field — matching the envKeys splice path so neither can silently drop it.
func replaceOrderedListField(envelope json.RawMessage, fieldName string, entries []json.RawMessage) ([]byte, error) {
	keys, values, err := decodeOrderedObject(envelope)
	if err != nil {
		return nil, err
	}
	return encodeOrderedObjectWithList(keys, values, fieldName, entries)
}

// filterResourcesListResult keeps only resources whose URIs match a manifest
// capability with "read" or "*". Conditions are NOT evaluated here — an entry is
// kept on a name+action match alone — so a constraint's conditions, including an
// allowedValues on the synthesized "uri" argument, are enforced only on the call
// leg (DecideResourceRead), not at list time. This matches tools/list and the JWT
// list filter (anyCapCovers), which likewise defer conditions to the call leg; the
// trade-off is that a resource whose read always denies on a uri allowedValues can
// still be advertised. Fails closed to an empty list on error.
func filterResourcesListResult(resultBytes json.RawMessage, mdp *ManifestPDP, claims map[string]interface{}) ListFilterResult {
	return filterListResult(resultBytes, listKeyResources, func(raw json.RawMessage) (bool, string) {
		var entry struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return false, ""
		}
		c := mdp.findConstraint(EnforceTarget{Type: capability.TargetTypeResource, Name: entry.URI}, claims)
		if c != nil && containsAction(c.Actions, "read") {
			return true, entry.URI
		}
		return false, ""
	})
}

// filterToolsListResult keeps only tools whose names match a manifest capability
// with "call" or "*". If the matched constraint pins a descriptionHash (exact-name
// tool: entries only), the live description is verified and a mismatch removes the
// tool. Fails closed to an empty list on error.
// toolListEntry is the subset of a tools/list entry the description-hash pin needs.
// Shared by the enforce-mode filter (filterToolsListResult) and the audit-mode
// RecordObservedToolHashes pass so both decode the same fields.
type toolListEntry struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description,omitempty"`
	InputSchema  map[string]interface{} `json:"inputSchema,omitempty"`
	Title        string                 `json:"title,omitempty"`
	Annotations  map[string]interface{} `json:"annotations,omitempty"`
	OutputSchema map[string]interface{} `json:"outputSchema,omitempty"`
}

// recordPinnedToolHash records entry's live description hash iff its NAME is pinned by
// any manifest entry — keyed off pinnedTools, not a selected constraint. A duplicate
// non-pinned sibling (or a pinned sibling lacking the "call" action) can win
// findConstraint selection and shadow the pin; gating on the selected constraint would
// then skip recording and leave the call leg unable to detect a mid-session description
// rotation. Gating on the pinned set still bounds the map by the operator-controlled
// manifest, so a name-rotating upstream cannot flood it. Recording passes the pin, so a
// mismatch is sticky-marked poisoned atomically (record + mark under one lock). Returns
// whether the tool was pinned so the filter can consult the sticky poison mark. Shared
// by the enforce-mode filter and the audit-mode RecordObservedToolHashes pass so an
// audit route records identically to an enforce route.
func (p *ManifestPDP) recordPinnedToolHash(entry toolListEntry) (pinned bool) {
	pin, pinned := p.pinnedTools[entry.Name]
	if pinned {
		p.recordObservedToolHash(entry.Name, entry.Description, entry.Title, entry.Annotations, entry.InputSchema, entry.OutputSchema, pin)
	}
	return pinned
}

// toolListEntryName is a lightweight decode target for a single tools/list entry — its
// name only. RecordObservedToolHashes uses it to test the pinnedTools gate BEFORE paying
// for the full toolListEntry decode (which can include large inputSchema/outputSchema/
// annotations maps): most catalogs are small-pinned-fraction, and the entries
// recordPinnedToolHash would discard for being unpinned should not first be fully
// unmarshaled just to read their name.
type toolListEntryName struct {
	Name string `json:"name"`
}

// RecordObservedToolHashes walks a tools/list result and records each pinned tool's
// live description hash without filtering the catalog, so the call-leg descriptionHash
// pin can still trip on an audit-mode (observe) route — where FilterToolsList (which
// otherwise records these while pruning) is bypassed and the catalog is forwarded
// verbatim. It applies the same pinnedTools gate as the filter, so it records no hash
// the filter would not, and prunes nothing. It also returns the number of tool entries
// in result (mirroring CountListEntries) so the caller — which must invoke this
// unconditionally on the audit-mode tools/list path — gets its audit-record entry count
// as a byproduct of this one decode, rather than a second full decode of the same bytes.
// Fail-open on a malformed envelope (returns 0): this is best-effort bookkeeping for the
// pin, never itself an enforcement decision.
func (p *ManifestPDP) RecordObservedToolHashes(_ context.Context, result json.RawMessage) int {
	if len(result) == 0 {
		return 0
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(result, &envelope); err != nil {
		return 0
	}
	rawArray, ok := envelope[listKeyTools]
	if !ok {
		return 0
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(rawArray, &entries); err != nil {
		return 0
	}
	if len(p.pinnedTools) == 0 {
		// Nothing to record: skip the per-entry decode entirely rather than fully
		// unmarshaling every entry only to find none pinned.
		return len(entries)
	}
	for _, raw := range entries {
		var name toolListEntryName
		if err := json.Unmarshal(raw, &name); err != nil {
			continue
		}
		if _, pinned := p.pinnedTools[name.Name]; !pinned {
			// Not pinned: skip the full toolListEntry decode (schema/annotations maps)
			// for an entry recordPinnedToolHash would discard anyway.
			continue
		}
		var entry toolListEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue
		}
		p.recordPinnedToolHash(entry)
	}
	return len(entries)
}

func filterToolsListResult(resultBytes json.RawMessage, mdp *ManifestPDP, claims map[string]interface{}) ListFilterResult {
	return filterListResult(resultBytes, listKeyTools, func(raw json.RawMessage) (bool, string) {
		var entry toolListEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return false, ""
		}
		c := mdp.findConstraint(EnforceTarget{Type: capability.TargetTypeTool, Name: entry.Name}, claims)

		// Record the live description whenever the tool NAME is pinned (see
		// recordPinnedToolHash), atomically sticky-marking a mismatch as poisoned BEFORE
		// any early return below.
		pinned := mdp.recordPinnedToolHash(entry)

		// c is nil when the tool is absent from the manifest; guard every dereference
		// below on it.
		if c == nil || !containsAction(c.Actions, "call") {
			return false, ""
		}
		// A poisoned pinned tool stays hidden even on a later clean observation (sticky),
		// mirroring the call-leg deny so the list a host is shown never contains a tool
		// its call leg will reject.
		if pinned && mdp.isToolPoisoned(entry.Name) {
			return false, ""
		}
		return true, entry.Name
	})
}

// filterPromptsListResult keeps only prompts whose names match a manifest
// capability with "get" or "*". Conditions are NOT evaluated here — an entry is
// kept on a name+action match alone. prompts/list carries no host arguments, but
// DecidePromptGet synthesizes {"name": name}, so a constraint's conditions —
// including an allowedValues on the synthesized "name" argument — are enforced
// only on the call leg (DecidePromptGet), not at list time. This matches tools/list
// and the JWT list filter (anyCapCovers), which likewise defer conditions to the
// call leg; the trade-off is that a prompt whose get always denies on a name
// allowedValues can still be advertised. Fails closed to an empty list on error.
func filterPromptsListResult(resultBytes json.RawMessage, mdp *ManifestPDP, claims map[string]interface{}) ListFilterResult {
	return filterListResult(resultBytes, listKeyPrompts, func(raw json.RawMessage) (bool, string) {
		var entry struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return false, ""
		}
		c := mdp.findConstraint(EnforceTarget{Type: capability.TargetTypePrompt, Name: entry.Name}, claims)
		if c != nil && containsAction(c.Actions, "get") {
			return true, entry.Name
		}
		return false, ""
	})
}

// JWTClaimsPtr returns the *JWTClaims stored in ctx, or nil when none is
// present. Used to capture a session's identity at initialize so server-initiated
// decisions can be audited with the same agent_id/task_id.
func JWTClaimsPtr(ctx context.Context) *JWTClaims {
	if c, ok := jwtClaimsFromContext(ctx); ok {
		return c
	}
	return nil
}

// agentIDFromContext returns the agent_id from any JWT claims stored in ctx,
// or "" when no JWT claims are present.  Used by kill-switch callers to
// thread the agent dimension into ShouldBlock.
func agentIDFromContext(ctx context.Context) string {
	if c, ok := jwtClaimsFromContext(ctx); ok {
		return c.AgentID
	}
	return ""
}

// reservedClaimKeys are the input.claims keys whose values come exclusively from
// the canonical JWTClaims fields, never the raw top-level token claims, so a token
// cannot shadow the proxy's identity by planting a same-named top-level claim.
var reservedClaimKeys = map[string]struct{}{
	"sub":      {},
	"iss":      {},
	"task_id":  {},
	"agent_id": {},
}

// jwtClaimsAsMap returns the flat input.claims map for the JWT claims in ctx, or nil
// when no claims are present. The map is memoized on the *JWTClaims at validation
// time (JWTClaims.flatClaims), so this hands out the precomputed map rather than
// rebuilding it on every enforced request, list filter, and sampling decision. A
// JWTClaims built without ValidateToken (e.g. tests) has no memoized map, so the map
// is built on the fly for that case (never stored — the *JWTClaims may be shared).
//
// The returned map MUST be treated as read-only by every caller (it is handed to
// third-party PolicyEvaluators).
func jwtClaimsAsMap(ctx context.Context) map[string]interface{} {
	c, ok := jwtClaimsFromContext(ctx)
	if !ok {
		return nil
	}
	if c.flatClaims != nil {
		return c.flatClaims
	}
	return buildFlatClaims(c)
}

// buildFlatClaims flattens a *JWTClaims into the input.claims map used in policy
// evaluation. Called once at validation to memoize JWTClaims.flatClaims (see
// jwtClaimsAsMap).
//
// Every raw top-level claim is exposed so a policy may reference any IdP claim via
// input.claims.<name>. On top of that base the four canonical keys (sub, iss,
// task_id, agent_id) are authoritative: a same-named custom claim never overrides
// them, and an empty canonical value omits the key rather than falling back to the
// raw claim — so a token cannot shadow the proxy's identity.
func buildFlatClaims(c *JWTClaims) map[string]interface{} {
	m := make(map[string]interface{}, len(c.Extra)+4)
	// Base layer: every raw top-level claim, minus the reserved keys, which are
	// set authoritatively from the canonical fields below.
	for k, v := range c.Extra {
		if _, reserved := reservedClaimKeys[k]; reserved {
			continue
		}
		m[k] = v
	}
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	if c.TaskID != "" {
		m["task_id"] = c.TaskID
	}
	if c.AgentID != "" {
		m["agent_id"] = c.AgentID
	}
	return m
}

// -----------------------------------------------------------------
// redactFields directive: mask JSON paths in tool-call result text.
// Applied post-allow only.
// -----------------------------------------------------------------

// ApplyRedactObligs applies redactFields obligations to a tools/call result,
// returning redacted bytes or an error. It MUST NOT return unredacted bytes when
// redact paths are non-empty and the response cannot be structurally verified
// (fail closed; see the capability-manifest guide § 5a).
//
// The result is decoded into a generic map so fields the proxy does not model
// (structuredContent, _meta, annotations, non-text content) survive the round-trip.
// Redaction applies to (1) each text content item whose body is clean JSON and (2)
// the structuredContent object. Content that is not a clean JSON container — free-form
// text, malformed JSON, JSON embedded in prose, a scalar — carries no addressable JSON
// object key and passes through unchanged; redactFields redacts cleanly-parseable JSON
// only and does NOT fail the response closed over string content it cannot parse. It
// fails closed on a structural/resource guard: an unparseable (or trailing-data)
// envelope, a structurally unverifiable content array/item shape, the depth bound, or a
// resource/resource_link content item (whose embedded text/blob body this redactor
// cannot inspect) — the last so an upstream cannot evade a declared redactFields
// obligation by embedding the named field inside a resource. image/audio items, which
// carry no addressable JSON body, still pass through.
func ApplyRedactObligs(resultBytes []byte, obligs []capability.Obligation) ([]byte, error) {
	if len(obligs) == 0 {
		return resultBytes, nil
	}

	var paths []string
	for _, ob := range obligs {
		if ob.Type == capability.DirectiveTypeRedactFields {
			paths = append(paths, ob.Paths...)
		}
	}
	if len(paths) == 0 {
		return resultBytes, nil
	}
	// Normalize the optional "$."/"$" JSONPath root marker ONCE here (paths is a fresh
	// slice, so the manifest's own Paths are untouched). Every downstream consumer on this
	// path takes the already-normalized slice and does NOT re-strip: rebaseLeafPaths compares
	// the pre-normalized paths against blob prefixes without re-stripping, and redactJSONValue
	// masks via the raw worker redactDotPathRec. Stripping twice is not idempotent for an
	// original "$.$…" spelling (a field whose key is literally "$"), which would leak.
	for i := range paths {
		paths[i] = normalizeDotPathRoot(paths[i])
	}

	// Preserve the original bytes so a response no path actually matches can be
	// returned verbatim (byte-for-byte), rather than re-marshaled — encoding/json
	// sorts map keys, so an unconditional re-marshal reorders the envelope (and any
	// JSON-object text item) even when nothing was redacted.
	original := resultBytes

	// Strip leading UTF-8 BOM(s) and JSON whitespace: encoding/json rejects a BOM, so
	// a BOM-prefixed envelope would otherwise fail the whole response closed.
	resultBytes = trimLeadingSpaceAndBOM(resultBytes)

	// Decode into a generic map so unknown fields survive the round-trip. UseNumber
	// so non-redacted integers above 2^53 round-trip byte-exact (marshalNoHTMLEscape
	// serializes json.Number verbatim).
	var result map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(resultBytes))
	dec.UseNumber()
	if err := dec.Decode(&result); err != nil {
		// Fail closed: never return unredacted data when we have paths to redact.
		return nil, fmt.Errorf("redactFields: failed to parse upstream response: %w", err)
	}
	// A JSON null envelope decodes into a nil map with no error — the one non-object
	// shape encoding/json accepts (arrays/scalars/bools all error above). It is not a
	// structurally valid tools/call result object, so fail closed like every sibling
	// non-object envelope rather than forwarding it with the obligation marked applied.
	if result == nil {
		return nil, fmt.Errorf("redactFields: response envelope is JSON null, not an object; cannot verify redaction (fail closed)")
	}
	// Decode stops after the first value; trailing tokens make the envelope a
	// malformed/ambiguous container that the documented contract refuses, mirroring
	// the per-text-item guard in redactJSONText — fail closed rather than silently
	// drop the trailing data on re-marshal.
	if dec.More() {
		return nil, fmt.Errorf("redactFields: trailing data after response envelope; cannot verify redaction (fail closed)")
	}

	// (1) Redact within each text content item. Any structurally unverifiable shape
	// — a non-array `content`, a non-object item, an item with no string `type`, an
	// unrecognized type, or a type=="text" item whose body is not a string — could
	// hide the named field, so each fails the whole response closed rather than
	// forward unredacted.
	changed := false
	if raw, present := result["content"]; present {
		content, ok := raw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("redactFields: response 'content' is present but is not an array (%T); cannot verify redaction (fail closed)", raw)
		}
		for _, item := range content {
			obj, ok := item.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("redactFields: response 'content' item is not an object (%T); cannot verify redaction (fail closed)", item)
			}
			t, ok := obj["type"].(string)
			if !ok || t == "" {
				return nil, fmt.Errorf("redactFields: response 'content' item has no string 'type'; cannot verify redaction (fail closed)")
			}
			if t != "text" {
				switch t {
				case "resource", "resource_link":
					// A resource / resource_link content item nests a `resource` object that
					// can carry a `text` or `blob` body holding arbitrary (possibly sensitive)
					// data this redactor does NOT walk. Silently forwarding it would let an
					// upstream evade a declared redactFields obligation by embedding the named
					// field inside a resource body. An active redaction obligation cannot be
					// satisfied over content the redactor cannot inspect, so fail the whole
					// response closed rather than forward it unredacted. See
					// docs/capability-manifest-guide.md.
					return nil, fmt.Errorf("redactFields: response 'content' item type %q carries an embedded resource body this redactor cannot inspect; cannot verify redaction (fail closed)", t)
				default:
					if !isRecognizedContentType(t) {
						return nil, fmt.Errorf("redactFields: response 'content' item has unrecognized type %q; cannot verify redaction (fail closed)", t)
					}
					// Recognized binary media (image/audio) carries no addressable JSON body a
					// redactFields dot-path could match, so it is preserved unchanged.
					continue
				}
			}
			text, ok := obj["text"].(string)
			if !ok {
				return nil, fmt.Errorf("redactFields: text content item has a non-string 'text' body (%T); cannot verify redaction (fail closed)", obj["text"])
			}
			redacted, err := redactJSONText(text, paths)
			if err != nil {
				return nil, err // fail closed
			}
			if redacted != text {
				changed = true
			}
			obj["text"] = redacted
		}
	}

	// (2) Redact within structuredContent (MCP 2025-06+ structured result), in place,
	// with the same fail-closed rigor as the content path above. See
	// redactStructuredContentField.
	scChanged, scErr := redactStructuredContentField(result, paths)
	if scErr != nil {
		return nil, scErr // fail closed
	}
	if scChanged {
		changed = true
	}

	// No path matched anything: return the original bytes verbatim so a response
	// the redaction did not touch is preserved byte-for-byte (key order, scalar
	// formatting, and any leading BOM/whitespace all intact). The re-marshal below
	// would otherwise reorder every envelope key via encoding/json's sorted-map
	// output even though nothing was redacted.
	if !changed {
		return original, nil
	}

	// Re-serialize WITHOUT HTML escaping: the default escaping of <, >, & (and
	// U+2028/U+2029) would rewrite passthrough values (URLs, HTML/XML, code) even in
	// fields no redaction path matched, breaking the "content not redacted is
	// preserved unchanged" guarantee for hosts that hash or diff the raw bytes.
	out, err := marshalNoHTMLEscape(result)
	if err != nil {
		return nil, fmt.Errorf("redactFields: failed to re-marshal redacted response: %w", err)
	}
	return out, nil
}

// recognizedContentTypes is the set of MCP content-item types this build models.
// Redaction applies only to "text" items (and structuredContent). "image"/"audio"
// carry no top-level JSON object body a dot path could name, so they pass through
// unchanged. An unrecognized type fails the response closed.
//
// "resource"/"resource_link" are recognized here (so an unrecognized-type guard does
// not fire on them) but, unlike image/audio, they do NOT pass through when a
// redactFields obligation is active: they nest a "resource" object with a text/blob
// body this redactor cannot walk, so ApplyRedactObligs fails the response closed over
// them rather than let an upstream evade redaction by embedding the field there.
var recognizedContentTypes = map[string]struct{}{
	"text":          {},
	"image":         {},
	"audio":         {},
	"resource":      {},
	"resource_link": {},
}

// isRecognizedContentType reports whether t is an MCP content-item type this
// build models (see recognizedContentTypes).
func isRecognizedContentType(t string) bool {
	_, ok := recognizedContentTypes[t]
	return ok
}

// utf8BOM is the UTF-8 byte-order mark (U+FEFF) as its three raw bytes, to keep
// the source ASCII-clean. encoding/json rejects a leading BOM and TrimSpace does
// not treat it as whitespace, so the redaction paths strip it explicitly —
// otherwise a BOM-prefixed JSON container evades redaction (fail open).
var utf8BOM = string([]byte{0xEF, 0xBB, 0xBF})

// trimLeadingSpaceAndBOM returns s with its entire leading run of UTF-8 BOMs and
// JSON whitespace removed, so the result begins at the first significant byte. It is
// generic over string and []byte so the two redaction paths share ONE implementation
// — the []byte envelope (ApplyRedactObligs) and the string leaf
// (classifyRedactableLeaf) — without a string twin AND without heap-copying a string
// leaf into a []byte just to trim it. The result is a reslice of s (no copy).
//
// The whole run (not just an offset-0 BOM) must go: a BOM anywhere in the leading
// run — behind a tab, doubled — would otherwise survive, keep encoding/json failing,
// and make classifyRedactableLeaf see 0xEF instead of '{', misclassifying a real JSON
// container as prose and forwarding it UNREDACTED.
func trimLeadingSpaceAndBOM[T ~string | ~[]byte](s T) T {
	i := 0
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
			i++
		}
		// string(s[i:i+3]) is free for a string operand and a bounded 3-byte copy for
		// a []byte operand — never the whole leaf.
		if i+len(utf8BOM) <= len(s) && string(s[i:i+len(utf8BOM)]) == utf8BOM {
			i += len(utf8BOM)
			continue
		}
		return s[i:]
	}
}

// marshalNoHTMLEscape marshals v as JSON without escaping <, >, & (and
// U+2028/U+2029), which the redaction path must not do or it would mutate
// passthrough content. The encoder's trailing newline is trimmed.
func marshalNoHTMLEscape(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// redactJSONText redacts the given dot-paths from a single text content item whose body
// may be JSON. It is a thin wrapper over redactContainerString (the shared core): a string
// that parses cleanly as a JSON object/array is redacted and re-serialized (recursively,
// including doubly-encoded JSON-container string values nested inside it); anything else —
// prose, a scalar, malformed JSON, or JSON embedded in prose — is returned unchanged.
// redactFields never fails the response closed over string content it cannot parse.
func redactJSONText(text string, paths []string) (string, error) {
	out, _, err := redactContainerString(text, paths, "", 0)
	return out, err
}

// redactContainerString redacts a string that is a (possibly multiply doubly-encoded) JSON
// container. It is the shared core of the text-content path (redactJSONText), the
// structuredContent string path (redactStructuredContentField), and the nested string-leaf
// walk (redactNestedJSONStrings), so the classify -> redact -> recurse -> re-serialize
// policy lives in one place. A string that parses cleanly as a JSON object/array is
// unwrapped, redacted (its object keys AND its own nested JSON-container string values, up
// to maxRedactionDepth), and re-serialized. A string that decodes to ANOTHER JSON string
// (a further string-encoding layer, e.g. a value double- or triple-JSON-encoded before
// delivery) recurses into that decoded string rather than passing it through, so a
// container hidden under any number of string layers is still reached — mirroring the
// coverage this function's callers document. Anything that is NOT a clean JSON container or
// string-encoded layer — prose, a genuine scalar, malformed JSON, or JSON embedded in
// surrounding prose — passes through byte-for-byte. redactFields does not fail the response
// closed over such content; data not modeled as clean JSON fields is redacted upstream (see
// the manifest guide and docs/threat-model-mcp.md). prefix rebases dot-paths to the string's
// position; depth bounds the recursion (both the container-key walk AND the string-layer
// unwrap share this one counter, so the total encoding depth an adversarial upstream can
// force is still capped at maxRedactionDepth).
func redactContainerString(s string, paths []string, prefix string, depth int) (redacted string, changed bool, err error) {
	if depth > maxRedactionDepth {
		return "", false, fmt.Errorf("redactFields: nested JSON content exceeds the redaction depth limit %d; cannot verify redaction (fail closed)", maxRedactionDepth)
	}
	decoded, kind := classifyRedactableLeaf(s)
	switch kind {
	case leafKindString:
		// A further string-encoding layer: recurse into the decoded inner string so a
		// container hidden under multiple layers of JSON-string encoding is still
		// reached, instead of treating the one-decode-away scalar as terminal.
		inner, innerChanged, ierr := redactContainerString(decoded.(string), paths, prefix, depth+1)
		if ierr != nil {
			return "", false, ierr
		}
		if !innerChanged {
			return s, false, nil // nothing matched at any layer: preserve the original bytes
		}
		return finalizeRedactedLeaf(inner)
	case leafKindContainer:
		changed, err = redactStructuredContentValue(decoded, paths, prefix, depth)
		if err != nil {
			return "", false, err // depth-limit guard or an internal re-marshal error
		}
		if !changed {
			return s, false, nil // nothing matched at any depth: preserve the original bytes
		}
		return finalizeRedactedLeaf(decoded)
	default:
		// Prose, a genuine scalar, malformed JSON, or JSON embedded in prose: no clean
		// JSON object to redact. Return the ORIGINAL string byte-for-byte (no
		// re-marshal/key reorder).
		return s, false, nil
	}
}

// finalizeRedactedLeaf re-marshals a redacted leaf value (an inner string from the
// leafKindString case, or a decoded container from the leafKindContainer case) back
// to JSON text, sharing the marshal-and-wrap-error tail both redactContainerString
// branches otherwise duplicate. Always reports changed=true: both callers already
// know something changed before calling this (that's why they're re-marshaling at
// all) and return their unmarshaled original directly on the unchanged path instead.
func finalizeRedactedLeaf(v interface{}) (redacted string, changed bool, err error) {
	out, merr := marshalNoHTMLEscape(v)
	if merr != nil {
		return "", false, fmt.Errorf("redactFields: failed to re-marshal redacted JSON content: %w", merr)
	}
	return string(out), true, nil
}

// maxRedactionDepth (256) is enforced in redactNestedJSONStrings, which walks EVERY
// structuredContent (and text) value — incrementing depth on each structural child and each
// doubly-encoded unwrap layer — and fails the WHOLE response closed past this limit. So 256
// is the operative bound on the redactable depth of ANY such value, plain or doubly-encoded,
// not just deeply-nested encoded payloads. It is a resource guard, not a content check,
// capping the worst-case re-marshal and dot-prefix-build cost against an adversarial input.
// The structural key-masking pass (redactJSONValue) carries no separate depth guard: it runs
// on the same value the string pass already depth-bounds (and only descends named paths plus
// array elements), so the response is denied at 256 regardless. encoding/json's own
// 10000-level decode cap is a far higher, separate bound — a response nested past it fails to
// decode and is rejected at the envelope — but 256 always fires first. No realistic tool
// result nests anywhere near this deep.
const maxRedactionDepth = 256

// leafRedactionKind classifies what a one-layer JSON decode of a redaction leaf yielded.
type leafRedactionKind int

const (
	// leafKindOther is prose, a genuine scalar (number/bool/null), malformed JSON, or
	// JSON embedded in surrounding prose: not redactable, passed through unchanged.
	leafKindOther leafRedactionKind = iota
	// leafKindContainer is a JSON object or array: the shape redactFields acts on directly.
	leafKindContainer
	// leafKindString is a JSON string scalar: a further string-encoding layer that may
	// itself decode to a container (or another string layer) and must be recursed into,
	// not treated as terminal — the fix for the double-encoding fail-open.
	leafKindString
)

// classifyRedactableLeaf decodes ONE JSON layer of the string s and reports what it found:
// a redactable container (leafKindContainer, the decoded object/array), a further
// string-encoding layer (leafKindString, the decoded inner string — the caller must decode
// it again to reach any container it wraps), or a terminal value (leafKindOther: prose, a
// genuine scalar, malformed JSON, or JSON embedded in prose) the caller passes through
// unchanged. redactFields never fails the response closed over string content it cannot
// parse — it redacts named fields of valid JSON only (see docs/threat-model-mcp.md).
//
// Fast-path guard: a string with no '{', no leading '"', and no leading '[' cannot name an
// object key, wrap one directly (as an object OR an array of objects), or wrap a further
// string-encoding layer that itself wraps one, so the decoder is skipped entirely (the
// common-leaf fast path); UseNumber preserves large-integer fidelity for the surviving
// fields on re-marshal. The envelope's first decode already resolves any "{" JSON escape to
// a literal '{' byte, so a directly-embedded leafKindContainer is always caught by the '{'
// check alone — the leading-'"'/leading-'[' arms exist only for a NESTED encoding layer or
// an array wrapper. Concretely: a doubly-encoded value can spell its INNER layer's braces
// as {/} unicode escapes, so the once-decoded Go string is a further JSON string (starts
// with '"') containing no literal '{' byte that still decodes to an object; the same
// evasion works one level further out via an array of escaped-brace string-encoded objects
// (`["{ssn...}"]`), which contains no literal '{' anywhere and starts with '[', not '"'.
// Bailing on '{' (or '{'-or-'"') alone would skip that layer and let the object it wraps
// pass through unredacted (see the redactNestedJSONStrings doc comment on doubly-encoded
// smuggling). A leading '"' or '[' that turns out to decode to plain prose, a scalar, or an
// array of non-container elements still terminates safely as leafKindOther after one
// bounded recursion (depth capped at maxRedactionDepth), so accepting these two extra
// prefixes costs no extra fail-closed risk.
func classifyRedactableLeaf(s string) (decoded interface{}, kind leafRedactionKind) {
	trimmed := trimLeadingSpaceAndBOM(s)
	// '"' and '[' use HasPrefix (position-0 only) deliberately: under JSON grammar a
	// container's or a further string layer's start token must be the first
	// non-whitespace/BOM byte, so a '"' or '[' appearing later in the string cannot
	// itself open one. '{' intentionally stays ContainsRune (whole-string), broader
	// than strictly needed, because a bare embedded '{' not at position 0 is already
	// handled safely: it still has to pass the decode+dec.More() check below to be
	// treated as anything but leafKindOther, so widening it to HasPrefix would only
	// narrow coverage, not fix a bug. Do not "harmonize" the three checks to all use
	// HasPrefix without re-deriving this.
	looksLikeJSON := strings.ContainsRune(trimmed, '{') || strings.HasPrefix(trimmed, `"`) || strings.HasPrefix(trimmed, `[`)
	if !looksLikeJSON {
		return nil, leafKindOther
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var val interface{}
	// Decode stops after the first value; a decode error OR trailing tokens means s is not
	// a single clean JSON value (malformed, or JSON embedded in prose) — pass through.
	if dec.Decode(&val) != nil || dec.More() {
		return nil, leafKindOther
	}
	switch v := val.(type) {
	case map[string]interface{}, []interface{}:
		return val, leafKindContainer
	case string:
		return v, leafKindString
	default:
		return nil, leafKindOther // a genuine JSON scalar (number/bool/null): no object key
	}
}

// redactJSONValue applies every dot-path redaction to a decoded JSON value,
// handling a top-level object or array of objects. It reports whether it actually
// masked a field. A value that matched no path (including any scalar) reports
// false, so the caller leaves the ORIGINAL bytes untouched — re-marshaling a map
// the redaction did not touch would reorder its keys (encoding/json sorts map
// keys) and could change scalar byte representation (1e308 -> 1e+308), breaking
// the "content not redacted is preserved unchanged" guarantee.
func redactJSONValue(val interface{}, paths []string) bool {
	switch v := val.(type) {
	case map[string]interface{}:
		changed := false
		for _, p := range paths {
			// paths arrive already root-normalized: ApplyRedactObligs strips the
			// optional "$."/"$" JSONPath marker once up front and threads the same
			// slice through the walk and rebaseLeafPaths. Redact via the raw worker
			// so the marker is NOT stripped a second time — a second strip is not
			// idempotent for a path that, after the first strip, still begins with
			// "$." or equals "$" (i.e. an original "$.$…" spelling targeting a field
			// whose key is literally "$"): it would over-strip and leak that field.
			// ApplyRedactObligs already normalized the marker once up front.
			if redactDotPathRec(v, p) {
				changed = true
			}
		}
		return changed
	case []interface{}:
		// Recurse into every element so objects at any nesting depth are redacted
		// (stopping at the first array level would leak nested fields).
		changed := false
		for _, item := range v {
			if redactJSONValue(item, paths) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

// redactStructuredContentField redacts result["structuredContent"] in place (if present)
// and reports whether it changed. A JSON object or array is redacted directly; a JSON-string
// body is run through redactContainerString (a clean JSON container is unwrapped and
// redacted; prose, malformed JSON, or JSON embedded in prose passes through). A JSON null,
// number, or bool carries no named field and passes through. redactFields never fails the
// whole response closed over a structuredContent shape it cannot redact.
//
// This is the TOP-LEVEL value dispatch; redactNestedJSONStrings applies the same
// object/array-vs-string-vs-pass-through policy to NESTED values during the unwrap walk, and
// both funnel string leaves through the shared redactContainerString core. A change to which
// shapes redact versus pass through must be mirrored in both, or top-level and nested values
// of the same shape would redact differently.
func redactStructuredContentField(result map[string]interface{}, paths []string) (bool, error) {
	sc, ok := result["structuredContent"]
	if !ok {
		return false, nil
	}
	switch scv := sc.(type) {
	case map[string]interface{}, []interface{}:
		return redactStructuredContentValue(scv, paths, "", 0)
	case string:
		out, c, err := redactContainerString(scv, paths, "", 0)
		if err != nil {
			return false, err // depth-limit guard or an internal re-marshal error
		}
		if c {
			result["structuredContent"] = out
		}
		return c, nil
	default:
		// JSON null, number, or bool: a scalar structuredContent carries no named field, so
		// there is nothing to redact and nothing that could hide one — pass it through. This
		// is deliberately MORE lenient than the content-array path in ApplyRedactObligs, which
		// fails closed on a structurally anomalous shape: a malformed content item can conceal
		// a text body carrying the field, whereas a bare scalar cannot. Do not reconcile the
		// two — failing closed here would needlessly block valid scalar results, and passing
		// anomalous content shapes through there would fail open on a real hiding place.
		return false, nil
	}
}

// redactStructuredContentValue redacts an already-decoded structuredContent container
// (object or array) in place, at dot-prefix `prefix` from the structuredContent root: it
// masks the object keys the manifest paths address (redactJSONValue, with paths rebased
// to prefix) AND recursively unwraps any doubly-encoded JSON-container string leaf at any
// depth (redactNestedJSONStrings, whose string case calls back here for each unwrapped
// layer). It reports whether anything changed. A string that is not a clean JSON container
// passes through unchanged; only the depth guard fails closed.
func redactStructuredContentValue(v interface{}, paths []string, prefix string, depth int) (changed bool, err error) {
	keysChanged := redactJSONValue(v, rebaseLeafPaths(paths, prefix))
	_, stringsChanged, serr := redactNestedJSONStrings(v, paths, prefix, depth)
	if serr != nil {
		return false, serr
	}
	return keysChanged || stringsChanged, nil
}

// redactNestedJSONStrings walks a decoded structuredContent value and applies redaction
// to every string leaf that is a doubly-encoded JSON payload — a value an upstream can
// use to smuggle a named field past the structural-key redaction (redactJSONValue),
// which only addresses object keys and ignores string scalars (e.g. {"data":"{\"ssn\":
// \"x\"}"} or ["{\"ssn\":\"x\"}"]). Each leaf is run through redactContainerString — the
// SAME treatment a top-level structuredContent string gets — so a leaf that parses cleanly
// as a JSON container is unwrapped, redacted, and re-serialized; anything that is not a
// clean JSON container (prose, a scalar, malformed JSON, or JSON embedded in prose) passes
// through unchanged. An unwrapped container is redacted via redactStructuredContentValue,
// which recurses back here, so a field hidden under MULTIPLE encoding layers is reached too.
//
// prefix is the dot-path from the structuredContent root to v; it rebases each leaf's
// paths (see rebaseLeafPaths) so a path like data.ssn reaches the ssn smuggled inside a
// string at key "data" — the same field the structural pass redacts in the honest,
// un-encoded {"data":{"ssn":...}} shape. Object keys extend the prefix; array elements
// are transparent to dot-paths and inherit it. Maps and slices are mutated in place; the
// string case returns its replacement (which the parent writes back), so the first
// return is load-bearing only for a leaf.
func redactNestedJSONStrings(v interface{}, paths []string, prefix string, depth int) (redacted interface{}, changed bool, err error) {
	if depth > maxRedactionDepth {
		return nil, false, fmt.Errorf("redactFields: nested JSON content exceeds the redaction depth limit %d; cannot verify redaction (fail closed)", maxRedactionDepth)
	}
	// This walk finds and unwraps doubly-encoded string leaves only. Object-key masking for
	// the whole decoded value is done once, up front, by the redactJSONValue pass in
	// redactStructuredContentValue (redactDotPathRec descends named paths itself), so the two
	// passes are deliberately separate concerns, not a redundant double key-walk: fusing them
	// would re-thread the path-rebasing/array-descent logic through one traversal for a
	// marginal gain on size-bounded responses, at real risk to this DLP path.
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			childPrefix := k
			if prefix != "" {
				childPrefix = prefix + "." + k
			}
			nv, c, cerr := redactNestedJSONStrings(child, paths, childPrefix, depth+1)
			if cerr != nil {
				return nil, false, cerr
			}
			if c {
				val[k] = nv
				changed = true
			}
		}
		return val, changed, nil
	case []interface{}:
		for i, child := range val {
			// Array elements are transparent to dot-paths (a path applies to every
			// element), so the prefix is inherited unchanged.
			nv, c, cerr := redactNestedJSONStrings(child, paths, prefix, depth+1)
			if cerr != nil {
				return nil, false, cerr
			}
			if c {
				val[i] = nv
				changed = true
			}
		}
		return val, changed, nil
	case string:
		// A doubly-encoded JSON-container leaf gets the same redact / re-serialize treatment
		// as any container string; redactContainerString recurses back through
		// redactStructuredContentValue, so a field under a further encoding layer is reached
		// too. A non-container string (prose, malformed, embedded-in-prose) passes through.
		out, c, cerr := redactContainerString(val, paths, prefix, depth+1)
		if cerr != nil {
			return nil, false, cerr
		}
		return out, c, nil
	}
	return v, false, nil
}

// rebaseLeafPaths returns the dot-paths to apply, at its own root, to a doubly-encoded
// JSON-container string unwrapped at dot-prefix `prefix` within structuredContent. A path
// may redact inside the blob only if the honest, un-encoded shape would redact a field at
// this same position, so each input path maps as follows:
//
//   - A BARE single-segment path (e.g. "ssn") applies at the blob root unchanged: a bare
//     field name is redacted at the top level of every unwrapped container — the documented
//     doubly-encoded smuggling defense, where bare "ssn" catches an ssn smuggled at any layer.
//   - A multi-segment path addressing a location UNDER `prefix` (e.g. "data.ssn" reached via
//     key "data") contributes the remainder after the prefix ("ssn") — the same field the
//     structural pass redacts in the honest {"data":{"ssn":...}} shape.
//   - A multi-segment path anchored ELSEWHERE (it does not start with prefix+".") names
//     nothing inside this blob, so it is dropped. Retaining its absolute form and re-applying
//     it at the blob root would mask a differently-located field the manifest never named —
//     over-redaction that the honest, un-encoded shape does not perform.
//
// paths arrive already root-normalized — ApplyRedactObligs strips the optional "$."/"$"
// JSONPath marker once up front and threads the same slice through the walk — so this does
// NOT re-strip it; the comparisons below are against blob prefixes built from raw JSON keys
// (which carry no marker), and redactJSONValue applies them via redactDotPathRec without a
// second strip.
func rebaseLeafPaths(paths []string, prefix string) []string {
	if prefix == "" {
		return paths
	}
	dotPrefix := prefix + "."
	// Single pass with lazy copy-on-write: alias the input while every path so far is kept
	// verbatim, and copy only when the first path is rebased or dropped — so an all-bare batch
	// (the common case, and any batch needing no rebasing) returns the input slice uncopied.
	out := paths
	rewritten := false
	for i, p := range paths {
		switch {
		case !strings.Contains(p, "."):
			// Bare single segment: applies at the blob root unchanged (smuggling defense).
			if rewritten {
				out = append(out, p)
			}
		case strings.HasPrefix(p, dotPrefix):
			// Addresses a location under this blob: rebase to the remainder after the prefix.
			if !rewritten {
				out = append([]string(nil), paths[:i]...)
				rewritten = true
			}
			out = append(out, p[len(dotPrefix):])
		default:
			// Anchored elsewhere: names nothing in this blob; drop it to avoid over-redaction.
			if !rewritten {
				out = append([]string(nil), paths[:i]...)
				rewritten = true
			}
		}
	}
	return out
}

// redactedSentinel is the placeholder a redacted field's value is replaced with.
// redactFields MASKS rather than strips: the matched key stays present and its
// value becomes this sentinel, so a host sees that the field existed but never its
// value. (Stripping the key instead would hide the field's very existence — a
// different disclosure trade-off; see docs/threat-model-mcp.md.)
const redactedSentinel = "[redacted]"

// normalizeDotPathRoot strips the optional JSONPath root marker from a dot-path EXACTLY
// once — only the two real spellings "$." and a lone "$" — leaving a real $-prefixed field
// name ("$schema", "$ref", …) intact and matched literally. It is the single definition of
// the root-marker rule, shared by ApplyRedactObligs (which applies it once up front so the
// rule is not re-evaluated at every node of the walk) and rebaseLeafPaths (nested-string
// rebasing).
func normalizeDotPathRoot(dotPath string) string {
	switch {
	case strings.HasPrefix(dotPath, "$."):
		return dotPath[len("$."):]
	case dotPath == "$":
		return ""
	}
	return dotPath
}

// redactDotPathRec is the recursive worker for the redactFields walk. It does NOT
// strip the "$"/"$." root marker: ApplyRedactObligs normalizes that exactly once up
// front, so a $-prefixed nested field name here is matched literally. It reports
// whether a field was masked.
func redactDotPathRec(obj map[string]interface{}, dotPath string) bool {
	parts := strings.SplitN(dotPath, ".", 2)
	key := parts[0]
	if len(parts) == 1 {
		if _, present := obj[key]; !present {
			return false
		}
		// Mask in place: replace the value with the sentinel, keep the key. The
		// prior value (object, array, number, or string) is discarded wholesale.
		obj[key] = redactedSentinel
		return true
	}
	return redactValuePath(obj[key], parts[1])
}

// redactValuePath applies the remaining dot-path to a value that may be a nested
// object or an arbitrarily nested array of objects (so "results.ssn" works whether
// results is an object or an array of objects). Scalars and absent values are a
// no-op. Calls redactDotPathRec (the root marker is normalized once up front by
// ApplyRedactObligs, not re-stripped at each level). Reports whether any field was masked.
func redactValuePath(val interface{}, dotPath string) bool {
	switch v := val.(type) {
	case map[string]interface{}:
		return redactDotPathRec(v, dotPath)
	case []interface{}:
		changed := false
		for _, item := range v {
			if redactValuePath(item, dotPath) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}
