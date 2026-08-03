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
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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

	// DecideResourceCancel authorizes a resources/unsubscribe: the CANCELLATION of a
	// subscription this session already holds. It is a separate entry point from
	// DecideResourceRead, not a synonym, because cancelling moves no data — it only ever
	// REDUCES flow — and the read decision is a committing one.
	//
	// Routing a cancel through DecideResourceRead made it consume the resource's maxCalls
	// quota, record a sequenceBlock antecedent, and apply the entry's labelOutput taint,
	// all for a call that transfers nothing. Worse, once that quota was spent (or a
	// timeWindow closed, or the client roamed out of an ipRange) the cancel was itself
	// DENIED — so the host could not stop a stream it had legitimately started, which is
	// the exact failure mapping the method was meant to remove.
	//
	// The decision is therefore name-and-action only: the URI must match a resource entry
	// this caller may `read`, evaluated with the same matcher the resources/list filter
	// uses, and no condition is evaluated and no session state is committed. That is the
	// right authority question for a cancel — a URI the manifest never permitted was never
	// subscribable, so naming it here is a host talking about a channel it does not have —
	// and it is strictly narrower than the subscribe it undoes.
	DecideResourceCancel(ctx context.Context, sessionID, uri, sourceIP string) capability.EnforceResponse

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
	//
	// CONTRACT: an implementation MUST be CPU-only and non-blocking — decide from the
	// claims already on ctx and return. Do NOT perform network I/O, acquire contended
	// locks, or sleep. Callers evaluate this gate on latency-sensitive paths, including
	// immediately before taking process-wide locks, so a blocking implementation would
	// stall traffic well beyond the request that triggered it. Fetch anything you need
	// (keys, directories, audience mappings) out of band and consult a cached view here.
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

	// CommitDeclassified applies an approved declassification's label clear, for a call the
	// decision AUTHORIZED and the transport has now actually performed. labels is the
	// decision's LabelsPendingClear — what the approval authorized, not what will
	// necessarily change.
	//
	// It is on this interface because the two halves sit on opposite sides of it. Decide
	// resolves the approval, burns a single-use grant, and hands back the labels to clear;
	// only the transport knows whether the call went on to reach the upstream and return a
	// deliverable response. Applying the clear inside Decide instead made the labels
	// invisible to every concurrent decision for the whole upstream round trip — a sink the
	// taint existed to stop could be allowed and forwarded while the sanitizing call was
	// still in flight — and no compensating undo could close that, because the window opened
	// before the undo could possibly run.
	//
	// It follows that the transport must call this ONLY on the success path. Every refusal
	// below the decision (--require-audit=strict, an upstream transport failure, a redaction
	// failure) simply does not call it, and the labels were never gone.
	//
	// It returns what actually CHANGED — the intersection with what the anchor is carrying at
	// commit time — because the caller stamps that onto the tape as a SIGNED assertion, and
	// an approval to clear a label the session never held is a permitted no-op that must
	// record no labels_cleared and no approver. An implementation that holds no flow state
	// reports (nil, nil): it cleared nothing, which is the truth and is the safe state.
	// An error means the clear may have partly landed; the labels that stay over-block a
	// later sink, which is the fail-closed residual.
	//
	// CONTEXT CONTRACT: the caller must preserve the request's validated claims. An
	// implementation resolves the state anchor from them (a task-anchored call is accounted
	// against the TASK key), so a context detached with context.Background() would clear the
	// wrong key — leaving the task tainted, dropping a label the session never asked to drop,
	// and reporting success. Detach cancellation only (context.WithoutCancel), never the
	// values. This differs from ReleaseSession above, which owns only session-anchored state
	// and may be fully detached.
	CommitDeclassified(ctx context.Context, sessionID string, labels []string) (cleared []string, err error)

	// HardenRefusal re-stamps a refusal that some OTHER layer produced with the verdicts
	// THIS PDP would have contributed had it been consulted, and returns the composed
	// refusal.
	//
	// It exists for the wrapper case. A composing PDP (the JWT layer) refuses some calls on
	// its own terms and short-circuits above the PDP it wraps, so the inner one never runs
	// — and three things it would have supplied are silently lost: the redaction
	// obligations a downgraded deny must carry, the interface-pin break, and the effect
	// ceiling. Each loss turned "adding a JWT" into "removing a guarantee", which inverts
	// the rule that a token may only ever restrict.
	//
	// It is on the CONTRACT rather than reached through a type assertion for the same
	// reason the list-filtering and sampling facets are: the wrapper previously asserted
	// its inner to a concrete *ManifestPDP and silently did nothing for any other
	// implementation, so a third-party PDP holding a pin or a ceiling composed as if it
	// held neither. Each implementation also owns its own ORDERING internally, which is
	// where that rationale belongs — the wrapper had to restate it.
	//
	// Contract for implementers:
	//   - MUST NOT turn a refusal into an allow, and MUST NOT return anything softer than
	//     what it was given: not downgradable if the input was not, and never dropping
	//     obligations from a refusal that remains forwardable.
	//   - MUST NOT commit session state. It runs on a path the PDP deliberately never
	//     reached, for a call that will not be forwarded, so a committing check here would
	//     leave exactly the phantom state the decision path's ordering prevents.
	//   - MUST be a safe identity for a PDP with nothing to contribute (AlwaysAllowPDP,
	//     DenyAllPDP), and for an allow.
	HardenRefusal(ctx context.Context, sessionID string, r capability.EnforceResponse, target EnforceTarget, args map[string]interface{}) capability.EnforceResponse
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

// jsonKeyName is the tools/list entry key the pin routes on, as it appears on the wire.
const jsonKeyName = "name"

// jsonKeyNameFolded is jsonKeyName under the same fold scanToolEntry applies to every
// top-level key, so the two are compared in one space. It must be derived rather than
// written out: capability.FoldJSONKey maps each rune to a fixed representative of its
// simple-fold orbit, and which representative that is belongs to that function, not to
// this literal. A hand-written spelling that stopped matching would not fail loudly —
// scanToolEntry would silently stop collecting names, leaving poisonCandidates with
// nothing to poison on an untrustworthy entry.
var jsonKeyNameFolded = capability.FoldJSONKey(jsonKeyName)

// listKeyToolsFolded is listKeyTools under that same fold, for toolsKeyAmbiguous's
// case-variant sibling check. Derived for the reason above, not written out.
var listKeyToolsFolded = capability.FoldJSONKey(listKeyTools)

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

// listDecodeOutcome classifies how far decodeListEntries got. The failures are kept
// DISTINCT rather than folded into one "not ok" because the two callers must react
// differently: countListEntries reports 0 for all of them, while armPinsFromToolsList
// treats an unreadable envelope or array as ambiguous (poison every pin) but a plainly
// absent key as benign (a host renders no tools from it).
type listDecodeOutcome int

const (
	listDecodeOK          listDecodeOutcome = iota // entries decoded (possibly an empty array)
	listDecodeEmptyResult                          // no result bytes at all
	listDecodeBadEnvelope                          // result is not a JSON object
	listDecodeKeyAbsent                            // object decoded, but carries no fieldName key
	listDecodeBadArray                             // fieldName present but not an array of entries
)

// decodeListEntries decodes a */list result envelope down to the entry array under
// fieldName, returning the entries and an outcome the caller switches on. Ambiguity in
// the envelope itself (a duplicate or case-variant fieldName key) is NOT this
// function's concern — callers that care check it separately via toolsKeyAmbiguous,
// which re-scans the raw bytes rather than the already-folded decode below.
//
// One decode contract for both consumers: the length-only countListEntries and the
// pin-arming walk previously spelled this same envelope→lookup→array sequence out
// separately, so a change to how a list envelope is read had to be made twice.
func decodeListEntries(result json.RawMessage, fieldName string) (entries []json.RawMessage, outcome listDecodeOutcome) {
	if len(result) == 0 {
		return nil, listDecodeEmptyResult
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(result, &envelope); err != nil {
		return nil, listDecodeBadEnvelope
	}
	rawArray, ok := envelope[fieldName]
	if !ok {
		return nil, listDecodeKeyAbsent
	}
	if err := json.Unmarshal(rawArray, &entries); err != nil {
		return nil, listDecodeBadArray
	}
	return entries, listDecodeOK
}

// countListEntries returns the number of entries in the fieldName array of a
// */list result envelope, or 0 for an empty/absent/unparseable result. It backs
// the exported CountListEntries (the audit/wiretap best-effort entry count); the
// filter paths (passThroughList, filterListResult) decode entries from their own
// key-ordered envelope decode instead, so they preserve sibling fields and key
// order, so this stays a length-only helper.
func countListEntries(result json.RawMessage, fieldName string) int {
	entries, _ := decodeListEntries(result, fieldName)
	return len(entries) // nil on every failure outcome, so no branch is needed
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
//
// clock is the caller's decision clock, passed through to denyResponse so a kill
// deny stamps DecidedAt from the same source as every other deny (and as the allow
// path), honoring a frozen test clock. A nil clock falls back to the wall clock.
func killCheck(ctx context.Context, clock enforcement.Clock, ks killswitch.Checker, sessionID string) *capability.EnforceResponse {
	if ks == nil {
		return nil
	}
	blocked, err := ks.ShouldBlock(ctx, agentIDFromContext(ctx), sessionID)
	if err != nil {
		deny := denyResponse(clock, capability.ErrCodeKillSwitchError, "", "kill switch check failed: "+err.Error())
		return &deny
	}
	if blocked {
		deny := denyResponse(clock, capability.ErrCodeKillSwitch, "", "session has been terminated by a kill-switch command")
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
	return denyResponseWithDetails(clock, code, condType, message, nil)
}

// denyResponseWithDetails is denyResponse for a deny that carries structured details, and it
// is the ONE place in this package that may set Denial.Details.
//
// The bound lives here rather than at each call site for the reason pkg/enforcement gives for
// putting it inside its own denyResponse: a denial's details echo caller-controlled values —
// the argument that missed the allowlist, the operation that was refused — so every denied
// call is otherwise a lever on signed-log growth at whatever rate the caller can issue them.
// A rule each producer has to remember is a rule that gets forgotten silently: the deny stays
// well-formed, signed and chain-verifiable, just unbounded. Routing denyResponse through this
// with nil details means the bound is inherited by every deny this package builds, and setting
// Denial.Details anywhere else is the mistake to catch in review.
//
// enforcement.BoundDenialDetails is deliberately NOT idempotent (see its doc), which is the
// other reason there is exactly one funnel: a value bounded here must not pass through it
// again.
func denyResponseWithDetails(clock enforcement.Clock, code, condType, message string, details map[string]interface{}) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision:  capability.DecisionDeny,
		RequestID: enforcement.NewRequestID(),
		DecidedAt: clockNow(clock).UTC().Format(time.RFC3339Nano),
		Denial: &capability.DenialInfo{
			Code:          code,
			ConditionType: condType,
			Message:       message,
			Details:       enforcement.BoundDenialDetails(details),
		},
	}
}

// denyFromCondition builds this layer's deny from a verdict a SHARED condition evaluator
// produced (enforcement.EvaluateAllowedValues today), so a refusal raised on the JWT
// capability-claim path is the same refusal — code, condition type, and structured details —
// the manifest path records for the same input.
//
// The details are the point. "One logical refusal, two record shapes depending only on
// whether a token was involved" is the defect class this closes: the manifest path's
// VALUE_NOT_PERMITTED carries details{argument, value, allowedValues} and the JWT path's
// carried none, so a SIEM rule written against one found nothing for a token-scoped caller —
// and the transport reads details["argument"] to name the offending argument in the
// host-facing error, which that path could not do either.
//
// name — the capability-claim target this condition came from — is prefixed onto the shared
// message rather than replacing it. A grant is one of an OR-list, so which entry refused is
// the diagnostic a bare condition message cannot supply.
func denyFromCondition(clock enforcement.Clock, name string, cerr *enforcement.ConditionError) capability.EnforceResponse {
	return denyResponseWithDetails(clock, cerr.Code, cerr.ConditionType,
		fmt.Sprintf("%q: %s", name, cerr.Message), cerr.Details)
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

// DecideResourceCancel returns a wiretap allow for every resources/unsubscribe, unless a
// kill is active.
func (p AlwaysAllowPDP) DecideResourceCancel(ctx context.Context, sessionID, _, _ string) capability.EnforceResponse {
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
	return killCheck(ctx, p.clock, p.ks, sessionID)
}

// CheckAudience pins no token audience: a wiretap/audit-mode route forwards every call,
// so it imposes no per-route audience requirement.
func (AlwaysAllowPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}

// RecordObservedToolHashes records no hashes — a wiretap PDP pins no tool
// descriptions — but still reports an entry count for the caller's audit record.
// With no pin to arm and no catalog to carry, only the count is wanted, so this
// takes the length-only countListEntries rather than building an ordered envelope
// (key slice plus key-to-RawMessage map) and discarding all of it. That is the same
// best-effort accounting the exported CountListEntries does on this very path.
func (AlwaysAllowPDP) RecordObservedToolHashes(_ context.Context, result json.RawMessage) int {
	return countListEntries(result, listKeyTools)
}

// ReleaseSession is a no-op: a wiretap PDP enforces no policy and holds no per-session
// flow state to release.
func (AlwaysAllowPDP) ReleaseSession(_ context.Context, _ string) {}

// CommitDeclassified never clears anything: a wiretap PDP holds no flow store and
// authorizes no declassification, so no decision it returns can carry a LabelsPendingClear.
//
// Reaching it WITH labels therefore means some other layer authorized a clear this one
// cannot perform, and that is reported as an error rather than as a silent empty result.
// The two are different facts, and the caller writes a signed record from the difference: an
// empty result means "the clear ran and moved nothing", which for a wiring fault would put
// an ordinary allow on the tape for a policy whose sanitizing step never takes effect. The
// old contract carried a `restored bool` for exactly this distinction.
func (AlwaysAllowPDP) CommitDeclassified(_ context.Context, _ string, labels []string) ([]string, error) {
	return nil, noFlowStateErr(labels, "audit-mode (wiretap) decision point")
}

// HardenRefusal returns the refusal unchanged: a wiretap PDP declares no pin, no ceiling
// and no redaction, so it has nothing to compose onto another layer's verdict.
func (AlwaysAllowPDP) HardenRefusal(_ context.Context, _ string, r capability.EnforceResponse, _ EnforceTarget, _ map[string]interface{}) capability.EnforceResponse {
	return r
}

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

// DecideResourceRead denies every resources/read, resources/subscribe, and
// resources/unsubscribe.
func (p DenyAllPDP) DecideResourceRead(_ context.Context, _, _, _ string) capability.EnforceResponse {
	return p.deny()
}

// DecideResourceCancel denies every resources/unsubscribe. A no-policy route authorizes
// nothing, so it has authorized no subscription to cancel either.
func (p DenyAllPDP) DecideResourceCancel(_ context.Context, _, _, _ string) capability.EnforceResponse {
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
// descriptions (and denies every call regardless) — but still reports an entry count
// for the caller's audit record, via the same length-only countListEntries
// AlwaysAllowPDP uses.
func (DenyAllPDP) RecordObservedToolHashes(_ context.Context, result json.RawMessage) int {
	return countListEntries(result, listKeyTools)
}

// ReleaseSession is a no-op: the fail-closed default holds no per-session flow state.
func (DenyAllPDP) ReleaseSession(_ context.Context, _ string) {}

// CommitDeclassified never clears anything: the fail-closed default allows nothing, so no
// decision it returns can authorize a clear. Same reporting rule as AlwaysAllowPDP's.
func (DenyAllPDP) CommitDeclassified(_ context.Context, _ string, labels []string) ([]string, error) {
	return nil, noFlowStateErr(labels, "deny-all (no policy) decision point")
}

// noFlowStateErr builds the fault a decision point returns when it is handed labels to clear
// and holds no flow state to clear them from, or nil for the empty set (where "cleared
// nothing" and "nothing to clear" are genuinely the same state).
//
// It exists so the several no-op implementations report identically. Each of them means the
// same thing — the policy's sanitizing step will not take effect on this path — and a silent
// empty result would make that indistinguishable from an approved clear whose labels the
// anchor was not carrying, which is a routine, healthy outcome.
func noFlowStateErr(labels []string, who string) error {
	if len(labels) == 0 {
		return nil
	}
	return fmt.Errorf("%s holds no flow-label state, so the approved declassification of %v cannot be applied (wiring fault, not a store failure)", who, labels)
}

// HardenRefusal returns the refusal unchanged: the "no policy" default declares no pin, no
// ceiling and no redaction, so it has nothing to compose onto another layer's verdict.
func (DenyAllPDP) HardenRefusal(_ context.Context, _ string, r capability.EnforceResponse, _ EnforceTarget, _ map[string]interface{}) capability.EnforceResponse {
	return r
}

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

	// sequenceAntecedents is the set of bare tool names some sequenceBlock condition
	// names in its afterTools, built once at construction and never mutated. It bounds
	// which MANIFEST-ABSENT targets are worth recording an audit-mode antecedent for:
	// only a name a later sequenceBlock can actually query needs history. See
	// decideTarget's no-match branch.
	sequenceAntecedents map[string]struct{}
	// surface holds the Tier-2 interface pin: the advertised-surface hash every session
	// first saw for each tool, and the sticky set of tools whose surface later changed
	// (see surface_pin.go). Unlike pinnedTools it is not derived from the manifest — it
	// pins what the UPSTREAM advertises, so it covers tools no operator pinned — and
	// unlike observedToolHash/poisonedTools it is keyed per session, so a legitimate
	// upstream upgrade re-baselines on the next session instead of denying for the life
	// of the process. Always non-nil for a PDP built by NewManifestPDP; a nil value is a
	// working "pinning off" state for a directly-constructed one.
	surface *SurfaceBaseline

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
	return &ManifestPDP{caps: caps, parsedTargets: parsed, engine: engine, ks: ks, observedToolHash: make(map[string]string), pinnedTools: pinned, surface: NewSurfaceBaseline(), sequenceAntecedents: collectSequenceAntecedents(caps), anyLabelOutput: anyLabelOutput}
}

// collectSequenceAntecedents gathers every bare tool name any sequenceBlock condition
// lists in afterTools, normalized the way handleSequenceBlock normalizes them so the two
// agree on what counts as the same name. Built once, read-only thereafter.
func collectSequenceAntecedents(caps []capability.Constraint) map[string]struct{} {
	var names map[string]struct{}
	for i := range caps {
		for _, cond := range caps[i].Conditions {
			sb, ok := cond.(capability.SequenceBlockCondition)
			if !ok {
				p, isPtr := cond.(*capability.SequenceBlockCondition)
				if !isPtr || p == nil {
					continue
				}
				sb = *p
			}
			for _, prior := range sb.AfterTools {
				bare := strings.TrimSpace(enforcement.StripEnginePrefix(prior))
				if bare == "" {
					continue
				}
				if names == nil {
					names = make(map[string]struct{})
				}
				names[bare] = struct{}{}
			}
		}
	}
	return names
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

// recordObservedHash stores the hash of a tool's live model-facing surface (description +
// title + annotations + input/output parameter descriptions) seen in a tools/list
// response, so decideTarget can enforce a pinned descriptionHash on the call leg against
// the same surface the host was shown. Callers must gate this on a pinned exact-tool
// constraint match (see filterToolsListResult) and pass that constraint's pinned hash as
// pin.
//
// It takes an already-computed hash rather than the entry's fields because the SAME hash
// arms Tier-2's baseline in the same walk (armPinsFromToolsList), and computing it at both
// places hashed every pinned tool's whole inputSchema twice per tools/list. Both pins
// compare the same bytes by construction — SurfaceHash is the one spelling — so there was
// never a reason for two computations, only a seam that made it easy.
//
// Recording the observed hash and marking a mismatch as poisoned happen under a SINGLE
// lock, so the two updates are atomic: a concurrent call-leg reader (pinViolated, also
// single-locked) can never observe the hash updated but the poison mark not yet set, which
// would let an interleaving honest-session overwrite re-open the pin. pin is the
// constraint's DescriptionHash ("" only for a non-pinned caller, in which case no poison
// is possible).
func (p *ManifestPDP) recordObservedHash(name, h, pin string) {
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

// markToolPoisoned sets the sticky poison mark for a pinned tool name so its call leg
// (pinViolated) denies until the process restarts. Used when a tools/list response cannot
// be reduced to a trustworthy hash for a pinned tool — an entry that fails to decode into
// the hashed surface, or one carrying duplicate top-level keys a host may render
// differently than the proxy hashed. Idempotent and safe under concurrent tools/list
// responses; mirrors the atomic poison-set inside recordObservedHash.
func (p *ManifestPDP) markToolPoisoned(name string) {
	p.descMu.Lock()
	if p.poisonedTools == nil {
		p.poisonedTools = make(map[string]struct{})
	}
	p.poisonedTools[name] = struct{}{}
	p.descMu.Unlock()
}

// poisonAllPinned sticky-poisons every pinned tool name. Reserved for an ambiguity that
// taints the WHOLE response — an undecodable envelope or tools array, or a duplicate or
// case-variant "tools" key that leaves the proxy and a host reading different arrays — so
// no entry within it can be believed. The pin is a security control, not best-effort
// bookkeeping, and a response the proxy cannot verify any pin against must not leave the
// mid-session poisoning pin unarmed. A no-op when nothing is pinned.
//
// An ambiguity confined to ONE entry must NOT come here: poisonCandidates scopes the
// poison to the pinned names that entry could present, so an unrelated malformed entry
// cannot disable pins it never named. The mark is sticky to process exit and the PDP is
// shared across every session on the route, so the blast radius is permanent — keep it as
// narrow as the evidence.
func (p *ManifestPDP) poisonAllPinned() {
	if !p.hasPinnedTools() {
		return
	}
	p.descMu.Lock()
	if p.poisonedTools == nil {
		p.poisonedTools = make(map[string]struct{})
	}
	for name := range p.pinnedTools {
		p.poisonedTools[name] = struct{}{}
	}
	p.descMu.Unlock()
}

// pinViolated reports whether a pinned tool's call leg must be denied: it was ever
// observed poisoned (sticky), OR its most recently observed hash differs from the
// pin. BOTH are read under a single RLock so the call leg cannot observe a torn
// state (poison not yet set AND a just-overwritten clean hash) that would let a
// poisoned call through. With recordObservedHash marking poison atomically on a
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
	return killCheck(ctx, p.engineClock(), p.ks, sessionID)
}

// CheckAudience pins no token audience: the manifest layer enforces capabilities, not
// the JWT aud claim. Per-route token-audience pinning lives in the JWTPDP wrapper.
func (*ManifestPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}

// ReleaseSession releases the session's Tier-2 interface baseline and its accumulated
// flow-label state on teardown, via the engine (which namespaces the store keys by route). A
// no-op when the policy uses no flow control or no store is wired (see
// Engine.ClearSessionLabels). Best-effort: a store fault on teardown is swallowed rather
// than surfaced — the session is already gone, and a Redis-backed store reclaims an orphaned
// key by idle TTL regardless.
//
// The label release is SESSION-anchored. Under task anchoring the same taint may have been
// written under the task's key instead, and that is deliberately not reclaimed here: it is
// the state whose whole purpose is to outlive this session, and clearing it on disconnect
// would let an agent launder a task's taint by reconnecting.
//
// A spent single-use declassify grant is NOT released here, and not because of the anchor: the
// ledger is unanchored by construction (it lives in the call counter under the grant's own id),
// so a burn belongs to the APPROVAL rather than to any session or task. Releasing it on
// teardown would have made "once" mean once per connection, which is the property the ledger
// was moved out of the label store to stop meaning.
func (p *ManifestPDP) ReleaseSession(ctx context.Context, sessionID string) {
	// Drop the Tier-2 interface baseline first, and unconditionally: it is local state
	// that must be reclaimed even for a PDP built without an engine, and leaving it
	// behind would both leak memory on a long-lived gateway and carry a broken pin into a
	// reused session id.
	p.surface.Release(sessionID)
	if p.engine == nil {
		return
	}
	_ = p.engine.ClearSessionLabels(ctx, sessionID)
}

// CommitDeclassified applies the clear an approved declassification authorized, for a call
// the transport has now performed. See the interface for why the commit has to be reachable
// from there at all.
//
// The claims come from the context so the request resolves to the SAME anchor the decision
// was accounted against: under task anchoring the call's state lives on the task's key, and
// clearing the session's would leave the task tainted while dropping a label the session
// never asked to drop. Every other field of the request is irrelevant here —
// CommitDeclassification is a keyed read-then-Remove and evaluates no policy — so this
// deliberately does not rebuild the decision's target or arguments.
func (p *ManifestPDP) CommitDeclassified(ctx context.Context, sessionID string, labels []string) ([]string, error) {
	// p == nil covers a typed-nil (*ManifestPDP)(nil) reaching the transport's committer
	// interface, where the caller's `!= nil` check passes and the dereference below would
	// panic a request goroutine after the upstream call has already run.
	if p == nil || p.engine == nil {
		// A PDP with no engine holds no flow store, so the clear cannot happen. Reported as a
		// fault, not as an empty result: see noFlowStateErr.
		return nil, noFlowStateErr(labels, "manifest decision point with no engine")
	}
	// The claims come from the context so the request resolves to the SAME anchor the
	// decision used; see the interface's context contract.
	return p.engine.CommitDeclassification(ctx, &capability.EnforceRequest{
		SessionID: sessionID,
		Claims:    jwtClaimsAsMap(ctx),
	}, labels)
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
	if deny := killCheck(ctx, p.engineClock(), p.ks, sessionID); deny != nil {
		return *deny
	}

	// descriptionHash pin (tools/call leg). A constraint may pin a tool's
	// description hash to defend against an upstream that rewrites the description to
	// inject a prompt (tool poisoning, FM-5). filterToolsListResult hides a
	// description-changed tool from tools/list, but a host calling by name (a cached
	// tool) would otherwise bypass the pin on the call leg. Enforce it here against the
	// most recently observed description. It denies only when the description HAS been
	// re-observed and no longer matches — the mid-session change the session-start drift
	// probe cannot catch. An as-yet-unobserved description is not denied (the probe
	// already verified every pin at establishment). Returns hardDenyResponse: a
	// tool-poisoning deny is not downgradable even under audit (see that helper for how
	// HardDeny survives stamp() and isObserveDeny).
	//
	// This runs BEFORE findConstraint and the no-match return below, keyed off
	// pinnedTools (every pinned entry for this name), never off the SELECTED constraint:
	// the pin must fire on an observed mismatch regardless of whether — or which —
	// constraint findConstraint selects. Running it AFTER the no-match return would let
	// a pinned name with no constraint selected for this caller (e.g. a principal-scoped
	// pinned entry whose claims do not satisfy it → findConstraint returns nil) fall
	// through to a plain, downgradable AUTHORIZATION_FAILED that an audit route forwards
	// to the poisoned upstream; running it after the action check would let an
	// audit-mode constraint downgrade the same call. Firing here off the name keeps a
	// genuine poisoning a hard AUTHORIZATION_FAILED; a matching or as-yet-unobserved
	// description does not deny here and still reaches the accurate no-match/action
	// checks below.
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

	// Tier-2 interface pin (tools/call leg). The FM-5 block above covers tools an
	// operator pinned to a specific hash; this covers EVERY tool, against the surface the
	// session first saw. It runs in the same position and for the same reason: keyed off
	// the tool NAME rather than a selected constraint, before findConstraint, so a
	// mid-session surface rewrite is a hard AUTHORIZATION_FAILED that an audit route
	// cannot downgrade and forward to the rewritten upstream. Only tools/call carries an
	// advertised surface to pin, so the schema==validateSchema gate scopes it exactly as
	// the FM-5 block is scoped.
	if schema == validateSchema && p.surface.Broken(sessionID, target.Name) {
		return hardDenyResponse(p.engineClock(), capability.ErrCodeAuthorizationFailed,
			fmt.Sprintf("tool %q advertised a different interface surface than when this session started (description, title, annotations, or a parameter description changed); refusing to forward (fail closed) — start a new session to re-baseline after a deliberate upstream change", target.Name))
	}

	// Find the most specific matching constraint, scoped to the target type and the
	// caller's principal. The manifest is an allowlist: only listed targets pass.
	claims := jwtClaimsAsMap(ctx)

	// Build the enforce request before the no-match return, not after it: EVERY
	// downgradable deny below — the no-match one included — needs it to record the
	// antecedent in session history. TargetName/Target carry target.Name (for
	// input.target.* and the audit record); Claims back input.claims.agent_id/task_id/etc.
	req := &capability.EnforceRequest{
		SessionID:  sessionID,
		TargetName: target.Name,
		Arguments:  args,
		Context:    capability.EnforceRequestContext{SourceIP: sourceIP},
		Target: &capability.EnforceRequestTarget{
			Type: string(target.Type),
			Name: target.Name,
		},
		Claims: claims,
		// A cooperating client's per-call flow attribution, if it sent one. Union-only at
		// the sink (see capability/attribution.go), so an untrusted client's declaration
		// can only produce more denials — which is what makes honoring it need no trust
		// decision.
		DeclaredLabels: declaredLabelsFromContext(ctx),
		// The human approvals the verified token granted. Nil for every request that is
		// not a declassification, which is nearly all of them; without one, a declassify
		// directive escalates rather than clearing a label.
		DeclassifyApprovals: declassifyApprovalsFromContext(ctx),
		// The attenuation the token's delegation chain declared, already asserted to narrow
		// at every hop. Nil for every non-delegated request; when present it can only ever
		// subtract from what the manifest already allowed.
		Delegation: delegationFromContext(ctx),
	}

	matched := p.findConstraint(target, claims)
	if matched == nil {
		// A no-match deny is downgradable, so a route running --audit FORWARDS it and the
		// upstream response reaches the host — carrying whatever the manifest declared
		// redactable for this target. No constraint was selected, so the obligations come
		// from every entry NAMING this target (see withForwardObligations); dropping them
		// here would leak on exactly the principal-scoped-miss shape the descriptionHash pin
		// above is positioned to catch.
		resp := p.withForwardObligations(ctx, denyResponse(p.engineClock(), capability.ErrCodeAuthorizationFailed, "",
			fmt.Sprintf("%s %q is not listed in the capability manifest", target.Type, target.Name)), target)
		// Record the antecedent here too, matching every other downgradable deny branch.
		// Under --audit this deny is forwarded and the manifest-absent tool actually RUNS,
		// so omitting the record left a later enforced sequenceBlock naming it Peeking an
		// empty history and failing OPEN — "observe predicts enforce" broken for exactly
		// the targets an observe run exists to discover. matched is nil, which the
		// antecedent path handles: no constraint means no flow relevance, so only the
		// sequenceBlock antecedent is committed.
		//
		// Gated on the name being one some sequenceBlock actually lists in afterTools.
		// This branch is the ONLY antecedent site whose target name is not bounded by the
		// manifest, and the record costs a call-counter key that lives for the history
		// window: recording every unlisted name let a caller on an observe route mint one
		// key per made-up tool name until the counter hit its cap, at which point the
		// record FAILS and recordAuditModeAntecedent returns a hard deny — non-downgradable
		// even under --audit. An observe route whose whole contract is "log, never block"
		// would then start hard-denying every call, listed tools included. A name no
		// sequenceBlock can query has no history worth keeping, so skipping it costs the
		// guarantee nothing and bounds the key space to manifest-authored names.
		if _, queryable := p.sequenceAntecedents[target.Name]; queryable {
			if override := recordAuditModeAntecedent(ctx, p.engine, p.engineClock(), req, nil, &resp); override != nil {
				return *override
			}
		}
		return resp
	}
	// Union labelOutput across every entry matching this request, so a source read carries
	// its taint even when the entry findConstraint scored highest (a more-specific or
	// principal-scoped sibling) lacks labelOutput while another matching entry has it —
	// otherwise the taint is silently dropped and a later sink fails open. A no-op for a
	// policy with no sources, and for the common single-source case. Only the recorded
	// labelOutput changes; conditions, actions, and argumentSchema all read matched's own
	// (unchanged) properties, and obligations skip labelOutput.
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

	// A constraint in audit (observe) mode downgrades its own denial to a
	// logged-but-forwarded allow. stamp applies that downgrade only to the verdicts
	// returned BELOW this point: the kill-switch, no-match, stray-schema, and
	// descriptionHash returns above never pass through it and stay hard-deny.
	// Stamping explicitly at each return site (rather than via a deferred mutation
	// of a named return) keeps which verdicts are downgradable visible in the
	// control flow, so a future early return added below cannot silently inherit it.
	stamp := func(r capability.EnforceResponse) capability.EnforceResponse {
		// Never stamp/forward a hard deny: it blocks even on an audit-only constraint or a
		// route running under --audit (e.g. antecedent record failure), so it reaches no
		// host and needs no forwarded-response obligations.
		if r.Denial != nil && r.Denial.HardDeny {
			return r
		}
		// The per-entry flag records only the per-CONSTRAINT audit posture. The whole-route
		// --audit posture is not stamped here: the transport reads that from its own flag.
		if matched.IsAuditOnly() {
			r.AuditOnly = true
		}
		// A downgraded (observe-mode) deny is still forwarded to the host, so it must carry
		// the same redactFields obligations a genuine allow of this constraint would — the
		// transport applies redaction only from resp.Obligations, so leaving them empty
		// forwards the upstream response unredacted, silently dropping the redaction the
		// manifest declared (a condition, argumentSchema, or action-check failure all reach
		// here without having run collectObligations). The genuine-allow path collects them
		// in evaluateMatched; mirror it for the downgraded deny.
		return p.withForwardObligationsFor(ctx, r, matched)
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

// recordAuditModeAntecedent records session state when an audit-mode constraint OR a
// route running under --audit (WithSkipQuota) DOWNGRADES a deny to a forwarded call.
// The two are gated together because the transport downgrades on the SAME union
// (isObserveDeny fires on fp.audit OR dec.AuditOnly); gating only on the per-constraint
// flag would miss the standard whole-route observe deployment, where constraints are
// NOT individually marked auditOnly. On that path EvaluateConditions returns the
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
	// Gate on the per-constraint enforcement:audit flag OR the whole-route --audit
	// posture (SkipQuota), matching the transport's own downgrade union (isObserveDeny:
	// fp.audit || dec.AuditOnly). Without the SkipQuota leg a route-level --audit deny is
	// forwarded but its antecedent is never recorded, so a later enforced sequenceBlock
	// naming this tool Peeks empty history and fails OPEN.
	if willForwardDeny(ctx, matched) && resp.Decision != capability.DecisionAllow && (resp.Denial == nil || !resp.Denial.HardDeny) {
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
	for i := range p.caps {
		pt := p.parsedTargetAt(i)
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
		fallback.Offer(i, s, hasPrincipal)
		if containsAction(c.Actions, required) {
			primary.Offer(i, s, hasPrincipal)
		}
	}
	if primary.Best() >= 0 {
		return &p.caps[primary.Best()]
	}
	if fallback.Best() >= 0 {
		return &p.caps[fallback.Best()]
	}
	return nil
}

// parsedTargetAt returns caps[i]'s target parsed into (type, bare).
//
// parsedTargets is built parallel to caps by NewManifestPDP, so the hot path reads the
// once-parsed pair instead of re-scanning the static Target string. A ManifestPDP built
// directly (a struct literal, as some tests do) leaves it unpopulated; this falls back to
// an inline ParseTarget then, mirroring how handleIPRange parses when Networks() reports
// the condition was not pre-compiled.
//
// The three scans over caps (findConstraint, directivesNamingTarget,
// matchingLabelOutputUnion) each opened with a byte-identical copy of this cache-or-parse
// preamble. One copy means a change to how a target is parsed -- or to how the
// unpopulated-cache fallback behaves -- cannot land on two of the three scans and leave
// the third selecting against a differently-parsed target.
func (p *ManifestPDP) parsedTargetAt(i int) parsedTarget {
	if len(p.parsedTargets) == len(p.caps) {
		return p.parsedTargets[i]
	}
	tt, bare, err := capability.ParseTarget(p.caps[i].Target)
	return parsedTarget{typ: tt, bare: bare, parseErr: err != nil}
}

// newConstraintScorer returns the shared constraint-selection tiebreak tracker
// (enforcement.ConstraintScorer): higher target specificity wins, and at equal
// specificity a principal-scoped entry beats a general one regardless of manifest
// order. findConstraint uses one for its primary scan and one for its fallback.
//
// It delegates rather than reimplementing: this predicate used to be a
// character-for-character copy of the engine's, so a precedence change made in one
// place would have left the proxy and the engine selecting different constraints for
// the same request — a silent policy divergence, not a cosmetic duplication. The
// scores fed in here are unscaled while the engine scales by its resourceScoreWeight;
// that is a monotonic transform, so every comparison the scorer makes is unaffected.
func newConstraintScorer() enforcement.ConstraintScorer {
	return enforcement.NewConstraintScorer()
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
	// A DECLASSIFYING constraint is never augmented. validateDeclassifyCoherence refuses
	// labelOutput and declassify on one constraint at load precisely because the two write
	// the same session state in opposite directions on one call; synthesizing a labelOutput
	// here would rebuild that shape at runtime out of two individually-coherent entries —
	// a `tool:*` source and a specific sanitizer — and the outcome would then be decided by
	// session history rather than by policy. The union exists so a sibling cannot SHADOW a
	// source's taint; a declassify entry is not a source that forgot its label, it is the
	// one action whose whole purpose is to remove one.
	if len(capability.DeclassifyLabelsOf(matched)) > 0 {
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

// willForwardDeny reports whether a deny for this constraint will be downgraded to a
// forwarded call, so the response still reaches the host. It is the PDP-side spelling of
// the transport's isObserveDeny — per-constraint `enforcement: audit` OR the whole-route
// --audit posture (which arrives as SkipQuota on the ctx) — and every concern that must
// track "this deny is really a forward" reads it from here rather than restating the
// union. matched may be nil (a no-match deny), which only a route-level --audit forwards.
// The kill-switch and HardDeny exclusions the transport also applies are handled at each
// call site, which has the response in hand.
func willForwardDeny(ctx context.Context, matched *capability.Constraint) bool {
	return enforcement.WillForwardDeny(ctx, matched)
}

// withForwardObligationsFor fills r with matched's post-allow obligations when r is a deny
// that will be forwarded (see willForwardDeny), so the transport redacts the forwarded
// response exactly as it would a genuine allow.
//
// The decision test is `!= DecisionAllow`, not `== DecisionDeny`, matching the transport's
// own fail-closed gate: a zero-value or unset Decision is forwarded there, so gating on
// `== DecisionDeny` here would let it through unredacted. Fills only when the response
// carries none yet — a flow/record-fault deny already carries them. CollectObligations
// returns a HardDeny for an unwired directive type; honor it (fail closed) rather than
// forwarding unredacted.
func (p *ManifestPDP) withForwardObligationsFor(ctx context.Context, r capability.EnforceResponse, matched *capability.Constraint) capability.EnforceResponse {
	if r.Decision == capability.DecisionAllow || len(r.Obligations) > 0 {
		return r
	}
	if !willForwardDeny(ctx, matched) || matched == nil {
		return r
	}
	obs, deny := p.engine.CollectObligations(delegationFromContext(ctx), matched, r.RequestID, r.DecidedAt)
	if deny != nil {
		return *deny
	}
	r.Obligations = obs
	return r
}

// withForwardObligations is the no-match counterpart of withForwardObligationsFor: no
// constraint was selected, so the obligations come from every capability NAMING this
// target, regardless of principal scoping. That is deliberately wider than findConstraint:
// the response is about to be forwarded, and any entry declaring a field of this target
// redactable is reason enough to mask it. A no-match deny is only ever forwarded by a
// route-level --audit, so this is a no-op on an enforce route.
func (p *ManifestPDP) withForwardObligations(ctx context.Context, r capability.EnforceResponse, target EnforceTarget) capability.EnforceResponse {
	if r.Decision == capability.DecisionAllow || len(r.Obligations) > 0 || !enforcement.SkipQuota(ctx) {
		return r
	}
	dirs := p.directivesNamingTarget(target)
	chain := delegationFromContext(ctx)
	// No early return on `len(dirs) == 0`: a delegated caller whose hops compose a
	// redactFields list must have it applied even when no manifest entry names this target,
	// and CollectObligations already answers "is there anything to apply" — restating that
	// question here meant asking the chain twice and gave a second place for the two to
	// disagree about when the response is forwarded unmasked.
	obs, deny := p.engine.CollectObligations(chain, &capability.Constraint{Target: string(target.Type) + ":" + target.Name, Directives: dirs}, r.RequestID, r.DecidedAt)
	if deny != nil {
		return *deny
	}
	if len(obs) == 0 {
		return r
	}
	r.Obligations = obs
	return r
}

// hardenOnBrokenInterface re-stamps a refusal that some OTHER layer produced as a hard,
// non-downgradable one when this PDP holds a broken interface pin for the target. broke
// reports whether it fired, so the caller can stop treating the response as forwardable.
//
// It exists for the wrapper case. Both interface pins — the operator's FM-5
// descriptionHash and the automatic Tier-2 surface baseline — are enforced inside
// ManifestPDP.Decide, keyed off the tool NAME and placed before findConstraint precisely
// so that no later, softer verdict can preempt them. A JWTPDP wrapping this PDP breaks
// that placement from the outside: it short-circuits above the inner on its own denies
// (a target absent from mcp.capabilities, a failing JWT condition), so Decide never runs
// and the pin never fires. The composed refusal is then a SOFT deny — and a route running
// --audit downgrades a soft deny to a forwarded call, sending the request to the very
// upstream whose interface was rewritten. Turning the JWT on removed a guarantee, which
// inverts the "JWT can only restrict, never expand" invariant.
//
// Both pin reads are pure lookups against state armed by an earlier tools/list, so this
// commits nothing: it cannot leave a sequenceBlock antecedent, a flow label, or a consumed
// maxCalls slot behind for a call that is never forwarded. That is what makes it safe to
// run on a path the inner PDP deliberately never reached. The effect ceiling has the same
// problem and needed a narrower answer, since reaching it normally means running conditions
// that DO commit; hardenOnEffectCeiling covers it through the engine's non-committing
// CeilingVerdictFor, and runs only when this one did not fire.
//
// Only tools/call carries an advertised surface to pin, matching the schema gate the two
// blocks inside Decide use.
func (p *ManifestPDP) hardenOnBrokenInterface(sessionID string, r capability.EnforceResponse, target EnforceTarget) (capability.EnforceResponse, bool) {
	if r.Decision == capability.DecisionAllow || r.Denial == nil || r.Denial.HardDeny {
		return r, false
	}
	if target.Type != capability.TargetTypeTool {
		return r, false
	}
	pin, isPinned := p.pinnedTools[target.Name]
	fm5Broken := isPinned && p.pinViolated(target.Name, pin)
	if !fm5Broken && !p.surface.Broken(sessionID, target.Name) {
		return r, false
	}
	// The other layer's code and message are preserved — its verdict is why the call was
	// refused, and rewriting it would hide the authorization failure the caller must fix.
	// Only the forwardability changes, which is the one property the pin governs.
	denial := *r.Denial
	denial.HardDeny = true
	// The two pins fail for different reasons and have different remedies, so the message
	// must say which one fired. The FM-5 pin compares the live surface against the
	// MANIFEST's descriptionHash (remedy: re-review the tool and re-pin); Tier-2 compares
	// it against what THIS SESSION saw at its start (remedy: a new session re-baselines).
	// One combined sentence sent an operator hitting a manifest-pin break to restart a
	// session, which changes nothing.
	reason := "advertised a different interface surface than when this session started (interface pin), so a new session is needed to re-baseline it"
	if fm5Broken {
		reason = "no longer matches the descriptionHash this manifest pins for it, so the pinned surface must be re-reviewed and re-pinned"
	}
	denial.Message = denial.Message + " (additionally: tool " + strconv.Quote(target.Name) +
		" " + reason + "; this call is refused outright and cannot be forwarded by an audit-mode route)"
	r.Denial = &denial
	// Obligations describe how to redact a FORWARDED response. This one is not forwarded.
	r.Obligations = nil
	return r, true
}

// hardenRequest builds the EnforceRequest a *VerdictFor seam is asked about. Both hardening
// paths need the identical shape, and they had two copies of it — ten lines each, differing
// only in one field — which is the same duplication the seams themselves exist to remove,
// one level up. canonicalApprovalTarget resolves off req.Target per FIELD, so the literal is
// load-bearing: a divergence here reproduces exactly the padded-target bug the centralized
// resolver was introduced to prevent.
//
// jwtConditionArgs synthesizes the {"uri"}/{"name"} map DecideResourceRead and DecidePromptGet
// build, so a contract naming one of those resolves to the same value here that the full path
// would have resolved.
//
// Delegation is deliberately absent, for both callers. A *VerdictFor seam may only HARDEN a
// refusal, and a delegation refusal is downgradable by design — the full path forwards it
// under --audit too, so there is no inversion here for a composed delegation verdict to
// close, and producing a soft verdict through a harden-only seam would break that seam's
// contract to fix nothing.
func hardenRequest(ctx context.Context, sessionID string, target EnforceTarget, args, claims map[string]interface{}) *capability.EnforceRequest {
	return &capability.EnforceRequest{
		SessionID:  sessionID,
		TargetName: target.Name,
		Arguments:  jwtConditionArgs(target, args),
		Target: &capability.EnforceRequestTarget{
			Type: string(target.Type),
			Name: target.Name,
		},
		Claims:         claims,
		DeclaredLabels: declaredLabelsFromContext(ctx),
	}
}

// composeHardened folds a *VerdictFor seam's verdict onto the refusal it is hardening: the
// verdict becomes the PRIMARY response (its code and structured details are the whole point),
// with the wrapping layer's own reason appended so an operator fixing the token still sees why
// authorization failed.
//
// The AuditOnly AND is the load-bearing part and belongs here rather than at each caller: the
// composed refusal must never be SOFTER than the one it replaces. The ceiling's onExceed:deny
// arm is built with the matched constraint's own audit posture, so a constraint marked
// `enforcement: audit` hands back AuditOnly=true — which the transport's isObserveDeny reads as
// "downgrade and forward". Inheriting it turned a JWT refusal that BLOCKED on an enforce route
// into a forwarded, executed call. Taking the AND keeps the composed posture at least as hard
// as both inputs, for every seam that routes through here.
//
// The Denial is copied before its Message is rewritten, so the caller never mutates a value the
// engine still owns.
func composeHardened(r, verdict capability.EnforceResponse) capability.EnforceResponse {
	out := verdict
	if out.Denial != nil && r.Denial != nil && r.Denial.Message != "" {
		denial := *out.Denial
		denial.Message = denial.Message +
			" (this call was also refused by the wrapping authorization layer: " + r.Denial.Message + ")"
		out.Denial = &denial
	}
	out.AuditOnly = out.AuditOnly && r.AuditOnly
	return out
}

// hardenOnEffectCeiling re-stamps a refusal that some OTHER layer produced as the effect
// ceiling's own refusal when the manifest's ceiling would have refused this action too.
// over reports whether it fired.
//
// It is the ceiling's half of the wrapper problem hardenOnBrokenInterface solves for the
// interface pins. A JWTPDP wrapping this PDP short-circuits above it on its own denials —
// a target absent from mcp.capabilities, a failing JWT condition — so evaluateMatched
// never runs and the ceiling never evaluates. The call is still refused, so this is not a
// fail-open in the usual sense; what is lost is the KIND of refusal:
//
//   - The ESCALATION never happens. The ceiling's ESCALATION_REQUIRED is a hard,
//     non-downgradable refusal carrying the consequence inputs a human acts on
//     (ceiling_exceeded, effect_class, carried_labels). A plain AUTHORIZATION_FAILED
//     carries none of them, so an action that should have entered the approval queue
//     silently does not and `eunox stats` under-counts escalations.
//   - The refusal is DOWNGRADABLE. A route running --audit forwards a soft deny, so a
//     JWT-wrapped route forwards a call the same manifest without the JWT refuses
//     outright. Adding a JWT weakened enforcement, which inverts "a JWT may only restrict".
//
// Unlike the pin reads — pure lookups against state an earlier tools/list armed — the
// ceiling sits behind the matched constraint's conditions, and some of those COMMIT
// (maxCalls consumes a window slot, labelOutput writes a flow label, sequenceBlock writes
// an antecedent). Running them for a call that is already refused and will never be
// forwarded would leave exactly the phantom state the engine's ordering exists to prevent.
// So this goes through the engine's narrow, non-committing CeilingVerdictFor, which
// evaluates the ceiling and NOTHING else; see that method for what the narrowing does and
// does not reproduce.
//
// The gates below are the STRUCTURAL ones the real path applies before a ceiling could
// ever be reached — no ceiling configured, no constraint selected for this caller, or a
// constraint that does not permit this action — each of which means the manifest refuses
// on its own terms and the ceiling never runs. They are all pure predicates, so applying
// them here costs nothing and keeps the composed verdict faithful where it can be cheaply.
//
// The ceiling verdict becomes the PRIMARY response: its code and structured details are
// the whole point (an AUTHORIZATION_FAILED with the pin's message appended would leave
// stats under-counting escalations exactly as before). The wrapping layer's own reason is
// appended to the message so an operator fixing the token still sees why authorization
// failed.
func (p *ManifestPDP) hardenOnEffectCeiling(ctx context.Context, sessionID string, r capability.EnforceResponse, target EnforceTarget, args map[string]interface{}) (capability.EnforceResponse, bool) {
	if r.Decision == capability.DecisionAllow || r.Denial == nil || r.Denial.HardDeny {
		return r, false
	}
	claims := jwtClaimsAsMap(ctx)
	matched := p.findConstraint(target, claims)
	if matched == nil || !containsAction(matched.Actions, requiredActionFor(target.Type)) {
		return r, false
	}
	verdict := p.engine.CeilingVerdictFor(ctx, hardenRequest(ctx, sessionID, target, args, claims), matched)
	if verdict == nil {
		return r, false
	}
	out := composeHardened(r, *verdict)
	if out.Denial != nil && out.Denial.HardDeny {
		// Never forwarded (the escalate arm), so there is no response to redact and
		// obligations would be a claim that a redaction ran.
		out.Obligations = nil
		return out, true
	}
	// Still downgradable (onExceed: deny), so a route running --audit WILL forward it — and
	// a forwarded response must carry the manifest's redactFields obligations or it reaches
	// the host unmasked. Stripping them here re-opened the exact fail-open this whole seam
	// exists to close: adding an effect ceiling silently removed redaction that the same
	// request got without one.
	return p.withForwardObligationsFor(ctx, out, matched), true
}

// HardenRefusal composes this PDP's own verdicts onto a refusal another layer produced.
// See the PolicyDecisionPoint contract for why it is on the interface.
//
// The ORDER is decideTarget's own, restated where it belongs. There the two interface-pin
// checks sit above findConstraint precisely so no later, softer verdict can preempt them,
// and the effect ceiling is the LAST thing evaluateMatched reaches — so a tool whose
// interface was rewritten mid-session is refused for that reason rather than re-labelled as
// an approval request. The obligations fill is what remains for a refusal that is still
// forwardable.
//
// Nothing here commits: both pin reads are pure lookups against state an earlier tools/list
// armed, and the ceiling goes through the engine's non-committing CeilingVerdictFor.
func (p *ManifestPDP) HardenRefusal(ctx context.Context, sessionID string, r capability.EnforceResponse, target EnforceTarget, args map[string]interface{}) capability.EnforceResponse {
	if r.Decision == capability.DecisionAllow {
		return r
	}
	if r.Denial != nil && r.Denial.HardDeny {
		// Already non-downgradable and carrying no forwarded response to redact; there is
		// nothing this PDP could add that would make it harder.
		return r
	}
	if hardened, broke := p.hardenOnBrokenInterface(sessionID, r, target); broke {
		return hardened
	}
	if hardened, over := p.hardenOnEffectCeiling(ctx, sessionID, r, target, args); over {
		return hardened
	}
	if hardened, unapproved := p.hardenOnUnapprovedDeclassify(ctx, sessionID, r, target, args); unapproved {
		return hardened
	}
	return p.withForwardObligations(ctx, r, target)
}

// hardenOnUnapprovedDeclassify replaces an outer layer's downgradable refusal with the
// declassify escalation when the matched constraint clears a flow label and the request
// carries no approval covering it.
//
// It exists for the same COMPOSED case hardenOnEffectCeiling does, and the failure it
// closes is sharper. A wrapping PDP (the JWT layer) can refuse a call on its own terms and
// short-circuit above the inner PDP, so evaluateMatched never runs and checkDeclassify
// never fires. That refusal is a SOFT deny, which a route running --audit downgrades to a
// forward — so adding a JWT would forward a declassification the same manifest hard-refuses
// without one, inverting the rule that a token may only ever restrict. The forward is the
// worst of the two outcomes here: it performs the action AND leaves the taint the policy
// said the action clears.
//
// Like the ceiling's, it COMMITS nothing — but unlike the ceiling's it is not a pure
// comparison either: answering "would this have been authorized" requires knowing whether a
// single-use grant is still live, which is a ledger read. The read records nothing, so a
// call refused here still leaves no spent approval behind; what it costs is one Peek per
// covering grant on a path that only runs for an already-refused call.
// It runs AFTER the ceiling so a call that is over the consequence bound reports that, the
// same precedence the full path applies.
//
// It answers the question through the engine's non-committing DeclassifyVerdictFor rather
// than deriving one here, exactly as the ceiling's sibling delegates to CeilingVerdictFor,
// and the reason is that a hand-rolled answer HAD diverged twice. It resolved the approval
// target itself (`string(target.Type) + ":" + target.Name`), which does not trim a padded
// name — one of the three divergences canonicalApprovalTarget's doc records as already
// paid for, each of which turned a correctly-scoped grant into a permanent, unsatisfiable
// escalation. And it built its own DenialInfo without CarriedLabels, so the same logical
// refusal had two record shapes depending on whether a JWT layer wrapped the call, with the
// JWT-wrapped one missing the field an approver needs first ("what is this session already
// carrying"). One resolver, one refusal builder, one record shape.
func (p *ManifestPDP) hardenOnUnapprovedDeclassify(ctx context.Context, sessionID string, r capability.EnforceResponse, target EnforceTarget, args map[string]interface{}) (capability.EnforceResponse, bool) {
	if r.Decision == capability.DecisionAllow || r.Denial == nil || r.Denial.HardDeny {
		return r, false
	}
	// No engine means no checkDeclassify on the unwrapped path either, so there is no verdict
	// this could be weaker than — and nothing to read the ledger with.
	if p.engine == nil {
		return r, false
	}
	claims := jwtClaimsAsMap(ctx)
	matched := p.findConstraint(target, claims)
	if matched == nil || !containsAction(matched.Actions, requiredActionFor(target.Type)) {
		return r, false
	}
	// The cheap structural test BEFORE the request is built. DeclassifyVerdictFor's first
	// real gate is this same question, and it is false for every deployment that declares no
	// declassify directive — i.e. essentially all of them — so asking it here keeps the
	// throwaway argument map and two context walks off the denial path of every route that
	// has nothing to declassify.
	if len(capability.DeclassifyLabelsOf(matched)) == 0 {
		return r, false
	}
	// The shared request shape, plus the approvals — the verdict turns on them, and the
	// engine reads them off the request rather than the context.
	req := hardenRequest(ctx, sessionID, target, args, claims)
	req.DeclassifyApprovals = declassifyApprovalsFromContext(ctx)
	// nil means the declassification would have been authorized — a live covering approval,
	// or nothing to clear at all — so the outer layer's verdict stands as it was. Every
	// refusal arm is the engine's own, including the hard `ledger_unavailable` one: a fault
	// that left a downgradable verdict in place made an unreachable ledger the way to run,
	// on an --audit route, a declassification the same manifest blocks without a token.
	verdict := p.engine.DeclassifyVerdictFor(ctx, req, matched)
	if verdict == nil {
		return r, false
	}
	// composeHardened carries the AuditOnly AND. Every declassify refusal is built hard
	// (escalateResponse leaves AuditOnly false for the same reason the ceiling's escalation
	// does), so for this caller it is a backstop rather than a live correction — which is an
	// argument for sharing the composition, not for hand-writing a weaker one here.
	out := composeHardened(r, *verdict)
	// Obligations are stripped only for a refusal that is never forwarded, and re-filled
	// otherwise — the same rule the ceiling's sibling applies, rather than an unconditional
	// strip resting on "every declassify refusal is hard". Stripping unconditionally is the
	// shape that re-opened a fail-open there: a downgradable refusal reaching the host on an
	// --audit route with the manifest's redactFields already discarded, so the response
	// arrives unmasked.
	if out.Denial != nil && out.Denial.HardDeny {
		out.Obligations = nil
		return out, true
	}
	return p.withForwardObligationsFor(ctx, out, matched), true
}

// directivesNamingTarget collects the directives of every capability whose target type +
// pattern match target, ignoring principal scoping — the "what did the manifest declare
// about this target" question, as opposed to findConstraint's "which entry governs this
// caller". Used only to fill obligations onto a forwarded no-match deny.
func (p *ManifestPDP) directivesNamingTarget(target EnforceTarget) []capability.Directive {
	var dirs []capability.Directive
	for i := range p.caps {
		if pt := p.parsedTargetAt(i); pt.parseErr || pt.typ != target.Type || !matchBare(pt.bare, target.Name) {
			continue
		}
		dirs = append(dirs, p.caps[i].Directives...)
	}
	return dirs
}

// matchingLabelOutputUnion collects the union of labelOutput labels from every capability
// whose target type + pattern match target AND whose principal scoping the caller's claims
// satisfy — the same "applies to this request" test findConstraint uses, minus the
// specificity/action tie-break, because ANY matching source entry's taint applies. Order is
// unspecified (the engine reorders into the canonical vocabulary). nil when nothing matches.
func (p *ManifestPDP) matchingLabelOutputUnion(target EnforceTarget, claims map[string]interface{}) []string {
	var set map[string]struct{}
	for i := range p.caps {
		if pt := p.parsedTargetAt(i); pt.parseErr || pt.typ != target.Type || !matchBare(pt.bare, target.Name) {
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

// DecideResourceCancel authorizes a resources/unsubscribe by MATCH ALONE: the URI must
// name a resource entry this caller may read. No condition is evaluated and nothing is
// committed — see the contract for why a cancellation is not a read.
//
// It reuses findConstraint + containsAction, the same pair the resources/list filter
// applies, so what a session may cancel is exactly what it may see listed. A poisoned or
// otherwise unreadable entry is not a consideration here: a cancel names a URI, not a
// catalog entry, and carries no description a host renders.
//
// The matched entry's per-constraint observe posture (enforcement: audit) IS carried onto
// the response, exactly as decideTarget's stamp does for a read. Building the response
// directly here skips that stamp, and dropping it broke the method in both directions on
// an observe entry: the read deny was downgraded and FORWARDED (the subscription really
// opened) while the cancel deny stayed hard, restoring the very dead end this entry point
// removes — and on the allowing spelling the tape recorded audit_only=true for the read and
// audit_only=false for the unsubscribe, claiming an observe-only entry enforced the cancel.
// A no-match deny carries no entry and so no posture, which is right: there is nothing
// declaring observe mode for a URI the manifest never names.
func (p *ManifestPDP) DecideResourceCancel(ctx context.Context, sessionID, uri, _ string) capability.EnforceResponse {
	if deny := p.CheckKill(ctx, sessionID); deny != nil {
		return *deny
	}
	c := p.findConstraint(EnforceTarget{Type: capability.TargetTypeResource, Name: uri},
		jwtClaimsAsMap(ctx))
	if c == nil {
		return denyResponse(p.engineClock(), capability.ErrCodeAuthorizationFailed, "",
			fmt.Sprintf("resource %q is not permitted by the capability manifest, so there is no subscription to it to cancel", uri))
	}
	if !containsAction(c.Actions, requiredActionFor(capability.TargetTypeResource)) {
		return withCancelAuditPosture(denyResponse(p.engineClock(), capability.ErrCodeCapabilityDenied, "",
			fmt.Sprintf("resource %q is present in the manifest but not with the %q action, so there is no subscription to it to cancel", uri, requiredActionFor(capability.TargetTypeResource))), c)
	}
	// The delegation target gate. A cancel is authorized by MATCH ALONE — no conditions, no
	// quota, no session-state commit — and this belongs on the match side of that line
	// rather than the metering side: it is authority, not accounting, so it commits nothing
	// and cannot deny an unsubscribe by spending a budget. Without it this method's own
	// documented invariant ("what a session may cancel is exactly what it may see listed")
	// became false the moment the list filter learned about chains.
	if deny := delegationTargetDenial(ctx, p.engineClock(),
		EnforceTarget{Type: capability.TargetTypeResource, Name: uri}, c.IsAuditOnly()); deny != nil {
		return *deny
	}
	return withCancelAuditPosture(newAllowResponse(p.engineClock()), c)
}

// withCancelAuditPosture stamps the matched constraint's enforcement: audit posture onto a
// cancel response, the one field decideTarget's stamp contributes that a match-only
// decision still needs. Everything else stamp does (obligations, flow labels, condition
// details) describes work a cancel deliberately does not perform.
func withCancelAuditPosture(r capability.EnforceResponse, matched *capability.Constraint) capability.EnforceResponse {
	if matched.IsAuditOnly() {
		r.AuditOnly = true
	}
	return r
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
	if deny := killCheck(ctx, p.engineClock(), p.ks, sessionID); deny != nil {
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
	// on system: targets at manifest load. A manifest built in-process could still
	// carry it, and evaluateAndRecord below would then stamp AuditOnly onto a condition
	// deny, which the transport's observe gate (isObserveDeny) downgrades to a forwarded
	// sampling request EVEN on an enforce route — silently defeating sampling's
	// deny-by-default posture. Refuse with a non-downgradable ENFORCEMENT_ERROR,
	// mirroring the stray-argumentSchema guard above (both are "the loader rejects it,
	// but a programmatic manifest could carry it"). Route-level --audit still forwards
	// sampling, but that is the transport's call, not a per-entry downgrade.
	if matched.IsAuditOnly() {
		return hardDenyResponse(p.engineClock(), capability.ErrCodeEnforcementError,
			fmt.Sprintf("constraint %q carries enforcement:audit, which is tool/resource-only and not supported on system:sampling/createMessage; refusing to forward sampling under an unenforced observe posture (fail closed)", matched.Target))
	}

	// Conditions on the opt-in entry MUST be evaluated — skipping them is a
	// fail-open on the only enforcement point for server-initiated sampling.
	// sampling/createMessage carries no tool args, so the request uses an empty set.
	// Sampling keeps its own constraint-resolution head but shares evaluateAndRecord
	// so its condition tail cannot drift from the other paths.
	req := &capability.EnforceRequest{
		SessionID:  sessionID,
		TargetName: capability.MethodSamplingCreateMessage,
		Arguments:  map[string]interface{}{},
		Context:    capability.EnforceRequestContext{SourceIP: sourceIP},
		Target: &capability.EnforceRequestTarget{
			Type: string(capability.TargetTypeSystem),
			Name: capability.MethodSamplingCreateMessage,
		},
		Claims: claims,
		// Sampling is the one enforced method that drives the HOST's model, so it is the
		// one a quarantined delegate most wants and the one whose omission is least
		// visible: with this field unset every delegation gate short-circuits on
		// IsEmpty() and a chain granting one read tool still reaches inference. The JWT
		// layer already learned this exact lesson for mcp.capabilities ("sampling was the
		// one enforced method that ignored it"); this is the same seam, so it carries the
		// same field every other decision path carries.
		Delegation: delegationFromContext(ctx),
		// Approvals for the same reason: a declassify directive on the sampling opt-in
		// must be satisfiable by the same grant that satisfies it anywhere else.
		DeclassifyApprovals: declassifyApprovalsFromContext(ctx),
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
	return filterToolsListResult(result, p, jwtClaimsAsMap(ctx), delegationFromContext(ctx), sessionIDFromContext(ctx), CompleteToolListingFromContext(ctx))
}

// FilterResourcesList implements ListFilterer for the manifest PDP.
func (p *ManifestPDP) FilterResourcesList(ctx context.Context, result json.RawMessage) ListFilterResult {
	return filterResourcesListResult(result, p, jwtClaimsAsMap(ctx), delegationFromContext(ctx))
}

// FilterPromptsList implements ListFilterer for the manifest PDP.
func (p *ManifestPDP) FilterPromptsList(ctx context.Context, result json.RawMessage) ListFilterResult {
	return filterPromptsListResult(result, p, jwtClaimsAsMap(ctx), delegationFromContext(ctx))
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
//
// Top-level keys are additionally required to be unambiguous under Unicode simple
// fold, and a fold collision is an error. This is load-bearing rather than hygiene:
// encodeOrderedObjectWithList substitutes the pruned array for the list key alone and
// re-emits every SIBLING key's bytes verbatim, so an envelope carrying both "tools"
// and "Tools" would ship the unfiltered sibling array straight through the filter —
// past every ListFilterer, including the fail-closed no-policy default. Go's decoder
// (and any reader binding keys case-insensitively: the Go MCP SDK, .NET with
// PropertyNameCaseInsensitive) resolves both to one field and keeps the LAST in
// document order, i.e. the array the proxy never pruned. Refusing the envelope is a
// denial, not a bypass, which is the direction this proxy fails.
//
// The fold is capability.FoldJSONKey, the same rule scanToolEntry applies to a tool
// entry's top-level keys and rejectDuplicateJSONKeys applies to request params, so the
// three layers cannot drift. It applies at the TOP level only: nested entry schemas
// decode into map[string]interface{}, whose keys are exact, and sibling properties
// "Name"/"name" inside a schema are legal and honest (see scanToolEntry).
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
	// folded maps a fold-canonical key to the first raw spelling seen under it, so a
	// collision can name both spellings in the error.
	folded := make(map[string]string)
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
		fk := capability.FoldJSONKey(key)
		if prior, dup := folded[fk]; dup {
			return nil, nil, fmt.Errorf("list envelope carries ambiguous top-level keys %q and %q (they differ only by case fold, so a host may render a different value than this proxy filtered)", prior, key)
		}
		folded[fk] = key
		// No duplicate check on `values` here: an EXACT duplicate necessarily collides in
		// `folded` two lines above (a key folds to itself) and has already been rejected,
		// so every key that reaches this point is new. Guarding it would suggest duplicates
		// are tolerated, when refusing them is the load-bearing behavior.
		keys = append(keys, key)
		values[key] = raw
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
func filterResourcesListResult(resultBytes json.RawMessage, mdp *ManifestPDP, claims map[string]interface{}, chain *capability.DelegationChain) ListFilterResult {
	// The entry-ambiguity gate, the constraint lookup and the action check live in
	// keepByManifestEntry, shared with prompts/list; only the id field differs. Here the
	// smuggled key would be "uri" vs "URI", which decides which resource the host
	// believes it is reading.
	return filterListResult(resultBytes, listKeyResources,
		keepByManifestEntry(mdp, claims, chain, capability.TargetTypeResource, "read", func(raw json.RawMessage) (string, bool) {
			var entry struct {
				URI string `json:"uri"`
			}
			if err := json.Unmarshal(raw, &entry); err != nil {
				return "", false
			}
			return entry.URI, true
		}))
}

// keepByManifestEntry builds the per-entry keep predicate that resources/list and
// prompts/list share. The two filters were near-verbatim copies differing only in the id
// field, the target type and the required action — and what they duplicated was the
// security-relevant part: the fail-closed ambiguity gate, the constraint lookup, and the
// action check. A copy is how one flavor gets a gate the other does not, which is exactly
// what entryKeysAmbiguous exists to prevent across list flavors.
//
// tools/list keeps its own predicate: it additionally verifies a descriptionHash pin and
// consults the sticky poisoned set, so folding it in would parameterize away the very
// logic that makes it different.
//
// entryID decodes the entry's identity and reports false when the entry cannot be
// decoded — the fail-closed direction, dropping the entry from the catalog.
func keepByManifestEntry(
	mdp *ManifestPDP,
	claims map[string]interface{},
	chain *capability.DelegationChain,
	targetType capability.TargetType,
	requiredAction string,
	entryID func(json.RawMessage) (string, bool),
) func(json.RawMessage) (bool, string) {
	return func(raw json.RawMessage) (bool, string) {
		if entryKeysAmbiguous(raw) {
			return false, ""
		}
		id, ok := entryID(raw)
		if !ok {
			return false, ""
		}
		// An entry no hop of the caller's delegation chain admits is hidden, for the reason
		// every other hide-here-and-deny-there rule in this file exists: the call leg will
		// refuse it, and a catalog advertising an action the caller cannot take is a catalog
		// the model will spend turns trying to use. Delegation narrows only, so this can
		// only ever remove entries a wider caller would still see.
		// Guarded on IsEmpty() rather than left to PermitsTarget's own nil fast path: the
		// fast path skips the SCAN, but the string concat naming the target is built by the
		// caller before the call happens, on every entry, on the overwhelming majority of
		// requests that carry no chain at all — exactly the per-entry allocation the
		// targetIndex map exists to keep off this path for a delegated caller.
		if !chain.IsEmpty() {
			if permitted, _ := chain.PermitsTarget(string(targetType) + ":" + id); !permitted {
				return false, ""
			}
		}
		c := mdp.findConstraint(EnforceTarget{Type: targetType, Name: id}, claims)
		if c != nil && containsAction(c.Actions, requiredAction) {
			return true, id
		}
		return false, ""
	}
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

// maxDuplicateKeyScanDepth bounds how deep the duplicate-key scan recurses before it
// fails closed, guarding the stack against an adversarially nested entry. It is set well
// ABOVE the nesting the hashed surface itself covers (capability's parameter-description
// walk bounds at 64 SCHEMA levels, and a schema level is two JSON levels — a "properties"
// object plus the property object), so an honest deep schema is never reported as
// duplicated here: past its own bound the hash walk records an overflow sentinel and the
// resulting hash simply mismatches the pin. Keeping this bound strictly looser than the
// hashed surface's is load-bearing — a tighter one would poison honest deeply-nested tools.
const maxDuplicateKeyScanDepth = 512

// toolEntryScan is the verdict of scanToolEntry: whether the entry's bytes can be trusted
// to decode to the same surface a host renders, plus every name the entry could present.
type toolEntryScan struct {
	// untrustworthy reports that Go's decode of this entry may differ from what a host
	// renders, so neither its name nor its hashed surface may be believed.
	untrustworthy bool
	// names holds every top-level name value the entry carries (more than one only when
	// the key is duplicated). It bounds which pins the entry could impersonate, so a
	// malformed entry poisons only those rather than every pin on the route.
	//
	// Only meaningful when namesComplete is set: see below.
	names []string
	// namesComplete reports that the scan walked the WHOLE entry, so names is the full
	// set of names it could present. When false the scan aborted partway (malformed
	// tokens, a non-string key, or a value nested past the depth bound) and names holds
	// only what had been seen so far -- which may be nothing at all, since a tool entry is
	// free to place its deep "inputSchema" BEFORE its "name". Treating that truncated list
	// as authoritative poisons a subset of the pins the entry could impersonate, and often
	// the empty set, so an aborted scan must poison every pin instead: the set of pins an
	// unreadable entry could be impersonating is unknown, not empty.
	namesComplete bool
}

// scanToolEntry decides whether a tools/list entry's bytes can be trusted, and collects
// the names it could present to a host.
//
// Two distinct collision rules, because Go resolves the two levels differently:
//
//   - TOP level, matched case-INSENSITIVELY. encoding/json binds object keys to struct
//     fields by a case-folding match and keeps the LAST one, so {"description":"<INJECT>",
//     "Description":"<CLEAN>"} decodes to <CLEAN> and hashes clean while a case-sensitive
//     host (JSON.parse, the Python SDK) renders <INJECT>. Exact duplicates fold together
//     too, so one rule covers both. This is why the scan folds here and nowhere else. The
//     fold must be capability.FoldJSONKey (Unicode simple-fold), matching the decoder's
//     own field matcher: strings.ToLower is strictly weaker and misses variants that are
//     already lower case, such as U+017F in "deſcription".
//   - NESTED, matched EXACTLY. Nested values decode into map[string]interface{}, whose
//     keys are exact, so only a byte-identical repeat is a divergence. Folding here would
//     be wrong: a schema with sibling properties "Name" and "name" is legal and honest.
//     Nested duplicates still matter because the hash covers parameter descriptions at
//     any depth, so a duplicate one level down is an injection surface.
//
// Any malformed or over-deep input reports untrustworthy. How the walk itself works — a
// single byte-level streaming pass, why values are never converted, and why a
// float64-overflowing literal must not error it — is documented once on keyScanner, which
// performs it.
func scanToolEntry(raw json.RawMessage) toolEntryScan {
	return scanJSONKeys(raw, jsonKeyScanOpts{})
}

// jsonKeyScanOpts configures scanJSONKeys for one of its two callers. Both ask the same
// security question — can Go's decode of these bytes differ from what a consumer renders?
// — but they hand the bytes to DIFFERENT decoders, and the fold rule follows the decoder,
// so it is a per-caller policy rather than a caller-independent constant.
type jsonKeyScanOpts struct {
	// allowArrayRoot admits a JSON array as the root value. A tools/list entry must be an
	// object, so scanToolEntry leaves this false and a non-object root is untrustworthy
	// with a knowably-empty name set. The redaction path scans values that are legally
	// either shape — structuredContent and any doubly-encoded leaf may be an array of
	// objects — so it sets this, and the array root simply opens the walk like any other
	// composite.
	allowArrayRoot bool

	// foldKeys, when non-nil, REPLACES the struct-binding fold rule below with a scoped
	// one: a key is folded (so a case variant of it collides with it) only when its folded
	// form is in this set, and then at EVERY depth. The redaction path sets it; see
	// redactionFoldKeys for which names go in and why the unscoped rule is wrong there.
	//
	// nil keeps the tools/list rule: fold the ROOT object's keys, match exactly below.
	// That rule is derived from encoding/json binding an entry's top-level keys to the
	// mcp.ToolEntry STRUCT by a case-folding match (so {"description":"<INJECT>",
	// "Description":"<CLEAN>"} decodes to <CLEAN> and hashes clean while a case-sensitive
	// host renders <INJECT>), while nested values decode into map[string]interface{} with
	// exact keys (so a schema carrying sibling properties "Name" and "name" is legal and
	// honest, and folding there would refuse it). See the scanToolEntry doc for the full
	// derivation.
	foldKeys map[string]struct{}
}

// scanJSONKeys is the shared streaming walk behind every duplicate-key gate in this
// package: the */list entry gate (scanToolEntry, and entryKeysAmbiguous through it) and
// the redaction path's envelope/leaf gate (redactionKeysAmbiguous). Sharing one
// implementation keeps them from drifting on the depth bound, the number handling, or the
// EXACT-duplicate rule — which is caller-independent: a byte-identical repeated key is a
// divergence at every depth for every consumer (Go keeps the last, a first-wins parser
// keeps the first), so it is untrustworthy regardless of opts.
//
// What the callers do NOT share is which keys are additionally folded; that is
// opts.foldKeys, documented on jsonKeyScanOpts.
func scanJSONKeys(raw json.RawMessage, opts jsonKeyScanOpts) toolEntryScan {
	// Classify the root from its first significant byte. A container root — the only shape
	// with keys to scan, and the only one either caller passes in production — goes to the
	// byte walk below. Everything else is handed to encoding/json, which is what decides
	// "valid scalar" from "malformed" here, so that classification stays byte-identical to
	// the decoder's without this scanner having to re-derive JSON's literal grammar for a
	// case it never sees in production.
	i := skipJSONSpace(raw, 0)
	if i < len(raw) && (raw[i] == '{' || (opts.allowArrayRoot && raw[i] == '[')) {
		return scanContainerKeys(raw, i, opts)
	}
	return classifyNonContainerRoot(raw)
}

// classifyNonContainerRoot handles a root scanJSONKeys will not walk: a scalar, a
// (non-admitted) array, or bytes that are not JSON at all.
//
// Either way the value is untrustworthy — it cannot decode into the hashed tool surface, so
// the filter must drop it — but the two differ in what they say about the entry's candidate
// NAMES. A well-formed non-object carries no top-level "name", so a host renders no tool
// name from it and its candidate set is knowably EMPTY: namesComplete is set and the caller
// poisons nothing, rather than escalating one null entry to a route-wide, sticky poison of
// every pinned tool. Bytes that do not parse at all say nothing about what they could be
// presenting, so the set stays unknown (namesComplete false) and the caller widens.
//
// The entries arrive as json.RawMessage elements of an already-unmarshaled array, so each is
// exactly one complete, well-formed JSON value: reading its first token is enough to
// classify it, with no trailing bytes left to hide anything.
func classifyNonContainerRoot(raw json.RawMessage) toolEntryScan {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber so a float64-overflowing literal (1e999) yields a json.Number instead of
	// erroring, which would otherwise report a well-formed scalar as unparseable.
	dec.UseNumber()
	if _, err := dec.Token(); err != nil {
		return toolEntryScan{untrustworthy: true}
	}
	return toolEntryScan{untrustworthy: true, namesComplete: true}
}

// The three positions the walk can be in inside a container.
const (
	scanStateValue = iota // raw[p] begins a value, or closes an empty array
	scanStateKey          // raw[p] begins a key, or closes an empty object
	scanStateNext         // raw[p] is ',' or this container's closer
)

// keyScanFrame tracks one open composite. seen is allocated lazily: most nested objects in a
// tool schema are small, and an empty-object-heavy payload should not cost a map header per
// object. empty distinguishes a closer that ends an EMPTY container from one that follows a
// comma (a trailing comma, which JSON forbids).
type keyScanFrame struct {
	object bool
	seen   map[string]struct{}
	empty  bool
}

// keyScanner is the byte-level duplicate-key walk: one streaming pass over raw, collecting
// each object's keys under the caller's fold policy and reporting a collision, plus (for the
// struct-binding caller) every top-level name value.
//
// It reads the BYTES rather than driving encoding/json's tokenizer, and the difference is
// the reason it exists: the tokenizer materializes every value it walks — a Go string per
// string, a json.Number per number, an interface box per delimiter — while this scan needs
// none of them. Only object KEYS become strings here (a scan that compares keys has to), and
// values are traversed by advancing past them. The gate runs twice over every allowed
// tools/call carrying a redactFields obligation (once over the envelope, once over every
// JSON leaf) and once per entry of every */list, so the values it does not need were the
// bulk of what it paid for.
//
// The walk is iterative with an explicit frame stack, not recursion over re-decoded
// sub-values: decoding each value into a json.RawMessage and recursing on those same bytes
// copies them once per level of nesting, making the scan O(bytes x depth) — at
// maxDuplicateKeyScanDepth 512 that let one hostile entry cost hundreds of megabytes of
// transient garbage. This form is O(bytes).
//
// The REQUEST-side gate, mcp.rejectDuplicateJSONKeys, asks the same security question of
// request params and shares the iterative-frame-stack shape, but it still drives
// encoding/json's tokenizer — only this one walks bytes. They are two implementations of
// one rule, which is a real cost: a grammar fix here is not a fix there. Consolidating them
// means a scanner in pkg/ (the only layer both packages reach) and an oracle for the
// request path too, which is its own change; until then, do not read the shared shape as a
// shared implementation.
//
// Malformed bytes anywhere report untrustworthy: this is a strict JSON walk, not a lenient
// one. It never has to be the authority on well-formedness in production — both callers have
// already decoded these exact bytes with encoding/json before asking — so refusing something
// the decoder would have accepted denies rather than admits.
type keyScanner struct {
	raw   []byte
	opts  jsonKeyScanOpts
	stack []keyScanFrame
	p     int
	st    int
	// pendingName is set when the value about to be read is the ENTRY's top-level name
	// value, so the names it could present to a host are collected in the same pass. Only
	// the struct-binding caller (opts.foldKeys == nil, i.e. the tools/list entry gate) reads
	// out.names; the redaction gate consults untrustworthy alone, so it never arms this and
	// never pays for the name collection.
	pendingName bool
	done        bool
	out         toolEntryScan
}

// scanContainerKeys walks the container beginning at raw[start] and returns its verdict.
func scanContainerKeys(raw json.RawMessage, start int, opts jsonKeyScanOpts) toolEntryScan {
	s := keyScanner{raw: raw, opts: opts, stack: make([]keyScanFrame, 0, 8), p: start + 1}
	s.stack = append(s.stack, keyScanFrame{object: raw[start] == '{', empty: true})
	s.st = scanStateValue
	if s.stack[0].object {
		s.st = scanStateKey
	}
	return s.run()
}

// run drives the walk to the root container's closer or to the first malformed byte.
//
// Every abort returns the verdict accumulated SO FAR rather than a fresh zero value, so
// names already collected survive -- and leaves namesComplete false, so the caller knows the
// list is truncated and widens the poison accordingly.
func (s *keyScanner) run() toolEntryScan {
	for !s.done {
		s.p = skipJSONSpace(s.raw, s.p)
		if s.p >= len(s.raw) {
			s.out.untrustworthy = true
			return s.out
		}
		var ok bool
		switch c := s.raw[s.p]; s.st {
		case scanStateKey:
			ok = s.stepKey(c)
		case scanStateValue:
			ok = s.stepValue(c)
		default:
			ok = s.stepNext(c)
		}
		if !ok {
			s.out.untrustworthy = true
			return s.out
		}
	}
	// The stack unwound to empty: the whole value was walked, so names is authoritative.
	s.out.namesComplete = true
	return s.out
}

// top is the innermost open container. It is only ever read between pushes: push invalidates
// the pointer (append may move the backing array), which is why callers re-take it.
func (s *keyScanner) top() *keyScanFrame { return &s.stack[len(s.stack)-1] }

// push opens a nested container, refusing one nested past the depth bound.
func (s *keyScanner) push(object bool) bool {
	if len(s.stack) >= maxDuplicateKeyScanDepth {
		return false // pathologically deep
	}
	s.top().empty = false
	s.stack = append(s.stack, keyScanFrame{object: object, empty: true})
	s.st = scanStateValue
	if object {
		s.st = scanStateKey
	}
	s.p++
	s.pendingName = false
	return true
}

// pop closes the innermost container, ending the walk when it was the root.
func (s *keyScanner) pop() {
	s.p++
	s.stack = s.stack[:len(s.stack)-1]
	if len(s.stack) == 0 {
		s.done = true
		return
	}
	s.st = scanStateNext
}

// stepKey reads one object key (or closes an empty object): the collision check itself.
func (s *keyScanner) stepKey(c byte) bool {
	if c == '}' && s.top().empty {
		s.pop()
		return true
	}
	if c != '"' {
		return false
	}
	end, simple, ok := scanJSONStringSpan(s.raw, s.p)
	if !ok {
		return false
	}
	key, ok := decodeJSONStringSpan(s.raw[s.p:end], simple)
	if !ok {
		return false
	}
	s.p = skipJSONSpace(s.raw, end)
	if s.p >= len(s.raw) || s.raw[s.p] != ':' {
		return false
	}
	s.p++
	depth := len(s.stack)
	canon := s.canonicalize(key, depth)
	top := s.top()
	if top.seen == nil {
		top.seen = make(map[string]struct{})
	}
	if _, dup := top.seen[canon]; dup {
		s.out.untrustworthy = true
	}
	top.seen[canon] = struct{}{}
	top.empty = false
	s.pendingName = s.opts.foldKeys == nil && depth == 1 && canon == jsonKeyNameFolded
	s.st = scanStateValue
	return true
}

// canonicalize applies the caller's fold policy to one key (see jsonKeyScanOpts). Everything
// not folded is compared byte-exactly, which is what catches the caller-independent exact
// duplicate. capability.FoldJSONKey, not strings.ToLower: ToLower leaves an already-lower-case
// case variant such as U+017F ("deſcription") distinct from "description", so the collision
// the decoder makes would go unseen and the bytes would clear the scan.
func (s *keyScanner) canonicalize(key string, depth int) string {
	switch {
	case s.opts.foldKeys != nil:
		// Scoped fold, at every depth: only a name whose case variant could change what a
		// consumer resolves. Depth-uniform on purpose -- an unscoped rule keyed to depth made
		// the verdict depend on whether the value happened to be wrapped in an array, since
		// the bracket occupies a level of its own.
		//
		// A key already equal to its folded form needs no rewrite (canon is that form), so
		// only the variant spelling is redirected onto it -- which is what makes the two
		// collide in `seen`.
		if folded := capability.FoldJSONKey(key); folded != key {
			if _, scoped := s.opts.foldKeys[folded]; scoped {
				return folded
			}
		}
	case depth == 1:
		// Struct-binding fold, root object only. depth == 1 IS the root object here: this arm
		// is reached only when opts.foldKeys is nil, and that caller does not admit an array
		// root, so the root frame is always the object.
		return capability.FoldJSONKey(key)
	}
	return key
}

// stepValue reads one value (or closes an empty array).
func (s *keyScanner) stepValue(c byte) bool {
	switch {
	case c == ']' && !s.top().object && s.top().empty:
		s.pop()
		return true
	case c == '{' || c == '[':
		return s.push(c == '{')
	case c == '"':
		end, simple, ok := scanJSONStringSpan(s.raw, s.p)
		if !ok {
			return false
		}
		if s.pendingName {
			// Decode only the value the caller will attribute a pin to; every other string
			// in the payload is walked past without becoming a Go string.
			//
			// A decode failure ABORTS the walk rather than skipping the name, matching the
			// key path. Continuing would finish with namesComplete set and this entry's name
			// missing from the list, so an entry the scan could not fully read would poison
			// the EMPTY set of pins instead of every pin — the widening an unreadable entry
			// is supposed to trigger. No input reaches this today (a span this scanner
			// accepts is one encoding/json decodes), which is exactly why the branch has to
			// state the fail-closed direction rather than rely on being unreachable.
			name, dok := decodeJSONStringSpan(s.raw[s.p:end], simple)
			if !dok {
				return false
			}
			if name != "" {
				s.out.names = append(s.out.names, name)
			}
			s.pendingName = false
		}
		s.p = end
	default:
		end, ok := scanJSONScalarSpan(s.raw, s.p)
		if !ok {
			return false
		}
		s.p = end
		s.pendingName = false
	}
	s.top().empty = false
	s.st = scanStateNext
	return true
}

// stepNext reads the separator or closer that must follow a completed member.
func (s *keyScanner) stepNext(c byte) bool {
	switch c {
	case ',':
		s.p++
		s.st = scanStateValue
		if s.top().object {
			s.st = scanStateKey
		}
		return true
	case '}':
		if !s.top().object {
			return false
		}
		s.pop()
		return true
	case ']':
		if s.top().object {
			return false
		}
		s.pop()
		return true
	}
	return false
}

// skipJSONSpace returns the index of the first byte at or after p that is not JSON
// whitespace. The four bytes are exactly what encoding/json skips; a UTF-8 BOM is
// deliberately NOT among them, so a BOM-prefixed root falls to classifyNonContainerRoot and
// is refused there, as the decoder refuses it.
func skipJSONSpace(raw []byte, p int) int {
	for p < len(raw) {
		switch raw[p] {
		case ' ', '\t', '\r', '\n':
			p++
		default:
			return p
		}
	}
	return p
}

// scanJSONStringSpan walks the JSON string beginning at raw[p] (which must be '"') and
// returns the index just past its closing quote.
//
// simple reports that the span's contents are plain ASCII text — every byte in 0x20..0x7F,
// no backslash — so the string's value is the span between the quotes with no decoding.
// (0x7F, DEL, is included deliberately: encoding/json's own fast path admits it, since that
// path's guard is `c < utf8.RuneSelf`, not printability.)
//
// The flag is a CONSERVATIVE approximation of encoding/json's fast path, not an exact
// mirror: the decoder also returns valid multi-byte UTF-8 uncopied, while this marks every
// byte >= 0x80 non-simple and routes it through json.Unmarshal. Erring that way is the
// point — the decoder's copying path rewrites INVALID UTF-8 to U+FFFD, so two keys that
// differ only in invalid bytes fold together there; treating a non-ASCII span as simple
// would leave them distinct here and miss a collision the decoder makes. Widening this to
// "no escape and valid UTF-8" would match the decoder byte for byte and is the correct way
// to make non-ASCII keys cheap, but it must be derived from unquoteBytes, not assumed.
func scanJSONStringSpan(raw []byte, p int) (end int, simple, ok bool) {
	simple = true
	for i := p + 1; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '"':
			return i + 1, simple, true
		case c == '\\':
			simple = false
			// Validate the escape here rather than leaving it to the decode below: the
			// decode runs only for a KEY (and for the one name value the tools/list caller
			// attributes), so an invalid escape inside any other string would otherwise be
			// walked past as if the bytes were fine — reporting trustworthy where the
			// decoder these bytes are checked against refuses them outright. Wrong
			// direction on a fail-closed gate.
			i++
			if i >= len(raw) {
				return 0, false, false
			}
			switch raw[i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				// Four hex digits. A lone surrogate is NOT rejected — the decoder
				// substitutes U+FFFD for one rather than erroring — so only the digits
				// are checked.
				if i+4 >= len(raw) {
					return 0, false, false
				}
				for j := i + 1; j <= i+4; j++ {
					if !isHexDigit(raw[j]) {
						return 0, false, false
					}
				}
				i += 4
			default:
				return 0, false, false
			}
		case c < 0x20 || c >= utf8.RuneSelf:
			// A raw control byte is invalid JSON; a non-ASCII byte is valid but takes the
			// decoder's copying path, so it is not simple.
			if c < 0x20 {
				return 0, false, false
			}
			simple = false
		}
	}
	return 0, false, false // unterminated
}

// isHexDigit reports whether b is one of the sixteen hex digits a \u escape admits.
func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// decodeJSONStringSpan returns the Go string a JSON string span decodes to. The simple span
// (see scanJSONStringSpan) is its own contents; anything else goes through encoding/json, so
// escapes, surrogate pairs, and invalid UTF-8 resolve exactly as the decoder resolves them
// rather than by a second implementation of the same rules.
func decodeJSONStringSpan(span []byte, simple bool) (string, bool) {
	if simple {
		return string(span[1 : len(span)-1]), true
	}
	var s string
	if err := json.Unmarshal(span, &s); err != nil {
		return "", false
	}
	return s, true
}

// scanJSONScalarSpan walks the non-string scalar beginning at raw[p] — a number, true,
// false, or null — and returns the index just past it. A number is validated against JSON's
// grammar but never converted: an out-of-range literal (1e999) must not error the walk, or
// it would report a valid entry untrustworthy and, worse, shield a later duplicate behind
// that error. This is the byte-level equivalent of the decoder's UseNumber mode.
func scanJSONScalarSpan(raw []byte, p int) (end int, ok bool) {
	switch raw[p] {
	case 't':
		return matchJSONLiteral(raw, p, "true")
	case 'f':
		return matchJSONLiteral(raw, p, "false")
	case 'n':
		return matchJSONLiteral(raw, p, "null")
	}
	i := p
	if i < len(raw) && raw[i] == '-' {
		i++
	}
	// int: a single 0, or a nonzero digit followed by digits.
	switch {
	case i < len(raw) && raw[i] == '0':
		i++
	case i < len(raw) && raw[i] >= '1' && raw[i] <= '9':
		for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
			i++
		}
	default:
		return 0, false
	}
	// frac
	if i < len(raw) && raw[i] == '.' {
		i++
		start := i
		for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
			i++
		}
		if i == start {
			return 0, false
		}
	}
	// exp
	if i < len(raw) && (raw[i] == 'e' || raw[i] == 'E') {
		i++
		if i < len(raw) && (raw[i] == '+' || raw[i] == '-') {
			i++
		}
		start := i
		for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
			i++
		}
		if i == start {
			return 0, false
		}
	}
	return i, true
}

// matchJSONLiteral returns the index just past lit when raw[p:] begins with it.
func matchJSONLiteral(raw []byte, p int, lit string) (end int, ok bool) {
	if p+len(lit) <= len(raw) && string(raw[p:p+len(lit)]) == lit {
		return p + len(lit), true
	}
	return 0, false
}

// entryKeysAmbiguous reports whether a */list entry's own bytes could decode to a
// different surface than a host renders — the fail-closed gate every list filter applies
// per entry, independent of whether the manifest pins a descriptionHash. It is
// scanToolEntry's verdict without the pin-attribution names; tools, resources, and prompts
// all share it so an entry-poisoning shape cannot be closed on one list flavor and left
// open on the other two.
func entryKeysAmbiguous(raw json.RawMessage) bool {
	return scanToolEntry(raw).untrustworthy
}

// EntryKeysAmbiguous is the exported form of the per-entry ambiguity gate, for the startup
// drift check.
//
// The drift comparison is the layer that verifies live tool descriptions against the
// manifest's descriptionHash pin and refuses the session on a mismatch, so it consumes the
// same bytes for the same security question as the runtime list filter — and decoding them
// with a plain json.Unmarshal let exactly the shape this detects through: an entry carrying
// "description" alongside "deſcription" (U+017F, already lower case) binds the second to
// the struct field, hashes CLEAN against the pin, and the unconditionally-fatal startup
// refusal never fires, while a case-sensitive host renders the injected value. Exporting
// the check rather than restating it keeps the two layers on one rule.
func EntryKeysAmbiguous(raw json.RawMessage) bool {
	return entryKeysAmbiguous(raw)
}

// recordPinnedToolHash records entry's live description hash iff its NAME is pinned by
// any manifest entry — keyed off pinnedTools, not a selected constraint. A duplicate
// non-pinned sibling (or a pinned sibling lacking the "call" action) can win
// findConstraint selection and shadow the pin; gating on the selected constraint would
// then skip recording and leave the call leg unable to detect a mid-session description
// rotation. Gating on the pinned set still bounds the map by the operator-controlled
// manifest, so a name-rotating upstream cannot flood it. Recording passes the pin, so a
// mismatch is sticky-marked poisoned atomically (record + mark under one lock).
//
// The caller MUST have cleared the entry through scanToolEntry first: this trusts
// entry.Name, and a duplicated or case-variant name key makes that value untrustworthy.
func (p *ManifestPDP) recordPinnedToolHash(name, surface string) {
	if pin, pinned := p.pinnedTools[name]; pinned {
		p.recordObservedHash(name, surface, pin)
	}
}

// hasPinnedTools reports whether the manifest pins any tool's descriptionHash. It is the
// ONE authority on "is there anything to arm": armPinsFromToolsList gates its whole body
// on it, filterToolsListResult gates the CALL on it (see there for why the caller needs
// its own gate), and poisonAllPinned short-circuits on it. Writing the predicate once is
// what keeps those three from drifting into disagreement about when the pass may be
// skipped.
//
// pinnedTools is built once by NewManifestPDP and never mutated, so this needs no lock.
func (p *ManifestPDP) hasPinnedTools() bool { return len(p.pinnedTools) > 0 }

// anyNamePinned reports whether any of names is pinned by the manifest. It reads
// pinnedTools, which NewManifestPDP builds once and never mutates, so no lock is needed
// (unlike the observed-hash and poison maps, which descMu guards).
func (p *ManifestPDP) anyNamePinned(names []string) bool {
	for _, n := range names {
		if _, pinned := p.pinnedTools[n]; pinned {
			return true
		}
	}
	return false
}

// poisonCandidates sticky-poisons every pinned name an untrustworthy entry could present
// to a host. Scoping the poison to the entry's own candidate names — rather than every pin
// on the route — keeps the fail-closed property while bounding the blast radius: an
// unrelated malformed entry elsewhere in the catalog cannot disable pins it never named.
func (p *ManifestPDP) poisonCandidates(names []string) {
	for _, n := range names {
		if _, pinned := p.pinnedTools[n]; pinned {
			p.markToolPoisoned(n)
		}
	}
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
//
// When any pinned tool exists this is a security control, not best-effort bookkeeping: a
// tools/list it cannot reduce to a comparable hash for a pinned tool fails CLOSED by
// sticky-poisoning the affected pin(s), so the call leg denies rather than leaving the
// mid-session poisoning pin unarmed. See armPinsFromToolsList, which both this and the
// enforce-mode filter call, for exactly which shapes fail closed and how widely. With NO
// pinned tool there is nothing to protect, so the walk only counts entries.
func (p *ManifestPDP) RecordObservedToolHashes(ctx context.Context, result json.RawMessage) int {
	// The per-entry verdicts are for a caller that goes on to FILTER the same bytes; this
	// route forwards the catalog verbatim, so there is nothing to hand them to.
	count, _ := p.armPinsFromToolsList(sessionIDFromContext(ctx), result, CompleteToolListingFromContext(ctx))
	return count
}

// armPinsFromToolsList walks a tools/list result, records every pinned tool's live
// description hash, and sticky-poisons the pins it cannot verify. It is the ONE pass that
// arms the descriptionHash pin, shared by the observe route (RecordObservedToolHashes,
// where the catalog is forwarded verbatim and this is the only thing arming the pin) and
// the enforce-mode filter — so the two genuinely cannot diverge, rather than mirroring each
// other by hand. It returns the entry count (mirroring CountListEntries, so the audit
// record needs no second decode) and whether the entry array decoded.
//
// It prunes nothing and mutates no catalog: filtering is the caller's job. Running it to
// completion BEFORE any filtering is load-bearing — poisoning discovered at entry N must
// be visible to the keep decision for entry 1, or the emitted catalog could advertise a
// tool whose call leg then hard-denies.
//
// What fails closed, and how widely:
//   - An entry whose bytes are untrustworthy (scanToolEntry: a duplicate or case-variant
//     top-level key, or a duplicate nested in a hashed description) poisons only the pinned
//     names THAT ENTRY could present — never the whole route, so an unrelated malformed
//     entry cannot disable pins it never named. That narrowing holds only when the scan
//     actually enumerated the entry's names; an entry whose bytes ABORTED the scan
//     (malformed tokens, a non-string key, nesting past the depth bound) has an unknown
//     name set, not an empty one, so it poisons every pin. A provably-non-object entry
//     (null, a number, a string, an array) is the opposite case: it is untrustworthy and
//     gets filtered out, but its name set is knowably EMPTY, so it poisons nothing.
//   - An entry that will not decode into the hashed surface poisons just its own pin.
//   - An ambiguous ENVELOPE — undecodable, an undecodable tools array, or a duplicate or
//     case-variant "tools" key (Go keeps one array while a host may render the other) —
//     poisons every pin, because no entry in it can be believed. A plainly absent tools
//     key is not ambiguous: a host renders no tools from it, so nothing is poisoned.
func (p *ManifestPDP) armPinsFromToolsList(sessionID string, result json.RawMessage, completeListing bool) (entryCount int, verdicts []toolEntryVerdict) {
	pinned := p.hasPinnedTools()
	// Tier-2 arms off the same pass, so the two pins read one decode of one response and
	// cannot disagree about what the upstream advertised. It applies to EVERY tool, so
	// unlike the FM-5 gates below it is never skipped for want of a manifest pin.
	tier2 := p.surface != nil
	entries, outcome := decodeListEntries(result, listKeyTools)
	switch outcome {
	case listDecodeEmptyResult:
		// No bytes at all: nothing was rendered to a host, so nothing is ambiguous. No
		// Tier-2 baseline is taken either — an absent response must not become the
		// session's idea of the advertised surface.
		return 0, nil
	case listDecodeBadEnvelope, listDecodeBadArray:
		// The envelope or its array is unreadable, so no entry in it can be believed.
		p.poisonAllPinned()
		p.surface.BreakAll(sessionID)
		return 0, nil
	case listDecodeKeyAbsent:
		// No exact "tools" key. toolsKeyAmbiguous also catches a case-variant sibling
		// ("Tools") that still decodes for a host whose reader binds it
		// case-insensitively, and the proxy cannot tell what that host sees, so treat it
		// as ambiguous; a plainly absent key is not.
		if toolsKeyAmbiguous(result) {
			p.poisonAllPinned()
			p.surface.BreakAll(sessionID)
		}
		return 0, nil
	case listDecodeOK:
	}
	if !pinned && !tier2 {
		// Nothing to record or protect: skip the per-entry scan and decode entirely rather
		// than walking every entry only to find none pinned. No verdicts either: a filter
		// running over the same bytes must reach its own conclusions.
		return len(entries), nil
	}
	// A duplicate or case-variant "tools" key leaves Go and the host reading different
	// arrays, so no entry below can be believed.
	if toolsKeyAmbiguous(result) {
		p.poisonAllPinned()
		p.surface.BreakAll(sessionID)
		// No verdicts: the array these entries came from is not the array a host
		// necessarily reads, so nothing here may be handed to the filter as settled.
		return len(entries), nil
	}
	var surfaces []ToolSurface
	if tier2 {
		surfaces = make([]ToolSurface, 0, len(entries))
	}
	// One verdict per entry, in document order, so a filter walking the same array can
	// reuse this pass's scan and decode instead of repeating both. See toolEntryVerdict.
	verdicts = make([]toolEntryVerdict, 0, len(entries))
	for _, raw := range entries {
		scan := scanToolEntry(raw)
		if scan.untrustworthy {
			verdicts = append(verdicts, toolEntryVerdict{known: true, drop: true})
			if !scan.namesComplete {
				// The scan aborted before walking the whole entry, so its name list is
				// truncated and may be EMPTY -- a tool entry is free to put a deep
				// inputSchema before its name. Poisoning that subset would poison nothing
				// for exactly the entry that defeated the scan, leaving the pin unarmed on
				// an audit route where this pass is the only thing arming it. The pins an
				// unreadable entry could be impersonating are unknown, not none.
				p.poisonAllPinned()
				p.surface.BreakAll(sessionID)
				continue
			}
			p.poisonCandidates(scan.names)
			// Same narrowing for Tier-2: deny only the names this entry could present. An
			// entry whose bytes are ambiguous cannot be baselined at all (the proxy does
			// not know which surface the host reads), so breaking is the only fail-closed
			// option -- skipping would leave the tool unpinned for the session.
			p.surface.MarkBroken(sessionID, scan.names...)
			continue
		}
		// Decide on the NAME before paying for the decode. The unmarshal below pulls in
		// the entry's whole inputSchema -- by far the largest thing on this path -- and
		// everything the FM-5 half feeds is gated on the name being pinned:
		// recordPinnedToolHash looks the name up in pinnedTools, and the decode-failure
		// branch poisons candidates that poisonCandidates would filter to the same empty
		// set. The scan above already produced the name set, so with Tier-2 off an
		// unpinned entry (the common case on any manifest that pins one tool out of fifty)
		// can be skipped outright. Tier-2 pins EVERY advertised tool, so when it is on the
		// decode is unavoidable -- that is the cost of covering tools nobody pinned, and it
		// is paid on */list, not on the call leg.
		if !tier2 && !p.anyNamePinned(scan.names) {
			// Skipped without decoding, so this pass concluded nothing about the entry: the
			// filter must reach its own verdict rather than read an absence as a keep.
			verdicts = append(verdicts, toolEntryVerdict{})
			continue
		}
		var entry toolListEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			verdicts = append(verdicts, toolEntryVerdict{known: true, drop: true})
			// The name is trustworthy (the scan cleared it) but the entry will not decode
			// into the hashed surface: poison just this pin rather than skip, which would
			// leave it unarmed on a poisoned entry a lenient host still renders.
			p.poisonCandidates(scan.names)
			p.surface.MarkBroken(sessionID, scan.names...)
			continue
		}
		// One hash per entry, shared by both pins. FM-5 pins some tools and Tier-2 pins
		// every one, over the SAME hash of the SAME bytes — so a pinned tool's whole
		// inputSchema was being hashed twice per tools/list before this.
		surface := SurfaceHash(entry.Description, entry.Title, entry.Annotations, entry.InputSchema, entry.OutputSchema)
		p.recordPinnedToolHash(entry.Name, surface)
		verdicts = append(verdicts, toolEntryVerdict{known: true, name: entry.Name})
		if tier2 {
			surfaces = append(surfaces, ToolSurface{Name: entry.Name, Hash: surface})
		}
	}
	// One Observe per response, after the whole walk: a break discovered at entry N must
	// be visible to the keep decision for entry 1 (the caller filters only once this
	// returns), exactly as the FM-5 poisoning is.
	if tier2 {
		emitSurfaceChanges(p.surface.Observe(sessionID, surfaces, completeListing))
	}
	return len(entries), verdicts
}

// toolEntryVerdict is armPinsFromToolsList's per-entry conclusion, handed to the list
// filter so ONE pass scans and decodes each entry.
//
// The two passes asked the same two questions of every entry — are its bytes ambiguous
// (scanToolEntry), and what does it decode to (json.Unmarshal, which pulls in the whole
// inputSchema, by far the largest thing here) — and answered them separately, per entry,
// on every tools/list. With Tier-2 pinning every advertised tool that is the hottest
// catalog path there is.
//
// Sharing verdicts does NOT relax the ordering the two passes need: arming still runs to
// completion before any keep decision, because a break discovered at entry N must be
// visible to the keep decision for entry 1.
//
// known=false means "this pass concluded nothing" — arming bailed before the entry, or
// skipped decoding it — and the filter falls back to deciding for itself. Absence is never
// read as a keep: every state that could hide a drop is either known+drop or unknown.
type toolEntryVerdict struct {
	// known reports that arming actually evaluated this entry.
	known bool
	// drop reports that the entry must not be advertised: ambiguous bytes, or bytes that
	// will not decode into the hashed surface.
	drop bool
	// name is the decoded tool name, meaningful only when known && !drop.
	name string
}

// verdictAt returns the arming pass's verdict for entry index i, or the zero (unknown)
// verdict when arming produced none — a short or nil slice can only mean arming bailed
// early, and an out-of-range read must not be mistaken for a settled keep.
func verdictAt(verdicts []toolEntryVerdict, i int) toolEntryVerdict {
	if i < 0 || i >= len(verdicts) {
		return toolEntryVerdict{}
	}
	return verdicts[i]
}

// evaluateToolEntry is the fallback the filter uses for an entry arming did not conclude
// on: the same ambiguity scan and decode, in the same order, so a fallback verdict is
// indistinguishable from an armed one.
func evaluateToolEntry(raw json.RawMessage) toolEntryVerdict {
	if entryKeysAmbiguous(raw) {
		return toolEntryVerdict{known: true, drop: true}
	}
	var entry toolListEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return toolEntryVerdict{known: true, drop: true}
	}
	return toolEntryVerdict{known: true, name: entry.Name}
}

// toolsKeyAmbiguous reports whether raw's top-level JSON object carries the tools/list
// "tools" key ambiguously: duplicated, case-variant, or (when the exact spelling "tools" is
// absent) shadowed by a case-variant sibling like "Tools". A plain decode into a map keeps
// only the LAST such key, and a struct tag falls back to a case-insensitive match when the
// exact spelling is missing — either way, a host that reads the same bytes differently (a
// case-sensitive JSON.parse, or one that keeps a different duplicate) can see an entirely
// different tools array than this proxy decoded. A plainly absent key is not ambiguous: a
// host renders no tools from it either. Malformed input reports true: the caller fails
// closed.
func toolsKeyAmbiguous(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return true
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return true
	}
	exact, folded := 0, 0
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return true
		}
		key, ok := keyTok.(string)
		if !ok {
			return true
		}
		// capability.FoldJSONKey, not strings.EqualFold: EqualFold is Unicode simple
		// folding too, so there is no live divergence today, but this scan and the
		// JSON-RPC envelope scan exist to catch exactly the shape a weaker fold misses.
		// Sharing the one folding rule the other layers use (rejectDuplicateJSONKeys,
		// scanToolEntry, decodeOrderedObject) is what keeps them from drifting apart
		// independently — which is how one of them ended up on strings.ToLower before.
		switch {
		case key == listKeyTools:
			exact++
			folded++
		case capability.FoldJSONKey(key) == listKeyToolsFolded:
			folded++
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return true
		}
	}
	if folded == 0 {
		return false
	}
	return folded > 1 || exact == 0
}

// ToolsKeyAmbiguous is the exported form of the envelope-level "tools" key ambiguity gate,
// for the startup drift probe (FetchAllToolPages).
//
// armPinsFromToolsList (below) already refuses to trust an ambiguous envelope on the runtime
// list-filter path — poisoning every pin rather than believing whichever array Go's decode
// happened to keep. Before this export, the drift probe's own page decode
// (internal/drift.FetchAllToolPages, into a plain toolsListPage struct) had no equivalent
// check: a duplicate or case-variant "tools" key there silently resolved to one array with no
// error, so a poisoned catalog could pass the unconditionally-fatal FM-5 startup refusal
// cleanly, only to be caught later — and more disruptively, as a mid-session poisonAllPinned
// — once the identical bytes reached the runtime path. Exporting the same check keeps both
// layers on one rule instead of letting the drift probe silently trust a shape the runtime
// path would refuse.
func ToolsKeyAmbiguous(raw json.RawMessage) bool {
	return toolsKeyAmbiguous(raw)
}

func filterToolsListResult(resultBytes json.RawMessage, mdp *ManifestPDP, claims map[string]interface{}, chain *capability.DelegationChain, sessionID string, completeListing bool) ListFilterResult {
	// Arm the pins over the WHOLE catalog first, then filter. Recording and poisoning
	// happen here — in the one pass the observe route shares (armPinsFromToolsList) — so
	// the two routes cannot drift, and so every poison discovered anywhere in the array is
	// already visible to the keep decision for the first entry. Poisoning from inside the
	// per-entry predicate below could not retract an entry it had already accepted, which
	// would emit a catalog advertising a tool whose call leg hard-denies.
	//
	// The gate is repeated HERE, at the call site, even though armPinsFromToolsList
	// self-gates on the same predicate: its gate sits AFTER decodeListEntries, so an
	// unpinned manifest — the common shape — otherwise paid a full envelope decode plus a
	// tools-array decode whose result this caller discards. Moving the early-out inside
	// the callee cannot help, because the OTHER caller (RecordObservedToolHashes) needs
	// the entry count that decode produces; only a caller that discards the count can
	// skip the work, and only the caller knows that.
	//
	// Skipping is semantics-preserving because every effect of the function — each poison
	// branch and the per-entry loop — is behind hasPinnedTools, and this caller ignores the
	// return value. That is a property of the callee, not a coincidence: if
	// armPinsFromToolsList ever gains an effect on the UNPINNED path, this gate silently
	// skips it on the enforce route while the observe route still runs it, so this gate
	// must be removed in the same change. Both sides read one predicate so the pairing is
	// at least visible.
	//
	// Tier-2 widens the gate: it pins every advertised tool, so there is always something
	// to arm and the skip applies only to a PDP with neither pin active (a directly
	// constructed one, where surface is nil).
	var verdicts []toolEntryVerdict
	if mdp.hasPinnedTools() || mdp.surface != nil {
		_, verdicts = mdp.armPinsFromToolsList(sessionID, resultBytes, completeListing)
	}

	// Entry index within the array, advanced once per keep call. filterListResult walks
	// the array it decoded from these same bytes in document order, single-threaded, and
	// arming returns verdicts only for an unambiguous envelope carrying exactly one
	// "tools" array — the one case where both passes provably see the same array — so the
	// index aligns. Any misalignment degrades to an unknown verdict, which re-derives.
	entryIdx := -1
	return filterListResult(resultBytes, listKeyTools, func(raw json.RawMessage) (bool, string) {
		entryIdx++
		// Drop an entry whose own bytes are ambiguous BEFORE trusting its decoded name.
		// armPinsFromToolsList self-gates on len(pinnedTools) > 0, so without this the
		// entire fold defense would be inert on the common manifest that pins no
		// descriptionHash: an entry carrying both "name" and "Name" is kept under Go's
		// decoded (last-wins) name while a case-sensitive host renders the other, so the
		// proxy advertises a tool it never authorized and its description — the FM-5
		// injection surface — reaches the model. Catalog integrity does not depend on
		// whether the operator opted into pins, so the check does not either.
		//
		// The scan and the decode happen ONCE per entry: arming already performed both and
		// handed over its conclusion (see toolEntryVerdict). An entry it did not conclude
		// on is evaluated here, by the same rules in the same order.
		v := verdictAt(verdicts, entryIdx)
		if !v.known {
			v = evaluateToolEntry(raw)
		}
		if v.drop {
			return false, ""
		}
		// Hidden when the caller's delegation chain does not reach it, mirroring the call
		// leg's own delegation gate so the catalog never advertises a tool this delegate
		// will be refused. Placed before the constraint lookup because it does not need
		// one: the chain bounds the caller regardless of what the manifest says.
		// Guarded on IsEmpty() for the same reason keepByManifestEntry is: the string concat
		// naming the target would otherwise be built on every entry, on every request, even
		// for the overwhelming majority that carry no delegation chain at all.
		if !chain.IsEmpty() {
			if permitted, _ := chain.PermitsTarget("tool:" + v.name); !permitted {
				return false, ""
			}
		}
		c := mdp.findConstraint(EnforceTarget{Type: capability.TargetTypeTool, Name: v.name}, claims)

		// c is nil when the tool is absent from the manifest; guard every dereference
		// below on it.
		if c == nil || !containsAction(c.Actions, "call") {
			return false, ""
		}
		// A poisoned pinned tool stays hidden even on a later clean observation (sticky),
		// mirroring the call-leg deny so the list a host is shown never contains a tool
		// its call leg will reject.
		if _, pinned := mdp.pinnedTools[v.name]; pinned && mdp.isToolPoisoned(v.name) {
			return false, ""
		}
		// Same rule for the Tier-2 pin, which needs no manifest entry: a tool whose
		// advertised surface changed mid-session is hidden here as well as denied on the
		// call leg, so the catalog a host is shown never advertises a tool the call leg
		// will reject.
		//
		// TOOLS ONLY, deliberately stated: neither this pin nor the manifest's
		// descriptionHash covers prompt or resource descriptions, which reach the model
		// the same way a tool description does. The machinery is generic over (name,
		// hash), so extending it is a design decision rather than a rewrite — but until
		// that is made, the two other list flavors carry only the per-entry ambiguity
		// gate, not a surface pin.
		if mdp.surface.Broken(sessionID, v.name) {
			return false, ""
		}
		return true, v.name
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
func filterPromptsListResult(resultBytes json.RawMessage, mdp *ManifestPDP, claims map[string]interface{}, chain *capability.DelegationChain) ListFilterResult {
	// Shares keepByManifestEntry with resources/list, so the entry-ambiguity gate cannot
	// be present on one flavor and missing on the other: a prompt entry carrying both
	// "name" and "Name" would otherwise be kept under Go's decoded name while a host
	// renders the other, and a prompt description reaches the model exactly as a tool
	// description does. All three list flavors share the FM-5 surface.
	return filterListResult(resultBytes, listKeyPrompts,
		keepByManifestEntry(mdp, claims, chain, capability.TargetTypePrompt, "get", func(raw json.RawMessage) (string, bool) {
			var entry struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &entry); err != nil {
				return "", false
			}
			return entry.Name, true
		}))
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
	return c.flatMap()
}

// flatMap is jwtClaimsAsMap for a caller that already holds the *JWTClaims — the JWT
// PDP's own decision path, which reads the claims off its validated token rather than
// back out of the context. Same memoized map, same read-only contract; nil-safe so a
// caller need not branch.
func (c *JWTClaims) flatMap() map[string]interface{} {
	if c == nil {
		return nil
	}
	if c.flatClaims != nil {
		return c.flatClaims
	}
	// A JWTClaims built without ValidateToken (e.g. tests) has no memoized map. Never
	// stored — the *JWTClaims may be shared across a session's requests.
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
