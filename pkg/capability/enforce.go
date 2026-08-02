// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"context"
	"time"
)

// EnforceRequestTarget identifies the namespace type and bare name of the
// resource being enforced. Set by ManifestPDP.Decide before condition evaluation
// and made available as input.target in Rego policy conditions.
type EnforceRequestTarget struct {
	// Type is the namespace prefix: "tool", "resource", "prompt", or "system".
	Type string `json:"type"`
	// Name is the bare resource name after the namespace prefix is stripped.
	Name string `json:"name"`
}

// EnforceRequest is the input payload for runtime capability enforcement.
type EnforceRequest struct {
	SessionID string `json:"sessionId"`
	// TargetName identifies what is being enforced, in the OPTIONALLY PREFIXED
	// spelling the caller used: a bare tool name ("read_file"), an explicitly
	// namespaced one ("tool:read_file"), a resource URI ("resource:file:///etc/hosts"),
	// a prompt ("prompt:summarize"), or a system target
	// ("system:sampling/createMessage"). A bare name defaults to the tool namespace.
	//
	// It is deliberately NOT tool-only — every namespace the proxy enforces arrives
	// here — which is why it is not called ToolName: under that name the field read as
	// a tool identifier while carrying resource URIs and system targets, so every
	// helper reconciling it with Target had to spend a paragraph on the mismatch.
	// Target carries the same identity already SPLIT into (type, bare name) and is set
	// by every ManifestPDP entry point; prefer it when you have it, and treat this
	// field as the caller-supplied spelling to be split (splitEnginePrefix) or matched
	// verbatim.
	TargetName string                 `json:"targetName"`
	Arguments  map[string]interface{} `json:"arguments"`
	Context    EnforceRequestContext  `json:"context"`
	// Target carries the namespace type and bare name of the resource being
	// enforced. Populated by ManifestPDP.Decide; available as input.target in
	// Rego policy conditions. Nil when not set.
	Target *EnforceRequestTarget `json:"target,omitempty"`
	// Claims carries the JWT capability claims from the authenticated token,
	// keyed by claim name (e.g. "sub", "iss", "task_id", "agent_id").
	// Available as input.claims in Rego policy conditions. Empty map when no
	// JWT is present in the request context.
	Claims map[string]interface{} `json:"claims,omitempty"`
	// Directives optionally carries post-allow obligations exposed as
	// input.directives in Rego (always [] there, never null). The engine does NOT
	// write this field — it threads the matched constraint's directives through the
	// context instead, so it never mutates a shared caller request (a data race). A
	// direct BuildRegoInput caller may set it to surface directives itself.
	Directives []Directive `json:"directives,omitempty"`
	// DeclaredLabels carries a cooperating client's per-call attribution (the
	// `io.eunolabs.context-manifest` block in the request's `_meta`): native flow labels
	// it asserts THIS call's inputs carry. They are UNIONED into the session's
	// accumulated set for this call's sink check and are never written into session
	// state. Union-only is the security property, not a simplification — see
	// attribution.go. Empty for every non-cooperating client, which is the default and
	// costs nothing.
	DeclaredLabels []string `json:"declaredLabels,omitempty"`
}

// EnforceRequestContext carries request attributes used during enforcement.
// Tool argument values are passed via EnforceRequest.Arguments — condition
// handlers read the specific parameter they need by name via the condition's
// Argument field rather than relying on pre-extracted context.
type EnforceRequestContext struct {
	SourceIP string `json:"sourceIp,omitempty"` // used by ipRange condition
	Now      string `json:"now,omitempty"`      // fallback for input.context.timestamp in policy conditions when the engine has not stamped one via context
}

// TableAccess describes the table and columns accessed by a request. Used
// internally by the enforcement engine's allowedTables condition handler, which
// derives it by parsing the named tool argument identified by the condition's
// Argument field (see parseTableArgument in pkg/enforcement).
type TableAccess struct {
	Table   string   `json:"table"`
	Columns []string `json:"columns,omitempty"`
}

// EnforceResponse reports the decision and any obligations from enforcement.
type EnforceResponse struct {
	RequestID string   `json:"requestId"`
	Decision  Decision `json:"decision"`
	// AuditOnly is set when the matched constraint is in audit (observe) mode: the
	// Decision reports the true verdict, but a Deny should be logged and forwarded
	// rather than enforced. The engine stamps it on every deny for a matched
	// constraint; the PDP stamps it for its own paths (allow, action-mismatch) that
	// bypass the engine. Never set for kill-switch, no-match, or JWT-intersection
	// denials.
	AuditOnly   bool         `json:"auditOnly,omitempty"`
	Obligations []Obligation `json:"obligations,omitempty"`
	Denial      *DenialInfo  `json:"denial,omitempty"`
	DecidedAt   string       `json:"decidedAt"`
	// LabelsOut is the set of native flow labels this call's output asserted into the
	// session (from its labelOutput directives), and CarriedLabels is the session's
	// accumulated label set observed at decision time (before this call's own output
	// is added). Both are populated by the engine only for flow-relevant constraints
	// (those carrying a flowLabel condition or a labelOutput directive) and are stamped
	// onto the audit record so a source->sink flow reconstructs from the tape. Sorted
	// in the fixed vocabulary order for a deterministic record; nil on a non-flow call.
	LabelsOut     []string `json:"labelsOut,omitempty"`
	CarriedLabels []string `json:"carriedLabels,omitempty"`
	// Effect is the contract the decision resolved against this call's arguments, stamped
	// on an ALLOW so a post-hoc check has the declaration in hand. Its one consumer is the
	// effect-receipt verifier, which compares what a server ATTESTS it did against what
	// policy DECLARED it would do; without the declaration threaded here, that comparison
	// would have to re-resolve the contract from the matched constraint, and a second
	// resolution is a place for the decision and the check to silently disagree about what
	// the call's effect was.
	//
	// In-process only (json:"-"), like HardDeny: it is a decision artifact for the
	// transport, not a wire field, and the audit record carries the effect's own rendered
	// details rather than this struct.
	Effect *ResolvedEffect `json:"-"`
}

// Decision identifies the enforcement outcome.
type Decision string

// Enforcement decision values.
const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	// DecisionEscalate marks an action the policy would permit but whose CONSEQUENCE
	// exceeds the effectCeiling: it needs human approval, not a policy verdict.
	//
	// It is not a third forwarding state. Every forward gate in the proxy tests
	// `!= DecisionAllow`, so an escalation is NOT forwarded — the fail-closed reading
	// of "escalate" with no approval integration wired is "deny, and say why". What it
	// changes is the RECORD and the reason: the tape carries decision=escalate and the
	// consequence inputs (class, blast radius, compensating action), so an auditor —
	// or a control plane driving an approval workflow — can tell an action awaiting a
	// human from one policy forbids outright.
	DecisionEscalate Decision = "escalate"
)

// DenialInfo describes why enforcement denied a request.
type DenialInfo struct {
	Code          string                 `json:"code"`
	ConditionType string                 `json:"conditionType"`
	Message       string                 `json:"message"`
	Details       map[string]interface{} `json:"details,omitempty"`
	// HardDeny marks a deny that must not be downgraded to an audit-mode forward
	// even when the matched constraint is in audit-only mode or the route runs
	// under --audit. Analogous to a kill-switch denial; used by
	// recordAuditModeAntecedent when RecordSessionCall fails and the sequenceBlock
	// integrity guarantee can no longer be upheld.
	HardDeny bool `json:"-"` // transport-only signal; never written to the audit record
}

// CallCounter tracks per-key invocation counts within a sliding time window.
// Implementations must be safe for concurrent use.
//
// Every method is mandatory — the full contract WithCallCounter accepts, not a
// core with optional type-asserted extensions: IncrementAndGet backs the counting
// conditions, Peek backs sequenceBlock, IncrementIfBelow / AdmitAll back
// maxCalls. Folding them into one contract means a backend that omits any fails to
// satisfy CallCounter at compile time, rather than wiring up cleanly and then
// failing every maxCalls/sequenceBlock condition closed at runtime. A custom
// backend pins conformance with `var _ capability.CallCounter = (*MyCounter)(nil)`.
type CallCounter interface {
	// IncrementAndGet records a call and returns the in-window count, retaining at
	// most maxEntries most-recent in-window timestamps so storage stays bounded
	// under sustained traffic. maxEntries must be >= 1.
	IncrementAndGet(ctx context.Context, key string, windowSec, maxEntries int) (int64, error)

	// Peek reports a key's in-window count WITHOUT recording a call, so
	// sequenceBlock can ask "was tool A already called this session?" without the
	// lookup itself counting.
	Peek(ctx context.Context, key string, windowSec int) (int64, error)

	// IncrementIfBelow atomically records a call only when fewer than limit calls
	// are already in the window, so an over-limit (denied) call never writes a new
	// entry — maxCalls requires this to avoid the unbounded growth and self-
	// extending lockout a plain increment-then-compare caused. admitted reports
	// whether the call was recorded; count is the in-window total; retryAfter
	// estimates the time until a slot frees on a denial. limit must be >= 1.
	IncrementIfBelow(ctx context.Context, key string, windowSec int, limit int64) (count int64, admitted bool, retryAfter time.Duration, err error)

	// AdmitAll is the multi-bucket analogue of the two single-bucket admissions above: it
	// records all of SEVERAL quota buckets only when every one has headroom
	// (admitted=true), otherwise records NOTHING (admitted=false) with deniedIndex naming a
	// blocking bucket, total its resulting total, and retryAfter its estimate. It exists so
	// a constraint carrying more than one quota-consuming condition cannot over-admit by
	// racing the check->commit gap a per-bucket commit would leave.
	//
	// The buckets may MIX accountings. A QuotaBucket either counts entries (maxCalls) or
	// sums magnitudes (a cumulative blastRadius bound), and one call to this method admits
	// both kinds together atomically. That is the whole point: "no more than 20 refunds an
	// hour AND no more than $2,000 an hour" is one natural policy, and committing the two
	// separately would let a call the second denies spend the first's budget.
	//
	// buckets must be non-empty, each bucket valid (see QuotaBucket), and no two may address
	// the same (Key, WindowSec) — two buckets sharing one physical key cannot be committed
	// consistently. A malformed batch fails closed and records nothing.
	AdmitAll(ctx context.Context, buckets []QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error)

	// AddIfTotalBelow is the WEIGHTED sibling of IncrementIfBelow: it atomically adds
	// weight to a key's in-window total only when the resulting total would not exceed
	// limit, so an over-limit call writes NOTHING. It backs the cumulative blastRadius
	// bound — "no more than $2,000 of refunds an hour" — which per-call authorization
	// structurally cannot see: four hundred individually-permitted $10 refunds are each
	// legal and only the aggregate is catastrophic.
	//
	// It is a generalization of the counting methods above rather than a second
	// accounting system: maxCalls is this with every weight equal to 1. It lives on this
	// one contract for that reason, and is a MANDATORY method by the same convention the
	// rest obey — a backend that omitted it would fail every velocity condition closed at
	// runtime instead of failing to compile.
	//
	// The counting methods are nonetheless kept separate, deliberately: a count is O(1)
	// in every backend (ZCARD, a slice length) while a weighted total is O(n) in the
	// window (the per-entry weights have to be summed), so folding maxCalls onto this
	// would make every rate-limit check pay a linear scan it does not need.
	//
	// total is the post-add total when admitted and the current total when denied.
	// retryAfter estimates when enough weight ages out for THIS call's weight to fit.
	// weight must be finite and non-negative; limit must be finite and in
	// (0, MaxWeightedTotal] — the bound at which both backends still represent a total
	// exactly. Out-of-range inputs fail closed with a structured error and write nothing,
	// so a misconfigured bound stays distinguishable from an exhausted one.
	//
	// PRECISION. Both backends accumulate in IEEE-754 double precision, in timestamp
	// order, deliberately: the Redis backend's Lua arithmetic is float64 and nothing
	// else is available there, so making the in-memory backend exact would be the two
	// backends disagreeing rather than one of them being right. Every total below
	// MaxWeightedTotal composed of integral magnitudes is exact; a fractional magnitude
	// (a currency amount) can differ from an exact decimal sum in the last bits, far
	// below any bound an operator authors.
	AddIfTotalBelow(ctx context.Context, key string, windowSec int, weight, limit float64) (total float64, admitted bool, retryAfter time.Duration, err error)
}

// MaxWeightedTotal is the largest weighted total a CallCounter backend represents exactly,
// and therefore the largest limit — and largest single weight — AddIfTotalBelow accepts.
//
// It is 2^53 for the same reason the counting limit is: the Redis backend evaluates its
// admission in Lua, whose numbers are IEEE-754 doubles, so a larger value would be
// silently rounded to a threshold the operator never authored. No real cumulative bound
// approaches it — a $2,000-per-hour refund ceiling is thirteen orders of magnitude below.
//
// It lives on the CONTRACT rather than in a backend package because three layers apply it
// to the same input class: the manifest loader (rejecting an unrepresentable authored
// bound), the engine (refusing to sum a magnitude it would have to round), and each
// backend (its own fail-closed guard). A bound every layer "mirrors" is exactly the guard
// that ends up missing from one of them.
const MaxWeightedTotal float64 = 1 << 53

// QuotaBucket is one quota-consuming admission in a multi-condition commit: the sliding
// window it draws on, what this call contributes, and the bound the resulting total must
// not exceed.
//
// Counted is the one field that changes the ACCOUNTING, and it exists for cost rather than
// expressiveness. A counted bucket's total is the number of entries in the window, which
// every backend answers in O(1) (a ZCARD, a slice length); a weighted bucket's total is the
// sum of the per-entry magnitudes, which is O(n). maxCalls is a weighted bucket with every
// weight equal to 1, so the two could be one — but folding them would make every rate-limit
// check pay a linear scan it does not need, and a maxCalls quota is documented to reach the
// millions. Declaring the accounting per bucket keeps one commit path without that cost.
type QuotaBucket struct {
	// Key is the caller-namespaced counter key; WindowSec the sliding window it is
	// counted over. Together they address one physical bucket.
	Key       string
	WindowSec int
	// Counted selects entry-counting over weight-summing. Weight is ignored when set: a
	// counted call contributes exactly one entry.
	Counted bool
	// Weight is this call's contribution to a weighted total. Must be finite,
	// non-negative, and at most MaxWeightedTotal. A weight that cannot move the total is
	// admitted but not recorded — it can never affect a future decision, and recording it
	// is the one case that would grow a key without bound.
	Weight float64
	// Limit is the largest total the bucket may hold after this call. Must be positive and
	// at most MaxWeightedTotal.
	Limit float64
}

// FlowLabelStore holds each session's accumulated information-flow-control label
// set — the source->sink provenance state a labelOutput directive writes and a
// flowLabel condition reads. It is a seam distinct from CallCounter because
// provenance has a different contract than counting: it is a MONOTONIC per-session
// set with a SESSION-SCOPED lifetime, not a decaying sliding-window count. The
// CallCounter's window ages a taint out mid-session (a fail-open the flow-control
// "for all flows" claim cannot tolerate), so flow state lives here instead. See
// pkg/flowlabelstore.
//
// Implementations must be safe for concurrent use. The sessionKey is opaque and
// already namespaced by the caller (the engine folds its route namespace and the
// session id into it, mirroring the CallCounter key discipline), so a shared
// backend keeps gateway routes and sessions disjoint. All methods fail closed:
// a backend fault surfaces as an error the engine turns into a deny (an
// unreadable source->sink state must never be mistaken for "clean context").
//
// A custom backend pins conformance with
// `var _ capability.FlowLabelStore = (*MyStore)(nil)`.
type FlowLabelStore interface {
	// Add unions labels into the session's accumulated set (idempotent — adding a
	// label already present is a no-op). An empty labels list is a no-op. A backend
	// that reclaims idle keys by TTL refreshes it here, so an active session never
	// expires while it keeps emitting labels.
	Add(ctx context.Context, sessionKey string, labels ...string) error

	// Get returns the session's accumulated set (SET semantics: deduplicated,
	// order unspecified — the engine reorders into the canonical vocabulary order).
	// An absent session returns an empty slice and a nil error, never an error. A
	// TTL-reclaiming backend refreshes the idle TTL here too, so reading a live
	// session's taint keeps it alive.
	Get(ctx context.Context, sessionKey string) ([]string, error)

	// Remove deletes the named labels from the session's set (idempotent — removing
	// an absent label is a no-op). It backs the fail-closed rollback of a source
	// call's flow write when the paired sequenceBlock antecedent write then faults:
	// the per-session decision lock makes this rollback race-free, so it removes
	// exactly the labels the faulted call added and never a concurrent source's. An
	// empty labels list is a no-op.
	Remove(ctx context.Context, sessionKey string, labels ...string) error

	// Clear releases the session's entire set, called from the transport's session
	// teardown so an ended session retains no state and a reused session id starts
	// clean. Clearing an absent session is a no-op.
	Clear(ctx context.Context, sessionKey string) error
}
