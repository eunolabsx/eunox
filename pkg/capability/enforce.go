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
// conditions, Peek backs sequenceBlock, IncrementIfBelow / IncrementIfAllBelow back
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

	// IncrementIfAllBelow is the multi-bucket analogue of IncrementIfBelow: it
	// records all of SEVERAL maxCalls buckets only when every one is strictly below
	// its limit (admitted=true), otherwise records NOTHING (admitted=false) with
	// deniedIndex naming a blocking bucket, count its total, and retryAfter its
	// estimate. It exists so a constraint with more than one maxCalls cannot
	// over-admit by racing the check->commit gap a per-bucket commit would leave.
	// keys, windowSecs, and limits are parallel and must share one non-zero length;
	// each limit must be >= 1 and each windowSec in range, else it fails closed and
	// records nothing. The single-bucket path stays on IncrementIfBelow.
	IncrementIfAllBelow(ctx context.Context, keys []string, windowSecs []int, limits []int64) (admitted bool, deniedIndex int, count int64, retryAfter time.Duration, err error)
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
