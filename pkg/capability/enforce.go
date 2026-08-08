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
	// TargetName identifies what is being enforced, in the OPTIONALLY PREFIXED spelling
	// the caller used: a bare tool name, an explicitly namespaced one ("tool:read_file"),
	// a resource URI, a prompt, or a system target. A bare name defaults to the tool
	// namespace. Deliberately NOT called ToolName since every namespace arrives here, not
	// just tools; Target carries the same identity already split into (type, name) — prefer
	// it when set.
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
	// DeclassifyApprovals carries the human approvals the request's VERIFIED token
	// granted (the `mcp.declassify` claim), already parsed and validated. They are the
	// only thing that lets a declassify directive clear a flow label instead of
	// escalating. Empty on every request that is not a declassification — including every
	// request with no token at all, which is why a deployment with no approval integration
	// escalates rather than silently declassifying.
	//
	// It is a typed field rather than a lookup into Claims for the same reason
	// DeclaredLabels is: the engine must not re-derive a security-critical input from an
	// untyped claim map on the hot path, where a decode slip reads as "no approval"
	// (harmless) or "some approval" (not).
	DeclassifyApprovals []DeclassifyApproval `json:"declassifyApprovals,omitempty"`
	// Delegation carries the attenuation the request's VERIFIED token declared across a
	// delegation chain (its RFC 8693 `act` actors and its `mcp.delegation` grants), already
	// decoded, validated, and asserted to narrow at every hop. Nil for every non-delegated
	// request, which is nearly all of them.
	//
	// Like DeclassifyApprovals it is a typed field rather than a lookup into Claims, and for
	// the same reason: every axis it carries bounds the decision, so re-deriving it from an
	// untyped claim map on the hot path would put a decode slip between the operator's
	// narrowing and its enforcement. See delegation.go.
	Delegation *DelegationChain `json:"delegation,omitempty"`
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
	// Declassification is the authorized second phase of a flow-label clear: the labels an
	// APPROVED declassify directive may remove, plus the approval that authorized them. Nil
	// when nothing was authorized (the common case).
	//
	// AUTHORIZED, not applied, is the load-bearing distinction: the clear is performed by the
	// CALLER via CommitDeclassification once the call has actually run. Applying it inside
	// the decision would make the labels invisible to concurrent decisions for the whole
	// upstream round trip, letting a sink the taint exists to stop be forwarded while the
	// sanitizing call is still in flight. The handle is the ONLY thing the commit accepts —
	// its authorized set is unexported, so the second phase cannot clear more than the first
	// authorized — and a caller that never commits leaves the session as tainted as it found
	// it (fail-closed).
	//
	// In-process only (json:"-"): a stateful, single-use decision artifact for the caller. The
	// audit record's own top-level, HMAC-signed labels_cleared/approver/approval_id fields
	// report what the commit actually CHANGED, never what was merely authorized here.
	Declassification *Declassification `json:"-"`
	// Effect is the contract the decision resolved against this call's arguments, stamped on
	// an ALLOW so the effect-receipt verifier can compare what a server ATTESTS it did
	// against what policy DECLARED — without this, that comparison would have to re-resolve
	// the contract, a second resolution that could silently disagree with the first.
	//
	// In-process only (json:"-"), like HardDeny: a decision artifact for the transport, not a
	// wire field.
	Effect *ResolvedEffect `json:"-"`
	// HandlerFaults names the condition types whose registered handler broke an engine contract
	// in a direction the engine REPAIRED. THE one statement of that repair, which every other
	// site cites rather than re-derives:
	//
	// The engine owns the only place a quota is consumed, so a handler that derives a bucket
	// where the request authorizes no consumption is answered by dropping the bucket — the
	// outcome a conforming handler produces for that posture, so the call is decided exactly as
	// it would have been. Refusing instead would charge a caller for a plugin's bug, and would
	// do it on the one posture that reaches the fault at all, whose whole contract is that it
	// never blocks. A fault the engine CANNOT repair (one that leaves a declared restriction
	// unevaluated) is a denial, never an entry here.
	//
	// Repaired is not tolerated: the transport stamps this onto the record so an operator sees
	// the bug. It rides whatever record the decision produces, allow or deny — a fault is a
	// fact about the decision, not about its verdict, and the posture that produces one is the
	// posture where a deny is forwarded rather than blocking.
	//
	// Nil on every call in a healthy deployment. In-process only (json:"-"), like the two
	// fields above.
	HandlerFaults []HandlerFault `json:"-"`
}

// HandlerFault names one repaired violation: WHICH registered handler misbehaved, and WHICH
// contract it broke. Both, because the second is what an operator acts on — a report naming
// only the condition type is unambiguous exactly while one repairable violation exists, and
// stops being so the day a second does, with the records already written by then.
//
// The asymmetry it removes: the refused half of the same contract produces a full
// *ConditionError (code, condition type, and a message naming the violated contract) while the
// repaired half appended a bare string. Two halves of one contract, two data shapes.
type HandlerFault struct {
	// Type is the condition discriminator whose registered handler broke the contract.
	Type string `json:"type"`
	// Contract names what it broke, from the closed set below rather than as prose: this
	// value is what an operator's alert keys on.
	Contract HandlerContract `json:"contract"`
}

// HandlerContract is the closed vocabulary of engine contracts a registered handler can break
// in a direction the engine REPAIRS. A violation the engine cannot repair is a denial with its
// own code and message, never an entry here — see [EnforceResponse.HandlerFaults].
type HandlerContract string

// HandlerContractQuotaUnderSkip is the one repairable violation this build has: a committing
// handler derived a quota bucket for a request whose context authorized no consumption
// (observe mode). The engine drops the bucket, which is the outcome a conforming handler
// produces for that posture.
const HandlerContractQuotaUnderSkip HandlerContract = "quota_bucket_under_skip_quota"

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
// Every method is mandatory: IncrementAndGet backs the counting conditions, Peek backs
// sequenceBlock, and AdmitAll backs every quota bound. Folding them into one contract means
// a backend that omits any fails to satisfy CallCounter at compile time rather than wiring
// up cleanly and failing conditions closed at runtime. A custom backend pins conformance
// with `var _ capability.CallCounter = (*MyCounter)(nil)`.
//
// There is exactly ONE admission primitive (AdmitAll) on purpose: it replaced two
// single-bucket forms that could each be independently correct while quietly diverging from
// each other, a drift nothing on the decision path would exercise. A backend author writes
// one admission and every quota bound rides it.
type CallCounter interface {
	// IncrementAndGet records a call and returns the in-window count, retaining at
	// most maxEntries most-recent in-window timestamps so storage stays bounded
	// under sustained traffic. maxEntries must be >= 1.
	IncrementAndGet(ctx context.Context, key string, windowSec, maxEntries int) (int64, error)

	// Peek reports a key's in-window count WITHOUT recording a call, so
	// sequenceBlock can ask "was tool A already called this session?" without the
	// lookup itself counting.
	Peek(ctx context.Context, key string, windowSec int) (int64, error)

	// AdmitAll is the ONE quota admission: records all buckets only when every one has
	// headroom (admitted=true), otherwise records NOTHING (admitted=false), with
	// deniedIndex naming the blocking bucket, total its resulting total, and retryAfter an
	// estimate. A multi-bucket batch admits mixed accountings (entry-counted maxCalls,
	// weight-summed cumulative blastRadius) atomically, so "20 refunds/hr AND $2,000/hr" is
	// one commit rather than two that could let one budget spend past the other.
	//
	// An over-limit call records NOTHING (retrying must not extend the lockout or grow the
	// store). buckets must be non-empty, each valid, and no two may share a (Key,
	// WindowSec) — a malformed batch fails closed.
	//
	// PRECISION: a weighted total accumulates in IEEE-754 double precision to match the
	// Redis backend's Lua arithmetic, so an in-process backend stays consistent with it
	// rather than being independently exact and therefore disagreeing.
	AdmitAll(ctx context.Context, buckets []QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error)
}

// MaxWeightedTotal is the largest weighted total a CallCounter backend represents exactly,
// and therefore the largest limit — and largest single weight — a QuotaBucket accepts.
//
// It is 2^53 because the Redis backend evaluates admission in Lua (IEEE-754 doubles), so a
// larger value would silently round to a threshold the operator never authored. Lives on
// the contract, not a backend package, because the manifest loader, the engine, and each
// backend all apply it to the same input class.
const MaxWeightedTotal float64 = 1 << 53

// QuotaBucket is one quota-consuming admission in a multi-condition commit: the sliding
// window it draws on, what this call contributes, and the bound the resulting total must
// not exceed.
//
// Counted changes the ACCOUNTING for cost, not expressiveness: a counted bucket's total is
// O(1) (entry count), a weighted bucket's is O(n) (summed magnitudes). maxCalls could be a
// weighted bucket with every weight 1, but folding them would make every rate-limit check
// (documented to reach the millions) pay a linear scan it doesn't need.
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
	//
	// A COUNTED bucket's limit is additionally a number of calls: it must be a whole number
	// and at least 1. Both halves are enforced, and neither follows from being a positive
	// float64 — a bound below 1 can never admit, which is a misconfiguration a backend must
	// report as one rather than as an exhausted quota, and a fractional bound makes a
	// backend deriving its retry pivot arithmetically (Redis does) fault where an in-process
	// one merely denies.
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
	// call's flow write when the paired sequenceBlock antecedent write then faults.
	// That rollback is a compensating delete against SHARED state, so the engine
	// performs it only where no other caller can be writing the same key — see
	// Engine.rollbackLabels, which declines it for a task-anchored request rather
	// than relying on an ordering guarantee it cannot see. An empty labels list is a
	// no-op.
	Remove(ctx context.Context, sessionKey string, labels ...string) error

	// Clear releases the session's entire set, called from the transport's session
	// teardown so an ended session retains no state and a reused session id starts
	// clean. Clearing an absent session is a no-op.
	Clear(ctx context.Context, sessionKey string) error
}
