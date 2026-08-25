// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

// Symbolic error codes for denial responses.
const (
	ErrCodeAuthorizationFailed = "AUTHORIZATION_FAILED"
	ErrCodeCapabilityDenied    = "CAPABILITY_DENIED"
	// ErrCodeInvalidParams indicates a structural argument validation failure
	// (argumentSchema). It maps to JSON-RPC -32602. argumentSchema failures
	// take precedence over condition failures.
	ErrCodeInvalidParams   = "INVALID_PARAMS"
	ErrCodeConditionFailed = "CONDITION_FAILED"
	// ErrCodeKillSwitch denies a request whose session or agent has been killed.
	// ErrCodeKillSwitchError denies when the kill-switch backend itself errors —
	// the proxy fails closed rather than treating an error as "not blocked".
	ErrCodeKillSwitch      = "KILL_SWITCH"
	ErrCodeKillSwitchError = "KILL_SWITCH_ERROR"
	ErrCodeMissingContext  = "MISSING_CONTEXT"
	ErrCodeRateLimited     = "RATE_LIMITED"
	// ErrCodeNoJWTClaims is returned by JWTPDP when no validated token claims are
	// present in the request context. It is an authentication failure, not a
	// capability miss, and maps to -32001 (AUTHORIZATION_FAILED).
	ErrCodeNoJWTClaims = "NO_JWT_CLAIMS"
	// ErrCodeOperationNotPermitted and ErrCodeValueNotPermitted are returned when
	// an allowedOperations or allowedValues condition rejects a call, by both the
	// enforcement engine and the JWTPDP so the symbolic code is path-independent.
	// They map to -32003 (as CONDITION_FAILED). A value simply outside the
	// permitted set — including a non-string scalar matching no allowed value — is
	// a permitted-set miss, not "malformed". Structural failures stay distinct: an
	// absent/empty argument denies with MISSING_CONTEXT, and an allowedOperations
	// condition missing its 'argument' field with CONDITION_FAILED.
	ErrCodeOperationNotPermitted = "OPERATION_NOT_PERMITTED"
	ErrCodeValueNotPermitted     = "VALUE_NOT_PERMITTED"
	// ErrCodeEnforcementError is the fail-closed code for a request that can be neither
	// allowed nor cleanly rejected BY POLICY: the engine, one of its backends, or a
	// registered handler failed in a way that left a declared restriction unevaluated.
	// It is the fault half of [ClassifyDenialCode] — the distinction an operator filtering
	// the tape needs in order to tell "the caller hit their budget" from "the budget could
	// not be evaluated" — so a condition path that cannot reach a verdict denies with THIS
	// rather than with the policy-verdict CONDITION_FAILED. The PDP and transport layers
	// emit it for their own fail-closed paths (a redaction failure, an undelivered
	// server-initiated request, a malformed */list response). Maps to JSON-RPC -32603.
	ErrCodeEnforcementError = "ENFORCEMENT_ERROR"
	// ErrCodeAuditUnavailable denies an otherwise-authorized call under
	// --require-audit=strict when the audit trail has degraded (a record dropped
	// under back-pressure, or a log write failed): a call that cannot be durably
	// recorded must not be forwarded. It is a server-side availability failure, not
	// a policy denial, so it maps to JSON-RPC -32603, keeping it distinct from the
	// -32001/-32002/-32003 policy codes.
	ErrCodeAuditUnavailable = "AUDIT_UNAVAILABLE"
	// ErrCodeSamplingDenied denies a server-initiated sampling/createMessage call
	// policy does not permit (no sampling entry in the manifest, or a JWT claim
	// withholds it). On the wire it surfaces as AUTHORIZATION_FAILED (-32001) for the
	// upstream initiator (forwardServerRequest's hard deny), distinct from the
	// host-facing -32002 capability denials; the symbolic SAMPLING_DENIED is what the
	// audit tape records. Exported (not a bare literal at the PDP call sites) so a
	// typo cannot diverge the wire/audit code, and denialToJSONRPCCode maps it
	// explicitly to -32001 so the wire code, the mapping, and the docs stay in lockstep.
	ErrCodeSamplingDenied = "SAMPLING_DENIED"
	// ErrCodeEscalationRequired refuses an action needing human approval rather than a
	// policy verdict alone: either an effectCeiling escalation (consequence exceeds the
	// bound).
	// It is a REFUSAL, not a pending state — fail-closed to "not forwarded".
	//
	// A ceiling escalation is not satisfiable by retrying (it escalates again until the
	// ceiling or contract changes); an approval-gated escalation IS, once a token carrying a
	// covering approval is presented — the audit record's condition_type distinguishes
	// them. Shares -32003 with the other condition-failure codes on the wire; the
	// symbolic code and decision=escalate are what distinguish it.
	ErrCodeEscalationRequired = "ESCALATION_REQUIRED"
	// ErrCodeUnsupportedProtocolVersion refuses a request whose MCP protocol revision
	// cannot be established: none declared on a context that never negotiated one, a
	// declared revision this build does not speak, or a declaration disagreeing with the
	// context it arrived in. The last is the reason this is a REFUSAL rather than a
	// fallback — a revision flip inside one context is indistinguishable from a probe for
	// the more permissive method table, and each revision has its own.
	//
	// It names no policy target (the request was never matched), so IsInfraDenialCode
	// treats it as infrastructure and `eunox suggest` skips it.
	ErrCodeUnsupportedProtocolVersion = "UNSUPPORTED_PROTOCOL_VERSION"
	// ErrCodeUnroutableMethod refuses a message no routing table can route: a method this
	// build dispatches under no revision, one the requesting peer's revision removed, or one
	// that arrived in a framing that revision does not dispatch. It is the fail-closed routing
	// default's own code, in BOTH framings.
	//
	// It exists because the class is the encoding. This refusal used to borrow
	// AUTHORIZATION_FAILED — a genuine policy code for a message no policy evaluated — so
	// [ClassifyDenialCode] called it a policy verdict and [DenialInfo.Downgradable] answered
	// true for it; what actually kept an observing route from forwarding a message it has no
	// route for was that the fail-closed path never built a DenialInfo and so never asked.
	// Routing it through the shared deny path — the obvious cleanup, and the shape every other
	// refusal already has — would have turned that into a wiretap inventing a route.
	//
	// The WIRE code stays -32001, so what changes for a host is error.data.code (and the
	// symbolic code a SIEM rule matches), not the JSON-RPC integer it branches on.
	ErrCodeUnroutableMethod = "UNROUTABLE_METHOD"
	// ErrCodeUntranslatableAcrossRevisions refuses a message that a mismatched host/upstream
	// revision pair cannot carry: the method is routable for the requesting peer and the leg is
	// live, but honoring it would require eunox to hold per-exchange state on behalf of a peer
	// whose revision has none, or to hand a peer a result variant its revision cannot read.
	//
	// It is distinct from UNSUPPORTED_PROTOCOL_VERSION, which says a revision could not be
	// ESTABLISHED, and from UNROUTABLE_METHOD, which says no table could route the method at
	// all. This one says both of those succeeded and the PAIR is what cannot be served — the
	// only refusal whose cause is a relationship between two peers rather than a fact about
	// one. An operator reading a tape needs that separable: it is the code that says "this
	// deployment is mid-migration", and the one a matched pair can never produce.
	//
	// The WIRE code is -32022, shared with UNSUPPORTED_PROTOCOL_VERSION, because the problem a
	// host can act on is the same one — the revisions in play do not line up. ADR-0006 also
	// names -32601 for a method with "no home for the pair"; that case never reaches here,
	// having already been answered by the fail-closed routing default under
	// UNROUTABLE_METHOD, which precedes this check.
	ErrCodeUntranslatableAcrossRevisions = "UNTRANSLATABLE_ACROSS_REVISIONS"
	// ErrCodeHeaderMismatch refuses a Streamable HTTP POST whose 2026-07-28 routing headers
	// (`Mcp-Method`, `Mcp-Name`) disagree with the body they describe, or omit what that
	// revision requires.
	//
	// Its own code rather than INVALID_PARAMS, because the two are read for different things:
	// a malformed body is a client that got the shape wrong, while a header that names a
	// different method or target than the body executes is an ENFORCEMENT-CONFUSION attempt —
	// the headers exist so an intermediary can route, meter and log without parsing, and a
	// disagreeing pair is metered as one call and executed as another. An operator grepping
	// the tape for someone probing that boundary needs it under its own name.
	ErrCodeHeaderMismatch = "HEADER_MISMATCH"
)

// Fixed JSON-RPC integer error codes for denial responses.
// These are the wire codes sent to MCP hosts and upstream servers.
const (
	JSONRPCCodeInvalidParams       = -32602 // INVALID_PARAMS (also the standard JSON-RPC invalid params code)
	JSONRPCCodeAuthorizationFailed = -32001 // AUTHORIZATION_FAILED
	JSONRPCCodeCapabilityDenied    = -32002 // CAPABILITY_DENIED
	JSONRPCCodeConditionFailed     = -32003 // CONDITION_FAILED
	// JSONRPCCodeRateLimited is the wire code for ErrCodeRateLimited. It shares
	// the CONDITION_FAILED integer because a rate limit is a failed maxCalls
	// condition; the symbolic code in error.data.code disambiguates the two.
	JSONRPCCodeRateLimited = -32003 // RATE_LIMITED
	// JSONRPCCodeEnforcementError is the wire code for ErrCodeEnforcementError: the
	// standard JSON-RPC internal-error code, because an enforcement-engine failure
	// is a server-side internal error, not a policy denial.
	JSONRPCCodeEnforcementError = -32603 // ENFORCEMENT_ERROR
	// JSONRPCCodeUnsupportedProtocolVersion is the wire code for
	// ErrCodeUnsupportedProtocolVersion. Unlike every other code here it is not eunox's to
	// choose: -32022 is assigned by the MCP specification, which is also why it sits in the
	// -32020..-32099 band eunox otherwise never mints into.
	JSONRPCCodeUnsupportedProtocolVersion = -32022 // UNSUPPORTED_PROTOCOL_VERSION (spec-assigned)
	// JSONRPCCodeHeaderMismatch is the wire code for ErrCodeHeaderMismatch. Like -32022 it is
	// not eunox's to choose: 2026-07-28 assigns it, which is also why it sits in the
	// -32020..-32099 band eunox otherwise never mints into. See SpecAssignedWireCodes.
	JSONRPCCodeHeaderMismatch = -32020 // HEADER_MISMATCH (spec-assigned)
)

// AllDenialCodes lists every symbolic denial code (ErrCode*). It exists so
// DenialWireCode's coverage can be enumerated in a test: adding an ErrCode* here
// without a matching case in DenialWireCode fails TestDenialWireCode_CoversEveryCode,
// turning a forgotten wire mapping into a test-time miss rather than a silent
// CAPABILITY_DENIED. A new ErrCode* must be added to both this list and DenialWireCode.
var AllDenialCodes = []string{
	ErrCodeAuthorizationFailed,
	ErrCodeCapabilityDenied,
	ErrCodeInvalidParams,
	ErrCodeConditionFailed,
	ErrCodeKillSwitch,
	ErrCodeKillSwitchError,
	ErrCodeMissingContext,
	ErrCodeRateLimited,
	ErrCodeNoJWTClaims,
	ErrCodeOperationNotPermitted,
	ErrCodeValueNotPermitted,
	ErrCodeEnforcementError,
	ErrCodeAuditUnavailable,
	ErrCodeSamplingDenied,
	ErrCodeEscalationRequired,
	ErrCodeUnsupportedProtocolVersion,
	ErrCodeUnroutableMethod,
	ErrCodeUntranslatableAcrossRevisions,
	ErrCodeHeaderMismatch,
}

// DenialWireCode maps a symbolic denial code (ErrCode*) to the JSON-RPC integer
// error code sent to MCP hosts and upstream servers. It lives beside the codes it
// maps between so the symbolic→wire pairing is reviewable at one altitude: a new
// ErrCode* added without a case here is caught by TestDenialWireCode_CoversEveryCode
// rather than silently shipping on the wire as CAPABILITY_DENIED (-32002) while its
// own error.data.code says otherwise. ok is false for an unrecognized code (the
// fallback wire code is CAPABILITY_DENIED), letting callers distinguish the fallback
// from an explicit mapping.
func DenialWireCode(code string) (wire int, ok bool) {
	switch code {
	case ErrCodeInvalidParams:
		return JSONRPCCodeInvalidParams, true
	// Authorization/authentication-layer events share -32001 with
	// AUTHORIZATION_FAILED: kill-switch and missing-claims failures are credential
	// problems, not capability misses. SAMPLING_DENIED is a server-initiated-request
	// denial that also surfaces as -32001 (forwardServerRequest's hard deny), distinct
	// from the host-facing -32002.
	// UNROUTABLE_METHOD shares -32001 too: it is the code AUTHORIZATION_FAILED's wire
	// half already carried for the fail-closed routing default, kept so splitting the
	// symbolic code off does not also move the integer every host branches on.
	case ErrCodeAuthorizationFailed,
		ErrCodeKillSwitch, ErrCodeKillSwitchError,
		ErrCodeNoJWTClaims,
		ErrCodeSamplingDenied,
		ErrCodeUnroutableMethod:
		return JSONRPCCodeAuthorizationFailed, true
	// Condition-failure codes share -32003: a failed maxCalls (RATE_LIMITED), a
	// missing required argument (MISSING_CONTEXT), and the allowedOperations/
	// allowedValues failures.
	// ESCALATION_REQUIRED joins them: an over-ceiling action is a failed policy
	// condition on the consequence axis, and the symbolic code (plus decision=escalate
	// on the tape) is what tells a host "a human must approve this" rather than "this
	// is forbidden".
	case ErrCodeConditionFailed, ErrCodeRateLimited,
		ErrCodeMissingContext,
		ErrCodeOperationNotPermitted, ErrCodeValueNotPermitted,
		ErrCodeEscalationRequired:
		return JSONRPCCodeConditionFailed, true
	// Server-side failures (an enforcement-engine error, or AUDIT_UNAVAILABLE from
	// the --require-audit=strict gate) are not policy verdicts, so they use the
	// JSON-RPC internal-error code, distinct from -32001/-32002/-32003.
	case ErrCodeEnforcementError, ErrCodeAuditUnavailable:
		return JSONRPCCodeEnforcementError, true
	// The one spec-assigned code eunox emits: a peer whose protocol revision cannot be
	// established gets -32022, not a policy code, because nothing about policy was reached.
	// UNTRANSLATABLE_ACROSS_REVISIONS joins it on the spec-assigned integer: the two differ in
	// WHY the revisions are a problem (one could not be established, the other could not be
	// bridged), and error.data.code is what separates them, but a host branching on the
	// integer wants the same answer from both — stop, the revisions do not line up.
	case ErrCodeUnsupportedProtocolVersion, ErrCodeUntranslatableAcrossRevisions:
		return JSONRPCCodeUnsupportedProtocolVersion, true
	// The second spec-assigned code eunox emits, and it does NOT join the -32022 pair above:
	// those two both say "the revisions do not line up", where this says the pair of halves
	// describing ONE request do not. A host branching on the integer wants different answers.
	case ErrCodeHeaderMismatch:
		return JSONRPCCodeHeaderMismatch, true
	case ErrCodeCapabilityDenied:
		return JSONRPCCodeCapabilityDenied, true
	default:
		return JSONRPCCodeCapabilityDenied, false
	}
}

// DenialClass says what KIND of thing refused a call: the policy, the emergency stop, or a
// failure that stopped either from reaching a verdict.
//
// It is DERIVED from the denial's code rather than carried beside it. The alternative — a
// second field, or the hand-set bool it would join — asks every producer to restate in a flag
// what it has already said in the code, and the sites disagreed: refusals of the same class,
// written weeks apart, blocked or downgraded depending on which neighbour was copied. A code
// is a thing a refusal cannot omit, so classifying from it is the one answer nothing can
// forget to give.
type DenialClass uint8

const (
	// DenialClassPolicy is a verdict the policy reached: the rules were evaluated and they
	// refuse this call. The only class an observing route may downgrade to a forward, because
	// it is the only one where "what would enforce mode have done" is actually known.
	DenialClassPolicy DenialClass = iota
	// DenialClassRevocation is the emergency stop. Separate from a fault because it is not a
	// failure at all — the system is working exactly as intended — and separate from a policy
	// verdict because no policy was consulted.
	DenialClassRevocation
	// DenialClassFault is a refusal produced because no verdict could be reached: an engine
	// bug, a backend that failed or answered nonconformingly, a registered handler that broke
	// its contract, the audit trail that must record the call being unavailable, or a message
	// that never reached policy at all (its revision could not be established, or no routing
	// table could route it). Never downgradable — there is no verdict to stand in for the one
	// that never ran.
	DenialClassFault
)

// ClassifyDenialCode reports which class of refusal code names. It classifies the codes THIS
// vocabulary defines (AllDenialCodes, each covered by TestClassifyDenialCode_CoversEveryCode);
// anything else — an out-of-tree PDP's own code, or one the transport layer mints for a
// refusal taken before policy was reached — falls to policy, which is why a consumer asking a
// broader question (internal/transport's IsInfraDenialCode) reads this AND its own list rather
// than only this.
func ClassifyDenialCode(code string) DenialClass {
	switch code {
	case ErrCodeKillSwitch, ErrCodeKillSwitchError:
		return DenialClassRevocation
	// AUDIT_UNAVAILABLE joins the engine faults: the call was authorized and the refusal is
	// that it cannot be durably recorded, which is a property of the trail, not of the caller.
	case ErrCodeEnforcementError, ErrCodeAuditUnavailable:
		return DenialClassFault
	// Neither of these was ever matched against policy: one peer's protocol revision could not
	// be established, and the other's message no revision's routing tables could route. Both
	// refusals precede every gate that could reach a verdict, so an observing route has none of
	// its own to forward in their place.
	// UNTRANSLATABLE_ACROSS_REVISIONS joins them, and its downgrade is the one that would do
	// real damage: an observing route forwarding a message this refuses would hand a peer a
	// result variant its revision cannot read, or leave an upstream blocked on an exchange the
	// host can never complete. There is no policy verdict to forward in its place either — the
	// pair is refused before any match runs.
	case ErrCodeUnsupportedProtocolVersion, ErrCodeUnroutableMethod, ErrCodeUntranslatableAcrossRevisions:
		return DenialClassFault
	// HEADER_MISMATCH joins them, and for the same structural reason rather than by analogy: it
	// is refused at the HTTP envelope, before any match runs, so there is no policy verdict to
	// forward in its place. The downgrade would also be the worst of the three to permit — an
	// observing route forwarding a request whose halves disagree hands the very confusion this
	// refusal exists to catch to every downstream reader that trusts the header, which is the
	// one posture where "forward and log" is not a safe approximation of enforcing.
	case ErrCodeHeaderMismatch:
		return DenialClassFault
	default:
		return DenialClassPolicy
	}
}

// Downgradable reports whether an OBSERVING route (whole-route --audit, or a per-constraint
// `enforcement: audit`) may forward the call this denial refuses instead of blocking it.
//
// The two reasons not to are asked separately because they answer to different owners: the
// CLASS is a property of the refusal, derived from its code, and BlockOverride is a producer's
// explicit override for a policy verdict that must block anyway (one whose downgrade would
// itself corrupt state the verdict protects). A nil denial is not downgradable: defaulting an
// absent reason to "forward it" is the wrong direction to fail in.
//
// It is the ONLY complete answer to "will an observing route forward this?", and every layer
// asks it here rather than reading BlockOverride — which is half the answer, and the half a
// producer can forget. Reading the raw bool is how a fault-class refusal minted by a third
// constructor gets committed session state for a call the transport then blocks.
func (d *DenialInfo) Downgradable() bool {
	return d != nil && !d.BlockOverride && ClassifyDenialCode(d.Code) == DenialClassPolicy
}
