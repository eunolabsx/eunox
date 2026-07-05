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
	// ErrCodeEnforcementError is a reserved, fail-closed code for an internal
	// enforcement-engine failure while evaluating a matched constraint's conditions
	// — a request that can be neither allowed nor cleanly rejected by policy. It is
	// distinct from CAPABILITY_DENIED and CONDITION_FAILED. No reachable path emits
	// it today (condition handlers, including an unreachable MaxCalls backend, still
	// resolve to CONDITION_FAILED); the PDP keeps it as a defensive guard so a
	// future internal error denies with a distinct, matchable code rather than
	// falling open. The resource-read and prompt-get paths also reuse it for a
	// resource:/prompt: constraint carrying a tool-only argumentSchema (rejected at
	// load, so likewise unreachable), denying rather than forwarding with the schema
	// silently skipped. Maps to JSON-RPC -32603.
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
	case ErrCodeAuthorizationFailed,
		ErrCodeKillSwitch, ErrCodeKillSwitchError,
		ErrCodeNoJWTClaims,
		ErrCodeSamplingDenied:
		return JSONRPCCodeAuthorizationFailed, true
	// Condition-failure codes share -32003: a failed maxCalls (RATE_LIMITED), a
	// missing required argument (MISSING_CONTEXT), and the allowedOperations/
	// allowedValues failures.
	case ErrCodeConditionFailed, ErrCodeRateLimited,
		ErrCodeMissingContext,
		ErrCodeOperationNotPermitted, ErrCodeValueNotPermitted:
		return JSONRPCCodeConditionFailed, true
	// Server-side failures (an enforcement-engine error, or AUDIT_UNAVAILABLE from
	// the --require-audit=strict gate) are not policy verdicts, so they use the
	// JSON-RPC internal-error code, distinct from -32001/-32002/-32003.
	case ErrCodeEnforcementError, ErrCodeAuditUnavailable:
		return JSONRPCCodeEnforcementError, true
	case ErrCodeCapabilityDenied:
		return JSONRPCCodeCapabilityDenied, true
	default:
		return JSONRPCCodeCapabilityDenied, false
	}
}
