// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ResolveArgument looks up the value a condition's `argument` refers to. A plain
// name is a top-level key (the default, unchanged). A reference beginning with
// "$." is a dotted path into nested object arguments: "$.a.b" reads
// args["a"].(map)["b"]. A reference beginning with "$$." is the escaped literal
// form of a top-level key that itself starts with "$.": "$$.x" reads the literal
// key args["$.x"], not a traversal into args["x"]. Argument-matching conditions
// (allowedValues, allowedOperations, allowedExtensions, allowedTables,
// recipientDomain) all resolve through here, so the path syntax is uniform across
// them.
//
// Fail closed: a malformed "$." path, a segment that lands on a non-object, or a
// missing key all return (nil, false) — exactly the "argument missing" signal a
// missing flat key produces, which the callers already deny on.
func ResolveArgument(args map[string]interface{}, ref string) (interface{}, bool) {
	return capability.ResolveArgument(args, ref)
}

// BuildRegoInput constructs the standard Rego input document from an
// EnforceRequest. The returned map contains:
//
//	{
//	  "arguments":  req.Arguments,              // always {} — never null
//	  "target":     {"type": ..., "name": ...}, // when req.Target != nil
//	  "claims":     {...},                       // always {} — never null
//	  "directives": [...],                       // always [] — never null
//	  "context": {
//	    "session_id": req.SessionID,
//	    "source_ip":  req.Context.SourceIP,
//	    "request_id": requestID,               // from RequestIDFromContext(ctx)
//	    "timestamp":  timestamp,               // from TimestampFromContext(ctx)
//	  },
//	}
//
// It returns a non-nil error if any directive cannot be serialized into
// input.directives. A PolicyEvaluator calling this must treat that as a deny: a
// shortened input.directives would let a policy gating on the decision's
// obligations (e.g. count(input.directives) > 0) decide on incomplete information.
func BuildRegoInput(ctx context.Context, req *capability.EnforceRequest) (map[string]interface{}, error) {
	args := req.Arguments
	if args == nil {
		args = map[string]interface{}{}
	}

	// req.Claims is the memoized JWTClaims.flatClaims map, shared read-only across
	// every (possibly concurrent) request on the token. Hand a shallow copy to the
	// PolicyEvaluator: input.claims crosses into pluggable third-party code (OPA/
	// Cedar), and a copy gives each evaluation its own top-level map so an evaluator
	// that writes into input.claims cannot corrupt the shared map or race concurrent
	// readers — restoring the per-call isolation the pre-memoization fresh-map-per-call
	// build provided. (Nested claim values were shared before the memoization too.)
	claims := map[string]interface{}{}
	for k, v := range req.Claims {
		claims[k] = v
	}

	// Prefer the directives the engine threaded through ctx over req.Directives
	// (the engine passes them via ctx rather than mutating req, which would race
	// concurrent readers). A direct caller that set req.Directives is still honored.
	regoDirectives := req.Directives
	if ctxDirs, ok := directivesFromContext(ctx); ok {
		regoDirectives = ctxDirs
	}
	directives, err := directivesToRegoInput(regoDirectives)
	if err != nil {
		return nil, err
	}

	input := map[string]interface{}{
		"arguments":  args,
		"claims":     claims,
		"directives": directives,
		"context": map[string]interface{}{
			"session_id": req.SessionID,
			"source_ip":  req.Context.SourceIP,
			"request_id": RequestIDFromContext(ctx),
			"timestamp":  timestampForInput(ctx, req),
		},
	}

	if req.Target != nil {
		input["target"] = map[string]interface{}{
			"type": req.Target.Type,
			"name": req.Target.Name,
		}
	}

	return input, nil
}

// timestampForInput resolves input.context.timestamp: the timestamp the engine
// threaded through ctx (the same instant stamped on DecidedAt), falling back to a
// direct caller's req.Context.Now.
func timestampForInput(ctx context.Context, req *capability.EnforceRequest) string {
	if ts := TimestampFromContext(ctx); ts != "" {
		return ts
	}
	return req.Context.Now
}

// directivesToRegoInput converts Directive values into a non-nil []interface{}
// (empty when none) so Rego policies can iterate input.directives without a null
// guard. A directive that cannot be JSON round-tripped is reported as an error,
// not silently dropped — a short slice would understate the decision's obligations.
func directivesToRegoInput(directives []capability.Directive) ([]interface{}, error) {
	out := make([]interface{}, 0, len(directives))
	for i, d := range directives {
		b, err := json.Marshal(capability.DirectiveWrapper{Directive: d})
		if err != nil {
			return nil, fmt.Errorf("directive[%d] (%T) marshal failed: %w", i, d, err)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("directive[%d] (%T) unmarshal failed: %w", i, d, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// registerBuiltins registers all built-in condition handlers.
func (e *Engine) registerBuiltins() {
	e.handlers[capability.ConditionTypeTimeWindow] = ConditionHandlerFunc(e.handleTimeWindow)
	e.handlers[capability.ConditionTypeIPRange] = ConditionHandlerFunc(e.handleIPRange)
	e.handlers[capability.ConditionTypeMaxCalls] = maxCallsHandler{e: e}
	e.handlers[capability.ConditionTypeAllowedOperations] = ConditionHandlerFunc(e.handleAllowedOperations)
	e.handlers[capability.ConditionTypeAllowedExtensions] = ConditionHandlerFunc(e.handleAllowedExtensions)
	e.handlers[capability.ConditionTypeAllowedTables] = ConditionHandlerFunc(e.handleAllowedTables)
	e.handlers[capability.ConditionTypeRecipientDomain] = ConditionHandlerFunc(e.handleRecipientDomain)
	e.handlers[capability.ConditionTypeAllowedValues] = ConditionHandlerFunc(e.handleAllowedValues)
	e.handlers[capability.ConditionTypeSequenceBlock] = ConditionHandlerFunc(e.handleSequenceBlock)
	e.handlers[capability.ConditionTypeFlowLabel] = ConditionHandlerFunc(e.handleFlowLabel)
	e.handlers[capability.ConditionTypeEffectClass] = ConditionHandlerFunc(e.handleEffectClass)
	e.handlers[capability.ConditionTypeBlastRadius] = blastRadiusHandler{e: e}
	e.handlers[capability.ConditionTypePolicy] = ConditionHandlerFunc(e.handlePolicy)
	e.handlers[capability.ConditionTypeCustom] = ConditionHandlerFunc(e.handleCustom)
}

func (e *Engine) handleTimeWindow(_ context.Context, cond capability.Condition, _ *capability.EnforceRequest) *ConditionError {
	tw, condErr := castCondition[capability.TimeWindowCondition](cond)
	if condErr != nil {
		return condErr
	}

	// Fail closed on a window that restricts nothing. The manifest loader rejects a
	// both-empty window (validateTimeWindow), but a direct/programmatic caller of the
	// exported engine can construct one, and silently returning allow would fall open
	// for a security rule — mirroring the empty-afterTools sequenceBlock guard below.
	if tw.NotBefore == "" && tw.NotAfter == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeTimeWindow,
			Message:       "timeWindow condition declares neither notBefore nor notAfter; a window with no bounds restricts nothing",
		}
	}

	now := e.clock.Now().UTC()

	// Manifest-loaded conditions are pre-parsed (Compile at load), so the hot path
	// compares ready time.Time values and never calls time.Parse. An uncompiled
	// condition (constructed directly, e.g. in a test) compiles a LOCAL copy once and
	// reads it back through the same accessor, rather than re-implementing the RFC3339
	// parse per bound here: one parser, so the uncompiled path cannot drift from
	// Compile. The copy is deliberate — the engine must not cache state onto a
	// condition it does not own. Compile reports the FIRST malformed bound, so a
	// condition with both a violated notBefore and a malformed notAfter now denies on
	// the malformed bound rather than the violated one; both are denials, and reporting
	// the structural error first is the more useful of the two.
	notBefore, notAfter, compiled := tw.Window()
	if !compiled {
		local := *tw
		if err := local.Compile(); err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeTimeWindow,
				Message:       err.Error(),
			}
		}
		notBefore, notAfter, _ = local.Window()
	}

	if tw.NotBefore != "" {
		if now.Before(notBefore) {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeTimeWindow,
				Message:       "request is before the allowed time window",
				Details: map[string]interface{}{
					"notBefore": tw.NotBefore,
					"now":       now.Format(time.RFC3339Nano),
				},
			}
		}
	}

	if tw.NotAfter != "" {
		// The window is half-open: [notBefore, notAfter). notBefore is inclusive,
		// notAfter exclusive, so !now.Before(notAfter) denies now >= notAfter —
		// "allow until T" closes at T rather than admitting one more call at T.
		if !now.Before(notAfter) {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeTimeWindow,
				Message:       "request is at or after the allowed time window",
				Details: map[string]interface{}{
					"notAfter": tw.NotAfter,
					"now":      now.Format(time.RFC3339Nano),
				},
			}
		}
	}

	return nil
}

func (e *Engine) handleIPRange(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	ipr, condErr := castCondition[capability.IPRangeCondition](cond)
	if condErr != nil {
		return condErr
	}

	if req.Context.SourceIP == "" {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeIPRange,
			Message:       "sourceIp is required for ipRange condition",
		}
	}

	ip := net.ParseIP(req.Context.SourceIP)
	if ip == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeIPRange,
			Message:       fmt.Sprintf("invalid source IP: %s", req.Context.SourceIP),
		}
	}

	// Manifest-loaded conditions are pre-compiled, so the hot path matches against
	// ready networks and never calls net.ParseCIDR.
	networks, ok := ipr.Networks()
	if !ok {
		// Not pre-compiled (a programmatically constructed condition). Compile a LOCAL
		// copy and read it back through the same accessor rather than re-implementing the
		// CIDR loop here: one parser, so the uncompiled path cannot drift from Compile.
		// The copy is deliberate — the engine must not cache state onto a condition it
		// does not own. The loader rejects malformed CIDRs, so this error branch is
		// reachable only for hand-built conditions; fail closed on it.
		local := *ipr
		if err := local.Compile(); err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeIPRange,
				Message:       fmt.Sprintf("invalid CIDR in condition: %v", err),
			}
		}
		networks, _ = local.Networks()
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return nil
		}
	}

	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeIPRange,
		Message:       "source IP is not in allowed ranges",
		Details: map[string]interface{}{
			"sourceIp":     req.Context.SourceIP,
			"allowedCIDRs": ipr.CIDRs,
		},
	}
}

// maxCallsBucket derives the counter bucket for a maxCalls condition: it casts the
// condition, applies the skip-quota bypass, and validates the counter, session, and
// target. Both the direct condition-handler path (maxCallsHandler.Handle) and the engine's
// atomic multi-condition commit (commitDeferredConditions, engine.go) reach it through
// PrepareCommit, so they build the SAME key under the SAME fail-closed guards. skip is true when quota
// must not be consumed (--audit observe mode via WithSkipQuota — treat the condition
// as satisfied); condErr is non-nil on any deny; otherwise the condition and its
// bucket key are returned.
func (e *Engine) maxCallsBucket(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (mc *capability.MaxCallsCondition, key string, skip bool, condErr *ConditionError) {
	mc, condErr = castCondition[capability.MaxCallsCondition](cond)
	if condErr != nil {
		return nil, "", false, condErr
	}

	if e.counter == nil {
		return nil, "", false, &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       "call counter not configured",
		}
	}

	// A missing sessionID would merge quota across all anonymous callers (quota
	// bypass / DoS). Deny rather than share a cross-session bucket.
	if req.SessionID == "" {
		return nil, "", false, &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       "sessionId is required for maxCalls condition",
		}
	}

	// Build a unique key from session + target type + bare name.
	//
	// The target type must be in the key because req.TargetName is only the bare name:
	// a tool "export" and a prompt "export" would otherwise drain one budget.
	// sessionTargetKey derives the (type, name) pair exactly as RecordSessionCall does
	// — prefix from splitEnginePrefix, overridden by Target.Type when set; name from
	// sessionTargetName — so a direct ValidateAction caller that leaves req.Target nil
	// keys the same bucket the antecedent record uses, rather than collapsing distinct
	// namespaces' targets onto one empty-type bucket.
	//
	// windowSeconds is deliberately NOT part of this logical key: per-window
	// isolation is supplied by each backend appending windowSec to the physical key.
	// Two conditions sharing one window are rejected at load
	// (validateQuotaBucketsDistinct). Route scoping is unneeded — session IDs are
	// per-connection UUIDs and the transport rejects cross-route sessions — and
	// compositeCounterKey length-prefixes every component against collision.
	targetType, toolName := sessionTargetKey(req)
	// An empty bare name would key every such call into one bucket. Deny rather
	// than quota-account an unidentifiable target.
	if toolName == "" {
		return nil, "", false, &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       "tool or resource name is required for maxCalls condition",
		}
	}

	// Skip the counter (treating the condition as satisfied) when quota must not be
	// consumed: --audit observe mode (WithSkipQuota).
	//
	// Deliberately AFTER the structural guards above, not before them. Observe mode exists
	// to predict what enforcement would do, and only the counter INCREMENT is what it must
	// not perform; a nil counter, an empty session, or an unidentifiable target are
	// misconfigurations that deny in enforce mode no matter what the quota is. Skipping
	// first hid exactly those from the audit log — the run an operator makes precisely to
	// find them — and reported ALLOW where enforce mode would have written
	// MISSING_CONTEXT/CONDITION_FAILED. Same rationale as commitDeferredConditions'
	// validate-then-skip ordering (engine.go), which this now matches.
	if SkipQuota(ctx) {
		return nil, "", true, nil
	}
	return mc, e.anchoredKey("maxcalls", req, targetType, toolName), false, nil
}

// maxCallsHandler is the built-in maxCalls condition handler. maxCalls commits a
// sliding-window slot on admit, so beyond the plain Handle path it implements
// CommittingConditionHandler: the engine treats it as a deferred condition (run
// after all pure predicates) and, when a constraint carries more than one deferred
// condition, admits it via the atomic multi-bucket commit. Both facets share
// maxCallsBucket so the single- and multi-condition paths build the SAME key under
// the SAME fail-closed guards.
type maxCallsHandler struct{ e *Engine }

// Handle implements ConditionHandler by routing through PrepareCommit and admitting the
// single bucket, so the pure checks and the bucket derivation have ONE implementation. The
// engine's deferred path calls PrepareCommit directly; this exists for a direct caller of
// the exported condition-handler seam.
func (h maxCallsHandler) Handle(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return h.e.prepareAndAdmit(ctx, h, cond, req)
}

// PrepareCommit implements CommittingConditionHandler: it derives the counter bucket
// WITHOUT consuming a slot, so the engine can admit several deferred conditions in one
// atomic AdmitAll. maxCalls carries no pure checks of its own beyond the structural guards
// maxCallsBucket applies.
func (h maxCallsHandler) PrepareCommit(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	mc, key, skip, condErr := h.e.maxCallsBucket(ctx, cond, req)
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	if skip {
		return DeferredCommit{}, true, nil
	}
	return DeferredCommit{
		Bucket: capability.QuotaBucket{
			Key:       key,
			WindowSec: mc.WindowSeconds,
			// Counted: a maxCalls bucket bounds the NUMBER of calls, which every backend
			// answers in O(1). It is the weight-1 case of the weighted accounting, kept
			// distinct only so a large quota does not pay a linear scan per check.
			Counted: true,
			Limit:   float64(mc.Count),
		},
		Deny: func(total float64, retryAfter time.Duration) *ConditionError {
			// Surface a Retry-After hint so a caller can back off; fall back to the full
			// window when the backend has no estimate.
			return maxCallsRateLimited(mc, int64(total), retryAfterSeconds(retryAfter, mc.WindowSeconds))
		},
	}, false, nil
}

// retryAfterSeconds converts a backend retry-after estimate to whole seconds
// (rounded up), falling back to the full window when the estimate is unavailable
// (<= 0). Shared by the commit and check-only maxCalls denial paths so both
// advise the hint the same way.
func retryAfterSeconds(d time.Duration, windowSec int) int64 {
	// Fall back to the full window when the estimate is unavailable (<= 0). This
	// must precede the ceiling: a negative sub-second duration truncates to 0, which
	// the fractional ceiling would otherwise round up to 1s.
	if d <= 0 {
		return int64(windowSec)
	}
	secs := int64(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	// No floor guard needed: with d > 0, secs is always at least 1.
	return secs
}

// maxCallsRateLimited builds the RATE_LIMITED ConditionError shared by the commit
// and check-only maxCalls denial paths, keeping the Details shape identical.
func maxCallsRateLimited(mc *capability.MaxCallsCondition, current, retryAfterSec int64) *ConditionError {
	return &ConditionError{
		Code:          capability.ErrCodeRateLimited,
		ConditionType: capability.ConditionTypeMaxCalls,
		Message:       "call limit exceeded",
		Details: map[string]interface{}{
			"limit":      mc.Count,
			"current":    current,
			"window":     mc.WindowSeconds,
			"retryAfter": retryAfterSec,
		},
	}
}

func (e *Engine) handleAllowedOperations(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	ao, condErr := castCondition[capability.AllowedOperationsCondition](cond)
	if condErr != nil {
		return condErr
	}

	// Require an explicit argument field (like allowedExtensions/allowedTables): a
	// scan-all-args mode would let a request hide the allowed verb in a benign
	// argument and produced nondeterministic results from map iteration order.
	if ao.Argument == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedOperations,
			Message:       "allowedOperations condition requires an explicit 'argument' field naming the tool parameter that carries the operation",
		}
	}

	// Distinguish the failure modes for the audit trail: a present-but-non-string
	// argument is CONDITION_FAILED (wrong shape), an absent or whitespace-only value
	// stays MISSING_CONTEXT. The lookup resolves a "$." path into nested arguments.
	rawVal, present := ResolveArgument(req.Arguments, ao.Argument)
	if !present {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeAllowedOperations,
			Message:       fmt.Sprintf("argument %q is missing", ao.Argument),
			Details:       map[string]interface{}{"argument": ao.Argument},
		}
	}
	s, isString := rawVal.(string)
	if !isString {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedOperations,
			Message:       fmt.Sprintf("argument %q must be a string, got %T", ao.Argument, rawVal),
			Details:       map[string]interface{}{"argument": ao.Argument},
		}
	}
	operation := OperationVerb(s)
	if operation == "" {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeAllowedOperations,
			Message:       fmt.Sprintf("argument %q is empty", ao.Argument),
			Details:       map[string]interface{}{"argument": ao.Argument},
		}
	}

	// No wildcard: the operations list is an explicit allowlist. A "*" entry is
	// rejected at load (validateAllowedOperations); matching it here would turn the
	// condition into a no-op permitting any verb. AllowsOperation matches against the
	// entries Compile pre-trimmed at load, resolving either way to
	// capability.MatchOperation — the same matcher the JWT shorthand PDP calls with a
	// bare claim-derived slice, so the manifest and JWT paths cannot diverge.
	if ao.AllowsOperation(operation) {
		return nil
	}

	return &ConditionError{
		// OPERATION_NOT_PERMITTED matches the denial_code the JWT PDP emits for the
		// same failure, keeping audit records and SIEM rules consistent across the
		// manifest and JWT paths. Malformed-input denials above stay CONDITION_FAILED.
		Code:          capability.ErrCodeOperationNotPermitted,
		ConditionType: capability.ConditionTypeAllowedOperations,
		Message:       fmt.Sprintf("operation %q is not allowed", operation),
		Details: map[string]interface{}{
			"operation":         operation,
			"allowedOperations": ao.Operations,
		},
	}
}

// resolveStringOrStringArray reads the named argument as a cleaned (trimmed,
// non-blank) list of strings: a single string yields one element, an array one per
// item. Shared by allowedExtensions and recipientDomain, which must fail closed
// identically. condType names the originating condition in every returned error.
//
// Fail-closed taxonomy (kept in lock-step across both conditions):
//   - a non-string or blank array item is a wrong-input CONDITION_FAILED, not a
//     silently dropped entry (an all-blank array must not look like MISSING_CONTEXT);
//   - a present-but-non-string/array value is a wrong-type CONDITION_FAILED;
//   - a missing or empty result is MISSING_CONTEXT.
func resolveStringOrStringArray(args map[string]interface{}, argName, condType string) ([]string, *ConditionError) {
	var out []string
	if v, ok := ResolveArgument(args, argName); ok {
		s, isString := v.(string)
		items, isArray := asInterfaceSlice(v)
		switch {
		case isString:
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				out = []string{trimmed}
			}
		case isArray:
			// ONE validation arm for both array shapes (see asInterfaceSlice): the
			// blank-element and non-string-item rules are security-relevant fail-closed
			// checks, and keeping two hand-mirrored copies is how one of them silently
			// loses a check.
			for _, item := range items {
				s, ok := item.(string)
				if !ok {
					return nil, &ConditionError{
						Code:          capability.ErrCodeConditionFailed,
						ConditionType: condType,
						Message:       fmt.Sprintf("argument %q array contains a non-string item: %T", argName, item),
						Details:       map[string]interface{}{"argument": argName},
					}
				}
				if strings.TrimSpace(s) == "" {
					return nil, &ConditionError{
						Code:          capability.ErrCodeConditionFailed,
						ConditionType: condType,
						Message:       fmt.Sprintf("argument %q array contains a blank element", argName),
						Details:       map[string]interface{}{"argument": argName},
					}
				}
				out = append(out, strings.TrimSpace(s))
			}
		default:
			return nil, &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: condType,
				Message:       fmt.Sprintf("argument %q must be a string or array of strings, got %T", argName, v),
				Details:       map[string]interface{}{"argument": argName},
			}
		}
	}
	if len(out) == 0 {
		return nil, &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: condType,
			Message:       fmt.Sprintf("argument %q is missing or empty", argName),
			Details:       map[string]interface{}{"argument": argName},
		}
	}
	return out, nil
}

func (e *Engine) handleAllowedExtensions(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	ae, condErr := castCondition[capability.AllowedExtensionsCondition](cond)
	if condErr != nil {
		return condErr
	}

	if ae.Argument == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedExtensions,
			Message:       "allowedExtensions condition requires an explicit 'argument' field naming the tool parameter that carries the file path",
		}
	}

	// The argument may carry a single path (string) or multiple (array). Every path
	// must pass the allowlist — one disallowed entry denies the whole call.
	paths, cerr := resolveStringOrStringArray(req.Arguments, ae.Argument, capability.ConditionTypeAllowedExtensions)
	if cerr != nil {
		return cerr
	}

	// The normalized allowlist: lowercased, every entry a dotted suffix matched on a
	// dot boundary via HasSuffix (".gz" matches "data.gz" not "datagz"), blanks
	// dropped and duplicates collapsed. Built once at manifest load (Compile) and
	// merely read here; a condition built programmatically, with no load pass to
	// compile it, normalizes on the spot instead. An empty allowlist denies every path.
	//
	// The match is intentionally asymmetric and broader than it looks: a SINGLE
	// entry (".gz") matches BOTH "file.gz" AND "archive.tar.gz" (".gz" is a
	// dot-boundary suffix of ".tar.gz"), while a COMPOUND entry (".tar.gz") matches
	// only "archive.tar.gz". There is no way to allow ".gz" but deny ".tar.gz" with
	// this allow-only condition; pin the path with allowedValues instead. Documented
	// in the manifest guide; changing the runtime match here would break
	// purpose-built compound allowlists (the single-segment WARNING lives in the
	// validation layer, not here).
	allowed := ae.MatchExtensions()

	for _, filePath := range paths {
		// Normalize '\' separators to '/' and percent-decode (%2f -> '/', %2e -> '.')
		// before matching, so directory components are stripped on the form the
		// upstream actually resolves: path.Base/Ext key off the OS separator, so a
		// backslash or %2f-encoded separator would otherwise smuggle a directory
		// component into the matched file name. An embedded NUL fails closed (a
		// NUL-truncating upstream opens a different file than the suffix checked
		// here). A merely malformed '%' is NOT a confinement concern — '%' is a legal
		// filename char for a non-decoding upstream — so it falls back to the literal
		// form below. Shared with MatchValueGlob via decodePathForConfinement.
		//
		// The gate below uses path.Ext (final-segment view: "is there any
		// extension?") while matching and the denial detail use the full dotted
		// suffix; the two are deliberately not interchangeable.
		normalizedPath, decodeErr := decodePathForConfinement(filePath)
		switch {
		case errors.Is(decodeErr, errPathNUL):
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeAllowedExtensions,
				Message:       "file path contains a NUL byte",
				Details: map[string]interface{}{
					"filePath":          filePath,
					"allowedExtensions": ae.Extensions,
				},
			}
		case errors.Is(decodeErr, errPathMalformedEscape):
			// A valid encoded separator riding alongside the bad escape must still deny.
			// PathUnescape failed on the WHOLE value, so the token was never decoded —
			// matching the literal form treats "evil.exe%2f..%2fx.csv" as a permitted
			// ".csv" file while a lenient upstream resolves the separator into a
			// directory component. (An encoded NUL riding alongside the bad escape
			// already took the errPathNUL arm above, inside decodePathForConfinement, so
			// it cannot reach here.) confineSlashlessPattern applies the identical guard
			// on its own lenient fallback.
			if containsEncodedSeparator(filePath) {
				return &ConditionError{
					Code:          capability.ErrCodeConditionFailed,
					ConditionType: capability.ConditionTypeAllowedExtensions,
					Message:       "file path contains an undecodable percent-escape alongside an encoded path separator",
					Details: map[string]interface{}{
						"filePath":          filePath,
						"allowedExtensions": ae.Extensions,
					},
				}
			}
			// Literal '%' (not a valid escape): match on the separator-folded literal
			// form, since a literal-path upstream opens the file verbatim.
			normalizedPath = strings.ReplaceAll(filePath, "\\", "/")
		}
		ext := strings.ToLower(path.Ext(normalizedPath))
		if ext == "" {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeAllowedExtensions,
				Message:       "file has no extension",
				Details: map[string]interface{}{
					"filePath":          filePath,
					"allowedExtensions": ae.Extensions,
				},
			}
		}

		// Match the file name (not the directory path, so a dotted directory cannot
		// smuggle an extension) against each allowed suffix, on a dot boundary.
		base := strings.ToLower(path.Base(normalizedPath))
		matched := false
		for _, suffix := range allowed {
			if strings.HasSuffix(base, suffix) {
				matched = true
				break
			}
		}
		if !matched {
			// Report the full dotted suffix (".zip.gz", not just ".gz") so a
			// compound-allowlist denial names what actually failed to match.
			suffix := fileSuffix(base)
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeAllowedExtensions,
				Message:       fmt.Sprintf("file extension %q is not allowed", suffix),
				Details: map[string]interface{}{
					"filePath":          filePath,
					"extension":         suffix,
					"allowedExtensions": ae.Extensions,
				},
			}
		}
	}

	return nil
}

// fileSuffix returns a file name's full dotted suffix for denial messages:
// ".zip.gz" for "backup.zip.gz", ".env" for a bare ".env". The suffix is
// everything from the first dot following the base name; a dotfile's leading dots
// are its name prefix, not a boundary, so they are skipped first (hidden
// ".tar.gz" thus yields ".gz", base "tar"). Presentational only — the allow/deny
// decision is made by HasSuffix in handleAllowedExtensions, and the denial record
// always carries the full "filePath" in its Details.
func fileSuffix(base string) string {
	trimmed := strings.TrimLeft(base, ".") // skip a dotfile's own leading dot(s)
	leading := len(base) - len(trimmed)
	if i := strings.IndexByte(trimmed, '.'); i >= 0 {
		return strings.ToLower(base[leading+i:])
	}
	return strings.ToLower(base)
}

func (e *Engine) handleAllowedTables(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	at, condErr := castCondition[capability.AllowedTablesCondition](cond)
	if condErr != nil {
		return condErr
	}

	if at.Argument == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedTables,
			Message:       "allowedTables condition requires an explicit 'argument' field naming the tool parameter that carries the table name(s)",
		}
	}

	// Parse the named argument into a []TableAccess.  The argument value may be:
	//   string                  → single table name, no columns
	//   []interface{} of string → multiple table names, no columns
	//   map[string]interface{}  → {table: "name", columns: ["a","b"]} (single)
	//   []interface{} of maps   → array of the above (multiple with columns)
	var tables []capability.TableAccess
	if v, ok := ResolveArgument(req.Arguments, at.Argument); ok {
		parsed, perr := parseTableArgument(v)
		if perr != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeAllowedTables,
				Message:       fmt.Sprintf("argument %q %s", at.Argument, perr),
				Details:       map[string]interface{}{"argument": at.Argument},
			}
		}
		tables = parsed
	}
	if len(tables) == 0 {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeAllowedTables,
			Message:       fmt.Sprintf("argument %q is missing or empty", at.Argument),
			Details:       map[string]interface{}{"argument": at.Argument},
		}
	}

	// The case-folded lookup structures: the allowed-table set, the column-restriction
	// index (keyed by lowercased table so a "users" restriction still covers table
	// "USERS" rather than skipping the column ACL, with values in original case so
	// denial details echo the manifest), and the per-table matching column sets. Built
	// once at manifest load (Compile) and merely read here; a condition built
	// programmatically, with no load pass to compile it, builds them on the spot.
	allowedTableSet, columnsByTable, columnSets := at.TableLookup()

	for _, access := range tables {
		tableKey := strings.ToLower(access.Table)
		if !allowedTableSet[tableKey] {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeAllowedTables,
				Message:       fmt.Sprintf("table %q is not allowed", access.Table),
				Details: map[string]interface{}{
					"table":         access.Table,
					"allowedTables": at.Tables,
				},
			}
		}

		// When a table has column restrictions, an empty access.Columns must be
		// denied — else an agent could bypass the column ACL by omitting the field.
		if columnsByTable != nil {
			allowedCols, hasColumnRestriction := columnsByTable[tableKey]
			if hasColumnRestriction {
				if len(access.Columns) == 0 {
					return &ConditionError{
						Code:          capability.ErrCodeMissingContext,
						ConditionType: capability.ConditionTypeAllowedTables,
						Message:       fmt.Sprintf("column list required for table %q (column restrictions are configured)", access.Table),
						Details: map[string]interface{}{
							"table":          access.Table,
							"allowedColumns": allowedCols,
						},
					}
				}
				colSet := columnSets[tableKey]
				for _, col := range access.Columns {
					// Trim the request column to match the trimmed allowlist set:
					// parseTableArgument stores column names verbatim (only blank-rejecting),
					// so a whitespace-padded "id " would otherwise miss an allowlisted "id"
					// and be false-denied. The table-name comparison above is already
					// symmetric (parseTableArgument trims table names); columns are the one
					// place the request side was left untrimmed. The denial message keeps the
					// original, untrimmed col so the operator sees exactly what was sent.
					if !colSet[strings.ToLower(strings.TrimSpace(col))] {
						return &ConditionError{
							Code:          capability.ErrCodeConditionFailed,
							ConditionType: capability.ConditionTypeAllowedTables,
							Message:       fmt.Sprintf("column %q on table %q is not allowed", col, access.Table),
							Details: map[string]interface{}{
								"table":          access.Table,
								"column":         col,
								"allowedColumns": allowedCols,
							},
						}
					}
				}
			}
		}
	}

	return nil
}

func (e *Engine) handleRecipientDomain(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	rd, condErr := castCondition[capability.RecipientDomainCondition](cond)
	if condErr != nil {
		return condErr
	}

	if rd.Argument == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeRecipientDomain,
			Message:       "recipientDomain condition requires an explicit 'argument' field naming the tool parameter that carries the recipient address(es)",
		}
	}

	recipients, cerr := resolveStringOrStringArray(req.Arguments, rd.Argument, capability.ConditionTypeRecipientDomain)
	if cerr != nil {
		return cerr
	}

	// The lowercased, trimmed domain set. Built once at manifest load (Compile) and
	// merely read here; a condition built programmatically, with no load pass to
	// compile it, builds it on the spot.
	domainSet := rd.MatchDomains()

	for _, recipient := range recipients {
		parts := strings.SplitN(recipient, "@", 2)
		// Require exactly one non-empty local part and one non-empty domain with no
		// internal whitespace, no second "@", no IP-literal ("user@[192.168.1.1]"),
		// and no leading/trailing dot. Each would otherwise surface as a misleading
		// "domain not allowed" denial (or, for syntax like "[192.168.1.1]", silently
		// match only an allowlist entry that literally repeats it). Failing closed
		// here with a distinct "invalid recipient email" keeps malformed input
		// separable from a real policy denial. The recipient is TrimSpace'd above, so
		// any remaining whitespace is internal.
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" ||
			strings.ContainsFunc(parts[0], unicode.IsSpace) ||
			strings.ContainsFunc(parts[1], unicode.IsSpace) ||
			strings.ContainsRune(parts[1], '@') ||
			strings.ContainsAny(parts[1], "[]") ||
			strings.HasPrefix(parts[1], ".") || strings.HasSuffix(parts[1], ".") {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeRecipientDomain,
				Message:       fmt.Sprintf("invalid recipient email: %s", recipient),
			}
		}
		domain := strings.ToLower(parts[1])
		if !domainSet[domain] {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeRecipientDomain,
				Message:       fmt.Sprintf("recipient domain %q is not allowed", domain),
				Details: map[string]interface{}{
					"recipient":      recipient,
					"domain":         domain,
					"allowedDomains": rd.Domains,
				},
			}
		}
	}

	return nil
}

func (e *Engine) handleAllowedValues(_ context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return EvaluateAllowedValues(cond, req)
}

// EvaluateAllowedValues is the ONE implementation of the allowedValues predicate, exported
// so the JWT capability-claim path evaluates the identical check instead of hand-copying it.
//
// It is a plain function rather than a method because the check reads nothing off the engine:
// no clock, no counter, no store. That is also what makes it safe for the composed caller —
// it decides and COMMITS NOTHING, so a wrapping PDP can run it before the inner PDP's own
// decision without double-counting a window slot, writing a flow label, or recording a
// sequenceBlock antecedent. (The engine's full evaluator does commit, which is why routing
// the shorthand path through EvaluateConditions is not the same fix; see the same constraint
// on CeilingVerdictFor and DeclassifyVerdictFor.)
//
// The duplication it removes had already produced two divergences and one live defect. The
// copy lacked the empty-argument guard and the structured Details below, so one logical
// refusal reached the tape with two shapes depending only on whether a token was involved,
// and a SIEM rule written against the manifest path's allowedValues denial found nothing for
// a token-scoped caller. Earlier, task-variable resolution was added on this side and not the
// other, and every grant carrying a "${task.*}" reference denied every call under it. Both
// are the same mechanism, and a shared predicate is what retires it: the next semantic added
// here — a coercion rule, a reference kind, a bounded-details rule — reaches both paths by
// construction rather than by whoever edits it remembering there are two.
//
// A caller outside the engine must pass the returned Details through BoundDenialDetails
// before they reach an audit record; on the engine's own path denyResponse does that for
// every deny it builds.
func EvaluateAllowedValues(cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	av, condErr := castCondition[capability.AllowedValuesCondition](cond)
	if condErr != nil {
		return condErr
	}

	if av.Argument == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedValues,
			Message:       "allowedValues condition has empty argument name",
		}
	}

	// Unreachable from the engine, which never evaluates a condition without a request, but
	// this is an exported seam now: a nil request must DENY rather than panic the request
	// goroutine (fail-open-via-crash) or read as a condition that passed.
	if req == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedValues,
			Message:       "allowedValues evaluated with no request to check against",
		}
	}

	argValue, present := ResolveArgument(req.Arguments, av.Argument)
	if !present {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeAllowedValues,
			Message:       fmt.Sprintf("required argument %q is missing", av.Argument),
			Details: map[string]interface{}{
				"argument": av.Argument,
			},
		}
	}

	// MatchAllowedValue centralizes the string-glob-vs-non-string-exact semantics AND the
	// task-context variable resolution, both shared with the JWT shorthand PDP (see its doc
	// for the rationale).
	if MatchAllowedValue(argValue, av.Values, req.Claims) {
		return nil
	}

	return &ConditionError{
		// VALUE_NOT_PERMITTED matches the denial_code the JWT PDP emits for the same
		// failure, keeping audit records and SIEM rules consistent across the manifest
		// and JWT paths. Malformed-input denials above stay CONDITION_FAILED.
		Code:          capability.ErrCodeValueNotPermitted,
		ConditionType: capability.ConditionTypeAllowedValues,
		Message:       fmt.Sprintf("argument %q value is not in the allowed set", av.Argument),
		Details: map[string]interface{}{
			"argument":      av.Argument,
			"value":         argValue,
			"allowedValues": av.Values,
		},
	}
}

// MatchAllowedValue reports whether argValue satisfies an allowedValues set. It is
// the single matcher shared by EvaluateAllowedValues and, through it, the JWT shorthand
// PDP, and it
// answers the WHOLE question — glob matching and task-context variable resolution
// together — against the caller's validated claims.
//
// claims is what makes that possible, and it is a parameter rather than a second call
// a caller must remember. Resolution used to live outside this function, and the
// consequence was structural: the matcher SKIPS a recognized "${task.*}" entry, so a
// caller that ran only this voided every grant carrying one. That is what the JWT
// shorthand path did — a token whose capability claim read
// `tool:fetch_workspace?workspace_id=${task.id}` skipped its only allowed-value entry,
// matched nothing, and denied every call under the grant with VALUE_NOT_PERMITTED and no
// diagnostic naming the cause. It fails closed, so it was a silent usability defect rather
// than a widening — and the fix is to make the two inseparable, so a future caller
// inherits "task vars resolve" by construction instead of "task vars never match" by
// default. nil claims (no token) simply resolve nothing.
//
// One loop, one classification per entry: the skip rule and the resolve rule are the two
// halves of the same decision about one allowed-value, so evaluating them in separate
// passes both re-parsed every entry and left the two able to disagree about what counts as
// a recognized reference — a disagreement that voids the grant silently, which is the very
// defect above.
//
// A string allowed entry is matched ONLY as a glob via MatchValueGlob, never by
// exact equality: MatchValueGlob treats a metacharacter-free pattern as a literal,
// so a plain value still matches itself, while an exact-first check would let the
// literal pattern text bypass a glob (values: ["[0-9]"] means a single digit, not
// "[0-9]"). A string pattern cannot match a non-string argument.
//
// A non-string entry (bool, number, nil) is matched by exact value, with
// numericEqual bridging the YAML-int vs JSON-float64 type gap.
func MatchAllowedValue(argValue interface{}, allowed []interface{}, claims map[string]interface{}) bool {
	argStr, argIsString := argValue.(string)
	for _, a := range allowed {
		pattern, ok := a.(string)
		if !ok {
			if reflect.DeepEqual(a, argValue) || numericEqual(a, argValue) {
				return true
			}
			continue
		}
		// ONE classification per entry, deciding both branches. A recognized "${task.*}"
		// entry is a reference, never a pattern: it carries no glob metacharacter, so
		// MatchValueGlob would treat it as a literal — and an argument whose value happened
		// to be the placeholder TEXT ("${task.id}") would satisfy an identity binding by
		// spelling it out. So the two rules are mutually exclusive per entry, which is
		// exactly why they belong in one loop. Two passes with two different predicates
		// (IsTaskVarRef to skip, ParseVariableRef to resolve) could disagree if the closed
		// set ever moved, and an entry skipped by the first that the second declined to
		// resolve would match NOTHING — silently voiding the grant, which is the defect this
		// function was rewritten to fix.
		name, isRef := capability.ParseVariableRef(pattern)
		if _, known := capability.TaskVarClaimKey(name); isRef && known {
			// A resolved value is IdP-supplied text compared by EXACT equality, never
			// through the glob below: run through MatchValueGlob, a claim of "*" would
			// become an allow-anything wildcard the token holder chose for themselves. An
			// unresolvable reference (no token, or the claim absent or empty) matches
			// nothing rather than falling back to the placeholder text, so a missing
			// identity never widens the set.
			if !argIsString || len(claims) == 0 {
				continue
			}
			if resolved, ok := capability.ResolveTaskVar(name, claims); ok && resolved == argStr {
				return true
			}
			continue
		}
		// Not a recognized reference. That includes an UNRECOGNIZED "${STAGE}", which this
		// matcher must keep treating as a literal: it is shared with the JWT shorthand path,
		// whose values come from a TOKEN's capability claim rather than a manifest, so such
		// a value has never passed through the loader and voiding it would kill the grant
		// with no diagnostic anywhere to grep for. It stays a literal and matches itself.
		if argIsString && MatchValueGlob(pattern, argStr) {
			return true
		}
	}
	return false
}

// OperationVerb extracts the operation token from an argument value: the uppercased
// first whitespace-delimited word, or "" when s is empty or blank. It is the shared
// verb extractor for allowedOperations matching across the engine's
// handleAllowedOperations and the JWT shorthand PDP, so the two cannot diverge on
// how an operation is derived from a string argument (e.g. "SELECT * FROM t" yields
// "SELECT").
//
// First token ONLY, deliberately: a compound statement ("SELECT 1; DROP TABLE users")
// verbs as its leading word, so allowedOperations does not block the trailing
// statement — see AllowedOperationsCondition's doc for why the boundary is documented
// rather than widened, and what to pair the condition with. Anything more than a verb
// gate belongs in argumentSchema, an external PolicyEvaluator, or the database's own
// grants; do not grow a SQL parser here.
func OperationVerb(s string) string {
	return capability.OperationVerb(s)
}

// numericEqual reports whether a and b are both numeric and equal in value,
// independent of concrete Go type. Manifest values decode from YAML as int while
// request arguments decode as float64, so a bare manifest integer would not
// reflect.DeepEqual-match the same request number without this bridge. Non-numeric
// values return false (handled by the caller's exact-match path).
//
// When both represent an integer they are compared exactly — as int64 within that
// range, and as an exact rational beyond it — so two distinct integers that share a
// float64 are never conflated at any magnitude. Only genuinely FRACTIONAL values fall
// back to the float64 comparison.
func numericEqual(a, b any) bool {
	ia, aInt := asInt64(a)
	ib, bInt := asInt64(b)
	if aInt && bInt {
		return ia == ib
	}
	// Exactly one operand is a representable int64 and the other is not (e.g.
	// math.MaxInt64 vs math.MaxInt64+1): they are by definition distinct integers
	// and must not be collapsed onto a shared float64, which would round them equal.
	if aInt != bInt {
		return false
	}
	// Neither is int64-representable. When BOTH are still integers, compare them
	// exactly: the float64 fallback below rounds distinct integers above 2^63 onto a
	// shared value, so allowedValues: [9223372036854775808] would admit the argument
	// 9223372036854775809 — a value outside the declared set, which is the fail-open
	// direction. The int64 arm above cannot cover this because neither side fits.
	//
	// Restricted to integers on purpose. A fractional decimal literal and its float64
	// coercion are genuinely different rationals (0.1 is not the binary double nearest
	// 0.1), so comparing those exactly would make an argument of 0.1 stop matching a
	// manifest value of 0.1 — breaking working policies to no security benefit, since
	// the float64 approximation is consistent on both sides.
	if ra, ok := exactIntegerRat(a); ok {
		if rb, ok := exactIntegerRat(b); ok {
			return ra.Cmp(rb) == 0
		}
	}
	fa, aOK := toFloat64(a)
	fb, bOK := toFloat64(b)
	return aOK && bOK && fa == fb
}

// exactIntegerRat returns v's exact value as a *big.Rat when v holds an INTEGER of any
// magnitude, reporting false for a fractional value, a non-numeric, or a non-finite
// float. It is the beyond-int64 companion to asInt64: the two together let a numeric
// comparison stay exact across the whole integer range instead of lapsing to float64
// (and its rounding) at 2^63.
//
// A float64 operand converts through its exact binary value, which is what that
// operand actually is — a float64 that reads as 9223372036854775808 IS 2^63 exactly,
// and comparing it against the decimal literal 9223372036854775809 correctly reports
// them distinct.
func exactIntegerRat(v any) (*big.Rat, bool) {
	r, ok := exactRat(v)
	if !ok || !r.IsInt() {
		return nil, false
	}
	return r, true
}

// Bounds on the decimal literal exactRat will hand to big.Rat.SetString. Both are
// REQUIRED, not defensive: SetString's mantissa scan is superlinear, and its exponent
// handling materializes 10^N, so an unbounded parse is a CPU/memory denial of service
// on the pre-forward enforcement path — reachable with one tool-call argument, since
// arguments decode in UseNumber mode and arrive here as their verbatim literal text.
// Measured on the un-guarded form: a 1M-digit fractional literal cost 1.8 s of one
// core, and the 9-byte "1e1000000" cost ~25 ms and ~1 MiB, both per comparison and
// multiplied by the number of allowedValues/enum entries.
//
// internal/mcp's MsgKey bounds its own big.Rat parse the same way and for the same
// reason; the values match it deliberately. They are generous relative to the job:
// this arm exists to compare integers around and above 2^63 exactly, which needs
// tens of digits, so 1024 leaves orders of magnitude of headroom while making the
// worst case sub-millisecond. A literal past either bound falls through to the
// float64 comparison, which is what happened for every such value before the exact
// arm existed — no new fail-open, just no exactness for a literal no policy writes.
// The literal bound lives in pkg/capability (NumericLiteralBounded): the JSON-RPC id
// parse, this exact comparison, and the effect layer's blast-radius parse all need the
// identical guard against the identical input class, and three hand-rolled copies is how
// one of them ends up without it.

// exactRat returns v's exact value as a *big.Rat, without the float64 round-trip
// asInt64/toFloat64 take. Only the types that can carry a value outside int64 range
// are handled — everything else reaches a comparison through asInt64 first.
func exactRat(v any) (*big.Rat, bool) {
	switch n := v.(type) {
	case json.Number:
		// SetString parses the decimal literal exactly, including the digits a float64
		// coercion would round away. It also accepts exponent forms ("1e30"), which is
		// what makes this the right parse for an argument decoded in UseNumber mode —
		// and what makes the exponent bound necessary.
		if !capability.NumericLiteralBounded(string(n)) {
			return nil, false
		}
		return new(big.Rat).SetString(string(n))
	case uint64:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(n)), true
	case uint:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(uint64(n))), true
	case float32:
		return ratFromFloat(float64(n))
	case float64:
		return ratFromFloat(n)
	}
	return nil, false
}

// ratFromFloat is exactRat's float arm: big.Rat cannot represent Inf or NaN, and
// SetFloat64 returns nil for both, so report those as having no exact value rather
// than dereferencing nil. A float64 needs no length bound — it is already 8 bytes.
func ratFromFloat(f float64) (*big.Rat, bool) {
	r := new(big.Rat).SetFloat64(f)
	return r, r != nil
}

// maxInt64Uint is math.MaxInt64 as a uint64, for the unsigned arms of asInt64. The
// float64 range bounds that used to sit here live in pkg/capability alongside
// FloatToInt64, the single definition of "exactly representable as an int64" this
// package's comparison and that package's manifest-load validation now share.
const maxInt64Uint = uint64(1<<63 - 1)

// asInt64 reports the int64 value of v when v holds an integer: any signed/unsigned
// integer within int64 range, a json.Number parsing as an integer, or an integral
// in-range float. It lets numericEqual compare integers exactly rather than through
// a lossy float64 round-trip; out-of-range or fractional values report false so the
// caller falls back to the float64 path. json.Number is handled for arguments
// decoded in UseNumber mode, which would otherwise spuriously deny on a string
// compare.
func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		if f, err := n.Float64(); err == nil {
			return capability.FloatToInt64(f)
		}
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		if u := uint64(n); u <= maxInt64Uint {
			return int64(u), true
		}
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n <= maxInt64Uint {
			return int64(n), true
		}
	case float32:
		return capability.FloatToInt64(float64(n))
	case float64:
		return capability.FloatToInt64(n)
	}
	return 0, false
}

// toFloat64 converts any Go numeric type to float64, reporting false for
// non-numeric values. bool is deliberately excluded so that true/1 and false/0
// are never treated as numerically equal. json.Number is handled for the same
// UseNumber-decoded argument reason as asInt64.
func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return f, true
		}
		return 0, false
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// handleSequenceBlock blocks the current call when any tool named in afterTools
// was previously recorded in this session.
//
// Known limitation — concurrent same-session requests: the antecedent check
// (a counter Peek on the antecedent tool's key) and the recording of an antecedent's
// call (RecordSessionCall's IncrementAndGet on that tool's key, on a SEPARATE
// request) are not atomic, so firing the antecedent and the blocked tool
// concurrently on one session can let the blocked tool Peek empty history and slip
// through. This is intrinsic to two independent requests racing; only per-session
// serialization could close it, which the engine deliberately does not impose.
// MCP's per-session request model is serial, so a compliant client never triggers
// it. Note this is NOT a Redis-atomicity gap that a check-and-set admission (the shape
// AdmitAll uses) could close: the check and the antecedent's recording happen in different
// requests on different keys, so there is no single key/op to make atomic, and the
// race is identical under the in-memory and Redis backends. See
// docs/capability-manifest-guide.md (sequenceBlock).
func (e *Engine) handleSequenceBlock(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	sb, condErr := castCondition[capability.SequenceBlockCondition](cond)
	if condErr != nil {
		return condErr
	}

	// Fail closed on a malformed condition: with no antecedent tools the rule
	// can never fire, which is almost certainly an authoring mistake. Deny rather
	// than silently allowing everything.
	if len(sb.AfterTools) == 0 {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeSequenceBlock,
			Message:       "sequenceBlock condition requires a non-empty 'afterTools' list naming the tools whose prior use blocks this call",
		}
	}

	// Fail closed when an entry names no tool after its prefix is stripped and
	// whitespace trimmed (e.g. "", "tool:", "  "): such an entry can never match a
	// recorded name, so silently skipping it would let an all-empty list fall
	// through to allow — fail-open for a security rule. This pre-check runs before the
	// counter/history checks below and is load-bearing for the antecedent loop, which
	// relies on every bare name being non-empty and so carries no empty-name guard of
	// its own.
	var emptyAfterTools []string
	for _, prior := range sb.AfterTools {
		if strings.TrimSpace(StripEnginePrefix(prior)) == "" {
			emptyAfterTools = append(emptyAfterTools, prior)
		}
	}
	if len(emptyAfterTools) > 0 {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeSequenceBlock,
			Message:       fmt.Sprintf("sequenceBlock 'afterTools' contains entries that name no tool after the namespace prefix is stripped: %v", emptyAfterTools),
			Details: map[string]interface{}{
				"emptyAfterTools": emptyAfterTools,
				"afterTools":      sb.AfterTools,
			},
		}
	}

	if e.counter == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeSequenceBlock,
			Message:       "call counter not configured",
		}
	}

	// A missing sessionID would merge history across anonymous callers, letting one
	// session gate another. Deny rather than consult a shared bucket.
	if req.SessionID == "" {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeSequenceBlock,
			Message:       "sessionId is required for sequenceBlock condition",
		}
	}

	// Resolve the blocked target's namespace as RecordSessionCall does: prefer the
	// explicit req.Target.Type, falling back to the req.TargetName prefix (bare
	// defaults to "tool"), and to req.Target.Name when req.TargetName is empty
	// (resource/prompt requests carry the identifier there). Reporting in
	// namespace:name form disambiguates same-named targets in the audit log.
	blockedType, blockedName := splitEnginePrefix(req.TargetName)
	if req.Target != nil {
		if req.Target.Type != "" {
			blockedType = req.Target.Type
		}
		if blockedName == "" && req.Target.Name != "" {
			blockedName = strings.TrimSpace(req.Target.Name)
		}
	}
	blockedTarget := blockedType + ":" + blockedName
	// When no name is present (both req.TargetName and req.Target.Name absent), report
	// "(unknown)" rather than the misleading "tool:" sentinel, so a SIEM rule parsing
	// blockedTool as namespace:name does not extract an empty name.
	blockedDetail := blockedTarget
	if blockedName == "" {
		blockedDetail = "(unknown)"
	}
	// Every history access below runs on a context detached from the REQUEST's
	// cancellation. ctx is the host request context, which net/http cancels the instant
	// the client disconnects, and a backend that honors it (the Redis pipeline does;
	// the in-memory one ignores ctx) then fails both the lookup and the re-arm. That
	// hands the gate's own I/O to the party the gate constrains: a client that probes
	// the blocked target and drops the connection each time gets a fail-closed deny —
	// from the lookup ERROR, never reaching the count > 0 branch — so the marker is
	// never refreshed and the gate reverts to expiring on pure wall clock, the
	// fail-open the re-arm exists to close, triggerable at will.
	//
	// Detaching also makes the verdict accurate rather than a spurious infrastructure
	// denial for any genuinely cancelled request. WithoutCancel keeps the context's
	// values (a backend reading request-scoped state still sees them) and drops only
	// the cancellation; the Redis client's own dial/read/write timeouts still bound
	// every call, so a partitioned backend cannot wedge this.
	histCtx := context.WithoutCancel(ctx)
	for _, prior := range sb.AfterTools {
		// Resolve each antecedent's namespace from its prefix (bare defaults to
		// "tool"), mirroring RecordSessionCall, so afterTools: [export] matches only
		// the tool and [prompt:export] only the prompt. Trim whitespace so a padded
		// "export " still matches the recorded name. No empty-name guard is needed —
		// the pre-check above guaranteed priorTool is non-empty. Report by namespace
		// in denials to disambiguate a manifest listing both "export" and
		// "prompt:export".
		priorType, priorTool := splitEnginePrefix(prior)
		priorTool = strings.TrimSpace(priorTool)
		priorTarget := priorType + ":" + priorTool
		key := e.sequenceHistoryKey(req, priorType, priorTool)

		count, err := e.counter.Peek(histCtx, key, sequenceHistoryWindowSec)
		if err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeSequenceBlock,
				Message:       fmt.Sprintf("session history lookup failed: %v", err),
			}
		}
		if count > 0 {
			// Re-arm the antecedent marker so its retention measures inactivity rather
			// than age. The marker is only refreshed by a fresh call to the antecedent
			// (RecordSessionCall), so without this a session that called the antecedent
			// once has its gate expire sequenceHistoryWindowSec later even while the
			// session is demonstrably still live and still probing the blocked target —
			// a purely wall-clock fail-OPEN of a security gate. Refreshing here makes a
			// session that keeps attempting the blocked target keep the gate armed.
			//
			// Best-effort by design (histCtx is detached from request cancellation — see above): this runs on a path that has ALREADY decided to
			// deny, so a write fault cannot turn this denial into an allow, and
			// surfacing it as a lookup error would convert a correct, precise
			// sequenceBlock denial into a generic backend-fault one — strictly worse
			// operator signal for the same outcome. The failure mode of ignoring it is
			// only that retention keeps measuring from the antecedent's own call, which
			// is exactly the pre-existing behavior. maxEntries is the same
			// sequenceHistoryMaxEntries the recorder uses, and the backends retain the
			// NEWEST entries, so this refreshes the single marker rather than growing it.
			//
			// Only the marker that MATCHED is refreshed: the loop returns here, and a
			// target recorded under two spellings (RecordSessionCall's alias + primary)
			// has only the probed one re-armed. That is the documented per-pair contract —
			// retention measures inactivity of THIS (antecedent, blocked target) pair —
			// not an oversight; a pair no call ever exercises still ages out.
			_, _ = e.counter.IncrementAndGet(histCtx, key, sequenceHistoryWindowSec, sequenceHistoryMaxEntries)
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeSequenceBlock,
				Message:       fmt.Sprintf("%s %q was already called in this session; %s %q is blocked after it", priorType, priorTool, blockedType, blockedName),
				Details: map[string]interface{}{
					"afterTool":   priorTarget,
					"blockedTool": blockedDetail,
					"afterTools":  sb.AfterTools,
				},
			}
		}
	}

	return nil
}

func (e *Engine) handlePolicy(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	pc, condErr := castCondition[capability.PolicyCondition](cond)
	if condErr != nil {
		return condErr
	}

	// Fail closed: a policy condition must not be silently allowed when no evaluator
	// is wired up. Configure one via WithPolicyEvaluator.
	if e.policyEvaluator == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypePolicy,
			Message:       "no policy evaluator configured; register one via WithPolicyEvaluator",
			Details: map[string]interface{}{
				"backend": pc.Backend,
			},
		}
	}

	return e.policyEvaluator.Evaluate(ctx, pc.Backend, pc.Config, pc.Input, req)
}

func (e *Engine) handleCustom(_ context.Context, cond capability.Condition, _ *capability.EnforceRequest) *ConditionError {
	cc, condErr := castCondition[capability.CustomCondition](cond)
	if condErr != nil {
		return condErr
	}

	// Fail closed: no handler is registered for custom conditions. Supply one via
	// WithConditionHandler(capability.ConditionTypeCustom, handler).
	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeCustom,
		Message:       fmt.Sprintf("no handler registered for custom condition %q; register one via enforcement.WithConditionHandler", cc.Name),
		Details: map[string]interface{}{
			"name": cc.Name,
		},
	}
}

// parseTableArgument converts a raw tool argument value into a []TableAccess.
// Accepted shapes:
//
//	string                                   → [{Table: s}]
//	[]interface{} of strings                 → [{Table: s}, ...]
//	map{"table": s, "columns": [...]}        → [{Table: s, Columns: [...]}]
//	[]interface{} of the above maps          → [{Table, Columns}, ...]
//
// A non-string item inside an array argument, a non-string entry inside a
// table's columns list, or a map that carries no non-empty "table" entry is a
// structurally malformed argument: it returns a non-nil error so the caller can
// deny fail-closed rather than silently evaluating the valid subset (matching
// allowedExtensions and recipientDomain).
func parseTableArgument(v interface{}) ([]capability.TableAccess, error) {
	// Both array shapes share ONE arm (see asInterfaceSlice). Checked before the type
	// switch so a native []string reaches the same blank-element and non-string-item
	// rules as a decoded []interface{} rather than a mirrored copy of them.
	if items, isArray := asInterfaceSlice(v); isArray {
		var out []capability.TableAccess
		for _, item := range items {
			switch item.(type) {
			case string, map[string]interface{}:
				parsed, err := parseTableArgument(item)
				if err != nil {
					// Keep the array context so a malformed element is not reported
					// as if the whole argument were a bare map.
					return nil, fmt.Errorf("array element %s", err)
				}
				if len(parsed) == 0 {
					// A blank element in a populated array (e.g. "" in ["users", ""])
					// is structurally malformed — unlike a top-level empty argument,
					// which is MISSING_CONTEXT. Fail closed rather than drop it.
					return nil, fmt.Errorf("array element is an empty or blank table name")
				}
				out = append(out, parsed...)
			default:
				return nil, fmt.Errorf("array contains a non-string item: %T", item)
			}
		}
		return out, nil
	}
	switch t := v.(type) {
	case string:
		if s := strings.TrimSpace(t); s != "" {
			return []capability.TableAccess{{Table: s}}, nil
		}
	case map[string]interface{}:
		tableName, _ := t["table"].(string)
		if tableName = strings.TrimSpace(tableName); tableName == "" {
			// A map with no non-empty "table" entry (e.g. {"columns": ["id"]}) is
			// structurally malformed, not a missing argument — the value is present
			// but lacks the required entry. Fail closed with CONDITION_FAILED rather
			// than the misleading MISSING_CONTEXT denial.
			return nil, fmt.Errorf("is a map with no non-empty 'table' entry")
		}
		ta := capability.TableAccess{Table: tableName}
		// An absent "columns" entry (or an explicit JSON null) means unrestricted column
		// access, intentionally. Anything present must be an array of strings; a silently
		// unhandled shape would leave ta.Columns nil, which reads as "allow all columns"
		// and turns an intended restriction into a wildcard.
		if rawCols := t["columns"]; rawCols != nil {
			cols, isArray := asInterfaceSlice(rawCols)
			if !isArray {
				return nil, fmt.Errorf("table %q columns must be an array of strings; got %T", tableName, rawCols)
			}
			for _, c := range cols {
				col, ok := c.(string)
				if !ok {
					return nil, fmt.Errorf("table %q columns list contains a non-string item: %T", tableName, c)
				}
				// A blank column is structurally malformed: dropping it would quietly
				// change the enforced policy with no audit trace. Fail closed.
				if strings.TrimSpace(col) == "" {
					return nil, fmt.Errorf("table %q columns list contains an empty or blank column name", tableName)
				}
				ta.Columns = append(ta.Columns, col)
			}
		}
		return []capability.TableAccess{ta}, nil
	default:
		// A present argument of an unsupported scalar type (number, boolean, null) is
		// a type mismatch, not a missing value: fail closed with CONDITION_FAILED. The
		// string/array/map cases above fall through to nil,nil for a genuinely empty
		// value, which the caller reports as MISSING_CONTEXT.
		return nil, fmt.Errorf("must be a string, object, or array of strings/objects; got %T", v)
	}
	return nil, nil
}

// asInterfaceSlice normalizes the two shapes a JSON array argument arrives in onto
// one slice: []interface{} from a JSON decode, and []string from a library caller
// populating EnforceRequest.Arguments natively. ok is false for anything that is not
// an array, which each caller reports as its own type mismatch.
//
// The point is that every array-validating parser then has ONE arm to get right. The
// blank-element and non-string-item checks those parsers run are fail-closed security
// rules (a dropped blank element quietly changes the enforced policy; an unhandled
// []string used to leave a column restriction nil, which reads as "allow all
// columns"), and hand-mirroring them per shape is exactly how one copy loses a check.
// A native []string is copied into a fresh []interface{} rather than validated in
// place; the slices are small (a tool's argument list) and this runs only for an
// argument that is actually an array.
func asInterfaceSlice(v interface{}) ([]interface{}, bool) {
	switch t := v.(type) {
	case []interface{}:
		return t, true
	case []string:
		out := make([]interface{}, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// asCondition returns cond as *T, accepting either a *T or a value T, since a
// manifest condition may decode into either form. Returns (nil, false) otherwise.
// It delegates to capability.AsValueOrPointer — the single value-or-pointer
// normalizer, shared with the directive-side predicates — so the type-switch
// pattern lives in exactly one place instead of a bespoke copy per concrete type.
func asCondition[T any](cond capability.Condition) (*T, bool) {
	return capability.AsValueOrPointer[T](cond)
}

// castCondition casts cond to *T (via asCondition) and, on a type mismatch,
// builds the ConditionError every handler returns for it. T is constrained to
// capability.Condition so condType is DERIVED from a zero T's own
// ConditionType() method rather than passed as a second, independently-typed
// argument — a prior version took condType as a string parameter, which let a
// call site pair the wrong ConditionType constant with T (e.g.
// castCondition[TimeWindowCondition](cond, ConditionTypeIPRange)) and compile
// silently, corrupting the ConditionType field of a fail-closed deny on the
// signed audit tape. Deriving it from T closes that class of mismatch entirely.
//
// A TYPED-NIL pointer — a (*AllowedValuesCondition)(nil) placed into a programmatically
// built Constraint, or handed to an exported predicate — matches asCondition's `case *T`
// arm and would come back as (nil, nil), after which every handler dereferences it and
// panics the request goroutine: fail-open-via-crash, on the one path whose entire job is
// to fail closed. It is refused here rather than at each of the thirteen handlers,
// mirroring the typed-nil guard CollectObligations applies to directives for the same
// reason. The manifest loader never produces one; an exported seam's caller can.
func castCondition[T capability.Condition](cond capability.Condition) (*T, *ConditionError) {
	t, ok := asCondition[T](cond)
	if !ok || t == nil {
		var zero T
		condType := zero.ConditionType()
		return nil, &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: condType,
			Message:       fmt.Sprintf("invalid %s condition type", condType),
		}
	}
	return t, nil
}
