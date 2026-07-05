// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	if !capability.IsArgumentPath(ref) {
		v, ok := args[capability.ArgumentLiteralKey(ref)]
		return v, ok
	}
	segs := capability.ArgumentPathSegments(ref)
	if segs == nil {
		return nil, false // malformed path: fail closed
	}
	var cur interface{} = args
	for _, seg := range segs {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
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
	// condition (constructed directly, e.g. in a test) reports ok=false and each
	// bound is parsed on demand below, preserving the same behavior.
	preNotBefore, preNotAfter, compiled := tw.Window()

	if tw.NotBefore != "" {
		notBefore := preNotBefore
		if !compiled {
			parsed, err := time.Parse(time.RFC3339Nano, tw.NotBefore)
			if err != nil {
				return &ConditionError{
					Code:          capability.ErrCodeConditionFailed,
					ConditionType: capability.ConditionTypeTimeWindow,
					Message:       fmt.Sprintf("invalid notBefore time: %s", tw.NotBefore),
				}
			}
			notBefore = parsed.UTC()
		}
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
		notAfter := preNotAfter
		if !compiled {
			parsed, err := time.Parse(time.RFC3339Nano, tw.NotAfter)
			if err != nil {
				return &ConditionError{
					Code:          capability.ErrCodeConditionFailed,
					ConditionType: capability.ConditionTypeTimeWindow,
					Message:       fmt.Sprintf("invalid notAfter time: %s", tw.NotAfter),
				}
			}
			notAfter = parsed.UTC()
		}
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
	if networks, ok := ipr.Networks(); ok {
		for _, network := range networks {
			if network.Contains(ip) {
				return nil
			}
		}
	} else {
		// Not pre-compiled (a programmatically constructed condition): parse and
		// match in one pass. The loader rejects malformed CIDRs, so the parse-error
		// branch is reachable only for hand-built conditions; fail closed on it.
		for _, cidr := range ipr.CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return &ConditionError{
					Code:          capability.ErrCodeConditionFailed,
					ConditionType: capability.ConditionTypeIPRange,
					Message:       fmt.Sprintf("invalid CIDR in condition: %s", cidr),
				}
			}
			if network.Contains(ip) {
				return nil
			}
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
// target. The single-condition handler (handleMaxCalls) and the atomic
// multi-condition commit (commitDeferredAtomic, engine.go) both go through it so
// they build the SAME key under the SAME fail-closed guards. skip is true when quota
// must not be consumed (--audit observe mode via WithSkipQuota — treat the condition
// as satisfied); condErr is non-nil on any deny; otherwise the condition and its
// bucket key are returned.
func (e *Engine) maxCallsBucket(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (mc *capability.MaxCallsCondition, key string, skip bool, condErr *ConditionError) {
	mc, condErr = castCondition[capability.MaxCallsCondition](cond)
	if condErr != nil {
		return nil, "", false, condErr
	}

	// Skip the counter (treating the condition as satisfied) when quota must not be
	// consumed: --audit observe mode (WithSkipQuota).
	if skipQuota(ctx) {
		return nil, "", true, nil
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
	// The target type must be in the key because req.ToolName is only the bare name:
	// a tool "export" and a prompt "export" would otherwise drain one budget.
	// sessionTargetKey derives the (type, name) pair exactly as recordSessionCall does
	// — prefix from splitEnginePrefix, overridden by Target.Type when set; name from
	// sessionTargetName — so a direct ValidateAction caller that leaves req.Target nil
	// keys the same bucket the antecedent record uses, rather than collapsing distinct
	// namespaces' targets onto one empty-type bucket.
	//
	// windowSeconds is deliberately NOT part of this logical key: per-window
	// isolation is supplied by each backend appending windowSec to the physical key.
	// Two conditions sharing one window are rejected at load
	// (validateMaxCallsWindowsDistinct). Route scoping is unneeded — session IDs are
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
	return mc, compositeCounterKey("maxcalls", e.counterKeyNamespace, req.SessionID, targetType, toolName), false, nil
}

// maxCallsHandler is the built-in maxCalls condition handler. maxCalls commits a
// sliding-window slot on admit, so beyond the plain Handle path it implements
// CommittingConditionHandler: the engine treats it as a deferred condition (run
// after all pure predicates) and, when a constraint carries more than one deferred
// condition, admits it via the atomic multi-bucket commit. Both facets share
// maxCallsBucket so the single- and multi-condition paths build the SAME key under
// the SAME fail-closed guards.
type maxCallsHandler struct{ e *Engine }

// Handle implements ConditionHandler for the single-condition path.
func (h maxCallsHandler) Handle(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return h.e.handleMaxCalls(ctx, cond, req)
}

// PrepareCommit implements CommittingConditionHandler: it derives the counter
// bucket WITHOUT consuming a slot, so commitDeferredAtomic can admit several
// deferred conditions in one atomic IncrementIfAllBelow.
func (h maxCallsHandler) PrepareCommit(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	mc, key, skip, condErr := h.e.maxCallsBucket(ctx, cond, req)
	if skip {
		return DeferredCommit{}, true, nil
	}
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	return DeferredCommit{
		Key:        key,
		WindowSecs: mc.WindowSeconds,
		Limit:      int64(mc.Count),
		Deny: func(count int64, retryAfter time.Duration) *ConditionError {
			// Surface a Retry-After hint so a caller can back off; fall back to the full
			// window when the backend has no estimate.
			return maxCallsRateLimited(mc, count, retryAfterSeconds(retryAfter, mc.WindowSeconds))
		},
	}, false, nil
}

// handleMaxCalls evaluates a single maxCalls condition, committing a sliding-window
// slot via the backend's atomic IncrementIfBelow so a denied (over-limit) call
// never writes a new timestamp. A constraint carrying more than one maxCalls is
// committed atomically across all of them by commitDeferredAtomic (engine.go), so
// this single-condition path needs no separate non-committing pre-check.
func (e *Engine) handleMaxCalls(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	mc, key, skip, condErr := e.maxCallsBucket(ctx, cond, req)
	if skip {
		return nil
	}
	if condErr != nil {
		return condErr
	}

	count, admitted, retryAfter, err := e.counter.IncrementIfBelow(ctx, key, mc.WindowSeconds, int64(mc.Count))
	if err != nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       fmt.Sprintf("call counter error: %v", err),
		}
	}

	if !admitted {
		// Surface a Retry-After hint so a caller can back off instead of holding the
		// window full; fall back to the full window if the backend has no estimate.
		return maxCallsRateLimited(mc, count, retryAfterSeconds(retryAfter, mc.WindowSeconds))
	}

	return nil
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
	// condition into a no-op permitting any verb. MatchAllowedOperation is the shared
	// case-insensitive matcher the JWT shorthand PDP also uses.
	if MatchAllowedOperation(ao.Operations, operation) {
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
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				out = []string{s}
			}
		case []interface{}:
			for _, item := range t {
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
		case []string:
			// A library caller can populate Arguments with a native []string (JSON
			// decoding yields []interface{}). Accept it with the same blank-entry
			// validation rather than failing on a misleading "got []string" error.
			for _, s := range t {
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

	// Normalize the allowlist once: lowercased, with a leading dot added only when
	// the entry doesn't already start with one, so every entry is a dotted suffix
	// matched on a dot boundary via HasSuffix (".gz" matches "data.gz" not
	// "datagz"). This does not collapse extra dots an entry already starts with —
	// an entry written as "..gz" is left as two leading dots, not folded down to
	// one, so it would then only match a file name literally ending in "..gz".
	// Blank entries are skipped, duplicates collapsed; an empty allowlist denies
	// every path.
	//
	// The match is intentionally asymmetric and broader than it looks: a SINGLE
	// entry (".gz") matches BOTH "file.gz" AND "archive.tar.gz" (".gz" is a
	// dot-boundary suffix of ".tar.gz"), while a COMPOUND entry (".tar.gz") matches
	// only "archive.tar.gz". There is no way to allow ".gz" but deny ".tar.gz" with
	// this allow-only condition; pin the path with allowedValues instead. Documented
	// in the manifest guide; changing the runtime match here would break
	// purpose-built compound allowlists (the single-segment WARNING lives in the
	// validation layer, not here).
	allowed := make([]string, 0, len(ae.Extensions))
	seen := make(map[string]struct{}, len(ae.Extensions))
	for _, ext := range ae.Extensions {
		n := strings.ToLower(strings.TrimSpace(ext))
		if n == "" {
			continue
		}
		if !strings.HasPrefix(n, ".") {
			n = "." + n
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		allowed = append(allowed, n)
	}

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

	// Table and column names are matched case-insensitively: many databases (MySQL,
	// SQL Server) treat identifiers case-insensitively, so a case-sensitive match
	// would let "Password_Hash" slip past a column ACL written as "password_hash".
	// Trim each allowlist entry before lowercasing: request table names are already
	// whitespace-trimmed (parseTableArgument), so a manifest entry carrying surrounding
	// whitespace (" users") would never match and silently deny every call. Mirrors
	// handleAllowedExtensions, which trims for the same reason.
	allowedTableSet := make(map[string]bool, len(at.Tables))
	for _, t := range at.Tables {
		allowedTableSet[strings.ToLower(strings.TrimSpace(t))] = true
	}

	// Index the column-restriction map by lowercased table name so the per-table
	// lookup is case-insensitive too (else a "users" restriction would miss table
	// "USERS" and skip the column ACL). Values keep the original-case column lists
	// so denial details echo the manifest.
	var columnsByTable map[string][]string
	if at.Columns != nil {
		columnsByTable = make(map[string][]string, len(at.Columns))
		for table, cols := range at.Columns {
			columnsByTable[strings.ToLower(strings.TrimSpace(table))] = cols
		}
	}

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
				colSet := make(map[string]bool, len(allowedCols))
				for _, c := range allowedCols {
					colSet[strings.ToLower(strings.TrimSpace(c))] = true
				}
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

	// Trim each allowlist entry before lowercasing: recipients are already
	// whitespace-trimmed (resolveStringOrStringArray), so a manifest entry with
	// surrounding whitespace ("example.com ") would never match and silently deny every
	// call. Mirrors handleAllowedExtensions, which trims for the same reason.
	domainSet := make(map[string]bool, len(rd.Domains))
	for _, d := range rd.Domains {
		domainSet[strings.ToLower(strings.TrimSpace(d))] = true
	}

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

	// MatchAllowedValue centralizes the string-glob-vs-non-string-exact semantics
	// shared with the JWT shorthand PDP (see its doc for the rationale).
	if MatchAllowedValue(argValue, av.Values) {
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
// the single matcher shared by handleAllowedValues and the JWT shorthand PDP.
//
// A string allowed entry is matched ONLY as a glob via MatchValueGlob, never by
// exact equality: MatchValueGlob treats a metacharacter-free pattern as a literal,
// so a plain value still matches itself, while an exact-first check would let the
// literal pattern text bypass a glob (values: ["[0-9]"] means a single digit, not
// "[0-9]"). A string pattern cannot match a non-string argument.
//
// A non-string entry (bool, number, nil) is matched by exact value, with
// numericEqual bridging the YAML-int vs JSON-float64 type gap.
func MatchAllowedValue(argValue interface{}, allowed []interface{}) bool {
	for _, a := range allowed {
		if pattern, ok := a.(string); ok {
			if s, ok := argValue.(string); ok && MatchValueGlob(pattern, s) {
				return true
			}
			continue
		}
		if reflect.DeepEqual(a, argValue) || numericEqual(a, argValue) {
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
func OperationVerb(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToUpper(fields[0])
}

// MatchAllowedOperation reports whether op is in the allowed operations set,
// compared case-insensitively. A "*" entry is NOT a wildcard here — it is rejected
// at manifest load (validateAllowedOperations), so a literal "*" only ever matches
// the operation "*". Shared by handleAllowedOperations and the JWT shorthand PDP so
// operation-matching semantics live in one place rather than two parallel copies.
func MatchAllowedOperation(allowed []string, op string) bool {
	for _, a := range allowed {
		// Trim each allowlist entry: the request verb is already whitespace-trimmed
		// (OperationVerb), so an entry with surrounding whitespace ("SELECT ") would
		// never EqualFold-match and silently deny every call. This path is also shared
		// with the JWT shorthand PDP, whose operation claims never pass through the
		// manifest validator, so the trim matters there too.
		if strings.EqualFold(strings.TrimSpace(a), op) {
			return true
		}
	}
	return false
}

// numericEqual reports whether a and b are both numeric and equal in value,
// independent of concrete Go type. Manifest values decode from YAML as int while
// request arguments decode as float64, so a bare manifest integer would not
// reflect.DeepEqual-match the same request number without this bridge. Non-numeric
// values return false (handled by the caller's exact-match path).
//
// When both represent an integer they are compared exactly as int64, so two
// distinct integers above 2^53 (sharing a float64) are not conflated. Genuinely
// fractional or out-of-int64-range values fall back to the float64 comparison.
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
	fa, aOK := toFloat64(a)
	fb, bOK := toFloat64(b)
	return aOK && bOK && fa == fb
}

// int64 bounds expressed as float64. 2^63 is exactly representable in float64, so
// the half-open guard [minInt64Float, twoTo63Float) admits exactly the floats
// that convert to a valid int64 without overflow.
const (
	minInt64Float = -9223372036854775808.0 // -2^63
	twoTo63Float  = 9223372036854775808.0  // 2^63 (one past math.MaxInt64)
	maxInt64Uint  = uint64(1<<63 - 1)      // math.MaxInt64
)

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
			return floatToInt64(f)
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
		return floatToInt64(float64(n))
	case float64:
		return floatToInt64(n)
	}
	return 0, false
}

// floatToInt64 returns f as an int64 when f is integral and within int64 range,
// reporting false otherwise. The range is guarded before the conversion because a
// float outside int64 range converts to an implementation-defined value in Go.
func floatToInt64(f float64) (int64, bool) {
	if f < minInt64Float || f >= twoTo63Float {
		return 0, false
	}
	i := int64(f)
	if float64(i) != f { // f carried a fractional part
		return 0, false
	}
	return i, true
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
// (history.Peek on the antecedent tool's key) and the recording of an antecedent's
// call (recordSessionCall's IncrementAndGet on that tool's key, on a SEPARATE
// request) are not atomic, so firing the antecedent and the blocked tool
// concurrently on one session can let the blocked tool Peek empty history and slip
// through. This is intrinsic to two independent requests racing; only per-session
// serialization could close it, which the engine deliberately does not impose.
// MCP's per-session request model is serial, so a compliant client never triggers
// it. Note this is NOT a Redis-atomicity gap that an IncrementIfBelow-style check-
// and-set could close: the check and the antecedent's recording happen in different
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
		if strings.TrimSpace(stripEnginePrefix(prior)) == "" {
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

	history := e.counter // non-nil: the e.counter == nil guard above already denied

	// Resolve the blocked target's namespace as recordSessionCall does: prefer the
	// explicit req.Target.Type, falling back to the req.ToolName prefix (bare
	// defaults to "tool"), and to req.Target.Name when req.ToolName is empty
	// (resource/prompt requests carry the identifier there). Reporting in
	// namespace:name form disambiguates same-named targets in the audit log.
	blockedType, blockedName := splitEnginePrefix(req.ToolName)
	if req.Target != nil {
		if req.Target.Type != "" {
			blockedType = req.Target.Type
		}
		if blockedName == "" && req.Target.Name != "" {
			blockedName = strings.TrimSpace(req.Target.Name)
		}
	}
	blockedTarget := blockedType + ":" + blockedName
	// When no name is present (both req.ToolName and req.Target.Name absent), report
	// "(unknown)" rather than the misleading "tool:" sentinel, so a SIEM rule parsing
	// blockedTool as namespace:name does not extract an empty name.
	blockedDetail := blockedTarget
	if blockedName == "" {
		blockedDetail = "(unknown)"
	}
	for _, prior := range sb.AfterTools {
		// Resolve each antecedent's namespace from its prefix (bare defaults to
		// "tool"), mirroring recordSessionCall, so afterTools: [export] matches only
		// the tool and [prompt:export] only the prompt. Trim whitespace so a padded
		// "export " still matches the recorded name. No empty-name guard is needed —
		// the pre-check above guaranteed priorTool is non-empty. Report by namespace
		// in denials to disambiguate a manifest listing both "export" and
		// "prompt:export".
		priorType, priorTool := splitEnginePrefix(prior)
		priorTool = strings.TrimSpace(priorTool)
		priorTarget := priorType + ":" + priorTool
		key := sequenceHistoryKey(e.counterKeyNamespace, req.SessionID, priorType, priorTool)

		count, err := history.Peek(ctx, key, sequenceHistoryWindowSec)
		if err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeSequenceBlock,
				Message:       fmt.Sprintf("session history lookup failed: %v", err),
			}
		}
		if count > 0 {
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
	switch t := v.(type) {
	case string:
		if s := strings.TrimSpace(t); s != "" {
			return []capability.TableAccess{{Table: s}}, nil
		}
	case []interface{}:
		var out []capability.TableAccess
		for _, item := range t {
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
	case []string:
		// A library caller can pass a native []string (JSON decoding yields
		// []interface{}), which would otherwise hit default and be denied on a "got
		// []string" error. Mirror the []interface{} arm, failing closed on a blank
		// element in a populated array.
		var out []capability.TableAccess
		for _, name := range t {
			trimmed := strings.TrimSpace(name)
			if trimmed == "" {
				return nil, fmt.Errorf("array element is an empty or blank table name")
			}
			out = append(out, capability.TableAccess{Table: trimmed})
		}
		return out, nil
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
		switch cols := t["columns"].(type) {
		case nil:
			// No "columns" entry: unrestricted column access (intentional).
		case []interface{}:
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
		case []string:
			// A library caller can set "columns" to a native []string. Without this
			// case the assertion failed silently, leaving ta.Columns nil — which means
			// "allow all columns", turning an intended restriction into a wildcard.
			for _, col := range cols {
				if strings.TrimSpace(col) == "" {
					return nil, fmt.Errorf("table %q columns list contains an empty or blank column name", tableName)
				}
				ta.Columns = append(ta.Columns, col)
			}
		default:
			return nil, fmt.Errorf("table %q columns must be an array of strings; got %T", tableName, t["columns"])
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

// asCondition returns cond as *T, accepting either a *T or a value T, since a
// manifest condition may decode into either form. Returns (nil, false) otherwise.
func asCondition[T any](cond capability.Condition) (*T, bool) {
	// Switch on any(cond): a direct cond.(*T) is rejected because *T is not provably
	// a capability.Condition, but a type switch over an empty interface accepts both.
	switch t := any(cond).(type) {
	case *T:
		return t, true
	case T:
		return &t, true
	default:
		return nil, false
	}
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
func castCondition[T capability.Condition](cond capability.Condition) (*T, *ConditionError) {
	t, ok := asCondition[T](cond)
	if !ok {
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
