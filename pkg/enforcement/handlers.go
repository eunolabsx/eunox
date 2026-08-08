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

// ResolveArgument looks up the value a condition's `argument` refers to. A plain name is
// a top-level key; "$.a.b" is a dotted path into nested object arguments; "$$.x" is the
// escaped literal form of a top-level key that itself starts with "$.". Every
// argument-matching condition resolves through here, so the path syntax is uniform.
//
// Fail closed: a malformed path, a segment landing on a non-object, or a missing key all
// return (nil, false) — the same "argument missing" signal callers already deny on.
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
// A non-nil error means a directive could not be serialized into input.directives, and
// the caller must treat that as a deny — a shortened list would let a policy gating on
// input.directives decide on incomplete information.
func BuildRegoInput(ctx context.Context, req *capability.EnforceRequest) (map[string]interface{}, error) {
	args := req.Arguments
	if args == nil {
		args = map[string]interface{}{}
	}

	// req.Claims is a memoized map shared read-only across every request on the token.
	// Hand the PolicyEvaluator (pluggable third-party OPA/Cedar code) a shallow copy so
	// a writer into input.claims cannot corrupt the shared map or race concurrent readers.
	claims := map[string]interface{}{}
	for k, v := range req.Claims {
		claims[k] = v
	}

	// Prefer directives threaded via ctx (mutating req would race concurrent readers)
	// over req.Directives, still honored for a direct caller.
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

// timestampForInput resolves input.context.timestamp: the instant threaded through ctx
// (the same one stamped on DecidedAt), falling back to a direct caller's req.Context.Now.
func timestampForInput(ctx context.Context, req *capability.EnforceRequest) string {
	if ts := TimestampFromContext(ctx); ts != "" {
		return ts
	}
	return req.Context.Now
}

// directivesToRegoInput converts Directive values into a non-nil []interface{} so Rego
// policies can iterate input.directives without a null guard. A directive that cannot be
// JSON round-tripped is reported as an error, not silently dropped.
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

// registerBuiltins registers all built-in condition handlers. Each goes in through
// registerBuiltin, which reads its optional-subsystem declaration off the token's
// prototype-registry entry rather than restating it here.
func (e *Engine) registerBuiltins() {
	e.registerBuiltin(capability.ConditionTypeTimeWindow, ConditionHandlerFunc(e.handleTimeWindow))
	e.registerBuiltin(capability.ConditionTypeIPRange, ConditionHandlerFunc(e.handleIPRange))
	e.registerBuiltinCommitting(capability.ConditionTypeMaxCalls, maxCallsHandler{e: e})
	e.registerBuiltin(capability.ConditionTypeAllowedOperations, ConditionHandlerFunc(e.handleAllowedOperations))
	e.registerBuiltin(capability.ConditionTypeAllowedExtensions, ConditionHandlerFunc(e.handleAllowedExtensions))
	e.registerBuiltin(capability.ConditionTypeAllowedTables, ConditionHandlerFunc(e.handleAllowedTables))
	e.registerBuiltin(capability.ConditionTypeRecipientDomain, ConditionHandlerFunc(e.handleRecipientDomain))
	e.registerBuiltin(capability.ConditionTypeAllowedValues, ConditionHandlerFunc(e.handleAllowedValues))
	e.registerBuiltin(capability.ConditionTypeSequenceBlock, ConditionHandlerFunc(e.handleSequenceBlock))
	e.registerBuiltin(capability.ConditionTypeFlowLabel, ConditionHandlerFunc(e.handleFlowLabel))
	e.registerBuiltin(capability.ConditionTypeEffectClass, ConditionHandlerFunc(e.handleEffectClass))
	e.registerBuiltinCommitting(capability.ConditionTypeBlastRadius, blastRadiusHandler{e: e})
	// `policy` answers from the PolicyEvaluator its dispatch calls rather than from its
	// registry entry, since what an out-of-tree evaluator reads is knowable from the
	// evaluator but not from a token TYPE. See policyConditionHandler.
	e.registerBuiltin(capability.ConditionTypePolicy, policyConditionHandler{e: e})
	// `custom` deliberately does NOT: handleCustom consults no evaluator at all, so
	// answering from the PolicyEvaluator would let an evaluator wired for `policy` declare
	// on behalf of a token it has nothing to do with.
	e.registerBuiltin(capability.ConditionTypeCustom, ConditionHandlerFunc(e.handleCustom))
}

// policyConditionHandler is the built-in handler for the `policy` extension point: it runs
// the in-tree dispatch and, for the subsystem gates, forwards the question to the
// PolicyEvaluator that dispatch will call — a token type cannot know what an embedder's
// evaluator reads, but the evaluator itself can say. Not asking it would keep antecedent
// recording wired for the WHOLE engine on account of one capability that has nothing to do
// with it. An evaluator that does not implement SubsystemDependent, or isn't wired, leaves
// the declaration unclassified (every subsystem), the conservative prior answer.
type policyConditionHandler struct{ e *Engine }

// Handle implements [ConditionHandler].
func (h policyConditionHandler) Handle(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return h.e.handlePolicy(ctx, cond, req)
}

// UsesEngineSubsystems implements [SubsystemDependent] by asking the evaluator that will
// actually run, read once after every option is applied so it is the one this engine was
// built with.
func (h policyConditionHandler) UsesEngineSubsystems() []capability.EngineSubsystem {
	if d, ok := h.e.policyEvaluator.(SubsystemDependent); ok {
		return d.UsesEngineSubsystems()
	}
	return nil // unclassified: depends on everything
}

func (e *Engine) handleTimeWindow(_ context.Context, cond capability.Condition, _ *capability.EnforceRequest) *ConditionError {
	tw, condErr := castCondition[capability.TimeWindowCondition](cond)
	if condErr != nil {
		return condErr
	}

	// Fail closed on a window that restricts nothing. The loader rejects a both-empty
	// window, but a direct/programmatic caller can construct one, and silently allowing
	// would fall open for a security rule.
	if tw.NotBefore == "" && tw.NotAfter == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeTimeWindow,
			Message:       "timeWindow condition declares neither notBefore nor notAfter; a window with no bounds restricts nothing",
		}
	}

	now := e.clock.Now().UTC()

	// Manifest-loaded conditions are pre-parsed, so the hot path compares ready time.Time
	// values. An uncompiled condition (built directly, e.g. in a test) compiles a LOCAL
	// copy — the engine must not cache state onto a condition it does not own — through
	// the same accessor, so the uncompiled path cannot drift from Compile.
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
		// Half-open window [notBefore, notAfter): "allow until T" closes at T rather
		// than admitting one more call at T.
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

	// Manifest-loaded conditions are pre-compiled, so the hot path never calls net.ParseCIDR.
	networks, ok := ipr.Networks()
	if !ok {
		// Not pre-compiled (a programmatically constructed condition). Compile a LOCAL
		// copy — the engine must not cache state onto a condition it does not own — so the
		// uncompiled path cannot drift from Compile. Reachable only for hand-built
		// conditions; fail closed.
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

// maxCallsBucket derives the counter bucket for a maxCalls condition: casts the condition,
// applies the skip-quota bypass, and validates the counter, session, and target. skip is true
// under --audit observe mode (treat as satisfied); condErr is non-nil on any deny.
func (e *Engine) maxCallsBucket(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (mc *capability.MaxCallsCondition, key string, skip bool, condErr *ConditionError) {
	mc, condErr = castCondition[capability.MaxCallsCondition](cond)
	if condErr != nil {
		return nil, "", false, condErr
	}

	if e.counter == nil {
		return nil, "", false, &ConditionError{
			Code:          capability.ErrCodeEnforcementError,
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

	// Build a unique key from session + target type + bare name: the type must be in the
	// key because req.TargetName is only the bare name (a tool and a prompt named "export"
	// would otherwise drain one budget). sessionTargetKey derives the pair exactly as
	// RecordSessionCall does, so both key the same bucket. windowSeconds is deliberately
	// NOT part of this logical key — each backend appends it to the physical key, and two
	// conditions sharing one window are rejected at load. Route scoping comes from
	// anchoredKey's counterKeyNamespace prefix, not from here.
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

	// Deliberately AFTER the structural guards above: skipping the counter itself is what
	// observe mode must not perform, but a nil counter, empty session, or unidentifiable
	// target are misconfigurations observe mode should still surface, not hide as ALLOW.
	if SkipQuota(ctx) {
		return nil, "", true, nil
	}
	return mc, e.anchoredKey("maxcalls", req, targetType, toolName), false, nil
}

// maxCallsHandler is the built-in maxCalls condition handler. It commits a sliding-window
// slot on admit, so it is a CommittingConditionHandler: the engine runs it after every pure
// predicate and admits it through the atomic multi-bucket commit.
type maxCallsHandler struct{ e *Engine }

// PrepareCommit implements CommittingConditionHandler: runs the condition's pure checks and
// derives the counter bucket WITHOUT consuming a slot, so the engine can admit several
// deferred conditions in one atomic AdmitAll.
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
			// Counted: bounds the NUMBER of calls (O(1) in every backend), the weight-1
			// case of weighted accounting kept distinct so a large quota avoids a linear scan.
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

// retryAfterSeconds converts a backend retry-after estimate to whole seconds (rounded up),
// falling back to the full window when unavailable. Shared by the commit and check-only
// maxCalls denial paths.
func retryAfterSeconds(d time.Duration, windowSec int) int64 {
	// Must precede the ceiling below: a negative sub-second duration truncates to 0,
	// which the fractional ceiling would otherwise round up to 1s.
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

	// A scan-all-args mode would let a request hide the allowed verb in a benign
	// argument and produce nondeterministic results from map iteration order.
	if ao.Argument == "" {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeAllowedOperations,
			Message:       "allowedOperations condition requires an explicit 'argument' field naming the tool parameter that carries the operation",
		}
	}

	// Distinguish failure modes for the audit trail: present-but-non-string is
	// CONDITION_FAILED (wrong shape), absent/blank stays MISSING_CONTEXT.
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

	// No wildcard: a "*" entry is rejected at load, so this is always an explicit
	// allowlist. AllowsOperation resolves through capability.MatchOperation, the same
	// matcher the JWT shorthand PDP uses, so the two paths cannot diverge.
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

// resolveStringOrStringArray reads the named argument as a cleaned (trimmed, non-blank)
// list of strings. Shared by allowedExtensions and recipientDomain so both fail closed
// identically: a non-string/blank array item or wrong-type value is CONDITION_FAILED
// (never silently dropped), a missing/empty result is MISSING_CONTEXT.
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
			// ONE validation arm for both array shapes (see asInterfaceSlice): two
			// hand-mirrored copies is how one silently loses a fail-closed check.
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

	// One disallowed entry among the (possibly several) paths denies the whole call.
	paths, cerr := resolveStringOrStringArray(req.Arguments, ae.Argument, capability.ConditionTypeAllowedExtensions)
	if cerr != nil {
		return cerr
	}

	// Normalized allowlist (lowercased, dotted suffix, dot-boundary HasSuffix match).
	// Deliberately asymmetric: a SINGLE ".gz" entry matches both "file.gz" and
	// "archive.tar.gz"; only a COMPOUND ".tar.gz" entry excludes the plain form. No way
	// to allow ".gz" but deny ".tar.gz" here — pin the path with allowedValues instead.
	allowed := ae.MatchExtensions()

	for _, filePath := range paths {
		// Normalize separators/percent-encoding before matching so a backslash or
		// %2f-encoded separator cannot smuggle a directory component past path.Base/Ext,
		// which key off the OS separator. A malformed '%' is not a confinement concern
		// ('%' is a legal filename char for a non-decoding upstream) and falls back to
		// the literal form below.
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
			// A valid encoded separator riding alongside the bad escape must still deny:
			// PathUnescape failed whole, so matching the literal form would treat
			// "evil.exe%2f..%2fx.csv" as a permitted ".csv" file.
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

// fileSuffix returns a file name's full dotted suffix for denial messages: ".zip.gz" for
// "backup.zip.gz". A dotfile's leading dots are its name prefix, skipped first (hidden
// ".tar.gz" yields ".gz"). Presentational only; the decision is made by HasSuffix.
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

	// Case-folded lookup structures: keyed by lowercased table so a "users" restriction
	// still covers "USERS", with values in original case so denial details echo the manifest.
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
					// Trim the request column to match the trimmed allowlist set: a
					// whitespace-padded "id " would otherwise miss an allowlisted "id". The
					// denial message keeps the original untrimmed col.
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

	domainSet := rd.MatchDomains()

	for _, recipient := range recipients {
		parts := strings.SplitN(recipient, "@", 2)
		// Require one non-empty local part and domain, no internal whitespace, no second
		// "@", no IP-literal, no leading/trailing dot — a distinct "invalid recipient
		// email" keeps malformed input separable from a real policy denial.
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
// so the JWT capability-claim path evaluates the identical check instead of hand-copying it
// (the prior copy diverged twice: missing the empty-argument guard, and missing task-variable
// resolution so every "${task.*}" grant denied every call under it).
//
// A plain function, not a method, because it reads nothing off the engine and COMMITS
// NOTHING — safe for a composing layer to run before the inner PDP's own decision without
// double-counting a window slot or writing a flow label.
//
// It does NOT cover WithConditionHandler overrides: a caller reaching this package-level
// predicate directly runs the built-in regardless of an engine's registry. A composing layer
// must ask the DECIDING engine — (*Engine).NonCommittingConditionVerdict — instead; this stays
// exported as that built-in's implementation and for a caller with no engine at all.
//
// A caller outside the engine must pass the returned Details through BoundDenialDetails
// before they reach an audit record.
//
// It reads exactly req.Arguments and req.Claims and nothing else — pinned by a test in
// internal/pdp that fails when a field is added to capability.EnforceRequest.
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

	// Unreachable from the engine, but this is an exported seam: a nil request must DENY
	// rather than panic (fail-open-via-crash) or read as passed.
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

	// MatchAllowedValue centralizes glob-vs-exact matching and task-variable resolution,
	// shared with the JWT shorthand PDP.
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

// MatchAllowedValue reports whether argValue satisfies an allowedValues set. Single matcher
// shared by EvaluateAllowedValues and, through it, the JWT shorthand PDP; it answers glob
// matching and task-context variable resolution TOGETHER against the caller's claims — kept
// inseparable because resolving them in a caller-optional second pass previously let a
// grant carrying a "${task.*}" entry silently match nothing (VALUE_NOT_PERMITTED with no
// diagnostic). nil claims resolve nothing.
//
// A string entry is matched ONLY as a glob via MatchValueGlob, never exact-first (an
// exact-first check would let literal pattern text like "[0-9]" bypass its glob meaning).
// A non-string entry (bool, number, nil) is matched by exact value, with numericEqual
// bridging the YAML-int vs JSON-float64 type gap.
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
		// ONE classification per entry, deciding both branches: a recognized "${task.*}"
		// entry is a reference, never a pattern (else the argument's literal placeholder
		// TEXT would satisfy an identity binding by spelling it out). Two separate passes
		// could disagree if the closed set ever moved, silently voiding the grant.
		name, isRef := capability.ParseVariableRef(pattern)
		if _, known := capability.TaskVarClaimKey(name); isRef && known {
			// Compared by EXACT equality, never through the glob below — a claim of "*"
			// would otherwise become an allow-anything wildcard the token holder chose for
			// themselves. Unresolvable (no token, or claim absent) matches nothing.
			if !argIsString || len(claims) == 0 {
				continue
			}
			if resolved, ok := capability.ResolveTaskVar(name, claims); ok && resolved == argStr {
				return true
			}
			continue
		}
		// An UNRECOGNIZED "${STAGE}" stays a literal: values here can come from a TOKEN's
		// capability claim, which never passed through the manifest loader, so voiding it
		// would kill the grant with no diagnostic to grep for.
		if argIsString && MatchValueGlob(pattern, argStr) {
			return true
		}
	}
	return false
}

// OperationVerb extracts the operation token from an argument value: the uppercased first
// whitespace-delimited word, or "" when blank. Shared by handleAllowedOperations and the
// JWT shorthand PDP so the two cannot diverge.
//
// First token ONLY, deliberately: a compound statement ("SELECT 1; DROP TABLE users")
// verbs as its leading word, so allowedOperations does not block the trailing statement —
// pair with argumentSchema or an external PolicyEvaluator for more; do not grow a SQL
// parser here.
func OperationVerb(s string) string {
	return capability.OperationVerb(s)
}

// numericEqual reports whether a and b are both numeric and equal in value, independent of
// concrete Go type — manifest values decode as YAML int while request arguments decode as
// float64, so a bare manifest integer would not reflect.DeepEqual-match the same number.
//
// When both represent an integer they are compared exactly (int64 within range, an exact
// rational beyond it), so two distinct integers sharing a float64 are never conflated.
// Only genuinely FRACTIONAL values fall back to the float64 comparison.
func numericEqual(a, b any) bool {
	ia, aInt := asInt64(a)
	ib, bInt := asInt64(b)
	if aInt && bInt {
		return ia == ib
	}
	// Exactly one operand is a representable int64: they are by definition distinct
	// integers and must not be collapsed onto a shared float64, which would round
	// them equal.
	if aInt != bInt {
		return false
	}
	// Neither is int64-representable but both are still integers: compare exactly, since
	// the float64 fallback below would round distinct integers above 2^63 together (a
	// fail-open — allowedValues: [9223372036854775808] would admit 9223372036854775809).
	//
	// Restricted to integers: a fractional decimal literal and its float64 coercion are
	// genuinely different rationals (0.1 is not the binary double nearest 0.1), so
	// comparing those exactly would make an argument of 0.1 stop matching a
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
// magnitude, false for a fractional/non-numeric/non-finite value. The beyond-int64
// companion to asInt64, so a numeric comparison stays exact past 2^63 rather than
// lapsing to float64 rounding.
func exactIntegerRat(v any) (*big.Rat, bool) {
	r, ok := exactRat(v)
	if !ok || !r.IsInt() {
		return nil, false
	}
	return r, true
}

// Bounds on the decimal literal exactRat hands to big.Rat.SetString are REQUIRED, not
// defensive: SetString's mantissa scan is superlinear and its exponent handling
// materializes 10^N, an unbounded parse is a CPU/memory DoS reachable with one tool-call
// argument (measured: a 1M-digit literal cost 1.8s of one core; "1e1000000" cost ~25ms and
// ~1MiB, per comparison, multiplied by the entry count). A literal past the bound falls
// through to the float64 comparison — no new fail-open, just no exactness for a value no
// policy writes. The bound itself lives in pkg/capability.NumericLiteralBounded, shared
// with the JSON-RPC id parse and the effect layer's blast-radius parse.

// exactRat returns v's exact value as a *big.Rat, without the float64 round-trip
// asInt64/toFloat64 take, for the types that can carry a value outside int64 range.
func exactRat(v any) (*big.Rat, bool) {
	switch n := v.(type) {
	case json.Number:
		// SetString parses the decimal literal exactly, including digits a float64
		// coercion would round away, and accepts exponent forms — hence the bound above.
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

// maxInt64Uint is math.MaxInt64 as a uint64, for the unsigned arms of asInt64.
const maxInt64Uint = uint64(1<<63 - 1)

// asInt64 reports the int64 value of v when v holds an integer, letting numericEqual
// compare integers exactly instead of through a lossy float64 round-trip; out-of-range or
// fractional values report false so the caller falls back to float64. json.Number is
// handled for arguments decoded in UseNumber mode.
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

// toFloat64 converts any Go numeric type to float64, false for non-numeric values. bool is
// deliberately excluded so true/1 and false/0 are never treated as numerically equal.
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

// handleSequenceBlock blocks the current call when any tool named in afterTools was
// previously recorded in this session.
//
// Known limitation — concurrent same-session requests: the antecedent's Peek and its
// RecordSessionCall write (a SEPARATE request, different key) are not atomic, so firing
// both concurrently can let the blocked tool Peek empty history and slip through. Intrinsic
// to two independent requests racing on different keys — not a check-and-set gap AdmitAll
// could close — and identical under every backend. MCP's per-session model is serial, so a
// compliant client never triggers it. See docs/capability-manifest-guide.md (sequenceBlock).
func (e *Engine) handleSequenceBlock(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	sb, condErr := castCondition[capability.SequenceBlockCondition](cond)
	if condErr != nil {
		return condErr
	}

	// A rule that can never fire is almost certainly an authoring mistake; deny rather
	// than silently allow everything.
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
			Code:          capability.ErrCodeEnforcementError,
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

	// Resolve the blocked target's namespace as RecordSessionCall does, so reporting in
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
	// Report "(unknown)" rather than the misleading "tool:" sentinel when no name is
	// present, so a SIEM rule parsing blockedTool as namespace:name gets no empty name.
	blockedDetail := blockedTarget
	if blockedName == "" {
		blockedDetail = "(unknown)"
	}
	// Detached from the REQUEST's cancellation: net/http cancels ctx the instant the client
	// disconnects, and a backend honoring it (Redis; not in-memory) would then hand the
	// gate's own I/O to the party the gate constrains — a client that probes and drops the
	// connection each time gets a fail-closed deny before the marker is ever refreshed,
	// reverting the gate to expire on pure wall clock (a fail-open, triggerable at will).
	// WithoutCancel keeps context values while the backend's own dial/read/write timeouts
	// still bound every call.
	histCtx := context.WithoutCancel(ctx)
	for _, prior := range sb.AfterTools {
		// Mirrors RecordSessionCall's namespace resolution, so afterTools: [export] matches
		// only the tool and [prompt:export] only the prompt.
		priorType, priorTool := splitEnginePrefix(prior)
		priorTool = strings.TrimSpace(priorTool)
		priorTarget := priorType + ":" + priorTool
		key := e.sequenceHistoryKey(req, priorType, priorTool)

		count, err := e.counter.Peek(histCtx, key, sequenceHistoryWindowSec)
		if err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeEnforcementError,
				ConditionType: capability.ConditionTypeSequenceBlock,
				Message:       fmt.Sprintf("session history lookup failed: %v", err),
			}
		}
		if count > 0 {
			// Re-arm the marker so retention measures inactivity, not age: without this a
			// still-live session probing the blocked target has its gate expire on pure wall
			// clock (fail-open). Best-effort (errors ignored): this path has ALREADY decided
			// to deny, so a write fault cannot turn it into an allow, and only the marker that
			// MATCHED is refreshed — the documented per-(antecedent, blocked target) contract.
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

	// The extension point's own "no usable handler" refusal, and the same class as the
	// registry's: nothing evaluated the condition, so there is no verdict for an observing
	// route to downgrade to.
	if e.policyEvaluator == nil {
		return &ConditionError{
			Code:          capability.ErrCodeEnforcementError,
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

	// As handlePolicy's: an unwired extension point evaluated nothing, so the refusal is a
	// fault rather than a verdict. Supply a handler via
	// WithConditionHandler(capability.ConditionTypeCustom, handler).
	return &ConditionError{
		Code:          capability.ErrCodeEnforcementError,
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
// A non-string item, non-string column entry, or a map with no non-empty "table" entry is
// structurally malformed: returns a non-nil error so the caller denies fail-closed rather
// than silently evaluating the valid subset.
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
					// Keep the array context so it is not reported as if the whole
					// argument were a bare map.
					return nil, fmt.Errorf("array element %s", err)
				}
				if len(parsed) == 0 {
					// A blank element in a populated array is structurally malformed,
					// unlike a top-level empty argument (MISSING_CONTEXT).
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
			// Present but lacking the required entry: CONDITION_FAILED, not the
			// misleading MISSING_CONTEXT.
			return nil, fmt.Errorf("is a map with no non-empty 'table' entry")
		}
		ta := capability.TableAccess{Table: tableName}
		// An absent "columns" entry means unrestricted access, intentionally. Anything
		// present must be an array of strings; a silently unhandled shape would leave
		// ta.Columns nil, which reads as "allow all columns" — the wrong direction.
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
				// Dropping a blank column would quietly change the enforced policy.
				if strings.TrimSpace(col) == "" {
					return nil, fmt.Errorf("table %q columns list contains an empty or blank column name", tableName)
				}
				ta.Columns = append(ta.Columns, col)
			}
		}
		return []capability.TableAccess{ta}, nil
	default:
		// An unsupported scalar type is a type mismatch, not a missing value. The
		// string/array/map cases above fall through to nil,nil for a genuinely empty
		// value, which the caller reports as MISSING_CONTEXT.
		return nil, fmt.Errorf("must be a string, object, or array of strings/objects; got %T", v)
	}
	return nil, nil
}

// asInterfaceSlice normalizes the two shapes a JSON array argument arrives in — a JSON
// decode's []interface{} and a library caller's native []string — onto one slice, so every
// array-validating parser has ONE arm to get right instead of hand-mirroring its
// fail-closed checks per shape. ok is false for anything that is not an array.
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

// castCondition casts cond to *T and, on a type mismatch, builds the ConditionError every
// handler returns for it. T is constrained to capability.Condition so condType is DERIVED
// from a zero T's own ConditionType() rather than passed separately — a prior version's
// string parameter let a call site pair the wrong ConditionType constant with T and
// compile silently, corrupting the audit tape.
//
// The cast goes through capability.AsValueOrPointer — shared with the directive-side
// predicates, so the value-or-pointer type switch lives in one place — since a manifest
// condition may decode into either form.
//
// A TYPED-NIL pointer handed to an exported predicate is returned AS-IS by
// AsValueOrPointer's `case *T` arm — (nil, true), so ok alone does not refuse it — and every
// handler would then dereference it and panic (fail-open-via-crash). The `t == nil` half of
// the guard below is what catches that, once here rather than at each handler, mirroring
// CollectObligations' typed-nil guard for directives.
func castCondition[T capability.Condition](cond capability.Condition) (*T, *ConditionError) {
	t, ok := capability.AsValueOrPointer[T](cond)
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
