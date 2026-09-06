// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Regression tests for high/medium findings from docs/arch-review-2026-06-01.md
// and docs/architecture-review-2026-06.md.
//
//   - duplicate matching logic between pdp.go and engine.go:
//     MatchesResource and ResourceSpecificity are now exported so callers share
//     the same implementation rather than maintaining parallel copies.
//
//   - AllowedOperationsCondition now requires an explicit argument field;
//     scan-all-args mode (Argument=="") is no longer supported.
//
//   - synthetic constraint double-dispatch: EvaluateConditions lets callers
//     that already found the winning constraint skip the second match pass.
//
//   - ValidateAction / FindMatchingCapability now strip the namespace prefix
//     from constraint.Target so v0.2 prefixed manifests match bare req.TargetName.

// Additional coverage for condition handlers, the as* type-assertion helpers,
// the JSON-schema validator, and engine matching/scoring edge cases.

// Regression tests — engine
// matching, Rego-input plumbing, condition error codes, and specificity scoring.

// Regression tests — audit-mode stamping
// on engine denials, post-wildcard specificity scoring, namespaced sequenceBlock
// denial details, and the fail-closed guard for unhandled directive types.

package enforcement_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// Both built-in counter backends must satisfy the full capability.CallCounter
// contract — IncrementAndGet plus the folded-in Peek and
// PeekRetryAfter. The maxCalls and sequenceBlock handlers call those
// directly and fail closed only when no counter is configured, so a backend that
// dropped one of the folded methods stops compiling here instead of failing at
// runtime.
var (
	_ capability.CallCounter = (*callcounter.InMemory)(nil)
	_ capability.CallCounter = (*callcounter.Redis)(nil)
)

type fakeClock struct{ now time.Time }

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }
func (fc *fakeClock) Now() time.Time      { return fc.now }

func TestEngine_ValidateAction_NoMatchingCapability(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "unknown-tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "other-tool", Actions: []string{"read"}},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
}

func TestEngine_ValidateAction_AllowWildcard(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "any-tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "*", Actions: []string{"*"}},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.NotEmpty(t, resp.RequestID)
	assert.NotEmpty(t, resp.DecidedAt)
}

func TestEngine_ValidateAction_AllowExactMatch(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "email:send",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "email:send", Actions: []string{"call"}},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_ValidateAction_PrefixMatch(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:read",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "file:*", Actions: []string{"*"}},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_TimeWindow_Allow(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
					NotAfter:  "2025-06-15T14:00:00Z",
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_TimeWindow_DenyBefore(t *testing.T) {
	now := time.Date(2025, 6, 15, 9, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeTimeWindow, resp.Denial.ConditionType)
}

func TestEngine_TimeWindow_DenyAfter(t *testing.T) {
	now := time.Date(2025, 6, 15, 15, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotAfter: "2025-06-15T14:00:00Z",
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeTimeWindow, resp.Denial.ConditionType)
}

// TestEngine_TimeWindow_Boundaries pins the half-open window semantics:
// [notBefore, notAfter). A call at exactly notBefore is allowed (inclusive lower
// bound); a call at exactly notAfter is denied (exclusive upper bound).
func TestEngine_TimeWindow_Boundaries(t *testing.T) {
	const (
		notBefore = "2025-06-15T10:00:00Z"
		notAfter  = "2025-06-15T14:00:00Z"
	)
	constraints := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.TimeWindowCondition{NotBefore: notBefore, NotAfter: notAfter},
		},
	}}

	for _, tc := range []struct {
		name string
		now  time.Time
		want capability.Decision
	}{
		{"exactly notBefore is allowed", time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC), capability.DecisionAllow},
		{"one ns before notAfter is allowed", time.Date(2025, 6, 15, 13, 59, 59, 999999999, time.UTC), capability.DecisionAllow},
		{"exactly notAfter is denied", time.Date(2025, 6, 15, 14, 0, 0, 0, time.UTC), capability.DecisionDeny},
		{"one ns before notBefore is denied", time.Date(2025, 6, 15, 9, 59, 59, 999999999, time.UTC), capability.DecisionDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := enforcement.New(enforcement.WithClock(newFakeClock(tc.now)))
			resp := engine.ValidateAction(context.Background(), &capability.EnforceRequest{TargetName: "tool"}, constraints)
			assert.Equal(t, tc.want, resp.Decision)
		})
	}
}

func TestEngine_IPRange_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Context:    capability.EnforceRequestContext{SourceIP: "10.0.1.50"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_IPRange_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Context:    capability.EnforceRequestContext{SourceIP: "192.168.1.1"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeIPRange, resp.Denial.ConditionType)
}

func TestEngine_IPRange_MissingSourceIP(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

func TestEngine_IPRange_InvalidCIDR(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Context: capability.EnforceRequestContext{
			SourceIP: "10.0.0.1",
		},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.IPRangeCondition{CIDRs: []string{"not-a-valid-cidr"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeIPRange, resp.Denial.ConditionType)
}

// TestEngine_RecordSessionCall covers the exported RecordSessionCall: a call
// recorded through it must arm a later sequenceBlock that names the
// recorded tool, and its no-op guards (no session, no counter) must return nil.
func TestEngine_RecordSessionCall(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	antecedent := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "read_credentials",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_credentials"},
	}
	require.NoError(t, engine.RecordSessionCall(ctx, antecedent))

	// A sequenceBlock naming the recorded tool must now fire for another tool.
	blocked := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "write_external",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "write_external"},
	}
	matched := &capability.Constraint{
		Target:  "tool:write_external",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
		},
	}
	resp := engine.EvaluateConditions(ctx, blocked, matched)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)

	// Guard paths return nil without recording: no session ID, and a fresh engine
	// with no counter configured.
	require.NoError(t, engine.RecordSessionCall(ctx, &capability.EnforceRequest{TargetName: "x"}))
	require.NoError(t, enforcement.New().RecordSessionCall(ctx, antecedent))
}

func TestEngine_MaxCalls_Allow(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	caps := []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
			},
		},
	}

	// First call should be allowed
	resp := engine.ValidateAction(ctx, &req, caps)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MaxCalls_Deny(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	caps := []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 3, WindowSeconds: 60},
			},
		},
	}

	// Make 3 calls (all should be allowed)
	for i := 0; i < 3; i++ {
		resp := engine.ValidateAction(ctx, &req, caps)
		assert.Equal(t, capability.DecisionAllow, resp.Decision, "call %d should be allowed", i+1)
	}

	// 4th call should be denied
	resp := engine.ValidateAction(ctx, &req, caps)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
}

// TestEngine_MaxCalls_NotConsumedWhenLaterConditionDenies is the regression:
// a maxCalls slot must not be burned for a call that a later condition denies.
// maxCalls is declared BEFORE allowedValues, and several calls fail allowedValues;
// because maxCalls (a commit-on-admit condition) is now evaluated only after the
// pure predicates pass, those denied calls consume no quota, so the full quota is
// still available to legitimate calls that satisfy every condition.
func TestEngine_MaxCalls_NotConsumedWhenLaterConditionDenies(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	caps := []capability.Constraint{
		{
			Target:  "tool:read_file",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				// maxCalls declared FIRST, before the predicate that can deny.
				&capability.MaxCallsCondition{Count: 2, WindowSeconds: 60},
				&capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/safe/*"}},
			},
		},
	}

	bad := capability.EnforceRequest{
		SessionID: "sess-1", TargetName: "read_file",
		Arguments: map[string]interface{}{"path": "/etc/passwd"},
	}
	// Three calls that fail allowedValues; each would previously have burned a slot.
	for i := 0; i < 3; i++ {
		resp := engine.ValidateAction(ctx, &bad, caps)
		assert.Equal(t, capability.DecisionDeny, resp.Decision, "bad call %d", i+1)
		assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType,
			"bad call must be denied by allowedValues, not maxCalls")
	}

	good := capability.EnforceRequest{
		SessionID: "sess-1", TargetName: "read_file",
		Arguments: map[string]interface{}{"path": "/safe/ok.txt"},
	}
	// The full quota of 2 must still be available — the denied calls consumed none.
	for i := 0; i < 2; i++ {
		resp := engine.ValidateAction(ctx, &good, caps)
		assert.Equal(t, capability.DecisionAllow, resp.Decision,
			"good call %d must be allowed; the quota was not burned by the earlier denials", i+1)
	}
	// maxCalls is still enforced for genuinely-admitted calls: the 3rd good call
	// exhausts the window and is rate-limited.
	resp := engine.ValidateAction(ctx, &good, caps)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
}

func TestEngine_MaxCalls_EmptySessionIDDenies(t *testing.T) {
	// When SessionID is empty the maxCalls counter key would merge traffic from
	// every session, creating a shared global counter — a mis-accounting bug that
	// can also be abused to exhaust another tenant's quota.  The engine must
	// deny with ErrCodeMissingContext rather than silently increment the counter.
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		// SessionID intentionally blank.
		TargetName: "tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 100, WindowSeconds: 60},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeMaxCalls, resp.Denial.ConditionType)
}

func TestEngine_MaxCalls_EmptyToolNameDenies(t *testing.T) {
	// A tool name that strips to "" (e.g. a bare "tool:") would key every such
	// call into one shared per-session bucket with an empty name component. The
	// engine must deny with
	// ErrCodeMissingContext rather than quota-account an unidentifiable tool,
	// matching the empty-result guards in RecordSessionCall and handleSequenceBlock
	// and the fail-closed posture of the empty-sessionID guard.
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool:", // strips to ""
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "*",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 100, WindowSeconds: 60},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeMaxCalls, resp.Denial.ConditionType)
}

// TestEngine_MaxCalls_PrefixNormalizedKey is the regression test:
// the maxCalls quota bucket must key on the prefix-stripped tool name, matching
// RecordSessionCall's sequenceBlock history. The constraint matcher strips the
// "tool:" prefix from both sides, so the same constraint matches whether the
// request arrives as "tool:read_file" or "read_file"; both forms must consume the
// same quota bucket. Otherwise a caller could reset its own quota by toggling the
// prefix.
func TestEngine_MaxCalls_PrefixNormalizedKey(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	caps := []capability.Constraint{
		{
			Target:  "read_file",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 2, WindowSeconds: 60},
			},
		},
	}

	// Two allowed calls with the prefixed form fill the window.
	prefixed := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool:read_file"}
	for i := 0; i < 2; i++ {
		resp := engine.ValidateAction(ctx, &prefixed, caps)
		require.Equal(t, capability.DecisionAllow, resp.Decision, "prefixed call %d should be allowed", i+1)
	}

	// Switching to the bare form must hit the SAME exhausted bucket, not a fresh
	// one. Before the fix this was admitted because the key was built from the raw
	// "tool:read_file" while the bare request keyed on "read_file".
	bare := capability.EnforceRequest{SessionID: "sess-1", TargetName: "read_file"}
	resp := engine.ValidateAction(ctx, &bare, caps)
	assert.Equal(t, capability.DecisionDeny, resp.Decision, "bare form must share the prefixed form's quota bucket")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
}

func TestEngine_MaxCalls_TargetTypeNamespacesQuota(t *testing.T) {
	// Regression: req.TargetName is the bare target name, so a tool, a
	// prompt, and a resource that share a name ("export") used to produce the
	// identical session-and-name counter key and drained one quota bucket between
	// them. The key now includes req.Target.Type (and the window length), so each
	// target type gets its own bucket. Exhaust the tool's small quota, then confirm
	// the same-named prompt and resource each still have their full, independent
	// quota — demonstrating all three namespaces are mutually independent.
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	const name = "export"
	const sessionID = "sess-1"

	capsFor := func(targetType string) []capability.Constraint {
		return []capability.Constraint{{
			Target:     targetType + ":" + name,
			Actions:    []string{"*"},
			Conditions: []capability.Condition{&capability.MaxCallsCondition{Count: 2, WindowSeconds: 60}},
		}}
	}
	reqFor := func(targetType string) capability.EnforceRequest {
		return capability.EnforceRequest{
			SessionID:  sessionID,
			TargetName: name,
			Target:     &capability.EnforceRequestTarget{Type: targetType, Name: name},
		}
	}

	toolReq, toolCaps := reqFor("tool"), capsFor("tool")
	promptReq, promptCaps := reqFor("prompt"), capsFor("prompt")
	resourceReq, resourceCaps := reqFor("resource"), capsFor("resource")

	// Exhaust the tool's quota: two allows, third denied.
	for i := 0; i < 2; i++ {
		resp := engine.ValidateAction(ctx, &toolReq, toolCaps)
		assert.Equal(t, capability.DecisionAllow, resp.Decision, "tool call %d should be allowed", i+1)
	}
	resp := engine.ValidateAction(ctx, &toolReq, toolCaps)
	require.Equal(t, capability.DecisionDeny, resp.Decision, "tool quota should be exhausted")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)

	// The same-named prompt and resource must be unaffected: their counter keys
	// differ by target type, so each still has its full quota of two allows and
	// is then independently rate-limited on its own third call.
	for _, tc := range []struct {
		targetType string
		req        capability.EnforceRequest
		caps       []capability.Constraint
	}{
		{"prompt", promptReq, promptCaps},
		{"resource", resourceReq, resourceCaps},
	} {
		for i := 0; i < 2; i++ {
			resp := engine.ValidateAction(ctx, &tc.req, tc.caps)
			assert.Equal(t, capability.DecisionAllow, resp.Decision,
				"%s call %d must not consume the same-named tool's quota", tc.targetType, i+1)
		}
		resp := engine.ValidateAction(ctx, &tc.req, tc.caps)
		require.Equal(t, capability.DecisionDeny, resp.Decision,
			"%s quota should be exhausted on its own", tc.targetType)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
	}
}

func TestEngine_MaxCalls_NilTargetResolvesToToolType(t *testing.T) {
	// A direct ValidateAction caller that leaves req.Target nil has its maxCalls
	// bucket type derived from the ToolName prefix (splitEnginePrefix), exactly as
	// RecordSessionCall does — an unprefixed name resolves to "tool". So a nil-Target
	// ToolName "export" and an explicit tool:export request share ONE quota bucket,
	// closing the keying divergence that previously put the nil-Target call in a
	// distinct empty-type bucket.
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	const name = "export"
	const sessionID = "sess-1"

	caps := []capability.Constraint{{
		Target:     name,
		Actions:    []string{"*"},
		Conditions: []capability.Condition{&capability.MaxCallsCondition{Count: 2, WindowSeconds: 60}},
	}}
	nilTargetReq := capability.EnforceRequest{SessionID: sessionID, TargetName: name} // Target intentionally nil
	toolReq := capability.EnforceRequest{
		SessionID:  sessionID,
		TargetName: name,
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: name},
	}

	// Exhaust the shared bucket via the nil-Target request.
	for i := 0; i < 2; i++ {
		resp := engine.ValidateAction(ctx, &nilTargetReq, caps)
		assert.Equal(t, capability.DecisionAllow, resp.Decision, "nil-Target call %d should be allowed", i+1)
	}
	resp := engine.ValidateAction(ctx, &nilTargetReq, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision, "nil-Target quota should be exhausted")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)

	// The explicit tool:export request shares the same (session, "tool", "export")
	// bucket, so its quota is already exhausted — no separate empty-type bucket.
	resp = engine.ValidateAction(ctx, &toolReq, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision,
		"a tool-typed request must share the nil-Target bucket (both resolve to type \"tool\")")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
}

// TestEngine_MaxCalls_DistinctWindowsCountIndependently is the engine-level
// regression test: two maxCalls conditions on one capability that
// declare *different* windows must each maintain their own sliding-window count,
// not write into a single shared entry. Before the fix the InMemory counter keyed
// every maxCalls condition for a (session, target) by the same key, so each
// admitted call appended one timestamp per condition — after K admitted calls the
// shared entry held 2K timestamps, and the tighter condition (count 10, short
// window) denied on the 6th real call instead of the 11th, an effective limit of
// 5 = 10/2. With windowSeconds folded into the key the two conditions address
// independent buckets, so the tighter limit binds at exactly its configured count.
func TestEngine_MaxCalls_DistinctWindowsCountIndependently(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "export",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "export"},
	}

	// A tight short window (10 per minute) and a loose long window (1000 per hour).
	// The long window's high count means it never binds within this test; the only
	// limit that should fire is the short window's, at exactly its 10th call.
	caps := []capability.Constraint{{
		Target:  "tool:export",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 10, WindowSeconds: 60},
			&capability.MaxCallsCondition{Count: 1000, WindowSeconds: 3600},
		},
	}}

	// All 10 calls within the short window's configured count must be admitted.
	// Under the pre-fix shared-key behavior the 6th would have been denied.
	for i := 0; i < 10; i++ {
		resp := engine.ValidateAction(ctx, &req, caps)
		require.Equal(t, capability.DecisionAllow, resp.Decision,
			"call %d should be admitted; the short-window limit is 10", i+1)
	}

	// The 11th call exceeds the short window's count of 10 and is rate-limited.
	resp := engine.ValidateAction(ctx, &req, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision, "11th call exceeds the short-window limit")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeMaxCalls, resp.Denial.ConditionType)
	// The denial must report the short window's real count (10), not an inflated
	// 20 — the audit count and retry_after_seconds hint depend on it being accurate.
	if assert.NotNil(t, resp.Denial.Details) {
		assert.Equal(t, 10, resp.Denial.Details["limit"])
		assert.Equal(t, int64(10), resp.Denial.Details["current"])
		assert.Equal(t, 60, resp.Denial.Details["window_seconds"])
	}
}

// TestEngine_MaxCalls_LongWindowNotPrunedByShortWindow pins the fail-OPEN
// direction — the cross-window prune that flags the "more serious security concern." Two maxCalls conditions on one capability, a
// loose short window and a tight long window, with calls spread so each lands
// alone in the short window but all accumulate in the long window. Pre-fix, both
// conditions shared one entry, so the short window's 60s prune (run first on
// every call) erased the long window's history every time the calls were spaced
// past 60s — the long window's count never climbed and its limit never tripped,
// silently failing open. With per-window buckets the long window keeps its full
// history and its limit binds.
func TestEngine_MaxCalls_LongWindowNotPrunedByShortWindow(t *testing.T) {
	// A mutable clock drives the counter's sliding window deterministically.
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time { return now }))
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "export",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "export"},
	}
	caps := []capability.Constraint{{
		Target:  "tool:export",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 100, WindowSeconds: 60}, // short, loose — never binds
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 3600}, // long, tight — the binding limit
		},
	}}

	// Five calls 70s apart: each is alone in the 60s short window (so its limit of
	// 100 never binds), and all five fall inside the 3600s long window. Pre-fix the
	// short window's 70s-spaced prune wiped the shared entry every call, so the long
	// window never reached its limit of 5 — the fail-open this test guards.
	for i := 0; i < 5; i++ {
		resp := engine.ValidateAction(ctx, &req, caps)
		require.Equal(t, capability.DecisionAllow, resp.Decision, "call %d should be admitted", i+1)
		now = now.Add(70 * time.Second)
	}

	// The 6th call (350s elapsed, still inside the hour) is the long window's 6th
	// and exceeds its count of 5. Pre-fix it was admitted (fail-open); now it denies.
	resp := engine.ValidateAction(ctx, &req, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision, "6th call exceeds the long-window limit of 5")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeMaxCalls, resp.Denial.ConditionType)
	// The denial comes from the long window, reporting its own limit and length.
	if assert.NotNil(t, resp.Denial.Details) {
		assert.Equal(t, 5, resp.Denial.Details["limit"])
		assert.Equal(t, 3600, resp.Denial.Details["window_seconds"])
	}
}

func TestEngine_AllowedOperations_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file",
		Arguments:  map[string]interface{}{"op": "read"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "file",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Argument: "op", Operations: []string{"read", "list"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedOperations_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file",
		Arguments:  map[string]interface{}{"op": "delete"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "file",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Argument: "op", Operations: []string{"read", "list"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeAllowedOperations, resp.Denial.ConditionType)
}

// TestEngine_AllowedOperations_WildcardDoesNotAllowAnyVerb is the regression: a literal "*" in the operations list must NOT match an arbitrary
// verb at runtime. The wildcard is rejected at manifest load, but the handler
// must also fail closed if such a list reaches enforcement (e.g. a manifest
// assembled in-process), rather than silently permitting every operation.
func TestEngine_AllowedOperations_WildcardDoesNotAllowAnyVerb(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "query_db",
		Arguments:  map[string]interface{}{"sql": "DROP TABLE users"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "query_db",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Argument: "sql", Operations: []string{"*"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision, `"*" must not allow DROP`)
	assert.Equal(t, capability.ConditionTypeAllowedOperations, resp.Denial.ConditionType)
}

func TestEngine_AllowedExtensions_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:read",
		Arguments:  map[string]interface{}{"path": "/docs/report.pdf"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "file:read",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf", ".txt", ".md"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedExtensions_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:read",
		Arguments:  map[string]interface{}{"path": "/etc/passwords.sh"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "file:read",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf", ".txt", ".md"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
}

// TestEngine_AllowedExtensions_BackslashSeparator pins: extension matching
// must key off the final path component regardless of separator style. On Linux
// filepath.Base/Ext treat "\" as an ordinary character, so a Windows-style path
// was matched against the whole "dir\file" string rather than the file name. The
// fix normalizes "\" to "/" and matches via the OS-independent path package, so
// the denial names the real final-component extension (".exe") and never a
// backslash-laden hybrid suffix.
func TestEngine_AllowedExtensions_BackslashSeparator(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:read",
		Arguments:  map[string]interface{}{"path": `safe.pdf\malware.exe`},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "file:read",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf"}},
			},
		},
	})
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
	// The reported extension is the final component's (".exe"), not a
	// backslash-laden ".pdf\malware.exe" produced by treating "\" as a literal.
	assert.Equal(t, ".exe", resp.Denial.Details["extension"])
	assert.NotContains(t, resp.Denial.Details["extension"], `\`)
}

// TestEngine_AllowedExtensions_BackslashAllowedFile is the allow-direction
// counterpart for the backslash separator fix: a Windows-style path whose true final component carries a
// permitted extension is allowed, with the directory portion (which may carry a
// disallowed-looking dotted segment) stripped before matching.
func TestEngine_AllowedExtensions_BackslashAllowedFile(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:read",
		Arguments:  map[string]interface{}{"path": `malware.exe\report.pdf`},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "file:read",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// TestEngine_AllowedExtensions_BlankArrayElementFailsClosed pins: a blank
// (empty/whitespace) element in an allowedExtensions path array must fail closed
// with CONDITION_FAILED, matching allowedTables, instead of being silently dropped
// (which would mislabel an all-blank array as MISSING_CONTEXT and hide malformed
// client input).
func TestEngine_AllowedExtensions_BlankArrayElementFailsClosed(t *testing.T) {
	engine := enforcement.New()
	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:read",
		Arguments:  map[string]interface{}{"paths": []interface{}{"/data/report.pdf", "  "}},
	}
	resp := engine.ValidateAction(context.Background(), &req, []capability.Constraint{
		{
			Target:  "file:read",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "paths", Extensions: []string{".pdf"}},
			},
		},
	})
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "blank element")
}

// TestEngine_RecipientDomain_BlankArrayElementFailsClosed is the recipientDomain
// counterpart.
func TestEngine_RecipientDomain_BlankArrayElementFailsClosed(t *testing.T) {
	engine := enforcement.New()
	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool:send_email",
		Arguments:  map[string]interface{}{"to": []interface{}{"alice@example.com", ""}},
	}
	resp := engine.ValidateAction(context.Background(), &req, []capability.Constraint{
		{
			Target:  "tool:send_email",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
			},
		},
	})
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeRecipientDomain, resp.Denial.ConditionType)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "blank element")
}

// TestEngine_AllowedExtensions_NativeStringSlice pins: a native []string
// argument value (which a library caller can produce, unlike json.Unmarshal which
// always yields []interface{}) must be evaluated against the constraint, not
// rejected with a spurious "got []string" type error.
func TestEngine_AllowedExtensions_NativeStringSlice(t *testing.T) {
	engine := enforcement.New()
	constraints := []capability.Constraint{
		{
			Target:  "file:read",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "paths", Extensions: []string{".go", ".ts"}},
			},
		},
	}

	// Allowed: every native-[]string entry has a permitted extension.
	allow := engine.ValidateAction(context.Background(), &capability.EnforceRequest{
		TargetName: "file:read",
		Arguments:  map[string]interface{}{"paths": []string{"main.go", "app.ts"}},
	}, constraints)
	assert.Equal(t, capability.DecisionAllow, allow.Decision)

	// Denied on policy (not type): a disallowed extension in the native []string.
	deny := engine.ValidateAction(context.Background(), &capability.EnforceRequest{
		TargetName: "file:read",
		Arguments:  map[string]interface{}{"paths": []string{"secret.pem"}},
	}, constraints)
	require.Equal(t, capability.DecisionDeny, deny.Decision)
	require.NotNil(t, deny.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedExtensions, deny.Denial.ConditionType)
	assert.NotContains(t, deny.Denial.Message, "got []string")

	// Blank entry in the native []string still fails closed.
	blank := engine.ValidateAction(context.Background(), &capability.EnforceRequest{
		TargetName: "file:read",
		Arguments:  map[string]interface{}{"paths": []string{"main.go", "  "}},
	}, constraints)
	require.Equal(t, capability.DecisionDeny, blank.Decision)
	assert.Contains(t, blank.Denial.Message, "blank element")
}

// TestEngine_AllowedExtensions_CompoundSuffixSemantics characterizes the
// documented suffix-match behavior so it cannot silently change. The
// match is asymmetric: a simple ".gz" entry admits BOTH "data.gz" and the compound
// "archive.tar.gz" (because ".gz" is a suffix of ".tar.gz" on a dot boundary), so an
// operator cannot allow ".gz" while blocking ".tar.gz" with this allow-only
// condition. The reverse direction is narrow: a compound ".tar.gz" entry admits
// "backup.tar.gz" but NOT a bare "data.gz".
func TestEngine_AllowedExtensions_CompoundSuffixSemantics(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	check := func(t *testing.T, allowlist []string, path string, want capability.Decision) {
		t.Helper()
		req := capability.EnforceRequest{
			SessionID:  "sess-1",
			TargetName: "file:read",
			Arguments:  map[string]interface{}{"path": path},
		}
		resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
			Target:  "file:read",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: allowlist},
			},
		}})
		assert.Equalf(t, want, resp.Decision, "allowlist=%v path=%q", allowlist, path)
	}

	// Simple entry ".gz" matches the plain file...
	check(t, []string{".gz"}, "/data/data.gz", capability.DecisionAllow)
	// ...AND the compound file: this is the documented broadening.
	check(t, []string{".gz"}, "/data/archive.tar.gz", capability.DecisionAllow)

	// Compound entry ".tar.gz" matches the compound file...
	check(t, []string{".tar.gz"}, "/data/backup.tar.gz", capability.DecisionAllow)
	// ...but NOT the bare single-extension file.
	check(t, []string{".tar.gz"}, "/data/data.gz", capability.DecisionDeny)
}

func TestEngine_AllowedTables_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "db:query",
		Arguments: map[string]interface{}{
			"table": map[string]interface{}{
				"table":   "users",
				"columns": []interface{}{"name", "email"},
			},
		},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "db:query",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{
					Argument: "table",
					Tables:   []string{"users", "orders"},
					Columns:  map[string][]string{"users": {"name", "email", "id"}},
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedTables_DenyTable(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "db:query",
		Arguments:  map[string]interface{}{"table": "secrets"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "db:query",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users", "orders"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
}

func TestEngine_AllowedTables_DenyColumn(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "db:query",
		Arguments: map[string]interface{}{
			"table": map[string]interface{}{
				"table":   "users",
				"columns": []interface{}{"password_hash"},
			},
		},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "db:query",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{
					Argument: "table",
					Tables:   []string{"users"},
					Columns:  map[string][]string{"users": {"name", "email"}},
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

// TestEngine_AllowedTables_WhitespacePaddedColumnAllowed pins the trim-both-sides
// invariant for columns: a request column carrying surrounding whitespace (e.g.
// "id ") is not blank (it survives the blank-column guard) and must match an
// allowlisted "id" rather than being false-denied. The allowlist set is trimmed,
// so the request side must be trimmed on comparison too — else "id " misses
// colSet{"id"} and an explicitly allowed column is denied with CONDITION_FAILED.
func TestEngine_AllowedTables_WhitespacePaddedColumnAllowed(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "db:query",
		Arguments: map[string]interface{}{
			"table": map[string]interface{}{
				"table":   "users",
				"columns": []interface{}{"id ", " email"},
			},
		},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "db:query",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{
					Argument: "table",
					Tables:   []string{"users"},
					Columns:  map[string][]string{"users": {"id", "email"}},
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// TestEngine_AllowedTables_BlankColumnFailsClosed pins: a blank element in
// the request's columns array is structurally malformed and must fail closed with
// CONDITION_FAILED, not be silently dropped (which would quietly enforce a
// different column set than the manifest author specified).
func TestEngine_AllowedTables_BlankColumnFailsClosed(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()
	constraints := []capability.Constraint{{
		Target:  "db:query",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedTablesCondition{
				Argument: "table",
				Tables:   []string{"users"},
				Columns:  map[string][]string{"users": {"id", "name"}},
			},
		},
	}}

	for _, tc := range []struct{ name, blank string }{
		{"empty column", ""},
		{"whitespace column", "  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := capability.EnforceRequest{
				TargetName: "db:query",
				Arguments: map[string]interface{}{
					"table": map[string]interface{}{
						"table":   "users",
						"columns": []interface{}{"id", tc.blank},
					},
				},
			}
			resp := engine.ValidateAction(ctx, &req, constraints)
			require.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
			assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
			assert.Contains(t, resp.Denial.Message, "blank column name")
		})
	}
}

// TestEngine_AllowedTables_NativeStringColumns pins: when the request's
// "columns" field is a native []string (rather than the json.Unmarshal-produced
// []interface{}), the column ACL must still be enforced. The old []interface{}
// type assertion failed silently, leaving Columns nil (== allow all columns) and
// turning an intended restriction into a wildcard.
func TestEngine_AllowedTables_NativeStringColumns(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()
	constraints := []capability.Constraint{{
		Target:  "db:query",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedTablesCondition{
				Argument: "table",
				Tables:   []string{"users"},
				Columns:  map[string][]string{"users": {"id", "name"}},
			},
		},
	}}

	// A native []string requesting a forbidden column must now be denied, not
	// silently allowed.
	deny := engine.ValidateAction(ctx, &capability.EnforceRequest{
		TargetName: "db:query",
		Arguments: map[string]interface{}{
			"table": map[string]interface{}{
				"table":   "users",
				"columns": []string{"id", "secret_hash"},
			},
		},
	}, constraints)
	require.Equal(t, capability.DecisionDeny, deny.Decision)
	require.NotNil(t, deny.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedTables, deny.Denial.ConditionType)

	// A native []string within the allowed set is permitted.
	allow := engine.ValidateAction(ctx, &capability.EnforceRequest{
		TargetName: "db:query",
		Arguments: map[string]interface{}{
			"table": map[string]interface{}{
				"table":   "users",
				"columns": []string{"id", "name"},
			},
		},
	}, constraints)
	assert.Equal(t, capability.DecisionAllow, allow.Decision)
}

// TestEngine_AllowedTables_EmptyColumnsWithRestriction is the empty-columns regression test.
//
// When a capability defines column restrictions for a table, an agent that sends
// an empty columns slice must be denied. Previously, `if hasColumnRestriction &&
// len(access.Columns) > 0` skipped the column check entirely for an empty slice,
// allowing full-column access to tables with configured restrictions.
func TestEngine_AllowedTables_EmptyColumnsWithRestriction(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-h3",
		TargetName: "db:query",
		Arguments: map[string]interface{}{
			"table": map[string]interface{}{
				"table":   "payments",
				"columns": []interface{}{}, // empty — must be denied
			},
		},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "db:query",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{
					Argument: "table",
					Tables:   []string{"payments"},
					Columns:  map[string][]string{"payments": {"amount", "currency"}},
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision, "empty column list must be denied when column restrictions exist")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
}

func TestEngine_RecipientDomain_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "email:send",
		Arguments: map[string]interface{}{
			"to": []interface{}{"user@example.com", "admin@example.com"},
		},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "email:send",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_RecipientDomain_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "email:send",
		Arguments: map[string]interface{}{
			"to": []interface{}{"user@example.com", "evil@attacker.com"},
		},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "email:send",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeRecipientDomain, resp.Denial.ConditionType)
}

// TestEngine_RecipientDomain_MalformedDomain pins: structurally invalid
// domains (IP-literal syntax, leading/trailing dot) are denied with a distinct
// "invalid recipient email" reason rather than a misleading "domain not allowed",
// so an operator reading the audit log can tell malformed input from a policy
// denial — and so an IP-literal can never silently match an allowlist entry.
func TestEngine_RecipientDomain_MalformedDomain(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	for _, addr := range []string{
		"user@[192.168.1.1]",
		"user@.example.com",
		"user@example.com.",
	} {
		req := capability.EnforceRequest{
			SessionID:  "sess-1",
			TargetName: "email:send",
			Arguments:  map[string]interface{}{"to": addr},
		}
		resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
			{
				Target:  "email:send",
				Actions: []string{"*"},
				Conditions: []capability.Condition{
					&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
				},
			},
		})
		require.Equal(t, capability.DecisionDeny, resp.Decision, "addr %q should be denied", addr)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ConditionTypeRecipientDomain, resp.Denial.ConditionType)
		assert.Contains(t, resp.Denial.Message, "invalid recipient email", "addr %q", addr)
	}
}

func TestEngine_RedactFields_ProducesObligation(t *testing.T) {
	// redactFields is a directive. Obligations are collected from
	// Directives after all conditions pass.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Directives: []capability.Directive{
				&capability.RedactFieldsDirective{Fields: []string{"$.ssn", "$.creditCard"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 1)
	assert.Equal(t, "redactFields", resp.Obligations[0].Type)
	assert.Equal(t, []string{"$.ssn", "$.creditCard"}, resp.Obligations[0].Paths)
}

func TestEngine_PolicyCondition_DenyWhenNoEvaluatorConfigured(t *testing.T) {
	// Without a PolicyEvaluator the engine must deny (fail-closed) so that a
	// misconfigured deployment cannot silently allow policy-gated requests.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa", Config: map[string]interface{}{"policy": "allow"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypePolicy, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "WithPolicyEvaluator")
}

func TestEngine_PolicyCondition_EvaluatorAllow(t *testing.T) {
	evaluator := &fakePolicyEvaluator{result: nil}
	engine := enforcement.New(enforcement.WithPolicyEvaluator(evaluator))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.True(t, evaluator.called)
}

func TestEngine_PolicyCondition_EvaluatorDeny(t *testing.T) {
	evaluator := &fakePolicyEvaluator{
		result: &enforcement.ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypePolicy,
			Message:       "policy denies this action",
		},
	}
	engine := enforcement.New(enforcement.WithPolicyEvaluator(evaluator))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, "policy denies this action", resp.Denial.Message)
}

// fakePolicyEvaluator is a test double for enforcement.PolicyEvaluator.
type fakePolicyEvaluator struct {
	called bool
	result *enforcement.ConditionError
}

func (f *fakePolicyEvaluator) Evaluate(_ context.Context, _ string, _, _ interface{}, _ *capability.EnforceRequest) *enforcement.ConditionError {
	f.called = true
	return f.result
}

func TestEngine_CustomCondition_DenyWhenNoHandlerRegistered(t *testing.T) {
	// Without an explicit handler registered for ConditionTypeCustom the engine
	// must deny (fail-closed) so that unknown custom conditions cannot silently
	// allow requests.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.CustomCondition{Name: "my-check", Config: "data"},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeCustom, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "my-check")
	assert.Contains(t, resp.Denial.Message, "WithConditionHandler")
}

func TestEngine_AllowedExtensions_MissingArgumentField(t *testing.T) {
	// A condition without the "argument" field must be denied fail-closed.
	// The "argument" field is required — guessing argument names is not allowed.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "file:write"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "file:write",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Extensions: []string{".pdf"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "'argument'")
}

func TestEngine_AllowedExtensions_ArgumentValueMissing(t *testing.T) {
	// "argument" is set but the named argument is absent from the tool call.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:write",
		Arguments:  map[string]interface{}{"other": "value"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "file:write",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
}

func TestEngine_AllowedTables_MissingArgumentField(t *testing.T) {
	// A condition without the "argument" field must be denied fail-closed.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "db:query"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "db:query",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{Tables: []string{"users"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "'argument'")
}

func TestEngine_AllowedTables_ArgumentValueMissing(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "db:query",
		Arguments:  map[string]interface{}{"other": "irrelevant"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "db:query",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

// TestEngine_AllowedTables_WrongArgumentType is the regression: when the
// named argument is present but carries an unsupported scalar type (a number or
// boolean), the denial must be CONDITION_FAILED with a type-mismatch message —
// not the misleading MISSING_CONTEXT "argument is missing or empty", which sends
// an operator hunting for a missing field that is actually present.
func TestEngine_AllowedTables_WrongArgumentType(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	caps := []capability.Constraint{
		{
			Target:  "db:query",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}},
			},
		},
	}

	for _, tc := range []struct {
		name string
		val  interface{}
	}{
		{"number argument", float64(42)},
		{"boolean argument", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := capability.EnforceRequest{
				SessionID:  "sess-1",
				TargetName: "db:query",
				Arguments:  map[string]interface{}{"table": tc.val},
			}
			resp := engine.ValidateAction(ctx, &req, caps)
			assert.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
			assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
			assert.NotContains(t, resp.Denial.Message, "missing or empty")
			assert.Contains(t, resp.Denial.Message, "must be a string, object, or array")
		})
	}
}

func TestEngine_RecipientDomain_MissingArgumentField(t *testing.T) {
	// A condition without the "argument" field must be denied fail-closed.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "email:send"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "email:send",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.RecipientDomainCondition{Domains: []string{"example.com"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeRecipientDomain, resp.Denial.ConditionType)
	assert.Contains(t, resp.Denial.Message, "'argument'")
}

func TestEngine_RecipientDomain_ArgumentValueMissing(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "email:send",
		Arguments:  map[string]interface{}{"subject": "hello"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "email:send",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

func TestEngine_RegisterCustomCondition(t *testing.T) {
	ctx := context.Background()

	// Override the custom handler to deny all, registered at construction via the
	// WithConditionHandler option (applied after the built-ins, so it wins).
	engine := enforcement.New(enforcement.WithConditionHandler(capability.ConditionTypeCustom, enforcement.ConditionHandlerFunc(func(_ context.Context, _ capability.Condition, _ *capability.EnforceRequest) *enforcement.ConditionError {
		return &enforcement.ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeCustom,
			Message:       "custom condition denied",
		}
	})))

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.CustomCondition{Name: "deny-all"},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, "custom condition denied", resp.Denial.Message)
}

func TestEngine_MultipleConditions_AllMustPass(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Context: capability.EnforceRequestContext{
			SourceIP: "10.0.0.5",
		},
		Arguments: map[string]interface{}{"op": "read"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
					NotAfter:  "2025-06-15T14:00:00Z",
				},
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
				&capability.AllowedOperationsCondition{Argument: "op", Operations: []string{"read", "write"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MultipleConditions_FirstFailureDenies(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(now)
	engine := enforcement.New(enforcement.WithClock(clock))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Context: capability.EnforceRequestContext{
			SourceIP: "192.168.1.1", // Not in allowed range

		},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
					NotAfter:  "2025-06-15T14:00:00Z",
				},
				&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeIPRange, resp.Denial.ConditionType)
}

// TestEngine_EmptyActions_FailsClosed verifies that a constraint with an empty
// actions list does not match any call: the engine denies, consistent with the
// fail-closed invariant and with the manifest loader, which rejects empty
// "actions" at load time.
func TestEngine_EmptyActions_FailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		actions []string
	}{
		{name: "nil actions", actions: nil},
		{name: "empty actions slice", actions: []string{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := enforcement.New()
			ctx := context.Background()

			req := capability.EnforceRequest{
				SessionID:  "sess-1",
				TargetName: "tool",
			}

			resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
				{Target: "tool", Actions: tc.actions},
			})
			assert.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
		})
	}
}

func TestEngine_AllowedExtensions_FromNamedArgument(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:write",
		Arguments:  map[string]interface{}{"filePath": "/tmp/data.csv"},
	}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "file:write",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "filePath", Extensions: []string{"csv", "json"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_TimeWindow_IgnoresRequestContextNow(t *testing.T) {
	// req.Context.Now must be ignored; the server clock is always authoritative
	fixedTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	engine := enforcement.New(enforcement.WithClock(newFakeClock(fixedTime)))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Context: capability.EnforceRequestContext{
			// Client supplies a different "now" that falls outside the window —
			// the engine must not use it; it must use the server clock instead.
			Now: "2020-01-01T00:00:00Z",
		},
	}

	// Window is open at the fixed server time (12:00) — should allow
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T10:00:00Z",
					NotAfter:  "2025-06-15T14:00:00Z",
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)

	// Window is closed at the fixed server time (12:00) — should deny regardless of req.Context.Now
	req2 := capability.EnforceRequest{
		SessionID:  "sess-2",
		TargetName: "tool",
		Context: capability.EnforceRequestContext{
			// Client supplies a "now" inside the (future) window — must be ignored
			Now: "2025-06-15T16:00:00Z",
		},
	}
	resp2 := engine.ValidateAction(ctx, &req2, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-06-15T15:00:00Z",
					NotAfter:  "2025-06-15T17:00:00Z",
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp2.Decision)
}

func TestEngine_AllowedValues_Allow(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	tests := []struct {
		name     string
		argument string
		values   []interface{}
		args     map[string]interface{}
	}{
		{
			name:     "string match",
			argument: "format",
			values:   []interface{}{"json", "csv"},
			args:     map[string]interface{}{"format": "json"},
		},
		{
			name:     "boolean match",
			argument: "strict",
			values:   []interface{}{true},
			args:     map[string]interface{}{"strict": true},
		},
		{
			name:     "nil value in allowed list",
			argument: "filter",
			values:   []interface{}{nil, "all"},
			args:     map[string]interface{}{"filter": nil},
		},
		// Glob patterns — path.Match semantics.
		{
			name:     "glob slash-star matches file under directory",
			argument: "path",
			values:   []interface{}{"/reports/*"},
			args:     map[string]interface{}{"path": "/reports/q3.pdf"},
		},
		{
			name:     "glob star-dot-ext matches extension",
			argument: "path",
			values:   []interface{}{"*.pdf"},
			args:     map[string]interface{}{"path": "report.pdf"},
		},
		{
			name:     "glob question-mark matches single char",
			argument: "env",
			values:   []interface{}{"prod-?"},
			args:     map[string]interface{}{"env": "prod-1"},
		},
		{
			name:     "glob mixed with exact: exact value wins before reaching glob",
			argument: "path",
			values:   []interface{}{"/reports/q3.pdf", "/reports/*"},
			args:     map[string]interface{}{"path": "/reports/q3.pdf"},
		},
		{
			name:     "glob with prefix wildcard",
			argument: "service",
			values:   []interface{}{"aws-*"},
			args:     map[string]interface{}{"service": "aws-prod"},
		},
		// Bare "*" is an explicit allow-all, including values that contain '/'
		// (path.Match alone would have denied these).
		{
			name:     "bare star allows path with slash",
			argument: "path",
			values:   []interface{}{"*"},
			args:     map[string]interface{}{"path": "/reports/sub/q3.pdf"},
		},
		{
			name:     "bare star allows uri",
			argument: "uri",
			values:   []interface{}{"*"},
			args:     map[string]interface{}{"uri": "file:///etc/passwd"},
		},
		// A "**" path segment matches a whole subtree.
		{
			name:     "doublestar matches nested path",
			argument: "path",
			values:   []interface{}{"/reports/**"},
			args:     map[string]interface{}{"path": "/reports/sub/q3.pdf"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := capability.EnforceRequest{
				SessionID:  "sess-1",
				TargetName: "tool",
				Arguments:  tt.args,
			}
			resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
				{
					Target:  "tool",
					Actions: []string{"*"},
					Conditions: []capability.Condition{
						&capability.AllowedValuesCondition{
							Argument: tt.argument,
							Values:   tt.values,
						},
					},
				},
			})
			assert.Equal(t, capability.DecisionAllow, resp.Decision, tt.name)
		})
	}
}

func TestEngine_AllowedValues_Deny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Arguments:  map[string]interface{}{"format": "xml"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "format",
					Values:   []interface{}{"json", "csv"},
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType)
}

func TestEngine_AllowedValues_GlobDeny(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	tests := []struct {
		name     string
		argument string
		values   []interface{}
		args     map[string]interface{}
	}{
		{
			name:     "glob no match: path outside directory",
			argument: "path",
			values:   []interface{}{"/reports/*"},
			args:     map[string]interface{}{"path": "/internal/secret.txt"},
		},
		{
			name:     "glob no match: subdirectory not matched by single star",
			argument: "path",
			values:   []interface{}{"/reports/*"},
			args:     map[string]interface{}{"path": "/reports/sub/file.txt"},
		},
		{
			name:     "glob no match: extension mismatch",
			argument: "path",
			values:   []interface{}{"*.pdf"},
			args:     map[string]interface{}{"path": "report.csv"},
		},
		{
			name:     "doublestar still respects its prefix",
			argument: "path",
			values:   []interface{}{"/reports/**"},
			args:     map[string]interface{}{"path": "/internal/secret.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := capability.EnforceRequest{
				SessionID:  "sess-1",
				TargetName: "tool",
				Arguments:  tt.args,
			}
			resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
				{
					Target:  "tool",
					Actions: []string{"*"},
					Conditions: []capability.Condition{
						&capability.AllowedValuesCondition{
							Argument: tt.argument,
							Values:   tt.values,
						},
					},
				},
			})
			assert.Equal(t, capability.DecisionDeny, resp.Decision, tt.name)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType)
		})
	}
}

func TestEngine_AllowedValues_MalformedGlobFallsThrough(t *testing.T) {
	// A malformed glob pattern (path.ErrBadPattern) must not cause an error —
	// it should fall through to the next value and ultimately deny.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Arguments:  map[string]interface{}{"path": "/reports/q3.pdf"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "path",
					Values:   []interface{}{"[bad-pattern"},
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

// path.Match glob semantics tests.

func TestEngine_ValidateAction_GlobQuestionMark(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:a",
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "file:?", Actions: []string{"*"}},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_ValidateAction_GlobQuestionMark_NoMatch(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:ab",
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "file:?", Actions: []string{"*"}},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_ValidateAction_GlobCharacterClass(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool:b",
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "tool:[abc]", Actions: []string{"*"}},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_ValidateAction_MidStringWildcard(t *testing.T) {
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "file:data.csv",
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "file:*.csv", Actions: []string{"*"}},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestValidateResourcePattern_Valid(t *testing.T) {
	cases := []string{"*", "tool:*", "file:?.csv", "tool:[abc]", "email:send"}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			assert.NoError(t, enforcement.ValidateResourcePattern(c))
		})
	}
}

func TestValidateResourcePattern_Invalid(t *testing.T) {
	// Unclosed character class is a malformed pattern.
	err := enforcement.ValidateResourcePattern("tool:[abc")
	assert.Error(t, err)
}

func TestEngine_MostSpecificMatch_NarrowCapabilityWins(t *testing.T) {
	// Exact resource beats glob: email:send is more specific than email:*
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{TargetName: "email:send"}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "email:*", Actions: []string{"call"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Target: "email:send", Actions: []string{"call"}},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MostSpecificMatch_ExactResourceBeatsWildcard(t *testing.T) {
	// Exact resource entry (no conditions) wins over glob with a deny condition.
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{TargetName: "email:send"}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "email:*", Actions: []string{"call"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Target: "email:send", Actions: []string{"call"}},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MostSpecificMatch_LongerPrefixWins(t *testing.T) {
	// A longer literal prefix in a glob beats a shorter one.
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{TargetName: "tool:mail"}

	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{Target: "tool:*", Actions: []string{"call"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Target: "tool:mail", Actions: []string{"call"}},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MostSpecificMatch_OrderingDoesNotMatter(t *testing.T) {
	// The most-specific constraint wins regardless of its position in the list.
	engine := enforcement.New()
	ctx := context.Background()
	req := capability.EnforceRequest{TargetName: "file:read"}
	constraints := []capability.Constraint{
		{Target: "file:*", Actions: []string{"call"}, Conditions: []capability.Condition{&capability.TimeWindowCondition{NotBefore: "2999-01-01T00:00:00Z"}}},
		{Target: "file:read", Actions: []string{"call"}},
	}

	respA := engine.ValidateAction(ctx, &req, constraints)
	assert.Equal(t, capability.DecisionAllow, respA.Decision)

	respB := engine.ValidateAction(ctx, &req, []capability.Constraint{constraints[1], constraints[0]})
	assert.Equal(t, capability.DecisionAllow, respB.Decision)
}

// ── ConditionError ──────────────────────────────────────────────────────────

func TestConditionError_Error(t *testing.T) {
	t.Parallel()
	ce := &enforcement.ConditionError{
		Code:          "TEST_CODE",
		ConditionType: "timeWindow",
		Message:       "something went wrong",
	}
	assert.Equal(t, "something went wrong", ce.Error())
}

// ── FindMatchingCapability ──────────────────────────────────────────────────

func TestEngine_FindMatchingCapability_ReturnsMatch(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()

	req := &capability.EnforceRequest{TargetName: "read_file"}
	caps := []capability.Constraint{
		{Target: "write_file", Actions: []string{"*"}},
		{Target: "read_file", Actions: []string{"*"}},
	}

	matched := engine.FindMatchingCapability(req, caps)
	require.NotNil(t, matched)
	assert.Equal(t, "read_file", matched.Target)
}

func TestEngine_FindMatchingCapability_ReturnsNilWhenNoMatch(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()

	req := &capability.EnforceRequest{TargetName: "delete_file"}
	caps := []capability.Constraint{
		{Target: "read_file", Actions: []string{"*"}},
	}

	matched := engine.FindMatchingCapability(req, caps)
	assert.Nil(t, matched)
}

// ── Value-form condition branch coverage ───────────────────────────────────
//
// Each `as*` helper in pkg/enforcement/handlers.go tries the pointer-form type
// assertion first and falls back to value-form. Existing tests always pass pointer
// conditions. The tests below pass value-form (non-pointer) conditions to exercise
// the second branch.

func TestEngine_TimeWindow_ValueForm(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	engine := enforcement.New(enforcement.WithClock(newFakeClock(now)))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			// value form — not pointer
			capability.TimeWindowCondition{
				NotBefore: "2025-06-15T10:00:00Z",
				NotAfter:  "2025-06-15T14:00:00Z",
			},
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_IPRange_ValueForm(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "tool",
		Context:    capability.EnforceRequestContext{SourceIP: "192.168.1.50"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			capability.IPRangeCondition{CIDRs: []string{"192.168.0.0/16"}}, // value form
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedOperations_ValueForm(t *testing.T) {
	t.Parallel()
	// Exercises the value-form (non-pointer) branch of asAllowedOperations.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "db",
		Arguments:  map[string]interface{}{"query": "SELECT 1"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "db",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			capability.AllowedOperationsCondition{Argument: "query", Operations: []string{"SELECT"}}, // value form
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedExtensions_ValueForm(t *testing.T) {
	t.Parallel()
	// Exercises the value-form (non-pointer) branch of asAllowedExtensions.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "file:read",
		Arguments:  map[string]interface{}{"path": "/docs/report.pdf"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "file:read",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".pdf"}}, // value form
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedTables_ValueForm(t *testing.T) {
	t.Parallel()
	// Exercises the value-form (non-pointer) branch of asAllowedTables.
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "db:query",
		Arguments:  map[string]interface{}{"table": "reports"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "db:query",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			capability.AllowedTablesCondition{Argument: "table", Tables: []string{"reports"}}, // value form
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_MaxCalls_ValueForm(t *testing.T) {
	t.Parallel()
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-mc-val", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			capability.MaxCallsCondition{Count: 5, WindowSeconds: 60}, // value form
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_RecipientDomain_ValueForm(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "email:send",
		Arguments:  map[string]interface{}{"to": "alice@example.com"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "email:send",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}}, // value form
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_Policy_ValueForm(t *testing.T) {
	t.Parallel()
	// A nil PolicyEvaluator with a policy condition is fail-closed (deny).
	// The important thing is that asPolicy's value-form branch is exercised.
	engine := enforcement.New() // no PolicyEvaluator wired
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			capability.PolicyCondition{Backend: "opa"}, // value form
		},
	}})
	// Fail-closed: no evaluator → deny.
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_Custom_ValueForm(t *testing.T) {
	t.Parallel()
	// The built-in custom handler always denies (fail-closed). This test verifies
	// that asCustom's value-form branch is exercised: a value-form CustomCondition
	// is correctly identified and the handler is reached (result is deny, as designed).
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			capability.CustomCondition{Name: "my-custom", Config: nil}, // value form
		},
	}})
	// Fail-closed: built-in handleCustom always denies.
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeCustom, resp.Denial.ConditionType)
}

func TestEngine_AllowedValues_ValueForm(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": "/reports/q3.pdf"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "read_file",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			capability.AllowedValuesCondition{ // value form
				Argument: "path",
				Values:   []interface{}{"/reports/*"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// ── Additional coverage tests ───────────────────────────────────────────────

func TestEngine_MatchesResource_BadGlobPattern(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()

	req := &capability.EnforceRequest{TargetName: "anything"}
	matched := engine.FindMatchingCapability(req, []capability.Constraint{
		{Target: "[", Actions: []string{"*"}},
	})
	assert.Nil(t, matched, "bad glob pattern must produce no match")
}

func TestEngine_AllowedOperations_EmptyArgument_RequiresExplicit(t *testing.T) {
	// AllowedOperationsCondition with Argument=="" is no longer valid.
	// An explicit argument field is required (matching allowedExtensions and
	// allowedTables behavior). Omitting argument now returns CONDITION_FAILED.
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "myTool",
		Arguments:  map[string]interface{}{"query": "SELECT id FROM users"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "myTool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Operations: []string{"SELECT"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "explicit 'argument'")

	// With explicit argument set, the same request is allowed.
	req2 := capability.EnforceRequest{
		SessionID:  "sess-2",
		TargetName: "myTool",
		Arguments:  map[string]interface{}{"query": "SELECT id FROM users"},
	}
	resp2 := engine.ValidateAction(ctx, &req2, []capability.Constraint{
		{
			Target:  "myTool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Argument: "query", Operations: []string{"SELECT"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp2.Decision)
}

func TestEngine_TimeWindow_InvalidNotBefore(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithClock(newFakeClock(time.Now())))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{NotBefore: "not-a-date"},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeTimeWindow, resp.Denial.ConditionType)
}

// TestEngine_TimeWindow_BothBoundsEmpty pins the handler's fail-closed guard: a
// direct/programmatic caller constructing a timeWindow with neither bound (which the
// manifest loader rejects, but the exported engine must also defend against) denies
// rather than falling open, since a boundless window restricts nothing.
func TestEngine_TimeWindow_BothBoundsEmpty(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithClock(newFakeClock(time.Now())))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeTimeWindow, resp.Denial.ConditionType)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
}

func TestEngine_TimeWindow_InvalidNotAfter(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithClock(newFakeClock(time.Now())))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{NotAfter: "not-a-date"},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeTimeWindow, resp.Denial.ConditionType)
}

func TestEngine_AllowedValues_EmptyArgumentName(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: "", Values: []interface{}{"x"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType)
}

func TestEngine_AllowedValues_MissingArgument(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Arguments:  nil, // no arguments at all
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp"}},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

func TestEngine_AllowedValues_ExactMatchNonString(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Arguments:  map[string]interface{}{"count": float64(42)},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "count",
					Values:   []interface{}{float64(42)},
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// TestEngine_AllowedValues_NumericTypeMismatch verifies that a manifest value
// decoded as a Go int (the type gopkg.in/yaml.v3 produces for a bare integer)
// matches a request argument decoded as float64 (the type encoding/json
// produces), and vice versa. reflect.DeepEqual alone treats int(42) and
// float64(42) as unequal, which previously denied a value explicitly listed in
// the manifest.
func TestEngine_AllowedValues_NumericTypeMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name     string
		values   []interface{}
		arg      interface{}
		decision capability.Decision
	}{
		{"yaml-int-vs-json-float-allow", []interface{}{42, 100}, float64(42), capability.DecisionAllow},
		{"json-float-vs-yaml-int-allow", []interface{}{float64(42)}, 42, capability.DecisionAllow},
		{"int64-vs-float-allow", []interface{}{int64(7)}, float64(7), capability.DecisionAllow},
		{"numeric-mismatch-deny", []interface{}{42, 100}, float64(43), capability.DecisionDeny},
		// bool must never be conflated with a numeric 1/0.
		{"bool-not-numeric-one", []interface{}{1}, true, capability.DecisionDeny},
		{"numeric-one-not-bool", []interface{}{true}, float64(1), capability.DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			engine := enforcement.New()
			req := capability.EnforceRequest{
				SessionID:  "sess-1",
				TargetName: "tool",
				Arguments:  map[string]interface{}{"count": tc.arg},
			}
			resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
				{
					Target:  "tool",
					Actions: []string{"*"},
					Conditions: []capability.Condition{
						&capability.AllowedValuesCondition{
							Argument: "count",
							Values:   tc.values,
						},
					},
				},
			})
			assert.Equal(t, tc.decision, resp.Decision)
		})
	}
}

func TestEngine_AllowedValues_NoMatch(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Arguments:  map[string]interface{}{"color": "c"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "color",
					Values:   []interface{}{"a", "b"},
				},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

// TestEngine_AllowedValues_LiteralPatternStringDenied verifies that the literal
// pattern text does not bypass a glob constraint. values: ["[0-9]"] is meant to
// admit a single digit; the metacharacter-containing pattern string itself must
// NOT be allowed (the prior exact-match-before-glob order let it through). The
// glob "[0-9]" must still admit "5".
func TestEngine_AllowedValues_LiteralPatternStringDenied(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	build := func() []capability.Constraint {
		return []capability.Constraint{
			{
				Target:  "tool",
				Actions: []string{"*"},
				Conditions: []capability.Condition{
					&capability.AllowedValuesCondition{
						Argument: "digit",
						Values:   []interface{}{"[0-9]"},
					},
				},
			},
		}
	}

	// The literal pattern string must be denied (it is not a single digit).
	denyReq := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool",
		Arguments:  map[string]interface{}{"digit": "[0-9]"},
	}
	resp := engine.ValidateAction(ctx, &denyReq, build())
	assert.Equal(t, capability.DecisionDeny, resp.Decision,
		"literal pattern string %q must not bypass the glob constraint", "[0-9]")

	// A value the glob genuinely matches must be allowed.
	allowReq := capability.EnforceRequest{
		SessionID:  "sess-2",
		TargetName: "tool",
		Arguments:  map[string]interface{}{"digit": "5"},
	}
	resp = engine.ValidateAction(ctx, &allowReq, build())
	assert.Equal(t, capability.DecisionAllow, resp.Decision,
		"a single digit must satisfy the [0-9] glob")
}

// errorCounter is a capability.CallCounter whose AdmitAll always returns
// an error, so maxCalls exercises counter-error handling rather than the
// fail-closed "no counter configured" branch.
type errorCounter struct{}

func (errorCounter) IncrementAndGet(_ context.Context, _ string, _, _ int) (int64, error) {
	return 0, errors.New("counter error")
}

func (errorCounter) Peek(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}

func (errorCounter) AdmitAll(_ context.Context, _ []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return false, 0, 0, 0, errors.New("counter error")
}

func TestEngine_MaxCalls_CounterError(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithCallCounter(errorCounter{}))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 10, WindowSeconds: 60},
			},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "call counter error")
}

// allowEvaluator is a PolicyEvaluator that always allows.
type allowEvaluator struct{}

func (allowEvaluator) Evaluate(_ context.Context, _ string, _, _ interface{}, _ *capability.EnforceRequest) *enforcement.ConditionError {
	return nil
}

func TestEngine_Policy_WithEvaluator_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithPolicyEvaluator(allowEvaluator{}))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{
		{
			Target:  "tool",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "test"},
			},
		},
	})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// ── Named-argument mode tests ───────────────────────────────────────────────
//
// Each condition type that previously relied on hardcoded heuristic argument
// name extraction now supports an explicit "argument" field.  The tests below
// verify that specifying the argument name takes precedence over the heuristic
// and works for non-standard argument names.

func TestEngine_AllowedOperations_NamedArgument_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	// Tool uses "command" instead of "sql"/"query"/"statement".
	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "run_db",
		Arguments:  map[string]interface{}{"command": "SELECT * FROM orders"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "run_db",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedOperationsCondition{
				Argument:   "command",
				Operations: []string{"SELECT"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedOperations_NamedArgument_Deny(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "run_db",
		Arguments:  map[string]interface{}{"command": "DROP TABLE orders"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "run_db",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedOperationsCondition{
				Argument:   "command",
				Operations: []string{"SELECT"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeAllowedOperations, resp.Denial.ConditionType)
}

func TestEngine_AllowedOperations_NamedArgument_Missing(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "run_db",
		Arguments:  map[string]interface{}{"other": "value"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "run_db",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedOperationsCondition{
				Argument:   "command",
				Operations: []string{"SELECT"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

// TestEngine_AllowedOperations_NamedArgument_WrongType is the regression guard:
// when the named argument is present but holds a non-string
// value, the denial must carry ErrCodeConditionFailed (the tool supplied the
// field with the wrong type) rather than ErrCodeMissingContext, which would
// mislead an operator reading the audit trail into thinking the field was
// absent. Empty/whitespace strings and genuinely absent fields stay
// MISSING_CONTEXT.
func TestEngine_AllowedOperations_NamedArgument_WrongType(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	cases := []struct {
		name     string
		value    interface{}
		present  bool
		wantCode string
	}{
		{name: "integer value", value: 42, present: true, wantCode: capability.ErrCodeConditionFailed},
		{name: "boolean value", value: true, present: true, wantCode: capability.ErrCodeConditionFailed},
		{name: "float value", value: 3.14, present: true, wantCode: capability.ErrCodeConditionFailed},
		{name: "array value", value: []interface{}{"SELECT"}, present: true, wantCode: capability.ErrCodeConditionFailed},
		{name: "empty string", value: "", present: true, wantCode: capability.ErrCodeMissingContext},
		{name: "whitespace string", value: "   ", present: true, wantCode: capability.ErrCodeMissingContext},
		{name: "absent argument", value: nil, present: false, wantCode: capability.ErrCodeMissingContext},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := map[string]interface{}{}
			if tc.present {
				args["command"] = tc.value
			} else {
				args["other"] = "value"
			}
			req := capability.EnforceRequest{
				SessionID:  "sess",
				TargetName: "run_db",
				Arguments:  args,
			}
			resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
				Target:  "run_db",
				Actions: []string{"*"},
				Conditions: []capability.Condition{
					&capability.AllowedOperationsCondition{
						Argument:   "command",
						Operations: []string{"SELECT"},
					},
				},
			}})
			assert.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, tc.wantCode, resp.Denial.Code)
			assert.Equal(t, capability.ConditionTypeAllowedOperations, resp.Denial.ConditionType)
		})
	}
}

func TestEngine_AllowedExtensions_NamedArgument_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "upload",
		Arguments:  map[string]interface{}{"filename": "/data/report.csv"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "upload",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedExtensionsCondition{
				Argument:   "filename",
				Extensions: []string{".csv", ".json"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedExtensions_NamedArgument_Deny(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "upload",
		Arguments:  map[string]interface{}{"filename": "/data/malware.exe"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "upload",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedExtensionsCondition{
				Argument:   "filename",
				Extensions: []string{".csv", ".json"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_AllowedTables_NamedArgument_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "query",
		Arguments:  map[string]interface{}{"target_table": "orders"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "query",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedTablesCondition{
				Argument: "target_table",
				Tables:   []string{"orders", "customers"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_AllowedTables_NamedArgument_Deny(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "query",
		Arguments:  map[string]interface{}{"target_table": "salaries"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "query",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedTablesCondition{
				Argument: "target_table",
				Tables:   []string{"orders", "customers"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_AllowedTables_NamedArgument_ArrayAllow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "query",
		Arguments: map[string]interface{}{
			"target_table": []interface{}{"orders", "customers"},
		},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "query",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedTablesCondition{
				Argument: "target_table",
				Tables:   []string{"orders", "customers", "products"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// TestEngine_AllowedTables_ArrayWithEmptyElement pins: an empty or blank
// string element inside a populated tables array must fail closed (it was
// silently dropped before), matching how a top-level empty string and a
// non-string array element already deny. The denial is CONDITION_FAILED, not the
// misleading MISSING_CONTEXT used for a genuinely empty argument.
func TestEngine_AllowedTables_ArrayWithEmptyElement(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	caps := []capability.Constraint{{
		Target:  "query",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.AllowedTablesCondition{
				Argument: "target_table",
				Tables:   []string{"orders", "customers"},
			},
		},
	}}

	for _, tc := range []struct {
		name string
		arr  []interface{}
	}{
		{"empty string element", []interface{}{"orders", ""}},
		{"blank string element", []interface{}{"orders", "   "}},
		{"map element with blank table", []interface{}{"orders", map[string]interface{}{"table": ""}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := capability.EnforceRequest{
				SessionID:  "sess",
				TargetName: "query",
				Arguments:  map[string]interface{}{"target_table": tc.arr},
			}
			resp := engine.ValidateAction(ctx, &req, caps)
			assert.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
			assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
			assert.NotContains(t, resp.Denial.Message, "missing or empty")
		})
	}
}

func TestEngine_RecipientDomain_NamedArgument_Allow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "send_notification",
		Arguments:  map[string]interface{}{"dest_email": "alice@example.com"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "send_notification",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.RecipientDomainCondition{
				Argument: "dest_email",
				Domains:  []string{"example.com"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEngine_RecipientDomain_NamedArgument_Deny(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "send_notification",
		Arguments:  map[string]interface{}{"dest_email": "attacker@evil.com"},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "send_notification",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.RecipientDomainCondition{
				Argument: "dest_email",
				Domains:  []string{"example.com"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
}

func TestEngine_RecipientDomain_NamedArgument_ArrayAllow(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "send_notification",
		Arguments: map[string]interface{}{
			"dest_email": []interface{}{"alice@example.com", "bob@example.com"},
		},
	}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "send_notification",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.RecipientDomainCondition{
				Argument: "dest_email",
				Domains:  []string{"example.com"},
			},
		},
	}})
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// TestEngine_MaxCalls_DeniedCallsDoNotExtendLockout is the engine-level
// regression test: a denied maxCalls call must not be counted, so
// a client that keeps retrying within the window does not push its own recovery
// out, and the recovery happens on time once the original calls age out.
func TestEngine_MaxCalls_DeniedCallsDoNotExtendLockout(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time { return now }))
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 2, WindowSeconds: 60},
		},
	}}

	// Two allowed calls fill the window.
	for i := 0; i < 2; i++ {
		resp := engine.ValidateAction(ctx, &req, caps)
		require.Equal(t, capability.DecisionAllow, resp.Decision)
	}

	// The next call is denied with a RATE_LIMITED code and a retry_after_seconds hint.
	resp := engine.ValidateAction(ctx, &req, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
	require.NotNil(t, resp.Denial.Details)
	retryAfter, ok := resp.Denial.Details["retry_after_seconds"].(int64)
	require.True(t, ok, "denial must carry an integer-seconds retry_after_seconds hint")
	assert.Equal(t, int64(60), retryAfter, "oldest call expires one full window out")

	// Keep retrying through the window; every call is denied and records nothing.
	for sec := 1; sec <= 59; sec++ {
		now = now.Add(time.Second)
		r := engine.ValidateAction(ctx, &req, caps)
		require.Equal(t, capability.DecisionDeny, r.Decision, "second %d must still be denied", sec)
	}

	// One tick past the window: the original two calls have aged out, so a retry
	// is admitted even though the client never paused.
	now = now.Add(2 * time.Second)
	r := engine.ValidateAction(ctx, &req, caps)
	assert.Equal(t, capability.DecisionAllow, r.Decision, "lockout must clear once the original window passes")
}

// TestEngine_MaxCalls_NoCounterFailsClosed verifies that with no call counter
// configured, the atomic check-and-record maxCalls requires cannot run and the
// condition denies fail-closed rather than silently allowing the call. Before
// the quota admission was folded into capability.CallCounter this was tested with a
// counter that lacked the atomic check; that gap is now a compile error, so a nil
// counter is the only remaining trigger.
func TestEngine_MaxCalls_NoCounterFailsClosed(t *testing.T) {
	t.Parallel()
	engine := enforcement.New() // no call counter → no atomic rate-limit check
	ctx := context.Background()

	req := capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	resp := engine.ValidateAction(ctx, &req, []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 10, WindowSeconds: 60},
		},
	}})
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeMaxCalls, resp.Denial.ConditionType)
}

// ── Exported MatchesResource / ResourceSpecificity ────────────────────────────

func TestMatchesResource_ExactMatch(t *testing.T) {
	t.Parallel()
	if !enforcement.MatchesResource("tool:read_file", "tool:read_file") {
		t.Error("exact match must return true")
	}
}

func TestMatchesResource_Wildcard(t *testing.T) {
	t.Parallel()
	if !enforcement.MatchesResource("*", "anything") {
		t.Error("'*' must match any tool name")
	}
}

func TestMatchesResource_GlobPattern(t *testing.T) {
	t.Parallel()
	if !enforcement.MatchesResource("file:*.csv", "file:data.csv") {
		t.Error("glob pattern must match")
	}
	if enforcement.MatchesResource("file:*.csv", "file:data.json") {
		t.Error("glob pattern must not match wrong extension")
	}
}

func TestMatchesResource_NoMatch(t *testing.T) {
	t.Parallel()
	if enforcement.MatchesResource("read_file", "write_file") {
		t.Error("different names must not match")
	}
}

func TestResourceSpecificity_ExactHighest(t *testing.T) {
	t.Parallel()
	exact := enforcement.ResourceSpecificity("read_file", "read_file")
	glob := enforcement.ResourceSpecificity("read_*", "read_file")
	wildcard := enforcement.ResourceSpecificity("*", "read_file")
	if exact <= glob {
		t.Errorf("exact (%d) must score higher than glob (%d)", exact, glob)
	}
	if glob <= wildcard {
		t.Errorf("prefix glob (%d) must score higher than bare wildcard (%d)", glob, wildcard)
	}
}

func TestResourceSpecificity_LongerPrefixWins(t *testing.T) {
	t.Parallel()
	longer := enforcement.ResourceSpecificity("read_file_*", "read_file_csv")
	shorter := enforcement.ResourceSpecificity("read_*", "read_file_csv")
	if longer <= shorter {
		t.Errorf("longer prefix glob (%d) must score higher than shorter (%d)", longer, shorter)
	}
}

// TestResourceSpecificity_CountsRunesNotBytes pins that the scorer counts literal
// runes, not UTF-8 bytes: the in-place utf8 cursor must score a multi-byte
// character exactly as it would a single rune, or specificity ties silently
// reorder for non-ASCII targets.
func TestResourceSpecificity_CountsRunesNotBytes(t *testing.T) {
	t.Parallel()
	// "café_*" and the ASCII-equivalent "cafe_*" both have 5 literal runes and must
	// score identically; counting 'é' as 2 bytes would inflate the multi-byte score.
	multibyte := enforcement.ResourceSpecificity("café_*", "café_report")
	ascii := enforcement.ResourceSpecificity("cafe_*", "cafe_report")
	if multibyte != ascii {
		t.Errorf("multi-byte pattern scored %d, ASCII-equivalent scored %d; literal counting must be rune-based, not byte-based", multibyte, ascii)
	}
	// A bracket class with a multi-byte member ("[oô]") is still one wildcard, and
	// decoding the multi-byte rune while scanning to the closing ']' must not crash
	// or miscount the surrounding literals.
	if got := enforcement.ResourceSpecificity("rép[oô]rt", "réport"); got <= 0 {
		t.Errorf("class with a multi-byte member scored %d, want a positive literal-weighted score", got)
	}
	// An escaped multi-byte rune is two literals (the backslash plus the rune) and
	// the escape must consume the whole rune so a following byte is not misparsed.
	if got := enforcement.ResourceSpecificity(`\é_file`, "é_file"); got <= 0 {
		t.Errorf("escaped multi-byte literal scored %d, want a positive score", got)
	}
}

// ── Exported StripEnginePrefix ────────────────────────────────────────────────

// TestStripEnginePrefix pins the recognized-namespace set the engine strips at
// runtime, which manifest validation reuses to reject a
// sequenceBlock afterTools entry whose prefix is not recognized. A recognized
// prefix is removed; a bare name or an unrecognized prefix is returned unchanged
// (the signal validation keys off to flag a fail-open entry).
func TestStripEnginePrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"tool:read_file", "read_file"},
		{"resource:file:///secrets", "file:///secrets"},
		{"prompt:summarize", "summarize"},
		{"system:initialize", "initialize"},
		{"read_file", "read_file"},           // bare name unchanged
		{"mcp:read_file", "mcp:read_file"},   // unrecognized prefix unchanged
		{"Tool:read_file", "Tool:read_file"}, // case mismatch unchanged
		{"tool:", ""},                        // recognized prefix, empty name
	}
	for _, tc := range cases {
		if got := enforcement.StripEnginePrefix(tc.in); got != tc.want {
			t.Errorf("StripEnginePrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── EvaluateConditions avoids double-dispatch ─────────────────────────────────

func TestEvaluateConditions_Allow(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	matched := &capability.Constraint{
		Target:  "read_file",
		Actions: []string{"call"},
		// No conditions → always allow.
	}
	req := &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{},
	}
	resp := e.EvaluateConditions(context.Background(), req, matched)
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("expected Allow, got %v: %+v", resp.Decision, resp.Denial)
	}
}

func TestEvaluateConditions_DenyOnConditionFailure(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	min5 := 5
	matched := &capability.Constraint{
		Target:  "read_file",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			// AllowedValues on "path" argument — will fail because arg is missing.
			&capability.AllowedValuesCondition{
				Argument: "path",
				Values:   []interface{}{"/safe/*"},
			},
		},
	}
	_ = min5
	req := &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{}, // "path" absent → deny
	}
	resp := e.EvaluateConditions(context.Background(), req, matched)
	if resp.Decision != capability.DecisionDeny {
		t.Error("expected Deny when required argument is missing")
	}
}

func TestEvaluateConditions_ReturnsObligations(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	// redactFields is a directive, not a condition. Obligations are
	// collected from Directives after all conditions pass.
	matched := &capability.Constraint{
		Target:  "read_file",
		Actions: []string{"call"},
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"$.result.secret"}},
		},
	}
	req := &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "read_file",
	}
	resp := e.EvaluateConditions(context.Background(), req, matched)
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("expected Allow with obligation, got Deny: %+v", resp.Denial)
	}
	if len(resp.Obligations) != 1 || resp.Obligations[0].Type != "redactFields" {
		t.Errorf("expected one redactFields obligation, got %+v", resp.Obligations)
	}
}

func TestEvaluateConditions_UnknownConditionDenies(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	matched := &capability.Constraint{
		Target:  "tool",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.CustomCondition{Name: "unregistered"},
		},
	}
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "tool"}
	resp := e.EvaluateConditions(context.Background(), req, matched)
	// CustomCondition has no registered handler → deny fail-closed.
	if resp.Decision != capability.DecisionDeny {
		t.Error("unknown condition must deny fail-closed")
	}
}

// ── allowedOperations with explicit argument ──────────────────────────────────
// Argument="" (scan-all-args) is no longer valid; an explicit
// argument field is required, matching allowedExtensions and allowedTables.
// The tests below use Argument:"sql" to exercise the correct path.

func TestHandleAllowedOperations_ExplicitArg_Allow(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "query_db",
		Arguments:  map[string]interface{}{"sql": "SELECT id FROM users"},
	}, []capability.Constraint{{
		Target:  "query_db",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.AllowedOperationsCondition{Argument: "sql", Operations: []string{"SELECT"}},
		},
	}})
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("expected Allow for SELECT, got Deny: %+v", resp.Denial)
	}
}

func TestHandleAllowedOperations_ExplicitArg_Deny_WrongVerb(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "query_db",
		Arguments:  map[string]interface{}{"sql": "DROP TABLE users"},
	}, []capability.Constraint{{
		Target:  "query_db",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.AllowedOperationsCondition{Argument: "sql", Operations: []string{"SELECT"}},
		},
	}})
	if resp.Decision != capability.DecisionDeny {
		t.Error("expected Deny for DROP when only SELECT is allowed")
	}
	// An operation outside the allowlist denies with OPERATION_NOT_PERMITTED,
	// matching the JWT enforcement path's denial_code.
	if resp.Denial.Code != capability.ErrCodeOperationNotPermitted {
		t.Errorf("expected OPERATION_NOT_PERMITTED code, got %q", resp.Denial.Code)
	}
}

func TestHandleAllowedOperations_ExplicitArg_CaseInsensitive(t *testing.T) {
	// Regression: case-insensitive matching must work with explicit arg.
	t.Parallel()
	e := enforcement.New()

	for _, sql := range []string{"SELECT * FROM t", "select id from t"} {
		resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{
			SessionID:  "s",
			TargetName: "db",
			Arguments:  map[string]interface{}{"q": sql},
		}, []capability.Constraint{{
			Target:  "db",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.AllowedOperationsCondition{Argument: "q", Operations: []string{"SELECT"}},
			},
		}})
		if resp.Decision != capability.DecisionAllow {
			t.Errorf("sql=%q: expected Allow, got Deny: %+v", sql, resp.Denial)
		}
	}
}

// ── ValidateAction / FindMatchingCapability with prefixed targets ─────────────

// TestValidateAction_PrefixedTarget_MatchesBareToolName verifies that
// a v0.2 manifest constraint "tool:read_file" must match bare req.TargetName
// "read_file". Before the fix, FindMatchingCapability returned nil for every
// prefixed constraint, making ValidateAction and FindMatchingCapability dead.
func TestValidateAction_PrefixedTarget_MatchesBareToolName(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "read_file", // bare — as ManifestPDP.Decide supplies it
	}, []capability.Constraint{
		{Target: "tool:read_file", Actions: []string{"call"}},
	})
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("regression: prefixed constraint should match bare ToolName; got Deny: %+v", resp.Denial)
	}
}

// TestValidateAction_PrefixedTarget_GlobMatchesBareToolName verifies that glob
// patterns in prefixed constraints work correctly with bare ToolNames.
func TestValidateAction_PrefixedTarget_GlobMatchesBareToolName(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "read_file",
	}, []capability.Constraint{
		{Target: "tool:read_*", Actions: []string{"call"}},
	})
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("regression: prefixed glob should match bare ToolName; got Deny: %+v", resp.Denial)
	}
}

// TestFindMatchingCapability_PrefixedTarget verifies FindMatchingCapability
// returns the correct constraint when given a prefixed constraint and bare name.
func TestFindMatchingCapability_PrefixedTarget(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	caps := []capability.Constraint{
		{Target: "tool:read_file", Actions: []string{"call"}},
		{Target: "tool:write_file", Actions: []string{"call"}},
	}
	req := &capability.EnforceRequest{TargetName: "read_file"}
	matched := e.FindMatchingCapability(req, caps)
	if matched == nil {
		t.Fatal("regression: FindMatchingCapability returned nil for prefixed constraint with bare ToolName")
	}
	if matched.Target != "tool:read_file" {
		t.Errorf("regression: wrong constraint matched: %s", matched.Target)
	}
}

// TestFindMatchingCapability_ColonPrefixedResourceName verifies that a resource
// or prompt whose bare name itself begins with a recognized namespace token (e.g.
// a resource "system:config" or a prompt "tool:reboot") still matches its
// covering constraint. The bare name is derived from req.Target.Name verbatim,
// not via prefix-splitting, so the leading token is not wrongly stripped.
func TestFindMatchingCapability_ColonPrefixedResourceName(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	// Resource whose bare name "system:config" begins with the "system" token.
	t.Run("resource with namespace-token name matches", func(t *testing.T) {
		t.Parallel()
		caps := []capability.Constraint{
			{Target: "resource:system:config", Actions: []string{"read"}},
		}
		req := &capability.EnforceRequest{
			TargetName: "system:config",
			Target:     &capability.EnforceRequestTarget{Type: "resource", Name: "system:config"},
		}
		matched := e.FindMatchingCapability(req, caps)
		if matched == nil {
			t.Fatal("regression: FindMatchingCapability returned nil for resource:system:config")
		}
		if matched.Target != "resource:system:config" {
			t.Errorf("regression: wrong constraint matched: %s", matched.Target)
		}
	})

	// Prompt sibling: bare name "tool:reboot" begins with the "tool" token.
	t.Run("prompt with namespace-token name matches", func(t *testing.T) {
		t.Parallel()
		caps := []capability.Constraint{
			{Target: "prompt:tool:reboot", Actions: []string{"get"}},
		}
		req := &capability.EnforceRequest{
			TargetName: "tool:reboot",
			Target:     &capability.EnforceRequestTarget{Type: "prompt", Name: "tool:reboot"},
		}
		matched := e.FindMatchingCapability(req, caps)
		if matched == nil {
			t.Fatal("regression: FindMatchingCapability returned nil for prompt:tool:reboot")
		}
		if matched.Target != "prompt:tool:reboot" {
			t.Errorf("regression: wrong constraint matched: %s", matched.Target)
		}
	})

	// Non-collapse guard: a request for resource "system:config" must NOT match a
	// DISTINCT constraint "resource:config". Deriving the bare name verbatim keeps
	// the two names distinct rather than collapsing "system:config" to "config".
	t.Run("distinct resource name does not collapse", func(t *testing.T) {
		t.Parallel()
		caps := []capability.Constraint{
			{Target: "resource:config", Actions: []string{"read"}},
		}
		req := &capability.EnforceRequest{
			TargetName: "system:config",
			Target:     &capability.EnforceRequestTarget{Type: "resource", Name: "system:config"},
		}
		if matched := e.FindMatchingCapability(req, caps); matched != nil {
			t.Errorf("regression: system:config wrongly matched resource:config: %s", matched.Target)
		}
	})
}

// TestValidateAction_PrefixedBothSides verifies that callers who pass a prefixed
// ToolName and prefixed constraints (the pre-existing pattern) still work correctly.
func TestValidateAction_PrefixedBothSides(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "tool:read_file", // prefixed ToolName
	}, []capability.Constraint{
		{Target: "tool:read_file", Actions: []string{"call"}}, // prefixed constraint
	})
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("regression: prefixed-both-sides should still work; got Deny: %+v", resp.Denial)
	}
}

// TestHandleAllowedOperations_EmptyArg_RequiresExplicit verifies that omitting
// the argument field is now a condition failure.
func TestHandleAllowedOperations_EmptyArg_RequiresExplicit(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "query_db",
		Arguments:  map[string]interface{}{"sql": "SELECT 1"},
	}, []capability.Constraint{{
		Target:  "query_db",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.AllowedOperationsCondition{Argument: "", Operations: []string{"SELECT"}},
		},
	}})
	if resp.Decision != capability.DecisionDeny {
		t.Error("regression: empty Argument must be denied (explicit argument required)")
	}
	if resp.Denial.Code != capability.ErrCodeConditionFailed {
		t.Errorf("expected CONDITION_FAILED, got %q", resp.Denial.Code)
	}
}

// fakeCondition reports an arbitrary discriminator while NOT being any of the
// concrete condition structs. Dispatching it exercises each handler's "invalid
// <type> condition" branch and the corresponding as*() final `return nil,false`.
type fakeCondition struct{ ct string }

func (f fakeCondition) ConditionType() string { return f.ct }

// runCondition matches a single constraint carrying cond and returns the response.
func runCondition(t *testing.T, e *enforcement.Engine, cond capability.Condition, args map[string]interface{}, sourceIP string) capability.EnforceResponse {
	t.Helper()
	constraints := []capability.Constraint{
		{Target: "tool", Actions: []string{"call"}, Conditions: []capability.Condition{cond}},
	}
	req := &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "tool",
		Arguments:  args,
		Context:    capability.EnforceRequestContext{SourceIP: sourceIP},
	}
	resp := e.ValidateAction(context.Background(), req, constraints)
	return resp
}

// TestHandlers_WrongConcreteType drives every builtin handler with a condition
// whose discriminator is correct but whose concrete type is wrong, hitting the
// "invalid ... condition type" branch and the as*() fall-through.
func TestHandlers_WrongConcreteType(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	types := []string{
		capability.ConditionTypeTimeWindow,
		capability.ConditionTypeIPRange,
		capability.ConditionTypeMaxCalls,
		capability.ConditionTypeAllowedOperations,
		capability.ConditionTypeAllowedExtensions,
		capability.ConditionTypeAllowedTables,
		capability.ConditionTypeRecipientDomain,
		capability.ConditionTypeAllowedValues,
		capability.ConditionTypePolicy,
		capability.ConditionTypeCustom,
	}

	for _, ct := range types {
		t.Run(ct, func(t *testing.T) {
			t.Parallel()
			resp := runCondition(t, enforcement.New(), fakeCondition{ct: ct}, nil, "")
			assert.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Contains(t, resp.Denial.Message, "invalid")
			// castCondition derives ConditionType (and the message) from the concrete
			// type parameter, not a hand-passed constant — pin that it reports the
			// dispatched-to handler's OWN type, matching the constant that routed here.
			assert.Equal(t, ct, resp.Denial.ConditionType)
		})
	}
	_ = e
}

// TestHandlers_ValueTypeConditions passes value-typed (non-pointer) conditions
// so the as*() helpers take their value-assertion branch.
func TestHandlers_ValueTypeConditions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		cond     capability.Condition
		args     map[string]interface{}
		sourceIP string
		decision capability.Decision
	}{
		{
			// A value-type (not pointer) timeWindow with a bound, exercising asTimeWindow's
			// value branch. It must carry at least one bound: a both-empty window now fails
			// closed (see TestEngine_TimeWindow_BothBoundsEmpty).
			name:     "timeWindow value type within window passes",
			cond:     capability.TimeWindowCondition{NotAfter: "2999-01-01T00:00:00Z"},
			decision: capability.DecisionAllow,
		},
		{
			name:     "ipRange match",
			cond:     capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			sourceIP: "10.1.2.3",
			decision: capability.DecisionAllow,
		},
		{
			name:     "allowedOperations match",
			cond:     capability.AllowedOperationsCondition{Argument: "sql", Operations: []string{"SELECT"}},
			args:     map[string]interface{}{"sql": "SELECT * FROM t"},
			decision: capability.DecisionAllow,
		},
		{
			name:     "allowedExtensions match",
			cond:     capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".csv"}},
			args:     map[string]interface{}{"path": "/data/x.csv"},
			decision: capability.DecisionAllow,
		},
		{
			name:     "allowedTables match",
			cond:     capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}},
			args:     map[string]interface{}{"table": "users"},
			decision: capability.DecisionAllow,
		},
		{
			name:     "recipientDomain match",
			cond:     capability.RecipientDomainCondition{Argument: "to", Domains: []string{"corp.example"}},
			args:     map[string]interface{}{"to": "a@corp.example"},
			decision: capability.DecisionAllow,
		},
		{
			name:     "allowedValues match",
			cond:     capability.AllowedValuesCondition{Argument: "x", Values: []interface{}{"ok"}},
			args:     map[string]interface{}{"x": "ok"},
			decision: capability.DecisionAllow,
		},
		{
			name:     "policy without evaluator denies",
			cond:     capability.PolicyCondition{Backend: "opa"},
			decision: capability.DecisionDeny,
		},
		{
			name:     "custom without handler denies",
			cond:     capability.CustomCondition{Name: "thing"},
			decision: capability.DecisionDeny,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := runCondition(t, enforcement.New(), tc.cond, tc.args, tc.sourceIP)
			assert.Equal(t, tc.decision, resp.Decision)
		})
	}
}

// TestMaxCalls_ValueType covers asMaxCalls' value branch (the condition passed by
// value rather than by pointer).
func TestMaxCalls_ValueType(t *testing.T) {
	t.Parallel()
	e := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	constraints := []capability.Constraint{
		{Target: "tool", Actions: []string{"call"}, Conditions: []capability.Condition{
			capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
		}},
	}
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "tool"}
	// First call is within the maxCalls:5 quota → allow, exercising the value branch.
	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// TestMaxCalls_NoCounter covers the "call counter not configured" branch, through the whole
// decision rather than the shared bucket helper: the class is what decides whether an observing
// posture forwards, and its blastRadius twin lives in velocity_test.go.
func TestMaxCalls_NoCounter(t *testing.T) {
	t.Parallel()
	resp := runCondition(t, enforcement.New(), &capability.MaxCallsCondition{Count: 1, WindowSeconds: 60}, nil, "")
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Contains(t, resp.Denial.Message, "call counter not configured")
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.False(t, resp.Denial.Downgradable(),
		"the budget was never evaluated, so no observing posture may forward past it")
}

// TestIPRange_ErrorBranches exercises missing IP, malformed IP, malformed CIDR,
// and out-of-range outcomes.
func TestIPRange_ErrorBranches(t *testing.T) {
	t.Parallel()

	t.Run("missing sourceIp", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}}, nil, "")
		assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	})

	t.Run("malformed sourceIp", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}}, nil, "not-an-ip")
		assert.Contains(t, resp.Denial.Message, "invalid source IP")
	})

	t.Run("malformed cidr", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.IPRangeCondition{CIDRs: []string{"bad-cidr"}}, nil, "10.1.2.3")
		assert.Contains(t, resp.Denial.Message, "invalid CIDR")
	})

	t.Run("out of range", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.IPRangeCondition{CIDRs: []string{"192.168.0.0/16"}}, nil, "10.1.2.3")
		assert.Contains(t, resp.Denial.Message, "not in allowed ranges")
	})
}

// TestIPRange_CompiledPath exercises the pre-compiled hot path: a
// condition whose CIDRs were compiled at load time (as the manifest loader does)
// is matched against the cached *net.IPNet values, not re-parsed per request.
// In-range allows and out-of-range denies, identical to the uncompiled fallback.
func TestIPRange_CompiledPath(t *testing.T) {
	t.Parallel()

	t.Run("in range allowed", func(t *testing.T) {
		t.Parallel()
		cond := &capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}}
		require.NoError(t, cond.Compile())
		if _, ok := cond.Networks(); !ok {
			t.Fatal("precondition: condition should report compiled networks")
		}
		resp := runCondition(t, enforcement.New(), cond, nil, "10.1.2.3")
		assert.Equal(t, capability.DecisionAllow, resp.Decision)
	})

	t.Run("out of range denied", func(t *testing.T) {
		t.Parallel()
		cond := &capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}}
		require.NoError(t, cond.Compile())
		resp := runCondition(t, enforcement.New(), cond, nil, "192.168.1.1")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Contains(t, resp.Denial.Message, "not in allowed ranges")
	})
}

// TestIPRange_FallbackDeniesOnMalformedCIDR pins that the uncompiled fallback
// evaluates a malformed CIDR the SAME way the compiled path does: the condition as a
// whole is malformed, so the call is denied — even when an earlier CIDR in the list
// contains the source IP.
//
// The fallback used to interleave parse-and-match, so a match reached before the bad
// entry allowed the call. That was a second CIDR parser with its own semantics, and
// it diverged from Compile in the fail-open direction: the manifest loader rejects
// this list outright (Compile returns the first parse error), so a policy the
// compiled path refuses to load was being partially honored by the hand-built path.
// The fallback now compiles a local copy and reads it through the same accessor, so
// there is one parser and one answer. Only a hand-built (uncompiled) condition can
// reach this at all, since the loader rejects malformed CIDRs up front.
func TestIPRange_FallbackDeniesOnMalformedCIDR(t *testing.T) {
	t.Parallel()
	cond := &capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8", "bad-cidr"}}
	if _, ok := cond.Networks(); ok {
		t.Fatal("precondition: condition must be uncompiled to exercise the fallback")
	}
	resp := runCondition(t, enforcement.New(), cond, nil, "10.1.2.3")
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Contains(t, resp.Denial.Message, "invalid CIDR in condition")

	// A well-formed list still matches through the fallback, so the fix tightened only
	// the malformed case rather than breaking uncompiled matching outright.
	ok := &capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}}
	assert.Equal(t, capability.DecisionAllow, runCondition(t, enforcement.New(), ok, nil, "10.1.2.3").Decision)
}

// TestTimeWindow_InvalidTimes covers the RFC3339 parse-error branches.
func TestTimeWindow_InvalidTimes(t *testing.T) {
	t.Parallel()

	t.Run("invalid notBefore", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.TimeWindowCondition{NotBefore: "nonsense"}, nil, "")
		assert.Contains(t, resp.Denial.Message, "invalid notBefore")
	})

	t.Run("invalid notAfter", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.TimeWindowCondition{NotAfter: "nonsense"}, nil, "")
		assert.Contains(t, resp.Denial.Message, "invalid notAfter")
	})
}

// TestAllowedExtensions_ErrorBranches covers empty-argument, missing-value,
// no-extension, and not-allowed outcomes.
func TestAllowedExtensions_ErrorBranches(t *testing.T) {
	t.Parallel()

	t.Run("empty argument field", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedExtensionsCondition{Extensions: []string{".csv"}}, nil, "")
		assert.Contains(t, resp.Denial.Message, "explicit 'argument'")
	})

	t.Run("missing value", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".csv"}}, map[string]interface{}{}, "")
		assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	})

	t.Run("no extension", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".csv"}}, map[string]interface{}{"path": "/data/noext"}, "")
		assert.Contains(t, resp.Denial.Message, "no extension")
	})

	t.Run("not allowed", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".csv"}}, map[string]interface{}{"path": "/data/x.exe"}, "")
		assert.Contains(t, resp.Denial.Message, "not allowed")
	})
}

// TestAllowedExtensions_Dotfiles is a regression guard. Go's
// filepath.Ext scans back to the final dot, so for a dotfile (leading dot, no
// further dot) it returns the whole name — filepath.Ext(".env") == ".env", not
// "" as Node.js's path.extname would. Dotfiles therefore flow through the normal
// allowlist check and are matched/denied like any other extension; they are
// never misclassified as "file has no extension". These cases lock that in so a
// future refactor of the extension-extraction logic can't silently regress it.
func TestAllowedExtensions_Dotfiles(t *testing.T) {
	t.Parallel()

	allow := []struct {
		name string
		path string
		exts []string
	}{
		{"dotfile matches dotted entry", "/app/.env", []string{".env"}},
		{"dotfile matches bare entry", "/app/.env", []string{"env"}},
		{"dotfile bare path", ".env", []string{".env"}},
		{"gitignore", "/repo/.gitignore", []string{".gitignore"}},
		{"bashrc", "/home/u/.bashrc", []string{".bashrc"}},
		{"dotfile among regular entries", "/app/.env", []string{".csv", ".env", ".json"}},
		{"multi-dot dotfile matches final segment", "/app/.env.local", []string{".local"}},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			t.Parallel()
			resp := runCondition(t, enforcement.New(), &capability.AllowedExtensionsCondition{Argument: "path", Extensions: tc.exts}, map[string]interface{}{"path": tc.path}, "")
			assert.Equal(t, capability.DecisionAllow, resp.Decision)
		})
	}

	// A dotfile not in the allowlist is denied as a normal extension mismatch —
	// "not allowed", carrying the actual extension — never "file has no extension".
	t.Run("deny/dotfile not in allowlist", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".txt"}}, map[string]interface{}{"path": "/app/.env"}, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Contains(t, resp.Denial.Message, "not allowed")
		assert.NotContains(t, resp.Denial.Message, "no extension")
	})
}

// TestAllowedExtensions_ArrayArgument covers the multi-path form used by tools
// like read_multiple_files: the argument is an array of paths and every path
// must pass the extension allowlist or the call is denied (fail closed).
func TestAllowedExtensions_ArrayArgument(t *testing.T) {
	t.Parallel()

	cond := &capability.AllowedExtensionsCondition{Argument: "paths", Extensions: []string{".csv", ".json"}}

	t.Run("all paths allowed", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"paths": []interface{}{"/data/a.csv", "/data/b.json"}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionAllow, resp.Decision)
	})

	t.Run("one disallowed extension denies", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"paths": []interface{}{"/data/a.csv", "/data/secret.env"}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Contains(t, resp.Denial.Message, "not allowed")
	})

	t.Run("one path with no extension denies", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"paths": []interface{}{"/data/a.csv", "/data/id_rsa"}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Contains(t, resp.Denial.Message, "no extension")
	})

	t.Run("empty array is missing context", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"paths": []interface{}{}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
	})

	t.Run("array with a non-string item fails closed", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"paths": []interface{}{"/data/a.csv", 42, nil}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "non-string item")
	})

	t.Run("array entirely of non-strings fails closed", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"paths": []interface{}{1, 2}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "non-string item")
	})
}

// TestAllowedExtensions_CompoundExtensions is the regression guard. Matching is
// suffix-based on the file name, so a compound allowlist entry
// like ".tar.gz" is honored in full: it admits "backup.tar.gz" (previously a
// false deny, because filepath.Ext returned only ".gz" and never matched the
// ".tar.gz" entry) and rejects a bare "data.gz" (previously a silent scope
// change, because ".tar.gz" degraded to ".gz"). Single-component entries keep
// their existing final-segment behavior.
func TestAllowedExtensions_CompoundExtensions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		path  string
		exts  []string
		allow bool
	}{
		// The core fix: a compound entry matches its compound file.
		{"compound entry matches compound file", "/data/backup.tar.gz", []string{".tar.gz"}, true},
		{"compound among other entries", "/data/archive.tar.gz", []string{".csv", ".tar.gz"}, true},
		// The compound entry no longer silently widens to its last segment.
		{"compound entry rejects bare last segment", "/data/data.gz", []string{".tar.gz"}, false},
		{"compound entry rejects different middle", "/data/backup.zip.gz", []string{".tar.gz"}, false},
		{"compound entry rejects different last", "/data/backup.tar.bz2", []string{".tar.gz"}, false},
		// Entries normalize: leading dot optional, case-insensitive.
		{"compound entry without leading dot", "/data/x.tar.gz", []string{"tar.gz"}, true},
		{"compound entry mixed case", "/data/X.TAR.GZ", []string{".tar.gz"}, true},
		{"compound entry uppercase allowlist", "/data/x.tar.gz", []string{".TAR.GZ"}, true},
		// Suffix semantics: a single-component entry admits any file ending in it,
		// including double extensions. Documented in the manifest guide.
		{"single entry admits double extension", "/data/payload.exe.gz", []string{".gz"}, true},
		{"single entry admits dotted name", "/data/data.backup.csv", []string{".csv"}, true},
		// The leading dot is a hard segment boundary, so ".gz" never matches a
		// run-on suffix like ".tgz".
		{"dot boundary blocks run-on suffix", "/data/x.tgz", []string{".gz"}, false},
		// Blank allowlist entries are skipped, not treated as a wildcard.
		{"blank entries skipped, compound still honored", "/data/x.tar.gz", []string{"", ".tar.gz"}, true},
		{"only blank entries denies fail-closed", "/data/x.tar.gz", []string{"", " "}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cond := &capability.AllowedExtensionsCondition{Argument: "path", Extensions: tc.exts}
			resp := runCondition(t, enforcement.New(), cond, map[string]interface{}{"path": tc.path}, "")
			if tc.allow {
				assert.Equal(t, capability.DecisionAllow, resp.Decision)
			} else {
				assert.Equal(t, capability.DecisionDeny, resp.Decision)
				assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
				assert.Contains(t, resp.Denial.Message, "not allowed")
			}
		})
	}

	// The array form holds every path to the compound allowlist: one bare ".gz"
	// among ".tar.gz" files denies the whole call (fail closed).
	t.Run("array form, one bare last-segment denies", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedExtensionsCondition{Argument: "paths", Extensions: []string{".tar.gz"}}
		args := map[string]interface{}{"paths": []interface{}{"/data/a.tar.gz", "/data/b.gz"}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Contains(t, resp.Denial.Message, "not allowed")
	})

	// A compound-allowlist denial names the file's full dotted suffix, not just
	// its final segment, so the message and audit detail are actionable.
	t.Run("compound deny reports full suffix", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".tar.gz"}}
		resp := runCondition(t, enforcement.New(), cond, map[string]interface{}{"path": "/data/backup.zip.gz"}, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Contains(t, resp.Denial.Message, ".zip.gz")
		assert.Equal(t, ".zip.gz", resp.Denial.Details["extension"])
	})

	// Duplicate and overlapping entries normalize to the same set and behave
	// identically to a de-duplicated allowlist.
	t.Run("duplicate entries are collapsed", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".gz", ".gz", "gz", ".GZ"}}
		resp := runCondition(t, enforcement.New(), cond, map[string]interface{}{"path": "/data/x.gz"}, "")
		assert.Equal(t, capability.DecisionAllow, resp.Decision)
	})
}

// TestAllowedTables_ColumnsAndShapes covers parseTableArgument map handling and
// the column-restriction branches.
func TestAllowedTables_ColumnsAndShapes(t *testing.T) {
	t.Parallel()

	t.Run("empty argument field", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedTablesCondition{Tables: []string{"users"}}, nil, "")
		assert.Contains(t, resp.Denial.Message, "explicit 'argument'")
	})

	t.Run("table not allowed", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}}, map[string]interface{}{"table": "secrets"}, "")
		assert.Contains(t, resp.Denial.Message, "not allowed")
	})

	t.Run("column required but absent", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{
			Argument: "table",
			Tables:   []string{"users"},
			Columns:  map[string][]string{"users": {"id", "name"}},
		}
		// map shape with no columns → column list required.
		args := map[string]interface{}{"table": map[string]interface{}{"table": "users"}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Contains(t, resp.Denial.Message, "column list required")
	})

	t.Run("column not allowed", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{
			Argument: "table",
			Tables:   []string{"users"},
			Columns:  map[string][]string{"users": {"id"}},
		}
		args := map[string]interface{}{"table": map[string]interface{}{"table": "users", "columns": []interface{}{"ssn"}}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Contains(t, resp.Denial.Message, "is not allowed")
	})

	t.Run("columns allowed passes", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{
			Argument: "table",
			Tables:   []string{"users"},
			Columns:  map[string][]string{"users": {"id", "name"}},
		}
		args := map[string]interface{}{"table": []interface{}{
			map[string]interface{}{"table": "users", "columns": []interface{}{"id", "name"}},
		}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionAllow, resp.Decision)
	})

	t.Run("array with a non-string table item fails closed", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}}
		args := map[string]interface{}{"table": []interface{}{"users", 42, nil}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "neither a table name nor a table object")
	})

	t.Run("non-string column fails closed", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{
			Argument: "table",
			Tables:   []string{"users"},
			Columns:  map[string][]string{"users": {"id", "name"}},
		}
		args := map[string]interface{}{"table": map[string]interface{}{"table": "users", "columns": []interface{}{"id", 7}}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "non-string item")
	})

	// Regression: a map argument that is present and populated but
	// lacks the "table" key is structurally malformed, not "missing or empty".
	// It must deny with CONDITION_FAILED and a message describing the real
	// problem, not the misleading MISSING_CONTEXT "argument is missing or empty".
	t.Run("map missing table key fails closed with accurate error", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}}
		args := map[string]interface{}{"table": map[string]interface{}{"columns": []interface{}{"id", "name"}}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "no non-empty 'table' entry")
		assert.NotContains(t, resp.Denial.Message, "missing or empty")
	})

	t.Run("empty map fails closed with accurate error", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}}
		args := map[string]interface{}{"table": map[string]interface{}{}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "no non-empty 'table' entry")
	})

	t.Run("array item missing table key fails closed", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}}
		args := map[string]interface{}{"table": []interface{}{
			map[string]interface{}{"table": "users"},
			map[string]interface{}{"columns": []interface{}{"id"}},
		}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		// The array branch wraps the element error so the array context is not lost.
		assert.Contains(t, resp.Denial.Message, "array element")
		assert.Contains(t, resp.Denial.Message, "no non-empty 'table' entry")
	})

	// Regression: a library caller may pass a native []string for the
	// table-name argument (rather than a JSON-decoded []interface{}). The outer
	// type switch must handle it like the []interface{} arm rather than falling to
	// default and denying with a misleading "got []string" type error.
	t.Run("native []string argument allowed", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users", "orders"}}
		args := map[string]interface{}{"table": []string{"users", "orders"}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionAllow, resp.Decision)
	})

	t.Run("native []string with a disallowed table denies on the merits", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}}
		args := map[string]interface{}{"table": []string{"users", "secrets"}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		// A real allowlist denial, not the "got []string" type-mismatch error.
		assert.Contains(t, resp.Denial.Message, "not allowed")
		assert.NotContains(t, resp.Denial.Message, "[]string")
	})

	t.Run("native []string with a blank element fails closed", func(t *testing.T) {
		t.Parallel()
		cond := &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}}
		args := map[string]interface{}{"table": []string{"users", "  "}}
		resp := runCondition(t, enforcement.New(), cond, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "empty or blank table name")
	})
}

// TestAllowedTables_CaseInsensitive verifies that table and column names are
// matched case-insensitively, consistent with allowedExtensions,
// allowedOperations, and recipientDomain.
//
// Two distinct case-sensitivity bugs are covered:
//   - The table/column comparisons themselves were exact byte matches, so a
//     manifest written in one case falsely denied an argument in another, and a
//     column ACL written as "password_hash" was bypassed by "Password_Hash".
//   - The per-table column-restriction map lookup (at.Columns[access.Table]) was
//     also case-sensitive: a restriction keyed "users" was not found for an
//     argument table "USERS", which silently skipped the column ACL entirely —
//     the more dangerous, second-order bypass.
func TestAllowedTables_CaseInsensitive(t *testing.T) {
	t.Parallel()

	tableCol := func(table string, cols ...interface{}) map[string]interface{} {
		m := map[string]interface{}{"table": table}
		if cols != nil {
			m["columns"] = cols
		}
		return m
	}

	tests := []struct {
		name         string
		cond         *capability.AllowedTablesCondition
		args         map[string]interface{}
		wantDecision capability.Decision
		wantCode     string // checked only when wantDecision is Deny
		msgContains  string
	}{
		{
			name:         "lowercase manifest matches uppercase argument",
			cond:         &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}},
			args:         map[string]interface{}{"table": "USERS"},
			wantDecision: capability.DecisionAllow,
		},
		{
			name:         "uppercase manifest matches lowercase argument",
			cond:         &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"USERS"}},
			args:         map[string]interface{}{"table": "users"},
			wantDecision: capability.DecisionAllow,
		},
		{
			name:         "mixed-case manifest and argument still match",
			cond:         &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"Users"}},
			args:         map[string]interface{}{"table": "uSeRs"},
			wantDecision: capability.DecisionAllow,
		},
		{
			name: "column allowlist matches in opposite case",
			cond: &capability.AllowedTablesCondition{
				Argument: "table",
				Tables:   []string{"users"},
				Columns:  map[string][]string{"users": {"Name", "Email"}},
			},
			args:         map[string]interface{}{"table": tableCol("users", "name", "email")},
			wantDecision: capability.DecisionAllow,
		},
		{
			name: "mixed-case column-map key matches case-mismatched argument table",
			cond: &capability.AllowedTablesCondition{
				Argument: "table",
				Tables:   []string{"Users"},
				Columns:  map[string][]string{"Users": {"name"}},
			},
			args:         map[string]interface{}{"table": tableCol("users", "NAME")},
			wantDecision: capability.DecisionAllow,
		},
		{
			// The load-bearing security case: a disallowed column must still be
			// denied when the argument table differs in case from the manifest
			// key. Before the fix the at.Columns["users"] lookup missed on
			// "USERS", skipping the column ACL and allowing password_hash through.
			name: "disallowed column denied despite table-name case mismatch",
			cond: &capability.AllowedTablesCondition{
				Argument: "table",
				Tables:   []string{"users"},
				Columns:  map[string][]string{"users": {"name", "email"}},
			},
			args:         map[string]interface{}{"table": tableCol("USERS", "Password_Hash")},
			wantDecision: capability.DecisionDeny,
			wantCode:     capability.ErrCodeConditionFailed,
			msgContains:  "is not allowed",
		},
		{
			// Same bypass class for the column name itself: an upper-cased
			// disallowed column must not slip past a lower-cased allowlist.
			name: "disallowed column denied regardless of column case",
			cond: &capability.AllowedTablesCondition{
				Argument: "table",
				Tables:   []string{"users"},
				Columns:  map[string][]string{"users": {"name"}},
			},
			args:         map[string]interface{}{"table": tableCol("Users", "PASSWORD_HASH")},
			wantDecision: capability.DecisionDeny,
			wantCode:     capability.ErrCodeConditionFailed,
			msgContains:  "is not allowed",
		},
		{
			// The "column list required" guard must still fire when the argument
			// table case-differs from the manifest key, proving the column ACL is
			// located (not skipped) before the empty-columns check.
			name: "empty columns still required under table-name case mismatch",
			cond: &capability.AllowedTablesCondition{
				Argument: "table",
				Tables:   []string{"users"},
				Columns:  map[string][]string{"users": {"name"}},
			},
			args:         map[string]interface{}{"table": tableCol("USERS")},
			wantDecision: capability.DecisionDeny,
			wantCode:     capability.ErrCodeMissingContext,
			msgContains:  "column list required",
		},
		{
			name:         "genuinely disallowed table still denied regardless of case",
			cond:         &capability.AllowedTablesCondition{Argument: "table", Tables: []string{"users"}},
			args:         map[string]interface{}{"table": "SECRETS"},
			wantDecision: capability.DecisionDeny,
			wantCode:     capability.ErrCodeConditionFailed,
			msgContains:  "is not allowed",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := runCondition(t, enforcement.New(), tc.cond, tc.args, "")
			assert.Equal(t, tc.wantDecision, resp.Decision)
			if tc.wantDecision == capability.DecisionDeny {
				require.NotNil(t, resp.Denial)
				assert.Equal(t, capability.ConditionTypeAllowedTables, resp.Denial.ConditionType)
				if tc.wantCode != "" {
					assert.Equal(t, tc.wantCode, resp.Denial.Code)
				}
				if tc.msgContains != "" {
					assert.Contains(t, resp.Denial.Message, tc.msgContains)
				}
			}
		})
	}
}

// TestRecipientDomain_ErrorBranches covers empty-argument, list handling, the
// invalid-email branch, and a disallowed domain.
func TestRecipientDomain_ErrorBranches(t *testing.T) {
	t.Parallel()

	t.Run("empty argument field", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.RecipientDomainCondition{Domains: []string{"corp.example"}}, nil, "")
		assert.Contains(t, resp.Denial.Message, "explicit 'argument'")
	})

	t.Run("invalid email", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.RecipientDomainCondition{Argument: "to", Domains: []string{"corp.example"}}, map[string]interface{}{"to": "no-at-sign"}, "")
		assert.Contains(t, resp.Denial.Message, "invalid recipient email")
	})

	// Malformed recipients with an empty local part, empty domain, or internal
	// whitespace around the "@" must be rejected as invalid emails, not surfaced
	// as domain-restriction denials. "corp.example" is allowed, so a
	// domain-restriction denial would only fire on a non-empty, disallowed
	// domain; these inputs must not reach that branch — in particular the
	// whitespace cases would otherwise leave a leading space on the parsed
	// domain (" corp.example") and read as "domain not allowed". See.
	// "user@@corp.example" is the case: a non-empty local part before a
	// second, embedded "@". SplitN yields domain "@corp.example", which a bare
	// allowlist never lists, so before the fix it denied with the misleading
	// "domain not allowed" rather than "invalid recipient email".
	for _, recipient := range []string{
		"user@", "@corp.example", "@@corp.example", "user@@corp.example",
		"user@corp@example", "user@ corp.example", "user @corp.example", "us er@corp.example",
	} {
		recipient := recipient
		t.Run("malformed email "+recipient, func(t *testing.T) {
			t.Parallel()
			resp := runCondition(t, enforcement.New(), &capability.RecipientDomainCondition{Argument: "to", Domains: []string{"corp.example"}}, map[string]interface{}{"to": recipient}, "")
			assert.Equal(t, capability.DecisionDeny, resp.Decision)
			assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
			assert.Contains(t, resp.Denial.Message, "invalid recipient email")
			assert.NotContains(t, resp.Denial.Message, "not allowed")
		})
	}

	t.Run("disallowed domain in list", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"to": []interface{}{"a@corp.example", "b@evil.com"}}
		resp := runCondition(t, enforcement.New(), &capability.RecipientDomainCondition{Argument: "to", Domains: []string{"corp.example"}}, args, "")
		assert.Contains(t, resp.Denial.Message, "not allowed")
	})

	t.Run("array with a non-string item fails closed", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"to": []interface{}{"a@corp.example", 42, nil}}
		resp := runCondition(t, enforcement.New(), &capability.RecipientDomainCondition{Argument: "to", Domains: []string{"corp.example"}}, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "non-string item")
	})

	t.Run("array entirely of non-strings fails closed", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"to": []interface{}{42, nil}}
		resp := runCondition(t, enforcement.New(), &capability.RecipientDomainCondition{Argument: "to", Domains: []string{"corp.example"}}, args, "")
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "non-string item")
	})
}

// TestAllowedValues_EmptyArgument covers the empty-argument-name guard.
func TestAllowedValues_EmptyArgument(t *testing.T) {
	t.Parallel()
	resp := runCondition(t, enforcement.New(), &capability.AllowedValuesCondition{Values: []interface{}{"x"}}, nil, "")
	assert.Contains(t, resp.Denial.Message, "empty argument name")
}

// TestAllowedOperations_ExplicitArg covers the explicit-argument path,
// including the allow and deny outcomes (scan-all-args removed).
func TestAllowedOperations_ExplicitArg(t *testing.T) {
	t.Parallel()

	t.Run("allow with explicit arg", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedOperationsCondition{Argument: "q", Operations: []string{"SELECT"}}, map[string]interface{}{"q": "select 1"}, "")
		assert.Equal(t, capability.DecisionAllow, resp.Decision)
	})

	t.Run("deny wrong verb", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedOperationsCondition{Argument: "q", Operations: []string{"SELECT"}}, map[string]interface{}{"q": "drop table t"}, "")
		// A disallowed operation denies with OPERATION_NOT_PERMITTED.
		assert.Equal(t, capability.ErrCodeOperationNotPermitted, resp.Denial.Code)
	})

	t.Run("empty argument field requires explicit", func(t *testing.T) {
		t.Parallel()
		resp := runCondition(t, enforcement.New(), &capability.AllowedOperationsCondition{Operations: []string{"SELECT"}}, map[string]interface{}{"q": "select 1"}, "")
		assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "explicit 'argument'")
	})
}

// TestSchemaValidate_DirectBranches exercises validator branches not reached by
// the existing argument_schema_test table: maxLength, maxItems, item-level
// errors, invalid pattern compilation, and nested objects.
func TestSchemaValidate_DirectBranches(t *testing.T) {
	t.Parallel()

	maxLen := 3
	cases := []struct {
		name    string
		args    map[string]interface{}
		schema  *capability.ArgumentSchema
		wantErr bool
		frag    string
	}{
		{
			name: "maxLength violation",
			args: map[string]interface{}{"q": "toolong"},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{"q": {MaxLength: &maxLen}},
			},
			wantErr: true,
			frag:    "maxLength",
		},
		{
			name: "maxItems violation",
			args: map[string]interface{}{"ids": []interface{}{"a", "b", "c", "d"}},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{"ids": {MaxItems: intPtrC(2)}},
			},
			wantErr: true,
			frag:    "maxItems",
		},
		{
			name: "array item violation",
			args: map[string]interface{}{"ids": []interface{}{"ab"}},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"ids": {Items: &capability.ArgumentSchema{MinLength: intPtrC(5)}},
				},
			},
			wantErr: true,
			frag:    "minLength",
		},
		{
			name: "array items pass",
			args: map[string]interface{}{"ids": []interface{}{"hello", "world"}},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"ids": {Items: &capability.ArgumentSchema{MinLength: intPtrC(3)}},
				},
			},
		},
		{
			name: "invalid pattern regex",
			args: map[string]interface{}{"q": "x"},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{"q": {Pattern: "[unclosed"}},
			},
			wantErr: true,
			frag:    "invalid pattern",
		},
		{
			name: "nested object required missing",
			args: map[string]interface{}{"outer": map[string]interface{}{}},
			schema: &capability.ArgumentSchema{
				Properties: map[string]*capability.ArgumentSchema{
					"outer": {Required: []string{"inner"}},
				},
			},
			wantErr: true,
			frag:    "inner",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := enforcement.ValidateArgumentSchema(tc.args, tc.schema)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.frag)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestEngine_MatchingEdgeCases covers actionPermitted (empty + unrecognized)
// and ResourceSpecificity / FindMatchingCapability tie-breaking.
func TestEngine_MatchingEdgeCases(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	t.Run("empty actions fails closed", func(t *testing.T) {
		t.Parallel()
		constraints := []capability.Constraint{{Target: "tool", Actions: nil}}
		req := &capability.EnforceRequest{TargetName: "tool"}
		resp := e.ValidateAction(context.Background(), req, constraints)
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
	})

	t.Run("unrecognized action skips constraint", func(t *testing.T) {
		t.Parallel()
		constraints := []capability.Constraint{{Target: "tool", Actions: []string{"read"}}}
		req := &capability.EnforceRequest{TargetName: "tool"}
		resp := e.ValidateAction(context.Background(), req, constraints)
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
	})

	t.Run("more specific resource wins", func(t *testing.T) {
		t.Parallel()
		// A wildcard and an exact match both match; exact must win.
		constraints := []capability.Constraint{
			{Target: "*", Actions: []string{"call"}, Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: "x", Values: []interface{}{"never"}},
			}},
			{Target: "tool", Actions: []string{"call"}},
		}
		req := &capability.EnforceRequest{TargetName: "tool", Arguments: map[string]interface{}{"x": "other"}}
		resp := e.ValidateAction(context.Background(), req, constraints)
		assert.Equal(t, capability.DecisionAllow, resp.Decision, "exact target should win over wildcard")
	})

	t.Run("principal beats general at equal specificity regardless of order", func(t *testing.T) {
		t.Parallel()
		// A general constraint is listed FIRST with a condition the request fails,
		// and a principal-scoped constraint is listed SECOND with no conditions.
		// The principal-scoped entry must win despite being declared later, so the
		// request is allowed.
		constraints := []capability.Constraint{
			{Target: "query_db", Actions: []string{"call"}, Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: "x", Values: []interface{}{"never"}},
			}},
			{Target: "query_db", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"alice"}}},
		}
		req := &capability.EnforceRequest{
			TargetName: "query_db",
			Arguments:  map[string]interface{}{"x": "other"},
			Claims:     map[string]interface{}{"sub": "alice"},
		}
		resp := e.ValidateAction(context.Background(), req, constraints)
		assert.Equal(t, capability.DecisionAllow, resp.Decision,
			"a principal-scoped constraint must beat a general one even when declared later")
	})

	t.Run("two equal-specificity principal constraints resolve first-wins", func(t *testing.T) {
		t.Parallel()
		// Two constraints with identical target and identical principal tie on
		// specificity. The FIRST declared wins: the first carries a
		// condition the request fails, so the request is denied — proving the second
		// (condition-free, would-allow) constraint does not displace the first.
		constraints := []capability.Constraint{
			{Target: "query_db", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"alice"}}, Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: "x", Values: []interface{}{"never"}},
			}},
			{Target: "query_db", Actions: []string{"call"}, Principal: map[string][]string{"sub": {"alice"}}},
		}
		req := &capability.EnforceRequest{
			TargetName: "query_db",
			Arguments:  map[string]interface{}{"x": "other"},
			Claims:     map[string]interface{}{"sub": "alice"},
		}
		resp := e.ValidateAction(context.Background(), req, constraints)
		assert.Equal(t, capability.DecisionDeny, resp.Decision,
			"the first declared of two equal-specificity principal constraints must win")
	})

	t.Run("specificity scoring", func(t *testing.T) {
		t.Parallel()
		// Exact == toolName => the dominating exact-match sentinel.
		assert.Equal(t, 1<<27, enforcement.ResourceSpecificity("tool", "tool"))
		// No wildcard, not equal: the general formula applies (prefixLen*10 -
		// wildcardCount = 5*10 - 0). MatchesResource filters non-matching
		// literals before FindMatchingCapability ever scores them, so this value
		// is unreachable in ranking; the assertion just pins the formula.
		assert.Equal(t, 5*10, enforcement.ResourceSpecificity("other", "tool"))
		// Has wildcard => prefixLen*10 - wildcardCount.
		assert.Equal(t, 4*10-1, enforcement.ResourceSpecificity("file*", "fileabc"))
	})
}

// TestFindMatchingCapability_NonWildcardLiteralFilteredBeforeScoring guards the
// invariant: ResourceSpecificity no longer has a "literal but
// not equal to the tool name" branch, because such a target can never reach
// scoring. MatchesResource only admits an exact match or a glob, so a
// non-wildcard target that differs from the tool name is dropped by
// FindMatchingCapability before ResourceSpecificity is called. If a future
// change let such a literal through, this constraint would be selected and the
// assertion below would fail.
func TestFindMatchingCapability_NonWildcardLiteralFilteredBeforeScoring(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	constraints := []capability.Constraint{
		{Target: "read_file", Actions: []string{"call"}},
	}
	req := &capability.EnforceRequest{TargetName: "write_file"}
	assert.Nil(t, e.FindMatchingCapability(req, constraints),
		"a non-wildcard target that differs from the tool name must not match, "+
			"so ResourceSpecificity is never reached for it")
}

// TestResourceSpecificity_BackslashEscapedLiteralReachesScoring documents the
// one way a non-wildcard resource that differs from the tool name still reaches
// ResourceSpecificity: path.Match honors backslash escapes, so a target like
// `a\b` matches tool name "ab" yet is not string-equal to it. The removed
// score-900 branch was reachable only for this degenerate input (no manifest
// writes it). It now scores by the general prefixLen*10 formula and still
// outranks any glob that matches the same name, so dropping the branch never
// flips a ranking decision.
func TestResourceSpecificity_BackslashEscapedLiteralReachesScoring(t *testing.T) {
	t.Parallel()
	// The escaped literal matches a string it is not equal to, so it reaches
	// scoring without hitting the exact-match (1000) branch.
	require.True(t, enforcement.MatchesResource(`a\b`, "ab"))
	require.NotEqual(t, `a\b`, "ab")

	// `a\b` matches the 2-character input "ab": the backslash is a control char that
	// makes 'b' literal, not a matchable rune, so literalCount is 2, not 3.
	escaped := enforcement.ResourceSpecificity(`a\b`, "ab") // 2 literal chars, no wildcard => 20
	assert.Equal(t, 2*10, escaped)

	// It still outscores any glob that also matches "ab", so removing the
	// score-900 branch cannot reorder a real ranking.
	for _, glob := range []string{"*", "a?", "ab*", "a*"} {
		require.True(t, enforcement.MatchesResource(glob, "ab"), "precondition: %q matches ab", glob)
		assert.Greater(t, escaped, enforcement.ResourceSpecificity(glob, "ab"),
			"escaped literal `a\\b` must outscore glob %q matching the same name", glob)
	}
}

// TestResourceSpecificity_BackslashEscapedBracket pins the fix:
// a backslash-escaped '[' is a literal, not the opening of a character class.
// Before the fix, ResourceSpecificity fell into the '[' arm for the escaped
// bracket, inflating wildcardCount and consuming following runes as class
// internals, which let a broad "file*" glob tie (or beat) an exact escaped match.
func TestResourceSpecificity_BackslashEscapedBracket(t *testing.T) {
	t.Parallel()
	// Precondition: path.Match treats `file\[1]` as the literal string "file[1]".
	require.True(t, enforcement.MatchesResource(`file\[1]`, "file[1]"))
	require.True(t, enforcement.MatchesResource("file*", "file[1]"))

	// `file\[1]` matches the 7-character input "file[1]" (f,i,l,e,[,1,]). The
	// backslash is a control char, not a matchable rune, so literalCount is 7: the
	// escaped '[' counts once as the literal it matches, not as backslash+bracket.
	escaped := enforcement.ResourceSpecificity(`file\[1]`, "file[1]")
	assert.Equal(t, 7*10, escaped)

	// The escaped exact match must strictly outrank the broad glob so the stricter
	// policy wins regardless of manifest order.
	glob := enforcement.ResourceSpecificity("file*", "file[1]")
	assert.Greater(t, escaped, glob,
		"escaped-bracket exact match must outrank the broad file* glob")
}

// TestEngine_PolicyEvaluator covers handlePolicy's happy path through a wired
// evaluator and asPolicy's pointer branch.
func TestEngine_PolicyEvaluator(t *testing.T) {
	t.Parallel()

	allowEval := policyEvalFunc(func(_ context.Context, _ string, _, _ interface{}, _ *capability.EnforceRequest) *enforcement.ConditionError {
		return nil
	})
	e := enforcement.New(enforcement.WithPolicyEvaluator(allowEval))
	resp := runCondition(t, e, &capability.PolicyCondition{Backend: "opa"}, nil, "")
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// policyEvalFunc adapts a function to enforcement.PolicyEvaluator.
type policyEvalFunc func(ctx context.Context, backend string, config, input interface{}, req *capability.EnforceRequest) *enforcement.ConditionError

func (f policyEvalFunc) Evaluate(ctx context.Context, backend string, config, input interface{}, req *capability.EnforceRequest) *enforcement.ConditionError {
	return f(ctx, backend, config, input, req)
}

// ── ValidateAction recognizes the per-namespace canonical verb ──────────

// TestValidateAction_CanonicalVerbPerNamespace pins that ValidateAction matches a
// constraint carrying its namespace's canonical action verb — "read" for
// resource:, "get" for prompt:, "allow" for system: — not only "call"/"*". Before
// the fix, actionPermitted recognized only "call"/"*", so any resource/prompt/
// system constraint with its proper verb produced a spurious "no matching
// capability" denial even for a valid manifest. The request is typed
// either via req.Target.Type or via the engine prefix on req.TargetName.
func TestValidateAction_CanonicalVerbPerNamespace(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	cases := []struct {
		name             string
		constraintTarget string
		action           string
		reqToolName      string
		reqTargetType    string // "" => rely on the engine prefix in reqToolName
		reqTargetName    string
	}{
		{"tool:call via Target", "tool:read_file", "call", "read_file", "tool", "read_file"},
		{"resource:read via Target", "resource:file:///data/*", "read", "file:///data/report.csv", "resource", "file:///data/report.csv"},
		{"prompt:get via Target", "prompt:code_review", "get", "code_review", "prompt", "code_review"},
		{"system:allow via Target", "system:sampling/createMessage", "allow", "sampling/createMessage", "system", "sampling/createMessage"},
		// Same grants, typed only through the engine prefix on req.TargetName.
		{"resource:read via prefix", "resource:file:///data/*", "read", "resource:file:///data/report.csv", "", ""},
		{"prompt:get via prefix", "prompt:code_review", "get", "prompt:code_review", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := &capability.EnforceRequest{SessionID: "s", TargetName: tc.reqToolName}
			if tc.reqTargetType != "" {
				req.Target = &capability.EnforceRequestTarget{Type: tc.reqTargetType, Name: tc.reqTargetName}
			}
			resp := e.ValidateAction(context.Background(), req, []capability.Constraint{
				{Target: tc.constraintTarget, Actions: []string{tc.action}},
			})
			assert.Equal(t, capability.DecisionAllow, resp.Decision,
				"%s: canonical verb %q must match %q", tc.name, tc.action, tc.constraintTarget)
		})
	}
}

// ── cross-namespace constraints must not match ──────────────────────────

// TestFindMatchingCapability_NamespaceTypeMustMatch is the regression: a
// constraint authored for one namespace must never match a request of
// another even when the bare names overlap. A bare, untyped req.TargetName defaults
// to the "tool" namespace, so a wildcard "resource:*" constraint can no longer
// approve a tool call.
func TestFindMatchingCapability_NamespaceTypeMustMatch(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	t.Run("resource:* does not match a bare tool call", func(t *testing.T) {
		t.Parallel()
		req := &capability.EnforceRequest{SessionID: "s", TargetName: "delete_database"}
		resp := e.ValidateAction(context.Background(), req, []capability.Constraint{
			{Target: "resource:*", Actions: []string{"*"}},
		})
		assert.Equal(t, capability.DecisionDeny, resp.Decision,
			"a resource: constraint must not authorize a tool call")
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
	})

	t.Run("tool constraint does not match an explicit resource request", func(t *testing.T) {
		t.Parallel()
		req := &capability.EnforceRequest{
			SessionID:  "s",
			TargetName: "export",
			Target:     &capability.EnforceRequestTarget{Type: "resource", Name: "export"},
		}
		resp := e.ValidateAction(context.Background(), req, []capability.Constraint{
			{Target: "tool:export", Actions: []string{"*"}},
		})
		assert.Equal(t, capability.DecisionDeny, resp.Decision,
			"a tool: constraint must not authorize a resource request")
	})

	t.Run("FindMatchingCapability skips the wrong-type constraint", func(t *testing.T) {
		t.Parallel()
		req := &capability.EnforceRequest{TargetName: "delete_database"} // bare → tool
		matched := e.FindMatchingCapability(req, []capability.Constraint{
			{Target: "resource:*", Actions: []string{"*"}},
		})
		assert.Nil(t, matched, "wildcard resource constraint must not match a bare tool name")
	})
}

// ── input.context.timestamp carries the request time ────────────────────

// TestValidateAction_TimestampReachesRegoInput is the regression:
// the engine must thread its decision timestamp into the policy input so a
// time-based Rego rule sees the real request time, not the perennially-empty
// req.Context.Now.
func TestValidateAction_TimestampReachesRegoInput(t *testing.T) {
	t.Parallel()
	// A sub-second nanosecond component so the test pins the RFC3339Nano precision:
	// with second-precision RFC3339 the .123456789 fraction would be
	// truncated and a time-based Rego rule would silently see a zeroed sub-second.
	fixed := time.Date(2026, 6, 14, 9, 30, 0, 123456789, time.UTC)
	var captured map[string]interface{}
	spy := &spyDirectiveEvaluator{out: &captured}
	e := enforcement.New(enforcement.WithClock(newFakeClock(fixed)), enforcement.WithPolicyEvaluator(spy))

	req := &capability.EnforceRequest{SessionID: "s", TargetName: "read_file"}
	e.ValidateAction(context.Background(), req, []capability.Constraint{{
		Target:     "tool:read_file",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.PolicyCondition{Backend: "opa"}},
	}})

	require.NotNil(t, captured, "policy evaluator was not called")
	ctxMap, ok := captured["context"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, fixed.UTC().Format(time.RFC3339Nano), ctxMap["timestamp"],
		"input.context.timestamp must carry the engine clock's request time at nanosecond precision")
}

// ── the engine must not mutate the caller's EnforceRequest.Directives ──────────

// TestValidateAction_DoesNotMutateRequestDirectives is the regression:
// ValidateAction and EvaluateConditions previously wrote the matched
// constraint's directives onto the caller's *EnforceRequest, a surprising side
// effect and a data race on a shared request. The obligations must still be
// produced (from the matched constraint) without touching req.
func TestValidateAction_DoesNotMutateRequestDirectives(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	constraints := []capability.Constraint{{
		Target:     "tool:export",
		Actions:    []string{"call"},
		Directives: []capability.Directive{&capability.RedactFieldsDirective{Fields: []string{"ssn"}}},
	}}

	req := &capability.EnforceRequest{SessionID: "s", TargetName: "export"}
	resp := e.ValidateAction(context.Background(), req, constraints)
	require.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.Nil(t, req.Directives, "ValidateAction must not write directives onto the caller's request")
	require.Len(t, resp.Obligations, 1, "the redactFields obligation must still be produced")

	// EvaluateConditions has the same contract.
	req2 := &capability.EnforceRequest{SessionID: "s", TargetName: "export"}
	e.EvaluateConditions(context.Background(), req2, &constraints[0])
	assert.Nil(t, req2.Directives, "EvaluateConditions must not write directives onto the caller's request")
}

// TestValidateAction_ConcurrentSharedRequestNoRace shares one *EnforceRequest
// across concurrent ValidateAction calls and a concurrent reader of the field the
// engine used to mutate. Under `go test -race` this fails if the engine writes
// req.Directives (the data race); with the fix every access is a
// read.
func TestValidateAction_ConcurrentSharedRequestNoRace(t *testing.T) {
	t.Parallel()
	e := enforcement.New()
	constraints := []capability.Constraint{{
		Target:     "tool:export",
		Actions:    []string{"call"},
		Directives: []capability.Directive{&capability.RedactFieldsDirective{Fields: []string{"ssn"}}},
	}}
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "export"}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.ValidateAction(context.Background(), req, constraints)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = req.Directives
		}
	}()
	wg.Wait()
	assert.Nil(t, req.Directives)
}

// ── Wrong-type arguments are CONDITION_FAILED, not MISSING_CONTEXT ───────────

func TestConditions_WrongTypeArgument_ConditionFailed(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	cases := []struct {
		name      string
		cond      capability.Condition
		condType  string
		arguments map[string]interface{}
	}{
		{
			"allowedExtensions number arg",
			&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".txt"}},
			capability.ConditionTypeAllowedExtensions,
			map[string]interface{}{"path": 42.0},
		},
		{
			"allowedExtensions bool arg",
			&capability.AllowedExtensionsCondition{Argument: "path", Extensions: []string{".txt"}},
			capability.ConditionTypeAllowedExtensions,
			map[string]interface{}{"path": true},
		},
		{
			"recipientDomain object arg",
			&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
			capability.ConditionTypeRecipientDomain,
			map[string]interface{}{"to": map[string]interface{}{"addr": "x@example.com"}},
		},
		{
			"recipientDomain number arg",
			&capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com"}},
			capability.ConditionTypeRecipientDomain,
			map[string]interface{}{"to": 7.0},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{
				SessionID:  "s",
				TargetName: "do_thing",
				Arguments:  tc.arguments,
			}, []capability.Constraint{{
				Target:     "tool:do_thing",
				Actions:    []string{"call"},
				Conditions: []capability.Condition{tc.cond},
			}})
			require.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code,
				"a present-but-wrong-type argument is CONDITION_FAILED, not MISSING_CONTEXT")
			assert.Equal(t, tc.condType, resp.Denial.ConditionType)
		})
	}
}

// ── single-pass ResourceSpecificity scoring formula ─────────────────────────────

// TestResourceSpecificity_SinglePassFormula pins the specificity formula after
// the single-pass rewrite and the post-wildcard literal fix: EVERY non-wildcard
// rune counts toward the literal score — including
// those after a glob metacharacter — and every metacharacter is subtracted.
func TestResourceSpecificity_SinglePassFormula(t *testing.T) {
	t.Parallel()
	// "read_" (5) + '*' + "_v2" (3) => 8 literal runes, 1 wildcard => 79.
	// The trailing "_v2" counts; the prefix-only formula scored it 49.
	assert.Equal(t, 8*10-1, enforcement.ResourceSpecificity("read_*_v2", "read_x_v2"))
	// Multiple metacharacters: literal "a" (1), then '*' and '?'. 1 literal rune,
	// 2 wildcards => 8.
	assert.Equal(t, 1*10-2, enforcement.ResourceSpecificity("a*?", "abc"))
	// Exact equality short-circuits to the dominating exact-match sentinel.
	assert.Equal(t, 1<<27, enforcement.ResourceSpecificity("read_file", "read_file"))
}

// TestResourceSpecificity_ExactBeatsLongGlob pins that an exact-name match
// outranks a glob no matter how long the glob's literal portion is. The former
// fixed 1000 sentinel was beaten by any glob whose literal run exceeded ~100
// runes, letting a broad glob outrank an exact constraint for a long target name.
func TestResourceSpecificity_ExactBeatsLongGlob(t *testing.T) {
	t.Parallel()
	name := "file:///home/user/projects/acme/reports/2026/q2/financials/confidential/board/summary/final/report.pdf"
	exact := enforcement.ResourceSpecificity(name, name)
	glob := enforcement.ResourceSpecificity(name[:len(name)-1]+"*", name)
	assert.Greater(t, exact, glob,
		"exact match must outrank a long glob matching the same name")
}

// TestResourceSpecificity_WildcardTiebreakClamped pins that the wildcard
// tiebreaker can never cancel a literal-count advantage: a more-specific pattern
// (more literals) outranks a looser one even when it carries far more
// metacharacters, because the wildcard penalty is clamped strictly below one
// literal step.
func TestResourceSpecificity_WildcardTiebreakClamped(t *testing.T) {
	t.Parallel()
	val := "abXXXXXXXXXXXX" // "ab" + 12 single chars
	more := enforcement.ResourceSpecificity("ab????????????", val)
	less := enforcement.ResourceSpecificity("a*", val)
	assert.Greater(t, more, less,
		"the 2-literal pattern must beat the 1-literal catch-all despite more wildcards")
}

// ── The engine stamps AuditOnly on a matched-constraint deny ─────────────────

// TestAuditOnly_StampedByEngineOnDeny pins that ValidateAction and
// EvaluateConditions set EnforceResponse.AuditOnly from the matched constraint's
// enforcement mode on a condition-failure deny. Before the fix only the PDP's
// defer stamped it, so a direct engine caller saw AuditOnly=false on an audit
// constraint's own denial and could not tell it apart from a hard deny.
func TestAuditOnly_StampedByEngineOnDeny(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	failing := []capability.Condition{
		&capability.AllowedValuesCondition{Argument: "x", Values: []interface{}{"yes"}},
	}
	req := &capability.EnforceRequest{
		TargetName: "debug_exec",
		Arguments:  map[string]interface{}{"x": "no"}, // fails the allowedValues check
	}

	t.Run("audit constraint deny is AuditOnly", func(t *testing.T) {
		t.Parallel()
		audit := &capability.Constraint{
			Target:      "tool:debug_exec",
			Actions:     []string{"call"},
			Enforcement: capability.EnforcementAudit,
			Conditions:  failing,
		}

		respEC := e.EvaluateConditions(context.Background(), req, audit)
		assert.Equal(t, capability.DecisionDeny, respEC.Decision)
		assert.True(t, respEC.AuditOnly, "EvaluateConditions must stamp AuditOnly for an audit-mode constraint deny")

		respVA := e.ValidateAction(context.Background(), req, []capability.Constraint{*audit})
		assert.Equal(t, capability.DecisionDeny, respVA.Decision)
		assert.True(t, respVA.AuditOnly, "ValidateAction must stamp AuditOnly for an audit-mode constraint deny")
	})

	t.Run("enforce constraint deny stays hard", func(t *testing.T) {
		t.Parallel()
		enforce := &capability.Constraint{
			Target:     "tool:debug_exec",
			Actions:    []string{"call"},
			Conditions: failing,
		}

		respEC := e.EvaluateConditions(context.Background(), req, enforce)
		assert.Equal(t, capability.DecisionDeny, respEC.Decision)
		assert.False(t, respEC.AuditOnly, "an enforce-mode constraint deny must not be AuditOnly")

		respVA := e.ValidateAction(context.Background(), req, []capability.Constraint{*enforce})
		assert.Equal(t, capability.DecisionDeny, respVA.Decision)
		assert.False(t, respVA.AuditOnly)
	})

	t.Run("no-match deny is never AuditOnly", func(t *testing.T) {
		t.Parallel()
		// A request matching no constraint is a hard deny regardless of any audit
		// entry elsewhere in the manifest.
		resp := e.ValidateAction(context.Background(), &capability.EnforceRequest{TargetName: "unlisted"},
			[]capability.Constraint{{Target: "tool:debug_exec", Actions: []string{"call"}, Enforcement: capability.EnforcementAudit}})
		assert.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.False(t, resp.AuditOnly, "a no-match deny must stay a hard deny")
	})
}

// ── Post-wildcard literal content raises specificity ─────────────────────────

// TestSpecificity_PostWildcardLiteralWins pins the fix: a pattern whose
// literal content follows a leading wildcard (e.g. "*_admin") is more specific
// than the bare catch-all "*", so it wins regardless of manifest order. Before
// the fix both scored -1 (only the pre-wildcard prefix counted), so the winner
// depended on list position and the more specific entry could be silently
// shadowed.
func TestSpecificity_PostWildcardLiteralWins(t *testing.T) {
	t.Parallel()

	// "*_admin" (6 literal runes, 1 wildcard) => 59; "*" => -1.
	assert.Equal(t, 6*10-1, enforcement.ResourceSpecificity("*_admin", "create_admin"))
	assert.Equal(t, 0*10-1, enforcement.ResourceSpecificity("*", "create_admin"))
	assert.Greater(t,
		enforcement.ResourceSpecificity("*_admin", "create_admin"),
		enforcement.ResourceSpecificity("*", "create_admin"),
		"a wildcard pattern with trailing literal content must outscore the bare catch-all")

	e := enforcement.New()
	req := &capability.EnforceRequest{TargetName: "create_admin"}

	// The catch-all is listed FIRST; the more specific "*_admin" must still win.
	caps := []capability.Constraint{
		{Target: "tool:*", Actions: []string{"call"}},
		{Target: "tool:*_admin", Actions: []string{"call"}},
	}
	matched := e.FindMatchingCapability(req, caps)
	require.NotNil(t, matched)
	assert.Equal(t, "tool:*_admin", matched.Target,
		"the trailing-literal pattern must win the tie even when the catch-all is first")

	// Order-independence: reversing the list selects the same constraint.
	matchedRev := e.FindMatchingCapability(req, []capability.Constraint{caps[1], caps[0]})
	require.NotNil(t, matchedRev)
	assert.Equal(t, "tool:*_admin", matchedRev.Target)
}

// ── sequenceBlock denial details report blockedTool with its namespace ────────

// TestSequenceBlock_BlockedToolNamespaced pins that the sequenceBlock denial
// reports blockedTool in namespace:name form (consistent with afterTool) and
// names the blocked target's namespace in the message. Before the fix blockedTool
// was the bare name, so an audit query could not filter both sides of a denial
// with one namespace-qualified pattern, and a tool/prompt/resource sharing a bare
// name was ambiguous.
func TestSequenceBlock_BlockedToolNamespaced(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{
		{Target: "tool:read_credentials", Actions: []string{"call"}},
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
			},
		},
	}

	resp := callOnce(t, engine, "sess-311", "read_credentials", caps)
	require.Equal(t, capability.DecisionAllow, resp.Decision)

	resp = callOnce(t, engine, "sess-311", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	// Both sides of the denial are now namespace-qualified.
	assert.Equal(t, "tool:read_credentials", resp.Denial.Details["afterTool"])
	assert.Equal(t, "tool:write_external", resp.Denial.Details["blockedTool"])
	assert.Contains(t, resp.Denial.Message, `tool "write_external" is blocked after it`)
}

// ── an unhandled directive type fails closed ──────────────────────────────────

// unknownDirective is a directive type the engine does not know how to translate
// into an obligation. It exists only to exercise the fail-closed default arm of
// the obligation-collection loop.
type unknownDirective struct{}

func (unknownDirective) DirectiveType() string { return "unknownTestDirective" }
func (unknownDirective) ToObligation() capability.Obligation {
	return capability.Obligation{Type: "unknownTestDirective"}
}

// TestObligationLoop_UnhandledDirectiveFailsClosed pins that a directive the
// engine cannot emit an obligation for produces a hard deny with
// ENFORCEMENT_ERROR rather than being silently dropped (a fail-open). redactFields
// is the only real type today, so this guards the maintenance trap a second
// directive type would otherwise spring.
func TestObligationLoop_UnhandledDirectiveFailsClosed(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	matched := &capability.Constraint{
		Target:     "tool:export",
		Actions:    []string{"call"},
		Directives: []capability.Directive{unknownDirective{}},
	}
	req := &capability.EnforceRequest{TargetName: "export"}

	t.Run("EvaluateConditions", func(t *testing.T) {
		t.Parallel()
		resp := e.EvaluateConditions(context.Background(), req, matched)
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
		assert.Contains(t, resp.Denial.Message, "unhandled obligation type")
		assert.False(t, resp.AuditOnly, "an unwired directive is an engine bug, not a downgradable verdict")
		assert.False(t, resp.Denial.Downgradable(), "the deny must not be downgradable, so stamp()/isObserveDeny cannot turn it into a forward")
	})

	t.Run("ValidateAction", func(t *testing.T) {
		t.Parallel()
		resp := e.ValidateAction(context.Background(), req, []capability.Constraint{*matched})
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	})

	// A redactFields directive still produces its obligation on allow — the
	// default arm does not interfere with the supported type.
	t.Run("redactFields still works", func(t *testing.T) {
		t.Parallel()
		ok := &capability.Constraint{
			Target:     "tool:export",
			Actions:    []string{"call"},
			Directives: []capability.Directive{&capability.RedactFieldsDirective{Fields: []string{"ssn"}}},
		}
		resp := e.EvaluateConditions(context.Background(), req, ok)
		require.Equal(t, capability.DecisionAllow, resp.Decision)
		require.Len(t, resp.Obligations, 1)
		assert.Equal(t, capability.DirectiveTypeRedactFields, resp.Obligations[0].Type)
	})

	// An unwired directive is an engine bug, not a policy verdict: the fail-closed
	// deny is intentionally NOT downgraded to AuditOnly even for an audit-mode
	// constraint — forwarding a response the engine could not post-process (e.g. an
	// un-applied redaction) is exactly the leak audit mode must not wave through.
	t.Run("audit-mode constraint still hard-denies, not AuditOnly", func(t *testing.T) {
		t.Parallel()
		auditMatched := &capability.Constraint{
			Target:      "tool:export",
			Actions:     []string{"call"},
			Enforcement: capability.EnforcementAudit,
			Directives:  []capability.Directive{unknownDirective{}},
		}
		resp := e.EvaluateConditions(context.Background(), req, auditMatched)
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
		assert.False(t, resp.AuditOnly,
			"an unwired-directive engine error must hard-deny even for an audit-mode constraint")
	})
}

// TestObligationLoop_TypedNilDirectiveSkipped is a regression: a typed-nil
// directive pointer in a programmatically built Constraint must be skipped, not
// dereferenced. ToObligation has a value receiver, so calling it through a
// (*RedactFieldsDirective)(nil) — which is a non-nil interface — would panic. The
// manifest loader never produces one, but a constructed Constraint must not crash
// the engine on a fail-closed path.
func TestObligationLoop_TypedNilDirectiveSkipped(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	var nilDir *capability.RedactFieldsDirective // typed-nil pointer
	matched := &capability.Constraint{
		Target:     "tool:export",
		Actions:    []string{"call"},
		Directives: []capability.Directive{nilDir},
	}
	req := &capability.EnforceRequest{TargetName: "export"}

	require.NotPanics(t, func() {
		resp := e.EvaluateConditions(context.Background(), req, matched)
		// The nil directive is skipped, leaving no obligation; the call is allowed.
		require.Equal(t, capability.DecisionAllow, resp.Decision)
		assert.Empty(t, resp.Obligations)
	})
}

// TestObligationDeny_DoesNotPoisonSessionHistory pins: when CollectObligations
// fails closed (an unhandled directive type), the call must NOT have been recorded
// in session history. Recording it first would let a later sequenceBlock condition
// on a different tool see the denied tool as "run" and fire when it should not —
// the prerequisite was denied and never forwarded upstream.
func TestObligationDeny_DoesNotPoisonSessionHistory(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, deny func(e *enforcement.Engine, ctx context.Context, req *capability.EnforceRequest, c *capability.Constraint) capability.EnforceResponse) {
		counter := callcounter.NewInMemory()
		e := enforcement.New(enforcement.WithCallCounter(counter))
		ctx := context.Background()

		// Tool A's constraint carries an unhandled directive, so its obligation
		// collection fails closed even though it has no failing condition.
		reqA := &capability.EnforceRequest{
			SessionID:  "sess-1",
			TargetName: "read_credentials",
			Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_credentials"},
		}
		matchedA := &capability.Constraint{
			Target:     "tool:read_credentials",
			Actions:    []string{"call"},
			Directives: []capability.Directive{unknownDirective{}},
		}
		respA := deny(e, ctx, reqA, matchedA)
		require.Equal(t, capability.DecisionDeny, respA.Decision)
		require.NotNil(t, respA.Denial)
		require.Equal(t, capability.ErrCodeEnforcementError, respA.Denial.Code)

		// Tool B is gated by a sequenceBlock requiring read_credentials to have run.
		// Because A was denied (and never forwarded), history must be clean, so the
		// sequenceBlock must NOT fire and B is allowed.
		reqB := &capability.EnforceRequest{
			SessionID:  "sess-1",
			TargetName: "write_external",
			Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "write_external"},
		}
		matchedB := &capability.Constraint{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
			},
		}
		respB := e.EvaluateConditions(ctx, reqB, matchedB)
		assert.Equal(t, capability.DecisionAllow, respB.Decision,
			"session history must not record a call denied by CollectObligations")
	}

	t.Run("ValidateAction", func(t *testing.T) {
		t.Parallel()
		run(t, func(e *enforcement.Engine, ctx context.Context, req *capability.EnforceRequest, c *capability.Constraint) capability.EnforceResponse {
			resp := e.ValidateAction(ctx, req, []capability.Constraint{*c})
			return resp
		})
	})

	t.Run("EvaluateConditions", func(t *testing.T) {
		t.Parallel()
		run(t, func(e *enforcement.Engine, ctx context.Context, req *capability.EnforceRequest, c *capability.Constraint) capability.EnforceResponse {
			resp := e.EvaluateConditions(ctx, req, c)
			return resp
		})
	})
}

// spyLimiter wraps an InMemory counter and records how many AdmitAll
// calls were ADMITTED per window, so a test can prove a denied call did not burn
// a sibling window's quota. It embeds *callcounter.InMemory so it still
// satisfies the whole capability.CallCounter contract, Peek included.
type spyLimiter struct {
	*callcounter.InMemory
	mu              sync.Mutex
	admittedByWindo map[int]int
}

func newSpyLimiter() *spyLimiter {
	return &spyLimiter{InMemory: callcounter.NewInMemory(), admittedByWindo: map[int]int{}}
}

// AdmitAll is the one commit path the engine takes, single-bucket or multi-bucket
// alike: it delegates to the embedded counter and, only on an
// all-or-nothing admit, records one admitted slot per window. A denied batch records
// nothing, so the spy still proves a denied call burned no sibling window's quota.
func (s *spyLimiter) AdmitAll(ctx context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	admitted, deniedIndex, total, retryAfter, err = s.InMemory.AdmitAll(ctx, buckets)
	if admitted {
		s.mu.Lock()
		for _, b := range buckets {
			s.admittedByWindo[b.WindowSec]++
		}
		s.mu.Unlock()
	}
	return admitted, deniedIndex, total, retryAfter, err
}

func (s *spyLimiter) admitted(windowSec int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.admittedByWindo[windowSec]
}

// TestMaxCalls_MultiWindow_DenialDoesNotBurnSiblingQuota pins: when a
// constraint carries two maxCalls conditions on different windows, a call denied
// by the longer window must NOT consume a slot in the shorter window. Before the
// fix the shorter (declared-first) window committed its slot in its own admission
// before the longer window denied, permanently displacing a legitimate call.
func TestMaxCalls_MultiWindow_DenialDoesNotBurnSiblingQuota(t *testing.T) {
	spy := newSpyLimiter()
	e := enforcement.New(enforcement.WithCallCounter(spy))
	ctx := context.Background()

	// 10 calls/hour AND 5 calls/day; the daily budget binds first. The hourly
	// condition is declared first so it commits first under the old code.
	caps := []capability.Constraint{{
		Target:  "tool:export",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 10, WindowSeconds: 3600},
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 86400},
		},
	}}
	req := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "export",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "export"},
	}

	// Exhaust the daily budget (5 allowed calls).
	for i := 0; i < 5; i++ {
		resp := e.ValidateAction(ctx, req, caps)
		require.Equal(t, capability.DecisionAllow, resp.Decision, "call %d should be allowed", i+1)
	}
	require.Equal(t, 5, spy.admitted(3600), "5 allowed calls must have consumed 5 hourly slots")
	require.Equal(t, 5, spy.admitted(86400), "5 allowed calls must have consumed 5 daily slots")

	// 6th call: the daily window (limit 5) denies. The hourly window still has
	// room (5 < 10) but must NOT be charged for this rejected call.
	resp := e.ValidateAction(ctx, req, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeMaxCalls, resp.Denial.ConditionType)

	assert.Equal(t, 5, spy.admitted(3600),
		"a call denied by the daily window must not consume an hourly slot")
}

// ── Follow-up: a [...] character class scores as one wildcard ────────────────

// TestSpecificity_CharacterClassScoredAsSingleWildcard pins that a bracket class
// is scored like a single '?' rather than having its members and closing ']'
// counted as literal characters, which over-weighted bracket patterns (e.g.
// read_[abc] scored 89 instead of 49). Raised in review of the fix.
func TestSpecificity_CharacterClassScoredAsSingleWildcard(t *testing.T) {
	t.Parallel()

	// A class matches exactly one character, so it scores like '?'.
	assert.Equal(t,
		enforcement.ResourceSpecificity("read_?", "read_a"),
		enforcement.ResourceSpecificity("read_[abc]", "read_a"),
		"a [...] class must score like '?', not like its expanded members")
	// 5 literal runes ("read_") + 1 wildcard (the class) => 49, not the old 89.
	assert.Equal(t, 5*10-1, enforcement.ResourceSpecificity("read_[abc]", "read_a"))
	// A negated class is also one wildcard; '^' and ']' are not literals.
	assert.Equal(t, 5*10-1, enforcement.ResourceSpecificity("read_[^x]", "read_a"))
	// Class internals do not affect the score: a wide class scores the same as a
	// narrow one.
	assert.Equal(t,
		enforcement.ResourceSpecificity("read_[abcdefgh]", "read_a"),
		enforcement.ResourceSpecificity("read_[xy]", "read_a"),
		"the number of class members must not change specificity")
}

// TestEngine_MaxCalls_CheckOnlyDenialReportsTightRetryAfter is the
// regression: when a constraint carries multiple maxCalls conditions the denying
// condition is evaluated in the non-committing check-only pass, which previously
// could only advise the FULL window as the retry-after hint. With a read-only
// PeekRetryAfter the check-only denial now reports the same tight estimate the
// commit path would — the time until the oldest over-limit entry ages out.
func TestEngine_MaxCalls_CheckOnlyDenialReportsTightRetryAfter(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time { return now }))
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ctx := context.Background()

	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "export",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "export"},
	}
	// Two maxCalls conditions force the two-pass check-only evaluation. The hourly
	// limit (3) binds; the per-minute limit (100) never does, but its presence is
	// what routes the denial through the check-only pass.
	caps := []capability.Constraint{{
		Target:  "tool:export",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 3, WindowSeconds: 3600},
			&capability.MaxCallsCondition{Count: 100, WindowSeconds: 60},
		},
	}}

	// Three admitted calls at T=0,1,2s fill the hourly limit.
	for i := 0; i < 3; i++ {
		now = base.Add(time.Duration(i) * time.Second)
		resp := engine.ValidateAction(ctx, &req, caps)
		require.Equal(t, capability.DecisionAllow, resp.Decision, "call %d should be admitted", i+1)
	}

	// At T=3590s the hourly window is nearly exhausted: the oldest entry (T=0)
	// frees a slot at T=3600, only 10s away. The 4th call is denied in the
	// check-only pass and must advise ~10s, NOT the full 3600s window.
	now = base.Add(3590 * time.Second)
	resp := engine.ValidateAction(ctx, &req, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeRateLimited, resp.Denial.Code)
	require.NotNil(t, resp.Denial.Details)
	retryAfter, ok := resp.Denial.Details["retry_after_seconds"].(int64)
	require.True(t, ok, "denial must carry an integer-seconds retry_after_seconds hint")
	assert.Equal(t, int64(10), retryAfter,
		"check-only denial must report the tight estimate (oldest entry frees at T=3600), not the full window")
	assert.Less(t, retryAfter, int64(3600), "retry_after_seconds must be tighter than the full window")
}

// The read-only retry-after peek the check-only maxCalls pass uses is part
// of the capability.CallCounter contract now, pinned by the assertions near the
// top of this file; both built-in backends implement it.

// ---- merged from argument_path_test.go ----

// decideWithAllowedValues evaluates a single allowedValues condition with the
// given argument reference and request arguments, returning the decision.
func decideWithAllowedValues(t *testing.T, argument string, values []interface{}, args map[string]interface{}) capability.Decision {
	t.Helper()
	engine := enforcement.New()
	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "tool:do",
		Arguments:  args,
	}
	resp := engine.ValidateAction(context.Background(), &req, []capability.Constraint{
		{
			Target:  "tool:do",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: argument, Values: values},
			},
		},
	})
	return resp.Decision
}

func TestNestedArgumentPath_AllowedValues(t *testing.T) {
	nested := func(owner string) map[string]interface{} {
		return map[string]interface{}{
			"request": map[string]interface{}{
				"owner": owner,
				"meta":  map[string]interface{}{"id": "42"},
			},
		}
	}

	tests := []struct {
		name     string
		argument string
		values   []interface{}
		args     map[string]interface{}
		want     capability.Decision
	}{
		{
			name:     "nested path matches allowed value",
			argument: "$.request.owner",
			values:   []interface{}{"acme-corp"},
			args:     nested("acme-corp"),
			want:     capability.DecisionAllow,
		},
		{
			name:     "nested path value not allowed → deny",
			argument: "$.request.owner",
			values:   []interface{}{"acme-corp"},
			args:     nested("rogue-corp"),
			want:     capability.DecisionDeny,
		},
		{
			name:     "deeper nested path",
			argument: "$.request.meta.id",
			values:   []interface{}{"42"},
			args:     nested("acme-corp"),
			want:     capability.DecisionAllow,
		},
		{
			name:     "missing intermediate key → fail closed",
			argument: "$.request.absent.id",
			values:   []interface{}{"42"},
			args:     nested("acme-corp"),
			want:     capability.DecisionDeny,
		},
		{
			name:     "path lands on non-object → fail closed",
			argument: "$.request.owner.id", // owner is a string, not an object
			values:   []interface{}{"x"},
			args:     nested("acme-corp"),
			want:     capability.DecisionDeny,
		},
		{
			name:     "malformed path → fail closed",
			argument: "$.request..owner",
			values:   []interface{}{"acme-corp"},
			args:     nested("acme-corp"),
			want:     capability.DecisionDeny,
		},
		{
			name:     "glob still applies through a nested path",
			argument: "$.request.owner",
			values:   []interface{}{"acme-*"},
			args:     nested("acme-corp"),
			want:     capability.DecisionAllow,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideWithAllowedValues(t, tc.argument, tc.values, tc.args); got != tc.want {
				t.Errorf("decision = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestLiteralDottedKey_NotTraversed verifies the invariant that a plain
// (non-"$.") argument with a dot is an exact top-level key, never a path — so an
// argument literally named "a.b" still matches and is not silently traversed.
func TestLiteralDottedKey_NotTraversed(t *testing.T) {
	args := map[string]interface{}{
		"a.b": "literal",                                 // a real top-level key with a dot
		"a":   map[string]interface{}{"b": "nested-val"}, // a nested structure
	}
	// Literal key "a.b" resolves to the top-level value, not args["a"]["b"].
	if got := decideWithAllowedValues(t, "a.b", []interface{}{"literal"}, args); got != capability.DecisionAllow {
		t.Errorf("literal dotted key should match the top-level value, got %v", got)
	}
	// The same key must NOT be satisfied by the nested "nested-val".
	if got := decideWithAllowedValues(t, "a.b", []interface{}{"nested-val"}, args); got != capability.DecisionDeny {
		t.Errorf("literal dotted key must not be traversed into args[a][b], got %v", got)
	}
	// The "$." form does traverse to the nested value.
	if got := decideWithAllowedValues(t, "$.a.b", []interface{}{"nested-val"}, args); got != capability.DecisionAllow {
		t.Errorf("$. path should traverse to the nested value, got %v", got)
	}
}

// TestEscapedDollarDotLiteral_NotTraversed verifies that a tool argument literally
// named "$.x" (a legal JSON object key) can be referenced with the "$$." escape
// without being silently traversed as args["x"] — the collision the escape exists
// to close (a manifest condition must match the argument it names, never a
// different one it happens to collide with).
func TestEscapedDollarDotLiteral_NotTraversed(t *testing.T) {
	args := map[string]interface{}{
		"$.x": "literal-dollar-key",     // a real top-level key starting with "$."
		"x":   "would-be-traversed-val", // the key a "$." path would resolve to
	}
	// The escaped literal "$$.x" matches the real "$.x" argument.
	if got := decideWithAllowedValues(t, "$$.x", []interface{}{"literal-dollar-key"}, args); got != capability.DecisionAllow {
		t.Errorf("escaped literal should match the literal \"$.x\" argument, got %v", got)
	}
	// It must NOT be satisfied by args["x"] (the traversal target of unescaped "$.x").
	if got := decideWithAllowedValues(t, "$$.x", []interface{}{"would-be-traversed-val"}, args); got != capability.DecisionDeny {
		t.Errorf("escaped literal must not resolve to args[x], got %v", got)
	}
	// The unescaped "$." form still traverses to args["x"], unaffected by the escape.
	if got := decideWithAllowedValues(t, "$.x", []interface{}{"would-be-traversed-val"}, args); got != capability.DecisionAllow {
		t.Errorf("unescaped $. path should still traverse to args[x], got %v", got)
	}
}

// TestEscapedDollarDollarDotLiteral_NoCollision verifies the escape generalizes
// past its shortest form: a tool argument literally named "$$.x" (itself starting
// with the shortest "$$." escape prefix) must be reachable via a THIRD leading
// dollar ("$$$.x"), distinctly from "$$.x" resolving to the literal key "$.x". A
// fixed single-level escape would collide here — "$$.x" could only ever mean
// "the escaped form of $.x", with no way to name the literal key "$$.x" itself,
// reproducing the same silently-wrong-argument bug one level up.
func TestEscapedDollarDollarDotLiteral_NoCollision(t *testing.T) {
	args := map[string]interface{}{
		"$.x":  "value-for-dollar-x",
		"$$.x": "value-for-dollar-dollar-x",
	}
	// "$$.x" resolves to the literal key "$.x" (unchanged from before).
	if got := decideWithAllowedValues(t, "$$.x", []interface{}{"value-for-dollar-x"}, args); got != capability.DecisionAllow {
		t.Errorf("\"$$.x\" should match the literal \"$.x\" argument, got %v", got)
	}
	if got := decideWithAllowedValues(t, "$$.x", []interface{}{"value-for-dollar-dollar-x"}, args); got != capability.DecisionDeny {
		t.Errorf("\"$$.x\" must not resolve to args[\"$$.x\"], got %v", got)
	}
	// "$$$.x" (one more leading dollar) resolves to the literal key "$$.x", not
	// back to "$.x" — the two-hop reference reaches a DIFFERENT argument.
	if got := decideWithAllowedValues(t, "$$$.x", []interface{}{"value-for-dollar-dollar-x"}, args); got != capability.DecisionAllow {
		t.Errorf("\"$$$.x\" should match the literal \"$$.x\" argument, got %v", got)
	}
	if got := decideWithAllowedValues(t, "$$$.x", []interface{}{"value-for-dollar-x"}, args); got != capability.DecisionDeny {
		t.Errorf("\"$$$.x\" must not resolve to args[\"$.x\"], got %v", got)
	}
}

// ---- merged from directives_engine_test.go ----

// TestDirectives_ObligationsAfterConditionsPass verifies that
// redactFields obligations are collected from Directives (not Conditions)
// and only appended when all conditions pass.
func TestDirectives_ObligationsAfterConditionsPass(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraint := capability.Constraint{
		Target:  "tool:read_file",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.AllowedValuesCondition{
				Argument: "path",
				Values:   []interface{}{"/reports/*"},
			},
		},
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"$.user.ssn", "$.creditCard"}},
		},
	}

	req := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": "/reports/q3.pdf"},
	}

	resp := e.EvaluateConditions(context.Background(), req, &constraint)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 1)
	assert.Equal(t, capability.DirectiveTypeRedactFields, resp.Obligations[0].Type)
	assert.Equal(t, []string{"$.user.ssn", "$.creditCard"}, resp.Obligations[0].Paths)
}

// TestDirectives_NotCollectedWhenConditionFails verifies that
// directives are NOT applied when a condition denies the request (obligations
// must be empty on deny).
func TestDirectives_NotCollectedWhenConditionFails(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraint := capability.Constraint{
		Target:  "tool:read_file",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.AllowedValuesCondition{
				Argument: "path",
				Values:   []interface{}{"/reports/*"},
			},
		},
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"$.user.ssn"}},
		},
	}

	req := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": "/internal/secrets.txt"},
	}

	resp := e.EvaluateConditions(context.Background(), req, &constraint)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	// Directives must not produce obligations when the request is denied.
	assert.Empty(t, resp.Obligations)
}

// TestDirectives_NoneProducesNoObligations verifies that a constraint with
// no directives produces an empty obligations list on allow.
func TestDirectives_NoneProducesNoObligations(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraint := capability.Constraint{
		Target:  "tool:read_file",
		Actions: []string{"call"},
	}

	req := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "read_file",
	}

	resp := e.EvaluateConditions(context.Background(), req, &constraint)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	assert.Empty(t, resp.Obligations)
}

// TestDirectives_MultipleRedactMergeObligations verifies that
// multiple redactFields directives each produce their own obligation entry.
func TestDirectives_MultipleRedactMergeObligations(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraint := capability.Constraint{
		Target:  "tool:query_db",
		Actions: []string{"call"},
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"$.ssn"}},
			&capability.RedactFieldsDirective{Fields: []string{"$.creditCard", "$.cvv"}},
		},
	}

	req := &capability.EnforceRequest{SessionID: "s", TargetName: "query_db"}

	resp := e.EvaluateConditions(context.Background(), req, &constraint)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 2)
	assert.Equal(t, []string{"$.ssn"}, resp.Obligations[0].Paths)
	assert.Equal(t, []string{"$.creditCard", "$.cvv"}, resp.Obligations[1].Paths)
}

// TestDirectives_ValidateActionCollectsObligations verifies that ValidateAction
// (full matching + condition evaluation) also collects directive obligations.
// The engine's ValidateAction operates on bare names (no namespace prefix);
// namespace routing is handled by ManifestPDP.findConstraint before calling
// EvaluateConditions.
func TestDirectives_ValidateActionCollectsObligations(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraints := []capability.Constraint{
		{
			Target:  "export", // bare name: engine.ValidateAction does not strip prefixes
			Actions: []string{"*"},
			Directives: []capability.Directive{
				&capability.RedactFieldsDirective{Fields: []string{"password"}},
			},
		},
	}

	req := &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "export",
	}

	resp := e.ValidateAction(context.Background(), req, constraints)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 1)
	assert.Equal(t, capability.DirectiveTypeRedactFields, resp.Obligations[0].Type)
	assert.Equal(t, []string{"password"}, resp.Obligations[0].Paths)
}

// unregisteredCondition implements capability.Condition with a discriminator
// the engine has no handler for. Used to exercise the engine's fail-closed path
// when something bypasses the JSON unmarshal layer's allowlist of types.
type unregisteredCondition struct{}

func (unregisteredCondition) ConditionType() string { return "definitely-not-a-real-condition" }

// TestDirectives_UnknownConditionTypeFailsClosed verifies the engine's own
// fail-closed behavior when a constraint carries a condition whose discriminator
// has no registered handler. The JSON unmarshal layer already rejects unknown
// types at parse time, but a programmatic caller (or a future code path that
// constructs Constraints directly) could still pass one through; the engine
// must deny rather than silently treat it as satisfied.
func TestDirectives_UnknownConditionTypeFailsClosed(t *testing.T) {
	t.Parallel()
	e := enforcement.New()

	constraint := capability.Constraint{
		Target:  "tool:read_file",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			unregisteredCondition{},
		},
	}

	req := &capability.EnforceRequest{SessionID: "sess", TargetName: "read_file"}
	resp := e.EvaluateConditions(context.Background(), req, &constraint)
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "definitely-not-a-real-condition")
}

// ---- merged from rego_input_test.go ----

// ── BuildRegoInput ─────────────────────────────────────────────────────────────

func TestBuildRegoInput_MinimalRequest(t *testing.T) {
	// A request with only SessionID and ToolName; no Target, no Claims.
	ctx := context.Background()
	req := &capability.EnforceRequest{
		SessionID:  "sess-min",
		TargetName: "read_file",
	}

	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	// arguments must be an empty map, not nil.
	args, ok := input["arguments"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[arguments] type = %T, want map[string]interface{}", input["arguments"])
	}
	if len(args) != 0 {
		t.Errorf("input[arguments] = %v, want empty map", args)
	}

	// claims must be an empty map (not nil).
	claims, ok := input["claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[claims] type = %T, want map[string]interface{}", input["claims"])
	}
	if len(claims) != 0 {
		t.Errorf("input[claims] = %v, want empty map", claims)
	}

	// target must be absent when req.Target is nil.
	if _, present := input["target"]; present {
		t.Errorf("input[target] should be absent when req.Target is nil; got %v", input["target"])
	}

	// context must carry session_id.
	ctx2, ok := input["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[context] type = %T, want map[string]interface{}", input["context"])
	}
	if ctx2["session_id"] != "sess-min" {
		t.Errorf("context.session_id = %q, want %q", ctx2["session_id"], "sess-min")
	}
}

// TestBuildRegoInput_MapsAreCopies pins the accident guard on both maps in the document.
// Writing into input.claims corrupted a map memoized and shared across every request on the
// token; writing into input.arguments reached a map that outlives the decision — the pure
// conditions ordered after `policy` resolve from it, and the transport builds the tools/call
// audit record's argument details from it after Decide returns. Only claims was copied, which
// is the asymmetry this closes; nested values stay shared by design, as the comment states.
func TestBuildRegoInput_MapsAreCopies(t *testing.T) {
	ctx := context.Background()
	req := &capability.EnforceRequest{
		SessionID:  "sess-copy",
		TargetName: "query_db",
		Arguments:  map[string]interface{}{"sql": "SELECT 1"},
		Claims:     map[string]interface{}{"sub": "user-abc"},
	}

	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	gotArgs, ok := input["arguments"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[arguments] type = %T, want map[string]interface{}", input["arguments"])
	}
	gotClaims, ok := input["claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[claims] type = %T, want map[string]interface{}", input["claims"])
	}

	// An evaluator writing into the document it was handed.
	gotArgs["sql"] = "DROP TABLE users"
	gotArgs["injected"] = true
	gotClaims["sub"] = "user-root"

	if got := req.Arguments["sql"]; got != "SELECT 1" {
		t.Errorf("req.Arguments[sql] = %v, want the value later conditions and the audit record read", got)
	}
	if _, added := req.Arguments["injected"]; added {
		t.Error("req.Arguments gained a key written into input.arguments")
	}
	if got := req.Claims["sub"]; got != "user-abc" {
		t.Errorf("req.Claims[sub] = %v, want the memoized token claim untouched", got)
	}
}

func TestBuildRegoInput_Arguments(t *testing.T) {
	ctx := context.Background()
	req := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "read_file",
		Arguments: map[string]interface{}{
			"path":     "/reports/q3.pdf",
			"encoding": "utf-8",
		},
	}

	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	args, ok := input["arguments"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[arguments] type = %T", input["arguments"])
	}
	if args["path"] != "/reports/q3.pdf" {
		t.Errorf("arguments.path = %q, want %q", args["path"], "/reports/q3.pdf")
	}
	if args["encoding"] != "utf-8" {
		t.Errorf("arguments.encoding = %q, want %q", args["encoding"], "utf-8")
	}
}

func TestBuildRegoInput_WithTarget(t *testing.T) {
	// When req.Target is set, input["target"] must reflect its type and name.
	cases := []struct {
		targetType string
		targetName string
	}{
		{"tool", "read_file"},
		{"resource", "file:///data/reports/*"},
		{"prompt", "code_review"},
		{"system", "sampling/createMessage"},
	}

	for _, tc := range cases {
		t.Run(tc.targetType+":"+tc.targetName, func(t *testing.T) {
			ctx := context.Background()
			req := &capability.EnforceRequest{
				SessionID:  "sess-1",
				TargetName: tc.targetName,
				Target: &capability.EnforceRequestTarget{
					Type: tc.targetType,
					Name: tc.targetName,
				},
			}

			input, err := enforcement.BuildRegoInput(ctx, req)
			if err != nil {
				t.Fatalf("BuildRegoInput returned error: %v", err)
			}

			target, ok := input["target"].(map[string]interface{})
			if !ok {
				t.Fatalf("input[target] type = %T, want map[string]interface{}", input["target"])
			}
			if target["type"] != tc.targetType {
				t.Errorf("target.type = %q, want %q", target["type"], tc.targetType)
			}
			if target["name"] != tc.targetName {
				t.Errorf("target.name = %q, want %q", target["name"], tc.targetName)
			}
		})
	}
}

func TestBuildRegoInput_WithClaims(t *testing.T) {
	ctx := context.Background()
	req := &capability.EnforceRequest{
		SessionID:  "sess-2",
		TargetName: "query_db",
		Claims: map[string]interface{}{
			"sub":      "user-abc",
			"iss":      "https://idp.example.com",
			"agent_id": "agent-42",
			"task_id":  "task-007",
		},
	}

	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	claims, ok := input["claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[claims] type = %T, want map[string]interface{}", input["claims"])
	}
	for k, want := range map[string]string{
		"sub":      "user-abc",
		"iss":      "https://idp.example.com",
		"agent_id": "agent-42",
		"task_id":  "task-007",
	} {
		if got, _ := claims[k].(string); got != want {
			t.Errorf("claims[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestBuildRegoInput_Context(t *testing.T) {
	ctx := context.Background()
	req := &capability.EnforceRequest{
		SessionID:  "sess-ctx",
		TargetName: "list_files",
		Context: capability.EnforceRequestContext{
			SourceIP: "192.168.1.10",
			Now:      "2026-06-01T12:00:00Z",
		},
	}

	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	ctxMap, ok := input["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[context] type = %T", input["context"])
	}

	if ctxMap["session_id"] != "sess-ctx" {
		t.Errorf("context.session_id = %q, want %q", ctxMap["session_id"], "sess-ctx")
	}
	if ctxMap["source_ip"] != "192.168.1.10" {
		t.Errorf("context.source_ip = %q, want %q", ctxMap["source_ip"], "192.168.1.10")
	}
	if ctxMap["timestamp"] != "2026-06-01T12:00:00Z" {
		t.Errorf("context.timestamp = %q, want %q", ctxMap["timestamp"], "2026-06-01T12:00:00Z")
	}
}

func TestBuildRegoInput_AllFields(t *testing.T) {
	// Full round-trip: all policy input fields populated.
	ctx := context.Background()
	req := &capability.EnforceRequest{
		SessionID:  "sess-full",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": "/data/report.pdf"},
		Context: capability.EnforceRequestContext{
			SourceIP: "10.0.0.1",
			Now:      "2026-06-01T00:00:00Z",
		},
		Target: &capability.EnforceRequestTarget{
			Type: "tool",
			Name: "read_file",
		},
		Claims: map[string]interface{}{
			"sub":      "u1",
			"agent_id": "a1",
		},
	}

	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	// Verify all top-level keys are present.
	for _, key := range []string{"arguments", "target", "claims", "context", "directives"} {
		if _, ok := input[key]; !ok {
			t.Errorf("missing top-level key %q in Rego input", key)
		}
	}

	// Spot-check values.
	if args, ok := input["arguments"].(map[string]interface{}); ok {
		if args["path"] != "/data/report.pdf" {
			t.Errorf("arguments.path wrong")
		}
	}
	if tgt, ok := input["target"].(map[string]interface{}); ok {
		if tgt["type"] != "tool" || tgt["name"] != "read_file" {
			t.Errorf("target wrong: %v", tgt)
		}
	}
	if cl, ok := input["claims"].(map[string]interface{}); ok {
		if cl["sub"] != "u1" || cl["agent_id"] != "a1" {
			t.Errorf("claims wrong: %v", cl)
		}
	}
	if cmap, ok := input["context"].(map[string]interface{}); ok {
		if cmap["session_id"] != "sess-full" || cmap["source_ip"] != "10.0.0.1" {
			t.Errorf("context wrong: %v", cmap)
		}
	}
}

func TestBuildRegoInput_NilArguments_DefaultsToEmptyMap(t *testing.T) {
	// Nil arguments must not produce nil in the Rego input (OPA would reject it).
	ctx := context.Background()
	req := &capability.EnforceRequest{
		SessionID:  "sess-3",
		TargetName: "tool",
		Arguments:  nil,
	}

	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	args, ok := input["arguments"].(map[string]interface{})
	if !ok {
		t.Fatalf("arguments type = %T, want map", input["arguments"])
	}
	if args == nil {
		t.Error("arguments must not be nil in Rego input")
	}
}

func TestBuildRegoInput_NilClaims_DefaultsToEmptyMap(t *testing.T) {
	// Nil claims must be an empty map, not absent, so that Rego policies can
	// safely reference input.claims.* without a guard.
	ctx := context.Background()
	req := &capability.EnforceRequest{
		SessionID:  "sess-4",
		TargetName: "tool",
		Claims:     nil,
	}

	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	claims, ok := input["claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("claims type = %T, want map", input["claims"])
	}
	if claims == nil {
		t.Error("claims must not be nil in Rego input")
	}
}

// ── RequestIDFromContext ──────────────────────────────────────────────────────

func TestRequestIDFromContext_EmptyWhenNotSet(t *testing.T) {
	// A fresh context has no request ID.
	id := enforcement.RequestIDFromContext(context.Background())
	if id != "" {
		t.Errorf("RequestIDFromContext(background) = %q, want empty", id)
	}
}

func TestRequestIDFromContext_InjectedByValidateAction(t *testing.T) {
	// ValidateAction stores a request ID in the context before dispatching
	// condition handlers. A spy evaluator captures it and confirms it is set.
	var capturedID string
	spy := &spyRequestIDEvaluator{capturedRequestID: &capturedID}
	engine := enforcement.New(enforcement.WithPolicyEvaluator(spy))
	ctx := context.Background()

	req := &capability.EnforceRequest{
		SessionID:  "sess-reqid",
		TargetName: "run_query",
	}

	engine.ValidateAction(ctx, req, []capability.Constraint{
		{
			Target:  "run_query",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})

	if capturedID == "" {
		t.Error("request_id must be injected into context before policy handler is called")
	}
}

// spyRequestIDEvaluator captures the request ID from the context it receives.
type spyRequestIDEvaluator struct {
	capturedRequestID *string
}

func (s *spyRequestIDEvaluator) Evaluate(ctx context.Context, _ string, _, _ interface{}, _ *capability.EnforceRequest) *enforcement.ConditionError {
	*s.capturedRequestID = enforcement.RequestIDFromContext(ctx)
	return nil // allow
}

// ── Policy condition receives Target and Claims ────────────────────────────────

func TestPolicyEvaluator_ReceivesTargetInRequest(t *testing.T) {
	// When ManifestPDP populates req.Target before calling ValidateAction,
	// the PolicyEvaluator should receive the same target values.
	// This test simulates that scenario at the enforcement engine level.
	var capturedReq *capability.EnforceRequest
	spy := &spyReqEvaluator{captured: &capturedReq}
	engine := enforcement.New(enforcement.WithPolicyEvaluator(spy))
	ctx := context.Background()

	req := &capability.EnforceRequest{
		SessionID:  "sess-tgt",
		TargetName: "read_file",
		Target: &capability.EnforceRequestTarget{
			Type: "tool",
			Name: "read_file",
		},
	}

	engine.ValidateAction(ctx, req, []capability.Constraint{
		{
			Target:  "read_file",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})

	if capturedReq == nil {
		t.Fatal("policy evaluator was not called")
	}
	if capturedReq.Target == nil {
		t.Fatal("req.Target must be non-nil when set by the caller")
	}
	if capturedReq.Target.Type != "tool" {
		t.Errorf("req.Target.Type = %q, want %q", capturedReq.Target.Type, "tool")
	}
	if capturedReq.Target.Name != "read_file" {
		t.Errorf("req.Target.Name = %q, want %q", capturedReq.Target.Name, "read_file")
	}
}

func TestPolicyEvaluator_ReceivesClaimsInRequest(t *testing.T) {
	// JWT claims set on the request are forwarded unchanged to the evaluator.
	var capturedReq *capability.EnforceRequest
	spy := &spyReqEvaluator{captured: &capturedReq}
	engine := enforcement.New(enforcement.WithPolicyEvaluator(spy))
	ctx := context.Background()

	claims := map[string]interface{}{
		"sub":      "user-xyz",
		"agent_id": "agent-99",
	}
	req := &capability.EnforceRequest{
		SessionID:  "sess-claims",
		TargetName: "send_email",
		Claims:     claims,
	}

	engine.ValidateAction(ctx, req, []capability.Constraint{
		{
			Target:  "send_email",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})

	if capturedReq == nil {
		t.Fatal("policy evaluator was not called")
	}
	if capturedReq.Claims == nil {
		t.Fatal("req.Claims must be non-nil")
	}
	if capturedReq.Claims["sub"] != "user-xyz" {
		t.Errorf("claims.sub = %v, want %q", capturedReq.Claims["sub"], "user-xyz")
	}
	if capturedReq.Claims["agent_id"] != "agent-99" {
		t.Errorf("claims.agent_id = %v, want %q", capturedReq.Claims["agent_id"], "agent-99")
	}
}

func TestPolicyEvaluator_BackwardCompat_ArgumentsOnlyPolicy(t *testing.T) {
	// A policy evaluator that only reads input.arguments must continue to work
	// correctly even when Target and Claims are present in the request. This
	// verifies the additive (backward-compatible) nature of target+claims expansion.
	engine := enforcement.New(enforcement.WithPolicyEvaluator(&argumentsOnlyEvaluator{
		requiredArgKey:   "path",
		requiredArgValue: "/reports/",
	}))
	ctx := context.Background()

	// Call with target and claims populated — evaluator only checks arguments.
	req := &capability.EnforceRequest{
		SessionID:  "sess-bc",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": "/reports/q4.pdf"},
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_file"},
		Claims:     map[string]interface{}{"sub": "u1"},
	}

	resp := engine.ValidateAction(ctx, req, []capability.Constraint{
		{
			Target:  "read_file",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}

	// Same call with a path that violates the arguments-only policy.
	req2 := &capability.EnforceRequest{
		SessionID:  "sess-bc",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": "/etc/passwd"},
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_file"},
	}
	resp2 := engine.ValidateAction(ctx, req2, []capability.Constraint{
		{
			Target:  "read_file",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})
	if resp2.Decision != capability.DecisionDeny {
		t.Errorf("decision = %q, want deny", resp2.Decision)
	}
}

// ── BuildRegoInput integrates with RequestIDFromContext ───────────────────────

func TestBuildRegoInput_RequestIDFromEngine(t *testing.T) {
	// When the engine injects a request ID into context before calling handlers,
	// BuildRegoInput must include that ID in input.context.request_id.
	var capturedInput map[string]interface{}
	spy := &spyBuildRegoInputEvaluator{captured: &capturedInput}
	engine := enforcement.New(enforcement.WithPolicyEvaluator(spy))
	ctx := context.Background()

	req := &capability.EnforceRequest{
		SessionID:  "sess-rid",
		TargetName: "archive",
		Arguments:  map[string]interface{}{"target": "old-logs"},
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "archive"},
	}

	engine.ValidateAction(ctx, req, []capability.Constraint{
		{
			Target:  "archive",
			Actions: []string{"*"},
			Conditions: []capability.Condition{
				&capability.PolicyCondition{Backend: "opa"},
			},
		},
	})

	if capturedInput == nil {
		t.Fatal("spy evaluator was not called")
	}
	ctxMap, ok := capturedInput["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("input.context type = %T", capturedInput["context"])
	}
	rid, _ := ctxMap["request_id"].(string)
	if rid == "" {
		t.Error("input.context.request_id must be set (non-empty UUID) when engine injects it")
	}
	if ctxMap["session_id"] != "sess-rid" {
		t.Errorf("input.context.session_id = %q, want %q", ctxMap["session_id"], "sess-rid")
	}
	if tgt, ok := capturedInput["target"].(map[string]interface{}); ok {
		if tgt["type"] != "tool" {
			t.Errorf("input.target.type = %q, want %q", tgt["type"], "tool")
		}
	} else {
		t.Errorf("input.target missing or wrong type: %T", capturedInput["target"])
	}
}

// ── Test helpers ─────────────────────────────────────────────────────────────

// spyReqEvaluator captures the EnforceRequest it receives.
type spyReqEvaluator struct {
	captured **capability.EnforceRequest
}

func (s *spyReqEvaluator) Evaluate(_ context.Context, _ string, _, _ interface{}, req *capability.EnforceRequest) *enforcement.ConditionError {
	*s.captured = req
	return nil
}

// spyBuildRegoInputEvaluator calls BuildRegoInput and stores the result.
type spyBuildRegoInputEvaluator struct {
	captured *map[string]interface{}
}

func (s *spyBuildRegoInputEvaluator) Evaluate(ctx context.Context, _ string, _, _ interface{}, req *capability.EnforceRequest) *enforcement.ConditionError {
	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		return &enforcement.ConditionError{Code: "POLICY_DENY", Message: err.Error()}
	}
	*s.captured = input
	return nil
}

// argumentsOnlyEvaluator mimics an existing policy that only checks
// input.arguments (backward-compat test).
type argumentsOnlyEvaluator struct {
	requiredArgKey   string
	requiredArgValue string // value must *start with* this prefix
}

func (a *argumentsOnlyEvaluator) Evaluate(_ context.Context, _ string, _, _ interface{}, req *capability.EnforceRequest) *enforcement.ConditionError {
	v, _ := req.Arguments[a.requiredArgKey].(string)
	if len(v) >= len(a.requiredArgValue) && v[:len(a.requiredArgValue)] == a.requiredArgValue {
		return nil
	}
	return &enforcement.ConditionError{
		Code:    "POLICY_DENY",
		Message: "argument value does not match required prefix",
	}
}

// ── input.directives always present ────────────────────────────────────────────

func TestBuildRegoInput_DirectivesAlwaysPresent_NilDirectives(t *testing.T) {
	// A request with no Directives field must still produce "directives": []
	// in the Rego input so Rego policies can iterate input.directives safely.
	req := &capability.EnforceRequest{
		SessionID:  "sess-h1",
		TargetName: "tool:sampling/createMessage",
	}

	input, err := enforcement.BuildRegoInput(context.Background(), req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	dirs, ok := input["directives"]
	if !ok {
		t.Fatal("Rego input is missing required top-level key 'directives'")
	}
	slice, ok := dirs.([]interface{})
	if !ok {
		t.Fatalf("input.directives type = %T, want []interface{}", dirs)
	}
	if slice == nil {
		t.Error("input.directives must not be nil")
	}
	if len(slice) != 0 {
		t.Errorf("input.directives len = %d, want 0", len(slice))
	}
}

func TestBuildRegoInput_DirectivesAlwaysPresent_EmptySlice(t *testing.T) {
	req := &capability.EnforceRequest{
		SessionID:  "sess-h2",
		TargetName: "tool:read_file",
		Directives: []capability.Directive{},
	}

	input, err := enforcement.BuildRegoInput(context.Background(), req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	slice, ok := input["directives"].([]interface{})
	if !ok {
		t.Fatalf("input.directives type = %T, want []interface{}", input["directives"])
	}
	if len(slice) != 0 {
		t.Errorf("input.directives len = %d, want 0", len(slice))
	}
}

func TestBuildRegoInput_RedactFieldsDirective_Shape(t *testing.T) {
	// A redactFields directive must appear in input.directives with the correct
	// JSON shape: {"type": "redactFields", "fields": [...]}.
	req := &capability.EnforceRequest{
		SessionID:  "sess-h3",
		TargetName: "tool:export_data",
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"user.ssn", "card.number"}},
		},
	}

	input, err := enforcement.BuildRegoInput(context.Background(), req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	slice, ok := input["directives"].([]interface{})
	if !ok {
		t.Fatalf("input.directives type = %T, want []interface{}", input["directives"])
	}
	if len(slice) != 1 {
		t.Fatalf("input.directives len = %d, want 1", len(slice))
	}

	m, ok := slice[0].(map[string]interface{})
	if !ok {
		t.Fatalf("input.directives[0] type = %T, want map[string]interface{}", slice[0])
	}
	if m["type"] != "redactFields" {
		t.Errorf("input.directives[0].type = %q, want %q", m["type"], "redactFields")
	}
	fields, ok := m["fields"].([]interface{})
	if !ok {
		t.Fatalf("input.directives[0].fields type = %T, want []interface{}", m["fields"])
	}
	if len(fields) != 2 {
		t.Fatalf("input.directives[0].fields len = %d, want 2", len(fields))
	}
	if fields[0] != "user.ssn" || fields[1] != "card.number" {
		t.Errorf("input.directives[0].fields = %v, want [user.ssn card.number]", fields)
	}
}

func TestBuildRegoInput_MultipleDirectives(t *testing.T) {
	req := &capability.EnforceRequest{
		SessionID:  "sess-h4",
		TargetName: "tool:export_data",
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"secret"}},
			&capability.RedactFieldsDirective{Fields: []string{"token"}},
		},
	}

	input, err := enforcement.BuildRegoInput(context.Background(), req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	slice, ok := input["directives"].([]interface{})
	if !ok || len(slice) != 2 {
		t.Fatalf("input.directives = %v, want 2 entries", input["directives"])
	}
}

// ── input.directives fails closed on an unserializable directive ──────────────

// unserializableDirective is a Directive whose payload type is unknown to
// capability.marshalDirective, so DirectiveWrapper.MarshalJSON returns an error.
// It models a future or programmatically constructed directive that is not
// JSON-roundtrippable — exactly the case that used to be silently dropped.
type unserializableDirective struct{}

func (unserializableDirective) DirectiveType() string               { return "unserializable" }
func (unserializableDirective) ToObligation() capability.Obligation { return capability.Obligation{} }

func TestBuildRegoInput_UnserializableDirective_ReturnsError(t *testing.T) {
	// A directive that cannot be marshaled must surface as an error rather than
	// being silently dropped from input.directives, so the caller (a
	// PolicyEvaluator) can fail closed instead of deciding on a short slice.
	req := &capability.EnforceRequest{
		SessionID:  "sess-bad-directive",
		TargetName: "tool:export_data",
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"user.ssn"}},
			unserializableDirective{},
		},
	}

	input, err := enforcement.BuildRegoInput(context.Background(), req)
	if err == nil {
		t.Fatal("BuildRegoInput must return an error when a directive cannot be serialized; got nil")
	}
	if input != nil {
		t.Errorf("BuildRegoInput must return a nil input on error; got %v", input)
	}
}

func TestEvaluateConditions_UnserializableDirective_FailsClosed(t *testing.T) {
	// The fail-closed chain end to end: a constraint carrying a directive that
	// cannot be serialized must make a policy evaluator that builds Rego input
	// deny, rather than evaluate against a silently shortened input.directives.
	// This exercises the full engine -> policy condition -> evaluator ->
	// BuildRegoInput error -> deny path that this PR exists to protect.
	var captured map[string]interface{}
	spy := &spyDirectiveEvaluator{out: &captured}
	e := enforcement.New(enforcement.WithPolicyEvaluator(spy))

	constraint := capability.Constraint{
		Target:  "export",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			capability.PolicyCondition{Backend: "opa"},
		},
		Directives: []capability.Directive{
			unserializableDirective{},
		},
	}
	req := &capability.EnforceRequest{SessionID: "sess-fc", TargetName: "export"}

	resp := e.EvaluateConditions(context.Background(), req, &constraint)
	if resp.Decision != capability.DecisionDeny {
		t.Errorf("decision = %q, want deny when a directive cannot be serialized", resp.Decision)
	}
	if captured != nil {
		t.Error("evaluator must not capture Rego input when BuildRegoInput fails closed")
	}
}

// ── input.arguments always {} — never null ──────────────────────────────────────

func TestBuildRegoInput_ArgumentsAlwaysPresent_NoArgs(t *testing.T) {
	// system:sampling/createMessage carries no arguments. BuildRegoInput must
	// still emit "arguments": {} so Rego policies don't need a null guard.
	req := &capability.EnforceRequest{
		SessionID:  "sess-h5",
		TargetName: "system:sampling/createMessage",
		Arguments:  nil,
	}

	input, err := enforcement.BuildRegoInput(context.Background(), req)
	if err != nil {
		t.Fatalf("BuildRegoInput returned error: %v", err)
	}

	args, ok := input["arguments"].(map[string]interface{})
	if !ok {
		t.Fatalf("input.arguments type = %T, want map[string]interface{}", input["arguments"])
	}
	if args == nil {
		t.Error("input.arguments must not be nil for a no-arg target")
	}
	if len(args) != 0 {
		t.Errorf("input.arguments len = %d, want 0", len(args))
	}
}

// ── EvaluateConditions populates req.Directives from matched constraint ────────

func TestEvaluateConditions_PopulatesDirectivesOnReq(t *testing.T) {
	// When EvaluateConditions runs, it must populate req.Directives from the
	// matched constraint before conditions are evaluated, so that a spy
	// PolicyEvaluator calling BuildRegoInput sees the correct input.directives.
	var captured map[string]interface{}

	spy := &spyDirectiveEvaluator{out: &captured}
	e := enforcement.New(enforcement.WithPolicyEvaluator(spy))

	constraint := capability.Constraint{
		Target:  "export",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			capability.PolicyCondition{Backend: "opa"},
		},
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"sensitive"}},
		},
	}

	req := &capability.EnforceRequest{
		SessionID:  "sess-h6",
		TargetName: "export",
		Arguments:  map[string]interface{}{"format": "json"},
	}

	// spy always allows; we just want to capture the input
	e.EvaluateConditions(context.Background(), req, &constraint)

	if captured == nil {
		t.Fatal("spy policy evaluator was not called")
	}
	slice, ok := captured["directives"].([]interface{})
	if !ok {
		t.Fatalf("input.directives type = %T, want []interface{}", captured["directives"])
	}
	if len(slice) != 1 {
		t.Fatalf("input.directives len = %d, want 1", len(slice))
	}
	m, ok := slice[0].(map[string]interface{})
	if !ok || m["type"] != "redactFields" {
		t.Errorf("input.directives[0] = %v, want {type:redactFields, ...}", slice[0])
	}
}

func TestEvaluateConditions_NoDirectives_EmptySliceInRegoInput(t *testing.T) {
	// A constraint with no directives must produce "directives": [] in Rego input.
	var captured map[string]interface{}

	spy := &spyDirectiveEvaluator{out: &captured}
	e := enforcement.New(enforcement.WithPolicyEvaluator(spy))

	constraint := capability.Constraint{
		Target:  "query_db",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			capability.PolicyCondition{Backend: "opa"},
		},
	}
	req := &capability.EnforceRequest{TargetName: "query_db"}

	e.EvaluateConditions(context.Background(), req, &constraint)

	if captured == nil {
		t.Fatal("spy policy evaluator was not called")
	}
	slice, ok := captured["directives"].([]interface{})
	if !ok {
		t.Fatalf("input.directives type = %T, want []interface{}", captured["directives"])
	}
	if len(slice) != 0 {
		t.Errorf("input.directives len = %d, want 0 for no-directive constraint", len(slice))
	}
}

// ── ValidateAction populates req.Directives from matched constraint ────────────

func TestValidateAction_PopulatesDirectivesOnReq(t *testing.T) {
	// ValidateAction must also set req.Directives before running conditions so
	// that a policy condition gets the correct input.directives.
	var captured map[string]interface{}

	spy := &spyDirectiveEvaluator{out: &captured}
	e := enforcement.New(enforcement.WithPolicyEvaluator(spy))

	constraints := []capability.Constraint{{
		Target:  "export",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			capability.PolicyCondition{Backend: "opa"},
		},
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"pii"}},
		},
	}}

	req := &capability.EnforceRequest{TargetName: "export"}
	e.ValidateAction(context.Background(), req, constraints)

	if captured == nil {
		t.Fatal("spy policy evaluator was not called")
	}
	slice, ok := captured["directives"].([]interface{})
	if !ok || len(slice) != 1 {
		t.Errorf("input.directives = %v, want 1 entry", captured["directives"])
	}
}

// ── Backward compatibility: input.arguments-only policies unaffected ──────────

func TestExistingArgumentsPoliciesUnaffected(t *testing.T) {
	// A policy condition that only reads input.arguments must continue to
	// receive the correct arguments, unaffected by the new directives field.
	var captured map[string]interface{}

	spy := &spyDirectiveEvaluator{out: &captured}
	e := enforcement.New(enforcement.WithPolicyEvaluator(spy))

	constraint := capability.Constraint{
		Target:  "read_file",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			capability.PolicyCondition{Backend: "opa"},
		},
	}
	req := &capability.EnforceRequest{
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": "/reports/q3.pdf"},
	}

	e.EvaluateConditions(context.Background(), req, &constraint)

	if captured == nil {
		t.Fatal("spy policy evaluator was not called")
	}
	args, ok := captured["arguments"].(map[string]interface{})
	if !ok {
		t.Fatalf("input.arguments type = %T", captured["arguments"])
	}
	if args["path"] != "/reports/q3.pdf" {
		t.Errorf("input.arguments.path = %v, want /reports/q3.pdf", args["path"])
	}
}

// ── spyDirectiveEvaluator ─────────────────────────────────────────────────────

// spyDirectiveEvaluator always allows and records the Rego input it receives.
type spyDirectiveEvaluator struct {
	out *map[string]interface{}
}

func (s *spyDirectiveEvaluator) Evaluate(
	ctx context.Context,
	_ string, _, _ interface{},
	req *capability.EnforceRequest,
) *enforcement.ConditionError {
	input, err := enforcement.BuildRegoInput(ctx, req)
	if err != nil {
		return &enforcement.ConditionError{Code: "POLICY_DENY", Message: err.Error()}
	}
	*s.out = input
	return nil
}

// ---- merged from resource_target_test.go ----

// TestMaxCalls_ResourceTarget_NoToolName is the regression: a maxCalls
// condition on a non-tool capability (resources/read, prompts/get, …) carries the
// identifier in req.Target.Name, not req.TargetName. Before the fix the maxCalls bucket derivation
// denied every such call with a misleading "tool name is required" MISSING_CONTEXT
// before any count check, and never keyed the counter. It must now fall back to
// req.Target.Name and enforce the limit.
func TestMaxCalls_ResourceTarget_NoToolName(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	matched := &capability.Constraint{
		Target:  "resource:file:///data/secret",
		Actions: []string{"read"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 1, WindowSeconds: 60},
		},
	}
	newReq := func() *capability.EnforceRequest {
		return &capability.EnforceRequest{
			SessionID: "sess-r",
			// ToolName intentionally empty: a resource read carries its identifier
			// in Target.Name.
			Target: &capability.EnforceRequestTarget{Type: "resource", Name: "file:///data/secret"},
		}
	}

	// First read is allowed (count 1 of 1) — NOT denied as "tool name required".
	resp := engine.EvaluateConditions(context.Background(), newReq(), matched)
	require.Equal(t, capability.DecisionAllow, resp.Decision,
		"first read must be allowed, not denied with a missing-tool-name error: %+v", resp.Denial)

	// Second read is denied by the rate limit, proving the counter was keyed on the
	// resource name rather than rejected before counting.
	resp = engine.EvaluateConditions(context.Background(), newReq(), matched)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeMaxCalls, resp.Denial.ConditionType)
}

// TestSequenceBlock_ResourceTarget_BlockedNameInDetails is the regression:
// when the blocked target is a resource (req.TargetName empty, the URI in
// req.Target.Name), the denial audit details must carry the resource name, not a
// bare "resource:".
func TestSequenceBlock_ResourceTarget_BlockedNameInDetails(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	ctx := context.Background()

	// Record the antecedent tool so the sequenceBlock fires.
	require.NoError(t, engine.RecordSessionCall(ctx, &capability.EnforceRequest{
		SessionID:  "sess-r",
		TargetName: "read_credentials",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_credentials"},
	}))

	blocked := &capability.EnforceRequest{
		SessionID: "sess-r",
		// ToolName empty: the blocked target is a resource.
		Target: &capability.EnforceRequestTarget{Type: "resource", Name: "file:///data/out"},
	}
	matched := &capability.Constraint{
		Target:  "resource:file:///data/out",
		Actions: []string{"read"},
		Conditions: []capability.Condition{
			&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
		},
	}

	resp := engine.EvaluateConditions(ctx, blocked, matched)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	bt, _ := resp.Denial.Details["blockedTool"].(string)
	assert.Equal(t, "resource:file:///data/out", bt,
		"blockedTool must carry the resource name, not a bare \"resource:\"")
}

// ---- merged from sequence_block_test.go ----

// callOnce drives one tool call through the engine against the supplied
// capabilities and returns the decision response.
func callOnce(t *testing.T, engine *enforcement.Engine, sessionID, tool string, caps []capability.Constraint) capability.EnforceResponse {
	t.Helper()
	req := capability.EnforceRequest{SessionID: sessionID, TargetName: tool}
	resp := engine.ValidateAction(context.Background(), &req, caps)
	return resp
}

// exfilCaps models the canonical sequential-exfiltration policy: read_credentials
// is freely callable, but write_external is denied once read_credentials has run
// in the same session.
func exfilCaps() []capability.Constraint {
	return []capability.Constraint{
		{Target: "tool:read_credentials", Actions: []string{"call"}},
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
			},
		},
	}
}

func TestSequenceBlock_BlocksWriteAfterRead(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := exfilCaps()

	// read_credentials → allowed, and recorded in session history.
	resp := callOnce(t, engine, "sess-1", "read_credentials", caps)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)

	// write_external → denied because read_credentials ran first.
	resp = callOnce(t, engine, "sess-1", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, "tool:read_credentials", resp.Denial.Details["afterTool"])
}

// TestSequenceBlock_BlockedCallReArmsHistory pins the retention semantics: a blocked
// call that FINDS the antecedent marker re-arms it, so the 24h history window measures
// inactivity of the antecedent/blocked pair rather than age since the antecedent's own
// call. Without the re-arm the gate expired purely by wall-clock — a session that read
// credentials once was allowed to write externally a day later, a time-based fail-OPEN
// of a security gate.
//
// The counter's own clock governs the window, so the fake time func drives it.
func TestSequenceBlock_BlockedCallReArmsHistory(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}))
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	caps := exfilCaps()

	require.Equal(t, capability.DecisionAllow,
		callOnce(t, engine, "sess-1", "read_credentials", caps).Decision)

	// Three probes, each 20h after the previous. The antecedent is never called again,
	// so by the third probe 60h have passed since it ran — well past the 24h window.
	// Each denial must re-arm the marker, keeping the next probe inside the window.
	for i, label := range []string{"20h", "40h", "60h"} {
		advance(20 * time.Hour)
		resp := callOnce(t, engine, "sess-1", "write_external", caps)
		require.Equalf(t, capability.DecisionDeny, resp.Decision,
			"probe %d (%s after the antecedent) must stay blocked: each denial re-arms the marker", i+1, label)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	}
}

// TestSequenceBlock_HistoryExpiresAfterFullInactivity is the other half of the
// retention contract: the re-arm above extends the window on ACTIVITY, it does not
// make the marker permanent. A session that goes quiet on both legs past the window
// loses the gate — the documented limitation, pinned here so a change to the retention
// semantics is deliberate rather than incidental.
func TestSequenceBlock_HistoryExpiresAfterFullInactivity(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}))
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	caps := exfilCaps()

	require.Equal(t, capability.DecisionAllow,
		callOnce(t, engine, "sess-1", "read_credentials", caps).Decision)

	// No activity on either leg for longer than the window.
	mu.Lock()
	now = now.Add(25 * time.Hour)
	mu.Unlock()

	assert.Equal(t, capability.DecisionAllow,
		callOnce(t, engine, "sess-1", "write_external", caps).Decision,
		"the marker is reclaimed after a full window of inactivity on both legs")
}

// TestSequenceBlock_BlocksAfterManyAntecedentCalls guards the cap at
// the engine level. RecordSessionCall now retains only the most-recent history
// marker (maxEntries=1) instead of one per call, so a high-rate antecedent no
// longer grows the session-history slice without bound. Presence (Peek > 0) must
// still be preserved, so write_external is denied however many times
// read_credentials ran.
func TestSequenceBlock_BlocksAfterManyAntecedentCalls(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := exfilCaps()

	for i := 0; i < 1000; i++ {
		require.Equal(t, capability.DecisionAllow,
			callOnce(t, engine, "sess-1", "read_credentials", caps).Decision,
			"antecedent call %d must stay allowed", i)
	}

	resp := callOnce(t, engine, "sess-1", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
}

// TestSequenceBlock_AntecedentWithTrailingWhitespaceStillBlocks is the
// regression: when the antecedent is called with a tool name carrying trailing
// whitespace ("read_credentials "), RecordSessionCall must canonicalize the name
// (TrimSpace) before keying session history, so the later sequenceBlock lookup —
// which trims its afterTools entries — finds the antecedent and still DENIES the
// gated tool. Before the fix the recording key kept the space, the lookup key did
// not, and the mismatch let write_external through (fail open).
func TestSequenceBlock_AntecedentWithTrailingWhitespaceStillBlocks(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	// A glob antecedent cap so a tool name carrying a trailing space still matches
	// and is allowed/recorded — the precondition for the recording-vs-lookup key
	// mismatch the fix closes. (An exact-target cap would reject the spaced name at
	// matching and never reach recording.)
	caps := []capability.Constraint{
		{Target: "tool:read_*", Actions: []string{"call"}},
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
			},
		},
	}

	// Antecedent called with a trailing space in the tool name.
	resp := callOnce(t, engine, "sess-1", "read_credentials ", caps)
	require.Equal(t, capability.DecisionAllow, resp.Decision)

	// The gated tool must still be denied: the antecedent ran, recorded under the
	// trimmed name that the sequenceBlock lookup uses.
	resp = callOnce(t, engine, "sess-1", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision, "trailing whitespace on the antecedent must not bypass sequenceBlock")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
}

func TestSequenceBlock_AllowsWriteBeforeRead(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := exfilCaps()

	// write_external first → allowed (read_credentials has not run yet). This is
	// the maxCalls-semantics gap the condition closes: ordering matters.
	resp := callOnce(t, engine, "sess-1", "write_external", caps)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)

	// read_credentials afterwards → still allowed.
	resp = callOnce(t, engine, "sess-1", "read_credentials", caps)
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestSequenceBlock_IsSessionScoped(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := exfilCaps()

	// read_credentials in session A must not gate write_external in session B.
	assert.Equal(t, capability.DecisionAllow, callOnce(t, engine, "sess-A", "read_credentials", caps).Decision)
	assert.Equal(t, capability.DecisionAllow, callOnce(t, engine, "sess-B", "write_external", caps).Decision)
	// But within session A the block holds.
	assert.Equal(t, capability.DecisionDeny, callOnce(t, engine, "sess-A", "write_external", caps).Decision)
}

// TestSequenceBlock_ColonSessionScopedIndependently checks that sessions whose
// IDs differ only by where a ":" falls keep independent sequenceBlock history.
// Session IDs are unconstrained strings that may contain the ":"
// the history key uses internally as a field separator; the length-prefixed key
// keeps each (session, type, target) tuple in its own bucket so one session's
// recorded antecedent cannot leak into a neighbouring session's lookup. The
// key-level injectivity is proven directly in counter_key_internal_test.go; this
// exercises the same property end to end through the engine.
func TestSequenceBlock_ColonSessionScopedIndependently(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := exfilCaps()

	// In session "a:b", read_credentials arms the block, so write_external denies.
	require.Equal(t, capability.DecisionAllow, callOnce(t, engine, "a:b", "read_credentials", caps).Decision)
	require.Equal(t, capability.DecisionDeny, callOnce(t, engine, "a:b", "write_external", caps).Decision)

	// Sessions "a" and "b" never ran read_credentials, so their write_external is
	// allowed: the colon in "a:b" must not leak history into a neighbouring key.
	assert.Equal(t, capability.DecisionAllow, callOnce(t, engine, "a", "write_external", caps).Decision)
	assert.Equal(t, capability.DecisionAllow, callOnce(t, engine, "b", "write_external", caps).Decision)
}

func TestSequenceBlock_ToleratesNamespacePrefixInAfterTools(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{
		{Target: "tool:read_credentials", Actions: []string{"call"}},
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				// Authored with a "tool:" prefix — must still match the bare name.
				&capability.SequenceBlockCondition{AfterTools: []string{"tool:read_credentials"}},
			},
		},
	}

	assert.Equal(t, capability.DecisionAllow, callOnce(t, engine, "s", "read_credentials", caps).Decision)
	assert.Equal(t, capability.DecisionDeny, callOnce(t, engine, "s", "write_external", caps).Decision)
}

func TestSequenceBlock_DeniedAntecedentDoesNotArm(t *testing.T) {
	// An antecedent call that is itself DENIED never reaches the upstream and
	// must not arm the block: recording happens only on allow.
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{
		// read_credentials is capped at zero useful calls via a sequenceBlock on
		// itself is awkward; instead model denial by a maxCalls:0-style limit is
		// not available, so use a non-matching argument condition: allowedValues
		// on a missing arg always denies.
		{
			Target:  "tool:read_credentials",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: "mode", Values: []interface{}{"never"}},
			},
		},
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
			},
		},
	}

	// read_credentials is denied (missing required argument), so it is not recorded.
	assert.Equal(t, capability.DecisionDeny, callOnce(t, engine, "s", "read_credentials", caps).Decision)
	// write_external therefore proceeds — the antecedent never actually ran.
	assert.Equal(t, capability.DecisionAllow, callOnce(t, engine, "s", "write_external", caps).Decision)
}

func TestSequenceBlock_EmptyAfterToolsFailsClosed(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: nil},
			},
		},
	}

	resp := callOnce(t, engine, "s", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
}

func TestSequenceBlock_AllEntriesStripToEmptyFailsClosed(t *testing.T) {
	// Every afterTools entry reduces to "" once its namespace prefix is stripped,
	// so none can ever match session history. Before the loop skipped
	// them all and returned allow — fail-open. The condition must now deny.
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{"tool:", "resource:"}},
			},
		},
	}

	resp := callOnce(t, engine, "s", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, []string{"tool:", "resource:"}, resp.Denial.Details["emptyAfterTools"])
}

func TestSequenceBlock_WhitespaceOnlyEntryFailsClosed(t *testing.T) {
	// A whitespace-only entry strips to non-empty whitespace but still names no
	// real tool — the same class of authoring error as "" or a bare "tool:". The
	// strip-then-trim guard must catch it rather than key history on a tool
	// literally named " ".
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{"tool: ", "  "}},
			},
		},
	}

	resp := callOnce(t, engine, "s", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, []string{"tool: ", "  "}, resp.Denial.Details["emptyAfterTools"])
}

func TestSequenceBlock_WhitespacePaddedNameStillMatches(t *testing.T) {
	// An entry padded with whitespace around a real name (e.g. " read_credentials ")
	// must still gate the block: history is keyed on the trimmed bare name, which
	// equals the whitespace-free recorded tool name.
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{
		{Target: "tool:read_credentials", Actions: []string{"call"}},
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{" read_credentials "}},
			},
		},
	}

	assert.Equal(t, capability.DecisionAllow, callOnce(t, engine, "s", "read_credentials", caps).Decision)
	assert.Equal(t, capability.DecisionDeny, callOnce(t, engine, "s", "write_external", caps).Decision)
}

func TestSequenceBlock_OneEntryStripsToEmptyFailsClosed(t *testing.T) {
	// A single empty-after-strip entry alongside a valid one is still an authoring
	// error: the author meant to name a tool and did not. Fail closed and surface
	// it rather than quietly honouring only the valid entries.
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials", "tool:"}},
			},
		},
	}

	resp := callOnce(t, engine, "s", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, []string{"tool:"}, resp.Denial.Details["emptyAfterTools"])
}

func TestSequenceBlock_EmptySessionIDFailsClosed(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := exfilCaps()

	resp := callOnce(t, engine, "", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeMissingContext, resp.Denial.Code)
}

func TestSequenceBlock_NoCounterFailsClosed(t *testing.T) {
	// Engine without a call counter cannot consult session history → deny.
	engine := enforcement.New()
	caps := exfilCaps()

	resp := callOnce(t, engine, "s", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
}

// callTyped drives one call through the engine with an explicit target type set
// on the request — as every ManifestPDP entry point does in production — so the
// recorded session-history key is namespaced by target type.
func callTyped(t *testing.T, engine *enforcement.Engine, sessionID, targetType, name string, caps []capability.Constraint) capability.EnforceResponse {
	t.Helper()
	req := capability.EnforceRequest{
		SessionID:  sessionID,
		TargetName: name,
		Target:     &capability.EnforceRequestTarget{Type: targetType, Name: name},
	}
	resp := engine.ValidateAction(context.Background(), &req, caps)
	return resp
}

func TestSequenceBlock_NamespacedByTargetType(t *testing.T) {
	// Regression: RecordSessionCall keys session history by target type,
	// so a tool named "export" and a prompt named "export" record into separate
	// seq: buckets instead of colliding on one. A sequenceBlock resolves each
	// afterTools entry's namespace from its prefix (a bare entry defaults to the
	// tool namespace), so it fires only when an antecedent of the *matching* type
	// ran earlier in the session.
	const name = "export"

	// A server exposing both a tool and a prompt named "export", plus a
	// write_external guarded by a sequenceBlock on the given afterTools entry.
	// The export constraints only need to allow the antecedent so it is recorded
	// — the recorded namespace comes from req.Target.Type, not the matched cap.
	capsBlocking := func(afterTool string) []capability.Constraint {
		return []capability.Constraint{
			{Target: "tool:export", Actions: []string{"*"}},
			{Target: "prompt:export", Actions: []string{"*"}},
			{
				Target:  "tool:write_external",
				Actions: []string{"call"},
				Conditions: []capability.Condition{
					&capability.SequenceBlockCondition{AfterTools: []string{afterTool}},
				},
			},
		}
	}
	// write_external is blocked once a *tool* named "export" has run (bare
	// afterTools entry -> tool namespace) ...
	blockOnToolExport := capsBlocking("export")
	// ... or once a *prompt* named "export" has run (explicit prompt: prefix
	// selects the prompt namespace).
	blockOnPromptExport := capsBlocking("prompt:export")

	t.Run("prompt antecedent does not trip a tool-keyed block", func(t *testing.T) {
		// Core of the bug: a prompts/get for prompt "export" must NOT satisfy a
		// sequenceBlock that names the tool "export". Before the fix both recorded
		// into seq:<session>:export and this call was a false-positive deny.
		engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
		assert.Equal(t, capability.DecisionAllow,
			callTyped(t, engine, "s", "prompt", name, blockOnToolExport).Decision)
		assert.Equal(t, capability.DecisionAllow,
			callTyped(t, engine, "s", "tool", "write_external", blockOnToolExport).Decision,
			"a same-named prompt must not trip a tool-keyed sequenceBlock")
	})

	t.Run("tool antecedent trips a tool-keyed block", func(t *testing.T) {
		// The matching namespace still fires: the tool "export" arms the block.
		engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
		assert.Equal(t, capability.DecisionAllow,
			callTyped(t, engine, "s", "tool", name, blockOnToolExport).Decision)
		resp := callTyped(t, engine, "s", "tool", "write_external", blockOnToolExport)
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
		// The denial names the antecedent by its namespace (audit clarity).
		assert.Equal(t, "tool:export", resp.Denial.Details["afterTool"])
		assert.Contains(t, resp.Denial.Message, `tool "export" was already called`)
	})

	t.Run("prompt antecedent trips a prompt-keyed block", func(t *testing.T) {
		// Authoring afterTools: [prompt:export] selects the prompt namespace, so
		// the prompt "export" arms the block.
		engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
		assert.Equal(t, capability.DecisionAllow,
			callTyped(t, engine, "s", "prompt", name, blockOnPromptExport).Decision)
		resp := callTyped(t, engine, "s", "tool", "write_external", blockOnPromptExport)
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.NotNil(t, resp.Denial)
		assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
		// A prompt antecedent is reported as such, not as a bare/"tool" name.
		assert.Equal(t, "prompt:export", resp.Denial.Details["afterTool"])
		assert.Contains(t, resp.Denial.Message, `prompt "export" was already called`)
	})

	t.Run("tool antecedent does not trip a prompt-keyed block", func(t *testing.T) {
		// The converse direction: a tools/call for tool "export" must NOT satisfy
		// a sequenceBlock that names prompt:export.
		engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
		assert.Equal(t, capability.DecisionAllow,
			callTyped(t, engine, "s", "tool", name, blockOnPromptExport).Decision)
		assert.Equal(t, capability.DecisionAllow,
			callTyped(t, engine, "s", "tool", "write_external", blockOnPromptExport).Decision,
			"a same-named tool must not trip a prompt-keyed sequenceBlock")
	})
}

// TestSequenceBlock_RecordsAntecedentFromTargetName is the regression: a
// direct caller may set req.Target (Type+Name) while leaving req.TargetName empty.
// RecordSessionCall must fall back to req.Target.Name to derive the bare tool
// name; otherwise the antecedent is never recorded and a later sequenceBlock
// Peek finds an empty key and fails OPEN.
func TestSequenceBlock_RecordsAntecedentFromTargetName(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{
		// A wildcard tool allow matches the antecedent even though its bare name
		// is carried only by Target (req.TargetName is empty).
		{Target: "tool:*", Actions: []string{"*"}},
		{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
			},
		},
	}

	// Antecedent: ToolName empty, name carried only by Target. Allowed by tool:*,
	// and the fix records it under the read_credentials history key.
	antecedent := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_credentials"},
	}
	resp := engine.ValidateAction(context.Background(), &antecedent, caps)
	require.Equal(t, capability.DecisionAllow, resp.Decision)

	// write_external must now be DENIED: the antecedent was recorded from
	// Target.Name, so the sequenceBlock Peek detects it (no fail-open).
	dep := callOnce(t, engine, "sess-1", "write_external", caps)
	require.Equal(t, capability.DecisionDeny, dep.Decision)
	require.NotNil(t, dep.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, dep.Denial.ConditionType)
}

// recordingErrorCounter is a capability.CallCounter whose IncrementAndGet — the
// write RecordSessionCall makes to arm a sequenceBlock — always fails, while the
// read methods succeed. It models a transient counter-backend fault (e.g. a brief
// Redis partition or a targeted key eviction) at the moment an allowed antecedent
// call is recorded.
type recordingErrorCounter struct{}

func (recordingErrorCounter) IncrementAndGet(_ context.Context, _ string, _, _ int) (int64, error) {
	return 0, errors.New("counter write failed")
}

func (recordingErrorCounter) Peek(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}

func (recordingErrorCounter) AdmitAll(_ context.Context, _ []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return true, 0, 0, 0, nil
}

// recordFailureMessage is the denial message emitted when session-history
// recording fails. Pinned here so both fail-closed tests assert the same wire
// text the engine returns.
const recordFailureMessage = "session history recording failed; sequenceBlock state is unreliable"

// TestSequenceBlock_RecordFailureFailsClosed asserts that when recording an
// otherwise-allowed call into session history fails, the call is DENIED rather
// than allowed. Swallowing the write error would leave the antecedent
// unrecorded, and a later sequenceBlock Peek on that empty key would conclude
// the antecedent never ran and fail OPEN.
func TestSequenceBlock_RecordFailureFailsClosed(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(recordingErrorCounter{}))
	caps := exfilCaps()

	// read_credentials carries no conditions and would normally be allowed and
	// recorded; the counter write fails, so the call must fail closed.
	resp := callOnce(t, engine, "sess-1", "read_credentials", caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	assert.Equal(t, recordFailureMessage, resp.Denial.Message)
	// phase=record marks this as a recording-path failure, distinct from an
	// actual sequenceBlock hit (which carries afterTool/blockedTool details).
	assert.Equal(t, "record", resp.Denial.Details["phase"])
}

// TestSequenceBlock_RecordFailureFailsClosed_EvaluateConditions covers the same
// fail-closed behavior on the EvaluateConditions entry point used by callers
// that have already selected the winning constraint.
func TestSequenceBlock_RecordFailureFailsClosed_EvaluateConditions(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(recordingErrorCounter{}))
	matched := &capability.Constraint{Target: "tool:read_credentials", Actions: []string{"call"}}
	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "read_credentials"}

	resp := engine.EvaluateConditions(context.Background(), req, matched)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	assert.Equal(t, recordFailureMessage, resp.Denial.Message)
	assert.Equal(t, "record", resp.Denial.Details["phase"])
}

// TestSequenceBlock_RecordFailureAuditModeIsAuditOnly asserts that under an
// audit-mode constraint a recording-path failure produces an AuditOnly denial
// (logged, call forwarded) rather than a hard block. A transient counter-backend
// fault during a staged "observe only" rollout must not silently convert the
// posture into a full block of every call.
func TestSequenceBlock_RecordFailureAuditModeIsAuditOnly(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(recordingErrorCounter{}))
	matched := &capability.Constraint{
		Target:      "tool:read_credentials",
		Actions:     []string{"call"},
		Enforcement: capability.EnforcementAudit,
	}
	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "read_credentials"}

	resp := engine.EvaluateConditions(context.Background(), req, matched)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, "record", resp.Denial.Details["phase"])
	// The crux: an audit-mode constraint downgrades the recording-failure
	// deny to observe-only so the call is forwarded, not hard-blocked.
	assert.True(t, resp.AuditOnly, "recording failure under audit mode must be AuditOnly")
}

// TestSequenceBlock_RecordFailureAuditModePreservesObligations asserts that an
// audit-mode recording-path failure preserves the obligations already collected
// from the matched constraint (e.g. redactFields). Because the AuditOnly denial
// is forwarded to upstream, dropping the obligations would leak fields the
// manifest marked for redaction.
func TestSequenceBlock_RecordFailureAuditModePreservesObligations(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(recordingErrorCounter{}))
	matched := &capability.Constraint{
		Target:      "tool:get_secret",
		Actions:     []string{"call"},
		Enforcement: capability.EnforcementAudit,
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"$.result.secret_value"}},
		},
	}
	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "get_secret"}

	resp := engine.EvaluateConditions(context.Background(), req, matched)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.True(t, resp.AuditOnly, "audit-mode recording failure must be AuditOnly (forwarded)")
	require.Len(t, resp.Obligations, 1, "redactFields obligation must survive the recording-failure path")
	assert.Equal(t, capability.DirectiveTypeRedactFields, resp.Obligations[0].Type)
	assert.Equal(t, []string{"$.result.secret_value"}, resp.Obligations[0].Paths)
}

// TestSequenceBlock_RecordFailureEnforceModeHardDenies is the counterpart: under
// the default (enforce) mode a recording failure is a hard deny, not AuditOnly.
func TestSequenceBlock_RecordFailureEnforceModeHardDenies(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(recordingErrorCounter{}))
	matched := &capability.Constraint{Target: "tool:read_credentials", Actions: []string{"call"}}
	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "read_credentials"}

	resp := engine.EvaluateConditions(context.Background(), req, matched)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.False(t, resp.AuditOnly, "recording failure under enforce mode must be a hard deny")
}

// TestSequenceBlock_SkipQuotaObservesDenial is the regression: the proxy's --audit
// (observe) mode uses WithSkipQuota, which must still EVALUATE sequenceBlock and
// RECORD session history so an operator observes the would-be denial — a
// read-then-write sequence yields a DENY under WithSkipQuota.
func TestSequenceBlock_SkipQuotaObservesDenial(t *testing.T) {
	caps := exfilCaps()
	readReq := &capability.EnforceRequest{SessionID: "s1", TargetName: "read_credentials"}
	writeReq := &capability.EnforceRequest{SessionID: "s1", TargetName: "write_external"}

	// WithSkipQuota: history recorded for the antecedent, sequenceBlock observed.
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	skipCtx := enforcement.WithSkipQuota(context.Background())
	resp := engine.ValidateAction(skipCtx, readReq, caps)
	require.Equal(t, capability.DecisionAllow, resp.Decision)
	resp = engine.ValidateAction(skipCtx, writeReq, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision,
		"WithSkipQuota must observe the sequenceBlock denial")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
}

// TestMaxCalls_SkipQuotaDoesNotConsume confirms the other half: audit
// mode (WithSkipQuota) must NOT consume MaxCalls quota — an observed call is
// logged-and-forwarded, not enforced — so a maxCalls:1 tool stays allowed across
// repeated observed calls.
func TestMaxCalls_SkipQuotaDoesNotConsume(t *testing.T) {
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	caps := []capability.Constraint{{
		Target:  "tool:x",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 1, WindowSeconds: 60},
		},
	}}
	skipCtx := enforcement.WithSkipQuota(context.Background())
	for i := 0; i < 3; i++ {
		resp := engine.ValidateAction(skipCtx, &capability.EnforceRequest{SessionID: "s", TargetName: "x"}, caps)
		require.Equalf(t, capability.DecisionAllow, resp.Decision,
			"WithSkipQuota must not consume maxCalls quota (call %d)", i+1)
	}
}

// TestEngine_MultiMaxCalls_AtomicUnderConcurrency proves the multi-maxCalls TOCTOU
// is closed end to end: a constraint carrying two maxCalls (each limit 1) admits
// exactly one of many concurrent same-session calls. The former per-bucket
// check->commit path could let several race past both checks and then all commit.
// Run with -race.
func TestEngine_MultiMaxCalls_AtomicUnderConcurrency(t *testing.T) {
	counter := callcounter.NewInMemory()
	e := enforcement.New(enforcement.WithCallCounter(counter))
	caps := []capability.Constraint{{
		Target:  "tool:export",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 1, WindowSeconds: 3600},
			&capability.MaxCallsCondition{Count: 1, WindowSeconds: 86400},
		},
	}}
	req := capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "export",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "export"},
	}

	const goroutines = 64
	var (
		mu       sync.Mutex
		allowCnt int
		start    = make(chan struct{})
		wg       sync.WaitGroup
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			r := req // per-goroutine copy (shares the read-only Target pointer)
			<-start
			resp := e.ValidateAction(context.Background(), &r, caps)
			if resp.Decision == capability.DecisionAllow {
				mu.Lock()
				allowCnt++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, 1, allowCnt, "two maxCalls of limit 1 must admit exactly one concurrent call")
}

// unwiredDirective is a Directive whose obligation type the engine does not know how to
// apply. CollectObligations returns a BlockOverride for it — an engine bug, not a verdict.
type unwiredDirective struct{}

func (unwiredDirective) DirectiveType() string { return "notARealDirective" }
func (unwiredDirective) ToObligation() capability.Obligation {
	return capability.Obligation{Type: "notARealDirective"}
}

// TestDirectives_CollectedOnDowngradableDeny is the counterpart to
// TestDirectives_NotCollectedWhenConditionFails: when a deny will be FORWARDED rather
// than blocked, it MUST carry the matched constraint's obligations.
//
// Under `enforcement: audit` (or a route-level --audit) the transport downgrades a deny
// to a forwarded call and applies redaction only when the response carries obligations.
// A downgradable deny built with nil obligations therefore hands the host the very fields
// the manifest marked for redaction — giving a request whose condition FAILED strictly
// fewer protections than one that passed. This exercises the raw exported API, the path
// an external embedder uses, which never reaches the ManifestPDP layer that fills the
// same gap for the shipped proxy.
func TestDirectives_CollectedOnDowngradableDeny(t *testing.T) {
	t.Parallel()

	newConstraint := func(auditOnly bool) capability.Constraint {
		c := capability.Constraint{
			Target:  "tool:read_file",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
			},
			Directives: []capability.Directive{
				&capability.RedactFieldsDirective{Fields: []string{"$.user.ssn"}},
			},
		}
		if auditOnly {
			c.Enforcement = "audit"
		}
		return c
	}
	req := func() *capability.EnforceRequest {
		return &capability.EnforceRequest{
			SessionID:  "sess-1",
			TargetName: "read_file",
			Arguments:  map[string]interface{}{"path": "/internal/secrets.txt"},
		}
	}
	assertRedacts := func(t *testing.T, resp capability.EnforceResponse) {
		t.Helper()
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		require.Len(t, resp.Obligations, 1, "a forwarded deny must carry the constraint's obligations")
		assert.Equal(t, capability.DirectiveTypeRedactFields, resp.Obligations[0].Type)
		assert.Equal(t, []string{"$.user.ssn"}, resp.Obligations[0].Paths)
	}

	t.Run("per-constraint enforcement:audit", func(t *testing.T) {
		t.Parallel()
		c := newConstraint(true)
		e := enforcement.New()
		assertRedacts(t, e.EvaluateConditions(context.Background(), req(), &c))
		assertRedacts(t, e.ValidateAction(context.Background(), req(), []capability.Constraint{c}))
	})

	t.Run("route-level --audit via SkipQuota", func(t *testing.T) {
		t.Parallel()
		c := newConstraint(false) // the CONSTRAINT enforces; the route observes
		e := enforcement.New()
		ctx := enforcement.WithSkipQuota(context.Background())
		assertRedacts(t, e.EvaluateConditions(ctx, req(), &c))
		assertRedacts(t, e.ValidateAction(ctx, req(), []capability.Constraint{c}))
	})

	// The argumentSchema deny returns from ValidateAction BEFORE evaluateMatched, so it
	// needs the rule restated at its own site; without it this leg forwards unredacted.
	t.Run("argumentSchema deny is downgradable too", func(t *testing.T) {
		t.Parallel()
		c := newConstraint(true)
		c.Conditions = nil
		c.ArgumentSchema = &capability.ArgumentSchema{Required: []string{"absent_field"}}
		e := enforcement.New()
		assertRedacts(t, e.ValidateAction(context.Background(), req(), []capability.Constraint{c}))
	})

	// The control: a BLOCKING deny is never forwarded, so it must stay free of
	// obligations — their presence on a deny keeps meaning "really a forward".
	t.Run("blocking deny still carries none", func(t *testing.T) {
		t.Parallel()
		c := newConstraint(false)
		e := enforcement.New()
		resp := e.ValidateAction(context.Background(), req(), []capability.Constraint{c})
		require.Equal(t, capability.DecisionDeny, resp.Decision)
		assert.Empty(t, resp.Obligations)
	})
}

// TestUnwiredDirective_DoesNotPreemptTheConditionVerdict pins the ordering that keeps a
// wiretap route from blocking. CollectObligations runs before the conditions so its
// result can be stamped onto a downgradable deny, but its DENY must still be returned
// where the original ordering returned it: after runConditions. Returning it early would
// preempt the condition verdict, and an unwired directive produces a BlockOverride — which
// isObserveDeny refuses to downgrade, so an audit-mode constraint documented never to
// block would start BLOCKING live traffic.
func TestUnwiredDirective_DoesNotPreemptTheConditionVerdict(t *testing.T) {
	t.Parallel()
	constraint := capability.Constraint{
		Target:      "tool:read_file",
		Actions:     []string{"call"},
		Enforcement: "audit",
		Conditions: []capability.Condition{
			&capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
		},
		Directives: []capability.Directive{unwiredDirective{}},
	}
	req := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": "/internal/secrets.txt"},
	}

	resp := enforcement.New().ValidateAction(context.Background(), req, []capability.Constraint{constraint})
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeValueNotPermitted, resp.Denial.Code,
		"the condition verdict must win; an unwired directive must not preempt it")
	assert.False(t, resp.Denial.BlockOverride, "an audit-mode route must not be made to block")

	// With the conditions PASSING, the unwired directive is still caught — a real engine
	// bug must hard-deny rather than be silently skipped.
	req.Arguments["path"] = "/reports/q3.txt"
	bug := enforcement.New().ValidateAction(context.Background(), req, []capability.Constraint{constraint})
	require.Equal(t, capability.DecisionDeny, bug.Decision)
	require.NotNil(t, bug.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, bug.Denial.Code)
	assert.False(t, bug.Denial.Downgradable(), "an unwired directive must block even under audit mode")
	assert.Empty(t, bug.Obligations, "a hard deny carries no obligations")
}

// TestUnwiredDirective_DoesNotDropASiblingsObligations pins that CollectObligations keeps
// already-collected redactions when a LATER directive carries an unknown obligation type.
// evaluateMatched calls CollectObligations UP FRONT and
// stamps whatever it collected onto a LATER, unrelated condition-driven deny via a
// deferred closure — the ordering TestUnwiredDirective_DoesNotPreemptTheConditionVerdict
// pins. Before the fix, CollectObligations discarded every already-collected obligation
// the moment it hit the sibling unwired directive, so the condition-driven deny (which
// never even reaches the unwired directive's own hard-block path) was forwarded on an
// audit-mode route with its redactFields silently dropped — the field the manifest marked
// for redaction reached the host intact.
func TestUnwiredDirective_DoesNotDropASiblingsObligations(t *testing.T) {
	t.Parallel()
	constraint := capability.Constraint{
		Target:      "tool:read_file",
		Actions:     []string{"call"},
		Enforcement: "audit",
		Conditions: []capability.Condition{
			&capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
		},
		// redactFields collects successfully BEFORE the loop reaches the unwired
		// directive; the condition below denies before CollectObligations's own error
		// return is ever consulted, so this deny's obligations come only from the
		// up-front partial collection.
		Directives: []capability.Directive{
			&capability.RedactFieldsDirective{Fields: []string{"$.user.ssn"}},
			unwiredDirective{},
		},
	}
	req := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": "/internal/secrets.txt"},
	}

	resp := enforcement.New().ValidateAction(context.Background(), req, []capability.Constraint{constraint})
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeValueNotPermitted, resp.Denial.Code, "the condition verdict must still win")
	assert.False(t, resp.Denial.BlockOverride, "an audit-mode route must not be made to block")
	require.Len(t, resp.Obligations, 1,
		"a sibling directive's unwired obligation type must not drop this forwarded deny's redactFields")
	assert.Equal(t, capability.DirectiveTypeRedactFields, resp.Obligations[0].Type)
	assert.Equal(t, []string{"$.user.ssn"}, resp.Obligations[0].Paths)
}

// TestNoMatchDeny_CarriesObligationsWhenForwarded covers the last downgradable deny the
// engine produces: no constraint was selected for this caller, yet a route running
// --audit forwards the call anyway. The obligations come from every capability NAMING the
// target, regardless of principal scoping.
func TestNoMatchDeny_CarriesObligationsWhenForwarded(t *testing.T) {
	t.Parallel()
	// Principal-scoped, so it does not match a claimless request — but it names the target.
	caps := []capability.Constraint{{
		Target:     "tool:read_*",
		Actions:    []string{"call"},
		Principal:  map[string][]string{"agent_id": {"someone-else"}},
		Directives: []capability.Directive{&capability.RedactFieldsDirective{Fields: []string{"$.user.ssn"}}},
	}}
	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "read_file"}
	e := enforcement.New()

	forwarded := e.ValidateAction(enforcement.WithSkipQuota(context.Background()), req, caps)
	require.Equal(t, capability.DecisionDeny, forwarded.Decision)
	require.Len(t, forwarded.Obligations, 1, "a forwarded no-match deny must still redact")
	assert.Equal(t, []string{"$.user.ssn"}, forwarded.Obligations[0].Paths)

	// On an enforce route the same deny BLOCKS, so it carries nothing.
	blocked := e.ValidateAction(context.Background(), req, caps)
	require.Equal(t, capability.DecisionDeny, blocked.Decision)
	assert.Empty(t, blocked.Obligations)
}

// ctxHonoringCounter wraps a CallCounter and fails every operation whose context is
// already cancelled, the way the Redis backend does (its pipeline Exec propagates
// cancellation). The in-memory backend ignores ctx entirely, so without this wrapper
// no test can see a cancellation-sensitive bug on the counter path.
type ctxHonoringCounter struct{ inner capability.CallCounter }

func (c ctxHonoringCounter) IncrementAndGet(ctx context.Context, key string, windowSec, maxEntries int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return c.inner.IncrementAndGet(ctx, key, windowSec, maxEntries)
}

func (c ctxHonoringCounter) Peek(ctx context.Context, key string, windowSec int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return c.inner.Peek(ctx, key, windowSec)
}

func (c ctxHonoringCounter) AdmitAll(ctx context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	if err := ctx.Err(); err != nil {
		return false, 0, 0, 0, err
	}
	return c.inner.AdmitAll(ctx, buckets)
}

// TestSequenceBlock_ReArmSurvivesRequestCancellation closes the bypass in the re-arm
// itself: the host request context is cancelled the moment a client disconnects, and
// a backend that honors ctx (Redis does) would then drop the re-arm write. A client
// that probes the blocked target and immediately drops the connection is still denied
// each time, but without a detached context it never refreshes the marker — so the
// gate reverts to expiring on pure wall clock, which is precisely the fail-open the
// re-arm exists to close, triggerable at will.
func TestSequenceBlock_ReArmSurvivesRequestCancellation(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	counter := ctxHonoringCounter{inner: callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}))}
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	caps := exfilCaps()

	require.Equal(t, capability.DecisionAllow,
		engine.ValidateAction(context.Background(),
			&capability.EnforceRequest{SessionID: "sess-1", TargetName: "read_credentials"}, caps).Decision)

	// Probe the blocked target every 20h with a context that is ALREADY cancelled,
	// modelling a client that disconnects the instant it sends the request.
	for i := 0; i < 3; i++ {
		mu.Lock()
		now = now.Add(20 * time.Hour)
		mu.Unlock()

		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		resp := engine.ValidateAction(cancelled,
			&capability.EnforceRequest{SessionID: "sess-1", TargetName: "write_external"}, caps)
		require.Equalf(t, capability.DecisionDeny, resp.Decision,
			"probe %d must be denied even with a cancelled context", i+1)
	}

	// 60h after the antecedent, with no uncancelled traffic in between, a clean probe
	// must STILL be blocked: the cancelled probes re-armed the marker.
	resp := engine.ValidateAction(context.Background(),
		&capability.EnforceRequest{SessionID: "sess-1", TargetName: "write_external"}, caps)
	require.Equal(t, capability.DecisionDeny, resp.Decision,
		"a client that disconnects on every probe must not be able to age the gate out")
}
