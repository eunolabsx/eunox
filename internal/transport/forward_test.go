// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/mcp/mcptest"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fwdCapturedRecord struct {
	decision      string
	code          string
	details       map[string]interface{}
	obligs        []string
	auditOnly     bool
	labelsOut     []string
	carriedLabels []string
	labelsCleared []string
	approver      string
	approvalID    string
	identifier    string
	sessionID     string
	// revision is read off the context the recorder was called with — the ONE carrier the real
	// sink stamps protocol_revision from, so a test asserting on it exercises the same seam.
	revision capability.Revision
}

type fwdRecorder struct {
	records []fwdCapturedRecord
	// degraded/reason/detail drive the AuditDegraded report so the
	// --require-audit=strict gate can be exercised without a real failing sink.
	// reason is host-facing prose; detail is the discrete counts stamped into the
	// structured deny record. Default zero value = healthy.
	degraded bool
	reason   string
	detail   map[string]interface{}
	// degradeOnRecord, when set, flips degraded (and reason) to true the moment
	// RecordAllow/RecordDeny is called — simulating a sink whose OWN enqueue for
	// THIS call is what trips degradation, for exercising
	// warnIfStrictAuditJustDegraded's healthy-before/degraded-after detection.
	degradeOnRecord bool
}

func (f *fwdRecorder) RecordAllow(_ context.Context, sessionID, identifier, _ string, details map[string]interface{}, obligs []string, auditOnly bool, labelsOut, carriedLabels []string) {
	f.records = append(f.records, fwdCapturedRecord{
		decision: "allow", details: details, obligs: obligs, auditOnly: auditOnly, identifier: identifier, labelsOut: labelsOut, carriedLabels: carriedLabels, sessionID: sessionID,
	})
	if f.degradeOnRecord {
		f.degraded = true
		f.reason = "audit trail degraded: 1 record(s) dropped under back-pressure"
	}
}

func (f *fwdRecorder) RecordDeclassifiedAllow(_ context.Context, sessionID, identifier, _ string, details map[string]interface{}, obligs []string, auditOnly bool, labelsOut, carriedLabels, labelsCleared []string, approver, approvalID string) {
	f.records = append(f.records, fwdCapturedRecord{
		decision: "allow", details: details, obligs: obligs, auditOnly: auditOnly, identifier: identifier, labelsOut: labelsOut, carriedLabels: carriedLabels, labelsCleared: labelsCleared, approver: approver, approvalID: approvalID, sessionID: sessionID,
	})
	if f.degradeOnRecord {
		f.degraded = true
		f.reason = "audit trail degraded: 1 record(s) dropped under back-pressure"
	}
}

func (f *fwdRecorder) RecordDeny(ctx context.Context, sessionID, identifier, _, denialCode, _ string, details map[string]interface{}, observe bool) {
	f.records = append(f.records, fwdCapturedRecord{
		decision: "deny", code: denialCode, details: details, auditOnly: observe, identifier: identifier, sessionID: sessionID,
		revision: capability.ProtocolRevisionFromContext(ctx),
	})
	if f.degradeOnRecord {
		f.degraded = true
		f.reason = "audit trail degraded: 1 record(s) dropped under back-pressure"
	}
}

func (f *fwdRecorder) AuditDegraded() (degraded bool, reason string, detail map[string]interface{}) {
	return f.degraded, f.reason, f.detail
}

func allowDecision() capability.EnforceResponse {
	return capability.EnforceResponse{Decision: capability.DecisionAllow}
}

func TestUpstreamErrorDetail(t *testing.T) {
	assert.Nil(t, upstreamErrorDetail(mcp.RPCMsg{Result: json.RawMessage(`{}`)}),
		"a clean success must add no detail")
	got := upstreamErrorDetail(mcp.RPCMsg{Error: &mcp.RPCError{Code: -32000, Message: "boom: secret leaked"}})
	require.NotNil(t, got)
	assert.Equal(t, -32000, got[audit.UpstreamErrorCodeKey])
	// The upstream message can carry sensitive content; only the code is recorded.
	for _, v := range got {
		assert.NotContains(t, toString(v), "secret")
	}
}

func toString(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestEnforcedForwardCore_AllowRecordsUpstreamErrorDetail(t *testing.T) {
	rec := &fwdRecorder{}
	fp := forwardParams{
		rec:       rec,
		sessionID: "s",
		callUpstream: func(_ context.Context, _ mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{Error: &mcp.RPCError{Code: -32000, Message: "upstream said no"}}, nil
		},
	}
	resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	// The upstream's error response is forwarded to the host verbatim...
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32000, resp.Error.Code)
	// ...and the audit tape records an honest allow (the proxy authorized it) carrying
	// the upstream error code so it is distinguishable from a clean success.
	require.Len(t, rec.records, 1)
	assert.Equal(t, "allow", rec.records[0].decision)
	require.NotNil(t, rec.records[0].details)
	assert.Equal(t, -32000, rec.records[0].details[audit.UpstreamErrorCodeKey])
}

func TestEnforcedForwardCore_AllowCleanSuccessHasNoDetail(t *testing.T) {
	rec := &fwdRecorder{}
	fp := forwardParams{
		rec:       rec,
		sessionID: "s",
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
		},
	}
	resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	require.Nil(t, resp.Error)
	require.Len(t, rec.records, 1)
	assert.Equal(t, "allow", rec.records[0].decision)
	assert.Nil(t, rec.records[0].details, "a clean success must record no extra detail")
}

func TestEnforcedForwardCore_BlockOverrideDoesNotCallUpstream(t *testing.T) {
	rec := &fwdRecorder{}
	called := false
	fp := forwardParams{
		rec:       rec,
		sessionID: "s",
		callUpstream: func(_ context.Context, _ mcp.RPCMsg) (mcp.RPCMsg, error) {
			called = true
			return mcp.RPCMsg{}, nil
		},
	}
	dec := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: capability.ErrCodeCapabilityDenied},
	}
	resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, dec, "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	assert.False(t, called, "a hard deny must never reach the upstream")
	require.NotNil(t, resp.Error)
	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeCapabilityDenied, rec.records[0].code)
}

// TestEnforcedForwardCore_RedactionFailureRecordsDeny pins that when a
// redactFields obligation fails to apply to the upstream response, the call is
// NOT silently dropped from the audit trail: a deny is recorded (so an
// adversarial upstream cannot make a redactFields-guarded call vanish from the
// tape) and the host receives a generic internal error.
func TestEnforcedForwardCore_RedactionFailureRecordsDeny(t *testing.T) {
	rec := &fwdRecorder{}
	fp := forwardParams{
		rec:       rec,
		sessionID: "s",
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			// "content" present but not an array makes ApplyRedactObligs fail closed.
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"content":"not-an-array"}`)}, nil
		},
	}
	dec := capability.EnforceResponse{
		Decision:    capability.DecisionAllow,
		Obligations: []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"ssn"}}},
	}
	resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, dec, "tools/call", "read_file", "read_file", "tool", true, upstreamErrorDetail)

	require.NotNil(t, resp.Error, "host must receive an internal error when redaction fails")
	require.Len(t, rec.records, 1, "a redaction failure must still write exactly one audit record")
	assert.Equal(t, "deny", rec.records[0].decision, "redaction failure must record a deny, not silence")
	assert.Equal(t, capability.ErrCodeEnforcementError, rec.records[0].code)
}

// TestAuditObligationNames pins the token shape recorded in the audit log's
// obligations[] field: one "type:path" entry per matched redact path (so the tape
// shows WHICH fields were masked), a bare "type" token for an obligation that
// carries no paths, and flattening across multiple obligations.
func TestAuditObligationNames(t *testing.T) {
	t.Run("one token per path", func(t *testing.T) {
		got := auditObligationNames([]capability.Obligation{
			{Type: capability.DirectiveTypeRedactFields, Paths: []string{"$.ssn", "nested.token"}},
		})
		assert.Equal(t, []string{"redactFields:$.ssn", "redactFields:nested.token"}, got)
	})
	t.Run("bare type when no paths", func(t *testing.T) {
		got := auditObligationNames([]capability.Obligation{
			{Type: capability.DirectiveTypeRedactFields},
		})
		assert.Equal(t, []string{"redactFields"}, got)
	})
	t.Run("flattens across obligations", func(t *testing.T) {
		got := auditObligationNames([]capability.Obligation{
			{Type: capability.DirectiveTypeRedactFields, Paths: []string{"$.a"}},
			{Type: capability.DirectiveTypeRedactFields, Paths: []string{"$.b", "$.c"}},
		})
		assert.Equal(t, []string{"redactFields:$.a", "redactFields:$.b", "redactFields:$.c"}, got)
	})
	t.Run("nil for no obligations", func(t *testing.T) {
		assert.Nil(t, auditObligationNames(nil))
	})
}

// TestEnforcedForwardCore_RecordsRedactPaths pins that an allowed call whose matched
// constraint carries a redactFields directive records the masked field PATHS (one
// "type:path" token each), not merely the directive type, on the allow record — and
// that the subscription path (recordObligations=false) records none.
func TestEnforcedForwardCore_RecordsRedactPaths(t *testing.T) {
	newFP := func(rec *fwdRecorder) forwardParams {
		return forwardParams{
			rec:       rec,
			sessionID: "s",
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				// Free-form text content: redaction forwards it unchanged (no fail-closed),
				// so the allow path runs and the obligation tokens are recorded.
				return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"content":[{"type":"text","text":"hi"}]}`)}, nil
			},
		}
	}
	dec := capability.EnforceResponse{
		Decision:    capability.DecisionAllow,
		Obligations: []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"$.ssn", "nested.token"}}},
	}

	t.Run("tool call records type:path tokens", func(t *testing.T) {
		rec := &fwdRecorder{}
		resp := enforcedForwardCore(context.Background(), newFP(rec), nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, dec, "tools/call", "get_secret_record", "get_secret_record", "tool", true, upstreamErrorDetail)
		require.Nil(t, resp.Error)
		require.Len(t, rec.records, 1)
		assert.Equal(t, "allow", rec.records[0].decision)
		assert.Equal(t, []string{"redactFields:$.ssn", "redactFields:nested.token"}, rec.records[0].obligs)
	})

	t.Run("subscription records no obligation tokens", func(t *testing.T) {
		rec := &fwdRecorder{}
		_ = enforcedForwardCore(context.Background(), newFP(rec), nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, dec, "resources/subscribe", "memory:notes", "memory:notes", "resource subscription", false, upstreamErrorDetail)
		require.Len(t, rec.records, 1)
		assert.Nil(t, rec.records[0].obligs)
	})

	// An allowed redactFields call whose upstream returns a JSON-RPC ERROR result
	// (Result == nil) masks nothing — there is no body to redact — so the allow record
	// must NOT list the directive's fields as masked. obligations[] records WHICH
	// fields were masked, not merely that a directive was attached.
	t.Run("error result records no obligation tokens", func(t *testing.T) {
		rec := &fwdRecorder{}
		fp := forwardParams{
			rec:       rec,
			sessionID: "s",
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				// Upstream answered the (allowed) call with a JSON-RPC error envelope:
				// no result body, so the redaction block is skipped.
				return mcp.RPCMsg{ID: msg.ID, Error: &mcp.RPCError{Code: -32000, Message: "upstream boom"}}, nil
			},
		}
		resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, dec, "tools/call", "get_secret_record", "get_secret_record", "tool", true, upstreamErrorDetail)
		require.NotNil(t, resp.Error, "the upstream error must be forwarded to the host")
		require.Len(t, rec.records, 1)
		assert.Equal(t, "allow", rec.records[0].decision, "policy allowed the call, so it records an allow")
		assert.Nil(t, rec.records[0].obligs, "no result body was redacted, so no obligation tokens are recorded")
	})

	// An adversarial or misconfigured upstream can smuggle a redactable value through
	// error.data when it answers an allowed redactFields call with a JSON-RPC error.
	// The result-shaped redaction pass never runs (Result == nil), so error.data must
	// be stripped fail-closed rather than forwarded to the host unredacted.
	t.Run("error data stripped when redactFields obligation present", func(t *testing.T) {
		rec := &fwdRecorder{}
		fp := forwardParams{
			rec:       rec,
			sessionID: "s",
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				return mcp.RPCMsg{ID: msg.ID, Error: &mcp.RPCError{
					Code:    -32000,
					Message: "boom",
					Data:    json.RawMessage(`{"ssn":"123-45-6789"}`),
				}}, nil
			},
		}
		resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, dec, "tools/call", "get_secret_record", "get_secret_record", "tool", true, upstreamErrorDetail)
		require.NotNil(t, resp.Error, "the upstream error is still forwarded to the host")
		assert.Nil(t, resp.Error.Data, "error.data must be dropped fail-closed under a redactFields obligation")
		assert.Equal(t, "boom", resp.Error.Message, "the error message and code still reach the host")
	})

	// A malformed/adversarial upstream that returns BOTH a result and an error (JSON-RPC
	// forbids it, but a hostile upstream may still emit it) must not smuggle a
	// declared-redactable value through error.data by also attaching a redacted result.
	// The error.data strip is independent of the result-redaction branch.
	t.Run("error data stripped even when a result is also present", func(t *testing.T) {
		rec := &fwdRecorder{}
		fp := forwardParams{
			rec:       rec,
			sessionID: "s",
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				return mcp.RPCMsg{
					ID:     msg.ID,
					Result: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`),
					Error:  &mcp.RPCError{Code: -32000, Message: "boom", Data: json.RawMessage(`{"ssn":"123-45-6789"}`)},
				}, nil
			},
		}
		resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, dec, "tools/call", "get_secret_record", "get_secret_record", "tool", true, upstreamErrorDetail)
		require.NotNil(t, resp.Error, "the error object is still forwarded")
		assert.Nil(t, resp.Error.Data, "error.data must be dropped even when a result is present")
		assert.NotContains(t, string(resp.Result), "123-45-6789", "the secret must not leak via either channel")
	})

	// Without a redactFields obligation there is nothing to protect, so error.data
	// must pass through untouched.
	t.Run("error data preserved without redact obligation", func(t *testing.T) {
		rec := &fwdRecorder{}
		fp := forwardParams{
			rec:       rec,
			sessionID: "s",
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				return mcp.RPCMsg{ID: msg.ID, Error: &mcp.RPCError{
					Code:    -32000,
					Message: "boom",
					Data:    json.RawMessage(`{"detail":"diagnostic"}`),
				}}, nil
			},
		}
		noOblig := capability.EnforceResponse{Decision: capability.DecisionAllow}
		resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, noOblig, "tools/call", "get_record", "get_record", "tool", true, upstreamErrorDetail)
		require.NotNil(t, resp.Error)
		require.NotNil(t, resp.Error.Data, "error.data must be preserved when no redact obligation is attached")
		assert.Contains(t, string(resp.Error.Data), "diagnostic")
	})
}

// TestEnforcedForwardCore_NilDenialDoesNotPanic pins the fail-closed normalization
// of a deny decision whose Denial pointer is nil — a contract a third-party PDP
// reaching the exported seam could violate. The proxy must deny with a structured
// code, not crash the request goroutine.
func TestEnforcedForwardCore_NilDenialDoesNotPanic(t *testing.T) {
	rec := &fwdRecorder{}
	called := false
	fp := forwardParams{
		rec:       rec,
		sessionID: "s",
		callUpstream: func(_ context.Context, _ mcp.RPCMsg) (mcp.RPCMsg, error) {
			called = true
			return mcp.RPCMsg{}, nil
		},
	}
	dec := capability.EnforceResponse{Decision: capability.DecisionDeny} // Denial left nil
	resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, dec, "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	assert.False(t, called, "a nil-Denial deny must still hard-block the upstream")
	require.NotNil(t, resp.Error)
	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, rec.records[0].code,
		"a nil Denial must normalize to a structured AUTHORIZATION_FAILED")
}

// TestIsObserveDeny_Matrix pins the exact allow/deny matrix isObserveDeny
// enforces once denial has been normalized to non-nil (both call sites run it
// through normalizeDenial first, so isObserveDeny itself assumes non-nil): a
// kill-switch denial is never downgraded to an observed forward regardless of
// audit mode, a hard denial is never downgraded, and only a soft denial in
// audit or audit-only mode is downgraded to observe.
func TestIsObserveDeny_Matrix(t *testing.T) {
	soft := &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed, BlockOverride: false}
	hard := &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed, BlockOverride: true}
	killSwitch := &capability.DenialInfo{Code: capability.ErrCodeKillSwitch}

	cases := []struct {
		name             string
		denial           *capability.DenialInfo
		audit, auditOnly bool
		want             bool
	}{
		{"soft deny, no audit mode", soft, false, false, false},
		{"soft deny, route audit mode", soft, true, false, true},
		{"soft deny, per-entry audit-only", soft, false, true, true},
		{"hard deny, route audit mode never downgrades", hard, true, false, false},
		{"hard deny, per-entry audit-only never downgrades", hard, false, true, false},
		{"kill switch, route audit mode never downgrades", killSwitch, true, false, false},
		{"kill switch, per-entry audit-only never downgrades", killSwitch, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isObserveDeny(tc.denial, tc.audit, tc.auditOnly)
			assert.Equal(t, tc.want, got)
		})
	}
}

// breakMode names one way contractBreakingCommitHandler breaks the engine's PrepareCommit
// contract. Typed, and with no fall-through default, so a mistyped mode cannot silently select
// an arm nobody chose — this fixture is what distinguishes the union's arms from each other.
type breakMode int

const (
	modeSoftDeny breakMode = iota
	modeUnauthorizedSkip
	modeCommitUnderObserve
)

// contractBreakingCommitHandler is a committing condition handler that breaks the engine's
// PrepareCommit contract in one chosen way, so this package can observe what the transport
// does with each verdict pkg/enforcement produces for it. Its twin on the engine side is
// sentinelCommitHandler (pkg/enforcement/engine_internal_test.go), which encodes the same
// contract for that package's own tests; the two are kept in agreement by hand, since a shared
// fixture would have to live in a package pkg/enforcement's internal tests cannot import.
type contractBreakingCommitHandler struct{ mode breakMode }

func (h contractBreakingCommitHandler) PrepareCommit(context.Context, capability.Condition, *capability.EnforceRequest) (enforcement.DeferredCommit, bool, *enforcement.ConditionError) {
	switch h.mode {
	case modeSoftDeny:
		// A verdict, not a contract violation: an ordinary condition failure from the same path.
		return enforcement.DeferredCommit{}, false, &enforcement.ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeMaxCalls,
			Message:       "over limit",
		}
	case modeUnauthorizedSkip:
		return enforcement.DeferredCommit{}, true, nil
	case modeCommitUnderObserve:
		return enforcement.DeferredCommit{
			Bucket: capability.QuotaBucket{Key: "fault-bucket", WindowSec: 60, Counted: true, Limit: 5},
			Deny: func(float64, time.Duration) *enforcement.ConditionError {
				return &enforcement.ConditionError{Code: capability.ErrCodeConditionFailed, Message: "over limit"}
			},
		}, false, nil
	}
	panic("unknown break mode")
}

// TestObserveDowngrade_EngineVerdictsFollowWillForwardDeny is what pkg/enforcement's hard
// denies are justified BY. That package writes "where WillForwardDeny answers yes, a
// downgradable verdict is forwarded and a non-downgradable one is not" on exactly one doc
// comment and cites it from the refusals that depend on it — but it neither answers
// Downgradable nor implements the downgrade, so nothing there could fail if this rule ever
// narrowed. This runs a real engine verdict through the real forward core for each arm of the
// union, and for BOTH reasons a refusal resists the downgrade: the class its code names, and
// the producer's explicit override.
//
// The constraint is `enforcement: audit` throughout: WillForwardDeny answers yes for it, and
// it is the posture the unauthorized-skip refusal is actually reachable on (a route-level
// --audit sets SkipQuota, which AUTHORIZES the skip).
func TestObserveDowngrade_EngineVerdictsFollowWillForwardDeny(t *testing.T) {
	caps := func(enf string) []capability.Constraint {
		return []capability.Constraint{{
			Target:      "tool",
			Actions:     []string{"*"},
			Enforcement: enf,
			Conditions:  []capability.Condition{&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60}},
		}}
	}
	decide := func(ctx context.Context, enf string, mode breakMode) capability.EnforceResponse {
		eng := enforcement.New(
			enforcement.WithCallCounter(callcounter.NewInMemory()),
			enforcement.WithCommittingConditionHandler(capability.ConditionTypeMaxCalls, contractBreakingCommitHandler{mode: mode}),
		)
		return eng.ValidateAction(ctx, &capability.EnforceRequest{SessionID: "s", TargetName: "tool"}, caps(enf))
	}
	forward := func(t *testing.T, dec capability.EnforceResponse, auditRoute bool) (*fwdRecorder, bool) {
		t.Helper()
		rec := &fwdRecorder{}
		called := false
		fp := forwardParams{
			rec:       rec,
			sessionID: "s",
			audit:     auditRoute,
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				called = true
				return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
			},
		}
		enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, dec, "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)
		return rec, called
	}

	t.Run("a downgradable verdict is forwarded on a route running --audit", func(t *testing.T) {
		// The route-level arm: an ordinary ENFORCE constraint, downgraded because the ROUTE is
		// observing. Driving only the per-constraint arm left `auditMode ||` in isObserveDeny
		// deletable with this test still green.
		dec := decide(enforcement.WithSkipQuota(context.Background()), "", modeSoftDeny)
		require.Equal(t, capability.DecisionDeny, dec.Decision)
		require.False(t, dec.AuditOnly, "the constraint is not audit-only; the route is what forwards")

		rec, called := forward(t, dec, true)
		assert.True(t, called, "a route running --audit delivers the call")
		require.Len(t, rec.records, 2)
		assert.Equal(t, "deny", rec.records[0].decision)
		assert.True(t, rec.records[0].auditOnly)
	})

	t.Run("a kill-switch denial is never downgraded", func(t *testing.T) {
		// The second exemption isObserveDeny applies, and the one WillForwardDeny cannot
		// express: a kill is recognized by its CODE and sets no override, so a reader who took
		// "the BlockOverride flag is the only thing that never downgrades" literally would forward
		// an operator's emergency stop.
		dec := capability.EnforceResponse{
			Decision: capability.DecisionDeny,
			Denial:   &capability.DenialInfo{Code: capability.ErrCodeKillSwitch},
		}
		require.False(t, dec.Denial.BlockOverride, "the premise: a kill is blocked by its code, not by the flag")

		rec, called := forward(t, dec, true)
		assert.False(t, called, "an emergency stop must block even on a route running --audit")
		require.Len(t, rec.records, 1)
		assert.Equal(t, "deny", rec.records[0].decision)
		assert.False(t, rec.records[0].auditOnly)
	})

	t.Run("a downgradable verdict is forwarded on an audit-only constraint", func(t *testing.T) {
		dec := decide(context.Background(), capability.EnforcementAudit, modeSoftDeny)
		require.Equal(t, capability.DecisionDeny, dec.Decision)
		require.NotNil(t, dec.Denial)
		require.False(t, dec.Denial.BlockOverride, "an ordinary condition failure is a policy verdict, not an engine bug")

		rec, called := forward(t, dec, false)
		assert.True(t, called, "the union's forwarding half: an audit-mode constraint delivers the call")
		require.Len(t, rec.records, 2, "the downgrade records the observed verdict, then the forwarded call")
		assert.Equal(t, "deny", rec.records[0].decision)
		assert.True(t, rec.records[0].auditOnly, "and records it as observed rather than enforced")
		assert.Equal(t, "allow", rec.records[1].decision)
	})

	t.Run("a fault-class refusal is not downgraded", func(t *testing.T) {
		// An unauthorized skip leaves the deferred set unchecked, so the engine reached no
		// verdict — a FAULT, and the class is what blocks it. The flag is not set here and does
		// not need to be: that is the whole point of deriving the exemption from the code.
		dec := decide(context.Background(), capability.EnforcementAudit, modeUnauthorizedSkip)
		require.Equal(t, capability.DecisionDeny, dec.Decision)
		require.NotNil(t, dec.Denial)
		require.Equal(t, capability.ErrCodeEnforcementError, dec.Denial.Code)
		require.False(t, dec.Denial.Downgradable(), "no verdict was reached, so there is none to stand in for the call")

		rec, called := forward(t, dec, false)
		assert.False(t, called, "the exemption pkg/enforcement relies on must actually block on the one posture that reaches it")
		require.Len(t, rec.records, 1)
		assert.Equal(t, "deny", rec.records[0].decision)
		assert.False(t, rec.records[0].auditOnly, "a blocked call must not be recorded as an observed forward")
	})

	t.Run("a producer's override blocks a policy verdict", func(t *testing.T) {
		// The other reason Downgradable answers no, and the only one a CODE cannot express: a
		// policy verdict whose producer marked it non-downgradable because forwarding it would
		// corrupt the state the verdict protects (the engine's anchorUnresolved, the PDP's
		// descriptionHash pin). Same code as the forwarded arm above; only the override differs.
		dec := capability.EnforceResponse{
			Decision: capability.DecisionDeny,
			Denial:   &capability.DenialInfo{Code: capability.ErrCodeConditionFailed, BlockOverride: true},
		}
		require.Equal(t, capability.DenialClassPolicy, capability.ClassifyDenialCode(dec.Denial.Code),
			"the premise: the class alone would forward this")

		rec, called := forward(t, dec, true)
		assert.False(t, called, "a producer's override must block even on a route running --audit")
		require.Len(t, rec.records, 1)
		assert.False(t, rec.records[0].auditOnly)
	})

	t.Run("an absorbed handler fault forwards and lands on the tape", func(t *testing.T) {
		// The other half of the same contract, and the reason it is NOT a hard deny: a route
		// running --audit promises never to block, and the engine consumes nothing either way.
		dec := decide(enforcement.WithSkipQuota(context.Background()), "", modeCommitUnderObserve)
		require.Equal(t, capability.DecisionAllow, dec.Decision)

		rec, called := forward(t, dec, true)
		assert.True(t, called, "a wiretap route must not be turned into an outage by a plugin bug")
		require.Len(t, rec.records, 1)
		assert.Equal(t, "allow", rec.records[0].decision)
		assert.Equal(t, []interface{}{map[string]interface{}{
			"type":     capability.ConditionTypeMaxCalls,
			"contract": string(capability.HandlerContractQuotaUnderSkip),
		}}, rec.records[0].details[audit.HandlerFaultKey],
			"absorbing the fault must not hide it: the record names the handler AND the contract it broke")
		assert.True(t, audit.IsReservedDetailKey(audit.HandlerFaultKey),
			"an unreserved key would be mined by `eunox suggest` as a caller-supplied tool argument")
	})

	t.Run("an unevaluable condition is not downgraded", func(t *testing.T) {
		// The third unevaluable-condition refusal, and the one that used to be forwarded: it
		// was built as a policy verdict while its two siblings set the flag, so an observing
		// route delivered the call with the restriction never evaluated once, and reported
		// "would be allowed" for a call enforce mode denies. It carries the fault code now, and
		// what blocks it is the class rather than a bool a fourth refusal might forget.
		eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
		dec := eng.ValidateAction(context.Background(), &capability.EnforceRequest{SessionID: "s", TargetName: "tool"},
			[]capability.Constraint{{
				Target:      "tool",
				Actions:     []string{"*"},
				Enforcement: capability.EnforcementAudit,
				Conditions:  []capability.Condition{unmodelledCondition{}},
			}})
		require.Equal(t, capability.DecisionDeny, dec.Decision)
		require.NotNil(t, dec.Denial)
		require.Equal(t, capability.ErrCodeEnforcementError, dec.Denial.Code)

		rec, called := forward(t, dec, true)
		assert.False(t, called, "a condition nothing could evaluate must not be forwarded as though it had passed")
		require.Len(t, rec.records, 1)
		assert.Equal(t, "deny", rec.records[0].decision)
		assert.False(t, rec.records[0].auditOnly)
	})
}

// unmodelledCondition carries a discriminator no build models — the shape a programmatically
// built constraint, or a prototype-registry entry whose handler registration was forgotten,
// presents to the engine.
type unmodelledCondition struct{}

// ConditionType implements capability.Condition.
func (unmodelledCondition) ConditionType() string { return "definitely-not-a-real-condition" }

// TestIsObserveDeny_NilDenialIsNotDowngradable pins the direction a missing reason must fail
// in. Both callers (enforcedForwardCore's manifest leg and forwardServerRequest's sampling
// leg) normalize via normalizeDenial first, so nil is unreachable in-tree; the property is
// what happens if one ever stops. An early version treated nil as "safe to downgrade to an
// observed forward", a fail-open; a later one dereferenced it, which is loud but takes the
// proxy down from the enforcement goroutine. Answering false is both: the call is blocked, and
// nothing is forwarded on the strength of a reason nobody supplied.
func TestIsObserveDeny_NilDenialIsNotDowngradable(t *testing.T) {
	assert.False(t, isObserveDeny(nil, true, false),
		"a denial with no reason must not be downgraded to a forward on an observing route")
}

// TestEnforcedForwardCore_StrictAudit_DegradedDeniesAndSkipsUpstream pins the
// --require-audit=strict gate: when the audit trail has degraded, an
// otherwise-allowed call is denied fail-closed (AUDIT_UNAVAILABLE) and the
// upstream is never contacted, so no privileged call is forwarded unaudited.
func TestEnforcedForwardCore_StrictAudit_DegradedDeniesAndSkipsUpstream(t *testing.T) {
	rec := &fwdRecorder{
		degraded: true,
		reason:   "audit trail degraded: 3 record(s) dropped under back-pressure",
		detail:   map[string]interface{}{"dropped_count": int64(3)},
	}
	called := false
	fp := forwardParams{
		rec:              rec,
		sessionID:        "s",
		strictAuditState: strictAuditState{requireAuditStrict: true},
		callUpstream: func(_ context.Context, _ mcp.RPCMsg) (mcp.RPCMsg, error) {
			called = true
			return mcp.RPCMsg{}, nil
		},
	}
	resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	assert.False(t, called, "a degraded strict-audit gate must never reach the upstream")
	require.NotNil(t, resp.Error)
	assert.Equal(t, capability.JSONRPCCodeEnforcementError, resp.Error.Code, "AUDIT_UNAVAILABLE maps to -32603")
	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeAuditUnavailable, rec.records[0].code)
	// The structured deny detail carries DISCRETE counts, never the free-form prose
	// 'reason' (that is host-facing only).
	require.NotNil(t, rec.records[0].details)
	assert.NotContains(t, rec.records[0].details, "reason", "structured deny detail must not carry free-form prose")
	assert.Equal(t, int64(3), rec.records[0].details["dropped_count"])
}

// TestEnforcedForwardCore_StrictAudit_HealthyForwards confirms strict mode is a
// no-op while the audit trail is healthy: the call forwards and records an allow.
func TestEnforcedForwardCore_StrictAudit_HealthyForwards(t *testing.T) {
	rec := &fwdRecorder{} // healthy
	called := false
	fp := forwardParams{
		rec:              rec,
		sessionID:        "s",
		strictAuditState: strictAuditState{requireAuditStrict: true},
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			called = true
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
		},
	}
	resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	assert.True(t, called, "a healthy strict-audit gate must forward normally")
	assert.Nil(t, resp.Error)
	require.Len(t, rec.records, 1)
	assert.Equal(t, "allow", rec.records[0].decision)
}

// TestEnforcedForwardCore_StrictAudit_BoundaryCallWarnsImmediately is a regression
// test for the retrospective-gate gap: the strict-audit gate check runs BEFORE
// callUpstream using degradation counters that only reflect prior calls, so a call
// whose own RecordAllow enqueue is the first one dropped is still forwarded — the
// gate only starts denying the NEXT call. warnIfStrictAuditJustDegraded narrows
// that gap's blind spot by comparing AuditDegraded() immediately before and after
// this exact call's own record call, and printing an immediate SECURITY line the
// instant the trail flips from healthy to degraded on this call.
func TestEnforcedForwardCore_StrictAudit_BoundaryCallWarnsImmediately(t *testing.T) {
	rec := &fwdRecorder{degradeOnRecord: true} // starts healthy; degrades on its own RecordAllow
	fp := forwardParams{
		rec:              rec,
		sessionID:        "s",
		strictAuditState: strictAuditState{requireAuditStrict: true},
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
		},
	}

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)
	_ = w.Close()
	os.Stderr = oldStderr
	captured, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Nil(t, resp.Error, "the boundary call is still forwarded — this is a diagnostic, not a new denial")
	require.Len(t, rec.records, 1)
	assert.Equal(t, "allow", rec.records[0].decision)
	assert.Contains(t, string(captured), "SECURITY: --require-audit=strict",
		"the boundary call whose own record just degraded the trail must be flagged immediately, not only on the next request")
	assert.Contains(t, string(captured), `"read_file"`, "the warning should name the affected call")
}

// TestEnforcedForwardCore_NonStrict_DegradedStillForwards confirms the default
// (non-strict) posture is unchanged: even a degraded trail forwards the call,
// the documented fail-open-on-audit tradeoff. Strict mode is strictly opt-in.
func TestEnforcedForwardCore_NonStrict_DegradedStillForwards(t *testing.T) {
	rec := &fwdRecorder{degraded: true, reason: "degraded"}
	called := false
	fp := forwardParams{
		rec:              rec,
		sessionID:        "s",
		strictAuditState: strictAuditState{requireAuditStrict: false}, // default
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			called = true
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
		},
	}
	resp := enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	assert.True(t, called, "without strict mode a degraded trail must not block the forward")
	assert.Nil(t, resp.Error)
	require.Len(t, rec.records, 1)
	assert.Equal(t, "allow", rec.records[0].decision)
}

// TestDispatchList_StrictAudit_DegradedDeniesAndSkipsUpstream pins that the
// strict-audit gate also covers */list enumeration: a degraded trail denies the
// list call fail-closed without contacting the upstream.
func TestDispatchList_StrictAudit_DegradedDeniesAndSkipsUpstream(t *testing.T) {
	rec := &fwdRecorder{degraded: true, reason: "audit trail degraded: 1 audit write failure(s)"}
	called := false
	d := dispatchParams{
		forwardParams: forwardParams{
			rec:              rec,
			sessionID:        "s",
			strictAuditState: strictAuditState{requireAuditStrict: true},
			callUpstream: func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
				called = true
				return mcp.RPCMsg{Result: json.RawMessage(`{"tools":[]}`)}, nil
			},
		},
		// CheckKill returns nil; the strict gate is what fires
		pdp: pdp.AlwaysAllowPDP{},
	}
	resp := dispatchList(context.Background(), d, mcp.RPCMsg{ID: mcp.RawJSON(`1`), Method: "tools/list"}, pdp.ListFilterer.FilterToolsList)

	assert.False(t, called, "a degraded strict-audit gate must skip the */list upstream call")
	require.NotNil(t, resp.Error)
	assert.Equal(t, capability.JSONRPCCodeEnforcementError, resp.Error.Code)
	require.Len(t, rec.records, 1)
	assert.Equal(t, capability.ErrCodeAuditUnavailable, rec.records[0].code)
}

// TestForwardServerRequest_StrictAudit_DegradedDeniesSampling pins that the
// strict-audit gate also covers the fifth enforced method, sampling/createMessage,
// whose allow leg runs through forwardServerRequest: with a degraded trail the
// allowed sampling request is failed closed to the upstream initiator
// (AUDIT_UNAVAILABLE) and never forwarded to the host.
func TestForwardServerRequest_StrictAudit_DegradedDeniesSampling(t *testing.T) {
	rec := &fwdRecorder{degraded: true, reason: "audit trail degraded: 2 record(s) dropped under back-pressure"}
	forwarded := false
	var upstreamReply mcp.RPCMsg
	fp := serverRequestParams{
		rec:              rec,
		sessionID:        "s",
		pdp:              newTestManifestPDP(capability.Constraint{Target: "system:sampling/createMessage", Actions: []string{"allow"}}),
		forward:          func(context.Context, mcp.RPCMsg) bool { forwarded = true; return true },
		unblocker:        writingSeam(func(m mcp.RPCMsg) error { upstreamReply = m; return nil }),
		strictAuditState: strictAuditState{requireAuditStrict: true},
	}
	forwardServerRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}, fp)

	assert.False(t, forwarded, "a degraded strict-audit gate must not forward sampling to the host")
	require.NotNil(t, upstreamReply.Error, "the upstream initiator must receive a fail-closed error")
	assert.Equal(t, capability.JSONRPCCodeEnforcementError, upstreamReply.Error.Code)
	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeAuditUnavailable, rec.records[0].code)
}

// TestForwardServerRequest_StrictAudit_HealthyForwardsSampling is the control:
// with a healthy trail, strict mode forwards an allowed sampling request normally.
func TestForwardServerRequest_StrictAudit_HealthyForwardsSampling(t *testing.T) {
	rec := &fwdRecorder{} // healthy
	forwarded := false
	fp := serverRequestParams{
		rec:              rec,
		sessionID:        "s",
		pdp:              newTestManifestPDP(capability.Constraint{Target: "system:sampling/createMessage", Actions: []string{"allow"}}),
		forward:          func(context.Context, mcp.RPCMsg) bool { forwarded = true; return true },
		unblocker:        writingSeam(func(mcp.RPCMsg) error { t.Error("a healthy gate must not write an error to the upstream"); return nil }),
		strictAuditState: strictAuditState{requireAuditStrict: true},
	}
	forwardServerRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}, fp)

	assert.True(t, forwarded, "a healthy strict gate must forward allowed sampling")
	require.Len(t, rec.records, 1)
	assert.Equal(t, "allow", rec.records[0].decision)
}

// TestForwardServerRequest_SamplingFlowLabelDenyRecordsDetails is the regression for the
// sampling leg dropping structured deny details: an ENFORCED flowLabel deny on
// system:sampling must record the blocked provenance class in the audit record's details,
// exactly as the tool/resource/prompt path (enforcedForwardCore) does. RecordDeny omits
// carried_labels on a deny precisely BECAUSE a flowLabel deny names the offending class in
// its details, so a nil-details sampling record would leave the blocked class absent from
// the signed tape entirely.
func TestForwardServerRequest_SamplingFlowLabelDenyRecordsDetails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))

	// Taint session "s" with a confidential source read.
	_, err := engine.RecordLabels(ctx, &capability.EnforceRequest{SessionID: "s", TargetName: "read_secret"},
		&capability.Constraint{Target: "tool:read_secret", Actions: []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}}})
	require.NoError(t, err)

	// A sampling sink that admits only public-provenance flows: the confidential taint is
	// blocked, an enforced deny (no --audit, non-audit constraint).
	samplingSink := capability.Constraint{
		Target:     "system:sampling/createMessage",
		Actions:    []string{"allow"},
		Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}},
	}
	dp := pdp.NewManifestPDP([]capability.Constraint{samplingSink}, engine, killswitch.NewInMemory())

	rec := &fwdRecorder{}
	var upstreamReply mcp.RPCMsg
	fp := serverRequestParams{
		rec:       rec,
		sessionID: "s",
		pdp:       dp,
		forward: func(context.Context, mcp.RPCMsg) bool {
			t.Error("an enforced flowLabel deny must not forward to the host")
			return false
		},
		unblocker: writingSeam(func(m mcp.RPCMsg) error { upstreamReply = m; return nil }),
	}
	forwardServerRequest(ctx, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}, fp)

	// The upstream initiator gets a fail-closed error...
	require.NotNil(t, upstreamReply.Error, "the upstream initiator must receive a fail-closed error")
	// ...and the deny record names the blocked provenance class in its structured details.
	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision)
	require.NotNil(t, rec.records[0].details, "a flowLabel sampling deny must record structured details, not nil")
	assert.Equal(t, capability.FlowLabelConfidential, rec.records[0].details["blockedLabel"],
		"the sampling deny record must name the blocked class, as the tool path does")
	assert.Equal(t, []string{capability.FlowLabelConfidential}, rec.records[0].details["blockedLabels"])
}

// TestForwardServerRequest_StrictAudit_DegradedDeniesNonSampling is the
// regression for the non-sampling leg (roots/list, elicitation/create, …)
// bypassing --require-audit=strict: unlike sampling/createMessage, non-sampling
// server-initiated requests are not policy-enforced, but a degraded audit trail
// leaves them just as unaudited, so a degraded trail must fail them closed
// (AUDIT_UNAVAILABLE to the upstream initiator) instead of forwarding to the host.
func TestForwardServerRequest_StrictAudit_DegradedDeniesNonSampling(t *testing.T) {
	rec := &fwdRecorder{degraded: true, reason: "audit trail degraded: 1 audit write failure(s)"}
	forwarded := false
	var upstreamReply mcp.RPCMsg
	fp := serverRequestParams{
		rec:       rec,
		sessionID: "s",
		// CheckKill returns nil; the strict gate is what fires
		pdp:              pdp.AlwaysAllowPDP{},
		forward:          func(context.Context, mcp.RPCMsg) bool { forwarded = true; return true },
		unblocker:        writingSeam(func(m mcp.RPCMsg) error { upstreamReply = m; return nil }),
		strictAuditState: strictAuditState{requireAuditStrict: true},
	}
	forwardServerRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "roots/list"}, fp)

	assert.False(t, forwarded, "a degraded strict-audit gate must not forward a non-sampling server request to the host")
	require.NotNil(t, upstreamReply.Error, "the upstream initiator must receive a fail-closed error")
	assert.Equal(t, capability.JSONRPCCodeEnforcementError, upstreamReply.Error.Code)
	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeAuditUnavailable, rec.records[0].code)
}

// TestForwardServerRequest_StrictAudit_HealthyForwardsNonSampling is the control:
// with a healthy trail, strict mode still forwards a non-sampling server request
// normally.
func TestForwardServerRequest_StrictAudit_HealthyForwardsNonSampling(t *testing.T) {
	rec := &fwdRecorder{} // healthy
	forwarded := false
	fp := serverRequestParams{
		rec:              rec,
		sessionID:        "s",
		pdp:              pdp.AlwaysAllowPDP{},
		forward:          func(context.Context, mcp.RPCMsg) bool { forwarded = true; return true },
		unblocker:        writingSeam(func(mcp.RPCMsg) error { t.Error("a healthy gate must not write an error to the upstream"); return nil }),
		strictAuditState: strictAuditState{requireAuditStrict: true},
	}
	forwardServerRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "roots/list"}, fp)

	assert.True(t, forwarded, "a healthy strict gate must forward a non-sampling server request")
	require.Len(t, rec.records, 1)
	assert.Equal(t, "allow", rec.records[0].decision)
}

// TestForwardServerRequest_ObserveLeg_RecordsDenyBeforeForward pins the audit
// ordering invariant for the sampling observe leg: the would-be-deny record
// (audit_only) must be enqueued BEFORE the request is forwarded to the host, so a
// crash between the enqueue and the forward cannot leave a delivered request with no
// audit evidence — matching enforcedForwardCore's record-before-act observe branch.
func TestForwardServerRequest_ObserveLeg_RecordsDenyBeforeForward(t *testing.T) {
	rec := &fwdRecorder{} // healthy
	forwardedBeforeRecords := -1
	fp := serverRequestParams{
		rec:       rec,
		audit:     true, // route-level audit mode → observe-and-forward a would-be deny
		sessionID: "s",
		// An empty manifest denies sampling/createMessage; audit mode downgrades the
		// hard deny to an observe.
		pdp: newTestManifestPDP(capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}}),
		forward: func(context.Context, mcp.RPCMsg) bool {
			// Capture how many records existed at the moment of forwarding: the deny
			// observation must already be among them.
			forwardedBeforeRecords = len(rec.records)
			return true
		},
		unblocker: writingSeam(func(mcp.RPCMsg) error { t.Error("observe leg must not write an error to the upstream"); return nil }),
	}
	forwardServerRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}, fp)

	require.Len(t, rec.records, 2, "observe leg writes a deny observation then a forward outcome")
	assert.Equal(t, "deny", rec.records[0].decision, "the would-be deny must be recorded first")
	assert.True(t, rec.records[0].auditOnly, "the deny observation is audit_only")
	assert.Equal(t, "allow", rec.records[1].decision, "the forward outcome (allow) is recorded second")
	assert.Equal(t, 1, forwardedBeforeRecords, "the deny observation must be enqueued BEFORE the forward")
}

// forwardOrderRecorder is an auditRecorder whose RecordDeny writes a sentinel
// line to os.Stderr (redirected by the test to a pipe) so its call can be
// ordered against forwardServerRequest's own Fprintf on the very same stream,
// mirroring orderTrackingRecorder in dispatch_test.go.
type forwardOrderRecorder struct{}

func (forwardOrderRecorder) RecordAllow(context.Context, string, string, string, map[string]interface{}, []string, bool, []string, []string) {
}

func (forwardOrderRecorder) RecordDeclassifiedAllow(context.Context, string, string, string, map[string]interface{}, []string, bool, []string, []string, []string, string, string) {
}

func (forwardOrderRecorder) RecordDeny(context.Context, string, string, string, string, string, map[string]interface{}, bool) {
	fmt.Fprintln(os.Stderr, "RECORD_DENY_CALLED")
}

func (forwardOrderRecorder) AuditDegraded() (degraded bool, reason string, detail map[string]interface{}) {
	return false, "", nil
}

// TestForwardServerRequest_ObserveLeg_RecordsBeforeLogging pins the
// record-before-act invariant for the sampling audit-mode observe branch: the
// would-be-deny record must be enqueued before the "AUDIT: ... would be denied"
// stderr notice, so a crash between the two can never leave a SIEM-visible
// alert with no corresponding tamper-evident audit record. Regression for the
// same ordering bug dispatchUnmapped was fixed for — this leg had it too.
func TestForwardServerRequest_ObserveLeg_RecordsBeforeLogging(t *testing.T) {
	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	fp := serverRequestParams{
		rec:       forwardOrderRecorder{},
		audit:     true, // route-level audit mode → observe-and-forward a would-be deny
		sessionID: "s",
		// An empty manifest denies sampling/createMessage; audit mode downgrades the
		// hard deny to an observe.
		pdp:     newTestManifestPDP(capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}}),
		forward: func(context.Context, mcp.RPCMsg) bool { return true },
		// The seam's diagnostic channel is left UNSET rather than pointed at io.Discard: this leg's
		// notice resolves its destination at write time, which is what lets it reach the os.Stderr
		// swapped in above. A channel naming a writer would answer the ordering question about the
		// wrong pipe.
		unblocker: unwrittenSeam(func(mcp.RPCMsg) error { t.Error("observe leg must not write an error to the upstream"); return nil }),
	}
	forwardServerRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: "sampling/createMessage"}, fp)

	_ = w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	logged := buf.String()

	recordIdx := strings.Index(logged, "RECORD_DENY_CALLED")
	logIdx := strings.Index(logged, "AUDIT: sampling/createMessage would be denied")
	require.NotEqual(t, -1, recordIdx, "RecordDeny was not called; got: %q", logged)
	require.NotEqual(t, -1, logIdx, "audit notice was not logged; got: %q", logged)
	assert.Less(t, recordIdx, logIdx,
		"RecordDeny must be called BEFORE the stderr audit notice; got: %q", logged)
}

// TestForwardServerRequest_StrictAudit_DegradedDeniesSamplingObserveLeg covers the
// audit-mode observe leg: a would-be-denied sampling request that route-level audit
// mode would normally observe-and-forward is instead failed closed under strict mode
// when the trail is degraded — matching enforcedForwardCore, which gates after its
// own observe downgrade.
func TestForwardServerRequest_StrictAudit_DegradedDeniesSamplingObserveLeg(t *testing.T) {
	rec := &fwdRecorder{degraded: true, reason: "audit trail degraded: 1 audit write failure(s)"}
	forwarded := false
	var upstreamReply mcp.RPCMsg
	fp := serverRequestParams{
		rec:       rec,
		sessionID: "s",
		audit:     true, // route audit mode → a would-be-deny is observed-and-forwarded
		// No system:sampling opt-in → DecideSampling denies (a capability deny, not a
		// kill-switch deny), so the request reaches the audit-mode observe leg.
		pdp:              newTestManifestPDP(capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}}),
		forward:          func(context.Context, mcp.RPCMsg) bool { forwarded = true; return true },
		unblocker:        writingSeam(func(m mcp.RPCMsg) error { upstreamReply = m; return nil }),
		strictAuditState: strictAuditState{requireAuditStrict: true},
	}
	forwardServerRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Method: "sampling/createMessage"}, fp)

	assert.False(t, forwarded, "strict mode must fail closed on the audit-mode observe leg when degraded")
	require.NotNil(t, upstreamReply.Error, "the upstream initiator must receive a fail-closed error")
	assert.Equal(t, capability.JSONRPCCodeEnforcementError, upstreamReply.Error.Code)
	// One AUDIT_UNAVAILABLE deny, not the two-record observe-then-forward pattern.
	require.Len(t, rec.records, 1)
	assert.Equal(t, capability.ErrCodeAuditUnavailable, rec.records[0].code)
}

// TestEnforcedForwardCore_UpstreamErrorDetailSignsAndVerifies drives the real
// allow-with-upstream-error path through a live *audit.Sink and confirms the
// persisted record both carries the upstream_error_code detail and verifies clean
// under the chain HMAC — a sign-and-verify round trip for the new details key
// (CONTRIBUTING asks for one on new audit-record fields).
func TestEnforcedForwardCore_UpstreamErrorDetailSignsAndVerifies(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	fp := forwardParams{
		rec:       sink,
		sessionID: "sess",
		callUpstream: func(_ context.Context, _ mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{Error: &mcp.RPCError{Code: -32000, Message: "upstream refused"}}, nil
		},
	}
	_ = enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	require.NoError(t, sink.Close()) // flush the drainer to disk

	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	require.Len(t, lines, 1)
	keys, err := audit.LoadOrCreateKeys(strings.TrimSuffix(logPath, ".jsonl") + ".key")
	require.NoError(t, err)
	verifier := audit.NewVerifier(keys)
	ok, err := verifier.VerifyRecord(lines[0])
	require.NoError(t, err)
	require.True(t, ok, "an allow record carrying upstream_error_code must verify clean")

	recs := readAuditRecords(t, logPath)
	require.Len(t, recs, 1)
	assert.Equal(t, "allow", recs[0]["decision"])
	details, _ := recs[0]["details"].(map[string]interface{})
	require.NotNil(t, details, "the persisted allow record must carry details")
	assert.Equal(t, float64(-32000), details[audit.UpstreamErrorCodeKey])
}

func TestBindIsLoopbackOnly(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"[::1]", true}, // bracketed IPv6 loopback (net.ParseIP rejects brackets)
		{"localhost", true},
		// Case-insensitivity and trailing-FQDN-dot tolerance, delegated to
		// capability.IsLoopbackHost: bindIsLoopbackOnly used to keep its own
		// case-sensitive, non-dot-trimmed copy of this check, which missed these.
		{"LOCALHOST", true},
		{"Localhost", true},
		{"localhost.", true},
		{"", false},        // wildcard (all interfaces)
		{"0.0.0.0", false}, // wildcard
		{"::", false},      // wildcard
		{"[::]", false},    // bracketed wildcard is still not loopback-only
		{"10.0.0.5", false},
		{"192.168.1.10", false},
		{"example.com", false}, // non-IP hostname: cannot prove loopback-only
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, bindIsLoopbackOnly(c.host), "bindIsLoopbackOnly(%q)", c.host)
	}
}

// TestOpenNonLoopbackBind covers the startup "non-loopback bind + no auth + no JWT"
// SECURITY warning condition: it fires ONLY when the bind is non-loopback AND no auth
// token AND no JWT is configured, so a loopback bind, a configured token, or configured
// JWT each suppress it.
func TestOpenNonLoopbackBind(t *testing.T) {
	cases := []struct {
		name          string
		bind          string
		authToken     string
		jwtConfigured bool
		want          bool
	}{
		{"non-loopback, no auth, no jwt: warn", "0.0.0.0", "", false, true},
		{"non-loopback, routable addr, open: warn", "10.0.0.5", "", false, true},
		{"loopback suppresses", "127.0.0.1", "", false, false},
		{"auth token suppresses", "0.0.0.0", "secret", false, false},
		{"jwt suppresses", "0.0.0.0", "", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, openNonLoopbackBind(c.bind, c.authToken, c.jwtConfigured))
		})
	}
}

// TestAuditSink_CloseRace_NoSendOnClosedChannel hammers Record() from many
// goroutines while Close() runs concurrently. Before the fix, a Record() send
// executing the `case s.records <- rec` arm at the instant Close() closed the
// channel panicked the process with "send on closed channel" — even though the
// send was the selected arm of a select. The read-lock/closed guard makes the
// send and the channel close mutually exclusive, so this must complete without
// panicking. Run under `go test -race` (CI default) to also surface any data
// race on the shutdown state.
func TestAuditSink_CloseRace_NoSendOnClosedChannel(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	const producers = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(producers)
	for i := 0; i < producers; i++ {
		go func() {
			defer wg.Done()
			<-start // release all producers at once to widen the race window
			for j := 0; j < 500; j++ {
				// Must not panic even when the channel is closed underneath us.
				sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
			}
		}()
	}

	close(start)
	// Close concurrently with the in-flight producers: they keep calling Record()
	// while (and after) this runs, and none may panic.
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	wg.Wait()

	// A second Close must remain a safe no-op — idempotency is preserved alongside
	// the new shutdown guard.
	if err := sink.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestAuditSink_RecordAfterClose_DropsWithoutPanic exercises the deterministic
// post-close path: once Close() has run, Record() must count the record as a
// drop and return without sending on the closed channel. Without the closed
// guard this send would panic with "send on closed channel" every time.
func TestAuditSink_RecordAfterClose_DropsWithoutPanic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	before := sink.DroppedRecords()
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if got := sink.DroppedRecords(); got != before+1 {
		t.Fatalf("record after close: dropped = %d, want %d", got, before+1)
	}
}

// TestAuditSink_RecordNoRaceOnDetailsMutation is the concurrency guard for the
// same fix: many goroutines each hand a live map/slice to Record and then keep
// mutating it while the drainer serializes records in the background. Run with
// -race; before the clone was added the detector could flag the drainer reading
// the map while the caller wrote it.
func TestAuditSink_RecordNoRaceOnDetailsMutation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.Open(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"), 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}

	const goroutines = 32
	const perGoroutine = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				nested := map[string]interface{}{"secret": "v"}
				details := map[string]interface{}{"path": "/tmp/file", "n": float64(j), "nested": nested}
				obligs := []string{"redactFields"}
				sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", details, obligs, true, nil, nil)
				// Race the drainer: keep writing to the same structures — top-level
				// and nested — after the handoff. The deep clone inside Record means
				// the drainer never touches these, so the detector must stay silent.
				for k := 0; k < 8; k++ {
					details["path"] = "mutated"
					details[string(rune('a'+k))] = k
					nested["secret"] = "mutated"
					obligs[0] = "mutated"
				}
			}
		}()
	}
	wg.Wait()

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestAuditRotate_TriggeredByMaxBytes verifies that the drain goroutine
// triggers a rotation when the log grows past maxBytes.
func TestAuditRotate_TriggeredByMaxBytes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"

	// 1-byte limit → any record triggers rotation.
	sink, err := audit.Open(logPath, dir+"/audit.key", 1, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// Write a record → triggers drain → triggers rotate().
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)

	// Closing flushes the drainer.
	if err := sink.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// The rotated file should exist (named audit.jsonl.YYYYMMDDTHHMMSSZ).
	entries, _ := os.ReadDir(dir)
	rotated := 0
	for _, e := range entries {
		if len(e.Name()) > len("audit.jsonl.") {
			rotated++
		}
	}
	if rotated == 0 {
		t.Error("expected at least one rotated audit log file")
	}
}

// TestAuditDroppedRecords_Initial verifies DroppedRecords() on a fresh sink.
func TestAuditDroppedRecords_Initial(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if got := sink.DroppedRecords(); got != 0 {
		t.Errorf("expected 0 dropped records initially, got %d", got)
	}
}

// TestAuditSink_Close_Idempotent verifies that calling Close twice is safe.
func TestAuditSink_Close_Idempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	// Second close must not panic or error.
	if err := sink.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// testAuditIdentity is this package's stand-in for the caller-identity extractor the BINARY
// wires into the sink (cmd/eunox/audit_identity.go). It is deliberately a local double rather
// than a shared helper: the production adapter is the one place that joins internal/pdp to
// internal/audit, and importing it here would be the transport layer reaching back into the
// binary. What these tests assert is that the transport threads a request's validated claims
// into the context the sink reads — not which claim the binary maps onto which field, which
// cmd/eunox tests directly.
func testAuditIdentity(ctx context.Context) audit.Identity {
	c := pdp.JWTClaimsPtr(ctx)
	if c == nil {
		return audit.Identity{}
	}
	return audit.Identity{
		AgentID:         c.AgentID,
		TaskID:          c.TaskID,
		UserID:          c.Subject,
		Delegate:        c.Delegation.Delegate(),
		DelegationDepth: c.Delegation.ActorDepth(),
	}
}

func newTempAuditSink(t *testing.T) (sink *audit.Sink, logPath string) {
	t.Helper()
	dir := t.TempDir()
	var err error
	sink, err = audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0, audit.WithIdentity(testAuditIdentity))
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	return sink, dir + "/audit.jsonl"
}

// readAuditRecords reads all JSONL lines from logPath and returns them parsed.
func readAuditRecords(t *testing.T, logPath string) []map[string]interface{} { //nolint:unparam // logPath intentionally varies per call
	t.Helper()
	data, err := os.ReadFile(logPath) //nolint:gosec // G304: path is test-controlled temp dir
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var out []map[string]interface{}
	for _, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Errorf("unmarshal audit line: %v (line: %s)", err, line)
			continue
		}
		out = append(out, rec)
	}
	return out
}

// findAuditRecord returns the first record in records whose target equals
// target and, when decision is non-empty, whose decision also matches.
// Returns nil when no match is found.
func findAuditRecord(records []map[string]interface{}, target, decision string) map[string]interface{} {
	for _, r := range records {
		if v, _ := r["target"].(string); v != target {
			continue
		}
		if decision != "" {
			if d, _ := r["decision"].(string); d != decision {
				continue
			}
		}
		return r
	}
	return nil
}

// findAuditRecordByMethod returns the first record whose method equals method
// and, when decision is non-empty, whose decision also matches. Unmapped-method
// denials carry a method but no structured target, so they are located this way
// rather than by target.
func findAuditRecordByMethod(records []map[string]interface{}, method, decision string) map[string]interface{} {
	for _, r := range records {
		if v, _ := r["method"].(string); v != method {
			continue
		}
		if decision != "" {
			if d, _ := r["decision"].(string); d != decision {
				continue
			}
		}
		return r
	}
	return nil
}

// auditProxy returns a fresh HTTPProxy in --audit (observe) mode backed by the
// given upstream URL and PDP, wired to the provided audit sink.
func auditProxy(t *testing.T, upstreamURL string, dp pdp.PolicyDecisionPoint, sink *audit.Sink) *HTTPProxy {
	t.Helper()
	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         dp,
		UpstreamURL: upstreamURL,
		Audit:       true,
		Sink:        sink,
		Port:        0,
	})
	return proxy
}

// initAuditSession performs an MCP initialize handshake against srv.
func initAuditSession(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	msg := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test", "version": "0"},
		},
	}
	resp := postMCPWithBody(t, srv, msg, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status %d", resp.StatusCode)
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("no Mcp-Session-Id in response")
	}
	return sid
}

// ─────────────────────────────────────────────────────────────────────────────
// Core forwarding behavior
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditOnly_DeniedRequestForwarded(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	sink, _ := newTempAuditSink(t)
	proxy := auditProxy(t, upstream.srv.URL, denyAllPDP{}, sink)
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initAuditSession(t, proxySrv)

	msg := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "secret_tool",
			"arguments": map[string]interface{}{"key": "value"},
		},
	}
	resp := postMCPWithBody(t, proxySrv, msg, sid)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error != nil {
		t.Errorf("unexpected JSON-RPC error: %+v", result.Error)
	}
	if result.Result == nil {
		t.Error("expected upstream result, got nil")
	}
}

func TestAuditOnly_AllowedRequestForwarded(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	sink, _ := newTempAuditSink(t)
	proxy := auditProxy(t, upstream.srv.URL, pdp.AlwaysAllowPDP{}, sink)
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initAuditSession(t, proxySrv)

	msg := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/reports/q3.pdf"},
		},
	}
	resp := postMCPWithBody(t, proxySrv, msg, sid)
	defer func() { _ = resp.Body.Close() }()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error != nil {
		t.Errorf("unexpected error: %+v", result.Error)
	}
	if result.Result == nil {
		t.Error("expected result, got nil")
	}
}

func TestAuditOnly_NoManifest_ForwardsAll(t *testing.T) {
	// audit-only works without a policy: forward every call regardless.
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	sink, _ := newTempAuditSink(t)
	proxy := auditProxy(t, upstream.srv.URL, pdp.AlwaysAllowPDP{}, sink)
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initAuditSession(t, proxySrv)

	for _, tool := range []string{"read_file", "write_file", "delete_all"} {
		msg := map[string]interface{}{
			"jsonrpc": "2.0", "id": 2, "method": "tools/call",
			"params": map[string]interface{}{"name": tool, "arguments": map[string]interface{}{}},
		}
		resp := postMCPWithBody(t, proxySrv, msg, sid)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("tool %q: status %d, want 200", tool, resp.StatusCode)
		}
	}
}

// TestAuditOnly_WiretapRoute_Kill_HardBlocks is the transport-level guard for the
// wiretap-kill fix. A policyless enforcement: audit route whose wiretap PDP is
// wired to the kill switch (NewAlwaysAllowPDP) forwards calls normally, but once a
// kill is active the proxy returns a KILL_SWITCH JSON-RPC error to the host and
// never contacts the upstream. The PDP- and BuildRoutes-level tests stop at the
// decision; this one exercises the load-bearing forward.go observe gate
// (Downgradable() && audit — a revocation is not a policy verdict, so its class refuses the
// downgrade), which must hard-block rather than log-and-forward the kill-switch denial even
// though the route is in audit mode.
func TestAuditOnly_WiretapRoute_Kill_HardBlocks(t *testing.T) {
	t.Parallel()

	// A counting upstream so the "not contacted after kill" claim is exact. Only
	// tools/call hits are counted, excluding the initialize handshake.
	var mu sync.Mutex
	toolCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case msg.Method == "initialize":
			w.Header().Set("Mcp-Session-Id", "up-sess")
			initResult, _ := json.Marshal(map[string]interface{}{
				"protocolVersion": capability.Revision20251125.String(),
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "test", "version": "0"},
			})
			_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
		case msg.IsNotification():
			w.WriteHeader(http.StatusAccepted)
		default:
			mu.Lock()
			toolCalls++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID,
				Result: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)})
		}
	})
	upstream := httptest.NewServer(mux)
	defer upstream.Close()

	ks := killswitch.NewInMemory()
	sink, _ := newTempAuditSink(t)
	proxy := auditProxy(t, upstream.URL, pdp.NewAlwaysAllowPDP(ks), sink)
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initAuditSession(t, proxySrv)

	call := func() mcp.RPCMsg {
		t.Helper()
		msg := map[string]interface{}{
			"jsonrpc": "2.0", "id": 2, "method": "tools/call",
			"params": map[string]interface{}{"name": "read_file", "arguments": map[string]interface{}{}},
		}
		resp := postMCPWithBody(t, proxySrv, msg, sid)
		defer func() { _ = resp.Body.Close() }()
		var result mcp.RPCMsg
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return result
	}

	// Before the kill the wiretap route forwards: the host gets the upstream result.
	if got := call(); got.Error != nil || got.Result == nil {
		t.Fatalf("pre-kill: want forwarded upstream result, got error=%+v result=%s", got.Error, got.Result)
	}
	mu.Lock()
	before := toolCalls
	mu.Unlock()
	if before != 1 {
		t.Fatalf("pre-kill: want 1 upstream tools/call, got %d", before)
	}

	// Activate the kill (the emergency-stop case), then repeat the same call.
	if err := ks.ActivateGlobal(context.Background()); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}

	got := call()
	if got.Error == nil {
		t.Fatalf("post-kill: want a JSON-RPC error, got result=%s", got.Result)
	}
	if want := denialToJSONRPCCode(capability.ErrCodeKillSwitch); got.Error.Code != want {
		t.Errorf("post-kill: error code = %d, want %d (KILL_SWITCH)", got.Error.Code, want)
	}
	mu.Lock()
	after := toolCalls
	mu.Unlock()
	if after != before {
		t.Errorf("post-kill: upstream must not be contacted; tools/call count went %d -> %d", before, after)
	}
}

func TestAuditOnly_NormalMode_DenyStillBlocks(t *testing.T) {
	// Confirm that removing audit-only restores normal blocking.
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         denyAllPDP{},
		UpstreamURL: upstream.srv.URL,
		Audit:       false,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initAuditSession(t, proxySrv)

	msg := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{"name": "read_file", "arguments": map[string]interface{}{}},
	}
	resp := postMCPWithBody(t, proxySrv, msg, sid)
	defer func() { _ = resp.Body.Close() }()

	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Denial is a JSON-RPC error, not a tool result.
	if result.Error == nil {
		t.Fatal("expected JSON-RPC error for denied tools/call, got nil error")
	}
	if result.Error.Code != capability.JSONRPCCodeCapabilityDenied {
		t.Errorf("error.code = %d, want %d (CAPABILITY_DENIED)", result.Error.Code, capability.JSONRPCCodeCapabilityDenied)
	}
}

// TestPerEntryAudit_HTTP_DenyForwardedAndRecorded: over HTTP, in NORMAL mode (no
// route-level audit-only), a tool whose matched entry is `enforcement: audit` has
// its condition failure forwarded rather than blocked, and the would-be denial is
// recorded with audit_only=true. The rest of the manifest keeps enforcing.
func TestPerEntryAudit_HTTP_DenyForwardedAndRecorded(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	manifest := &config.LocalManifest{
		Name:         "test",
		Version:      "1.0.0",
		Capabilities: []capability.Constraint{auditToolEntry()}, // tool:read_file, audit, allowedValues /allowed/*
	}
	dp := pdp.NewManifestPDP(manifest.Capabilities, enforcement.New(), killswitch.NewInMemory())
	sink, logPath := newTempAuditSink(t)

	// NORMAL mode: AuditOnly stays false — only the matched entry is in audit mode.
	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         dp,
		UpstreamURL: upstream.srv.URL,
		Audit:       false,
		Sink:        sink,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initAuditSession(t, proxySrv)
	msg := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/blocked"}, // fails allowedValues → would deny
		},
	}
	resp := postMCPWithBody(t, proxySrv, msg, sid)
	defer func() { _ = resp.Body.Close() }()

	// Forwarded: the upstream result is returned, not a CapabilityDenied error.
	var result mcp.RPCMsg
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("per-entry audit: expected forwarded result, got JSON-RPC error %+v", result.Error)
	}
	if result.Result == nil {
		t.Error("expected upstream result, got nil")
	}

	// The would-be denial was recorded and marked audit_only.
	_ = sink.Close()
	denyRec := findAuditRecord(readAuditRecords(t, logPath), "read_file", "deny")
	if denyRec == nil {
		t.Fatal("expected a deny audit record for the observed denial")
	}
	if denyRec["audit_only"] != true {
		t.Errorf("expected audit_only=true on per-entry audit deny, got %v", denyRec["audit_only"])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit record content
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditOnly_DenyRecord_MarkedAuditOnly(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	manifest := &config.LocalManifest{
		Name:    "test",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:allowed_tool", Actions: []string{"call"}},
		},
	}
	dp := pdp.NewManifestPDP(manifest.Capabilities, enforcement.New(), killswitch.NewInMemory())
	sink, logPath := newTempAuditSink(t)
	proxy := auditProxy(t, upstream.srv.URL, dp, sink)
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initAuditSession(t, proxySrv)
	msg := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "blocked_tool",
			"arguments": map[string]interface{}{},
		},
	}
	resp := postMCPWithBody(t, proxySrv, msg, sid)
	_ = resp.Body.Close()

	_ = sink.Close()
	r := findAuditRecord(readAuditRecords(t, logPath), "blocked_tool", "deny")
	if r == nil {
		t.Fatal("no deny record found for blocked_tool")
	}
	if r["audit_only"] != true {
		t.Errorf("expected audit_only=true, got %v", r["audit_only"])
	}
	if r["denial_code"] == nil || r["denial_code"] == "" {
		t.Errorf("expected denial_code to be set, got %v", r["denial_code"])
	}
}

func TestAuditOnly_AllowRecord_ContainsToolArguments(t *testing.T) {
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	sink, logPath := newTempAuditSink(t)
	proxy := auditProxy(t, upstream.srv.URL, pdp.AlwaysAllowPDP{}, sink)
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initAuditSession(t, proxySrv)
	msg := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name": "read_file",
			"arguments": map[string]interface{}{
				"path":     "/reports/q3.pdf",
				"encoding": "utf-8",
			},
		},
	}
	resp := postMCPWithBody(t, proxySrv, msg, sid)
	_ = resp.Body.Close()

	_ = sink.Close()
	r := findAuditRecord(readAuditRecords(t, logPath), "read_file", "allow")
	if r == nil {
		t.Fatal("no allow record found for read_file")
	}
	details, ok := r["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("details missing or wrong type in allow record: %v", r)
	}
	if details["path"] != "/reports/q3.pdf" {
		t.Errorf("expected path in details, got %v", details)
	}
	if details["encoding"] != "utf-8" {
		t.Errorf("expected encoding in details, got %v", details)
	}
	if r["audit_only"] != true {
		t.Errorf("expected audit_only=true on allow record, got %v", r["audit_only"])
	}
}

func TestAuditOnly_AllowRecord_NormalMode_NoArguments(t *testing.T) {
	// In normal (non-audit-only) mode, allow records must NOT contain arguments.
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	sink, logPath := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: upstream.srv.URL,
		Audit:       false,
		Sink:        sink,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	sid := initAuditSession(t, proxySrv)
	msg := map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/secret"},
		},
	}
	resp := postMCPWithBody(t, proxySrv, msg, sid)
	_ = resp.Body.Close()

	_ = sink.Close()
	recs := readAuditRecords(t, logPath)

	for _, r := range recs {
		if r["target"] == "read_file" && r["decision"] == "allow" {
			if _, ok := r["details"]; ok {
				t.Error("allow record in normal mode must not contain details (args)")
			}
			if _, ok := r["audit_only"]; ok {
				t.Error("audit_only must not appear in normal-mode record")
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// auditRecord struct
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditOnly_StdioProxy_SamplingForwarded_DenyAllPDP(t *testing.T) {
	// In audit-only mode, sampling/createMessage from the upstream must be
	// forwarded even when no manifest permits it.
	hw := &mockHostWriter{}
	uw := &mockUpstreamWriter{}

	p := &StdioProxy{
		pdp:        denyAllPDP{},
		sessionID:  "test-sess",
		hostWriter: mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:   mcp.NewMsgWriter(&writerAdapter{uw}),
		audit:      true,
	}

	p.handleUpstreamRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`99`),
		Method:  "sampling/createMessage",
		Params:  json.RawMessage(`{"messages":[],"maxTokens":100}`),
	})

	if len(hw.messages) != 1 {
		t.Fatalf("expected sampling forwarded to host, got %d messages", len(hw.messages))
	}
	if len(uw.messages) != 0 {
		t.Errorf("unexpected error to upstream: %+v", uw.messages)
	}
}

func TestAuditOnly_StdioProxy_SamplingForwarded_ManifestNoSamplingEntry(t *testing.T) {
	hw := &mockHostWriter{}
	uw := &mockUpstreamWriter{}

	dp := newTestManifestPDP(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	p := &StdioProxy{
		pdp:        dp,
		sessionID:  "test-sess",
		hostWriter: mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:   mcp.NewMsgWriter(&writerAdapter{uw}),
		audit:      true,
	}

	p.handleUpstreamRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "sampling/createMessage",
		Params:  json.RawMessage(`{"messages":[],"maxTokens":50}`),
	})

	if len(hw.messages) != 1 {
		t.Fatalf("expected sampling forwarded to host in audit-only mode, got %d", len(hw.messages))
	}
	if len(uw.messages) != 0 {
		t.Errorf("unexpected error to upstream")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Stdio proxy: denied tool call is forwarded
// ─────────────────────────────────────────────────────────────────────────────

// autoRespondWriter wraps a StdioProxy's upstream writer so that every write
// immediately delivers a canned response into the matching pending channel.
// This lets unit tests exercise handleToolsCall without a real subprocess.
type autoRespondWriter struct {
	proxy    *StdioProxy
	response mcp.RPCMsg
}

func (w *autoRespondWriter) Write(p []byte) (int, error) {
	line := bytes.TrimRight(p, "\n")
	var msg mcp.RPCMsg
	if err := json.Unmarshal(line, &msg); err != nil {
		return 0, err
	}
	key := mcp.MsgKey(msg.ID)
	w.proxy.pendingMu.Lock()
	ch, ok := w.proxy.byUpstreamID[key]
	w.proxy.pendingMu.Unlock()
	if ok {
		resp := w.response
		resp.ID = msg.ID
		ch <- upstreamResult{msg: resp}
	}
	return len(p), nil
}

func TestAuditOnly_StdioProxy_DeniedToolForwarded(t *testing.T) {
	hw := &mockHostWriter{}

	manifest := &config.LocalManifest{
		Name:    "test",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Target: "tool:allowed_tool", Actions: []string{"call"}},
		},
	}
	dp := pdp.NewManifestPDP(manifest.Capabilities, enforcement.New(), killswitch.NewInMemory())

	fakeResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: `{"ok":true}`}},
	})

	p := &StdioProxy{
		pdp:        dp,
		sessionID:  "sess",
		hostWriter: mcp.NewMsgWriter(&writerAdapter{hw}),
		audit:      true,
	}
	// Wire the auto-responding upstream writer after the proxy is constructed
	// so p is available in the closure.
	p.upWriter = mcp.NewMsgWriter(&autoRespondWriter{
		proxy:    p,
		response: mcp.RPCMsg{JSONRPC: "2.0", Result: fakeResult},
	})

	p.handleHostRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`42`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"blocked_tool","arguments":{}}`),
	})

	if len(hw.messages) != 1 {
		t.Fatalf("expected 1 message to host, got %d", len(hw.messages))
	}
	if hw.messages[0].Error != nil {
		t.Errorf("unexpected error: %+v", hw.messages[0].Error)
	}
	if hw.messages[0].Result == nil {
		t.Error("expected upstream result forwarded to host")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// auditSink.Record: new audit parameter
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditSink_Record_AuditOnlyWrittenToFile(t *testing.T) {
	sink, logPath := newTempAuditSink(t)

	sink.RecordAllow(context.Background(), "sess1", "read_file", "tools/call", map[string]interface{}{"path": "/x"}, nil, true, nil, nil)
	sink.RecordDeny(context.Background(), "sess1", "write_file", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	_ = sink.Close()

	recs := readAuditRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}

	if recs[0]["audit_only"] != true {
		t.Errorf("first record: expected audit_only=true, got %v", recs[0]["audit_only"])
	}
	if _, ok := recs[1]["audit_only"]; ok {
		t.Error("second record: audit_only must be omitted when false")
	}
}

func TestAuditSink_Record_AuditOnlyPreservesHMACVerification(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/audit.jsonl"
	keyPath := dir + "/audit.key"

	sink, err := audit.Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("openAuditSink: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, true, nil, nil)
	_ = sink.Close()

	data, _ := os.ReadFile(logPath) //nolint:gosec // G304: path is test-controlled temp dir
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		t.Fatal("no audit record written")
	}

	// Open a fresh sink with the same key to verify.
	verifier, err := audit.Open(dir+"/x.jsonl", keyPath, 0, 0)
	if err != nil {
		t.Fatalf("verifier sink: %v", err)
	}
	defer func() { _ = verifier.Close() }()

	ok, err := verifier.VerifyRecord(lines[0])
	if err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}
	if !ok {
		t.Error("HMAC verification failed for audit-only record")
	}
}

// TestAuditSink_Record_StructuredTargetFields verifies that Record derives the
// structured target_type/target/method fields from the MCP method — not from the
// overloaded identifier — and that records carrying these fields pass HMAC
// sign-and-verify (the round-trip required for any audit-record shape change).
func TestAuditSink_Record_StructuredTargetFields(t *testing.T) {
	sink, logPath := newTempAuditSink(t)

	// memory:notes is an opaque resource URI (no "://") that a string heuristic
	// would misread as a tool; the prompt identifier carries the "prompts/"
	// display prefix that target must strip.
	sink.RecordAllow(context.Background(), "s", "memory:notes", "resources/read", nil, nil, false, nil, nil)
	sink.RecordAllow(context.Background(), "s", "prompts/code_review", "prompts/get", nil, nil, false, nil, nil)
	sink.RecordDeny(context.Background(), "s", "read_file", "tools/call", "AUTHORIZATION_FAILED", "", nil, false)
	sink.RecordDeny(context.Background(), "s", "sampling/createMessage", "sampling/createMessage", "SAMPLING_DENIED", "", nil, false)
	// A pre-dispatch record (e.g. a JWT rejection) carries no MCP method, so the
	// structured target fields are omitted entirely.
	sink.RecordDeny(context.Background(), "s", "", "", "JWT_INVALID", "jwt", nil, false)
	_ = sink.Close()

	recs := readAuditRecords(t, logPath)
	if len(recs) != 5 {
		t.Fatalf("expected 5 records, got %d", len(recs))
	}

	wants := []struct{ targetType, target, method string }{
		{"resource", "memory:notes", "resources/read"},
		{"prompt", "code_review", "prompts/get"},
		{"tool", "read_file", "tools/call"},
		{"system", "sampling/createMessage", "sampling/createMessage"},
		{"", "", ""}, // JWT pre-dispatch: all three omitted
	}
	check := func(i int, field, want string) {
		got, present := recs[i][field]
		if want == "" {
			if present {
				t.Errorf("record %d: %s = %v; want field absent", i, field, got)
			}
			return
		}
		if got != want {
			t.Errorf("record %d: %s = %v; want %q", i, field, got, want)
		}
	}
	for i, w := range wants {
		check(i, "target_type", w.targetType)
		check(i, "target", w.target)
		check(i, "method", w.method)
		// The legacy tool_name field has been removed from the audit shape; it
		// must never appear on a record.
		if _, ok := recs[i]["tool_name"]; ok {
			t.Errorf("record %d: tool_name must not be present (field removed)", i)
		}
	}

	// Sign-and-verify round-trip: the new fields are covered by the HMAC, so each
	// written record must still verify against the same key.
	data, err := os.ReadFile(logPath) //nolint:gosec // G304: path is test-controlled temp dir
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		ok, err := sink.VerifyRecord(line)
		if err != nil {
			t.Fatalf("record %d: VerifyRecord: %v", i, err)
		}
		if !ok {
			t.Errorf("record %d: HMAC verification failed with structured target fields", i)
		}
	}
}

// TestLoadOrCreateAuditKeys_GeneratesThenReloads asserts a fresh key file is
// created on first use and the same key is returned on the next load.
func TestLoadOrCreateAuditKeys_GeneratesThenReloads(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "sub", "audit.key")

	first, err := audit.LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if len(first) != 1 || len(first[0]) != 32 {
		t.Fatalf("expected one 32-byte key, got %d keys", len(first))
	}

	second, err := audit.LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !bytes.Equal(second[0], first[0]) {
		t.Error("reload must return the same persisted key, not regenerate it")
	}
}

// TestVerifyAuditLog_SanitizesControlCharsInInvalidLine pins that the
// INVALID diagnostic interpolates attacker-influenceable fields (target from an
// upstream tool/resource name, session_id from the client header). A field
// carrying a literal newline must not inject a spurious second INVALID line into
// audit-verify output that a SIEM would miscount as a real finding.
func TestVerifyAuditLog_SanitizesControlCharsInInvalidLine(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	// Both fields carry a newline followed by a forged INVALID line.
	spoofSession := "sess\nINVALID  seq=98 request_id=forged session_id= target=spoofed-session"
	spoofTarget := "tool-x\nINVALID  seq=99 request_id=forged session_id= target=spoofed-target"
	sink.RecordAllow(context.Background(), spoofSession, spoofTarget, "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Corrupt the stored _hmac so the record fails its per-record HMAC under its
	// OWN key — the INVALID branch (content tampering), which interpolates the
	// attacker-influenceable target/session_id fields. Verifying with a DIFFERENT
	// key is no longer an INVALID: a record naming a key_id the ring lacks is now
	// classified UNKNOWN_KEY_ID (a retired-key state), so to exercise the INVALID
	// path we tamper the content and verify with the matching key.
	marker := []byte(`"_hmac":"sha256:`)
	idx := bytes.Index(data, marker)
	if idx < 0 {
		t.Fatal("record has no _hmac to corrupt")
	}
	pos := idx + len(marker)
	if data[pos] == '0' {
		data[pos] = '1'
	} else {
		data[pos] = '0'
	}

	keys, err := audit.LoadOrCreateKeys(filepath.Join(filepath.Dir(logPath), "audit.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	var out strings.Builder
	if _, err := audit.VerifyLog(bytes.NewReader(data), audit.NewVerifier(keys), "", time.Time{}, &out); err != nil {
		t.Fatalf("verifyAuditLog: %v", err)
	}
	output := out.String()

	invalidLines := 0
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if strings.HasPrefix(line, "INVALID") {
			invalidLines++
		}
	}
	if invalidLines != 1 {
		t.Fatalf("expected exactly 1 INVALID line (no injected lines), got %d:\n%s", invalidLines, output)
	}
	if strings.Contains(output, "\nINVALID  seq=98") || strings.Contains(output, "\nINVALID  seq=99") {
		t.Errorf("an embedded newline was not sanitized, allowing line injection:\n%s", output)
	}
}

// TestLoadOrCreateAuditKeys_ConcurrentCreateConverges pins that when
// multiple processes/goroutines start concurrently against the same missing key
// path, the atomic O_EXCL create plus re-read on EEXIST must make every caller
// return the SAME persisted key. Before the fix each racer generated its own
// in-memory key, one won the WriteFile race, and the losers signed with a key
// that was never persisted — making audit-verify fail for their records.
func TestLoadOrCreateAuditKeys_ConcurrentCreateConverges(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "audit.key")

	const racers = 16
	var wg sync.WaitGroup
	results := make([][]byte, racers)
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // line everyone up so the create genuinely races
			keys, err := audit.LoadOrCreateKeys(keyPath)
			if err != nil {
				errs[idx] = err
				return
			}
			results[idx] = keys[0]
		}(i)
	}
	close(start)
	wg.Wait()

	// The key actually persisted on disk is the source of truth.
	persisted, err := audit.LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("reload persisted key: %v", err)
	}
	for i := range racers {
		if errs[i] != nil {
			t.Fatalf("racer %d: %v", i, errs[i])
		}
		if !bytes.Equal(results[i], persisted[0]) {
			t.Fatalf("racer %d returned a key that does not match the persisted key; "+
				"records it signs would fail audit-verify", i)
		}
	}
}

// TestLoadOrCreateAuditKeys_MultipleKeys asserts every key line is loaded in
// file order (active key first), so audit-verify can validate records signed
// before a rotation.
func TestLoadOrCreateAuditKeys_MultipleKeys(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	// Two valid 64-hex-char keys plus a comment and blank line that must be skipped.
	content := "# active key first\n" +
		strings.Repeat("a", 64) + "\n" +
		"\n" +
		strings.Repeat("b", 64) + "\n"
	if err := os.WriteFile(keyPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	keys, err := audit.LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

// TestLoadOrCreateAuditKeys_MalformedFailsClosed asserts a key file that exists
// but holds a malformed key is a hard error, never a silent regeneration
// (regenerating would invalidate every previously signed record).
func TestLoadOrCreateAuditKeys_MalformedFailsClosed(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(keyPath, []byte("not-a-valid-hex-key\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := audit.LoadOrCreateKeys(keyPath); err == nil {
		t.Error("expected a hard error for a malformed key file, got nil")
	}
}

// TestAuditRecord_StampsJWTAgentAndTask verifies that a validated JWT's agent_id,
// task_id, and user_id (the subject) are stamped onto records (§ 5.8), and omitted
// when no JWT is present.
func TestAuditRecord_StampsJWTAgentAndTask(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)

	ctx := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{
		AgentID: "agent-xyz",
		TaskID:  "task-abc",
		Subject: "sub-1",
	})
	sink.RecordAllow(ctx, "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	// No JWT in context → agent_id/task_id must be omitted.
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readAuditRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if recs[0]["agent_id"] != "agent-xyz" {
		t.Errorf("agent_id=%v, want agent-xyz", recs[0]["agent_id"])
	}
	if recs[0]["task_id"] != "task-abc" {
		t.Errorf("task_id=%v, want task-abc", recs[0]["task_id"])
	}
	if recs[0]["user_id"] != "sub-1" {
		t.Errorf("user_id=%v, want sub-1", recs[0]["user_id"])
	}
	if _, present := recs[1]["agent_id"]; present {
		t.Error("agent_id must be omitted when no JWT is present")
	}
	if _, present := recs[1]["task_id"]; present {
		t.Error("task_id must be omitted when no JWT is present")
	}
	if _, present := recs[1]["user_id"]; present {
		t.Error("user_id must be omitted when no JWT is present")
	}
}

// TestSamplingAuditRecord_CarriesSessionJWTIdentity verifies that a
// server-initiated sampling/createMessage decision — handled on the upstream
// reader with no host request in scope — is audited with the agent_id/task_id
// captured from the JWT on the session's initialize request (§ 5.8).
func TestSamplingAuditRecord_CarriesSessionJWTIdentity(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)

	rt := &UpstreamRoute{
		pdp: newTestManifestPDP(
			capability.Constraint{Target: "system:sampling/createMessage", Actions: []string{"allow"}},
		),
		sink: &routeSink{sink: sink},
	}
	sess := newTestSession(&httpSession{
		id:     "sess-1",
		route:  rt,
		claims: &pdp.JWTClaims{AgentID: "agent-xyz", TaskID: "task-abc"},
		done:   make(chan struct{}),
		// No SSE subscriber here, so the request is answered back to its initiator — which needs
		// an upstream sink, or the destroyed answer appends a second record of its own and this
		// test stops being about identity. See serverRequestUnblocker.answer.
		upWriter: mcp.NewMsgWriter(io.Discard),
	})

	id := json.RawMessage(`1`)
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: &id, Method: "sampling/createMessage"}

	(&HTTPProxy{}).handleHTTPUpstreamRequest(context.Background(), sess, msg)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readAuditRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 sampling record, got %d", len(recs))
	}
	r := recs[0]
	if r["target_type"] != "system" || r["target"] != "sampling/createMessage" {
		t.Errorf("target = %v:%v, want system:sampling/createMessage", r["target_type"], r["target"])
	}
	if r["agent_id"] != "agent-xyz" {
		t.Errorf("agent_id = %v, want agent-xyz", r["agent_id"])
	}
	if r["task_id"] != "task-abc" {
		t.Errorf("task_id = %v, want task-abc", r["task_id"])
	}
}

// TestSamplingAuditRecord_NoJWT_OmitsIdentity confirms that without a JWT on the
// session, the sampling record carries no agent_id/task_id (omitted, not empty).
func TestSamplingAuditRecord_NoJWT_OmitsIdentity(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)

	rt := &UpstreamRoute{
		pdp: newTestManifestPDP(
			capability.Constraint{Target: "system:sampling/createMessage", Actions: []string{"allow"}},
		),
		sink: &routeSink{sink: sink},
	}
	// upWriter as above: the answer to the undelivered request must land, or its own drop record
	// joins the one this test counts.
	sess := newTestSession(&httpSession{id: "sess-2", route: rt, done: make(chan struct{}), upWriter: mcp.NewMsgWriter(io.Discard)}) // no claims

	id := json.RawMessage(`1`)
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: &id, Method: "sampling/createMessage"}

	(&HTTPProxy{}).handleHTTPUpstreamRequest(context.Background(), sess, msg)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readAuditRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 sampling record, got %d", len(recs))
	}
	if _, present := recs[0]["agent_id"]; present {
		t.Error("agent_id must be omitted when the session has no JWT")
	}
	if _, present := recs[0]["task_id"]; present {
		t.Error("task_id must be omitted when the session has no JWT")
	}
}

// TestEnforcedForward_MaxCallsSlotNotRefundedOnUpstreamFailure is the executable pin for
// the quota invariant enforcedForwardCore documents at its upstream-failure branch: the
// maxCalls slot a call consumed at DECISION time stays consumed when the upstream
// forward then fails.
//
// Without this test the invariant is prose, and the obvious-looking "fix" — a
// compensating decrement on that branch — ships against a fully green suite while
// inverting maxCalls from a hard ceiling into one an attacker resets at will by inducing
// upstream timeouts. The behavior is deliberate: the counter increment is atomic WITH the
// decision (which is what makes the limit exact under concurrent requests), and a failed
// forward does not prove the upstream did not execute the call — a write timeout means
// the request bytes were already handed over. Over-counting is the fail-closed direction.
func TestEnforcedForward_MaxCallsSlotNotRefundedOnUpstreamFailure(t *testing.T) {
	t.Parallel()

	fu := newFakeUpstream()
	upSrv := httptest.NewServer(fu)
	upURL := upSrv.URL

	manifest := []capability.Constraint{{
		Target:  "tool:read_file",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 1, WindowSeconds: 60},
		},
	}}
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	dp := pdp.NewManifestPDP(manifest, engine, killswitch.NewInMemory())
	_, proxySrv := newTestRemoteProxy(t, upURL, httpProxyOptions{PDP: dp})
	sid := initSession(t, proxySrv)

	// Take the upstream away AFTER the session is established, so the next tools/call
	// clears policy (consuming the one slot) and then fails in transport.
	upSrv.Close()

	params, err := json.Marshal(mcp.ToolCallParams{Name: "read_file", Arguments: map[string]interface{}{}})
	require.NoError(t, err)

	first := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call", Params: params}
	firstResp := decodeRPC(t, postMCP(t, proxySrv, first, sid))
	require.NotNil(t, firstResp.Error, "the upstream is gone, so the forward must fail")
	require.NotContains(t, firstResp.Error.Message, capability.ErrCodeRateLimited,
		"the first call is within the limit; it must fail on the upstream, not on policy")

	// The slot is gone even though the call never demonstrably executed: the second call
	// is denied by maxCalls, not by the upstream being unreachable.
	second := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: "tools/call", Params: params}
	secondResp := decodeRPC(t, postMCP(t, proxySrv, second, sid))
	require.NotNil(t, secondResp.Error, "expected a denial once the quota is spent")
	assert.Equal(t, capability.JSONRPCCodeRateLimited, secondResp.Error.Code,
		"the failed forward must still have consumed the maxCalls slot (no compensating refund)")
	assert.True(t, strings.HasPrefix(secondResp.Error.Message, capability.ErrCodeRateLimited),
		"error.message must begin with the symbolic RATE_LIMITED code, got %q", secondResp.Error.Message)
}

// killDeny is the kill-switch deny decision the kill recorders are handed.
func killDeny() *capability.EnforceResponse {
	return &capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: capability.ErrCodeKillSwitch},
	}
}

// TestKillSubject_VerifiedVsClaimed pins killSubject's two edge cases that no other test
// covers: a claimed subject built from a request that never carried the header at all
// (the session-creating-initialize shape), and a hand-built zero value bypassing both
// constructors. The routing fact itself — verified populates the signed session_id,
// claimed leaves it EMPTY and survives only as the unverified details.claimed_session_id
// — is pinned one layer up, against the real recorders, by
// TestRecordKillDenial_SubjectRoutesTheSessionID and TestRecordKillDrop_SubjectRoutesTheSessionID
// (and, end-to-end through handleSessionPost, by
// TestHandleSessionPost_UnresolvedSessionKillDeny_DoesNotForgeSessionID and its Drop
// counterpart in http_test.go); asserting it a third time here against the bare methods
// would just be the same fact under a third name.
func TestKillSubject_VerifiedVsClaimed(t *testing.T) {
	t.Parallel()

	t.Run("claimed with no header contributes nothing", func(t *testing.T) {
		t.Parallel()
		// The session-creating initialize path takes this shape: no session exists and the
		// header is absent, so the record is identical to the verified-empty-id one.
		subj := claimedSession(httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
		assert.Empty(t, subj.auditSessionID())
		assert.Nil(t, subj.auditDetails(nil), "a missing header must leave no empty key")
	})

	t.Run("zero value fails safe", func(t *testing.T) {
		t.Parallel()
		// A hand-written composite literal bypassing the constructors must degrade toward
		// recording less, not toward asserting an id as fact.
		var subj killSubject
		assert.Empty(t, subj.auditSessionID())
		assert.Nil(t, subj.auditDetails(nil))
	})
}

// TestRecordKillDenial_SubjectRoutesTheSessionID pins that the recorders honour the subject
// rather than stamping whatever string they were handed: the same denial recorded for a
// verified and a claimed subject must differ in exactly that one respect. Together with the
// end-to-end tests over handleSessionPost this covers both halves — the wiring here, the
// live HTTP path there.
func TestRecordKillDenial_SubjectRoutesTheSessionID(t *testing.T) {
	t.Parallel()

	req := newTestRequestWithSession("victim-real-session-id")

	verifiedRec := &fwdRecorder{}
	resp := recordKillDenial(context.Background(), verifiedRec, killDeny(), mcp.RawJSON(`1`), verifiedSession("sess-1"), "tools/call")
	require.NotNil(t, resp.Error, "the host still gets a structured denial either way")
	require.Len(t, verifiedRec.records, 1)
	assert.Equal(t, "sess-1", verifiedRec.records[0].sessionID)
	assert.Nil(t, verifiedRec.records[0].details)

	claimedRec := &fwdRecorder{}
	resp = recordKillDenial(context.Background(), claimedRec, killDeny(), mcp.RawJSON(`1`), claimedSession(req), "tools/call")
	require.NotNil(t, resp.Error)
	require.Len(t, claimedRec.records, 1)
	assert.Empty(t, claimedRec.records[0].sessionID,
		"a claimed id must not be forgeable into the signed session_id field")
	assert.Equal(t, "victim-real-session-id", claimedRec.records[0].details["claimed_session_id"])
}

// TestRecordKillDrop_SubjectRoutesTheSessionID is the dropped-message counterpart of
// TestRecordKillDenial_SubjectRoutesTheSessionID, and additionally pins that folding a
// claimed id into the details does not cost the transport-leg tag an operator triages by.
func TestRecordKillDrop_SubjectRoutesTheSessionID(t *testing.T) {
	t.Parallel()

	req := newTestRequestWithSession("victim-real-session-id")

	verifiedRec := &fwdRecorder{}
	recordKillDrop(context.Background(), verifiedRec, killDeny(), verifiedSession("sess-1"),
		"notifications/cancelled", "notifications/cancelled", legHTTPNotification)
	require.Len(t, verifiedRec.records, 1)
	assert.Equal(t, "sess-1", verifiedRec.records[0].sessionID)
	assert.Equal(t, string(legHTTPNotification), verifiedRec.records[0].details["transport"])
	assert.NotContains(t, verifiedRec.records[0].details, "claimed_session_id")

	claimedRec := &fwdRecorder{}
	recordKillDrop(context.Background(), claimedRec, killDeny(), claimedSession(req),
		"notifications/cancelled", "notifications/cancelled", legHTTPNotification)
	require.Len(t, claimedRec.records, 1)
	assert.Empty(t, claimedRec.records[0].sessionID,
		"a claimed id must not be forgeable into the signed session_id field")
	assert.Equal(t, string(legHTTPNotification), claimedRec.records[0].details["transport"])
	assert.Equal(t, "victim-real-session-id", claimedRec.records[0].details["claimed_session_id"])
}

// TestHandlerFaultDetail_KeysMatchTheTypesOwnTags pins the two spellings of one shape
// together. handlerFaultDetail renders capability.HandlerFault into the plain map the audit
// layer's value bounder recurses into, which means the field names exist twice: as json tags
// on the type, and as string literals in the renderer. Nothing else ties them, so renaming a
// tag would leave the tape emitting the old key with every test still green.
func TestHandlerFaultDetail_KeysMatchTheTypesOwnTags(t *testing.T) {
	t.Parallel()
	rendered := handlerFaultDetail(capability.EnforceResponse{
		HandlerFaults: []capability.HandlerFault{{
			Type:     capability.ConditionTypeMaxCalls,
			Contract: capability.HandlerContractQuotaUnderSkip,
		}},
	})
	faults, ok := rendered[audit.HandlerFaultKey].([]interface{})
	require.True(t, ok, "the detail value must be a plain slice the audit bounder recurses into")
	require.Len(t, faults, 1)
	got, ok := faults[0].(map[string]interface{})
	require.True(t, ok, "each fault must be a plain map")

	// Marshalling the type is what the json tags govern; the renderer must produce the same
	// keys, or the tape and every other JSON path describe the fault differently.
	raw, err := json.Marshal(capability.HandlerFault{
		Type:     capability.ConditionTypeMaxCalls,
		Contract: capability.HandlerContractQuotaUnderSkip,
	})
	require.NoError(t, err)
	var viaTags map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &viaTags))
	assert.Equal(t, viaTags, got,
		"the audit render and capability.HandlerFault's own json tags must agree on every key")
}
