// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// -----------------------------------------------------------------
// Test doubles
// -----------------------------------------------------------------

// errKS is a kill-switch Checker whose ShouldBlock always errors, exercising the
// fail-closed kill-store-error branch (ErrCodeKillSwitchError) of killCheck and
// every Decide*/CheckKill path that embeds it.
type errKS struct{ killswitch.Checker }

func (errKS) ShouldBlock(_ context.Context, _, _ string) (bool, error) {
	return false, errKSUnavailable
}

type errString struct{ s string }

func (e *errString) Error() string { return e.s }

var errKSUnavailable = &errString{"kill switch backend unavailable"}

// -----------------------------------------------------------------
// ManifestPDP.DecideSampling — allow + deny + condition-deny
// -----------------------------------------------------------------

// A manifest with an explicit system:sampling/createMessage opt-in (action
// "allow") permits server-initiated sampling.
func TestManifestPDP_DecideSampling_OptInAllows(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:  "system:sampling/createMessage",
		Actions: []string{"allow"},
	})
	resp := p.DecideSampling(context.Background(), "sess-1", "10.0.0.1")
	require.Equal(t, capability.DecisionAllow, resp.Decision, "denial: %+v", resp.Denial)
	assert.NotEmpty(t, resp.RequestID)
	assert.NotEmpty(t, resp.DecidedAt)
}

// With no sampling opt-in in the manifest, sampling is denied (fail closed) with
// the SAMPLING_DENIED code.
func TestManifestPDP_DecideSampling_NoOptInDenies(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:  "tool:read_file",
		Actions: []string{"call"},
	})
	resp := p.DecideSampling(context.Background(), "sess-1", "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, "SAMPLING_DENIED", resp.Denial.Code)
}

// A sampling opt-in whose action is not "allow" (e.g. only "*"? no — a wrong
// action like "read") is denied: containsAction(matched.Actions, "allow") is the
// gate, so a constraint present but not granting "allow" still denies.
func TestManifestPDP_DecideSampling_WrongActionDenies(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:  "system:sampling/createMessage",
		Actions: []string{"read"},
	})
	resp := p.DecideSampling(context.Background(), "sess-1", "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, "SAMPLING_DENIED", resp.Denial.Code)
}

// A sampling opt-in guarded by a condition that fails (a timeWindow whose
// notBefore is in the future) is denied through evaluateAndRecord — conditions on
// the opt-in are evaluated, not skipped.
func TestManifestPDP_DecideSampling_ConditionFailsDenies(t *testing.T) {
	t.Parallel()
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	p := newTestManifestPDP(capability.Constraint{
		Target:     "system:sampling/createMessage",
		Actions:    []string{"allow"},
		Conditions: []capability.Condition{capability.TimeWindowCondition{NotBefore: future}},
	})
	resp := p.DecideSampling(context.Background(), "sess-1", "")
	require.Equal(t, capability.DecisionDeny, resp.Decision, "a future notBefore must deny")
	require.NotNil(t, resp.Denial)
}

// The kill switch is checked first on the sampling path: a killed session is
// denied with KILL_SWITCH even when the opt-in would otherwise allow.
func TestManifestPDP_DecideSampling_KilledSessionDenies(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	p := newTestManifestPDPWithKS(ks, capability.Constraint{
		Target:  "system:sampling/createMessage",
		Actions: []string{"allow"},
	})
	require.NoError(t, ks.KillSession(context.Background(), "sess-killed"))
	resp := p.DecideSampling(context.Background(), "sess-killed", "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeKillSwitch, resp.Denial.Code)
}

// A kill-store error on the sampling path fails closed with KILL_SWITCH_ERROR.
func TestManifestPDP_DecideSampling_KillStoreErrorFailsClosed(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDPWithKS(errKS{}, capability.Constraint{
		Target:  "system:sampling/createMessage",
		Actions: []string{"allow"},
	})
	resp := p.DecideSampling(context.Background(), "sess-1", "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeKillSwitchError, resp.Denial.Code)
}

// The package-level DecideSampling helper dispatches to the PDP's own method.
func TestDecideSampling_Helper_DispatchesToPDP(t *testing.T) {
	t.Parallel()
	var p DenyAllPDP
	resp := p.DecideSampling(context.Background(), "sess", "")
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
}

// -----------------------------------------------------------------
// killCheck error path + ManifestPDP.CheckKill / JWTPDP.CheckKill
// -----------------------------------------------------------------

// ManifestPDP.CheckKill returns a KILL_SWITCH deny for a killed session, a
// KILL_SWITCH_ERROR deny on a kill-store error, and nil otherwise.
func TestManifestPDP_CheckKill(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Not killed: nil.
	ksOK := killswitch.NewInMemory()
	pOK := newTestManifestPDPWithKS(ksOK)
	assert.Nil(t, pOK.CheckKill(ctx, "sess-1"))

	// Killed session: KILL_SWITCH.
	require.NoError(t, ksOK.KillSession(ctx, "sess-killed"))
	got := pOK.CheckKill(ctx, "sess-killed")
	require.NotNil(t, got)
	assert.Equal(t, capability.ErrCodeKillSwitch, got.Denial.Code)

	// Kill-store error: KILL_SWITCH_ERROR (fail closed).
	pErr := newTestManifestPDPWithKS(errKS{})
	gotErr := pErr.CheckKill(ctx, "sess-1")
	require.NotNil(t, gotErr)
	require.NotNil(t, gotErr.Denial)
	assert.Equal(t, capability.ErrCodeKillSwitchError, gotErr.Denial.Code)
	assert.Contains(t, gotErr.Denial.Message, "kill switch check failed")
}

// JWTPDP.CheckKill mirrors the embedded kill check: KILL_SWITCH for a killed
// session, KILL_SWITCH_ERROR on a store error, nil otherwise.
func TestJWTPDP_CheckKill(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ks := killswitch.NewInMemory()
	p := NewJWTPDP(JWTPDPOptions{KillSwitch: ks})
	assert.Nil(t, p.CheckKill(ctx, "sess-ok"))

	require.NoError(t, ks.ActivateGlobal(ctx))
	got := p.CheckKill(ctx, "sess-1")
	require.NotNil(t, got)
	require.NotNil(t, got.Denial)
	assert.Equal(t, capability.ErrCodeKillSwitch, got.Denial.Code)

	// No kill switch wired (JWT-only without a manager): nil.
	pNoKS := NewJWTPDP(JWTPDPOptions{})
	assert.Nil(t, pNoKS.CheckKill(ctx, "sess-1"))

	// Kill-store error.
	pErr := NewJWTPDP(JWTPDPOptions{KillSwitch: errKS{}})
	gotErr := pErr.CheckKill(ctx, "sess-1")
	require.NotNil(t, gotErr)
	require.NotNil(t, gotErr.Denial)
	assert.Equal(t, capability.ErrCodeKillSwitchError, gotErr.Denial.Code)
}

// -----------------------------------------------------------------
// IsKillSwitchDenial
// -----------------------------------------------------------------

func TestIsKillSwitchDenial(t *testing.T) {
	t.Parallel()
	assert.True(t, IsKillSwitchDenial(&capability.DenialInfo{Code: capability.ErrCodeKillSwitch}))
	assert.True(t, IsKillSwitchDenial(&capability.DenialInfo{Code: capability.ErrCodeKillSwitchError}))
	assert.False(t, IsKillSwitchDenial(&capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed}))
	assert.False(t, IsKillSwitchDenial(nil))
}

// -----------------------------------------------------------------
// decideTarget deny paths (no-match, CAPABILITY_DENIED, INVALID_PARAMS,
// audit-mode antecedent recording, targetOperationPhrase)
// -----------------------------------------------------------------

// A target absent from the manifest is denied AUTHORIZATION_FAILED, and the
// message names the target type and name.
func TestDecideTarget_NoMatch_AuthorizationFailed(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}})
	resp := callTool(p, context.Background(), "exfil", nil)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
	assert.Contains(t, resp.Denial.Message, "exfil")
}

// A matching constraint whose actions do not permit the operation is denied
// CAPABILITY_DENIED, exercising the targetOperationPhrase wording per target type.
func TestDecideTarget_ActionMismatch_CapabilityDenied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// tool: actions [read] but a call is required.
	toolP := newTestManifestPDP(capability.Constraint{Target: "tool:read_file", Actions: []string{"read"}})
	tr := callTool(toolP, ctx, "read_file", nil)
	require.Equal(t, capability.DecisionDeny, tr.Decision)
	require.NotNil(t, tr.Denial)
	assert.Equal(t, capability.ErrCodeCapabilityDenied, tr.Denial.Code)
	assert.Contains(t, tr.Denial.Message, "tool")

	// resource: actions [subscribe] but read is required -> "resource reads".
	resP := newTestManifestPDP(capability.Constraint{Target: "resource:file:///data/*", Actions: []string{"subscribe"}})
	rr := resP.DecideResourceRead(ctx, "sess", "file:///data/a.csv", "")
	require.Equal(t, capability.DecisionDeny, rr.Decision)
	require.NotNil(t, rr.Denial)
	assert.Equal(t, capability.ErrCodeCapabilityDenied, rr.Denial.Code)
	assert.Contains(t, rr.Denial.Message, "resource reads")

	// prompt: actions [list] but get is required -> "prompts/get".
	prP := newTestManifestPDP(capability.Constraint{Target: "prompt:code_review", Actions: []string{"list"}})
	pr := prP.DecidePromptGet(ctx, "sess", "code_review", "")
	require.Equal(t, capability.DecisionDeny, pr.Decision)
	require.NotNil(t, pr.Denial)
	assert.Equal(t, capability.ErrCodeCapabilityDenied, pr.Denial.Code)
	assert.Contains(t, pr.Denial.Message, "prompts/get")
}

// A tools/call whose arguments violate the constraint's argumentSchema is denied
// INVALID_PARAMS (schema validation runs before conditions).
func TestDecideTarget_SchemaViolation_InvalidParams(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:         "tool:read_file",
		Actions:        []string{"call"},
		ArgumentSchema: &capability.ArgumentSchema{Required: []string{"path"}},
	})
	// Missing the required "path" argument.
	resp := callTool(p, context.Background(), "read_file", map[string]interface{}{})
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeInvalidParams, resp.Denial.Code)
}

// An audit-mode (enforcement: audit) constraint downgrades a CAPABILITY_DENIED
// to a forwarded allow stamped AuditOnly, and the antecedent is recorded so a
// later sequenceBlock does not fail open. This drives recordAuditModeAntecedent's
// record branch and the audit-mode defer in decideTarget.
func TestDecideTarget_AuditMode_DowngradesAndRecords(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:      "tool:read_file",
		Actions:     []string{"read"}, // does not permit "call"
		Enforcement: capability.EnforcementAudit,
	})
	resp := callTool(p, context.Background(), "read_file", nil)
	// Audit mode logs-and-forwards: the response is still a deny verdict, but
	// stamped AuditOnly so the transport downgrades it to a forwarded allow.
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.True(t, resp.AuditOnly, "an audit-mode constraint must stamp AuditOnly")
}

// recordingCounter is a capability.CallCounter that counts session-history
// writes (IncrementAndGet) so a test can observe whether
// recordAuditModeAntecedent actually recorded an antecedent. The read-only and
// maxCalls methods are inert stubs — the antecedent path only writes.
type recordingCounter struct{ writes int }

func (c *recordingCounter) IncrementAndGet(context.Context, string, int, int) (int64, error) {
	c.writes++
	return int64(c.writes), nil
}
func (c *recordingCounter) Peek(context.Context, string, int) (int64, error) { return 0, nil }
func (c *recordingCounter) IncrementIfBelow(context.Context, string, int, int64) (count int64, admitted bool, retryAfter time.Duration, err error) {
	return 0, true, 0, nil
}
func (c *recordingCounter) IncrementIfAllBelow(context.Context, []string, []int, []int64) (admitted bool, deniedIndex int, count int64, retryAfter time.Duration, err error) {
	return true, 0, 0, 0, nil
}

// recordAuditModeAntecedent records a session-history antecedent ONLY when the
// matched constraint is audit-only AND the decision is a DOWNGRADABLE deny — every
// other combination must be a no-op (a genuine allow is already recorded inside the
// engine; an enforced deny or a HardDeny audit-mode deny means the tool never ran).
// The counting counter makes the distinction observable, so a regression that
// broadened or inverted the guard (recording on an allow, an enforced deny, or a
// HardDeny deny) fails here rather than silently corrupting later sequenceBlock
// antecedent history.
func TestRecordAuditModeAntecedent_RecordsOnlyOnAuditDeny(t *testing.T) {
	t.Parallel()
	counter := &recordingCounter{}
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "t"}
	auditOnly := &capability.Constraint{Target: "tool:t", Actions: []string{"call"}, Enforcement: capability.EnforcementAudit}
	enforced := &capability.Constraint{Target: "tool:t", Actions: []string{"call"}}

	// No-op: an enforced (not audit-only) deny — the tool never ran.
	recordAuditModeAntecedent(context.Background(), engine, nil, req, enforced,
		&capability.EnforceResponse{Decision: capability.DecisionDeny})
	// No-op: audit-only but an allow — already recorded inside the engine.
	recordAuditModeAntecedent(context.Background(), engine, nil, req, auditOnly,
		&capability.EnforceResponse{Decision: capability.DecisionAllow})
	require.Equal(t, 0, counter.writes, "no antecedent must be recorded on the no-op paths")

	// Recording path: an audit-mode deny still forwards and runs the tool, so the
	// antecedent must be recorded for a later sequenceBlock Peek.
	recordAuditModeAntecedent(context.Background(), engine, nil, req, auditOnly,
		&capability.EnforceResponse{Decision: capability.DecisionDeny})
	require.Equal(t, 1, counter.writes, "an audit-mode deny must record exactly one antecedent")

	// No-op: an audit-mode deny that is HARD (HardDeny) is NOT downgraded — the tool
	// never runs — so recording it would poison history with a phantom antecedent a
	// later sequenceBlock reads as "ran", spuriously blocking a downstream call.
	recordAuditModeAntecedent(context.Background(), engine, nil, req, auditOnly,
		&capability.EnforceResponse{Decision: capability.DecisionDeny, Denial: &capability.DenialInfo{HardDeny: true}})
	require.Equal(t, 1, counter.writes, "a HardDeny audit-mode deny must NOT record an antecedent (the tool never ran)")
}

// TestRecordAuditModeAntecedent_BackfillsFlowLabels asserts the audit-mode downgrade
// stamps the forwarded observe record with the same flow it produced: labels_out from
// the labelOutput this source asserts, and carried_labels from what had flowed into the
// session before it. A structural early-return deny (evaluateMatched never ran, so
// CarriedLabels arrives nil) is the path that would otherwise log empty labels though the
// tool runs and the data is produced — the gap this back-fill closes.
func TestRecordAuditModeAntecedent_BackfillsFlowLabels(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))

	// Pre-taint the session: an earlier source read asserted "internal".
	prior := &capability.Constraint{
		Target:     "tool:a",
		Actions:    []string{"call"},
		Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelInternal}}},
	}
	_, err := engine.RecordLabels(ctx, &capability.EnforceRequest{SessionID: "s", TargetName: "a"}, prior)
	require.NoError(t, err)

	// An audit-only source read that labels its output "confidential", hitting a
	// downgradable deny with no labels stamped yet (the structural early-return shape).
	src := &capability.Constraint{
		Target:      "tool:t",
		Actions:     []string{"call"},
		Enforcement: capability.EnforcementAudit,
		Directives:  []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
	}
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "t"}
	resp := &capability.EnforceResponse{Decision: capability.DecisionDeny}
	override := recordAuditModeAntecedent(ctx, engine, engine.Clock(), req, src, resp)

	require.Nil(t, override, "a clean record must not override the downgrade")
	assert.Equal(t, []string{capability.FlowLabelConfidential}, resp.LabelsOut,
		"labels_out must reflect the labels this forwarded read asserts")
	assert.Equal(t, []string{capability.FlowLabelInternal}, resp.CarriedLabels,
		"carried_labels must reflect what flowed into the session before this read")
}

// TestRecordAuditModeAntecedent_NonFlowConstraintNoLabels asserts the flow back-fill is
// gated on the same per-constraint predicate the genuine-allow path uses: a NON-flow
// constraint (no flowLabel condition, no labelOutput directive) downgraded under audit in
// a TAINTED session must not stamp carried_labels/labels_out — matching the empty-label
// record a genuine allow of that constraint writes — instead of over-reporting the
// session's accumulated labels on a call that is neither a flow source nor a sink.
func TestRecordAuditModeAntecedent_NonFlowConstraintNoLabels(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter), enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()))

	// Taint the session via a real source read elsewhere.
	src := &capability.Constraint{
		Target:     "tool:a",
		Actions:    []string{"call"},
		Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}},
	}
	_, err := engine.RecordLabels(ctx, &capability.EnforceRequest{SessionID: "s", TargetName: "a"}, src)
	require.NoError(t, err)

	// A non-flow audit-only constraint hits a downgradable deny in the SAME tainted session.
	nonFlow := &capability.Constraint{Target: "tool:ping", Actions: []string{"call"}, Enforcement: capability.EnforcementAudit}
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "ping"}
	resp := &capability.EnforceResponse{Decision: capability.DecisionDeny}
	override := recordAuditModeAntecedent(ctx, engine, engine.Clock(), req, nonFlow, resp)

	require.Nil(t, override, "a clean record must not override the downgrade")
	assert.Nil(t, resp.CarriedLabels, "a non-flow constraint must not stamp carried_labels, matching its genuine-allow record")
	assert.Nil(t, resp.LabelsOut, "a non-flow constraint asserts no labels")
}

// targetOperationPhrase covers the system target (default bare-type branch) too.
func TestTargetOperationPhrase_AllTypes(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "resource reads", targetOperationPhrase(capability.TargetTypeResource))
	assert.Equal(t, "prompts/get", targetOperationPhrase(capability.TargetTypePrompt))
	assert.Equal(t, string(capability.TargetTypeTool), targetOperationPhrase(capability.TargetTypeTool))
	assert.Equal(t, string(capability.TargetTypeSystem), targetOperationPhrase(capability.TargetTypeSystem))
}

// -----------------------------------------------------------------
// JWTClaimsPtr / AuditIdentityFromContext
// -----------------------------------------------------------------

func TestJWTClaimsPtr(t *testing.T) {
	t.Parallel()
	// Present.
	claims := &JWTClaims{AgentID: "agent-1", TaskID: "task-9"}
	got := JWTClaimsPtr(WithJWTClaims(context.Background(), claims))
	require.NotNil(t, got)
	assert.Equal(t, "agent-1", got.AgentID)

	// Absent.
	assert.Nil(t, JWTClaimsPtr(context.Background()))
}

func TestAuditIdentityFromContext(t *testing.T) {
	t.Parallel()
	// With claims: agent/task/user (sub) all flow through.
	ctx := WithJWTClaims(context.Background(), &JWTClaims{AgentID: "agent-1", TaskID: "task-9", Subject: "user-7"})
	agentID, taskID, userID := AuditIdentityFromContext(ctx)
	assert.Equal(t, "agent-1", agentID)
	assert.Equal(t, "task-9", taskID)
	assert.Equal(t, "user-7", userID)

	// Without claims: all empty.
	agentID, taskID, userID = AuditIdentityFromContext(context.Background())
	assert.Empty(t, agentID)
	assert.Empty(t, taskID)
	assert.Empty(t, userID)
}

// -----------------------------------------------------------------
// NewJWTPDPWithCache / Cache
// -----------------------------------------------------------------

// NewJWTPDPWithCache builds a route wrapper sharing the validator's JWKS cache,
// and Cache() exposes that same cache instance.
func TestNewJWTPDPWithCache_SharesCache(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "shared-k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	validator := NewJWTPDP(JWTPDPOptions{
		JWKSURI:                  srv.URL + "/",
		Issuer:                   "iss",
		Audience:                 "aud",
		CacheTTL:                 5 * time.Second,
		ExperimentalCapabilities: true,
	})
	shared := validator.Cache()
	require.NotNil(t, shared, "Cache() must expose the validator's JWKS cache")

	inner := newTestManifestPDP(capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}})
	route := NewJWTPDPWithCache(JWTPDPOptions{
		Issuer:   "iss",
		Audience: "aud",
		Inner:    inner,
	}, shared)
	require.NotNil(t, route)
	// The route wrapper shares the exact cache instance, not a fresh one.
	assert.Same(t, shared, route.Cache())

	// The wrapper still enforces: a token validated through the shared validator
	// flows into the route's Decide and intersects with its inner manifest.
	token := makeIDPToken(t, key, []string{"tool:read_file"}, "iss", "aud", "sub", time.Now().Add(time.Hour))
	ctx, err := validator.ValidateToken(context.Background(), "Bearer "+token)
	require.NoError(t, err)
	resp := route.Decide(ctx, "sess", EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, map[string]interface{}{}, "")
	assert.Equal(t, capability.DecisionAllow, resp.Decision, "denial: %+v", resp.Denial)
}

// -----------------------------------------------------------------
// JWT list filtering by claims (tools/resources/prompts)
// -----------------------------------------------------------------

// The JWT ListFilterer methods route through filterList and apply claim-based
// filtering when mcp.capabilities is present.
func TestJWTPDP_FilterResourcesAndPrompts_ByClaims(t *testing.T) {
	t.Parallel()
	p := NewJWTPDP(JWTPDPOptions{})
	ctx := WithJWTClaims(context.Background(), &JWTClaims{
		Capabilities:    []string{"resource:file:///data/*", "prompt:code_review"},
		HasCapabilities: true,
	})

	resOut := p.FilterResourcesList(ctx, json.RawMessage(`{"resources":[{"uri":"file:///data/a"},{"uri":"file:///nope"}]}`)).Result
	assert.Equal(t, []string{"file:///data/a"}, entryNames(t, resOut, "resources", "uri"))

	prOut := p.FilterPromptsList(ctx, json.RawMessage(`{"prompts":[{"name":"code_review"},{"name":"nope"}]}`)).Result
	assert.Equal(t, []string{"code_review"}, entryNames(t, prOut, "prompts", "name"))
}

// TestJWTPDP_FilterToolsList_DropsMalformedEntryAndKeepsSiblingField pins two
// properties of the claim-filtering path (via entryCoveredByClaims/
// filterListResult) that are otherwise easy to regress: a single malformed
// (non-object) entry is dropped on its own rather than failing the whole list,
// and a sibling envelope field (nextCursor) survives the splice.
func TestJWTPDP_FilterToolsList_DropsMalformedEntryAndKeepsSiblingField(t *testing.T) {
	t.Parallel()
	p := NewJWTPDP(JWTPDPOptions{})
	ctx := WithJWTClaims(context.Background(), &JWTClaims{
		Capabilities:    []string{"tool:read_file"},
		HasCapabilities: true,
	})

	in := json.RawMessage(`{"tools":[{"name":"read_file"},{"name":"exfil"},42],"nextCursor":"c1"}`)
	out := p.FilterToolsList(ctx, in).Result
	assert.Equal(t, []string{"read_file"}, entryNames(t, out, "tools", "name"))
	assert.Contains(t, string(out), "nextCursor")
}

// entryNames decodes the named string field from each entry of the named array in
// a filtered list envelope.
func entryNames(t *testing.T, out json.RawMessage, field, key string) []string {
	t.Helper()
	var env map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &env))
	var entries []map[string]interface{}
	require.NoError(t, json.Unmarshal(env[field], &entries))
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if v, ok := e[key].(string); ok {
			names = append(names, v)
		}
	}
	return names
}

// -----------------------------------------------------------------
// parseCapHeads — malformed-claim drop paths (trailing '?' and bad target)
// -----------------------------------------------------------------

func TestParseCapHeads_DropsMalformed(t *testing.T) {
	t.Parallel()
	heads := parseCapHeads([]string{
		"tool:read_file",          // valid, no conditions
		"tool:query?op=X",         // valid with condition suffix
		"tool:bad?",               // trailing '?' with no pairs -> dropped
		"noprefix",                // no recognized namespace -> dropped
		"resource:file:///data/*", // valid resource
	})
	// Only the three valid heads survive.
	require.Len(t, heads, 3)
	assert.Equal(t, "read_file", heads[0].bareName)
	assert.Equal(t, capability.TargetTypeTool, heads[0].prefix)
	assert.Equal(t, "op=X", heads[1].condpart)
	assert.Equal(t, capability.TargetTypeResource, heads[2].prefix)
}

// buildConstraintsFromParsed drops a matching claim whose condition suffix is
// malformed (fail closed) — e.g. a key that is percent-encoded.
func TestBuildConstraintsFromParsed_MalformedSuffixDropped(t *testing.T) {
	t.Parallel()
	// A head whose condpart is invalid (percent-encoded key) but which matches the
	// target: parseCondSuffix errors, so the claim grants nothing.
	heads := []capHead{{prefix: capability.TargetTypeTool, bareName: "query_db", condpart: "%65nc=x"}}
	out := buildConstraintsFromParsed(heads, EnforceTarget{Type: capability.TargetTypeTool, Name: "query_db"})
	assert.Empty(t, out, "a matching claim with a malformed condition suffix must grant nothing")

	// Sanity: a well-formed suffix on a matching claim yields one constraint.
	good := []capHead{{prefix: capability.TargetTypeTool, bareName: "query_db", condpart: "op=SELECT"}}
	got := buildConstraintsFromParsed(good, EnforceTarget{Type: capability.TargetTypeTool, Name: "query_db"})
	require.Len(t, got, 1)
	require.Len(t, got[0].Conditions, 1)
}

// -----------------------------------------------------------------
// decodeJWTClaimsPreservingNumbers — malformed inputs (fail closed)
// -----------------------------------------------------------------

func TestDecodeJWTClaimsPreservingNumbers_Malformed(t *testing.T) {
	t.Parallel()

	// Not 3 segments.
	_, err := decodeJWTClaimsPreservingNumbers("only.two")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 3 segments")

	// 3 segments but the payload is not valid base64url.
	_, err = decodeJWTClaimsPreservingNumbers("aaa.!!!notbase64!!!.ccc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding JWT payload segment")

	// 3 segments, valid base64url, but the payload is not a JSON object.
	// base64url("not json") with no padding.
	badPayload := "header." + b64url("not json") + ".sig"
	_, err = decodeJWTClaimsPreservingNumbers(badPayload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding claims")

	// Happy path: a JSON object decodes, preserving a large integer as json.Number.
	okPayload := "header." + b64url(`{"big":9007199254740993}`) + ".sig"
	claims, err := decodeJWTClaimsPreservingNumbers(okPayload)
	require.NoError(t, err)
	n, ok := claims["big"].(json.Number)
	require.True(t, ok, "large integer must decode as json.Number, got %T", claims["big"])
	assert.Equal(t, "9007199254740993", n.String())
}

// b64url returns the raw (unpadded) base64url encoding of s, matching a JWS
// payload segment.
func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// -----------------------------------------------------------------
// Redaction: ApplyRedactObligs, redactJSONText, RedactDotPath,
// redactValuePath, isRecognizedContentType, classifyRedactableLeaf,
// marshalNoHTMLEscape, redactJSONValue
// -----------------------------------------------------------------

var redactSSN = []capability.Obligation{
	{Type: capability.DirectiveTypeRedactFields, Paths: []string{"ssn"}},
}

// No obligations / no redact paths is a pure passthrough.
func TestApplyRedactObligs_NoObligations_Passthrough(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"hi"}]}`)

	out, err := ApplyRedactObligs(body, nil)
	require.NoError(t, err)
	assert.Equal(t, body, out)

	// An obligation list that carries no redactFields paths is also a passthrough.
	out, err = ApplyRedactObligs(body, []capability.Obligation{{Type: capability.DirectiveTypeRedactFields}})
	require.NoError(t, err)
	assert.Equal(t, body, out)
}

// A redactFields obligation masks the named field in a JSON text content body
// and in structuredContent (value -> "[redacted]"), preserving everything else.
func TestApplyRedactObligs_RedactsTextAndStructuredContent(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"{\"ssn\":\"123\",\"name\":\"alice\"}"}],"structuredContent":{"ssn":"456","keep":true}}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "123")
	assert.NotContains(t, s, "456")
	assert.Contains(t, s, "alice")
	assert.Contains(t, s, "keep")
}

// structuredContent delivered as a JSON-string scalar (rather than an object) must
// be redacted, not silently forwarded. Before the fix the scalar fell through
// redactJSONValue's default arm, leaking the secret while the audit record claimed
// redaction applied.
func TestApplyRedactObligs_StructuredContentJSONString_Redacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":"{\"ssn\":\"SECRET1\",\"keep\":\"v\"}"}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "SECRET1", "ssn inside a JSON-string structuredContent must be redacted")
	assert.Contains(t, s, "keep")
}

// A doubly-encoded JSON string nested inside a structuredContent OBJECT (a value
// that is itself a serialized object carrying the named field) must be redacted, not
// forwarded verbatim — the structural-key pass alone would no-op on it while the
// audit record claims redaction applied.
func TestApplyRedactObligs_StructuredContentNestedJSONString_Redacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"data":"{\"ssn\":\"SECRET2\",\"keep\":\"v\"}","other":"plain"}}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "SECRET2", "ssn inside a nested JSON-string value must be redacted")
	assert.Contains(t, s, "keep")
	assert.Contains(t, s, "plain")
}

// The same nested-string leak via a structuredContent ARRAY whose element is a
// serialized JSON object.
func TestApplyRedactObligs_StructuredContentArrayJSONString_Redacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":["{\"ssn\":\"SECRET3\"}","plain element"]}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "SECRET3", "ssn inside a JSON-string array element must be redacted")
	assert.Contains(t, s, "plain element")
}

// A nested string that LOOKS like a JSON container but does not parse cleanly — here a
// truncated object missing its closing brace — is NOT cleanly-parseable JSON, so it
// is not a redactable container and passes through unchanged rather than failing the
// response closed. redactFields redacts named fields of valid JSON only; a field hidden in
// malformed JSON is out of scope (see docs/threat-model-mcp.md) and must be redacted
// upstream. This documents the accepted residual: the malformed value is NOT redacted.
func TestApplyRedactObligs_StructuredContentNestedMalformedContainer_PassesThrough(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"data":"{\"ssn\":\"LEAKED_SSN_VALUE\""}}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err, "malformed JSON is not a redactable container; it passes through, not fail closed")
	assert.Equal(t, body, out, "the response is returned verbatim (malformed JSON is out of scope, not redacted)")
}

// A nested string that is a clean JSON container followed by trailing data is not a single
// clean JSON value, so it passes through unchanged rather than failing closed.
func TestApplyRedactObligs_StructuredContentNestedTrailingData_PassesThrough(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"data":"{\"ssn\":\"LEAKED_SSN_VALUE\"} trailing"}}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err, "a container-plus-trailing-data string is not a clean JSON container; it passes through")
	assert.Equal(t, body, out)
}

// A dotted manifest path (data.ssn) — the natural spelling for the honest shape
// {"data":{"ssn":...}} — must also redact the doubly-encoded form {"data":"{\"ssn\":...}"}:
// the leaf's dot-prefix is rebased so data.ssn reaches the ssn inside the string at key
// data. Before the rebase, the full path was matched against the inner root and missed.
func TestApplyRedactObligs_StructuredContentNestedDottedPath_Redacted(t *testing.T) {
	t.Parallel()
	dotted := []capability.Obligation{
		{Type: capability.DirectiveTypeRedactFields, Paths: []string{"data.ssn"}},
	}
	body := []byte(`{"structuredContent":{"data":"{\"ssn\":\"LEAKED_SSN_VALUE\",\"keep\":\"v\"}"}}`)
	out, err := ApplyRedactObligs(body, dotted)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "LEAKED_SSN_VALUE", "a dotted path must reach ssn inside a string smuggled at key data")
	assert.Contains(t, s, "keep")
}

// Brace-bearing nested prose (e.g. a templated summary like "...{query}") is NOT valid
// JSON, so it passes through unchanged — it must NOT fail the response closed. This is the
// availability behavior the redaction policy guarantees: redactFields redacts valid JSON only and
// never denies a response over a string it cannot parse.
func TestApplyRedactObligs_StructuredContentNestedBraceProse_PassesThrough(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"summary":"found 3 results matching {query}"}}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err, "brace-bearing prose is not valid JSON and must pass through, not fail closed")
	assert.Contains(t, string(out), "found 3 results matching {query}", "the brace-bearing prose is preserved")
}

// Brace-FREE nested prose carries no JSON object key, parses as no container, and passes
// through unchanged — no availability regression for ordinary string content — while a
// co-resident structural ssn key is still redacted. The assertion checks the distinctive
// secret VALUE is gone, not merely the key token.
func TestApplyRedactObligs_StructuredContentNestedPlainProse_Preserved(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"summary":"found 3 results, all ok","ssn":"DISTINCT_SSN_VALUE"}}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "found 3 results, all ok", "brace-free prose must pass through")
	assert.NotContains(t, s, "DISTINCT_SSN_VALUE", "the structural ssn key (and its value) is still redacted")
}

// A secret buried under MORE than one encoding layer (a string that decodes to an object
// whose own value is another doubly-encoded string) must still be redacted: unwrapping
// recurses to any depth, not just one level.
func TestApplyRedactObligs_StructuredContentNestedJSONString_DeepRedacted(t *testing.T) {
	t.Parallel()
	// structuredContent.data is a string -> {"wrap": "<string>"} -> {"ssn":"DEEP_SSN_VALUE"}.
	body := []byte(`{"structuredContent":{"data":"{\"wrap\":\"{\\\"ssn\\\":\\\"DEEP_SSN_VALUE\\\",\\\"keep\\\":\\\"v\\\"}\"}"}}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "DEEP_SSN_VALUE", "ssn buried two encoding layers deep must be redacted")
	assert.Contains(t, s, "keep")
}

// The same multi-layer redaction when structuredContent itself is delivered as a JSON
// string (the top-level-string path must recurse to any depth too). Also asserts a sibling
// survives and the output is still well-formed JSON, not merely that the secret is absent
// (NotContains alone would pass on empty/garbled output).
func TestApplyRedactObligs_StructuredContentTopLevelString_DeepRedacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":"{\"data\":\"{\\\"ssn\\\":\\\"DEEP_SSN_VALUE\\\",\\\"keep\\\":\\\"survives\\\"}\"}"}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "DEEP_SSN_VALUE", "ssn inside a doubly-encoded top-level structuredContent string must be redacted")
	assert.Contains(t, s, "survives", "the sibling value must be preserved, not dropped or garbled")
	assert.True(t, json.Valid(out), "redacted output must remain well-formed JSON")
}

// A text content body that is a clean JSON OBJECT carrying a doubly-encoded string value
// must have the smuggled field redacted, in parity with structuredContent — the text path
// now recurses through the same shared core (closing the prior content[].text fail-open).
func TestApplyRedactObligs_TextContentDoublyEncoded_Redacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"{\"data\":\"{\\\"ssn\\\":\\\"LEAK_X\\\",\\\"keep\\\":\\\"v\\\"}\"}"}]}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "LEAK_X", "ssn smuggled in a doubly-encoded text content value must be redacted")
	assert.Contains(t, s, "keep")
}

// A JSON null structuredContent (a valid "no structured result" shape) carries no field
// and must pass through byte-for-byte, not fail the whole response closed.
func TestApplyRedactObligs_StructuredContentNull_Preserved(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"ok"}],"structuredContent":null}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err, "null structuredContent must not fail the response closed")
	assert.Equal(t, body, out, "an untouched response (null structuredContent, prose text) is returned verbatim")
}

// A JSONPath-style "$.data.ssn" path must reach the field inside a smuggled string, the
// same as the bare "data.ssn" spelling — exercises the "$." normalization shared by the
// structural pass and rebaseLeafPaths.
func TestApplyRedactObligs_StructuredContentNestedDollarPath_Redacted(t *testing.T) {
	t.Parallel()
	dollar := []capability.Obligation{
		{Type: capability.DirectiveTypeRedactFields, Paths: []string{"$.data.ssn"}},
	}
	body := []byte(`{"structuredContent":{"data":"{\"ssn\":\"LEAK_X\",\"keep\":\"v\"}"}}`)
	out, err := ApplyRedactObligs(body, dollar)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "LEAK_X", "$.data.ssn must reach ssn inside a string smuggled at key data")
	assert.Contains(t, s, "keep")
}

// Re-marshaling a redacted doubly-encoded string must preserve its surviving siblings
// byte-faithfully: a large integer keeps full precision (UseNumber) and <,>,& are not
// HTML-escaped on the inner re-encode.
func TestApplyRedactObligs_StructuredContentNestedString_PreservesSiblingFidelity(t *testing.T) {
	t.Parallel()
	body := []byte(`{"structuredContent":{"data":"{\"ssn\":\"SSN_SECRET_VALUE\",\"amount\":9007199254740993,\"html\":\"a<b>&c\"}"}}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `\"ssn\":\"[redacted]\"`, "ssn masked inside the smuggled string")
	assert.NotContains(t, s, "SSN_SECRET_VALUE", "the original ssn value must not survive masking")
	assert.Contains(t, s, "9007199254740993", "large integer sibling preserved verbatim (UseNumber)")
	assert.Contains(t, s, "a<b>&c", "HTML chars in a sibling not escaped on the inner re-marshal")
}

// structuredContent nested deeper than maxRedactionDepth cannot be cheaply verified and
// fails the whole response closed (defense-in-depth; also bounds the worst-case recursion
// and re-marshal cost against an adversarial upstream).
func TestApplyRedactObligs_StructuredContentExcessiveDepth_FailsClosed(t *testing.T) {
	t.Parallel()
	const depth = maxRedactionDepth + 50
	var b strings.Builder
	b.WriteString(`{"structuredContent":`)
	for i := 0; i < depth; i++ {
		b.WriteString(`{"a":`)
	}
	b.WriteString(`"x"`)
	for i := 0; i < depth; i++ {
		b.WriteString(`}`)
	}
	b.WriteString(`}`)
	_, err := ApplyRedactObligs([]byte(b.String()), redactSSN)
	require.Error(t, err, "structuredContent nested beyond the redaction depth limit must fail closed")
}

// structuredContent that is a bare scalar carries no named field: a prose string and a
// non-string scalar (number/bool/null) both pass through unchanged. redactFields never
// fails the response closed over a scalar structuredContent it cannot redact.
func TestApplyRedactObligs_StructuredContentScalar_PassesThrough(t *testing.T) {
	t.Parallel()
	// A prose scalar string: forwarded unchanged.
	body := []byte(`{"structuredContent":"just a status line"}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	assert.Equal(t, body, out)

	// A number scalar: no named field; passes through unchanged (not fail closed).
	num := []byte(`{"structuredContent":42}`)
	out, err = ApplyRedactObligs(num, redactSSN)
	require.NoError(t, err, "a number structuredContent has no field to redact and must pass through")
	assert.Equal(t, num, out)
}

// unwiredDirective is a Directive whose ToObligation returns a type the engine
// cannot translate, exercising the fail-closed ENFORCEMENT_ERROR path in
// collectObligations. The manifest loader rejects unknown directive types, so this
// is reachable only via a programmatically built constraint (defense in depth).
type unwiredDirective struct{}

func (unwiredDirective) DirectiveType() string { return "unwiredTestDirective" }
func (unwiredDirective) ToObligation() capability.Obligation {
	return capability.Obligation{Type: "unwiredTestDirective"}
}

// TestDecide_AuditModeUnwiredDirective_StaysHardDeny pins that an unwired directive
// under an AUDIT-mode constraint is NOT downgraded to a logged-and-forwarded allow.
// The engine returns a hard ENFORCEMENT_ERROR (an engine bug, not a policy verdict);
// decideTarget's stamp must leave AuditOnly false (and HardDeny set) so the transport
// blocks the call rather than forwarding it — the fail-closed deny must survive.
func TestDecide_AuditModeUnwiredDirective_StaysHardDeny(t *testing.T) {
	t.Parallel()
	p := newTestManifestPDP(capability.Constraint{
		Target:      "tool:export",
		Actions:     []string{"call"},
		Enforcement: "audit",
		Directives:  []capability.Directive{unwiredDirective{}},
	})
	resp := callTool(p, context.Background(), "export", nil)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.False(t, resp.AuditOnly, "an audit-mode constraint must NOT downgrade a hard ENFORCEMENT_ERROR to a forward")
	assert.True(t, resp.Denial.HardDeny, "the deny must remain hard through stamp()")
}

// A doubly-encoded text body — a JSON STRING scalar whose decoded value is ANOTHER JSON
// string encoding an object (not a genuine scalar) — must still be redacted: the extra
// string-encoding layer is unwrapped and re-classified rather than treated as a terminal
// scalar. Regression for the fail-open where classifyRedactableLeaf's default arm passed a
// string-encoded container through unchanged because it looked one decode away from a
// "genuine" scalar.
func TestApplyRedactObligs_DoublyEncodedTextString_Redacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"\"{\\\"ssn\\\":\\\"DDD\\\"}\""}]}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "DDD", "ssn hidden behind a second JSON-string encoding layer must be redacted")
	assert.True(t, json.Valid(out), "redacted output must remain well-formed JSON")
}

// The same double-string-encoding gap, but for structuredContent.data (the exact shape from
// the reported leak): a value that is a JSON string whose decoded value is ANOTHER JSON
// string encoding the object carrying the named field. Fixtures are built with json.Marshal
// (rather than hand-escaped literals) so each encoding layer is unambiguously correct.
func TestApplyRedactObligs_StructuredContentDoublyStringEncoded_Redacted(t *testing.T) {
	t.Parallel()
	layer2, err := json.Marshal(map[string]interface{}{"ssn": "123-45-6789"})
	require.NoError(t, err)
	layer1, err := json.Marshal(string(layer2)) // a JSON string encoding layer2
	require.NoError(t, err)
	sc, err := json.Marshal(map[string]interface{}{"data": json.RawMessage(layer1)})
	require.NoError(t, err)
	body := []byte(`{"content":[],"structuredContent":`)
	body = append(body, sc...)
	body = append(body, '}')
	require.True(t, json.Valid(body), "test fixture must itself be well-formed JSON")

	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "123-45-6789", "ssn hidden behind a double string-encoding layer must be redacted, not leaked in cleartext")
	assert.True(t, json.Valid(out), "redacted output must remain well-formed JSON")
}

// A secret behind THREE string-encoding layers must also be reached — the fix recurses
// through classifyRedactableLeaf's string-scalar case regardless of how many layers deep the
// container sits, bounded only by maxRedactionDepth.
func TestApplyRedactObligs_TripleStringEncoded_Redacted(t *testing.T) {
	t.Parallel()
	layer3, err := json.Marshal(map[string]interface{}{"ssn": "TRIPLE_SSN"})
	require.NoError(t, err)
	layer2, err := json.Marshal(string(layer3))
	require.NoError(t, err)
	layer1, err := json.Marshal(string(layer2))
	require.NoError(t, err)
	sc, err := json.Marshal(map[string]interface{}{"data": json.RawMessage(layer1)})
	require.NoError(t, err)
	body := []byte(`{"structuredContent":`)
	body = append(body, sc...)
	body = append(body, '}')
	require.True(t, json.Valid(body), "test fixture must itself be well-formed JSON")

	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "TRIPLE_SSN", "ssn hidden behind three string-encoding layers must be redacted")
}

// TestApplyRedactObligs_UnicodeEscapedBraceDoublyEncoded_Redacted pins the fail-open fix in
// classifyRedactableLeaf's fast-path guard: a doubly string-encoded container whose INNER
// string-encoding layer spells its braces as {/} unicode escapes instead of literal
// '{'/'}' bytes. layer1 is itself a valid JSON string literal (starts with '"') that decodes
// directly to the real object {"ssn":"SECRET"} — but layer1's own text contains no literal
// '{' byte, only the six-character {/} escape sequences. The old guard
// (`!strings.ContainsRune(trimmed, '{')`) bailed to leafKindOther on layer1 without ever
// decoding it, so the object was never reached and the field passed through unredacted. The
// literal-brace spelling of the identical payload was already covered (see
// TestApplyRedactObligs_StructuredContentDoublyStringEncoded_Redacted) and remained
// redacted throughout — only this escaping variant of the same double-encoding leaked.
func TestApplyRedactObligs_UnicodeEscapedBraceDoublyEncoded_Redacted(t *testing.T) {
	t.Parallel()
	// layer1 is exactly {"ssn":"SECRET"} JSON-string-encoded with its braces spelled
	// {/} instead of the literal bytes a normal json.Marshal would produce.
	layer1 := "\"\\u007B\\\"ssn\\\":\\\"SECRET\\\"\\u007D\""
	require.True(t, json.Valid([]byte(layer1)), "layer1 must itself be valid JSON (a JSON string literal)")
	require.False(t, strings.ContainsRune(layer1, '{'), "layer1 must contain no literal brace byte (the escaping this test targets)")

	layer2, err := json.Marshal(layer1) // encode layer1 again as an ordinary JSON string
	require.NoError(t, err)
	sc, err := json.Marshal(map[string]interface{}{"data": json.RawMessage(layer2)})
	require.NoError(t, err)
	body := []byte(`{"structuredContent":`)
	body = append(body, sc...)
	body = append(body, '}')
	require.True(t, json.Valid(body), "test fixture must itself be well-formed JSON")

	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "SECRET", "ssn hidden behind a unicode-escaped-brace doubly-encoded layer must be redacted, not leaked in cleartext")
	assert.True(t, json.Valid(out), "redacted output must remain well-formed JSON")
}

// TestApplyRedactObligs_ArrayWrappedUnicodeEscapedBrace_Redacted pins the same
// unicode-escaped-brace evasion one container level further out: an ARRAY whose sole
// element is the escaped-brace string literal from
// TestApplyRedactObligs_UnicodeEscapedBraceDoublyEncoded_Redacted. arrayText contains no
// literal '{' byte anywhere (the object's braces are escaped, and the array's own
// delimiters are '['/']', not '{'/'}') and does not start with '"' — it starts with '[' —
// so the object-only fix (checking for a literal '{' or a leading '"') does not reach it;
// classifyRedactableLeaf must also treat a leading '[' as "might be JSON" so this array
// gets decoded and its wrapped object reached and redacted.
func TestApplyRedactObligs_ArrayWrappedUnicodeEscapedBrace_Redacted(t *testing.T) {
	t.Parallel()
	obj := "\"\\u007B\\\"ssn\\\":\\\"SECRET\\\"\\u007D\""
	arrayText := "[" + obj + "]"
	require.True(t, json.Valid([]byte(arrayText)), "arrayText must itself be valid JSON (an array containing a JSON string literal)")
	require.False(t, strings.ContainsRune(arrayText, '{'), "arrayText must contain no literal brace byte (the escaping this test targets)")
	require.False(t, strings.HasPrefix(arrayText, `"`), "arrayText must not start with a quote (it starts with the array's '[')")

	content := []byte(`{"content":[{"type":"text","text":` + strconv.Quote(arrayText) + `}]}`)
	require.True(t, json.Valid(content), "test fixture must itself be well-formed JSON")

	out, err := ApplyRedactObligs(content, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "SECRET", "ssn hidden behind an array-wrapped unicode-escaped-brace layer must be redacted, not leaked in cleartext")
	assert.True(t, json.Valid(out), "redacted output must remain well-formed JSON")
}

// TestApplyRedactObligs_ArrayWrappedDoublyEncoded_Redacted pins the DLP control at
// one container level below the top-level string: a text body (or a structuredContent
// string) that is an ARRAY whose elements are serialized JSON objects must still have
// the named field removed. The nested-string walk recurses into the array and unwraps
// each string element, so the secret is redacted rather than forwarded with no error.
func TestApplyRedactObligs_ArrayWrappedDoublyEncoded_Redacted(t *testing.T) {
	t.Parallel()
	// (1) content text body: text == ["{\"ssn\":\"LEAKED_SSN_VALUE\"}"]
	content := []byte(`{"content":[{"type":"text","text":"[\"{\\\"ssn\\\":\\\"LEAKED_SSN_VALUE\\\"}\"]"}]}`)
	outC, errC := ApplyRedactObligs(content, redactSSN)
	require.NoError(t, errC)
	assert.NotContains(t, string(outC), "LEAKED_SSN_VALUE", "ssn in an array-wrapped doubly-encoded text body must be redacted")

	// (2) structuredContent as a STRING wrapping the same array.
	sc := []byte(`{"structuredContent":"[\"{\\\"ssn\\\":\\\"LEAKED_SSN_VALUE\\\"}\"]"}`)
	outS, errS := ApplyRedactObligs(sc, redactSSN)
	require.NoError(t, errS)
	assert.NotContains(t, string(outS), "LEAKED_SSN_VALUE", "ssn in an array-wrapped doubly-encoded structuredContent string must be redacted")
}

// rebaseLeafPaths must not OVER-redact a doubly-encoded blob: a dotted path is anchored to
// the position the honest (un-encoded) shape would redact, so the encoded and honest shapes
// redact exactly the same field. Regression for a bug where the retained absolute path was
// re-applied at the unwrapped blob's root, deleting a same-named field one level too deep
// (manifest-fidelity violation / host data loss, asymmetric with the honest shape).
func TestApplyRedactObligs_RebaseNoOverRedact_HonestEqualsEncoded(t *testing.T) {
	t.Parallel()

	// Case A — an OVERLAPPING path whose leading segment repeats inside the blob. data.ssn
	// names structuredContent.data.ssn (OUTER) only; the deeper structuredContent.data.data.ssn
	// (INNER) is NOT named and must survive in BOTH the honest and doubly-encoded shapes.
	dataSSN := []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"data.ssn"}}}
	encA := []byte(`{"structuredContent":{"data":"{\"data\":{\"ssn\":\"INNER\"},\"ssn\":\"OUTER\"}"}}`)
	honA := []byte(`{"structuredContent":{"data":{"data":{"ssn":"INNER"},"ssn":"OUTER"}}}`)
	oEncA, eEncA := ApplyRedactObligs(encA, dataSSN)
	oHonA, eHonA := ApplyRedactObligs(honA, dataSSN)
	require.NoError(t, eEncA)
	require.NoError(t, eHonA)
	assert.NotContains(t, string(oHonA), "OUTER", "honest: the named field data.ssn is redacted")
	assert.Contains(t, string(oHonA), "INNER", "honest: the unnamed nested data.data.ssn survives")
	assert.NotContains(t, string(oEncA), "OUTER", "encoded: the named field is redacted, in parity with honest")
	assert.Contains(t, string(oEncA), "INNER", "encoded: the unnamed nested field must NOT be over-redacted")

	// Case B — a multi-segment path anchored ELSEWHERE (no top-level "user" key). The honest
	// shape redacts nothing; the doubly-encoded blob must likewise be left byte-for-byte intact.
	userEmail := []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"user.email"}}}
	encB := []byte(`{"structuredContent":{"account":"{\"user\":{\"email\":\"NESTED\"}}"}}`)
	honB := []byte(`{"structuredContent":{"account":{"user":{"email":"NESTED"}}}}`)
	oEncB, eEncB := ApplyRedactObligs(encB, userEmail)
	oHonB, eHonB := ApplyRedactObligs(honB, userEmail)
	require.NoError(t, eEncB)
	require.NoError(t, eHonB)
	assert.Equal(t, honB, oHonB, "honest: user.email names nothing here; response returned byte-for-byte")
	assert.Equal(t, encB, oEncB, "encoded: a path anchored elsewhere must NOT over-redact the blob")
}

// A clean JSON object nested past the depth limit inside a content[].text body fails the
// response closed, and the error must NOT misattribute the failure to structuredContent: the
// text path reaches the same depth guard. Regression for the hard-coded error wording.
func TestApplyRedactObligs_TextDepthError_NotMisattributed(t *testing.T) {
	t.Parallel()
	const depth = maxRedactionDepth + 50
	var b strings.Builder
	for i := 0; i < depth; i++ {
		b.WriteString(`{"a":`)
	}
	b.WriteString(`"x"`)
	for i := 0; i < depth; i++ {
		b.WriteString(`}`)
	}
	// The deep object is the body of a TEXT content item; the response has no structuredContent.
	textBody, err := json.Marshal(b.String())
	require.NoError(t, err)
	body := []byte(`{"content":[{"type":"text","text":` + string(textBody) + `}]}`)
	_, rerr := ApplyRedactObligs(body, redactSSN)
	require.Error(t, rerr, "a text body nested beyond the depth limit must fail closed")
	assert.NotContains(t, rerr.Error(), "structuredContent", "a text-body depth failure must not be misattributed to structuredContent")
	assert.Contains(t, rerr.Error(), "depth limit", "the error names the depth limit")
}

// A recognized non-text content item (image) carries no JSON text body, so it is
// preserved verbatim while redaction proceeds. This exercises
// isRecognizedContentType's true branch and the recognized-non-text continue.
func TestApplyRedactObligs_RecognizedNonTextContentPreserved(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"image","data":"abc","mimeType":"image/png"},{"type":"text","text":"{\"ssn\":\"SSN_SECRET_VALUE\"}"}]}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "image/png", "recognized non-text content preserved")
	assert.Contains(t, s, `\"ssn\":\"[redacted]\"`, "ssn in the text sibling is masked")
	assert.NotContains(t, s, "SSN_SECRET_VALUE", "the original ssn value must not survive masking")
}

// An unrecognized content type is structurally unverifiable and fails closed.
func TestApplyRedactObligs_UnrecognizedContentType_FailsClosed(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"hologram","payload":"secret"}]}`)
	_, err := ApplyRedactObligs(body, redactSSN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized type")
}

// A present-but-non-array content field fails the response closed.
func TestApplyRedactObligs_NonArrayContent_FailsClosed(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":{"type":"text","text":"x"}}`)
	_, err := ApplyRedactObligs(body, redactSSN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an array")
}

// A content item that is not an object fails closed.
func TestApplyRedactObligs_NonObjectContentItem_FailsClosed(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":["just a string"]}`)
	_, err := ApplyRedactObligs(body, redactSSN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an object")
}

// A content item with no string type cannot be classified and fails closed.
func TestApplyRedactObligs_ContentItemNoType_FailsClosed(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"text":"x"}]}`)
	_, err := ApplyRedactObligs(body, redactSSN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no string 'type'")
}

// A type=="text" item whose text body is not a string fails closed (an upstream
// could hide the secret inside an object-valued text field).
func TestApplyRedactObligs_NonStringTextBody_FailsClosed(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":{"ssn":"hidden"}}]}`)
	_, err := ApplyRedactObligs(body, redactSSN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-string 'text' body")
}

// An unparseable response envelope fails closed.
func TestApplyRedactObligs_UnparseableEnvelope_FailsClosed(t *testing.T) {
	t.Parallel()
	_, err := ApplyRedactObligs([]byte(`{not json`), redactSSN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse upstream response")
}

// Trailing data after the response envelope fails the whole response closed: a
// two-value body is a malformed/ambiguous envelope, matching the per-text-item
// guard and the documented "unparseable envelope fails closed" contract, rather
// than silently dropping the trailing value on re-marshal.
func TestApplyRedactObligs_TrailingDataAfterEnvelope_FailsClosed(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"{\"ssn\":\"123-45-6789\"}"}]}` + "\n" + `{"injected":true}`)
	_, err := ApplyRedactObligs(body, redactSSN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trailing data after response envelope")
}

// Every non-object result envelope under a redactFields directive fails closed: the
// array/scalar/bool shapes error on decode into a map, and a bare JSON null (which
// encoding/json decodes into a nil map with no error) is rejected explicitly so it does
// not slip through with the obligation marked applied though nothing was verified.
func TestApplyRedactObligs_NonObjectEnvelope_FailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "null", body: `null`, wantErr: "JSON null, not an object"},
		{name: "array", body: `[]`, wantErr: "cannot unmarshal"},
		{name: "string", body: `"x"`, wantErr: "cannot unmarshal"},
		{name: "number", body: `5`, wantErr: "cannot unmarshal"},
		{name: "bool", body: `true`, wantErr: "cannot unmarshal"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := ApplyRedactObligs([]byte(tc.body), redactSSN)
			require.Error(t, err, "a %s result envelope must fail closed, not forward unverified", tc.name)
			assert.Nil(t, out, "no bytes are returned when failing closed")
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// A text content body that is malformed JSON (a truncated object) is not a clean JSON
// container, so it passes through unchanged rather than failing closed.
func TestApplyRedactObligs_MalformedJSONTextBody_PassesThrough(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"{\"ssn\":\"x\""}]}`) // truncated object
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err, "malformed JSON text body passes through, not fail closed")
	assert.Equal(t, body, out)
}

// redactJSONText: prose is forwarded unchanged; a JSON scalar is unchanged; a clean JSON
// object is redacted; malformed/trailing-data JSON is not a clean container and passes through.
func TestRedactJSONText_Paths(t *testing.T) {
	t.Parallel()
	paths := []string{"ssn"}

	// Free-form prose: returned unchanged.
	out, err := redactJSONText("just a log line, not JSON", paths)
	require.NoError(t, err)
	assert.Equal(t, "just a log line, not JSON", out)

	// Bracketed log prefix is prose, not a container.
	out, err = redactJSONText("[ERROR] something failed", paths)
	require.NoError(t, err)
	assert.Equal(t, "[ERROR] something failed", out)

	// A JSON scalar string: no structured field, unchanged.
	out, err = redactJSONText(`"hello"`, paths)
	require.NoError(t, err)
	assert.Equal(t, `"hello"`, out)

	// A JSON object: ssn redacted, other fields preserved.
	out, err = redactJSONText(`{"ssn":"123","keep":"yes"}`, paths)
	require.NoError(t, err)
	assert.NotContains(t, out, "123")
	assert.Contains(t, out, "keep")

	// A top-level array of objects: masked element-by-element (key kept, value sentinel).
	out, err = redactJSONText(`[{"ssn":"a"},{"ssn":"b","keep":1}]`, paths)
	require.NoError(t, err)
	assert.Equal(t, `[{"ssn":"[redacted]"},{"keep":1,"ssn":"[redacted]"}]`, out)

	// A malformed object container is not clean JSON: passes through unchanged.
	out, err = redactJSONText(`{"ssn":"x"`, paths)
	require.NoError(t, err)
	assert.Equal(t, `{"ssn":"x"`, out)

	// Trailing data after a complete value is not a single clean JSON value: unchanged.
	out, err = redactJSONText(`{"ssn":"x"} trailing`, paths)
	require.NoError(t, err)
	assert.Equal(t, `{"ssn":"x"} trailing`, out)

	// A status-word prefix before a JSON object is not clean JSON either: unchanged
	// (accepted residual — embedded JSON in prose is out of scope; redact upstream).
	out, err = redactJSONText(`OK {"ssn":"x"}`, paths)
	require.NoError(t, err)
	assert.Equal(t, `OK {"ssn":"x"}`, out)

	// A scalar array (no object) is prose-like: unchanged.
	out, err = redactJSONText(`[1,2,3]`, paths)
	require.NoError(t, err)
	assert.Equal(t, `[1,2,3]`, out)
}

func TestIsRecognizedContentType(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"text", "image", "audio", "resource", "resource_link"} {
		assert.Truef(t, isRecognizedContentType(ok), "%q should be recognized", ok)
	}
	for _, bad := range []string{"hologram", "", "video", "TEXT"} {
		assert.Falsef(t, isRecognizedContentType(bad), "%q should not be recognized", bad)
	}
}

// RedactDotPath: nested keys, array traversal, JSONPath root marker handling, and
// $-prefixed real field names.
func TestRedactDotPath_Variants(t *testing.T) {
	t.Parallel()

	// Nested path through an object.
	obj := map[string]interface{}{"results": map[string]interface{}{"ssn": "x", "name": "a"}}
	redactDotPath(obj, "results.ssn")
	inner := obj["results"].(map[string]interface{})
	assert.Equal(t, "[redacted]", inner["ssn"], "nested ssn must be masked")
	assert.Contains(t, inner, "name")

	// Path through an array of objects (redactValuePath array branch).
	arr := map[string]interface{}{"rows": []interface{}{
		map[string]interface{}{"ssn": "a", "k": 1},
		map[string]interface{}{"ssn": "b", "k": 2},
	}}
	redactDotPath(arr, "rows.ssn")
	for _, it := range arr["rows"].([]interface{}) {
		m := it.(map[string]interface{})
		assert.Equal(t, "[redacted]", m["ssn"])
		assert.Contains(t, m, "k")
	}

	// Path through a nested array of arrays of objects.
	nested := map[string]interface{}{"grid": []interface{}{
		[]interface{}{map[string]interface{}{"ssn": "deep"}},
	}}
	redactDotPath(nested, "grid.ssn")
	leaf := nested["grid"].([]interface{})[0].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "[redacted]", leaf["ssn"], "ssn reachable through nested arrays must be masked")

	// "$." root marker stripped exactly once.
	dollar := map[string]interface{}{"ssn": "x", "keep": "y"}
	redactDotPath(dollar, "$.ssn")
	assert.Equal(t, "[redacted]", dollar["ssn"])
	assert.Contains(t, dollar, "keep")

	// A lone "$" targets the root: dotPath becomes "", masking the "" key (a
	// no-op on a normal object) without panicking.
	lone := map[string]interface{}{"a": 1}
	redactDotPath(lone, "$")
	assert.Contains(t, lone, "a")

	// A real $-prefixed field name ("$ref") is matched literally, not stripped.
	schema := map[string]interface{}{"$ref": "x", "ref": "keep"}
	redactDotPath(schema, "$ref")
	assert.Equal(t, "[redacted]", schema["$ref"], "$ref must be masked literally")
	assert.Contains(t, schema, "ref", "the unrelated sibling 'ref' must survive")

	// An absent key at any level is a no-op.
	redactDotPath(map[string]interface{}{"a": 1}, "missing.deep.key")
}

// redactValuePath leaves scalars and absent values untouched (the default
// switch arm) and descends through arrays/objects.
func TestRedactValuePath_ScalarAndAbsentNoOp(t *testing.T) {
	t.Parallel()
	// Scalar value at the traversal point: no-op (no panic).
	obj := map[string]interface{}{"a": "scalar"}
	redactDotPath(obj, "a.b.c")
	assert.Equal(t, "scalar", obj["a"], "a scalar mid-path is left untouched")

	// Object branch reached via redactValuePath.
	nested := map[string]interface{}{"a": map[string]interface{}{"b": map[string]interface{}{"secret": 1, "k": 2}}}
	redactDotPath(nested, "a.b.secret")
	leaf := nested["a"].(map[string]interface{})["b"].(map[string]interface{})
	assert.Equal(t, "[redacted]", leaf["secret"])
	assert.Contains(t, leaf, "k")
}

// redactJSONValue returns false for a pure-scalar array so the caller leaves the
// original bytes untouched, and true for a redactable structure.
func TestRedactJSONValue_ScalarArrayReturnsFalse(t *testing.T) {
	t.Parallel()
	assert.False(t, redactJSONValue([]interface{}{1.0, 2.0, "x"}, []string{"ssn"}))
	assert.False(t, redactJSONValue("scalar", []string{"ssn"}))
	assert.True(t, redactJSONValue(map[string]interface{}{"ssn": "x"}, []string{"ssn"}))
	assert.True(t, redactJSONValue([]interface{}{map[string]interface{}{"ssn": "x"}}, []string{"ssn"}))
}

// marshalNoHTMLEscape does not escape <, >, & and trims the trailing newline.
func TestMarshalNoHTMLEscape(t *testing.T) {
	t.Parallel()
	out, err := marshalNoHTMLEscape(map[string]interface{}{"url": "https://x/?a=1&b=2", "tag": "<b>"})
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "&b=2", "ampersand must not be HTML-escaped")
	assert.Contains(t, s, "<b>", "angle brackets must not be HTML-escaped")
	assert.False(t, strings.HasSuffix(s, "\n"), "trailing newline must be trimmed")

	// A value json.Marshal cannot encode surfaces an error.
	_, err = marshalNoHTMLEscape(make(chan int))
	require.Error(t, err)
}

// ApplyRedactObligs preserves <, >, & in non-redacted text via the
// no-HTML-escape re-marshal.
func TestApplyRedactObligs_PreservesHTMLChars(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"{\"ssn\":\"SSN_SECRET_VALUE\",\"html\":\"<b>&amp;</b>\"}"}]}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	// The non-redacted html field is preserved with its literal <, >, & rather
	// than HTML-escaped to the < / & unicode escapes
	// (marshalNoHTMLEscape sets SetEscapeHTML(false)).
	assert.Contains(t, s, "<b>&amp;</b>", "HTML characters must be preserved verbatim, not escaped")
	assert.NotContains(t, s, "\\u003c", "'<' must not be emitted as its unicode escape")
	assert.NotContains(t, s, "\\u0026", "'&' must not be emitted as its unicode escape")
	assert.Contains(t, s, `\"ssn\":\"[redacted]\"`, "the redacted field is masked, not removed")
	assert.NotContains(t, s, "SSN_SECRET_VALUE", "the original ssn value must not survive masking")
}

// TestApplyRedactObligs_TopLevelSiblingKey_Redacted: a declared field sitting DIRECTLY on
// a top-level result key must be redacted, not just one nested inside a sibling's value.
// The sibling pass only ever descended into each key's value, so the flat spelling
// forwarded the secret verbatim while the equivalent nested shape was masked — same
// obligation, same field name, opposite outcome depending on how deep the upstream put it.
func TestApplyRedactObligs_TopLevelSiblingKey_Redacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"hi"}],"ssn":"123-45-6789","keep":"v"}`)
	out, err := ApplyRedactObligs(body, redactSSN)
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "123-45-6789", "a redactFields path naming a top-level result key must mask it")
	assert.Contains(t, s, "keep")
	assert.Contains(t, s, "hi")
}

// The dotted spelling rooted at the envelope must work too: "data.ssn" against
// {"data":{"ssn":...}} names a real path through the result object.
func TestApplyRedactObligs_TopLevelDottedPath_Redacted(t *testing.T) {
	t.Parallel()
	body := []byte(`{"data":{"ssn":"SECRET-TOP","keep":"v"}}`)
	out, err := ApplyRedactObligs(body, []capability.Obligation{
		{Type: capability.DirectiveTypeRedactFields, Paths: []string{"data.ssn"}},
	})
	require.NoError(t, err)
	s := string(out)
	assert.NotContains(t, s, "SECRET-TOP")
	assert.Contains(t, s, "keep")
}

// A path rooted at content/structuredContent stays with those keys' own shape-specific
// passes: it must redact WITHIN the component, never mask the whole component (which
// would strip a result the host needs while the operator only asked for a field).
func TestApplyRedactObligs_ContentRootedPath_DoesNotMaskWholeComponent(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"text","text":"visible"}]}`)
	out, err := ApplyRedactObligs(body, []capability.Obligation{
		{Type: capability.DirectiveTypeRedactFields, Paths: []string{"content"}},
	})
	require.NoError(t, err)
	assert.Contains(t, string(out), "visible", "a content-rooted path must not mask the whole content array")
}
