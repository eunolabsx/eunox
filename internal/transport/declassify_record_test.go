// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// declassifiedAllow is the decision an approved declassification produces.
func declassifiedAllow() capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision:      capability.DecisionAllow,
		CarriedLabels: []string{capability.FlowLabelInternal, capability.FlowLabelPII},
		LabelsCleared: []string{capability.FlowLabelPII},
		Approver:      "alice@example.com",
		ApprovalID:    "apr-9",
	}
}

func cleanUpstream() func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
	return func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
		return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
	}
}

// TestEnforcedForwardCore_DeclassifiedAllowRecordsTheApproval covers the transport leg of
// the declassification record — the branch that chooses the approval-carrying recorder,
// and the one that lands the three fields on the tape.
//
// It exists because that leg had NO coverage: the branch and routeSink's recorder were
// both never executed by any test, leaving the field wiring for the rarest records on the
// tape — and the ones an auditor most needs complete — unguarded.
func TestEnforcedForwardCore_DeclassifiedAllowRecordsTheApproval(t *testing.T) {
	rec := &fwdRecorder{}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	resp := enforcedForwardCore(context.Background(), fp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Nil(t, resp.Error)
	require.Len(t, rec.records, 1)
	got := rec.records[0]
	assert.Equal(t, "allow", got.decision, "a declassification is an allow; labels_cleared is what distinguishes it")
	assert.Equal(t, []string{capability.FlowLabelPII}, got.labelsCleared)
	assert.Equal(t, "alice@example.com", got.approver)
	assert.Equal(t, "apr-9", got.approvalID)
	assert.Equal(t, []string{capability.FlowLabelInternal, capability.FlowLabelPII}, got.carriedLabels)
	assert.Nil(t, got.details, "the approval's facts are fields, never injected into the details map")
}

// TestEnforcedForwardCore_OrdinaryAllowCarriesNoApproval is the negative half: a call that
// cleared nothing takes the plain recorder and stamps none of the three fields, so no
// ordinary allow can be mistaken for a declassification.
func TestEnforcedForwardCore_OrdinaryAllowCarriesNoApproval(t *testing.T) {
	rec := &fwdRecorder{}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	enforcedForwardCore(context.Background(), fp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	require.Len(t, rec.records, 1)
	assert.Empty(t, rec.records[0].labelsCleared)
	assert.Empty(t, rec.records[0].approver)
	assert.Empty(t, rec.records[0].approvalID)
}

// TestEnforcedForwardCore_DeclassifyDoesNotMutateCallerDetails is the aliasing guard. On
// the audit-mode tools/call path the details map an allowDetails closure returns IS the
// caller's live parsed argument map, which dispatch.go documents must never be mutated.
// Writing the approval id into it put a key the caller never sent onto the signed tape and
// silently overwrote a real argument of the same name.
func TestEnforcedForwardCore_DeclassifyDoesNotMutateCallerDetails(t *testing.T) {
	rec := &fwdRecorder{}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	// A closure returning the caller's own map by reference, as the tools/call one does.
	live := map[string]interface{}{"path": "/tmp/x"}
	enforcedForwardCore(context.Background(), fp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false,
		func(mcp.RPCMsg) map[string]interface{} { return live })

	assert.Equal(t, map[string]interface{}{"path": "/tmp/x"}, live,
		"the caller's argument map must be untouched")
	require.Len(t, rec.records, 1)
	assert.Equal(t, "apr-9", rec.records[0].approvalID, "the approval id travels as a field")
}

// TestRouteSink_DeclassifiedAllowStampsRouteIdentity pins that the gateway wrapper stamps
// the same route provenance on a declassification record that it stamps on every other
// allow. It is a hand-maintained parallel of RecordAllow, so a dropped route field would
// otherwise produce a valid, signed, chain-verified record with a blank upstream — and
// only on the rarest record shape.
func TestRouteSink_DeclassifiedAllowStampsRouteIdentity(t *testing.T) {
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	require.NoError(t, err)
	rs := &routeSink{sink: sink, upstream: "crm", policyVersion: "1.2.3", policySHA256: "abc123"}

	rs.RecordDeclassifiedAllow(context.Background(), "s", "sanitize", "tools/call", nil, nil, false,
		nil, []string{capability.FlowLabelPII}, []string{capability.FlowLabelPII}, "alice@example.com", "apr-9")
	require.NoError(t, sink.Close())

	raw, err := os.ReadFile(dir + "/audit.jsonl")
	require.NoError(t, err)
	line := strings.TrimSpace(string(raw))
	for _, want := range []string{
		`"upstream":"crm"`, `"policy_version":"1.2.3"`, `"policy_sha256":"abc123"`,
		`"labels_cleared":["pii"]`, `"approver":"alice@example.com"`, `"approval_id":"apr-9"`,
	} {
		assert.Contains(t, line, want)
	}
}

// restoreSpy is the transport's view of the PDP for the undo path: it records what it was
// asked to put back, and can fault on demand so the fail-open residual is reachable.
type restoreSpy struct {
	labels  []string
	calls   int
	failErr error
}

func (r *restoreSpy) RestoreDeclassified(_ context.Context, _ string, labels []string) error {
	r.calls++
	r.labels = append([]string(nil), labels...)
	return r.failErr
}

// TestEnforcedForwardCore_RefusalAfterDeclassifyRestoresTheLabels is the fail-open the
// declassify commit ordering opened. The clear happens inside Decide; three of this
// transport's own gates then refuse the call WITHOUT ever reaching the upstream, so the
// sanitizing action never runs while the taint it was authorized to clear is already gone.
// The next egress flowLabel would have blocked now passes.
//
// labelOutput's identical ordering is safe — a call that taints and then fails leaves EXTRA
// taint, which over-blocks — so only this direction needs the undo. And unlike the engine's
// internal fault arms, nothing below the decision could reach the flow store before this
// seam existed.
func TestEnforcedForwardCore_RefusalAfterDeclassifyRestoresTheLabels(t *testing.T) {
	for name, tc := range map[string]struct {
		fp       func(*fwdRecorder, *restoreSpy) forwardParams
		wantCode string
	}{
		// --require-audit=strict with a degraded trail: the upstream is never called.
		"strict-audit gate": {
			func(rec *fwdRecorder, spy *restoreSpy) forwardParams {
				rec.degraded, rec.reason = true, "audit trail degraded"
				return forwardParams{
					rec: rec, sessionID: "s", callUpstream: cleanUpstream(), restorer: spy,
					strictAuditState: strictAuditState{requireAuditStrict: true},
				}
			},
			capability.ErrCodeAuditUnavailable,
		},
		"upstream failure": {
			func(rec *fwdRecorder, spy *restoreSpy) forwardParams {
				return forwardParams{
					rec: rec, sessionID: "s", restorer: spy,
					callUpstream: func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
						return mcp.RPCMsg{}, errors.New("upstream gone")
					},
				}
			},
			codeUpstreamError,
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec, spy := &fwdRecorder{}, &restoreSpy{}
			enforcedForwardCore(context.Background(), tc.fp(rec, spy), mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
				declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

			require.Equal(t, 1, spy.calls, "a refusal below the decision must undo the clear it committed")
			assert.Equal(t, []string{capability.FlowLabelPII}, spy.labels,
				"exactly what the decision reported CHANGED, not what the approval authorized")

			require.Len(t, rec.records, 1)
			got := rec.records[0]
			assert.Equal(t, "deny", got.decision)
			assert.Equal(t, tc.wantCode, got.code)
			assert.Equal(t, []string{capability.FlowLabelPII}, got.details["declassify_reverted"],
				"the tape must say a declassification was committed and undone; the record was silent about it")
			assert.Equal(t, "apr-9", got.details["declassify_approval_id"],
				"the grant stays burned, so the record names it for reconciliation")
			assert.Equal(t, true, got.details["flow"])
			assert.Nil(t, got.details["declassify_orphaned"], "the restore succeeded")
		})
	}
}

// TestEnforcedForwardCore_RedactionFailureRestoresTheLabels is the third exit. It is
// separate because its refusal is produced inside the response-handling block rather than
// by a gate, so it takes a different route to the same record.
func TestEnforcedForwardCore_RedactionFailureRestoresTheLabels(t *testing.T) {
	rec, spy := &fwdRecorder{}, &restoreSpy{}
	fp := forwardParams{rec: rec, sessionID: "s", restorer: spy,
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			// A result the redact path cannot walk, so ApplyRedactObligs fails.
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`"not-an-object"`)}, nil
		}}
	dec := declassifiedAllow()
	dec.Obligations = []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"$.ssn"}}}

	resp := enforcedForwardCore(context.Background(), fp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		dec, "tools/call", "sanitize", "sanitize", "tool", true, upstreamErrorDetail)

	require.NotNil(t, resp.Error, "a redaction failure must not forward the response")
	require.Equal(t, 1, spy.calls)
	require.Len(t, rec.records, 1)
	assert.Equal(t, capability.ErrCodeEnforcementError, rec.records[0].code)
	assert.Equal(t, []string{capability.FlowLabelPII}, rec.records[0].details["declassify_reverted"])
}

// TestEnforcedForwardCore_UnrestorableDeclassifyIsRecorded is the residual. The restore is
// best-effort — the flow store may be the very thing that is unreachable — and when it
// fails the labels really are gone for a call that never ran. That is a genuine fail-open,
// and the ONE thing the record has to carry, because nothing else can tell the operator
// their session is now less tainted than the calls it actually made.
func TestEnforcedForwardCore_UnrestorableDeclassifyIsRecorded(t *testing.T) {
	rec := &fwdRecorder{degraded: true, reason: "audit trail degraded"}
	spy := &restoreSpy{failErr: errors.New("flow store unreachable")}
	fp := forwardParams{
		rec: rec, sessionID: "s", callUpstream: cleanUpstream(), restorer: spy,
		strictAuditState: strictAuditState{requireAuditStrict: true},
	}

	enforcedForwardCore(context.Background(), fp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Len(t, rec.records, 1)
	got := rec.records[0]
	assert.Equal(t, []string{capability.FlowLabelPII}, got.details["declassify_orphaned"],
		"a label that could not be put back is the fail-open residual and must be on the tape")
	assert.Nil(t, got.details["declassify_reverted"], "it was not reverted")
	assert.Equal(t, "apr-9", got.details["declassify_approval_id"])
	// The strict gate's own counts survive the merge — the undo adds fields, never replaces
	// the record the refusal is actually about.
	assert.Equal(t, capability.ErrCodeAuditUnavailable, got.code)
}

// TestEnforcedForwardCore_OrdinaryRefusalTouchesNoRestorer is the negative half: a call
// that cleared nothing must not reach the restorer at all, and its refusal record must not
// grow declassify fields. This is every call in a deployment with no declassify directive.
func TestEnforcedForwardCore_OrdinaryRefusalTouchesNoRestorer(t *testing.T) {
	rec, spy := &fwdRecorder{}, &restoreSpy{}
	fp := forwardParams{rec: rec, sessionID: "s", restorer: spy,
		callUpstream: func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{}, errors.New("upstream gone")
		}}

	enforcedForwardCore(context.Background(), fp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	assert.Zero(t, spy.calls, "a decision that cleared nothing has nothing to undo")
	require.Len(t, rec.records, 1)
	assert.Nil(t, rec.records[0].details["declassify_reverted"])
	assert.Nil(t, rec.records[0].details["declassify_orphaned"])
}

// TestEnforcedForwardCore_SuccessfulForwardDoesNotUndo guards the ordering mistake this
// seam invites: the undo runs only where a refusal is actually returned. Evaluating it
// alongside the strict-audit gate rather than inside its blocking arm would revert the
// clear on every clean forward, silently un-doing every declassification the proxy performs.
func TestEnforcedForwardCore_SuccessfulForwardDoesNotUndo(t *testing.T) {
	rec, spy := &fwdRecorder{}, &restoreSpy{}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream(), restorer: spy,
		strictAuditState: strictAuditState{requireAuditStrict: true}} // strict on, trail HEALTHY

	resp := enforcedForwardCore(context.Background(), fp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Nil(t, resp.Error)
	assert.Zero(t, spy.calls, "a forwarded call's declassification stands")
	require.Len(t, rec.records, 1)
	assert.Equal(t, []string{capability.FlowLabelPII}, rec.records[0].labelsCleared)
}

// TestStartupFatalManifestCheck_DeclassifyNeedsAnHTTPHost refuses a declassify directive on
// a stdio HOST at startup, where it could never be satisfied.
//
// An approval arrives only on a validated JWT, and --jwks-uri is categorically rejected on
// a stdio host — no stdio path populates claims at all — so every call to such a capability
// escalates ESCALATION_REQUIRED/no_approval forever with no way to approve it and no error
// to explain why. That is the same "the capability could never be satisfied" outcome
// validateDeclassify refuses an empty label list to avoid, reached by another route, and it
// is decidable from the config alone exactly as the audience-pin refusal beside it is.
//
// The axis is the HOST transport, not the upstream's: a stdio UPSTREAM behind an http
// gateway is fine, because the token arrives on the host leg.
func TestStartupFatalManifestCheck_DeclassifyNeedsAnHTTPHost(t *testing.T) {
	declassifying := &config.LocalManifest{
		SchemaVersion: config.ManifestSchemaVersion02,
		Name:          "p",
		Version:       "1.0.0",
		Capabilities: []capability.Constraint{{
			Target:     "tool:sanitize",
			Actions:    []string{"call"},
			Directives: []capability.Directive{capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}},
		}},
	}
	u := &config.UpstreamConfig{Name: "up"}

	err := startupFatalManifestCheck(u, config.HostTransportStdio, declassifying)
	require.Error(t, err, "a stdio host cannot present an approval, so the directive must be refused at startup")
	assert.Contains(t, err.Error(), "declassify")

	assert.NoError(t, startupFatalManifestCheck(u, config.HostTransportHTTP, declassifying),
		"an http host can present an approval, so the same manifest boots")

	// A manifest without the directive is unaffected on either host.
	plain := &config.LocalManifest{
		SchemaVersion: config.ManifestSchemaVersion02, Name: "p", Version: "1.0.0",
		Capabilities: []capability.Constraint{{Target: "tool:read", Actions: []string{"call"}}},
	}
	assert.NoError(t, startupFatalManifestCheck(u, config.HostTransportStdio, plain))
}
