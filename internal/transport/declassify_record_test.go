// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
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
