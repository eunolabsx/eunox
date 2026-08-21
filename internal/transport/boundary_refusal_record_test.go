// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The two properties every refusal taken with NO policy decision behind it owes the signed
// tape: it may not fabricate a target the sink derives from a method name, and — on an
// established session — it may not record the absence that means "written before a revision
// could be resolved".

package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// recordsFromSessionPost drives one host message through the established-session POST path and
// returns the records the sink took.
func recordsFromSessionPost(t *testing.T, p *pdp.ManifestPDP, msg mcp.RPCMsg) []map[string]interface{} {
	t.Helper()
	sink, logPath := newTempAuditSink(t)
	route := &UpstreamRoute{name: "up1", pdp: p, sink: &routeSink{sink: sink, upstream: "up1"}}
	proxy := newTestHTTPProxy()
	proxy.sessions["sess-1"] = newTestSession(&httpSession{
		id: "sess-1", route: route, hostRev: handshakeRevision, done: make(chan struct{}),
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "sess-1")
	proxy.handleSessionPost(httptest.NewRecorder(), req, route, "sess-1", msg)
	_ = sink.Close()
	return readAuditRecords(t, logPath)
}

// requireNoPhantomTarget fails when a record carries target fields the sink can only have
// synthesized from the method name it was handed as an identifier.
func requireNoPhantomTarget(t *testing.T, rec map[string]interface{}, code string) {
	t.Helper()
	if target, ok := rec["target"]; ok && target != "" {
		t.Errorf("%s recorded target=%q — the identifier must be dropped for a method that resolves a target type, or the sink stamps a target named after the method", code, target)
	}
	if tt, ok := rec["target_type"]; ok && tt != "" {
		t.Errorf("%s recorded target_type=%q, want none", code, tt)
	}
}

// TestKillDenial_RecordsNoPhantomTarget is the A5 regression for the boundary kill gate. A
// kill on tools/list stamped target_type=tool target=tools/list — a tool literally named
// after the method — contradicting the one rule every policy-free refusal follows and
// polluting target-based aggregation on the signed tape.
func TestKillDenial_RecordsNoPhantomTarget(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	if err := ks.KillSession(context.Background(), "sess-1"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	records := recordsFromSessionPost(t,
		newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call", "list"}}),
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsList})

	rec := findAuditRecordByCode(records, capability.ErrCodeKillSwitch)
	if rec == nil {
		t.Fatalf("a killed session's tools/list left no KILL_SWITCH record; got %+v", records)
	}
	if method, _ := rec["method"].(string); method != capability.MethodToolsList {
		t.Errorf("record method=%q, want %q — the method field is where the name belongs", method, capability.MethodToolsList)
	}
	requireNoPhantomTarget(t, rec, capability.ErrCodeKillSwitch)
}

// TestMalformedDeny_RecordsNoPhantomTarget is the A5 regression for the other boundary
// refusal. Every method reaching malformedDeny resolves a target type, so passing the method
// through as the identifier synthesized exactly the `tool:tools/call` phantom the function's
// own comment claimed it avoided.
func TestMalformedDeny_RecordsNoPhantomTarget(t *testing.T) {
	t.Parallel()
	records := recordsFromSessionPost(t,
		newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		mcp.RPCMsg{
			JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
			Params: json.RawMessage(`{"name":""}`),
		})

	rec := findAuditRecordByCode(records, codeInvalidRequest)
	if rec == nil {
		t.Fatalf("an empty tools/call name left no %s record; got %+v", codeInvalidRequest, records)
	}
	requireNoPhantomTarget(t, rec, codeInvalidRequest)
}

// TestEstablishedSessionLegsStampTheSessionRevision is the A4 regression. The upstream-driven
// legs write from a context no host request ever passed through, and the sink OMITS
// protocol_revision for such a context — which on this tape is documented to mean "written
// before a revision could be resolved". Every established session pinned one at creation.
func TestEstablishedSessionLegsStampTheSessionRevision(t *testing.T) {
	t.Parallel()
	s := &httpSession{id: "sess-1", hostRev: handshakeRevision}
	got := capability.ProtocolRevisionFromContext(s.withSessionRecordContext(context.Background()))
	if got != handshakeRevision {
		t.Errorf("withSessionRecordContext left protocol_revision %q, want the session's pin %q", got, handshakeRevision)
	}

	// A session that never pinned one still records a revision rather than the absence:
	// resolveRevision's empty-carrier rule is the surface eunox already shipped.
	bare := &httpSession{id: "sess-2"}
	if got := capability.ProtocolRevisionFromContext(bare.withSessionRecordContext(context.Background())); got != capability.DefaultRevision {
		t.Errorf("an unpinned session resolved %q, want %q", got, capability.DefaultRevision)
	}
}

// TestEnsureProtocolRevision_NeverOverwritesTheRequestsOwn pins the half that makes the same
// helper safe on a leg that DOES have a request in scope: a session-level pin must not
// replace the revision the request was actually decided under, which is what a second
// unconditional stamp would do on a session spanning revisions.
func TestEnsureProtocolRevision_NeverOverwritesTheRequestsOwn(t *testing.T) {
	t.Parallel()
	ctx := capability.WithProtocolRevision(context.Background(), capability.DefaultRevision)
	got := capability.ProtocolRevisionFromContext(ensureProtocolRevision(ctx, "2026-07-28"))
	if got != capability.DefaultRevision {
		t.Errorf("ensureProtocolRevision overwrote a resolved revision with %q", got)
	}
}
