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
	"io"
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

	// A leg with NO pin stamps nothing: on this tape an absent protocol_revision means
	// "written before one could be resolved", which is the truth for a connection that has
	// not negotiated yet (stdio pins only on its first dispatched message). Defaulting here
	// would put a revision on the tape for a negotiation that never happened — the same false
	// claim, in the other direction, that the stamp exists to remove.
	bare := &httpSession{id: "sess-2"}
	if got := capability.ProtocolRevisionFromContext(bare.withSessionRecordContext(context.Background())); got != "" {
		t.Errorf("an unpinned leg stamped %q, want no revision at all", got)
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

// TestKillDrop_NoSiteCanNameItsOwnTarget is the follow-up regression. Fixing the two refusals
// the review named left four sibling kill-DROP sites each passing their own method name, so a
// notification-framed tools/list on a revoked session still stamped a tool named tools/list.
// The rule is structural now — recordKillDrop takes the message — so this walks the call sites
// to keep it that way: none may pass a name of its own.
func TestKillDrop_NoSiteCanNameItsOwnTarget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		msg  mcp.RPCMsg
		want string
	}{
		{
			name: "a target-resolving method names no target",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", Method: capability.MethodToolsList},
			want: "",
		},
		{
			name: "a method that resolves none keeps its identifier",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/cancelled"},
			want: "notifications/cancelled",
		},
		{
			name: "a host response is labelled, not left blank",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{}`)},
			want: methodLabelServerResponse,
		},
		{
			name: "a leg with no message at all names neither field",
			msg:  mcp.RPCMsg{},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			recordKillDrop(context.Background(), rec, killDeny(), verifiedSession("sess-1"), tc.msg, legHTTPNotification)
			if len(rec.records) != 1 {
				t.Fatalf("expected one record, got %d", len(rec.records))
			}
			if got := rec.records[0].identifier; got != tc.want {
				t.Errorf("identifier = %q, want %q — the identifier is what the sink derives target_type/target from", got, tc.want)
			}
		})
	}
}

// TestServerInitiatedLeg_NoRecordNamesAPolicyTarget is the same rule on the leg where the METHOD
// is the upstream's own choice.
//
// Neither transport's reader gates which methods an upstream may name in a server-initiated
// request, and the non-sampling branch of forwardServerRequest runs no PDP at all — its own doc
// says so. Passing the method through as the identifier therefore let an upstream send
// `{"id":1,"method":"tools/call"}` and have the sink synthesize `target_type: tool, target:
// tools/call` from it. The ALLOW arm is the one that matters most: `eunox suggest` mines allow
// records into a proposed manifest, and only DENY records are filtered by IsInfraDenialCode — so
// the upstream, not the operator, chose a capability in the draft.
func TestServerInitiatedLeg_NoRecordNamesAPolicyTarget(t *testing.T) {
	t.Parallel()
	// tools/call because it RESOLVES a target type; a method that resolves none cannot show the bug.
	call := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall}

	for _, tc := range []struct {
		name string
		// leg mutates the params into the posture under test.
		leg  func(*serverRequestParams, *fwdRecorder)
		want string
	}{
		{
			name: "forwarded and delivered (the allow suggest mines)",
			leg:  func(*serverRequestParams, *fwdRecorder) {},
		},
		{
			name: "no client accepted it",
			leg: func(fp *serverRequestParams, _ *fwdRecorder) {
				fp.forward = func(context.Context, mcp.RPCMsg) forwardOutcome { return forwardUndelivered }
			},
		},
		{
			name: "the session was revoked",
			leg: func(fp *serverRequestParams, _ *fwdRecorder) {
				ks := killswitch.NewInMemory()
				if err := ks.KillSession(context.Background(), "sess-1"); err != nil {
					t.Fatalf("KillSession: %v", err)
				}
				fp.pdp = newTestManifestPDPWithKS(ks)
			},
		},
		{
			name: "the audit trail degraded under --require-audit=strict",
			leg: func(fp *serverRequestParams, rec *fwdRecorder) {
				rec.degraded, rec.reason = true, "audit trail degraded (test probe)"
				fp.requireAuditStrict = true
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			fp := serverRequestParams{
				sessionID: "sess-1",
				pdp:       pdp.AlwaysAllowPDP{},
				forward:   func(context.Context, mcp.RPCMsg) forwardOutcome { return forwardDelivered },
				unblocker: answeringSeam(func(mcp.RPCMsg) error { return nil }, rec, httpServerRequestLegs, io.Discard),
			}
			tc.leg(&fp, rec)

			forwardServerRequest(revisionContext(handshakeRevision), call, fp)

			if len(rec.records) != 1 {
				t.Fatalf("expected one record, got %d: %+v", len(rec.records), rec.records)
			}
			if got := rec.records[0].identifier; got != tc.want {
				t.Errorf("identifier = %q, want %q — nothing on this leg decides, so no record may name a policy target the PDP never saw", got, tc.want)
			}
		})
	}

	// The control: the sampling leg's policy deny KEEPS its identifier. A PDP ran there and
	// `system:sampling/createMessage` is the manifest target it decided against, so blanking it
	// would lose the one target on this leg that is real.
	t.Run("a policy decision names its real target", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		forwardServerRequest(revisionContext(handshakeRevision),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: capability.MethodSamplingCreateMessage},
			serverRequestParams{
				sessionID: "sess-1", pdp: pdp.DenyAllPDP{},
				unblocker: answeringSeam(func(mcp.RPCMsg) error { return nil }, rec, httpServerRequestLegs, io.Discard),
			})
		if len(rec.records) != 1 {
			t.Fatalf("expected one record, got %d", len(rec.records))
		}
		if got := rec.records[0].identifier; got != capability.MethodSamplingCreateMessage {
			t.Errorf("identifier = %q, want %q — a refusal a PDP produced names the target it decided against",
				got, capability.MethodSamplingCreateMessage)
		}
	})
}

// TestServerInitiatedAllow_ReachesTheTapeWithNoTarget is the same finding read off the SIGNED
// record rather than off the identifier the sink derives it from, since what an operator and
// `eunox suggest` consume is the tape.
func TestServerInitiatedAllow_ReachesTheTapeWithNoTarget(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	rec := asRecorder(&routeSink{sink: sink, upstream: "up1"})

	forwardServerRequest(revisionContext(handshakeRevision),
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall},
		serverRequestParams{
			sessionID: "sess-1", pdp: pdp.AlwaysAllowPDP{},
			forward:   func(context.Context, mcp.RPCMsg) forwardOutcome { return forwardDelivered },
			unblocker: answeringSeam(func(mcp.RPCMsg) error { return nil }, rec, httpServerRequestLegs, io.Discard),
		})
	_ = sink.Close()

	got := findAuditRecordByMethod(readAuditRecords(t, logPath), capability.MethodToolsCall, "allow")
	if got == nil {
		t.Fatal("the forwarded server-initiated request left no allow record")
	}
	requireNoPhantomTarget(t, got, "allow")
}

// TestSessionGateDeny_RecordsNoPhantomTarget is the rule at the one site an UNAUTHORIZED caller
// drives, and the reason it matters more here than on the upstream leg: the worker id is DERIVED
// from claims (issuer, subject, agent id), so anyone who can name those for a victim can address
// that worker, and the POST body then chose the target. AUTHORIZATION_FAILED is a policy class, so
// unlike the leg above `eunox suggest` does not skip these.
func TestSessionGateDeny_RecordsNoPhantomTarget(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	route := &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{sink: sink, upstream: "up1"}}
	proxy := newTestHTTPProxy()
	// BOUND to a victim's identity, which is what makes the owner binding refuse a request
	// carrying none.
	proxy.sessions["sess-1"] = newTestSession(&httpSession{
		id: "sess-1", route: route, hostRev: handshakeRevision, done: make(chan struct{}),
		claims: &pdp.JWTClaims{Issuer: "https://idp.example", Subject: "victim"},
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "sess-1")
	proxy.handleSessionPost(httptest.NewRecorder(), req, route, "sess-1",
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall})
	_ = sink.Close()

	got := findAuditRecordByCode(readAuditRecords(t, logPath), capability.ErrCodeAuthorizationFailed)
	if got == nil {
		t.Fatal("a request refused by the session-owner binding left no AUTHORIZATION_FAILED record")
	}
	if method, _ := got["method"].(string); method != capability.MethodToolsCall {
		t.Errorf("record method=%q, want %q — the method field is where the name belongs", method, capability.MethodToolsCall)
	}
	requireNoPhantomTarget(t, got, capability.ErrCodeAuthorizationFailed)
}
