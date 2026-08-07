// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The per-message gate order, asserted rather than described. The order itself is declared
// once, in dispatch.go's package comment; these cells pin the two properties a reordered
// transport prologue would silently change — which gate refuses a message first, and
// therefore which code a revoked session's probes are recorded under, a SIEM-facing signal
// during an emergency stop.

package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// unknownRevisionCall is a request declaring a revision no build speaks, so its revision
// cannot be resolved at all — the shape that reaches the refusal ahead of every later gate.
func unknownRevisionCall(id string) mcp.RPCMsg {
	return mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(id), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"probe","_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}`),
	}
}

// TestGateOrder_RevisionRefusalPrecedesKillOnStdio pins the exception the ordering costs, on
// the transport whose prologue places it: a revoked session's bad-version probe is recorded
// as UNSUPPORTED_PROTOCOL_VERSION, not KILL_SWITCH. Driven through the real serve loop, so
// moving the negotiation call after the per-message kill check fails here rather than quietly
// relabelling an incident responder's evidence.
//
// The second message is the bound on that exception: on the same revoked session, a message
// whose revision DOES resolve is refused by the kill gate as always.
func TestGateOrder_RevisionRefusalPrecedesKillOnStdio(t *testing.T) {
	ks := killswitch.NewInMemory()
	if err := ks.KillSession(context.Background(), "killed-sess"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	sink, logPath := newTempAuditSink(t)
	pr, pw := io.Pipe()
	hw := &mockHostWriter{}
	p := &StdioProxy{
		pdp:          newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sessionID:    "killed-sess",
		sink:         sink,
		hostReader:   mcp.NewMsgReader(pr),
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		stderr:       io.Discard,
		upstreamDone: make(chan struct{}),
	}

	done := make(chan struct{})
	go func() { p.serveHost(context.Background()); close(done) }()

	enc := json.NewEncoder(pw)
	if err := enc.Encode(unknownRevisionCall(`1`)); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	if err := enc.Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: methodPing}); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	_ = pw.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveHost did not return after the host closed stdin")
	}
	_ = sink.Close()

	records := readAuditRecords(t, logPath)
	probe := findAuditRecordByMethod(records, capability.MethodToolsCall, "deny")
	if probe == nil {
		t.Fatalf("the bad-version probe left no record; got %+v", records)
	}
	if code, _ := probe["denial_code"].(string); code != capability.ErrCodeUnsupportedProtocolVersion {
		t.Errorf("probe denial_code = %q, want %q — negotiation must refuse before the kill gate, since a message with no resolvable revision has no method table to be looked up in", code, capability.ErrCodeUnsupportedProtocolVersion)
	}
	ping := findAuditRecordByMethod(records, methodPing, "deny")
	if ping == nil {
		t.Fatalf("the revocation gate left no record for the resolvable message; got %+v", records)
	}
	if code, _ := ping["denial_code"].(string); code != capability.ErrCodeKillSwitch {
		t.Errorf("ping denial_code = %q, want %q — the exception is scoped to messages whose revision cannot be resolved", code, capability.ErrCodeKillSwitch)
	}
}

// TestGateOrder_RevisionRefusalPrecedesKillOnHTTP is the same property on the other
// transport, which places the same two gates in its own prologue. Asserting it on both is the
// point: the ordering is a shared rule, and the failure mode is one prologue drifting.
func TestGateOrder_RevisionRefusalPrecedesKillOnHTTP(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	if err := ks.KillSession(context.Background(), "killed-sess"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	sink, logPath := newTempAuditSink(t)
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{sink: sink, upstream: "up1"},
	}
	proxy := newTestHTTPProxy()
	proxy.sessions["killed-sess"] = newTestSession(&httpSession{
		id: "killed-sess", route: route, hostRev: handshakeRevision, done: make(chan struct{}),
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "killed-sess")
	w := httptest.NewRecorder()
	proxy.handleSessionPost(w, req, route, "killed-sess", unknownRevisionCall(`1`))
	_ = sink.Close()

	if !strings.Contains(w.Body.String(), "-32022") {
		t.Errorf("response body = %q, want the -32022 revision refusal", w.Body.String())
	}
	records := readAuditRecords(t, logPath)
	probe := findAuditRecordByMethod(records, capability.MethodToolsCall, "deny")
	if probe == nil {
		t.Fatalf("the bad-version probe left no record; got %+v", records)
	}
	if code, _ := probe["denial_code"].(string); code != capability.ErrCodeUnsupportedProtocolVersion {
		t.Errorf("probe denial_code = %q, want %q — both transports must place negotiation ahead of the kill check", code, capability.ErrCodeUnsupportedProtocolVersion)
	}
}

// TestGateOrder_DispatchedRecordsNameTheRevisionTheyRoutedBy is the end-to-end half of the
// single-carrier property: a request that actually reaches the dispatcher must leave a record
// naming the revision whose table routed it. An absent protocol_revision is reserved for a
// record written before any revision was resolved, so a transport that routed by one value
// and recorded nothing is the exact confusion the two carriers used to allow.
func TestGateOrder_DispatchedRecordsNameTheRevisionTheyRoutedBy(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	route := &UpstreamRoute{
		name: "up1",
		pdp:  pdp.AlwaysAllowPDP{},
		sink: &routeSink{sink: sink, upstream: "up1"},
	}
	proxy := newTestHTTPProxy()
	proxy.sessions["live-sess"] = newTestSession(&httpSession{
		id: "live-sess", route: route, hostRev: handshakeRevision, done: make(chan struct{}),
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(SessionHeader, "live-sess")
	proxy.handleSessionPost(httptest.NewRecorder(), req, route, "live-sess",
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "agents/delegate"})
	_ = sink.Close()

	rec := findAuditRecordByMethod(readAuditRecords(t, logPath), "agents/delegate", "deny")
	if rec == nil {
		t.Fatal("the unmapped method left no record")
	}
	if got, _ := rec["protocol_revision"].(string); got != handshakeRevision.String() {
		t.Errorf("protocol_revision = %q, want %q — the record must name the revision whose table refused it", got, handshakeRevision)
	}
}

// TestGateOrder_ServerInitiatedLegInheritsTheRevisionStamp is the regression for the entry
// point that had NEITHER carrier: the server-initiated leg has no host request to read a
// revision from, so every sampling decision on a negotiated session was recorded as though
// none had been resolved — indistinguishable on the tape from a pre-session refusal. The
// transports now supply the session's revision as a fact and the shared leg does the stamping,
// so a future server-initiated entry point inherits it rather than re-placing it.
func TestGateOrder_ServerInitiatedLegInheritsTheRevisionStamp(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	fp := serverRequestParams{
		rec:           &routeSink{sink: sink, upstream: "up1"},
		sessionID:     "sess",
		pdp:           pdp.AlwaysAllowPDP{},
		revision:      capability.Revision20260728,
		forward:       func(mcp.RPCMsg) bool { return true },
		writeUpstream: func(mcp.RPCMsg) {},
		errOut:        io.Discard,
	}
	forwardServerRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "roots/list"}, fp)
	_ = sink.Close()

	rec := findAuditRecordByMethod(readAuditRecords(t, logPath), "roots/list", "")
	if rec == nil {
		t.Fatal("the server-initiated forward left no record")
	}
	if got, _ := rec["protocol_revision"].(string); got != capability.Revision20260728.String() {
		t.Errorf("protocol_revision = %q, want %q — this leg's records must name the revision its session negotiated", got, capability.Revision20260728)
	}
}

// TestGateOrder_NotificationGateAppliesTheCanonicalOrder pins the shared notification gate's
// own sequence, which both transports now inherit instead of hand-placing four checks each.
//
// Each case differs only in which step should claim the notification, so a reordering shows
// up as the wrong record (or a record where silence is correct) rather than as a still-passing
// "it was dropped" assertion.
func TestGateOrder_NotificationGateAppliesTheCanonicalOrder(t *testing.T) {
	t.Parallel()
	killed := &capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: capability.ErrCodeKillSwitch},
	}
	cases := []struct {
		name     string
		method   string
		revoked  bool
		wantCode string // "" means the gate must record nothing at all
	}{
		{
			// The swallowed set precedes revocation: the proxy already handled the thing this
			// announces, so it is neither an error nor an event even on a revoked session.
			name: "swallowed before revoked", method: mcp.MethodNotificationsInitialized, revoked: true,
		},
		{
			// Revocation precedes the fail-closed rejects: an emergency stop must be what the
			// tape says refused this, not the routing verdict that would have followed.
			name: "revoked before unmapped", method: "agents/delegate", revoked: true,
			wantCode: capability.ErrCodeKillSwitch,
		},
		{
			name: "revoked before enforced-method smuggling", method: capability.MethodToolsCall, revoked: true,
			wantCode: capability.ErrCodeKillSwitch,
		},
		{
			// Enforced-method smuggling precedes the unmapped default, so the record names the
			// framing violation rather than an authorization verdict never reached.
			name: "enforced smuggling on a live session", method: capability.MethodToolsCall,
			wantCode: codeInvalidRequest,
		},
		{
			name: "unmapped on a live session", method: "agents/delegate",
			wantCode: capability.ErrCodeAuthorizationFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			gate := hostNotificationGate{
				rec: rec, sessionID: "sess", errOut: io.Discard, leg: legStdioNotification,
				checkKill: func() *capability.EnforceResponse {
					if tc.revoked {
						return killed
					}
					return nil
				},
			}
			if gate.admit(revisionContext(capability.DefaultRevision), mcp.RPCMsg{JSONRPC: "2.0", Method: tc.method}) {
				t.Fatalf("%q must not be forwarded", tc.method)
			}
			if tc.wantCode == "" {
				if len(rec.records) != 0 {
					t.Fatalf("records = %+v, want none: a swallowed notification is dropped before anything records it", rec.records)
				}
				return
			}
			if len(rec.records) != 1 || rec.records[0].code != tc.wantCode {
				t.Fatalf("records = %+v, want one %q", rec.records, tc.wantCode)
			}
		})
	}
}

// TestGateOrder_LocallyAnsweredMethodsInheritRevocation pins the structural half of the kill
// gate: it is applied at the dispatchRequest boundary rather than inside each locally-answered
// handler, so every method in that table is covered by construction.
func TestGateOrder_LocallyAnsweredMethodsInheritRevocation(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	if err := ks.KillSession(context.Background(), "killed-sess"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	ctx := revisionContext(capability.DefaultRevision)
	for method := range tablesFromContext(ctx).local {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			d := dispatchParams{
				forwardParams: forwardParams{rec: rec, sessionID: "killed-sess", errOut: io.Discard},
				pdp:           newTestManifestPDPWithKS(ks),
				buildInit: func(msg mcp.RPCMsg) mcp.RPCMsg {
					return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{}`)}
				},
			}
			resp := dispatchRequest(ctx, d, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method})
			if resp.Error == nil {
				t.Fatalf("%s answered a revoked session; got result %s", method, resp.Result)
			}
			if len(rec.records) != 1 || rec.records[0].code != capability.ErrCodeKillSwitch {
				t.Fatalf("%s: records = %+v, want one KILL_SWITCH", method, rec.records)
			}
		})
	}
}

// TestGateOrder_RevisionRidesOneCarrier is the regression for the two carriers this seam
// collapsed: the routing tables and the audit record's protocol_revision were threaded
// separately from the same local variable, with opposite zero-value semantics, so an entry
// point that set one and forgot the other recorded "no revision decided" for a request it had
// definitely decided under one. Routing now reads the context the record reads.
func TestGateOrder_RevisionRidesOneCarrier(t *testing.T) {
	t.Parallel()
	// The newer revision removed ping, so the table the dispatcher picked is observable in the
	// verdict — and the record it writes must name that same revision.
	rec := &fwdRecorder{}
	d := dispatchParams{
		forwardParams: forwardParams{rec: rec, errOut: io.Discard},
		pdp:           pdp.AlwaysAllowPDP{},
	}
	ctx := revisionContext(capability.Revision20260728)
	if resp := dispatchRequest(ctx, d, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: methodPing}); resp.Error == nil {
		t.Fatal("ping must be unmapped for a peer on the revision that removed it")
	}
	if got := capability.ProtocolRevisionFromContext(ctx); got != capability.Revision20260728 {
		t.Fatalf("the routing context must be the one the sink stamps from; got %q", got)
	}
	// And the reverse direction: a context that negotiated nothing routes by the shipped
	// default rather than by an empty table, so omission cannot reach a different method set.
	if !isEnforcedMethod(context.Background(), capability.MethodToolsCall) {
		t.Error("an unnegotiated context must resolve to the default revision's tables")
	}
	if requestRevision(context.Background()) != capability.DefaultRevision {
		t.Error("requestRevision must resolve the empty carrier to the default revision, in one place")
	}
}
