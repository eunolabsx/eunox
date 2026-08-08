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
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
				rec: staticRecorder(rec), subject: verifiedSession("sess"), established: true, errOut: io.Discard, leg: legStdioNotification,
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

// TestGateOrder_CreatingInitializeAppliesTheCanonicalOrder pins the canonical order on the
// one request prologue that lives outside dispatchRequest: the HTTP session-creating
// initialize. The same bytes must record the same code stdio records for its initialize —
// negotiation ahead of the kill gate — or an emergency stop relabels a bad-version probe's
// evidence on one transport only. The second POST bounds the exception: a resolvable
// initialize on the same killed proxy is refused by the kill gate as always, and its record
// names the revision negotiation had already resolved and stamped.
func TestGateOrder_CreatingInitializeAppliesTheCanonicalOrder(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	if err := ks.ActivateGlobal(context.Background()); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}
	sink, logPath := newTempAuditSink(t)
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{sink: sink, upstream: "up1"},
	}
	proxy := newTestHTTPProxy()

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", CTJSON)
		w := httptest.NewRecorder()
		proxy.handleMCPPost(w, req, route)
		return w
	}

	w := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}}`)
	if !strings.Contains(w.Body.String(), "-32022") {
		t.Errorf("bad-revision creating initialize: body = %q, want the -32022 revision refusal", w.Body.String())
	}
	post(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`)

	_ = sink.Close()
	var badRevision, killed map[string]interface{}
	for _, rec := range readAuditRecords(t, logPath) {
		if m, _ := rec["method"].(string); m != mcp.MethodInitialize {
			continue
		}
		switch code, _ := rec["denial_code"].(string); code {
		case capability.ErrCodeUnsupportedProtocolVersion:
			badRevision = rec
		case capability.ErrCodeKillSwitch:
			killed = rec
		}
	}
	if badRevision == nil {
		t.Fatal("the bad-revision probe must record UNSUPPORTED_PROTOCOL_VERSION — kill active or not, negotiation refuses first on both transports")
	}
	if killed == nil {
		t.Fatal("the resolvable initialize must still be refused by the kill gate")
	}
	if rev, _ := killed["protocol_revision"].(string); rev != string(handshakeRevision) {
		t.Errorf("kill record protocol_revision = %q, want %q — the resolved revision is stamped before the later pre-session gates record", rev, string(handshakeRevision))
	}
}

// TestGateOrder_InitializeNotificationAppliesTheCanonicalOrder covers the third sessionless
// entry point: an id-less `initialize`. It now reaches both shared helpers rather than
// restating them — negotiateHostRevision, then hostNotificationGate.admit — and this pins the
// outcome that placement produces. Before it, an unhonorable declaration on this arm recorded
// KILL_SWITCH under a kill and NOTHING at all without one, while stdio recorded
// UNSUPPORTED_PROTOCOL_VERSION for the identical bytes.
func TestGateOrder_InitializeNotificationAppliesTheCanonicalOrder(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		kill bool
	}{
		{"no kill active", false},
		{"global kill active", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ks := killswitch.NewInMemory()
			if tc.kill {
				if err := ks.ActivateGlobal(context.Background()); err != nil {
					t.Fatalf("ActivateGlobal: %v", err)
				}
			}
			sink, logPath := newTempAuditSink(t)
			route := &UpstreamRoute{
				name: "up1",
				pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
				sink: &routeSink{sink: sink, upstream: "up1"},
			}
			proxy := newTestHTTPProxy()

			body := `{"jsonrpc":"2.0","method":"initialize","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}}`
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			req.Header.Set("Content-Type", CTJSON)
			w := httptest.NewRecorder()
			proxy.handleMCPPost(w, req, route)
			_ = sink.Close()

			// A notification never receives a JSON-RPC body, kill or no kill.
			if w.Body.Len() != 0 {
				t.Errorf("an initialize notification must be acked bodyless, got %q", w.Body.String())
			}
			rec := findAuditRecordByMethod(readAuditRecords(t, logPath), mcp.MethodInitialize, "deny")
			if rec == nil {
				t.Fatal("a notification declaring an unhonorable revision must leave a record, not be dropped silently")
			}
			if code, _ := rec["denial_code"].(string); code != capability.ErrCodeUnsupportedProtocolVersion {
				t.Errorf("denial_code = %q, want %q — negotiation refuses ahead of the kill gate on every entry point, as it does on stdio", code, capability.ErrCodeUnsupportedProtocolVersion)
			}
		})
	}
}

// TestGateOrder_SessionCapDenialNamesItsRevision closes the stamp's last gap on the
// creating path. The cap refusal sits between gates that record protocol_revision, so
// leaving it on the unstamped request context made a post-negotiation refusal read, under
// this package's own "absent means pre-negotiation" convention, as though nothing had been
// negotiated at all.
func TestGateOrder_SessionCapDenialNamesItsRevision(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{sink: sink, upstream: "up1"},
	}
	proxy := newTestHTTPProxy()
	// Every slot already taken, so the pre-spawn reservation refuses without an upstream.
	proxy.maxSessions = 1
	proxy.establishing = 1

	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Content-Type", CTJSON)
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, route)
	_ = sink.Close()

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 from the session cap", w.Code)
	}
	rec := findAuditRecordByMethod(readAuditRecords(t, logPath), "", "deny")
	if rec == nil {
		t.Fatal("the session-cap refusal must leave a record")
	}
	if got, _ := rec["protocol_revision"].(string); got != string(handshakeRevision) {
		t.Errorf("protocol_revision = %q, want %q — a refusal after negotiation must name the revision it decided under", got, string(handshakeRevision))
	}
}

// staticRecorder adapts a test recorder to the gate's rec THUNK. Production supplies a thunk
// because a pre-session recorder costs a rate-limit token to resolve; a test recorder costs
// nothing, so it is handed over as a constant.
func staticRecorder(rec auditRecorder) func() auditRecorder {
	return func() auditRecorder { return rec }
}

// negotiationPrimitives are the two functions that IMPLEMENT the head of the gate order, and
// the one function allowed to call them. Every host message must reach revision negotiation
// through a transport's negotiateHostRevision — the shared prologue — rather than through a
// hand-placed copy.
var negotiationPrimitives = map[string]string{
	"resolveHostRevision": "negotiateHostRevision",
	"refuseHostRevision":  "negotiateHostRevision",
}

// TestGateOrder_NegotiationIsReachedOnlyThroughTheSharedPrologue is the derivation-style guard
// the entry points had no equivalent of.
//
// The order itself is declared once and applied by two shared helpers, but nothing stopped a
// new entry point from calling the primitives directly and getting the sequence subtly wrong —
// which is what happened: an id-less `initialize` with no session reached neither helper, so
// it negotiated nothing at all and recorded either the wrong code or no record while stdio
// recorded UNSUPPORTED_PROTOCOL_VERSION for identical bytes. Each such arm was then covered by
// a TestGateOrder_* someone had to remember to write.
//
// This turns the next one into a build failure instead. An AST walk for the reason
// TestGuardedCompositeLiterals is one: the rule is "which FUNCTION may call this", which no
// enabled linter expresses.
func TestGateOrder_NegotiationIsReachedOnlyThroughTheSharedPrologue(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("listing package sources: %v", err)
	}
	fset := token.NewFileSet()
	calls := 0
	for _, e := range entries {
		name := e.Name()
		// Non-test sources only: a test legitimately drives the primitives directly to pin
		// the negotiation rule itself.
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				ident, isIdent := call.Fun.(*ast.Ident)
				if !isIdent {
					return true
				}
				caller, guarded := negotiationPrimitives[ident.Name]
				if !guarded {
					return true
				}
				calls++
				if fn.Name.Name != caller {
					t.Errorf("%s: %s calls %s directly; every entry point must reach negotiation through %s, or the gate order is hand-placed again",
						name, fn.Name.Name, ident.Name, caller)
				}
				return true
			})
		}
	}
	// Not vacuous: a rename that leaves the guard matching nothing would otherwise pass while
	// guarding nothing.
	if calls < len(negotiationPrimitives) {
		t.Errorf("found %d guarded call(s); expected at least one per primitive (%d) — has one been renamed?", calls, len(negotiationPrimitives))
	}
}

// TestGateOrder_SessionlessNotificationInheritsTheSharedGate pins the one thing the
// sessionless arm answers differently, and that it is a FACT rather than a reordering.
//
// The swallowed set is what the proxy has ALREADY handled. On an established leg an id-less
// `initialize` announces a handshake that happened, so it is dropped before revocation is even
// asked (that is the canonical order, and stdio does the same). Pre-session nothing has been
// handled, so the same bytes still reach revocation and an emergency stop RECORDS the attempt
// instead of returning a silent readiness ack. Both arms answer 202 with no body; what differs
// is the tape, which is the whole point.
func TestGateOrder_SessionlessNotificationInheritsTheSharedGate(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	if err := ks.ActivateGlobal(context.Background()); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}
	sink, logPath := newTempAuditSink(t)
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{sink: sink, upstream: "up1"},
	}
	proxy := newTestHTTPProxy()

	// NO session header: that absence is what selects this arm. With one set, handleMCPPost
	// routes to handleSessionPost's unknown-session branch instead, which produces an
	// identically shaped record — so every assertion below would pass while testing the wrong
	// code path (it did).
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","method":"initialize"}`))
	req.Header.Set("Content-Type", CTJSON)
	w := httptest.NewRecorder()
	proxy.handleMCPPost(w, req, route)
	_ = sink.Close()

	if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
		t.Fatalf("status = %d body = %q, want a bodyless 202: a notification takes no JSON-RPC response", w.Code, w.Body.String())
	}
	rec := findAuditRecordByMethod(readAuditRecords(t, logPath), mcp.MethodInitialize, "deny")
	if rec == nil {
		t.Fatal("a pre-session initialize notification under a global kill must be recorded; the proxy has handled no handshake, so there is nothing for the swallowed set to stand for")
	}
	if code, _ := rec["denial_code"].(string); code != capability.ErrCodeKillSwitch {
		t.Errorf("denial_code = %q, want %q", code, capability.ErrCodeKillSwitch)
	}
	// The gate's own subject rule, inherited rather than re-implemented: this arm resolved no
	// session, so nothing may be signed into session_id as fact.
	if got, _ := rec["session_id"].(string); got != "" {
		t.Errorf("session_id = %q, want empty — a pre-session record must not vouch for a session", got)
	}
	// The discriminator between this arm and handleSessionPost's: only this one negotiates
	// before recording, so only its record names the revision it decided under.
	if got, _ := rec["protocol_revision"].(string); got != string(handshakeRevision) {
		t.Fatalf("protocol_revision = %q, want %q — the record came from an arm that never negotiated, so this test is not exercising the sessionless gate", got, string(handshakeRevision))
	}
}

// TestGateOrder_SessionlessNotificationSpendsNoKillRecordBudget pins the direction the shared
// gate must NOT change: resolving the recorder is not free on a pre-session leg.
//
// preSessionKillRecorder draws from the catKill token bucket, which exists so an
// unauthenticated flood cannot make the tape unbounded. Building the gate with the recorder
// already resolved spent a token on every id-less `initialize` — a message that is 202-acked,
// allocates nothing and records nothing — so a peer sending them faster than the bucket
// refills could empty it and silence the pre-session KILL_SWITCH records an emergency stop
// depends on. The recorder is a thunk for that reason, and this is what says so.
func TestGateOrder_SessionlessNotificationSpendsNoKillRecordBudget(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{sink: sink, upstream: "up1"},
	}
	proxy := newTestHTTPProxy()

	// Comfortably more than the bucket's burst: if each one spends a token, nothing is left.
	for range 25 {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"initialize"}`))
		req.Header.Set("Content-Type", CTJSON)
		w := httptest.NewRecorder()
		proxy.handleMCPPost(w, req, route)
		if w.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", w.Code)
		}
	}
	// The budget must be untouched, so a real refusal still records.
	if rec := proxy.preSessionKillRecorder(route); rec == nil {
		t.Fatal("the kill-record budget was spent by notifications that recorded nothing; an unauthenticated flood can now silence the emergency stop's own records")
	}
	_ = sink.Close()
	if recs := readAuditRecords(t, logPath); len(recs) != 0 {
		t.Errorf("no kill was active, so nothing should have been recorded; got %d record(s)", len(recs))
	}
}
