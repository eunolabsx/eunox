// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestBuildUpstreamOpener_PinSelectsTheMethod is the property #245 was filed for: the
// operator's pin has to reach the WIRE, not merely a label. Before the opener was
// revision-selected, both rows produced `initialize`.
func TestBuildUpstreamOpener_PinSelectsTheMethod(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pin        capability.Revision
		wantMethod string
	}{
		{pin: "", wantMethod: mcp.MethodInitialize},
		{pin: capability.Revision20251125, wantMethod: mcp.MethodInitialize},
		{pin: capability.Revision20260728, wantMethod: mcp.MethodServerDiscover},
	}
	for _, tc := range cases {
		msg, err := BuildUpstreamOpenerWithID(UpstreamOpenRevision(tc.pin), mcp.RawJSON(`1`))
		if err != nil {
			t.Fatalf("pin %q: %v", tc.pin, err)
		}
		if msg.Method != tc.wantMethod {
			t.Errorf("pin %q opened with %q, want %q", tc.pin, msg.Method, tc.wantMethod)
		}
	}
}

// TestBuildUpstreamOpener_HandshakeBytesAreUnchanged is the 2025-11-25 regression guard for
// this file: the `auto` opener must be byte-identical to what every release before the
// revision-selected opener sent, or an existing deployment's upstream sees new traffic at
// session start.
func TestBuildUpstreamOpener_HandshakeBytesAreUnchanged(t *testing.T) {
	t.Parallel()
	SetProxyVersion("1.2.3")
	t.Cleanup(func() { SetProxyVersion("dev") })

	msg, err := BuildUpstreamOpenerWithID(UpstreamOpenRevision(""), mcp.RawJSON(`7`))
	if err != nil {
		t.Fatalf("build opener: %v", err)
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"eunox-proxy","version":"1.2.3"},"protocolVersion":"2025-11-25"}}`
	if string(raw) != want {
		t.Errorf("the handshake opener's bytes changed.\n got: %s\nwant: %s", raw, want)
	}
}

// TestBuildUpstreamOpener_DeclaringLegCarriesTheDeclaration: on the revision that removed the
// handshake, every request states its own version — including the one that opens the leg. Not
// writing it was one of the four unresolved halves of the pin: nothing in the tree ever emitted
// capability.MetaKeyProtocolVersion outbound.
func TestBuildUpstreamOpener_DeclaringLegCarriesTheDeclaration(t *testing.T) {
	t.Parallel()
	msg, err := BuildUpstreamOpenerWithID(capability.Revision20260728, mcp.RawJSON(`1`))
	if err != nil {
		t.Fatalf("build opener: %v", err)
	}
	declared, present, err := mcp.DeclaredRevisionOf(msg)
	if err != nil {
		t.Fatalf("reading the opener's own declaration: %v", err)
	}
	if !present {
		t.Fatalf("the discover opener declared no revision; params = %s", msg.Params)
	}
	if declared != capability.Revision20260728 {
		t.Errorf("declared %q, want %q", declared, capability.Revision20260728)
	}
	// The client-capabilities member is the per-request replacement for the handshake's own
	// `capabilities: {}`, so a proxy that advertises nothing upstream keeps advertising nothing.
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		t.Fatalf("decoding opener params: %v", err)
	}
	if got := string(params.Meta[capability.MetaKeyClientCapabilities]); got != `{}` {
		t.Errorf("clientCapabilities = %s, want {} — a proxy advertises no capabilities of its own upstream", got)
	}
}

// TestDeclareUpstreamRevision covers what eunox stamps on the requests it ORIGINATES: nothing
// at all on a negotiating leg, and a declaration merged into whatever params the request
// already carried on a declaring one.
func TestDeclareUpstreamRevision(t *testing.T) {
	t.Parallel()

	probe := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`"_drift"`), Method: capability.MethodToolsList,
		Params: json.RawMessage(`{"cursor":"page2"}`)}

	unchanged, err := DeclareUpstreamRevision(probe, capability.Revision20251125)
	if err != nil {
		t.Fatalf("negotiating leg: %v", err)
	}
	if string(unchanged.Params) != `{"cursor":"page2"}` {
		t.Errorf("a negotiating leg's request was rewritten: %s", unchanged.Params)
	}

	declaring, err := DeclareUpstreamRevision(probe, capability.Revision20260728)
	if err != nil {
		t.Fatalf("declaring leg: %v", err)
	}
	var params struct {
		Cursor string                     `json:"cursor"`
		Meta   map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(declaring.Params, &params); err != nil {
		t.Fatalf("decoding declared params: %v", err)
	}
	if params.Cursor != "page2" {
		t.Errorf("the declaration dropped the request's own params: cursor = %q", params.Cursor)
	}
	if got := string(params.Meta[capability.MetaKeyProtocolVersion]); got != `"2026-07-28"` {
		t.Errorf("declared version = %s, want %q", got, capability.Revision20260728)
	}
	// The input must not be mutated: RPCMsg is copied by value but Params is a slice header,
	// and a caller reusing a request across pages would otherwise accumulate declarations.
	if string(probe.Params) != `{"cursor":"page2"}` {
		t.Errorf("DeclareUpstreamRevision mutated its input: %s", probe.Params)
	}
}

// TestUpstreamOpenerCompletion: only the revision that HAS a handshake closes one.
func TestUpstreamOpenerCompletion(t *testing.T) {
	t.Parallel()
	notif, wanted, err := UpstreamOpenerCompletion(handshakeRevision)
	if err != nil || !wanted {
		t.Fatalf("handshake revision: wanted=%v err=%v, want a completion", wanted, err)
	}
	if notif.Method != mcp.MethodNotificationsInitialized {
		t.Errorf("completion method = %q, want %q", notif.Method, mcp.MethodNotificationsInitialized)
	}
	if _, wanted, err := UpstreamOpenerCompletion(capability.Revision20260728); err != nil || wanted {
		t.Errorf("declaring revision: wanted=%v err=%v, want no completion — it has no handshake to close", wanted, err)
	}
}

// TestApplyUpstreamOpenerResult_Discover: the discover reply is validated with the same
// fail-closed shape the handshake's is, minus the version — that revision negotiates none, so
// requiring a field no conforming server can answer would refuse every one of them.
func TestApplyUpstreamOpenerResult_Discover(t *testing.T) {
	t.Parallel()
	ok := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`),
		Result: json.RawMessage(`{"capabilities":{"tools":{}},"serverInfo":{"name":"up","version":"3.2.1"},"instructions":"hi"}`)}
	hs, err := ApplyUpstreamOpenerResult(capability.Revision20260728, ok)
	if err != nil {
		t.Fatalf("a valid discover result was rejected: %v", err)
	}
	if hs.ServerVersion != "3.2.1" || hs.Instructions != "hi" || hs.Capabilities == nil {
		t.Errorf("handshake facts = %+v", hs)
	}
	if hs.ProtocolVersion != "" {
		t.Errorf("ProtocolVersion = %q, want empty — a declaring leg negotiates none", hs.ProtocolVersion)
	}

	for _, tc := range []struct {
		name   string
		result string
		want   string
	}{
		{name: "null result", result: `null`, want: "capabilities"},
		{name: "no serverInfo", result: `{"capabilities":{}}`, want: "serverInfo"},
	} {
		_, err := ApplyUpstreamOpenerResult(capability.Revision20260728,
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(tc.result)})
		if err == nil {
			t.Errorf("%s: accepted, want a fail-closed refusal", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %q, want it to mention %q", tc.name, err, tc.want)
		}
	}

	// An upstream error to the opener aborts the leg, naming the method that was refused.
	_, err = ApplyUpstreamOpenerResult(capability.Revision20260728,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Error: &mcp.RPCError{Code: -32601, Message: "no such method"}})
	if err == nil || !strings.Contains(err.Error(), mcp.MethodServerDiscover) {
		t.Errorf("error = %v, want a refusal naming %s", err, mcp.MethodServerDiscover)
	}
}

// TestUpstreamOpen_EveryPublishedRevisionHasAnOpener is the derivation-style guard: a revision
// this build declares it speaks but cannot OPEN a leg at is one an operator can pin and then
// watch fail at session start. The opener is selected by a boolean today, so a third revision
// inherits the declaring branch — this asserts that branch actually produces a usable opener
// rather than silently reusing a method that revision may not have.
func TestUpstreamOpen_EveryPublishedRevisionHasAnOpener(t *testing.T) {
	t.Parallel()
	for _, rev := range capability.PublishedRevisions() {
		msg, err := BuildUpstreamOpenerWithID(rev, mcp.RawJSON(`1`))
		if err != nil {
			t.Errorf("revision %s: %v", rev, err)
			continue
		}
		if msg.Method == "" || !msg.IsRequest() {
			t.Errorf("revision %s: opener is not a request: %+v", rev, msg)
		}
		// A declaring revision's opener must state its own version, since that revision
		// requires the declaration on every request — the opener included.
		if declaresPerRequestRevision(rev) {
			if _, present, err := mcp.DeclaredRevisionOf(msg); err != nil || !present {
				t.Errorf("revision %s: opener carries no declaration (err=%v)", rev, err)
			}
		}
	}
}

// TestPinnedUpstreamLeg_ReachesTheWire is #245's whole claim, asserted against a live
// upstream rather than against the builders: an operator who pins a revision gets a leg
// OPENED, HEADED and DECLARED at that revision, on every request eunox itself originates.
//
// Before this, all three named the handshake revision whatever the pin said, so the pin was a
// label on a leg opened some other way.
func TestPinnedUpstreamLeg_ReachesTheWire(t *testing.T) {
	type seen struct {
		method   string
		header   string
		declared string
	}
	var (
		mu       sync.Mutex
		requests []seen
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg mcp.RPCMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		declared, _, _ := mcp.DeclaredRevisionOf(msg)
		mu.Lock()
		requests = append(requests, seen{method: msg.Method, header: r.Header.Get("MCP-Protocol-Version"), declared: declared.String()})
		mu.Unlock()

		w.Header().Set("Content-Type", CTJSON)
		switch msg.Method {
		case mcp.MethodServerDiscover:
			w.Header().Set(SessionHeader, "up-sess")
			result, _ := json.Marshal(map[string]interface{}{
				"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":   map[string]interface{}{"name": "new-upstream", "version": "1.0.0"},
			})
			_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: result})
		case capability.MethodToolsList:
			_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{"tools":[]}`)})
		default:
			resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{"method": msg.Method})
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	t.Cleanup(upstream.Close)

	probed := false
	_, srv := newTestRemoteProxy(t, upstream.URL, httpProxyOptions{
		UpstreamProtocolVersion: capability.Revision20260728,
		// A no-op hook, wired only so the session-start tools/list probe RUNS: that probe is a
		// request eunox originates on this leg, so it owes the declaration exactly as the opener
		// does, and a test that never issues one would pass on the opener alone.
		DriftCheck: func(json.RawMessage, string, error) error { probed = true; return nil },
	})
	// The HOST leg is still opened by `initialize`, which is the older revision's method: the
	// pin governs the UPSTREAM leg alone, which is the asymmetry a proxy exists to hold.
	if sid := initSession(t, srv); sid == "" {
		t.Fatal("no session established")
	}

	if !probed {
		t.Fatal("the session-start drift probe never ran, so the tools/list leg is unasserted")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) < 2 {
		t.Fatalf("the upstream saw %d request(s), want the opener plus the drift probe", len(requests))
	}
	if got := requests[0].method; got != mcp.MethodServerDiscover {
		t.Errorf("the leg was opened with %q, want %q — the pin did not select the opener", got, mcp.MethodServerDiscover)
	}
	for _, req := range requests {
		if req.header != capability.Revision20260728.String() {
			t.Errorf("%s carried MCP-Protocol-Version %q, want %q", req.method, req.header, capability.Revision20260728)
		}
		if req.declared != capability.Revision20260728.String() {
			t.Errorf("%s declared %q in _meta, want %q — this revision requires the declaration on every request", req.method, req.declared, capability.Revision20260728)
		}
		if req.method == mcp.MethodNotificationsInitialized {
			t.Error("a declaring leg was sent notifications/initialized; that revision has no handshake to close")
		}
	}
}
