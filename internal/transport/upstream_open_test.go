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

// TestBuildUpstreamOpener_PinSelectsTheMethod: the operator's pin has to reach the WIRE, not
// merely a label. Before the opener was revision-selected, every row produced `initialize`.
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
	// Not parallel, and restoring the SAVED value rather than a literal: proxyVersion is
	// package-global and buildInitializeParams reads it on every upstream open, so a parallel
	// writer races every test that opens a leg — and a cleanup that writes back a guessed
	// default silently reverts whatever a serial test had set.
	prev := proxyVersion
	t.Cleanup(func() { proxyVersion = prev })
	SetProxyVersion("1.2.3")

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

	probe := mcp.RPCMsg{JSONRPC: "2.0", ID: driftProbeID, Method: capability.MethodToolsList,
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
	notif, wanted := UpstreamOpenerCompletion(handshakeRevision)
	if !wanted {
		t.Fatal("handshake revision: want a completion")
	}
	if notif.Method != mcp.MethodNotificationsInitialized {
		t.Errorf("completion method = %q, want %q", notif.Method, mcp.MethodNotificationsInitialized)
	}
	if _, wanted := UpstreamOpenerCompletion(capability.Revision20260728); wanted {
		t.Error("declaring revision: want no completion — it has no handshake to close")
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
	if hs.Notice != "" {
		t.Errorf("Notice = %q, want none — a declaring leg negotiates no version, so a reply carrying none states no disagreement", hs.Notice)
	}

	for _, tc := range []struct {
		name   string
		result string
		want   string
	}{
		{name: "null result", result: `null`, want: "capabilities"},
		{name: "no serverInfo", result: `{"capabilities":{}}`, want: "serverInfo"},
		// A discover reply that VOLUNTEERS a version is stating a disagreement, and the
		// declaring opener must be judged for it exactly as the handshake opener is.
		{name: "volunteers a contradicting version", result: `{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{}}`, want: "opened at"},
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

// TestPinnedUpstreamLeg_ReachesTheWire is the whole claim, asserted against a live upstream
// rather than against the builders: an operator who pins a revision gets a leg
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

// TestDeclareUpstreamRevision_MalformedParamsFailClosed covers the two shapes that look like
// successes to a naive decoder: params that are the JSON literal `null` (which unmarshals into
// a map by NILLING it, with no error), and a params body carrying a duplicate key.
func TestDeclareUpstreamRevision_MalformedParamsFailClosed(t *testing.T) {
	t.Parallel()
	// `null` params must not panic, and must not silently produce a declaration-only body: the
	// caller asked to declare on params it supplied, and eunox cannot tell which it meant.
	nullParams := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsList,
		Params: json.RawMessage(`null`)}
	got, err := DeclareUpstreamRevision(nullParams, capability.Revision20260728)
	if err != nil {
		t.Fatalf("null params: %v", err)
	}
	if declared, present, err := mcp.DeclaredRevisionOf(got); err != nil || !present || declared != capability.Revision20260728 {
		t.Errorf("null params produced %s (declared=%q present=%v err=%v)", got.Params, declared, present, err)
	}

	for _, tc := range []struct {
		name   string
		params string
	}{
		{name: "duplicate key", params: `{"cursor":"a","cursor":"b"}`},
		{name: "not an object", params: `["cursor"]`},
		{name: "_meta is not an object", params: `{"_meta":7}`},
	} {
		msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsList,
			Params: json.RawMessage(tc.params)}
		if _, err := DeclareUpstreamRevision(msg, capability.Revision20260728); err == nil {
			t.Errorf("%s: accepted %s, want a fail-closed refusal", tc.name, tc.params)
		}
	}
}

// TestDeclareUpstreamRevision_MergesIntoAnExistingMeta: the declaration joins whatever `_meta`
// the request already carries rather than replacing it. Replacing it would silently drop a
// progress token or an attribution block, with the member's absence at the upstream as the
// only symptom.
func TestDeclareUpstreamRevision_MergesIntoAnExistingMeta(t *testing.T) {
	t.Parallel()
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsList,
		Params: json.RawMessage(`{"_meta":{"progressToken":"tok-1"}}`)}
	got, err := DeclareUpstreamRevision(msg, capability.Revision20260728)
	if err != nil {
		t.Fatalf("declaring: %v", err)
	}
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(got.Params, &params); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if string(params.Meta["progressToken"]) != `"tok-1"` {
		t.Errorf("the declaration replaced the request's own _meta: %s", got.Params)
	}
	if string(params.Meta[capability.MetaKeyProtocolVersion]) != `"2026-07-28"` {
		t.Errorf("declared version missing from the merged _meta: %s", got.Params)
	}
}

// TestUpstreamOpenRevision_UnsupportedPinFailsClosed: this is an exported resolver behind an
// exported option field, and the branch an unvalidated value would otherwise fall into is the
// DECLARING one — the newest wire behavior, reached by a value nobody checked.
func TestUpstreamOpenRevision_UnsupportedPinFailsClosed(t *testing.T) {
	t.Parallel()
	for _, pin := range []capability.Revision{"", "2025-06-18", "latest", "2026-07-29"} {
		if got := UpstreamOpenRevision(pin); got != handshakeRevision {
			t.Errorf("UpstreamOpenRevision(%q) = %q, want the handshake revision — an unrecognized pin must not select the declaring opener", pin, got)
		}
	}
}

// TestInitializeAcrossRevisions_IsTranslatedNarrowly: a host handshake reaching a leg that
// speaks a handshake-less revision is ANSWERED from that leg's discovery data — ADR-0006's
// discovery translation — but only after the capability object is narrowed to what the pair can
// actually carry.
//
// The narrowing is the whole of what makes answering safe, and it is what this test guards.
// Handing over the discover object verbatim would stamp the handshake revision on a capability
// set in the newer revision's shape, and the host would feature-detect off methods eunox then
// denies fail-closed — which is worse for it than a refusal, because it plans around a surface
// it cannot use. This was refused outright before the boundary existed, for exactly that
// reason; what changed is that the answer can now be made honest rather than withheld.
func TestInitializeAcrossRevisions_IsTranslatedNarrowly(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{
		upstreamRev: capability.Revision20260728,
		upstreamCaps: map[string]interface{}{
			// Advertised by the declaring upstream and NOT carryable: this build knows no
			// methods for it, so it cannot know whether they translate.
			"subscriptions": map[string]interface{}{},
			"tools":         map[string]interface{}{"listChanged": true},
			"prompts":       map[string]interface{}{},
			// Carryable, EXCEPT for the sub-flag naming the one refused pair inside it.
			"resources": map[string]interface{}{"subscribe": true, "listChanged": true},
		},
		done: make(chan struct{}),
	})
	resp := sess.buildInitResponse(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: mcp.MethodInitialize})
	if resp.Error != nil {
		t.Fatalf("the handshake was refused rather than translated: %+v", resp.Error)
	}
	if strings.Contains(string(resp.Result), "subscriptions") {
		t.Error("a capability this build cannot reason about reached the host; an unknown surface must be dropped, not forwarded")
	}
	if strings.Contains(string(resp.Result), "subscribe") {
		t.Error("resources.subscribe reached the host, promising a pair the boundary refuses")
	}
	for _, kept := range []string{"tools", "prompts", "resources", "listChanged"} {
		if !strings.Contains(string(resp.Result), kept) {
			t.Errorf("%q was dropped; narrowing must keep what the pair can carry, or the answer is useless", kept)
		}
	}

	// The matched case is untouched — including the subscribe flag, which is only refused
	// because the PAIR cannot carry it, never because the method is unsupported.
	ok := newTestSession(&httpSession{
		upstreamRev:  handshakeRevision,
		upstreamCaps: map[string]interface{}{"tools": map[string]interface{}{}, "resources": map[string]interface{}{"subscribe": true}},
		done:         make(chan struct{}),
	})
	matched := ok.buildInitResponse(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: mcp.MethodInitialize})
	if matched.Error != nil {
		t.Fatalf("a matched handshake was refused: %+v", matched.Error)
	}
	if !strings.Contains(string(matched.Result), "subscribe") {
		t.Error("a matched pair lost resources.subscribe; narrowing must not reach the matched path")
	}
}

// TestOpenerRegistry_EveryPublishedRevisionDeclaresItsOpener is the build-time guard the
// opener registry exists for: a revision this build says it speaks but cannot open a leg at is
// one an operator can pin and then watch fail against a live upstream.
//
// It also pins the two facts an inherited declaration would get wrong. An opener that
// negotiates the version must not also declare one per request (the two are alternatives, not
// a pair), and a declaring revision must have no completion — there is no handshake to close.
func TestOpenerRegistry_EveryPublishedRevisionDeclaresItsOpener(t *testing.T) {
	t.Parallel()
	for _, rev := range capability.PublishedRevisions() {
		spec, declared := openerRegistry[rev]
		if !declared {
			t.Errorf("revision %s is published but declares no opener; add an openerRegistry entry rather than letting it inherit another revision's", rev)
			continue
		}
		if spec.method == "" {
			t.Errorf("revision %s declares an empty opener method", rev)
		}
		if spec.negotiatesVersion && spec.declares {
			t.Errorf("revision %s both negotiates a version and declares one per request; they are alternatives", rev)
		}
		if spec.declares && spec.completion != "" {
			t.Errorf("revision %s declares per request but has completion %q; a revision with no handshake has nothing to close", rev, spec.completion)
		}
	}
	// A stale entry is the other direction: a revision the registry describes but this build
	// no longer speaks would be dead weight a reader trusts.
	for rev := range openerRegistry {
		if !rev.Supported() {
			t.Errorf("openerRegistry declares %s, which this build does not speak; drop the stale entry", rev)
		}
	}
}

// TestOpenerNegotiatesVersion_FollowsTheDeclaration: the version header is suppressed for the
// request that PERFORMS the negotiation and for nothing else. Keyed on the leg's revision, so a
// host-forwarded message merely sharing the opener's name on a leg that does not open with it
// still carries its header.
func TestOpenerNegotiatesVersion_FollowsTheDeclaration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rev    capability.Revision
		method string
		want   bool
	}{
		{rev: capability.Revision20251125, method: mcp.MethodInitialize, want: true},
		{rev: capability.Revision20251125, method: capability.MethodToolsCall, want: false},
		// The declaring leg's opener negotiates nothing — it is an ordinary request of a
		// revision the client already stated, so it carries the header like any other.
		{rev: capability.Revision20260728, method: mcp.MethodServerDiscover, want: false},
		{rev: capability.Revision20260728, method: mcp.MethodInitialize, want: false},
	}
	for _, tc := range cases {
		if got := openerNegotiatesVersion(tc.rev, tc.method); got != tc.want {
			t.Errorf("openerNegotiatesVersion(%q, %q) = %v, want %v", tc.rev, tc.method, got, tc.want)
		}
	}
}
