// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"
)

// withRevision runs fn with the process revision set to rev and restores it afterwards, so a
// table row cannot leak its revision into the next one.
func withRevision(t *testing.T, rev string, fn func()) {
	t.Helper()
	prev := serverRevision
	serverRevision = rev
	defer func() { serverRevision = prev }()
	fn()
}

// declaringRequest builds a request carrying the per-request revision declaration.
func declaringRequest(t *testing.T, method, declared string) *rpcMsg {
	t.Helper()
	params, err := json.Marshal(map[string]interface{}{
		"_meta": map[string]interface{}{metaKeyProtocolVersion: declared},
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return &rpcMsg{JSONRPC: "2.0", ID: rawID(t, "1"), Method: method, Params: params}
}

// A declaring upstream must refuse a request with no declaration. This is the assertion the
// whole interop matrix rests on: it is what proves eunox declares the revision on every
// request it sends such a leg, rather than the matrix passing because the mock was lenient.
func TestCheckDeclaration_RefusesAnUndeclaredRequest(t *testing.T) {
	cases := []struct {
		name    string
		params  string
		wantErr bool
	}{
		{"no params at all", "", true},
		{"params without _meta", `{"name":"read_file"}`, true},
		{"_meta without the version key", `{"_meta":{"other":"x"}}`, true},
		{"declaration of the wrong revision", `{"_meta":{"` + metaKeyProtocolVersion + `":"2025-11-25"}}`, true},
		{"declaration not a string", `{"_meta":{"` + metaKeyProtocolVersion + `":7}}`, true},
		{"params not an object", `"scalar"`, true},
		{"correct declaration", `{"_meta":{"` + metaKeyProtocolVersion + `":"2026-07-28"}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withRevision(t, revisionDeclaring, func() {
				msg := &rpcMsg{JSONRPC: "2.0", ID: rawID(t, "1"), Method: "tools/list"}
				if tc.params != "" {
					msg.Params = json.RawMessage(tc.params)
				}
				err := checkDeclaration(msg)
				if tc.wantErr != (err != nil) {
					t.Fatalf("checkDeclaration = %v, wantErr %v", err, tc.wantErr)
				}
			})
		})
	}
}

// The handshake revision requires no declaration, so the gate must not fire there.
func TestCheckDeclaration_HandshakeRevisionRequiresNone(t *testing.T) {
	withRevision(t, revisionHandshake, func() {
		msg := &rpcMsg{JSONRPC: "2.0", ID: rawID(t, "1"), Method: "tools/list"}
		if err := checkDeclaration(msg); err != nil {
			t.Fatalf("handshake revision refused an undeclared request: %v", err)
		}
	})
}

// A notification is exempt: eunox forwards a host's notifications verbatim and originates
// none of its own on a declaring leg, so requiring a declaration would refuse a message on
// the strength of what the host omitted rather than what the proxy did.
func TestCheckDeclaration_ExemptsNotifications(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		msg := &rpcMsg{JSONRPC: "2.0", Method: "notifications/progress"}
		if err := checkDeclaration(msg); err != nil {
			t.Fatalf("notification refused: %v", err)
		}
	})
}

func TestCheckMethodExists_PerRevisionMethodSet(t *testing.T) {
	cases := []struct {
		rev, method string
		wantFound   bool
	}{
		{revisionHandshake, "initialize", true},
		{revisionHandshake, "ping", true},
		{revisionHandshake, "resources/subscribe", true},
		{revisionHandshake, "server/discover", false},
		{revisionDeclaring, "server/discover", true},
		{revisionDeclaring, "initialize", false},
		{revisionDeclaring, "ping", false},
		{revisionDeclaring, "resources/subscribe", false},
		{revisionDeclaring, "resources/unsubscribe", false},
		{revisionDeclaring, "completion/complete", false},
		{revisionDeclaring, "tools/call", true},
		{revisionDeclaring, "tools/list", true},
		{revisionDeclaring, "resources/read", true},
		{revisionDeclaring, "prompts/get", true},
	}
	for _, tc := range cases {
		t.Run(tc.rev+"/"+tc.method, func(t *testing.T) {
			withRevision(t, tc.rev, func() {
				err := checkMethodExists(tc.method)
				if tc.wantFound != (err == nil) {
					t.Fatalf("checkMethodExists(%q) under %s = %v, want found=%v",
						tc.method, tc.rev, err, tc.wantFound)
				}
			})
		})
	}
}

// A declaring leg negotiates no version, so a conforming server answers with none. eunox's
// checkNegotiatedRevision treats a volunteered version as a disagreement to report, so a mock
// that carried one would make the matrix assert against a non-conforming peer.
func TestDiscoverResult_VolunteersNoProtocolVersion(t *testing.T) {
	result := discoverResult()
	if _, ok := result["protocolVersion"]; ok {
		t.Fatal("discover result carries protocolVersion; a declaring leg negotiates none")
	}
	// eunox's validateOpenerResultFields requires both of these on every opener reply.
	for _, key := range []string{"capabilities", "serverInfo"} {
		if _, ok := result[key]; !ok {
			t.Fatalf("discover result missing required %q", key)
		}
	}
}

// The declaring revision removes the resources/subscribe pair, so advertising the capability
// that names it would describe a surface this server refuses.
func TestDiscoverResult_DropsTheSubscribeCapability(t *testing.T) {
	caps, ok := discoverResult()["capabilities"].(map[string]interface{})
	if !ok {
		t.Fatal("capabilities is not an object")
	}
	resources, ok := caps["resources"].(map[string]interface{})
	if !ok {
		t.Fatal("resources capability is not an object")
	}
	if _, ok := resources["subscribe"]; ok {
		t.Fatal("declaring discover advertises subscribe, a capability its revision removed")
	}
}

func TestStampResultShape(t *testing.T) {
	withRevision(t, revisionHandshake, func() {
		got, ok := stampResultShape("tools/list", map[string]interface{}{"tools": []string{}}).(map[string]interface{})
		if !ok {
			t.Fatal("result is not an object")
		}
		if _, present := got["resultType"]; present {
			t.Fatal("handshake revision stamped resultType, which only 2026-07-28 defines")
		}
	})
	withRevision(t, revisionDeclaring, func() {
		call, ok := stampResultShape("tools/call", map[string]interface{}{"content": []string{}}).(map[string]interface{})
		if !ok {
			t.Fatal("result is not an object")
		}
		if call["resultType"] != "complete" {
			t.Fatalf("tools/call resultType = %v, want complete", call["resultType"])
		}
		if _, present := call["cacheScope"]; present {
			t.Fatal("tools/call carries cacheScope, which belongs to the cacheable list results")
		}
		list, ok := stampResultShape("tools/list", map[string]interface{}{"tools": []string{}}).(map[string]interface{})
		if !ok {
			t.Fatal("result is not an object")
		}
		// Deliberately the WRONG answer for a response eunox filters. A mock that volunteered
		// `private` could not tell a working clamp from an absent one, so this value is what
		// gives the host-side clamp assertion its meaning.
		if list["cacheScope"] != "public" {
			t.Fatalf("tools/list cacheScope = %v, want public (the unclamped value)", list["cacheScope"])
		}
	})
}

// dispatch must apply both gates before any handler runs, so a handler cannot serve a request
// the running revision should have refused.
func TestDispatch_AppliesTheRevisionGatesBeforeHandlers(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		undeclared := &rpcMsg{JSONRPC: "2.0", ID: rawID(t, "1"), Method: "tools/list"}
		if _, err := dispatch(undeclared, nil); err == nil {
			t.Fatal("dispatch served an undeclared request on a declaring leg")
		}
		removed := declaringRequest(t, "ping", revisionDeclaring)
		res, err := dispatch(removed, nil)
		if err == nil {
			t.Fatalf("dispatch served ping on a declaring leg: %v", res)
		}
		if err.Code != -32601 {
			t.Fatalf("removed-method code = %d, want -32601", err.Code)
		}
		discover := declaringRequest(t, "server/discover", revisionDeclaring)
		if _, err := dispatch(discover, nil); err != nil {
			t.Fatalf("dispatch refused server/discover on a declaring leg: %v", err)
		}
	})
	withRevision(t, revisionHandshake, func() {
		discover := &rpcMsg{JSONRPC: "2.0", ID: rawID(t, "1"), Method: "server/discover"}
		err := func() *rpcError { _, e := dispatch(discover, nil); return e }()
		if err == nil || err.Code != -32601 {
			t.Fatalf("handshake revision served server/discover: %v", err)
		}
	})
}
