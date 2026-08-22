// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// withRevision runs fn with the process's served revision set to rev and restores it after.
// The revision is a package variable set once at startup, so these tests cannot run parallel
// with each other — which is why none of them calls t.Parallel().
func withRevision(t *testing.T, rev string, fn func()) {
	t.Helper()
	prior := protocolRevision
	protocolRevision = rev
	defer func() { protocolRevision = prior }()
	fn()
}

// declaringRequest builds a request carrying the per-request declaration the declaring
// revision requires.
func declaringRequest(id int, method, extra string) rpcMsg {
	params := `{"_meta":{"` + metaKeyProtocolVersion + `":"` + revisionDeclaring + `"}`
	if extra != "" {
		params += "," + extra
	}
	params += "}"
	return rpcMsg{JSONRPC: "2.0", ID: rawID(id), Method: method, Params: json.RawMessage(params)}
}

func TestParseProtocolRevision(t *testing.T) {
	for _, ok := range []string{revisionHandshake, revisionDeclaring} {
		if got, err := parseProtocolRevision(ok); err != nil || got != ok {
			t.Errorf("parseProtocolRevision(%q) = (%q, %v), want (%q, nil)", ok, got, err, ok)
		}
	}
	// An unknown value must be refused rather than defaulted: silently serving the old
	// revision on a typo makes a mismatch demo pass for the wrong reason.
	for _, bad := range []string{"", "2026-07-27", "latest", "2025-11-25 "} {
		if _, err := parseProtocolRevision(bad); err == nil {
			t.Errorf("parseProtocolRevision(%q) accepted an unknown revision", bad)
		}
	}
}

// TestOpenerBoundary is the assertion the demo exists to make: each revision serves its own
// opener and answers the other one -32601, so an operator can see exactly where the boundary
// is instead of getting a server that quietly speaks both.
func TestOpenerBoundary(t *testing.T) {
	cases := []struct {
		rev      string
		served   string
		refused  string
		makeMsg  func(method string) rpcMsg
		wantCode int
	}{
		{revisionHandshake, "initialize", "server/discover",
			func(m string) rpcMsg { return rpcMsg{JSONRPC: "2.0", ID: rawID(1), Method: m} }, -32601},
		{revisionDeclaring, "server/discover", "initialize",
			func(m string) rpcMsg { return declaringRequest(1, m, "") }, -32601},
	}
	for _, tc := range cases {
		t.Run(tc.rev, func(t *testing.T) {
			withRevision(t, tc.rev, func() {
				out := captureHandle(t, tc.makeMsg(tc.served))
				if out.Error != nil {
					t.Fatalf("%s must serve %s, got error %+v", tc.rev, tc.served, out.Error)
				}
				refused := captureHandle(t, tc.makeMsg(tc.refused))
				if refused.Error == nil || refused.Error.Code != tc.wantCode {
					t.Fatalf("%s must answer %s with %d, got %+v", tc.rev, tc.refused, tc.wantCode, refused.Error)
				}
			})
		})
	}
}

// TestOpenerResult_DeclaringNegotiatesNoVersion pins the shape the proxy's opener validation
// expects: a declaring reply carries capabilities and serverInfo but volunteers no
// protocolVersion, because that revision negotiates none.
func TestOpenerResult_DeclaringNegotiatesNoVersion(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		out := captureHandle(t, declaringRequest(1, "server/discover", ""))
		if out.Error != nil {
			t.Fatalf("unexpected error: %+v", out.Error)
		}
		var result map[string]interface{}
		if err := json.Unmarshal(out.Result, &result); err != nil {
			t.Fatalf("parsing discover result: %v", err)
		}
		if _, ok := result["protocolVersion"]; ok {
			t.Error("a declaring opener reply must not volunteer a protocolVersion")
		}
		for _, want := range []string{"capabilities", "serverInfo", "resultType"} {
			if _, ok := result[want]; !ok {
				t.Errorf("discover result missing %q", want)
			}
		}
	})
}

// TestDeclarationRequired pins that the declaring revision refuses a request carrying no
// per-request declaration. That is what makes the mock prove the proxy declares on the
// requests it originates, rather than only on the ones a host already declared.
func TestDeclarationRequired(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		for _, method := range []string{"server/discover", "tools/list", "tools/call"} {
			out := captureHandle(t, rpcMsg{JSONRPC: "2.0", ID: rawID(1), Method: method})
			if out.Error == nil || out.Error.Code != -32600 {
				t.Errorf("%s with no declaration: want -32600, got %+v", method, out.Error)
			}
		}
		// A declaration naming another revision is refused for the same reason.
		bad := rpcMsg{JSONRPC: "2.0", ID: rawID(1), Method: "tools/list",
			Params: json.RawMessage(`{"_meta":{"` + metaKeyProtocolVersion + `":"` + revisionHandshake + `"}}`)}
		if out := captureHandle(t, bad); out.Error == nil {
			t.Error("a declaration naming another revision must be refused")
		}
	})
}

// TestHandshakeRevisionNeedsNoDeclaration is the negative control: the old revision agreed
// its version once, so a bare request is conforming and must not be refused.
func TestHandshakeRevisionNeedsNoDeclaration(t *testing.T) {
	withRevision(t, revisionHandshake, func() {
		out := captureHandle(t, rpcMsg{JSONRPC: "2.0", ID: rawID(2), Method: "tools/list"})
		if out.Error != nil {
			t.Fatalf("unexpected error: %+v", out.Error)
		}
	})
}

// TestListCachingMembers pins the fixture the L-6 clamp is demonstrated against. The mock
// emits `cacheScope: "public"` deliberately — it is the WRONG answer for a response the proxy
// filters per caller, so a demo that reads `private` off the proxy's reply is reading a
// working clamp rather than an upstream that never said anything.
func TestListCachingMembers(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		out := captureHandle(t, declaringRequest(2, "tools/list", ""))
		if out.Error != nil {
			t.Fatalf("unexpected error: %+v", out.Error)
		}
		var result map[string]interface{}
		if err := json.Unmarshal(out.Result, &result); err != nil {
			t.Fatalf("parsing tools/list result: %v", err)
		}
		if result["cacheScope"] != "public" {
			t.Errorf("cacheScope = %v, want \"public\" (the value the proxy's clamp must overwrite)", result["cacheScope"])
		}
		if result["resultType"] != "complete" {
			t.Errorf("resultType = %v, want \"complete\"", result["resultType"])
		}
		if result["ttlMs"] == nil {
			t.Error("a declaring list result must carry ttlMs")
		}
	})
}

// TestHandshakeListResultIsUnchanged pins that adding the declaring revision changed nothing
// about the old one: no resultType, no caching members, byte-identical to what this mock has
// always sent.
func TestHandshakeListResultIsUnchanged(t *testing.T) {
	withRevision(t, revisionHandshake, func() {
		out := captureHandle(t, rpcMsg{JSONRPC: "2.0", ID: rawID(2), Method: "tools/list"})
		for _, absent := range []string{"resultType", "cacheScope", "ttlMs"} {
			if strings.Contains(string(out.Result), absent) {
				t.Errorf("the handshake revision must not emit %q", absent)
			}
		}
	})
}

// TestToolCallCarriesResultType covers the non-list result shape on the declaring revision.
func TestToolCallCarriesResultType(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		msg := declaringRequest(3, "tools/call", `"name":"read_file","arguments":{"path":"/reports/q3.pdf"}`)
		out := captureHandle(t, msg)
		if out.Error != nil {
			t.Fatalf("unexpected error: %+v", out.Error)
		}
		var result map[string]interface{}
		if err := json.Unmarshal(out.Result, &result); err != nil {
			t.Fatalf("parsing tools/call result: %v", err)
		}
		if result["resultType"] != "complete" {
			t.Errorf("resultType = %v, want \"complete\"", result["resultType"])
		}
	})
}
