// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"strconv"
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

// declaringBody builds a request body carrying the per-request declaration the declaring
// revision requires.
func declaringBody(id int, method, extra string) string {
	params := `{"_meta":{"` + metaKeyProtocolVersion + `":"` + revisionDeclaring + `"}`
	if extra != "" {
		params += "," + extra
	}
	params += "}"
	return `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"` + method + `","params":` + params + `}`
}

func TestParseProtocolRevision(t *testing.T) {
	for _, ok := range []string{revisionHandshake, revisionDeclaring} {
		if got, err := parseProtocolRevision(ok); err != nil || got != ok {
			t.Errorf("parseProtocolRevision(%q) = (%q, %v), want (%q, nil)", ok, got, err, ok)
		}
	}
	for _, bad := range []string{"", "2026-07-27", "latest"} {
		if _, err := parseProtocolRevision(bad); err == nil {
			t.Errorf("parseProtocolRevision(%q) accepted an unknown revision", bad)
		}
	}
}

// TestOpenerBoundary is the assertion the mock exists to make: each revision serves its own
// opener and answers the other one -32601.
func TestOpenerBoundary(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		srv := newServer()
		w := post(t, srv, declaringBody(1, "server/discover", ""), "")
		if w.Code != http.StatusOK || decodeMsg(t, w).Error != nil {
			t.Fatalf("the declaring revision must serve server/discover: %d %s", w.Code, w.Body.String())
		}
		refused := decodeMsg(t, post(t, srv, declaringBody(2, "initialize", ""), ""))
		if refused.Error == nil || refused.Error.Code != -32601 {
			t.Fatalf("the declaring revision must answer initialize -32601, got %+v", refused.Error)
		}
	})
	withRevision(t, revisionHandshake, func() {
		srv := newServer()
		sid := initSession(t, srv)
		refused := decodeMsg(t, post(t, srv, `{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{}}`, sid))
		if refused.Error == nil || refused.Error.Code != -32601 {
			t.Fatalf("the handshake revision must answer server/discover -32601, got %+v", refused.Error)
		}
	})
}

// TestDeclaringRevisionIsSessionless pins the transport-level half of the revision: the
// declaring revision removed the protocol session along with the handshake, so the opener
// returns no session header and later requests are served without one. Demanding a header
// there would model the opposite of what the revision is for.
func TestDeclaringRevisionIsSessionless(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		srv := newServer()
		w := post(t, srv, declaringBody(1, "server/discover", ""), "")
		if sid := w.Header().Get(sessionHeader); sid != "" {
			t.Errorf("the declaring revision must not mint a session id, got %q", sid)
		}
		list := post(t, srv, declaringBody(2, "tools/list", ""), "")
		if list.Code != http.StatusOK {
			t.Fatalf("tools/list without a session header: want 200, got %d (%s)", list.Code, list.Body.String())
		}
	})
}

// TestDeclarationRequired pins that the declaring revision refuses a request carrying no
// per-request declaration — what makes the mock prove the proxy declares on the requests it
// originates rather than only on the ones a host already declared.
func TestDeclarationRequired(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		srv := newServer()
		for _, method := range []string{"server/discover", "tools/list"} {
			body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{}}`
			got := decodeMsg(t, post(t, srv, body, ""))
			if got.Error == nil || got.Error.Code != -32600 {
				t.Errorf("%s with no declaration: want -32600, got %+v", method, got.Error)
			}
		}
	})
}

// TestHandshakeRevisionUnchanged is the negative control for the whole change: serving the old
// revision allocates a session, needs no declaration, and emits none of the newer revision's
// result members.
func TestHandshakeRevisionUnchanged(t *testing.T) {
	withRevision(t, revisionHandshake, func() {
		srv := newServer()
		sid := initSession(t, srv)
		w := post(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, sid)
		body := w.Body.String()
		for _, absent := range []string{"resultType", "cacheScope", "ttlMs"} {
			if strings.Contains(body, absent) {
				t.Errorf("the handshake revision must not emit %q", absent)
			}
		}
	})
}

// TestListCachingMembers pins the fixture the proxy's L-6 clamp is demonstrated against: the
// mock emits `cacheScope: "public"` deliberately, so a demo reading `private` off the proxy's
// reply is reading a working clamp rather than an upstream that never said anything.
func TestListCachingMembers(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		srv := newServer()
		w := post(t, srv, declaringBody(2, "tools/list", ""), "")
		var result map[string]interface{}
		if err := json.Unmarshal(decodeMsg(t, w).Result, &result); err != nil {
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

// TestDeclaringOpenerNegotiatesNoVersion pins the shape the proxy's opener validation expects:
// capabilities and serverInfo present, no volunteered protocolVersion.
func TestDeclaringOpenerNegotiatesNoVersion(t *testing.T) {
	withRevision(t, revisionDeclaring, func() {
		srv := newServer()
		var result map[string]interface{}
		if err := json.Unmarshal(decodeMsg(t, post(t, srv, declaringBody(1, "server/discover", ""), "")).Result, &result); err != nil {
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
