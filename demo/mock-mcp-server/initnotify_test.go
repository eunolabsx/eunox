// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"testing"
)

// TestInitializeNotificationDoesNotCreateSession guards against the case where handlePost
// handled method == "initialize" before checking whether the message was a
// JSON-RPC request, so an initialize *notification* (no id) allocated and stored
// a session and returned a session header, growing the session map without bound
// on repeated invalid notifications. A notification must be accepted (202)
// without mutating session state or assigning a session ID.
func TestInitializeNotificationDoesNotCreateSession(t *testing.T) {
	srv := newServer()

	const notify = `{"jsonrpc":"2.0","method":"initialize","params":{}}`
	for i := 0; i < 5; i++ {
		w := post(t, srv, notify, "")
		if w.Code != http.StatusAccepted {
			t.Fatalf("initialize notification: got status %d, want %d", w.Code, http.StatusAccepted)
		}
		if sid := w.Header().Get(sessionHeader); sid != "" {
			t.Fatalf("initialize notification assigned a session ID %q", sid)
		}
	}

	srv.mu.RLock()
	n := len(srv.sessions)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("initialize notifications created %d sessions, want 0", n)
	}

	// A real initialize *request* (with id) must still create exactly one session.
	w := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("initialize request: got status %d, want %d", w.Code, http.StatusOK)
	}
	if w.Header().Get(sessionHeader) == "" {
		t.Fatal("initialize request did not assign a session ID")
	}
	srv.mu.RLock()
	n = len(srv.sessions)
	srv.mu.RUnlock()
	if n != 1 {
		t.Fatalf("after one initialize request, have %d sessions, want 1", n)
	}
}

// TestInitializeNullIDIsRequest guards against decoding `"id": null` to a nil
// pointer, which would misclassify a valid id:null initialize request as a
// notification: the initialize path would fall through to 202 Accepted with no
// session instead of returning 200 OK and an Mcp-Session-Id. rpcMsg.UnmarshalJSON
// must keep a present-null id non-nil so isRequest() classifies it correctly.
func TestInitializeNullIDIsRequest(t *testing.T) {
	srv := newServer()

	w := post(t, srv, `{"jsonrpc":"2.0","id":null,"method":"initialize","params":{}}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("id:null initialize: got status %d, want %d", w.Code, http.StatusOK)
	}
	if w.Header().Get(sessionHeader) == "" {
		t.Fatal("id:null initialize did not assign a session ID")
	}
	// The response must echo the null id verbatim (a present, valid identifier).
	msg := decodeMsg(t, w)
	if msg.ID == nil || string(*msg.ID) != "null" {
		t.Fatalf("id:null initialize response did not echo a null id; got %v", msg.ID)
	}

	srv.mu.RLock()
	n := len(srv.sessions)
	srv.mu.RUnlock()
	if n != 1 {
		t.Fatalf("id:null initialize created %d sessions, want 1", n)
	}
}
