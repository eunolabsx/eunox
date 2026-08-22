// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleKill_DimensionDistinguishesSessionAllFromGlobal is the property that makes
// the CLI's `--session all` escape hatch meaningful beyond the kill store. A session id is
// operator-settable, so one can literally be "all"; without a dimension field, revoking
// that session and halting the whole deployment produce the same signed audit record and
// the same response body, and `eunox kill` prints that body verbatim. An incident
// responder would have no way to tell the two apart.
func TestHandleKill_DimensionDistinguishesSessionAllFromGlobal(t *testing.T) {
	post := func(t *testing.T, body string) map[string]interface{} {
		t.Helper()
		proxy := newHTTPProxy(httpProxyOptions{Port: 3000, ControlToken: testControlToken})
		req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", CTJSON)
		req.Header.Set(ControlTokenHeader, testControlToken)
		req.RemoteAddr = "127.0.0.1:9999"
		req.Host = "127.0.0.1:9999"
		rr := httptest.NewRecorder()
		proxy.handleKill(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%q)", rr.Code, rr.Body.String())
		}
		var out map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding response %q: %v", rr.Body.String(), err)
		}
		return out
	}

	global := post(t, `{"all":true}`)
	sessionAll := post(t, `{"sessionId":"all"}`)

	// Both name "all" — that is exactly the collision — so the dimension is the only
	// thing that separates them.
	if global["killed"] != "all" || sessionAll["killed"] != "all" {
		t.Fatalf("precondition: both should report killed=all, got %v and %v", global, sessionAll)
	}
	if global["dimension"] != "global" {
		t.Errorf("global kill dimension = %v, want \"global\"", global["dimension"])
	}
	if sessionAll["dimension"] != "session" {
		t.Errorf("--session all dimension = %v, want \"session\"", sessionAll["dimension"])
	}
	if global["dimension"] == sessionAll["dimension"] {
		t.Error("a session named \"all\" must not be indistinguishable from a deployment-wide stop")
	}
}

// TestHandleKill_RejectsSessionIDWithAll is the single-object twin of the trailing-token
// refusal: that guard stops a smuggled SECOND JSON value, but one valid object naming both
// fields expresses the same half-described kill. Running the All arm and dropping sessionId
// resolves the ambiguity by a field order no reviewer of the body can see, turning a body
// that reads as a targeted kill into a deployment-wide stop.
func TestHandleKill_RejectsSessionIDWithAll(t *testing.T) {
	t.Parallel()
	proxy := newHTTPProxy(httpProxyOptions{Port: 3000, ControlToken: testControlToken})
	req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(`{"sessionId":"s1","all":true}`))
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(ControlTokenHeader, testControlToken)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Host = "127.0.0.1:9999"
	rr := httptest.NewRecorder()
	proxy.handleKill(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body=%q)", rr.Code, rr.Body.String())
	}
	// The refusal has to precede the kill, not merely change the response: the whole point is
	// that the deployment-wide stop the All arm would have run never happens.
	if status := killStatusForTest(t, proxy); status.GlobalActive {
		t.Error("an incoherent body must not activate the global kill switch")
	}
}

// TestHandleKill_RejectsSmuggledSessionIDInsideOneObject covers the two shapes that express
// the half-described kill INSIDE one valid JSON object, which the post-decode field guard
// alone cannot see: it reads values encoding/json has already resolved. A duplicate member
// is kept last-wins and an unmodelled one is dropped, so both bodies read to a human as a
// targeted kill and reach the guard as a bare {"all":true}.
func TestHandleKill_RejectsSmuggledSessionIDInsideOneObject(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		// Last duplicate wins, so SessionID decodes empty and All survives.
		"duplicate sessionId": `{"sessionId":"s1","all":true,"sessionId":""}`,
		// Case-insensitive member matching: the second spelling is the one that binds.
		"case-variant sessionId": `{"sessionId":"s1","all":true,"SESSIONID":""}`,
		// Unmodelled member, silently dropped without DisallowUnknownFields.
		"misspelled sessionId": `{"session_id":"s1","all":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			proxy := newHTTPProxy(httpProxyOptions{Port: 3000, ControlToken: testControlToken})
			req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(ControlTokenHeader, testControlToken)
			req.RemoteAddr = "127.0.0.1:9999"
			req.Host = "127.0.0.1:9999"
			rr := httptest.NewRecorder()
			proxy.handleKill(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body=%q)", rr.Code, rr.Body.String())
			}
			if status := killStatusForTest(t, proxy); status.GlobalActive {
				t.Error("a body a reviewer reads as a targeted kill must not activate the global switch")
			}
		})
	}
}

// TestHandleKill_AcceptsTheTwoCoherentBodies is the other side of the closed-schema guard:
// tightening the decode must not have narrowed the two bodies the endpoint exists to serve.
func TestHandleKill_AcceptsTheTwoCoherentBodies(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"global":   `{"all":true}`,
		"targeted": `{"sessionId":"s1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			proxy := newHTTPProxy(httpProxyOptions{Port: 3000, ControlToken: testControlToken})
			req := httptest.NewRequest(http.MethodPost, "/control/kill", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", CTJSON)
			req.Header.Set(ControlTokenHeader, testControlToken)
			req.RemoteAddr = "127.0.0.1:9999"
			req.Host = "127.0.0.1:9999"
			rr := httptest.NewRecorder()
			proxy.handleKill(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 (body=%q)", rr.Code, rr.Body.String())
			}
		})
	}
}
