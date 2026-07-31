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
