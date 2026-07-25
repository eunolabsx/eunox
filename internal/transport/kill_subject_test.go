// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// TestGlobalKill_RegistryMissSeparatesClaimedSessionID pins that a kill denial for an
// Mcp-Session-Id that does NOT resolve in the session registry records the id as the
// unverified details.claimed_session_id, never as the structured session_id.
//
// This is only reachable while a GLOBAL kill is active: CheckKill then denies EVERY id,
// including one the caller invented, so stamping it as session_id would let anyone mint
// KILL_SWITCH records attributed to a victim's (or a nonexistent) session. It is the same
// separation checkOrigin and the JWT refusal path already apply — see killSubject.
func TestGlobalKill_RegistryMissSeparatesClaimedSessionID(t *testing.T) {
	const forgedSessionID = "victim-session-not-in-registry"

	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{
			// A request gets a JSON-RPC KILL_SWITCH error body.
			name: "request",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`,
			want: http.StatusOK,
		},
		{
			// A notification is fire-and-forget: recorded, then acked with a bodyless 202.
			name: "notification",
			body: `{"jsonrpc":"2.0","method":"notifications/progress"}`,
			want: http.StatusAccepted,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ks := killswitch.NewInMemory()
			if err := ks.ActivateGlobal(context.Background()); err != nil {
				t.Fatalf("ActivateGlobal: %v", err)
			}
			sink, logPath := newTempAuditSink(t)
			// The route PDP is what handleSessionPost consults, so it carries the kill
			// switch. AlwaysAllowPDP keeps every other gate open, isolating the kill path.
			proxy := newHTTPProxy(httpProxyOptions{
				Bind: "127.0.0.1", Sink: sink, KS: ks, PDP: pdp.NewAlwaysAllowPDP(ks),
			})

			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(SessionHeader, forgedSessionID)
			rec := httptest.NewRecorder()
			proxy.handleMCP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.want, rec.Body.String())
			}

			_ = sink.Close()
			var killRec map[string]interface{}
			for _, r := range readAuditRecords(t, logPath) {
				if code, _ := r["denial_code"].(string); code == "KILL_SWITCH" {
					killRec = r
					break
				}
			}
			if killRec == nil {
				t.Fatal("no KILL_SWITCH deny record written for the registry-miss request")
			}
			if got, _ := killRec["session_id"].(string); got != "" {
				t.Errorf("session_id = %q, want empty: the id never resolved in the registry, so it is unverified", got)
			}
			details, ok := killRec["details"].(map[string]interface{})
			if !ok {
				t.Fatalf("details = %v, want a map carrying claimed_session_id", killRec["details"])
			}
			if got, _ := details["claimed_session_id"].(string); got != forgedSessionID {
				t.Errorf("details.claimed_session_id = %q, want %q", got, forgedSessionID)
			}
		})
	}
}

// TestKillSubject_VerifiedVsClaimed pins the two constructors' record-shaping contract
// directly, so a future call site that picks the wrong one is caught here rather than
// only through a transport-level test.
func TestKillSubject_VerifiedVsClaimed(t *testing.T) {
	t.Parallel()

	known := knownSession("sess-abc")
	if got := known.sessionID(); got != "sess-abc" {
		t.Errorf("knownSession.sessionID() = %q, want the id in the structured field", got)
	}
	if got := known.details(nil); got != nil {
		t.Errorf("knownSession.details(nil) = %v, want nil: a verified id is not also a claimed one", got)
	}
	// A verified subject must leave a caller-supplied details map untouched.
	base := map[string]interface{}{"transport": "http-notification"}
	got := known.details(base)
	if _, ok := got["claimed_session_id"]; ok {
		t.Errorf("knownSession.details(base) added claimed_session_id: %v", got)
	}

	claimed := claimedSession("client-supplied")
	if got := claimed.sessionID(); got != "" {
		t.Errorf("claimedSession.sessionID() = %q, want empty so the unverified id never reaches session_id", got)
	}
	d := claimed.details(map[string]interface{}{"transport": "http-notification"})
	if d["claimed_session_id"] != "client-supplied" {
		t.Errorf("claimedSession.details() = %v, want claimed_session_id preserved alongside the caller's keys", d)
	}
	if d["transport"] != "http-notification" {
		t.Errorf("claimedSession.details() dropped the caller's keys: %v", d)
	}

	// The bound the pre-session refusal paths apply must apply here too: the id is
	// attacker-controlled, so an oversized header cannot become a log-flooding primitive.
	long := claimedSession(strings.Repeat("A", maxClaimedSessionIDLen+50)).details(nil)
	if got, _ := long["claimed_session_id"].(string); len(got) != maxClaimedSessionIDLen {
		t.Errorf("claimed_session_id length = %d, want it truncated to %d", len(got), maxClaimedSessionIDLen)
	}
	if truncated, _ := long["claimed_session_id_truncated"].(bool); !truncated {
		t.Error("truncation must be marked so an operator can tell a bounded id from a real one")
	}

	// An empty claimed id adds no key at all (a missing header leaves no empty detail).
	if got := claimedSession("").details(nil); got != nil {
		t.Errorf("claimedSession(\"\").details(nil) = %v, want nil", got)
	}
}
