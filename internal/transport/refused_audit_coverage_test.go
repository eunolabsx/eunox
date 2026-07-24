// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// containsAny reports whether s contains any of subs.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// hasAuditRecordWithCode reports whether any record carries the given deny denial_code.
func hasAuditRecordWithCode(records []map[string]interface{}, code string) bool {
	for _, rec := range records {
		if dc, _ := rec["denial_code"].(string); dc == code {
			return true
		}
	}
	return false
}

// TestCheckAuth_RecordsAuthFailed is the finding-14 regression: a missing/invalid static
// Authorization bearer token must leave an AUTH_FAILED record on the tamper-evident tape
// (an off-host brute-force otherwise leaves zero trace), and must never record the
// presented credential.
func TestCheckAuth_RecordsAuthFailed(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{
		PDP:         pdp.AlwaysAllowPDP{},
		UpstreamURL: "http://upstream.invalid",
		AuthToken:   "s3cret-token",
		Sink:        sink,
	})

	for _, tc := range []struct{ name, authHeader string }{
		{"missing", ""},
		{"wrong", "Bearer wrong-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
			req.RemoteAddr = "203.0.113.7:5555"
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			if proxy.checkAuth(rec, req) {
				t.Fatal("checkAuth must reject a missing/invalid token")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}

	_ = sink.Close()
	records := readAuditRecords(t, logPath)
	if !hasAuditRecordWithCode(records, "AUTH_FAILED") {
		t.Fatal("expected an AUTH_FAILED audit record for the rejected bearer token")
	}
	// The presented credential must never be recorded.
	for _, r := range records {
		if raw, _ := json.Marshal(r); containsAny(string(raw), "wrong-token", "s3cret-token") {
			t.Errorf("audit record leaked a token: %s", raw)
		}
	}
}

// TestCheckControlToken_RecordsControlAuthFailed is the finding-14 regression for the
// emergency-stop endpoint: a missing/invalid X-Eunox-Control-Token must leave a
// CONTROL_AUTH_FAILED record, so same-host probing of /control/kill is visible.
func TestCheckControlToken_RecordsControlAuthFailed(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{
		PDP:          pdp.AlwaysAllowPDP{},
		UpstreamURL:  "http://upstream.invalid",
		ControlToken: "control-s3cret",
		Sink:         sink,
	})

	req := httptest.NewRequest(http.MethodPost, "/control/kill", http.NoBody)
	req.RemoteAddr = "127.0.0.1:6666"
	req.Header.Set(ControlTokenHeader, "wrong-control")
	rec := httptest.NewRecorder()
	if proxy.checkControlToken(rec, req) {
		t.Fatal("checkControlToken must reject a wrong token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}

	_ = sink.Close()
	records := readAuditRecords(t, logPath)
	if !hasAuditRecordWithCode(records, "CONTROL_AUTH_FAILED") {
		t.Fatal("expected a CONTROL_AUTH_FAILED audit record for the rejected control token")
	}
	for _, r := range records {
		if raw, _ := json.Marshal(r); containsAny(string(raw), "wrong-control", "control-s3cret") {
			t.Errorf("audit record leaked a control token: %s", raw)
		}
	}
}

// TestDriftRefusal_RecordsDriftRefused is the finding-15 regression: when the startup
// manifest-drift check refuses a session (the FM-5 tool-poisoning event), a DRIFT_REFUSED
// record must land on the tamper-evident tape rather than only stderr + a generic 500.
func TestDriftRefusal_RecordsDriftRefused(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	_, proxySrv := newTestRemoteProxy(t, startFakeUpstream(t, newFullFakeUpstream()), httpProxyOptions{
		PDP: pdp.AlwaysAllowPDP{},
		DriftCheck: drift.CheckFunc(func(json.RawMessage, string, error) error {
			return errors.New("tool poisoned: descriptionHash mismatch")
		}),
		Sink: sink,
	})

	initMsg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`),
	}
	resp := postMCP(t, proxySrv, initMsg, "")
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a failing drift check must refuse the session, not return 200")
	}
	_ = resp.Body.Close()

	_ = sink.Close()
	records := readAuditRecords(t, logPath)
	if !hasAuditRecordWithCode(records, "DRIFT_REFUSED") {
		t.Fatal("expected a DRIFT_REFUSED audit record when the startup drift check refuses the session")
	}
	// The raw drift reason (which names drifted tools) must stay off the signed tape.
	for _, r := range records {
		if raw, _ := json.Marshal(r); containsAny(string(raw), "descriptionHash mismatch", "tool poisoned") {
			t.Errorf("audit record leaked the raw drift reason: %s", raw)
		}
	}
}

// TestIsInfraDenialCode_RefusalCodes pins that the four non-policy refusal codes are
// classified as infra denials, so the suggest subcommand skips them (they name no policy
// target to mine).
func TestIsInfraDenialCode_RefusalCodes(t *testing.T) {
	for _, code := range []string{"AUTH_FAILED", "CONTROL_AUTH_FAILED", "RESOURCE_EXHAUSTED", "DRIFT_REFUSED"} {
		if !IsInfraDenialCode(code) {
			t.Errorf("IsInfraDenialCode(%q) = false, want true", code)
		}
	}
	// A real policy denial is still NOT infra.
	if IsInfraDenialCode(capability.ErrCodeCapabilityDenied) {
		t.Error("CAPABILITY_DENIED must not be classified as an infra denial")
	}
}
