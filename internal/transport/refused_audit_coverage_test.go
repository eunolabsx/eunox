// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
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
	"github.com/eunolabs/eunox/pkg/killswitch"
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

// assertRecordsExclude fails the test if any audit record's JSON contains any of subs. It
// proves a presented credential or a raw drift reason never reaches the tape, folding the
// per-test marshal/scan loop into one helper.
func assertRecordsExclude(t *testing.T, records []map[string]interface{}, subs ...string) {
	t.Helper()
	for _, r := range records {
		if raw, _ := json.Marshal(r); containsAny(string(raw), subs...) {
			t.Errorf("audit record leaked a forbidden substring %v: %s", subs, raw)
		}
	}
}

// findAuditRecordByCode returns the first record carrying the given deny denial_code, or nil.
func findAuditRecordByCode(records []map[string]interface{}, code string) map[string]interface{} {
	for _, rec := range records {
		if dc, _ := rec["denial_code"].(string); dc == code {
			return rec
		}
	}
	return nil
}

// hasAuditRecordWithCode reports whether any record carries the given deny denial_code.
func hasAuditRecordWithCode(records []map[string]interface{}, code string) bool {
	return findAuditRecordByCode(records, code) != nil
}

// findAuditRecordsByCode returns every record carrying the given deny denial_code, in log
// order. The singular form answers "was it recorded"; this one answers "how many", which
// is the question the saturation gate's episode collapsing turns into a behavior.
func findAuditRecordsByCode(records []map[string]interface{}, code string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, rec := range records {
		if dc, _ := rec["denial_code"].(string); dc == code {
			out = append(out, rec)
		}
	}
	return out
}

// TestCheckAuth_RecordsAuthFailed pins that a missing/invalid static Authorization bearer
// token leaves an AUTH_FAILED record on the tamper-evident tape (an off-host brute-force
// otherwise leaves zero trace) and never records the presented credential. Each case wires
// its OWN sink and asserts inside the subtest, so the record is attributed to that specific
// case — a missing token and a wrong token must EACH record, not just one of them (an
// any-match after the loop would let a missing-token regression pass on the wrong-token
// record).
func TestCheckAuth_RecordsAuthFailed(t *testing.T) {
	for _, tc := range []struct{ name, authHeader string }{
		{"missing", ""},
		{"wrong", "Bearer wrong-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink, logPath := newTempAuditSink(t)
			proxy := newHTTPProxy(httpProxyOptions{
				PDP:         pdp.AlwaysAllowPDP{},
				UpstreamURL: "http://upstream.invalid",
				AuthToken:   "s3cret-token",
				Sink:        sink,
			})

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

			_ = sink.Close()
			records := readAuditRecords(t, logPath)
			if !hasAuditRecordWithCode(records, "AUTH_FAILED") {
				t.Fatalf("expected an AUTH_FAILED audit record for the %s bearer token", tc.name)
			}
			// The presented credential must never be recorded.
			assertRecordsExclude(t, records, "wrong-token", "s3cret-token")
		})
	}
}

// TestCheckControlToken_RecordsControlAuthFailed pins that a missing/invalid
// X-Eunox-Control-Token on the emergency-stop endpoint leaves a CONTROL_AUTH_FAILED
// record, so same-host probing of /control/kill is visible; the presented token is never
// recorded.
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
	assertRecordsExclude(t, records, "wrong-control", "control-s3cret")
}

// TestDriftRefusal_RecordsDriftRefused pins that when the startup manifest-drift check
// refuses a session (the FM-5 tool-poisoning event), a DRIFT_REFUSED record lands on the
// tamper-evident tape rather than only stderr + a generic 500, and the raw drift reason
// (which names the drifted tools) never reaches the signed tape.
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
	assertRecordsExclude(t, records, "descriptionHash mismatch", "tool poisoned")
}

// TestSessionSaturation_RecordsResourceExhausted covers the network-exposed transport:
// when the HTTP per-session in-flight cap is saturated, the server-busy refusal must leave
// a RESOURCE_EXHAUSTED record on the tape — a DoS-probe flood against the exposed transport
// must not be invisible while its stdio twin is recorded. Sharing the stdio helper, the
// refused method is recorded WITHOUT fabricating a target from it (the phantom-target trap).
func TestSessionSaturation_RecordsResourceExhausted(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	proxy, proxySrv := newTestRemoteProxy(t, startFakeUpstream(t, newFullFakeUpstream()), httpProxyOptions{
		PDP:        pdp.AlwaysAllowPDP{},
		DriftCheck: drift.CheckFunc(func(json.RawMessage, string, error) error { return nil }),
		Sink:       sink,
	})
	sid := initSession(t, proxySrv)

	// Saturate the session's in-flight cap directly, so the next enforced request is
	// refused by tryAcquireRequestSlot before it reaches the dispatcher — equivalent to a
	// flood of concurrent slow calls, without blocking that many upstream round-trips.
	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found after initialize")
	}
	for i := 0; i < maxConcurrentSessionRequests; i++ {
		if !sess.tryAcquireRequestSlot() {
			t.Fatalf("acquire %d must succeed within the cap", i)
		}
	}

	busy := decodeRPC(t, postMCP(t, proxySrv, mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`7`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"slow","arguments":{}}`),
	}, sid))
	if busy.Error == nil || busy.Error.Code != jsonRPCCodeServerBusy {
		t.Fatalf("a saturated session must return a server-busy error, got %+v", busy.Error)
	}

	_ = sink.Close()
	rec := findAuditRecordByCode(readAuditRecords(t, logPath), "RESOURCE_EXHAUSTED")
	if rec == nil {
		t.Fatal("expected a RESOURCE_EXHAUSTED record when the HTTP session pool is saturated")
	}
	if method, _ := rec["method"].(string); method != "tools/call" {
		t.Errorf("record method=%q, want tools/call", method)
	}
	// The refused method must NOT be fabricated into a target: passing the method as the
	// identifier would make deriveTargetFields synthesize target=="tools/call", a phantom
	// tool that pollutes target-based audit aggregation. target stays absent instead.
	if target, ok := rec["target"]; ok && target != "" {
		t.Errorf("RESOURCE_EXHAUSTED must record no target, got %q (phantom target from the method)", target)
	}
	if got, _ := rec["session_id"].(string); got != sid {
		t.Errorf("record session_id=%q, want the established session %q", got, sid)
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

// TestHandleKill_RecordsSuccessfulActivation pins the other half of the /control/kill
// audit story: every REFUSAL of the endpoint is recorded (CONTROL_AUTH_FAILED above),
// and now the successful activation is too. Without it an auditor sees a run of
// KILL_SWITCH denials with no signed evidence of when the stop was tripped or that it
// was authorized. The control token must never appear on the tape.
func TestHandleKill_RecordsSuccessfulActivation(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantScope string
	}{
		{"global", `{"all":true}`, killScopeAll},
		{"targeted", `{"sessionId":"sess-42"}`, "sess-42"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sink, logPath := newTempAuditSink(t)
			proxy := newHTTPProxy(httpProxyOptions{
				PDP:          pdp.AlwaysAllowPDP{},
				UpstreamURL:  "http://upstream.invalid",
				ControlToken: "control-s3cret",
				Sink:         sink,
			})

			req := httptest.NewRequest(http.MethodPost, "/control/kill", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", CTJSON)
			req.RemoteAddr = "127.0.0.1:6666"
			req.Host = "127.0.0.1:9999" // loopback Host so loopbackOnly's DNS-rebinding guard passes
			req.Header.Set(ControlTokenHeader, "control-s3cret")
			rec := httptest.NewRecorder()
			proxy.handleKill(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}

			_ = sink.Close()
			records := readAuditRecords(t, logPath)
			var found map[string]interface{}
			for _, r := range records {
				if m, _ := r["method"].(string); m == MethodControlKill {
					found = r
					break
				}
			}
			if found == nil {
				t.Fatalf("expected a %q audit record for a successful activation; got %d records", MethodControlKill, len(records))
			}
			if d, _ := found["decision"].(string); d != "allow" {
				t.Errorf("decision = %q, want \"allow\": the activation was authorized and performed, not refused", d)
			}
			details, _ := found["details"].(map[string]interface{})
			if got, _ := details["scope"].(string); got != tc.wantScope {
				t.Errorf("details.scope = %q, want %q", got, tc.wantScope)
			}
			// An administrative action addresses no MCP tool/resource/prompt, so no target
			// may be fabricated from the method string (the phantom-target trap).
			if tt, ok := found["target_type"].(string); ok && tt != "" {
				t.Errorf("target_type = %q, want empty for an administrative action", tt)
			}
			if tgt, ok := found["target"].(string); ok && tgt != "" {
				t.Errorf("target = %q, want empty for an administrative action", tgt)
			}
			assertRecordsExclude(t, records, "control-s3cret")
		})
	}
}

// TestHandleKill_NoRecordWhenActivationFails pins the ordering: the record is written
// only AFTER the kill store accepts the write, so the tape never claims a stop that did
// not take effect.
func TestHandleKill_NoRecordWhenActivationFails(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	proxy := newHTTPProxy(httpProxyOptions{
		PDP:          pdp.AlwaysAllowPDP{},
		UpstreamURL:  "http://upstream.invalid",
		ControlToken: "control-s3cret",
		Sink:         sink,
	})
	proxy.ks = failingKillSwitch{}

	req := httptest.NewRequest(http.MethodPost, "/control/kill", strings.NewReader(`{"all":true}`))
	req.Header.Set("Content-Type", CTJSON)
	req.RemoteAddr = "127.0.0.1:6666"
	req.Host = "127.0.0.1:9999" // loopback Host so loopbackOnly's DNS-rebinding guard passes
	req.Header.Set(ControlTokenHeader, "control-s3cret")
	rec := httptest.NewRecorder()
	proxy.handleKill(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when the kill store rejects the write", rec.Code)
	}

	_ = sink.Close()
	for _, r := range readAuditRecords(t, logPath) {
		if m, _ := r["method"].(string); m == MethodControlKill {
			t.Fatalf("a failed activation must not be recorded as one: %v", r)
		}
	}
}

// failingKillSwitch fails every write so the activation path can be driven into its
// fail-closed 500 without a real backend. Reads report "not blocked" so nothing else in
// the handler short-circuits first.
type failingKillSwitch struct{}

func (failingKillSwitch) ShouldBlock(context.Context, string, string) (bool, error) {
	return false, nil
}
func (failingKillSwitch) ActivateGlobal(context.Context) error   { return errors.New("backend down") }
func (failingKillSwitch) DeactivateGlobal(context.Context) error { return errors.New("backend down") }
func (failingKillSwitch) KillAgent(context.Context, string) error {
	return errors.New("backend down")
}
func (failingKillSwitch) ReviveAgent(context.Context, string) error {
	return errors.New("backend down")
}
func (failingKillSwitch) KillSession(context.Context, string) error {
	return errors.New("backend down")
}
func (failingKillSwitch) ReviveSession(context.Context, string) error {
	return errors.New("backend down")
}
func (failingKillSwitch) Reset(context.Context) error { return errors.New("backend down") }
func (failingKillSwitch) Status(context.Context) (*killswitch.Status, error) {
	return nil, errors.New("backend down")
}

// TestSessionCapDeny_CarriesRouteStamp pins the session-cap refusal's record SHAPE. It
// shares a denial code with the per-session in-flight cap, so it must share the record
// shape too: written through the ROUTE's sink, carrying the route name and policy stamp.
// It previously went through the proxy-wide, route-unstamped pre-session path, leaving one
// denial code with two shapes depending on which cap the flood happened to hit.
func TestSessionCapDeny_CarriesRouteStamp(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	proxy := &HTTPProxy{sink: sink, preSessionDenies: newPreSessionDenyLimiter()}
	route := &UpstreamRoute{
		name: "github",
		sink: &routeSink{sink: sink, upstream: "github", policyVersion: "1.2.3", policySHA256: "sha256:abc"},
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp/github", http.NoBody)

	proxy.recordSessionCapDeny(req, route)

	_ = sink.Close()
	rec := findAuditRecordByCode(readAuditRecords(t, logPath), "RESOURCE_EXHAUSTED")
	if rec == nil {
		t.Fatal("expected a RESOURCE_EXHAUSTED record for the session-cap refusal")
	}
	if got, _ := rec["upstream"].(string); got != "github" {
		t.Errorf("upstream = %q, want the route name — the session-cap record must carry the same route stamp as its in-flight-cap sibling", got)
	}
	if got, _ := rec["policy_version"].(string); got != "1.2.3" {
		t.Errorf("policy_version = %q, want 1.2.3", got)
	}
	details, _ := rec["details"].(map[string]interface{})
	if details == nil || details["reason"] != "session_limit_reached" {
		t.Errorf("details = %v, want reason=session_limit_reached", details)
	}
	// The rate limit is retained: unlike the in-flight cap, this refusal is reachable
	// without an established session, so it must stay behind the pre-session limiter.
	if got, _ := rec["session_id"].(string); got != "" {
		t.Errorf("session_id = %q, want empty — no session exists at the cap refusal", got)
	}
}

// TestNotificationSaturation_RecordsResourceExhausted: the notification pool's drop must
// leave the same RESOURCE_EXHAUSTED record its request-pool sibling does. The notification
// most worth having on the tape is notifications/cancelled — an incident responder asking
// why an aborted call ran to completion cannot get that answer from stderr alone.
func TestNotificationSaturation_RecordsResourceExhausted(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	proxy, proxySrv := newTestRemoteProxy(t, startFakeUpstream(t, newFullFakeUpstream()), httpProxyOptions{
		PDP:        pdp.AlwaysAllowPDP{},
		DriftCheck: drift.CheckFunc(func(json.RawMessage, string, error) error { return nil }),
		Sink:       sink,
	})
	sid := initSession(t, proxySrv)

	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found after initialize")
	}
	for i := 0; i < maxConcurrentSessionNotifications; i++ {
		if !sess.tryAcquireNotifySlot() {
			t.Fatalf("acquire %d must succeed within the cap", i)
		}
	}

	resp := postMCP(t, proxySrv, mcp.RPCMsg{
		JSONRPC: "2.0",
		Method:  "notifications/cancelled",
		Params:  json.RawMessage(`{"requestId":7}`),
	}, sid)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("dropped notification status = %d, want 202 (fire-and-forget ack)", resp.StatusCode)
	}
	_ = resp.Body.Close()

	_ = sink.Close()
	rec := findAuditRecordByCode(readAuditRecords(t, logPath), "RESOURCE_EXHAUSTED")
	if rec == nil {
		t.Fatal("expected a RESOURCE_EXHAUSTED record when the notification pool is saturated")
	}
	if method, _ := rec["method"].(string); method != "notifications/cancelled" {
		t.Errorf("record method=%q, want notifications/cancelled", method)
	}
	if got, _ := rec["session_id"].(string); got != sid {
		t.Errorf("record session_id=%q, want the established session %q", got, sid)
	}
}

// TestNotificationSaturation_CollapsesEpisodeAndRollsUpSuppressed is the end-to-end half of
// the saturation gate: a session that keeps a pool saturated writes ONE record for the
// episode, and the elided drops surface as suppressed_refusal_count on the NEXT episode's
// record rather than vanishing.
//
// The notification path is the one that needed this most. It costs an established session
// nothing per drop — no upstream round trip, no response body to await — and it answers 202
// Accepted, byte-identical to a successful forward, so a flooding client gets no signal to
// back off and simply keeps going. One record per dropped frame therefore made this the
// cheapest way to push the audit sink's bounded queue into its MONOTONIC drop counter,
// which latches AuditDegraded() for the process lifetime and, under the default
// --require-audit=strict, denies every enforced call on every route: a saturation condition
// on one session becoming a proxy-wide outage.
func TestNotificationSaturation_CollapsesEpisodeAndRollsUpSuppressed(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	proxy, proxySrv := newTestRemoteProxy(t, startFakeUpstream(t, newFullFakeUpstream()), httpProxyOptions{
		PDP:        pdp.AlwaysAllowPDP{},
		DriftCheck: drift.CheckFunc(func(json.RawMessage, string, error) error { return nil }),
		Sink:       sink,
	})
	sid := initSession(t, proxySrv)

	sess := proxy.getSession(sid)
	if sess == nil {
		t.Fatal("session not found after initialize")
	}
	saturate := func() {
		t.Helper()
		for i := 0; i < maxConcurrentSessionNotifications; i++ {
			if !sess.tryAcquireNotifySlot() {
				t.Fatalf("acquire %d must succeed within the cap", i)
			}
		}
	}
	dropOne := func() {
		resp := postMCP(t, proxySrv, mcp.RPCMsg{
			JSONRPC: "2.0",
			Method:  "notifications/cancelled",
			Params:  json.RawMessage(`{"requestId":7}`),
		}, sid)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("dropped notification status = %d, want 202 (fire-and-forget ack)", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	// Episode one: three drops against a saturated pool.
	saturate()
	const firstEpisodeDrops = 3
	for i := 0; i < firstEpisodeDrops; i++ {
		dropOne()
	}

	// Episode two: a slot frees and is re-taken (the acquire is what ends an episode — a
	// release alone does not, since nothing was admitted through the pool), then one more
	// drop. That record must carry the two drops elided from episode one.
	sess.releaseNotifySlot()
	if !sess.tryAcquireNotifySlot() {
		t.Fatal("the freed slot must be re-acquirable")
	}
	dropOne()

	_ = sink.Close()
	recs := findAuditRecordsByCode(readAuditRecords(t, logPath), "RESOURCE_EXHAUSTED")
	if len(recs) != 2 {
		t.Fatalf("got %d RESOURCE_EXHAUSTED records, want 2 — one per saturation episode, not one per dropped frame", len(recs))
	}
	if details, _ := recs[0]["details"].(map[string]interface{}); details[detailSuppressedRefusalCount] != nil {
		t.Errorf("the first record of an episode elides nothing, so it must omit %s; got %v", detailSuppressedRefusalCount, details[detailSuppressedRefusalCount])
	}
	details, _ := recs[1]["details"].(map[string]interface{})
	if got := details[detailSuppressedRefusalCount]; got != float64(firstEpisodeDrops-1) {
		t.Errorf("%s = %v, want %d — the drops elided by episode collapsing must still reach the tape", detailSuppressedRefusalCount, got, firstEpisodeDrops-1)
	}
	// The scope names the pool's own reach, never the proxy-wide bucket's: sharing that
	// bucket would let this session's flood elide an unrelated AUTH_FAILED/ORIGIN_REJECTED
	// record, so a saturation rollup must never claim suppressedScopeProxy.
	if got := details[detailSuppressedRefusalScope]; got != suppressedScopeSession {
		t.Errorf("%s = %v, want %q", detailSuppressedRefusalScope, got, suppressedScopeSession)
	}
	// The gate changes admission only: the record keeps the shape its sibling has.
	if method, _ := recs[1]["method"].(string); method != "notifications/cancelled" {
		t.Errorf("record method=%q, want notifications/cancelled", method)
	}
	if got, _ := recs[1]["session_id"].(string); got != sid {
		t.Errorf("record session_id=%q, want the established session %q", got, sid)
	}
}

// TestUnsupportedMediaType_RecordsRefusal pins that a 415 lands on the tamper-evident
// tape like every other transport-level refusal. Without it, a content-type sweep of
// the sessionless initialize POST — the one /mcp entry point that needs no custom
// header — and of the emergency stop was the single refusal an incident responder
// could not see, while the same actor's wrong-Origin attempts were fully recorded.
//
// The attacker-controlled header VALUE must never reach the tape; only the count does.
func TestUnsupportedMediaType_RecordsRefusal(t *testing.T) {
	cases := []struct {
		name        string
		contentType []string
		wantCount   float64
	}{
		{"wrong media type", []string{"text/plain"}, 1},
		{"absent header", nil, 0},
		{"duplicated header", []string{CTJSON, CTJSON}, 2},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sink, logPath := newTempAuditSink(t)
			proxy := newHTTPProxy(httpProxyOptions{
				PDP:         pdp.AlwaysAllowPDP{},
				UpstreamURL: "http://upstream.invalid",
				Sink:        sink,
			})
			route := proxy.routes[""]

			body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{},"secret":"s3cret-body"}`
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			req.Header.Del("Content-Type")
			for _, v := range tc.contentType {
				req.Header.Add("Content-Type", v)
			}
			req.RemoteAddr = "203.0.113.7:5555"
			rec := httptest.NewRecorder()
			proxy.handleMCPPost(rec, req, route)
			if rec.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", rec.Code)
			}

			_ = sink.Close()
			records := readAuditRecords(t, logPath)
			if !hasAuditRecordWithCode(records, codeUnsupportedMediaType) {
				t.Fatalf("expected an %s audit record for the refused content type; got %d records", codeUnsupportedMediaType, len(records))
			}
			var found map[string]interface{}
			for _, r := range records {
				if c, _ := r["denial_code"].(string); c == codeUnsupportedMediaType {
					found = r
					break
				}
			}
			details, _ := found["details"].(map[string]interface{})
			if got, _ := details["header_count"].(float64); got != tc.wantCount {
				t.Errorf("details.header_count = %v, want %v", got, tc.wantCount)
			}
			// Neither the offending header value nor the request body may be recorded.
			assertRecordsExclude(t, records, "text/plain", "s3cret-body")
		})
	}
}

// TestUnsupportedMediaType_IsNonPolicyCode pins that the new code joins its siblings in
// the infra-denial set, so `suggest` skips it rather than mining a phantom policy target
// out of a malformed request.
func TestUnsupportedMediaType_IsNonPolicyCode(t *testing.T) {
	if !IsInfraDenialCode(codeUnsupportedMediaType) {
		t.Errorf("%s names no policy target, so it must be classified as an infra denial", codeUnsupportedMediaType)
	}
}

// TestDecodeStrictJSON_RecordsMalformedBody pins that the two 400 legs of
// decodeStrictJSON (malformed JSON, a trailing token after the JSON value) land on the
// tamper-evident tape under INVALID_REQUEST, the same way the sibling 415 already does —
// a malformed body on the same shared decode path must not be the one refusal that
// leaves no trace. Covers both call sites (the /mcp body and the /control/kill body)
// since they share this one function.
func TestDecodeStrictJSON_RecordsMalformedBody(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		body   string
		header func(*http.Request)
		reason string
	}{
		{
			name:   "mcp malformed json",
			path:   "/mcp",
			body:   `{"jsonrpc":"2.0`,
			reason: "malformed_json",
		},
		{
			name:   "mcp trailing data",
			path:   "/mcp",
			body:   `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}{"all":true}`,
			reason: "trailing_data",
		},
		{
			name:   "control/kill malformed json",
			path:   "/control/kill",
			body:   `not json`,
			reason: "malformed_json",
			header: func(r *http.Request) { r.Header.Set(ControlTokenHeader, testControlToken) },
		},
		{
			name:   "control/kill trailing data",
			path:   "/control/kill",
			body:   `{"all":true}{"all":false}`,
			reason: "trailing_data",
			header: func(r *http.Request) { r.Header.Set(ControlTokenHeader, testControlToken) },
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sink, logPath := newTempAuditSink(t)
			proxy := newHTTPProxy(httpProxyOptions{
				PDP:          pdp.AlwaysAllowPDP{},
				UpstreamURL:  "http://upstream.invalid",
				ControlToken: testControlToken,
				Sink:         sink,
			})

			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", CTJSON)
			req.RemoteAddr = "127.0.0.1:9999"
			req.Host = "127.0.0.1:9999" // loopback Host so loopbackOnly's DNS-rebinding guard passes
			if tc.header != nil {
				tc.header(req)
			}
			rec := httptest.NewRecorder()
			switch tc.path {
			case "/mcp":
				proxy.handleMCPPost(rec, req, proxy.routes[""])
			case "/control/kill":
				proxy.handleKill(rec, req)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}

			_ = sink.Close()
			records := readAuditRecords(t, logPath)
			found := findAuditRecordByCode(records, codeInvalidRequest)
			if found == nil {
				t.Fatalf("expected an %s audit record for the malformed body; got %d records", codeInvalidRequest, len(records))
			}
			details, _ := found["details"].(map[string]interface{})
			if got, _ := details["reason"].(string); got != tc.reason {
				t.Errorf("details.reason = %q, want %q", got, tc.reason)
			}
			// Neither the raw body nor the presented control token may reach the tape.
			assertRecordsExclude(t, records, tc.body, testControlToken)
		})
	}
}

// TestDecodeStrictJSON_RouteStampedWhenRouteIsKnown pins that the /mcp malformed-body
// refusal carries the same route stamp as its session-cap sibling once a route is
// resolved, rather than being written through the unstamped proxy-wide sink despite the
// route already being known. decodeStrictJSON's own doc comment used to claim this record
// "can fire before route resolution" for BOTH its callers; that was only ever true for
// /control/kill (no route concept) — handleMCP already 404s an unknown upstream before
// handleMCPPost, and hence decodeStrictJSON, ever runs, so the /mcp leg always has one.
func TestDecodeStrictJSON_RouteStampedWhenRouteIsKnown(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	route := &UpstreamRoute{
		name: "github",
		pdp:  pdp.AlwaysAllowPDP{},
		sink: &routeSink{sink: sink, upstream: "github", policyVersion: "1.2.3", policySHA256: "sha256:abc"},
	}
	proxy := &HTTPProxy{
		sessions:           make(map[string]*httpSession),
		sink:               sink,
		preSessionDenies:   newPreSessionDenyLimiter(),
		allowedOriginHosts: buildAllowedOriginHosts(""),
		routes:             map[string]*UpstreamRoute{"github": route},
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp/github", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", CTJSON)
	rec := httptest.NewRecorder()
	proxy.handleMCPPost(rec, req, route)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}

	_ = sink.Close()
	found := findAuditRecordByCode(readAuditRecords(t, logPath), codeInvalidRequest)
	if found == nil {
		t.Fatal("expected an INVALID_REQUEST audit record for the malformed body")
	}
	if got, _ := found["upstream"].(string); got != "github" {
		t.Errorf("upstream = %q, want %q — the route was already resolved when decodeStrictJSON ran", got, "github")
	}
	if got, _ := found["policy_version"].(string); got != "1.2.3" {
		t.Errorf("policy_version = %q, want 1.2.3", got)
	}
	if got, _ := found["policy_sha256"].(string); got != "sha256:abc" {
		t.Errorf("policy_sha256 = %q, want sha256:abc", got)
	}
}
