// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// TestPreSessionDenyLimiter_BoundsBurstAndCountsSuppressed pins the property that closes
// the unauthenticated audit-flood vector: a caller who can trigger refusals at an arbitrary
// rate must not be able to enqueue audit records at that rate. Without the bound, the queue
// overflows, the sink's monotonic drop counter latches AuditDegraded(), and
// --require-audit=strict then denies every legitimate request for the process lifetime.
func TestPreSessionDenyLimiter_BoundsBurstAndCountsSuppressed(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	l := newPreSessionDenyLimiter()
	l.setNow(func() time.Time { return now })

	admitted := 0
	const attempts = 5000
	catBurst := int(perCategoryDenyBurst)
	for i := 0; i < attempts; i++ {
		if ok, _ := l.admit(catAuth); ok {
			admitted++
		}
	}
	if admitted != catBurst {
		t.Fatalf("a burst with no clock movement must admit exactly the burst size; admitted %d, want %d", admitted, catBurst)
	}

	// The suppressed refusals are not lost: the next admitted record carries the count, so
	// an operator sees both that the attack happened and its scale.
	now = base.Add(time.Second)
	ok, suppressed := l.admit(catAuth)
	if !ok {
		t.Fatal("a refill second must admit again")
	}
	if want := uint64(attempts - catBurst); suppressed != want {
		t.Fatalf("suppressed = %d, want %d — every suppressed refusal must be folded into the next admitted record", suppressed, want)
	}

	// And the count resets, so the following record does not double-report.
	if ok, s := l.admit(catAuth); !ok || s != 0 {
		t.Fatalf("after reporting, the suppressed counter must reset; ok=%v suppressed=%d", ok, s)
	}
}

// TestRefusalRollup_NamesItsScopeOnARouteStampedRecord pins the record shape where the
// rollup's scope and the record's own stamp disagree.
//
// A category's tally is proxy-wide: one bucket per category bounds the write rate into the
// single shared audit queue across every route, so a suppressed refusal is folded into
// whichever record of that category is admitted next, whatever route it belongs to. The
// session cap is the one refusal that is BOTH route-stamped and fed by such a bucket, so a
// saturation flood against route A can surface as a five-figure count on a record reading
// `upstream: github`. A SIEM rule or an operator keyed on route + code then reads thousands
// of saturation refusals against github's policy digest when github saw one. The count
// names its own scope, so nothing is inferred from the stamp beside it.
func TestRefusalRollup_NamesItsScopeOnARouteStampedRecord(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	base := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	now := base
	lim := newPreSessionDenyLimiter()
	lim.setNow(func() time.Time { return now })
	proxy := &HTTPProxy{sink: sink, preSessionDenies: lim}
	other := &UpstreamRoute{
		name: "internal",
		sink: &routeSink{sink: sink, upstream: "internal", policyVersion: "9.9.9", policySHA256: "sha256:zzz"},
	}
	route := &UpstreamRoute{
		name: "github",
		sink: &routeSink{sink: sink, upstream: "github", policyVersion: "1.2.3", policySHA256: "sha256:abc"},
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp/internal", http.NoBody)

	// Saturate a DIFFERENT route. None of this is attributable to github.
	const attempts = 5000
	for i := 0; i < attempts; i++ {
		proxy.recordSessionCapDeny(context.Background(), req, other)
	}
	// Refill one second of tokens, then let github's session cap be the next admitted.
	now = base.Add(time.Second)
	proxy.recordSessionCapDeny(context.Background(), httptest.NewRequest(http.MethodPost, "/mcp/github", http.NoBody), route)

	_ = sink.Close()
	recs := readAuditRecords(t, logPath)
	var rec map[string]interface{}
	for _, r := range recs {
		if d, _ := r["details"].(map[string]interface{}); d != nil && d[detailSuppressedRefusalCount] != nil {
			rec = r
		}
	}
	if rec == nil {
		t.Fatal("expected an admitted record carrying the rollup")
	}
	details, _ := rec["details"].(map[string]interface{})
	want := float64(attempts - int(perCategoryDenyBurst))
	if got := details[detailSuppressedRefusalCount]; got != want {
		t.Fatalf("%s = %v, want %v — the suppressed refusals must be folded into the next admitted record", detailSuppressedRefusalCount, got, want)
	}
	if got := details[detailSuppressedRefusalScope]; got != suppressedScopeProxyCategory {
		t.Errorf("%s = %v, want %q — a route-stamped record must state that its tally spans every route, not just the one it names", detailSuppressedRefusalScope, got, suppressedScopeProxyCategory)
	}
	// The record still carries its route stamp: naming the scope is what makes the two
	// coexist, so this must not have been "fixed" by dropping the attribution instead.
	if got, _ := rec["upstream"].(string); got != "github" {
		t.Errorf("upstream = %q, want the route name — the stamp must survive alongside the rollup", got)
	}
	// The bare key belongs to an unrelated statistic: a */list ALLOW record reports
	// suppressed_count as the entries the manifest hid. A query written against it must not
	// also match an unauthenticated refusal flood.
	if _, collides := details["suppressed_count"]; collides {
		t.Errorf("the refusal rollup must not reuse suppressed_count, which names the */list filter statistic; got details %v", details)
	}

	// Every written record must still pass its per-record HMAC under the sink's own key —
	// the count/scope details are signed like any other field. CLAUDE.md requires a
	// sign-and-verify round trip for a new audit-record field; the assertions above alone
	// only confirm the decoded shape, not that the shape survives verification.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		ok, verr := sink.VerifyRecord(line)
		if verr != nil {
			t.Fatalf("VerifyRecord: %v", verr)
		}
		if !ok {
			t.Errorf("record failed HMAC verification: %s", line)
		}
	}
}

// TestRefusalLimiter_OneCategoryFloodDoesNotEraseAnother is the regression. Under a single
// proxy-wide bucket, an unauthenticated Origin probe — one cheap request, no credential —
// absorbed the whole refusal budget, so a CONCURRENT control-token brute force wrote no
// record of its own and survived only as a number folded onto somebody else's. That is the
// record an incident responder reads first, elided by the cheapest possible flood.
func TestRefusalLimiter_OneCategoryFloodDoesNotEraseAnother(t *testing.T) {
	sink, logPath := newTempAuditSink(t)
	base := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	lim := newPreSessionDenyLimiter()
	lim.setNow(func() time.Time { return base })
	proxy := &HTTPProxy{sink: sink, preSessionDenies: lim}
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)

	// Exhaust the origin budget many times over, with no clock movement.
	for i := 0; i < 5000; i++ {
		proxy.recordPreSessionDeny(req, "ORIGIN_REJECTED", catOrigin, nil)
	}
	// The control-token attempts that follow must still be recorded in full — kept
	// comfortably under catControl's own per-category burst so this stays a test of
	// cross-category fairness, not a second bound-exhaustion test.
	controlAttempts := int(perCategoryDenyBurst) - 1
	for i := 0; i < controlAttempts; i++ {
		proxy.recordPreSessionDeny(req, codeControlAuthFailed, catControl, nil)
	}

	_ = sink.Close()
	control := 0
	for _, r := range readAuditRecords(t, logPath) {
		if code, _ := r["denial_code"].(string); code == codeControlAuthFailed {
			control++
		}
	}
	if control != controlAttempts {
		t.Errorf("wrote %d control-token refusal records, want %d — a cheap flood in another category absorbed the evidence an incident responder reads first", control, controlAttempts)
	}
	// The flooding category is still bounded: the point is fairness between categories,
	// not removing the bound.
	origin := 0
	for _, r := range readAuditRecords(t, logPath) {
		if code, _ := r["denial_code"].(string); code == "ORIGIN_REJECTED" {
			origin++
		}
	}
	if want := int(perCategoryDenyBurst); origin != want {
		t.Errorf("wrote %d origin refusal records, want the burst size %d — the flood must still be bounded", origin, want)
	}
}

// TestRefusalCategories_AllHaveTheirOwnBucket pins the enumerated table against the
// declared constants: a category constant added without being registered in
// refusalCategories would silently share the unknown bucket with every other unregistered
// one, quietly re-creating the cross-category suppression the split exists to remove.
func TestRefusalCategories_AllHaveTheirOwnBucket(t *testing.T) {
	t.Parallel()
	lim := newPreSessionDenyLimiter()
	seen := map[*recordRateLimiter]refusalCategory{}
	for _, cat := range refusalCategories {
		b := lim.bucket(cat)
		if b == lim.unknown {
			t.Errorf("category %q fell through to the shared unknown bucket", cat)
			continue
		}
		if other, dup := seen[b]; dup {
			t.Errorf("categories %q and %q share a bucket", cat, other)
		}
		seen[b] = cat
	}
	// Every constant declared in this package must be in the list the table is built
	// from. Checked by value so a new constant that is never registered is caught.
	for _, cat := range []refusalCategory{catOrigin, catJWT, catAuth, catControl, catLoopback, catBody, catContentType, catSaturation} {
		if _, registered := lim.buckets[cat]; !registered {
			t.Errorf("category constant %q is not in refusalCategories", cat)
		}
	}
}

// TestPreSessionDenyLimiter_RefillIsRateBounded pins that sustained pressure is served at
// the configured rate rather than the caller's rate.
func TestPreSessionDenyLimiter_RefillIsRateBounded(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	l := newPreSessionDenyLimiter()
	l.setNow(func() time.Time { return now })

	catBurst := int(perCategoryDenyBurst)
	catRate := int(perCategoryDenyRate)

	// Drain the burst.
	for i := 0; i < catBurst; i++ {
		if ok, _ := l.admit(catAuth); !ok {
			t.Fatalf("burst token %d should have been admitted", i)
		}
	}
	if ok, _ := l.admit(catAuth); ok {
		t.Fatal("the bucket must be empty after the burst is drained")
	}

	// One second of refill yields exactly the per-second rate, not more.
	now = base.Add(time.Second)
	admitted := 0
	for i := 0; i < catRate*10; i++ {
		if ok, _ := l.admit(catAuth); ok {
			admitted++
		}
	}
	if admitted != catRate {
		t.Fatalf("one second of refill admitted %d, want %d", admitted, catRate)
	}
}

// TestPreSessionDenyLimiter_BackwardsClockDoesNotGrantTokens pins that a clock step
// backwards cannot mint refill (which would hand an attacker the rate they were denied).
func TestPreSessionDenyLimiter_BackwardsClockDoesNotGrantTokens(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	l := newPreSessionDenyLimiter()
	l.setNow(func() time.Time { return now })
	for i := 0; i < int(perCategoryDenyBurst); i++ {
		l.admit(catAuth)
	}
	now = base.Add(-time.Hour)
	if ok, _ := l.admit(catAuth); ok {
		t.Fatal("a backwards clock step must not refill the bucket")
	}
}

// TestHostAllowedForLoopbackEndpoint_PresentButHostlessIsRefused pins the DNS-rebinding
// pin's absent-Host carve-out to the header being genuinely ABSENT.
//
// normalizeHost reduces a PRESENT but host-less value to "" — net.SplitHostPort succeeds on
// ":8080" and returns an empty host, and "[]" reduces the same way — so keying the
// allowance off the normalized value let `Host: :8080` skip the entire rebinding pin on
// /control/kill, /healthz and /metrics. The carve-out's own rationale ("HTTP/1.1 requires
// the header, so no value means a non-browser local caller") does not hold for a header
// that was sent.
func TestHostAllowedForLoopbackEndpoint_PresentButHostlessIsRefused(t *testing.T) {
	t.Parallel()
	p := &HTTPProxy{allowedOriginHosts: map[string]bool{"localhost": true}}

	if !p.hostAllowedForLoopbackEndpoint("", "") {
		t.Error("a genuinely absent Host must still be admitted (HTTP/1.0 probe, hand-rolled client)")
	}
	for _, raw := range []string{":8080", "[]", ":", "[]:9000"} {
		if p.hostAllowedForLoopbackEndpoint(raw, normalizeHost(raw)) {
			t.Errorf("Host %q is present but carries no host part; it must not satisfy the rebinding pin", raw)
		}
	}
	if !p.hostAllowedForLoopbackEndpoint("localhost:3000", "localhost") {
		t.Error("a trusted name must still be admitted")
	}
	if p.hostAllowedForLoopbackEndpoint("attacker.com", "attacker.com") {
		t.Error("a foreign name is the rebinding case and must be refused")
	}
}

// TestAddClaimedSessionID_NilMapAndOversizedHeader pins the two hazards in the shared
// pre-session detail helper: a nil details map (what a refusal with no extra context
// passes) must not panic inside an HTTP handler on a security-refusal path, and the
// attacker-controlled header must be bounded so a single unauthenticated request cannot
// append most of a 1 MiB header to the tamper-evident tape.
func TestAddClaimedSessionID_NilMapAndOversizedHeader(t *testing.T) {
	t.Parallel()
	r := newTestRequestWithSession("abc")
	got := addClaimedSessionID(nil, r)
	if got["claimed_session_id"] != "abc" {
		t.Fatalf("a nil details map must be allocated, not panicked on; got %+v", got)
	}

	huge := make([]byte, 4096)
	for i := range huge {
		huge[i] = 'A'
	}
	r = newTestRequestWithSession(string(huge))
	got = addClaimedSessionID(map[string]interface{}{}, r)
	claimed, _ := got["claimed_session_id"].(string)
	if len(claimed) != maxClaimedSessionIDLen {
		t.Fatalf("claimed session id length = %d, want it bounded to %d", len(claimed), maxClaimedSessionIDLen)
	}
	if got["claimed_session_id_truncated"] != true {
		t.Error("truncation must be marked so the record is not read as a complete value")
	}
}

// newTestRequestWithSession builds a request carrying the given Mcp-Session-Id header.
func newTestRequestWithSession(id string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	r.Header.Set(SessionHeader, id)
	return r
}

// TestHostAllowedForLoopbackEndpoint_HonorsConfiguredOrigins pins that the loopback
// endpoints are no STRICTER than the /mcp Origin gate they claim to mirror.
//
// checkOrigin admits an Origin two ways: an exact listen.allowedOrigins match, or a
// hostname in the constructor-seeded host set. The Host pin consulted only the second, so
// an operator who allowlisted "http://eunox.internal:8080" could reach /mcp from that
// origin but got a 403 on /healthz, /metrics and /control/kill from the same host — the
// more sensitive endpoint was the permissive one.
func TestHostAllowedForLoopbackEndpoint_HonorsConfiguredOrigins(t *testing.T) {
	t.Parallel()
	p := &HTTPProxy{
		allowedOriginHosts: buildAllowedOriginHosts("127.0.0.1"),
		loopbackPinHosts: buildLoopbackPinHosts([]string{
			"http://eunox.internal:8080",
			"https://Scraper.Example",
			"null",               // opaque: contributes no hostname
			"file:///etc/passwd", // non-web scheme: contributes no hostname
		}),
	}
	for _, h := range []string{"eunox.internal", "scraper.example"} {
		if !p.hostAllowedForLoopbackEndpoint(h+":8080", h) {
			t.Errorf("host %q is an allowlisted Origin host and must satisfy the loopback pin", h)
		}
	}
	// The pin must not become a blanket pass: a name the operator never allowlisted is
	// still the DNS-rebinding case.
	if p.hostAllowedForLoopbackEndpoint("attacker.com", "attacker.com") {
		t.Error("a host absent from every allowlist must still be refused")
	}
	// An opaque or non-web allowedOrigins entry contributes no host, so it cannot be
	// smuggled in as a Host value.
	for _, h := range []string{"null", "etc"} {
		if p.hostAllowedForLoopbackEndpoint(h, h) {
			t.Errorf("%q came from a non-web allowedOrigins entry and must not satisfy the pin", h)
		}
	}
}

// TestBuildLoopbackPinHosts_DoesNotWidenTheOriginGate pins the reason this is a separate
// set: allowedOriginHosts is matched on hostname alone with ANY scheme and port, so folding
// these names into it would widen /mcp from "exactly http://eunox.internal:8080" to
// "eunox.internal on any scheme and port".
func TestBuildLoopbackPinHosts_DoesNotWidenTheOriginGate(t *testing.T) {
	t.Parallel()
	p := &HTTPProxy{
		allowedOrigins:     []string{"http://eunox.internal:8080"},
		allowedOriginHosts: buildAllowedOriginHosts("127.0.0.1"),
		loopbackPinHosts:   buildLoopbackPinHosts([]string{"http://eunox.internal:8080"}),
	}
	if !p.originAllowed("http://eunox.internal:8080") {
		t.Fatal("the exact allowlisted origin must still be accepted on /mcp")
	}
	if p.originAllowed("https://eunox.internal:9999") {
		t.Fatal("a different scheme/port on an allowlisted host must NOT be accepted on /mcp; the pin host set must not leak into the Origin gate")
	}
}

// TestPreSessionKillRecords_AreRateLimited is the regression for the one audit write an
// unauthenticated caller could still drive at an arbitrary rate.
//
// Three kill-switch legs fire before any session exists — a session-creating initialize
// under an active global kill, the sessionless initialize notification, and a POST naming
// an unknown or killed session. Each wrote one signed record per request. On an
// open-posture deployment a caller spraying initializes WHILE A KILL IS ACTIVE therefore
// overflowed the audit queue, whose monotonic drop counter latches AuditDegraded() for the
// process lifetime — leaving the default --require-audit=strict denying every route long
// after the kill was revived. Enforcement is never elided: every request below is denied
// whether or not its record was written.
func TestPreSessionKillRecords_AreRateLimited(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	ks := killswitch.NewInMemory()
	if err := ks.ActivateGlobal(context.Background()); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}
	route := &UpstreamRoute{
		name: "up1",
		pdp:  newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sink: &routeSink{sink: sink},
	}
	proxy := newTestHTTPProxy()
	// Drive the buckets from an injected clock: the burst is then the whole budget under
	// test, rather than a number that depends on how long the loop took to run.
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	proxy.preSessionDenies.setNow(func() time.Time { return now })

	post := func(i int) {
		msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Method: "tools/call"}
		req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
		req.Header.Set(SessionHeader, "no-such-session")
		w := httptest.NewRecorder()
		proxy.handleSessionPost(w, req, route, "no-such-session", msg)

		// Every one is DENIED — the bound elides records, never enforcement.
		var resp mcp.RPCMsg
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response %d is not JSON-RPC: %v (body=%s)", i, err, w.Body.String())
		}
		if resp.Error == nil {
			t.Fatalf("request %d must be denied while a global kill is active, got %s", i, w.Body.String())
		}
	}

	const attempts = 200
	for i := 0; i < attempts-1; i++ {
		post(i)
	}
	// One more after a refill second, so a record IS admitted to carry the rollup the
	// suppressed ones folded into.
	now = base.Add(time.Second)
	post(attempts - 1)

	if err := sink.Close(); err != nil {
		t.Fatalf("audit.Close: %v", err)
	}
	records := readAuditRecords(t, dir+"/audit.jsonl")
	denies := 0
	rollup := uint64(0)
	for _, rec := range records {
		if d, _ := rec["decision"].(string); d != "deny" {
			continue
		}
		denies++
		if details, _ := rec["details"].(map[string]interface{}); details != nil {
			if n, ok := details[detailSuppressedRefusalCount].(float64); ok {
				rollup += uint64(n)
				if scope, _ := details[detailSuppressedRefusalScope].(string); scope != suppressedScopeProxyCategory {
					t.Errorf("rollup scope = %q, want %q", scope, suppressedScopeProxyCategory)
				}
			}
		}
	}
	if denies == 0 {
		t.Fatal("the first refusals in a burst must be recorded in full — the bound caps the rate, it does not silence the evidence")
	}
	if denies >= attempts {
		t.Fatalf("%d of %d pre-session kill records were written; an unauthenticated caller must not set the audit write rate", denies, attempts)
	}
	// Nothing vanishes: every suppressed record is folded into a later one's rollup.
	if got := uint64(denies) + rollup; got != attempts {
		t.Errorf("recorded %d + suppressed %d = %d, want %d — a suppressed refusal must be counted, not lost", denies, rollup, got, attempts)
	}
}

// TestPreSessionAudienceDenials_AreRateLimited is D1's regression: a caller who holds one
// valid token for a SIBLING route's audience (accepted by the gateway's shared union JWT
// validator) reaches initAudienceDenial on every session-creating initialize this route
// refuses — no session or upstream ever exists. Before catAudience, that record was written
// through unbounded, the same audit-queue-flooding primitive the pre-session kill records
// are bounded against.
func TestPreSessionAudienceDenials_AreRateLimited(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	denied := &capability.EnforceResponse{
		Denial: &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed},
	}
	route := &UpstreamRoute{
		name: "up1",
		pdp:  denyAudiencePDP{deny: denied},
		sink: &routeSink{sink: sink},
	}
	proxy := newTestHTTPProxy()
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	now := base
	proxy.preSessionDenies.setNow(func() time.Time { return now })

	post := func(i int) {
		body, _ := json.Marshal(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Method: mcp.MethodInitialize})
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		proxy.handleMCPPost(w, req, route)

		var resp mcp.RPCMsg
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response %d is not JSON-RPC: %v (body=%s)", i, err, w.Body.String())
		}
		if resp.Error == nil {
			t.Fatalf("initialize %d must be denied by the audience pin, got %s", i, w.Body.String())
		}
	}

	const attempts = 200
	for i := 0; i < attempts-1; i++ {
		post(i)
	}
	now = base.Add(time.Second)
	post(attempts - 1)

	if err := sink.Close(); err != nil {
		t.Fatalf("audit.Close: %v", err)
	}
	records := readAuditRecords(t, dir+"/audit.jsonl")
	denies := 0
	rollup := uint64(0)
	for _, rec := range records {
		if d, _ := rec["decision"].(string); d != "deny" {
			continue
		}
		denies++
		if details, _ := rec["details"].(map[string]interface{}); details != nil {
			if n, ok := details[detailSuppressedRefusalCount].(float64); ok {
				rollup += uint64(n)
			}
		}
	}
	if denies == 0 {
		t.Fatal("the first refusals in a burst must be recorded in full — the bound caps the rate, it does not silence the evidence")
	}
	if denies >= attempts {
		t.Fatalf("%d of %d pre-session audience records were written; a caller with a valid-elsewhere token must not set the audit write rate", denies, attempts)
	}
	if got := uint64(denies) + rollup; got != attempts {
		t.Errorf("recorded %d + suppressed %d = %d, want %d — a suppressed refusal must be counted, not lost", denies, rollup, got, attempts)
	}
}

// TestRevisionRefusals_RollUpSuppressedCounts pins catRevision to the limiter's fold
// contract the two pre-session siblings already honor: a suppressed revision refusal must
// surface as suppressed_refusal_count on the next admitted -32022 record, not vanish.
// catRevision is the cheapest refusal an unauthenticated caller can force, so a dropped
// tally here is exactly the flood volume an incident responder would under-count.
func TestRevisionRefusals_RollUpSuppressedCounts(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	base := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	now := base
	lim := newPreSessionDenyLimiter()
	lim.setNow(func() time.Time { return now })
	proxy := &HTTPProxy{sink: sink, preSessionDenies: lim}
	route := &UpstreamRoute{name: "github", sink: &routeSink{sink: sink, upstream: "github"}}

	refuse := func() {
		msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "tools/call"}
		resp := refuseHostRevision(context.Background(), proxy.revisionRefusalRecorder(route), "", "", msg,
			errRevisionMismatch)
		// Every one is REFUSED on the wire — the bound elides records, never enforcement.
		if resp.Error == nil {
			t.Fatal("refuseHostRevision must refuse the request whether or not its record was admitted")
		}
	}

	const attempts = 200
	for i := 0; i < attempts-1; i++ {
		refuse()
	}
	// One more after a refill second, so a record IS admitted to carry the rollup the
	// suppressed ones folded into.
	now = base.Add(time.Second)
	refuse()

	if err := sink.Close(); err != nil {
		t.Fatalf("audit.Close: %v", err)
	}
	denies := 0
	rollup := uint64(0)
	for _, rec := range readAuditRecords(t, logPath) {
		if d, _ := rec["decision"].(string); d != "deny" {
			continue
		}
		denies++
		if details, _ := rec["details"].(map[string]interface{}); details != nil {
			if n, ok := details[detailSuppressedRefusalCount].(float64); ok {
				rollup += uint64(n)
				if scope, _ := details[detailSuppressedRefusalScope].(string); scope != suppressedScopeProxyCategory {
					t.Errorf("rollup scope = %q, want %q", scope, suppressedScopeProxyCategory)
				}
			}
		}
	}
	if denies == 0 {
		t.Fatal("the first refusals in a burst must be recorded in full — the bound caps the rate, it does not silence the evidence")
	}
	if denies >= attempts {
		t.Fatalf("%d of %d revision-refusal records were written; an unauthenticated caller must not set the audit write rate", denies, attempts)
	}
	// Nothing vanishes: every suppressed record is folded into a later one's rollup.
	if got := uint64(denies) + rollup; got != attempts {
		t.Errorf("recorded %d + suppressed %d = %d, want %d — a suppressed refusal must be counted, not lost", denies, rollup, got, attempts)
	}
}
