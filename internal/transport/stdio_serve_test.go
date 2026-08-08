// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// TestServeHost_ReturnsOnContextCancel is the regression for the stdio proxy not
// self-terminating on SIGINT/SIGTERM: serveHost blocked on os.Stdin (the host's
// pipe, which ctx cancellation does not close) and never returned, so after a
// signal killed the upstream the proxy lingered until the host happened to close
// stdin. serveHost must now wake on ctx cancellation and return promptly.
func TestServeHost_ReturnsOnContextCancel(t *testing.T) {
	t.Parallel()

	// A pipe whose write end is never written keeps hostReader.Read blocked, exactly
	// as an idle host's open stdin would.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })

	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		hostReader:   mcp.NewMsgReader(pr),
		hostWriter:   mcp.NewMsgWriter(io.Discard),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		upstreamDone: make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.serveHost(ctx); close(done) }()

	cancel()

	select {
	case <-done:
		// Good: serveHost returned on cancellation rather than blocking on stdin.
	case <-time.After(2 * time.Second):
		t.Fatal("serveHost did not return after ctx cancellation (proxy would ignore SIGTERM)")
	}
}

// TestServeHost_ReturnsOnUpstreamExit verifies serveHost also stops serving when
// the upstream exits on its own: every further host request would just fail with
// errUpstreamExited, so the loop returns and lets Start tear down.
func TestServeHost_ReturnsOnUpstreamExit(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	upstreamDone := make(chan struct{})

	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		hostReader:   mcp.NewMsgReader(pr),
		hostWriter:   mcp.NewMsgWriter(io.Discard),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		upstreamDone: upstreamDone,
	}

	done := make(chan struct{})
	go func() { p.serveHost(context.Background()); close(done) }()

	close(upstreamDone)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveHost did not return after the upstream exited")
	}
}

// stdioServe is the varying half of a serveHost fixture: everything else about the proxy is
// fixed by what Start actually produces, and belongs in serveHostLines rather than in a literal
// per test.
type stdioServe struct {
	// pdp decides; nil means AlwaysAllowPDP, which is what a test asserting on framing or
	// negotiation rather than on policy wants.
	pdp pdp.PolicyDecisionPoint
	// sessionID defaults to "sess". Set it when a kill switch names a session.
	sessionID string
	// sink, when set, gives the proxy a real audit tape so a test can read records back.
	sink *audit.Sink
}

// serveHostLines drives a StdioProxy's REAL serve loop over lines — one raw JSON-RPC message
// each, no trailing newline needed — and returns once the loop has finished, so a caller's
// assertions run against a settled proxy.
//
// "Settled" is specifically the EOF path: closing the host's stdin is what makes serveHost wait
// for its in-flight handlers before returning, which is what lets a caller read the host writer
// without synchronizing. A test that ends the loop by cancelling its context instead does NOT
// get that wait and cannot use this.
//
// One scaffold rather than a literal per test because the literal is the part that goes wrong.
// It carries upstreamRev, whose omission puts the proxy in a state Start never produces (no
// upstream leg), silently changing which declarations resolveHostRevision will honor — a test
// that forgets it exercises a proxy production does not build, and the omission is invisible at
// review. A field added to StdioProxy, or a change to serveHost's shutdown contract, is then one
// edit here instead of one per copy.
func serveHostLines(t *testing.T, cfg stdioServe, lines ...string) (*StdioProxy, *mockHostWriter) {
	t.Helper()
	decider := cfg.pdp
	if decider == nil {
		decider = pdp.AlwaysAllowPDP{}
	}
	sessionID := cfg.sessionID
	if sessionID == "" {
		sessionID = "sess"
	}
	hw := &mockHostWriter{}
	pr, pw := io.Pipe()
	p := &StdioProxy{
		pdp:       decider,
		sessionID: sessionID,
		sink:      cfg.sink,
		// The leg Start always leaves a proxy on: eunox opens every upstream with `initialize`,
		// so the handshake revision is what it addresses one as. Set HERE, once, because it
		// changes what resolveHostRevision honors.
		upstreamRev:  handshakeRevision,
		hostReader:   mcp.NewMsgReader(pr),
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		stderr:       io.Discard,
		upstreamDone: make(chan struct{}),
	}

	done := make(chan struct{})
	go func() { p.serveHost(context.Background()); close(done) }()
	// The writes run OFF this goroutine: an io.Pipe write blocks until a reader takes it, and
	// serveHost has exits that do not drain (upstream exit, a non-EOF read error, a shutdown
	// wake). Writing inline would then block forever with no reader and hang the test past the
	// bounded wait below, surfacing as go test's 10-minute panic pointing at this helper rather
	// than as the failure the caller wrote.
	go func() {
		for _, line := range lines {
			if _, err := io.WriteString(pw, strings.TrimRight(line, "\n")+"\n"); err != nil {
				return // the loop stopped reading; the wait below reports what happened
			}
		}
		_ = pw.Close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveHost did not return after the host closed stdin")
	}
	return p, hw
}

// blockingUpWriter is an upstream sink whose Write blocks until gate is closed,
// then records every message in order. It lets a test hold a request's upstream
// write open and observe what reaches the upstream and in what order.
type blockingUpWriter struct {
	gate chan struct{}
	mu   sync.Mutex
	msgs []mcp.RPCMsg
}

func (w *blockingUpWriter) Write(m mcp.RPCMsg) error {
	<-w.gate
	w.mu.Lock()
	w.msgs = append(w.msgs, m)
	w.mu.Unlock()
	return nil
}

func (w *blockingUpWriter) methods() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, len(w.msgs))
	for i, m := range w.msgs {
		out[i] = m.Method
	}
	return out
}

func (w *blockingUpWriter) messages() []mcp.RPCMsg {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]mcp.RPCMsg, len(w.msgs))
	copy(out, w.msgs)
	return out
}

// TestServeHost_NotificationPreservesWireOrder is the regression for a host
// notification overtaking a request it follows: requests are dispatched to async
// goroutines while notifications were written inline, so a notifications/cancelled
// could reach the upstream before the tools/call it cancels (making the cancel a
// no-op). serveHost must forward host→upstream messages in receipt order.
func TestServeHost_NotificationPreservesWireOrder(t *testing.T) {
	t.Parallel()

	up := &blockingUpWriter{gate: make(chan struct{})}
	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		sessionID:    "order-sess",
		byUpstreamID: make(map[string]chan upstreamResult),
		hostWriter:   mcp.NewMsgWriter(io.Discard),
		upWriter:     up,
		upstreamDone: make(chan struct{}),
	}

	// A tools/call immediately followed by a notifications/cancelled targeting it.
	input := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"slow","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}` + "\n"
	p.hostReader = mcp.NewMsgReader(strings.NewReader(input))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { p.serveHost(ctx); close(done) }()

	// While the request's upstream write is held open, neither the request nor the
	// notification may have reached the upstream: the request is blocked on the gate
	// and the notification is blocked on the ordering barrier behind it.
	time.Sleep(50 * time.Millisecond)
	if got := up.methods(); len(got) != 0 {
		t.Fatalf("nothing should reach the upstream while the request write is held; got %v", got)
	}

	// Release the request's upstream write. The barrier then lets the notification
	// through — but only AFTER the request, never before it.
	close(up.gate)

	deadline := time.After(2 * time.Second)
	for {
		if got := up.methods(); len(got) == 2 {
			if got[0] != "tools/call" || got[1] != "notifications/cancelled" {
				t.Fatalf("host wire order not preserved upstream: got %v, want [tools/call notifications/cancelled]", got)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("upstream did not receive both messages; got %v", up.methods())
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}

// TestServeHost_CancelRequestIDRewrittenToNonce is the regression for a
// notifications/cancelled being a permanent no-op through the proxy: every host
// request id is nonce-rewritten on the wire, but the cancel was forwarded
// verbatim, so its params.requestId named an id the upstream never saw and the
// upstream ignored the cancel. The forwarded cancel's requestId must equal the
// nonce the upstream received for the target request.
func TestServeHost_CancelRequestIDRewrittenToNonce(t *testing.T) {
	t.Parallel()

	up := &blockingUpWriter{gate: make(chan struct{})}
	close(up.gate) // do not hold writes: we only inspect what reaches the upstream
	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		sessionID:    "cancel-sess",
		byUpstreamID: make(map[string]chan upstreamResult),
		hostToUp:     make(map[string]*json.RawMessage),
		hostWriter:   mcp.NewMsgWriter(io.Discard),
		upWriter:     up,
		upstreamDone: make(chan struct{}),
	}

	input := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"slow","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}` + "\n"
	p.hostReader = mcp.NewMsgReader(strings.NewReader(input))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { p.serveHost(ctx); close(done) }()

	// Wait until both the request and the cancel have reached the upstream. The
	// request handler stays blocked awaiting a response that never comes, so its
	// hostToUp entry is still live when the cancel is translated.
	deadline := time.After(2 * time.Second)
	for len(up.messages()) != 2 {
		select {
		case <-deadline:
			t.Fatalf("upstream did not receive both messages; got %v", up.methods())
		case <-time.After(5 * time.Millisecond):
		}
	}

	msgs := up.messages()
	if msgs[0].Method != "tools/call" || msgs[1].Method != methodNotificationsCancelled {
		t.Fatalf("unexpected upstream messages: %v", up.methods())
	}
	reqNonce := mcp.MsgKey(msgs[0].ID)
	if reqNonce == "n:7" || reqNonce == "" {
		t.Fatalf("request id was not nonce-rewritten upstream: %s", reqNonce)
	}
	var params struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if err := json.Unmarshal(msgs[1].Params, &params); err != nil {
		t.Fatalf("decode cancel params: %v", err)
	}
	id := params.RequestID
	got := mcp.MsgKey(&id)
	if got == "n:7" {
		t.Fatal("cancel requestId still the host id 7; upstream would ignore the cancel")
	}
	if got != reqNonce {
		t.Fatalf("cancel requestId = %s, want the upstream nonce %s", got, reqNonce)
	}

	cancel()
	<-done
}

// TestRewriteCancelToNonce_DropsWhenNothingInFlight pins that a cancel for an
// unknown/completed request is dropped (the upstream would ignore it anyway) and
// that a non-cancel or malformed-params notification is left untouched.
func TestRewriteCancelToNonce_DropsWhenNothingInFlight(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	nonce := mcp.RawJSON(`"eunox-up-1"`)
	hostToUp := map[string]*json.RawMessage{"n:42": nonce}

	// In flight: rewritten to the nonce.
	cancel := mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsCancelled, Params: json.RawMessage(`{"requestId":42,"reason":"user"}`)}
	got, ok := rewriteCancelToNonce(&mu, hostToUp, cancel)
	if !ok {
		t.Fatal("expected rewrite for an in-flight request")
	}
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
		Reason    string          `json:"reason"`
	}
	if err := json.Unmarshal(got.Params, &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id := p.RequestID
	if mcp.MsgKey(&id) != mcp.MsgKey(nonce) {
		t.Fatalf("requestId not rewritten to nonce: %s", string(p.RequestID))
	}
	if p.Reason != "user" {
		t.Fatalf("reason field dropped: %q", p.Reason)
	}

	// Not in flight: dropped.
	if _, ok := rewriteCancelToNonce(&mu, hostToUp, mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsCancelled, Params: json.RawMessage(`{"requestId":999}`)}); ok {
		t.Fatal("expected drop for an unknown requestId")
	}
	// Non-cancel notification: left untouched.
	if _, ok := rewriteCancelToNonce(&mu, hostToUp, mcp.RPCMsg{JSONRPC: "2.0", Method: "notifications/progress", Params: json.RawMessage(`{"requestId":42}`)}); ok {
		t.Fatal("expected non-cancel notification to be left untouched")
	}
}

// TestServeHost_NotificationBarrierInterruptibleByCancel pins that the host-forward
// ordering barrier never re-introduces serveHost's earlier SIGTERM-deafness: a
// notification waiting for a request whose upstream write is wedged (the gate is
// never opened, mimicking an upstream that stops draining its stdin) must not pin
// the serve loop — ctx cancellation still returns it promptly.
func TestServeHost_NotificationBarrierInterruptibleByCancel(t *testing.T) {
	t.Parallel()

	up := &blockingUpWriter{gate: make(chan struct{})}
	// Open the gate at cleanup so the wedged handler goroutine unblocks and exits
	// rather than leaking past the test.
	t.Cleanup(func() { close(up.gate) })

	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		sessionID:    "barrier-sess",
		byUpstreamID: make(map[string]chan upstreamResult),
		hostWriter:   mcp.NewMsgWriter(io.Discard),
		upWriter:     up,
		upstreamDone: make(chan struct{}),
	}

	input := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"slow","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9}}` + "\n"
	p.hostReader = mcp.NewMsgReader(strings.NewReader(input))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.serveHost(ctx); close(done) }()

	// Let the request wedge on the gate and the notification block on the barrier.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("serveHost returned before cancellation (the request write should be wedged)")
	default:
	}

	cancel()
	select {
	case <-done:
		// Good: cancellation returned serveHost even though the barrier never drained.
	case <-time.After(2 * time.Second):
		t.Fatal("serveHost did not return on cancel while a notification waited on the ordering barrier")
	}
}

// TestServeHost_KilledServerResponseRecordsDeny pins the fix for the silently-dropped
// host reply to a server-initiated request on a killed session: the reply must NOT be
// routed to the upstream (kill semantics), and the drop must be RECORDED so a killed
// session's suppressed server-response is visible on the tape (mirroring the
// host-notification kill record). A response carries no method, so the record uses a
// fixed "server-response" identifier.
func TestServeHost_KilledServerResponseRecordsDeny(t *testing.T) {
	t.Parallel()

	sink, logPath := newTempAuditSink(t)
	ks := killswitch.NewInMemory()
	if err := ks.KillSession(context.Background(), "kill-sess"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	policy := newTestManifestPDPWithKS(ks, capability.Constraint{Target: "tool:*", Actions: []string{"call"}})

	up := &blockingUpWriter{gate: make(chan struct{})}
	close(up.gate) // do not block writes; the test asserts none happen

	p := &StdioProxy{
		pdp:          policy,
		sessionID:    "kill-sess",
		sink:         sink,
		byUpstreamID: make(map[string]chan upstreamResult),
		hostWriter:   mcp.NewMsgWriter(io.Discard),
		upWriter:     up,
		upstreamDone: make(chan struct{}),
	}
	// A host response (id 5) to a server-initiated request the proxy had forwarded.
	p.serverReqs.track(mcp.MsgKey(mcp.RawJSON(`5`)), io.Discard)
	p.hostReader = mcp.NewMsgReader(strings.NewReader(`{"jsonrpc":"2.0","id":5,"result":{}}` + "\n"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { p.serveHost(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveHost did not return after consuming the response input")
	}

	if got := up.messages(); len(got) != 0 {
		t.Errorf("a killed session's host reply must NOT be routed to the upstream; got %v", up.methods())
	}
	if err := sink.Close(); err != nil { // flush the drainer to disk
		t.Fatalf("sink.Close: %v", err)
	}
	recs := readAuditRecords(t, logPath)
	rec := findAuditRecordByMethod(recs, "server-response", "deny")
	if rec == nil {
		t.Fatalf("no deny record for the dropped server-response; records: %+v", recs)
	}
	details, _ := rec["details"].(map[string]interface{})
	if got, _ := details["transport"].(string); got != "stdio-server-response" {
		t.Errorf("deny record transport marker = %q, want stdio-server-response; record: %+v", got, rec)
	}
}

// signalingHostWriter forwards each host-bound message to a channel so a test can
// await a specific reply without racing on a shared slice.
type signalingHostWriter struct {
	ch chan mcp.RPCMsg
}

func (w *signalingHostWriter) Write(m mcp.RPCMsg) error {
	w.ch <- m
	return nil
}

// TestServeHost_ConcurrencyCapRejectsWhenSaturated is the regression for the stdio
// host loop spawning unbounded per-request goroutines: with the in-flight cap
// saturated (here sized to 1, with the sole slot held by a request blocked on a
// silent upstream), a further request must be rejected with a structured,
// retryable error rather than spawning another goroutine.
func TestServeHost_ConcurrencyCapRejectsWhenSaturated(t *testing.T) {
	t.Parallel()

	sink, logPath := newTempAuditSink(t)
	hostCh := make(chan mcp.RPCMsg, 4)
	p := &StdioProxy{
		pdp:          pdp.AlwaysAllowPDP{},
		sessionID:    "cap-sess",
		byUpstreamID: make(map[string]chan upstreamResult),
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{dest: &signalingHostWriter{ch: hostCh}}),
		// The upstream accepts the write but never responds; with upstreamTimeMs=0 the
		// first handler blocks indefinitely, holding its sole concurrency slot.
		upWriter:     mcp.NewMsgWriter(io.Discard),
		upstreamDone: make(chan struct{}),
		hostSem:      make(chan struct{}, 1), // cap of 1 so the second request saturates it
		sink:         sink,                   // wire the tape so the saturation refusal is recorded
	}

	// Three requests against a cap of 1: the first holds the sole slot on a silent
	// upstream, and the next two are both refused without the pool ever draining — one
	// saturation episode, so exactly one record (asserted below).
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"slow","arguments":{}}}` + "\n"
	p.hostReader = mcp.NewMsgReader(strings.NewReader(input))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { p.serveHost(ctx); close(done) }()

	// The first request holds the only slot (blocked on the silent upstream); the
	// second must come straight back as a server-busy error.
	select {
	case m := <-hostCh:
		if m.Error == nil {
			t.Fatalf("expected a server-busy error for the saturating request, got %+v", m)
		}
		if m.Error.Code != jsonRPCCodeServerBusy {
			t.Fatalf("server-busy error code: got %d, want %d", m.Error.Code, jsonRPCCodeServerBusy)
		}
		if id := mcp.MsgKey(m.ID); id != "n:2" {
			t.Fatalf("the rejection must carry the saturating request's id (n:2), got %s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the saturating request was not rejected (the in-flight cap did not engage)")
	}

	// The third request is refused the same way; drain its reply so the assertions below
	// run after both refusals have been recorded (or elided).
	select {
	case m := <-hostCh:
		if m.Error == nil || m.Error.Code != jsonRPCCodeServerBusy {
			t.Fatalf("the second saturating request must also be refused server-busy, got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the second saturating request was not rejected")
	}

	cancel()
	<-done

	// The saturation refusal must also land on the tamper-evident tape as
	// RESOURCE_EXHAUSTED — a silent server-busy would make a stdio DoS probe invisible.
	// The refused method is recorded, but NOT fabricated into a target (the identifier is
	// left empty), so target stays absent rather than a phantom "tools/call".
	//
	// Exactly ONE record for the two refusals: stdio's pool is gated by the same
	// saturationGate its HTTP siblings use, so a host hammering a saturated pool writes one
	// record per saturation EPISODE (with the elided count rolled into the next one) rather
	// than one per refused request, which would otherwise let a host drive the audit sink's
	// bounded queue into its monotonic drop counter.
	_ = sink.Close()
	recs := findAuditRecordsByCode(readAuditRecords(t, logPath), "RESOURCE_EXHAUSTED")
	if len(recs) != 1 {
		t.Fatalf("got %d RESOURCE_EXHAUSTED records for one saturation episode, want 1", len(recs))
	}
	rec := recs[0]
	if method, _ := rec["method"].(string); method != "tools/call" {
		t.Errorf("record method=%q, want tools/call", method)
	}
	if target, ok := rec["target"]; ok && target != "" {
		t.Errorf("RESOURCE_EXHAUSTED must record no target, got %q (phantom target from the method)", target)
	}
	// The gate the serve loop records through is the proxy's own, and it is re-armable:
	// serveHost clears it on every successful hostSem acquire, so a LATER saturation is a
	// new episode and records again. Without that re-arm the transport would report its
	// first saturation ever and then stay silent for the process lifetime.
	p.hostSaturation.clear()
	if ok, suppressed := p.hostSaturation.admit(); !ok || suppressed != 1 {
		t.Fatalf("the proxy's gate must re-arm and carry the elided refusal; ok=%v suppressed=%d, want true/1", ok, suppressed)
	}
}
