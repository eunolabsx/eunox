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

	// No messages: the host's stdin stays open and unwritten, keeping hostReader.Read blocked
	// exactly as an idle host's would.
	run := serveHostRunning(t, stdioServe{})
	run.stop()

	select {
	case <-run.done:
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

	run := serveHostRunning(t, stdioServe{})
	close(run.proxy.upstreamDone)

	select {
	case <-run.done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveHost did not return after the upstream exited")
	}
}

// stdioServe is the varying half of a StdioProxy fixture: everything else about the proxy is
// fixed by what Start actually produces, and belongs in newStdioProxy rather than in a literal
// per test.
//
// Every field's zero value is the shape most tests want, so a test names only what it actually
// varies — which is the point. The fields exist because a literal that omits one of the FIXED
// fields (upstreamRev especially) builds a proxy production never produces, and the omission is
// invisible at review.
type stdioServe struct {
	// pdp decides; nil means AlwaysAllowPDP, which is what a test asserting on framing or
	// negotiation rather than on policy wants.
	pdp pdp.PolicyDecisionPoint
	// sessionID defaults to "sess". Set it when a kill switch names a session.
	sessionID string
	// sink, when set, gives the proxy a real audit tape so a test can read records back.
	sink *audit.Sink
	// hostSink captures proxy->host messages; nil means the *mockHostWriter the fixture returns.
	// Set it for a test that must AWAIT a reply rather than read a settled slice.
	hostSink mcp.MsgSink
	// upSink captures proxy->upstream messages; nil discards them. Set it to assert on what
	// reached the upstream, or to hold an upstream write open.
	upSink mcp.MsgSink
	// hostSem bounds in-flight host handlers; nil lets serveHost size it as production does.
	// Set it (small) to drive the saturation path.
	hostSem chan struct{}
	// decideGate turns on per-anchor decision serialization, as a flow-relevant policy does in
	// production; nil leaves decisions unserialized.
	decideGate *decisionSerializer
	// stderr collects the proxy's diagnostic lines; nil discards them. Set it to assert on a
	// SECURITY/AUDIT line — through the proxy's own writer, never by reassigning os.Stderr,
	// which races every other test in the package.
	stderr io.Writer
	// setup runs after construction and before anything serves, for state a test must plant on
	// the proxy itself (a tracked server-request id, say).
	setup func(*StdioProxy)
}

// newStdioProxy builds the StdioProxy every stdio fixture in this package drives, so the FIXED
// half is written once.
//
// It carries upstreamRev, whose omission puts the proxy in a state Start never produces (no
// upstream leg), silently changing which declarations resolveHostRevision will honor. A field
// added to StdioProxy is one edit here rather than one per copy — which is the payoff the
// scaffold exists for, and which only holds while there is exactly one of it.
func newStdioProxy(cfg stdioServe, hostReader io.Reader) (*StdioProxy, *mockHostWriter) {
	decider := cfg.pdp
	if decider == nil {
		decider = pdp.AlwaysAllowPDP{}
	}
	sessionID := cfg.sessionID
	if sessionID == "" {
		sessionID = "sess"
	}
	hw := &mockHostWriter{}
	hostSink := cfg.hostSink
	if hostSink == nil {
		hostSink = hw
	}
	upSink := cfg.upSink
	if upSink == nil {
		upSink = mcp.NewMsgWriter(io.Discard)
	}
	errOut := cfg.stderr
	if errOut == nil {
		errOut = io.Discard
	}
	p := &StdioProxy{
		pdp:       decider,
		sessionID: sessionID,
		sink:      cfg.sink,
		// The leg Start always leaves a proxy on: eunox opens every upstream with `initialize`,
		// so the handshake revision is what it addresses one as. Set HERE, once, because it
		// changes what resolveHostRevision honors.
		upstreamRev: handshakeRevision,
		hostReader:  mcp.NewMsgReader(hostReader),
		hostWriter:  mcp.NewMsgWriter(&writerAdapter{hostSink}),
		upWriter:    upSink,
		stderr:      errOut,
		hostSem:     cfg.hostSem,
		decideGate:  cfg.decideGate,
		// The two maps Start always allocates: a nil byUpstreamID panics the first forward, and
		// a nil hostToUp drops every notifications/cancelled translation.
		byUpstreamID: make(map[string]chan upstreamResult),
		hostToUp:     make(map[string]*json.RawMessage),
		upstreamDone: make(chan struct{}),
	}
	if cfg.setup != nil {
		cfg.setup(p)
	}
	return p, hw
}

// serveHostLines drives a StdioProxy's REAL serve loop over lines — one raw JSON-RPC message
// each, no trailing newline needed — and returns once the loop has finished, so a caller's
// assertions run against a settled proxy.
//
// "Settled" is specifically the EOF path: closing the host's stdin is what makes serveHost wait
// for its in-flight handlers before returning, which is what lets a caller read the host writer
// without synchronizing. A test that must observe the loop MID-flight ends it by cancelling
// instead and uses serveHostRunning.
//
// Raw lines, so a test can feed bytes no marshaller would produce (a duplicate key, a stray
// member). Everything else takes serveHostMessages and lets this file own the framing.
func serveHostLines(t *testing.T, cfg stdioServe, lines ...string) (*StdioProxy, *mockHostWriter) {
	t.Helper()
	pr, pw := io.Pipe()
	p, hw := newStdioProxy(cfg, pr)

	done := make(chan struct{})
	go func() { p.serveHost(context.Background()); close(done) }()
	go writeHostLines(pw, lines, true)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveHost did not return after the host closed stdin")
	}
	return p, hw
}

// serveHostMessages is serveHostLines over MESSAGES: the fixture already owns the newline
// framing, so marshalling in each caller made the framing contract two homes instead of one.
func serveHostMessages(t *testing.T, cfg stdioServe, msgs ...mcp.RPCMsg) (*StdioProxy, *mockHostWriter) {
	t.Helper()
	return serveHostLines(t, cfg, encodeHostLines(t, msgs)...)
}

// stdioRun is a serve loop still RUNNING: the shape for a test that must observe the proxy
// mid-flight (a wedged upstream write, a saturated handler pool) rather than after it settles.
// The host's stdin stays open, so the loop ends only when the caller stops it.
type stdioRun struct {
	proxy *StdioProxy
	stop  context.CancelFunc
	done  <-chan struct{}
	// No host writer: a mid-flight run's replies must be AWAITED (stdioServe.hostSink), never
	// read off a slice the serve goroutine is still appending to.
}

// finish cancels the serve context and waits for the loop, so a test never leaves a goroutine
// wedged on an upstream write past its own end.
func (r stdioRun) finish(t *testing.T) {
	t.Helper()
	r.stop()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveHost did not return after its context was cancelled")
	}
}

// serveHostRunning starts the real serve loop over msgs and returns while it is still running.
// The pipe is deliberately left OPEN: an EOF would send the loop into its drain-and-return path,
// which is the one thing a mid-flight assertion must not race. Pass no messages for a proxy
// whose host is simply idle.
func serveHostRunning(t *testing.T, cfg stdioServe, msgs ...mcp.RPCMsg) stdioRun {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	p, _ := newStdioProxy(cfg, pr)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() { p.serveHost(ctx); close(done) }()
	go writeHostLines(pw, encodeHostLines(t, msgs), false)
	return stdioRun{proxy: p, stop: cancel, done: done}
}

// encodeHostLines renders messages as the JSON lines the host reader is fed.
func encodeHostLines(t *testing.T, msgs []mcp.RPCMsg) []string {
	t.Helper()
	lines := make([]string, 0, len(msgs))
	for _, msg := range msgs {
		raw, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshalling host message: %v", err)
		}
		lines = append(lines, string(raw))
	}
	return lines
}

// newTestStdioProxy is the same proxy for a test that calls a HANDLER directly
// (handleHostRequest, forwardHostNotification) instead of driving the serve loop: nothing reads
// the host's stdin, and each host-bound reply lands on the returned channel.
//
// It shares newStdioProxy rather than building its own literal — the second parallel fixture is
// how "a field added to StdioProxy is one edit" stopped being true the first time.
func newTestStdioProxy(t *testing.T, cfg stdioServe) (proxy *StdioProxy, replies <-chan mcp.RPCMsg) {
	t.Helper()
	ch := make(chan mcp.RPCMsg, 8)
	cfg.hostSink = &chanHostWriter{ch: ch}
	// An empty reader, never read: this path has no serve loop to feed.
	p, _ := newStdioProxy(cfg, strings.NewReader(""))
	return p, ch
}

// toolCallMsg is a host tools/call for a tool that never answers, the request every ordering
// and saturation fixture below wedges on.
func toolCallMsg(id, tool string) mcp.RPCMsg {
	return mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(id), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"` + tool + `","arguments":{}}`),
	}
}

// cancelNotification is the notifications/cancelled targeting the host request id.
func cancelNotification(requestID string) mcp.RPCMsg {
	return mcp.RPCMsg{
		JSONRPC: "2.0", Method: methodNotificationsCancelled,
		Params: json.RawMessage(`{"requestId":` + requestID + `}`),
	}
}

// writeHostLines feeds the host pipe, and MUST run off the test's own goroutine: an io.Pipe
// write blocks until a reader takes it, and serveHost has exits that do not drain (upstream
// exit, a non-EOF read error, a shutdown wake). Writing inline would then block forever with no
// reader and hang the test past its bounded wait, surfacing as go test's 10-minute panic
// pointing at this helper rather than as the failure the caller wrote.
func writeHostLines(pw *io.PipeWriter, lines []string, closeAfter bool) {
	for _, line := range lines {
		if _, err := io.WriteString(pw, strings.TrimRight(line, "\n")+"\n"); err != nil {
			return // the loop stopped reading; the caller's wait reports what happened
		}
	}
	if closeAfter {
		_ = pw.Close()
	}
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
	// A tools/call immediately followed by a notifications/cancelled targeting it.
	run := serveHostRunning(t, stdioServe{sessionID: "order-sess", upSink: up},
		toolCallMsg(`7`, "slow"), cancelNotification(`7`))
	defer run.finish(t)

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
	run := serveHostRunning(t, stdioServe{sessionID: "cancel-sess", upSink: up},
		toolCallMsg(`7`, "slow"), cancelNotification(`7`))
	defer run.finish(t)

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

	run := serveHostRunning(t, stdioServe{sessionID: "barrier-sess", upSink: up},
		toolCallMsg(`9`, "slow"), cancelNotification(`9`))

	// Let the request wedge on the gate and the notification block on the barrier.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-run.done:
		t.Fatal("serveHost returned before cancellation (the request write should be wedged)")
	default:
	}

	run.stop()
	select {
	case <-run.done:
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

	// A host response (id 5) to a server-initiated request the proxy had forwarded.
	serveHostLines(t, stdioServe{
		pdp: policy, sessionID: "kill-sess", sink: sink, upSink: up,
		setup: func(p *StdioProxy) { p.serverReqs.track(mcp.MsgKey(mcp.RawJSON(`5`)), io.Discard) },
	},
		`{"jsonrpc":"2.0","id":5,"result":{}}`,
	)

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

// chanHostWriter delivers each host-bound message to a buffered channel so a test can AWAIT a
// specific reply rather than read a settled slice. The send is non-blocking on purpose: the
// proxy's write path must never be gated on a test's read, or a fixture becomes the thing that
// wedges the loop it is measuring.
type chanHostWriter struct {
	ch chan mcp.RPCMsg
}

func (w *chanHostWriter) Write(m mcp.RPCMsg) error {
	select {
	case w.ch <- m:
	default:
	}
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
	// Three requests against a cap of 1: the first holds the sole slot on a silent upstream
	// (the default discarding sink accepts the write and never answers, and upstreamTimeMs=0
	// means the handler waits forever), and the next two are both refused without the pool ever
	// draining — one saturation episode, so exactly one record (asserted below).
	run := serveHostRunning(t, stdioServe{
		sessionID: "cap-sess",
		sink:      sink, // wire the tape so the saturation refusal is recorded
		hostSink:  &chanHostWriter{ch: hostCh},
		hostSem:   make(chan struct{}, 1), // cap of 1 so the second request saturates it
	},
		toolCallMsg(`1`, "slow"), toolCallMsg(`2`, "slow"), toolCallMsg(`3`, "slow"))

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

	run.finish(t)

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
	run.proxy.hostSaturation.clear()
	if ok, suppressed := run.proxy.hostSaturation.admit(); !ok || suppressed != 1 {
		t.Fatalf("the proxy's gate must re-arm and carry the elided refusal; ok=%v suppressed=%d, want true/1", ok, suppressed)
	}
}
