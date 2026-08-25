// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecisionSerializer_FIFOOrderUnderConcurrency proves the serialization primitive
// hands out and serves tickets in the order they were RESERVED (proxy-receipt order),
// regardless of the order the handler goroutines happen to reach begin — the property
// that makes the source-before-sink ordering deterministic.
func TestDecisionSerializer_FIFOOrderUnderConcurrency(t *testing.T) {
	t.Parallel()
	const n = 200
	g := newDecisionSerializer()
	// Reserve every ticket up front, in order, as the single-threaded reader would. One
	// anchor, which is what a stdio host resolves for every request on it.
	tickets := make([]decisionTicket, n)
	for i := range tickets {
		tickets[i] = g.take(sessionAnchorKey("sess"))
	}

	var mu sync.Mutex
	var order []int
	var wg sync.WaitGroup
	// Start the goroutines in REVERSE ticket order and stagger them, so a primitive that
	// served in arrival-at-begin order (rather than ticket order) would record a scrambled
	// sequence.
	for i := n - 1; i >= 0; i-- {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			end := g.begin(tickets[idx])
			mu.Lock()
			order = append(order, idx)
			mu.Unlock()
			end()
		}(i)
	}
	wg.Wait()

	if len(order) != n {
		t.Fatalf("recorded %d entries, want %d", len(order), n)
	}
	for i, got := range order {
		if got != i {
			t.Fatalf("decision %d ran out of receipt order: got ticket %d, want %d (full: %v)", i, got, i, order[:min(i+3, n)])
		}
	}
}

// delayedAddStore wraps a FlowLabelStore and sleeps briefly inside Add before
// delegating, widening the source-write window so the source->sink race is DETERMINISTIC
// rather than timing-dependent: it reproduces here, in-process, the real-world variance
// (subprocess + socket latency) that made the demo leak the flow 3-in-20 times. Without
// serialization the sink's Get races ahead of the delayed source Add and the egress is
// wrongly allowed; with per-session serialization the sink waits for the source's turn to
// end (after the delayed Add commits) and the egress is denied every time. Get/Remove/Clear
// pass straight through, so the real backend under test still handles them.
type delayedAddStore struct {
	inner capability.FlowLabelStore
	delay time.Duration
}

func (d *delayedAddStore) Add(ctx context.Context, sessionKey string, labels ...string) error {
	time.Sleep(d.delay)
	return d.inner.Add(ctx, sessionKey, labels...)
}
func (d *delayedAddStore) Get(ctx context.Context, sessionKey string) ([]string, error) {
	return d.inner.Get(ctx, sessionKey)
}
func (d *delayedAddStore) Remove(ctx context.Context, sessionKey string, labels ...string) error {
	return d.inner.Remove(ctx, sessionKey, labels...)
}
func (d *delayedAddStore) Clear(ctx context.Context, sessionKey string) error {
	return d.inner.Clear(ctx, sessionKey)
}

// newSerializedFlowProxy builds a StdioProxy whose policy is a flow source
// (read_secret -> labelOutput confidential) and a flow sink (send_email -> flowLabel
// allowing only public), with per-session decision serialization ON and a mock upstream
// that answers whatever is forwarded to it. Responses to the host are captured in hw.
// closeUp tears the responder down; hostReader supplies the host's stdin.
func newSerializedFlowProxy(t *testing.T, store capability.FlowLabelStore, sessionID string, hostReader io.Reader) (p *StdioProxy, hw *mockHostWriter, closeUp func()) {
	t.Helper()
	caps := []capability.Constraint{
		{Target: "tool:read_secret", Actions: []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}}},
		{Target: "tool:send_email", Actions: []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}}},
	}
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(store))
	dp := pdp.NewManifestPDP(caps, engine, killswitch.NewInMemory())

	upR, upW := io.Pipe()
	// The shared fixture, so this scaffold inherits every field Start actually sets — upstreamRev
	// above all, whose omission puts the proxy in a state production never builds.
	p, hw = newStdioProxy(stdioServe{
		pdp:        dp,
		sessionID:  sessionID,
		decideGate: newDecisionSerializer(), // per-session decision serialization ON
		upSink:     mcp.NewMsgWriter(upW),
	}, hostReader)
	// Mock upstream: read each forwarded request and push a canned result back to the
	// waiting handler (keyed by the nonce the proxy put on the wire).
	go func() {
		reader := mcp.NewMsgReader(upR)
		for {
			req, err := reader.Read()
			if err != nil {
				return
			}
			p.pendingMu.Lock()
			ch, ok := p.byUpstreamID[mcp.MsgKey(req.ID)]
			p.pendingMu.Unlock()
			if ok {
				ch <- upstreamResult{msg: mcp.RPCMsg{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{"ok":true}`)}}
			}
		}
	}()
	return p, hw, func() { _ = upW.Close(); _ = upR.Close() }
}

// TestFlowSerialize_ConcurrentEgressDeniedEveryTime is the ordered source->sink-under-
// concurrency acceptance test: a client that pipelines a tainting source read and
// an egress on ONE session — without waiting for the read's response — must have the
// egress denied EVERY time. The source and egress are dispatched to concurrent handler
// goroutines, so on the unserialized transport the sink could Get the label set before the
// source Adds it and slip the flow (the demo's 17/20). Per-session receipt-order
// serialization closes that: repeated 120x against both store backends, the
// egress denies every run and the source is always allowed and forwarded.
func TestFlowSerialize_ConcurrentEgressDeniedEveryTime(t *testing.T) {
	t.Parallel()
	newRedisStore := func(t *testing.T) capability.FlowLabelStore {
		mr := miniredis.RunT(t)
		client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		return flowlabelstore.NewRedis(client)
	}
	backends := []struct {
		name  string
		store func(*testing.T) capability.FlowLabelStore
	}{
		{"memory", func(*testing.T) capability.FlowLabelStore { return flowlabelstore.NewInMemory() }},
		{"redis", newRedisStore},
	}
	// The tainting read and the egress on one session, pipelined with no wait between them.
	const input = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_secret","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_email","arguments":{}}}` + "\n"

	for _, be := range backends {
		be := be
		t.Run(be.name, func(t *testing.T) {
			const runs = 40
			// One shared store across runs (each run uses a fresh session id, so the taint
			// is per-run), mirroring a long-lived proxy process serving many sessions. The
			// Add delay makes the source-before-sink ordering the SOLE determinant of the
			// outcome: it converts the timing-dependent leak (flaky, ~3-in-20 on the real
			// stack — the demo's number) into a deterministic one, so a regression that drops
			// the serialization leaks on EVERY run here rather than intermittently. (Verified:
			// with serialization removed, every run's egress is wrongly allowed.)
			store := &delayedAddStore{inner: be.store(t), delay: 20 * time.Millisecond}
			for i := 0; i < runs; i++ {
				p, hw, closeUp := newSerializedFlowProxy(t, store, fmt.Sprintf("sess-%d", i), strings.NewReader(input))

				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { p.serveHost(ctx); close(done) }()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					cancel()
					closeUp()
					t.Fatalf("run %d: serveHost hung (a serialized decision deadlocked?)", i)
				}
				cancel()
				closeUp()

				src := findByID(hw.messages, "2")
				egress := findByID(hw.messages, "3")
				if src == nil || egress == nil {
					t.Fatalf("run %d: missing a response (source=%v egress=%v); all=%+v", i, src, egress, hw.messages)
				}
				if src.Error != nil || src.Result == nil {
					t.Fatalf("run %d: the source read must be allowed and forwarded, got error=%+v", i, src.Error)
				}
				// The egress must be denied specifically by the flow-label sink — decode the
				// structured denial so a stray error (server-busy, upstream fault) cannot pass
				// this assertion as a false "denied".
				if egress.Error == nil {
					t.Fatalf("run %d: the egress must be DENIED (flowLabel) but was allowed — the source->sink race was not closed", i)
				}
				if ct := denialConditionType(egress); ct != capability.ConditionTypeFlowLabel {
					t.Fatalf("run %d: the egress deny must be a flowLabel deny, got conditionType %q (err %+v)", i, ct, egress.Error)
				}
			}
		})
	}
}

// TestFlowSerialize_SamplingSinkSerializedAgainstSource is the per-session-decision-
// serialization acceptance test for the sampling leg: a flowLabel sink on
// system:sampling/createMessage reads the same per-session flow state a host source read
// writes, but the sampling decision runs on the upstream-reader goroutine, OUTSIDE the host
// decideGate. serverRequestParams.decideSampling threads the per-session decision lock so the
// sampling peek is serialized with host-path source Adds — otherwise it could peek the flow
// set mid-commit of a host source's Add and slip the taint. A host source read that taints
// the session under the SAME gate (its ticket reserved first, as the single-threaded host
// reader would) commits before the sampling decision runs, so the sink denies every time.
// The Add delay makes ordering the SOLE determinant: without the lock the sampling peek races
// ahead of the delayed Add and is wrongly allowed (verified by removing decideLock).
func TestFlowSerialize_SamplingSinkSerializedAgainstSource(t *testing.T) {
	t.Parallel()
	const runs = 40
	// One shared store across runs (each run a fresh session id), mirroring a long-lived
	// proxy. The delayed Add widens the source-write window so a dropped lock leaks on EVERY
	// run rather than intermittently.
	store := &delayedAddStore{inner: flowlabelstore.NewInMemory(), delay: 20 * time.Millisecond}
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(store))
	caps := []capability.Constraint{
		{Target: "tool:read_secret", Actions: []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}}},
		{Target: "system:sampling/createMessage", Actions: []string{"allow"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}}},
	}
	dp := pdp.NewManifestPDP(caps, engine, killswitch.NewInMemory())

	for i := 0; i < runs; i++ {
		sessionID := fmt.Sprintf("sess-%d", i)
		gate := newDecisionSerializer()
		// The host reader reserves the source's decision ticket FIRST (receipt order), before
		// the sampling decision is dispatched to the upstream-reader goroutine.
		srcTicket := gate.take(sessionAnchorKey(sessionID))

		fp := serverRequestParams{
			sessionID: sessionID,
			// The sampling decision reserves its own (later) ticket and blocks until its turn —
			// the exact wiring stdio's samplingDecideLock installs.
			decideLock: func() (func(), bool) { return gate.begin(gate.take(sessionAnchorKey(sessionID))), true },
			pdp:        dp,
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			end := gate.begin(srcTicket)
			defer end()
			// The host source read taints the session (delayed Add) inside its serialized turn.
			src := dp.Decide(context.Background(), sessionID,
				pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_secret"}, map[string]interface{}{}, "")
			if src.Decision != capability.DecisionAllow {
				t.Errorf("run %d: the source read must be allowed, got %+v", i, src.Denial)
			}
		}()

		// The sampling sink decision serializes behind the source's turn and observes the taint.
		dec := fp.decideSampling(context.Background())
		wg.Wait()

		if dec.Decision != capability.DecisionDeny {
			t.Fatalf("run %d: the sampling sink must be DENIED — the source->sampling race was not closed", i)
		}
		if dec.Denial == nil || dec.Denial.ConditionType != capability.ConditionTypeFlowLabel {
			t.Fatalf("run %d: the sampling deny must be a flowLabel deny, got %+v", i, dec.Denial)
		}
	}
}

// denialConditionType decodes the structured conditionType from a denial response's
// error.data (the denialErrorData the transport stamps), so a test can assert WHICH
// control denied — "" for a non-denial or an undecodable payload.
func denialConditionType(msg *mcp.RPCMsg) string {
	if msg == nil || msg.Error == nil || msg.Error.Data == nil {
		return ""
	}
	var d struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(msg.Error.Data, &d)
	return d.Type
}

// findByID returns the first captured message whose JSON-RPC id matches, or nil. The
// host response carries the ORIGINAL host id (enforcedForwardCore/denialResult stamp
// msg.ID), which MsgKey canonicalizes to "n:<id>" for a numeric id.
func findByID(msgs []mcp.RPCMsg, id string) *mcp.RPCMsg {
	for i := range msgs {
		if mcp.MsgKey(msgs[i].ID) == "n:"+id {
			return &msgs[i]
		}
	}
	return nil
}

// TestAwaitHostDecisionsDrained_BlocksUntilInFlightZero pins the stdio teardown drain that
// gates ReleaseSession: on the signal/upstream-exit
// paths serveHost returns WITHOUT waiting for its handler goroutines, so Start must not clear
// per-session flow state while a sink handler is still mid-decision. The drain blocks on
// fwdHostInFlight and returns once it reaches zero.
func TestAwaitHostDecisionsDrained_BlocksUntilInFlightZero(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{decideGate: newDecisionSerializer()}
	p.fwdHostInFlight.Store(1) // a handler dispatched but still mid-decision

	done := make(chan struct{})
	go func() { p.awaitHostDecisionsDrained(2 * time.Second); close(done) }()

	// It must NOT return while a decision is in flight.
	select {
	case <-done:
		t.Fatal("drain returned while a host decision was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	// Once the handler settles, the drain returns promptly.
	p.fwdHostInFlight.Store(0)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not return after in-flight reached zero")
	}
}

// TestAwaitHostDecisionsDrained_BoundedByTimeout: a wedged handler (fwdHostInFlight never
// falls) must not hang teardown — the drain returns after its bounded timeout.
func TestAwaitHostDecisionsDrained_BoundedByTimeout(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{decideGate: newDecisionSerializer()}
	p.fwdHostInFlight.Store(1) // never drains

	start := time.Now()
	p.awaitHostDecisionsDrained(80 * time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 60*time.Millisecond {
		t.Fatalf("drain returned too early (%v); a wedged handler must be waited out to ~the timeout", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("drain blocked far past its timeout (%v)", elapsed)
	}
}

// TestAwaitHostDecisionsDrained_NoopWhenNoDecideGate: a non-flow session (decideGate nil)
// has no flow state to protect and ReleaseSession is itself a no-op, so the drain must
// short-circuit rather than add teardown latency waiting on unrelated in-flight handlers.
func TestAwaitHostDecisionsDrained_NoopWhenNoDecideGate(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{decideGate: nil}
	p.fwdHostInFlight.Store(5) // would block to the timeout if not short-circuited

	done := make(chan struct{})
	go func() { p.awaitHostDecisionsDrained(10 * time.Second); close(done) }()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("drain must be a no-op for a non-flow session (decideGate nil)")
	}
}

// TestDecisionSerializer_KeysOnTheAnchor is the stdio half of the property the HTTP gate
// registry provides: the FIFO turn is per ANCHOR, not per proxy. Two anchors accumulate no
// shared state, so their decisions must not queue behind each other; two requests on one
// anchor must.
//
// It is currently exercised only by this test, because nothing on the stdio path attaches
// validated claims and every request there resolves to the proxy's single session. That is why
// the keying is here rather than assumed: StdioProxyOptions.PDP is an exported seam, and the
// first per-request token channel on this transport would otherwise have left one FIFO queue
// silently serving two anchors' worth of state.
func TestDecisionSerializer_KeysOnTheAnchor(t *testing.T) {
	t.Parallel()
	g := newDecisionSerializer()
	a, b := sessionAnchorKey("sess-a"), taskAnchorKey("task-42")

	held := g.begin(g.take(a))
	// A ticket on a DIFFERENT anchor runs immediately.
	other := make(chan struct{})
	go func() { defer close(other); g.begin(g.take(b))() }()
	select {
	case <-other:
	case <-time.After(time.Second):
		t.Fatal("a different anchor must not queue behind this one")
	}

	// A second ticket on the SAME anchor waits.
	queued := make(chan struct{})
	ticket := g.take(a)
	go func() { defer close(queued); g.begin(ticket)() }()
	select {
	case <-queued:
		t.Fatal("a second request on one anchor must wait its turn")
	case <-time.After(20 * time.Millisecond):
	}
	held()
	select {
	case <-queued:
	case <-time.After(time.Second):
		t.Fatal("the turn must advance once released")
	}
	assert.Zero(t, g.size(), "a queue whose tickets have all been served must not be retained")
}

// TestDecisionSerializer_ZeroTicketIsANoOp: a request that was never serialized carries the
// zero ticket, and the call site must not have to branch on it.
func TestDecisionSerializer_ZeroTicketIsANoOp(t *testing.T) {
	t.Parallel()
	g := newDecisionSerializer()
	require.NotPanics(t, func() { g.begin(decisionTicket{})() })
	end, ok := g.beginWithin(decisionTicket{}, turnWait{perHolder: time.Millisecond, total: time.Millisecond})
	assert.True(t, ok, "an unserialized request is never refused its (absent) turn")
	require.NotPanics(t, end)
}

// TestDecisionSerializer_AbandonedTicketDoesNotStrandTheQueue is the property that makes
// bounding the server-initiated leg's wait SAFE, and it is the objection that kept that leg
// unbounded: this is a FIFO, so a ticket taken and then abandoned is a hole in the sequence,
// and every later ticket on the anchor waits behind a turn that will never come — trading a
// bounded stall for an unbounded one. Recording the give-up lets the turn skip it.
func TestDecisionSerializer_AbandonedTicketDoesNotStrandTheQueue(t *testing.T) {
	t.Parallel()
	g := newDecisionSerializer()
	anchor := sessionAnchorKey("sess-a")

	// Ticket 0 runs; tickets 1 and 2 are reserved behind it.
	first := g.begin(g.take(anchor))
	abandoned := g.take(anchor)
	later := g.take(anchor)

	// The middle ticket gives up while the first still holds the turn.
	end, ok := g.beginWithin(abandoned, turnWait{perHolder: 20 * time.Millisecond, total: 20 * time.Millisecond})
	assert.False(t, ok, "a turn that does not come up within the bound must be reported, not waited for")
	assert.Nil(t, end, "and no turn was taken, so there is nothing to release")

	// The ticket BEHIND the abandoned one must still be served.
	served := make(chan struct{})
	go func() { defer close(served); g.begin(later)() }()
	select {
	case <-served:
		t.Fatal("the last ticket must still wait for the first holder")
	case <-time.After(20 * time.Millisecond):
	}
	first()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("an abandoned ticket stranded every later ticket on the anchor")
	}
	assert.Zero(t, g.size(), "and the queue is reclaimed once the skipped ticket has been passed")
}

// TestDecisionSerializer_ConsecutiveAbandonmentsAreSkipped: a wedged reader can give up more
// than once, so the skip is a loop. One un-skipped hole stalls the anchor for the proxy's life,
// which is why this is asserted rather than left to the shape of the code.
func TestDecisionSerializer_ConsecutiveAbandonmentsAreSkipped(t *testing.T) {
	t.Parallel()
	g := newDecisionSerializer()
	anchor := sessionAnchorKey("sess-a")

	first := g.begin(g.take(anchor))
	for range 3 {
		_, ok := g.beginWithin(g.take(anchor), turnWait{perHolder: 10 * time.Millisecond, total: 10 * time.Millisecond})
		require.False(t, ok)
	}
	last := g.take(anchor)

	served := make(chan struct{})
	go func() { defer close(served); g.begin(last)() }()
	first()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("three consecutive abandonments must all be skipped, not just the first")
	}
	assert.Zero(t, g.size())
}

// TestDecisionSerializer_BeginWithinTakesATurnThatIsAvailable is the other half of the bound: a
// free anchor is entered immediately and the turn really is held afterwards. A bound that
// refused a turn it could have had would fail every sampling request on a busy-but-not-wedged
// proxy closed.
func TestDecisionSerializer_BeginWithinTakesATurnThatIsAvailable(t *testing.T) {
	t.Parallel()
	g := newDecisionSerializer()
	anchor := sessionAnchorKey("sess-a")

	end, ok := g.beginWithin(g.take(anchor), turnWait{perHolder: time.Second, total: time.Second})
	require.True(t, ok)
	require.NotNil(t, end)

	queued := make(chan struct{})
	ticket := g.take(anchor)
	go func() { defer close(queued); g.begin(ticket)() }()
	select {
	case <-queued:
		t.Fatal("a turn entered through the bounded path must exclude just as the unbounded one does")
	case <-time.After(20 * time.Millisecond):
	}
	end()
	select {
	case <-queued:
	case <-time.After(time.Second):
		t.Fatal("the turn must advance once released")
	}
	assert.Zero(t, g.size())
}

// TestStdioSamplingTurn_BoundedRatherThanWedgingTheReader is the acceptance test for the
// deadlock the bound closes.
//
// On stdio the server-initiated leg runs INLINE on the upstream reader goroutine, and that
// goroutine is the only one that delivers upstream responses to waiting host handlers. A
// declassifying host call holds its turn across its whole upstream round trip. So a sampling
// request arriving mid-clear waits for a turn whose holder is waiting for a response only the
// now-blocked reader can deliver: with an unbounded wait that unwinds when --upstream-timeout
// fires, and never at all when it is 0.
//
// Two things are asserted: the leg gives up rather than waiting forever, and the give-up leaves
// the FIFO usable — which is the objection that kept it unbounded.
func TestStdioSamplingTurn_BoundedRatherThanWedgingTheReader(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{sessionID: "sess-a", decideGate: newDecisionSerializer()}
	p.pinDecisionQueue()
	t.Cleanup(p.dropDecideQueue)

	// The host's declassifying call takes the turn and keeps it across its forward.
	host := p.decideGate.begin(p.decideGate.takeOn(p.decideQueue))

	start := time.Now()
	end, ok := p.samplingDecideLock()()
	waited := time.Since(start)
	assert.False(t, ok, "the sampling leg must give up rather than park the session's reader goroutine")
	assert.Nil(t, end, "no turn was taken, so there is nothing to release")
	assert.GreaterOrEqual(t, waited, samplingTurnWait.perHolder/2,
		"it must WAIT for the turn — an instant refusal would fail every sampling request under ordinary contention")
	assert.Less(t, waited, 4*samplingTurnWait.total, "and give up on roughly its own bound")

	// The host's next request is still served: the abandoned ticket did not strand the queue.
	next := p.decideGate.takeOn(p.decideQueue)
	served := make(chan struct{})
	go func() { defer close(served); p.decideGate.begin(next)() }()
	host()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("the abandoned sampling ticket stalled the host leg — a bounded stall traded for an unbounded one")
	}
}

// TestStdioUpstreamRequest_ReturnsWhileTheTurnIsHeld drives the REAL entry point the deadlock
// went through — the one the upstream reader calls inline — rather than the lock in isolation.
// That is the seam a refactor could drop the bound at while every primitive test still passed:
// samplingDecideLock is installed here and nowhere else.
//
// The policy grants no sampling at all, which is the issue's point restated as a test: the turn
// is taken BEFORE the sampling decision runs, so an upstream that policy denies sampling to
// could wedge the reader just as well as one it permits.
func TestStdioUpstreamRequest_ReturnsWhileTheTurnIsHeld(t *testing.T) {
	t.Parallel()
	uw := &mockUpstreamWriter{}
	p := &StdioProxy{
		pdp:        newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sessionID:  "sess-a",
		decideGate: newDecisionSerializer(),
		upWriter:   mcp.NewMsgWriter(&writerAdapter{uw}),
		hostWriter: mcp.NewMsgWriter(&writerAdapter{&mockHostWriter{}}),
	}
	p.pinDecisionQueue()
	t.Cleanup(p.dropDecideQueue)

	// A declassifying host call holds the turn across its upstream round trip — the response to
	// which only the goroutine below can deliver.
	held := p.decideGate.begin(p.decideGate.takeOn(p.decideQueue))
	t.Cleanup(held)

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.handleUpstreamRequest(context.Background(), mcp.RPCMsg{
			JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: capability.MethodSamplingCreateMessage,
		})
	}()
	select {
	case <-done:
	case <-time.After(4 * samplingTurnWait.total):
		t.Fatal("the upstream reader is wedged on a turn whose holder is waiting for a response only it can deliver")
	}

	// The upstream is ANSWERED rather than left hanging: a refusal it never receives leaves it
	// waiting on a reply forever, which is the deadlock relocated rather than closed.
	require.Len(t, uw.messages, 1, "the refused sampling request must be answered")
	assert.NotNil(t, uw.messages[0].Error)
}

// TestDecideSampling_RefusedTurnIsABlockOverride pins what a refused turn produces. The refusal has
// to be a DENY rather than an unserialized decision (the peek would be racing a host source's
// label write, the exact fail-open the turn exists to close), and it has to be HARD so an
// --audit route cannot downgrade it into the forward it exists to prevent.
func TestDecideSampling_RefusedTurnIsABlockOverride(t *testing.T) {
	t.Parallel()
	fp := serverRequestParams{
		sessionID:  "sess-a",
		decideLock: func() (func(), bool) { return nil, false },
		pdp:        pdp.AlwaysAllowPDP{},
	}

	dec := fp.decideSampling(context.Background())
	require.Equal(t, capability.DecisionDeny, dec.Decision, "an unenterable turn must not be decided unserialized")
	require.NotNil(t, dec.Denial)
	assert.Equal(t, capability.ConditionTypeFlowLabel, dec.Denial.ConditionType)
	assert.True(t, dec.Denial.BlockOverride, "an --audit route must not downgrade it into the forward it prevents")
	assert.Equal(t, "turn_unavailable", dec.Denial.Details["reason"])
}

// TestStdioDecisionAnchor_ResolvesThroughTheSharedResolver pins that the stdio proxy asks the
// same question the engine's key builder asks, from the connection identity it captured — the
// one source both of this transport's legs read, so the host leg and the server-initiated leg
// cannot land on different turns.
func TestStdioDecisionAnchor_ResolvesThroughTheSharedResolver(t *testing.T) {
	t.Parallel()
	claims := &pdp.JWTClaims{TaskID: "task-42"}

	plain := &StdioProxy{sessionID: "sess-a"}
	assert.Equal(t, sessionAnchorKey("sess-a"), plain.decisionAnchorKey())
	plain.claims = claims
	assert.Equal(t, sessionAnchorKey("sess-a"), plain.decisionAnchorKey(),
		"an operator who did not enable task anchoring sees the session turn, claims or no claims")

	anchored := &StdioProxy{sessionID: "sess-a", taskAnchored: true}
	assert.Equal(t, sessionAnchorKey("sess-a"), anchored.decisionAnchorKey(),
		"a connection with no token anchors on the session, exactly as the engine keys it")
	anchored.claims = claims
	assert.Equal(t, taskAnchorKey("task-42"), anchored.decisionAnchorKey(),
		"and a validated task claim keys the turn where the state lives")
}

// TestStdioPinnedQueue_IsSharedByBothLegsAndReclaimed covers what the pin buys and what it
// must not cost. Both legs take their tickets from the ONE queue the proxy pinned — a
// sampling sink that queued somewhere else would not be serialized against a host source's
// label write, which is the whole reason the server-initiated leg takes a turn at all — and
// the pin is released at teardown so a queue is not retained past the proxy that held it.
func TestStdioPinnedQueue_IsSharedByBothLegsAndReclaimed(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{sessionID: "sess-a", decideGate: newDecisionSerializer()}
	p.pinDecisionQueue()
	require.NotNil(t, p.decideQueue)
	require.Equal(t, 1, p.decideGate.size())

	// The host leg holds its turn; the sampling leg must wait for it rather than run beside it.
	host := p.decideGate.begin(p.decideGate.takeOn(p.decideQueue))
	sampling := p.samplingDecideLock()
	require.NotNil(t, sampling)
	entered := make(chan struct{})
	go func() {
		end, ok := sampling()
		if ok {
			end()
		}
		close(entered)
	}()
	select {
	case <-entered:
		t.Fatal("the server-initiated leg must queue behind the host leg's turn: they share one anchor")
	case <-time.After(20 * time.Millisecond):
	}
	host()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the sampling leg must run once the host turn is released")
	}

	// Still exactly one queue after all that traffic: the pin is what keeps the read loop off
	// the registry, and it is released when the proxy is done with it.
	assert.Equal(t, 1, p.decideGate.size())
	p.dropDecideQueue()
	assert.Zero(t, p.decideGate.size(), "a pinned queue must not outlive the proxy that pinned it")
}

// TestStdioDecisionTicket_UnpinnedProxyStillSerializes is the fail-open guard on the pin. The
// pinned queue is an optimization resolved in Start; a proxy driven without it (a direct
// serveHost caller, which is how much of this package's own coverage runs) must still take a
// real turn. A nil pin that quietly produced the zero ticket would leave every decision on
// such a proxy unserialized while every test kept passing — the source->sink race reopened by
// the very change that was meant to make the keying structural.
func TestStdioDecisionTicket_UnpinnedProxyStillSerializes(t *testing.T) {
	t.Parallel()
	p := &StdioProxy{sessionID: "sess-a", decideGate: newDecisionSerializer()}
	require.Nil(t, p.decideQueue, "this proxy never ran Start, so it holds no pin")

	first := p.decideGate.begin(p.takeDecisionTicket())
	second := p.takeDecisionTicket()
	entered := make(chan struct{})
	go func() { defer close(entered); p.decideGate.begin(second)() }()
	select {
	case <-entered:
		t.Fatal("an unpinned proxy must still serialize its decisions, not run them concurrently")
	case <-time.After(20 * time.Millisecond):
	}
	first()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the turn must advance once released")
	}

	// And the fallback resolves the same anchor the pin would have, so a proxy that pins
	// later does not move to a different queue.
	p.pinDecisionQueue()
	assert.Equal(t, 1, p.decideGate.size(), "the fallback and the pin address one queue, not two")
	p.dropDecideQueue()
}

// TestStdioUpstreamRequest_DoesNotStallResponseDelivery is the acceptance test for moving the
// server-initiated leg off the read loop, and it drives the whole reader rather than the lock.
//
// Bounding the sampling leg's wait turned a deadlock into a stall, and nothing bounded how
// OFTEN that stall could be provoked: the reader is the only goroutine that delivers upstream
// responses to waiting host handlers, so an upstream emitting one sampling/createMessage per
// in-flight declassifying call cost the whole session its response delivery for the length of
// the bound, every time. The handler runs on its own goroutine now, so a blocked one blocks
// only itself.
//
// The property is timed rather than merely reached: with the handler inline, the response
// below is not even READ off the pipe until the sampling wait expires, so the assertion is
// that delivery happens in a fraction of that bound.
func TestStdioUpstreamRequest_DoesNotStallResponseDelivery(t *testing.T) {
	t.Parallel()
	pr, pw := io.Pipe()
	p := &StdioProxy{
		// The policy grants no sampling: the turn is taken BEFORE the decision that would
		// refuse it, so an upstream policy denies sampling to can stall the reader just as
		// well as one it permits.
		pdp:          newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sessionID:    "sess-a",
		decideGate:   newDecisionSerializer(),
		upReader:     mcp.NewMsgReader(pr),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		hostWriter:   mcp.NewMsgWriter(io.Discard),
		byUpstreamID: map[string]chan upstreamResult{},
	}
	p.pinDecisionQueue()
	t.Cleanup(p.dropDecideQueue)

	// A declassifying host call holds the turn across its upstream round trip, waiting for the
	// very response this reader has to deliver.
	held := p.decideGate.begin(p.decideGate.takeOn(p.decideQueue))

	// That call's in-flight registration, exactly as callUpstream makes it.
	nonce := mcp.RawJSON(`"eunox-up-1"`)
	reply := make(chan upstreamResult, 1)
	p.byUpstreamID[mcp.MsgKey(nonce)] = reply

	readerDone := make(chan struct{})
	go func() { defer close(readerDone); p.readUpstream(context.Background()) }()

	start := time.Now()
	w := mcp.NewMsgWriter(pw)
	require.NoError(t, w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: capability.MethodSamplingCreateMessage}))
	require.NoError(t, w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: nonce, Result: json.RawMessage(`{"ok":true}`)}))

	select {
	case <-reply:
	case <-time.After(4 * samplingTurnWait.total):
		t.Fatal("the response never arrived: the reader is wedged behind the sampling handler")
	}
	assert.Less(t, time.Since(start), samplingTurnWait.perHolder/2,
		"the reader must keep delivering responses while a sampling handler waits for the turn, "+
			"not stall for the length of that wait")

	// Release the turn so the parked handler completes promptly, then tear down and drain it —
	// the reader exiting does not imply its handlers have.
	held()
	require.NoError(t, pw.Close())
	<-readerDone
	p.awaitServerRequestsDrained(4 * samplingTurnWait.total)
	assert.Zero(t, p.serverPool.inFlight.Load(), "every dispatched handler must be accounted for at teardown")
}

// TestHTTPUpstreamRequest_DoesNotStallTheSessionReader is the same acceptance test for the HTTP
// half, which kept the inline dispatch after the stdio leg moved off its reader.
//
// Same cycle, scoped to a session: httpSession.readUpstream is the only goroutine that delivers
// upstream responses to that session's waiting host handlers and relays notifications to its SSE
// subscribers, and the sampling leg takes the decision turn — bounded at samplingTurnWait —
// BEFORE the decision that would refuse it. A declassifying host call holds that turn across its
// whole upstream round trip, waiting for a response only this reader delivers, so an upstream
// emitting one sampling/createMessage per in-flight clear cost the session its response delivery
// for the length of the bound, every time.
//
// Timed rather than merely reached, exactly as the stdio case: with the handler inline the
// response below is not even READ off the pipe until the sampling wait expires.
func TestHTTPUpstreamRequest_DoesNotStallTheSessionReader(t *testing.T) {
	t.Parallel()
	pr, pw := io.Pipe()
	// The policy grants no sampling: the turn is taken BEFORE the decision that would refuse
	// it, so an upstream policy denies sampling to can stall the reader just as well as one it
	// permits.
	rt := &UpstreamRoute{
		name:        "up1",
		pdp:         newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		decideGates: newAnchorGates(),
	}
	sess := newTestSession(&httpSession{
		id:           "sess-a",
		route:        rt,
		proxy:        &HTTPProxy{},
		upReader:     mcp.NewMsgReader(pr),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		done:         make(chan struct{}),
		byUpstreamID: map[string]chan upstreamResult{},
	})
	sess.holdDecisionGate()
	t.Cleanup(sess.dropDecideGate)

	// A declassifying host call on this session holds the turn across its upstream round trip,
	// waiting for the very response this reader has to deliver.
	held, ok := sess.beginDecisionTurnWithin(turnWait{perHolder: 4 * samplingTurnWait.total, total: 4 * samplingTurnWait.total})
	require.True(t, ok, "the turn must be available before the test holds it")

	// That call's in-flight registration, exactly as callSubprocessUpstream makes it.
	nonce := mcp.RawJSON(`"eunox-up-1"`)
	reply := make(chan upstreamResult, 1)
	sess.byUpstreamID[mcp.MsgKey(nonce)] = reply

	go sess.readUpstream(context.Background())

	start := time.Now()
	w := mcp.NewMsgWriter(pw)
	require.NoError(t, w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: capability.MethodSamplingCreateMessage}))
	require.NoError(t, w.Write(mcp.RPCMsg{JSONRPC: "2.0", ID: nonce, Result: json.RawMessage(`{"ok":true}`)}))

	select {
	case <-reply:
	case <-time.After(4 * samplingTurnWait.total):
		t.Fatal("the response never arrived: the session reader is wedged behind the sampling handler")
	}
	assert.Less(t, time.Since(start), samplingTurnWait.perHolder/2,
		"the session reader must keep delivering responses while a sampling handler waits for the "+
			"turn, not stall for the length of that wait")

	// Release the turn so the parked handler completes promptly, then tear down and drain it —
	// the reader exiting does not imply its handlers have.
	held()
	require.NoError(t, pw.Close())
	<-sess.done
	sess.serverPool.drain(4 * samplingTurnWait.total)
	assert.Zero(t, sess.serverPool.inFlight.Load(), "every dispatched handler must be accounted for at teardown")
}

// TestHTTPUpstreamRequest_SaturationIsRefusedAndRecorded is the HTTP half of the bound that had
// to come with the goroutine. The pool is PER SESSION, so the refusal and its record belong to
// the session whose upstream flooded — one session cannot consume another's slots, nor elide
// another's saturation record.
func TestHTTPUpstreamRequest_SaturationIsRefusedAndRecorded(t *testing.T) {
	t.Parallel()
	uw := &mockUpstreamWriter{}
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	require.NoError(t, err)
	sess := newTestSession(&httpSession{
		id: "sess-a",
		// The real route sink, not a stand-in: the record has to survive the wrapper the
		// gateway actually stamps it through, reached via asRecorder as the dispatch does.
		route:    &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{sink: sink, upstream: "up1"}},
		proxy:    &HTTPProxy{},
		upWriter: mcp.NewMsgWriter(&writerAdapter{uw}),
	})

	release := make(chan struct{})
	blocked := make(chan struct{}, maxConcurrentServerRequests)
	for range maxConcurrentServerRequests {
		sess.serverPool.dispatch(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`)},
			serverRequestDispatch{
				handle: func(context.Context, mcp.RPCMsg) { blocked <- struct{}{}; <-release },
			})
	}
	for range maxConcurrentServerRequests {
		<-blocked
	}

	sess.dispatchUpstreamRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: capability.MethodSamplingCreateMessage,
	})

	assert.Equal(t, int64(maxConcurrentServerRequests), sess.serverPool.inFlight.Load(),
		"a refused request must not have been dispatched")
	require.Len(t, uw.messages, 1, "the refused request must be answered, not left hanging")
	require.NotNil(t, uw.messages[0].Error)
	assert.Equal(t, jsonRPCCodeServerBusy, uw.messages[0].Error.Code, "and refused as retryable overload, not as a policy denial")

	close(release)
	sess.serverPool.drain(4 * samplingTurnWait.total)
	assert.Zero(t, sess.serverPool.inFlight.Load())

	require.NoError(t, sink.Close())
	raw, err := os.ReadFile(dir + "/audit.jsonl")
	require.NoError(t, err)
	line := strings.TrimSpace(string(raw))
	require.NotEmpty(t, line, "a saturating upstream must leave a trace on the tape")
	for _, want := range []string{`"` + codeResourceExhausted + `"`, `"session_id":"sess-a"`, `"upstream":"up1"`} {
		assert.Contains(t, line, want, "the refusal record must name the code, the session whose pool it was, and its route")
	}
}

// TestReleaseSessionState_DrainsServerInitiatedHandlers is the teardown half of the HTTP move.
// Those handlers no longer run on the reader, so the reader's exit no longer implies they have
// finished — and one still running past this point writes its audit record into a sink whose
// route is going away, or reads flow state ReleaseSession has just cleared.
func TestReleaseSessionState_DrainsServerInitiatedHandlers(t *testing.T) {
	t.Parallel()
	sess := newTestSession(&httpSession{
		id:    "sess-a",
		route: &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}},
		proxy: &HTTPProxy{shutdownMs: 4000},
	})

	running, finished := make(chan struct{}), make(chan struct{})
	sess.serverPool.dispatch(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`)},
		serverRequestDispatch{
			handle: func(context.Context, mcp.RPCMsg) {
				close(running)
				time.Sleep(30 * time.Millisecond)
				close(finished)
			},
		})
	<-running

	releaseSessionState(sess)
	select {
	case <-finished:
	default:
		t.Fatal("teardown released session state while a server-initiated handler was still running")
	}
}

// TestStdioUpstreamRequest_SaturationIsRefusedAndRecorded covers the bound that had to come
// with the goroutine. An upstream emitting server-initiated requests faster than the host
// answers them would otherwise grow goroutines without limit — the hazard hostSem exists for
// on the other side, arriving from the upstream instead.
//
// Both halves matter: the upstream is ANSWERED (a request it never gets a reply to leaves it
// waiting forever) and the refusal is RECORDED, so a flood leaves a trace on the tamper-evident
// tape rather than only a stream of error replies.
func TestStdioUpstreamRequest_SaturationIsRefusedAndRecorded(t *testing.T) {
	t.Parallel()
	uw := &mockUpstreamWriter{}
	rec := &fwdRecorder{}
	p := &StdioProxy{
		pdp:        pdp.AlwaysAllowPDP{},
		sessionID:  "sess-a",
		upWriter:   mcp.NewMsgWriter(&writerAdapter{uw}),
		hostWriter: mcp.NewMsgWriter(io.Discard),
		recCached:  rec,
	}
	p.recOnce.Do(func() {}) // the recorder is injected; keep rec() from rebuilding it

	// Saturate through the pool's own dispatch rather than by pre-filling its semaphore, so
	// what is under test is the admission path the transport actually takes.
	release := make(chan struct{})
	blocked := make(chan struct{}, maxConcurrentServerRequests)
	for range maxConcurrentServerRequests {
		p.serverPool.dispatch(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`)},
			serverRequestDispatch{
				handle: func(context.Context, mcp.RPCMsg) { blocked <- struct{}{}; <-release },
			})
	}
	for range maxConcurrentServerRequests {
		<-blocked // every slot is held before the refusal is attempted
	}

	p.dispatchUpstreamRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Method: capability.MethodSamplingCreateMessage,
	})

	assert.Equal(t, int64(maxConcurrentServerRequests), p.serverPool.inFlight.Load(),
		"a refused request must not have been dispatched")
	require.Len(t, uw.messages, 1, "the refused request must be answered, not left hanging")
	require.NotNil(t, uw.messages[0].Error)
	assert.Equal(t, jsonRPCCodeServerBusy, uw.messages[0].Error.Code, "and refused as retryable overload, not as a policy denial")
	require.Len(t, rec.records, 1, "a saturating upstream must leave a trace on the tape")
	assert.Equal(t, codeResourceExhausted, rec.records[0].code)

	// A freed slot ends the episode: the next request is dispatched normally.
	close(release)
	p.awaitServerRequestsDrained(4 * samplingTurnWait.total)
	p.dispatchUpstreamRequest(context.Background(), mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`8`), Method: capability.MethodSamplingCreateMessage,
	})
	p.awaitServerRequestsDrained(4 * samplingTurnWait.total)
	assert.Zero(t, p.serverPool.inFlight.Load())
}
