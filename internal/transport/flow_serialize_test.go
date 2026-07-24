// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// TestDecisionSerializer_FIFOOrderUnderConcurrency proves the serialization primitive
// hands out and serves tickets in the order they were RESERVED (proxy-receipt order),
// regardless of the order the handler goroutines happen to reach begin — the property
// that makes the source-before-sink ordering deterministic (piece B).
func TestDecisionSerializer_FIFOOrderUnderConcurrency(t *testing.T) {
	t.Parallel()
	const n = 200
	g := newDecisionSerializer()
	// Reserve every ticket up front, in order, as the single-threaded reader would.
	tickets := make([]uint64, n)
	for i := range tickets {
		tickets[i] = g.take()
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
// closeUp tears the responder down.
func newSerializedFlowProxy(t *testing.T, store capability.FlowLabelStore, sessionID string) (p *StdioProxy, hw *mockHostWriter, closeUp func()) {
	t.Helper()
	caps := []capability.Constraint{
		{Target: "tool:read_secret", Actions: []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelConfidential}}}},
		{Target: "tool:send_email", Actions: []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}}},
	}
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()), enforcement.WithFlowLabelStore(store))
	dp := pdp.NewManifestPDP(caps, engine, killswitch.NewInMemory())

	hw = &mockHostWriter{}
	upR, upW := io.Pipe()
	p = &StdioProxy{
		pdp:          dp,
		sessionID:    sessionID,
		decideGate:   newDecisionSerializer(), // per-session decision serialization ON (piece B)
		pending:      make(map[string]chan upstreamResult),
		byUpstreamID: make(map[string]chan upstreamResult),
		hostToUp:     make(map[string]*json.RawMessage),
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(upW),
		upstreamDone: make(chan struct{}),
	}
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

// TestFlowSerialize_ConcurrentEgressDeniedEveryTime is the FR-H3 (ordered source->sink
// under concurrency) acceptance test: a client that pipelines a tainting source read and
// an egress on ONE session — without waiting for the read's response — must have the
// egress denied EVERY time. The source and egress are dispatched to concurrent handler
// goroutines, so on the unserialized transport the sink could Get the label set before the
// source Adds it and slip the flow (the demo's 17/20). Per-session receipt-order
// serialization (piece B) closes that: repeated 120x against both store backends, the
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
				p, hw, closeUp := newSerializedFlowProxy(t, store, fmt.Sprintf("sess-%d", i))
				p.hostReader = mcp.NewMsgReader(strings.NewReader(input))

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
