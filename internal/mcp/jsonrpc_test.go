// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestRPCMsg_IDNullClassifiedAsRequest: a JSON-RPC
// message carrying an explicit "id": null is a valid request/response, not a
// notification. Plain *json.RawMessage decoding collapses present-null and absent
// to nil; RPCMsg.UnmarshalJSON must keep present-null as a non-nil "null" id so
// the classification helpers route it correctly and the response echoes null.
func TestRPCMsg_IDNullClassifiedAsRequest(t *testing.T) {
	cases := []struct {
		name           string
		wire           string
		wantIDNonNil   bool
		wantRequest    bool
		wantNotif      bool
		wantResponse   bool
		wantIDRawIfSet string
	}{
		{
			name:           "present-null id with method is a request",
			wire:           `{"jsonrpc":"2.0","id":null,"method":"tools/list"}`,
			wantIDNonNil:   true,
			wantRequest:    true,
			wantIDRawIfSet: "null",
		},
		{
			name:         "absent id with method is a notification",
			wire:         `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			wantIDNonNil: false,
			wantNotif:    true,
		},
		{
			name:           "present-null id without method is a response",
			wire:           `{"jsonrpc":"2.0","id":null,"result":{}}`,
			wantIDNonNil:   true,
			wantResponse:   true,
			wantIDRawIfSet: "null",
		},
		{
			name:           "integer id with method is a request",
			wire:           `{"jsonrpc":"2.0","id":7,"method":"tools/call"}`,
			wantIDNonNil:   true,
			wantRequest:    true,
			wantIDRawIfSet: "7",
		},
		{
			name:           "string id with method is a request",
			wire:           `{"jsonrpc":"2.0","id":"abc","method":"tools/call"}`,
			wantIDNonNil:   true,
			wantRequest:    true,
			wantIDRawIfSet: `"abc"`,
		},
		{
			name:           "integer id without method is a response",
			wire:           `{"jsonrpc":"2.0","id":7,"result":{}}`,
			wantIDNonNil:   true,
			wantResponse:   true,
			wantIDRawIfSet: "7",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m RPCMsg
			if err := json.Unmarshal([]byte(tc.wire), &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if (m.ID != nil) != tc.wantIDNonNil {
				t.Fatalf("ID non-nil = %v, want %v", m.ID != nil, tc.wantIDNonNil)
			}
			if m.ID != nil && tc.wantIDRawIfSet != "" && string(*m.ID) != tc.wantIDRawIfSet {
				t.Fatalf("ID raw = %q, want %q", string(*m.ID), tc.wantIDRawIfSet)
			}
			if got := m.IsRequest(); got != tc.wantRequest {
				t.Errorf("IsRequest = %v, want %v", got, tc.wantRequest)
			}
			if got := m.IsNotification(); got != tc.wantNotif {
				t.Errorf("IsNotification = %v, want %v", got, tc.wantNotif)
			}
			if got := m.IsResponse(); got != tc.wantResponse {
				t.Errorf("IsResponse = %v, want %v", got, tc.wantResponse)
			}
		})
	}
}

// TestMsgKey_CanonicalizesByValue verifies MsgKey keys an ID by its decoded
// JSON value and type, not by raw byte spelling, so equivalent encodings of the
// same string ID correlate, while strings, numbers, and null stay disjoint.
func TestMsgKey_CanonicalizesByValue(t *testing.T) {
	// Two spellings of the same string value must share a key.
	if MsgKey(RawJSON(`"\u0061"`)) != MsgKey(RawJSON(`"a"`)) {
		t.Errorf("escaped and literal string IDs must canonicalize to the same key: %q vs %q",
			MsgKey(RawJSON(`"\u0061"`)), MsgKey(RawJSON(`"a"`)))
	}
	// Surrounding whitespace must not change the key.
	if MsgKey(RawJSON(` 7 `)) != MsgKey(RawJSON(`7`)) {
		t.Errorf("whitespace-padded numeric ID must canonicalize to the same key")
	}
	// A numeric ID and a string ID with the same textual form must not collide.
	if MsgKey(RawJSON(`7`)) == MsgKey(RawJSON(`"7"`)) {
		t.Errorf("numeric and string IDs with the same text must not collide")
	}
	// Numerically-equal numeric IDs spelled differently must share a key, so a
	// host that re-serializes 5 as 5.0 or 5e0 still correlates to the same
	// pending server-initiated request.
	for _, eq := range []string{`5.0`, `5e0`, `5.00`, `0.5e1`} {
		if MsgKey(RawJSON(eq)) != MsgKey(RawJSON(`5`)) {
			t.Errorf("numeric ID %q must canonicalize to the same key as 5: got %q vs %q",
				eq, MsgKey(RawJSON(eq)), MsgKey(RawJSON(`5`)))
		}
	}
	// Distinct numeric values must still produce distinct keys.
	if MsgKey(RawJSON(`5`)) == MsgKey(RawJSON(`50`)) {
		t.Errorf("distinct numeric IDs 5 and 50 must not collide")
	}
	// A large integer beyond int64 range canonicalizes via big.Rat without
	// collapsing into the fallback raw key.
	if got := MsgKey(RawJSON(`123456789012345678901234567890`)); got != "n:123456789012345678901234567890" {
		t.Errorf("large integer ID keyed unexpectedly: %q", got)
	}
	// An integral value reached via the big.Rat branch (a non-int64 spelling like
	// 5.0) must key by its integer form "n:5", matching the int64 fast path so the
	// two spellings correlate. RatString already omits the denominator when it is 1
	// (rendering "5", not "5/1"); these cases guard against a future regression that
	// would reintroduce the "5/1" form and silently drop the correlated response.
	if got := MsgKey(RawJSON(`5.0`)); got != "n:5" {
		t.Errorf("integral big.Rat ID 5.0 must key as %q, got %q", "n:5", got)
	}
	if MsgKey(RawJSON(`5`)) != MsgKey(RawJSON(`5.0`)) {
		t.Errorf("int 5 and decimal 5.0 must share a key: %q vs %q",
			MsgKey(RawJSON(`5`)), MsgKey(RawJSON(`5.0`)))
	}
	// A scientific-notation integral value collapses to its plain integer key.
	if got := MsgKey(RawJSON(`5e2`)); got != "n:500" {
		t.Errorf("integral big.Rat ID 5e2 must key as %q, got %q", "n:500", got)
	}
	// A genuinely non-integral value keeps the reduced rational form and keys
	// distinctly from any integer.
	if got := MsgKey(RawJSON(`1.5`)); got != "n:3/2" {
		t.Errorf("non-integral ID 1.5 must key as %q, got %q", "n:3/2", got)
	}
	if MsgKey(RawJSON(`1.5`)) == MsgKey(RawJSON(`1`)) || MsgKey(RawJSON(`1.5`)) == MsgKey(RawJSON(`2`)) {
		t.Errorf("non-integral ID 1.5 must not collide with an integer key")
	}
	// null is its own key, distinct from the absent (notification) key.
	if MsgKey(RawJSON(`null`)) == MsgKey(nil) {
		t.Errorf("null ID must not key the same as an absent ID")
	}
	if MsgKey(nil) != "" {
		t.Errorf("absent ID must key to the empty string, got %q", MsgKey(nil))
	}
}

// TestMsgKey_LargeNumericIDsCanonicalize pins the widened numeric bounds: a
// large-but-legitimate numeric id (well under the DoS ceiling) must canonicalize by
// value so two spellings of the same number share a key, rather than orphaning a
// correlated reply when an upstream re-serializes the id in a different spelling.
func TestMsgKey_LargeNumericIDsCanonicalize(t *testing.T) {
	// 1e70 vs 1.0e+70 vs the plain 71-digit integer: all the same value, must share
	// one key (previously all fell to the raw-bytes fallback with the exponent bound at
	// 64, so the three spellings keyed differently).
	spellings := []string{`1e70`, `1.0e+70`, `10000000000000000000000000000000000000000000000000000000000000000000000`}
	first := MsgKey(RawJSON(spellings[0]))
	if strings.HasPrefix(first, "r:") {
		t.Fatalf("1e70 should canonicalize, not use the raw fallback; got %q", first)
	}
	for _, s := range spellings[1:] {
		if got := MsgKey(RawJSON(s)); got != first {
			t.Errorf("numeric id %q must key the same as %q: got %q vs %q", s, spellings[0], got, first)
		}
	}
	// A 65-digit integer (past the old 64-char length cap) canonicalizes as its own
	// decimal rather than the raw fallback.
	big65 := `10000000000000000000000000000000000000000000000000000000000000000`
	if got := MsgKey(RawJSON(big65)); got != "n:"+big65 {
		t.Errorf("65-digit integer id keyed unexpectedly: %q", got)
	}
}

// TestMsgKey_FastPathMatchesSlowPath verifies the zero-alloc plain-integer fast path
// produces byte-identical keys to the canonicalizing decoder path, including the
// non-canonical spellings the fast path must reject so the two paths never disagree.
func TestMsgKey_FastPathMatchesSlowPath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`0`, "n:0"},
		{`5`, "n:5"},
		{`-5`, "n:-5"},
		{`42`, "n:42"},
		{`9007199254740991`, "n:9007199254740991"}, // max safe JS integer
		{`-9007199254740991`, "n:-9007199254740991"},
		{`-0`, "n:0"},    // rejected by the fast path; slow path collapses to 0
		{`5.0`, "n:5"},   // float spelling of an integer, slow path
		{`5e2`, "n:500"}, // exponent spelling, slow path
	} {
		if got := MsgKey(RawJSON(tc.in)); got != tc.want {
			t.Errorf("MsgKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Non-canonical integer spellings JSON itself rejects ("+5", "05") must not key as
	// their canonical form — they fall through to the raw fallback, distinct from "n:5".
	for _, bad := range []string{`+5`, `05`, `007`} {
		if got := MsgKey(RawJSON(bad)); !strings.HasPrefix(got, "r:") {
			t.Errorf("non-canonical id %q must use the raw fallback, got %q", bad, got)
		}
	}
}

// TestMsgKey_GiantExponentDoesNotAmplify pins the fix for the big.Rat
// amplification DoS: a tiny numeric id with a huge exponent must NOT be expanded
// into a multi-megabyte big.Int/key. It is keyed via the cheap raw-bytes fallback
// and returns promptly.
func TestMsgKey_GiantExponentDoesNotAmplify(t *testing.T) {
	done := make(chan string, 1)
	go func() { done <- MsgKey(RawJSON(`1e1000000`)) }()
	select {
	case got := <-done:
		// The result must be the raw fallback ("r:"+raw), not a ~1MB materialized
		// decimal, so it stays tiny.
		if len(got) > 64 {
			t.Errorf("giant-exponent id produced an oversized key (len %d) — big.Rat was expanded", len(got))
		}
		if got != "r:1e1000000" {
			t.Errorf("giant-exponent id should key via the raw fallback, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("MsgKey did not return promptly for a giant-exponent id — amplification regression")
	}
}

// TestRPCMsg_IDNullRoundTrips verifies a present-null id is echoed back as
// "id":null (not omitted) when the message is re-marshaled, e.g. when building a
// response to a null-id request, and that an absent id stays omitted.
func TestRPCMsg_IDNullRoundTrips(t *testing.T) {
	var req RPCMsg
	if err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","id":null,"method":"tools/list"}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	resp, err := SuccessResponse(req.ID, map[string]any{"ok": true})
	if err != nil {
		t.Fatalf("SuccessResponse: %v", err)
	}
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(out); got != `{"jsonrpc":"2.0","id":null,"result":{"ok":true}}` {
		t.Fatalf("response = %s, want id echoed as null", got)
	}

	// A notification (absent id) must not gain an id when marshaled.
	notif, err := NotificationMsg("notifications/initialized", nil)
	if err != nil {
		t.Fatalf("NotificationMsg: %v", err)
	}
	out, err = json.Marshal(notif)
	if err != nil {
		t.Fatalf("marshal notif: %v", err)
	}
	if got := string(out); got != `{"jsonrpc":"2.0","method":"notifications/initialized"}` {
		t.Fatalf("notification = %s, want no id field", got)
	}
}

// deadlineBlockingWriter simulates a subprocess stdin pipe whose reader has stopped
// draining: once a write deadline is set, Write blocks until it passes and then returns
// an error wrapping os.ErrDeadlineExceeded, exactly as a pollable *os.File pipe write
// does. With no deadline set it accepts the write immediately. It implements
// writeDeadliner so NewMsgWriterWithTimeout arms it.
type deadlineBlockingWriter struct {
	mu       sync.Mutex
	deadline time.Time
	writes   int
}

func (w *deadlineBlockingWriter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deadline = t
	return nil
}

func (w *deadlineBlockingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.writes++
	d := w.deadline
	w.mu.Unlock()
	if d.IsZero() {
		return len(p), nil
	}
	if rem := time.Until(d); rem > 0 {
		time.Sleep(rem)
	}
	return 0, &os.PathError{Op: "write", Path: "pipe", Err: os.ErrDeadlineExceeded}
}

// TestMsgWriter_WriteTimeoutPoisons pins the write-deadline bound that resolves the
// stdio sampling + write-wedge deadlock: a write against an upstream that has stopped
// draining its stdin returns ErrUpstreamWriteTimeout within ~timeout instead of blocking
// forever, and the writer is then poisoned so a second write fails fast (letting a
// sampling reply queued behind a wedged request write return rather than block on the
// mutex indefinitely).
func TestMsgWriter_WriteTimeoutPoisons(t *testing.T) {
	t.Parallel()
	fw := &deadlineBlockingWriter{}
	mw := NewMsgWriterWithTimeout(fw, 50*time.Millisecond, nil)

	start := time.Now()
	err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrUpstreamWriteTimeout) {
		t.Fatalf("first write err = %v, want ErrUpstreamWriteTimeout", err)
	}
	if elapsed > time.Second {
		t.Fatalf("write took %s, want bounded by ~50ms deadline", elapsed)
	}

	// Poisoned: a second write must fail fast (no deadline wait) with the same sentinel.
	start = time.Now()
	err = mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	if !errors.Is(err, ErrUpstreamWriteTimeout) {
		t.Fatalf("second write err = %v, want ErrUpstreamWriteTimeout (poisoned)", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Fatalf("poisoned write took %s, want an immediate return", elapsed)
	}
	// The poisoned write must NOT reach the underlying writer (it would append a frame
	// after the desynced partial one).
	fw.mu.Lock()
	writes := fw.writes
	fw.mu.Unlock()
	if writes != 1 {
		t.Fatalf("underlying writer saw %d writes, want 1 (poisoned write must not reach it)", writes)
	}
}

// TestMsgWriter_NoTimeoutWhenUnset confirms NewMsgWriterWithTimeout degrades to the
// unbounded behavior when timeout<=0, and NewMsgWriter never arms a deadline, so a
// non-pipe writer (or --upstream-timeout=0) writes as before.
func TestMsgWriter_NoTimeoutWhenUnset(t *testing.T) {
	t.Parallel()
	// timeout<=0: no deadline armed even on a deadline-capable writer.
	fw := &deadlineBlockingWriter{}
	if mw := NewMsgWriterWithTimeout(fw, 0, nil); mw.deadliner != nil {
		t.Fatal("timeout<=0 must not arm a write deadline")
	}
	// A plain writer with a positive timeout: no deadline support, so it writes unbounded.
	mw := NewMsgWriterWithTimeout(io.Discard, 50*time.Millisecond, nil)
	if mw.deadliner != nil {
		t.Fatal("a writer without SetWriteDeadline must not be armed")
	}
	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "ping"}); err != nil {
		t.Fatalf("unbounded write err = %v, want nil", err)
	}
}

// unsupportedDeadlineWriter accepts writes but reports that it does not support write
// deadlines, modelling a pipe/platform where SetWriteDeadline fails.
type unsupportedDeadlineWriter struct{ writes int }

func (w *unsupportedDeadlineWriter) SetWriteDeadline(time.Time) error {
	return errors.New("write deadline not supported")
}
func (w *unsupportedDeadlineWriter) Write(p []byte) (int, error) { w.writes++; return len(p), nil }

// TestMsgWriter_OnPoisonFiresOnce pins that the teardown hook runs exactly once, on the
// poison transition — so any write path that first wedges tears the upstream down, and a
// later fail-fast poisoned write does not re-fire it.
func TestMsgWriter_OnPoisonFiresOnce(t *testing.T) {
	t.Parallel()
	fw := &deadlineBlockingWriter{}
	var poisons int
	var mu sync.Mutex
	mw := NewMsgWriterWithTimeout(fw, 50*time.Millisecond, func() {
		mu.Lock()
		poisons++
		mu.Unlock()
	})

	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); !errors.Is(err, ErrUpstreamWriteTimeout) {
		t.Fatalf("first write err = %v, want ErrUpstreamWriteTimeout", err)
	}
	// A second (poisoned) write must fail fast and must NOT re-fire the hook.
	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); !errors.Is(err, ErrUpstreamWriteTimeout) {
		t.Fatalf("second write err = %v, want ErrUpstreamWriteTimeout", err)
	}
	mu.Lock()
	got := poisons
	mu.Unlock()
	if got != 1 {
		t.Fatalf("onPoison fired %d times, want exactly 1", got)
	}
}

// TestMsgWriter_UnsupportedDeadlineDegrades pins the platform-degradation path: when the
// pipe rejects SetWriteDeadline, the writer is NOT armed (deadliner stays nil), so writes
// proceed unbounded rather than silently carrying a deadline that never fires. This makes
// "deadliner != nil" a true "the write is bounded" invariant.
func TestMsgWriter_UnsupportedDeadlineDegrades(t *testing.T) {
	t.Parallel()
	uw := &unsupportedDeadlineWriter{}
	mw := NewMsgWriterWithTimeout(uw, 50*time.Millisecond, func() {
		t.Error("onPoison must not fire when the deadline was never armed")
	})
	if mw.deadliner != nil {
		t.Fatal("a writer whose SetWriteDeadline fails must not be armed")
	}
	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "ping"}); err != nil {
		t.Fatalf("unbounded write err = %v, want nil", err)
	}
	if uw.writes != 1 {
		t.Fatalf("underlying writer saw %d writes, want 1", uw.writes)
	}
}

// shortWriter accepts only the first n bytes of a frame and then fails, modeling the
// non-deadline ways a mid-frame write can be cut off: EPIPE on a subprocess that exited
// mid-read, ENOSPC, or an interrupted write of a frame larger than PIPE_BUF.
type shortWriter struct {
	mu     sync.Mutex
	accept int
	writes int
	err    error
}

func (w *shortWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	n := w.accept
	if n > len(p) {
		n = len(p)
	}
	return n, w.err
}

// TestMsgWriter_PartialWritePoisons pins that ANY short write poisons the framer, not
// only a deadline timeout. A frame cut off part-way leaves the newline framing desynced
// exactly as a timed-out one does, so appending the next frame after it would splice two
// messages into one unparseable line. Keying the poison on the deadline error alone left
// every non-deadline partial write doing precisely that.
func TestMsgWriter_PartialWritePoisons(t *testing.T) {
	t.Parallel()
	sw := &shortWriter{accept: 4, err: syscall.EPIPE}
	// NewMsgWriter: no deadline armed at all, so this is unreachable from the old
	// deadline-keyed poison check.
	mw := NewMsgWriter(sw)

	err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	if !errors.Is(err, ErrFrameDesync) {
		t.Fatalf("partial write err = %v, want it wrapped as ErrFrameDesync (framing desynced)", err)
	}
	// It must NOT be reported as a deadline timeout: the classification layer stamps a
	// fabricated "did not respond within N ms" on the audit tape for that sentinel.
	if errors.Is(err, ErrUpstreamWriteTimeout) {
		t.Errorf("partial write err = %v, want it distinguishable from a deadline timeout", err)
	}
	if !errors.Is(err, syscall.EPIPE) {
		t.Errorf("partial write err = %v, want the underlying cause preserved", err)
	}

	// Poisoned: the next frame must not be appended onto the truncated one, and it must
	// report the CAUSE that broke the stream rather than collapsing onto one sentinel.
	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); !errors.Is(err, ErrFrameDesync) {
		t.Fatalf("second write err = %v, want ErrFrameDesync (poisoned)", err)
	}
	sw.mu.Lock()
	writes := sw.writes
	sw.mu.Unlock()
	if writes != 1 {
		t.Fatalf("underlying writer saw %d writes, want 1 (the poisoned write must not reach it)", writes)
	}
}

// TestMsgWriter_FullWriteWithErrorDoesNotPoison pins the other side of the rule: an
// io.Writer may legally return a non-nil error alongside n == len(p). The whole frame
// landed, so the framing is intact and the writer must stay usable — poisoning on any
// error at all would tear down sessions over a fully-delivered message.
func TestMsgWriter_FullWriteWithErrorDoesNotPoison(t *testing.T) {
	t.Parallel()
	sw := &shortWriter{accept: 1 << 20, err: errors.New("transient")} // accept >= any frame
	mw := NewMsgWriter(sw)

	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); errors.Is(err, ErrUpstreamWriteTimeout) {
		t.Fatalf("full write reported as a framing desync: %v", err)
	}
	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); errors.Is(err, ErrUpstreamWriteTimeout) {
		t.Fatalf("writer poisoned after a full write: %v", err)
	}
	sw.mu.Lock()
	writes := sw.writes
	sw.mu.Unlock()
	if writes != 2 {
		t.Errorf("underlying writer saw %d writes, want 2 (writer must stay usable)", writes)
	}
}

// TestMsgWriter_PartialWriteFiresOnPoisonHook pins that a non-deadline partial write also
// tears the session down: the hook is how the desynced stream gets reaped rather than
// reused, and it must not depend on which failure produced the partial frame.
func TestMsgWriter_PartialWriteFiresOnPoisonHook(t *testing.T) {
	t.Parallel()
	var fired atomic.Int32
	sw := &shortWriter{accept: 4, err: syscall.EPIPE}
	mw := NewMsgWriterWithTimeout(sw, time.Second, func() { fired.Add(1) })

	_ = mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	_ = mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	if got := fired.Load(); got != 1 {
		t.Errorf("onPoison fired %d times, want exactly 1 on the poison transition", got)
	}
}

// TestMsgWriter_ShortWriteWithoutErrorPoisons pins that the desync latch keys on the BYTE
// COUNT, not on the writer having reported an error. io.Writer requires a non-nil error on
// a short write, but the framing is broken either way, and a writer that violates the
// contract must not be allowed to append the next frame onto half of the previous one.
func TestMsgWriter_ShortWriteWithoutErrorPoisons(t *testing.T) {
	t.Parallel()
	sw := &shortWriter{accept: 4} // no error reported
	mw := NewMsgWriter(sw)

	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); !errors.Is(err, ErrFrameDesync) {
		t.Fatalf("contract-violating short write err = %v, want ErrFrameDesync", err)
	}
	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); !errors.Is(err, ErrFrameDesync) {
		t.Fatalf("second write err = %v, want the writer poisoned", err)
	}
	sw.mu.Lock()
	writes := sw.writes
	sw.mu.Unlock()
	if writes != 1 {
		t.Errorf("underlying writer saw %d writes, want 1", writes)
	}
}

// TestMsgWriter_DeadlinePoisonKeepsTimeoutSentinel pins the other side of the split: a
// genuine deadline expiry still reports ErrUpstreamWriteTimeout, on the first write and on
// every later one, so it is still classified as UPSTREAM_TIMEOUT rather than a crash.
func TestMsgWriter_DeadlinePoisonKeepsTimeoutSentinel(t *testing.T) {
	t.Parallel()
	mw := NewMsgWriterWithTimeout(&deadlineBlockingWriter{}, 20*time.Millisecond, nil)

	err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	if !errors.Is(err, ErrUpstreamWriteTimeout) {
		t.Fatalf("first write err = %v, want ErrUpstreamWriteTimeout", err)
	}
	if errors.Is(err, ErrFrameDesync) {
		t.Errorf("deadline expiry err = %v, want it distinct from a partial-frame desync", err)
	}
	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); !errors.Is(err, ErrUpstreamWriteTimeout) {
		t.Errorf("poisoned write err = %v, want the latched cause preserved", err)
	}
}

// TestMsgWriter_PoisonHookWithoutDeadline pins that a hookless-but-poisonable writer is
// not how the stdio host stream is built: NewMsgWriterWithPoisonHook gives an unbounded
// writer an owner, so a desync on a stream whose writes are fire-and-forget still tears
// something down instead of dropping every later message in silence.
func TestMsgWriter_PoisonHookWithoutDeadline(t *testing.T) {
	t.Parallel()
	var fired atomic.Int32
	mw := NewMsgWriterWithPoisonHook(&shortWriter{accept: 4, err: syscall.EPIPE}, func() { fired.Add(1) })

	_ = mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	_ = mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	if got := fired.Load(); got != 1 {
		t.Errorf("onPoison fired %d times, want exactly 1 on the poison transition", got)
	}
}
