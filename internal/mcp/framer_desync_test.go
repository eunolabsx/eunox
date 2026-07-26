// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

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
// not how the stdio host stream is built: SetPoisonHook gives an unbounded writer an
// owner, so a desync on a stream whose writes are fire-and-forget still tears something
// down instead of dropping every later message in silence.
func TestMsgWriter_PoisonHookWithoutDeadline(t *testing.T) {
	t.Parallel()
	var fired atomic.Int32
	mw := NewMsgWriter(&shortWriter{accept: 4, err: syscall.EPIPE})
	mw.SetPoisonHook(func() { fired.Add(1) })

	_ = mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	_ = mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"})
	if got := fired.Load(); got != 1 {
		t.Errorf("onPoison fired %d times, want exactly 1 on the poison transition", got)
	}
}

// TestMsgWriter_SetPoisonHookOnAlreadyPoisonedWriterDoesNotFire pins the documented
// boundary: a hook installed after the stream already desynced does not fire
// retroactively. Firing it would run a teardown for a transition its owner never
// observed — and on the stdio host path that teardown kills the upstream. The writer must
// still refuse every later write with the latched cause.
func TestMsgWriter_SetPoisonHookOnAlreadyPoisonedWriterDoesNotFire(t *testing.T) {
	t.Parallel()
	var fired atomic.Int32
	mw := NewMsgWriter(&shortWriter{accept: 4, err: syscall.EPIPE})

	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); !errors.Is(err, ErrFrameDesync) {
		t.Fatalf("first write err = %v, want ErrFrameDesync", err)
	}
	mw.SetPoisonHook(func() { fired.Add(1) })
	if err := mw.Write(RPCMsg{JSONRPC: "2.0", Method: "tools/call"}); !errors.Is(err, ErrFrameDesync) {
		t.Errorf("write after late hook install = %v, want the latched ErrFrameDesync", err)
	}
	if got := fired.Load(); got != 0 {
		t.Errorf("onPoison fired %d times for a transition that predates it, want 0", got)
	}
}
