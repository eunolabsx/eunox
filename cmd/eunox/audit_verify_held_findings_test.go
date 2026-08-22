// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// TestHeldFindings_WithholdsUntilReleased is the false-tamper-alarm regression: the
// rotation bracket only suppresses the exit-code verdict, so a pass that streamed its
// CHAIN BREAK lines straight to stdout still printed a tamper alarm the bracket then
// retracted. Nothing may reach the terminal until release.
func TestHeldFindings_WithholdsUntilReleased(t *testing.T) {
	var out strings.Builder
	h := &heldFindings{out: &out}

	if _, err := h.Write([]byte("CHAIN BREAK at seq 7\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("a finding must not reach the terminal before the bracket resolves; got %q", out.String())
	}

	h.release()
	if got := out.String(); got != "CHAIN BREAK at seq 7\n" {
		t.Fatalf("release must emit exactly what was held; got %q", got)
	}

	// Idempotent: the cap-exceeded flush and the end-of-pass release share this path.
	h.release()
	if got := out.String(); got != "CHAIN BREAK at seq 7\n" {
		t.Fatalf("a second release must not repeat the held lines; got %q", got)
	}
}

// TestHeldFindings_StreamsPastTheCap pins the bound: a rotation racing the pass fabricates
// a handful of lines at one seam, so a pass producing far more is reporting the log's own
// findings and must not be buffered a line per record.
func TestHeldFindings_StreamsPastTheCap(t *testing.T) {
	var out strings.Builder
	h := &heldFindings{out: &out}

	line := strings.Repeat("x", 1024) + "\n"
	for out.Len() == 0 {
		if _, err := h.Write([]byte(line)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if out.Len() == 0 && h.buf.Len() > heldFindingsCap {
			t.Fatal("the buffer grew past the cap without flushing")
		}
	}

	// Everything written so far was flushed, and writes after the cap go straight out.
	before := out.Len()
	if _, err := h.Write([]byte("after\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if out.Len() != before+len("after\n") {
		t.Fatalf("writes past the cap must stream; buffered %d bytes", out.Len()-before)
	}
	if h.buf.Len() != 0 {
		t.Fatalf("nothing may stay held once streaming; %d bytes remain", h.buf.Len())
	}
}
