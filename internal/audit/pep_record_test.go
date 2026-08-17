// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// enforcementPointOrFatal builds the stamp for id, failing the test rather than the
// assertion when the name itself is rejected — every caller here passes a valid one, so a
// failure means the vocabulary changed, not that the record is wrong.
func enforcementPointOrFatal(tb testing.TB, id string) capability.EnforcementPoint {
	tb.Helper()
	ep, err := capability.NewEnforcementPoint(id)
	if err != nil {
		tb.Fatalf("NewEnforcementPoint(%q): %v", id, err)
	}
	return ep
}

// TestRecord_PEPSignAndVerify is the required sign-and-verify round-trip for the pep field.
//
// What it closes: a sequence that crosses two enforcement points is reconstructed by reading
// their tapes together, and once merged the file a record came out of is gone. Without the
// writer named ON the record, a call the far side handled is indistinguishable from one this
// side did — and the name has to be in the SIGNED body for the attribution to mean anything,
// which is what the tamper leg below asserts.
func TestRecord_PEPSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0, WithEnforcementPoint(enforcementPointOrFatal(t, "edge-1")))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	sink.RecordAllow(ctx, "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.RecordDeny(ctx, "sess-1", "wire_transfer", "tools/call", capability.ErrCodeAuthorizationFailed, "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d", len(lines))
	}
	for i, line := range lines {
		if !bytes.Contains(line, []byte(`"pep":"mcp:edge-1"`)) {
			t.Fatalf("record %d must name the enforcement point that wrote it: %s", i, line)
		}
	}

	verifier := verifierFor(t, keyPath)
	for i, line := range lines {
		if ok, verr := verifier.VerifyRecord(line); !ok || verr != nil {
			t.Fatalf("record %d must verify: ok=%v err=%v", i, ok, verr)
		}
	}

	// Tamper: reattribute this instance's denial to a second enforcement point, which in a
	// merged reconstruction moves the refusal to a hop that never saw the call. A top-level
	// signed field makes that fail.
	tampered := bytes.Replace(lines[1], []byte(`"pep":"mcp:edge-1"`), []byte(`"pep":"mcp:edge-2"`), 1)
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a rewritten pep must break the record HMAC")
	}
	// And the other direction: stripping the field entirely must not leave a record that
	// still verifies as an unattributed one, or the attribution is removable at will.
	stripped := bytes.Replace(lines[0], []byte(`"pep":"mcp:edge-1",`), nil, 1)
	if ok, _ := verifier.VerifyRecord(stripped); ok {
		t.Fatal("a stripped pep must break the record HMAC")
	}
}

// TestRecord_PEPOmittedWhenUnconfigured: a single-enforcement-point deployment configures no
// name, and the field is then absent rather than stamped with a placeholder — the same
// honesty rule protocol_revision follows for a decision taken before negotiation.
func TestRecord_PEPOmittedWhenUnconfigured(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 1 {
		t.Fatalf("expected 1 record, got %d", len(lines))
	}
	if bytes.Contains(lines[0], []byte(`"pep"`)) {
		t.Fatalf("an unconfigured enforcement point must omit the field, not stamp an empty one: %s", lines[0])
	}
	if ok, verr := verifierFor(t, keyPath).VerifyRecord(lines[0]); !ok || verr != nil {
		t.Fatalf("record must verify: ok=%v err=%v", ok, verr)
	}
}

// TestSyntheticMarker_CarriesPEP: a marker is written BY an enforcement point about its own
// tape, so it carries the same stamp a decision does. In a merged reconstruction an
// unattributed loss-of-coverage marker is the one record an auditor most needs to place, and
// it is the record no request produces — so it cannot pick the value up from RecordParams.
func TestSyntheticMarker_CarriesPEP(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0, WithEnforcementPoint(enforcementPointOrFatal(t, "edge-1")))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.writeIntegrityMarker("tail_unsigned", map[string]interface{}{"claimed_tail_seq": 7})
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 1 {
		t.Fatalf("expected 1 marker, got %d", len(lines))
	}
	if !bytes.Contains(lines[0], []byte(`"pep":"mcp:edge-1"`)) {
		t.Fatalf("a synthetic marker must name its writer: %s", lines[0])
	}
	if ok, verr := verifierFor(t, keyPath).VerifyRecord(lines[0]); !ok || verr != nil {
		t.Fatalf("marker must verify: ok=%v err=%v", ok, verr)
	}
}

// TestQueueSize_CountsPEP keeps the enqueue reservation and the drainer's credit balanced:
// queueSize is charged once at enqueue and credited back verbatim, so a new variable-length
// field it does not count is heap the aggregate budget cannot see.
func TestQueueSize_CountsPEP(t *testing.T) {
	t.Parallel()
	const stamp = "mcp:edge-1"
	bare := auditRecord{}
	stamped := auditRecord{PEP: stamp}
	if got, want := stamped.queueSize()-bare.queueSize(), int64(len(stamp)); got != want {
		t.Errorf("queueSize delta for pep = %d, want %d", got, want)
	}
}

// TestWithEnforcementPoint_BoundsAHandMadeStamp: the constructor caps the name, but the
// option takes an EnforcementPoint a caller could also assemble by hand, and an unbounded one
// would ride every record past the scanner buffer the envelope cap exists to keep them under.
func TestWithEnforcementPoint_BoundsAHandMadeStamp(t *testing.T) {
	t.Parallel()
	var s Sink
	WithEnforcementPoint(capability.EnforcementPoint(strings.Repeat("x", auditEnvelopeFieldCap*2)))(&s)
	if len(s.pep) > auditEnvelopeFieldCap {
		t.Errorf("stamp of %d bytes was not bounded to %d", len(s.pep), auditEnvelopeFieldCap)
	}
}

// TestOpen_WarnsWhenTheTapeChangesEnforcementPoint: a tape has exactly one writer at a time,
// so a verified tail naming a different enforcement point means this log was written by
// another one first — an instance renamed, or a copied config. The chain still resumes (the
// tail is intact and every record names its own writer), so the only signal is the warning,
// which is what this pins.
func TestOpen_WarnsWhenTheTapeChangesEnforcementPoint(t *testing.T) {
	// Sequential (no t.Parallel): swaps the process-global os.Stderr, like the other
	// capture tests in this package.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	first, err := Open(logPath, keyPath, 0, 0, WithEnforcementPoint(enforcementPointOrFatal(t, "edge-1")))
	if err != nil {
		t.Fatalf("Open (first): %v", err)
	}
	first.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := first.Close(); err != nil {
		t.Fatalf("Close (first): %v", err)
	}

	reopen := func(t *testing.T, opts ...Option) string {
		t.Helper()
		old := os.Stderr
		r, w, perr := os.Pipe()
		if perr != nil {
			t.Fatalf("pipe: %v", perr)
		}
		os.Stderr = w
		sink, oerr := Open(logPath, keyPath, 0, 0, opts...)
		_ = w.Close()
		os.Stderr = old
		if oerr != nil {
			t.Fatalf("Open (reopen): %v", oerr)
		}
		defer func() {
			if cerr := sink.Close(); cerr != nil {
				t.Fatalf("Close (reopen): %v", cerr)
			}
		}()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		return buf.String()
	}

	t.Run("renamed instance warns", func(t *testing.T) {
		out := reopen(t, WithEnforcementPoint(enforcementPointOrFatal(t, "edge-2")))
		if !strings.Contains(out, `written by enforcement point "mcp:edge-1"`) ||
			!strings.Contains(out, `"mcp:edge-2"`) {
			t.Fatalf("expected a warning naming both enforcement points, got: %q", out)
		}
	})

	t.Run("dropped name warns", func(t *testing.T) {
		out := reopen(t)
		if !strings.Contains(out, "no enforcement point at all") {
			t.Fatalf("an instance that stamps nothing onto a named tape must warn, and must not render the absence as an empty name; got: %q", out)
		}
	})

	t.Run("same instance is silent", func(t *testing.T) {
		out := reopen(t, WithEnforcementPoint(enforcementPointOrFatal(t, "edge-1")))
		if strings.Contains(out, "enforcement point") {
			t.Fatalf("resuming a tape this instance itself wrote must say nothing, got: %q", out)
		}
	})
}

// TestOpen_FirstTimeStampIsNotAChange: a tape written before the operator configured a name
// carries none, and adopting one is an ordinary first-time configuration — warning there
// would fire on every upgrade, training operators to ignore the line that matters.
func TestOpen_FirstTimeStampIsNotAChange(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	first, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open (first): %v", err)
	}
	first.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := first.Close(); err != nil {
		t.Fatalf("Close (first): %v", err)
	}

	old := os.Stderr
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("pipe: %v", perr)
	}
	os.Stderr = w
	sink, err := Open(logPath, keyPath, 0, 0, WithEnforcementPoint(enforcementPointOrFatal(t, "edge-1")))
	_ = w.Close()
	os.Stderr = old
	if err != nil {
		t.Fatalf("Open (reopen): %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close (reopen): %v", err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if strings.Contains(buf.String(), "enforcement point") {
		t.Fatalf("adopting a name for the first time must not warn, got: %q", buf.String())
	}
}
