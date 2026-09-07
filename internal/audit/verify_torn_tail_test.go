// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyLog_TornTailIsNoVerdictNotTampering pins the disposition for the shape a
// lock-free pass over a LIVE log reaches every time it meets a write(2) still in flight: a
// final line with no terminating newline. It is not an INVALID record and it must not fail
// OK(); it is the same "re-run" answer ErrChainRotated gives.
func TestVerifyLog_TornTailIsNoVerdictNotTampering(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	writeChainSegment(t, logPath, keyPath, "", "a", "b", "c")

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("expected 3 records, got %d", len(lines))
	}
	// The last record cut mid-write: the two complete ones, then a prefix of the third
	// with no newline behind it.
	torn := append(bytes.Join(lines[:2], []byte("\n")), '\n')
	torn = append(torn, lines[2][:len(lines[2])/2]...)

	verifier := verifierFor(t, keyPath)
	var out strings.Builder
	res, err := VerifyLog(bytes.NewReader(torn), verifier, VerifyOptions{Out: &out})
	if !errors.Is(err, ErrUnterminatedTail) {
		t.Fatalf("a torn tail must report ErrUnterminatedTail, got err=%v res=%+v", err, res)
	}
	if res.Invalid != 0 || res.ChainBreaks != 0 {
		t.Fatalf("the torn fragment must not be classified at all, got %+v", res)
	}
	if res.Valid != 2 || res.Total != 2 {
		t.Fatalf("the two COMPLETE records must still be verified, got %+v", res)
	}
	if !res.OK() {
		t.Fatalf("a torn tail is not a finding: OK() must hold over the complete prefix, got %+v", res)
	}
	if strings.Contains(out.String(), "INVALID") {
		t.Fatalf("a torn tail must print no tampering finding; output:\n%s", out.String())
	}
}

// TestVerifyLog_TerminatedTailIsUnaffected: the same log with its newline intact is an
// ordinary clean pass, so the split function costs the common case nothing.
func TestVerifyLog_TerminatedTailIsUnaffected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	writeChainSegment(t, logPath, keyPath, "", "a", "b", "c")

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	res, err := VerifyLog(bytes.NewReader(raw), verifierFor(t, keyPath), VerifyOptions{Out: io.Discard})
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() || res.Valid != 3 {
		t.Fatalf("a newline-terminated log must verify clean, got %+v", res)
	}
}

// TestVerifyLog_TruncatedInteriorRecordStillFails: the disposition is scoped to the whole
// stream's LAST token. A record torn in the MIDDLE of the stream is followed by more bytes,
// so it is a complete (garbage) line and stays the finding it is — otherwise the no-verdict
// exit would be a way to hide an edit.
func TestVerifyLog_TruncatedInteriorRecordStillFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	writeChainSegment(t, logPath, keyPath, "", "a", "b", "c")

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	lines[1] = lines[1][:len(lines[1])/2]
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}

	var out strings.Builder
	res, err := VerifyLog(&buf, verifierFor(t, keyPath), VerifyOptions{Out: &out})
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.OK() {
		t.Fatalf("an interior truncation must still be reported, got a clean pass: %+v\n%s", res, out.String())
	}
}

// TestVerifyLogFiles_InteriorFileTornTailStillFails: VerifyLogFiles injects a newline
// between files, so only the LAST file's tail can be torn. A rotated sibling ending without
// one is a truncated archive and must not borrow the live base's no-verdict exit.
func TestVerifyLogFiles_InteriorFileTornTailStillFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	stamp := ".20260601T000000.000000000Z"
	writeChainSegment(t, logPath, keyPath, stamp, "a", "b")
	writeChainSegment(t, logPath, keyPath, "", "c", "d")

	sidecar := logPath + stamp
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatalf("ReadFile sidecar: %v", err)
	}
	if err := os.WriteFile(sidecar, raw[:len(raw)-8], 0o600); err != nil {
		t.Fatalf("truncate sidecar: %v", err)
	}

	files, err := LogChainFiles(logPath)
	if err != nil {
		t.Fatalf("LogChainFiles: %v", err)
	}
	var out strings.Builder
	res, err := VerifyLogFiles(files, verifierFor(t, keyPath), VerifyOptions{Out: &out})
	if errors.Is(err, ErrUnterminatedTail) {
		t.Fatalf("only the LAST file's tail may take the no-verdict exit; an interior one must be a finding")
	}
	if err != nil {
		t.Fatalf("VerifyLogFiles: %v", err)
	}
	if res.OK() {
		t.Fatalf("a truncated interior sibling must be reported, got a clean pass: %+v\n%s", res, out.String())
	}
}

// TestVerifyLog_TrailingWhitespaceIsNotATornTail: the scan loop already skips blank lines, so
// a stray trailing space or a file ending mid-blank-line is not a half-written record and
// must not turn a clean verdict into "re-run".
func TestVerifyLog_TrailingWhitespaceIsNotATornTail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "a", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	res, err := VerifyLog(bytes.NewReader(append(raw, ' ', ' ')), verifierFor(t, keyPath), VerifyOptions{Out: io.Discard})
	if err != nil {
		t.Fatalf("trailing whitespace must not be read as a torn record: %v", err)
	}
	if !res.OK() || res.Valid != 1 {
		t.Fatalf("expected a clean single-record pass, got %+v", res)
	}
}

// TestNewLineScanner_DropsATornTailForEveryReader: the scanner is the seam that keeps
// audit-verify, stats, suggest and doctor reading one chain the same way, and all four reach
// it through the same lazy by-name opens. A half-written tail that one classifies and another
// drops is two commands disagreeing about one file — stats counting it as a record with an
// unrecognized decision, doctor printing half a record as the newest line.
func TestNewLineScanner_DropsATornTailForEveryReader(t *testing.T) {
	t.Parallel()
	// The reporting readers pass no flag: for them the drop IS the whole disposition.
	sc := NewLineScanner(strings.NewReader("{\"a\":1}\n{\"b\":2"), nil)
	var got []string
	for sc.Scan() {
		got = append(got, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 || got[0] != `{"a":1}` {
		t.Fatalf("the torn fragment must not be handed to a reader, got %q", got)
	}

	torn := false
	sc = NewLineScanner(strings.NewReader("{\"a\":1}\n{\"b\":2"), &torn)
	for sc.Scan() { //nolint:revive // draining is the point
	}
	if !torn {
		t.Error("a caller that passes a flag must be told the stream ended mid-record")
	}

	torn = false
	sc = NewLineScanner(strings.NewReader("{\"a\":1}\n"), &torn)
	for sc.Scan() { //nolint:revive // draining is the point
	}
	if torn {
		t.Error("a newline-terminated stream is not torn")
	}
}
