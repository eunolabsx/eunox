// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Additional white-box coverage for the audit package: key/path resolution and
// "~" home expansion, LoadOrCreateKeys / generateAndPersistAuditKey round-trips,
// NewVerifier construction, VerifyLog over good and tampered logs, rotation +
// retention pruning, target-field derivation, the steady-state drain fsync via
// the public Sink API, syncDir's open-failure path, and readLastAuditLine over a
// large tail. These exercise branches the existing tests do not reach; they live
// in a separate file so the existing suites are untouched.

package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// errReader is an io.Reader that fails after returning some bytes, used to drive
// VerifyLog's scanner-error return path.
type errReader struct {
	data []byte
	off  int
	err  error
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.off < len(e.data) {
		n := copy(p, e.data[e.off:])
		e.off += n
		return n, nil
	}
	return 0, e.err
}

// TestNewVerifier_BuildsKeyringAndVerifies covers NewVerifier (previously 0%):
// the constructor must index every supplied key by its id and produce a Sink whose
// VerifyRecord validates a record signed by any key in the ring. An empty slice
// yields a keyring that verifies nothing.
func TestNewVerifier_BuildsKeyringAndVerifies(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "tool:a", "tool:b")

	keys, err := LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}

	verifier := NewVerifier(keys)
	if len(verifier.verifyKeys) != 1 {
		t.Fatalf("verifyKeys ring size = %d, want 1", len(verifier.verifyKeys))
	}
	if _, ok := verifier.verifyKeys[hmacKeyID(keys[0])]; !ok {
		t.Fatal("NewVerifier keyring does not index the supplied key by its id")
	}

	// Every record in the log must verify through the constructed verifier.
	res := verifyBytes(t, logLines(t, logPath), verifier)
	if !res.OK() {
		t.Fatalf("log written by writeChainLog did not verify through NewVerifier: %+v", res)
	}

	// Close on a verify-only Sink must be a safe no-op: it has no records channel or
	// drainer, so the guarded close must not panic (close(nil) would).
	if err := verifier.Close(); err != nil {
		t.Fatalf("Close on a verifier: %v", err)
	}

	// An empty key slice yields a verifier with an empty ring (verifies nothing,
	// fails closed).
	empty := NewVerifier(nil)
	if len(empty.verifyKeys) != 0 {
		t.Fatalf("NewVerifier(nil) ring size = %d, want 0", len(empty.verifyKeys))
	}
	// The record names a key id no ring entry holds, so VerifyRecord fails closed
	// (ok=false) and now reports the distinguishing errKeyIDNotInRing rather than a
	// bare (false, nil) — the record is unverifiable, not proven tampered.
	if ok, err := empty.VerifyRecord(logLines(t, logPath)[0]); ok || !errors.Is(err, errKeyIDNotInRing) {
		t.Fatalf("empty verifier validated a record: ok=%v err=%v (want ok=false, errKeyIDNotInRing)", ok, err)
	}
}

// TestExpandHome covers expandHome's branches (previously 25%): a bare "~"
// resolves to HOME, a "~/sub" joins under HOME, an absolute path and a relative
// non-tilde path pass through untouched, and an unresolvable home fails closed.
func TestExpandHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cases := []struct {
		in   string
		want string
	}{
		{"~", home},
		{"~/audit.jsonl", filepath.Join(home, "audit.jsonl")},
		{"~/.eunox/audit.key", filepath.Join(home, ".eunox", "audit.key")},
		{"/etc/eunox/audit.jsonl", "/etc/eunox/audit.jsonl"}, // absolute: passthrough
		{"relative/path", "relative/path"},                   // no leading ~: passthrough
	}
	for _, c := range cases {
		got, err := expandHome(c.in)
		if err != nil {
			t.Fatalf("expandHome(%q): unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("expandHome(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// A "~user/..." form must be REFUSED, not passed through. Go cannot resolve another
	// user's home portably, so the old passthrough treated "~alice/audit.jsonl" as an
	// ordinary relative path and silently created a directory literally named "~alice"
	// under the process cwd — putting the tamper-evident tape (or its HMAC key) somewhere
	// the operator never chose and will not think to look.
	for _, in := range []string{"~tilde-not-home", "~alice/audit.jsonl", "~root/.eunox/audit.key"} {
		if got, err := expandHome(in); err == nil {
			t.Errorf("expandHome(%q) = %q with no error; a ~user form must fail closed rather than resolve against the cwd", in, got)
		}
	}
}

// TestExpandHome_HomeUnavailable_FailsClosed verifies that when the home
// directory cannot be resolved, expandHome returns an error rather than the
// literal "~" form — so Open never writes the audit log into a directory named
// "~" under the CWD.
func TestExpandHome_HomeUnavailable_FailsClosed(t *testing.T) {
	// os.UserHomeDir reads $HOME on unix; an empty value makes it fail.
	t.Setenv("HOME", "")

	if _, err := expandHome("~"); err == nil {
		t.Fatal("expandHome(\"~\") must fail closed when the home directory is unavailable")
	}
	if _, err := expandHome("~/.eunox/audit.jsonl"); err == nil {
		t.Fatal("expandHome(\"~/...\") must fail closed when the home directory is unavailable")
	}
	// A non-tilde path must still resolve even with no home, since it never
	// consults UserHomeDir.
	if got, err := expandHome("/tmp/x"); err != nil || got != "/tmp/x" {
		t.Fatalf("expandHome(absolute) = (%q, %v), want (/tmp/x, nil) with no home", got, err)
	}
}

// TestResolveLogPath covers ResolveLogPath (previously 66.7%): an empty pref
// falls back to the built-in default (expanded under HOME), and a non-empty pref
// is honored verbatim after expansion.
func TestResolveLogPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Empty pref -> default ~/.eunox/audit.jsonl, expanded.
	got, err := ResolveLogPath("")
	if err != nil {
		t.Fatalf("ResolveLogPath(\"\"): %v", err)
	}
	want := filepath.Join(home, ".eunox", "audit.jsonl")
	if got != want {
		t.Fatalf("ResolveLogPath(\"\") = %q, want default %q", got, want)
	}

	// Explicit pref is used and expanded.
	if got, err := ResolveLogPath("~/custom.jsonl"); err != nil || got != filepath.Join(home, "custom.jsonl") {
		t.Fatalf("ResolveLogPath(\"~/custom.jsonl\") = (%q, %v)", got, err)
	}
	// An absolute explicit pref passes through.
	if got, err := ResolveLogPath("/var/log/eunox.jsonl"); err != nil || got != "/var/log/eunox.jsonl" {
		t.Fatalf("ResolveLogPath(absolute) = (%q, %v)", got, err)
	}
}

// TestResolveKeyPath covers ResolveKeyPath's flag/env/default precedence
// (previously 40%): an explicit pref wins, an empty pref falls back to
// EUNOX_AUDIT_KEY_PATH when set, and to the built-in default otherwise — each
// expanded through expandHome.
func TestResolveKeyPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Explicit pref wins over both env and default.
	t.Setenv("EUNOX_AUDIT_KEY_PATH", "/env/should/lose")
	if got, err := ResolveKeyPath("/explicit/key"); err != nil || got != "/explicit/key" {
		t.Fatalf("ResolveKeyPath(explicit) = (%q, %v), want /explicit/key", got, err)
	}

	// Empty pref falls back to the env var (expanded).
	t.Setenv("EUNOX_AUDIT_KEY_PATH", "~/env-key")
	if got, err := ResolveKeyPath(""); err != nil || got != filepath.Join(home, "env-key") {
		t.Fatalf("ResolveKeyPath(\"\") with env = (%q, %v), want %q", got, err, filepath.Join(home, "env-key"))
	}

	// Empty pref with no env var falls back to the built-in default.
	t.Setenv("EUNOX_AUDIT_KEY_PATH", "")
	if got, err := ResolveKeyPath(""); err != nil || got != filepath.Join(home, ".eunox", "audit.key") {
		t.Fatalf("ResolveKeyPath(\"\") default = (%q, %v), want %q", got, err, filepath.Join(home, ".eunox", "audit.key"))
	}
}

// TestLoadOrCreateKeys_RoundTrip covers LoadOrCreateKeys /
// generateAndPersistAuditKey: a fresh path generates and persists a single
// 32-byte key, and a subsequent load returns the very same key (the read-existing
// branch). The persisted file ends in a newline so a shell append rotation is
// safe.
func TestLoadOrCreateKeys_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "sub", "audit.key") // sub dir created by MkdirAll

	created, err := LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys (create): %v", err)
	}
	if len(created) != 1 || len(created[0]) != 32 {
		t.Fatalf("expected one 32-byte key, got %d keys", len(created))
	}

	raw := mustReadFile(t, keyPath)
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatal("persisted key file must end in a newline for safe shell append rotation")
	}
	// The persisted line must hex-decode back to the in-memory key.
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode persisted key: %v", err)
	}
	if !bytes.Equal(decoded, created[0]) {
		t.Fatal("persisted key does not match the returned in-memory key")
	}

	// A second load hits the read-existing branch and returns the same key.
	reloaded, err := LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys (reload): %v", err)
	}
	if !bytes.Equal(reloaded[0], created[0]) {
		t.Fatal("reloaded key differs from the generated key")
	}
}

// TestLoadOrCreateKeys_MultipleKeysPreserveOrder covers the multi-key read path:
// LoadOrCreateKeys returns every key in file order (active first), skipping blank
// and comment lines.
func TestLoadOrCreateKeys_MultipleKeysPreserveOrder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	active := nonZeroTestKey()
	retired := make([]byte, 32)
	for i := range retired {
		retired[i] = byte(255 - i)
	}
	content := "# leading comment\n" +
		hex.EncodeToString(active) + "\n" +
		"\n" + // blank line, skipped
		"# retired key below\n" +
		hex.EncodeToString(retired) + "\n"
	if err := os.WriteFile(keyPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	keys, err := LoadOrCreateKeys(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2 (blank/comment lines must be skipped)", len(keys))
	}
	if !bytes.Equal(keys[0], active) || !bytes.Equal(keys[1], retired) {
		t.Fatal("keys not returned in file order (active first)")
	}
}

// TestVerifyLog_GoodAndTampered drives VerifyLog over a real chained log: the
// untouched log verifies, and flipping a byte in a record's HMAC makes that
// record INVALID so the verdict fails. This also exercises the diagnostic output
// path.
func TestVerifyLog_GoodAndTampered(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "tool:a", "tool:b", "tool:c")
	verifier := verifierFor(t, keyPath)

	// Good log verifies cleanly.
	good := verifyBytes(t, logLines(t, logPath), verifier)
	if !good.OK() {
		t.Fatalf("clean log did not verify: %+v", good)
	}
	if good.Valid == 0 {
		t.Fatal("expected at least one valid record")
	}

	// Tamper with the middle record's content (flip a character in its target),
	// leaving the chain links intact: VerifyRecord recomputes the HMAC over the
	// content and must flag the mismatch.
	lines := logLines(t, logPath)
	tampered := bytes.Replace(lines[1], []byte(`"target":"tool:b"`), []byte(`"target":"tool:X"`), 1)
	if bytes.Equal(tampered, lines[1]) {
		t.Fatal("test setup: target replacement did not change the line")
	}
	lines[1] = tampered

	var out strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(lines, []byte("\n"))), verifier, "", time.Time{}, &out)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.OK() {
		t.Fatalf("tampered log unexpectedly verified clean; output:\n%s", out.String())
	}
	if res.Invalid == 0 {
		t.Fatalf("expected an INVALID record after tampering; result %+v", res)
	}
	if !strings.Contains(out.String(), "INVALID") {
		t.Fatalf("expected an INVALID diagnostic line, got:\n%s", out.String())
	}
}

// TestVerifyLog_ScannerError covers VerifyLog's error return: when the underlying
// reader fails mid-scan, VerifyLog surfaces the scanner error.
func TestVerifyLog_ScannerError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom: simulated read failure")
	// No trailing newline, so the scanner is still mid-token when Read returns the
	// error, forcing scanner.Err() to surface it.
	r := &errReader{data: []byte(`{"seq":1}`), err: sentinel}

	verifier := &Sink{key: nonZeroTestKey()}
	_, err := VerifyLog(r, verifier, "", time.Time{}, &strings.Builder{})
	if err == nil {
		t.Fatal("VerifyLog must return the scanner error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("VerifyLog error = %v, want it to wrap the sentinel", err)
	}
}

// TestVerifyLog_WithSinceFilterSkips exercises the --since reporting filter: a
// record older than the cutoff is HMAC-verified but counted as Skipped, while a
// record at-or-after the cutoff is counted Valid. The chain still verifies.
func TestVerifyLog_WithSinceFilterSkips(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Drive the record timestamps with a controllable clock so the --since cutoff
	// is deterministic.
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	var clockN int
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.now = func() time.Time {
		t := base.Add(time.Duration(clockN) * time.Hour)
		clockN++
		return t
	}
	sink.RecordAllow(context.Background(), "sess", "old", "tools/call", nil, nil, false, nil, nil)
	sink.RecordAllow(context.Background(), "sess", "new", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	verifier := verifierFor(t, keyPath)
	// Cutoff between the two records: the first (base) is skipped, the second
	// (base+1h) stays in the report window.
	cutoff := base.Add(30 * time.Minute)
	var out strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(logLines(t, logPath), []byte("\n"))),
		verifier, "", cutoff, &out)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() {
		t.Fatalf("chain must still verify with a --since filter: %+v\n%s", res, out.String())
	}
	if res.Skipped < 1 {
		t.Fatalf("expected at least one skipped (pre-cutoff) record, got %+v", res)
	}
	if res.Valid < 1 {
		t.Fatalf("expected at least one valid (post-cutoff) record, got %+v", res)
	}
}

// TestDrainFsyncSteadyState drives the public Sink API end to end so the drainer
// goroutine runs its steady-state fsync branch (queue drained, file present) and
// flushes via Close. The resulting log verifies, confirming the drain path wrote
// real signed records.
func TestDrainFsyncSteadyState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// A mix of allow and deny records through the public API so deriveTargetFields,
	// drain, writeRecord, and the steady-state fsync all run.
	sink.RecordAllow(context.Background(), "sess-1", "calc", "tools/call",
		map[string]interface{}{"x": 1}, []string{"redactFields:$.secret"}, false, nil, nil)
	sink.RecordDeny(context.Background(), "sess-1", "rm", "tools/call",
		"AUTHORIZATION_FAILED", "", map[string]interface{}{"reason": "not allowed"}, false)
	sink.RecordAllow(context.Background(), "sess-1", "memory://note", "resources/read", nil, nil, false, nil, nil)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := sink.WriteFailures(); got != 0 {
		t.Fatalf("WriteFailures = %d, want 0 on a healthy disk", got)
	}

	// The drained, signed records must verify as a chain.
	verifier := verifierFor(t, keyPath)
	res := verifyBytes(t, logLines(t, logPath), verifier)
	if !res.OK() {
		t.Fatalf("drained log did not verify: %+v", res)
	}
	if res.Total != 3 {
		t.Fatalf("expected 3 records, got %d", res.Total)
	}
}

// TestDeriveTargetFields covers deriveTargetFields and bareTargetName branches:
// the empty-method pre-dispatch case, the prompts/get prefix strip, an opaque
// resource URI kept under its method's namespace, and an unmapped method whose
// raw string is preserved with no target.
func TestDeriveTargetFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		method, ident string
		wantMethod    string
		wantType      string
		wantTarget    string
	}{
		{"empty method", "", "anything", "", "", ""},
		{"tools/call", "tools/call", "calc", "tools/call", "tool", "calc"},
		{"prompts/get strips prefix", "prompts/get", "prompts/greeting", "prompts/get", "prompt", "greeting"},
		{"resources/read keeps uri", "resources/read", "memory://x", "resources/read", "resource", "memory://x"},
		{"sampling", "sampling/createMessage", "sampling/createMessage", "sampling/createMessage", "system", "sampling/createMessage"},
		{"unmapped method preserved", "tools/execute", "calc", "tools/execute", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, tt, target := deriveTargetFields(c.method, c.ident)
			if m != c.wantMethod || tt != c.wantType || target != c.wantTarget {
				t.Errorf("deriveTargetFields(%q,%q) = (%q,%q,%q), want (%q,%q,%q)",
					c.method, c.ident, m, tt, target, c.wantMethod, c.wantType, c.wantTarget)
			}
		})
	}
}

// TestBareTargetName covers bareTargetName directly: only the prompt type strips
// the "prompts/" display prefix; every other target type passes through verbatim.
func TestBareTargetName(t *testing.T) {
	t.Parallel()
	if got := bareTargetName("prompt", "prompts/welcome"); got != "welcome" {
		t.Fatalf("prompt strip = %q, want welcome", got)
	}
	if got := bareTargetName("prompt", "welcome"); got != "welcome" {
		t.Fatalf("prompt without prefix = %q, want welcome", got)
	}
	if got := bareTargetName("tool", "prompts/looks-like-prompt"); got != "prompts/looks-like-prompt" {
		t.Fatalf("non-prompt type must not strip prefix, got %q", got)
	}
	if got := bareTargetName("resource", "memory://x"); got != "memory://x" {
		t.Fatalf("resource passthrough = %q", got)
	}
}

// TestSyncDir_OpenFailureTolerated covers syncDir's open-error branch: a
// nonexistent directory cannot be opened, which syncDir logs and tolerates
// (best-effort) rather than panicking or returning.
func TestSyncDir_OpenFailureTolerated(t *testing.T) {
	// Sequential (no t.Parallel): this test swaps the process-global os.Stderr to
	// capture syncDir's warning. Running it in parallel races every other
	// stderr-capture test under -race, so it stays in the sequential phase like the
	// other capture tests in this package (rotate_test.go, verify_test.go).
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	// Must not panic; the open failure is swallowed with a warning.
	syncDir(missing)

	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if !strings.Contains(buf.String(), "cannot open audit key dir") {
		t.Fatalf("expected an open-failure warning, got: %q", buf.String())
	}
}

// TestSyncDir_Success covers syncDir's happy path on a real directory: it opens,
// fsyncs, and closes without emitting a warning.
func TestSyncDir_Success(t *testing.T) {
	// Sequential (no t.Parallel): swaps the process-global os.Stderr, same as
	// TestSyncDir_OpenFailureTolerated.
	dir := t.TempDir()

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	syncDir(dir)

	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if strings.Contains(buf.String(), "WARN") {
		t.Fatalf("syncDir on a valid dir should not warn, got: %q", buf.String())
	}
}

// TestPruneRotated_DeletesOldestBeyondRetain covers pruneRotated's deletion path:
// with retain=2 and four genuine rotated siblings present, the two oldest are
// removed and the two newest kept, while an unrelated sibling (not matching the
// rotated stamp regex) is left untouched.
func TestPruneRotated_DeletesOldestBeyondRetain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// Four genuine rotated siblings with ascending timestamps (lexically sortable).
	stamps := []string{
		".20260101T000000.000000000Z",
		".20260102T000000.000000000Z",
		".20260103T000000.000000000Z",
		".20260104T000000.000000000Z",
	}
	for _, s := range stamps {
		if err := os.WriteFile(logPath+s, []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write rotated sibling: %v", err)
		}
	}
	// An unrelated sibling that the rotated regex must NOT match; it must survive.
	unrelated := logPath + ".backup"
	if err := os.WriteFile(unrelated, []byte("x"), 0o600); err != nil {
		t.Fatalf("write unrelated sibling: %v", err)
	}

	s := &Sink{logPath: logPath, retain: 2}
	s.pruneRotated()

	// The two oldest stamps are gone; the two newest remain.
	for i, st := range stamps {
		_, err := os.Stat(logPath + st)
		if i < 2 { // oldest two should be deleted
			if !os.IsNotExist(err) {
				t.Errorf("expected %q to be pruned, stat err = %v", logPath+st, err)
			}
		} else { // newest two should be kept
			if err != nil {
				t.Errorf("expected %q to be kept, stat err = %v", logPath+st, err)
			}
		}
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("unrelated sibling must not be pruned, stat err = %v", err)
	}
}

// TestPruneRotated_RetainZeroNoOp and the listing-error branch: retain<=0 keeps
// everything (early return), and a listing failure (the audit directory's
// readability removed) is logged, not fatal, and prunes nothing.
func TestPruneRotated_RetainZeroAndListingError(t *testing.T) {
	// Sequential (no t.Parallel): the listing-error branch below swaps the
	// process-global os.Stderr to capture the warning, which races other
	// stderr-capture tests under -race.

	// retain == 0: keep all (early return before any directory scan).
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	sib := logPath + ".20260101T000000.000000000Z"
	if err := os.WriteFile(sib, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	(&Sink{logPath: logPath, retain: 0}).pruneRotated()
	if _, err := os.Stat(sib); err != nil {
		t.Fatalf("retain=0 must keep all rotated siblings, stat err = %v", err)
	}

	// Listing error: point logPath into a directory that does not exist so
	// rotatedSiblings' ReadDir fails; pruneRotated must log and return without
	// panicking.
	missingDir := filepath.Join(dir, "nope")
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	(&Sink{logPath: filepath.Join(missingDir, "audit.jsonl"), retain: 1}).pruneRotated()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if !strings.Contains(buf.String(), "could not list rotated siblings") {
		t.Fatalf("expected a listing-failure warning, got: %q", buf.String())
	}
}

// TestRotationViaPublicAPI exercises a real size-triggered rotation through the
// public Sink API with a tiny rotateSizeBytes and retain=1: records written past
// the threshold rotate the active log, pruning leaves at most one rotated
// sibling, and the full chain (across the rotated file and the base) verifies.
func TestRotationViaPublicAPI(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// A small threshold so each record forces a rotation; retain 1 bounds siblings.
	sink, err := Open(logPath, keyPath, 256, 1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < 8; i++ {
		sink.RecordAllow(context.Background(), "sess", fmt.Sprintf("tool-%d", i), "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// At least one rotated sibling must exist, and retention must bound them to 1.
	sibs, _, err := scanLogDir(logPath)
	if err != nil {
		t.Fatalf("scanLogDir: %v", err)
	}
	var genuine int
	for _, s := range sibs {
		if rotatedAuditRe.MatchString(s[len(logPath):]) {
			genuine++
		}
	}
	if genuine == 0 {
		t.Fatal("expected at least one rotated sibling after many small-threshold writes")
	}
	if genuine > 1 {
		t.Fatalf("retain=1 must bound rotated siblings to 1, got %d", genuine)
	}

	// The newest rotated sibling concatenated with the base must verify as one
	// continuous chain (rotation carries seq/prev_hmac across files).
	newest := newestRotatedSibling(logPath)
	if newest == "" {
		t.Fatal("no newest rotated sibling found")
	}
	combined := append(logLines(t, newest), logLines(t, logPath)...)
	verifier := verifierFor(t, keyPath)
	res := verifyBytes(t, combined, verifier)
	if !res.OK() {
		t.Fatalf("chain across rotated sibling + base did not verify: %+v", res)
	}
}

// TestReadLastAuditLine_LargeTail covers readLastAuditLine over a file larger
// than a trivial size: it must return the last non-blank line. The records are
// written through the sink so the tail is a real signed record.
func TestReadLastAuditLine_LargeTail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var lastTool string
	for i := 0; i < 200; i++ {
		lastTool = fmt.Sprintf("tool-%d", i)
		sink.RecordAllow(context.Background(), "sess", lastTool, "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	last := mustReadLastAuditLine(t, logPath)
	if last == "" {
		t.Fatal("readLastAuditLine returned empty on a populated log")
	}
	if !strings.Contains(last, lastTool) {
		t.Fatalf("last line does not contain the final tool %q: %s", lastTool, last)
	}

	// A genuinely empty file returns ("", nil).
	emptyPath := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	if line := mustReadLastAuditLine(t, emptyPath); line != "" {
		t.Fatalf("empty file: got %q, want \"\"", line)
	}

	// An absent file returns ("", nil) too (the brand-new-install case).
	if line, err := readLastAuditLine(filepath.Join(dir, "absent.jsonl")); err != nil || line != "" {
		t.Fatalf("absent file: got (%q, %v), want (\"\", nil)", line, err)
	}
}

// TestReadLastAuditLine_BlankTrailingLines covers the blank-line trimming: a log
// whose final bytes are several empty (newline-only) lines must still return the
// last non-blank record line. interpretAuditTail TrimRights trailing newlines, so
// pure-newline trailing blanks are skipped.
func TestReadLastAuditLine_BlankTrailingLines(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	content := `{"seq":1,"target":"first"}` + "\n" +
		`{"seq":2,"target":"last"}` + "\n\n\n\n"
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	last := mustReadLastAuditLine(t, logPath)
	if !strings.Contains(last, `"target":"last"`) {
		t.Fatalf("got %q, want the last non-blank line", last)
	}
}

// TestJSONEncodedStringLen covers jsonEncodedStringLen: a plain string is its
// byte length plus two quotes, and an escape-heavy string expands (quotes,
// backslashes, control characters all grow under JSON encoding).
func TestJSONEncodedStringLen(t *testing.T) {
	t.Parallel()
	if got := jsonEncodedStringLen("abc"); got != len(`"abc"`) {
		t.Fatalf("jsonEncodedStringLen(\"abc\") = %d, want %d", got, len(`"abc"`))
	}
	if got := jsonEncodedStringLen(""); got != 2 {
		t.Fatalf("jsonEncodedStringLen(\"\") = %d, want 2 (just the quotes)", got)
	}
	// A quote and a control char both escape, so the encoded length exceeds raw+2.
	in := "\"\n\t\\"
	got := jsonEncodedStringLen(in)
	if got <= len(in)+2 {
		t.Fatalf("escape-heavy length = %d, want > raw+quotes (%d)", got, len(in)+2)
	}
}

// TestTruncatedObligations_Bounds covers truncatedObligations directly,
// including the shrink loop (kept entries that, with the sentinel, exceed the cap
// must be dropped one at a time until the result fits) and the lone-sentinel
// path (a huge "total" with no kept entries still returns the smallest marker).
func TestTruncatedObligations_Bounds(t *testing.T) {
	t.Parallel()

	// A normal truncation that already fits: kept prefix plus the
	// "obligations_truncated:N" sentinel, within the cap, no shrinking needed.
	kept := []string{"a", "b", "c"}
	out := truncatedObligations(kept, 10)
	if len(out) != len(kept)+1 {
		t.Fatalf("got %d entries, want kept(%d)+sentinel", len(out), len(kept))
	}
	if out[len(out)-1] != "obligations_truncated:7" {
		t.Fatalf("sentinel = %q, want obligations_truncated:7", out[len(out)-1])
	}

	// Shrink loop: a kept slice that on its own already exceeds the cap forces
	// truncatedObligations to drop trailing entries until the re-marshaled result
	// (kept prefix + sentinel) fits within auditObligationsTotalCap. Build entries
	// summing well past 64 KiB so several must be dropped.
	const entry = 4096
	bigKept := make([]string, 32) // 32 * 4096 = 128 KiB raw, over the 64 KiB cap
	for i := range bigKept {
		bigKept[i] = strings.Repeat("z", entry)
	}
	shrunk := truncatedObligations(bigKept, len(bigKept))
	encoded, err := json.Marshal(shrunk)
	if err != nil {
		t.Fatalf("marshal shrunk: %v", err)
	}
	if len(encoded) > auditObligationsTotalCap {
		t.Fatalf("shrink loop result is %d bytes, exceeds cap %d", len(encoded), auditObligationsTotalCap)
	}
	if len(shrunk) >= len(bigKept) {
		t.Fatalf("shrink loop kept %d entries, want fewer than the %d input", len(shrunk), len(bigKept))
	}
	if last := shrunk[len(shrunk)-1]; !strings.HasPrefix(last, "obligations_truncated:") {
		t.Fatalf("shrunk result missing sentinel; last = %q", last)
	}

	// Empty kept with a huge total: the lone sentinel is the smallest marker and is
	// returned regardless.
	loneOut := truncatedObligations(nil, 1<<30)
	if len(loneOut) != 1 || !strings.HasPrefix(loneOut[0], "obligations_truncated:") {
		t.Fatalf("lone-sentinel path = %v, want a single obligations_truncated marker", loneOut)
	}
}

// TestAuditDegraded_Branches covers AuditDegraded's reason strings: the healthy
// case, the failures-only case, and the combined dropped+failures case (the
// branch the existing dropped-only test does not reach). A nil receiver is
// healthy.
func TestAuditDegraded_Branches(t *testing.T) {
	t.Parallel()

	// nil receiver: healthy.
	var nilSink *Sink
	if degraded, reason, detail := nilSink.AuditDegraded(); degraded || reason != "" || detail != nil {
		t.Fatalf("nil sink: got (%v, %q, %v), want (false, \"\", nil)", degraded, reason, detail)
	}

	// Healthy sink: no drops, no failures.
	healthy := &Sink{}
	if degraded, _, detail := healthy.AuditDegraded(); degraded || detail != nil {
		t.Fatal("healthy sink reported degraded")
	}

	// Failures only: detail carries write_failure_count, not dropped_count.
	failOnly := &Sink{}
	failOnly.writeFailures.Store(3)
	degraded, reason, detail := failOnly.AuditDegraded()
	if !degraded || !strings.Contains(reason, "write failure") {
		t.Fatalf("failures-only: got (%v, %q)", degraded, reason)
	}
	if detail["write_failure_count"] != int64(3) {
		t.Fatalf("failures-only: detail = %v, want write_failure_count=3", detail)
	}
	if _, ok := detail["dropped_count"]; ok {
		t.Fatalf("failures-only: detail must omit dropped_count; got %v", detail)
	}

	// Both dropped and failures: the combined branch carries both discrete counts.
	both := &Sink{}
	both.dropped.Store(2)
	both.writeFailures.Store(5)
	degraded, reason, detail = both.AuditDegraded()
	if !degraded {
		t.Fatal("both: expected degraded")
	}
	if !strings.Contains(reason, "dropped") || !strings.Contains(reason, "write failure") {
		t.Fatalf("both: reason %q must mention dropped and write failures", reason)
	}
	if detail["dropped_count"] != int64(2) || detail["write_failure_count"] != int64(5) {
		t.Fatalf("both: detail = %v, want dropped_count=2 write_failure_count=5", detail)
	}
	if _, ok := detail["reason"]; ok {
		t.Fatalf("both: detail must not carry prose \"reason\"; got %v", detail)
	}
}

// TestOpen_NegativeRetainNormalized covers Open's retainRotated < 0 normalization
// branch: a negative retain is clamped to 0 (keep all), and the sink opens and
// writes a verifiable record.
func TestOpen_NegativeRetainNormalized(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// retainRotated = -5 must be normalized to 0.
	sink, err := Open(logPath, keyPath, 0, -5)
	if err != nil {
		t.Fatalf("Open with negative retain: %v", err)
	}
	if sink.retain != 0 {
		t.Fatalf("negative retain not normalized: got %d, want 0", sink.retain)
	}
	sink.RecordAllow(context.Background(), "sess", "tool", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	res := verifyBytes(t, logLines(t, logPath), verifierFor(t, keyPath))
	if !res.OK() {
		t.Fatalf("log did not verify: %+v", res)
	}
}

// TestGenerateAndPersistAuditKey_CreateRaceReadsWinnerKey covers the os.Link
// EEXIST branch in generateAndPersistAuditKey: when the link publish loses the
// race (the key file already exists), the starter reads back and returns the
// winner's persisted key rather than its own freshly generated one. The osLink
// seam forces the EEXIST after a valid key has been pre-published.
func TestGenerateAndPersistAuditKey_CreateRaceReadsWinnerKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	// Pre-publish a valid winner key at keyPath (the "other process linked first"
	// state). 32 non-zero bytes, hex-encoded with a trailing newline.
	winner := nonZeroTestKey()
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(winner)+"\n"), 0o600); err != nil {
		t.Fatalf("pre-publish winner key: %v", err)
	}

	orig := osLink
	t.Cleanup(func() { osLink = orig })
	// Force the link to report the target already exists, driving the
	// readPublishedAuditKeys("after create race") path.
	osLink = func(string, string) error { return os.ErrExist }

	got, err := generateAndPersistAuditKey(keyPath)
	if err != nil {
		t.Fatalf("generateAndPersistAuditKey on create race: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], winner) {
		t.Fatal("create-race path must return the pre-published winner key, not a fresh one")
	}
	// No temp files left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".audit-key-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestReadLastAuditLine_OffsetTailWindow covers the size > maxTail branch of
// readLastAuditLine: a log larger than the 4 MiB tail window must read only the
// trailing window (start = size - maxTail) and still return the true last line.
func TestReadLastAuditLine_OffsetTailWindow(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	// Build a file larger than the 4 MiB tail window with a recognizable final
	// line. A single long filler line followed by the real tail keeps it simple and
	// guarantees size > maxTail (4 MiB).
	const fillerBytes = (4 << 20) + (1 << 20) // 5 MiB of filler
	var b bytes.Buffer
	b.Grow(fillerBytes + 64)
	b.WriteString(`{"seq":1,"target":"`)
	b.Write(bytes.Repeat([]byte("a"), fillerBytes))
	b.WriteString(`"}` + "\n")
	b.WriteString(`{"seq":2,"target":"the-real-tail"}` + "\n")
	if err := os.WriteFile(logPath, b.Bytes(), 0o600); err != nil {
		t.Fatalf("write large log: %v", err)
	}

	last := mustReadLastAuditLine(t, logPath)
	if !strings.Contains(last, "the-real-tail") {
		t.Fatalf("offset tail window did not capture the true last line: %.80q", last)
	}
}

// TestLoadOrCreateKeys_NonNotExistReadError covers LoadOrCreateKeys' "read failed
// for a reason other than not-exist" branch: when keyPath is a directory,
// os.ReadFile fails with a non-IsNotExist error, which must propagate rather than
// triggering key generation.
func TestLoadOrCreateKeys_NonNotExistReadError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Make the "key path" a directory so ReadFile returns EISDIR (not IsNotExist).
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatalf("mkdir key path: %v", err)
	}
	if _, err := LoadOrCreateKeys(keyPath); err == nil {
		t.Fatal("LoadOrCreateKeys must propagate a non-not-exist read error (key path is a directory)")
	}
}

// TestLoadOrCreateKeys_CorruptFileNotRegenerated covers the parse-error branch of
// LoadOrCreateKeys: a present-but-invalid key file is a hard error, never silently
// regenerated (regeneration would invalidate every previously signed record).
func TestLoadOrCreateKeys_CorruptFileNotRegenerated(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(keyPath, []byte("not-hex-garbage\n"), 0o600); err != nil {
		t.Fatalf("write corrupt key: %v", err)
	}
	if _, err := LoadOrCreateKeys(keyPath); err == nil {
		t.Fatal("LoadOrCreateKeys must hard-error on a corrupt key file, not regenerate")
	}
	// The corrupt file must be left untouched (not overwritten).
	if got := strings.TrimSpace(string(mustReadFile(t, keyPath))); got != "not-hex-garbage" {
		t.Fatalf("corrupt key file was modified: %q", got)
	}
}

// TestRecordDeny_UnmappedMethodPreservesRawMethod drives RecordDeny with an
// unrecognized MCP method through the public API, then reads the record back to
// confirm deriveTargetFields preserved the raw method with an empty target_type —
// the post-dispatch unmapped-method branch.
func TestRecordDeny_UnmappedMethodPreservesRawMethod(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordDeny(context.Background(), "sess", "calc", "tools/execute",
		"AUTHORIZATION_FAILED", "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readAuditRecords(t, logPath)
	if len(recs) == 0 {
		t.Fatal("no records written")
	}
	last := recs[len(recs)-1]
	if last["method"] != "tools/execute" {
		t.Fatalf("method = %v, want the raw unmapped method preserved", last["method"])
	}
	if tt, ok := last["target_type"]; ok && tt != "" {
		t.Fatalf("target_type = %v, want empty for an unmapped method", tt)
	}
	if tgt, ok := last["target"]; ok && tgt != "" {
		t.Fatalf("target = %v, want empty for an unmapped method", tgt)
	}
}

// TestMarshalAndBoundDetails_NotSerializable covers marshalAndBoundDetails'
// marshal-error branch: a Details value that json.Marshal cannot encode (a
// function) must collapse the whole map to a single TruncatedKey marker rather
// than panic or produce a broken record. cloneAndBound returns the func as-is
// (default case), so the subsequent json.Marshal of the cloned map fails and the
// marker path runs. The result is the marshaled details blob (json.RawMessage).
func TestMarshalAndBoundDetails_NotSerializable(t *testing.T) {
	t.Parallel()
	in := map[string]interface{}{
		"ok":  "value",
		"bad": func() {}, // json.Marshal cannot encode a func
	}
	raw := marshalAndBoundDetails(in)
	if raw == nil {
		t.Fatal("marshalAndBoundDetails returned nil for a non-nil map")
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("marker blob is not valid JSON: %v (%s)", err, raw)
	}
	msg, ok := out[TruncatedKey]
	if !ok {
		t.Fatalf("expected the %q marker for a non-serializable map, got %v", TruncatedKey, out)
	}
	// The marker value is a STRUCTURED object carrying a stable reason code, not a
	// free-form prose string (see marshalTruncationMarker).
	info, ok := msg.(map[string]interface{})
	if !ok {
		t.Fatalf("marker value = %v (%T), want a structured object", msg, msg)
	}
	if info["reason"] != auditTruncReasonNotSerializable {
		t.Fatalf("marker reason = %v, want %q", info["reason"], auditTruncReasonNotSerializable)
	}
	// A nil or empty map still returns nil (omitempty keeps the details field absent).
	if marshalAndBoundDetails(nil) != nil {
		t.Fatal("marshalAndBoundDetails(nil) must return nil")
	}
	if marshalAndBoundDetails(map[string]interface{}{}) != nil {
		t.Fatal("marshalAndBoundDetails(empty) must return nil so details stays omitted")
	}
}

// TestWriteRecord_MarshalErrorCountsFailure covers writeRecord's marshal-error
// branch: when json.Marshal of the record fails (a Details value that cannot be
// encoded, placed directly on the record to bypass record()'s bounding), the
// record is dropped, a write failure is counted, and the chain head does not
// advance.
func TestWriteRecord_MarshalErrorCountsFailure(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	key := nonZeroTestKey()
	s := &Sink{key: key, keyID: hmacKeyID(key), maxBytes: 1 << 30, f: f}

	seqBefore := s.seq
	// Details carries invalid JSON, which json.Marshal of the record rejects (the
	// json.RawMessage field is validated on marshal). writeRecord is called directly
	// (not via record()), so the bad bytes reach json.Marshal and trigger the
	// marshal-error path — record()'s marshalAndBoundDetails produces only valid JSON.
	rec := &auditRecord{
		Decision: "allow",
		Target:   "tool:x",
		Details:  json.RawMessage("{not valid json"),
	}
	s.writeRecord(rec)

	if s.writeFailures.Load() == 0 {
		t.Fatal("expected a write failure from the marshal error")
	}
	if s.seq != seqBefore {
		t.Fatalf("chain head advanced on a marshal failure: seq %d, want %d", s.seq, seqBefore)
	}
	// Nothing should have been written to the file.
	if data := mustReadFile(t, logPath); len(data) != 0 {
		t.Fatalf("marshal-failed record was partially written: %q", data)
	}
}

// TestReadLastAuditLine_PermissionDenied covers readLastAuditLine's
// non-IsNotExist open-error branch: a file that exists but cannot be opened (no
// read permission) returns a propagated error, distinct from the ("", nil)
// brand-new-install case. Skipped when running as root, where mode bits are
// bypassed.
func TestReadLastAuditLine_PermissionDenied(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file permission bits")
	}
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(`{"seq":1}`+"\n"), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Restore a readable mode so t.TempDir cleanup can remove it.
	t.Cleanup(func() { _ = os.Chmod(logPath, 0o600) })

	got, err := readLastAuditLine(logPath)
	if err == nil {
		t.Fatalf("expected a permission error, got (%q, nil)", got)
	}
	if got != "" {
		t.Fatalf("expected empty line on open error, got %q", got)
	}
}

// TestOpen_LogPathResolveError covers Open's ResolveLogPath-error branch: a
// "~"-prefixed log path with no resolvable home directory fails closed before any
// file is created, rather than writing the audit log into a literal "~" directory.
func TestOpen_LogPathResolveError(t *testing.T) {
	t.Setenv("HOME", "") // make os.UserHomeDir fail so "~" cannot expand
	if _, err := Open("~/eunox/audit.jsonl", "/tmp/unused.key", 0, 0); err == nil {
		t.Fatal("Open must fail when the log path's home cannot be resolved")
	} else if !strings.Contains(err.Error(), "audit log path") {
		t.Fatalf("error = %v, want an 'audit log path' wrap", err)
	}
}

// TestOpen_KeyPathLoadError covers Open's LoadOrCreateKeys-error branch: when the
// resolved key path is an existing directory, key loading fails (ReadFile returns
// EISDIR) and Open propagates an 'audit key' error rather than starting.
func TestOpen_KeyPathLoadError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyDir := filepath.Join(dir, "keydir")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	if _, err := Open(logPath, keyDir, 0, 0); err == nil {
		t.Fatal("Open must fail when the key path is a directory")
	} else if !strings.Contains(err.Error(), "audit key") {
		t.Fatalf("error = %v, want an 'audit key' wrap", err)
	}
}

// TestOpen_LogDirCreateError covers Open's MkdirAll-error branch: when a path
// component of the log directory is an existing regular file, creating the log
// directory fails and Open returns a 'creating audit log directory' error.
func TestOpen_LogDirCreateError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A regular file where a directory component is expected.
	fileAsDir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	// logPath lives "inside" the regular file, so MkdirAll cannot create the parent.
	logPath := filepath.Join(fileAsDir, "sub", "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	if _, err := Open(logPath, keyPath, 0, 0); err == nil {
		t.Fatal("Open must fail when the log directory cannot be created")
	} else if !strings.Contains(err.Error(), "creating audit log directory") {
		t.Fatalf("error = %v, want a 'creating audit log directory' wrap", err)
	}
}

// TestOpen_RefusesSymlinkLogPath covers Open's non-regular-log-path guard: a log
// path that is a symlink (to a file outside the log directory, so it cannot
// simply be mistaken for an ordinary sibling) is refused rather than opened and
// appended through. Without this guard, LogChainFiles' IsRegular() directory
// filter (which exists to keep a symlink from seeding the verify chain) would
// silently exclude the symlinked log from every audit-verify run instead of
// Open ever detecting the mismatch.
func TestOpen_RefusesSymlinkLogPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real-target.jsonl")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, logPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	keyPath := filepath.Join(dir, "audit.key")
	if _, err := Open(logPath, keyPath, 0, 0); err == nil {
		t.Fatal("Open must refuse a symlinked log path")
	} else if !strings.Contains(err.Error(), "non-regular log path") {
		t.Fatalf("error = %v, want a 'non-regular log path' rejection", err)
	}
	// The symlink itself must be left untouched (not replaced by a regular file).
	if fi, err := os.Lstat(logPath); err != nil {
		t.Fatalf("lstat log path: %v", err)
	} else if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("Open must not have replaced the symlink")
	}
}

// TestGenerateAndPersistAuditKey_GenericLinkError covers the branch where
// os.Link fails with an error that is neither EEXIST (lost race) nor a
// no-hard-link error (EPERM/ENOSYS/EXDEV): a generic I/O failure must propagate
// as a publish error rather than falling back to rename or reading a winner key.
func TestGenerateAndPersistAuditKey_GenericLinkError(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")

	orig := osLink
	t.Cleanup(func() { osLink = orig })
	osLink = func(string, string) error { return errors.New("simulated generic link I/O error") }

	if _, err := generateAndPersistAuditKey(keyPath); err == nil {
		t.Fatal("a generic os.Link error must propagate as a publish failure")
	} else if !strings.Contains(err.Error(), "publishing audit key file") {
		t.Fatalf("error = %v, want a 'publishing audit key file' wrap", err)
	}
	// The key file must not exist (publish failed).
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("key file present after a failed publish: stat err = %v", err)
	}
}

// TestMarshalTruncationMarker_MarshalError covers the json.Marshal error branch:
// a value that cannot be encoded (e.g. a channel) falls back to the hardcoded
// not-serializable marker so the audit record always carries valid JSON.
func TestMarshalTruncationMarker_MarshalError(t *testing.T) {
	result := marshalTruncationMarker(map[string]interface{}{"bad": make(chan int)})
	var m map[string]interface{}
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("fallback must be valid JSON: %v", err)
	}
	trunc, ok := m[TruncatedKey].(map[string]interface{})
	if !ok {
		t.Fatalf("result must have %q key, got %v", TruncatedKey, m)
	}
	reason, _ := trunc["reason"].(string)
	if reason != auditTruncReasonNotSerializable {
		t.Errorf("reason = %q, want %q", reason, auditTruncReasonNotSerializable)
	}
}

// TestTightenKeyFileMode_AlreadyTight covers the early return when the key
// file already has no group/world bits set (perm&0o077 == 0).
func TestTightenKeyFileMode_AlreadyTight(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatalf("create key file: %v", err)
	}
	tightenKeyFileMode(keyPath)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat after tighten: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode after already-tight tighten = %#o, want 0600", got)
	}
}

// TestTightenKeyFileMode_StatError covers the os.Stat error path: a non-existent
// path causes os.Stat to fail, so tightenKeyFileMode logs a warning and returns
// without panicking.
func TestTightenKeyFileMode_StatError(t *testing.T) {
	tightenKeyFileMode(filepath.Join(t.TempDir(), "nonexistent.key"))
}

// TestTightenLogMode_StatError covers the f.Stat() error path: calling Stat on a
// closed *os.File returns "use of closed file", so tightenLogMode logs a warning
// and returns without panicking.
func TestTightenLogMode_StatError(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = f.Close()
	tightenLogMode(f, logPath)
}

// TestCloneAndBound_JSONNumber covers the json.Number case in cloneAndBound, which
// is distinct from the string case even though json.Number is a string alias —
// type-switch arms are dispatched by the concrete type, not the underlying kind.
func TestCloneAndBound_JSONNumber(t *testing.T) {
	n := json.Number("42")
	got := cloneAndBound(n)
	if got != n {
		t.Errorf("cloneAndBound(json.Number(%q)) = %v, want the same value", n, got)
	}
}
