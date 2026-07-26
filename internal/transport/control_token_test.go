// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlToken_GenerateWriteResolve_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.token")

	tok, err := GenerateControlToken()
	if err != nil {
		t.Fatalf("GenerateControlToken: %v", err)
	}
	if len(tok) != 64 { // 32 random bytes, hex-encoded
		t.Fatalf("token length = %d, want 64 hex chars", len(tok))
	}

	written, err := WriteControlTokenFile(path, tok)
	if err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	if written != path {
		t.Errorf("written path = %q, want %q", written, path)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 0600 (control token is a secret)", perm)
	}

	got, err := ResolveControlToken("", path)
	if err != nil {
		t.Fatalf("ResolveControlToken: %v", err)
	}
	if got != tok {
		t.Errorf("resolved token = %q, want %q (round-trip, trailing newline trimmed)", got, tok)
	}
}

func TestWriteControlTokenFile_OverwritesLooseModeWith0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.token")
	// Pre-create the file world-readable (0644) to simulate a stale/loose file;
	// the atomic temp-then-rename write must still land the secret at 0600.
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
	if _, err := WriteControlTokenFile(path, "newtoken"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 0600 even when the pre-existing file was 0644", perm)
	}
	got, err := ResolveControlToken("", path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "newtoken" {
		t.Errorf("token = %q, want newtoken", got)
	}
}

func TestResolveControlToken_FlagBeatsEnvAndFile(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "from-env")
	got, err := ResolveControlToken("from-flag", "/nonexistent/path")
	if err != nil {
		t.Fatalf("ResolveControlToken: %v", err)
	}
	if got != "from-flag" {
		t.Errorf("got %q, want from-flag (explicit flag must win)", got)
	}
}

func TestResolveControlToken_EnvBeatsFile(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "from-env")
	got, err := ResolveControlToken("", "/nonexistent/path")
	if err != nil {
		t.Fatalf("ResolveControlToken: %v", err)
	}
	if got != "from-env" {
		t.Errorf("got %q, want from-env", got)
	}
}

func TestResolveControlToken_WhitespaceOnlyEnv_FallsThroughToFile(t *testing.T) {
	// A whitespace-only EUNOX_CONTROL_TOKEN (e.g. a lone newline) must not
	// short-circuit with an empty token: it should fall through to the file
	// source, mirroring the flag arm's trim-then-test behavior.
	t.Setenv("EUNOX_CONTROL_TOKEN", "  \n\t ")
	path := filepath.Join(t.TempDir(), "control.token")
	if _, err := WriteControlTokenFile(path, "file-token"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	got, err := ResolveControlToken("", path)
	if err != nil {
		t.Fatalf("ResolveControlToken: %v", err)
	}
	if got != "file-token" {
		t.Errorf("got %q, want file-token (whitespace-only env must fall through to file)", got)
	}
}

func TestWriteControlTokenFile_DoesNotMutatePreexistingDirMode(t *testing.T) {
	// A PRE-EXISTING directory eunox did not create must NOT be force-chmod'd: doing so
	// could strip /tmp's sticky bit as root or fail with EPERM on a dir the user doesn't
	// own. The write must succeed and LEAVE the 0755 mode intact (a warning is emitted to
	// stderr, which the operator can act on).
	dir := filepath.Join(t.TempDir(), "eunox")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.token")
	if _, err := WriteControlTokenFile(path, "tok"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("dir mode = %o, want it LEFT at 0755 (eunox must not chmod a pre-existing dir it did not create)", perm)
	}
}

func TestWriteControlTokenFile_TightensDirItCreatesTo0700(t *testing.T) {
	// A directory eunox itself creates (via MkdirAll) IS at 0700 — the guarantee still
	// holds for a path eunox owns.
	base := t.TempDir()
	dir := filepath.Join(base, "created-by-eunox")
	path := filepath.Join(dir, "control.token")
	if _, err := WriteControlTokenFile(path, "tok"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir mode = %o, want 0700 for a directory eunox created", perm)
	}
}

func TestWriteControlTokenFile_WarnsOnPreexistingLooseDir(t *testing.T) {
	// The compensating control for NOT chmod'ing a pre-existing dir is a stderr WARNING;
	// assert it actually fires so a future change cannot silently drop or narrow the only
	// signal left to the operator once the 0700 force-chmod was removed. A group-only
	// (0750) fixture pins the GROUP leg of the 0o077 mask specifically: narrowing the check
	// to 0o007 (world-only) would stop warning here and fail this test.
	dir := filepath.Join(t.TempDir(), "eunox")
	if err := os.Mkdir(dir, 0o750); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}

	// Capture os.Stderr for the duration of the write.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	_, writeErr := WriteControlTokenFile(filepath.Join(dir, "control.token"), "tok")
	os.Stderr = origStderr
	_ = w.Close()

	if writeErr != nil {
		t.Fatalf("WriteControlTokenFile: %v", writeErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); !strings.Contains(got, "WARNING") || !strings.Contains(got, "group/world-accessible") {
		t.Errorf("expected a group/world-accessible WARNING on stderr for a pre-existing 0750 dir, got %q", got)
	}
}

func TestResolveControlToken_MissingFile_Errors(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "") // isolate from ambient env
	if got, err := ResolveControlToken("", filepath.Join(t.TempDir(), "absent.token")); err == nil {
		t.Fatalf("expected error for missing token file, got token %q", got)
	}
}

func TestResolveControlToken_EmptyFile_Errors(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "")
	path := filepath.Join(t.TempDir(), "empty.token")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveControlToken("", path); err == nil {
		t.Fatal("expected error for empty token file")
	}
}

func TestExpandHome_WithTilde(t *testing.T) {
	t.Parallel()
	home, _ := os.UserHomeDir()
	result, err := expandHome("~/foo/bar")
	if err != nil {
		t.Fatalf("expandHome(~/foo/bar) error: %v", err)
	}
	expected := fmt.Sprintf("%s/foo/bar", home)
	if result != expected {
		t.Errorf("expandHome(~/foo/bar) = %q, want %q", result, expected)
	}
}

// TestExpandHome_BareTilde regression: a path of exactly "~" (no
// trailing slash) must expand to the home directory, not be returned unchanged —
// otherwise openAuditSink would MkdirAll a directory literally named "~" under the
// CWD and silently misdirect the tamper-evident audit log there.
func TestExpandHome_BareTilde(t *testing.T) {
	t.Parallel()
	home, _ := os.UserHomeDir()
	result, err := expandHome("~")
	if err != nil {
		t.Fatalf("expandHome(~) error: %v", err)
	}
	if result != home {
		t.Errorf("expandHome(~) = %q, want %q", result, home)
	}
}

func TestExpandHome_NoTilde(t *testing.T) {
	t.Parallel()
	result, err := expandHome("/absolute/path")
	if err != nil {
		t.Fatalf("expandHome(/absolute/path) error: %v", err)
	}
	if result != "/absolute/path" {
		t.Errorf("expandHome(/absolute/path) = %q, want /absolute/path", result)
	}
}

func TestExpandHome_EmptyString(t *testing.T) {
	t.Parallel()
	result, err := expandHome("")
	if err != nil {
		t.Fatalf("expandHome('') error: %v", err)
	}
	if result != "" {
		t.Errorf("expandHome('') = %q, want ''", result)
	}
}

// TestExpandHome_HomeUnavailableFailsClosed regression: when the home
// directory cannot be resolved, expandHome must return an error (so openAuditSink
// refuses to start) rather than silently returning the literal "~/..." path, which
// would misplace the tamper-evident audit log under a "~" directory in the CWD.
func TestExpandHome_HomeUnavailableFailsClosed(t *testing.T) {
	// os.UserHomeDir reads $HOME on unix; clearing it makes resolution fail.
	t.Setenv("HOME", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("os.UserHomeDir still resolves with HOME unset on this platform; cannot exercise the failure path")
	}
	got, err := expandHome("~/.eunox/audit.jsonl")
	if err == nil {
		t.Fatalf("expandHome returned (%q, nil); want an error when the home dir is unavailable", got)
	}
	if got != "" {
		t.Errorf("expandHome returned path %q alongside the error; want empty so a caller cannot use a misresolved path", got)
	}
}

// TestWriteControlTokenFile_TightensEunoxOwnedDir is the upgrade regression: eunox's own
// control-token directory (the default ~/.eunox) left at 0755 by an older version must be
// tightened back to 0700, not merely warned about. Nothing else writes that directory, so
// there is no shared-use case a chmod could break.
func TestWriteControlTokenFile_TightensEunoxOwnedDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".eunox")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The upgrade shape: an older version left this directory group/world-readable.
	// Chmod explicitly, since Mkdir's mode is umask-masked.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}

	if _, err := WriteControlTokenFile("", "tok"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode = %o, want 0700 — eunox's own control-token directory must be tightened, not just warned about", perm)
	}
}

// TestWriteControlTokenFile_RefusesWorldWritableOperatorDir: eunox must not chmod a
// directory the operator chose (doing so would strip /tmp's sticky bit), but it must also
// not drop the emergency-stop credential into a directory any local user can rename files
// in — they could substitute their own token and take over /control/kill. Fail closed.
func TestWriteControlTokenFile_RefusesWorldWritableOperatorDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Chmod explicitly: Mkdir's mode is masked by the process umask, so 0777 there
	// commonly lands as 0755 and the test would assert nothing.
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}

	_, err := WriteControlTokenFile(filepath.Join(dir, "control.token"), "tok")
	if err == nil {
		t.Fatal("expected a fail-closed error for a world-writable, non-sticky control-token directory")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Errorf("error = %v, want it to name the writable directory", err)
	}
}

// TestWriteControlTokenFile_AllowsStickyOperatorDir: /tmp is 1777, and the sticky bit is
// exactly what stops another user renaming the token file away, so a sticky directory
// must still be usable (warned about, not refused).
func TestWriteControlTokenFile_AllowsStickyOperatorDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tmplike")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// 1777, the /tmp shape. Set via Chmod because Mkdir's mode is umask-masked.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}

	path := filepath.Join(dir, "control.token")
	if _, err := WriteControlTokenFile(path, "tok"); err != nil {
		t.Fatalf("a sticky world-writable directory must remain usable, got %v", err)
	}
	got, err := ResolveControlToken("", path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "tok" {
		t.Errorf("token = %q, want tok", got)
	}
}

// TestWriteControlTokenFile_WarnsButAllowsReadableOperatorDir: a 0755 operator-chosen
// directory leaves the 0600 token file unreadable to others, so it stays a warning.
func TestWriteControlTokenFile_WarnsButAllowsReadableOperatorDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "readable")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Chmod explicitly: Mkdir's mode is umask-masked, so the fixture must set it.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}

	path := filepath.Join(dir, "control.token")
	if _, err := WriteControlTokenFile(path, "tok"); err != nil {
		t.Fatalf("a group/world-readable operator directory must remain usable, got %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("directory mode = %o, want 0755 left untouched — eunox must not chmod a directory the operator chose", perm)
	}
}

// TestWriteControlTokenFile_NeverChmodsThroughSymlink: os.Chmod follows symlinks and
// there is no portable lchmod, so tightening a symlinked ~/.eunox would rewrite the mode
// of whatever it points at. The classic shape is an operator (or an attacker with write
// access to a shared home) linking ~/.eunox at a directory eunox does not own; chmod'ing
// it to 0700 would strip that directory's own access system-wide.
func TestWriteControlTokenFile_NeverChmodsThroughSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	target := filepath.Join(home, "shared")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	// 1777, the /tmp shape: sticky, so it passes the writable refusal and would reach
	// the chmod if the symlink were not detected.
	if err := os.Chmod(target, 0o777|os.ModeSticky); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".eunox")); err != nil {
		t.Fatal(err)
	}

	if _, err := WriteControlTokenFile("", "tok"); err != nil {
		t.Fatalf("a symlinked control-token directory must remain usable, got %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o777 {
		t.Errorf("symlink target mode = %o, want 0777 untouched — eunox must never chmod through a link", perm)
	}
	if info.Mode()&os.ModeSticky == 0 {
		t.Error("the symlink target lost its sticky bit: the chmod fired through the link")
	}
}

// TestWriteControlTokenFile_TightensDefaultDirSpelledAbsolutely: "eunox's own directory"
// is a location, not a spelling. A systemd unit cannot write "~", and an interactive
// shell expands it before eunox sees the argument — so keying the upgrade repair on the
// raw flag string skipped exactly the deployments most likely to need it.
func TestWriteControlTokenFile_TightensDefaultDirSpelledAbsolutely(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".eunox")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}

	// The absolute spelling of the default path, as a unit file or an expanding shell
	// would pass it.
	if _, err := WriteControlTokenFile(filepath.Join(dir, "control.token"), "tok"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode = %o, want 0700 — the upgrade repair must key on the location, not the spelling", perm)
	}
}
