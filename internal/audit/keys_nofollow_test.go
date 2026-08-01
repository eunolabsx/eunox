// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The HMAC key is the one audit file whose redirection is unrecoverable: whoever chooses
// the key chooses what verifies, so a key read through an attacker-planted symlink signs a
// tape the attacker can forge and audit-verify confirms. Every other file in this package
// pairs the Lstat guard with O_NOFOLLOW; the key was read with a plain os.ReadFile.

func writeTestKey(t *testing.T, path string) {
	t.Helper()
	key := strings.Repeat("ab", 32)
	if _, err := hex.DecodeString(key); err != nil {
		t.Fatalf("test key is not hex: %v", err)
	}
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func symlinkedKeyPath(t *testing.T) (linkPath, realPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated privileges on Windows")
	}
	dir := t.TempDir()
	realPath = filepath.Join(dir, "real.key")
	writeTestKey(t, realPath)
	linkPath = filepath.Join(dir, "audit.key")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
	return linkPath, realPath
}

func TestLoadOrCreateKeys_RefusesSymlinkedKeyFile(t *testing.T) {
	linkPath, realPath := symlinkedKeyPath(t)

	_, err := LoadOrCreateKeys(linkPath)
	if err == nil {
		t.Fatal("LoadOrCreateKeys must refuse a symlinked key file: following it lets whoever planted the link choose the signing key")
	}
	if !strings.Contains(err.Error(), EnvAuditKeyAllowSymlink) {
		t.Errorf("the refusal must name the secret-mount opt-out %s, got: %v", EnvAuditKeyAllowSymlink, err)
	}
	// The refusal must not have minted a key over the link (which would write through
	// to the target) or otherwise disturbed it.
	if _, err := os.Lstat(linkPath); err != nil {
		t.Errorf("the link itself must be left in place: %v", err)
	}
	data, err := os.ReadFile(realPath) //nolint:gosec // G304: test-owned temp path
	if err != nil || !strings.HasPrefix(string(data), strings.Repeat("ab", 32)) {
		t.Errorf("the symlink target must be left untouched, got %q (err %v)", string(data), err)
	}
}

func TestLoadKeys_RefusesSymlinkedKeyFile(t *testing.T) {
	linkPath, _ := symlinkedKeyPath(t)

	if _, err := LoadKeys(linkPath); err == nil {
		t.Fatal("LoadKeys must refuse a symlinked key file")
	}
}

// The documented escape hatch: a projected secret mount publishes each key as a symlink
// into a timestamped ..data directory, so refusing outright would break that deployment
// shape. With the opt-out set the key loads.
func TestLoadOrCreateKeys_SymlinkOptOutAcceptsSecretMountShape(t *testing.T) {
	linkPath, _ := symlinkedKeyPath(t)
	t.Setenv(EnvAuditKeyAllowSymlink, "1")

	keys, err := LoadOrCreateKeys(linkPath)
	if err != nil {
		t.Fatalf("with %s=1 a symlinked key must load: %v", EnvAuditKeyAllowSymlink, err)
	}
	if len(keys) != 1 || hex.EncodeToString(keys[0]) != strings.Repeat("ab", 32) {
		t.Fatalf("loaded the wrong key material: %x", keys)
	}
}

// The opt-out relaxes ONLY the symlink rule. A key path that RESOLVES to something that is
// not a regular file stays refused, checked through the open handle so there is no second
// path resolution to race: with the Lstat guard skipped, the handle check is the only
// thing standing between the opt-out and a device or FIFO whose read never returns.
func TestLoadOrCreateKeys_OptOutStillRefusesNonRegularTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "not-a-file")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.Symlink(target, keyPath); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
	t.Setenv(EnvAuditKeyAllowSymlink, "1")

	_, err := LoadOrCreateKeys(keyPath)
	if err == nil {
		t.Fatal("a key path resolving to a non-regular file must be refused even with the symlink opt-out set")
	}
	if !strings.Contains(err.Error(), "non-regular") {
		t.Errorf("error should name the non-regular resolution, got: %v", err)
	}
}

// A key file that is not a key file at all must not be buffered wholesale.
func TestLoadOrCreateKeys_RefusesOversizeKeyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(keyPath, make([]byte, maxAuditKeyFileBytes+1), 0o600); err != nil {
		t.Fatalf("write oversize file: %v", err)
	}
	if _, err := LoadOrCreateKeys(keyPath); err == nil {
		t.Fatal("an oversize key file must be refused")
	}
}

// The mode tightening now runs through the open handle rather than the path, but it must
// still tighten a loose key file (and still not widen a tight one).
func TestLoadOrCreateKeys_TightensThroughHandle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-mode bits are not meaningful on Windows")
	}
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	writeTestKey(t, keyPath)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("loosen key mode: %v", err)
	}

	if _, err := LoadOrCreateKeys(keyPath); err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := info.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("key mode after load = %#o, want group/world bits cleared", got)
	}
}

func TestAuditKeySymlinkAllowed_ParsesTruthyValues(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", " Yes "} {
		t.Setenv(EnvAuditKeyAllowSymlink, v)
		if !auditKeySymlinkAllowed() {
			t.Errorf("%q must enable the opt-out", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "maybe"} {
		t.Setenv(EnvAuditKeyAllowSymlink, v)
		if auditKeySymlinkAllowed() {
			t.Errorf("%q must NOT enable the opt-out (fail closed on anything but an explicit yes)", v)
		}
	}
}
