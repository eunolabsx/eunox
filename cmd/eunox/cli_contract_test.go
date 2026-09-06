// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestCmdInit_ForceWithoutOutput pins the binary-wide unpaired-flag rule (stated at
// cmdContracts' own --role/--statement guard) on init's --force: with the manifest going to
// stdout there is no file to overwrite, so the flag is a no-op and an operator who believed
// they had named an --output gets the manifest on stdout with nothing saying otherwise.
//
// The exit code alone proves nothing here — initFailExit is the command's one failure code,
// a failed upstream fetch included — so this asserts on the message AND on the upstream never
// being contacted, which is
// the second half of the guard's placement (rejecting after the introspection would make the
// operator wait out the whole probe to be told their flags were incoherent).
func TestCmdInit_ForceWithoutOutput(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"t"}}}`))
	}))
	defer srv.Close()

	var code int
	errOut := captureStderr(t, func() {
		code = cmdInit([]string{"--upstream-url", srv.URL, "--force"})
	})

	if code != initFailExit {
		t.Errorf("exit = %d, want %d (--force without --output)", code, initFailExit)
	}
	if !strings.Contains(errOut, "--force requires --output") {
		t.Errorf("stderr = %q, want it to name the unpaired flag", errOut)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("upstream was contacted %d time(s); an incoherent invocation must be refused before the introspection", n)
	}
}

// TestCmdSuggest_ForceWithoutOutput is init's twin one command over: the draft goes to stdout
// with no --output, so --force names nothing. Refused before the tape is opened, which the
// unreadable --audit-log proves: reaching the chain open would report the missing log instead.
func TestCmdSuggest_ForceWithoutOutput(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "no-such-audit.jsonl")

	var code int
	errOut := captureStderr(t, func() {
		code = cmdSuggest([]string{"--audit-log", absent, "--force"})
	})

	if code != suggestUsageExit {
		t.Errorf("exit = %d, want %d (--force without --output)", code, suggestUsageExit)
	}
	if !strings.Contains(errOut, "--force requires --output") {
		t.Errorf("stderr = %q, want it to name the unpaired flag rather than the unreadable log", errOut)
	}
}

// TestCmdInitSuggest_ForceWithOutputStillAccepted is the other side of the guard: --force is
// what makes an intentional overwrite possible, so refusing the unpaired form must not have
// narrowed the paired one.
func TestCmdInitSuggest_ForceWithOutputStillAccepted(t *testing.T) {
	dir := t.TempDir()
	logPath := writeTempFile(t, auditAllowToolLine(t, "read_file", map[string]interface{}{"path": "/tmp/a"}))
	out := filepath.Join(dir, "draft.yaml")

	if code := cmdSuggest([]string{"--audit-log", logPath, "--output", out}); code != 0 {
		t.Fatalf("first write: exit = %d, want 0", code)
	}
	// Without --force the pre-existing file is the refusal; with it, the overwrite lands.
	if code := cmdSuggest([]string{"--audit-log", logPath, "--output", out}); code != suggestUsageExit {
		t.Errorf("overwrite without --force: exit = %d, want %d", code, suggestUsageExit)
	}
	if code := cmdSuggest([]string{"--audit-log", logPath, "--output", out, "--force"}); code != 0 {
		t.Errorf("overwrite with --force: exit = %d, want 0", code)
	}
}

// TestCmdSuggest_DocumentedExitCodesAreReachable pins the usage block against the code it
// describes. suggest's help and its exit-code constant both used to document exit 1 for a
// failed --output write while every failure path returns 2, so the one code a script could
// have written a branch against was unreachable — a contract nothing could ever satisfy is
// worse than an undocumented one, because it reads as deliberate.
func TestCmdSuggest_DocumentedExitCodesAreReachable(t *testing.T) {
	logPath := writeTempFile(t, auditAllowToolLine(t, "read_file", map[string]interface{}{"path": "/tmp/a"}))

	// A refused --output: the failure the help attributed to exit 1.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	_ = captureStderr(t, func() {
		code = cmdSuggest([]string{"--audit-log", logPath, "--output", filepath.Join(blocker, "m.yaml")})
	})
	if code != suggestUsageExit {
		t.Errorf("refused --output: exit = %d, want %d", code, suggestUsageExit)
	}

	help := captureStdout(t, func() {
		if hcode := cmdSuggest([]string{"-h"}); hcode != 0 {
			t.Errorf("-h must exit 0, got %d", hcode)
		}
	})
	if !strings.Contains(help, "Exit codes:") {
		t.Fatalf("suggest usage must document its exit codes; got:\n%s", help)
	}
	// Every failure path here returns suggestUsageExit, so an exit-1 line in the block names
	// an outcome no invocation can produce.
	for _, line := range strings.Split(help, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "1 ") {
			t.Errorf("suggest documents an unreachable exit code: %q", strings.TrimSpace(line))
		}
	}
}
