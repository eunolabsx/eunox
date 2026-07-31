// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package transport

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestKillUpstreamProcess_ReapsWrapperGrandchild is the regression for the teardown
// gap: MCP servers are conventionally launched through a wrapper (`npx some-server`,
// `uvx ...`, a shell script) that forks the real server as a GRANDCHILD inheriting the
// same stdout pipe. Killing only the direct child left that grandchild running with
// the pipe open, so the EOF both bounded stdio teardowns wait for never arrived and a
// shutdown built to bound a wedged upstream hung instead.
//
// The pipe is the assertion, not the process table: this reads the upstream's stdout
// to EOF after the kill, which is exactly what readUpstream does. An orphan holding
// the write end blocks that read forever.
func TestKillUpstreamProcess_ReapsWrapperGrandchild(t *testing.T) {
	t.Parallel()

	// A wrapper that forks a long-lived grandchild inheriting stdout, then exits —
	// leaving the grandchild as the only holder of the pipe's write end. `exec` on the
	// sleep makes the grandchild replace the subshell so no extra layer survives.
	script := filepath.Join(t.TempDir(), "wrapper.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n( exec sleep 300 ) &\necho ready\nsleep 300\n"), 0o700); err != nil { //nolint:gosec // G306: test-controlled temp dir; the script must be executable
		t.Fatalf("write wrapper: %v", err)
	}

	cmd := exec.Command("/bin/sh", script)
	ConfigureUpstreamCmd(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		killUpstreamProcess(cmd.Process)
		_ = cmd.Wait()
	})

	// Wait until the grandchild has certainly been forked and holds the pipe.
	buf := make([]byte, len("ready\n"))
	if _, err := readFull(out, buf); err != nil {
		t.Fatalf("reading wrapper readiness: %v", err)
	}

	killUpstreamProcess(cmd.Process)

	// Drain to EOF, bounded. With only the direct child killed, the grandchild keeps
	// the write end open and this read never returns.
	eof := make(chan struct{})
	go func() {
		defer close(eof)
		drain := make([]byte, 256)
		for {
			if _, err := out.Read(drain); err != nil {
				return
			}
		}
	}()
	select {
	case <-eof:
	case <-time.After(10 * time.Second):
		t.Fatal("upstream stdout never reached EOF after the kill: a wrapper-spawned grandchild still holds the pipe, so every post-kill wait in the teardown paths would hang here")
	}
}

// TestConfigureUpstreamCmd_PlacesUpstreamInItsOwnGroup pins the spawn half. The group
// kill is only safe because the child is its own group LEADER — kill(-pid) against a
// child left in the parent's group would signal the PROXY'S group and take the proxy
// down with it. That invariant is what makes ConfigureUpstreamCmd, not each spawn
// site, the place the placement happens.
func TestConfigureUpstreamCmd_PlacesUpstreamInItsOwnGroup(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("/bin/sh", "-c", "sleep 300")
	ConfigureUpstreamCmd(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		killUpstreamProcess(cmd.Process)
		_ = cmd.Wait()
	})

	pgid, err := getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("getpgid: %v", err)
	}
	if pgid != cmd.Process.Pid {
		t.Errorf("upstream pgid = %d, want its own pid %d — it is not a group leader, so a group-targeted kill would reach the proxy's own group", pgid, cmd.Process.Pid)
	}
	if pgid == os.Getpid() {
		t.Error("upstream shares the test process's group")
	}
}

// readFull fills buf from r, returning the first error. io.ReadFull without the import
// churn of a single-use dependency in a build-tagged file.
func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		c, err := r.Read(buf[n:])
		n += c
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
