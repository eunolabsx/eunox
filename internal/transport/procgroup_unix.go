// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package transport

import (
	"os"
	"os/exec"
	"syscall"
)

// setUpstreamProcessGroup puts the upstream subprocess in its OWN process group, so
// the whole tree it spawns can be signalled as a unit. It is the syscall half of the
// teardown whose portable half is signalUpstreamGroup/killUpstreamGroup.
//
// MCP servers are conventionally launched through a wrapper — `npx some-mcp-server`,
// `uvx ...`, a shell script — which execs or forks the real server as a GRANDCHILD
// that inherits the same stdout pipe. Signalling only the direct child leaves that
// grandchild running with the pipe still open, so the EOF the proxy's reader is
// waiting on never arrives. Both bounded-teardown paths (the startup watchdog and the
// host-EOF shutdown) end in a wait for exactly that EOF, so the mechanisms built to
// BOUND a wedged upstream would themselves hang indefinitely — skipping the audit-sink
// flush that graceful shutdown exists to perform, and leaking the orphan besides.
//
// Setpgid also detaches the upstream from the proxy's own process group, so a Ctrl-C
// in a terminal no longer reaches it directly. That is deliberate and not a
// regression: the proxy installs a signal handler and forwards the signal through
// signalUpstream, which now targets the group. Delivery goes from "the terminal
// happens to signal both, in no defined order" to "the proxy tears its upstream down
// on its own schedule, with the SIGKILL fallback it already arms".
func setUpstreamProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// signalUpstreamGroup sends sig to the process GROUP led by proc, reporting whether
// the whole group was signalled. A false return means the caller must fall back to
// signalling the direct child alone — the group may not exist (setUpstreamProcessGroup
// is best-effort: a failed Setpgid still starts the process, in the parent's group,
// where a negative-pid kill would signal the PROXY'S OWN group and take the proxy down
// with it).
//
// The ESRCH guard is what makes that safe: kill(-pid) succeeds only when a group with
// that id exists, which is true exactly when Setpgid took effect, since the child is
// the group leader and its pid IS the group id. A child in the parent's group is not a
// group leader, so no group with its pid exists and the call fails with ESRCH rather
// than signalling the proxy's group.
func signalUpstreamGroup(proc *os.Process, sig os.Signal) bool {
	// Pid <= 1, not <= 0: POSIX defines kill(-1, sig) as "every process the caller may
	// signal", NOT "the group led by pid 1". In a PID namespace where eunox spawns the
	// first process the upstream can legitimately land on pid 1, and the ESRCH argument
	// below does not cover -1 because -1 is not a group id at all — the call would
	// succeed and broadcast SIGKILL across the container.
	if proc == nil || proc.Pid <= 1 {
		return false
	}
	sysSig, ok := sig.(syscall.Signal)
	if !ok {
		return false
	}
	return syscall.Kill(-proc.Pid, sysSig) == nil
}

// killUpstreamGroup SIGKILLs the process group led by proc, reporting whether the
// group was reached. See signalUpstreamGroup for why a false return is a required
// fallback signal rather than an error.
func killUpstreamGroup(proc *os.Process) bool {
	return signalUpstreamGroup(proc, syscall.SIGKILL)
}

// getpgid returns the process-group id of pid. Test-facing: the group-kill safety
// argument rests on the upstream being its own group LEADER, and that is the only way
// to assert it directly.
func getpgid(pid int) (int, error) {
	return syscall.Getpgid(pid)
}
