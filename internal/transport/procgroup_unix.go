// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package transport

import (
	"os"
	"os/exec"
	"syscall"
)

// setUpstreamProcessGroup puts the upstream subprocess in its own process group so the
// whole tree it spawns (a wrapper like `npx`/`uvx` often forks the real server as a
// grandchild sharing the same stdout pipe) can be signalled as a unit — otherwise the
// grandchild survives and the EOF a bounded teardown waits on never arrives, hanging
// shutdown. This also detaches the upstream from the proxy's own process group so a
// terminal Ctrl-C no longer reaches it directly; the proxy forwards the signal itself
// via signalUpstream instead, on its own schedule.
func setUpstreamProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// signalUpstreamGroup sends sig to the process group led by proc; a false return means
// the caller must fall back to signalling the direct child alone (setUpstreamProcessGroup's
// Setpgid is best-effort, and if it failed the child is still in the parent's group, so
// kill(-pid) would fail with ESRCH rather than accidentally signalling the proxy's own group).
func signalUpstreamGroup(proc *os.Process, sig os.Signal) bool {
	// Pid <= 1, not <= 0: POSIX defines kill(-1, sig) as "every process the caller may
	// signal", not "the group led by pid 1" — in a PID namespace the upstream can
	// legitimately be pid 1, and -1 would broadcast SIGKILL across the container.
	if proc == nil || proc.Pid <= 1 {
		return false
	}
	sysSig, ok := sig.(syscall.Signal)
	if !ok {
		return false
	}
	return syscall.Kill(-proc.Pid, sysSig) == nil
}

// killUpstreamGroup SIGKILLs the process group led by proc; see signalUpstreamGroup for
// why a false return is a fallback signal rather than an error.
func killUpstreamGroup(proc *os.Process) bool {
	return signalUpstreamGroup(proc, syscall.SIGKILL)
}

// getpgid returns the process-group id of pid. Test-facing, to assert directly that the
// upstream is its own group leader (the group-kill safety argument rests on that).
func getpgid(pid int) (int, error) {
	return syscall.Getpgid(pid)
}
