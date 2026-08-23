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

// signalUpstreamGroup sends sig to the process group led by proc, best-effort: every caller
// has already signalled the direct child, so a group signal that finds nothing (Setpgid is
// best-effort, and if it failed the child is still in the parent's group and kill(-pid) fails
// with ESRCH) leaves the child signalled and nothing further to do.
func signalUpstreamGroup(proc *os.Process, sig os.Signal) {
	// Pid <= 1, not <= 0: POSIX defines kill(-1, sig) as "every process the caller may
	// signal", not "the group led by pid 1" — in a PID namespace the upstream can
	// legitimately be pid 1, and -1 would broadcast SIGKILL across the container.
	if proc == nil || proc.Pid <= 1 {
		return
	}
	sysSig, ok := sig.(syscall.Signal)
	if !ok {
		return
	}
	_ = syscall.Kill(-proc.Pid, sysSig)
}

// killUpstreamGroup SIGKILLs the process group led by proc.
func killUpstreamGroup(proc *os.Process) {
	signalUpstreamGroup(proc, syscall.SIGKILL)
}

// getpgid returns the process-group id of pid. Test-facing, to assert directly that the
// upstream is its own group leader (the group-kill safety argument rests on that).
func getpgid(pid int) (int, error) {
	return syscall.Getpgid(pid)
}
