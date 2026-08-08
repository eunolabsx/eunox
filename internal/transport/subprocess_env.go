// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// sensitiveUpstreamEnvPrefixes are the eunox-owned environment variables that must
// never cross into an upstream MCP server subprocess — the least-trusted process the
// proxy launches. A subprocess spawned with cmd.Env left nil inherits the proxy's
// entire os.Environ(), including these:
//
//   - EUNOX_CONTROL_TOKEN — the loopback emergency-stop credential for POST
//     /control/kill (when supplied via environment rather than the 0600 token file). An
//     upstream holding it could stop the proxy.
//   - EUNOX_REDIS_PASSWORD — the shared call-counter / kill-switch backend password.
//     The environment is its RECOMMENDED supply channel (a flag value is visible in
//     /proc/<pid>/cmdline), so it is normally present in the proxy env; an upstream
//     holding it could reach the shared backend.
//
// This is a denylist of eunox-owned names. It deliberately does NOT try to cover an
// operator-declared upstream secret referenced from the gateway config (e.g. an
// ${API_KEY} inside an upstreamAuthHeader), whose environment-variable name is arbitrary
// and unknown here — scoping those needs an explicit per-upstream passthrough allowlist, a
// larger design change. Until then, a less-trusted upstream should be started with only
// the environment it may legitimately see.
var sensitiveUpstreamEnvNames = []string{
	"EUNOX_CONTROL_TOKEN",
	"EUNOX_REDIS_PASSWORD",
}

// isSensitiveUpstreamEnv reports whether an os.Environ() "NAME=VALUE" entry carries one
// of the eunox-owned secrets.
//
// Matched case-INSENSITIVELY because Windows folds environment-lookup case: a variable set
// as "Eunox_Control_Token" is resolved by os.Getenv("EUNOX_CONTROL_TOKEN") and used as the
// live credential, but os.Environ() reports it with the operator's original casing — a
// case-sensitive match would pass that secret straight through. Matching on the name only
// (split at the first "=") also keeps a longer variable like EUNOX_CONTROL_TOKEN_PATH,
// which merely starts with a secret's name, from being stripped: it's a different variable.
func isSensitiveUpstreamEnv(kv string) bool {
	name, _, ok := strings.Cut(kv, "=")
	if !ok {
		return false // not a NAME=VALUE entry; nothing to match
	}
	for _, secret := range sensitiveUpstreamEnvNames {
		if strings.EqualFold(name, secret) {
			return true
		}
	}
	return false
}

// ConfigureUpstreamCmd applies the settings every upstream subprocess must have before
// it is started, and is the ONLY approved way to prepare one. Centralizing the
// application — not just the denylist — matters because a spawn site that hand-assigns
// cmd.Env can silently omit it, and a nil cmd.Env inherits the proxy's entire
// os.Environ() (control token, Redis password) into the least-trusted process.
//
// Takes an already-built *exec.Cmd so it fits both the transports' exec.Command
// (subprocess lifecycles managed explicitly) and the CLI probe's exec.CommandContext.
// Call it immediately after construction, before Start.
//
// The process-group placement belongs here for the same reason as the environment: a
// spawn site that omits it produces an upstream whose wrapper-spawned grandchildren can't
// be reaped, and the symptom (a shutdown that hangs) shows up far from the spawn.
func ConfigureUpstreamCmd(cmd *exec.Cmd) {
	cmd.Stderr = os.Stderr
	cmd.Env = upstreamEnv()
	setUpstreamProcessGroup(cmd)
	// cmd.Cancel is deliberately NOT set here: os/exec refuses to Start a command that
	// has a Cancel but no context, and both transports build their upstream with a
	// plain exec.Command on purpose. A CommandContext caller wires
	// KillUpstreamProcess itself; see its doc.
}

// KillUpstreamProcess forcibly stops an upstream subprocess and everything it spawned.
// Exported for the one spawn site outside this package, the CLI's live-upstream probe
// (init / validate --live / doctor), which builds its command with exec.CommandContext
// and must set it as cmd.Cancel:
//
//	cmd.Cancel = func() error { transport.KillUpstreamProcess(cmd.Process); return nil }
//
// os/exec's DEFAULT Cancel is Process.Kill() on the direct child, which reaps a wrapper
// (`npx`, `uvx`) and orphans the real server — the leak ConfigureUpstreamCmd's process
// group exists to close. This cannot be folded into ConfigureUpstreamCmd because Cancel
// is invalid on the context-free commands the transports use.
func KillUpstreamProcess(proc *os.Process) { killUpstreamProcess(proc) }

// killUpstreamProcess forcibly stops an upstream subprocess AND everything it spawned,
// falling back to the direct child on a platform (or a failed Setpgid) with no process
// group to signal.
//
// It lives beside ConfigureUpstreamCmd because spawn and teardown are one contract: a
// site that reached for proc.Kill() directly would reap the wrapper and orphan the real
// server, leaking a process per session in HTTP mode.
//
// The direct child is signalled FIRST, and a failure there aborts the group kill — the
// ordering every caller's idempotence relies on. os.Process.Kill consults Go's own
// reaped-process state, so a call racing a completed cmd.Wait sends no signal at all,
// whereas a raw group kill(-pid) is resolved by the kernel against whatever holds that pid
// NOW. Several callers genuinely race a Wait (the stdio SIGKILL AfterFunc,
// httpSession.close's timer arm, the writer-poison hook). Every eunox upstream is a group
// LEADER (Setpgid), so under pid reuse the likeliest holder of a recycled pid is another
// session's upstream — a stale kill could SIGKILL session B's whole tree. Killing the
// leader before the group also keeps the pid reserved (a zombie isn't recycled until
// reaped), so the group id stays valid for the call that follows.
//
// proc may be nil (a session torn down before its subprocess started).
func killUpstreamProcess(proc *os.Process) {
	if proc == nil {
		return
	}
	if err := proc.Kill(); err != nil {
		// Already reaped, or gone. Do NOT issue a raw group signal against a pid that
		// may since have been recycled — that is the whole hazard above.
		return
	}
	killUpstreamGroup(proc)
}

// signalUpstreamProcess sends a graceful signal to an upstream subprocess and the tree
// it spawned, so a wrapper's grandchild gets the same chance to shut down cleanly. It
// takes killUpstreamProcess's leader-first ordering for the same reaped-pid reason.
func signalUpstreamProcess(proc *os.Process, sig os.Signal) {
	if proc == nil {
		return
	}
	if err := proc.Signal(sig); err != nil {
		return
	}
	signalUpstreamGroup(proc, sig)
}

// killUpstreamCmd force-kills cmd's process, tolerating cmd == nil (a remote-HTTP session,
// or one torn down before its subprocess started, has no *exec.Cmd). killUpstreamProcess's
// own nil guard is one field access too late: cmd.Process on a nil *exec.Cmd panics first.
// Every teardown site that kills a session's subprocess goes through this rather than
// hand-repeating the nil check, so a future addition to the guard lands everywhere at once.
func killUpstreamCmd(cmd *exec.Cmd) {
	if cmd != nil {
		killUpstreamProcess(cmd.Process)
	}
}

// waitBounded blocks until ch fires or d elapses, reporting whether ch fired first. On
// timeout it writes a notice to errOut naming what it was waiting for, so an operator sees
// why teardown gave up rather than the session silently hanging (every caller has its proxy's
// or session's writer in scope; a direct os.Stderr write would race a capturing test). It's
// the bounded post-kill wait every teardown path needs: a subprocess has just been
// force-killed, and the caller is waiting for that to unblock a pipe read or a handshake
// goroutine — but a descendant that escaped the process group (a double-fork, an explicit
// setsid, or a platform with no process-group teardown) can hold that pipe open
// indefinitely, and an unbounded wait here would defeat the reason the caller bounded
// itself. The caller is expected to give up and continue teardown regardless of the return
// value; ch's underlying goroutine, if any, is left to drain and exit on its own once the
// pipe it's blocked on eventually closes.
func waitBounded[T any](ch <-chan T, d time.Duration, what string, errOut io.Writer) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		_, _ = fmt.Fprintf(resolvedErrOut(errOut), "[eunox] %s still open after a forced kill (a descendant may have escaped the process group); abandoning the wait.\n", what)
		return false
	}
}

// upstreamEnv returns the current process environment with every eunox-owned secret
// removed, for use as an upstream subprocess's cmd.Env. Deliberately unexported: applying
// it is the caller's easiest thing to forget, so ConfigureUpstreamCmd is the only way in
// and there is no second, weaker path that sets the environment without the rest of the
// required spawn settings.
func upstreamEnv() []string {
	return slices.DeleteFunc(os.Environ(), isSensitiveUpstreamEnv)
}
