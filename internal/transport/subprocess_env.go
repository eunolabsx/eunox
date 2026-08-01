// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"fmt"
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
//     /control/kill (when an operator supplies it through the environment rather than
//     the 0600 token file). An upstream holding it could stop the proxy.
//   - EUNOX_REDIS_PASSWORD — the shared call-counter / kill-switch backend password.
//     The environment is its RECOMMENDED supply channel (a flag value is visible in
//     /proc/<pid>/cmdline), so in the recommended configuration it is always present
//     in the proxy env; an upstream holding it could reach the shared backend.
//
// This is a denylist of eunox-owned names. It deliberately does NOT try to cover an
// operator-declared upstream secret referenced from the gateway config (e.g. an
// ${API_KEY} inside an upstreamAuthHeader), whose environment-variable name is
// arbitrary and unknown here — scoping those requires an explicit per-upstream
// passthrough allowlist, a larger design change. Until then, an operator running a
// less-trusted upstream should start the proxy with only the environment that upstream
// may legitimately see.
var sensitiveUpstreamEnvNames = []string{
	"EUNOX_CONTROL_TOKEN",
	"EUNOX_REDIS_PASSWORD",
}

// isSensitiveUpstreamEnv reports whether an os.Environ() "NAME=VALUE" entry carries one
// of the eunox-owned secrets.
//
// The name is matched case-INSENSITIVELY because Windows is a release target and its
// environment lookup folds case: a variable set as "Eunox_Control_Token" is resolved by
// os.Getenv("EUNOX_CONTROL_TOKEN"), so the proxy uses it as the credential, but
// os.Environ() reports it with the operator's original casing. A case-sensitive match
// would therefore pass the live secret straight through to the upstream — the exact leak
// this file exists to prevent. Matching on the name only (splitting at the first "=")
// also keeps a longer variable that merely starts with a secret's name, such as
// EUNOX_CONTROL_TOKEN_PATH, from being stripped: it is a different variable.
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
// application — not just the denylist — is the point: a spawn site that hand-assigns
// cmd.Env can silently omit it, and a nil cmd.Env inherits the proxy's entire
// os.Environ() (control token, Redis password) into the least-trusted process. That
// failure mode is invisible, so the secure default must be un-forgettable rather than
// re-typed per site.
//
// It takes an already-built *exec.Cmd so it fits both the transports' deliberate
// exec.Command (subprocess lifecycles are managed explicitly, not by a context) and the
// CLI probe's exec.CommandContext. Call it immediately after construction, before Start.
//
// The process-group placement belongs here for the same un-forgettable-default reason
// as the environment: a spawn site that omits it produces an upstream whose
// wrapper-spawned grandchildren cannot be reaped, and the symptom (a shutdown that
// hangs) shows up far from the spawn.
func ConfigureUpstreamCmd(cmd *exec.Cmd) {
	cmd.Stderr = os.Stderr
	cmd.Env = upstreamEnv()
	setUpstreamProcessGroup(cmd)
	// cmd.Cancel is deliberately NOT set here. os/exec refuses to Start a command that
	// has a Cancel but no context, and both transports build their upstream with a plain
	// exec.Command on purpose (subprocess lifecycles are managed explicitly, not by a
	// context) — so wiring it here fails every subprocess session outright. A
	// CommandContext caller wires KillUpstreamProcess itself; see its doc.
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
// group exists to close, so a context-bound caller that keeps the default gets the
// detach with none of the teardown. This cannot be folded into ConfigureUpstreamCmd
// because Cancel is invalid on the context-free commands the transports use.
func KillUpstreamProcess(proc *os.Process) { killUpstreamProcess(proc) }

// killUpstreamProcess forcibly stops an upstream subprocess AND everything it spawned,
// falling back to the direct child on a platform (or a failed Setpgid) with no process
// group to signal.
//
// It lives beside ConfigureUpstreamCmd for the same reason the group placement does:
// spawn and teardown are one contract. Every kill site in the package goes through it,
// so a site that reached for proc.Kill() directly would reap the wrapper and orphan the
// real server — leaking a process per session in HTTP mode, and on the stdio startup
// and shutdown paths leaving the grandchild holding the stdout pipe whose EOF the
// bounded teardowns wait for.
//
// The direct child is signalled FIRST, and a failure there aborts the group kill. That
// ordering is what preserves the idempotence every caller relies on. os.Process.Kill
// consults Go's own reaped-process state (ErrProcessDone, and a pidfd where the kernel
// provides one), so a call racing a completed cmd.Wait sends no signal at all — whereas
// the group kill is a raw kill(-pid) that the kernel resolves against whatever holds
// that pid NOW. Several callers genuinely race a Wait: the stdio SIGKILL AfterFunc that
// stopKillTimer deliberately does not join, httpSession.close's timer arm against the
// per-session cleanup goroutine, and the writer-poison hook. Every eunox upstream is a
// group LEADER (pgid == pid) since ConfigureUpstreamCmd sets Setpgid, so under pid reuse
// the likeliest holder of a recycled pid is another session's upstream — session A's
// stale kill would SIGKILL session B's whole tree. Killing the leader before the group
// also keeps the pid reserved (a zombie is not recycled until reaped), so the group id
// stays valid for the call that follows.
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

// killUpstreamCmd force-kills cmd's process, tolerating cmd == nil (a remote-HTTP
// session, or one torn down before its subprocess started, has no *exec.Cmd at
// all). killUpstreamProcess's own nil guard is on *os.Process, one field access
// too late to help here: cmd.Process on a nil *exec.Cmd panics before that guard
// ever runs. Every stdio/HTTP teardown site that kills a session's subprocess goes
// through this rather than hand-repeating "if cmd != nil { killUpstreamProcess(cmd.Process) }",
// so a future addition to the guard (a log line, a metric) lands at every call site
// at once instead of in however many of them got updated.
func killUpstreamCmd(cmd *exec.Cmd) {
	if cmd != nil {
		killUpstreamProcess(cmd.Process)
	}
}

// waitBounded blocks until ch fires or d elapses, reporting whether ch fired first.
// On timeout it logs a stderr notice naming what (a short noun phrase, e.g.
// "upstream output stream") it was waiting for, so an operator sees why teardown
// gave up rather than the session silently hanging. It is the bounded post-kill
// wait every teardown path needs: a subprocess has just been force-killed, and the
// caller is waiting for that to unblock a pipe read (readUpstream's EOF) or a
// handshake goroutine (runInitHandshake) — but a descendant that escaped the
// process group (a double-fork, an explicit setsid, or a platform with no
// process-group teardown at all) can hold that pipe open indefinitely, and an
// unbounded wait here would turn a BOUNDED teardown into an unbounded one,
// defeating the reason the caller bounded it in the first place. The caller is
// expected to give up and continue teardown regardless of the return value; ch's
// underlying goroutine (if any) is left to drain and exit on its own once the pipe
// it is blocked on eventually closes.
func waitBounded[T any](ch <-chan T, d time.Duration, what string) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		fmt.Fprintf(os.Stderr, "[eunox] %s still open after a forced kill (a descendant may have escaped the process group); abandoning the wait.\n", what)
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
