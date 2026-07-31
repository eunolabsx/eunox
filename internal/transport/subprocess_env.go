// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"os"
	"os/exec"
	"slices"
	"strings"
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
}

// killUpstreamProcess forcibly stops an upstream subprocess AND everything it spawned,
// falling back to the direct child on a platform (or a failed Setpgid) with no process
// group to signal.
//
// It lives beside ConfigureUpstreamCmd for the same reason the group placement does:
// spawn and teardown are one contract. Every kill site in the package goes through it,
// so a site that reached for proc.Kill() directly would reap the wrapper and orphan the
// real server — leaking a process per session in HTTP mode, and on the stdio startup
// and shutdown paths leaving the grandchild holding the stdout pipe whose EOF the
// bounded teardowns wait for. proc may be nil (a session torn down before its
// subprocess started); killing an already-reaped process is a no-op whose error is
// ignored, so this is idempotent.
func killUpstreamProcess(proc *os.Process) {
	if proc == nil {
		return
	}
	if !killUpstreamGroup(proc) {
		_ = proc.Kill()
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
