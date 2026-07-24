// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"os"
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
var sensitiveUpstreamEnvPrefixes = []string{
	"EUNOX_CONTROL_TOKEN=",
	"EUNOX_REDIS_PASSWORD=",
}

// UpstreamEnv returns the current process environment with every eunox-owned secret
// (sensitiveUpstreamEnvPrefixes) removed, for use as an upstream subprocess's cmd.Env.
// Every subprocess spawn site — the stdio runtime upstream, the HTTP per-session
// upstream, and the CLI init/validate --live probe — MUST set cmd.Env to this rather
// than leaving it nil (which would inherit os.Environ() verbatim), so the proxy's
// secrets never reach the child. Exported so the cmd/eunox live-upstream probe shares
// the one denylist.
func UpstreamEnv() []string {
	return slices.DeleteFunc(os.Environ(), func(kv string) bool {
		for _, prefix := range sensitiveUpstreamEnvPrefixes {
			if strings.HasPrefix(kv, prefix) {
				return true
			}
		}
		return false
	})
}
