// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package transport

import (
	"os"
	"os/exec"
)

// Process-group teardown has no portable equivalent on Windows/js-wasm: there is no
// setpgid, and the nearest analogue (a Job Object) is a different lifetime model that
// would need its own design. These are no-ops reporting "the group was not reached",
// which routes every caller to the direct-child fallback it already has — the behavior
// this package had on every platform before the unix path was added.
//
// The consequence is stated rather than hidden: on these platforms a wrapper-launched
// upstream (`npx`, `uvx`) can still leave a grandchild holding the stdout pipe open.
// The post-kill waits are bounded independently for exactly that reason, so a surviving
// grandchild delays nothing — it leaks a process, but it no longer hangs shutdown.
// See procgroup_unix.go for the rationale.
func setUpstreamProcessGroup(*exec.Cmd) {}

func signalUpstreamGroup(*os.Process, os.Signal) bool { return false }

func killUpstreamGroup(*os.Process) bool { return false }
