// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package transport

import (
	"os"
	"os/exec"
)

// No portable process-group equivalent on Windows/js-wasm (no setpgid), so these are
// no-ops that route every caller to the direct-child fallback. A wrapper-launched
// upstream's grandchild may then leak, but post-kill waits are bounded independently so
// shutdown never hangs on it. See procgroup_unix.go.
func setUpstreamProcessGroup(*exec.Cmd) {}

func signalUpstreamGroup(*os.Process, os.Signal) bool { return false }

func killUpstreamGroup(*os.Process) bool { return false }
