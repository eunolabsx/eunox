// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

// Build-time proof that both built-in kill-switch backends satisfy the full
// Manager contract (and, through it, Checker). A backend that dropped any method
// breaks the build here — caught by go build ./..., not only by go test — so the
// in-memory and Redis backends cannot silently diverge into one implementing an
// operator action the other does not. Mirrors pkg/callcounter/contracts.go, whose
// two backends are wired the same way behind a common interface.
var (
	_ Manager = (*InMemory)(nil)
	_ Manager = (*Redis)(nil)
)
