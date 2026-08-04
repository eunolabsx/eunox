// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

// Build-time proof both backends satisfy the full Manager contract, so a dropped method
// breaks the build rather than only go test. Mirrors pkg/callcounter/contracts.go.
var (
	_ Manager = (*InMemory)(nil)
	_ Manager = (*Redis)(nil)
)
