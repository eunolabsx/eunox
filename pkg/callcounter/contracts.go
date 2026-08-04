// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import "github.com/eunolabs/eunox/pkg/capability"

// Build-time proof both built-in backends satisfy capability.CallCounter, so a dropped
// method breaks the build rather than only go test.
var (
	_ capability.CallCounter = (*InMemory)(nil)
	_ capability.CallCounter = (*Redis)(nil)
)
