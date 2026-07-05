// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import "github.com/eunolabs/eunox/pkg/capability"

// Build-time proof that both built-in call-counter backends satisfy the full
// capability.CallCounter contract. A backend that dropped any method breaks
// the build here — caught by go build ./..., not only by go test.
var (
	_ capability.CallCounter = (*InMemory)(nil)
	_ capability.CallCounter = (*Redis)(nil)
)
