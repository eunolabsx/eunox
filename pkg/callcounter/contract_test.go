// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter_test

import (
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
)

// Compile-time proof that both built-in call-counter backends satisfy the full
// capability.CallCounter contract. A backend that dropped any method breaks the build
// here rather than failing maxCalls/sequenceBlock closed at runtime with an opaque deny.
var (
	_ capability.CallCounter = (*callcounter.InMemory)(nil)
	_ capability.CallCounter = (*callcounter.Redis)(nil)
)
