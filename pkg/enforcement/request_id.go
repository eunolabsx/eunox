// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import "github.com/eunolabs/eunox/pkg/capability"

// requestIDGen mints IDs from a startup nonce + atomic counter, keeping
// crypto/rand off the enforcement hot path.
var requestIDGen = capability.NewIDGenerator("dec", 6)

// NewRequestID returns a process-unique, opaque per-decision correlation ID, shared by
// the engine and the JWT PDP so every decision stamps an ID the same cheap way.
func NewRequestID() string {
	return requestIDGen.Next()
}
