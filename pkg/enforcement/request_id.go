// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import "github.com/eunolabs/eunox/pkg/capability"

// requestIDGen mints per-decision correlation IDs from a startup nonce + atomic
// counter (via the shared capability.IDGenerator) rather than a per-decision
// crypto/rand UUID, keeping crypto/rand off the enforcement hot path.
var requestIDGen = capability.NewIDGenerator("dec", 6)

// NewRequestID returns a process-unique, opaque per-decision correlation ID. Cheap
// enough for the enforcement hot path (one atomic increment, no crypto/rand). Shared
// by the engine's EnforceResponse and the JWT PDP's allow/deny constructors so every
// decision stamps an ID the same cheap way.
//
// RequestID is an OPAQUE correlation string (its only consumer is
// input.context.request_id for a pluggable OPA/Cedar evaluator); nothing requires it
// to be a UUID.
func NewRequestID() string {
	return requestIDGen.Next()
}
