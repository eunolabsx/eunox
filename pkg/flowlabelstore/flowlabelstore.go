// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package flowlabelstore provides the per-session information-flow-control label
// store that backs the capability.FlowLabelStore seam: the monotonic source->sink
// provenance set a labelOutput directive writes and a flowLabel condition reads.
//
// It is deliberately a separate primitive from pkg/callcounter. A CallCounter is a
// decaying sliding-window count; provenance is a MONOTONIC, SESSION-LIFETIME set
// that must not age a taint out mid-session. A window would let a long-lived (or
// deliberately idled) session lose its taint — a fail-open the flow-control "for
// all flows, a class outside Allow never reaches this sink" claim cannot tolerate —
// so flow state lives here, in a store whose contract (Add/Get/Remove/Clear) matches
// provenance rather than counting.
//
// Two backends mirror pkg/callcounter: InMemory for single-replica deployments and
// tests, and Redis (shared keys under a refreshed idle TTL) for multi-instance
// deployments where a source read on one instance and a sink on another must see the
// same taint. Both are safe for concurrent use and fail closed — a backend fault
// surfaces as an error the engine turns into a deny, so an unreadable provenance
// state is never mistaken for clean context.
package flowlabelstore

import "github.com/eunolabs/eunox/pkg/capability"

// Build-time proof that both built-in backends satisfy the full
// capability.FlowLabelStore contract. A backend that dropped a method breaks the
// build here — caught by go build ./..., not only by go test.
var (
	_ capability.FlowLabelStore = (*InMemory)(nil)
	_ capability.FlowLabelStore = (*Redis)(nil)
)
