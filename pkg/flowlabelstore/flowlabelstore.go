// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package flowlabelstore provides the per-session information-flow-control label
// store that backs the capability.FlowLabelStore seam: the monotonic source->sink
// provenance set a labelOutput directive writes and a flowLabel condition reads.
//
// It is deliberately a separate primitive from pkg/callcounter. A CallCounter is a
// decaying sliding-window count; provenance is a MONOTONIC, ANCHOR-LIFETIME set
// that must not age a taint out mid-session. A window would let a long-lived (or
// deliberately idled) session lose its taint — a fail-open the flow-control "for
// all flows, a class outside Allow never reaches this sink" claim cannot tolerate —
// so flow state lives here, in a store whose contract (Add/Get/Remove/Clear) matches
// provenance rather than counting.
//
// Two backends mirror pkg/callcounter: InMemory for single-replica deployments and
// tests, and Redis (shared keys) for multi-instance deployments where a source read on
// one instance and a sink on another must see the same taint. Both are safe for
// concurrent use and fail closed — a backend fault surfaces as an error the engine turns
// into a deny, so an unreadable provenance state is never mistaken for clean context.
//
// Both also reclaim an ABANDONED anchor on a refreshed idle TTL, and the distinction from
// the window above is the whole design. A window ages a taint out by its AGE, which is the
// fail-open. An idle TTL refreshed by every Add and every Get ages an anchor out by its
// INACTIVITY, so a live anchor — one still emitting labels, or merely still having its
// taint read by sink checks — never expires, while one nothing will ever touch again is
// released. That distinction is what makes reclamation possible at all for a
// TASK-anchored key, which no session teardown owns: clearing it on disconnect would
// restore the per-PEP boundary the anchor exists to cross, and would let an agent launder
// a task's taint by reconnecting, so the idle bound is the only reclamation such a key can
// safely have. Without it the in-memory store grew one key per distinct task id for the
// life of the process, and its admission ceiling — an ADMISSION ceiling, never a reaper —
// turned into an availability cliff every flow-relevant call fell off at once.
package flowlabelstore

import "github.com/eunolabs/eunox/pkg/capability"

// Build-time proof that both built-in backends satisfy the full
// capability.FlowLabelStore contract. A backend that dropped a method breaks the
// build here — caught by go build ./..., not only by go test.
var (
	_ capability.FlowLabelStore = (*InMemory)(nil)
	_ capability.FlowLabelStore = (*Redis)(nil)
)
