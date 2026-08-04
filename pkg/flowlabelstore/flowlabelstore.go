// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package flowlabelstore provides the per-session information-flow-control label store
// that backs capability.FlowLabelStore: the monotonic source->sink provenance set a
// labelOutput directive writes and a flowLabel condition reads.
//
// It is a separate primitive from pkg/callcounter because provenance is a MONOTONIC,
// ANCHOR-LIFETIME set that must not age a taint out mid-session — a decaying window would
// let an idle session lose its taint, the fail-open flow control cannot tolerate.
//
// Two backends mirror pkg/callcounter (InMemory, Redis for shared multi-instance state)
// and both fail closed on a backend fault. Both also reclaim an ABANDONED anchor on a
// refreshed idle TTL rather than aging by raw age: refresh-on-touch is what makes
// reclamation safe for a TASK-anchored key, which no session teardown owns (clearing it
// on disconnect would let an agent launder a task's taint by reconnecting).
package flowlabelstore

import "github.com/eunolabs/eunox/pkg/capability"

// Build-time proof both built-in backends satisfy capability.FlowLabelStore, so a dropped
// method breaks the build rather than only go test.
var (
	_ capability.FlowLabelStore = (*InMemory)(nil)
	_ capability.FlowLabelStore = (*Redis)(nil)
)
