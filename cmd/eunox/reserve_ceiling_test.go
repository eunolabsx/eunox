// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// TestDefaultMaxSessions_IsTheHolderCountTheReserveCeilingAssumes is a tripwire for a number that
// is load-bearing in another package's prose and safety argument.
//
// internal/transport sizes the floored-write ceiling as `holders x keys`, where holders is THIS
// constant: the record half's doc block quotes 512x4 = 2048 against an audit queue 4096 deep, and
// the property that keeps a fleet-wide incident's leading edge from filling that queue — which
// would latch AuditDegraded() and deny every route under a strict-by-default --require-audit —
// depends on it. That package cannot import this one, so raising this value silently invalidates
// the argument there. If this fails, re-derive
// TestReserveCeiling_IsDerivedFromTheLiveSets in internal/transport and the two interval doc
// blocks it guards before updating the number here.
func TestDefaultMaxSessions_IsTheHolderCountTheReserveCeilingAssumes(t *testing.T) {
	t.Parallel()
	if defaultMaxSessions != 512 {
		t.Fatalf("defaultMaxSessions = %d, and internal/transport's reserve-ceiling arithmetic assumes 512", defaultMaxSessions)
	}
}
