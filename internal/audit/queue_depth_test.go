// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

// TestAuditChannelSize_IsTheQueueDepthTheReserveCeilingAssumes is a tripwire for a number another
// package reasons about but cannot see.
//
// internal/transport's floored-write reserve is affordable only because the leading edge of a
// fleet-wide incident — `holders x keys` records in one burst — stays under this queue. Overflowing
// it latches AuditDegraded(), which under a strict-by-default --require-audit denies every route, so
// LOWERING this value turns an arrival guarantee into a data-plane outage with nothing in that
// package failing. If this fails, re-derive TestReserveCeiling_IsDerivedFromTheLiveSets in
// internal/transport before updating the number here.
func TestAuditChannelSize_IsTheQueueDepthTheReserveCeilingAssumes(t *testing.T) {
	t.Parallel()
	if auditChannelSize != 4096 {
		t.Fatalf("auditChannelSize = %d, and internal/transport's reserve-ceiling safety argument assumes 4096", auditChannelSize)
	}
}
