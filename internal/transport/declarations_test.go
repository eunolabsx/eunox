// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSortedKeysWhere_FiltersAndOrders pins the two properties every vocabulary derived through it
// depends on, since neither is visible at the call sites.
//
// The ORDER is not cosmetic: each result builds a fixed table (bucket keys, reserve slots) whose
// identity would otherwise vary per process — a difference no assertion downstream can see. The
// FILTER is what makes a declaration authoritative rather than advisory.
func TestSortedKeysWhere_FiltersAndOrders(t *testing.T) {
	t.Parallel()
	m := map[string]int{"delta": 1, "alpha": 2, "charlie": 1, "bravo": 3}

	assert.Equal(t, []string{"charlie", "delta"}, sortedKeysWhere(m, func(v int) bool { return v == 1 }),
		"the keep predicate selects, and the result is ordered rather than in map order")
	assert.Equal(t, []string{"alpha", "bravo", "charlie", "delta"}, sortedKeysWhere(m, func(int) bool { return true }))
	assert.Empty(t, sortedKeysWhere(m, func(int) bool { return false }),
		"a vocabulary nothing declares is empty rather than nil-panicking downstream")
	assert.Empty(t, sortedKeysWhere(map[string]int(nil), func(int) bool { return true }))
}

// TestDerivedVocabulariesMatchTheirDeclarations is the cross-check the shared derivation makes
// cheap: each derived slice is exactly the subset its declaration table names.
//
// Per-table tests assert the declarations are well-formed; this asserts the DERIVATION reaches all
// of them, which is the failure a fourth hand-written copy would have reintroduced — a refinement
// landing on three of four is silent, and every one of these sizes a bucket table or a reserve.
func TestDerivedVocabulariesMatchTheirDeclarations(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		got  int
		want int
	}{
		"collapsedNoticeSites": {len(collapsedNoticeSites), countNotices(func(d noticeSiteDeclaration) bool { return d.collapse == collapseWindowed })},
		"floorProtectedSites":  {len(floorProtectedSites), countNotices(func(d noticeSiteDeclaration) bool { return d.floor == floorSiteProtected })},
		"refusalCategories":    {len(refusalCategories), countRefusals(meteringMetered)},
	} {
		assert.Equal(t, tc.want, tc.got, "%s must describe exactly what the declarations say", name)
		assert.Positive(t, tc.got, "%s is empty, so any assertion over it passes vacuously", name)
	}
}

func countNotices(keep func(noticeSiteDeclaration) bool) int {
	n := 0
	for _, decl := range meteredNotices {
		if keep(decl) {
			n++
		}
	}
	return n
}

func countRefusals(want refusalMetering) int {
	n := 0
	for _, decl := range refusalDeclarations {
		if decl.metering == want {
			n++
		}
	}
	return n
}
