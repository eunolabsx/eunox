// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The one derivation this package's declaration tables share: "the keys whose declaration says
// yes", sorted.
//
// Every bounded thing here is now DECLARED in a map and its vocabulary DERIVED from that map rather
// than typed out beside it — the notice classes, the collapse windows, the site floors, the refusal
// categories. That shape spread faster than the derivation did: four package-level functions, three
// of them identical modulo the key type, each sizing something load-bearing (a bucket table's keys,
// a budget divisor, a keyReserve's slots), and each therefore a place a later refinement could land
// on and miss the other two. A vocabulary that silently omits a key does not fail: the key falls to
// a floor-rate fallback bucket, or reserves no slot, or stops collapsing — all of which look like
// working code.
//
// pkg/capability made this call already, for two copies rather than four:
//
//	sortedRegistryKeys … is generic over the prototype constructor so the condition and directive
//	registries share one derivation: two copies of "collect the map keys and sort them" is the same
//	mirrored-table shape the registries themselves exist to remove, and a later refinement of how a
//	vocabulary is derived (an alias table, a non-lexical tie-break) must not land on one of them only.
//
// What deliberately stays separate is the one that PROJECTS rather than filters (see
// meteredNoticeClasses): map keys are unique and map values are not, so a projection needs a
// dedup its three neighbours must not have — dropping it is invisible in the source and makes
// noticeClasses fifteen entries where three were meant. That distinction was previously an unwritten
// property of which functions happened to range over keys.

package transport

import (
	"cmp"
	"slices"
)

// sortedKeysWhere returns the keys of m whose declaration satisfies keep, in ascending order.
//
// Sorted because every consumer builds a fixed table from the result — bucket keys, reserve slots —
// and a map's iteration order would make that table's identity vary per process, which is a
// difference no test can see and a heap profile can.
func sortedKeysWhere[K cmp.Ordered, V any](m map[K]V, keep func(V) bool) []K {
	out := make([]K, 0, len(m))
	for key, decl := range m {
		if !keep(decl) {
			continue
		}
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}
