// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The precondition tieredBuckets.admitWithFloor's delegation arm rests on and cannot itself
// enforce.
//
// The arm harvests the PARENT's accumulated tally for a key this table holds no bucket for,
// while a sibling holder that DOES hold one pushes its own tally back at its own tier when the
// parent refuses. Both are right in isolation. Together — one holder delegating a key another
// registers — the same refused write is reported once by each, at two different scopes, and the
// count that exists to tell an operator how much was elided over-states it in both places.
//
// Nothing in record_limiter.go can check this: whether a holder ever CHARGES a category is a
// property of its call sites. So it is asserted here, as a declaration with the reason attached,
// which is what makes adding a category to one session kind's table a deliberate edit rather
// than a silent re-opening of the double-count.

package transport

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionKindCharges declares, per HTTP session kind, the upstream-driven categories that kind
// can actually WRITE. It is a declaration and not a derivation — "can this leg reach this
// recorder" is not answerable from the tables — so each entry carries why.
var sessionKindCharges = map[string]struct {
	registers []refusalCategory
	charges   []refusalCategory
	why       string
}{
	"subprocess upstream": {
		registers: upstreamRefusalCategories,
		charges:   upstreamRefusalCategories,
		// It owns an upstream reader, so every server-initiated refusal is reachable.
		why: "a subprocess session tracks server-initiated requests, so all four arise",
	},
	"remote HTTP upstream": {
		registers: remoteUpstreamRefusalCategories,
		charges:   remoteUpstreamRefusalCategories,
		// The three it does not register are gated on a tracker entry this mode never creates:
		// there is no inbound channel, so nothing is ever tracked, displaced, over-cap, or
		// undeliverable. That is what keeps the delegation arm's precondition true.
		why: "a remote session has no upstream reader, so nothing enters the in-flight tracker",
	},
}

// TestRefusalCategories_NoKindDelegatesWhatASiblingCharges is the precondition itself: for every
// session kind, everything it can charge must be something it REGISTERS a bucket for — so no
// category is simultaneously delegated by one holder and charged-and-registered by another.
func TestRefusalCategories_NoKindDelegatesWhatASiblingCharges(t *testing.T) {
	t.Parallel()

	registered := map[refusalCategory][]string{}
	for kind, decl := range sessionKindCharges {
		has := make(map[refusalCategory]bool, len(decl.registers))
		for _, c := range decl.registers {
			has[c] = true
			registered[c] = append(registered[c], kind)
		}
		for _, c := range decl.charges {
			assert.Truef(t, has[c], "%s charges %q but registers no bucket for it, so it DELEGATES that write to the aggregate while a sibling kind registers and counts it — the same refused write then reports at two scopes (%s)", kind, c, decl.why)
		}
	}

	// The other half: a category some kind delegates must not be one another kind registers,
	// unless the delegating kind never charges it. The loop above establishes "never charges";
	// this asserts the pairing actually exists to be reasoned about, so the test is not passing
	// because the tables happen to be identical for an unrelated reason.
	delegatedSomewhere := false
	for _, decl := range sessionKindCharges {
		if len(decl.registers) < len(upstreamRefusalCategories) {
			delegatedSomewhere = true
		}
	}
	require.True(t, delegatedSomewhere, "no session kind delegates anything, so this test is asserting nothing; if the tables were deliberately unified, delete it along with the precondition comment in admitWithFloor")

	// And every kind's table must be drawn from the upstream-driven set the aggregate's floor is
	// keyed over (newUpstreamRefusalLimiter's floor is newKeyReserve(upstreamRefusalCategories)),
	// or a delegated category would reach the parent with no floor slot reserved for it.
	for kind, decl := range sessionKindCharges {
		for _, c := range decl.registers {
			assert.Containsf(t, upstreamRefusalCategories, c, "%s registers %q, which is outside the upstream-driven set the session floor is keyed over", kind, c)
		}
	}
}
