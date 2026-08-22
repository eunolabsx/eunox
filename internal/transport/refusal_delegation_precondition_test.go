// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The precondition tieredBuckets.admitWithFloor's delegation arm rests on and cannot itself
// enforce.
//
// The arm harvests the PARENT's accumulated tally for a key this table holds no bucket for,
// while a sibling holder that DOES hold one pushes its own tally back at its own tier when the
// parent refuses. Both are right in isolation. Together — one holder delegating a key another
// registers and charges — the same refused write is reported once by each, at two different
// scopes, and the count that exists to tell an operator how much was elided over-states it in
// both places.
//
// Nothing in record_limiter.go can check this: whether a holder ever CHARGES a category is a
// property of its call sites. So it is asserted here in two halves — an explicit per-kind
// declaration of what each charges, and a source-level check of the structural fact that
// declaration rests on.

package transport

import (
	"go/ast"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionKindCharges declares, per HTTP session kind, the upstream-driven categories that kind
// can actually WRITE.
//
// The `charges` lists are spelled out rather than pointed at the same variables `registers`
// uses. That is the whole point: aliasing them made the subset assertion below trivially true
// and unable to detect the hazard it names — a call site charging a category its holder
// delegates. Written out, narrowing a `registers` list without narrowing what that kind
// charges fails the test.
var sessionKindCharges = map[string]struct {
	registers []refusalCategory
	charges   []refusalCategory
	why       string
}{
	"subprocess upstream": {
		registers: upstreamRefusalCategories,
		charges:   []refusalCategory{catDisplaced, catUnroutableID, catServerRequestFailed, catRefusalUndeliverable, catUndeliveredForward},
		why:       "it owns an upstream reader, so every server-initiated refusal is reachable",
	},
	"remote HTTP upstream": {
		registers: remoteUpstreamRefusalCategories,
		// The ones it does not register are gated on a serverReqTracker entry (which this kind
		// never creates) or on the forward leg the upstream reader drives (which it never starts)
		// — see TestSessionKinds_OnlyTheSubprocessKindReadsItsUpstream for the structural fact
		// that makes that true rather than merely claimed.
		charges: []refusalCategory{catServerRequestFailed},
		why:     "it runs no upstream reader, so nothing ever enters the in-flight tracker",
	},
}

// TestRefusalCategories_NoKindDelegatesWhatASiblingCharges is the precondition itself: for
// every session kind, everything it can charge must be something it REGISTERS a bucket for —
// so no category is simultaneously delegated by one holder and charged-and-registered by
// another.
func TestRefusalCategories_NoKindDelegatesWhatASiblingCharges(t *testing.T) {
	t.Parallel()

	for kind, decl := range sessionKindCharges {
		has := make(map[refusalCategory]bool, len(decl.registers))
		for _, c := range decl.registers {
			has[c] = true
		}
		for _, c := range decl.charges {
			assert.Truef(t, has[c], "%s charges %q but registers no bucket for it, so it DELEGATES that write to the aggregate while a sibling kind registers and counts it — the same refused write then reports at two scopes (%s)", kind, c, decl.why)
		}
		// Every kind's table must be drawn from the upstream-driven set the aggregate's floor
		// is keyed over (newUpstreamRefusalLimiter reserves over upstreamRefusalCategories), or
		// a delegated category reaches the parent with no floor slot reserved for it.
		for _, c := range decl.registers {
			assert.Containsf(t, upstreamRefusalCategories, c, "%s registers %q, which is outside the upstream-driven set the session floor is keyed over", kind, c)
		}
	}

	// The pairing must actually EXIST to be reasoned about, so the assertions above are not
	// passing because the tables happen to be identical for an unrelated reason.
	delegated := false
	for _, decl := range sessionKindCharges {
		if len(decl.registers) < len(upstreamRefusalCategories) {
			delegated = true
		}
	}
	require.True(t, delegated, "no session kind delegates anything, so this test is asserting nothing; if the tables were deliberately unified, delete it along with the precondition comment in admitWithFloor")
}

// TestSessionKinds_OnlyTheSubprocessKindReadsItsUpstream is the structural half: the reason a
// remote session charges none of the three server-request categories is that nothing can ever
// enter its tracker, and the reason for THAT is that it starts no upstream reader.
//
// readUpstream is the only goroutine that delivers upstream-initiated messages, and
// trackServerRequest is reached only from that delivery. So "which constructor launches it" is
// the fact the declaration above rests on, and unlike the declaration it is checkable: a remote
// session that gained a reader would start charging categories it delegates, re-opening the
// double-count with no other test noticing.
func TestSessionKinds_OnlyTheSubprocessKindReadsItsUpstream(t *testing.T) {
	t.Parallel()

	starters := map[string]bool{}
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				g, ok := n.(*ast.GoStmt)
				if !ok {
					return true
				}
				if sel, ok := g.Call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "readUpstream" {
					starters[fn.Name.Name] = true
				}
				return true
			})
		}
	}

	assert.True(t, starters["newSession"], "the subprocess constructor must start the upstream reader; if it moved, this guard is watching the wrong function")
	assert.False(t, starters["newRemoteSession"], "a remote session that starts an upstream reader can populate its server-request tracker, so it begins charging the three categories it DELEGATES — see the precondition on tieredBuckets.admitWithFloor")

	// And nothing else launches one, which is what keeps the two-constructor reasoning above
	// from silently becoming a three-constructor question.
	for name := range starters {
		assert.Truef(t, name == "newSession" || strings.HasSuffix(name, "Test"),
			"%s starts an upstream reader; the session-kind reasoning behind remoteUpstreamRefusalCategories only covers newSession", name)
	}
}
