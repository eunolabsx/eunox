// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"go/ast"
	"maps"
	"slices"
	"testing"
)

// TestSessionEstablishment_IsReachedThroughOneTail is the source guard for the sequence both
// session-creating arms run: the pre-spawn slot reservation and its release, and the
// remote/local spawn the reservation exists to bound.
//
// The two arms — the session-creating initialize and the declaring peer's first request — used
// to hand-mirror that sequence, ~25 security-ordered lines differing only in the seed, with the
// second copy citing the first for one of its comments. gate_order_test.go pins the ORDER from
// another file, which is exactly what makes a divergence quiet: a fix landing on one copy leaves
// the other passing every test that reads only one arm. Holding the primitives to a single
// caller is what makes a third arm that re-rolls them fail the build instead.
//
// A guard over CALLS rather than over line shape: reserving without releasing, spawning without
// reserving, or reserving twice are all spelled as one of these calls somewhere other than
// establishSession, and none of them is visible to a test that drives requests.
func TestSessionEstablishment_IsReachedThroughOneTail(t *testing.T) {
	t.Parallel()
	// The primitives whose ordering IS the sequence.
	const tail = "*HTTPProxy.establishSession"
	primitives := map[string]string{
		"tryReserveSessionSlot": "the pre-spawn reservation",
		"releaseSessionSlot":    "its one-owner release",
		"newSession":            "the subprocess spawn",
		"newRemoteSession":      "the remote-upstream spawn",
	}

	// Recorded only for a call FROM the tail, so the vacuity check below also catches the tail
	// silently losing one of them — a violation elsewhere must not stand in for that.
	reachedFromTail := map[string]bool{}
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				name := callName(call)
				what, guarded := primitives[name]
				if !guarded {
					return true
				}
				// Resolved here rather than per declaration: the receiver render is the
				// expensive part and all but a handful of this package's functions call none
				// of these.
				if caller := qualifiedFuncName(fn); caller != tail {
					t.Errorf("%s:%d: %s calls %s (%s) directly; it belongs to %s, the one tail both session-creating arms share",
						src.name, src.fset.Position(call.Pos()).Line, caller, name, what, tail)
					return true
				}
				reachedFromTail[name] = true
				return true
			})
		}
	}
	// Fail OPEN otherwise: a rename, or a tail that stopped reserving or spawning, would leave
	// the guard passing over code it no longer guards.
	for _, name := range slices.Sorted(maps.Keys(primitives)) {
		if !reachedFromTail[name] {
			t.Errorf("%s is not called by %s; the guard has stopped guarding it (renamed, or the tail no longer runs it)", name, tail)
		}
	}
}
