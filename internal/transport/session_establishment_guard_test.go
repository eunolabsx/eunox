// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"fmt"
	"go/ast"
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
	// The primitives whose ordering IS the sequence. recordSessionCapDeny is deliberately not
	// here: writeSessionCreateError answers the post-spawn spelling of the same cap, so it has
	// two legitimate callers by design.
	const tail = "*HTTPProxy.establishSession"
	primitives := map[string]string{
		"tryReserveSessionSlot": "the pre-spawn reservation",
		"releaseSessionSlot":    "its one-owner release",
		"newSession":            "the subprocess spawn",
		"newRemoteSession":      "the remote-upstream spawn",
	}

	var violations []string
	seen := map[string]bool{}
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			caller := qualifiedFuncName(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				what, guarded := primitives[callName(call)]
				if !guarded {
					return true
				}
				seen[callName(call)] = true
				if caller != tail {
					violations = append(violations, fmt.Sprintf(
						"%s:%d: %s calls %s (%s) directly; it belongs to %s, the one tail both session-creating arms share",
						src.name, src.fset.Position(call.Pos()).Line, caller, callName(call), what, tail))
				}
				return true
			})
		}
	}
	for _, v := range dedupeSorted(violations) {
		t.Error(v)
	}
	// Fail OPEN otherwise: a rename that leaves every primitive uncalled would pass silently.
	for name := range primitives {
		if !seen[name] {
			t.Errorf("%s is called nowhere in this package's non-test sources; the guard has stopped guarding it (renamed, or the tail was inlined)", name)
		}
	}
}
