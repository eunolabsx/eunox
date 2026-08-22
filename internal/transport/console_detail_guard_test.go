// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The guard behind BoundConsoleDetail: a value a PEER authored may not reach an
// operator-facing string unbounded.
//
// The first form of this fix sanitized one site — a non-2xx HTTP body — and left the upstream's
// own JSON-RPC `error.message` embedded raw at three others, one of which prints on every
// glob-only session start two packages away. That is the failure mode a table test of the
// helper cannot catch: the helper was correct and simply not called. So the rule is enforced
// over the SOURCES, where "there is another site" is the thing being asserted.

package transport

import (
	"go/ast"
	"go/types"
	"testing"

	"github.com/stretchr/testify/require"
)

// consoleDetailGuardedDirs are the packages whose non-test sources may embed an upstream's
// JSON-RPC error message: the transport itself and the CLI's live-upstream probe, which points
// at the same upstream and prints to the same console.
var consoleDetailGuardedDirs = []string{".", "../../cmd/eunox"}

// TestConsoleDetail_EveryUpstreamMessageIsBounded walks for `<expr>.Error.Message` reaching a
// formatting call and requires it to pass through BoundConsoleDetail.
//
// Scoped to the ONE shape that carries an upstream's own prose, rather than to every foreign
// string: a JSON-RPC error message is unbounded by the protocol, is the upstream's to choose
// byte for byte, and is produced on any call it decides to reject — which is what makes it the
// console-flooding and escape-injection primitive the plain field name does not look like.
//
// RESIDUAL, stated rather than implied: a message stored in a local first
// (`msg := resp.Error.Message`) and formatted a few lines later is invisible here, as is any
// other foreign string this walk does not know to be one. What the guard buys is that the
// shape every current site uses cannot ship unwrapped; it does not make the console's input
// surface closed.
func TestConsoleDetail_EveryUpstreamMessageIsBounded(t *testing.T) {
	t.Parallel()

	found := 0
	for _, dir := range consoleDetailGuardedDirs {
		for _, src := range packageSourcesIn(t, dir) {
			ast.Inspect(src.file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				for _, arg := range call.Args {
					if !isUpstreamErrorMessage(arg) {
						continue
					}
					found++
					// The argument IS the bare selector, so whatever this call is, it received the
					// message unwrapped. A wrapped site passes BoundConsoleDetail(...) instead, and
					// the selector then appears only as that call's own argument — which this walk
					// reaches too, hence the exemption for the wrapper itself below.
					if isBoundConsoleDetailCall(call) {
						continue
					}
					require.Failf(t, "unbounded upstream message",
						"%s: %s embeds an upstream's JSON-RPC error message directly; wrap it in BoundConsoleDetail so a hostile upstream cannot drive the operator's console",
						src.fset.Position(arg.Pos()), types.ExprString(call.Fun))
				}
				return true
			})
		}
	}
	// A walk that matches nothing passes vacuously, which is exactly how this guard would decay
	// if the field were renamed or the sites moved.
	require.NotZero(t, found, "the walk found no upstream error messages at all; it is asserting nothing")
}

// isUpstreamErrorMessage reports whether e is the selector `<expr>.Error.Message` — the
// JSON-RPC error object's own prose on an mcp.RPCMsg.
func isUpstreamErrorMessage(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Message" {
		return false
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	return ok && inner.Sel.Name == "Error"
}

// isBoundConsoleDetailCall reports whether call is BoundConsoleDetail(...) — package-qualified
// (the CLI) or not (this package).
func isBoundConsoleDetailCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "BoundConsoleDetail"
	case *ast.SelectorExpr:
		return fn.Sel.Name == "BoundConsoleDetail"
	}
	return false
}
