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
//
// It is enforced over two SHAPES, which is a coverage boundary rather than a closed surface:
// an upstream's `error.message`, and a response body read into a local. The second was added
// after the first shipped and left the CLI's kill client — the same class, a different
// spelling — passing the build. Each test states what its own walk cannot see.

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
// surface closed. The one other shape that carries a peer's bytes to a console — a whole
// response body read into a local — has its own walk below rather than being folded in here:
// the two match different syntax and a walk that failed on either would name the wrong rule.
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

// TestConsoleDetail_EveryNetworkBodyIsBounded walks for a value read out of a response body
// (`b, _ := io.ReadAll(...)`) reaching a formatting call, and requires it to pass through
// BoundConsoleDetail.
//
// The second shape of the same rule, and the reason it exists is that the first one's coverage
// boundary was an artifact rather than a choice: the sibling matches `<expr>.Error.Message`, so
// the CLI's kill client — which reads a whole HTTP body into a local and prints it with %s —
// was invisible to it and did not fail the build when the rest of the class was fixed. A body
// is the same primitive as a message and bounded by nothing but the read limit, which is 64 KiB
// where the console's is 2.
//
// Deliberately still SHAPE-based, not taint-based: this matches one assignment form inside one
// function, so a body handed to a helper that formats it, or read through a wrapper this walk
// does not know as io.ReadAll, stays invisible — the sibling's residual, one shape wider.
// Tracking foreign bytes through the program is more machinery than a handful of sites earns;
// two shapes is where it stops paying, and that is now a recorded decision rather than whichever
// shape happened to be fixed first.
func TestConsoleDetail_EveryNetworkBodyIsBounded(t *testing.T) {
	t.Parallel()

	found := 0
	for _, dir := range consoleDetailGuardedDirs {
		for _, src := range packageSourcesIn(t, dir) {
			for _, decl := range src.file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				// Per function: the names are matched by spelling, so a `body` in one function
				// must not make a `body` in the next look like a read one.
				bodies := readAllResultNames(fn.Body)
				if len(bodies) == 0 {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || !isFormattingCall(call) {
						return true
					}
					for _, arg := range call.Args {
						bounded, unbounded := bodyUsesIn(arg, bodies)
						found += len(bounded) + len(unbounded)
						for _, name := range unbounded {
							require.Failf(t, "unbounded response body",
								"%s: %s formats %q, read from a response body; wrap it in BoundConsoleDetail so whatever answered cannot drive the operator's console",
								src.fset.Position(arg.Pos()), types.ExprString(call.Fun), name)
						}
					}
					return true
				})
			}
		}
	}
	require.NotZero(t, found, "the walk found no response bodies reaching a printer at all; it is asserting nothing")
}

// readAllResultNames collects the names bound to io.ReadAll's FIRST result inside body — the
// bytes, as opposed to the error beside them, which is eunox's own value and needs no bound.
func readAllResultNames(body *ast.BlockStmt) map[string]bool {
	names := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !isReadAllCall(call) {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
			names[id.Name] = true
		}
		return true
	})
	return names
}

// isReadAllCall reports whether call is io.ReadAll(...).
func isReadAllCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "ReadAll" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "io"
}

// isFormattingCall reports whether call renders its arguments for a reader — fmt's and log's
// printers, which is every way a string reaches an operator's console in these two packages.
// Decoders and byte helpers (json.Unmarshal, bytes.TrimSpace) take the same bodies and are not
// a console at all, which is what this narrowing is for.
func isFormattingCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && (pkg.Name == "fmt" || pkg.Name == "log")
}

// bodyUsesIn splits the response-body names used anywhere in arg by whether the use passes
// through BoundConsoleDetail. Descent STOPS at a wrapping call, so a name reached only under one
// is bounded however it is spelled beneath it (`string(b)`, `strings.TrimSpace(string(b))`).
func bodyUsesIn(arg ast.Expr, bodies map[string]bool) (bounded, unbounded []string) {
	ast.Inspect(arg, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isBoundConsoleDetailCall(call) {
			bounded = append(bounded, bodyNamesIn(call, bodies)...)
			return false
		}
		if id, ok := n.(*ast.Ident); ok && bodies[id.Name] {
			unbounded = append(unbounded, id.Name)
		}
		return true
	})
	return bounded, unbounded
}

// bodyNamesIn collects the response-body names appearing anywhere under n.
func bodyNamesIn(n ast.Node, bodies map[string]bool) []string {
	var out []string
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && bodies[id.Name] {
			out = append(out, id.Name)
		}
		return true
	})
	return out
}
