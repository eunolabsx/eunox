// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The teardown rule that a wait taken AFTER a forced kill is always bounded, turned from
// prose into a build failure.

package transport

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostKillWaitsAreBounded scans this package's non-test sources for a wait with no
// ceiling taken after a forced kill in the same statement list.
//
// The thing being waited for may never arrive: a descendant that escaped the process group
// holds a pipe open so the reader never finishes, or a child in an unreapable state never
// answers Wait. Either way the goroutine parked on it never reaches the teardown below, and
// on the three sites this found that meant a pinned maxSessions slot, a parked HTTP request
// handler, and a hung Start. The answer is waitBounded, or a reap moved to its own goroutine
// where parking costs one goroutine instead of the caller.
//
// What the scan holds is exactly that: within ONE statement list, a kill followed by a wait.
// It does not chase a wait through a helper, and it does not see a kill nested in a
// conditional — so it is a floor under the rule, not a proof of it.
func TestPostKillWaitsAreBounded(t *testing.T) {
	t.Parallel()
	for _, src := range packageSources(t) {
		for _, v := range unboundedPostKillWaits(src.fset, src.file) {
			t.Error(v)
		}
	}
}

// unboundedPostKillWaits walks f and returns one message per bare receive that follows a
// force-kill call in the same statement list.
//
// Scoped to the same statement LIST rather than to the whole function: that is the shape the
// rule is about (kill, then wait for what the kill was supposed to unblock), and it is what
// keeps a receive on an unrelated channel elsewhere in a long teardown function from being
// flagged. A switch or select CLAUSE body is such a list too, and not a BlockStmt — the site
// this guard was written for is the escalation arm of a `select`, so a BlockStmt-only walk
// would pass over the very shape it exists to catch.
func unboundedPostKillWaits(fset *token.FileSet, f *ast.File) []string {
	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		var list []ast.Stmt
		switch node := n.(type) {
		case *ast.BlockStmt:
			list = node.List
		case *ast.CaseClause:
			list = node.Body
		case *ast.CommClause:
			list = node.Body
		default:
			return true
		}
		killed := false
		for _, stmt := range list {
			if isForceKillCall(stmt) {
				killed = true
				continue
			}
			if killed && isUnboundedWait(stmt) {
				violations = append(violations, fmt.Sprintf(
					"%s: unbounded wait after a forced kill; use waitBounded(ch, d, what, errOut), or move the reap to its own goroutine, so a child that never answers cannot park this caller",
					fset.Position(stmt.Pos())))
			}
		}
		return true
	})
	return violations
}

// forceKillNames are the spellings of "stop the upstream now" in this package. Both the
// package-level helpers and the METHODS that wrap them, because a predicate matching only a
// bare identifier passes over the majority of this package's kill sites — `p.killUpstream()`
// and `s.killSubprocess()` are selector calls, and they are the ones the stdio teardown paths
// use.
var forceKillNames = map[string]bool{
	"killUpstreamCmd":     true,
	"killUpstreamProcess": true,
	"killUpstream":        true,
	"killSubprocess":      true,
}

// isForceKillCall reports whether stmt calls one of them, in either spelling.
func isForceKillCall(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	return forceKillNames[calleeName(call.Fun)]
}

// calleeName is the called function's own name for either spelling, `f(...)` or `x.f(...)`.
func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// isUnboundedWait reports whether stmt waits with no ceiling. Three spellings, because the
// hazard is the WAIT and not the syntax that discards its value: a bare `<-ch`, the same
// receive assigned away (`_ = <-ch`, `v := <-ch`), and a blocking `Wait()` call — which is
// what `<-ch` is standing in for at every site here, and what the two synchronous waits this
// guard found were spelled as.
func isUnboundedWait(stmt ast.Stmt) bool {
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		return isReceive(s.X) || isBlockingWait(s.X)
	case *ast.AssignStmt:
		for _, rhs := range s.Rhs {
			if isReceive(rhs) || isBlockingWait(rhs) {
				return true
			}
		}
	}
	return false
}

func isReceive(e ast.Expr) bool {
	unary, ok := e.(*ast.UnaryExpr)
	return ok && unary.Op == token.ARROW
}

// isBlockingWait reports whether e is a `Wait()`-named call — `cmd.Wait()`, or a method that
// wraps one (`p.waitUpstream()`), matched by name for isForceKillCall's reason.
func isBlockingWait(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	name := calleeName(call.Fun)
	return name == "Wait" || strings.HasPrefix(name, "wait") && name != "waitBounded"
}

// TestUnboundedPostKillWaits_DetectsTheShape proves the scan fires on every spelling it
// claims rather than merely passing over sources that happen to be clean — the bare receive,
// the same receive assigned away, a blocking Wait, and the method spellings of both halves —
// and that the three legitimate shapes beside them are not: a bounded wait, a reap moved to
// its own goroutine, and a wait with no kill above it. A predicate widened without this is as
// unproven as the narrow one it replaced.
func TestUnboundedPostKillWaits_DetectsTheShape(t *testing.T) {
	t.Parallel()
	const snippet = `package transport

func offender(waited chan struct{}) {
	killUpstreamCmd(nil)
	<-waited
}

func offenderInSelectClause(waited, other chan struct{}) {
	select {
	case <-waited:
	case <-other:
		killUpstreamCmd(nil)
		<-waited
	}
}

func offenderAssignedReceive(waited chan struct{}) {
	killUpstreamProcess(nil)
	_ = <-waited
}

func offenderBlockingWait(p *StdioProxy, cmd *exec.Cmd) {
	killUpstreamCmd(cmd)
	_ = cmd.Wait()
}

func offenderThroughMethodSpellings(p *StdioProxy) {
	p.killUpstream()
	p.waitUpstream()
}

func bounded(waited chan struct{}) {
	killUpstreamCmd(nil)
	waitBounded(waited, 0, "upstream process", nil)
}

func backgroundReap(cmd *exec.Cmd) {
	killUpstreamCmd(cmd)
	go func() { _ = cmd.Wait() }()
}

func noKill(waited chan struct{}) {
	<-waited
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "snippet.go", snippet, parser.AllErrors)
	require.NoError(t, err)

	got := unboundedPostKillWaits(fset, file)
	require.Len(t, got, 5, "every offending spelling must be flagged and no legitimate one; got %v", got)
	for _, v := range got {
		assert.Contains(t, v, "unbounded wait after a forced kill")
	}
}
