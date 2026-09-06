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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostKillWaitsAreBounded scans this package's non-test sources for a bare channel
// receive taken after a forced kill in the same block.
//
// waitBounded exists because the thing being waited for may never arrive: a descendant that
// escaped the process group (a double-fork, an explicit setsid, a platform with no
// process-group teardown) holds the pipe open, cmd.Wait never returns, and the teardown
// goroutine parked on it never reaches the cleanup below. Every such wait in this package
// is bounded — the session cleanup goroutine's was the one that was not, which pinned a
// maxSessions slot and the session's state for the proxy's life — and "every" is a claim a
// scan can hold where a reviewer counting sites cannot.
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
			if killed && isBareReceive(stmt) {
				violations = append(violations, fmt.Sprintf(
					"%s: unbounded receive after a forced kill; use waitBounded(ch, d, what, errOut) so an escaped descendant cannot park this teardown forever",
					fset.Position(stmt.Pos())))
			}
		}
		return true
	})
	return violations
}

// isForceKillCall reports whether stmt is a call to one of this package's force-kill helpers.
func isForceKillCall(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	fn, ok := call.Fun.(*ast.Ident)
	return ok && (fn.Name == "killUpstreamCmd" || fn.Name == "killUpstreamProcess")
}

// isBareReceive reports whether stmt is `<-ch` as a statement — a receive whose value is
// discarded, which is the spelling of "wait for this, however long it takes".
func isBareReceive(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	unary, ok := expr.X.(*ast.UnaryExpr)
	return ok && unary.Op == token.ARROW
}

// TestUnboundedPostKillWaits_DetectsTheShape proves the scan fires on the shape it is about
// rather than merely passing over sources that happen to be clean — and that the two
// legitimate spellings beside it (a bounded wait, and a receive with no kill above it) are
// not flagged.
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

func bounded(waited chan struct{}) {
	killUpstreamCmd(nil)
	waitBounded(waited, 0, "upstream output stream", nil)
}

func noKill(waited chan struct{}) {
	<-waited
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "snippet.go", snippet, parser.AllErrors)
	require.NoError(t, err)

	got := unboundedPostKillWaits(fset, file)
	require.Len(t, got, 2, "exactly the two offenders must be flagged; got %v", got)
	for _, v := range got {
		assert.Contains(t, v, "unbounded receive after a forced kill")
	}
}
