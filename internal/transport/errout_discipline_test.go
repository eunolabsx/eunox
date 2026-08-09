// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The package rule that every diagnostic line goes to a CALLER-configured writer, turned
// from prose into a build failure: a source scan for the one shape that breaks it, plus a
// behavioral check on the helpers that take the writer as a parameter rather than reading it
// off a proxy (those were the ones that drifted).

package transport

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoDiagnosticWritesStraightToStderr scans this package's non-test sources for
// fmt.Fprint*(os.Stderr, ...). Such a write bypasses the proxy's configured Stderr and races
// any goroutine (or test) that reads the process-global, which is why several sites that drifted
// to it were only noticed by a review. Resolving a NIL writer to os.Stderr stays legal — that
// is what resolvedErrOut/errOut() do — so the scan targets the call, not the mention.
//
// Also flags fmt.Fprint*(resolvedErrOut(nil), ...): resolvedErrOut(nil) IS os.Stderr, by its
// own documented fallback, so spelling it that way at a leaf site (one syntactic hop removed
// from a bare os.Stderr, and easy to reach for when threading a real parameter through several
// intermediate callers looks like more work) is behaviorally the exact violation this scan
// exists to catch, not a legitimate use of the resolver — every genuine caller passes the
// writer already in scope (a struct field, a parameter), never a literal nil.
func TestNoDiagnosticWritesStraightToStderr(t *testing.T) {
	t.Parallel()
	for _, src := range packageSources(t) {
		for _, v := range directStderrViolations(src.fset, src.file) {
			t.Error(v)
		}
	}
}

// directStderrViolations walks f (parsed with fset) and returns one message per call this
// package's discipline forbids. Shared by the real per-file scan above and
// TestDirectStderrViolations_DetectsBothEscapeShapes below, which proves the two shapes it
// looks for — a literal os.Stderr and the behaviorally-identical resolvedErrOut(nil) — are
// actually caught, against a synthetic snippet rather than trusting the real sources to
// (never) contain either one to exercise the positive case.
func directStderrViolations(fset *token.FileSet, f *ast.File) []string {
	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 || !isFmtPrintToWriter(call.Fun) {
			return true
		}
		arg := call.Args[0]
		switch {
		case isOSStderr(arg):
			violations = append(violations, fmt.Sprintf("%s: writes a diagnostic straight to os.Stderr; take an io.Writer from the caller and resolve it through resolvedErrOut", fset.Position(call.Pos())))
		case isResolvedErrOutOfNilLiteral(arg):
			violations = append(violations, fmt.Sprintf("%s: resolvedErrOut(nil) IS os.Stderr — thread the caller's actual writer through instead of spelling the fallback directly", fset.Position(call.Pos())))
		}
		return true
	})
	return violations
}

// TestDirectStderrViolations_DetectsBothEscapeShapes proves directStderrViolations actually
// fires on both forbidden shapes — not just that the real package sources happen to be clean of
// them, which would pass equally well if the detector were a no-op. A third, legitimate call
// (a real writer variable) pins the negative case: passing an in-scope writer is never flagged.
func TestDirectStderrViolations_DetectsBothEscapeShapes(t *testing.T) {
	t.Parallel()
	const src = `package transport

import (
	"fmt"
	"os"
)

func direct(w interface{}) {
	fmt.Fprintf(os.Stderr, "direct: %v\n", w)
}

func viaResolvedErrOutNil(w interface{}) {
	fmt.Fprintf(resolvedErrOut(nil), "escaped: %v\n", w)
}

func legitimate(w interface{ Write([]byte) (int, error) }) {
	fmt.Fprintf(w, "fine: %v\n", w)
	fmt.Fprintf(resolvedErrOut(w), "fine too: %v\n", w)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	require.NoError(t, err)

	violations := directStderrViolations(fset, f)
	require.Len(t, violations, 2, "expected exactly the direct os.Stderr call and the resolvedErrOut(nil) call to be flagged: %v", violations)
	assert.Contains(t, violations[0], "straight to os.Stderr")
	assert.Contains(t, violations[1], "resolvedErrOut(nil) IS os.Stderr")
}

// isFmtPrintToWriter reports whether e names one of fmt's writer-taking print functions.
func isFmtPrintToWriter(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "fmt" {
		return false
	}
	switch sel.Sel.Name {
	case "Fprint", "Fprintf", "Fprintln":
		return true
	}
	return false
}

// isOSStderr reports whether e is the os.Stderr selector.
func isOSStderr(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Stderr" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "os"
}

// isResolvedErrOutOfNilLiteral reports whether e is exactly resolvedErrOut(nil) — a call to
// this package's own nil-writer fallback with a literal nil argument, which always evaluates
// to os.Stderr. A variable that merely HAPPENS to hold nil at runtime is undecidable from
// syntax alone and deliberately not the target here; this catches the cheap, direct spelling.
func isResolvedErrOutOfNilLiteral(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	fn, ok := call.Fun.(*ast.Ident)
	if !ok || fn.Name != "resolvedErrOut" {
		return false
	}
	arg, ok := call.Args[0].(*ast.Ident)
	return ok && arg.Name == "nil"
}

// TestParameterizedDiagnostics_HonorTheCallersWriter drives each helper that receives its
// writer as a parameter and asserts the line lands there. These are the sites the discipline
// is easiest to lose: with no proxy in scope, os.Stderr is the path of least resistance.
func TestParameterizedDiagnostics_HonorTheCallersWriter(t *testing.T) {
	t.Parallel()

	t.Run("server-request tracker eviction", func(t *testing.T) {
		t.Parallel()
		var out syncBuffer
		var tr serverReqTracker
		for i := 0; i <= maxTrackedServerReqs; i++ {
			tr.track(mcp.RPCMsg{ID: mcp.RawJSON(fmt.Sprintf("%d", i)), Method: "roots/list"}, &out)
		}
		assert.Contains(t, out.String(), "server-initiated request tracker reached its")
	})

	t.Run("bounded teardown wait", func(t *testing.T) {
		t.Parallel()
		var out syncBuffer
		assert.False(t, waitBounded(make(chan struct{}), time.Millisecond, "upstream output stream", &out))
		assert.Contains(t, out.String(), "upstream output stream still open after a forced kill")
	})

	t.Run("upstream session DELETE failure", func(t *testing.T) {
		t.Parallel()
		var out syncBuffer
		// Port 0 never accepts, so client.Do fails and the diagnostic fires.
		DeleteMCPHTTPSession(http.DefaultClient, "http://127.0.0.1:0/mcp", "up-sess", "", capability.Revision20251125, &out)
		assert.Contains(t, out.String(), "upstream session DELETE failed")
	})

	t.Run("control-token directory mode", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "eunox")
		require.NoError(t, os.Mkdir(dir, 0o750)) //nolint:gosec // test fixture: deliberately loose mode
		require.NoError(t, os.Chmod(dir, 0o750)) //nolint:gosec // test fixture: deliberately loose mode
		var out syncBuffer
		_, err := WriteControlTokenFile(context.Background(), filepath.Join(dir, "control.token"), "tok", &out)
		require.NoError(t, err)
		assert.Contains(t, out.String(), "group/world-accessible")
	})
}
