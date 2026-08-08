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
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoDiagnosticWritesStraightToStderr scans this package's non-test sources for
// fmt.Fprint*(os.Stderr, ...). Such a write bypasses the proxy's configured Stderr and races
// any goroutine (or test) that reads the process-global, which is why several sites that drifted
// to it were only noticed by a review. Resolving a NIL writer to os.Stderr stays legal — that
// is what resolvedErrOut/errOut() do — so the scan targets the call, not the mention.
func TestNoDiagnosticWritesStraightToStderr(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, perr, name)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 || !isFmtPrintToWriter(call.Fun) || !isOSStderr(call.Args[0]) {
				return true
			}
			t.Errorf("%s: writes a diagnostic straight to os.Stderr; take an io.Writer from the caller and resolve it through resolvedErrOut", fset.Position(call.Pos()))
			return true
		})
	}
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
			tr.track(fmt.Sprintf("req-%d", i), &out)
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
