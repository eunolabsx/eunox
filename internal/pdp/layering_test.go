// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// modulePrefix is this module's import path, so the walk below can tell an intra-module
// import from a stdlib or third-party one.
const modulePrefix = "github.com/eunolabs/eunox/"

// TestPDPImportsNoInternalPackage asserts that this package's non-test sources import nothing
// from internal/ — it builds on pkg/* and third-party code alone.
//
// The rule is not aesthetic. This package is imported by internal/drift, internal/transport and
// the binary, so every edge out of it is linked by all three. The one that existed was onto
// internal/audit, for a single plain data struct — but the package that struct lives in is the
// audit WRITER (file I/O, HMAC signing, rotation, retention), and the audit.WithIdentity seam
// it was satisfying exists precisely so the writer need not know about the JWT/PDP layer.
// Satisfying that by pointing the arrow the other way removed no coupling; it moved it, and
// made internal/drift — which has nothing to do with the tape — link the writer. The adapter
// now lives at the join, in cmd/eunox/audit_identity.go.
//
// Kept as a test rather than a comment because a comment does not fail: an `import` line is one
// keystroke, the compiler is happy, and nothing else in the tree would notice. A deliberate
// future edge is a deliberate edit to this test, which is the review signal the language cannot
// produce on its own.
//
// Test files are excluded: a test may reach for internal/audit as a fixture without the shipped
// package linking it.
func TestPDPImportsNoInternalPackage(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Clean(name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquoting import %s: %v", name, imp.Path.Value, err)
			}
			if strings.HasPrefix(path, modulePrefix+"internal/") {
				t.Errorf("%s imports %s: internal/pdp must build on pkg/* alone, so that "+
					"internal/drift, internal/transport and the binary do not all link it. "+
					"If the edge is genuinely wanted, say why here and in the layering note "+
					"in CLAUDE.md.", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test sources found: the walk would pass vacuously")
	}
}
