// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// guardedStructs maps a security-invariant struct type to the files allowed to build one
// with a composite literal, and to the constructor an author should be reaching for
// instead. Every type here carries a session id whose PROVENANCE is the invariant: a
// literal written elsewhere can assign a client-controlled value to a field the audit
// record then signs as fact.
//
// The allowlist lives here, in a test, rather than in a comment, because that is the
// point: adding a construction site requires a deliberate edit to a security-invariant
// test, which is a review signal the type system alone cannot produce. Go's encapsulation
// is package-scoped, not file-scoped, so an unexported field is writable from any file in
// internal/transport — this is what closes that gap.
var guardedStructs = map[string]struct {
	files       []string
	constructor string
	why         string
}{
	"killSubject": {
		files:       []string{"forward.go"},
		constructor: "verifiedSession(id) or claimedSession(r)",
		why: "killSubject decides whether a session id is signed into the audit record's " +
			"session_id field as fact or kept as an unverified claim. A literal can set " +
			"verified: to a raw client-supplied header, producing an HMAC-chained record " +
			"asserting a session this proxy never established",
	},
	"forwardParams": {
		files:       []string{"stdio.go", "http_handlers.go"},
		constructor: "(*HTTPProxy).dispatchParams or (*StdioProxy).dispatchParams",
		why: "forwardParams.sessionID is recorded as the session that PERFORMED an action. " +
			"Both constructors take resolved session state (an *httpSession, or the stdio " +
			"proxy's own id) and so cannot be handed a raw Mcp-Session-Id header; a literal can",
	},
	"serverRequestParams": {
		files:       []string{"stdio.go", "http_handlers.go"},
		constructor: "(*HTTPProxy).dispatchParams or (*StdioProxy).dispatchParams",
		why: "serverRequestParams.sessionID is recorded as the session a server-initiated " +
			"sampling/roots/elicitation request was answered for, with the same provenance " +
			"requirement as forwardParams",
	},
}

// TestGuardedCompositeLiterals asserts that composite literals of the session-provenance
// structs appear only in the files allowed to construct them.
//
// This is the belt-and-suspenders the type alone cannot give. verifiedSession/
// claimedSession and the two dispatchParams constructors make the SAFE path the natural
// one — none of them can accept a raw request header where a session id is expected — but
// a hand-written literal bypasses all four, and nothing in the language stops one.
//
// Deliberately an AST walk rather than a linter rule: forbidigo matches identifiers in
// call position, not composite literals, so the rule cannot be expressed there at all
// (and it is not enabled in .golangci.yml, so adopting it would mean adding a linter that
// then could not do the job). One parse of the package's own sources covers all three
// types in a single pass, at test-only cost.
func TestGuardedCompositeLiterals(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	// Non-test sources only: tests legitimately build these structs directly to drive a
	// path, and holding test files to the rule would say nothing about production
	// provenance while making every new table-driven test edit this allowlist.
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing package sources: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no package parsed; the guard would pass vacuously")
	}

	found := map[string][]string{} // type name -> files containing a literal
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			base := filepath.Base(path)
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				// Only bare type names: these three are package-local, so a literal of one
				// is always spelled without a package qualifier.
				ident, ok := lit.Type.(*ast.Ident)
				if !ok {
					return true
				}
				if _, guarded := guardedStructs[ident.Name]; !guarded {
					return true
				}
				found[ident.Name] = append(found[ident.Name], base)
				return true
			})
		}
	}

	for name, rule := range guardedStructs {
		files := dedupeSorted(found[name])
		// A type that no longer appears at all means it was renamed or deleted and this
		// guard silently stopped guarding anything. Fail rather than pass vacuously.
		if len(files) == 0 {
			t.Errorf("no %s composite literal found in any non-test file: the type was renamed or removed, and this guard is no longer protecting it — update guardedStructs", name)
			continue
		}
		allowed := map[string]bool{}
		for _, f := range rule.files {
			allowed[f] = true
		}
		for _, f := range files {
			if allowed[f] {
				continue
			}
			t.Errorf("%s composite literal in %s is not allowed.\n"+
				"  Construct it with %s instead.\n"+
				"  Why: %s.\n"+
				"  If a new construction site is genuinely required, add %s to guardedStructs — "+
				"that edit is the review signal this guard exists to force.",
				name, f, rule.constructor, rule.why, f)
		}
		// An allowlisted file that no longer constructs the type leaves a stale entry that
		// silently re-permits a future literal there.
		for _, want := range rule.files {
			if !slices.Contains(files, want) {
				t.Errorf("guardedStructs allows %s literals in %s, but none remain there; drop the stale entry so it cannot silently re-permit one later", name, want)
			}
		}
	}
}

// dedupeSorted returns the unique entries of in, sorted, so failures name files in a
// stable order regardless of map iteration.
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
