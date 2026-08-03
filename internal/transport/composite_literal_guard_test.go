// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
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
		constructor: "a literal at one of the allowlisted sites, completed with .withPDP(pdp)",
		why: "serverRequestParams.sessionID is recorded as the session a server-initiated " +
			"sampling/roots/elicitation request was answered for, with the same provenance " +
			"requirement as forwardParams; its pdp and committer must also come from ONE " +
			"decision point, which is what withPDP derives",
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
	// Enumerate and parse the files directly rather than through parser.ParseDir. Two
	// reasons, and the second is the one that matters: ParseDir is deprecated, and it
	// associates files with packages WITHOUT considering build tags — so a literal in a
	// file behind a build tag could be dropped from the walk and pass the guard unseen. A
	// guard that silently skips files is worse than no guard. Every .go file in the
	// package directory is parsed here regardless of its tags.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("listing package sources: %v", err)
	}
	var sources []string
	for _, e := range entries {
		name := e.Name()
		// Non-test sources only: tests legitimately build these structs directly to drive
		// a path, and holding test files to the rule would say nothing about production
		// provenance while making every new table-driven test edit this allowlist.
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		sources = append(sources, name)
	}
	if len(sources) == 0 {
		t.Fatal("no package sources found; the guard would pass vacuously")
	}

	found := map[string][]string{} // type name -> files containing a literal
	for _, path := range sources {
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", path, perr)
		}
		base := filepath.Base(path)
		// A literal of a guarded type reaches this walk in two spellings, and matching only
		// the first is how a guard passes while the thing it guards is bypassed:
		// `killSubject{...}` names its type directly, while an element of
		// `[]killSubject{{...}}` or `map[string]forwardParams{"k": {…}}` ELIDES it
		// (lit.Type == nil) and inherits it from the enclosing literal's element type.
		// ast.Inspect gives no parent link, so the walk threads that context itself.
		walkLiterals(file, "", func(name string) {
			if _, guarded := guardedStructs[name]; guarded {
				found[name] = append(found[name], base)
			}
		})
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

// walkLiterals visits every composite literal under n, reporting the named type of each.
// elem is the type name an ELIDED literal inherits from its enclosing slice/array/map
// literal ("" when there is none), which is what makes `[]killSubject{{...}}` visible.
func walkLiterals(n ast.Node, elem string, report func(name string)) {
	ast.Inspect(n, func(node ast.Node) bool {
		lit, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		name := elem
		if lit.Type != nil {
			// Package-local types are always spelled bare; anything else (a qualified
			// type, a generic instantiation) is not one of the guarded three.
			if ident, isIdent := lit.Type.(*ast.Ident); isIdent {
				name = ident.Name
			} else {
				name = ""
			}
		}
		if name != "" {
			report(name)
		}
		// Descend with THIS literal's element type in scope, so its elided children
		// resolve. Recurse explicitly rather than returning true, because the child
		// literals need the context ast.Inspect does not carry.
		child := elementTypeName(lit.Type)
		for _, e := range lit.Elts {
			// A map/struct element is a KeyValueExpr; only its value can be an elided
			// literal of the element type.
			if kv, isKV := e.(*ast.KeyValueExpr); isKV {
				walkLiterals(kv.Value, child, report)
				continue
			}
			walkLiterals(e, child, report)
		}
		return false
	})
}

// elementTypeName returns the bare element type name of a slice, array, or map type, or
// "" when the type is not a container of a package-local named type. It is what an elided
// element literal inherits.
func elementTypeName(t ast.Expr) string {
	var elt ast.Expr
	switch typ := t.(type) {
	case *ast.ArrayType:
		elt = typ.Elt
	case *ast.MapType:
		elt = typ.Value
	default:
		return ""
	}
	// A pointer element (&T{} spelled as []*T{{…}}) elides the same way.
	if star, ok := elt.(*ast.StarExpr); ok {
		elt = star.X
	}
	if ident, ok := elt.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// dedupeSorted returns the unique entries of in, sorted, so failures name files in a
// stable order regardless of map iteration.
func dedupeSorted(in []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(in)))
}
