// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The stderr side of a refusal as a DECLARATION rather than a survey, mirroring what
// refusal_metering_test.go does for the record side.
//
// Four mechanisms bound a diagnostic line in this package — the shared notice bucket, riding the
// record's own admission verdict, a one-shot latch, and nothing at all — and only the first was
// ever written down. newRefusalNoticeLimiter's doc claims the shared bucket makes "how many
// diagnostic syscalls can a peer drive" ONE number; that is true only while every peer-drivable
// site actually charges it, which nothing checked. It is how the routing refusal's line came to be
// an unbuffered write syscall per frame while its record's exemption was argued in prose.

package transport

import (
	"go/ast"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noticeDeclarations answers, for every function in this package that writes a diagnostic line,
// how that line is bounded. Keyed by the function's own name (the last segment for a method),
// which is what the walk below can see.
//
// A function holding several lines declares ONE disposition for all of them: the lines in a given
// function are reached at the same rate by the same caller, and a function whose lines genuinely
// needed different answers would be one worth splitting.
var noticeDeclarations = map[string]noticeDeclaration{
	// (1) The shared notice bucket, through noticef. Every one of these is reachable at a peer's
	// (or an upstream's) send rate, one line per frame.
	"refuseUnroutable":     {bound: noticeMetered},
	"refuseUpstreamless":   {bound: noticeMetered},
	"enforcedForwardCore":  {bound: noticeMetered},
	"commitDeclassify":     {bound: noticeMetered},
	"upstreamErrInfo":      {bound: noticeMetered},
	"forwardServerRequest": {bound: noticeMetered},
	"writeToInitiator":     {bound: noticeMetered},
	"effectReceiptDetail":  {bound: noticeMetered},
	"handleMCPPost":        {bound: noticeMetered},
	"handleSessionPost":    {bound: noticeMetered},
	"forwardNotification":  {bound: noticeMetered},
	"post":                 {bound: noticeMetered},
	// stdio's, whose line is per `initialize` REQUEST: re-initialize is answered LOCALLY, so it
	// creates no session and contacts no upstream — the exemption it used to carry was reasoned
	// from a session's cost and did not apply.
	"buildInitResponse": {bound: noticeMetered},

	// (2) Gated on the RECORD's admission verdict, which spends that category's own bucket.
	"checkOrigin":            {bound: noticeRecordGated},
	"requireJSONContentType": {bound: noticeRecordGated},

	// (3) One-shot latches: at most one line however hard the source is driven.
	"warnStrictAuditOnce":           {bound: noticeOnce},
	"warnIfStrictAuditJustDegraded": {bound: noticeOnce},
	"track":                         {bound: noticeOnce},
	"broadcast":                     {bound: noticeOnce},

	// (4) Deliberately unbounded, each carrying the reason it cannot be driven per frame.
	"handleMetrics":             {bound: noticeExempt, why: exemptNotADiagnostic},
	"tightenTokenDir":           {bound: noticeExempt, why: exemptNotPeerDriven},
	"WriteControlTokenFile":     {bound: noticeExempt, why: exemptNotPeerDriven},
	"warnForwardedForPosture":   {bound: noticeExempt, why: exemptNotPeerDriven},
	"Serve":                     {bound: noticeExempt, why: exemptNotPeerDriven},
	"NewHTTPProxyGateway":       {bound: noticeExempt, why: exemptNotPeerDriven},
	"BuildRoutes":               {bound: noticeExempt, why: exemptNotPeerDriven},
	"DeleteMCPHTTPSession":      {bound: noticeExempt, why: exemptNotPeerDriven},
	"handleKill":                {bound: noticeExempt, why: exemptNotPeerDriven},
	"printRemoteUpstreamNotice": {bound: noticeExempt, why: exemptNotPeerDriven},
	"PrintRoutePolicyNotices":   {bound: noticeExempt, why: exemptNotPeerDriven},
	"signalUpstream":            {bound: noticeExempt, why: exemptNotPeerDriven},
	"awaitUpstreamDrain":        {bound: noticeExempt, why: exemptNotPeerDriven},
	"initUpstream":              {bound: noticeExempt, why: exemptNotPeerDriven},
	"waitBounded":               {bound: noticeExempt, why: exemptNotPeerDriven},
	"Start":                     {bound: noticeExempt, why: exemptNotPeerDriven},
	"writeSessionCreateError":   {bound: noticeExempt, why: exemptCostsASession},
	"newSession":                {bound: noticeExempt, why: exemptCostsASession},
	"newRemoteSession":          {bound: noticeExempt, why: exemptCostsASession},
	"reapOnce":                  {bound: noticeExempt, why: exemptCostsASession},
	"reclaimKilledSession":      {bound: noticeExempt, why: exemptCostsASession},
	"readUpstream":              {bound: noticeExempt, why: exemptOncePerConnection},
	"serveHost":                 {bound: noticeExempt, why: exemptOncePerConnection},
}

// noticeWriters are the fmt functions that put a diagnostic line on this package's error writer.
// noticef is deliberately absent: it IS the bucket, so a call to it is the metered mechanism
// rather than a site needing one.
var noticeWriters = map[string]bool{"Fprintf": true, "Fprintln": true, "Fprint": true}

// TestNoticeBounding_EveryDeclarationIsWellFormed is the build-time half: an entry with no
// disposition, or an exemption with no reason, fails here rather than shipping as a default.
func TestNoticeBounding_EveryDeclarationIsWellFormed(t *testing.T) {
	t.Parallel()
	for site, decl := range noticeDeclarations {
		switch decl.bound {
		case noticeUndeclared:
			t.Errorf("diagnostic site %q declares no bound; metered, record-gated, one-shot and deliberately-unbounded are all answers, and none may be inherited", site)
		case noticeExempt:
			assert.NotEmpty(t, decl.why, "site %q is exempt with no reason; the reason IS the exemption, and one without it is indistinguishable from an oversight", site)
		default:
			assert.Empty(t, decl.why, "site %q is bounded but carries an exemption reason, which reads as a disagreement with its own disposition", site)
		}
	}
}

// TestNoticeBounding_EverySiteIsDeclared walks every diagnostic write in the package's non-test
// sources and requires its enclosing function to declare how the line is bounded.
//
// This is the guard the record side has had and the notice side has not, and the one that makes
// newRefusalNoticeLimiter's "one number" claim checkable: a new diagnostic cannot ship with no
// answer, and a site declared METERED cannot write its line with a bare Fprintf.
func TestNoticeBounding_EverySiteIsDeclared(t *testing.T) {
	t.Parallel()
	seen, checked := map[string]bool{}, 0
	// name -> the distinct declaration sites that write a diagnostic under it.
	writers := map[string][]string{}
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fnDecl, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fnDecl.Body == nil {
				continue
			}
			name := fnDecl.Name.Name
			if name == "noticef" {
				// The bucket's own implementation, not a site that needs one.
				continue
			}
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel || !noticeWriters[sel.Sel.Name] {
					return true
				}
				pkg, isIdent := sel.X.(*ast.Ident)
				if !isIdent || pkg.Name != "fmt" {
					return true
				}
				checked++
				seen[name] = true
				declared, isDeclared := noticeDeclarations[name]
				if !isDeclared {
					t.Errorf("%s:%d: %s writes a diagnostic line with no entry in noticeDeclarations; declare how it is bounded (the shared notice bucket via noticef, its record's admission verdict, a one-shot latch, or exempt with a reason)",
						src.name, src.fset.Position(call.Pos()).Line, name)
					return true
				}
				if declared.bound == noticeMetered {
					t.Errorf("%s:%d: %s is declared metered but writes its line with a bare fmt.%s, which charges no bucket; go through noticef",
						src.name, src.fset.Position(call.Pos()).Line, name, sel.Sel.Name)
				}
				return true
			})
			// A metered site is recognized by its noticef call rather than by a bare writer.
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				if !isCallTo(n, "noticef") {
					return true
				}
				checked++
				seen[name] = true
				noteWriter(writers, name, src.name, fnDecl)
				declared, isDeclared := noticeDeclarations[name]
				switch {
				case !isDeclared:
					t.Errorf("%s:%d: %s writes a bounded diagnostic with no entry in noticeDeclarations",
						src.name, src.fset.Position(n.Pos()).Line, name)
				case declared.bound != noticeMetered:
					t.Errorf("%s:%d: %s charges the notice bucket but declares %s; a site's declaration and its mechanism are one decision",
						src.name, src.fset.Position(n.Pos()).Line, name, noticeBoundName(declared.bound))
				}
				return true
			})
		}
	}
	require.Positive(t, checked, "no diagnostic write was found in any non-test file; this guard would pass vacuously")
	// The key is a bare function name, which this package has duplicates of (readUpstream,
	// buildInitResponse, take, …). One declaration covering two writing twins would let the second
	// inherit the first's answer silently, so an ambiguous key is an error rather than a
	// coincidence to rely on.
	for name, files := range writers {
		assert.Len(t, files, 1,
			"%q writes a diagnostic in more than one type's method (%v); the declaration is keyed by bare name, so one answer would cover both — rename one, or key this table by receiver",
			name, files)
	}
	for site := range noticeDeclarations {
		assert.True(t, seen[site], "diagnostic site %q is declared but writes no line; a declaration nothing reaches is an answer to a question nobody asks", site)
	}
}

// noteWriter records that name writes a diagnostic in this receiver's method, so an ambiguous
// declaration key is detectable. Keyed by receiver type (or the file, for a package function),
// deduplicated so several lines in one function count once.
func noteWriter(writers map[string][]string, name, file string, fn *ast.FuncDecl) {
	site := file
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		site = exprString(fn.Recv.List[0].Type)
	}
	if !slices.Contains(writers[name], site) {
		writers[name] = append(writers[name], site)
	}
}

// exprString renders a receiver type as `*T` or `T`.
func exprString(e ast.Expr) string {
	if star, isStar := e.(*ast.StarExpr); isStar {
		return "*" + exprString(star.X)
	}
	if ident, isIdent := e.(*ast.Ident); isIdent {
		return ident.Name
	}
	return "?"
}

func noticeBoundName(b noticeBound) string {
	switch b {
	case noticeMetered:
		return "metered"
	case noticeRecordGated:
		return "record-gated"
	case noticeOnce:
		return "one-shot"
	case noticeExempt:
		return "exempt"
	default:
		return "undeclared"
	}
}
