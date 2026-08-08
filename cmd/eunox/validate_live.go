// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The `validate` subcommand: its flag parsing and route walk (cmdValidate,
// validateConfigRoutes, reportRouteOutcome, writePolicyLoadResults), plus the live drift
// report formatter --live renders.
//
// runValidateLive classifies every live tool against the manifest and renders
// four sections:
//
//	COVERED              — tools matched by exact manifest entries
//	WARNINGS             — glob matches + argument/version/hash drift (review required)
//	NOT COVERED          — tools with no manifest entry (denied by default)
//	STALE MANIFEST ENTRIES — manifest entries with no live tool match
//
// Exit 0 means clean (no FM-1 through FM-6 findings); exit 1 means a finding is
// present and operator review is required.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/transport"
)

// coveredEntry records a live tool that is covered by an exact manifest entry.
type coveredEntry struct {
	Tool     string
	Resource string
}

// liveReport holds the classified findings from a live drift check.
type liveReport struct {
	exactCovered []coveredEntry  // tools covered by exact-match entries
	fm1Warnings  []drift.Warning // FM-1: glob-matched tools
	fm3Warnings  []drift.Warning // FM-3: condition argument not in live schema
	fm4Warnings  []drift.Warning // FM-4: server version does not satisfy manifest pin
	fm5Warnings  []drift.Warning // FM-5: description hash mismatch
	fm6Warnings  []drift.Warning // FM-6: structural argumentSchema drift (added/retyped parameter)
	schemaAbsent []drift.Warning // SchemaAbsent: tool published no inputSchema, so pinned args unverified (advisory)
	fm2Stale     []drift.Warning // FM-2: manifest entries with no live tool (advisory)
	fm2Pinned    []drift.Warning // FM-2Pinned: a descriptionHash-pinned entry is absent upstream (CRITICAL: startup-blocking)
	uncovered    []string        // live tool names not covered by any manifest entry
	unclassified []drift.Warning // a Kind this report doesn't yet know how to bucket (fail loud, not silently dropped)
}

// buildLiveReport classifies the live tool set against the manifest using
// CheckManifestDrift and returns a liveReport ready for rendering.
// serverVersion is the version string from the upstream initialize response.
func buildLiveReport(manifest *config.LocalManifest, tools []drift.UpstreamTool, serverVersion string) liveReport {
	driftWarnings := drift.CheckManifestDrift(manifest, tools, serverVersion)
	return classifyDriftWarnings(manifest, tools, driftWarnings)
}

// classifyDriftWarnings buckets an already-computed drift.Warning slice against the
// manifest/tool set. Split out from buildLiveReport so tests can exercise the
// bucketing switch (including an unrecognized Kind) directly, without needing
// CheckManifestDrift to actually produce one.
func classifyDriftWarnings(manifest *config.LocalManifest, tools []drift.UpstreamTool, driftWarnings []drift.Warning) liveReport {
	// FM-1 accumulates as a slice, not a map keyed by tool name: two equal-specificity
	// globs can both match one tool, and keying would drop all but the last.
	var fm1 []drift.Warning
	fm1Tools := make(map[string]bool)
	fm2 := make(map[string]drift.Warning)
	fm2Pinned := make(map[string]drift.Warning)
	var fm3, fm4, fm5, fm6, schemaAbsent, unclassified []drift.Warning
	uncoveredSet := make(map[string]bool)

	for i := range driftWarnings {
		w := &driftWarnings[i]
		switch w.Kind {
		case drift.Fm1:
			fm1 = append(fm1, *w)
			fm1Tools[w.Tool] = true
		case drift.Fm2:
			// Advisory: a manifest entry matches no live tool. The proxy still starts;
			// the stale entry simply never matches.
			fm2[w.Resource] = *w
		case drift.Fm2Pinned:
			// Critical: a descriptionHash-pinned tool is absent upstream, so its integrity
			// cannot be verified and the proxy REFUSES TO START (same gate as FM-5).
			fm2Pinned[w.Resource] = *w
		case drift.Fm3:
			fm3 = append(fm3, *w)
		case drift.Fm4:
			fm4 = append(fm4, *w)
		case drift.Fm5:
			fm5 = append(fm5, *w)
		case drift.Fm6:
			fm6 = append(fm6, *w)
		case drift.SchemaAbsent:
			schemaAbsent = append(schemaAbsent, *w)
		case drift.Uncovered:
			uncoveredSet[w.Tool] = true
		default:
			// A drift.Kind this report doesn't recognize yet — route it into a visible
			// bucket rather than silently dropping it, which previously let "Result: ok"
			// print with an unhandled Kind vanished from the report.
			unclassified = append(unclassified, *w)
		}
	}

	// A tool with an outstanding FM-3/FM-5/FM-6 warning must NOT also appear in COVERED,
	// or a contradictory [OK]/[FAIL] pair could let an operator miss the warning.
	warnedTools := make(map[string]bool)
	for i := range fm3 {
		warnedTools[fm3[i].Tool] = true
	}
	for i := range fm5 {
		warnedTools[fm5[i].Tool] = true
	}
	for i := range fm6 {
		warnedTools[fm6[i].Tool] = true
	}
	for i := range schemaAbsent {
		warnedTools[schemaAbsent[i].Tool] = true
	}

	// Exact-covered: live tools that are NOT glob-matched (FM-1), NOT uncovered,
	// and have no outstanding FM-3/FM-5/FM-6 warning.
	var exactCovered []coveredEntry
	for _, tool := range tools {
		if uncoveredSet[tool.Name] {
			continue
		}
		if fm1Tools[tool.Name] {
			continue
		}
		if warnedTools[tool.Name] {
			continue
		}
		if c := drift.BestManifestConstraint(manifest, tool.Name); c != nil {
			exactCovered = append(exactCovered, coveredEntry{Tool: tool.Name, Resource: c.Target})
		}
	}
	sort.Slice(exactCovered, func(i, j int) bool {
		return exactCovered[i].Tool < exactCovered[j].Tool
	})

	// Deterministic order by (tool, resource); a tool can appear more than once when
	// multiple globs match it, so the secondary resource key keeps those stable.
	sort.Slice(fm1, func(i, j int) bool {
		if fm1[i].Tool != fm1[j].Tool {
			return fm1[i].Tool < fm1[j].Tool
		}
		return fm1[i].Resource < fm1[j].Resource
	})
	fm2Slice := sortedWarnings(fm2)
	fm2PinnedSlice := sortedWarnings(fm2Pinned)

	uncoveredSlice := make([]string, 0, len(uncoveredSet))
	for name := range uncoveredSet {
		uncoveredSlice = append(uncoveredSlice, name)
	}
	sort.Strings(uncoveredSlice)

	sort.Slice(unclassified, func(i, j int) bool {
		if unclassified[i].Resource != unclassified[j].Resource {
			return unclassified[i].Resource < unclassified[j].Resource
		}
		return unclassified[i].Tool < unclassified[j].Tool
	})

	return liveReport{
		exactCovered: exactCovered,
		fm1Warnings:  fm1,
		fm3Warnings:  fm3,
		fm4Warnings:  fm4,
		fm5Warnings:  fm5,
		fm6Warnings:  fm6,
		schemaAbsent: schemaAbsent,
		fm2Stale:     fm2Slice,
		fm2Pinned:    fm2PinnedSlice,
		uncovered:    uncoveredSlice,
		unclassified: unclassified,
	}
}

// countPhrase renders a count as "" (n<=0), "1 <singular>", or "<n> <plural>", for
// the drift-summary line. Callers pass both spellings so the noun stays grammatical.
func countPhrase(n int, singular, plural string) string {
	switch {
	case n <= 0:
		return ""
	case n == 1:
		return "1 " + singular
	default:
		return fmt.Sprintf("%d %s", n, plural)
	}
}

// sortedWarnings drains a resource-name -> Warning map into a slice ordered by resource,
// so the drift report is deterministic. Used by the FM-2 and FM-2-pinned sections.
func sortedWarnings(m map[string]drift.Warning) []drift.Warning {
	out := make([]drift.Warning, 0, len(m))
	for k := range m {
		out = append(out, m[k])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out
}

// runValidateLive writes a human-readable drift report to out and returns the
// exit code: 0 when clean (no FM-1 through FM-6 findings), 1 otherwise.
func runValidateLive(manifest *config.LocalManifest, tools []drift.UpstreamTool, serverVersion string, out io.Writer) int {
	rep := buildLiveReport(manifest, tools, serverVersion)
	return renderLiveReport(rep, out)
}

// renderLiveReport writes rep as a human-readable drift report to out and returns
// the exit code: 0 when clean, 1 otherwise. Split out from runValidateLive so tests
// can render a synthetically-classified liveReport directly.
func renderLiveReport(rep liveReport, out io.Writer) int {
	// wf/wln discard write errors (not actionable).
	wf, wln := writers(out)

	// gap emits a blank line between sections, but not before the first one.
	printed := false
	gap := func() {
		if printed {
			wln()
		}
		printed = true
	}

	if len(rep.exactCovered) > 0 {
		gap()
		wln("COVERED")
		for _, e := range rep.exactCovered {
			wf("  [OK] %-22s resource: %s\n", e.Tool, e.Resource)
		}
	}

	if len(rep.fm4Warnings) > 0 || len(rep.fm5Warnings) > 0 || len(rep.fm2Pinned) > 0 || len(rep.fm1Warnings) > 0 || len(rep.fm3Warnings) > 0 || len(rep.fm6Warnings) > 0 || len(rep.schemaAbsent) > 0 {
		gap()
		wln("WARNINGS")
		for i := range rep.fm4Warnings {
			w := &rep.fm4Warnings[i]
			actual := w.VersionActual
			if actual == "" {
				actual = "(unknown)"
			}
			wf("  [WARN] SERVER VERSION MISMATCH  pinned: %-18s actual: %s\n", w.Resource, actual)
		}
		for i := range rep.fm5Warnings {
			w := &rep.fm5Warnings[i]
			wf("  [FAIL] %-22s description hash mismatch  (resource: %s)\n    expected: %s\n    actual:   %s\n",
				w.Tool, w.Resource, w.HashExpected, w.HashActual)
		}
		for i := range rep.fm2Pinned {
			w := &rep.fm2Pinned[i]
			// The startup-blocking counterpart to FM-5; marked CRITICAL so it isn't
			// mistaken for an advisory stale entry below.
			wf("  [FAIL] %s  — DESCRIPTION-PINNED tool absent upstream (CRITICAL: proxy startup aborts; descriptionHash cannot be verified)\n", w.Resource)
		}
		for i := range rep.fm1Warnings {
			w := &rep.fm1Warnings[i]
			wf("  [WARN] %-22s resource: %-22s (glob match — confirm this is intended)\n", w.Tool, w.Resource)
		}
		for i := range rep.fm3Warnings {
			w := &rep.fm3Warnings[i]
			wf("  [WARN] %-22s argument=%q not in live inputSchema  (resource: %s)\n", w.Tool, w.Argument, w.Resource)
		}
		for i := range rep.fm6Warnings {
			w := &rep.fm6Warnings[i]
			wf("  [WARN] %-22s argument=%q %s  (resource: %s)\n", w.Tool, w.Argument, w.Detail, w.Resource)
		}
		for i := range rep.schemaAbsent {
			w := &rep.schemaAbsent[i]
			wf("  [WARN] %-22s no live inputSchema; pinned arguments could not be verified  (resource: %s)\n", w.Tool, w.Resource)
		}
	}

	if len(rep.uncovered) > 0 {
		gap()
		wln("NOT COVERED (denied by default)")
		for _, name := range rep.uncovered {
			wf("  - %s\n", name)
		}
	}

	if len(rep.fm2Stale) > 0 {
		gap()
		wln("STALE MANIFEST ENTRIES")
		for i := range rep.fm2Stale {
			w := &rep.fm2Stale[i]
			wf("  [FAIL] %s  — no matching upstream tool\n", w.Resource)
		}
	}

	if len(rep.unclassified) > 0 {
		gap()
		wln("UNCLASSIFIED DRIFT (unrecognized finding kind — treat as critical until investigated)")
		for i := range rep.unclassified {
			w := &rep.unclassified[i]
			wf("  [FAIL] kind=%s tool=%q resource=%q\n", w.Kind, w.Tool, w.Resource)
		}
	}

	gap()

	fm1Count := len(rep.fm1Warnings)
	fm2Count := len(rep.fm2Stale)
	fm2PinnedCount := len(rep.fm2Pinned)
	fm3Count := len(rep.fm3Warnings)
	fm4Count := len(rep.fm4Warnings)
	fm5Count := len(rep.fm5Warnings)
	fm6Count := len(rep.fm6Warnings)
	schemaAbsentCount := len(rep.schemaAbsent)
	unclassifiedCount := len(rep.unclassified)

	// SchemaAbsent is advisory (never one of FM-1..FM-6), so a SchemaAbsent-only report
	// stays exit 0 (its [WARN] line is still rendered above).
	if fm1Count == 0 && fm2Count == 0 && fm2PinnedCount == 0 && fm3Count == 0 && fm4Count == 0 && fm5Count == 0 && fm6Count == 0 && unclassifiedCount == 0 {
		wln("Result: ok — all manifest entries match live tools; no glob matches, hash mismatches, or argument drift detected.")
		if schemaAbsentCount > 0 {
			wf("Note: %s (advisory only — no live inputSchema to verify pinned arguments against).\n",
				countPhrase(schemaAbsentCount, "unverified-schema warning", "unverified-schema warnings"))
		}
		return 0
	}

	var parts []string
	addCount := func(n int, singular, plural string) {
		if s := countPhrase(n, singular, plural); s != "" {
			parts = append(parts, s)
		}
	}
	addCount(unclassifiedCount, "unclassified drift finding (critical)", "unclassified drift findings (critical)")
	addCount(fm5Count, "description hash mismatch", "description hash mismatches")
	addCount(fm2PinnedCount, "description-pinned tool missing (critical)", "description-pinned tools missing (critical)")
	addCount(fm3Count, "argument drift warning", "argument drift warnings")
	addCount(fm6Count, "structural schema drift warning", "structural schema drift warnings")
	addCount(schemaAbsentCount, "unverified-schema warning", "unverified-schema warnings")
	if fm4Count > 0 {
		parts = append(parts, "server version mismatch")
	}
	addCount(fm1Count, "glob match", "glob matches")
	addCount(fm2Count, "stale entry", "stale entries")
	wf("Result: %s. Exit 1.\n", strings.Join(parts, ", "))

	// Next steps: turn each finding into a concrete remedy.
	gap()
	wln("Next steps:")
	if unclassifiedCount > 0 {
		wln("  - Unclassified drift: this build of eunox reported a drift.Kind this report does not recognize.")
		wln("    Upgrade eunox, or file a bug — the finding is real but its remedy is unknown to this report.")
	}
	if fm5Count > 0 {
		wln("  - Description hash mismatch: a tool's description changed. Review the new description for")
		wln("    prompt-injection/poisoning, then re-pin with 'eunox init --pin-descriptions' once vetted.")
	}
	if fm2PinnedCount > 0 {
		wln("  - Description-pinned tool missing (CRITICAL): a descriptionHash-pinned tool is absent from the")
		wln("    live tools/list, so its description integrity cannot be verified — the proxy will REFUSE TO START.")
		wln("    Investigate why the tool is absent: if it should be present, fix the upstream; only if it was")
		wln("    intentionally removed, carefully delete BOTH the constraint AND its descriptionHash pin (deleting")
		wln("    the entry alone lowers security by dropping the integrity check).")
	}
	if fm3Count > 0 {
		wln("  - Argument drift: a condition targets an argument key not in the live inputSchema. The constraint")
		wln("    may never fire. Review the tool's current schema and update the condition's argument field.")
	}
	if fm6Count > 0 {
		wln("  - Structural schema drift: the live tool grew a parameter a closed argumentSchema did not declare,")
		wln("    or a declared parameter changed type. Review whether the new surface should be gated, then update")
		wln("    the argumentSchema (and any conditions) to match the tool as you intend to allow it.")
	}
	if fm4Count > 0 {
		wln("  - Server version mismatch: the upstream was updated. Re-review the manifest against the new")
		wln("    release and bump the manifest's 'serverVersion' pin once you have.")
	}
	if fm1Count > 0 {
		wln("  - Glob match: a new live tool fell inside an existing glob (a silent over-permission). Confirm")
		wln("    it is intended, or tighten the glob / add an explicit entry so the widening is deliberate.")
	}
	if fm2Count > 0 {
		wln("  - Stale entry: a manifest entry matches no live tool (renamed or removed upstream). Delete the")
		wln("    entry, or re-run 'eunox init' against the live server and reconcile against your manifest.")
	}
	return 1
}

// capturedAfterTerminator renders the clause the no-manifest error appends when a "--" took
// arguments off the command line before flag parsing saw them. Without it the operator reads
// "at least one manifest file is required" against a command line that visibly names one: the
// tokens are gone from the positional list and nothing else says where they went.
func capturedAfterTerminator(stdioCmd []string) string {
	if len(stdioCmd) == 0 {
		return ""
	}
	return fmt.Sprintf(" (note: everything after \"--\" was taken as a --live stdio upstream command, not as a manifest path: %q)", stdioCmd)
}

// cmdValidate runs the `validate` subcommand, returning the exit code (rather than
// calling os.Exit) so tests can drive every branch including the fail-closed error paths.
func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.Usage = func() {
		w := usageWriter(args)
		_, _ = fmt.Fprint(w, `Usage:
  eunox validate <manifest.yaml> [...] --live --upstream-url <url>
  eunox validate <manifest.yaml> [...] --live --transport stdio -- <cmd> [args...]
  eunox validate --config <eunox.yaml> [--live]

Validate manifest file(s). Without --live, checks file syntax and exits.
With --live, also connects to a running upstream MCP server and reports
contract drift between the manifest and the live tool set. The upstream is
reached over HTTP (--transport http --upstream-url, the default) or as a
subprocess (--transport stdio -- <command>).

With --config, every route in the config is walked: each route's manifest(s)
are merged and validated, and with --live each route's declared upstream
(http or stdio subprocess) is introspected — no need to re-specify the
upstream wiring. The config is the source of truth.

Exit codes:
  0  Manifests valid; with --live, all entries match live tools and no
     glob-matched tools were detected.
  1  Drift warnings or stale entries present (operator review required).
     Reserved for findings, so CI can gate on it; never used for usage errors.
  2  Usage error, or a manifest/config parse or upstream-connection failure.

With --config the exit code is the maximum across all routes.

Flags:
`)
		fs.SetOutput(w)
		fs.PrintDefaults()
	}

	live := fs.Bool("live", false, "Connect to a running upstream and report drift against the live tool set.")
	configPath := fs.String("config", "", "Path to an eunox config (YAML). Walks every route, validating each route's\nmanifest(s); with --live, each route's declared upstream is introspected.\nMutually exclusive with positional manifest files and --upstream-url.")
	transportFlag := fs.String("transport", config.HostTransportHTTP, "Upstream transport for --live: \"http\" (default, with --upstream-url) or \"stdio\"\n(subprocess command after \"--\").")
	upstreamURL := fs.String("upstream-url", "", "Base URL of the MCP HTTP server (required with --live --transport http, unless --config is set).")
	authHeader := fs.String("upstream-auth-header", "", `Header forwarded to the upstream in "Name: Value" format.`)
	tlsSkipVerify := fs.Bool("upstream-tls-skip-verify", false, "Skip TLS certificate verification for the upstream (development only).")

	// Split off a stdio subprocess command after the first standalone "--", before
	// parsing (Go's flag package would otherwise consume it). Unconditional, --live or not,
	// so the remainder never reaches parseFlagsAndPositionals as manifest paths — which is
	// why the no-manifest error below has to name what was captured, or a mistyped
	// `eunox validate -- ./manifest.yaml` reads as "no manifest file given" against a
	// command line that plainly has one.
	rawArgs := args
	var stdioCmd []string
	for i, a := range rawArgs {
		if a == "--" {
			stdioCmd = rawArgs[i+1:]
			rawArgs = rawArgs[:i]
			break
		}
	}

	// Allow flags and positional manifest files to be interspersed; a single fs.Parse
	// would treat --live in "validate manifest.yaml --live" as a filename.
	files, err := parseFlagsAndPositionals(fs, rawArgs)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		// 2, not 1: exit 1 is reserved for "drift warnings present", which CI gates on,
		// so a usage error must not read as a policy finding.
		return 2
	}

	transportSet := flagWasSet(fs, "transport")
	// Computed once and referenced at both guard sites below so the two copies of this
	// predicate cannot drift out of lockstep.
	upstreamFlagsGiven := *upstreamURL != "" || *authHeader != "" || *tlsSkipVerify || transportSet || len(stdioCmd) > 0

	// Mode selection: --config is mutually exclusive with positional manifests
	// and per-upstream flags — the config carries that wiring.
	if *configPath != "" {
		if len(files) > 0 {
			fmt.Fprintf(os.Stderr, "eunox validate: --config cannot be combined with positional manifest files (got %d); manifests are declared per-route in the config\n", len(files))
			return 2
		}
		if upstreamFlagsGiven {
			fmt.Fprintf(os.Stderr, "eunox validate: --config cannot be combined with --transport / --upstream-url / --upstream-auth-header / --upstream-tls-skip-verify / a stdio command; each route's transport and upstream wiring is declared in the config\n")
			return 2
		}
		cfg, err := config.LoadGatewayConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox validate: %v\n", err)
			return 2
		}
		// Base context; fetchRouteLive applies its own per-route timeout, so a slow
		// early route cannot exhaust a shared budget and fail the rest.
		return validateConfigRoutes(context.Background(), cfg, *live, os.Stdout)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "eunox validate: at least one manifest file is required (or use --config <eunox.yaml>)%s\n", capturedAfterTerminator(stdioCmd))
		return 2
	}

	// These flags only select how to reach a live upstream, so meaningless without
	// --live; reject rather than silently dropping them.
	if !*live && upstreamFlagsGiven {
		fmt.Fprintf(os.Stderr, "eunox validate: --transport / --upstream-url / --upstream-auth-header / --upstream-tls-skip-verify and a stdio command ('-- <cmd>') only apply with --live; add --live to drift-check against the upstream\n")
		return 2
	}

	// Syntax check (always runs).
	ok := true
	var manifests []*config.LocalManifest
	for _, f := range files {
		m, err := config.LoadManifest(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", f, err)
			ok = false
		} else {
			fmt.Printf("OK    %s  (name=%q version=%q capabilities=%d)\n", f, m.Name, m.Version, len(m.Capabilities))
			manifests = append(manifests, m)
		}
	}
	if !ok {
		// Exit 2 ("parse error"), not 1 ("drift"), so a CI script keyed on codes does
		// not mislabel a corrupt manifest as drift.
		return 2
	}

	// Must run even in the syntax-only path, or two positional manifests with a genuine
	// merge conflict would pass while the equivalent --config route (which always
	// merges) — and `proxy` itself — would refuse to boot on the same conflict.
	merged, err := config.MergeManifests(manifests)
	if err != nil {
		// A merge conflict is a parse-class error (exit 2), not drift.
		fmt.Fprintf(os.Stderr, "eunox validate: %v\n", err)
		return 2
	}

	// Advisory — never affects the exit code, since an unannotated capability is a
	// conservative default, not a defect.
	writeEffectCoverage(os.Stdout, "", merged, true)

	if !*live {
		return 0
	}

	spec, err := buildInitUpstreamSpec(*transportFlag, *upstreamURL, *authHeader, *tlsSkipVerify, stdioCmd)
	if err != nil {
		// A missing/incoherent upstream wiring is a connection error (exit 2), not drift.
		fmt.Fprintf(os.Stderr, "eunox validate: %v (or use --config <eunox.yaml>)\n", err)
		return 2
	}

	fmt.Printf("\nConnecting to upstream...")
	ctx, cancel := context.WithTimeout(context.Background(), liveUpstreamTimeout)
	defer cancel()
	info, err := fetchSpecLive(ctx, spec)
	if err != nil {
		fmt.Printf("  FAILED\n")
		fmt.Fprintf(os.Stderr, "eunox validate: %v\n", err)
		return 2
	}
	versionLabel := info.ServerVersion
	if versionLabel == "" {
		versionLabel = "unknown"
	}
	fmt.Printf("  ok (%d tool(s), server version: %s)\n\n", len(info.Tools), versionLabel)

	return runValidateLive(merged, info.Tools, info.ServerVersion, os.Stdout)
}

// writePolicyLoadResults prints one FAIL/OK line per outcome.LoadResults entry to out, each
// indented by prefix, so validate and doctor cannot diverge on how a route's per-file
// manifest load result is reported.
func writePolicyLoadResults(out io.Writer, prefix string, results []transport.PolicyLoadResult) {
	wf, _ := writers(out)
	for _, lr := range results {
		if lr.Err != nil {
			wf("%sFAIL  %s: %v\n", prefix, lr.Path, lr.Err)
			continue
		}
		wf("%sOK    %s  (name=%q version=%q capabilities=%d)\n", prefix, lr.Path, lr.Manifest.Name, lr.Manifest.Version, len(lr.Manifest.Capabilities))
	}
}

// reportRouteOutcome prints outcome's FAIL/OK/policy-config report for one route and
// reports whether its startup-fatal checks were satisfied. skip is true when the route's
// live-drift introspection must not proceed. Factored out of validateConfigRoutes's loop
// body to keep its nesting flat.
func reportRouteOutcome(out io.Writer, outcome transport.RouteManifestOutcome, live bool) (code int, skip bool) {
	wf, wln := writers(out)
	if outcome.NoPolicy {
		// Flag a config the proxy would refuse to start as FAIL rather than green-lighting
		// it or connecting to an upstream that would never serve traffic.
		if outcome.NoPolicyReason != "" {
			wf("  FAIL  this route fails closed at startup: %s.\n", outcome.NoPolicyReason)
			return 2, true
		}
		if outcome.AuditMode {
			wln("  (no policy configured — observe-only/wiretap route)")
		} else {
			wln("  (no policy configured — route is allow-all)")
		}
		// With --live, fall through to introspection for visibility (no manifest to
		// drift-check, but the upstream connection is still worth showing).
		return 0, !live
	}

	writePolicyLoadResults(out, "  ", outcome.LoadResults)
	if outcome.LoadFailed {
		return 2, true
	}
	if outcome.MergeErr != nil {
		wf("  FAIL  %v\n", outcome.MergeErr)
		return 2, true
	}
	if outcome.StartupErr != nil {
		wf("  FAIL  %v\n", outcome.StartupErr)
		return 2, true
	}
	// Advisory, never part of the exit code: an unannotated capability is the
	// fail-closed default working as intended, not a config defect.
	writeEffectCoverage(out, "  ", outcome.Merged, true)
	return 0, false
}

// validateConfigRoutes walks every upstream in cfg, validating each route's manifest(s)
// and — when live is set — introspecting the declared upstream and reporting drift. Exit
// code is the maximum across routes: 0 clean, 1 drift, 2 parse/connection failure.
func validateConfigRoutes(ctx context.Context, cfg *config.GatewayConfig, live bool, out io.Writer) int {
	wf, wln := writers(out)

	worst := 0
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		if i > 0 {
			wln()
		}
		wf("── route %q (transport: %s) ──\n", u.Name, u.Transport)

		// Reproduces the proxy's actual startup policy-load decision, via the shared
		// walk both validate and doctor use, so validate cannot green-light a config
		// `proxy` would refuse to boot.
		outcome := transport.WalkRouteManifests(cfg, u)

		exitCode, skip := reportRouteOutcome(out, outcome, live)
		if exitCode > worst {
			worst = exitCode
		}
		if skip {
			continue
		}

		if !live {
			continue
		}

		// Live drift check for this route.
		info, err := fetchRouteLive(ctx, u)
		if err != nil {
			wf("  Connecting to upstream...  FAILED\n  %v\n", err)
			if worst < 2 {
				worst = 2
			}
			continue
		}
		versionLabel := info.ServerVersion
		if versionLabel == "" {
			versionLabel = "unknown"
		}
		wf("  Connecting to upstream...  ok (%d tool(s), server version: %s)\n\n", len(info.Tools), versionLabel)

		if outcome.NoPolicy {
			wln("  (no manifest to compare against)")
			continue
		}
		code := runValidateLive(outcome.Merged, info.Tools, info.ServerVersion, out)
		if code > worst {
			worst = code
		}
	}
	return worst
}
