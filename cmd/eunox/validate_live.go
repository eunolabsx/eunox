// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Live drift report formatter for the validate --live subcommand.
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
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
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
	// FM-1 accumulates as a slice, not a map keyed by tool name: CheckManifestDrift
	// can now return two FM-1 findings for one tool (two equal-specificity globs both
	// matching it), and keying by tool name would drop all but the last — re-hiding an
	// over-permission the drift check deliberately surfaced. fm1Tools tracks which
	// tools have any FM-1 so the COVERED classification below can still exclude them.
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
			// Critical: a descriptionHash-pinned tool is absent upstream, so its
			// integrity cannot be verified and the proxy REFUSES TO START (same gate
			// as FM-5). Surfaced distinctly from an advisory stale entry — deleting
			// the entry would lower security by dropping the pin.
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
			// A drift.Kind this report doesn't recognize yet. Route it into a visible
			// bucket instead of silently dropping it — a switch with no default here
			// previously let an unhandled Kind vanish from the report while
			// "Result: ok" printed, the exact fail-open shape the rest of this codebase
			// guards against.
			unclassified = append(unclassified, *w)
		}
	}

	// Tools with an outstanding FM-3 (argument drift), FM-5 (description-hash
	// mismatch), or FM-6 warning must NOT also appear in COVERED: a contradictory
	// [OK]/[FAIL] pair would let an operator scanning COVERED miss the warning. COVERED
	// means "covered with no outstanding issues".
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

// sortedWarnings drains a resource-name -> Warning map into a slice ordered by
// resource, so the drift report is deterministic (Go randomizes map iteration order).
// Used by the FM-2 and FM-2-pinned sections. FM-1 is not keyed here: one tool can
// carry several glob findings, so it accumulates a slice and sorts inline (see
// buildLiveReport).
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
			// FM-2Pinned ("tool absent, hash can't be checked") is the startup-blocking
			// counterpart to FM-5 ("tool present, hash wrong"). Mark CRITICAL so it is
			// not mistaken for an advisory stale entry below.
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

	// SchemaAbsent is advisory (never one of FM-1..FM-6) — drift.go classifies it as
	// "advisory, never fatal" and the runtime hook forwards on it, so it must not gate
	// exit here. The documented contract is "exit 0 == no FM-1..FM-6 findings"; a
	// SchemaAbsent-only report stays exit 0 (its [WARN] line is still rendered above).
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
