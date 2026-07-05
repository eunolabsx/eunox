// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/pkg/capability"
)

// ─── buildLiveReport ─────────────────────────────────────────────────────────

func TestBuildLiveReport_ExactCovered(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:query_db", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}, {Name: "query_db"}}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.exactCovered) != 2 {
		t.Fatalf("exactCovered: want 2, got %d", len(rep.exactCovered))
	}
	if rep.exactCovered[0].Tool != "query_db" {
		t.Errorf("exactCovered[0]: want query_db (sorted), got %q", rep.exactCovered[0].Tool)
	}
	if len(rep.fm1Warnings) != 0 {
		t.Errorf("fm1Warnings: want 0, got %d", len(rep.fm1Warnings))
	}
	if len(rep.fm2Stale) != 0 {
		t.Errorf("fm2Stale: want 0, got %d", len(rep.fm2Stale))
	}
	if len(rep.uncovered) != 0 {
		t.Errorf("uncovered: want 0, got %d", len(rep.uncovered))
	}
}

func TestBuildLiveReport_GlobMatchedGoesToFM1(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:get_*", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "get_customer"}, {Name: "get_invoice"}}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.exactCovered) != 0 {
		t.Errorf("exactCovered: want 0 (glob matches should not appear here), got %d", len(rep.exactCovered))
	}
	if len(rep.fm1Warnings) != 2 {
		t.Errorf("fm1Warnings: want 2, got %d", len(rep.fm1Warnings))
	}
	// FM-1 slice must be sorted by tool name.
	if rep.fm1Warnings[0].Tool != "get_customer" || rep.fm1Warnings[1].Tool != "get_invoice" {
		t.Errorf("fm1Warnings order: want [get_customer, get_invoice], got [%s, %s]",
			rep.fm1Warnings[0].Tool, rep.fm1Warnings[1].Tool)
	}
}

// TestBuildLiveReport_EqualSpecificityGlobsNotCollapsed is the regression for the
// FM-1 report layer: CheckManifestDrift surfaces one finding per equal-specificity
// glob matching a tool, so buildLiveReport must carry every finding rather than
// keying by tool name — keying by tool would drop all but the last glob, re-hiding
// an over-permission the drift check deliberately reported. Mirrors
// drift.TestCheckManifestDrift_FM1_EqualSpecificityGlobsBothReported one layer up.
func TestBuildLiveReport_EqualSpecificityGlobsNotCollapsed(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_*", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:*_file", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.fm1Warnings) != 2 {
		t.Fatalf("fm1Warnings: want 2 (one per equal-specificity glob for the same tool), got %d: %+v",
			len(rep.fm1Warnings), rep.fm1Warnings)
	}
	resources := map[string]bool{}
	for _, w := range rep.fm1Warnings {
		if w.Tool != "read_file" {
			t.Errorf("fm1 tool: want read_file, got %q", w.Tool)
		}
		resources[w.Resource] = true
	}
	if !resources["tool:read_*"] || !resources["tool:*_file"] {
		t.Errorf("both globs must be surfaced in the report; got resources %v", resources)
	}
	// A glob-matched tool must not also be classified as exact-covered.
	if len(rep.exactCovered) != 0 {
		t.Errorf("exactCovered: want 0, got %d", len(rep.exactCovered))
	}
}

// TestBuildLiveReport_SchemaAbsent pins that a tool omitting its inputSchema while a
// covering constraint pins an argument is classified as an advisory schema_absent
// finding (not silently dropped by the report's kind switch, and not FM-3), and that
// such a tool is kept OUT of COVERED so the outstanding warning is not contradicted.
func TestBuildLiveReport_SchemaAbsent(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Target:  "tool:read_file",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
			},
		},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}} // no InputSchema

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.schemaAbsent) != 1 {
		t.Fatalf("schemaAbsent: want 1, got %d", len(rep.schemaAbsent))
	}
	if rep.schemaAbsent[0].Tool != "read_file" {
		t.Errorf("schemaAbsent tool: want read_file, got %q", rep.schemaAbsent[0].Tool)
	}
	if len(rep.fm3Warnings) != 0 {
		t.Errorf("fm3Warnings: want 0 (no schema means no FM-3), got %d", len(rep.fm3Warnings))
	}
	if len(rep.exactCovered) != 0 {
		t.Errorf("exactCovered: want 0 (a schema_absent tool has an outstanding warning), got %d", len(rep.exactCovered))
	}

	// A SchemaAbsent-only report must exit 0: SchemaAbsent is advisory (not one of
	// FM-1..FM-6), and drift.go classifies it "never fatal" — the running proxy serves
	// this exact config, so `validate --live` must not exit 1 and fail a CI pipeline
	// keyed on the documented "exit 0 == clean (no FM-1..FM-6)" contract.
	var buf bytes.Buffer
	if code := renderLiveReport(rep, &buf); code != 0 {
		t.Errorf("renderLiveReport with only SchemaAbsent findings: exit %d, want 0\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "advisory") {
		t.Errorf("SchemaAbsent-only ok report should still note the advisory warning\n%s", buf.String())
	}
}

func TestBuildLiveReport_FM2StaleEntries(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:legacy_search", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:old_export", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "new_search"}}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.fm2Stale) != 2 {
		t.Errorf("fm2Stale: want 2, got %d", len(rep.fm2Stale))
	}
	// FM-2 slice must be sorted by resource name.
	if rep.fm2Stale[0].Resource != "tool:legacy_search" || rep.fm2Stale[1].Resource != "tool:old_export" {
		t.Errorf("fm2Stale order: want [tool:legacy_search, tool:old_export], got [%s, %s]",
			rep.fm2Stale[0].Resource, rep.fm2Stale[1].Resource)
	}
}

func TestBuildLiveReport_Uncovered(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{
		{Name: "read_file"},
		{Name: "write_file"},
		{Name: "delete_file"},
	}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.uncovered) != 2 {
		t.Fatalf("uncovered: want 2, got %d: %v", len(rep.uncovered), rep.uncovered)
	}
	// Uncovered tools must be sorted.
	if rep.uncovered[0] != "delete_file" || rep.uncovered[1] != "write_file" {
		t.Errorf("uncovered order: want [delete_file, write_file], got %v", rep.uncovered)
	}
}

func TestClassifyDriftWarnings_UnrecognizedKindIsUnclassified(t *testing.T) {
	// A drift.Kind the switch has no case for must not be silently dropped: it needs
	// to land somewhere visible in the report rather than vanish while the summary
	// still says "ok".
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}}
	warnings := []drift.Warning{
		{Kind: drift.Kind("future_kind"), Tool: "read_file", Resource: "tool:read_file"},
	}

	rep := classifyDriftWarnings(manifest, tools, warnings)

	if len(rep.unclassified) != 1 {
		t.Fatalf("unclassified: want 1, got %d", len(rep.unclassified))
	}
	if rep.unclassified[0].Kind != drift.Kind("future_kind") {
		t.Errorf("unclassified[0].Kind: want future_kind, got %q", rep.unclassified[0].Kind)
	}
}

func TestRunValidateLive_UnrecognizedKind_Exit1(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}}
	rep := classifyDriftWarnings(manifest, tools, []drift.Warning{
		{Kind: drift.Kind("future_kind"), Tool: "read_file", Resource: "tool:read_file"},
	})

	var buf strings.Builder
	code := renderLiveReport(rep, &buf)

	if code != 1 {
		t.Errorf("unrecognized kind: expected exit 1 (fail loud), got %d\nOutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "UNCLASSIFIED DRIFT") {
		t.Error("should have UNCLASSIFIED DRIFT section")
	}
	if !strings.Contains(out, "future_kind") {
		t.Error("should mention the unrecognized kind")
	}
	if !strings.Contains(out, "unclassified drift finding") {
		t.Error("result should mention unclassified drift finding")
	}
}

func TestBuildLiveReport_FM3Advisory(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Target:  "tool:read_file",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
			},
		},
	)
	tools := []drift.UpstreamTool{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{"type": "string"},
			},
		},
	}}

	rep := buildLiveReport(manifest, tools, "")

	// read_file has an FM-3 argument-drift warning, so it must NOT appear in
	// COVERED — marking a tool as covered while it also carries a warning is
	// contradictory. COVERED means "covered with no outstanding issues".
	if len(rep.exactCovered) != 0 {
		t.Errorf("exactCovered: want empty (FM-3 tool excluded), got %v", rep.exactCovered)
	}
	if len(rep.fm3Warnings) != 1 {
		t.Errorf("fm3Warnings: want 1, got %d", len(rep.fm3Warnings))
	}
	if rep.fm3Warnings[0].Argument != "path" {
		t.Errorf("fm3Warnings[0].Argument: want path, got %q", rep.fm3Warnings[0].Argument)
	}
}

// TestBuildLiveReport_CleanToolStaysCovered guards that the FM-3/FM-5 exclusion
// does not over-reach: a tool with an exact entry and no outstanding
// warning still appears in COVERED.
func TestBuildLiveReport_CleanToolStaysCovered(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}}
	rep := buildLiveReport(manifest, tools, "")
	if len(rep.exactCovered) != 1 || rep.exactCovered[0].Tool != "read_file" {
		t.Errorf("exactCovered: want [{read_file,...}], got %v", rep.exactCovered)
	}
	if len(rep.fm3Warnings) != 0 {
		t.Errorf("fm3Warnings: want 0, got %d", len(rep.fm3Warnings))
	}
}

// ─── runValidateLive ─────────────────────────────────────────────────────────

func TestRunValidateLive_CleanManifest_Exit0(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:query_db", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}, {Name: "query_db"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 0 {
		t.Errorf("clean manifest: expected exit 0, got %d\nOutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "COVERED") {
		t.Error("clean manifest: output should have COVERED section")
	}
	if !strings.Contains(out, "read_file") {
		t.Error("clean manifest: output should mention read_file")
	}
	if !strings.Contains(out, "query_db") {
		t.Error("clean manifest: output should mention query_db")
	}
	if strings.Contains(out, "WARNINGS") {
		t.Error("clean manifest: output must not have WARNINGS section")
	}
	if !strings.Contains(out, "ok") {
		t.Error("clean manifest: result should say ok")
	}
}

func TestRunValidateLive_FM1GlobMatch_Exit1(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:delete_*", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "delete_all_records"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("glob match: expected exit 1, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "WARNINGS") {
		t.Error("should have WARNINGS section for FM-1")
	}
	if !strings.Contains(out, "delete_all_records") {
		t.Error("should mention delete_all_records in WARNINGS")
	}
	if !strings.Contains(out, "glob match") {
		t.Error("should say 'glob match' in WARNINGS")
	}
	// Glob-matched tool must NOT appear in COVERED (it's not exact-matched).
	if strings.Contains(out, "COVERED") {
		t.Error("output must not have COVERED section when all tools are glob-matched")
	}
	if !strings.Contains(out, "Exit 1") {
		t.Error("result should say Exit 1")
	}
}

func TestRunValidateLive_FM2StaleEntry_Exit1(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:legacy_search", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "new_search"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("stale entry: expected exit 1, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "STALE MANIFEST ENTRIES") {
		t.Error("should have STALE MANIFEST ENTRIES section")
	}
	if !strings.Contains(out, "legacy_search") {
		t.Error("should mention legacy_search as stale")
	}
	if !strings.Contains(out, "stale entry") {
		t.Error("result should say 'stale entry'")
	}
}

func TestRunValidateLive_UncoveredTools_Exit0(t *testing.T) {
	// Uncovered tools are informational and do not cause exit 1.
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{
		{Name: "read_file"},
		{Name: "uncovered_tool"},
	}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 0 {
		t.Errorf("uncovered only: expected exit 0, got %d\nOutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "NOT COVERED") {
		t.Error("should have NOT COVERED section")
	}
	if !strings.Contains(out, "uncovered_tool") {
		t.Error("should mention uncovered_tool")
	}
}

func TestRunValidateLive_FM3ArgumentDrift_Exit1(t *testing.T) {
	// FM-3 (a condition argument absent from the live inputSchema) is a potential
	// enforcement gap: the condition may never fire. It must fail the run (exit 1)
	// rather than printing "Result: ok" and exit 0, which would let CI pass
	// silently over a visible WARNINGS line.
	manifest := manifestWith(
		capability.Constraint{
			Target:  "tool:read_file",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/reports/*"}},
			},
		},
	)
	tools := []drift.UpstreamTool{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{"type": "string"},
			},
		},
	}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("FM-3 argument drift: expected exit 1, got %d\nOutput:\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "WARNINGS") {
		t.Error("FM-3 should appear in WARNINGS section")
	}
	if !strings.Contains(out, `"path"`) {
		t.Error("output should mention the missing argument name")
	}
	// The "ok" result must NOT be printed when an FM-3 warning is present.
	if strings.Contains(out, "Result: ok") {
		t.Errorf("must not print 'Result: ok' with an FM-3 warning present\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "argument drift") {
		t.Error("result summary should mention argument drift")
	}
}

func TestRunValidateLive_Mixed(t *testing.T) {
	// Scenario: one exact match, one glob match, one stale entry, one uncovered tool.
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:get_*", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:legacy_tool", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{
		{Name: "read_file"},
		{Name: "get_customer"},
		{Name: "uncovered_tool"},
	}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("mixed: expected exit 1, got %d", code)
	}
	out := buf.String()

	if !strings.Contains(out, "COVERED") || !strings.Contains(out, "read_file") {
		t.Error("read_file should appear in COVERED (exact match)")
	}
	if !strings.Contains(out, "WARNINGS") || !strings.Contains(out, "get_customer") {
		t.Error("get_customer should appear in WARNINGS (glob match)")
	}
	if !strings.Contains(out, "NOT COVERED") || !strings.Contains(out, "uncovered_tool") {
		t.Error("uncovered_tool should appear in NOT COVERED")
	}
	if !strings.Contains(out, "STALE MANIFEST ENTRIES") || !strings.Contains(out, "legacy_tool") {
		t.Error("legacy_tool should appear in STALE MANIFEST ENTRIES")
	}

	// Result should summarize both findings.
	if !strings.Contains(out, "glob match") {
		t.Error("result should mention glob match(es)")
	}
	if !strings.Contains(out, "stale entry") {
		t.Error("result should mention stale entry(ies)")
	}
}

func TestRunValidateLive_MultipleGlobMatches_PluralResult(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:get_*", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{
		{Name: "get_customer"},
		{Name: "get_invoice"},
		{Name: "get_report"},
	}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("3 glob matches: expected exit 1, got %d", code)
	}
	if !strings.Contains(buf.String(), "3 glob matches") {
		t.Errorf("result should say '3 glob matches', got: %s", buf.String())
	}
}

func TestRunValidateLive_MultipleStaleEntries_PluralResult(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:old_tool_a", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:old_tool_b", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "new_tool"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("2 stale entries: expected exit 1, got %d", code)
	}
	if !strings.Contains(buf.String(), "2 stale entries") {
		t.Errorf("result should say '2 stale entries', got: %s", buf.String())
	}
}

func TestRunValidateLive_EmptyToolList_Exit1(t *testing.T) {
	// Empty tool list means every manifest entry is stale.
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)

	var buf strings.Builder
	code := runValidateLive(manifest, nil, "", &buf)

	if code != 1 {
		t.Errorf("empty tools: expected exit 1 (stale manifest), got %d", code)
	}
	if !strings.Contains(buf.String(), "STALE") {
		t.Error("should have STALE section for empty tool list")
	}
}

func TestRunValidateLive_SectionsOmittedWhenEmpty(t *testing.T) {
	// Clean manifest — only COVERED should be present.
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	runValidateLive(manifest, tools, "", &buf)
	out := buf.String()

	for _, absent := range []string{"WARNINGS", "NOT COVERED", "STALE"} {
		if strings.Contains(out, absent) {
			t.Errorf("section %q should be absent for clean manifest", absent)
		}
	}
}

func TestRunValidateLive_ExactMatchLabelInCovered(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	runValidateLive(manifest, tools, "", &buf)

	// The COVERED line should show the resource name.
	out := buf.String()
	if !strings.Contains(out, "read_file") {
		t.Error("COVERED should show the resource name")
	}
}

func TestRunValidateLive_BlankLineBetweenSections(t *testing.T) {
	// When multiple sections are present there should be a blank line between them.
	manifest := manifestWith(
		capability.Constraint{Target: "tool:get_*", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{
		{Name: "get_customer"},
		{Name: "uncovered_tool"},
	}

	var buf strings.Builder
	runValidateLive(manifest, tools, "", &buf)
	out := buf.String()

	// There must be at least one blank line in the output (section separator).
	if !strings.Contains(out, "\n\n") {
		t.Error("output should contain at least one blank line between sections")
	}
}

// ─── FM-4: server version pinning ────────────────────────────────────────────

func TestBuildLiveReport_FM4_VersionMismatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.3"
	tools := []drift.UpstreamTool{{Name: "read_file"}}

	rep := buildLiveReport(manifest, tools, "1.3.0")

	if len(rep.fm4Warnings) != 1 {
		t.Fatalf("fm4Warnings: want 1, got %d", len(rep.fm4Warnings))
	}
	if rep.fm4Warnings[0].Resource != "1.2.3" {
		t.Errorf("fm4Warnings[0].Resource: want 1.2.3, got %q", rep.fm4Warnings[0].Resource)
	}
	if rep.fm4Warnings[0].VersionActual != "1.3.0" {
		t.Errorf("fm4Warnings[0].VersionActual: want 1.3.0, got %q", rep.fm4Warnings[0].VersionActual)
	}
}

func TestBuildLiveReport_FM4_VersionMatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.*"
	tools := []drift.UpstreamTool{{Name: "read_file"}}

	rep := buildLiveReport(manifest, tools, "1.2.5")

	if len(rep.fm4Warnings) != 0 {
		t.Errorf("fm4Warnings: want 0, got %d (wildcard match should not fire)", len(rep.fm4Warnings))
	}
}

func TestRunValidateLive_FM4VersionMismatch_Exit1(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.3"
	tools := []drift.UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "2.0.0", &buf)

	if code != 1 {
		t.Errorf("version mismatch: expected exit 1, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "WARNINGS") {
		t.Error("FM-4 should appear in WARNINGS section")
	}
	if !strings.Contains(out, "SERVER VERSION MISMATCH") {
		t.Error("FM-4 should show SERVER VERSION MISMATCH label")
	}
	if !strings.Contains(out, "1.2.3") {
		t.Error("output should show the pinned constraint")
	}
	if !strings.Contains(out, "2.0.0") {
		t.Error("output should show the actual version")
	}
	if !strings.Contains(out, "server version mismatch") {
		t.Error("result line should mention server version mismatch")
	}
}

func TestRunValidateLive_FM4VersionMatch_NoWarning(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.*"
	tools := []drift.UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "1.2.5", &buf)

	if code != 0 {
		t.Errorf("wildcard version match: expected exit 0, got %d\nOutput:\n%s", code, buf.String())
	}
	if strings.Contains(buf.String(), "SERVER VERSION MISMATCH") {
		t.Error("output must not contain SERVER VERSION MISMATCH for matching version")
	}
}

func TestRunValidateLive_FM4UnknownVersion_Exit1(t *testing.T) {
	// Server doesn't report a version but manifest has a pin.
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.0.0"
	tools := []drift.UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "", &buf)

	if code != 1 {
		t.Errorf("unknown version with pin: expected exit 1, got %d", code)
	}
	if !strings.Contains(buf.String(), "(unknown)") {
		t.Error("output should show (unknown) when server version is absent")
	}
}

func TestRunValidateLive_FM4NoPinConfigured_NoWarning(t *testing.T) {
	// No serverVersion in manifest — FM-4 must never fire regardless of actual.
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	tools := []drift.UpstreamTool{{Name: "read_file"}}

	var buf strings.Builder
	code := runValidateLive(manifest, tools, "99.0.0", &buf)

	if code != 0 {
		t.Errorf("no pin configured: expected exit 0, got %d\nOutput:\n%s", code, buf.String())
	}
	if strings.Contains(buf.String(), "SERVER VERSION") {
		t.Error("no server version warning expected when no pin is configured")
	}
}

// ===== merged from drift_test.go =====

func TestBuildLiveReport_FM5_DescriptionMismatch(t *testing.T) {
	hash := capability.ComputeToolHash("Safe description.", nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: hash},
	)
	tools := []drift.UpstreamTool{{Name: "read_file", Description: "POISONED"}}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.fm5Warnings) != 1 {
		t.Fatalf("fm5Warnings: want 1, got %d", len(rep.fm5Warnings))
	}
	if rep.fm5Warnings[0].Tool != "read_file" {
		t.Errorf("fm5Warnings[0].Tool: want read_file, got %q", rep.fm5Warnings[0].Tool)
	}
}

func TestBuildLiveReport_FM5_HashMatch_NotInWarnings(t *testing.T) {
	desc := "Reads a file."
	hash := capability.ComputeToolHash(desc, nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: hash},
	)
	tools := []drift.UpstreamTool{{Name: "read_file", Description: desc}}

	rep := buildLiveReport(manifest, tools, "")

	if len(rep.fm5Warnings) != 0 {
		t.Errorf("fm5Warnings: want 0, got %d: %v", len(rep.fm5Warnings), rep.fm5Warnings)
	}
}
