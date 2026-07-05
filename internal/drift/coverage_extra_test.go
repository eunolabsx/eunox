// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestDriftProbeUnavailable_SkipEmitsObservableWarning guards the visibility of a
// skipped drift probe: a
// glob-only manifest in non-strict mode still SKIPS the drift probe (returns nil,
// non-blocking) when tools/list is unavailable, but the skip must be OBSERVABLE — a
// structured warning that names the failure reason and states drift was NOT verified
// — so an operator never mistakes "probe skipped, drift unknown" for "probe
// succeeded, no drift detected".
func TestDriftProbeUnavailable_SkipEmitsObservableWarning(t *testing.T) {
	manifest := &config.LocalManifest{
		Capabilities: []capability.Constraint{
			// A glob entry with no descriptionHash pin: the skip stays non-fatal.
			{Target: "tool:read_*", Actions: []string{"call"}},
		},
	}

	old := os.Stderr
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("pipe: %v", perr)
	}
	os.Stderr = w
	err := driftProbeUnavailable(manifest, false, errors.New("dial tcp: connection refused"))
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("non-strict glob-only skip must stay non-blocking, got %v", err)
	}
	out := buf.String()
	for _, want := range []string{"drift=skipped", "NOT verified", "connection refused"} {
		if !strings.Contains(out, want) {
			t.Fatalf("skip warning must contain %q; got:\n%s", want, out)
		}
	}
}

// ─── MakeDriftCheck ───────────────────────────────────────────────────────────

// TestMakeDriftCheck_NilManifest confirms a nil manifest disables drift checking.
func TestMakeDriftCheck_NilManifest(t *testing.T) {
	if fn := MakeDriftCheck(nil, false); fn != nil {
		t.Error("MakeDriftCheck(nil, ...) must return a nil CheckFunc")
	}
}

// TestMakeDriftCheck_SuccessClean drives the success path: a well-formed
// tools/list result that matches the manifest yields no error.
func TestMakeDriftCheck_SuccessClean(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	fn := MakeDriftCheck(manifest, false)
	if fn == nil {
		t.Fatal("expected a non-nil CheckFunc for a non-nil manifest")
	}
	raw := json.RawMessage(`{"tools":[{"name":"read_file"}]}`)
	if err := fn(raw, "", nil); err != nil {
		t.Errorf("clean drift check must succeed, got %v", err)
	}
}

// TestMakeDriftCheck_SuccessDetectsCriticalDrift confirms the success path still
// returns an abort error when the parsed tools reveal critical (FM-5) drift.
func TestMakeDriftCheck_SuccessDetectsCriticalDrift(t *testing.T) {
	hash := capability.ComputeToolHash("Original safe description.", nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: hash},
	)
	fn := MakeDriftCheck(manifest, false)
	raw := json.RawMessage(`{"tools":[{"name":"read_file","description":"POISONED"}]}`)
	if err := fn(raw, "", nil); err == nil {
		t.Error("FM-5 description mismatch must abort even in non-strict mode")
	}
}

// TestMakeDriftCheck_ProbeError_NoPinsSkips covers the probe-failure path when
// the manifest has no descriptionHash pins: the failure is a best-effort skip.
func TestMakeDriftCheck_ProbeError_NoPinsSkips(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	fn := MakeDriftCheck(manifest, false)
	if err := fn(nil, "", errors.New("upstream timeout")); err != nil {
		t.Errorf("probe failure without pins must be a skip (nil error), got %v", err)
	}
}

// TestMakeDriftCheck_ProbeError_WithPinsFatal covers the probe-failure path when
// the manifest pins a descriptionHash: the failure must be fatal (fail closed).
func TestMakeDriftCheck_ProbeError_WithPinsFatal(t *testing.T) {
	hash := capability.ComputeToolHash("Reads a file.", nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: hash},
	)
	fn := MakeDriftCheck(manifest, false)
	err := fn(nil, "", errors.New("upstream timeout"))
	if err == nil {
		t.Fatal("probe failure with descriptionHash pins must be fatal")
	}
	if !strings.Contains(err.Error(), "descriptionHash pins") {
		t.Errorf("fatal error should mention descriptionHash pins, got %v", err)
	}
	if !strings.Contains(err.Error(), "upstream timeout") {
		t.Errorf("fatal error must wrap the probe error, got %v", err)
	}
}

// TestMakeDriftCheck_ProbeError_EmitsServerVersionDrift covers the FM-4-on-probe-
// failure path: serverVersion comes from the initialize handshake, so a manifest
// that pins only serverVersion (no descriptionHash) must still have that pin checked
// and its mismatch surfaced even when the tools/list probe fails. Non-strict, so the
// session is not aborted (FM-4 is advisory), but the warning must be emitted.
func TestMakeDriftCheck_ProbeError_EmitsServerVersionDrift(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_*", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.*" // version pin, no descriptionHash
	fn := MakeDriftCheck(manifest, false)

	old := os.Stderr
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("pipe: %v", perr)
	}
	os.Stderr = w
	// Probe failed, but the initialize handshake reported version 2.0.0, which does
	// not satisfy the "1.2.*" pin.
	err := fn(nil, "2.0.0", errors.New("upstream timeout"))
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("non-strict probe failure must stay non-blocking, got %v", err)
	}
	out := buf.String()
	for _, want := range []string{"drift=fm4", "2.0.0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("probe-failure path must still emit the FM-4 version-pin warning containing %q; got:\n%s", want, out)
		}
	}
}

// TestMakeDriftCheck_ParseError_EmitsServerVersionDrift is the parse-failure twin of
// TestMakeDriftCheck_ProbeError_EmitsServerVersionDrift: a malformed tools/list still
// loses the live tool list, but serverVersion comes from the completed initialize
// handshake, so a serverVersion-only pin must still be checked and its mismatch
// surfaced on this branch too. Non-strict, so the session is not aborted.
func TestMakeDriftCheck_ParseError_EmitsServerVersionDrift(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_*", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.*" // version pin, no descriptionHash
	fn := MakeDriftCheck(manifest, false)

	old := os.Stderr
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("pipe: %v", perr)
	}
	os.Stderr = w
	// tools/list parse fails (nil probe error), but the initialize handshake reported
	// version 2.0.0, which does not satisfy the "1.2.*" pin.
	err := fn(json.RawMessage(`{not valid`), "2.0.0", nil)
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("non-strict parse failure must stay non-blocking, got %v", err)
	}
	out := buf.String()
	for _, want := range []string{"drift=fm4", "2.0.0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("parse-failure path must still emit the FM-4 version-pin warning containing %q; got:\n%s", want, out)
		}
	}
}

// TestMakeDriftCheck_ProbeError_StrictNoPinsFatal is the regression test for the
// strict-drift bypass: a manifest with a glob entry and NO descriptionHash pin,
// under --strict-drift, against an upstream whose tools/list probe fails. The
// probe failure must abort startup — otherwise a drifted (or malicious) upstream
// could dodge FM-1/FM-2/FM-4 detection simply by withholding tools/list.
func TestMakeDriftCheck_ProbeError_StrictNoPinsFatal(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_*", Actions: []string{"call"}},
	)
	manifest.ServerVersion = "1.2.*" // an FM-4-eligible pin, still no descriptionHash
	fn := MakeDriftCheck(manifest, true)
	err := fn(nil, "", errors.New("upstream timeout"))
	if err == nil {
		t.Fatal("strict mode + unpinned manifest + failing probe must abort startup")
	}
	if !strings.Contains(err.Error(), "strict-drift") {
		t.Errorf("strict abort error should mention strict-drift, got %v", err)
	}
	if !strings.Contains(err.Error(), "upstream timeout") {
		t.Errorf("fatal error must wrap the probe error, got %v", err)
	}
}

// TestMakeDriftCheck_ParseError_NoPinsSkips covers the parse-failure branch
// (malformed tools/list with a nil probe error): with no pins it is a skip.
func TestMakeDriftCheck_ParseError_NoPinsSkips(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	fn := MakeDriftCheck(manifest, false)
	if err := fn(json.RawMessage(`not-json`), "", nil); err != nil {
		t.Errorf("parse failure without pins must be a skip (nil error), got %v", err)
	}
}

// TestMakeDriftCheck_ParseError_WithPinsFatal covers the parse-failure branch
// when the manifest pins a descriptionHash: it must be fatal (fail closed).
func TestMakeDriftCheck_ParseError_WithPinsFatal(t *testing.T) {
	hash := capability.ComputeToolHash("Reads a file.", nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: hash},
	)
	fn := MakeDriftCheck(manifest, false)
	if err := fn(json.RawMessage(`{not valid`), "", nil); err == nil {
		t.Error("parse failure with descriptionHash pins must be fatal")
	}
}

// TestMakeDriftCheck_ParseError_StrictNoPinsFatal confirms strict mode also makes
// a malformed tools/list (parse failure, no descriptionHash pin) fatal: a result
// we cannot parse is as opaque to drift checking as a probe we cannot complete.
func TestMakeDriftCheck_ParseError_StrictNoPinsFatal(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_*", Actions: []string{"call"}},
	)
	fn := MakeDriftCheck(manifest, true)
	if err := fn(json.RawMessage(`{not valid`), "", nil); err == nil {
		t.Error("strict mode + unpinned manifest + parse failure must be fatal")
	}
}

// TestMakeDriftCheck_TruncatedList_WithPinsFatal is a regression test: an upstream
// that ends pagination early returns fewer tools than the manifest names. When the
// two PINNED tools are named and only one comes back, the hidden tool is a pinned
// tool whose description hash we cannot verify (it could be a poisoned variant), so the
// truncation must abort startup — even though the pinned tool we did receive would
// itself verify. This is caught by the normal Fm2Pinned check (unconditionally
// fatal via hasCriticalDrift), not a dedicated truncation-floor guard: a manifest
// exact tool hidden by truncated pagination is absent from the live list exactly
// like a removed/renamed one, and Fm2Pinned does not care why it's absent.
func TestMakeDriftCheck_TruncatedList_WithPinsFatal(t *testing.T) {
	readHash := capability.ComputeToolHash("Reads a file.", nil)
	writeHash := capability.ComputeToolHash("Writes a file.", nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: readHash},
		capability.Constraint{Target: "tool:write_file", Actions: []string{"call"}, DescriptionHash: writeHash},
	)
	fn := MakeDriftCheck(manifest, false)
	// Only one of the two pinned tools comes back: the list was truncated, hiding a
	// pinned tool whose hash can no longer be verified.
	raw := json.RawMessage(`{"tools":[{"name":"read_file"}]}`)
	if err := fn(raw, "", nil); err == nil {
		t.Fatal("a tools/list that hides a descriptionHash-pinned tool must be fatal (Fm2Pinned)")
	}
}

// TestFm2PinnedLogLine_MentionsTruncation pins that the Fm2Pinned message names
// truncated pagination as a possible cause of a pinned tool's absence — the
// diagnostic the now-deleted truncation-floor guard used to carry in its own fatal
// error text lives here instead, in the finding's LogLine, since Fm2Pinned is now
// the sole path by which a truncation-hidden pinned tool is reported.
func TestFm2PinnedLogLine_MentionsTruncation(t *testing.T) {
	w := Warning{Kind: Fm2Pinned, Resource: "tool:write_file"}
	if !strings.Contains(w.LogLine(), "truncat") {
		t.Errorf("Fm2Pinned LogLine should mention possible truncation, got %q", w.LogLine())
	}
}

// TestFm2LogLine_MentionsTruncation is Fm2PinnedLogLine's sibling for the
// unpinned/non-fatal-by-default finding.
func TestFm2LogLine_MentionsTruncation(t *testing.T) {
	w := Warning{Kind: Fm2, Resource: "tool:write_file"}
	if !strings.Contains(w.LogLine(), "truncat") {
		t.Errorf("Fm2 LogLine should mention possible truncation, got %q", w.LogLine())
	}
}

// TestFm2LogLine_CitesLiveAndExpectedCounts pins that LiveToolCount/
// ExpectedToolCount actually render into the LogLine text: the quantified,
// list-wide evidence (how many live tools this session saw vs. how many the
// manifest names) the deleted truncation-floor guard used to carry in its own
// fatal error must still be visible to an operator, even though it no longer
// gates the fatal-abort decision.
func TestFm2LogLine_CitesLiveAndExpectedCounts(t *testing.T) {
	for _, kind := range []Kind{Fm2, Fm2Pinned} {
		w := Warning{Kind: kind, Resource: "tool:write_file", LiveToolCount: 3, ExpectedToolCount: 5}
		line := w.LogLine()
		if !strings.Contains(line, "3 live tool") || !strings.Contains(line, "5 exact tool") {
			t.Errorf("%s LogLine should cite the live/expected counts (3, 5), got %q", kind, line)
		}
	}
}

// TestLiveAndExpectedToolCounts pins the two counts liveAndExpectedToolCounts
// derives: the distinct LIVE tool-name count (duplicates in the live list
// collapse, so an upstream cannot inflate it by padding), and the distinct
// manifest EXACT tool-name count (globs and non-tool targets are excluded,
// and a duplicate exact target — the config layer permits pinned + unpinned
// entries for one name — collapses too).
func TestLiveAndExpectedToolCounts(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: "duplicate-exact-target"}, // collapses with the above
		capability.Constraint{Target: "tool:write_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:delete_*", Actions: []string{"call"}}, // glob: excluded
		capability.Constraint{Target: "resource:db/*", Actions: []string{"read"}}, // non-tool: excluded
	)
	live := []UpstreamTool{{Name: "read_file"}, {Name: "read_file"}, {Name: "other_tool"}} // duplicate live entry collapses

	liveCount, expectedCount := liveAndExpectedToolCounts(manifest, live)
	if liveCount != 2 {
		t.Errorf("liveCount = %d, want 2 (read_file + other_tool, duplicate collapsed)", liveCount)
	}
	if expectedCount != 2 {
		t.Errorf("expectedCount = %d, want 2 (read_file + write_file; glob and resource excluded, duplicate exact target collapsed)", expectedCount)
	}
}

// TestCheckManifestDrift_Fm2Pinned_PopulatesCounts is the end-to-end
// regression: CheckManifestDrift must actually populate LiveToolCount/
// ExpectedToolCount on an emitted Fm2Pinned finding, not just leave the
// zero-value the struct literal tests above set by hand.
func TestCheckManifestDrift_Fm2Pinned_PopulatesCounts(t *testing.T) {
	writeHash := capability.ComputeToolHash("Writes a file.", nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:write_file", Actions: []string{"call"}, DescriptionHash: writeHash},
	)
	live := []UpstreamTool{{Name: "read_file", Description: "Reads a file."}}

	warnings := CheckManifestDrift(manifest, live, "")
	var found bool
	for _, w := range warnings {
		if w.Kind != Fm2Pinned {
			continue
		}
		found = true
		if w.LiveToolCount != 1 {
			t.Errorf("Fm2Pinned.LiveToolCount = %d, want 1", w.LiveToolCount)
		}
		if w.ExpectedToolCount != 2 {
			t.Errorf("Fm2Pinned.ExpectedToolCount = %d, want 2", w.ExpectedToolCount)
		}
	}
	if !found {
		t.Fatal("expected an Fm2Pinned finding for the absent pinned write_file tool")
	}
}

// TestMakeDriftCheck_UnpinnedGhost_NonStrictNotFatal confirms a manifest that
// legitimately over-lists a removed/renamed UNPINNED tool does NOT abort startup
// merely because some OTHER tool carries a descriptionHash pin: the absent unpinned
// tool is a dead reference (plain Fm2, advisory in non-strict mode), not an
// unverifiable-integrity gap — Fm2Pinned fires only for the constraint that is
// itself pinned, and read_file's own hash verifies cleanly here.
func TestMakeDriftCheck_UnpinnedGhost_NonStrictNotFatal(t *testing.T) {
	hash := capability.ComputeToolHash("Reads a file.", nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: hash}, // pinned, present
		capability.Constraint{Target: "tool:ghost", Actions: []string{"call"}},                            // unpinned, removed upstream
	)
	fn := MakeDriftCheck(manifest, false)
	// The upstream honestly returns only the tool it still exposes, with the pinned
	// description intact so read_file's own hash verifies cleanly.
	raw := json.RawMessage(`{"tools":[{"name":"read_file","description":"Reads a file."}]}`)
	if err := fn(raw, "", nil); err != nil {
		t.Errorf("an unpinned dead reference under a non-strict manifest (even with an unrelated pin) must be advisory FM-2, not a fatal truncation abort, got %v", err)
	}
}

// TestMakeDriftCheck_TruncatedList_StrictFatal confirms --strict-drift also makes a
// short tools/list fatal, even with no descriptionHash pins: under strict mode a list
// we cannot trust is as opaque as a probe we cannot complete. Caught by plain Fm2
// (fatal under --strict-drift via IsFatal/hasFatalDrift), not a dedicated guard.
func TestMakeDriftCheck_TruncatedList_StrictFatal(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:write_file", Actions: []string{"call"}},
	)
	fn := MakeDriftCheck(manifest, true)
	raw := json.RawMessage(`{"tools":[{"name":"read_file"}]}`)
	if err := fn(raw, "", nil); err == nil {
		t.Fatal("strict mode + a missing exact tool must abort startup (Fm2, fatal under --strict-drift)")
	}
}

// TestMakeDriftCheck_ShortList_NoPinsNonStrictRunsChecks confirms the no-regression
// path: a short list under a non-strict, unpinned manifest is NOT treated as fatal
// truncation — it falls through to the normal checks, which flag the missing tool as a
// non-fatal FM-2 and let the session continue. Aborting an unpinned non-strict session
// over a (possibly legitimate) tool removal would be a regression.
func TestMakeDriftCheck_ShortList_NoPinsNonStrictRunsChecks(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:write_file", Actions: []string{"call"}},
	)
	fn := MakeDriftCheck(manifest, false)
	raw := json.RawMessage(`{"tools":[{"name":"read_file"}]}`)
	if err := fn(raw, "", nil); err != nil {
		t.Errorf("a short list under a non-strict, unpinned manifest must not abort (FM-2 warns and continues), got %v", err)
	}
}

// TestMakeDriftCheck_DuplicatePaddedList_WithPinsFatal pins that an upstream cannot
// evade drift detection by padding a short list with DUPLICATE entries: presence is
// determined by anyToolMatches (a live-list membership test), which duplicate entries
// cannot fake, so [read_file, read_file] still leaves the pinned write_file absent
// and Fm2Pinned fatal. This anti-padding property now comes for free from
// presence-based matching rather than a dedicated distinct-count floor.
func TestMakeDriftCheck_DuplicatePaddedList_WithPinsFatal(t *testing.T) {
	readHash := capability.ComputeToolHash("Reads a file.", nil)
	writeHash := capability.ComputeToolHash("Writes a file.", nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: readHash},
		capability.Constraint{Target: "tool:write_file", Actions: []string{"call"}, DescriptionHash: writeHash},
	)
	fn := MakeDriftCheck(manifest, false)
	// Two entries but only ONE distinct name: the pinned write_file is hidden behind a duplicate.
	raw := json.RawMessage(`{"tools":[{"name":"read_file"},{"name":"read_file"}]}`)
	if err := fn(raw, "", nil); err == nil {
		t.Fatal("a duplicate-padded list hiding a pinned tool must be fatal (Fm2Pinned)")
	}
}

// ─── driftProbeUnavailable ────────────────────────────────────────────────────

// TestDriftProbeUnavailable_NoPinsSkips confirms the skip branch returns nil when
// neither pins nor strict mode are in play.
func TestDriftProbeUnavailable_NoPinsSkips(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	if err := driftProbeUnavailable(manifest, false, errors.New("boom")); err != nil {
		t.Errorf("no pins, non-strict: driftProbeUnavailable must return nil, got %v", err)
	}
}

// TestDriftProbeUnavailable_WithPinsFatal confirms the fatal branch wraps the err.
func TestDriftProbeUnavailable_WithPinsFatal(t *testing.T) {
	hash := capability.ComputeToolHash("Reads a file.", nil)
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}, DescriptionHash: hash},
	)
	wrapped := errors.New("connection refused")
	err := driftProbeUnavailable(manifest, false, wrapped)
	if err == nil {
		t.Fatal("pins present: driftProbeUnavailable must return a fatal error")
	}
	if !errors.Is(err, wrapped) {
		t.Errorf("fatal error must wrap the original error, got %v", err)
	}
}

// TestDriftProbeUnavailable_StrictNoPinsFatal confirms that strict mode makes a
// probe failure fatal even when the manifest pins no descriptionHash — under
// --strict-drift an unreachable probe is indistinguishable from drift, so the
// FM-1/FM-2/FM-4 fatal-on-drift guarantee must not be silently voided.
func TestDriftProbeUnavailable_StrictNoPinsFatal(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_*", Actions: []string{"call"}},
	)
	wrapped := errors.New("connection refused")
	err := driftProbeUnavailable(manifest, true, wrapped)
	if err == nil {
		t.Fatal("strict mode without pins: a probe failure must be fatal")
	}
	if !errors.Is(err, wrapped) {
		t.Errorf("fatal error must wrap the original error, got %v", err)
	}
	if !strings.Contains(err.Error(), "strict-drift") {
		t.Errorf("strict abort error should mention strict-drift, got %v", err)
	}
}

// ─── evaluateDrift ────────────────────────────────────────────────────────────

// TestEvaluateDrift_Clean confirms a no-finding tool set returns nil.
func TestEvaluateDrift_Clean(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}}
	if err := evaluateDrift(manifest, tools, "", false); err != nil {
		t.Errorf("clean drift evaluation must return nil, got %v", err)
	}
}

// TestEvaluateDrift_StrictFatalAborts covers the strict && hasFatalDrift branch:
// an FM-1 (glob over-permission) finding aborts only when strict is set.
func TestEvaluateDrift_StrictFatalAborts(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_*", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}}

	// Non-strict: FM-1 is advisory, so the session continues.
	if err := evaluateDrift(manifest, tools, "", false); err != nil {
		t.Errorf("non-strict FM-1 must not abort, got %v", err)
	}
	// Strict: the same FM-1 finding aborts startup.
	err := evaluateDrift(manifest, tools, "", true)
	if err == nil {
		t.Fatal("strict mode must abort on a fatal (FM-1) finding")
	}
	if !strings.Contains(err.Error(), "strict-drift") {
		t.Errorf("strict abort error should mention strict-drift, got %v", err)
	}
}

// TestEvaluateDrift_NonFatalStrictNoAbort confirms that strict mode does not
// abort when only advisory (FM-3 / uncovered) findings are present.
func TestEvaluateDrift_NonFatalStrictNoAbort(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Target:  "tool:read_file",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/x"}},
			},
		},
	)
	// read_file matches but renames the pinned arg (FM-3, advisory); an extra
	// uncovered tool is advisory too. No FM-1/2/4/5.
	tools := []UpstreamTool{
		{
			Name: "read_file",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{"file_path": map[string]interface{}{}},
			},
		},
		{Name: "extra_tool"},
	}
	if err := evaluateDrift(manifest, tools, "", true); err != nil {
		t.Errorf("strict mode must not abort on advisory-only findings, got %v", err)
	}
}

// ─── FetchAllToolPages error / bound paths ────────────────────────────────────

// TestFetchAllToolPages_FetchError surfaces a fetcher error immediately.
func TestFetchAllToolPages_FetchError(t *testing.T) {
	want := errors.New("network down")
	_, err := FetchAllToolPages(func(_ string) (json.RawMessage, error) {
		return nil, want
	})
	if !errors.Is(err, want) {
		t.Errorf("FetchAllToolPages must propagate the fetcher error, got %v", err)
	}
}

// TestFetchAllToolPages_InvalidJSON covers the per-page unmarshal error path.
func TestFetchAllToolPages_InvalidJSON(t *testing.T) {
	_, err := FetchAllToolPages(func(_ string) (json.RawMessage, error) {
		return json.RawMessage(`{not valid json`), nil
	})
	if err == nil {
		t.Fatal("expected an error for a malformed page")
	}
	if !strings.Contains(err.Error(), "parsing tools/list page") {
		t.Errorf("error should mention parsing the page, got %v", err)
	}
}

// TestFetchAllToolPages_EmptyPageStops confirms a zero-length raw page (len==0)
// terminates pagination cleanly by skipping the unmarshal and yielding no tools.
func TestFetchAllToolPages_EmptyPageStops(t *testing.T) {
	merged, err := FetchAllToolPages(func(_ string) (json.RawMessage, error) {
		return json.RawMessage(``), nil
	})
	if err != nil {
		t.Fatalf("empty page must not error, got %v", err)
	}
	tools, err := ParseToolsListResult(merged)
	if err != nil {
		t.Fatalf("ParseToolsListResult: %v", err)
	}
	if len(tools) != 0 {
		t.Errorf("empty page should yield no tools, got %d", len(tools))
	}
}

// TestFetchAllToolPages_TooManyTools covers the per-tool ceiling: a page that
// pushes the running total past maxToolsListTools is refused.
func TestFetchAllToolPages_TooManyTools(t *testing.T) {
	// Build a single page whose tool array already exceeds the ceiling so the
	// guard trips after the first fetch (kept hermetic and fast).
	var sb strings.Builder
	sb.WriteString(`{"tools":[`)
	total := maxToolsListTools + 1
	for i := 0; i < total; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"name":"t"}`)
	}
	sb.WriteString(`]}`)
	page := json.RawMessage(sb.String())

	_, err := FetchAllToolPages(func(_ string) (json.RawMessage, error) {
		return page, nil
	})
	if err == nil {
		t.Fatal("expected an error when the tool count exceeds the ceiling")
	}
	if !strings.Contains(err.Error(), "refusing to page further") {
		t.Errorf("error should mention refusing to page further, got %v", err)
	}
}

// TestFetchAllToolPages_TooManyPages covers the page ceiling: an upstream that
// always returns a fresh cursor is cut off after maxToolsListPages iterations.
func TestFetchAllToolPages_TooManyPages(t *testing.T) {
	n := 0
	_, err := FetchAllToolPages(func(cursor string) (json.RawMessage, error) {
		n++
		// Always advance with a brand-new (unseen) cursor so the repeated-cursor
		// guard never trips; only the page ceiling can stop this.
		return json.RawMessage(`{"tools":[],"nextCursor":"c` + itoa(n) + `"}`), nil
	})
	if err == nil {
		t.Fatal("expected an error when the page count exceeds the ceiling")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error should mention exceeding the page limit, got %v", err)
	}
	if n != maxToolsListPages {
		t.Errorf("fetcher should be called exactly %d times, got %d", maxToolsListPages, n)
	}
}

// TestFetchAllToolPages_ByteBudget covers the total-bytes ceiling: many small
// pages that each stay well under the per-page/tool-count limits still add up
// past maxToolsListBytes and must be refused, while an ordinary small response
// still succeeds.
func TestFetchAllToolPages_ByteBudget(t *testing.T) {
	cases := []struct {
		name       string
		fetch      func() func(cursor string) (json.RawMessage, error)
		wantErrSub string // empty means success is expected
	}{
		{
			name: "many small pages exceeding the byte budget are rejected",
			fetch: func() func(cursor string) (json.RawMessage, error) {
				// Each page is ~100 KiB, far under a single MCP message's 4 MiB frame
				// limit and far under the page/tool-count ceilings, but enough of them
				// accumulate past maxToolsListBytes before either ceiling would trip.
				padding := strings.Repeat("x", 100*1024)
				n := 0
				return func(_ string) (json.RawMessage, error) {
					n++
					return json.RawMessage(`{"tools":[{"name":"t","description":"` + padding + `"}],"nextCursor":"c` + itoa(n) + `"}`), nil
				}
			},
			wantErrSub: "accumulated more than",
		},
		{
			name: "a normal-sized response still succeeds",
			fetch: func() func(cursor string) (json.RawMessage, error) {
				return func(_ string) (json.RawMessage, error) {
					return json.RawMessage(`{"tools":[{"name":"read_file"},{"name":"write_file"}]}`), nil
				}
			},
			wantErrSub: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FetchAllToolPages(tc.fetch())
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error = %q; want substring %q", err.Error(), tc.wantErrSub)
			}
		})
	}
}

// ─── BestManifestConstraint ───────────────────────────────────────────────────

// TestBestManifestConstraint_NoMatch covers the best<0 nil-return path: a
// manifest whose tool: entries do not match the queried name returns nil. A
// non-tool entry (resource:) is also present to exercise the ParseTarget /
// target-type skip inside the loop.
func TestBestManifestConstraint_NoMatch(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:other_tool", Actions: []string{"call"}},
		capability.Constraint{Target: "resource:read_file", Actions: []string{"read"}},
	)
	if c := BestManifestConstraint(manifest, "read_file"); c != nil {
		t.Errorf("expected nil for an unmatched tool name, got %+v", c)
	}
}

// TestBestManifestConstraint_HigherSpecificityWins confirms the s>bestScore
// branch picks the more specific (exact) constraint over a covering glob.
func TestBestManifestConstraint_HigherSpecificityWins(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_*", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	c := BestManifestConstraint(manifest, "read_file")
	if c == nil {
		t.Fatal("expected a matching constraint")
	}
	if c.Target != "tool:read_file" {
		t.Errorf("expected the exact constraint to win, got %q", c.Target)
	}
}

// ─── pinnedArgumentNames: argumentSchema Required branch ──────────────────────

// TestPinnedArgumentNames_RequiredBranch covers the ArgumentSchema.Required loop
// in pinnedArgumentNames: a required name not also present as a property must
// still be reported as a pinned argument (and surface as FM-3 when absent live).
func TestPinnedArgumentNames_RequiredBranch(t *testing.T) {
	c := &capability.Constraint{
		Target:  "tool:read_file",
		Actions: []string{"call"},
		ArgumentSchema: &capability.ArgumentSchema{
			Type:     capability.SchemaType{Single: "object"},
			Required: []string{"path"},
		},
	}
	names := pinnedArgumentNames(c)
	found := false
	for _, n := range names {
		if n == "path" {
			found = true
		}
	}
	if !found {
		t.Errorf("required argument name must be pinned; got %v", names)
	}
}

// TestCheckManifestDrift_FM3_ArgumentSchemaRequiredMissing exercises the same
// Required branch end-to-end: a required argument absent from the live schema is
// flagged FM-3.
func TestCheckManifestDrift_FM3_ArgumentSchemaRequiredMissing(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{
			Target:  "tool:read_file",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Type:     capability.SchemaType{Single: "object"},
				Required: []string{"path"},
			},
		},
	)
	tools := []UpstreamTool{{
		Name: "read_file",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"file_path": map[string]interface{}{}},
		},
	}}
	warnings := CheckManifestDrift(manifest, tools, "")
	fm3 := findKind(warnings, Fm3)
	if fm3 == nil {
		t.Fatal("expected FM-3 for a required argumentSchema name absent from the live schema")
	}
	if fm3.Argument != "path" {
		t.Errorf("FM-3 argument: want %q, got %q", "path", fm3.Argument)
	}
}

// ─── CheckManifestDrift: non-tool target skip branches ────────────────────────

// TestCheckManifestDrift_NonToolEntriesSkipped exercises the ParseTarget /
// target-type continue branches in the FM-2 and FM-3 loops: resource:, prompt:,
// and system: entries are not verified against the live tool list, so they
// produce no FM-2 even though no live tool matches them.
func TestCheckManifestDrift_NonToolEntriesSkipped(t *testing.T) {
	manifest := manifestWith(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "resource:file:///etc/*", Actions: []string{"read"}},
		capability.Constraint{Target: "prompt:summarize", Actions: []string{"get"}},
		capability.Constraint{Target: "system:health", Actions: []string{"call"}},
	)
	tools := []UpstreamTool{{Name: "read_file"}}
	warnings := CheckManifestDrift(manifest, tools, "")

	// The only tool: entry matches a live tool, so there must be no FM-2 at all:
	// the non-tool entries are skipped rather than flagged as dead references.
	if hasKind(warnings, Fm2) {
		t.Errorf("non-tool manifest entries must not produce FM-2: %+v", findAllKind(warnings, Fm2))
	}
	if hasKind(warnings, Fm2Pinned) {
		t.Error("non-tool manifest entries must not produce Fm2Pinned")
	}
}

// itoa is a tiny dependency-free int-to-string helper for building distinct
// pagination cursors in tests (avoids pulling strconv into the test surface for
// one call site).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
