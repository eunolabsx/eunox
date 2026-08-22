// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/pkg/capability"
)

// writeTapeFor writes one enforcement point's tape: a sink named pep, stamping taskID on
// every record, that allows each of targets in order. Returns the log and key paths.
func writeTapeFor(t *testing.T, dir, name, pep, taskID string, targets ...string) (logPath, keyPath string) {
	t.Helper()
	logPath = filepath.Join(dir, name+".jsonl")
	keyPath = filepath.Join(dir, name+".key")
	opts := []audit.Option{audit.WithIdentity(func(context.Context) audit.Identity {
		return audit.Identity{TaskID: taskID}
	})}
	if pep != "" {
		ep, err := capability.NewEnforcementPoint(pep)
		if err != nil {
			t.Fatalf("NewEnforcementPoint(%q): %v", pep, err)
		}
		opts = append(opts, audit.WithEnforcementPoint(ep))
	}
	sink, err := audit.Open(logPath, keyPath, 0, 0, opts...)
	if err != nil {
		t.Fatalf("audit.Open(%s): %v", name, err)
	}
	for _, target := range targets {
		sink.RecordAllow(context.Background(), "sess-"+name, target, "tools/call", nil, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close(%s): %v", name, err)
	}
	return logPath, keyPath
}

// runAuditVerifyCapturing drives the subcommand, returning its exit code and both streams.
func runAuditVerifyCapturing(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() { code = cmdAuditVerify(args) })
	})
	return code, stdout, stderr
}

// TestCmdAuditVerify_CrossPEP_JoinsOnTaskAndAttributesByPEP is the acceptance shape: two
// enforcement points, each with its own tape and its own signing key, verified as two
// independent chains, then the task they share printed as one sequence with each record
// attributed by the `pep` its writer stamped.
//
// What it asserts beyond "it runs": that the verdicts are PER TAPE (an exit code cannot
// say which tape broke), that both enforcement points appear in the joined table, and
// that the ordering assumption is STATED rather than implied — the timestamps come from
// two clocks eunox neither requires nor checks the sync of, so a reader who takes the
// order as proven has been misled by the tool.
func TestCmdAuditVerify_CrossPEP_JoinsOnTaskAndAttributesByPEP(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file", "summarize")
	logB, keyB := writeTapeFor(t, dir, "core", "core-1", "task-A", "wire_transfer")

	code, out, errOut := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-key-path", keyA,
		"--audit-log", logB, "--audit-key-path", keyB,
		"--task-id", "task-A")
	if code != 0 {
		t.Fatalf("two intact tapes must pass: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"Tape 1 verdict: PASS",
		"Tape 2 verdict: PASS",
		"Sequence for task_id=task-A: 3 record(s) across 2 tape(s).",
		"mcp:edge-1",
		"mcp:core-1",
		"read_file",
		"wire_transfer",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report must contain %q:\n%s", want, out)
		}
	}
	// The assumption the join rests on has to be on the page, above the table: an
	// ordering presented bare reads as an order that was established.
	for _, want := range []string{
		"Within a tape the order is proven",
		"ACROSS tapes nothing is proven",
		"neither requires nor checks clock sync",
		"Absence is not loss",
		"never a verdict",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the join must state %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "Within a tape the order is proven") > strings.Index(out, "TIME") {
		t.Error("the ordering assumption must be stated BEFORE the table, not under it")
	}
}

// TestCmdAuditVerify_CrossPEP_PerTapeVerdictsAreIndependent is the issue's second design
// point: N chains are N verdicts. A break on one tape must be reported as that tape's
// finding — naming it — rather than collapsed into a single exit status that says only
// "something failed", and the intact tape must still report PASS.
func TestCmdAuditVerify_CrossPEP_PerTapeVerdictsAreIndependent(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")
	logB, keyB := writeTapeFor(t, dir, "core", "core-1", "task-A", "wire_transfer", "settle")

	// Tamper with tape B's first record: rewrite its target, leaving the _hmac intact.
	data, err := os.ReadFile(logB) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"target":"wire_transfer"`, `"target":"read_file___"`, 1)
	if tampered == string(data) {
		t.Fatal("test setup: nothing was tampered with")
	}
	if err := os.WriteFile(logB, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-key-path", keyA,
		"--audit-log", logB, "--audit-key-path", keyB,
		"--task-id", "task-A")
	if code != 1 {
		t.Fatalf("a tape that fails verification is a finding (exit 1): exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "Tape 1 verdict: PASS") {
		t.Errorf("the intact tape must still report PASS:\n%s", out)
	}
	if !strings.Contains(out, "Tape 2 verdict: FAIL") || !strings.Contains(out, logB) {
		t.Errorf("the broken tape must be named as the one that failed:\n%s", out)
	}
	// The joined sequence must still carry the record that failed, marked — a sequence
	// that silently omits it hides the very thing it is being read for.
	if !strings.Contains(out, string(audit.StatusInvalid)) {
		t.Errorf("the failed record must appear in the join marked %q:\n%s", audit.StatusInvalid, out)
	}
}

// TestCmdAuditVerify_CrossPEP_KeysAreNotMerged pins the keying decision. Two tapes with
// two keys verify only when each is paired with ITS OWN key: merging the two rings would
// make a record signed by one enforcement point verify on the other's tape, which is
// exactly the forgery per-writer chains bound. An operator who separated the keys
// separated the trust domains, and this tool must not put them back together.
func TestCmdAuditVerify_CrossPEP_KeysAreNotMerged(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")
	logB, keyB := writeTapeFor(t, dir, "core", "core-1", "task-A", "wire_transfer")

	if code, out, _ := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-key-path", keyA,
		"--audit-log", logB, "--audit-key-path", keyB); code != 0 {
		t.Fatalf("correctly paired keys must pass: exit %d\n%s", code, out)
	}
	// Swap the keys: each tape is now checked against the other's ring. Both must fail
	// (UNKNOWN_KEY_ID), which is only possible because the rings stayed separate.
	code, out, _ := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-key-path", keyB,
		"--audit-log", logB, "--audit-key-path", keyA)
	if code != 1 {
		t.Fatalf("swapped keys must fail both tapes (exit 1), got %d\n%s", code, out)
	}
	if strings.Count(out, "verdict: FAIL") != 2 {
		t.Errorf("both tapes must fail under swapped keys — a merged ring would pass both:\n%s", out)
	}
}

// TestCmdAuditVerify_CrossPEP_SharedKeyRing covers the other half of the keying rule: one
// --audit-key-path for N tapes is the shared-signing-key deployment, and each tape is
// still its own independent pass against that one ring.
func TestCmdAuditVerify_CrossPEP_SharedKeyRing(t *testing.T) {
	dir := t.TempDir()
	logA, keyPath := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")
	// Second tape, same key file: audit.Open loads the existing key rather than minting one.
	logB := filepath.Join(dir, "core.jsonl")
	ep, err := capability.NewEnforcementPoint("core-1")
	if err != nil {
		t.Fatal(err)
	}
	sink, err := audit.Open(logB, keyPath, 0, 0, audit.WithEnforcementPoint(ep),
		audit.WithIdentity(func(context.Context) audit.Identity { return audit.Identity{TaskID: "task-A"} }))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-b", "wire_transfer", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}

	code, out, errOut := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-log", logB, "--audit-key-path", keyPath, "--task-id", "task-A")
	if code != 0 {
		t.Fatalf("one shared key over two tapes must pass: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "2 record(s) across 2 tape(s)") {
		t.Errorf("both tapes must contribute to the join:\n%s", out)
	}
}

// TestCmdAuditVerify_CrossPEP_KeyCountMismatchIsAUsageError asserts the keying rule is
// EXPLICIT: anything other than one shared key or one key per tape is refused, naming
// both counts, rather than silently pairing what it can and verifying the rest against a
// default.
func TestCmdAuditVerify_CrossPEP_KeyCountMismatchIsAUsageError(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")
	logB, keyB := writeTapeFor(t, dir, "core", "core-1", "task-A", "wire_transfer")
	logC, _ := writeTapeFor(t, dir, "mid", "mid-1", "task-A", "summarize")

	code, _, errOut := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-log", logB, "--audit-log", logC,
		"--audit-key-path", keyA, "--audit-key-path", keyB)
	if code != auditVerifyUsageExit {
		t.Fatalf("a key/tape count mismatch is a usage error (exit %d), got %d", auditVerifyUsageExit, code)
	}
	if !strings.Contains(errOut, "2 --audit-key-path value(s) for 3 --audit-log value(s)") {
		t.Errorf("the refusal must name both counts: %q", errOut)
	}
}

// TestCmdAuditVerify_CrossPEP_DuplicateTapeRefused covers the operator typo that would
// otherwise read as evidence: the same tape named twice contributes every record to the
// join twice, printing a duplicated sequence that looks like a replayed call.
func TestCmdAuditVerify_CrossPEP_DuplicateTapeRefused(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")

	code, _, errOut := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-log", logA, "--audit-key-path", keyA, "--task-id", "task-A")
	if code != auditVerifyUsageExit {
		t.Fatalf("a tape named twice is a usage error (exit %d), got %d", auditVerifyUsageExit, code)
	}
	if !strings.Contains(errOut, "names the same tape as tape 1") {
		t.Errorf("the refusal must say which tape it duplicates: %q", errOut)
	}

	// The same tape spelled two ways is the commoner form of that typo, and a lexical
	// comparison of the raw --audit-log values misses it: ResolveLogPath only expands
	// "~", so `./x.jsonl` and `x.jsonl` reached the guard as different strings and the
	// tape was verified twice and joined twice.
	t.Chdir(dir)
	code, _, errOut = runAuditVerifyCapturing(t,
		"--audit-log", "edge.jsonl", "--audit-log", "./edge.jsonl",
		"--audit-key-path", keyA, "--task-id", "task-A")
	if code != auditVerifyUsageExit {
		t.Fatalf("the same tape spelled two ways is still one tape (exit %d), got %d", auditVerifyUsageExit, code)
	}
	if !strings.Contains(errOut, "names the same tape as tape 1") {
		t.Errorf("the refusal must name the duplicate: %q", errOut)
	}
}

// TestCmdAuditVerify_TaskIDNarrowsTheReportedTallies pins what --task-id does BESIDES
// printing a sequence: like --request-id it narrows what is counted, so the tape's other
// records fall to the skipped tally. The help says so; this is what makes that true.
// Verification is unaffected — every record is still checked.
func TestCmdAuditVerify_TaskIDNarrowsTheReportedTallies(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "mixed.jsonl")
	keyPath := filepath.Join(dir, "mixed.key")
	task := "task-A"
	sink, err := audit.Open(logPath, keyPath, 0, 0,
		audit.WithIdentity(func(context.Context) audit.Identity { return audit.Identity{TaskID: task} }))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "s", "read_file", "tools/call", nil, nil, false, nil, nil)
	task = "task-B"
	sink.RecordAllow(context.Background(), "s", "list_dir", "tools/call", nil, nil, false, nil, nil)
	sink.RecordAllow(context.Background(), "s", "stat", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}

	code, out, errOut := runAuditVerifyCapturing(t,
		"--audit-log", logPath, "--audit-key-path", keyPath, "--task-id", "task-A")
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "Checked 3 record(s): 1 valid, 0 invalid, 2 skipped") {
		t.Errorf("--task-id must narrow the tallies as --request-id does:\n%s", out)
	}
	// And the help must say so, or the skipped tally reads as records that went unchecked.
	if !strings.Contains(auditVerifyHelp(t), "narrows which records are counted and printed") {
		t.Error("--task-id's help must state that it narrows counting, not only printing")
	}
}

// auditVerifyHelp renders the subcommand's --help text.
func auditVerifyHelp(t *testing.T) string {
	t.Helper()
	var out string
	_ = captureStderr(t, func() {
		out = captureStdout(t, func() { _ = cmdAuditVerify([]string{"--help"}) })
	})
	return out
}

// TestCmdAuditVerify_CrossPEP_UnknownTaskSaysSo asserts the fourth design point: a task
// absent from every named tape prints the absence explicitly and does NOT fail the run.
// Within one chain a gap is evidence; across tapes it is the expected shape of an
// enforcement point that never handled the call.
func TestCmdAuditVerify_CrossPEP_UnknownTaskSaysSo(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")
	logB, keyB := writeTapeFor(t, dir, "core", "core-1", "task-A", "wire_transfer")

	code, out, errOut := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-key-path", keyA,
		"--audit-log", logB, "--audit-key-path", keyB,
		"--task-id", "task-Z")
	if code != 0 {
		t.Fatalf("an absent task is not a finding: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "no record on any named tape carries this task_id") {
		t.Errorf("the empty join must say so plainly:\n%s", out)
	}
}

// TestCmdAuditVerify_CrossPEP_UnattributedTapeIsNamed covers the tape written by an
// instance with no configured enforcement-point name. Its records are placeable only by
// the file they came out of, which is precisely the attribution `pep` exists to replace,
// so the report says so rather than printing a blank column.
func TestCmdAuditVerify_CrossPEP_UnattributedTapeIsNamed(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")
	logB, keyB := writeTapeFor(t, dir, "core", "", "task-A", "wire_transfer")

	code, out, errOut := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-key-path", keyA,
		"--audit-log", logB, "--audit-key-path", keyB,
		"--task-id", "task-A")
	if code != 0 {
		t.Fatalf("an unattributed tape is not a finding: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "(unattributed)") {
		t.Errorf("an unattributed record must be marked in the table:\n%s", out)
	}
	if !strings.Contains(out, "carrying no `pep`") || !strings.Contains(out, logB) {
		t.Errorf("the note must name the tape to configure:\n%s", out)
	}
}

// TestCmdAuditVerify_SingleTapeReportIsUnchanged guards the default. Cross-tape mode adds
// a per-tape header and a verdict line, and neither may appear for the one-tape run every
// existing operator and CI job already parses.
func TestCmdAuditVerify_SingleTapeReportIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")

	code, out, errOut := runAuditVerifyCapturing(t, "--audit-log", logA, "--audit-key-path", keyA)
	if code != 0 {
		t.Fatalf("an intact tape must pass: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	for _, unwanted := range []string{"Tape 1:", "Tape 1 verdict:", "INDEPENDENT chains", "Sequence for task_id"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("single-tape output must not gain %q:\n%s", unwanted, out)
		}
	}
	if !strings.Contains(out, "Checked 1 record(s)") {
		t.Errorf("the summary line must be unchanged:\n%s", out)
	}
}

// TestCmdAuditVerify_TaskIDOnOneTapeStillPrintsTheSequence: a join over one tape is a
// filter, and the mode is uniform rather than gated on a tape count — an operator
// investigating one enforcement point gets the same view, with the same caveats, as one
// reading two.
func TestCmdAuditVerify_TaskIDOnOneTapeStillPrintsTheSequence(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file", "summarize")

	code, out, errOut := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-key-path", keyA, "--task-id", "task-A")
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "2 record(s) across 1 tape(s)") {
		t.Errorf("the sequence must print for a single tape too:\n%s", out)
	}
}

// TestCmdAuditVerify_CrossPEP_UnreadableTapeStopsTheRun asserts the run does not print a
// sequence assembled from the tapes it COULD read: a join silently missing an enforcement
// point's records is the one way this report can mislead about the thing it exists to
// show, so an unreadable tape is an operational failure (exit 2), not a skipped one.
func TestCmdAuditVerify_CrossPEP_UnreadableTapeStopsTheRun(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")
	missing := filepath.Join(dir, "never-written.jsonl")

	code, out, _ := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-key-path", keyA,
		"--audit-log", missing, "--audit-key-path", keyA,
		"--task-id", "task-A")
	if code != auditVerifyUsageExit {
		t.Fatalf("an unreadable tape is an operational failure (exit %d), got %d\n%s", auditVerifyUsageExit, code, out)
	}
	if strings.Contains(out, "Sequence for task_id") {
		t.Errorf("no sequence may be printed when a tape could not be read:\n%s", out)
	}
}

// TestRepeatedPath_RefusesEmpty: `--audit-log=` reads as an operator naming a tape, and
// resolving it to the DEFAULT log would verify a file they did not ask about and merge
// its records into the sequence.
func TestRepeatedPath_RefusesEmpty(t *testing.T) {
	var r repeatedPath
	if err := r.Set(""); err == nil {
		t.Fatal("an empty --audit-log must be refused, not resolved to the default log")
	}
	if err := r.Set("a.jsonl"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := r.String(); got != "a.jsonl" {
		t.Fatalf("String: got %q", got)
	}
}
