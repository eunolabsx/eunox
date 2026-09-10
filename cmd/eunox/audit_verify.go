// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// audit-verify: re-verify the local audit log's per-record HMAC signatures and its
// tamper-evident chain, across the base log and every rotated sibling — and, with
// --audit-log passed once per enforcement point, across several tapes as several
// INDEPENDENT chains (see audit_verify_join.go).

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
)

// loadConfigAuditDefaults loads configPath and fills empty audit-log / audit-key-path flags
// from its audit block, leaving explicit flags untouched (keyPath nil skips that default).
// The load error is returned rather than printed so callers can choose their own stance —
// doctor carries it into the bundle instead of aborting.
func loadConfigAuditDefaults(cmdName, configPath string, logPath, keyPath *string) (*config.GatewayConfig, error) {
	if configPath == "" {
		return nil, nil
	}
	cfg, err := config.LoadGatewayConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("eunox %s: loading config: %w", cmdName, err)
	}
	if *logPath == "" && cfg.Audit.Log != "" {
		*logPath = cfg.Audit.Log
	}
	if keyPath != nil && *keyPath == "" && cfg.Audit.KeyPath != "" {
		*keyPath = cfg.Audit.KeyPath
	}
	return cfg, nil
}

// applyConfigAuditDefaults is loadConfigAuditDefaults for the readers that abort on an
// unloadable config and take no key of their own (stats, suggest); doctor deliberately does
// not use this, and audit-verify takes applyConfigAuditDefaultsList instead — its
// --audit-log/--audit-key-path are repeatable, so the default fills a LIST.
func applyConfigAuditDefaults(cmdName, configPath string, logPath *string) error {
	_, err := loadConfigAuditDefaults(cmdName, configPath, logPath, nil)
	return err
}

// parseReaderArgs is the stance-free half of the preamble every audit-tape reader (suggest,
// stats, audit-verify, doctor) shares: parse args, map -h/--help to a clean exit, and reject
// a stray positional — the log is chosen with --audit-log/--config, never positionally, so
// `eunox stats audit.jsonl` must not silently report on the default log instead.
// done reports the caller must return code immediately (0 for -h, 1 for a usage error).
func parseReaderArgs(name string, fs *flag.FlagSet, args []string) (code int, done bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return 1, true
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "eunox %s: unexpected argument %q (use --audit-log to name the log file)\n", name, fs.Arg(0))
		return 1, true
	}
	return 0, false
}

// parseAuditReaderFlags runs parseReaderArgs, then lets --config fill the audit log path if
// the operator left it empty. configPath is a pointer (not a value) because it is read only
// after fs.Parse runs here; a by-value copy would capture the pre-parse empty string.
func parseAuditReaderFlags(name string, fs *flag.FlagSet, args []string, configPath, logPath *string) (code int, done bool) {
	if code, done := parseReaderArgs(name, fs, args); done {
		return code, done
	}
	if err := applyConfigAuditDefaults(name, *configPath, logPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	return 0, false
}

// resolveAuditReaderLogPath expands the reader's --audit-log to a concrete path. Kept
// separate from parseAuditReaderFlags because doctor does not resolve here — it reports an
// unresolvable path inside the bundle instead of refusing to print one.
func resolveAuditReaderLogPath(name, configured string) (string, bool) {
	logPath, err := audit.ResolveLogPath(configured)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox %s: %v\n", name, err)
		return "", false
	}
	return logPath, true
}

// parseAndResolveAuditLog runs the preamble the single-tape audit readers share before they
// can even locate their log — parseAuditReaderFlags, then resolveAuditReaderLogPath — and
// translates parseAuditReaderFlags' generic 1 to the caller's own usageExit (suggest/stats
// each reserve their non-2 codes for a command-specific outcome; see each one's own
// <name>UsageExit doc). done reports the caller must return exitCode immediately; logPath is
// valid only when done is false. Stops at path resolution rather than also opening the log,
// so a caller keeps its own stance on an unopenable one.
//
// audit-verify does not use it: its --audit-log is repeatable (one per enforcement point's
// tape), so it resolves a LIST through resolveAuditTapes, which also has the key pairing to
// decide.
func parseAndResolveAuditLog(name string, fs *flag.FlagSet, args []string, configPath, auditLogPath *string, usageExit int) (logPath string, exitCode int, done bool) {
	if code, doneParse := parseAuditReaderFlags(name, fs, args, configPath, auditLogPath); doneParse {
		if code != 0 {
			return "", usageExit, true
		}
		return "", code, true
	}
	logPath, ok := resolveAuditReaderLogPath(name, *auditLogPath)
	if !ok {
		return "", usageExit, true
	}
	return logPath, 0, false
}

// readAuditChainOrExit opens the merged rotated chain, hands it to consume, and BRACKETS
// that read against a rotation landing inside it — folding every failure into the caller's
// own usageExit and printing the (already fully-formatted) message verbatim. Shared by
// suggest and stats, the two readers that consume one concatenated rotated-chain io.Reader;
// audit-verify does not use this — it needs the discovered chain FILES themselves to verify
// per-file rather than stream one pass, and brackets that pass itself.
//
// The read and the bracket are ONE call rather than a reader plus a check the caller
// remembers to run: the check has to happen after the last record is consumed and before
// anything is printed, and a caller that forgets it is back to the silent failure this
// exists to close — the sequence would be re-hand-written per reader, which is how the two
// commands came to share this race in the first place.
func readAuditChainOrExit[T any](name, logPath string, usageExit int, consume func(io.Reader) (T, error)) (result T, exitCode int, done bool) {
	r, snap, err := openAuditChain(name, logPath)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return result, usageExit, true
	}
	defer func() { _ = r.Close() }()

	consumed, consumeErr := consume(r)
	// Checked BEFORE the read error, the ordering verifyOneTape states and for its reason: a
	// rotation produces read errors too. The chain is opened lazily by name, so a retention
	// prune unlinks a sibling this reader has not reached yet and a rotation leaves the base
	// absent for the length of its pre-reopen fsync — both surface as an open failure INSIDE
	// consume, and reporting that verbatim sends the operator after a missing or misconfigured
	// log. Reported as a failure rather than a caveat, and at the reader's usage code (2)
	// rather than a findings code: an inconclusive read is not a finding about the tape.
	//
	// The wording stays cause-neutral because CheckUnchanged answers three ways — the chain
	// moved, or the re-listing itself failed, or the base could not be stat'd — and only the
	// first says a record was missed.
	if err := snap.CheckUnchanged(); err != nil {
		fmt.Fprintf(os.Stderr, "eunox %s: %v; no report was produced — re-run "+
			"(against a quiescent log, or a copy of the chain)\n", name, err)
		return result, usageExit, true
	}
	if consumeErr != nil {
		fmt.Fprintf(os.Stderr, "eunox %s: reading log: %v\n", name, consumeErr)
		return result, usageExit, true
	}
	return consumed, 0, false
}

// auditVerifyUsageExit is audit-verify's exit code for a usage, config, key-resolution, or
// log-read failure, and for a pass a rotation raced (no verdict was reached). Exit 1 is
// reserved for a log that fails verification (like validate reserves it for findings), so
// a cron/CI job can tell tampering from a misconfigured flag or an inconclusive run.
// parseReaderArgs reports usage errors as 1, so this command translates at the call site.
const auditVerifyUsageExit = 2

// auditVerifyFindingsExit is the code a log that FAILS verification reports, and it OUTRANKS
// the inconclusive exit wherever a pass PROVED a finding without reaching the end of what it
// was asked to read — a torn final record, a scan a read error aborted, or a sibling tape
// that reached no verdict. Each of those is one write an attacker who can already tamper can
// also make: strip the final newline, or append a line past the scan window, which aborts the
// scan with no per-record finding of its own. Neither is a chain change, so the rotation
// bracket passes and re-running a file nobody is truncating answers the same thing forever;
// answering "inconclusive" over a tamper already classified would therefore move it out of
// the bucket a cron/CI gate watches, permanently, for one appended byte.
//
// It is a ranking, not a reclassification: a pass that proves nothing still reports
// auditVerifyUsageExit, and a rotation-raced pass proves nothing by construction (its
// findings can be fabricated by the rotation itself and are dropped unread, up to the
// heldFindings cap past which they have already streamed). What it does NOT reach is a
// tamper the pass never classified — an over-cap line placed BEFORE the tampered record
// leaves the scan aborting over a clean prefix, which no exit-code rule can rank; closing
// that needs the scan to resynchronize past the line rather than stop.
const auditVerifyFindingsExit = 1

// auditVerifySummaryFormat is hoisted to a constant so the site-drift test can assert the
// landing-page demo still quotes tallies this command actually emits.
const auditVerifySummaryFormat = "Checked %d record(s): %d valid, %d invalid, %d skipped, %d unknown-key, %d unverifiable; %d chain break(s).\n"

// auditVerifyUsage is the command's help text. Hoisted to a constant because the
// cross-tape half of it is the only statement anywhere of what a joined sequence does and
// does not establish, and an operator reads it before they have a report to read.
const auditVerifyUsage = `Usage: eunox audit-verify [flags]

Verify HMAC-SHA256 signatures in the local audit log.

Cross-enforcement-point mode: pass --audit-log once per enforcement point's tape.
Each is verified as its OWN chain, with its own key and its own verdict — records
from different enforcement points do not form one chain, since seq and prev_hmac
are per writer. With --task-id, the records those tapes share for one task are
then printed as one sequence, each attributed by the ` + "`pep`" + ` it was written with.
That sequence is a reconstruction, not a verdict: within a tape it follows the
order the tape proves, across tapes it rests on each writer's own clock (eunox
neither requires nor checks clock sync), and a call missing from an enforcement
point that never handled it is expected rather than evidence of loss. Only the
per-tape verdicts gate the exit code.

Exit codes:
  0  Every record verified and the tamper-evident chain is intact, on every tape.
  1  A tape failed verification (an invalid record, a chain break, an
     unverifiable or unknown-key record). Reserved for findings, so a cron or
     CI job can gate on it; never used for a flag or config error.
  2  A flag, config, key-resolution or log-read failure, or a pass that a
     rotation raced or that stopped on a half-written record — with nothing
     proved against the part that WAS read (inconclusive — re-run).

A finding the pass PROVED outranks a part of the run it could not cover, so a
run that proves one on any tape reports 1 even when another tape reached no
verdict: otherwise one appended byte (a stripped newline, or a line past the
scan window) would move a tamper into the inconclusive bucket for good, since
re-running a file nobody is truncating answers the same thing forever. Every
tape is attempted either way, and what the run could not cover is named on
stderr — and, with several tapes, by that tape's NO VERDICT line. With
--task-id the sequence is withheld, naming those tapes, rather than printed
from a partial read.

Flags:
`

// cmdAuditVerify runs the `audit-verify` subcommand, returning the exit code (rather than
// calling os.Exit) so tests can drive every branch.
func cmdAuditVerify(args []string) int {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	setUsage(fs, args, auditVerifyUsage)
	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the configured audit.log and\naudit.keyPath are used as defaults for --audit-log and --audit-key-path.")
	var logs, keys repeatedPath
	fs.Var(&logs, "audit-log", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl). Repeatable:\neach occurrence names one enforcement point's tape, verified as its own\nchain with its own verdict.")
	fs.Var(&keys, "audit-key-path", "Path to the HMAC signing key for the audit log (default: ~/.eunox/audit.key).\nOverrides EUNOX_AUDIT_KEY_PATH environment variable. Repeatable: pass one\n(every tape shares a key) or exactly one per --audit-log, in the same order.")
	requestID := fs.String("request-id", "", "Report (count and print) only the record with this request ID. Every record\nis still HMAC-verified and the tamper-evident chain is always checked; this\nfilter narrows the report, not the verification.")
	taskID := fs.String("task-id", "", "Print the sequence of records carrying this task ID, joined across every\n--audit-log and attributed by the pep field each record was written with.\nLike --request-id, it also narrows which records are counted and printed\n(others fall to the skipped tally); every record is still HMAC-verified and\nthe tamper-evident chain is always checked. The join is a reconstruction,\nnot a verdict: see the notes it prints.")
	since := fs.String("since", "", "Report (count and print) only records after this RFC3339 timestamp. Every\nrecord is still HMAC-verified and the tamper-evident chain is always checked;\nthis filter narrows the report, not the verification.")

	if code, done := parseReaderArgs("audit-verify", fs, args); done {
		if code != 0 {
			return auditVerifyUsageExit
		}
		return code
	}
	if err := applyConfigAuditDefaultsList("audit-verify", *configPath, &logs, &keys); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return auditVerifyUsageExit
	}
	tapes, err := resolveAuditTapes(logs, keys)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return auditVerifyUsageExit
	}
	opts := audit.VerifyOptions{RequestID: *requestID, TaskID: *taskID}
	if *since != "" {
		opts.Since, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox audit-verify: invalid --since value %q: %v\n", *since, err)
			return auditVerifyUsageExit
		}
	}
	return runAuditVerify(tapes, opts)
}

// applyConfigAuditDefaultsList fills an EMPTY --audit-log/--audit-key-path list from the
// config's audit block. A list the operator populated is left alone: the config supplies
// a default, never an extra member — silently appending the configured tape to the ones
// named on the command line would verify a file that was not asked about and merge its
// records into the join.
func applyConfigAuditDefaultsList(cmdName, configPath string, logs, keys *repeatedPath) error {
	var logDefault, keyDefault string
	if _, err := loadConfigAuditDefaults(cmdName, configPath, &logDefault, &keyDefault); err != nil {
		return err
	}
	if len(*logs) == 0 && logDefault != "" {
		*logs = append(*logs, logDefault)
	}
	if len(*keys) == 0 && keyDefault != "" {
		*keys = append(*keys, keyDefault)
	}
	return nil
}

// tapeOutcome is what a run learned about one tape. verdict says res is this tape's ANSWER
// rather than an accident of how far the pass got — a pass that stopped short sets it only
// when it proved a failure before stopping, since a clean prefix proves nothing about the
// records behind it. joinable says recs are this tape's WHOLE contribution to a sequence,
// which a pass with an unread suffix cannot claim even when it did prove one.
type tapeOutcome struct {
	res      audit.VerifyResult
	recs     []audit.JoinedRecord
	verdict  bool
	joinable bool
}

// runAuditVerify verifies every tape as its own chain, then prints the task-joined
// sequence if one was asked for. The exit code covers the per-tape VERDICTS only: the
// join establishes nothing (absence of a task's calls from an enforcement point that
// never handled them is expected, unlike a gap inside one chain), so it can never fail a
// run on its own.
//
// Every tape is attempted even after one reaches no verdict, and the ranking runs ONCE at
// the end. Stopping at the first tape that could not be read made the answer depend on the
// order the operator named them: a torn tail on the tape named first suppressed a proved
// tamper on the tape named second, which is the one-byte suppression auditVerifyFindingsExit
// exists to close, reachable without touching the tampered tape at all. What the stop
// protected was the join, and that is now protected directly — a sequence is printed only
// when every tape's contribution to it is whole, and withheld by NAME otherwise.
func runAuditVerify(tapes []auditTape, opts audit.VerifyOptions) int {
	if len(tapes) > 1 {
		fmt.Printf("Verifying %d audit tapes as %d INDEPENDENT chains: each enforcement point signs its own\n"+
			"tape with its own key, so there is one verdict per tape and no chain across them.\n", len(tapes), len(tapes))
	}
	rings := verifiedRings{}
	var joined []audit.JoinedRecord
	var partial []int
	failed := false
	for _, t := range tapes {
		if len(tapes) > 1 {
			fmt.Printf("\nTape %d: %s\n", t.num, t.logPath)
		}
		out := verifyOneTape(t, opts, rings)
		if len(tapes) > 1 {
			printTapeVerdict(t, out)
		}
		if out.verdict && !out.res.OK() {
			failed = true
		}
		if out.joinable {
			joined = append(joined, out.recs...)
			continue
		}
		partial = append(partial, t.num)
	}
	if opts.TaskID != "" {
		if len(partial) > 0 {
			printJoinWithheld(opts.TaskID, tapes, partial)
		} else {
			printJoinedSequence(opts.TaskID, tapes, joined)
		}
	} else if len(tapes) > 1 {
		fmt.Println("\nPass --task-id to print the sequence these tapes share for one task, attributed by `pep`.")
	}
	// A proved finding outranks a tape the run could not speak for, whichever order they
	// came in; see auditVerifyFindingsExit.
	if failed {
		return auditVerifyFindingsExit
	}
	if len(partial) > 0 {
		return auditVerifyUsageExit
	}
	return 0
}

// printJoinWithheld replaces the sequence when a tape was not read to the end of its chain.
// The join header tells its reader that a record missing from a tape means that enforcement
// point never handled the call; over a partly-read tape that reading is false and the table
// cannot carry the correction, so the sequence is withheld rather than footnoted.
func printJoinWithheld(taskID string, tapes []auditTape, partial []int) {
	fmt.Printf("\nSequence for task_id=%s: NOT printed. Tape(s) %s were not read to the end of their\n"+
		"chain, so a record missing from the sequence could mean that enforcement point never\n"+
		"handled the call OR that this run never read it — and the sequence is worth reading only\n"+
		"when those two are distinguishable. Re-run once every tape verifies.\n",
		audit.SanitizeAuditField(taskID), tapeList(partial, tapes))
}

// verifyOneTape runs the single-tape pass — key ring, rotated-sibling discovery, the
// bracketed verification, the tallies — and collects the task's records out of that same
// pass. It reports rather than exits: ranking one tape's answer against its siblings' is
// runAuditVerify's, so that the rule lives at one site.
func verifyOneTape(t auditTape, opts audit.VerifyOptions, rings verifiedRings) tapeOutcome {
	verifier, err := rings.verifierFor(t.keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return tapeOutcome{}
	}
	// Verify the whole rotated set as one chain, not just the base file — deletion of an
	// entire interior rotated file would otherwise go undetected. Snapshot rather than a
	// bare LogChainFiles: this runs against a live proxy under traffic (audit-verify takes
	// no lock by design), so the pass has to be bracketed against a rotation moving the
	// files under it.
	snap, err := audit.SnapshotLogChain(t.logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: discovering rotated audit logs for %s: %v\n", t.logPath, err)
		return tapeOutcome{}
	}
	if len(snap.Files) == 0 {
		fmt.Fprint(os.Stderr, auditLogMissingHint("audit-verify", t.logPath))
		return tapeOutcome{}
	}
	if len(snap.Files) > 1 {
		fmt.Printf("Verifying %d audit log files as one chain (oldest rotated to current base).\n", len(snap.Files))
	}

	// Findings are HELD rather than streamed: a rotation racing the pass fabricates a
	// CHAIN BREAK at the seam, and printing it before the bracket has run puts a tamper
	// alarm on the operator's terminal that the next line then retracts.
	held := &heldFindings{out: os.Stdout}
	pass := opts
	pass.Out = held
	// Collected only when a join was asked for: without a task id there is no join key,
	// and buffering every record of every tape to print nothing is a memory cost with no
	// reader.
	var recs []audit.JoinedRecord
	if opts.TaskID != "" {
		pass.Collect = func(r audit.JoinedRecord) {
			r.Tape = t.num
			recs = append(recs, r)
		}
	}
	res, verifyErr := audit.VerifyLogFiles(snap.Files, verifier, pass)
	// Checked before the read error and before any verdict, because a rotation landing
	// mid-pass produces those too: a pruned sibling reads as an open failure, a re-pointed
	// base as a PASS over an incomplete chain or a spurious CHAIN BREAK. "Re-run" is the
	// only honest answer to any of them, and it is NOT a finding, so it exits 2 not 1.
	// The held findings are DISCARDED with it — they describe a chain that was never read
	// as a whole, and the re-run reports the real ones. The collected records go with
	// them, for the same reason: a sequence assembled from a chain nobody could read is
	// not evidence of an order.
	if err := snap.CheckUnchanged(); err != nil {
		return noVerdictOutcome(t.logPath, err)
	}
	// The findings are released HERE, above both partial-pass arms and below the rotation
	// bracket, and the asymmetry is the whole reason the raced rotation is not one arm with
	// them: a raced rotation FABRICATES findings (a fresh base's head chained onto the
	// previous sibling's tail), so its lines must be dropped unread, while a torn tail or an
	// aborted scan fabricates none — every line below describes a record classified before
	// the stop. Suppressing these would let one stripped newline hide a proved tamper.
	held.release()
	if errors.Is(verifyErr, audit.ErrUnterminatedTail) {
		// Joinable: the fragment scanSignedLines dropped is not a COMPLETE record and nothing
		// follows it, so this tape's contribution to a sequence is whole.
		return partialPassOutcome(t, res, recs, verifyErr, "anything past that final fragment", true)
	}
	if verifyErr != nil {
		// Not joinable: an aborted scan leaves an unread SUFFIX, and the records in it would
		// go missing from a sequence that reads absence as "this point never handled the call".
		return partialPassOutcome(t, res, recs, fmt.Errorf("reading log: %w", verifyErr),
			"the rest of the tape past that failure", false)
	}

	if res.Total == 0 {
		// Not itself a failure, but indistinguishable from a fully truncated log without
		// an external anchor — say so plainly.
		fmt.Println("Checked 0 record(s). The log is empty; note that an empty or fully " +
			"truncated log cannot be distinguished from a never-written one without an " +
			"external high-water mark (ship records to an append-only sink).")
		return tapeOutcome{res: res, recs: recs, verdict: true, joinable: true}
	}
	printVerifySummary(res)
	return tapeOutcome{res: res, recs: recs, verdict: true, joinable: true}
}

// partialPassOutcome answers for a pass that stopped short of this tape's end — a torn final
// record, or a read error that aborted the scan. A finding it already PROVED stands (see
// auditVerifyFindingsExit); a clean prefix proves nothing about what follows and reaches no
// verdict at all. unread names what the pass did not reach, for the operator; joinable says
// the unread part holds no COMPLETE record.
//
// One function for both arms because the two must not drift on the advice an operator's
// runbook greps for — the reason noVerdictOutcome below is one function.
func partialPassOutcome(t auditTape, res audit.VerifyResult, recs []audit.JoinedRecord,
	err error, unread string, joinable bool) tapeOutcome {
	// res.OK() and not a narrower "was it really tampering" predicate, even though it counts
	// the two unverified-key states a summary note calls NOT tampering: it is the SAME
	// predicate a complete pass reports its verdict with, and a tape failing on those already
	// exits 1 with no read error involved. Narrowing it here would mean one appended byte
	// moved such a tape from 1 to 2 — the suppression this whole arm exists to refuse.
	if res.OK() {
		return noVerdictOutcome(t.logPath, err)
	}
	printVerifySummary(res)
	// On STDOUT beside the tallies, not only on stderr: the tallies are what a redirected
	// report and a SIEM ingest, and over an aborted scan they count an attacker-chosen
	// prefix, which reads exactly like a complete verification of the tape.
	fmt.Printf("Note: this pass certified a PREFIX of the tape — %s was not read. The tallies "+
		"above cover the records read before that stop and say nothing about the rest.\n", unread)
	fmt.Fprintf(os.Stderr, "eunox audit-verify: %s: %v; the findings above stand — they describe "+
		"records read before the stop — but %s was not read\n", t.logPath, err, unread)
	return tapeOutcome{res: res, recs: recs, verdict: true, joinable: joinable}
}

// noVerdictOutcome is the answer for a pass that covered something other than the chain it
// was asked about — a rotation landed inside it, its last record was still being written, or
// a read error stopped it with nothing proved against what it did read. It is NOT a finding,
// so it carries no verdict for the ranking, and no result: a verdict over a chain nobody
// could read whole is not one.
//
// One function because its callers must not drift on the advice an operator's runbook greps
// for; which of them may release its held findings first is the caller's own question, and it
// differs (see verifyOneTape).
func noVerdictOutcome(logPath string, err error) tapeOutcome {
	fmt.Fprintf(os.Stderr, "eunox audit-verify: %s: %v; no verdict was reached — re-run "+
		"(against a quiescent log, or a copy of the chain)\n", logPath, err)
	return tapeOutcome{}
}

// heldFindingsCap bounds what a bracketed pass withholds. A rotation racing the pass
// fabricates a handful of lines at one seam (a CHAIN BREAK plus a SEQ GAP), so a pass
// past this volume is reporting the LOG's findings, which an operator should see even if
// the bracket goes on to call the run inconclusive. Without a cap a wholly-tampered log
// would buffer a line per record.
const heldFindingsCap = 64 << 10

// heldFindings withholds VerifyLogFiles' finding lines until the rotation bracket has
// decided whether the pass covered a coherent chain, then either releases them or drops
// them with the inconclusive verdict. Past heldFindingsCap it gives up and streams: see
// the constant. A clean pass writes nothing here, so the common case buffers nothing.
type heldFindings struct {
	out       io.Writer
	buf       bytes.Buffer
	streaming bool
}

// Write never reports an error to the verifier: a findings line that cannot be shown must
// not abort a verification pass, and the verifier discards write errors anyway.
func (h *heldFindings) Write(p []byte) (int, error) {
	if h.streaming {
		_, _ = h.out.Write(p)
		return len(p), nil
	}
	h.buf.Write(p)
	if h.buf.Len() >= heldFindingsCap {
		h.streaming = true
		h.release()
	}
	return len(p), nil
}

// release writes out whatever is still held. Idempotent: the buffer is emptied, so the
// cap-exceeded flush and the end-of-pass release cannot print the same line twice.
func (h *heldFindings) release() {
	if h.buf.Len() == 0 {
		return
	}
	_, _ = h.out.Write(h.buf.Bytes())
	h.buf.Reset()
}

// printVerifySummary writes the tallies and the operator notes a non-empty pass produces.
// Split out of cmdAuditVerify to keep it under the length budget; the notes are the part that
// grows, since each one names a state the verdict alone cannot distinguish.
func printVerifySummary(res audit.VerifyResult) {
	fmt.Printf(auditVerifySummaryFormat,
		res.Total, res.Valid, res.Invalid, res.Skipped, res.UnknownKey, res.Unverifiable, res.ChainBreaks)
	// A missing-key state, not tampering — kept distinct from INVALID so a key rotation
	// isn't mistaken for corruption. The verdict still fails: unverified is unverified.
	if res.UnknownKey > 0 {
		fmt.Printf("Note: %d record(s) were signed with a key absent from the verification ring (UNKNOWN_KEY_ID) — "+
			"expected after a key rotation that retired the signing key. Add the retired key(s) to the ring "+
			"(--audit-key-path / the configured keyPath) to verify them; they are NOT counted as tampered.\n", res.UnknownKey)
	}
	// A record no key was available to check at all — nothing was checked, so it can't be
	// proven tampered the way a named-but-missing key_id can, but the verdict still fails.
	if res.Unverifiable > 0 {
		fmt.Printf("Note: %d record(s) could not be checked against any key (UNVERIFIABLE) — "+
			"typically a pre-key_id-era record whose signing key was retired. Add the original key(s) to the ring "+
			"to verify them; until then they cannot be distinguished from tampering and the verdict fails.\n", res.Unverifiable)
	}
	// Both notes below are keyed on the VERIFIED oldest seq, never the claimed one: FirstSeq
	// is adopted from the head record before its HMAC is checked, so on a failing log it is a
	// number the forger chose — and this is precisely the value an operator reconciles
	// against an external high-water mark. The two agree on a log that passes, so a clean
	// verify prints exactly what it printed before.
	if res.FirstSeq > 0 && res.FirstVerifiedSeq != res.FirstSeq {
		if res.FirstVerifiedSeq == 0 {
			fmt.Printf("Note: the oldest record claims seq %d, but no record's signature verified, so no "+
				"retained seq is proven — reconcile against your external high-water mark rather than "+
				"the claimed value.\n", res.FirstSeq)
		} else {
			fmt.Printf("Note: the oldest record claims seq %d but did not verify; the oldest seq proven by a "+
				"verified signature is %d — reconcile against that, not the claimed value.\n",
				res.FirstSeq, res.FirstVerifiedSeq)
		}
	}
	// seq > 1 across the whole chain means leading records (or whole rotated files) were
	// removed or pruned — unprovable from local files alone without an external anchor.
	if res.FirstVerifiedSeq > 1 {
		fmt.Printf("Note: the oldest verified record across the retained log files is seq %d, not 1 — "+
			"leading records (or whole leading rotated files) were removed or pruned by "+
			"retention (indistinguishable without an external anchor).\n", res.FirstVerifiedSeq)
	}
}
