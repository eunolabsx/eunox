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
     CI job can gate on it; never used for usage errors.
  2  Usage error, a config, key-resolution, or log-read failure, or a pass that
     a rotation raced (inconclusive — re-run).

Flags:
`

// cmdAuditVerify runs the `audit-verify` subcommand, returning the exit code (rather than
// calling os.Exit) so tests can drive every branch.
func cmdAuditVerify(args []string) int {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	fs.Usage = func() {
		w := usageWriter(args)
		_, _ = fmt.Fprint(w, auditVerifyUsage)
		fs.SetOutput(w)
		fs.PrintDefaults()
	}
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

// runAuditVerify verifies every tape as its own chain, then prints the task-joined
// sequence if one was asked for. The exit code covers the per-tape VERDICTS only: the
// join establishes nothing (absence of a task's calls from an enforcement point that
// never handled them is expected, unlike a gap inside one chain), so it can never fail a
// run on its own.
//
// A tape that cannot be read, or whose pass a rotation raced, stops the run at exit 2
// rather than being skipped: continuing would print a sequence missing that tape's
// records with nothing in the output saying so, which is the one way this report can
// mislead about the thing it exists to show.
func runAuditVerify(tapes []auditTape, opts audit.VerifyOptions) int {
	if len(tapes) > 1 {
		fmt.Printf("Verifying %d audit tapes as %d INDEPENDENT chains: each enforcement point signs its own\n"+
			"tape with its own key, so there is one verdict per tape and no chain across them.\n", len(tapes), len(tapes))
	}
	rings := verifiedRings{}
	var joined []audit.JoinedRecord
	failed := false
	for _, t := range tapes {
		if len(tapes) > 1 {
			fmt.Printf("\nTape %d: %s\n", t.num, t.logPath)
		}
		res, recs, code := verifyOneTape(t, opts, rings)
		if code != 0 {
			return code
		}
		joined = append(joined, recs...)
		if len(tapes) > 1 {
			printTapeVerdict(t, res)
		}
		if !res.OK() {
			failed = true
		}
	}
	if opts.TaskID != "" {
		printJoinedSequence(opts.TaskID, tapes, joined)
	} else if len(tapes) > 1 {
		fmt.Println("\nPass --task-id to print the sequence these tapes share for one task, attributed by `pep`.")
	}
	if failed {
		return 1
	}
	return 0
}

// verifyOneTape runs the single-tape pass — key ring, rotated-sibling discovery, the
// bracketed verification, the tallies — and collects the task's records out of that same
// pass. code is non-zero when the caller must stop (a read, key, or inconclusive
// failure); res and recs are meaningful only when it is 0.
func verifyOneTape(t auditTape, opts audit.VerifyOptions, rings verifiedRings) (audit.VerifyResult, []audit.JoinedRecord, int) {
	verifier, err := rings.verifierFor(t.keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return audit.VerifyResult{}, nil, auditVerifyUsageExit
	}
	// Verify the whole rotated set as one chain, not just the base file — deletion of an
	// entire interior rotated file would otherwise go undetected. Snapshot rather than a
	// bare LogChainFiles: this runs against a live proxy under traffic (audit-verify takes
	// no lock by design), so the pass has to be bracketed against a rotation moving the
	// files under it.
	snap, err := audit.SnapshotLogChain(t.logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: discovering rotated audit logs for %s: %v\n", t.logPath, err)
		return audit.VerifyResult{}, nil, auditVerifyUsageExit
	}
	if len(snap.Files) == 0 {
		fmt.Fprint(os.Stderr, auditLogMissingHint("audit-verify", t.logPath))
		return audit.VerifyResult{}, nil, auditVerifyUsageExit
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
		fmt.Fprintf(os.Stderr, "eunox audit-verify: %s: %v; no verdict was reached — re-run "+
			"(against a quiescent log, or a copy of the chain)\n", t.logPath, err)
		return audit.VerifyResult{}, nil, auditVerifyUsageExit
	}
	held.release()
	if verifyErr != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: reading log %s: %v\n", t.logPath, verifyErr)
		return audit.VerifyResult{}, nil, auditVerifyUsageExit
	}

	if res.Total == 0 {
		// Not itself a failure, but indistinguishable from a fully truncated log without
		// an external anchor — say so plainly.
		fmt.Println("Checked 0 record(s). The log is empty; note that an empty or fully " +
			"truncated log cannot be distinguished from a never-written one without an " +
			"external high-water mark (ship records to an append-only sink).")
		return res, recs, 0
	}
	printVerifySummary(res)
	return res, recs, 0
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
