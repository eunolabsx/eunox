// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// audit-verify's cross-enforcement-point half: resolving the tapes an operator named,
// verifying each as its OWN chain, and printing the task-joined sequence across them.
//
// The shape this file exists to keep separate: verification is per tape and a join is
// not verification. Each enforcement point signs its own chain over its own file with
// its own key, so N tapes are N independent verdicts — never one — and the sequence
// printed after them is a PRESENTATION of records those verdicts already judged, with
// its ordering assumption stated rather than implied (§3.14).

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/eunolabs/eunox/internal/audit"
)

// repeatedPath collects a repeatable path flag in the order the operator wrote it.
// Order is load-bearing for --audit-key-path, which pairs positionally with
// --audit-log.
type repeatedPath []string

// String renders the collected paths for flag's default display (always empty here:
// the defaults are resolved after parsing, from --config and the built-in path).
func (r *repeatedPath) String() string { return strings.Join(*r, ",") }

// Set appends one occurrence, refusing an empty value: `--audit-log=` reads as an
// operator naming a tape, and silently resolving it to the DEFAULT log would verify a
// file they did not ask about and join its records into the sequence.
func (r *repeatedPath) Set(v string) error {
	if v == "" {
		return fmt.Errorf("empty path")
	}
	*r = append(*r, v)
	return nil
}

// auditTape is one enforcement point's tape as the command addresses it: the base log
// path (whose rotated siblings are discovered per tape, exactly as in single-tape mode)
// and the key path whose ring verifies it.
type auditTape struct {
	num     int // 1-based, in the order the operator named the tapes
	logPath string
	keyPath string
}

// resolveAuditTapes pairs the --audit-log and --audit-key-path occurrences into tapes.
//
// The keying rule is the one decision a cross-PEP verifier cannot avoid making, and it
// is made EXPLICIT rather than inferred: either every tape verifies against one ring
// (the shared-key deployment — zero or one --audit-key-path), or each tape verifies
// against its own (N of each, paired positionally). Any other count is a usage error
// naming both counts.
//
// What it deliberately does NOT do is merge several key files into one ring. Merging
// would make a record signed by enforcement point B verify on A's tape, which is exactly
// the forgery the per-writer chains exist to bound: an operator who separates the keys
// has separated the trust domains, and this tool must not put them back together.
func resolveAuditTapes(logs, keys repeatedPath) ([]auditTape, error) {
	if len(logs) == 0 {
		// One unnamed tape: ResolveLogPath supplies the built-in default, as in
		// single-tape mode.
		logs = repeatedPath{""}
	}
	switch len(keys) {
	case 0, 1:
		// Shared ring (or the default key path). Not the same as merging rings: one
		// ring is used for each independent pass.
	case len(logs):
		// Paired positionally.
	default:
		return nil, fmt.Errorf("eunox audit-verify: %d --audit-key-path value(s) for %d --audit-log value(s): "+
			"pass one key path (every tape shares a signing key) or exactly one per tape, in the same order",
			len(keys), len(logs))
	}

	tapes := make([]auditTape, 0, len(logs))
	seen := make(map[string]int, len(logs))
	for i, l := range logs {
		logPath, err := audit.ResolveLogPath(l)
		if err != nil {
			return nil, fmt.Errorf("eunox audit-verify: %w", err)
		}
		// A tape named twice would be verified twice and would contribute every one of
		// its records to the join twice, which reads as a duplicated sequence rather
		// than as the operator's typo it is. Compared on the NORMALIZED path, because
		// the typo this catches is `./audit.jsonl` beside `audit.jsonl` at least as
		// often as the same string twice, and ResolveLogPath only expands "~".
		tapeKey := normalizedTapeKey(logPath)
		if prev, dup := seen[tapeKey]; dup {
			return nil, fmt.Errorf("eunox audit-verify: --audit-log %s names the same tape as tape %d; "+
				"each tape may be named once", logPath, prev)
		}
		seen[tapeKey] = i + 1

		key := ""
		switch {
		case len(keys) == 1:
			key = keys[0]
		case len(keys) > 1:
			key = keys[i]
		}
		keyPath, err := audit.ResolveKeyPath(key)
		if err != nil {
			return nil, fmt.Errorf("eunox audit-verify: %w", err)
		}
		tapes = append(tapes, auditTape{num: i + 1, logPath: logPath, keyPath: keyPath})
	}
	return tapes, nil
}

// normalizedTapeKey is the identity two --audit-log values are compared on: the path made
// absolute and lexically clean, so `./audit.jsonl` and `audit.jsonl` are one tape.
//
// Lexical only. Two paths reaching one file through a symlink or a hard link still read as
// two tapes and are verified (and joined) twice — closing that needs the file to exist to
// stat, and a tape that does not exist yet has its own report (auditLogMissingHint) that a
// stat error would replace with something less useful. Abs failing (no working directory)
// falls back to Clean rather than refusing: a lexical comparison is what this had before,
// and losing the whole run over a cwd lookup is worse than losing the `./` case.
func normalizedTapeKey(logPath string) string {
	if abs, err := filepath.Abs(logPath); err == nil {
		return abs
	}
	return filepath.Clean(logPath)
}

// verifiedRings caches one verification ring per resolved key path, so the shared-key
// case reads the key file once rather than once per tape. Caching the ring is not
// merging rings: each entry is the ring of exactly one key file.
type verifiedRings map[string]*audit.Sink

// verifierFor loads (or reuses) the ring for keyPath. Load-only, for the reason the
// single-tape path states: minting a key here would make every record report
// UNKNOWN_KEY and misdiagnose an operator error as a key rotation.
func (v verifiedRings) verifierFor(keyPath string) (*audit.Sink, error) {
	if s, ok := v[keyPath]; ok {
		return s, nil
	}
	keys, err := audit.LoadKeys(keyPath)
	if err != nil {
		return nil, fmt.Errorf("eunox audit-verify: loading audit key: %w", err)
	}
	// Keyed by key id, so records straddling a rotation each verify against the key that
	// signed them; records with no key_id (pre-rotation format) are tried against every key.
	s := audit.NewVerifier(keys)
	v[keyPath] = s
	return s, nil
}

// printTapeVerdict names one tape's own verdict. Printed only in cross-tape mode: with a
// single tape the exit code says the same thing, and with several it does not — "tape B
// has a break" and "the run failed" are different findings, and only one of them fits in
// an exit status.
func printTapeVerdict(t auditTape, res audit.VerifyResult) {
	verdict := "PASS"
	if !res.OK() {
		verdict = "FAIL"
	}
	fmt.Printf("Tape %d verdict: %s (%s)\n", t.num, verdict, t.logPath)
}

// printJoinHeader states what the joined sequence is and what it rests on, BEFORE the
// rows rather than after: the two assumptions below are the difference between reading
// the table as a record of what happened and reading it as what each writer said, and a
// caveat under a table is one an operator scrolls past.
func printJoinHeader(taskID string, tapes int, ord audit.JoinOrdering) {
	fmt.Printf("\nSequence for task_id=%s: %d record(s) across %d tape(s).\n",
		audit.SanitizeAuditField(taskID), len(ord.Ordered)+len(ord.Unordered), tapes)
	fmt.Println("Within a tape the order is proven and is what this follows: `seq` is signed and its")
	fmt.Println("contiguity is checked, so a record is never placed before a same-tape record its `seq`")
	fmt.Println("says came first. ACROSS tapes nothing is proven — `seq` orders nothing between writers, and")
	fmt.Println("the tapes are interleaved by `time`, which each enforcement point stamps from its own clock;")
	fmt.Println("eunox neither requires nor checks clock sync between them. Records from different tapes")
	fmt.Println("bearing the same instant are printed in the order the tapes were named, not a proven one.")
	fmt.Println("Absence is not loss: a call an enforcement point never handled is expected to be missing")
	fmt.Println("from its tape. Only a gap INSIDE one chain is evidence, and that is the per-tape verdict")
	fmt.Println("above — this sequence is a reconstruction, never a verdict.")
}

// printJoinCaveats reports what the ordering could not establish and what the local
// files DO falsify about it.
func printJoinCaveats(ord audit.JoinOrdering, tapes []auditTape) {
	if len(ord.NonMonotonicTapes) > 0 {
		// Why the TIME column can read backwards down the table: those rows are placed in
		// the order their tape PROVES, which the timestamps do not reproduce. Stated
		// without naming a cause, because this cannot establish one — see
		// audit.JoinOrdering.NonMonotonicTapes.
		fmt.Printf("Note: on tape(s) %s the recorded `time` does not increase with `seq`, so the TIME "+
			"column above does not increase down the table: within a tape `seq` is the proven order "+
			"(it is signed and contiguity-checked) and the sequence follows it. That is not by itself "+
			"a clock fault — a writer stamps `time` on the calling goroutine and assigns `seq` in its "+
			"drainer, so concurrent recorders on a busy tape are stamped in one order and sequenced in "+
			"the other — but a clock that did move backwards looks the same from here.\n",
			tapeList(ord.NonMonotonicTapes, tapes))
	}
	if len(ord.UnattributedTapes) > 0 {
		fmt.Printf("Note: tape(s) %s contributed record(s) carrying no `pep`, so they are attributed by "+
			"file above. That attribution does not survive being merged into a SIEM, which is what "+
			"`pep` (--audit-pep / audit.pep) exists to carry; configure it on those enforcement points.\n",
			tapeList(ord.UnattributedTapes, tapes))
	}
	if len(ord.Unordered) > 0 {
		fmt.Printf("Note: %d record(s) carry a `time` that does not parse and so have NO position in the "+
			"sequence; they are listed last. Each is counted INVALID by its own tape's verdict.\n",
			len(ord.Unordered))
	}
}

// tapeList renders tape numbers with their paths, so a note names something the operator
// can act on rather than an index into a flag order they have to reconstruct.
func tapeList(nums []int, tapes []auditTape) string {
	parts := make([]string, 0, len(nums))
	for _, n := range nums {
		if n >= 1 && n <= len(tapes) {
			parts = append(parts, fmt.Sprintf("%d (%s)", n, tapes[n-1].logPath))
			continue
		}
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ", ")
}

// printJoinedSequence writes the whole cross-tape report for one task: the header and
// its assumptions, the rows, then the caveats.
func printJoinedSequence(taskID string, tapes []auditTape, recs []audit.JoinedRecord) {
	ord := audit.OrderJoinedRecords(recs)
	printJoinHeader(taskID, len(tapes), ord)
	if len(ord.Ordered)+len(ord.Unordered) == 0 {
		fmt.Println("\n(no record on any named tape carries this task_id — see the absence note above)")
		return
	}
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	// One row shape, assembled as cells and joined once: a header literal plus a
	// separate per-column row call could drift on column count, which tabwriter renders
	// as a silently misaligned table rather than an error.
	writeRow := func(cells []string) { _, _ = fmt.Fprintf(tw, "%s\n", strings.Join(cells, "\t")) }
	writeRow([]string{"TIME", "PEP", "TAPE", "SEQ", "DECISION", "METHOD", "TARGET", "STATUS"})
	// Ordered then Unordered: a record with no parseable time belongs to the sequence
	// but has no position in it, so it is listed after the ones that do.
	for _, group := range [][]audit.JoinedRecord{ord.Ordered, ord.Unordered} {
		for i := range group {
			writeRow(joinRowCells(&group[i]))
		}
	}
	// The write errors tabwriter can report are the same non-actionable stdout failures
	// the rest of this report discards; it is already emitted by the time this returns.
	_ = tw.Flush()
	printJoinCaveats(ord, tapes)
}

// joinRowCells renders one joined record. Every field that reaches a terminal here comes
// off a tape a peer influenced (target and session_id are bounded but not control-char
// sanitized at storage), so each is sanitized — a literal newline would otherwise forge
// a row.
func joinRowCells(r *audit.JoinedRecord) []string {
	when := r.Time
	if !r.TimeOK {
		when = "(unparseable)"
	}
	pep := r.PEP
	if pep == "" {
		pep = "(unattributed)"
	}
	target := r.Target
	if r.TargetType != "" && target != "" {
		target = r.TargetType + ":" + target
	}
	decision := r.Decision
	if r.DenialCode != "" {
		decision += " " + r.DenialCode
	}
	return []string{
		audit.SanitizeAuditField(when),
		audit.SanitizeAuditField(pep),
		strconv.Itoa(r.Tape),
		strconv.FormatUint(r.Seq, 10),
		audit.SanitizeAuditField(decision),
		audit.SanitizeAuditField(r.Method),
		audit.SanitizeAuditField(target),
		string(r.Status),
	}
}
