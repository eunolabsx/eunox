// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// stats: a denial-count histogram over the local audit log, for spotting which
// tools and denial codes dominate before tightening a manifest.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/internal/audit"
)

// statsUsageExit is stats' exit code for a usage, config, or audit-log-read error, matching
// the proxy/validate/suggest/audit-verify convention (2 = usage error). stats reports no
// findings, so nothing here is reserved for exit 1 the way validate reserves it for drift and
// audit-verify for a failed chain — but the code still has to mean the same thing across the
// binary, or a script gating on it learns a rule with one silent exception.
const statsUsageExit = 2

// cmdStats runs the `stats` subcommand, returning the exit code (rather than calling
// os.Exit) so tests can drive every branch.
func cmdStats(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.Usage = func() {
		w := usageWriter(args)
		_, _ = fmt.Fprint(w, `Usage: eunox stats [flags]

Print a denial count histogram from the local audit log. Denials are split
into BLOCKED (enforce-mode — request was rejected) and OBSERVED (audit-mode
— request was forwarded; the verdict is recorded but was not enforced), so
that an operator running in audit mode while staging an allowlist can see
exactly what would be blocked if enforcement were enabled.

Exit codes:
  0  The histogram was printed (including for a log with no denials).
  2  Usage error, or a config or audit-log-read failure. There is no findings
     code: stats reports what the log already holds, so a busy histogram is
     not a failure.

Flags:
`)
		fs.SetOutput(w)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the configured audit.log is\nused as the default for --audit-log.")
	auditLogPath := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")

	if code, done := parseAuditReaderFlags("stats", fs, args, configPath, auditLogPath, nil); done {
		if code != 0 {
			// Translate the shared preamble's 1 to this command's own usage exit code;
			// see statsUsageExit.
			return statsUsageExit
		}
		return code
	}
	logPath, ok := resolveAuditReaderLogPath("stats", *auditLogPath)
	if !ok {
		return statsUsageExit
	}

	r, closeChain, err := openAuditChain("stats", logPath)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return statsUsageExit
	}
	defer closeChain()

	summary, err := computeAuditStats(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox stats: reading log: %v\n", err)
		return statsUsageExit
	}
	printAuditStats(os.Stdout, summary)
	return 0
}

// denialKey groups denials for histogram aggregation.
type denialKey struct{ tool, code string }

// statsTarget renders a record's target for the denial histogram: a structured
// target_type + target becomes a namespace-typed label ("tool:write_file"); a
// denial with no enforcement target (unmapped method, pre-dispatch JWT rejection)
// falls back to the raw method so distinct denials stay distinguishable.
func statsTarget(targetType, target, method string) string {
	if targetType != "" && target != "" {
		return targetType + ":" + target
	}
	return method
}

// auditStatsSummary is the aggregated view of the audit log. Denials are split
// by audit_only so an operator running in audit mode (forwarded, would-be
// denials) cannot misread observations as enforced blocks.
type auditStatsSummary struct {
	total        int
	allowed      int
	blocked      int // denials with audit_only=false (call was rejected)
	observed     int // denials with audit_only=true  (call was forwarded)
	escalated    int // decision=escalate: refused pending human approval (never forwarded)
	declassified int // allows that cleared a flow label under a human approval (labels_cleared present)
	// declassifyCommitFailed is the one to alert on: the call RAN and the clear did not
	// land, so the session keeps taint it should have dropped and every later sink
	// over-blocks until a new approval is issued.
	declassifyCommitFailed int
	// declassifyNotApplied is benign — the call was refused below the decision, so the
	// labels were never removed — but it explains a spent grant beside it.
	declassifyNotApplied int
	// declassifyResultWithheld counts refusals where the action EXECUTED and eunox dropped
	// its result (response redaction failed) — not a strict subset of the count above, and
	// its remedy differs: the sanitizing work is already done, so a re-minted approval
	// re-delivers rather than re-runs.
	declassifyResultWithheld int
	// spentApprovals counts single-use grants this log shows being burned — the
	// reconciliation signal for "which of my outstanding one-shot approvals are still live?".
	spentApprovals  int
	other           int // records with a decision outside "allow" | "deny" | "escalate"
	blockedDenials  map[denialKey]int
	observedDenials map[denialKey]int
}

// computeAuditStats scans an audit JSONL stream and returns the bucketed summary.
// Blank lines are skipped; undecodable lines go to the "other" bucket. Errors are
// only scanner-level (read failure, line too long).
func computeAuditStats(r io.Reader) (auditStatsSummary, error) {
	out := auditStatsSummary{
		blockedDenials:  make(map[denialKey]int),
		observedDenials: make(map[denialKey]int),
	}
	scanner := audit.NewLineScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		out.total++
		var rec struct {
			Decision      string   `json:"decision"`
			TargetType    string   `json:"target_type"`
			Target        string   `json:"target"`
			Method        string   `json:"method"`
			DenialCode    string   `json:"denial_code"`
			AuditOnly     bool     `json:"audit_only"`
			LabelsCleared []string `json:"labels_cleared"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			// Undecodable line: count in "other" so the total still reconciles
			// (allowed+blocked+observed+other == total).
			out.other++
			continue
		}
		out.addDeclassifyDetails(line)
		switch rec.Decision {
		case "allow":
			out.allowed++
			// Counted separately, not bucketed apart: the record is a genuine allow, and
			// this answers "how often did a human agree to drop taint".
			if len(rec.LabelsCleared) > 0 {
				out.declassified++
			}
		case "deny":
			k := denialKey{tool: statsTarget(rec.TargetType, rec.Target, rec.Method), code: rec.DenialCode}
			if rec.AuditOnly {
				out.observed++
				out.observedDenials[k]++
			} else {
				out.blocked++
				out.blockedDenials[k]++
			}
		case audit.DecisionEscalate:
			// Tallied with the blocked denials AND counted separately: "needs a human" is
			// the operator's own queue of work.
			k := denialKey{tool: statsTarget(rec.TargetType, rec.Target, rec.Method), code: rec.DenialCode}
			out.escalated++
			out.blocked++
			out.blockedDenials[k]++
		default:
			// Unknown decision value — count in "other" so the total reconciles.
			out.other++
		}
	}
	if err := scanner.Err(); err != nil {
		return auditStatsSummary{}, err
	}
	return out, nil
}

// declassifyProbe is the byte pattern addDeclassifyDetails scans a raw record for before
// paying for a second decode, derived from the producer's own key prefix so the two can't drift.
var declassifyProbe = []byte(audit.DeclassifyDetailPrefix)

// addDeclassifyDetails tallies the declassification facts riding in a record's `details`
// map. It probes the WHOLE line rather than capturing `details` on the outer struct — a
// RawMessage would copy the caller's entire argument map on most records — and decodes only
// on a hit. A miss reads as "no declassification facts", the safe direction.
func (s *auditStatsSummary) addDeclassifyDetails(line []byte) {
	if !bytes.Contains(line, declassifyProbe) {
		return
	}
	var rec struct {
		Details map[string]json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return
	}
	details := rec.Details
	if _, ok := details[audit.DeclassifySpentApprovalKey]; ok {
		s.spentApprovals++
	}
	if _, ok := details[audit.DeclassifyNotAppliedKey]; ok {
		s.declassifyNotApplied++
	}
	if _, ok := details[audit.DeclassifyResultWithheldKey]; ok {
		s.declassifyResultWithheld++
	}
	if _, ok := details[audit.DeclassifyCommitFailedKey]; ok {
		s.declassifyCommitFailed++
	}
}

// printAuditStats renders the bucketed summary in two tables — BLOCKED (enforced)
// and OBSERVED (audit-mode, call forwarded) — so an audit-mode denial is never
// mistaken for a block.
func printAuditStats(w io.Writer, s auditStatsSummary) {
	// wf/wln discard write errors (not actionable; same pattern as runValidateLive).
	wf, wln := writers(w)

	wf("Total records: %d  (allowed: %d, blocked: %d, observed: %d",
		s.total, s.allowed, s.blocked, s.observed)
	if s.escalated > 0 {
		wf(", of which escalated: %d", s.escalated)
	}
	if s.other > 0 {
		wf(", other: %d", s.other)
	}
	wln(")")
	if s.escalated > 0 {
		wln("  (escalated = refused pending human approval — an action over the effect ceiling, or a declassification no approval covered: the call was NOT forwarded, and it needs a human, not a policy fix.)")
	}
	if s.declassified > 0 {
		wf("  (declassified = %d allow(s) cleared a flow label under a human approval; every one names its approver in the record.)\n", s.declassified)
	}
	// FIRST among the declassification notes: means a session is not in the state the
	// policy describes — the approved clear did not land, so taint remains.
	if s.declassifyCommitFailed > 0 {
		wf("\n  ATTENTION: %d approved declassification(s) could not be applied after the call had already run\n", s.declassifyCommitFailed)
		wln("  (the flow store faulted at the commit; those sessions keep taint the policy says the action cleared,")
		wln("   so later sinks over-block until the action is retried under a new approval. Check the flow-store backend.)")
	}
	if s.declassifyNotApplied > 0 {
		wf("  (declassify-not-applied = %d refused call(s) whose approved clear was therefore never made; the labels were never removed, so nothing is under-tainted.)\n",
			s.declassifyNotApplied)
	}
	// Its own line, not "of those": can stand alone (a no-op clear leaves no not-applied
	// labels), and the remedy differs — the work is done, only delivery failed.
	if s.declassifyResultWithheld > 0 {
		wf("  (declassify-result-withheld = %d refused call(s) whose action had already EXECUTED upstream, with the result dropped because response redaction failed;\n"+
			"   the sanitizing work is done, so a fresh approval re-delivers rather than re-runs it. Check the redactFields paths against the real response shape.)\n",
			s.declassifyResultWithheld)
	}
	if s.spentApprovals > 0 {
		wf("  (single-use approvals spent = %d; each is burned for good, including on a clear that changed nothing or a call that was then refused. Reconcile these against your outstanding one-shot approvals — details.%s names each.)\n",
			s.spentApprovals, audit.DeclassifySpentApprovalKey)
	}
	if s.observed > 0 {
		wln("  (observed = audit-mode denials: the call was forwarded; the verdict is recorded but was not enforced.)")
	}
	if s.other > 0 {
		wln("  (other = records with an unrecognized decision value — possible audit-record schema mismatch.)")
	}
	wln()

	if s.blocked == 0 && s.observed == 0 {
		wln("No denials recorded.")
		return
	}

	if s.blocked > 0 {
		wln("BLOCKED DENIALS  (request was rejected)")
		writeDenialTable(w, s.blockedDenials)
	}
	if s.observed > 0 {
		if s.blocked > 0 {
			wln()
		}
		wln("OBSERVED DENIALS  (audit mode — request was forwarded)")
		writeDenialTable(w, s.observedDenials)
	}
}

// writeDenialTable renders one (tool, code) → count histogram in deterministic
// order: highest count first, then tool name, then denial code.
func writeDenialTable(w io.Writer, denials map[denialKey]int) {
	wf, wln := writers(w)

	type row struct {
		tool, code string
		count      int
	}
	rows := make([]row, 0, len(denials))
	for k, n := range denials {
		rows = append(rows, row{tool: k.tool, code: k.code, count: n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		if rows[i].tool != rows[j].tool {
			return rows[i].tool < rows[j].tool
		}
		return rows[i].code < rows[j].code
	})
	wf("%-30s  %-30s  %s\n", "TARGET", "CODE", "COUNT")
	wln(strings.Repeat("-", 72))
	for _, r := range rows {
		wf("%-30s  %-30s  %d\n", r.tool, r.code, r.count)
	}
}
