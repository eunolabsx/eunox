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
	"maps"
	"os"
	"slices"
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
  2  Usage error, a config or audit-log-read failure, or a read a rotation
     raced (inconclusive - re-run). There is no findings code: stats reports
     what the log already holds, so a busy histogram is not a failure.

Flags:
`)
		fs.SetOutput(w)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the configured audit.log is\nused as the default for --audit-log.")
	auditLogPath := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")

	logPath, code, done := parseAndResolveAuditLog("stats", fs, args, configPath, auditLogPath, statsUsageExit)
	if done {
		return code
	}
	summary, code, done := readAuditChainOrExit("stats", logPath, statsUsageExit, computeAuditStats)
	if done {
		return code
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
	total     int
	allowed   int
	blocked   int // denials with audit_only=false (call was rejected)
	observed  int // denials with audit_only=true  (call was forwarded)
	escalated int // decision=escalate: refused pending human approval (never forwarded)
	// handlerFaults counts records naming a condition handler whose contract violation the
	// engine repaired. It is the ONLY operator-visible trace of that repair — the call was
	// decided exactly as a conforming handler's would have been — so a run that never surfaces
	// it is the silent tolerance the report exists to prevent.
	handlerFaults int
	// unroutable counts eunox's OWN routing refusals per reason, and unroutableTotal their sum.
	// Their code already says they are routing rather than policy; what this adds is the
	// per-REASON split (which of the three ways) that a denial bucket keyed on the code alone
	// cannot carry — see addUnroutableDetails.
	unroutable      map[string]int
	unroutableTotal int
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
			Decision   string `json:"decision"`
			TargetType string `json:"target_type"`
			Target     string `json:"target"`
			Method     string `json:"method"`
			DenialCode string `json:"denial_code"`
			AuditOnly  bool   `json:"audit_only"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			// Undecodable line: count in "other" so the total still reconciles
			// (allowed+blocked+observed+other == total).
			out.other++
			continue
		}
		out.addHandlerFaultDetails(line)
		out.addUnroutableDetails(line)
		switch rec.Decision {
		case "allow":
			out.allowed++
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

// decodeDetails returns a record's `details` map when the raw line contains probe, and nil
// otherwise — the probe-then-decode step all three detail tallies share.
//
// The probe is what keeps this cheap: `details` is the caller's whole argument map, so decoding
// it on every record to answer a rare question is the cost each of these tallies exists to
// avoid. Each probe is derived from its producer's own key, so a rename there is a compile error
// rather than a filter that silently matches nothing.
//
// A decode failure reads as "no details", the direction that under-reports rather than
// inventing a count. Shared so a record hitting two probes decodes once per probe rather than
// once per tally with three copies of the same eight lines to keep in agreement.
func decodeDetails(line, probe []byte) map[string]json.RawMessage {
	if !bytes.Contains(line, probe) {
		return nil
	}
	var rec struct {
		Details map[string]json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil
	}
	return rec.Details
}

// handlerFaultProbe is addHandlerFaultDetails' pre-filter, derived from the producer's own key
// so the two cannot drift: the caller's whole argument map must not be decoded on every record
// to answer a rare question.
var handlerFaultProbe = []byte(audit.HandlerFaultKey)

// addHandlerFaultDetails tallies records reporting a repaired condition-handler fault. A miss
// reads as "no fault", the direction that under-reports rather than inventing an alert.
func (s *auditStatsSummary) addHandlerFaultDetails(line []byte) {
	if _, ok := decodeDetails(line, handlerFaultProbe)[audit.HandlerFaultKey]; ok {
		s.handlerFaults++
	}
}

// unroutableProbe is addUnroutableDetails' pre-filter, derived from the producer's own key for
// handlerFaultProbe's reason.
var unroutableProbe = []byte(audit.UnroutableKey)

// addUnroutableDetails tallies refusals eunox's own routing produced, per reason.
//
// Their code (UNROUTABLE_METHOD) says they are eunox's own routing rather than a policy block;
// this breaks them down by REASON, which is the part that tells an operator whether a discovery
// run met a method the peer's revision removed or one nobody has heard of. Without it, the tool
// the --audit banner points an operator at reports them as an undifferentiated block count.
func (s *auditStatsSummary) addUnroutableDetails(line []byte) {
	// Read through the producer's KEY, not a struct tag naming it: a rename there is a compile
	// error at the probe and would otherwise leave this silently matching nothing.
	raw, present := decodeDetails(line, unroutableProbe)[audit.UnroutableKey]
	if !present {
		return
	}
	var marker struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &marker); err != nil || marker.Reason == "" {
		return
	}
	if s.unroutable == nil {
		s.unroutable = map[string]int{}
	}
	s.unroutable[marker.Reason]++
	s.unroutableTotal++
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
		wln("  (escalated = refused pending human approval — an action over the effect ceiling: the call was NOT forwarded, and it needs a human, not a policy fix.)")
	}
	// An ATTENTION line because it names a deployment fault an operator must act on that
	// would otherwise be a raw JSONL key
	// nobody greps for. A repaired call looks like every other call on this summary.
	if s.handlerFaults > 0 {
		wf("\n  ATTENTION: %d record(s) name a condition handler that broke the engine's commit contract\n", s.handlerFaults)
		wln("  (a registered handler derived a quota bucket on a request that authorizes no consumption; eunox dropped the")
		wln("   bucket and decided the call as a conforming handler would, so nothing was charged and nothing was blocked —")
		wf("   but the handler is buggy and its budget is NOT being predicted by this run. details.%s names each handler and the contract it broke.)\n", audit.HandlerFaultKey)
	}
	// Named rather than left in the blocked bucket: these are eunox's OWN refusals, not the
	// upstream's behavior and not a policy verdict, and telling them apart is the whole reason
	// an operator runs a wiretap.
	if s.unroutableTotal > 0 {
		wf("\n  NOTE: %d refusal(s) were eunox's own routing, not a policy verdict\n", s.unroutableTotal)
		for _, reason := range slices.Sorted(maps.Keys(s.unroutable)) {
			wf("   - %s: %d\n", reason, s.unroutable[reason])
		}
		wln("  (the method is not dispatched under the MCP revision the host negotiated, so no policy evaluated it;")
		wln("   observe mode downgrades a policy verdict and these have none. If this dominates the tape, the host and")
		wln("   the upstream are on revisions that do not share the methods being called.)")
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
