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

// cmdStats runs the `stats` subcommand and returns the process exit code
// (rather than calling os.Exit itself), so tests can drive every branch. args
// carries the subcommand's own arguments (os.Args[2:] in a real invocation),
// threaded from run.
func cmdStats(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: eunox stats [flags]

Print a denial count histogram from the local audit log. Denials are split
into BLOCKED (enforce-mode — request was rejected) and OBSERVED (audit-mode
— request was forwarded; the verdict is recorded but was not enforced), so
that an operator running in audit mode while staging an allowlist can see
exactly what would be blocked if enforcement were enabled.

Flags:
`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the configured audit.log is\nused as the default for --audit-log.")
	auditLogPath := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")

	if code, done := parseAuditReaderFlags("stats", fs, args, configPath, auditLogPath, nil); done {
		return code
	}
	logPath, ok := resolveAuditReaderLogPath("stats", *auditLogPath)
	if !ok {
		return 1
	}

	r, closeChain, err := openAuditChain("stats", logPath)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return 1
	}
	defer closeChain()

	summary, err := computeAuditStats(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox stats: reading log: %v\n", err)
		return 1
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
	total           int
	allowed         int
	blocked         int // denials with audit_only=false (call was rejected)
	observed        int // denials with audit_only=true  (call was forwarded)
	other           int // records with a decision that is neither "allow" nor "deny"
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

// printAuditStats renders the bucketed summary in two tables — BLOCKED (enforced)
// and OBSERVED (audit-mode, call forwarded) — so an audit-mode denial is never
// mistaken for a block.
func printAuditStats(w io.Writer, s auditStatsSummary) {
	// wf/wln discard write errors (not actionable; same pattern as runValidateLive).
	wf, wln := writers(w)

	wf("Total records: %d  (allowed: %d, blocked: %d, observed: %d",
		s.total, s.allowed, s.blocked, s.observed)
	if s.other > 0 {
		wf(", other: %d", s.other)
	}
	wln(")")
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
