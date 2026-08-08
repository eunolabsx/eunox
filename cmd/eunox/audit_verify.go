// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// audit-verify: re-verify the local audit log's per-record HMAC signatures and its
// tamper-evident chain, across the base log and every rotated sibling.

package main

import (
	"errors"
	"flag"
	"fmt"
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

// applyConfigAuditDefaults is loadConfigAuditDefaults for readers that abort on an
// unloadable config (audit-verify, stats, suggest); doctor deliberately does not use this.
func applyConfigAuditDefaults(cmdName, configPath string, logPath, keyPath *string) error {
	_, err := loadConfigAuditDefaults(cmdName, configPath, logPath, keyPath)
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

// parseAuditReaderFlags runs parseReaderArgs, then lets --config fill any audit path the
// operator left empty. configPath is a pointer (not a value) because it is read only after
// fs.Parse runs here; a by-value copy would capture the pre-parse empty string.
func parseAuditReaderFlags(name string, fs *flag.FlagSet, args []string, configPath, logPath, keyPath *string) (code int, done bool) {
	if code, done := parseReaderArgs(name, fs, args); done {
		return code, done
	}
	if err := applyConfigAuditDefaults(name, *configPath, logPath, keyPath); err != nil {
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

// auditVerifyUsageExit is audit-verify's exit code for a usage, config, key-resolution, or
// log-read failure. Exit 1 is reserved for a log that fails verification (like validate
// reserves it for findings), so a cron/CI job can tell tampering from a misconfigured flag.
// parseAuditReaderFlags reports usage errors as 1, so this command translates at the call site.
const auditVerifyUsageExit = 2

// auditVerifySummaryFormat is hoisted to a constant so the site-drift test can assert the
// landing-page demo still quotes tallies this command actually emits.
const auditVerifySummaryFormat = "Checked %d record(s): %d valid, %d invalid, %d skipped, %d unknown-key, %d unverifiable; %d chain break(s).\n"

// cmdAuditVerify runs the `audit-verify` subcommand, returning the exit code (rather than
// calling os.Exit) so tests can drive every branch.
func cmdAuditVerify(args []string) int {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	fs.Usage = func() {
		w := usageWriter(args)
		_, _ = fmt.Fprint(w, `Usage: eunox audit-verify [flags]

Verify HMAC-SHA256 signatures in the local audit log.

Exit codes:
  0  Every record verified and the tamper-evident chain is intact.
  1  The log failed verification (an invalid record, a chain break, an
     unverifiable or unknown-key record). Reserved for findings, so a cron or
     CI job can gate on it; never used for usage errors.
  2  Usage error, or a config, key-resolution, or log-read failure.

Flags:
`)
		fs.SetOutput(w)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the configured audit.log and\naudit.keyPath are used as defaults for --audit-log and --audit-key-path.")
	auditLogPath := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")
	auditKeyPath := fs.String("audit-key-path", "", "Path to the HMAC signing key for the audit log (default: ~/.eunox/audit.key).\nOverrides EUNOX_AUDIT_KEY_PATH environment variable.")
	requestID := fs.String("request-id", "", "Report (count and print) only the record with this request ID. Every record\nis still HMAC-verified and the tamper-evident chain is always checked; this\nfilter narrows the report, not the verification.")
	since := fs.String("since", "", "Report (count and print) only records after this RFC3339 timestamp. Every\nrecord is still HMAC-verified and the tamper-evident chain is always checked;\nthis filter narrows the report, not the verification.")

	if code, done := parseAuditReaderFlags("audit-verify", fs, args, configPath, auditLogPath, auditKeyPath); done {
		if code != 0 {
			// Translate the shared preamble's 1 to this command's own usage exit code;
			// see auditVerifyUsageExit.
			return auditVerifyUsageExit
		}
		return code
	}
	logPath, ok := resolveAuditReaderLogPath("audit-verify", *auditLogPath)
	if !ok {
		return auditVerifyUsageExit
	}

	// Key path resolves: flag (already merged with config) > env var > default.
	expandedKeyPath, err := audit.ResolveKeyPath(*auditKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: %v\n", err)
		return auditVerifyUsageExit
	}
	// Load-only: minting a key here on a missing/mistyped path would make every record
	// report UNKNOWN_KEY and misdiagnose an operator error as a key rotation.
	keys, err := audit.LoadKeys(expandedKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: loading audit key: %v\n", err)
		return auditVerifyUsageExit
	}

	// Keyed by key id, so records straddling a rotation each verify against the key that
	// signed them; records with no key_id (pre-rotation format) are tried against every key.
	verifier := audit.NewVerifier(keys)

	// Verify the whole rotated set as one chain, not just the base file — deletion of an
	// entire interior rotated file would otherwise go undetected.
	chainFiles, err := audit.LogChainFiles(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: discovering rotated audit logs: %v\n", err)
		return auditVerifyUsageExit
	}
	if len(chainFiles) == 0 {
		fmt.Fprint(os.Stderr, auditLogMissingHint("audit-verify", logPath))
		return auditVerifyUsageExit
	}

	var sinceTime time.Time
	if *since != "" {
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox audit-verify: invalid --since value %q: %v\n", *since, err)
			return auditVerifyUsageExit
		}
	}

	if len(chainFiles) > 1 {
		fmt.Printf("Verifying %d audit log files as one chain (oldest rotated to current base).\n", len(chainFiles))
	}
	res, err := audit.VerifyLogFiles(chainFiles, verifier, *requestID, sinceTime, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: reading log: %v\n", err)
		return auditVerifyUsageExit
	}

	if res.Total == 0 {
		// Not itself a failure, but indistinguishable from a fully truncated log without
		// an external anchor — say so plainly.
		fmt.Println("Checked 0 record(s). The log is empty; note that an empty or fully " +
			"truncated log cannot be distinguished from a never-written one without an " +
			"external high-water mark (ship records to an append-only sink).")
		return 0
	}

	printVerifySummary(res)
	if !res.OK() {
		return 1
	}
	return 0
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
