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

// loadConfigAuditDefaults loads configPath and fills empty audit-log / audit-key-path
// flags from its audit block, leaving any explicitly-set flag untouched. keyPath may be
// nil (stats has no --audit-key-path), which skips the key default. cmdName labels the
// load error. A no-op returning (nil, nil) when configPath is empty.
//
// The load error is RETURNED with the parsed config rather than printed, so a caller can
// choose its own stance: every audit-log reader treats an unloadable config as fatal
// (applyConfigAuditDefaults), while doctor carries the failure into the support bundle —
// a config that will not parse is exactly the deployment a bundle exists to describe.
// Returning the config as well lets that caller reuse this parse instead of loading the
// same file a second time.
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

// applyConfigAuditDefaults is loadConfigAuditDefaults for the readers that have nothing
// useful to do with an unloadable config — audit-verify, stats, suggest — so the error is
// theirs to report and abort on. doctor deliberately does NOT use this.
func applyConfigAuditDefaults(cmdName, configPath string, logPath, keyPath *string) error {
	_, err := loadConfigAuditDefaults(cmdName, configPath, logPath, keyPath)
	return err
}

// parseAuditReaderFlags runs the preamble every subcommand that reads the audit tape
// (suggest, stats, audit-verify, doctor) performs identically: parse the flag set,
// map -h/--help to a clean exit, reject a stray positional, and let a --config fill any
// audit path the operator left empty.
//
// done reports that the caller must return code immediately: 0 for -h, 1 for a usage or
// config error (already reported on stderr). When done is false, code is 0 and parsing
// succeeded. keyPath may be nil for a reader that has no --audit-key-path.
//
// Every flag argument is a POINTER, configPath included: they are read after fs.Parse
// runs here, so a by-value configPath would capture the pre-parse empty string and
// silently skip the config defaulting entirely.
//
// The stray-positional rejection is the load-bearing half: the log is chosen with
// --audit-log/--config, never positionally, so `eunox stats audit.jsonl` must not
// silently report on the DEFAULT log while naming another file on the command line.
func parseAuditReaderFlags(name string, fs *flag.FlagSet, configPath, logPath, keyPath *string) (code int, done bool) {
	if err := fs.Parse(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return 1, true
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "eunox %s: unexpected argument %q (use --audit-log to name the log file)\n", name, fs.Arg(0))
		return 1, true
	}
	if err := applyConfigAuditDefaults(name, *configPath, logPath, keyPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	return 0, false
}

// resolveAuditReaderLogPath expands the reader's --audit-log to a concrete path,
// reporting a resolution failure under the subcommand's own name. ok is false when the
// caller must return 1. Kept separate from parseAuditReaderFlags because doctor
// deliberately does NOT resolve here: it reports an unresolvable path inside the support
// bundle rather than refusing to print one.
func resolveAuditReaderLogPath(name, configured string) (string, bool) {
	logPath, err := audit.ResolveLogPath(configured)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox %s: %v\n", name, err)
		return "", false
	}
	return logPath, true
}

// cmdAuditVerify runs the `audit-verify` subcommand and returns the process
// exit code (rather than calling os.Exit itself), so tests can drive every branch.
func cmdAuditVerify() int {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: eunox audit-verify [flags]

Verify HMAC-SHA256 signatures in the local audit log.

Flags:
`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the configured audit.log and\naudit.keyPath are used as defaults for --audit-log and --audit-key-path.")
	auditLogPath := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")
	auditKeyPath := fs.String("audit-key-path", "", "Path to the HMAC signing key for the audit log (default: ~/.eunox/audit.key).\nOverrides EUNOX_AUDIT_KEY_PATH environment variable.")
	requestID := fs.String("request-id", "", "Report (count and print) only the record with this request ID. Every record\nis still HMAC-verified and the tamper-evident chain is always checked; this\nfilter narrows the report, not the verification.")
	since := fs.String("since", "", "Report (count and print) only records after this RFC3339 timestamp. Every\nrecord is still HMAC-verified and the tamper-evident chain is always checked;\nthis filter narrows the report, not the verification.")

	if code, done := parseAuditReaderFlags("audit-verify", fs, configPath, auditLogPath, auditKeyPath); done {
		return code
	}
	logPath, ok := resolveAuditReaderLogPath("audit-verify", *auditLogPath)
	if !ok {
		return 1
	}

	// Key path resolves: flag (already merged with config) > env var > default.
	expandedKeyPath, err := audit.ResolveKeyPath(*auditKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: %v\n", err)
		return 1
	}
	// Load-only: audit-verify must never mint a key as a side effect. A missing key
	// file is an operator error (mistyped --audit-key-path, wrong machine) — creating a
	// fresh key here would make every record report UNKNOWN_KEY and misdiagnose that as a
	// key rotation. LoadKeys returns a clear not-found error instead.
	keys, err := audit.LoadKeys(expandedKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: loading audit key: %v\n", err)
		return 1
	}

	// Verifier keyring holds every key indexed by key id, so records straddling a
	// rotation each verify against the key that signed them; records with no key_id
	// (pre-rotation format) are tried against every key.
	verifier := audit.NewVerifier(keys)

	// Verify the whole rotated set as one chain (oldest sibling -> current base),
	// not just the base file. The tamper-evident chain spans rotation, so checking
	// a single file would miss deletion of an entire interior rotated file —
	// threading every sibling catches it (prev_hmac mismatch + seq gap).
	chainFiles, err := audit.LogChainFiles(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: discovering rotated audit logs: %v\n", err)
		return 1
	}
	if len(chainFiles) == 0 {
		// No base log and no rotated siblings: same first-run hint as the readers.
		fmt.Fprint(os.Stderr, auditLogMissingHint("audit-verify", logPath))
		return 1
	}

	var sinceTime time.Time
	if *since != "" {
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox audit-verify: invalid --since value %q: %v\n", *since, err)
			return 1
		}
	}

	if len(chainFiles) > 1 {
		fmt.Printf("Verifying %d audit log files as one chain (oldest rotated to current base).\n", len(chainFiles))
	}
	res, err := audit.VerifyLogFiles(chainFiles, verifier, *requestID, sinceTime, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox audit-verify: reading log: %v\n", err)
		return 1
	}

	if res.Total == 0 {
		// An empty log is not itself a failure, but it is indistinguishable from a
		// fully truncated one without an external anchor — say so plainly.
		fmt.Println("Checked 0 record(s). The log is empty; note that an empty or fully " +
			"truncated log cannot be distinguished from a never-written one without an " +
			"external high-water mark (ship records to an append-only sink).")
		return 0
	}

	fmt.Printf("Checked %d record(s): %d valid, %d invalid, %d skipped, %d legacy, %d unknown-key, %d unverifiable; %d chain break(s).\n",
		res.Total, res.Valid, res.Invalid, res.Skipped, res.Legacy, res.UnknownKey, res.Unverifiable, res.ChainBreaks)
	// UNKNOWN_KEY_ID is a missing-key state, not tampering — kept distinct from the
	// INVALID tally so a key rotation is not mistaken for corruption. The verdict
	// still fails (OK() counts it): the records can't be verified without the key.
	if res.UnknownKey > 0 {
		fmt.Printf("Note: %d record(s) were signed with a key absent from the verification ring (UNKNOWN_KEY_ID) — "+
			"expected after a key rotation that retired the signing key. Add the retired key(s) to the ring "+
			"(--audit-key-path / the configured keyPath) to verify them; they are NOT counted as tampered.\n", res.UnknownKey)
	}
	// UNVERIFIABLE is a record that names NO key_id which no held key matched: the
	// signing key cannot be identified, so it cannot be proven tampered the way a
	// named-but-missing key_id can. Surfaced distinctly from INVALID, but the verdict
	// still fails (OK() counts it) — fail-closed, since the cause may be tampering.
	if res.Unverifiable > 0 {
		fmt.Printf("Note: %d record(s) name no key_id and no key in the ring matched them (UNVERIFIABLE) — "+
			"typically a pre-key_id-era record whose signing key was retired. Add the original key(s) to the ring "+
			"to verify them; until then they cannot be distinguished from tampering and the verdict fails.\n", res.Unverifiable)
	}
	// Chain verification always runs, so the only note worth surfacing is a non-1
	// starting seq. Walked as one chain, seq > 1 means the oldest record across all
	// retained files is not seq 1 — leading records or whole leading rotated files
	// were removed or pruned. That deletion (and trailing truncation) is the one
	// case unprovable from local files without an external high-water mark.
	if res.FirstSeq > 1 {
		fmt.Printf("Note: the oldest record across the retained log files is seq %d, not 1 — "+
			"leading records (or whole leading rotated files) were removed or pruned by "+
			"retention (indistinguishable without an external anchor).\n", res.FirstSeq)
	}
	if !res.OK() {
		return 1
	}
	return 0
}
