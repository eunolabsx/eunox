// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// doctor: a user-initiated support bundle. Nothing is uploaded — the operator pastes it into
// a bug report. Redaction is allowlist-based (fixed secret-bearing field names + URL
// userinfo/query scrubbing) rather than heuristic, since heuristic secret detection silently
// corrupts diagnostics; the footer reminds the operator to skim before sharing.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/capability"
)

const (
	defaultDoctorAuditTail = 50
	doctorSep              = "────────────────────────────────────────────────────────────"
)

// errTrackingWriter records the first write error, so a short write to --output FILE (e.g.
// ENOSPC mid-bundle) is reported instead of silently producing a partial bundle that
// "Wrote support bundle" (exit 0) would otherwise vouch for.
type errTrackingWriter struct {
	w   io.Writer
	err error
}

func (e *errTrackingWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// redactedConfigFields names the YAML keys fully replaced with a length-only placeholder.
// Keep in sync with config.GatewayConfig — every sensitive field must land in this map or
// urlConfigFields. Declared in the canonical spelling and matched case-INSENSITIVELY; see
// redactedValueFor for why.
var redactedConfigFields = map[string]bool{
	"authToken":          true, // listen.authToken
	"upstreamAuthHeader": true, // upstreams[].upstreamAuthHeader
}

// urlConfigFields names the URL/URI keys scrubbed via config.RedactURL (userinfo/query/
// fragment stripped, host/path kept) instead of the full placeholder. upstreamUrl alone uses
// the stricter RedactURLForLog (drops the path too): its path routinely IS the credential
// (Slack/Telegram webhook secrets), while the rest are published, path-bearing identifiers
// where the path is load-bearing for diagnosis.
var urlConfigFields = map[string]func(string) string{
	"upstreamUrl":               capability.RedactURLForLog, // upstreams[].upstreamUrl; path can BE the credential
	"oauthResource":             config.RedactURL,           // listen.oauthResource (scalar, RFC 9728 resource URI)
	"oauthAuthorizationServers": config.RedactURL,           // listen.oauthAuthorizationServers (sequence of IdP URLs)
	"allowedOrigins":            config.RedactURL,           // listen.allowedOrigins (sequence)
}

// The case-folded indexes the lookup actually reads. Derived from the declarations above so
// the canonical spelling stays the documented one and the two cannot drift;
// TestDoctorRedaction_FoldedIndexesAreComplete fails a pair of declared keys that fold
// together, which would silently drop one.
var (
	redactedConfigFieldsFolded = foldConfigKeys(redactedConfigFields)
	urlConfigFieldsFolded      = foldConfigKeys(urlConfigFields)
)

// foldConfigKeys re-keys a redaction table by foldConfigKey.
func foldConfigKeys[V any](m map[string]V) map[string]V {
	folded := make(map[string]V, len(m))
	for k, v := range m {
		folded[foldConfigKey(k)] = v
	}
	return folded
}

// foldConfigKey is the ONE normalization a raw on-disk key goes through before it is matched
// against the redaction tables.
func foldConfigKey(k string) string { return strings.ToLower(k) }

// redactedValueFor returns the scrubbed replacement for a config value under key, and
// whether key names a sensitive field at all.
//
// The match is case-INSENSITIVE, which is not a heuristic: it is the same two key names,
// spelled the way an operator actually typed them. writeDoctorConfig raw-parses the file
// precisely so a config the typed loader REFUSED still renders — and since that loader
// rejects unknown keys case-sensitively, the configs only doctor handles are the misspelled
// ones. `AuthToken:` was therefore the one spelling guaranteed to reach a bundle destined
// for a public bug report, and the one spelling the allowlist missed.
//
// One resolver rather than a lookup pair in each of redactConfigValue's two map arms, so the
// string-keyed and interface-keyed walks cannot disagree about which keys are sensitive.
func redactedValueFor(key string, val interface{}) (interface{}, bool) {
	folded := foldConfigKey(key)
	if redactedConfigFieldsFolded[folded] {
		return redactString(val), true
	}
	if scrub := urlConfigFieldsFolded[folded]; scrub != nil {
		return redactURLValue(val, scrub), true
	}
	return nil, false
}

// redactURLValue scrubs a URL-bearing config value of any shape (scalar, sequence, or nested
// map) rather than the declared schema shape — the doctor bundle raw-parses on-disk YAML, so
// a field can arrive in a shape the typed loader would reject, and scrubbing by value shape
// avoids leaking a scalar written under an array-typed key.
func redactURLValue(val interface{}, redact func(string) string) interface{} {
	switch v := val.(type) {
	case string:
		return redact(v)
	case []interface{}:
		for i, it := range v {
			v[i] = redactURLValue(it, redact)
		}
		return v
	default:
		// A map or other nested shape: recurse so a credential under a known key is still
		// scrubbed; a scalar number/bool has nothing to scrub.
		redactConfigValue(val)
		return val
	}
}

// doctorOptions bundles the parsed CLI flags for cmdDoctor so the bundle
// writer can be unit-tested without going through flag parsing.
type doctorOptions struct {
	configPath   string
	auditLogPath string
	auditKeyPath string
	auditTail    int
	live         bool
	// cfg/cfgErr are the ONE ${ENV}-expanded load of configPath, shared by the audit-path
	// defaults and the manifest/live-drift sections. Both zero when configPath is empty;
	// exactly one set otherwise.
	cfg    *config.GatewayConfig
	cfgErr error
}

// parseDoctorReaderFlags is parseAuditReaderFlags for doctor, but an unloadable --config is
// RETURNED (nil cfg) instead of aborting — a config that won't parse is the case the bundle
// is most needed for, so it's reported inline and every other section still renders.
func parseDoctorReaderFlags(fs *flag.FlagSet, args []string, configPath, logPath, keyPath *string) (cfg *config.GatewayConfig, code int, done bool, cfgErr error) {
	if code, done := parseReaderArgs("doctor", fs, args); done {
		return nil, code, done, nil
	}
	cfg, cfgErr = loadConfigAuditDefaults("doctor", *configPath, logPath, keyPath)
	return cfg, 0, false, cfgErr
}

// doctorUsageExit is doctor's exit code for a usage error or a failure to write the bundle,
// matching every sibling reader (stats/suggest/audit-verify all use 2). Exit 1 is reserved
// for doctor's one FINDING — a config that would not load — so `doctor --config X && restart`
// stays a usable pre-flight gate rather than conflating a broken config with a typo'd flag
// and an unwritable --output under one code. parseReaderArgs reports usage errors as 1, so
// this command translates at the call site, as audit-verify does.
const doctorUsageExit = 2

// doctorUsage is the `doctor` subcommand's help text, a constant so the command body does not
// carry a screen of prose inline.
const doctorUsage = `Usage:
  eunox doctor [flags]

Print a user-initiated support bundle: binary identity, redacted transport
config, manifest digests + validation summary, the tail of the audit log
(values scrubbed), and — with --live — drift against each declared upstream.

Nothing leaves your machine. The bundle prints to stdout (or --output FILE)
so you control what gets pasted into a bug report. Secrets in named fields
(authToken, upstreamAuthHeader) are redacted; URL userinfo, query
values, and fragments are scrubbed in the URL/URI fields (upstreamUrl,
oauthResource, oauthAuthorizationServers, allowedOrigins). Field names are
matched case-insensitively, since a config this command renders may be one
the loader refused for misspelling them.
Command-line args, paths, and audit metadata are shown verbatim — skim
before sharing.

Flags:
`

// cmdDoctor runs the `doctor` subcommand, returning the exit code (rather than calling
// os.Exit) so tests can drive every branch in-process.
func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	setUsage(fs, args, doctorUsage)

	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the bundle includes the\nredacted config, manifest validation per route, and (with --live) drift.")
	auditLog := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")
	auditKey := fs.String("audit-key-path", "", "Path to the HMAC signing key (default: ~/.eunox/audit.key). Only used\nto report whether the key is loadable; signatures are not re-verified here.")
	auditTail := fs.Int("audit-tail", defaultDoctorAuditTail, "Number of trailing audit records to include (values redacted). 0 ⟹ skip.")
	live := fs.Bool("live", false, "Connect to each declared upstream and include the drift report.\nRequires --config; passed without one, the invocation is rejected rather\nthan producing a bundle with the section skipped.")
	output := fs.String("output", "", "Write the bundle to this file instead of stdout. The conventional name\nis eunox-doctor-<timestamp>.txt; --output auto picks one automatically.")

	// doctor deliberately stops here rather than resolving --audit-log: an unresolvable
	// path is reported INSIDE the bundle, since printing what it can beats refusing to print.
	cfg, code, done, cfgErr := parseDoctorReaderFlags(fs, args, configPath, auditLog, auditKey)
	if done {
		if code == 1 {
			return doctorUsageExit
		}
		return code
	}
	// --live introspects the upstreams a config declares, and there are none without one.
	// Rejected rather than left inert, per the binary-wide rule stated at cmdContracts'
	// unpaired-flag guard: this exited 0 with a skip note buried in section 5, so an
	// operator who believed they had named a --config got a bundle with no drift report and
	// nothing saying the invocation was incoherent. Knowable at parse time, so refused here
	// rather than after the audit tail is read.
	if *live && *configPath == "" {
		fmt.Fprintln(os.Stderr, "eunox doctor: --live requires --config (there are no declared upstreams to introspect without one)")
		return doctorUsageExit
	}
	// An unloadable config is NOT fatal here: it's carried into the bundle and every other
	// section still renders. Exit status stays non-zero though, so `doctor --config X &&
	// restart` remains a usable pre-flight gate instead of silently passing a broken config.
	exitCode := 0
	if cfgErr != nil {
		fmt.Fprintln(os.Stderr, cfgErr)
		fmt.Fprintln(os.Stderr, "The bundle is still written; the config-dependent sections report this error in place.")
		exitCode = 1
	}

	opts := doctorOptions{
		configPath:   *configPath,
		auditLogPath: *auditLog,
		auditKeyPath: *auditKey,
		auditTail:    *auditTail,
		live:         *live,
		cfg:          cfg,
		cfgErr:       cfgErr,
	}

	// Stdout: discard write errors (a broken pipe is not actionable).
	if *output == "" {
		writeDoctorBundle(os.Stdout, opts)
		return exitCode
	}

	outPath := *output
	if outPath == "auto" {
		outPath = fmt.Sprintf("eunox-doctor-%s.txt", time.Now().UTC().Format("20060102T150405Z"))
	}
	// The bundle always truncates (no --force gate here), so the symlink refusal is
	// unconditional — otherwise a planted link's TARGET would be truncated and re-moded.
	if err := refuseNonRegularOutput(outPath); err != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: %v\n", err)
		return doctorUsageExit
	}
	// config.OpenNoFollow closes the Lstat->open race the refusal above cannot for a symlink;
	// config.OpenNonBlock closes it for a FIFO, whose write-only open would otherwise block
	// inside open(2) until a reader arrives, leaving no post-open check reachable at all.
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|config.OpenNoFollow|config.OpenNonBlock, 0o600) //nolint:gosec // G304: --output is an operator-supplied destination
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: opening %q: %v\n", outPath, err)
		return doctorUsageExit
	}
	// Asked through the HANDLE, ahead of the re-tighten, so a substituted object is refused
	// rather than re-moded and written with a support bundle.
	if err := config.RefuseNonRegularHandle(f, "output file", outPath); err != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: %v\n", err)
		_ = f.Close()
		return doctorUsageExit
	}
	// Re-tighten on the open fd: O_CREATE applies 0600 only on creation, so a pre-existing
	// looser-mode file would otherwise keep that mode.
	if err := f.Chmod(0o600); err != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: tightening mode of %q: %v\n", outPath, err)
		_ = f.Close()
		return doctorUsageExit
	}
	// Track write errors AND the close (which flushes) so a truncated bundle is reported
	// rather than announced as complete.
	tw := &errTrackingWriter{w: f}
	writeDoctorBundle(tw, opts)
	closeErr := f.Close()
	if writeErr := tw.err; writeErr != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: writing %q: %v\n", outPath, writeErr)
		return doctorUsageExit
	}
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: writing %q: %v\n", outPath, closeErr)
		return doctorUsageExit
	}
	fmt.Fprintf(os.Stderr, "Wrote support bundle to %s\n", outPath)
	fmt.Fprintln(os.Stderr, "Review for any remaining sensitive values before sharing.")
	// Non-zero when the config could not be loaded (see above): the bundle was still
	// written, but the config is broken and a caller gating on this must hear about it.
	return exitCode
}

// writeDoctorBundle emits the support bundle to w. Sections are independent — a failure in
// one is reported in place and the remaining sections still render.
func writeDoctorBundle(w io.Writer, opts doctorOptions) {
	wln(w, "eunox doctor — support bundle")
	wf(w, "Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	wln(w)

	// Parsed ONCE by parseDoctorReaderFlags and shared by sections 3 and 5. Section 2
	// deliberately keeps its own RAW (no env expansion) read to show the config as written.
	cfg, cfgErr := opts.cfg, opts.cfgErr

	wln(w, doctorSep)
	wln(w, "1. Binary")
	wln(w, doctorSep)
	writeDoctorBinary(w)

	wln(w)
	wln(w, doctorSep)
	wln(w, "2. Config (redacted)")
	wln(w, doctorSep)
	if opts.configPath == "" {
		wln(w, "(no --config provided)")
	} else {
		writeDoctorConfig(w, opts.configPath)
	}

	wln(w)
	wln(w, doctorSep)
	wln(w, "3. Manifests")
	wln(w, doctorSep)
	if opts.configPath == "" {
		wln(w, "(no --config provided; nothing to validate)")
	} else {
		writeDoctorManifests(w, cfg, cfgErr)
	}

	wln(w)
	wln(w, doctorSep)
	wln(w, "4. Audit log")
	wln(w, doctorSep)
	writeDoctorAudit(w, opts.auditLogPath, opts.auditKeyPath, opts.auditTail)

	wln(w)
	wln(w, doctorSep)
	wln(w, "5. Live upstream check")
	wln(w, doctorSep)
	// No config-less --live arm: cmdDoctor rejects that invocation at parse time rather
	// than rendering a skip note for it.
	if opts.live {
		writeDoctorLive(w, cfg, cfgErr)
	} else {
		wln(w, "(skipped — pass --live to introspect each declared upstream)")
	}

	wln(w)
	wln(w, doctorSep)
	wln(w, "End of bundle. Nothing has been sent — review and paste manually.")
}

// writeDoctorBinary stamps binary identity: version, Go runtime, OS/arch, and (when
// embedded) the VCS commit SHA and dirty flag.
func writeDoctorBinary(w io.Writer) {
	wf(w, "  version:    %s\n", version)
	wf(w, "  go:         %s\n", runtime.Version())
	wf(w, "  os/arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)

	info, ok := debug.ReadBuildInfo()
	if !ok {
		wf(w, "  vcs:        (build info unavailable)\n")
		return
	}
	var rev, modified, vcsTime string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		case "vcs.time":
			vcsTime = s.Value
		}
	}
	switch rev {
	case "":
		wf(w, "  vcs:        (not embedded — `go install` or `go build .` in a git tree to capture)\n")
	default:
		wf(w, "  vcs:        %s (modified=%s, time=%s)\n", rev, modified, vcsTime)
	}
}

// writeDoctorConfig parses the raw config file (no env expansion, to surface the as-on-disk
// shape), redacts known-sensitive fields, and re-emits it as YAML.
func writeDoctorConfig(w io.Writer, path string) {
	wf(w, "  path: %s\n\n", path)

	// Bounded like the typed loader's read: doctor deliberately keeps going when
	// LoadGatewayConfig fails, so without its own cap this re-read would buffer whole the
	// misdirected multi-GB path the loader just refused — an OOM in the one command meant
	// to survive a broken config.
	raw, err := config.ReadBoundedFile(config.BoundedRead{
		Path:      path,
		What:      "gateway config",
		Max:       config.MaxGatewayConfigFileBytes,
		OverLimit: "refusing to buffer it into the doctor bundle",
	})
	if err != nil {
		wf(w, "  could not read: %v\n", err)
		return
	}
	var root interface{}
	if err := yaml.Unmarshal(raw, &root); err != nil {
		wf(w, "  could not parse YAML: %v\n", err)
		return
	}
	redactConfigValue(root)
	out, err := yaml.Marshal(root)
	if err != nil {
		wf(w, "  could not re-emit YAML: %v\n", err)
		return
	}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		wf(w, "  %s\n", line)
	}
}

// redactConfigValue walks a yaml.Unmarshal-shaped value in place, recursing into maps and
// slices, applying redactedValueFor at each key.
func redactConfigValue(v interface{}) {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, val := range x {
			if red, ok := redactedValueFor(k, val); ok {
				x[k] = red
				continue
			}
			redactConfigValue(val)
		}
	case map[interface{}]interface{}:
		// yaml.v3 decodes a mapping this way (not map[string]interface{}) whenever ANY key
		// is non-string. Without this case such a map falls through the no-op default and a
		// sibling authToken would be emitted verbatim into the bundle.
		for k, val := range x {
			if red, ok := redactedValueFor(fmt.Sprintf("%v", k), val); ok {
				x[k] = red
				continue
			}
			redactConfigValue(val)
		}
	case []interface{}:
		for _, it := range x {
			redactConfigValue(it)
		}
	}
}

// redactString renders a present secret as "<redacted len=N>" and an empty value as "", so
// an omitted secret reads differently from a present-but-redacted one.
func redactString(v interface{}) string {
	s, ok := v.(string)
	if !ok {
		return "<redacted non-string>"
	}
	if s == "" {
		return ""
	}
	return fmt.Sprintf("<redacted len=%d>", len(s))
}

// reportCfgErr writes the standard "could not load config" line and reports whether it did,
// so writeDoctorManifests/writeDoctorLive share one guard clause; the caller must return
// immediately when this reports true. A nil cfg with nil cfgErr means a hand-built
// doctorOptions skipped the load — reported as unusable rather than crashing on a nil deref.
func reportCfgErr(w io.Writer, cfg *config.GatewayConfig, cfgErr error) bool {
	switch {
	case cfgErr != nil:
		wf(w, "  could not load config: %v\n", cfgErr)
	case cfg == nil:
		wf(w, "  could not load config: no config was loaded\n")
	default:
		return false
	}
	return true
}

// writeDoctorManifests walks each declared upstream, loads its policy files, and prints the
// merged manifest digest. cfg is ${ENV}-expanded, so emit only non-sensitive derived fields
// (Name, Transport, digest) — never UpstreamURL, UpstreamAuthHeader, or other secrets.
func writeDoctorManifests(w io.Writer, cfg *config.GatewayConfig, cfgErr error) {
	if reportCfgErr(w, cfg, cfgErr) {
		return
	}
	wf(w, "  host transport: %s\n", cfg.HostTransport())
	wf(w, "  upstreams:      %d\n", len(cfg.Upstreams))

	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		wln(w)
		wf(w, "  ── route %q (transport: %s) ──\n", u.Name, u.Transport)

		// Shared walk (load -> merge -> startupFatalManifestCheck) reproduces the proxy's
		// actual startup decision, so the bundle can't report OK for a route it would refuse
		// to boot.
		outcome := transport.WalkRouteManifests(cfg, u)

		if outcome.NoPolicy {
			switch {
			case outcome.NoPolicyReason != "":
				wf(w, "    (WOULD FAIL CLOSED at startup: %s)\n", outcome.NoPolicyReason)
			case outcome.AuditMode:
				wln(w, "    (no policy configured — observe-only/wiretap route)")
			default:
				wln(w, "    (no policy configured — allow-all route)")
			}
			continue
		}
		writePolicyLoadResults(w, "    ", outcome.LoadResults)
		if outcome.LoadFailed {
			continue
		}
		if outcome.MergeErr != nil {
			wf(w, "    merged manifest:         <invalid: %v>\n", outcome.MergeErr)
			continue
		}
		merged := outcome.Merged
		if digest, err := merged.Digest(); err != nil {
			wf(w, "    merged digest:           <error: %v>\n", err)
		} else {
			wf(w, "    merged digest:           %s\n", digest)
		}
		if merged.ServerVersion != "" {
			wf(w, "    pinned serverVersion:    %s\n", merged.ServerVersion)
		}
		if n := merged.AuditOnlyCount(); n > 0 {
			wf(w, "    audit-only capabilities: %d (observed but not enforced)\n", n)
		}
		// "Everything escalates" and "half the policy is unannotated under a ceiling" are
		// the same fact; counts only, since this bundle is pasted into public bug reports.
		writeEffectCoverage(w, "    ", merged, false)
		if outcome.StartupErr != nil {
			wf(w, "    WOULD FAIL CLOSED at startup: %v\n", outcome.StartupErr)
		}
	}
}

// doctorLoadAuditKeys reads the audit key file for the bundle's loadability line, kept
// separate so the caller can distinguish "path never resolved" from "path resolved but
// unloadable" rather than naming the wrong problem.
func doctorLoadAuditKeys(resolvedKey string, resolveErr error) ([][]byte, error) {
	if resolveErr != nil {
		return nil, nil
	}
	return audit.LoadKeys(resolvedKey)
}

// writeDoctorAudit prints aggregated counts from the audit log, then the last `tail`
// records with `details` scrubbed and the HMAC stripped — re-verifiable via
// `eunox audit-verify` after sharing.
func writeDoctorAudit(w io.Writer, logPath, keyPath string, tail int) {
	resolvedLog, logErr := audit.ResolveLogPath(logPath)
	if logErr != nil {
		wf(w, "  log path:  (cannot resolve: %v)\n", logErr)
	} else {
		wf(w, "  log path:  %s\n", resolvedLog)
	}

	resolvedKey, keyErr := audit.ResolveKeyPath(keyPath)
	switch keys, loadErr := doctorLoadAuditKeys(resolvedKey, keyErr); {
	case keyErr != nil:
		wf(w, "  key path:  (cannot resolve: %v)\n", keyErr)
	case loadErr != nil:
		// LOADABILITY, not mere existence — a key file that exists but is unreadable,
		// truncated, or not hex used to report "(present)" in exactly the deployment
		// chasing UNKNOWN_KEY_ID. LoadKeys is read-only and mints nothing.
		wf(w, "  key path:  %s (NOT loadable: %v)\n", resolvedKey, loadErr)
	default:
		wf(w, "  key path:  %s (present, %d key(s) loadable)\n", resolvedKey, len(keys))
	}

	// Skip the stat when the path never resolved: resolvedLog is "" and os.Stat("") would
	// print a confusing second error atop the "cannot resolve" line.
	if logErr != nil {
		return
	}
	// Cover the FULL rotated set, not just the active base file — otherwise totals and tail
	// silently omit every rotated segment once the log has rotated at least once.
	//
	// Snapshot rather than a bare listing, for the reason the reporting readers take one:
	// the chain files are opened LAZILY by name (twice here — the totals pass and the tail
	// pass), so a rotation landing in between reads a fresh, nearly-empty base in place of
	// the sibling holding the newest records, and can leave the two passes describing
	// different chains. doctor is a diagnostic bundle rather than a command whose output is
	// acted on directly, so it CAVEATS rather than exiting — every other failure here is a
	// printed line too — but it must not present a raced total as a fact, least of all in
	// the artifact attached to a ticket that says the tape looks empty.
	snap, err := audit.SnapshotLogChain(resolvedLog)
	if err != nil {
		wf(w, "  log file:  %v\n", err)
		return
	}
	chainFiles := snap.Files
	if len(chainFiles) == 0 {
		wf(w, "  log file:  %v\n", os.ErrNotExist)
		return
	}
	// Deferred so it covers every exit below, including the two that return early: a caveat
	// printed on only some paths is the silence it exists to replace.
	defer func() {
		if cerr := snap.CheckUnchanged(); cerr != nil {
			wf(w, "  NOTE:      %v — the counts and tail above cover an unknown part of the chain; re-run\n", cerr)
		}
	}()
	var totalSize int64
	for _, p := range chainFiles {
		if fi, e := os.Stat(p); e == nil { //nolint:gosec // G304: operator-configured audit log path
			totalSize += fi.Size()
		}
	}
	if info, e := os.Stat(resolvedLog); e == nil { //nolint:gosec // G304: operator-configured audit log path
		wf(w, "  log size:  %d bytes across %d file(s) (active modified %s)\n",
			totalSize, len(chainFiles), info.ModTime().UTC().Format(time.RFC3339))
	} else {
		wf(w, "  log size:  %d bytes across %d file(s)\n", totalSize, len(chainFiles))
	}

	statsReader := audit.OpenLogChain(chainFiles)
	summary, statsErr := computeAuditStats(statsReader)
	_ = statsReader.Close()
	if statsErr != nil {
		wf(w, "  could not aggregate: %v\n", statsErr)
	} else {
		wf(w, "  totals:    records=%d allowed=%d blocked=%d observed=%d",
			summary.total, summary.allowed, summary.blocked, summary.observed)
		// escalated is a SUBSET of blocked (additional detail, not a missing addend), but
		// `eunox stats` reports it too — dropping it here would make the two views disagree.
		if summary.escalated > 0 {
			wf(w, " escalated=%d", summary.escalated)
		}
		if summary.other > 0 {
			wf(w, " other=%d", summary.other)
		}
		wln(w)
	}

	if tail <= 0 {
		wln(w)
		// A negative tail is a different mistake from an explicit 0; echo what was passed.
		if tail < 0 {
			wf(w, "  (--audit-tail=%d is negative — record tail skipped; pass a positive count, or 0 to skip deliberately)\n", tail)
		} else {
			wln(w, "  (--audit-tail=0 — record tail skipped)")
		}
		return
	}

	// The chain reader is not seekable, so reopen the chain for the tail pass.
	tailReader := audit.OpenLogChain(chainFiles)
	defer func() { _ = tailReader.Close() }()
	lines, err := tailAuditLines(tailReader, tail)
	if err != nil {
		wf(w, "  could not read tail: %v\n", err)
		return
	}
	wln(w)
	wf(w, "  Last %d record(s) (details values redacted, HMAC stripped):\n", len(lines))
	for _, line := range lines {
		wf(w, "    %s\n", redactAuditLine(line))
	}
}

// tailAuditLines returns the last n non-blank lines from r in original order, using a
// fixed-size circular buffer so an enormous log doesn't blow up memory (O(1) per record).
func tailAuditLines(r io.Reader, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	sc := audit.NewLineScanner(r)
	// Cap the up-front allocation: --audit-tail has no upper bound, and make([]string, 0, n)
	// would reserve ~32GB for a one-line log at n=2e9. The ring still grows to n via append.
	const maxTailPrealloc = 8192
	ring := make([]string, 0, min(n, maxTailPrealloc))
	next := 0        // write position once the ring is full
	wrapped := false // whether the ring has overwritten at least one slot
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if len(ring) < n {
			ring = append(ring, line)
			continue
		}
		// True circular-buffer write — O(1) per record; the prior copy(ring, ring[1:])
		// approach was O(n) per line, making --audit-tail O(records * n).
		ring[next] = line
		next = (next + 1) % n
		wrapped = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !wrapped {
		return ring, nil
	}
	// Wrapped: the oldest retained line sits at next. Rotate once into chronological order.
	ordered := make([]string, 0, n)
	ordered = append(ordered, ring[next:]...)
	ordered = append(ordered, ring[:next]...)
	return ordered, nil
}

// redactAuditLine returns line with the HMAC stripped and every `details` value replaced
// with "<redacted>" (keys preserved). Unparseable lines are flagged but kept.
func redactAuditLine(line string) string {
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return fmt.Sprintf(`{"_doctor_note":"unparseable record","raw_len":%d}`, len(line))
	}
	delete(rec, "_hmac")
	if raw, present := rec["details"]; present {
		if d, ok := raw.(map[string]interface{}); ok {
			for k := range d {
				d[k] = "<redacted>"
			}
		} else {
			// A non-object details value can't be scrubbed field-by-field and can only come
			// from a tampered or foreign record (eunox's own writer always emits an object) —
			// redact the whole value rather than pass a potential secret through.
			rec["details"] = "<redacted>"
		}
	}
	// A resource target holds a raw URI, which can embed credentials (userinfo/query).
	// Gate on target_type == "resource": tool/prompt/system targets are bare names, and one
	// containing '?'/'#'/'@' would otherwise be mis-parsed and rewritten by RedactURL.
	if t, ok := rec["target"].(string); ok && t != "" && rec["target_type"] == "resource" {
		rec["target"] = config.RedactURL(t)
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return fmt.Sprintf(`{"_doctor_note":"re-marshal failed","error":%q}`, err.Error())
	}
	return strings.TrimRight(buf.String(), "\n")
}

// writeDoctorLive reuses validateConfigRoutes so the bundle reports drift by the same rules
// as `eunox validate --config --live`.
func writeDoctorLive(w io.Writer, cfg *config.GatewayConfig, cfgErr error) {
	if reportCfgErr(w, cfg, cfgErr) {
		return
	}
	// No deadline here: fetchRouteLive applies its own per-route liveUpstreamTimeout, so a
	// shared parent deadline would starve later routes once an earlier one runs slow.
	iw := &indentWriter{w: w, prefix: []byte("  "), atLineStart: true}
	code := validateConfigRoutes(context.Background(), cfg, true, iw)
	wf(w, "\n  validate exit code: %d  (0=clean, 1=drift, 2=parse/connection error)\n", code)
}

// indentWriter prefixes each line with `prefix` so reused section writers line up under the
// doctor section header. atLineStart tracks state across Write calls for a split line.
type indentWriter struct {
	w           io.Writer
	prefix      []byte
	atLineStart bool
}

func (iw *indentWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if iw.atLineStart {
			if _, err := iw.w.Write(iw.prefix); err != nil {
				return written, err
			}
		}
		nl := bytes.IndexByte(p, '\n')
		if nl < 0 {
			n, err := iw.w.Write(p)
			iw.atLineStart = false
			return written + n, err
		}
		n, err := iw.w.Write(p[:nl+1])
		written += n
		// Mark line-start only once the newline actually reached the writer; a short write
		// leaves the stream mid-line.
		if n == nl+1 {
			iw.atLineStart = true
		}
		if err != nil {
			return written, err
		}
		p = p[nl+1:]
	}
	return written, nil
}
