// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// doctor: a user-initiated support bundle. Nothing is uploaded — the operator
// pastes it into a bug report. It gathers binary identity, redacted transport
// config, manifest digests + validation summary, the scrubbed tail of the audit
// log, and (with --live) drift against each declared upstream.
//
// Redaction is allowlist-based: a fixed set of secret-bearing field names is
// replaced with a length-only placeholder, and URL userinfo + query values are
// scrubbed; everything else is verbatim. The rule is deliberately narrow —
// heuristic secret detection silently corrupts diagnostics — and the footer
// reminds the operator to skim before sharing.

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

// wf and wln are package-level write helpers for the doctor bundle; per-call
// write errors are discarded here (not actionable for stdout). When the bundle
// goes to --output FILE, w is an *errTrackingWriter so a short write IS caught and
// the truncated file is reported instead of announced as complete.
func wf(w io.Writer, format string, args ...interface{}) { _, _ = fmt.Fprintf(w, format, args...) }
func wln(w io.Writer, args ...interface{})               { _, _ = fmt.Fprintln(w, args...) }

// writers binds w into the (wf, wln) pair used by the CLI's report writers, so a
// function emitting a single stream declares `wf, wln := writers(out)` once instead
// of re-deriving the two Fprintf/Fprintln closures inline at each site. They delegate
// to the package-level wf/wln, so the write logic lives in exactly one place.
func writers(w io.Writer) (writef func(string, ...interface{}), writeln func(...interface{})) {
	return func(format string, args ...interface{}) { wf(w, format, args...) },
		func(args ...interface{}) { wln(w, args...) }
}

// errTrackingWriter records the first write error. Writing to --output FILE makes
// a short write (e.g. ENOSPC mid-bundle) actionable: the on-disk file is a partial
// bundle missing later sections, which the operator would otherwise paste into a
// bug report believing it complete because the tool said "Wrote support bundle"
// and exited 0. The stdout path keeps the discard-errors behavior.
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

// redactedConfigFields names the YAML keys whose string values are scrubbed from
// the doctor bundle; anything not listed shows verbatim. Keep in sync with
// config.GatewayConfig — every sensitive field the schema admits must appear in one
// of these two maps: a full length-only placeholder (redactedConfigFields) or a URL
// scrub (urlConfigFields).
var redactedConfigFields = map[string]bool{
	"authToken":          true, // listen.authToken
	"upstreamAuthHeader": true, // upstreams[].upstreamAuthHeader
}

// urlConfigFields names the URL/URI keys whose value is routed through config.RedactURL
// (userinfo, query values, and fragment scrubbed; host/path kept) rather than emitted
// verbatim — whether the value is a single scalar URL or a sequence of them (see
// redactURLValue). Keyed on the field name because a credential is as likely in any of
// these as in the original upstreamUrl.
// upstreamUrl gets the strict log-facing form, which also drops the PATH. It is the one
// field here that routinely IS a webhook endpoint (Slack /services/T…/B…/<secret>,
// Telegram /bot<token>/…), where the path is the entire credential — and this bundle is
// generated to be pasted into a bug report, so it is the highest-exposure sink in the
// binary, not a place to preserve that detail. The host still identifies the upstream.
//
// The rest keep the bundle-facing form (path and query parameter NAMES preserved, values
// replaced with length-tagged placeholders). They are identifiers, not secret-bearing
// endpoints: an RFC 9728 resource URI and its authorization servers are published
// unauthenticated at /.well-known/oauth-protected-resource, and an allowed Origin is
// scheme://host with no path at all. Their paths are load-bearing for diagnosis — telling
// https://proxy.example.com/mcp/github from /mcp/jira is the point of reading the section.
var urlConfigFields = map[string]func(string) string{
	"upstreamUrl":               capability.RedactURLForLog, // upstreams[].upstreamUrl; path can BE the credential
	"oauthResource":             config.RedactURL,           // listen.oauthResource (scalar, RFC 9728 resource URI)
	"oauthAuthorizationServers": config.RedactURL,           // listen.oauthAuthorizationServers (sequence of IdP URLs)
	"allowedOrigins":            config.RedactURL,           // listen.allowedOrigins (sequence)
}

// redactURLValue scrubs a URL-bearing config value of ANY shape: a scalar URL string
// (userinfo/query/fragment stripped via config.RedactURL), a sequence of URL strings, or
// (defensively) a nested map. The doctor bundle raw-parses the on-disk YAML to surface
// a config exactly as written, so a URL field can arrive in a shape the typed loader
// would reject — a scalar where a list was expected, or a list where a scalar was.
// Scrubbing on the value's SHAPE rather than the declared schema shape means a
// credential under any URL key is scrubbed regardless of how it was (mis)written; the
// prior split scalar/array handling leaked a scalar written under an array-typed key.
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
		// A map or other nested shape: recurse so a credential under a known key inside
		// it is still scrubbed. A scalar number/bool has nothing to scrub.
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
	// cfg and cfgErr are the ONE ${ENV}-expanded load of configPath, performed by
	// parseDoctorReaderFlags so the audit-path defaults and the bundle's manifest
	// (section 3) and live-drift (section 5) walks share a single parse. Both are zero
	// when configPath is empty; exactly one is set otherwise.
	cfg    *config.GatewayConfig
	cfgErr error
}

// parseDoctorReaderFlags is parseAuditReaderFlags for doctor: identical flag parsing and
// stray-positional rejection (shared via parseReaderArgs), but an unloadable --config is
// RETURNED (with a nil cfg) instead of aborting. doctor's whole job is describing a broken
// deployment, so a config that will not parse is the case the bundle is most needed for; it
// is reported inside the bundle and every config-independent section still renders.
func parseDoctorReaderFlags(fs *flag.FlagSet, args []string, configPath, logPath, keyPath *string) (cfg *config.GatewayConfig, code int, done bool, cfgErr error) {
	if code, done := parseReaderArgs("doctor", fs, args); done {
		return nil, code, done, nil
	}
	cfg, cfgErr = loadConfigAuditDefaults("doctor", *configPath, logPath, keyPath)
	return cfg, 0, false, cfgErr
}

// cmdDoctor runs the `doctor` subcommand and returns the process exit code (rather
// than calling os.Exit itself), so tests can drive every branch in-process — matching
// every other fallible subcommand. args carries the subcommand's own arguments
// (os.Args[2:] in a real invocation), threaded from run.
func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage:
  eunox doctor [flags]

Print a user-initiated support bundle: binary identity, redacted transport
config, manifest digests + validation summary, the tail of the audit log
(values scrubbed), and — with --live — drift against each declared upstream.

Nothing leaves your machine. The bundle prints to stdout (or --output FILE)
so you control what gets pasted into a bug report. Secrets in named fields
(authToken, upstreamAuthHeader) are redacted; URL userinfo, query
values, and fragments are scrubbed in the URL/URI fields (upstreamUrl,
oauthResource, oauthAuthorizationServers, allowedOrigins).
Command-line args, paths, and audit metadata are shown verbatim — skim
before sharing.

Flags:
`)
		fs.PrintDefaults()
	}

	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the bundle includes the\nredacted config, manifest validation per route, and (with --live) drift.")
	auditLog := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")
	auditKey := fs.String("audit-key-path", "", "Path to the HMAC signing key (default: ~/.eunox/audit.key). Only used\nto report whether the key is loadable; signatures are not re-verified here.")
	auditTail := fs.Int("audit-tail", defaultDoctorAuditTail, "Number of trailing audit records to include (values redacted). 0 ⟹ skip.")
	live := fs.Bool("live", false, "Connect to each declared upstream and include the drift report.\nRequires --config.")
	output := fs.String("output", "", "Write the bundle to this file instead of stdout. The conventional name\nis eunox-doctor-<timestamp>.txt; --output auto picks one automatically.")

	// Shared with suggest/stats/audit-verify — the other readers of the same tape — so
	// the stray-positional rejection and the --config audit-path defaulting cannot drift
	// between them. doctor deliberately stops here rather than resolving --audit-log: an
	// unresolvable path is reported INSIDE the bundle, since a support bundle that prints
	// what it can beats one that refuses to print.
	cfg, code, done, cfgErr := parseDoctorReaderFlags(fs, args, configPath, auditLog, auditKey)
	if done {
		return code
	}
	// An unloadable config is NOT fatal here (unlike suggest/stats/audit-verify): it is
	// carried into the bundle and reported in the sections that need it, while every
	// other section still renders. The exit status is still non-zero, though —
	// `doctor --config X && restart` is a usable pre-flight gate, and exiting 0 would
	// silently pass it for a config the proxy will refuse to start on.
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
	// The bundle always truncates (there is no --force gate here), so the symlink refusal
	// is unconditional: without it a link planted at --output would have its TARGET
	// truncated and then re-moded 0600 by the Chmod below.
	if err := refuseNonRegularOutput(outPath); err != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: %v\n", err)
		return 1
	}
	// config.OpenNoFollow (O_NOFOLLOW on unix, 0 elsewhere) closes the Lstat->open race the
	// refusal above cannot; see writeGeneratedFile for the same pairing on the --output
	// overwrite path.
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|config.OpenNoFollow, 0o600) //nolint:gosec // G304: --output is an operator-supplied destination
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: opening %q: %v\n", outPath, err)
		return 1
	}
	// Re-tighten on the open fd: O_CREATE applies 0600 only on creation, so a pre-existing
	// looser-mode file (e.g. a prior 0644 bundle) would keep that mode. The bundle is
	// redacted, but its operational detail still warrants owner-only access — the same
	// re-tighten writeGeneratedFile applies to the generated manifest/config paths.
	if err := f.Chmod(0o600); err != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: tightening mode of %q: %v\n", outPath, err)
		_ = f.Close()
		return 1
	}
	// Track write errors AND the close (which flushes) so a truncated bundle is
	// reported with a non-zero exit rather than announced as complete.
	tw := &errTrackingWriter{w: f}
	writeDoctorBundle(tw, opts)
	closeErr := f.Close()
	if writeErr := tw.err; writeErr != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: writing %q: %v\n", outPath, writeErr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "eunox doctor: writing %q: %v\n", outPath, closeErr)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Wrote support bundle to %s\n", outPath)
	fmt.Fprintln(os.Stderr, "Review for any remaining sensitive values before sharing.")
	// Non-zero when the config could not be loaded (see above): the bundle was still
	// written, but the config is broken and a caller gating on this must hear about it.
	return exitCode
}

// writeDoctorBundle emits the support bundle to w. Sections are independent —
// a failure in any one (missing config, unreadable audit log, …) is reported
// in place and the remaining sections still render.
func writeDoctorBundle(w io.Writer, opts doctorOptions) {
	wln(w, "eunox doctor — support bundle")
	wf(w, "Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	wln(w)

	// The gateway config was parsed ONCE by parseDoctorReaderFlags and carried here for
	// the manifest (section 3) and live-drift (section 5) walks, which both operate on
	// the same ${ENV}-expanded config. Section 2 deliberately keeps its own RAW read (no
	// env expansion) so it can surface the config exactly as written on disk.
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
	switch {
	case !opts.live:
		wln(w, "(skipped — pass --live to introspect each declared upstream)")
	case opts.configPath == "":
		wln(w, "(skipped — --live requires --config)")
	default:
		writeDoctorLive(w, cfg, cfgErr)
	}

	wln(w)
	wln(w, doctorSep)
	wln(w, "End of bundle. Nothing has been sent — review and paste manually.")
}

// writeDoctorBinary stamps the binary identity: build version (from -ldflags),
// Go runtime, OS/arch, and (when the binary embeds VCS info) the commit SHA
// and dirty flag from runtime/debug.BuildInfo.
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

// writeDoctorConfig parses the raw config file (no env expansion — we want to
// surface the as-on-disk shape), redacts known-sensitive fields, and emits
// it back as YAML, indented under the section header.
func writeDoctorConfig(w io.Writer, path string) {
	wf(w, "  path: %s\n\n", path)

	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied --config path
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

// redactConfigValue walks a yaml.Unmarshal-shaped value in place, recursing into
// maps and slices. A redactedConfigFields key's value becomes a length-only
// placeholder; a urlConfigFields value is scrubbed through redactURLValue (userinfo/
// query/fragment stripped, host/path kept) whether it is a scalar URL or a sequence
// of them.
func redactConfigValue(v interface{}) {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, val := range x {
			switch {
			case redactedConfigFields[k]:
				x[k] = redactString(val)
			case urlConfigFields[k] != nil:
				x[k] = redactURLValue(val, urlConfigFields[k])
			default:
				redactConfigValue(val)
			}
		}
	case map[interface{}]interface{}:
		// gopkg.in/yaml.v3 decodes a mapping as map[interface{}]interface{} (NOT
		// map[string]interface{}) whenever ANY key is non-string (an integer, bool, ...).
		// Without this case such a map falls through the no-op default and every value in
		// it — including a sibling authToken/upstreamAuthHeader — is emitted verbatim into
		// the support bundle. Normalize each key to its string form and apply the same
		// redaction as the string-keyed case so a non-string sibling key cannot defeat it.
		for k, val := range x {
			ks := fmt.Sprintf("%v", k)
			switch {
			case redactedConfigFields[ks]:
				x[k] = redactString(val)
			case urlConfigFields[ks] != nil:
				x[k] = redactURLValue(val, urlConfigFields[ks])
			default:
				redactConfigValue(val)
			}
		}
	case []interface{}:
		for _, it := range x {
			redactConfigValue(it)
		}
	}
}

// redactString renders a present secret as "<redacted len=N>", a non-string as
// "<redacted non-string>", and an empty value as "" — so an omitted/empty secret
// reads differently from a present-but-redacted one.
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

// reportCfgErr writes the standard "could not load config" line when cfgErr is
// non-nil and reports whether it did, so writeDoctorManifests and writeDoctorLive
// report an unusable config identically instead of each keeping its own copy of the
// same guard clause. The caller's section body must return immediately when this
// reports true.
// A nil cfg with a nil cfgErr cannot come from parseDoctorReaderFlags (which always sets
// one or the other for a non-empty configPath) and means a hand-built doctorOptions
// skipped the load. Report it as unusable rather than fall through to a nil dereference
// that would crash the bundle mid-write.
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

// writeDoctorManifests walks each declared upstream, loads its policy files,
// reports per-file load result, and prints the merged manifest digest. Errors are
// reported in line and do not abort the section.
//
// cfg is loaded by the caller via config.LoadGatewayConfig (once, shared with the
// live-drift section), which expands ${ENV} references, so emit only non-sensitive
// derived fields (Name, Transport, digest) — never UpstreamURL, UpstreamAuthHeader,
// or other secret-bearing cfg fields. cfgErr is that load's error (config unusable).
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

		// Reproduce the proxy's actual startup policy-load decision so the bundle
		// cannot report OK for a route `proxy` would refuse to boot, via the shared
		// walk both doctor and validate use (load → merge → startupFatalManifestCheck).
		outcome := transport.WalkRouteManifests(cfg, u)

		if outcome.NoPolicy {
			// Classify exactly as the proxy would at startup, so a no-policy route
			// that would fail closed is not misreported as a valid wiretap.
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
		// Effect-contract coverage. In a bug report "everything escalates" and "half the
		// policy is unannotated under a ceiling" are the same fact, and the second one is
		// the one that explains it — so the bundle carries the ratio and the worklist
		// rather than leaving a reader to infer it from the manifest they cannot see.
		// Counts only: this bundle is pasted into public bug reports, and a capability
		// target is a resource URI or a tool name.
		writeEffectCoverage(w, "    ", merged, false)
		if outcome.StartupErr != nil {
			wf(w, "    WOULD FAIL CLOSED at startup: %v\n", outcome.StartupErr)
		}
	}
}

// doctorLoadAuditKeys reads the audit key file for the bundle's loadability line. It is a
// function rather than an inline call so the switch above can report the resolve failure
// and the load failure as the distinct diagnoses they are: a path that never resolved was
// never read, so reporting it as unloadable would name the wrong problem.
func doctorLoadAuditKeys(resolvedKey string, resolveErr error) ([][]byte, error) {
	if resolveErr != nil {
		return nil, nil
	}
	return audit.LoadKeys(resolvedKey)
}

// writeDoctorAudit prints aggregated counts from the audit log, then the last
// `tail` records with `details` values scrubbed and the (noisy) HMAC stripped —
// the operator can re-verify with `eunox audit-verify` after sharing.
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
		// LOADABILITY, not mere existence. A key file that exists but is unreadable,
		// truncated, or not hex reported "(present)" — in exactly the deployment chasing
		// UNKNOWN_KEY_ID, where the whole question is whether this host can verify its own
		// tape. LoadKeys never mints a key and (since it is the read-only counterpart) never
		// changes the file's mode, so this stays a read-only probe. No key material is
		// printed: the count is what an operator needs to see a rotation's keys are present.
		wf(w, "  key path:  %s (NOT loadable: %v)\n", resolvedKey, loadErr)
	default:
		wf(w, "  key path:  %s (present, %d key(s) loadable)\n", resolvedKey, len(keys))
	}

	// Skip the log-file stat when the path could not be resolved: resolvedLog is ""
	// and os.Stat("") would print a confusing second error on top of the "cannot
	// resolve" line. Mirrors the key-path block above.
	if logErr != nil {
		return
	}
	// Cover the FULL rotated set (siblings + active base), like audit-verify/stats,
	// not just the active base file — otherwise the totals and tail silently omit
	// every rotated segment once the log has rotated at least once.
	chainFiles, err := audit.LogChainFiles(resolvedLog)
	if err != nil {
		wf(w, "  log file:  %v\n", err)
		return
	}
	if len(chainFiles) == 0 {
		wf(w, "  log file:  %v\n", os.ErrNotExist)
		return
	}
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
		// escalated is a SUBSET of blocked (an escalation is a refusal), so it is
		// additional detail rather than a missing addend — but it is the one bucket that
		// says "a human was asked", and `eunox stats` over the same tape reports it. A
		// support bundle that silently drops it makes the two views of one log disagree
		// for whoever is reading the bundle instead of the machine.
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
		// A NEGATIVE tail is a different operator mistake from an explicit 0, and
		// reporting both as "=0" told someone who typed -50 that the skip was their own
		// choice. Echo what they actually passed.
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

// tailAuditLines returns the last n non-blank lines from r in original order.
// Uses a fixed-size circular buffer so an enormous log does not blow up memory and
// each record costs O(1), not O(n); the scanner buffer bound comes from
// audit.NewLineScanner so it stays identical to every other audit-log reader.
func tailAuditLines(r io.Reader, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	sc := audit.NewLineScanner(r)
	// Cap the up-front ring allocation: n flows straight from --audit-tail with no
	// bound, and make([]string, 0, n) reserves n*16 bytes immediately (e.g.
	// --audit-tail 2000000000 -> ~32 GB) even against a one-line log. The ring
	// appends, so it still grows to n only if the log actually has that many lines.
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
		// Ring full: overwrite the oldest slot and advance the write position modulo n.
		// This is the true circular-buffer write — O(1) per record, never shifting the
		// retained tail (the previous copy(ring, ring[1:]) was O(n) on every line past
		// the first n, making --audit-tail O(records * n)).
		ring[next] = line
		next = (next + 1) % n
		wrapped = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !wrapped {
		// Never overwrote a slot: the ring is already in chronological order.
		return ring, nil
	}
	// Wrapped: the oldest retained line now sits at next. Rotate exactly once into
	// chronological order — ring[next:] (older) followed by ring[:next] (newer).
	ordered := make([]string, 0, n)
	ordered = append(ordered, ring[next:]...)
	ordered = append(ordered, ring[:next]...)
	return ordered, nil
}

// redactAuditLine returns line with the HMAC stripped and every `details` value
// replaced with "<redacted>" (keys preserved). Unparseable lines are flagged but
// kept. Uses SetEscapeHTML(false) so the plain-text bundle stays readable.
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
			// A non-object details value (a string/array/number/bool) cannot be scrubbed
			// field-by-field, so the map assertion would skip it and the raw value would be
			// re-emitted verbatim into the support bundle. eunox's own writer always emits an
			// OBJECT details, so this shape can only come from a tampered or foreign record —
			// redact the whole value rather than pass a potential secret through (fail closed).
			rec["details"] = "<redacted>"
		}
	}
	// For resource targets the `target` field holds the raw resource URI, which can
	// embed credentials in userinfo or query (e.g. postgres://admin:hunter2@db, or
	// https://api/secrets?api_key=...). Scrub it with the same URL redactor used for
	// the config section so a credential does not survive into the support bundle.
	// Gate on target_type == "resource": tool/prompt/system targets are bare names,
	// not URIs, and a name that happens to contain '?'/'#'/'@' would otherwise be
	// mis-parsed by config.RedactURL and rewritten, distorting the bundle's record
	// relative to the signed tape.
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

// writeDoctorLive reuses validateConfigRoutes so the bundle reports drift by the
// same rules as `eunox validate --config --live`. cfg is loaded by the caller with
// ${ENV} expanded (shared with the manifest section); only the exit code is printed,
// no secret-bearing cfg fields. cfgErr is that load's error (config unusable).
func writeDoctorLive(w io.Writer, cfg *config.GatewayConfig, cfgErr error) {
	if reportCfgErr(w, cfg, cfgErr) {
		return
	}
	// Base context with no deadline: fetchRouteLive applies its own per-route
	// liveUpstreamTimeout, so a shared parent deadline would leave each later route
	// only the remaining budget and could report a healthy route as a connection
	// failure once a slow early route consumed most of it. Mirrors the
	// `validate --config --live` path (main.go), which passes context.Background()
	// for the same reason.
	iw := &indentWriter{w: w, prefix: []byte("  "), atLineStart: true}
	code := validateConfigRoutes(context.Background(), cfg, true, iw)
	wf(w, "\n  validate exit code: %d  (0=clean, 1=drift, 2=parse/connection error)\n", code)
}

// indentWriter prefixes each line written to it with `prefix` so reused section
// writers line up under the doctor section header. The pointer receiver tracks
// atLineStart across Write calls, handling a logical line split over several.
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
		// Mark line-start only once the newline actually reached the writer; a short
		// write leaves the stream mid-line, where a prefix must not be prepended.
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
