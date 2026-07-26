// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Per-route state for the multi-upstream gateway: what is a per-process scalar on
// HTTPProxy in single-upstream mode (upstream wiring, PDP, manifest, audit-mode
// flag) becomes per route here, so one HTTPProxy can front N upstreams. The
// shared audit sink is wrapped by a routeSink that stamps each record with the
// route name and the in-force policy version/digest.

package transport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// UpstreamRoute holds the per-route configuration and enforcement state for one
// /mcp/<name> route.
type UpstreamRoute struct {
	name string

	// Upstream wiring. transport selects the mode.
	transport             string // "stdio" | "http"
	command               string
	args                  []string
	upstreamURL           string
	upstreamAuthHeader    string
	upstreamTLSSkipVerify bool

	// Enforcement state for this route.
	pdp        pdp.PolicyDecisionPoint
	manifest   *config.LocalManifest // nil when no policy is configured (audit/observe only)
	audit      bool                  // observe mode: evaluate and log, but forward instead of block
	driftCheck drift.CheckFunc       // set inside BuildRoutes from its driftCheckFor hook; nil = no drift checking

	// serializeDecisions is set when the route's policy is flow- or sequenceBlock-relevant,
	// so each of its sessions serializes its decision phase (the PDP decision + state
	// write, NOT the upstream forward) to order a source's write before a later sink's
	// read. false keeps full intra-session
	// decision parallelism. Read-only after BuildRoutes.
	serializeDecisions bool

	// Policy provenance is captured once at load and lives only on sink, which is the
	// sole runtime consumer (it stamps every audit record). Keeping one authoritative
	// home avoids a route-side copy drifting from what the audit tape records.

	sink *routeSink

	// upstreamTransport is the shared *http.Transport for this route's remote-HTTP
	// upstream, built once (guarded by upstreamTransportOnce) and reused across all of
	// the route's client sessions so warm TCP/TLS connections are pooled instead of a
	// fresh handshake per session. Idle-conn accumulation under session churn is bounded
	// by the transport's IdleConnTimeout/MaxIdleConnsPerHost, not a per-session
	// CloseIdleConnections. nil for a stdio route (and until the first remote session).
	//
	// Atomic rather than a plain field because the two accessors run concurrently at
	// shutdown: closeIdleUpstreamConns is deferred until after srv.Shutdown, which
	// returns on TIMEOUT with straggler handlers still executing — one of which may be
	// inside sharedUpstreamTransport's Do, mid-write. A plain field would make that a
	// -race-detectable write/read pair with a possible torn or nil observation. The Once
	// still guarantees exactly one build; the atomic only makes the publish visible.
	// (Reading through the same Once would also close the race, but a shutdown that won
	// the Do would then permanently hand every straggler a nil transport, silently
	// demoting them to http.DefaultTransport and dropping this route's TLS settings.)
	upstreamTransport     atomic.Pointer[http.Transport]
	upstreamTransportOnce sync.Once
}

// sharedUpstreamTransport lazily builds (once) and returns this route's shared
// *http.Transport for its remote-HTTP upstream. upstreamTimeMs is the proxy-global
// per-call budget, constant for the proxy's lifetime, so a single build is correct.
func (r *UpstreamRoute) sharedUpstreamTransport(upstreamTimeMs int) *http.Transport {
	r.upstreamTransportOnce.Do(func() {
		r.upstreamTransport.Store(buildUpstreamTransport(r.upstreamTLSSkipVerify, upstreamTimeMs))
	})
	return r.upstreamTransport.Load()
}

// closeIdleUpstreamConns releases the route's shared upstream connection pool, called at
// proxy shutdown so idle sockets are freed promptly rather than lingering to process
// exit. A route that never opened a remote session (nil transport) is a no-op.
//
// The load is atomic because this runs concurrently with sharedUpstreamTransport's
// publish (see the field's comment): srv.Shutdown can return on timeout with a straggler
// handler still building the transport. Losing that race is benign — a transport
// published after this load simply keeps its idle conns until process exit, which is
// immediate here — while reading it unsynchronized would be an actual data race.
func (r *UpstreamRoute) closeIdleUpstreamConns() {
	if t := r.upstreamTransport.Load(); t != nil {
		t.CloseIdleConnections()
	}
}

// routeSink wraps the shared *audit.Sink with one route's identity so handler
// call-sites keep the same Record(...) signature; the route name and policy
// version/digest are injected here. A nil sink (audit log failed to open) is a
// no-op.
type routeSink struct {
	sink          *audit.Sink
	upstream      string
	policyVersion string
	policySHA256  string
}

// RecordAllow stamps the route identity and policy provenance onto an allow
// record and forwards to the shared sink. RecordAllow/RecordDeny match
// *audit.Sink's typed recorders so the HTTP handlers stay upstream-agnostic.
func (r *routeSink) RecordAllow(ctx context.Context, sessionID, identifier, method string, details map[string]interface{}, obligs []string, auditOnly bool, labelsOut, carriedLabels []string) {
	if r == nil || r.sink == nil {
		return
	}
	r.sink.Record(ctx, audit.RecordParams{
		Upstream:      r.upstream,
		PolicyVersion: r.policyVersion,
		PolicySHA256:  r.policySHA256,
		SessionID:     sessionID,
		Identifier:    identifier,
		Method:        method,
		Decision:      "allow",
		Details:       details,
		Obligations:   obligs,
		AuditOnly:     auditOnly,
		LabelsOut:     labelsOut,
		CarriedLabels: carriedLabels,
	})
}

// RecordDeny stamps route identity onto a deny record (see RecordAllow).
func (r *routeSink) RecordDeny(ctx context.Context, sessionID, identifier, method, denialCode, condType string, details map[string]interface{}, observe bool) {
	if r == nil || r.sink == nil {
		return
	}
	r.sink.Record(ctx, audit.RecordParams{
		Upstream:      r.upstream,
		PolicyVersion: r.policyVersion,
		PolicySHA256:  r.policySHA256,
		SessionID:     sessionID,
		Identifier:    identifier,
		Method:        method,
		Decision:      "deny",
		DenialCode:    denialCode,
		ConditionType: condType,
		Details:       details,
		AuditOnly:     observe,
	})
}

// AuditDegraded delegates to the shared sink so the --require-audit=strict gate
// sees the same drop/write-failure state for every route. detail carries the
// discrete counts for the structured deny record (reason stays prose, host-facing
// only). A nil receiver or nil sink reports healthy, mirroring RecordAllow/RecordDeny's
// guard so the three methods treat a missing sink identically: a strict proxy whose
// sink failed to open is refused at startup, so the runtime gate never observes one.
func (r *routeSink) AuditDegraded() (degraded bool, reason string, detail map[string]interface{}) {
	if r == nil || r.sink == nil {
		return false, "", nil
	}
	return r.sink.AuditDegraded()
}

// ResolveStrictDrift folds the global --strict-drift flag into the per-target
// strict-drift decision. The flag promotes any policed target to strict (even
// over a per-route 'strictDrift: false') but never a policyless one — it has
// nothing to check. configured is the per-route/default value from
// config.ResolveBool; policed reports whether the target has a manifest. Both
// host transports resolve precedence here so they cannot diverge.
func ResolveStrictDrift(configured, globalFlag, policed bool) bool {
	return configured || (globalFlag && policed)
}

// serverInitiatedMethods names the server-initiated MCP requests a remote HTTP
// upstream cannot service: eunox opens no inbound stream back to it, so a request
// it issues is never read and it receives no reply. Single-sourced so the gateway
// (BuildRoutes) and stdio-host (StdioProxy.connectUpstream) NOTICEs cannot drift.
const serverInitiatedMethods = "roots/list, elicitation/create, sampling/createMessage"

// mountClause renders the " on /mcp/<name>" suffix a startup notice appends to name the
// gateway route a message concerns, or "" for the single stdio upstream (no route
// mount, since it isn't reachable at a /mcp/<name> path). Single-sourced so
// printRemoteUpstreamNotice and PrintRoutePolicyNotices cannot spell the mount
// convention two different ways.
func mountClause(routePath string) string {
	if routePath == "" {
		return ""
	}
	return " on /mcp/" + routePath
}

// printRemoteUpstreamNotice writes the startup NOTICE warning that a remote HTTP
// upstream does not service server-initiated requests, so an operator is not left
// debugging a silent hang. label identifies the upstream (the route name on the
// gateway, the URL on the stdio host); routePath is the /mcp/<name> mount, or ""
// for the stdio host, which has no route.
func printRemoteUpstreamNotice(w io.Writer, label, routePath string) {
	_, _ = fmt.Fprintf(w,
		"[eunox] NOTICE: upstream %q is a remote HTTP upstream%s — server-initiated requests (%s) are NOT serviced and the upstream receives no reply to them; if it relies on them, run it as a stdio (subprocess) upstream instead.\n",
		label, mountClause(routePath), serverInitiatedMethods)
}

// PrintRoutePolicyNotices emits the open-posture startup notices shared by the stdio
// host and each gateway route: the upstreamTlsSkipVerify WARNING, the per-entry
// AUDIT-mode NOTICE, and the whole-route AUDIT MODE banner. Factored (and exported for
// the stdio host in package main) so the two transports cannot drift on wording — they
// had already diverged — and a new open-posture notice lands on both by construction.
// routePath is the upstream name for a gateway route (rendered as " on /mcp/<name>") and
// "" for the single stdio upstream (no route mount), mirroring printRemoteUpstreamNotice.
// The remote-HTTP NOTICE and the no-policy wiretap NOTICE are site-specific and stay at
// their call sites.
func PrintRoutePolicyNotices(w io.Writer, name, routePath string, auditOnlyCount int, auditMode, tlsSkipVerify bool) {
	mount := mountClause(routePath)
	if tlsSkipVerify {
		_, _ = fmt.Fprintf(w,
			"[eunox] WARNING: upstreamTlsSkipVerify is enabled for upstream %q%s. TLS certificate verification is DISABLED. Do NOT use in production.\n",
			name, mount)
	}
	if auditOnlyCount > 0 {
		_, _ = fmt.Fprintf(w,
			"[eunox] NOTICE: upstream %q has %d capability entry(ies) in AUDIT mode%s — matching calls are evaluated and logged but NOT blocked.\n",
			name, auditOnlyCount, mount)
	}
	if auditMode {
		_, _ = fmt.Fprintf(w,
			"[eunox] AUDIT MODE: upstream %q%s runs in observe mode — its policy is evaluated but NOT enforced; ALL calls are forwarded and logged.\n",
			name, mount)
	}
}

// BuildRoutes constructs one UpstreamRoute per config entry. Each route's PDP is
// built from its own manifest(s); the call counter and kill-switch are shared.
//
// globalStrictDrift is the --strict-drift CLI flag, resolved per route here (see
// ResolveStrictDrift). When it is set but no route has a policy, it had no effect,
// so BuildRoutes warns. A route's expectVersion mismatch is always fatal.
//
// driftCheckFor builds each route's session-start drift hook (the caller passes
// drift.MakeDriftCheck), keeping the drift policy logic out of this layer.
func BuildRoutes(cfg *config.GatewayConfig, sink *audit.Sink, counter capability.CallCounter, flowStore capability.FlowLabelStore, ks killswitch.Manager, globalStrictDrift bool, driftCheckFor func(*config.LocalManifest, bool) drift.CheckFunc) (map[string]*UpstreamRoute, error) {
	routes := make(map[string]*UpstreamRoute, len(cfg.Upstreams))
	anyPoliced := false
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]

		r := &UpstreamRoute{
			name:                  u.Name,
			transport:             u.Transport,
			command:               u.Command,
			args:                  u.Args,
			upstreamURL:           u.UpstreamURL,
			upstreamAuthHeader:    u.UpstreamAuthHeader,
			upstreamTLSSkipVerify: u.UpstreamTLSSkipVerify,
			audit:                 cfg.AuditModeFor(u),
			// Placeholder only — always overwritten below before the route serves any
			// request. DenyAllPDP matches the package's no-policy-default posture (an
			// AlwaysAllowPDP placeholder would silently allow everything if a future
			// change ever left it unreplaced).
			pdp: pdp.DenyAllPDP{},
		}

		// Fail-closed per-upstream startup guards (config-declared strictDrift requires
		// a policy; a policyless route must be in audit mode — otherwise it would
		// silently allow every call unenforced). Single-sourced in config so this
		// gateway and the stdio host (serveStdioHost) cannot drift on what they refuse.
		if err := cfg.StartupPolicyError(u); err != nil {
			return nil, err
		}
		configStrict := cfg.ResolvedStrictDrift(u)

		dp, manifest, policyVersion, policySHA256, err := LoadUpstreamPDP(u, cfg.HostTransport(), cfg.BaseDir, counter, flowStore, ks)
		if err != nil {
			return nil, err
		}
		r.pdp = dp
		r.manifest = manifest
		// Serialize this route's per-session decision phase when its policy is
		// flow- or sequenceBlock-relevant (both read per-session state a source writes
		// and a later call reads), so a source's write is ordered before a later sink's
		// read on the same session under concurrent in-flight requests.
		// A non-flow/non-sequence route keeps full
		// intra-session decision parallelism.
		r.serializeDecisions = manifest != nil && (manifest.HasFlowLabel() || manifest.HasSequenceBlock())
		// strictDrift is used only to build this route's drift hook (its one
		// consumer), so it stays a local rather than write-only route state.
		strictDrift := ResolveStrictDrift(configStrict, globalStrictDrift, manifest != nil)
		r.driftCheck = driftCheckFor(manifest, strictDrift)
		anyPoliced = anyPoliced || manifest != nil

		// The three open-posture notices shared with the stdio host (TLS-skip WARNING,
		// per-entry AUDIT NOTICE, whole-route AUDIT MODE banner). For a policyless route
		// auditOnlyCount is 0 and the AUDIT MODE banner is suppressed — the no-policy
		// wiretap NOTICE below carries that route's posture instead.
		auditOnlyCount, auditBanner := 0, false
		if manifest != nil {
			auditOnlyCount = manifest.AuditOnlyCount()
			auditBanner = r.audit
		}
		PrintRoutePolicyNotices(os.Stderr, u.Name, u.Name, auditOnlyCount, auditBanner, r.upstreamTLSSkipVerify)

		// A remote HTTP upstream has no inbound stream: eunox issues request/response
		// POSTs and never opens an SSE GET back to the upstream, so a server-initiated
		// request it sends (roots/list, elicitation/create, sampling/createMessage) is
		// never read and the upstream gets no reply. A manifest grant for the one
		// enforced server-initiated method (sampling) is already refused at startup in
		// LoadUpstreamPDP; surface the broader limitation as a NOTICE so an operator is
		// not left debugging a silent hang.
		if r.transport == config.HostTransportHTTP {
			printRemoteUpstreamNotice(os.Stderr, u.Name, u.Name)
		}

		if manifest == nil {
			// No policy but explicit enforcement: audit (the guard above rejected
			// no-policy-without-audit). Wiretap mode: every call forwarded and
			// logged, none blocked. Surface the open posture loudly (the AUDIT MODE
			// banner already fired above; this adds the "no policy / wiretap" specifics).
			fmt.Fprintf(os.Stderr,
				"[eunox] NOTICE: upstream %q has no policy and runs in AUDIT mode on /mcp/%s — "+
					"ALL calls are forwarded and logged but NOT blocked (wiretap).\n",
				u.Name, u.Name)
		}

		// Only wrap a real sink. A &routeSink{sink: nil} is never the nil pointer
		// asRecorder's zero-value check looks for, so wrapping unconditionally would
		// hand every call site a NON-nil auditRecorder on a sink-less route and
		// silently defeat every "no sink configured" fast path that tests
		// `rec != nil` — dispatchList would decode and count every */list catalog it
		// has nowhere to record. That is the same typed-nil trap StdioProxy.rec()
		// documents and avoids for the stdio host; leaving r.sink nil here keeps
		// asRecorder(route.sink) a genuine nil interface at each site. routeSink's
		// own methods no-op on a nil inner sink, so a caller that ignores the nil
		// and records anyway stays safe either way.
		if sink != nil {
			r.sink = &routeSink{
				sink:          sink,
				upstream:      r.name,
				policyVersion: policyVersion,
				policySHA256:  policySHA256,
			}
		}
		routes[u.Name] = r
	}
	if globalStrictDrift && !anyPoliced {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: --strict-drift had no effect: no route has a policy to check drift against.\n")
	}
	return routes, nil
}

// StartupFatalManifestCheck returns the startup-fatal error for an upstream's
// ALREADY-MERGED manifest — the checks that would make `proxy` refuse to boot but
// that a plain config.LoadManifest + config.MergeManifests does not evaluate: the
// expectVersion pin, the sampling/createMessage-on-http guard, and the stdio-host
// audience-pin guard (extend this one function for any future startup-fatal
// check, so it stays the single source of truth). It touches no network,
// CallCounter, or kill switch.
//
// hostTransport is the DEPLOYMENT's host-facing transport
// (config.GatewayConfig.HostTransport — stdio vs http gateway), a different axis
// from u.Transport (each upstream's OWN subprocess-vs-remote-HTTP reachability,
// orthogonal to how the host reaches eunox) — needed only by the audience-pin
// check below. This one function, not two split by which axis a check needs, is
// what lets `validate --config` and `doctor` (which parse the config but never
// see the eventual `proxy` invocation's flags) and LoadUpstreamPDP all share
// every startup-fatal check through a single call: a caller that has the
// deployment's host transport (all of them do — it's cfg.HostTransport(), read
// once) cannot forget half of what proxy would refuse to boot on.
//
// LoadUpstreamPDP calls this once it has merged. A caller that has ALREADY loaded
// and merged the same manifests for its own purposes (doctor's
// writeDoctorManifests, validate's validateConfigRoutes, both of which print the
// merged digest) should call this directly instead of calling LoadUpstreamPDP a
// second time just to read its error — that would re-parse and re-merge the
// manifest files and spin up a throwaway engine/PDP purely to discard it.
func StartupFatalManifestCheck(u *config.UpstreamConfig, hostTransport string, merged *config.LocalManifest) error {
	if u.ExpectVersion != "" && u.ExpectVersion != merged.Version {
		return fmt.Errorf("upstream %q: manifest version %q does not match pinned expectVersion %q", u.Name, merged.Version, u.ExpectVersion)
	}
	// A system:sampling/createMessage opt-in cannot be enforced for a remote HTTP
	// upstream: eunox reads server-initiated requests only from a subprocess
	// upstream, so a remote upstream's sampling/createMessage is never seen. Fail
	// closed rather than load a silently-inert grant.
	if u.Transport == config.HostTransportHTTP && merged.HasSamplingGrant() {
		return fmt.Errorf("upstream %q: manifest grants system:sampling/createMessage, but server-initiated sampling cannot be enforced for an http upstream — eunox does not read server-initiated requests back from a remote HTTP upstream, so the opt-in would be silently inert. Remove the sampling grant, or reach this upstream over stdio where sampling is enforced", u.Name)
	}
	// An audience pin is a JWT concept enforced only in gateway (transport: http)
	// mode with --jwks-uri; --jwks-uri is categorically rejected on a stdio host
	// (see serveStdioHost's own --jwks-uri rejection), so the pin can never be
	// enforced there regardless of any flag — unlike the gateway's
	// FirstRouteAudiencePin (which only fires when --jwks-uri is unset, a CLI flag
	// no caller here has visibility into), this is decidable from the config
	// alone. Fail closed rather than let an operator believe the route is
	// audience-gated when it is not.
	if hostTransport == config.HostTransportStdio && merged.Audience != "" {
		return fmt.Errorf("upstream %q declares an audience pin in its policy manifest, but audience pins are a JWT concept enforced only in gateway (transport: http) mode with --jwks-uri; a stdio host cannot enforce it. Remove the manifest 'audience' field or run this upstream as an http gateway route", u.Name)
	}
	return nil
}

// PolicyLoadResult is the outcome of loading one policy file named in an
// upstream's Policy list.
type PolicyLoadResult struct {
	Path     string // as declared in UpstreamConfig.Policy, before path resolution
	Manifest *config.LocalManifest
	Err      error
}

// RouteManifestOutcome is the result of walking one upstream's policy files
// through load, merge, and StartupFatalManifestCheck — the sequence `validate`
// and `doctor` both reproduce to report exactly what `proxy` would do at
// startup, without invoking LoadUpstreamPDP a second time.
type RouteManifestOutcome struct {
	NoPolicy       bool   // len(u.Policy) == 0
	NoPolicyReason string // cfg.NoPolicyStartupRejection(u); "" means the no-policy route would boot
	AuditMode      bool   // cfg.AuditModeFor(u); only meaningful when NoPolicy

	LoadResults []PolicyLoadResult // one per u.Policy entry, in declared order
	LoadFailed  bool               // true if any LoadResults[i].Err != nil

	Merged     *config.LocalManifest // nil unless every policy file loaded and merged cleanly
	MergeErr   error
	StartupErr error // StartupFatalManifestCheck(u, cfg.HostTransport(), Merged)
}

// WalkRouteManifests loads, resolves, and merges one upstream's policy files
// against cfg, then runs StartupFatalManifestCheck on the merged result — the
// shared walk behind `validate`'s FAIL/PASS report and `doctor`'s WOULD FAIL
// CLOSED / merged-digest report, so the two commands cannot drift apart on what
// counts as a startup-fatal manifest.
func WalkRouteManifests(cfg *config.GatewayConfig, u *config.UpstreamConfig) RouteManifestOutcome {
	if len(u.Policy) == 0 {
		return RouteManifestOutcome{
			NoPolicy:       true,
			NoPolicyReason: cfg.NoPolicyStartupRejection(u),
			AuditMode:      cfg.AuditModeFor(u),
		}
	}

	var out RouteManifestOutcome
	manifests := make([]*config.LocalManifest, 0, len(u.Policy))
	for _, pf := range u.Policy {
		// Resolve a relative policy path against the config file's directory, the
		// same way LoadUpstreamPDP (the proxy load path) does. An unresolvable "~"
		// form is reported as this entry's load error, so validate --config shows it
		// against the offending policy: line like any other bad path.
		resolved, err := config.ResolvePolicyPath(cfg.BaseDir, pf)
		var m *config.LocalManifest
		if err == nil {
			m, err = config.LoadManifest(resolved)
		}
		out.LoadResults = append(out.LoadResults, PolicyLoadResult{Path: pf, Manifest: m, Err: err})
		if err != nil {
			out.LoadFailed = true
			continue
		}
		manifests = append(manifests, m)
	}
	if out.LoadFailed {
		return out
	}

	merged, err := config.MergeManifests(manifests)
	if err != nil {
		out.MergeErr = err
		return out
	}
	out.Merged = merged
	out.StartupErr = StartupFatalManifestCheck(u, cfg.HostTransport(), merged)
	return out
}

// LoadUpstreamPDP builds the enforcement state for one upstream from its policy
// files: the PDP, the merged manifest (nil when no policy is configured), and the
// policy provenance (version + digest). With no policy it returns an allow-all
// PDP. A version pin (expectVersion) is validated here so the gateway
// (BuildRoutes) and the stdio host share identical policy-loading semantics.
//
// baseDir is the gateway config file's directory: a relative `policy:` path resolves
// against it, not the process working directory, so a config launched from any cwd
// finds its manifests. An empty baseDir (e.g. a programmatically built config) keeps
// the prior cwd-relative behavior. Absolute policy paths are used verbatim.
func LoadUpstreamPDP(u *config.UpstreamConfig, hostTransport, baseDir string, counter capability.CallCounter, flowStore capability.FlowLabelStore, ks killswitch.Manager) (policy pdp.PolicyDecisionPoint, manifest *config.LocalManifest, policyVersion, policySHA256 string, err error) {
	if len(u.Policy) == 0 {
		if u.ExpectVersion != "" {
			return nil, nil, "", "", fmt.Errorf("upstream %q: expectVersion %q set but no policy is configured", u.Name, u.ExpectVersion)
		}
		// Wire the shared kill switch into the wiretap PDP so /control/kill halts
		// even this policyless route — an emergency stop must stop it too.
		return pdp.NewAlwaysAllowPDP(ks), nil, "", "", nil
	}

	// A version pin is only meaningful against a single manifest: the merged version
	// comes from the first file, so a multi-file pin would silently track only that
	// file and miss drift in the others. Reject the ambiguous combination.
	if u.ExpectVersion != "" && len(u.Policy) > 1 {
		return nil, nil, "", "", fmt.Errorf("upstream %q: expectVersion is not supported with multiple policy files (got %d); the pin would track only the first file's version — merge them into one manifest to pin a version", u.Name, len(u.Policy))
	}

	manifests := make([]*config.LocalManifest, 0, len(u.Policy))
	for _, pf := range u.Policy {
		// Resolve a relative policy path against the config file's directory, not the
		// process cwd, so a config launched from any directory still finds its
		// manifests. An absolute path (or an empty baseDir, e.g. a programmatically
		// built config) is used verbatim. Shared with validate --config via
		// config.ResolvePolicyPath so the two paths cannot diverge.
		resolved, err := config.ResolvePolicyPath(baseDir, pf)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		m, err := config.LoadManifest(resolved)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		manifests = append(manifests, m)
	}
	merged, err := config.MergeManifests(manifests)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("upstream %q: %w", u.Name, err)
	}

	if err := StartupFatalManifestCheck(u, hostTransport, merged); err != nil {
		return nil, nil, "", "", err
	}

	// Namespace this route's counter keys by the upstream/route name so gateway routes
	// that share one CallCounter address disjoint maxCalls/sequenceBlock buckets — a
	// fail-closed backstop in the key itself against a session-id collision or a
	// cross-route session-binding regression, independent of the transport's per-route
	// session uniqueness. u.Name is always set (config rejects an empty name, and the
	// single-upstream path synthesizes one), so every route — including a lone
	// single-upstream route, where cross-route collision is impossible anyway — is
	// namespaced.
	engineOpts := []enforcement.Option{
		enforcement.WithCallCounter(counter),
		// Flow-label provenance lives in its own session-lifetime store, not the
		// sliding-window counter. Wired unconditionally
		// like the counter; the WithoutFlowLabels gate below skips the flow path for a
		// non-flow policy, so a wired-but-unused store costs nothing.
		enforcement.WithFlowLabelStore(flowStore),
		enforcement.WithCounterKeyNamespace(u.Name),
	}
	if !merged.HasSequenceBlock() {
		// No sequenceBlock in the policy: the per-call antecedent marker is never
		// read, so skip recording it (avoids a counter round-trip per call and the
		// fail-closed deny path that could burn a committed maxCalls slot on a write
		// fault).
		engineOpts = append(engineOpts, enforcement.WithoutAntecedentRecording())
	}
	if !merged.HasFlowLabel() {
		// No flowLabel condition or labelOutput directive anywhere in the policy: the
		// per-call flow-relevance scan and the peek/record path are pure overhead, and
		// skipping them also drops the recordLabels fail-closed deny path a source-only
		// policy would otherwise carry. Mirrors the WithoutAntecedentRecording gate above.
		engineOpts = append(engineOpts, enforcement.WithoutFlowLabels())
	}
	engine := enforcement.New(engineOpts...)
	digest, err := merged.Digest()
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("upstream %q: %w", u.Name, err)
	}
	return pdp.NewManifestPDP(merged.Capabilities, engine, ks), merged, merged.Version, digest, nil
}

// WrapRoutesWithJWT enables per-route JWT∩manifest intersection for a gateway.
// Each route's PDP is wrapped in a pdp.JWTPDP whose Inner is that route's existing
// PDP, so a single bearer token is intersected against each upstream's own
// manifest. The returned validator is the shared PDP the HTTP layer calls for
// ValidateToken; every per-route wrapper shares its JWKS cache (only the validator
// fetches keys — wrappers read already-validated claims from the request context).
//
// Per-route audience pinning: a route's effective audience is its manifest 'audience'
// when it declares one, else the global --jwt-audience (opts.Audience) fallback. The
// shared validator accepts the UNION of every route's effective audience, so a token
// minted for ANY route clears signature/exp/iss/aud validation once; each route wrapper
// then narrows to its OWN effective audience, so a token for route A's audience is
// denied on route B (the model deferred from the earlier documentation-only fix). The split keeps
// signature/exp/iss validation shared while making the audience assertion per-route.
// --jwt-allow-any-audience disables both layers, unchanged.
//
// Fails closed when audience pinning is active (AllowAnyAudience is false) but a route
// has no effective audience — neither a manifest 'audience' nor the global Audience
// fallback. An empty (or whitespace-only) effective audience would put "" into the
// accepted-audience union (widening the shared validator to accept any pinned route's
// token) and give the route wrapper an empty RouteAudience, which disables per-route
// narrowing and makes the route accept-any instead of reject. A whitespace-only value
// is caught here too because the shared validator's sanitizeAudiences drops it from the
// union, so admitting it would silently reject every token instead of surfacing the
// misconfiguration. The CLI never reaches this (validateJWTAudienceConfig requires a
// non-blank --jwt-audience whenever pinning is active), so the guard protects direct
// callers of this exported seam.
func WrapRoutesWithJWT(routes map[string]*UpstreamRoute, opts pdp.JWTPDPOptions) (*pdp.JWTPDP, error) {
	// Effective per-route audience and the union the shared validator accepts.
	routeAud := make(map[string]string, len(routes))
	seen := make(map[string]struct{}, len(routes)+1)
	var union []string
	for name, rt := range routes {
		eff := opts.Audience
		if rt.manifest != nil && rt.manifest.Audience != "" {
			eff = rt.manifest.Audience
		}
		if strings.TrimSpace(eff) == "" && !opts.AllowAnyAudience {
			return nil, fmt.Errorf("route %q has no effective JWT audience: set the manifest 'audience', pass a global audience, or enable AllowAnyAudience — an empty or whitespace-only audience with pinning active would widen the shared validator and disable per-route narrowing", name)
		}
		routeAud[name] = eff
		if _, dup := seen[eff]; !dup {
			seen[eff] = struct{}{}
			union = append(union, eff)
		}
	}

	// The shared validator pins the union (token validation only); it makes no routing
	// decision, so it carries no RouteAudience. A copy of opts keeps the caller's value
	// (and its single Audience) untouched.
	vopts := opts
	vopts.AcceptedAudiences = union
	validator := pdp.NewJWTPDP(vopts)

	for name, rt := range routes {
		// Share the validator's JWKS cache; wrappers never fetch keys, so skip the
		// throwaway JWKSCache+breaker NewJWTPDP would allocate. Copy opts and override
		// only the two per-route fields (RouteAudience, Inner), mirroring the vopts
		// pattern above, so a new validation-relevant JWTPDPOptions field cannot silently
		// be dropped from per-route wrappers. AcceptedAudiences is cleared because a route
		// wrapper pins its single RouteAudience, not the shared union; the cache fields
		// (JWKSURI/Client/Breaker/CacheTTL) are ignored by NewJWTPDPWithCache, which takes
		// the shared cache explicitly.
		wopts := opts
		wopts.AcceptedAudiences = nil
		wopts.RouteAudience = routeAud[name]
		wopts.Inner = rt.pdp
		rt.pdp = pdp.NewJWTPDPWithCache(wopts, validator.Cache())
	}
	return validator, nil
}

// AnyRouteHasMaxCalls reports whether any route's manifest uses maxCalls.
func AnyRouteHasMaxCalls(routes map[string]*UpstreamRoute) bool {
	for _, rt := range routes {
		// A policyless (wiretap) route has a nil manifest; guard explicitly.
		if rt.manifest != nil && rt.manifest.HasMaxCalls() {
			return true
		}
	}
	return false
}

// FirstRouteAudiencePin returns the name of a route whose manifest declares an
// `audience` pin, and true, or ("", false) if none does. A manifest audience is a
// JWT concept: it is consulted only by WrapRoutesWithJWT, which the binary wires
// solely when --jwks-uri is set. The CLI uses this to fail closed when a route pins an
// audience but no JWKS endpoint was configured — otherwise the pin is dead config and
// the route serves every request unauthenticated, the config-file form of the
// silently-ignored-JWT-auth footgun the --jwt-* flag guard already closes.
func FirstRouteAudiencePin(routes map[string]*UpstreamRoute) (string, bool) {
	for name, rt := range routes {
		// A policyless (wiretap) route has a nil manifest; guard explicitly.
		if rt.manifest != nil && rt.manifest.Audience != "" {
			return name, true
		}
	}
	return "", false
}

// AnyRouteHasSequenceBlock reports whether any route's manifest uses sequenceBlock.
// Like maxCalls, sequenceBlock enforcement reads per-session call history out of the
// shared call counter, which is per-process under the default in-memory backend; the
// multi-instance advisory uses this so a sequenceBlock-only policy is warned about too.
func AnyRouteHasSequenceBlock(routes map[string]*UpstreamRoute) bool {
	for _, rt := range routes {
		// A policyless (wiretap) route has a nil manifest; guard explicitly.
		if rt.manifest != nil && rt.manifest.HasSequenceBlock() {
			return true
		}
	}
	return false
}

// AnyRouteHasFlowLabel reports whether any route's manifest uses information-flow
// control (a flowLabel condition or a labelOutput directive). Like maxCalls/
// sequenceBlock, flow labels are per-session state in the shared call counter — per
// process under the default in-memory backend — so the multi-instance advisory warns on
// a flow policy too: without shared Redis, a source on one instance and a sink on
// another fail open silently.
func AnyRouteHasFlowLabel(routes map[string]*UpstreamRoute) bool {
	for _, rt := range routes {
		if rt.manifest != nil && rt.manifest.HasFlowLabel() {
			return true
		}
	}
	return false
}
