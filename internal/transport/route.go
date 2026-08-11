// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Per-route state for the multi-upstream gateway: what is a per-process scalar on
// HTTPProxy in single-upstream mode becomes per-route here, so one HTTPProxy can front N
// upstreams. The shared audit sink is wrapped by a routeSink that stamps each record with
// the route name and the in-force policy version/digest.

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
	// upstreamProtocolVersion is the operator's explicit protocol-revision pin for this
	// upstream; empty opens the leg with the handshake. Per route, not per proxy, because
	// a gateway's upstreams migrate on independent schedules.
	upstreamProtocolVersion capability.Revision

	// Enforcement state for this route.
	pdp        pdp.PolicyDecisionPoint
	manifest   *config.LocalManifest // nil when no policy is configured (audit/observe only)
	audit      bool                  // observe mode: evaluate and log, but forward instead of block
	driftCheck drift.CheckFunc       // set inside BuildRoutes from its driftCheckFor hook; nil = no drift checking

	// honorAttribution opts a route into the flow+effect draft grammar, admitting the
	// client-supplied io.eunolabs.context-manifest block in a request's _meta. Runtime
	// half of checkTokenGrammarVersion's load-time gate, which can't cover this since the
	// token never appears in a manifest. Read-only after BuildRoutes.
	honorAttribution bool

	// receipts verifies this upstream's signed effect receipts against the operator-
	// configured key domain for it. nil (default, no key domain configured) means Verify
	// returns nil without parsing anything, so an opted-out route pays nothing. Read-only
	// after BuildRoutes.
	receipts *capability.EffectReceiptVerifier

	// notices is this route's stderr-diagnostic table: one bucket per notice CLASS, charging the
	// proxy's aggregate as its parent. Per route so one tenant's flood of the cheapest peer-driven
	// line cannot suppress another tenant's — the rule saturationGate states for its own records,
	// one axis out.
	//
	// BuildRoutes builds it PARENTLESS and NewHTTPProxyGateway re-parents it, because the aggregate
	// belongs to a proxy that does not exist yet at build time. Built at both points rather than
	// only the second, so a route from this exported constructor that never reaches a proxy is
	// bounded on its own rather than nil — a nil table falls back to the aggregate DIRECTLY, which
	// on a gateway means one route holding the budget sized for all of them.
	notices *noticeLimiter

	// noticeCollapse holds this UPSTREAM's per-site collapse windows (see collapseWindowed in
	// meteredNotices). Per route rather than per session or per proxy because that is what those
	// faults are per: this route has one receipt verifier and one policy engine behind it, so "the
	// pin is stale" and "the flow store is down" are facts about it rather than about whoever
	// happened to call.
	// Assigned by BuildRoutes AND re-assigned by NewHTTPProxyGateway beside the notice table, so a
	// route reaching a proxy some other way cannot arrive with a working bucket table and no
	// windows — which would silently restore the per-frame flood with every guard still green.
	noticeCollapse *keyReserve[noticeSite]

	// taskAnchored mirrors the engine's WithTaskAnchoredState for this route: the
	// transport needs it to pick which key a request's decision turn is taken on, since
	// under task anchoring that isn't the session. Read-only after BuildRoutes.
	taskAnchored bool

	// decideGates hands out this route's decision turn (the PDP decision + state write,
	// not the upstream forward) — one gate per ANCHOR, so two sessions sharing a task
	// share it. Non-nil exactly when the policy is flow- or sequenceBlock-relevant; nil
	// keeps full decision parallelism.
	//
	// Its presence IS the flag: a separate serializeDecisions bool beside it could
	// silently disagree, running every decision unserialized despite being marked
	// serialized — the source->sink race the turn exists to close. Read-only after
	// BuildRoutes (the registry itself is internally synchronized).
	decideGates *anchorGates

	// Policy provenance is captured once at load and lives only on sink, the sole runtime
	// consumer, to avoid a route-side copy drifting from what the audit tape records.

	sink *routeSink

	// upstreamTransport is the shared *http.Transport for this route's remote-HTTP
	// upstream, built once (upstreamTransportOnce) and reused across the route's client
	// sessions so warm TCP/TLS connections are pooled instead of a fresh handshake per
	// session. nil for a stdio route (and until the first remote session).
	//
	// Atomic rather than a plain field: closeIdleUpstreamConns runs at shutdown
	// concurrently with a straggler handler still mid-write inside Do — a plain field
	// would make that a -race-detectable torn/nil read. The Once still guarantees exactly
	// one build; the atomic only makes the publish visible.
	upstreamTransport     atomic.Pointer[http.Transport]
	upstreamTransportOnce sync.Once
}

// sharedUpstreamTransport lazily builds (once) and returns this route's shared
// *http.Transport for its remote-HTTP upstream. upstreamTimeMs is constant for the
// proxy's lifetime, so a single build is correct.
func (r *UpstreamRoute) sharedUpstreamTransport(upstreamTimeMs int) *http.Transport {
	r.upstreamTransportOnce.Do(func() {
		r.upstreamTransport.Store(buildUpstreamTransport(r.upstreamTLSSkipVerify, upstreamTimeMs))
	})
	return r.upstreamTransport.Load()
}

// closeIdleUpstreamConns releases the route's shared upstream connection pool at proxy
// shutdown. A route that never opened a remote session (nil transport) is a no-op.
//
// The load is atomic because this can race sharedUpstreamTransport's publish (see the
// field's comment); losing that race is benign (the transport just keeps its idle conns
// until the imminent process exit), but an unsynchronized read would be a real data race.
func (r *UpstreamRoute) closeIdleUpstreamConns() {
	if t := r.upstreamTransport.Load(); t != nil {
		t.CloseIdleConnections()
	}
}

// routeSink wraps the shared *audit.Sink with one route's identity so handler call-sites
// keep the same Record(...) signature; the route name and policy version/digest are
// injected here. A nil sink (audit log failed to open) is a no-op.
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

// RecordDeclassifiedAllow stamps route identity onto the allow record for a call that
// also performed an approved declassification (see *audit.Sink's method of the same name
// for why the cleared labels and the approver travel together).
func (r *routeSink) RecordDeclassifiedAllow(ctx context.Context, sessionID, identifier, method string, details map[string]interface{}, obligs []string, auditOnly bool, labelsOut, carriedLabels, labelsCleared []string, approver, approvalID string) {
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
		LabelsCleared: labelsCleared,
		Approver:      approver,
		ApprovalID:    approvalID,
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

// AuditDegraded delegates to the shared sink so the --require-audit=strict gate sees the
// same drop/write-failure state for every route. A nil receiver or nil sink reports
// healthy, matching RecordAllow/RecordDeny's guard: a strict proxy whose sink failed to
// open is refused at startup, so the runtime gate never actually observes one.
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

// mountClause renders the " on /mcp/<name>" suffix a startup notice appends, or "" for the
// single stdio upstream. Single-sourced so printRemoteUpstreamNotice and
// PrintRoutePolicyNotices can't spell the mount convention two different ways.
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
		// Name the ENFORCED set, not the whole dispatch table: initialize/ping are
		// answered locally and never reach the upstream or the tape, and …/list forwards
		// the catalog unfiltered as an enumeration event — sweeping all of them into
		// "forwarded and logged" would over-claim.
		_, _ = fmt.Fprintf(w,
			"[eunox] AUDIT MODE: upstream %q%s runs in observe mode — its policy is evaluated but NOT enforced; every enforced call (%s) is forwarded and logged, and …/list forwards the full upstream catalog unfiltered.\n",
			name, mount, enforcedMethodSummary)
		// "Denied" is scoped to a host REQUEST — a method outside the dispatch table
		// arriving as a notification or server-initiated request never reaches
		// dispatchRequest, so saying otherwise would claim sampling/createMessage (which
		// observe mode forwards) is blocked here.
		_, _ = fmt.Fprintf(w,
			"[eunox] AUDIT MODE: upstream %q%s — observe mode does NOT lift the fail-closed default: a host REQUEST naming a method eunox does not dispatch (%s) is still denied and recorded, and the kill switch still hard-blocks. Server-initiated requests are decided separately (see sampling/createMessage).\n",
			name, mount, unmappedMethodExamples)
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
//
// w is where the startup notices (open-posture warnings, AUDIT MODE banners, the remote-HTTP
// server-initiated NOTICE) are written; a nil w means os.Stderr. Threaded as a parameter
// rather than hardcoded so a caller that wants to capture these lines (a test asserting on a
// banner) passes its own writer instead of reassigning the process-global os.Stderr, which
// races any other goroutine reading it.
func BuildRoutes(cfg *config.GatewayConfig, sink *audit.Sink, counter capability.CallCounter, flowStore capability.FlowLabelStore, ks killswitch.Manager, globalStrictDrift bool, driftCheckFor func(*config.LocalManifest, bool) drift.CheckFunc, w io.Writer) (map[string]*UpstreamRoute, error) {
	if w == nil {
		w = os.Stderr
	}
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
			// Empty when the operator wrote `auto` (or omitted the key): the handshake's own
			// reported version wins. LoadGatewayConfig has already refused anything that is
			// neither, so nothing this build cannot speak reaches the pin.
			upstreamProtocolVersion: u.ResolvedProtocolVersion(),
			audit:                   cfg.AuditModeFor(u),
			// Placeholder only, always overwritten below. DenyAllPDP matches the
			// package's no-policy-default posture; an AlwaysAllowPDP placeholder would
			// silently allow everything if a future change left it unreplaced.
			pdp: pdp.DenyAllPDP{},
			// Parentless here and re-parented by NewHTTPProxyGateway, which is where the
			// aggregate exists. Built HERE all the same, so a route this exported constructor
			// hands to something other than a proxy is bounded rather than holding a nil table
			// that falls back to whatever aggregate it is later asked about.
			notices: newRouteNoticeLimiter(nil),
			// Built here as well as at the proxy, so a route this exported constructor hands to
			// something other than a proxy collapses its faults exactly as one inside a gateway
			// does.
			noticeCollapse: newNoticeCollapse(),
		}

		// The upstream's own receipt-signing key domain, loaded ONCE at startup from a
		// local file (no fetch anywhere). A configured-but-unreadable key set is fatal
		// rather than a route that silently records every receipt as unverifiable —
		// indistinguishable from a server that stopped signing. Absent leaves the
		// verifier nil at no cost.
		receipts, err := LoadEffectReceiptVerifier(cfg.BaseDir, u.EffectReceiptKeys)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		r.receipts = receipts

		// Fail-closed per-upstream startup guards (config-declared strictDrift requires
		// a policy; a policyless route must be in audit mode). Single-sourced in config
		// so this gateway and the stdio host (serveStdioHost) cannot drift.
		if err := cfg.StartupPolicyError(u); err != nil {
			return nil, err
		}
		configStrict := cfg.ResolvedStrictDrift(u)

		taskAnchored := cfg.ResolvedTaskAnchoredState(u)
		dp, manifest, policyVersion, policySHA256, err := LoadUpstreamPDP(u, cfg.HostTransport(), cfg.BaseDir, counter, flowStore, ks, taskAnchored)
		if err != nil {
			return nil, err
		}
		r.pdp = dp
		r.manifest = manifest
		r.taskAnchored = taskAnchored
		// Serialize this route's decision phase when its policy accumulates state one
		// call writes and a later one reads, so a source's write orders before a later
		// sink's read on the same anchor under concurrent requests. A non-accumulating
		// policy keeps full decision parallelism (no registry, serializes() false).
		//
		// The predicate is config's NeedsDecisionTurn, shared with the stdio host so a
		// third state-accumulating token can't leave one transport serializing and the
		// other racing silently.
		//
		// The registry is per ROUTE, not per session, because the turn has to span the
		// anchor the state accrues to — identical task ids on two routes must address
		// different buckets.
		if manifest.NeedsDecisionTurn() {
			r.decideGates = newAnchorGates()
		}
		r.honorAttribution = manifest.HonorsAttributionInterface()
		strictDrift := ResolveStrictDrift(configStrict, globalStrictDrift, manifest != nil)
		r.driftCheck = driftCheckFor(manifest, strictDrift)
		anyPoliced = anyPoliced || manifest != nil

		// A policyless route has auditOnlyCount 0 and a suppressed AUDIT MODE banner —
		// the no-policy wiretap NOTICE below carries its posture instead.
		auditOnlyCount, auditBanner := 0, false
		if manifest != nil {
			auditOnlyCount = manifest.AuditOnlyCount()
			auditBanner = r.audit
		}
		PrintRoutePolicyNotices(w, u.Name, u.Name, auditOnlyCount, auditBanner, r.upstreamTLSSkipVerify)

		// A remote HTTP upstream has no inbound stream: eunox POSTs and never opens an
		// SSE GET back, so a server-initiated request the upstream sends is never read
		// and it gets no reply. A sampling grant on http is already refused at startup
		// in LoadUpstreamPDP; this surfaces the broader limitation.
		if r.transport == config.HostTransportHTTP {
			printRemoteUpstreamNotice(w, u.Name, u.Name)
		}

		if manifest == nil {
			// No policy but explicit enforcement: wiretap mode, every DISPATCHED call
			// forwarded and logged, none blocked on policy grounds.
			_, _ = fmt.Fprintf(w,
				"[eunox] NOTICE: upstream %q has no policy and runs in AUDIT mode on /mcp/%s — "+
					"every dispatched call is forwarded and logged, none blocked by policy (wiretap).\n",
				u.Name, u.Name)
		}

		// Only wrap a real sink: a &routeSink{sink: nil} is never the nil pointer
		// asRecorder's zero-value check looks for, so wrapping unconditionally would
		// hand every call site a non-nil recorder on a sink-less route and defeat every
		// `rec != nil` fast path (the same typed-nil trap StdioProxy.rec() avoids).
		if sink != nil {
			// Bound the three provenance fields ONCE here rather than re-deriving their
			// UTF-8 validity/length bound on every audit record (see
			// audit.BoundEnvelopeField's doc).
			r.sink = &routeSink{
				sink:          sink,
				upstream:      audit.BoundEnvelopeField(r.name),
				policyVersion: audit.BoundEnvelopeField(policyVersion),
				policySHA256:  audit.BoundEnvelopeField(policySHA256),
			}
		}
		routes[u.Name] = r
	}
	if globalStrictDrift && !anyPoliced {
		_, _ = fmt.Fprintf(w, "[eunox] WARNING: --strict-drift had no effect: no route has a policy to check drift against.\n")
	}
	return routes, nil
}

// startupFatalManifestCheck returns the startup-fatal error for an upstream's
// ALREADY-MERGED manifest — the checks that would make `proxy` refuse to boot but
// that a plain config.LoadManifest + config.MergeManifests does not evaluate: the
// expectVersion pin, the sampling/createMessage-on-http guard, and the stdio-host
// audience-pin guard (extend this one function for any future startup-fatal
// check, so it stays the single source of truth). It touches no network,
// CallCounter, or kill switch.
//
// hostTransport is the DEPLOYMENT's host-facing transport (stdio vs http gateway),
// a different axis from u.Transport (each upstream's own subprocess-vs-remote-HTTP
// reachability) — needed only by the audience-pin check below. This one function
// lets `validate --config` and `doctor` (which never see the eventual `proxy`
// invocation's flags) and LoadUpstreamPDP share every startup-fatal check through
// a single call.
//
// LoadUpstreamPDP calls this once it has merged. A caller that has ALREADY loaded
// and merged the same manifests for its own purposes (doctor's
// writeDoctorManifests, validate's validateConfigRoutes) should call this
// directly instead of calling LoadUpstreamPDP a second time just to read its
// error.
func startupFatalManifestCheck(u *config.UpstreamConfig, hostTransport string, merged *config.LocalManifest) error {
	if u.ExpectVersion != "" && u.ExpectVersion != merged.Version {
		return fmt.Errorf("upstream %q: manifest version %q does not match pinned expectVersion %q", u.Name, merged.Version, u.ExpectVersion)
	}
	// A system:sampling/createMessage opt-in cannot be enforced for a remote HTTP
	// upstream: eunox reads server-initiated requests only from a subprocess upstream.
	// Fail closed rather than load a silently-inert grant.
	if u.Transport == config.HostTransportHTTP && merged.HasSamplingGrant() {
		return fmt.Errorf("upstream %q: manifest grants system:sampling/createMessage, but server-initiated sampling cannot be enforced for an http upstream — eunox does not read server-initiated requests back from a remote HTTP upstream, so the opt-in would be silently inert. Remove the sampling grant, or reach this upstream over stdio where sampling is enforced", u.Name)
	}
	// An audience pin is a JWT concept enforced only in gateway mode with --jwks-uri,
	// which is categorically rejected on a stdio host, so the pin can never be enforced
	// there. Decidable from config alone, so fail closed rather than let an operator
	// believe the route is audience-gated when it is not.
	if hostTransport == config.HostTransportStdio && merged.Audience != "" {
		return fmt.Errorf("upstream %q declares an audience pin in its policy manifest, but audience pins are a JWT concept enforced only in gateway (transport: http) mode with --jwks-uri; a stdio host cannot enforce it. Remove the manifest 'audience' field or run this upstream as an http gateway route", u.Name)
	}
	// A declassify directive is satisfiable only by a human approval carried on a
	// validated JWT, which a stdio host can never present (--jwks-uri is rejected
	// there). Every call would escalate forever with no way to approve it — the same
	// "could never be satisfied" outcome validateDeclassify already refuses at the
	// manifest level, refused here for the same reason the audience pin is.
	//
	// The axis is the HOST transport, not the upstream's: a stdio upstream behind an
	// http gateway is fine, since the token arrives on the host leg.
	if hostTransport == config.HostTransportStdio && merged.HasDeclassify() {
		return fmt.Errorf("upstream %q declares a declassify directive in its policy manifest, but a declassification requires a human approval carried on a validated JWT, and a stdio host has no HTTP listener to present one to (--jwks-uri requires transport: http); every call to that capability would escalate forever with no way to approve it. Remove the directive or run this upstream as an http gateway route", u.Name)
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
// through load, merge, and startupFatalManifestCheck — the sequence `validate`
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
	StartupErr error // startupFatalManifestCheck(u, cfg.HostTransport(), Merged)
}

// WalkRouteManifests loads, resolves, and merges one upstream's policy files
// against cfg, then runs startupFatalManifestCheck on the merged result — the
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
		// Resolve a relative policy path against the config file's directory, the same
		// way LoadUpstreamPDP does, so an unresolvable "~" form shows against the
		// offending policy: line like any other bad path.
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
	out.StartupErr = startupFatalManifestCheck(u, cfg.HostTransport(), merged)
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
func LoadUpstreamPDP(u *config.UpstreamConfig, hostTransport, baseDir string, counter capability.CallCounter, flowStore capability.FlowLabelStore, ks killswitch.Manager, taskAnchored bool) (policy pdp.PolicyDecisionPoint, manifest *config.LocalManifest, policyVersion, policySHA256 string, err error) {
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
		// Resolve against the config file's directory, not the process cwd. Shared with
		// validate --config via config.ResolvePolicyPath so the two paths cannot diverge.
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

	if err := startupFatalManifestCheck(u, hostTransport, merged); err != nil {
		return nil, nil, "", "", err
	}

	// Namespace this route's counter keys by upstream/route name so gateway routes
	// sharing one CallCounter address disjoint maxCalls/sequenceBlock buckets — a
	// fail-closed backstop against a session-id collision or cross-route session-binding
	// regression, independent of the transport's own per-route session uniqueness.
	engineOpts := []enforcement.Option{
		enforcement.WithCallCounter(counter),
		// Flow-label provenance lives in its own session-lifetime store, not the
		// sliding-window counter. Wired unconditionally; the engine's own flow gate
		// skips the flow path for a non-flow policy, so this costs nothing unused.
		enforcement.WithFlowLabelStore(flowStore),
		enforcement.WithCounterKeyNamespace(u.Name),
		// The tokens this policy carries — a fact, handed to the ENGINE so it can decide
		// which optional subsystems to wire. This transport used to decide that itself
		// from what each token declares it depends on, but that declaration describes the
		// handler this build ships, and an embedder can register a different one for the
		// same token — only the party that knows which handlers are actually registered
		// can answer. Passed even when empty: "carries no tokens" and "nobody said" are
		// different statements, and only the first may skip anything.
		enforcement.WithPolicyTokens(merged.PolicyTokens()),
	}
	if merged.HasEffectCeiling() {
		// The tool-agnostic consequence bound, checked on every allow. Wired only when
		// declared: it can only narrow, and leaving it unset skips the per-allow check.
		engineOpts = append(engineOpts, enforcement.WithEffectCeiling(merged.EffectCeiling))
	}
	if taskAnchored {
		// Key this route's accumulated state on the caller's validated mcp.task_id claim
		// instead of its session, so taint/antecedents/budgets/spent approvals survive a
		// hop to another enforcement point. Wired only when asked: it changes what every
		// budget in the policy means, and a token with no task id is refused rather than
		// accounted twice.
		engineOpts = append(engineOpts, enforcement.WithTaskAnchoredState())
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
// denied on route B. --jwt-allow-any-audience disables both layers.
//
// Fails closed when audience pinning is active but a route has no effective audience: an
// empty (or whitespace-only) value would widen the shared validator's union and make the
// route wrapper accept-any instead of reject — including a whitespace-only value, which
// the validator's own sanitizeAudiences would drop from the union anyway, silently
// rejecting every token. The CLI never reaches this (validateJWTAudienceConfig requires a
// non-blank --jwt-audience whenever pinning is active); the guard protects direct callers
// of this exported seam.
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
		// The claim grammar's `op=` shorthand can't name the operation argument, so it
		// scans every argument while the engine's own handler hard-denies that empty
		// argument — a deliberate divergence, but only sound while both sides run the
		// semantics this build ships. An embedder who replaced allowedOperations gets the
		// replacement on the manifest path and the shipped predicate on the token path,
		// silently. Refuse the wiring here, where an operator can act on it.
		//
		// Gated on ExperimentalCapabilities: without it a token carrying mcp.capabilities
		// is rejected at validation, so the claim arm is unreachable and there's no
		// divergence to refuse.
		if opts.ExperimentalCapabilities && rt.pdp.ConditionHandlerOverridden(capability.ConditionTypeAllowedOperations) {
			return nil, fmt.Errorf("route %q registers a custom %s condition handler, which the JWT capability-claim path cannot enforce: its `op=` shorthand names no operation argument, so it scans every argument rather than dispatching through the handler. Drop the override, or disable --jwt-experimental-capabilities and express the restriction as a manifest constraint that names the operation argument",
				name, capability.ConditionTypeAllowedOperations)
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
		// only the two per-route fields so a new validation-relevant field can't
		// silently be dropped from per-route wrappers. AcceptedAudiences is cleared
		// because a route wrapper pins its single RouteAudience, not the shared union.
		wopts := opts
		wopts.AcceptedAudiences = nil
		wopts.RouteAudience = routeAud[name]
		wopts.Inner = rt.pdp
		rt.pdp = pdp.NewJWTPDPWithCache(wopts, validator.Cache())
	}
	return validator, nil
}

// AnyRouteAccumulatesSharedState reports whether any route's policy depends on state that
// outlives a single call — a maxCalls or cumulative blastRadius budget, the sequenceBlock
// antecedent history, the flow-label set. All of it is per-PROCESS under the default in-memory
// backends, so the gateway's multi-instance advisory warns on it.
//
// One predicate, derived from the class each token declares (config.AccumulatesSharedState),
// where there were four hand-written per-token spellings ORed together at the call site. The
// operator this advisory exists for is the one whose policy the list has not caught up with.
func AnyRouteAccumulatesSharedState(routes map[string]*UpstreamRoute) bool {
	for _, rt := range routes {
		// A policyless (wiretap) route has a nil manifest; the predicate is nil-safe, but
		// guard explicitly to match its siblings here.
		if rt.manifest != nil && rt.manifest.AccumulatesSharedState() {
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

// LoadEffectReceiptVerifier builds an upstream's effect-receipt verifier from a local JWKS
// path, or returns nil for an empty path — the default, under which no receipt handling
// happens at all.
//
// The path is LOCAL and read once at startup: eunox does not fetch receipt keys, since a
// network dependency would trade away the whole value of this check being local and
// unfalsifiable. It is also a DISTINCT key domain from the caller-authenticating JWKS —
// a receipt is a server's statement about its own behavior, and tying it to the token
// issuer that authenticates callers would let any party who can mint a caller token also
// mint attestations about a server.
//
// Exported so the CLI can build the same verifier for the single-upstream stdio host from
// its own flag, rather than a second loader that could drift on what it accepts.
func LoadEffectReceiptVerifier(baseDir, path string) (*capability.EffectReceiptVerifier, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	// Resolved against the CONFIG's directory, exactly as `policy:` is: a relative path
	// beside the config must mean the same thing however the proxy was launched.
	// Resolving against the process cwd could silently adopt a different file as the
	// receipt trust anchor, under which forged receipts verify and genuine ones don't.
	resolved, err := config.ResolvePolicyPath(baseDir, path)
	if err != nil {
		return nil, fmt.Errorf("resolving effectReceiptKeys path: %w", err)
	}
	// Same symlink and regular-file discipline every operator-supplied key path in the
	// binary gets: a key set is a trust anchor, so following a symlink to one is how a
	// local attacker substitutes it.
	if err := config.RefuseNonRegularPath(resolved, "effect-receipt key set"); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|config.OpenNoFollow, 0) //nolint:gosec // G304: operator-configured key-set path, guarded above
	if err != nil {
		return nil, fmt.Errorf("opening effectReceiptKeys %q: %w", resolved, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxEffectReceiptJWKSBytes))
	if err != nil {
		return nil, fmt.Errorf("reading effectReceiptKeys %q: %w", resolved, err)
	}
	v, err := capability.NewEffectReceiptVerifier(data, capability.DefaultReceiptMaxAge, capability.DefaultReceiptLeeway)
	if err != nil {
		return nil, fmt.Errorf("effectReceiptKeys %q: %w", resolved, err)
	}
	return v, nil
}

// maxEffectReceiptJWKSBytes bounds the key document read: a JWKS with a few dozen keys is
// a handful of kilobytes, so a mistyped path pointing at something enormous fails as a
// parse error rather than a startup that reads a gigabyte first.
const maxEffectReceiptJWKSBytes = 1 << 20
