// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"sync"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Tier-2 interface pinning auto-baselines the advertised surface of EVERY tool a
// session sees (no manifest entry required) and re-diffs on every later tools/list,
// closing what Tier-1's request-side conformance and the opt-in FM-5 descriptionHash
// pin (a specific, per-tool pin) leave open: a description rewritten mid-session on a
// tool nobody pinned.
//
// A strict superset of FM-5, not a second mechanism — the surface hash is the same
// capability.ComputeToolHash over the same model-facing bytes, so the two can never
// disagree about what a tool's surface IS; only what it's compared against differs.
//
// Scoped per SESSION: a surface changing WITHIN a session is anomalous (servers evolve
// across restarts, not mid-conversation), so a legitimate upstream upgrade re-baselines
// cleanly on the next session instead of denying for the life of the process.
//
// HONEST LIMIT: pure METADATA comparison. Catches tool-description poisoning and silent
// interface drift, NOT a rug pull where the interface is unchanged and only behavior
// differs — eunox verifies attestations, it does not monitor. See
// docs/interface-pinning-tier2.md.

// ToolSurface is one advertised tool reduced to the pair Tier-2 compares: the name it
// presents to a host and the hash of its model-facing surface (SurfaceHash).
type ToolSurface struct {
	Name string
	Hash string
}

// SurfaceHash returns the Tier-2 surface hash of an advertised tool — the same
// capability.ComputeToolHash bytes the FM-5 descriptionHash pin covers, so a baseline
// and a manifest pin are directly comparable.
func SurfaceHash(description, title string, annotations, inputSchema, outputSchema map[string]interface{}) string {
	return capability.ComputeToolHash(description, capability.ToolHashParams(title, annotations, inputSchema, outputSchema))
}

// SurfaceChangeKind classifies one Tier-2 finding.
type SurfaceChangeKind string

const (
	// SurfaceChanged — an already-baselined tool now advertises a different surface:
	// the pin break, denied on the call leg and hidden from tools/list for the rest of
	// the session.
	SurfaceChanged SurfaceChangeKind = "changed"
	// SurfaceAdded — a tool absent from the baseline appeared in a later tools/list.
	// Advisory (MCP supports a changing tool list; still gated by the manifest
	// allowlist), and baselined on sight so a later change to it still breaks.
	SurfaceAdded SurfaceChangeKind = "added"
	// SurfaceRemoved — a baselined tool is absent from a later tools/list. The
	// baseline entry is RETAINED (a tool that returns with a rewritten surface still
	// trips a break), reported once per disappearance.
	SurfaceRemoved SurfaceChangeKind = "removed"
	// SurfaceOverflow — the baseline reached maxSessionSurfaceEntries; the whole
	// session is sticky-broken rather than dropping the entry, which would silently
	// leave a tool unpinned.
	SurfaceOverflow SurfaceChangeKind = "overflow"
)

// maxSessionSurfaceEntries bounds one session's Tier-2 baseline, which is
// upstream-driven and unbounded otherwise — a name-rotating server adds a batch per
// tools/list for the life of the session (unlike FM-5's map, keyed off pinnedTools).
//
// At the ceiling the session fails closed (sticky-broken whole) rather than dropping
// entries (fail-open: an unpinned tool) or evicting the oldest (an upstream could drive
// that to evict exactly the tool it means to rewrite). 100k names is far past any real catalog.
const maxSessionSurfaceEntries = 100_000

// SurfaceChange is one Tier-2 finding. Baseline and Observed are the surface hashes
// either side of the comparison; both are empty for an added/removed finding.
type SurfaceChange struct {
	Tool     string
	Kind     SurfaceChangeKind
	Baseline string
	Observed string
}

// SurfaceBaseline holds the Tier-2 pin for every live session: the first surface hash
// observed per tool, plus the sticky set of tools whose surface later changed.
//
// A nil *SurfaceBaseline is a working "pinning disabled" value (every method a no-op),
// and it's safe for concurrent use — one per-route ManifestPDP serves N sessions in
// parallel in HTTP mode.
type SurfaceBaseline struct {
	mu       sync.RWMutex
	sessions map[string]*sessionSurface
}

// sessionSurface is one session's Tier-2 state. established distinguishes "never seen a
// tools/list" from "seen, and this tool wasn't in it" — without it every first
// observation would report as an addition.
type sessionSurface struct {
	established bool
	hashes      map[string]string
	broken      map[string]struct{}
	// allBroken is the sticky whole-session break BreakAll sets. A flag rather than a
	// sweep over hashes, since the tools it must cover are exactly the ones a sweep
	// can't see (not-yet-baselined, or advertised later).
	allBroken bool
	// overflowed marks the cap was hit, so the ERROR line emits once per session, not
	// once per over-cap tool.
	overflowed bool
	// reportedGone holds tools whose disappearance was already reported, so a
	// vanished tool doesn't log on every later listing; dropped from the set when
	// seen again, so a second disappearance reports.
	reportedGone map[string]struct{}
}

// NewSurfaceBaseline creates an empty Tier-2 baseline.
func NewSurfaceBaseline() *SurfaceBaseline {
	return &SurfaceBaseline{sessions: make(map[string]*sessionSurface)}
}

// Observe records this session's view of the advertised tool set and returns every
// Tier-2 finding. The FIRST call establishes the baseline and reports nothing; later
// calls compare.
//
// A changed surface is STICKY-broken — never cleared by a later clean observation,
// since a rotated-back description would otherwise re-open the call leg for a host
// still holding the poisoned copy. Recovery is a new session. An empty sessionID
// buckets to itself, so an anonymous caller is still pinned (over-block only, never under-block).
func (b *SurfaceBaseline) Observe(sessionID string, tools []ToolSurface, complete bool) []SurfaceChange {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.session(sessionID)

	// A PARTIAL view (one page) can baseline/re-diff each tool it contains, but says
	// nothing about which tools exist — reporting membership from a page would falsely
	// report every tool on OTHER pages as disappeared on every pagination cycle. Only a
	// complete listing establishes baseline membership; the session-start probe (all
	// pages merged) and a later unpaginated host tools/list both supply one. See
	// WithCompleteToolListing.
	first := !s.established
	if complete {
		s.established = true
	}
	reportMembership := complete && !first

	var changes []SurfaceChange
	seen := make(map[string]struct{}, len(tools))
	for _, t := range tools {
		seen[t.Name] = struct{}{}
		// Present again: a later disappearance is a new event and reports again.
		delete(s.reportedGone, t.Name)
		baseline, known := s.hashes[t.Name]
		switch {
		case !known:
			if len(s.hashes) >= maxSessionSurfaceEntries {
				// Fail closed instead of baselining an unbounded set; the tool is
				// NOT recorded (so the map stops growing) and allBroken is what
				// keeps that from meaning "unpinned". See maxSessionSurfaceEntries.
				s.allBroken = true
				if !s.overflowed {
					s.overflowed = true
					changes = append(changes, SurfaceChange{Tool: t.Name, Kind: SurfaceOverflow})
				}
				continue
			}
			s.hashes[t.Name] = t.Hash
			if reportMembership {
				changes = append(changes, SurfaceChange{Tool: t.Name, Kind: SurfaceAdded})
			}
		case baseline != t.Hash:
			// Sticky: marked before returning, so the call leg denies even if a
			// later list re-advertises the baseline surface.
			s.broken[t.Name] = struct{}{}
			changes = append(changes, SurfaceChange{
				Tool: t.Name, Kind: SurfaceChanged, Baseline: baseline, Observed: t.Hash,
			})
		}
	}
	if reportMembership {
		// Sorted so a multi-tool removal reports in a stable order — the findings are read
		// as a set, and map order would make two identical sessions log differently.
		var gone []string
		for name := range s.hashes {
			if _, still := seen[name]; still {
				continue
			}
			if _, already := s.reportedGone[name]; already {
				continue // its disappearance was reported; it has not disappeared again
			}
			gone = append(gone, name)
		}
		sort.Strings(gone)
		for _, name := range gone {
			s.reportedGone[name] = struct{}{}
			changes = append(changes, SurfaceChange{Tool: name, Kind: SurfaceRemoved})
		}
	}
	return changes
}

// MarkBroken sticky-breaks the named tools without a hash comparison, for a tools/list
// entry whose BYTES cannot be trusted to decode to what a host renders (a duplicate or
// case-variant key) — the fail-closed move is to deny every name it could be
// presenting, whether or not that name was ever baselined.
func (b *SurfaceBaseline) MarkBroken(sessionID string, tools ...string) {
	if b == nil || len(tools) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.session(sessionID)
	for _, t := range tools {
		s.broken[t] = struct{}{}
	}
}

// BreakAll sticky-breaks EVERY tool in this session, baselined or not, now or later —
// reserved for an ambiguity that taints a WHOLE tools/list response, where the set of
// names it could be impersonating is UNKNOWN rather than none. Scoped to the session, so
// recovery is a new session, not a proxy restart.
//
// Sets a flag rather than sweeping the baseline map: on a session's FIRST tools/list the
// map is still empty, so a sweep would break nothing and the response's other entries
// would then baseline clean and stay callable.
func (b *SurfaceBaseline) BreakAll(sessionID string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.session(sessionID).allBroken = true
}

// session returns the session's state, creating it if absent. Callers hold b.mu.
func (b *SurfaceBaseline) session(sessionID string) *sessionSurface {
	if b.sessions == nil {
		b.sessions = make(map[string]*sessionSurface)
	}
	s := b.sessions[sessionID]
	if s == nil {
		s = &sessionSurface{hashes: make(map[string]string)}
		b.sessions[sessionID] = s
	}
	if s.broken == nil {
		s.broken = make(map[string]struct{})
	}
	if s.reportedGone == nil {
		s.reportedGone = make(map[string]struct{})
	}
	return s
}

// Broken reports whether a tool's Tier-2 pin is broken — surface changed, an
// untrustworthy entry could have impersonated it, or the whole session is broken.
// Consulted by both the call leg (hard deny) and the tools/list filter, so a shown tool
// never has its call leg reject.
func (b *SurfaceBaseline) Broken(sessionID, tool string) bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	s := b.sessions[sessionID]
	if s == nil {
		return false
	}
	if s.allBroken {
		return true
	}
	_, broken := s.broken[tool]
	return broken
}

// Release drops a session's baseline on teardown, so an ended session retains no state
// and a reused session id starts clean. Called from ManifestPDP.ReleaseSession alongside
// the flow-label release.
func (b *SurfaceBaseline) Release(sessionID string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	delete(b.sessions, sessionID)
	b.mu.Unlock()
}

// LogLine formats a Tier-2 finding as one structured stderr line, matching
// internal/drift's FM-1..FM-6 shape so an operator greps findings uniformly. A break is
// ERROR (denies); an add/remove is WARN.
func (c SurfaceChange) LogLine() string {
	switch c.Kind {
	case SurfaceChanged:
		return "[eunox] ERROR drift=tier2 tool=" + quote(c.Tool) +
			" — advertised surface changed mid-session (baseline " + c.Baseline + ", now " + c.Observed +
			"); the tool is denied and hidden for the rest of this session (tool-description poisoning or silent interface drift). Metadata comparison only: an unchanged interface with changed BEHAVIOR is not covered"
	case SurfaceAdded:
		return "[eunox] WARN drift=tier2 tool=" + quote(c.Tool) +
			" — tool appeared after the session's interface baseline was taken; it is baselined on sight and still gated by the manifest allowlist"
	case SurfaceRemoved:
		return "[eunox] WARN drift=tier2 tool=" + quote(c.Tool) +
			" — tool disappeared after the session's interface baseline was taken; its baseline is retained, so a return with a changed surface still trips a pin break"
	case SurfaceOverflow:
		return "[eunox] ERROR drift=tier2 tool=" + quote(c.Tool) +
			" — the upstream advertised more than " + strconv.Itoa(maxSessionSurfaceEntries) +
			" distinct tool names in this session, past the interface-pinning baseline's bound; every tool is now denied and hidden for the rest of this session (an upstream rotating tool names is itself anomalous). Recovery is a new session"
	default:
		return "[eunox] WARN drift=tier2 tool=" + quote(c.Tool)
	}
}

// quote renders a tool name with %q — real escaping. An upstream-controlled name with a
// quote and a newline could otherwise forge additional log lines on the operator's
// stderr stream.
func quote(s string) string {
	return fmt.Sprintf("%q", s)
}

// surfaceLog is where Tier-2 findings are written. It is a package variable solely so a
// test can capture the lines; production always writes to stderr, alongside the startup
// drift findings an operator already greps for.
var surfaceLog io.Writer = os.Stderr

// emitSurfaceChanges writes one structured line per Tier-2 finding. A break is also
// enforced (call-leg deny plus hidden from tools/list), so the line is the operator's
// notice of an enforcement action, not the enforcement itself.
func emitSurfaceChanges(changes []SurfaceChange) {
	for _, c := range changes {
		// Discarded explicitly: a failed write here is not actionable (the
		// enforcement it announces already happened). Written out because this goes
		// through a variable for test capture, which errcheck doesn't exempt the way
		// it exempts a literal os.Stderr write.
		_, _ = fmt.Fprintln(surfaceLog, c.LogLine())
	}
}

// sessionIDKey types the context value carrying the session id into the PDP's
// list-filtering paths, which cross the ListFilterer interface (ctx, result) with no
// session parameter.
type sessionIDKey struct{}

// WithSessionID returns a child context carrying the transport's session id, so the
// list-filtering and hash-observing paths can key per-session state. The enforced
// Decide* paths take the session id as an explicit parameter instead and don't need it.
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey{}, sessionID)
}

// sessionIDFromContext returns the session id attached by WithSessionID, or "" when the
// caller attached none. An absent id is not an error: it buckets into the anonymous
// baseline, which can only over-block.
func sessionIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(sessionIDKey{}).(string)
	return id
}

// declaredLabelsKey types the context value carrying a cooperating client's per-call
// flow attribution; rides context rather than widening every PDP's Decide* signature for
// one optional, additive hint.
type declaredLabelsKey struct{}

// WithDeclaredLabels returns a child context carrying a client's per-call flow
// attribution (the `io.eunolabs.context-manifest` block in `_meta`). The labels are
// UNIONED into the session's accumulated set for that call's sink check — never
// subtracted, never written into session state. See capability/attribution.go.
func WithDeclaredLabels(ctx context.Context, labels []string) context.Context {
	if len(labels) == 0 {
		return ctx
	}
	return context.WithValue(ctx, declaredLabelsKey{}, capability.NormalizeDeclaredLabels(labels))
}

// declaredLabelsFromContext returns the client-attributed labels, or nil when the client
// attributed nothing — the default for every non-cooperating client.
func declaredLabelsFromContext(ctx context.Context) []string {
	labels, _ := ctx.Value(declaredLabelsKey{}).([]string)
	return labels
}

// completeListingKey marks a tools/list observation as covering the WHOLE advertised
// surface rather than one page of it.
type completeListingKey struct{}

// WithCompleteToolListing marks the tools/list result on this context as a complete
// listing. Tier-2 reports additions/removals only for a complete listing — a single page
// can't distinguish "gone" from "on another page", and surface CHANGES are detected
// either way.
//
// Two callers mark it, and BOTH are needed: the session-start drift probe (all pages
// merged) establishes the baseline, and a later unpaginated host tools/list is what a
// complete observation can be compared against — with only one marking, every complete
// observation would be the session's first, with nothing to compare against.
//
// The default (unmarked) is conservative: a paginated listing is treated as partial,
// suppressing membership findings but never a break.
func WithCompleteToolListing(ctx context.Context) context.Context {
	return context.WithValue(ctx, completeListingKey{}, true)
}

// CompleteToolListingFromContext reports whether this observation covers the whole
// advertised surface (false unless WithCompleteToolListing marked it). Exported as the
// reader half of that setter so the transport can assert what it marked at its own boundary.
func CompleteToolListingFromContext(ctx context.Context) bool {
	complete, _ := ctx.Value(completeListingKey{}).(bool)
	return complete
}
