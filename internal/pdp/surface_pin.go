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

// Tier-2 interface pinning.
//
// Tier-1 (shipped) is request-side conformance: argument validation, method mapping,
// fail-closed unmapped methods. The opt-in descriptionHash pin (FM-5) is the operator's
// explicit, per-tool pin to a SPECIFIC hash, verified at session init and on the call
// leg. Tier-2 closes the two gaps that leaves: it AUTO-baselines the advertised surface
// of EVERY tool a session sees — no manifest entry required — and re-diffs on every
// later tools/list, so a description rewritten mid-session (the tool-poisoning carrier)
// trips a pin break on a tool nobody pinned.
//
// It is a strict superset of the FM-5 machinery, not a second one: the surface hash is
// capability.ComputeToolHash over exactly the same model-facing bytes FM-5 pins
// (description + every parameter description + title + annotations + outputSchema
// descriptions), so the two can never disagree about what a tool's surface IS. The
// difference is only WHAT it is compared against — a manifest-declared hash (FM-5) or
// the first hash this session saw (Tier-2) — and how widely it applies.
//
// Scope is per SESSION, deliberately. A tool's advertised surface changing WITHIN a
// session is anomalous: MCP servers evolve across restarts, not mid-conversation. Keying
// the baseline by session means a legitimate upstream upgrade re-baselines cleanly on the
// next session instead of denying for the life of the process, so a false positive costs
// one session rather than requiring an operator to restart the proxy. (The per-route
// ManifestPDP is shared across every session on the route, which is exactly why the
// baseline cannot be a bare per-PDP map: two sessions whose upstream subprocesses were
// launched either side of a server upgrade would otherwise poison each other.)
//
// HONEST LIMIT — this is pure METADATA comparison. It catches tool-description poisoning
// and silent interface drift. It does NOT catch a rug pull where the advertised interface
// is unchanged and only the upstream's BEHAVIOR differs; detecting that would mean
// watching server behavior, which eunox does not do (it verifies attestations, it does not
// monitor). Operator-facing copy must state that non-coverage rather than imply Tier-2 is
// a general anti-tamper guarantee. See docs/interface-pinning-tier2.md.

// ToolSurface is one advertised tool reduced to the pair Tier-2 compares: the name it
// presents to a host and the hash of its model-facing surface (SurfaceHash).
type ToolSurface struct {
	Name string
	Hash string
}

// SurfaceHash returns the Tier-2 surface hash of an advertised tool. It is
// capability.ComputeToolHash over the SAME model-facing bytes the FM-5 descriptionHash
// pin covers, so a Tier-2 baseline and a manifest pin are directly comparable values and
// the two pins cannot drift on what a tool's surface is.
func SurfaceHash(description, title string, annotations, inputSchema, outputSchema map[string]interface{}) string {
	return capability.ComputeToolHash(description, capability.ToolHashParams(title, annotations, inputSchema, outputSchema))
}

// SurfaceChangeKind classifies one Tier-2 finding.
type SurfaceChangeKind string

const (
	// SurfaceChanged — an already-baselined tool now advertises a different surface.
	// This is the pin break: the tool is denied on the call leg and hidden from
	// tools/list for the rest of the session.
	SurfaceChanged SurfaceChangeKind = "changed"
	// SurfaceAdded — a tool absent from the session's baseline appeared in a later
	// tools/list. Advisory: MCP explicitly supports a changing tool list
	// (notifications/tools/list_changed), and a new tool is still gated by the manifest
	// allowlist, so it is reported rather than denied. Its surface is baselined on sight,
	// so a LATER change to it is a break like any other.
	SurfaceAdded SurfaceChangeKind = "added"
	// SurfaceRemoved — a baselined tool is absent from a later tools/list. Advisory for
	// the same reason. The baseline entry is deliberately RETAINED, so a tool that
	// disappears and returns with a rewritten surface still trips a break rather than
	// being re-baselined to the rewritten value. Reported once per disappearance, not on
	// every listing that continues to omit it.
	SurfaceRemoved SurfaceChangeKind = "removed"
	// SurfaceOverflow — the session's baseline reached maxSessionSurfaceEntries. The
	// session is sticky-broken WHOLE (every tool denied, every tool hidden) rather than
	// dropping the entry, which would silently leave a tool unpinned. Reported once per
	// session, at ERROR: it denies.
	SurfaceOverflow SurfaceChangeKind = "overflow"
)

// maxSessionSurfaceEntries bounds one session's Tier-2 baseline.
//
// Tier-2 pins EVERY advertised tool and retains a removed tool's baseline, so the map is
// upstream-driven and grows across listings: a name-rotating server advertising fresh
// names each time adds a batch per tools/list, for the life of a long-lived stdio session
// or a slowly-reaped HTTP one. (The FM-5 map next to it cannot be flooded — it is keyed
// off the operator's pinnedTools — which is precisely the bound Tier-2 gave up by
// covering the tools nobody pinned.)
//
// At the ceiling the session fails closed, in the pin's own idiom: sticky-broken whole,
// one ERROR line. Not dropping entries — a dropped baseline is an UNPINNED tool, which is
// the fail-open direction — and not evicting the oldest, which an upstream could drive to
// evict exactly the tool it means to rewrite. 100k names is far past any real catalog.
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
// A nil *SurfaceBaseline is a working "pinning disabled" value — every method is a no-op
// returning the zero value — so a caller holding one never needs a nil branch.
//
// Safe for concurrent use: in HTTP mode one per-route ManifestPDP serves N sessions, each
// with its own upstream, and their tools/list responses arrive in parallel.
type SurfaceBaseline struct {
	mu       sync.RWMutex
	sessions map[string]*sessionSurface
}

// sessionSurface is one session's Tier-2 state. established distinguishes "this session
// has never seen a tools/list" from "it has, and this tool was not in it" — without it,
// the very first observation of every tool would be reported as an addition.
type sessionSurface struct {
	established bool
	hashes      map[string]string
	broken      map[string]struct{}
	// allBroken is the sticky whole-session break BreakAll sets: every tool in this
	// session is denied and hidden, whether or not it was ever baselined. A flag rather
	// than a sweep over hashes, because the tools BreakAll must cover are exactly the
	// ones a sweep cannot see — the not-yet-baselined ones on the response that
	// triggered it, and any the upstream advertises later.
	allBroken bool
	// overflowed marks that maxSessionSurfaceEntries was hit, so the ERROR line is
	// emitted once for the session rather than once per over-cap tool per listing.
	overflowed bool
	// reportedGone holds the baselined tools whose disappearance has already been
	// reported. A removal is a per-disappearance event; without this, a tool that
	// vanishes once logs on EVERY later listing, filling the stream that carries breaks.
	// A tool seen again is dropped from the set, so a second disappearance reports again.
	reportedGone map[string]struct{}
}

// NewSurfaceBaseline creates an empty Tier-2 baseline.
func NewSurfaceBaseline() *SurfaceBaseline {
	return &SurfaceBaseline{sessions: make(map[string]*sessionSurface)}
}

// Observe records this session's view of the advertised tool set and returns every
// Tier-2 finding it produced. The FIRST call for a session establishes the baseline and
// reports nothing; each later call compares against it.
//
// A changed surface is recorded as STICKY-broken: the mark is never cleared by a later
// clean observation, because an upstream that rotates a description back would otherwise
// re-open the call leg for a host still holding the poisoned copy. Recovery is a new
// session, not a re-list.
//
// sessionID may be empty (a direct caller with no session): the empty string is its own
// bucket rather than a skipped check, so an anonymous caller is still pinned. Sharing one
// bucket can only over-block, never under-block.
func (b *SurfaceBaseline) Observe(sessionID string, tools []ToolSurface, complete bool) []SurfaceChange {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.session(sessionID)

	// A PARTIAL view (one page of a paginated tools/list) can baseline and re-diff each
	// tool it contains — a surface change is per-tool and needs no knowledge of the rest —
	// but it says nothing about which tools exist. Only a complete listing establishes the
	// session's baseline for membership, and only a complete listing may report an
	// addition or a removal; a page otherwise reported every tool on the OTHER pages as
	// disappeared, on every pagination cycle, into the same stderr stream that carries
	// genuine break findings.
	//
	// The membership gate therefore needs a complete listing that is NOT the session's
	// first, which means more than one caller has to be able to supply one. Both do: the
	// session-start probe (which merges every page) establishes it, and any later host
	// tools/list the transport judges unpaginated is comparable against it. See
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
				// Fail closed for the session instead of baselining an unbounded set. The
				// tool is NOT recorded, so the map stops growing; allBroken is what keeps
				// that from meaning "unpinned". See maxSessionSurfaceEntries.
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
			// Sticky: mark before returning, so the call leg denies from here on even if
			// a later list re-advertises the baseline surface.
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
			if s.reportedGone == nil {
				s.reportedGone = make(map[string]struct{})
			}
			s.reportedGone[name] = struct{}{}
			changes = append(changes, SurfaceChange{Tool: name, Kind: SurfaceRemoved})
		}
	}
	return changes
}

// MarkBroken sticky-breaks the named tools in this session without a hash comparison,
// for a tools/list entry whose BYTES cannot be trusted to decode to what a host renders
// (a duplicate or case-variant key). Such an entry cannot be baselined — the proxy does
// not know which name or surface the host sees — so the fail-closed move is to deny every
// name it could be presenting, exactly as the FM-5 path sticky-poisons an entry's
// candidate pins. Marking a name that was never baselined is deliberate: the deny must
// hold whether or not the impersonated tool was in the baseline.
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

// BreakAll sticky-breaks EVERY tool in this session — baselined or not, now or later.
// Reserved for an ambiguity that taints a WHOLE tools/list response: an entry whose bytes
// aborted the trust scan before its name set was known, so the names it could be
// impersonating are UNKNOWN rather than none. Scoped to the session (Tier-2's whole state
// is), so recovery is a new session rather than a proxy restart.
//
// It sets a flag rather than sweeping the baseline map, because the tools it has to cover
// are the ones a sweep cannot see. On a session's FIRST tools/list the map is still empty
// — Observe baselines the clean entries only after this walk finishes — so a sweep broke
// nothing at all, and the remaining entries of the very response that could not be
// believed were then baselined clean and stayed callable. That is the case this exists
// for. The flag also covers tools a later listing adds, which is what "the impersonation
// set is unknown" means once the response naming them is untrustworthy.
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

// Broken reports whether a tool's Tier-2 pin has been broken in this session — because
// its advertised surface was observed to differ from the session's baseline, because an
// untrustworthy entry could have been impersonating it (MarkBroken), or because the whole
// session is broken (BreakAll, or a baseline overflow). Consulted on the tools/call leg (a
// hard deny) and by the tools/list filter (the tool is hidden), so the catalog a host is
// shown never contains a tool its call leg will reject.
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

// LogLine formats a Tier-2 finding as one structured stderr line, matching the shape
// internal/drift emits for FM-1..FM-6 (`[eunox] <LEVEL> drift=<kind> ...`) so an operator
// greps interface findings uniformly regardless of which layer detected them. A break is
// ERROR — it denies the tool — while an add/remove is WARN.
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

// quote renders a tool name with %q — real escaping, the way internal/drift's LogLines
// do. Concatenating bare quotes let an UPSTREAM-CONTROLLED tool name containing a quote
// and a newline forge additional lines on the operator's stderr channel: a hostile server
// could advertise a tool whose name closes the field and appends a benign-looking
// `drift=tier2` line, masking a real break in the one stream an operator greps for them.
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
		// Discarded explicitly. A failed write to the finding sink is not actionable from
		// the decision path — the enforcement it announces has already happened, and the
		// only alternative to dropping the notice would be failing the call over an
		// unwritable stderr. (internal/drift's equivalent writes to os.Stderr by name,
		// which errcheck exempts by default; this one goes through a variable so a test
		// can capture it, so the discard is written out.)
		_, _ = fmt.Fprintln(surfaceLog, c.LogLine())
	}
}

// sessionIDKey types the context value carrying the transport's session id into the
// PDP's list-filtering paths. Those cross the PolicyDecisionPoint/ListFilterer
// interfaces, which take (ctx, result) and no session — the same reason JWT claims ride
// the context (see WithJWTClaims). Tier-2's baseline is per-session, so the filter and
// the observe pass need the id the call leg already receives as a parameter.
type sessionIDKey struct{}

// WithSessionID returns a child context carrying the transport's session id, so the
// list-filtering and hash-observing paths can key per-session state. The transport
// attaches it on the */list path; the enforced Decide* paths take the session id as an
// explicit parameter and do not need it.
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

// declaredLabelsKey types the context value carrying a cooperating client's per-call flow
// attribution (the `io.eunolabs.context-manifest` block in the request's `_meta`) from the
// transport into the PDP. It rides the context for the same reason the session id does:
// the Decide* signatures take the target and its arguments, not the request envelope, and
// widening them for an optional, additive hint would push it onto every PDP
// implementation and test double.
type declaredLabelsKey struct{}

// WithDeclaredLabels returns a child context carrying a client's per-call flow
// attribution. The labels are UNIONED into the session's accumulated set for that call's
// sink check — never subtracted, and never written into session state. See
// capability/attribution.go for why the interface is one-directional.
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
// listing. Tier-2 reports tool additions and removals only for a complete listing: a
// single page cannot distinguish "this tool is gone" from "this tool is on another page",
// and reporting it anyway produced a false removal notice on every pagination cycle.
// Surface CHANGES are per-tool and are detected either way.
//
// Two callers mark it, and BOTH are needed for the membership findings to exist at all.
// The session-start drift probe fetches every page and concatenates them
// (drift.FetchAllToolPages), which establishes the baseline; the transport marks a HOST
// tools/list whose request carried no cursor and whose response carried no nextCursor
// (transport.completeToolsListing), which is what a later complete listing can be compared
// AGAINST. With only the probe marking, every complete observation was that session's
// first, so an addition or a removal had nothing to be a change from — and a route with no
// drift check configured (the probe is gated on one) never took a complete observation at
// all.
//
// The default (unmarked) is the conservative one: a paginated listing is treated as
// partial, which suppresses membership findings but never a break.
func WithCompleteToolListing(ctx context.Context) context.Context {
	return context.WithValue(ctx, completeListingKey{}, true)
}

// CompleteToolListingFromContext reports whether this observation covers the whole
// advertised surface. False unless a caller explicitly marked it with
// WithCompleteToolListing.
//
// Exported as the reader half of that setter so the layer that decides completeness —
// the transport, which is the only thing that can see a request's cursor and a response's
// nextCursor together — can assert what it marked. The membership findings this gates are
// advisory and logged, with no decision to observe, so without a reader the transport's
// half of the contract would be untestable at the boundary that implements it. That is
// precisely how it came to be wired such that the gate could never open.
func CompleteToolListingFromContext(ctx context.Context) bool {
	complete, _ := ctx.Value(completeListingKey{}).(bool)
	return complete
}
