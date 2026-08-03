// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Delegation attenuation is the other half of scoping authority to an identity. `principal`
// answers "which caller does this capability apply to"; this answers "what is left of that
// caller's authority after it hands work to a sub-agent". A delegate is not a second
// principal with its own grants — it is its delegator's authority MINUS something, and the
// minus is what has to be checkable.
//
// Two claims carry it, both on a token this proxy has already verified:
//
//   - `act`, the RFC 8693 §4.1 actor chain, nested most-recent-actor-outermost. It carries
//     WHO: `{"sub":"user","act":{"sub":"agent-b","act":{"sub":"agent-a"}}}` reads "agent-b,
//     which got this from agent-a, acting for user".
//   - `mcp.delegation`, an array of grants ordered delegator-first (agent-a, then agent-b),
//     one per hop. It carries WHAT each hop kept.
//
// Every grant NARROWS along a fixed direction per field:
//
//	targets       subset      — a delegate may reach fewer actions, never more
//	labels        superset    — a delegate's calls carry at least as much taint
//	allowLabels   subset      — a delegate may carry taint into fewer sinks
//	redactFields  superset    — a delegate sees at least as much redacted
//	maxEffectClass  no higher — a delegate may cause no more consequential an effect
//
// Three of the five are also ASSERTED at the token boundary (ValidateDelegationChain) rather
// than left to the minting side's care. A hop that moves one of those the other way is a
// WIDENING, and a widening token is rejected outright rather than clamped. Clamping would let a
// mis-minted (or forged-upstream) token keep working while quietly meaning something other than
// what it says, and the whole value of the chain is that "the delegate is no broader than its
// delegator" is a property someone can check rather than a convention someone follows. The
// other two — labels and redactFields — are unioned across hops by the decision path and so
// cannot widen at all; NarrowsFrom says why asserting them anyway was harmful.
//
// The assertion is not what the enforcement rests on, though — the decision path applies
// EVERY hop's grant, not just the last one. So even a chain whose monotonicity check was
// somehow skipped cannot let hop 3 reach what hop 1 forbade. The assertion exists to make a
// broken chain loud at the boundary; the per-hop application makes it harmless regardless.
//
// Nothing here can widen anything, which is why consuming these claims needs no experimental
// gate (unlike `mcp.capabilities`, which REPLACES the authorization surface and therefore
// fails open if a build ignores it). A token with no `act` and no `mcp.delegation` — that is,
// nearly every token — costs a nil check.
const (
	// ClaimActor is the RFC 8693 actor-chain claim name.
	ClaimActor = "act"
	// ClaimDelegation is the name of the per-hop grant array inside a validated token's
	// `mcp` object.
	ClaimDelegation = "delegation"
)

// MaxDelegationDepth bounds how many hops a chain may declare. A depth cap is required, not
// hygiene: the chain is attacker-influenced input that the decision path walks once per
// enforced call, and both the nested `act` decode and the per-hop application are linear in
// it. Eight is far above any real delegation topology (a planner handing to a researcher
// handing to a tool-runner is three) and far below anything that costs measurable time.
const MaxDelegationDepth = 8

// actorIdentityMembers are the `act` members this build admits without decoding: the ones an
// RFC 8693 IdP writes to say WHICH namespace the actor's `sub` belongs to. They are
// identity-descriptive and scope nothing, so ignoring them loses no narrowing — which is the
// bar for admitting a member at all. Anything else stays refused, because a member this build
// does not recognize may well be the one carrying the attenuation.
var actorIdentityMembers = []string{"iss", "client_id"}

// DelegationGrant is ONE hop's remaining authority: what the delegate at this depth kept of
// what its delegator held. Every field is optional except Subject, and an omitted field means
// "this hop narrowed nothing on this axis" — never "this hop granted everything", because a
// grant is applied on TOP of the manifest and every other hop, so silence removes nothing.
type DelegationGrant struct {
	// Subject is the identity this hop delegates TO, matching the `act` chain entry at the
	// same depth. Mandatory: a hop that names no delegate cannot be checked against the
	// actor chain, and an unattributable narrowing is not one an auditor can reconstruct.
	Subject string `json:"subject"`

	// Targets is the exhaustive set of actions this hop may reach, in manifest target
	// spelling ("tool:read_file"). Pointer to distinguish absent (nil — this hop places no
	// target restriction, deferring to the manifest and the other hops) from present-empty
	// (&[]string{} — this hop reaches NOTHING, the deny-all a quarantine mints). That is the
	// same absent/present-empty rule the mcp.capabilities claim uses, for the same reason:
	// the two must not collapse, because one of them is the strictest grant expressible.
	//
	// Entries are LITERAL and matched literally — a glob metacharacter is refused. An
	// approval-shaped grant that widens across every matching action is exactly what a
	// pattern in a scoped grant produces (the same reasoning that keeps a declassify
	// approval's target literal), and set containment between literal sets is a subset test
	// an operator can verify by reading, which a containment test between two glob languages
	// is not.
	Targets *[]string `json:"targets,omitempty"`

	// Labels are native flow labels every call this delegate makes carries, unioned into the
	// call's flow check. It is the taint side of a quarantine: a sub-agent reading arbitrary
	// web content is `untrusted` whatever the tool it calls says, so any sink that does not
	// permit `untrusted` denies it.
	//
	// They are used for the check only and never written into the anchor's accumulated set —
	// the delegate's own constitution, not something it deposits on the task for everyone
	// after it.
	Labels []string `json:"labels,omitempty"`

	// AllowLabels caps which flow labels this delegate may carry INTO a sink: the effective
	// allow-set at any flowLabel condition is the manifest's Allow intersected with every
	// hop's AllowLabels. Pointer for the same absent/present-empty distinction Targets
	// draws, and present-empty is the load-bearing value — it is the full quarantine, where
	// no labeled flow reaches any sink at all, so a fully-injected sub-agent sharing a
	// tainted task can reach nothing regardless of which tool it is tricked into calling.
	AllowLabels *[]string `json:"allowLabels,omitempty"`

	// RedactFields are field paths masked from every response this delegate receives, unioned
	// with the matched constraint's own redactFields. A hop composes redaction rather than
	// re-authoring it: a delegator that masks `ssn` cannot have a delegate that does not.
	RedactFields []string `json:"redactFields,omitempty"`

	// MaxEffectClass caps the reversibility class this delegate may cause. It composes with
	// the policy's effectCeiling by being checked alongside it, and unlike the ceiling an
	// over-class call here is a DENY rather than an escalation: the ceiling asks a human
	// about a consequence the policy permits, while this is a delegate exceeding the
	// authority it was handed, which no approval on this path is scoped to grant.
	MaxEffectClass string `json:"maxEffectClass,omitempty"`
}

// DelegationChain is a verified token's delegation state: the actor identities from `act`
// and the per-hop grants from `mcp.delegation`, both ordered DELEGATOR-FIRST (the reverse of
// `act`'s most-recent-outermost nesting, so index 0 is the earliest actor in both).
type DelegationChain struct {
	// Actors are the `act` chain subjects, delegator-first. Empty when the token carries no
	// act claim.
	Actors []string
	// Grants are the per-hop grants, delegator-first. Empty when the token carries no
	// mcp.delegation claim.
	Grants []DelegationGrant

	// The four derived views the decision path reads, computed ONCE by
	// ValidateDelegationChain and never written again. A chain is built at token validation
	// and is immutable and shared read-only across every request on that token, so rebuilding
	// these per call was pure repeated work — and not trivial work: each allocated a map and a
	// sorted slice, and handleFlowLabel reads two of them once per flowLabel condition, so an
	// eight-hop chain paid dozens of identical map builds on every decision.
	//
	// This is the same memoize-at-validation pattern JWTClaims already uses for its parsed
	// capability heads and its flattened claims map, and it is safe for the same reason: the
	// value is finished before any request can observe it, so no reader ever races a write.
	// A chain built by a struct literal (in tests) has none of them; every accessor falls back
	// to computing on the fly and never stores, so a literal-built chain behaves identically.
	memo *delegationMemo
	// targetIndex is the per-hop target sets PermitsTarget tests against, so a catalog filter
	// is O(1) per entry per hop instead of a linear scan of every hop's list. nil for a
	// literal-built chain, where PermitsTarget falls back to scanning.
	targetIndex []map[string]struct{}
}

// delegationMemo holds the precomputed views. A pointer so the zero DelegationChain (and any
// struct-literal one) is plainly "not memoized" rather than "memoized to empty".
type delegationMemo struct {
	forcedLabels   []string
	allowLabels    []string
	allowCapped    bool
	redactFields   []string
	effectClass    string
	effectSubject  string
	effectClassSet bool
}

// memoize computes the derived views once. Called only from ValidateDelegationChain, before
// the chain is published to any reader.
func (c *DelegationChain) memoize() {
	c.targetIndex = make([]map[string]struct{}, len(c.Grants))
	for i := range c.Grants {
		if c.Grants[i].Targets == nil {
			continue
		}
		set := make(map[string]struct{}, len(*c.Grants[i].Targets))
		for _, t := range *c.Grants[i].Targets {
			set[t] = struct{}{}
		}
		c.targetIndex[i] = set
	}
	m := &delegationMemo{}
	m.forcedLabels = c.computeForcedLabels()
	m.allowLabels, m.allowCapped = c.computeAllowedLabelCap()
	m.redactFields = c.computeRedactFields()
	m.effectClass, m.effectSubject, m.effectClassSet = c.computeEffectClassCap()
	c.memo = m
}

// IsEmpty reports whether the token carried no delegation state at all — the overwhelmingly
// common case, which every consumer short-circuits on.
func (c *DelegationChain) IsEmpty() bool {
	return c == nil || (len(c.Actors) == 0 && len(c.Grants) == 0)
}

// Delegate returns the identity the token is currently held by: the last actor in the chain
// (delegator-first order, so the most recent actor is last), or "" when the token carries no
// actor chain.
//
// It is the RFC 8693 reading of the chain in one place — "the outermost `act` is who holds
// this now" — for a caller that needs to attribute or log a delegated call. eunox does not
// currently stamp it on the audit record: a delegated ALLOW is recorded under the token's
// `sub` like any other, and only a delegation REFUSAL names a hop (the one that blocked it, in
// the denial's details). Adding it to the tape means a new top-level signed field and the
// threat-model entry that goes with it, which is a deliberate change rather than a side
// effect of this accessor existing.
func (c *DelegationChain) Delegate() string {
	if c == nil || len(c.Actors) == 0 {
		return ""
	}
	return c.Actors[len(c.Actors)-1]
}

// PermitsTarget reports whether every hop's grant admits target (canonical "<type>:<bare>"
// spelling), and names the first hop that does not.
//
// It applies EVERY hop rather than only the most attenuated one. Given the monotonicity
// assertion the two are equivalent, which is the point: the check that enforces and the check
// that asserts are independent, so neither being wrong makes the other unsound. A hop with no
// Targets restriction admits everything; a hop with a present-empty one admits nothing.
func (c *DelegationChain) PermitsTarget(target string) (ok bool, blockedBy string) {
	if c == nil {
		return true, ""
	}
	for i := range c.Grants {
		g := &c.Grants[i]
		if g.Targets == nil {
			continue
		}
		// The precomputed set when the chain came through validation (every production
		// chain), a linear scan for a struct-literal one. The index matters because this runs
		// per CATALOG ENTRY in the list filters: a 200-entry catalog behind an eight-hop chain
		// was up to 200x8x|targets| string comparisons on every tools/list, three times over
		// for the three list flavors.
		if i < len(c.targetIndex) && c.targetIndex[i] != nil {
			if _, ok := c.targetIndex[i][target]; !ok {
				return false, g.Subject
			}
			continue
		}
		if !slices.Contains(*g.Targets, target) {
			return false, g.Subject
		}
	}
	return true, ""
}

// computeForcedLabels does the work ForcedLabels memoizes. The CONTRACT is stated on the
// exported accessor; copying it here named the wrong function and left two statements of one
// rule to drift apart.
func (c *DelegationChain) computeForcedLabels() []string {
	if c == nil {
		return nil
	}
	var all []string
	for i := range c.Grants {
		all = append(all, c.Grants[i].Labels...)
	}
	if len(all) == 0 {
		return nil
	}
	return NormalizeDeclaredLabels(all)
}

// computeAllowedLabelCap does the work AllowedLabelCap memoizes; the contract is on the
// exported accessor.
func (c *DelegationChain) computeAllowedLabelCap() (allowed []string, capped bool) {
	if c == nil {
		return nil, false
	}
	var acc map[string]bool
	for i := range c.Grants {
		g := &c.Grants[i]
		if g.AllowLabels == nil {
			continue
		}
		hop := make(map[string]bool, len(*g.AllowLabels))
		for _, l := range *g.AllowLabels {
			hop[l] = true
		}
		if !capped {
			acc, capped = hop, true
			continue
		}
		for l := range acc {
			if !hop[l] {
				delete(acc, l)
			}
		}
	}
	if !capped || len(acc) == 0 {
		return nil, capped
	}
	keys := make([]string, 0, len(acc))
	for l := range acc {
		keys = append(keys, l)
	}
	// NormalizeDeclaredLabels is the ONE renderer of a label set in canonical vocabulary
	// order, shared with the attribution path and ForcedLabels above. A third hand-rolled copy
	// of that loop would be a third place to update when the vocabulary grows, and this one
	// decides which labels a delegated call may carry into a sink — a divergence there is a
	// silent change in what is permitted, not a compile error.
	return NormalizeDeclaredLabels(keys), true
}

// computeRedactFields does the work RedactFields memoizes; the contract is on the exported
// accessor.
func (c *DelegationChain) computeRedactFields() []string {
	if c == nil {
		return nil
	}
	set := map[string]bool{}
	for i := range c.Grants {
		for _, f := range c.Grants[i].RedactFields {
			set[f] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// computeEffectClassCap does the work EffectClassCap memoizes; the contract is on the
// exported accessor.
func (c *DelegationChain) computeEffectClassCap() (class, subject string, ok bool) {
	if c == nil {
		return "", "", false
	}
	for i := range c.Grants {
		g := &c.Grants[i]
		if g.MaxEffectClass == "" {
			continue
		}
		if !ok || !EffectClassAtMost(class, g.MaxEffectClass) {
			class, subject, ok = g.MaxEffectClass, g.Subject, true
		}
	}
	return class, subject, ok
}

// ForcedLabels returns the union of every hop's Labels, in canonical vocabulary order. These
// are unioned into a call's flow check — never into the anchor's stored set.
func (c *DelegationChain) ForcedLabels() []string {
	if c == nil {
		return nil
	}
	if c.memo != nil {
		return c.memo.forcedLabels
	}
	return c.computeForcedLabels()
}

// AllowedLabelCap returns the intersection of every hop's AllowLabels, and whether any hop
// declared one. A nil-with-true result is the full quarantine (no labeled flow reaches any
// sink); false means no hop capped the sink allow-set and the manifest's own Allow stands
// unmodified.
func (c *DelegationChain) AllowedLabelCap() (allowed []string, capped bool) {
	if c == nil {
		return nil, false
	}
	if c.memo != nil {
		return c.memo.allowLabels, c.memo.allowCapped
	}
	return c.computeAllowedLabelCap()
}

// RedactFields returns the union of every hop's RedactFields, sorted for a deterministic
// obligation. Composing rather than replacing is the narrowing direction: a delegate sees at
// least as much masked as its delegator did.
func (c *DelegationChain) RedactFields() []string {
	if c == nil {
		return nil
	}
	if c.memo != nil {
		return c.memo.redactFields
	}
	return c.computeRedactFields()
}

// EffectClassCap returns the most restrictive MaxEffectClass any hop declared, and the hop
// that declared it. ok is false when no hop capped the class.
func (c *DelegationChain) EffectClassCap() (class, subject string, ok bool) {
	if c == nil {
		return "", "", false
	}
	if c.memo != nil {
		return c.memo.effectClass, c.memo.effectSubject, c.memo.effectClassSet
	}
	return c.computeEffectClassCap()
}

// Validate checks one grant in isolation: the fields it declares must be ones this build can
// enforce as written. Every failure is an error the caller turns into a rejected TOKEN, for
// the reason every other claim-borne grant in this package is validated at the boundary — a
// grant that quietly evaluated to "restricts nothing" would turn an IdP template mistake into
// an invisible loss of the narrowing an operator believes is in force.
func (g *DelegationGrant) Validate() error {
	if g == nil {
		return fmt.Errorf("delegation grant is null")
	}
	if strings.TrimSpace(g.Subject) == "" {
		return fmt.Errorf("delegation grant must name the delegate it applies to in 'subject'")
	}
	if g.Targets != nil {
		for _, t := range *g.Targets {
			t = strings.TrimSpace(t)
			if t == "" {
				return fmt.Errorf("delegation grant for %q has an empty entry in 'targets'", g.Subject)
			}
			// Only '*' is refused, and only because it is the character an author writes
			// when they MEAN a pattern. Delegated targets are matched literally, so no
			// metacharacter can widen anything — which is exactly why refusing the full
			// GlobMetaChars set was wrong: it made a resource URI carrying a query string
			// ("resource:https://api.example.com/search?q=x") or a Windows path unexpressible,
			// and because a malformed grant rejects the TOKEN, one such target refused every
			// request the caller made rather than the one resource it named.
			if strings.Contains(t, "*") {
				return fmt.Errorf("delegation grant for %q: target %q contains '*'; a delegated target is matched literally, so a pattern would silently grant nothing rather than the set of actions it appears to name — list the actions explicitly", g.Subject, t)
			}
			if _, _, err := ParseTarget(t); err != nil {
				return fmt.Errorf("delegation grant for %q: %w", g.Subject, err)
			}
		}
	}
	for _, l := range g.Labels {
		if !IsFlowLabel(l) {
			return fmt.Errorf("delegation grant for %q: 'labels' contains unknown flow label %q; valid native labels are %v", g.Subject, l, FlowLabelVocabulary())
		}
	}
	if g.AllowLabels != nil {
		for _, l := range *g.AllowLabels {
			if !IsFlowLabel(l) {
				return fmt.Errorf("delegation grant for %q: 'allowLabels' contains unknown flow label %q; valid native labels are %v", g.Subject, l, FlowLabelVocabulary())
			}
		}
	}
	for _, f := range g.RedactFields {
		if strings.TrimSpace(f) == "" {
			return fmt.Errorf("delegation grant for %q has an empty entry in 'redactFields'", g.Subject)
		}
	}
	if g.MaxEffectClass != "" && !IsEffectClass(g.MaxEffectClass) {
		return fmt.Errorf("delegation grant for %q: maxEffectClass %q is not one of %v", g.Subject, g.MaxEffectClass, EffectClassVocabulary())
	}
	return nil
}

// NarrowsFrom reports whether g is no broader than prior on every axis, naming the axis and
// the offending value when it is not. It is the monotonicity assertion, and it is written as
// a per-axis check rather than a single "is a subset" because each axis narrows in its OWN
// direction — targets and allowLabels shrink, labels and redactFields grow — and a reader has
// to be able to see that each direction was chosen deliberately.
//
// A field the delegator left unset bounds nothing, so a delegate setting one is a narrowing
// (there is nothing to compare against and nothing was widened). A field the delegate leaves
// unset likewise removes nothing: the delegator's grant is applied at decision time in its own
// right, so an omitted field cannot escape it.
//
// Only THREE of the five axes are asserted here, and the split is not an oversight. An axis is
// checkable at the boundary when a hop's value reads as a CLAIM OF AUTHORITY — targets ("I may
// reach these"), allowLabels ("I may carry taint into these sinks"), maxEffectClass ("I may
// cause up to this") — where declaring more than the delegator held is visible nonsense worth
// being loud about even though the decision path refuses it anyway.
//
// labels and redactFields are the other kind: a hop declaring them imposes something on ITSELF,
// and the decision path UNIONS them across every hop. A hop that names a different taint than
// its delegator adds to it; a hop that names none inherits its delegator's untouched. Neither
// can widen, by construction — so there is nothing at the boundary to assert, and asserting it
// anyway did real damage: it demanded every hop restate every ancestor's labels and redactions,
// and a chain that did not (which is the ordinary way these are minted, since the union makes
// restating pointless) was reported as a widening and REJECTED THE TOKEN. A monotonicity check
// that denies a monotone chain is worse than no check on that axis.
func (g *DelegationGrant) NarrowsFrom(prior *DelegationGrant) error {
	if g == nil {
		// Every other method in this package guards its receiver; this one is reached with a
		// slice element in-tree, so the guard is defense in depth rather than a live path —
		// but an API whose neighbours are all nil-safe must not have the one member that
		// panics.
		return fmt.Errorf("delegation grant is null")
	}
	if prior == nil {
		return nil
	}
	if prior.Targets != nil && g.Targets != nil {
		allowed := make(map[string]bool, len(*prior.Targets))
		for _, t := range *prior.Targets {
			allowed[t] = true
		}
		for _, t := range *g.Targets {
			if !allowed[t] {
				return fmt.Errorf("hop %q reaches target %q, which its delegator %q does not hold; a delegate cannot be granted authority its delegator lacks", g.Subject, t, prior.Subject)
			}
		}
	}
	if prior.AllowLabels != nil && g.AllowLabels != nil {
		allowed := make(map[string]bool, len(*prior.AllowLabels))
		for _, l := range *prior.AllowLabels {
			allowed[l] = true
		}
		for _, l := range *g.AllowLabels {
			if !allowed[l] {
				return fmt.Errorf("hop %q admits flow label %q at a sink, which its delegator %q does not; a delegate cannot carry taint anywhere its delegator cannot", g.Subject, l, prior.Subject)
			}
		}
	}
	if prior.MaxEffectClass != "" && g.MaxEffectClass != "" && !EffectClassAtMost(g.MaxEffectClass, prior.MaxEffectClass) {
		return fmt.Errorf("hop %q caps effect class at %q, above its delegator %q's cap of %q", g.Subject, g.MaxEffectClass, prior.Subject, prior.MaxEffectClass)
	}
	return nil
}

// tightenedBy folds one hop into the running floor the next hop is compared against: the
// narrowest value seen so far on each axis, in that axis's own direction. It is the
// accumulator ValidateDelegationChain walks the chain with, so a hop that omits an axis
// carries the previous constraint forward rather than erasing it.
//
// It is deliberately NOT the effective grant the decision path applies — that stays "every hop
// applies", so the enforcement does not depend on this fold being right. This only decides
// what a later hop is measured against.
// It folds only the three axes NarrowsFrom asserts. labels and redactFields are unioned by the
// decision path across every hop and cannot widen (see NarrowsFrom), so accumulating them into
// a floor nobody compares against was work with no reader.
func (g *DelegationGrant) tightenedBy(next *DelegationGrant) *DelegationGrant {
	out := *g
	out.Subject = next.Subject
	if next.Targets != nil {
		out.Targets = next.Targets
	}
	if next.AllowLabels != nil {
		out.AllowLabels = next.AllowLabels
	}
	if next.MaxEffectClass != "" && (out.MaxEffectClass == "" || EffectClassAtMost(next.MaxEffectClass, out.MaxEffectClass)) {
		out.MaxEffectClass = next.MaxEffectClass
	}
	return &out
}

// ParseActorChain decodes the RFC 8693 `act` claim into subjects ordered DELEGATOR-FIRST.
// raw is the claim as it came off a verified token; absent or JSON null yields (nil, nil).
//
// RFC 8693 §4.1 nests the chain most-recent-actor-OUTERMOST, so this reverses it: index 0 is
// the earliest actor, which is the order a narrowing chain is read and compared in. Getting
// that backwards would compare each hop against its own delegate and report every correct
// chain as a widening.
//
// A malformed chain is an error, never a silently-truncated one: a chain this build cannot
// read is a token making a delegation claim it cannot honor.
func ParseActorChain(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	type actNode struct {
		Sub string          `json:"sub"`
		Act json.RawMessage `json:"act,omitempty"`
	}
	var outermost []string
	cur := raw
	for depth := 0; len(cur) > 0 && string(cur) != "null"; depth++ {
		if depth >= MaxDelegationDepth {
			return nil, fmt.Errorf("%s claim nests more than %d actors; refusing to walk an unbounded delegation chain", ClaimActor, MaxDelegationDepth)
		}
		var node actNode
		// Strict, exactly as the grant decoder is: an IdP template that misspells "act" as
		// "acts" would otherwise TRUNCATE the chain silently, and with an act-only token
		// nothing downstream detects it — the hop-for-hop agreement check is skipped when
		// there are no grants, and Delegate() then names the wrong actor.
		//
		// Strict does NOT mean sub-and-act-only. RFC 8693 §4.1 defines an `act` value as a set
		// of claims identifying the actor, and a token-exchange IdP routinely writes the actor's
		// issuer beside its subject to say WHICH namespace that subject belongs to. Refusing
		// those made every request on such a token deny — an outage produced by a member that
		// scopes nothing this build applies. They are admitted by name rather than by admitting
		// unknown members generally, so a misspelling is still refused.
		if err := decodeClaimObject(cur, &node, fmt.Sprintf("%s claim at depth %d", ClaimActor, depth), actorIdentityMembers...); err != nil {
			return nil, err
		}
		sub := strings.TrimSpace(node.Sub)
		if sub == "" {
			return nil, fmt.Errorf("%s claim at depth %d carries no 'sub'; an actor with no identity cannot be attributed or scoped", ClaimActor, depth)
		}
		outermost = append(outermost, sub)
		cur = node.Act
	}
	// Reverse into delegator-first order.
	out := make([]string, len(outermost))
	for i, s := range outermost {
		out[len(outermost)-1-i] = s
	}
	return out, nil
}

// ParseDelegationGrants decodes the `mcp.delegation` claim into validated grants,
// delegator-first (the order the claim is authored in). Absent or null yields (nil, nil).
//
// Unknown fields are rejected for the reason every other claim decoder in this package
// rejects them: a misspelled "targts" would decode to a grant with NO target restriction —
// a narrowing that silently is not one.
func ParseDelegationGrants(raw json.RawMessage) ([]DelegationGrant, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return nil, fmt.Errorf("mcp.%s claim must be an array of delegation grants: %w", ClaimDelegation, err)
	}
	if len(msgs) == 0 {
		// A present-empty array is NOT the same as an absent claim, and the two must not
		// collapse — the same absent/present-empty rule Targets and AllowLabels draw, for the
		// same reason. Absent means "this token makes no delegation-grant statement", which is
		// the supported act-only shape; present-empty means "zero hops", which DISAGREES with
		// an act chain that names any. Returning a non-nil zero-length slice is what lets
		// ValidateDelegationChain tell them apart and refuse the second.
		return []DelegationGrant{}, nil
	}
	if len(msgs) > MaxDelegationDepth {
		return nil, fmt.Errorf("mcp.%s declares %d hops, more than the maximum of %d", ClaimDelegation, len(msgs), MaxDelegationDepth)
	}
	out := make([]DelegationGrant, 0, len(msgs))
	for i, m := range msgs {
		var g DelegationGrant
		if err := decodeClaimObject(m, &g, fmt.Sprintf("mcp.%s grant %d", ClaimDelegation, i)); err != nil {
			return nil, err
		}
		g.Subject = strings.TrimSpace(g.Subject)
		g.Targets = trimmedListPtr(g.Targets)
		g.RedactFields = trimmedList(g.RedactFields)
		if err := g.Validate(); err != nil {
			return nil, fmt.Errorf("mcp.%s grant %d: %w", ClaimDelegation, i, err)
		}
		out = append(out, g)
	}
	return out, nil
}

// ValidateDelegationChain is the whole token-boundary check on a decoded chain: the grants
// must line up with the actor chain, and each hop must narrow its delegator. It returns the
// assembled chain or an error the caller turns into a rejected token.
//
// Grants without an actor chain are accepted (an IdP that does not emit RFC 8693 `act` can
// still express attenuation, and a grant can only narrow), but an actor chain and a grant
// list that DISAGREE are refused. A mismatch means the token's two halves describe different
// delegations, and picking either one would be guessing which of them the control plane meant.
//
// grants distinguishes NIL (the claim was absent — the act-only shape, where the chain carries
// identities and states no narrowing) from PRESENT-EMPTY (the claim declared zero hops, which
// disagrees with an act chain naming any). Collapsing the two made `"delegation": []` beside a
// correct act chain the one mis-mint that passed silently, and it is the likeliest one an IdP
// template produces.
func ValidateDelegationChain(actors []string, grants []DelegationGrant) (*DelegationChain, error) {
	if len(actors) == 0 && len(grants) == 0 {
		return nil, nil
	}
	if len(actors) > MaxDelegationDepth {
		return nil, fmt.Errorf("%s claim declares %d actors, more than the maximum of %d", ClaimActor, len(actors), MaxDelegationDepth)
	}
	if len(actors) > 0 && grants != nil {
		if len(actors) != len(grants) {
			return nil, fmt.Errorf("token declares %d actor(s) in %s but %d delegation grant(s) in mcp.%s; the two describe the same chain and must agree hop for hop", len(actors), ClaimActor, len(grants), ClaimDelegation)
		}
		for i := range grants {
			if grants[i].Subject != actors[i] {
				return nil, fmt.Errorf("delegation grant %d applies to %q but the %s chain names %q at that hop; a grant must scope the actor it sits beside", i, grants[i].Subject, ClaimActor, actors[i])
			}
		}
	}
	// Each hop is compared against the ACCUMULATED narrowest of everything before it, not
	// merely against its immediate predecessor. Pairwise comparison is vacuous the moment an
	// intervening hop omits an axis: with grants [{targets:[x]}, {}, {targets:[x, wipe_db]}]
	// both adjacent checks skip the targets axis (one side is absent each time) and the chain
	// is accepted, though hop 3 declares authority hop 1 never held. The decision path applies
	// every hop, so that chain is still refused at wipe_db — but the boundary check exists
	// precisely to make a mis-minted chain LOUD, and a check that stays silent on the shape it
	// was written for is not one.
	// len(grants) may be 0 — an `act`-only token expresses the chain's identities and no
	// narrowing at all, which is well-formed. Indexing grants[0] unconditionally panicked on
	// exactly that shape.
	var floor DelegationGrant
	for i := 1; i < len(grants); i++ {
		if i == 1 {
			floor = grants[0]
		}
		if err := grants[i].NarrowsFrom(&floor); err != nil {
			return nil, fmt.Errorf("delegation chain widens at hop %d: %w", i, err)
		}
		floor = *floor.tightenedBy(&grants[i])
	}
	chain := &DelegationChain{Actors: actors, Grants: grants}
	chain.memoize()
	return chain, nil
}

// trimEach returns a copy of list with each entry space-trimmed, so a padded claim value
// compares equal to the manifest spelling it names. Always non-nil, so each caller applies its
// OWN empty-list policy — which is the one thing that differs between the two below, and the
// one thing that must not be shared.
func trimEach(list []string) []string {
	out := make([]string, len(list))
	for i, v := range list {
		out[i] = strings.TrimSpace(v)
	}
	return out
}

// trimmedList collapses an empty input to nil: for the slice-valued fields, empty and absent
// mean the same thing.
func trimmedList(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	return trimEach(list)
}

// trimmedListPtr preserves the absent(nil)/present-empty distinction the pointer-valued fields
// depend on: a present-empty list must stay present-empty (it is the deny-all grant), never
// collapse to nil (which means unrestricted).
func trimmedListPtr(list *[]string) *[]string {
	if list == nil {
		return nil
	}
	out := trimEach(*list)
	return &out
}
