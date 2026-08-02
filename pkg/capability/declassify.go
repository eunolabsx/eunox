// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// DirectiveTypeDeclassify is the discriminator for declassify directives — the
// approval-gated half of information-flow control, and the ONLY token in the grammar
// that removes a flow label.
const DirectiveTypeDeclassify = "declassify"

// ClaimDeclassify is the name of the approval-grant claim inside a validated token's
// `mcp` object. Its value is the array a DeclassifyApproval decodes from.
const ClaimDeclassify = "declassify"

// DeclassifyDirective clears the named native flow Labels from the session's accumulated
// set on an ALLOWED call — but only when the request carries a human approval covering
// them. It is the declassification path: policy states WHERE a label may be dropped,
// and an approval states that a human agreed to drop it HERE.
//
// It is the mirror of labelOutput and the only fail-OPEN direction in the flow layer.
// labelOutput adds taint, and adding taint can only ever produce more denials; clearing
// it can only ever produce more allows. That asymmetry is why declassify is not simply
// "labelOutput with a minus sign":
//
//   - An unapproved call carrying this directive is NOT allowed-without-declassifying.
//     Forwarding it while silently leaving the labels in place would let an author write
//     a declassification the proxy never performs, and the next sink would deny for a
//     reason the policy says should not apply — a policy that reads as broken rather than
//     as enforced. It escalates instead (ESCALATION_REQUIRED), which is the fail-closed
//     reading of "a human has not approved this yet".
//   - The escalation is a HARD refusal with AuditOnly unset, exactly as the effect
//     ceiling's is: a route running --audit downgrades a policy verdict being staged, and
//     "no human has approved dropping this label" is not a verdict being staged. The one
//     downgrade that would defeat the control entirely is the one that must not exist.
//   - An approval must cover EVERY label named here. A partial grant escalates rather
//     than clearing the covered subset: the directive is what the policy says must be
//     cleared for the call to make sense, and half-clearing it leaves the operator
//     believing a label is gone while a later sink still sees it.
//
// Labels are drawn from the closed native vocabulary; an unknown one is a load error.
// The directive carries no response obligation — like labelOutput, its effect is the
// engine's per-session state write — so it is valid on any target a declassification can
// sit at.
type DeclassifyDirective struct {
	Labels []string `json:"labels"`
}

// DirectiveType returns the declassify discriminator.
func (DeclassifyDirective) DirectiveType() string { return DirectiveTypeDeclassify }

// ToObligation is required by the Directive interface. declassify carries no response
// obligation — its effect is the engine's session-state write — so the engine skips it
// before this would be emitted (see collectObligations), exactly as it does for
// labelOutput. The declassify-typed sentinel returned here is never marshaled onto a
// response, so it carries no payload and Obligation gains no declassify case.
func (d DeclassifyDirective) ToObligation() Obligation {
	return Obligation{Type: DirectiveTypeDeclassify}
}

// IsDeclassifyDirective reports whether d is a declassify directive (value or pointer
// form). Single-sourced alongside IsLabelOutputDirective so the engine's allow-tail gate
// and the config-level multi-instance advisory cannot drift on what counts as flow.
// Nil-safe.
func IsDeclassifyDirective(d Directive) bool {
	_, ok := AsValueOrPointer[DeclassifyDirective](d)
	return ok
}

// DeclassifyLabelsOf returns the labels the constraint's declassify directive clears, in
// canonical vocabulary order, or nil when it carries none. A typed-nil directive
// contributes nothing rather than panicking. Two declassify directives on one constraint
// are rejected at load, so in practice this returns at most one directive's labels; the
// union is taken anyway so a programmatically built constraint cannot silently drop one.
func DeclassifyLabelsOf(c *Constraint) []string {
	if c == nil {
		return nil
	}
	set := map[string]bool{}
	for _, dir := range c.Directives {
		d, ok := AsValueOrPointer[DeclassifyDirective](dir)
		if !ok || d == nil {
			continue
		}
		for _, l := range d.Labels {
			set[l] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for _, l := range flowLabelVocabulary {
		if set[l] {
			out = append(out, l)
		}
	}
	// A label outside the closed vocabulary cannot appear here on a loaded manifest
	// (validation rejects it) but can on a programmatically built constraint. Append it
	// rather than dropping it: the engine's own check errors on an unknown label, and a
	// silently dropped one would shrink what the caller asked to clear.
	if len(out) != len(set) {
		var extra []string
		for l := range set {
			if !flowLabelSet[l] {
				extra = append(extra, l)
			}
		}
		sort.Strings(extra)
		out = append(out, extra...)
	}
	return out
}

// DeclassifyApproval is ONE human approval to drop flow labels at one action, carried in
// the `mcp.declassify` claim of a token this proxy has already verified (signature,
// issuer, audience, expiry). It is evidence, not a decision: the proxy verifies and
// scopes it, the control plane mints it after a human acts.
//
// The claim is the carrier because it is the only approval channel that is already
// operator-controlled end to end. eunox consumes IdP tokens and never mints them, and the
// JWKS it validates against is configured by the operator — so an approval riding a
// verified token needs no new key domain, no new trust root, and no fetch on the decision
// path. (This is the same reasoning that blocked effect receipts until an operator-owned
// key domain existed: a signature is only worth what the key domain behind it is.)
//
// The honest limit, which the docs state rather than hide: the token is held by the agent,
// so an approval minted into it can be replayed for as long as that token lives, at any
// action the grant's Target names. That is why Target is matched LITERALLY and Approver is
// mandatory, and why the operator's control plane should mint a short-lived token per
// approval rather than a standing grant. The proxy enforces scope and records the
// approver; it cannot make a long-lived grant safe.
type DeclassifyApproval struct {
	// Labels are the native flow labels this approval permits dropping. Non-empty; every
	// entry must be in the closed vocabulary.
	Labels []string `json:"labels"`
	// Target is the ONE action this approval covers, in manifest target spelling
	// ("tool:publish_report"). It is matched LITERALLY against the request's canonical
	// target, never as a glob: a glob in an approval fails OPEN (it widens what a single
	// human approval covers), which is the opposite of how a glob fails in a policy
	// allowlist. A grant carrying a glob metacharacter is refused.
	Target string `json:"target"`
	// Approver identifies the human who approved. Mandatory: an approval with no
	// accountable human is not human approval, and it is the value stamped on the tape
	// (the `approver` audit field) that makes the record answerable later.
	Approver string `json:"approver"`
	// ID optionally carries the control plane's own record identifier for this approval,
	// echoed into the audit record's details so a tape entry joins back to the approval
	// workflow that produced it. Absent is fine; empty and absent are the same.
	ID string `json:"id,omitempty"`
}

// Covers reports whether this approval authorizes clearing every label in want at target.
// It is the whole authorization test, kept in one place so the engine cannot implement a
// looser version of it: the target must match literally and the label set must be a
// SUPERSET of what the directive clears.
//
// target is the request's canonical "<type>:<bare>" spelling. A malformed or empty
// approval never covers anything — Validate rejects those at the token boundary, and this
// stays independently fail-closed for a programmatically built approval.
func (a *DeclassifyApproval) Covers(target string, want []string) bool {
	if a == nil || a.Approver == "" || a.Target == "" || len(a.Labels) == 0 || len(want) == 0 {
		return false
	}
	if a.Target != target {
		return false
	}
	granted := make(map[string]bool, len(a.Labels))
	for _, l := range a.Labels {
		granted[l] = true
	}
	for _, l := range want {
		if !granted[l] {
			return false
		}
	}
	return true
}

// Validate fails closed on an approval that cannot be enforced as written. It runs at the
// token boundary (see ParseDeclassifyApprovals), so a malformed grant is a rejected TOKEN
// rather than a grant that silently covers nothing — the same posture the experimental
// mcp.capabilities claim takes. A grant that quietly evaluated to "covers nothing" would
// turn an IdP misconfiguration into a permanent, invisible escalation loop.
func (a *DeclassifyApproval) Validate() error {
	if a == nil {
		return fmt.Errorf("declassify approval is null")
	}
	if len(a.Labels) == 0 {
		return fmt.Errorf("declassify approval must name at least one label in 'labels'")
	}
	for _, l := range a.Labels {
		if !IsFlowLabel(l) {
			return fmt.Errorf("declassify approval 'labels' contains unknown flow label %q; valid native labels are %v", l, flowLabelVocabulary)
		}
	}
	target := strings.TrimSpace(a.Target)
	if target == "" {
		return fmt.Errorf("declassify approval must name the action it covers in 'target'")
	}
	if ContainsGlobMeta(target) {
		return fmt.Errorf("declassify approval target %q contains a glob metacharacter (%s); an approval target is matched literally, so a pattern would widen one human approval across every matching action", target, GlobMetaChars)
	}
	if _, _, err := ParseTarget(target); err != nil {
		return fmt.Errorf("declassify approval target: %w", err)
	}
	if strings.TrimSpace(a.Approver) == "" {
		return fmt.Errorf("declassify approval must name the human who approved it in 'approver'")
	}
	return nil
}

// ParseDeclassifyApprovals decodes the `mcp.declassify` claim value into validated
// approvals. raw is the value as it came off a verified token (a []interface{} of
// objects); nil or absent yields (nil, nil), which is the overwhelmingly common case and
// costs nothing.
//
// Every failure is an ERROR, never a silently-dropped grant: an unparseable or invalid
// approval means the token says something about declassification this build cannot
// enforce, and the caller rejects the token. Decoding is strict about unknown fields for
// the same reason the manifest decoders are — a misspelled "lables" would decode to an
// EMPTY label set, i.e. a grant that covers nothing while looking like it covers
// something.
func ParseDeclassifyApprovals(raw interface{}) ([]DeclassifyApproval, error) {
	if raw == nil {
		return nil, nil
	}
	// Round-trip through JSON rather than type-asserting the generic map: the claim
	// arrives as whatever encoding/json produced for an `any`, and re-marshaling is the
	// one decode path that gets field binding, type checking, and unknown-field rejection
	// from the same rules every other wire type in this package uses.
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("mcp.%s claim cannot be re-encoded: %w", ClaimDeclassify, err)
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(b, &msgs); err != nil {
		return nil, fmt.Errorf("mcp.%s claim must be an array of approval objects: %w", ClaimDeclassify, err)
	}
	if len(msgs) == 0 {
		// An explicitly empty array is a token that grants no declassification. That is
		// well-formed, not an error: it is exactly what a control plane emits when it
		// revokes every outstanding approval without dropping the claim.
		return nil, nil
	}
	out := make([]DeclassifyApproval, 0, len(msgs))
	for i, m := range msgs {
		var a DeclassifyApproval
		if err := rejectUnknownJSONFields(m, &a, fmt.Sprintf("mcp.%s approval %d", ClaimDeclassify, i)); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(m, &a); err != nil {
			return nil, fmt.Errorf("mcp.%s approval %d: %w", ClaimDeclassify, i, err)
		}
		a.Target = strings.TrimSpace(a.Target)
		a.Approver = strings.TrimSpace(a.Approver)
		a.ID = strings.TrimSpace(a.ID)
		if err := a.Validate(); err != nil {
			return nil, fmt.Errorf("mcp.%s approval %d: %w", ClaimDeclassify, i, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// FindDeclassifyApproval returns the first approval covering every label in want at
// target, or nil when none does. Order is the token's, so a control plane that appends
// approvals gets the oldest covering grant — which is the one whose id an operator is
// most likely to be holding. Returning the grant itself (rather than a bool) is what lets
// the caller stamp the approver and id onto the audit record.
func FindDeclassifyApproval(approvals []DeclassifyApproval, target string, want []string) *DeclassifyApproval {
	for i := range approvals {
		if approvals[i].Covers(target, want) {
			return &approvals[i]
		}
	}
	return nil
}
