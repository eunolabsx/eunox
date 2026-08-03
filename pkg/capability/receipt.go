// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Effect receipts — the runtime counterpart of the authoring-time contract.
//
// An effect contract is an ASSERTION: the operator's manifest (or a reviewed registry
// entry) says what a call does, and nothing in eunox observes whether the server behaves
// that way. The design refuses to find out by watching: eunox verifies attestations, it
// does not monitor servers, and no payload inference or egress observation is on the table.
//
// A receipt is the honest way to close that loop. A server MAY publish, in a tool RESULT's
// `_meta`, a SIGNED statement of what it actually did; eunox verifies the signature and
// checks the statement against the contract the pre-call decision used, and puts the
// verdict on the tape. The server says, eunox checks the claim — no observation of the
// server anywhere in it.
//
// Four properties are load-bearing, and each has a specific failure it prevents:
//
//   - VERIFICATION ONLY. The proxy reads the declared receipt block and nothing else. No
//     server-egress watching, no payload inference.
//   - FAIL CLOSED ON TRUST. An unsigned or unverifiable receipt earns NOTHING — it records
//     as such and grants no reduction in friction. Otherwise a malicious server forges
//     "reversible, 1 row" and buys itself a lower bar, which inverts the control.
//   - POST-HOC, NEVER RETROACTIVE. The call already happened. A receipt cannot un-forward
//     it, so an inconsistency is EVIDENCE on the tape and an input to future friction —
//     never a late denial, which would be a decision made after the side effect.
//   - ZERO COST WHEN UNCONFIGURED. No receipt handling at all unless an operator configures
//     the key domain for an upstream. A non-supporting server simply never sets the field,
//     and value accrues per server, so this needs no ecosystem coordination.
//
// The key domain is the server's own, configured PER UPSTREAM — deliberately NOT the JWKS
// that authenticates CALLERS. A receipt is a statement by the upstream about its own
// behavior, closer to package signing than to an access token; wiring it to the caller's
// IdP would mean any party that can mint a caller token can also mint attestations about a
// server's behavior, which is a different trust question with a different answer. The
// verification machinery is shared (the same asymmetric-only algorithm allowlist every JWS
// in this package obeys); only the key set differs.

// MetaKeyEffectReceipt is the reverse-DNS `_meta` key a server publishes a signed effect
// receipt under. Namespaced so a non-supporting server, host, or client simply never sets
// it and nothing changes.
const MetaKeyEffectReceipt = "io.eunolabs.effect-receipt"

// EffectReceipt is the `_meta` block itself: an envelope carrying one compact JWS. The
// envelope is deliberately thin — everything that matters is inside the signature, because
// a field outside it is a field an intermediary can rewrite.
type EffectReceipt struct {
	// JWS is the compact-serialized signature over the receipt's claims.
	JWS string `json:"jws"`
}

// EffectReceiptClaims is what a server attests, as the signed payload of the JWS.
//
// It mirrors the contract vocabulary exactly — the same closed effect classes, the same
// magnitude-and-unit shape — so "consistent with what was declared" is a comparison
// between like values rather than a translation between two schemas that could drift.
type EffectReceiptClaims struct {
	// Tool is the advertised tool name this receipt is about. It must match the call, or
	// the receipt attests to something else entirely.
	Tool string `json:"tool"`
	// Class is the effect class the server says the action actually had.
	Class string `json:"class,omitempty"`
	// BlastRadius is the magnitude the server says the action actually had (rows touched,
	// amount moved, recipients reached).
	BlastRadius *json.Number `json:"blastRadius,omitempty"`
	// Unit labels the magnitude, exactly as a contract's does. Never compared — eunox
	// models no unit algebra — but recorded, so a reader can tell rows from dollars.
	Unit string `json:"unit,omitempty"`
	// CompensatingAction names what reverses the action, when the server says one exists.
	CompensatingAction string `json:"compensatingAction,omitempty"`
	// IssuedAt is the Unix second the receipt was signed. It bounds replay to the
	// freshness window (see EffectReceiptVerifier.MaxAge) — it does not eliminate replay,
	// which would need a nonce eunox supplies on the request leg.
	IssuedAt int64 `json:"iat"`
}

// ReceiptVerdict is the closed vocabulary of receipt outcomes. It is closed for the same
// reason the effect classes are: a verdict a SIEM rule selects on cannot be free-form
// prose, and "unverifiable" and "inconsistent" are different enough incidents that
// collapsing them would hide the one that matters.
type ReceiptVerdict string

const (
	// ReceiptVerified — the signature verified against the upstream's configured key
	// domain AND the claims are consistent with the contract the decision used.
	ReceiptVerified ReceiptVerdict = "verified"
	// ReceiptMalformed — a receipt block is present but is not a well-formed envelope.
	// It earns nothing; the shape is the server's to fix.
	ReceiptMalformed ReceiptVerdict = "malformed"
	// ReceiptUnverified — the signature could not be verified: an unknown key, a bad
	// signature, a stale or future-dated receipt. It earns nothing. This is the fail-closed
	// case, and it must stay distinct from "no receipt at all": a server that USED to
	// attest and now cannot is a different event from one that never did.
	ReceiptUnverified ReceiptVerdict = "unverified"
	// ReceiptInconsistent — the signature verified, and the server's own account of what
	// it did contradicts the contract the decision was made against. The strongest signal
	// this surface produces, and still only evidence: the call already happened.
	ReceiptInconsistent ReceiptVerdict = "inconsistent"
)

// Machine-readable inconsistency reasons. Stable tokens for the tape, never prose.
const (
	// ReceiptReasonTool — the receipt names a different tool than the call.
	ReceiptReasonTool = "tool_mismatch"
	// ReceiptReasonClass — the server says it did something MORE consequential than the
	// contract declared.
	ReceiptReasonClass = "effect_class"
	// ReceiptReasonBlastRadius — the server says it affected MORE than the contract's
	// resolved magnitude for this call.
	ReceiptReasonBlastRadius = "blast_radius"
	// ReceiptReasonCompensation — the contract declared a compensating action and the
	// receipt names a different one (or none).
	ReceiptReasonCompensation = "compensating_action"
	// ReceiptReasonUnknownClass — the receipt's class is outside the closed vocabulary, so
	// it cannot be shown to sit within the declaration. Fail closed: an unrecognized class
	// is not a small one.
	ReceiptReasonUnknownClass = "unknown_effect_class"
	// ReceiptReasonBlastRadiusUnstated — the contract quantified this call's magnitude and
	// the receipt says nothing about it. Silence is not agreement: a server that moved a
	// million dollars against a $10 declaration and simply omitted the field would
	// otherwise record as `verified`, the strongest signal this surface emits, for an
	// attestation that never covered the one dimension the contract bounded.
	ReceiptReasonBlastRadiusUnstated = "blast_radius_unstated"
	// ReceiptReasonClassUnstated — the contract declared a class below the top and the
	// receipt says nothing about the one it landed in. The same rule as
	// ReceiptReasonBlastRadiusUnstated, applied to the other declared dimension: a server
	// that performed an irreversible action against a `reversible` declaration and simply
	// omitted `class` would otherwise record as `verified`, because every class comparison
	// below is gated on the field being present. It does not fire when the declaration is
	// already `irreversible` — an unstated class cannot exceed the top of the vocabulary, so
	// there is nothing silence could be hiding.
	ReceiptReasonClassUnstated = "effect_class_unstated"
)

// ReceiptResult is one receipt's outcome. A nil *ReceiptResult means the server published
// no receipt at all — the default for every non-supporting server, and the one case that
// records nothing, so an upstream that does not participate costs nothing anywhere.
type ReceiptResult struct {
	Verdict ReceiptVerdict
	// Reasons are the stable inconsistency tokens, sorted, for an inconsistent verdict.
	Reasons []string
	// Claims is the verified payload, present for a verified or inconsistent verdict. It
	// is nil for every unverified one, because an unverified claim must not be read as a
	// fact about what the server did.
	Claims *EffectReceiptClaims
}

// AuditDetails renders a receipt outcome as the structured fields a tool-call allow record
// carries. Scalar values under a single reserved prefix, so a SIEM rule selects every
// receipt event on one key rather than enumerating them.
//
// A claim is recorded ONLY when it was verified. Recording an unverified server's stated
// class beside a verdict field would put an unauthenticated assertion on the signed tape in
// a shape a later reader could mistake for a checked fact.
func (r *ReceiptResult) AuditDetails() map[string]interface{} {
	if r == nil {
		return nil
	}
	d := map[string]interface{}{"effect_receipt": string(r.Verdict)}
	if len(r.Reasons) > 0 {
		d["effect_receipt_inconsistent"] = r.Reasons
	}
	if r.Claims == nil {
		return d
	}
	if r.Claims.Class != "" {
		d["effect_receipt_class"] = r.Claims.Class
	}
	if r.Claims.BlastRadius != nil {
		d["effect_receipt_blast_radius"] = r.Claims.BlastRadius.String()
		if r.Claims.Unit != "" {
			d["effect_receipt_blast_radius_unit"] = r.Claims.Unit
		}
	}
	if r.Claims.CompensatingAction != "" {
		d["effect_receipt_compensating_action"] = r.Claims.CompensatingAction
	}
	return d
}

// EffectReceiptVerifier verifies receipts against ONE upstream's key domain.
//
// The key set is static and supplied at construction — no fetch, on the decision path or
// off it. That is not an omission: an upstream's receipt-signing keys are part of the
// operator's configuration for that upstream, exactly as its command line or its URL is,
// and making the proxy fetch them would put a network dependency behind a check whose whole
// value is that it is local and unfalsifiable.
//
// A nil *EffectReceiptVerifier is the "receipts not configured" value: Verify returns nil
// without parsing anything, so an operator who configured no key domain pays nothing at
// all — not a parse, not an allocation, not a map lookup on the result's `_meta`.
type EffectReceiptVerifier struct {
	keys *jose.JSONWebKeySet
	// maxAge bounds how old a receipt may be. It is what makes a captured receipt stop
	// being usable, and it is a BOUND on replay rather than a cure: within the window a
	// server could re-present one. Eliminating replay needs a nonce eunox supplies on the
	// request leg, which is a protocol addition rather than a verification detail.
	maxAge time.Duration
	// leeway absorbs clock skew between the signing server and this proxy, in both
	// directions: a receipt dated slightly in the future is skew, not forgery.
	leeway time.Duration
}

// Default receipt freshness bounds. The window is short because a receipt describes a call
// that just completed: anything older is either a replay or a server clock so wrong that
// its attestations are not worth much either way.
const (
	DefaultReceiptMaxAge = 5 * time.Minute
	DefaultReceiptLeeway = 60 * time.Second
	// MaxReceiptKeys bounds the key set a receipt may be trialled against; see
	// NewEffectReceiptVerifier. It matches the JWKS cache's own per-response cap.
	MaxReceiptKeys = 100
)

// NewEffectReceiptVerifier builds a verifier from a JWKS document — the upstream's own
// receipt-signing keys, not the caller IdP's.
//
// It rejects a key set carrying any symmetric key. A shared secret cannot attest to
// anything: whoever verifies could also have signed, so a receipt "verified" against one
// proves nothing about which party produced it — the same reason every other JWS in this
// package is restricted to asymmetric algorithms.
func NewEffectReceiptVerifier(jwksJSON []byte, maxAge, leeway time.Duration) (*EffectReceiptVerifier, error) {
	var ks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksJSON, &ks); err != nil {
		return nil, fmt.Errorf("parsing effect-receipt JWKS: %w", err)
	}
	if len(ks.Keys) == 0 {
		// An empty key set can verify nothing, so every receipt would record as
		// unverified — indistinguishable from a misconfigured path. Refuse at load, where
		// the operator sees it.
		return nil, fmt.Errorf("effect-receipt JWKS contains no keys")
	}
	for i := range ks.Keys {
		if !ks.Keys[i].IsPublic() {
			return nil, fmt.Errorf("effect-receipt JWKS key %q is not a public key; a receipt is an attestation, and a key that can verify one must not be able to sign it", ks.Keys[i].KeyID)
		}
	}
	if len(ks.Keys) > MaxReceiptKeys {
		// The kid-less fan-out bound, mirroring the JWKS cache's own cap and for the same
		// reason: a receipt carrying no kid is trialled against every key, so an unbounded
		// key set is an unbounded amount of signature verification an upstream can force
		// on the response path of every call.
		return nil, fmt.Errorf("effect-receipt JWKS carries %d keys, more than the %d a kid-less receipt may be trialled against", len(ks.Keys), MaxReceiptKeys)
	}
	if maxAge <= 0 {
		maxAge = DefaultReceiptMaxAge
	}
	// EffectiveLeeway is the shared sentinel resolver: 0 means "default", negative means
	// "disabled". Hand-rolling it here inverted that — negative meant default and 0 meant
	// disabled — so an operator disabling skew tolerance would have got 60 seconds of it,
	// the fail-open direction for a replay bound.
	leeway = EffectiveLeeway(leeway)
	return &EffectReceiptVerifier{keys: &ks, maxAge: maxAge, leeway: leeway}, nil
}

// ParseEffectReceipt extracts the receipt envelope from a tool result's `_meta`. ok is
// false when the server published none, which is the default and is not an error.
func ParseEffectReceipt(meta map[string]json.RawMessage) (raw json.RawMessage, ok bool) {
	v, present := meta[MetaKeyEffectReceipt]
	if !present || len(v) == 0 || string(v) == "null" {
		return nil, false
	}
	return v, true
}

// Verify checks a receipt block against this upstream's key domain and against the effect
// the pre-call decision resolved, and returns the verdict for the tape.
//
// It returns nil — recording nothing — when receipts are not configured or the server
// published none. Every other outcome is a verdict, including the failures: a receipt that
// cannot be verified is a fact worth recording precisely because it is the shape a forgery
// takes.
//
// declared may be nil (a caller with no resolved effect in hand); the consistency check
// then covers only what does not depend on the declaration — the tool binding and the
// class vocabulary. It never upgrades a verdict: an absent declaration cannot make an
// inconsistent receipt consistent, it can only leave less to compare against.
func (v *EffectReceiptVerifier) Verify(rawMeta json.RawMessage, tool string, declared *ResolvedEffect, now time.Time) *ReceiptResult {
	// A nil verifier is the documented "receipts not configured" value. A non-nil one with
	// no key set can only come from a zero-value literal (the fields are unexported, so an
	// embedder or test double reaching for &EffectReceiptVerifier{} is the natural way) —
	// it can verify nothing, and must fail CLOSED rather than panic the dispatch goroutine
	// on attacker-influenced upstream output.
	if v == nil || v.keys == nil || len(rawMeta) == 0 {
		return nil
	}
	var env EffectReceipt
	if err := json.Unmarshal(rawMeta, &env); err != nil || strings.TrimSpace(env.JWS) == "" {
		return &ReceiptResult{Verdict: ReceiptMalformed}
	}
	claims, err := v.verifySignature(env.JWS, now)
	if err != nil {
		// Deliberately one verdict for every signature-side failure — unknown key, bad
		// signature, stale, future-dated, unparseable payload. They are all "this cannot be
		// treated as the server's word", and splitting them would invite a consumer to treat
		// some of them as softer than others, which is exactly the friction reduction an
		// unverifiable receipt must not earn.
		return &ReceiptResult{Verdict: ReceiptUnverified}
	}
	reasons := receiptInconsistencies(claims, tool, declared)
	if len(reasons) > 0 {
		return &ReceiptResult{Verdict: ReceiptInconsistent, Reasons: reasons, Claims: claims}
	}
	return &ReceiptResult{Verdict: ReceiptVerified, Claims: claims}
}

// verifySignature checks the compact JWS against the configured key set and returns its
// claims. Every failure is an error; the caller collapses them to one verdict.
func (v *EffectReceiptVerifier) verifySignature(compact string, now time.Time) (*EffectReceiptClaims, error) {
	sig, err := jose.ParseSigned(compact, JWKSAlgorithms())
	if err != nil {
		return nil, fmt.Errorf("parsing effect receipt: %w", err)
	}
	// One signature only. A multi-signature JWS would leave "which key vouched for this"
	// ambiguous, and an attestation whose signer is ambiguous attests to nothing.
	if len(sig.Signatures) != 1 {
		return nil, fmt.Errorf("effect receipt must carry exactly one signature, got %d", len(sig.Signatures))
	}
	kid := sig.Signatures[0].Header.KeyID

	// FindKeys is the shared selector every JWS path in this package uses: it returns the
	// keys matching kid, or ALL keys when the receipt carries none. Reusing it (rather than
	// inlining the same loop) is what keeps the kid-less fan-out identical to the one the
	// IdP path bounds — and the fan-out is why NewEffectReceiptVerifier caps the key count:
	// a hostile upstream publishing a kid-less JWS in every result would otherwise force one
	// signature verification per configured key, synchronously, on every tools/call.
	candidates := FindKeys(v.keys, kid)
	var payload []byte
	var verifyErr error
	for i := range candidates {
		k := &candidates[i]
		p, err := sig.Verify(k)
		if err != nil {
			verifyErr = err
			continue
		}
		payload = p
		verifyErr = nil
		break
	}
	if payload == nil {
		if verifyErr != nil {
			return nil, fmt.Errorf("effect receipt signature did not verify: %w", verifyErr)
		}
		return nil, fmt.Errorf("effect receipt names key %q, which is not in this upstream's receipt key set", kid)
	}

	var claims EffectReceiptClaims
	// BlastRadius is a typed *json.Number, so the literal's exact text is preserved by the
	// declared type — a magnitude for a large row count is never widened through float64 and
	// compared against a value the server never signed. (UseNumber would add nothing here:
	// it governs decoding into interface{} only.) bytes.NewReader avoids the []byte -> string
	// -> Reader copy of the whole payload on every verification.
	if err := json.NewDecoder(bytes.NewReader(payload)).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decoding effect receipt claims: %w", err)
	}
	if claims.IssuedAt == 0 {
		return nil, fmt.Errorf("effect receipt carries no 'iat'; an undated attestation is replayable forever")
	}
	issued := time.Unix(claims.IssuedAt, 0)
	if now.Sub(issued) > v.maxAge+v.leeway {
		return nil, fmt.Errorf("effect receipt is older than the freshness window")
	}
	if issued.Sub(now) > v.leeway {
		return nil, fmt.Errorf("effect receipt is dated in the future beyond the clock-skew allowance")
	}
	return &claims, nil
}

// receiptInconsistencies compares a VERIFIED receipt against the tool called and the
// effect the decision resolved, returning the stable reason tokens for anything that
// contradicts the declaration. Sorted, so two identical incidents record identically.
//
// The comparison is one-directional on purpose. A server saying it did something SMALLER or
// LESS consequential than declared is consistent: the contract is an upper bound the
// decision was made against, and staying under it is the contract being honored. Only
// exceeding it is a contradiction. The runtime-dynamic case — a contract that could not be
// resolved before the call — is likewise consistent by construction, since there is no
// declared bound to exceed; the receipt is then the only account of what happened, which is
// exactly the effect this surface exists to carry.
func receiptInconsistencies(claims *EffectReceiptClaims, tool string, declared *ResolvedEffect) []string {
	var reasons []string
	if claims.Tool != tool {
		// A receipt about another tool is not evidence about this call, however well it is
		// signed. Reported rather than ignored: a server systematically returning the wrong
		// tool's receipt is a defect an operator needs to see.
		reasons = append(reasons, ReceiptReasonTool)
	}
	if claims.Class != "" && !IsEffectClass(claims.Class) {
		reasons = append(reasons, ReceiptReasonUnknownClass)
	}
	if declared == nil {
		sort.Strings(reasons)
		return reasons
	}
	if claims.Class == "" && declared.Class != EffectIrreversible {
		// Silence is not agreement, on this dimension exactly as on the magnitude one below.
		// Class is omitempty and every comparison in this function is gated on it being
		// present, so a receipt carrying only `tool` + `iat` tripped nothing and recorded
		// `verified` — the strongest signal this surface emits — for an attestation that
		// never covered the class the contract bounded.
		//
		// Not fired at the top of the vocabulary: an unstated class cannot exceed
		// `irreversible`, so silence there hides nothing and flagging it would report an
		// inconsistency against a declaration no receipt could contradict.
		reasons = append(reasons, ReceiptReasonClassUnstated)
	}
	if claims.Class != "" && IsEffectClass(claims.Class) && !EffectClassAtMost(claims.Class, declared.Class) {
		reasons = append(reasons, ReceiptReasonClass)
	}
	if declared.Quantified() && claims.BlastRadius == nil {
		// The same rule claimsLessConsequentialThanDeclared applies to an unstated CLASS:
		// an attestation that omits a declared dimension has not attested to it.
		reasons = append(reasons, ReceiptReasonBlastRadiusUnstated)
	}
	if claims.BlastRadius != nil && declared.Quantified() {
		if actual, ok := ParseBlastRadiusNumber(*claims.BlastRadius); !ok || actual.Cmp(declared.BlastRadius) > 0 {
			// An unparseable magnitude counts as exceeding: a size that cannot be read
			// cannot be shown to be within the declaration, which is the same fail-closed
			// rule the blastRadius condition applies to a call's own arguments.
			reasons = append(reasons, ReceiptReasonBlastRadius)
		}
	}
	if declared.CompensatingAction != "" && claims.CompensatingAction != declared.CompensatingAction &&
		!claimsLessConsequentialThanDeclared(claims, declared) {
		// The contract said this action is undone by a specific compensating action. A
		// server that reports a different one — or none — is reporting that the declared
		// undo does not apply, which is the mislabel the consequence gate exists to catch.
		//
		// Unless the server says it did something STRICTLY less consequential than
		// declared, in which case the compensation leg is moot: a reversible action needs
		// no undo, and demanding one would flag every honest server that stayed well inside
		// its own contract.
		reasons = append(reasons, ReceiptReasonCompensation)
	}
	sort.Strings(reasons)
	return reasons
}

// claimsLessConsequentialThanDeclared reports whether a receipt says the action landed
// strictly BELOW the declared class. A receipt that declares no class says nothing about
// where it landed, so it does not qualify — an unstated class must not silently excuse a
// missing compensating action.
func claimsLessConsequentialThanDeclared(claims *EffectReceiptClaims, declared *ResolvedEffect) bool {
	return claims.Class != "" &&
		claims.Class != declared.Class &&
		EffectClassAtMost(claims.Class, declared.Class)
}
