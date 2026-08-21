// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
)

// The effect-receipt surface: a server attests what it actually did, eunox verifies the
// attestation. Every test here is a sign-and-verify round trip, because that is the only
// way to pin the property the surface exists for — a receipt eunox cannot verify must earn
// NOTHING, or a malicious server forges "reversible, 1 row" and buys itself a lower bar,
// which inverts the control.

// receiptSigner is a test key pair plus the JWKS a verifier is built from.
type receiptSigner struct {
	signer jose.Signer
	jwks   []byte
}

// newReceiptSigner builds an Ed25519 signing key and the public JWKS for it.
func newReceiptSigner(t *testing.T, kid string) *receiptSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: priv, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}}})
	require.NoError(t, err)
	return &receiptSigner{signer: signer, jwks: jwks}
}

// sign renders claims as a signed `_meta` receipt block.
func (s *receiptSigner) sign(t *testing.T, claims *capability.EffectReceiptClaims) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	obj, err := s.signer.Sign(payload)
	require.NoError(t, err)
	compact, err := obj.CompactSerialize()
	require.NoError(t, err)
	block, err := json.Marshal(capability.EffectReceipt{JWS: compact})
	require.NoError(t, err)
	return block
}

// num builds a *json.Number for a receipt magnitude.
func rnum(s string) *json.Number {
	n := json.Number(s)
	return &n
}

// declaredRefund is the contract a decision resolved for a $100 refund.
func declaredRefund() *capability.ResolvedEffect {
	v, _ := capability.ParseBlastRadiusNumber(json.Number("100"))
	return &capability.ResolvedEffect{
		Class:              capability.EffectCompensable,
		CompensatingAction: "tool:reverse_refund",
		BlastRadius:        v,
		Unit:               "usd",
		Annotated:          true,
	}
}

func newVerifier(t *testing.T, s *receiptSigner) *capability.EffectReceiptVerifier {
	t.Helper()
	v, err := capability.NewEffectReceiptVerifier(s.jwks, 0, 0)
	require.NoError(t, err)
	return v
}

// TestEffectReceiptSignAndVerifyRoundTrip is the acceptance case: a receipt the server
// signed, consistent with the contract the decision used, verifies and lands on the tape
// with the claims it attested.
func TestEffectReceiptSignAndVerifyRoundTrip(t *testing.T) {
	s := newReceiptSigner(t, "receipt-1")
	v := newVerifier(t, s)
	now := time.Now()

	block := s.sign(t, &capability.EffectReceiptClaims{
		Tool:               "refund",
		Class:              capability.EffectCompensable,
		BlastRadius:        rnum("100"),
		Unit:               "usd",
		CompensatingAction: "tool:reverse_refund",
		IssuedAt:           now.Unix(),
	})

	got := v.Verify(block, "refund", declaredRefund(), now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptVerified, got.Verdict)
	require.NotNil(t, got.Claims)
	assert.Equal(t, "100", got.Claims.BlastRadius.String())

	details := got.AuditDetails()
	assert.Equal(t, "verified", details["effect_receipt"])
	assert.Equal(t, capability.EffectCompensable, details["effect_receipt_class"])
	assert.Equal(t, "100", details["effect_receipt_blast_radius"])
	assert.Equal(t, "usd", details["effect_receipt_blast_radius_unit"])
	assert.Equal(t, "tool:reverse_refund", details["effect_receipt_compensating_action"])
	assert.NotContains(t, details, "effect_receipt_inconsistent")
}

// TestEffectReceiptForgedByAnotherKeyEarnsNothing is the non-negotiable: a receipt signed
// by a key outside this upstream's domain must record as unverified and carry NO claims. A
// forged "reversible, 1 row" that reached the tape as fact would invert the control it is
// meant to strengthen.
func TestEffectReceiptForgedByAnotherKeyEarnsNothing(t *testing.T) {
	server := newReceiptSigner(t, "receipt-1")
	attacker := newReceiptSigner(t, "receipt-1") // same kid, different key
	v := newVerifier(t, server)
	now := time.Now()

	block := attacker.sign(t, &capability.EffectReceiptClaims{
		Tool:        "refund",
		Class:       capability.EffectReversible,
		BlastRadius: rnum("1"),
		IssuedAt:    now.Unix(),
	})

	got := v.Verify(block, "refund", declaredRefund(), now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptUnverified, got.Verdict)
	assert.Nil(t, got.Claims, "an unverified claim must never be recorded as a fact about what the server did")
	details := got.AuditDetails()
	assert.Equal(t, "unverified", details["effect_receipt"])
	assert.NotContains(t, details, "effect_receipt_class")
}

// TestEffectReceiptUnknownKidEarnsNothing covers the other half of the key domain: a
// receipt naming a key the operator did not configure is unverifiable, not trusted.
func TestEffectReceiptUnknownKidEarnsNothing(t *testing.T) {
	server := newReceiptSigner(t, "configured")
	other := newReceiptSigner(t, "not-configured")
	v := newVerifier(t, server)
	now := time.Now()

	block := other.sign(t, &capability.EffectReceiptClaims{Tool: "refund", IssuedAt: now.Unix()})
	got := v.Verify(block, "refund", nil, now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptUnverified, got.Verdict)
}

// TestEffectReceiptInconsistencies covers each way a VERIFIED receipt can contradict the
// contract the decision was made against. Each is evidence on the tape, never a late
// denial — the call already happened.
func TestEffectReceiptInconsistencies(t *testing.T) {
	s := newReceiptSigner(t, "k")
	v := newVerifier(t, s)
	now := time.Now()

	cases := []struct {
		name   string
		tool   string
		claims capability.EffectReceiptClaims
		want   string
	}{
		{
			name:   "the server did something more consequential than declared",
			tool:   "refund",
			claims: capability.EffectReceiptClaims{Tool: "refund", Class: capability.EffectIrreversible, CompensatingAction: "tool:reverse_refund", IssuedAt: now.Unix()},
			want:   capability.ReceiptReasonClass,
		},
		{
			name:   "the server affected more than the declared magnitude",
			tool:   "refund",
			claims: capability.EffectReceiptClaims{Tool: "refund", Class: capability.EffectCompensable, BlastRadius: rnum("5000"), CompensatingAction: "tool:reverse_refund", IssuedAt: now.Unix()},
			want:   capability.ReceiptReasonBlastRadius,
		},
		{
			name:   "the declared undo does not apply",
			tool:   "refund",
			claims: capability.EffectReceiptClaims{Tool: "refund", Class: capability.EffectCompensable, IssuedAt: now.Unix()},
			want:   capability.ReceiptReasonCompensation,
		},
		{
			name:   "the receipt is about another tool",
			tool:   "refund",
			claims: capability.EffectReceiptClaims{Tool: "read_file", Class: capability.EffectCompensable, CompensatingAction: "tool:reverse_refund", IssuedAt: now.Unix()},
			want:   capability.ReceiptReasonTool,
		},
		{
			name:   "the receipt names a class outside the closed vocabulary",
			tool:   "refund",
			claims: capability.EffectReceiptClaims{Tool: "refund", Class: "mostly-harmless", CompensatingAction: "tool:reverse_refund", IssuedAt: now.Unix()},
			want:   capability.ReceiptReasonUnknownClass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := v.Verify(s.sign(t, &tc.claims), tc.tool, declaredRefund(), now)
			require.NotNil(t, got)
			assert.Equal(t, capability.ReceiptInconsistent, got.Verdict)
			assert.Contains(t, got.Reasons, tc.want)
			assert.Contains(t, got.AuditDetails()["effect_receipt_inconsistent"], tc.want)
		})
	}
}

// TestEffectReceiptSmallerThanDeclaredIsConsistent pins the comparison's direction. The
// contract is an UPPER BOUND the decision was made against, so a server reporting a smaller
// or less consequential action is honoring it. Flagging that would make every honest
// server look inconsistent.
func TestEffectReceiptSmallerThanDeclaredIsConsistent(t *testing.T) {
	s := newReceiptSigner(t, "k")
	v := newVerifier(t, s)
	now := time.Now()

	block := s.sign(t, &capability.EffectReceiptClaims{
		Tool: "refund", Class: capability.EffectReversible, BlastRadius: rnum("5"), IssuedAt: now.Unix(),
	})
	got := v.Verify(block, "refund", declaredRefund(), now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptVerified, got.Verdict)
}

// TestEffectReceiptCarriesRuntimeDynamicEffect covers the case receipts uniquely serve: an
// effect that depends on server state and so could not be resolved before the call. There
// is no declared bound to exceed, so the receipt is consistent — and it is the only account
// of what actually happened, which is why it is recorded.
func TestEffectReceiptCarriesRuntimeDynamicEffect(t *testing.T) {
	s := newReceiptSigner(t, "k")
	v := newVerifier(t, s)
	now := time.Now()

	// Declared unquantified: the manifest could not say how much this call would touch.
	unquantified := &capability.ResolvedEffect{Class: capability.EffectIrreversible, Annotated: true}
	block := s.sign(t, &capability.EffectReceiptClaims{
		Tool: "purge", Class: capability.EffectIrreversible, BlastRadius: rnum("3"), Unit: "rows", IssuedAt: now.Unix(),
	})

	got := v.Verify(block, "purge", unquantified, now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptVerified, got.Verdict)
	assert.Equal(t, "3", got.AuditDetails()["effect_receipt_blast_radius"])
}

// TestEffectReceiptFreshness pins the replay bound. A receipt is undated, stale, or
// future-dated beyond the skew allowance — each is unverifiable, because an attestation
// that can be re-presented indefinitely attests to nothing about THIS call.
func TestEffectReceiptFreshness(t *testing.T) {
	s := newReceiptSigner(t, "k")
	v, err := capability.NewEffectReceiptVerifier(s.jwks, time.Minute, 10*time.Second)
	require.NoError(t, err)
	now := time.Now()

	for _, tc := range []struct {
		name string
		iat  int64
	}{
		{"undated", 0},
		{"older than the freshness window", now.Add(-10 * time.Minute).Unix()},
		{"dated beyond the skew allowance", now.Add(10 * time.Minute).Unix()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := s.sign(t, &capability.EffectReceiptClaims{Tool: "refund", IssuedAt: tc.iat})
			got := v.Verify(block, "refund", nil, now)
			require.NotNil(t, got)
			assert.Equal(t, capability.ReceiptUnverified, got.Verdict)
		})
	}

	// Small skew inside the allowance is skew, not forgery.
	block := s.sign(t, &capability.EffectReceiptClaims{Tool: "refund", IssuedAt: now.Add(5 * time.Second).Unix()})
	got := v.Verify(block, "refund", nil, now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptVerified, got.Verdict)
}

// TestEffectReceiptMalformedBlock pins that a present-but-shapeless block is reported
// rather than ignored — the server tried to attest and got the envelope wrong, which is
// its to fix — and still earns nothing.
func TestEffectReceiptMalformedBlock(t *testing.T) {
	s := newReceiptSigner(t, "k")
	v := newVerifier(t, s)
	for _, raw := range []string{`{}`, `{"jws":""}`, `"not an object"`, `{"jws":"not-a-jws"}`} {
		got := v.Verify(json.RawMessage(raw), "refund", nil, time.Now())
		require.NotNil(t, got, "block %s", raw)
		assert.Contains(t, []capability.ReceiptVerdict{capability.ReceiptMalformed, capability.ReceiptUnverified}, got.Verdict)
		assert.Nil(t, got.Claims)
	}
}

// TestEffectReceiptZeroCostWhenUnconfigured pins the non-negotiable that keeps this surface
// free for everyone who did not opt in: a nil verifier does nothing at all, and a server
// that publishes no receipt produces no result to record.
func TestEffectReceiptZeroCostWhenUnconfigured(t *testing.T) {
	var unconfigured *capability.EffectReceiptVerifier
	assert.Nil(t, unconfigured.Verify(json.RawMessage(`{"jws":"anything"}`), "refund", declaredRefund(), time.Now()))

	s := newReceiptSigner(t, "k")
	v := newVerifier(t, s)
	assert.Nil(t, v.Verify(nil, "refund", nil, time.Now()), "no receipt block means nothing to record")

	_, present := capability.ParseEffectReceipt(map[string]json.RawMessage{})
	assert.False(t, present)
	_, present = capability.ParseEffectReceipt(map[string]json.RawMessage{capability.MetaKeyEffectReceipt: json.RawMessage(`null`)})
	assert.False(t, present, "an explicit null is not a receipt")

	// A nil result renders no audit details at all, so an upstream that never attests
	// leaves the record byte-identical to one from before the surface existed.
	assert.Nil(t, (*capability.ReceiptResult)(nil).AuditDetails())
}

// TestNewEffectReceiptVerifierRejectsUnusableKeySets pins the load-time guards. Each of
// these would make every receipt record as unverified, which is indistinguishable from a
// server that stopped signing — so they fail where the operator sees them.
func TestNewEffectReceiptVerifierRejectsUnusableKeySets(t *testing.T) {
	_, err := capability.NewEffectReceiptVerifier([]byte(`not json`), 0, 0)
	require.Error(t, err)

	_, err = capability.NewEffectReceiptVerifier([]byte(`{"keys":[]}`), 0, 0)
	require.ErrorContains(t, err, "no keys")

	// A PRIVATE key in the set: whoever can verify could also sign, so a receipt
	// "verified" against it proves nothing about which party produced it.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privJWKS, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: priv, KeyID: "p", Algorithm: string(jose.RS256)}}})
	require.NoError(t, err)
	_, err = capability.NewEffectReceiptVerifier(privJWKS, 0, 0)
	require.ErrorContains(t, err, "not a public key")
}

// TestNewEffectReceiptVerifierRefusesAmbiguousKeySetMembers: an operator configures this
// key set for one upstream and reads it before doing so, and encoding/json binds member
// names case-insensitively keeping the LAST — so a second, case-variant "keys" hands the
// verifier a key domain the operator never reviewed, in a file that reads correctly.
// Refused rather than decoded, the same answer the registry's trust store gives.
func TestNewEffectReceiptVerifierRefusesAmbiguousKeySetMembers(t *testing.T) {
	reviewed := newReceiptSigner(t, "reviewed")
	substituted := newReceiptSigner(t, "substituted")

	// The premise: the substituted set is the one a plain unmarshal keeps.
	var decoded jose.JSONWebKeySet
	ambiguous := []byte(fmt.Sprintf(`{"keys":%s,"Keys":%s}`,
		keysArray(t, reviewed.jwks), keysArray(t, substituted.jwks)))
	require.NoError(t, json.Unmarshal(ambiguous, &decoded))
	require.Len(t, decoded.Keys, 1)
	require.Equal(t, "substituted", decoded.Keys[0].KeyID)

	_, err := capability.NewEffectReceiptVerifier(ambiguous, 0, 0)
	require.ErrorContains(t, err, "same name to a JSON decoder")

	// A member the unmarshal below skips without range-checking must not end the scan
	// either: the substitution is still there behind it.
	padded := []byte(fmt.Sprintf(`{"pad":1e999,"keys":%s,"Keys":%s}`,
		keysArray(t, reviewed.jwks), keysArray(t, substituted.jwks)))
	var padDecoded jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(padded, &padDecoded), "the premise: the decoder reads it happily")
	require.Equal(t, "substituted", padDecoded.Keys[0].KeyID)
	_, err = capability.NewEffectReceiptVerifier(padded, 0, 0)
	require.ErrorContains(t, err, "same name to a JSON decoder")

	// A key set whose members are merely REPEATED across sibling key objects is ordinary
	// and must still load.
	both, err := json.Marshal(map[string]json.RawMessage{"keys": json.RawMessage(
		"[" + keysArrayInner(t, reviewed.jwks) + "," + keysArrayInner(t, substituted.jwks) + "]")})
	require.NoError(t, err)
	_, err = capability.NewEffectReceiptVerifier(both, 0, 0)
	require.NoError(t, err)
}

// keysArray returns the "keys" array of a JWKS document, and keysArrayInner its contents
// without the brackets, so a test can build a document carrying two of them.
func keysArray(t *testing.T, jwks []byte) string {
	t.Helper()
	var doc struct {
		Keys json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(jwks, &doc))
	return string(doc.Keys)
}

func keysArrayInner(t *testing.T, jwks []byte) string {
	t.Helper()
	arr := keysArray(t, jwks)
	return strings.TrimSuffix(strings.TrimPrefix(arr, "["), "]")
}

// TestEffectReceiptSilentAboutAQuantifiedDimension pins that silence is not agreement. A
// contract that quantified the call's magnitude and a receipt that says nothing about it do
// not agree — they simply never met. Recording `verified` there, the strongest signal this
// surface emits, would let a server that moved a million dollars against a $10 declaration
// earn the same verdict as one that reported honestly, just by omitting a field.
func TestEffectReceiptSilentAboutAQuantifiedDimension(t *testing.T) {
	s := newReceiptSigner(t, "k")
	v := newVerifier(t, s)
	now := time.Now()

	block := s.sign(t, &capability.EffectReceiptClaims{
		Tool: "refund", Class: capability.EffectCompensable,
		CompensatingAction: "tool:reverse_refund", IssuedAt: now.Unix(),
	})
	got := v.Verify(block, "refund", declaredRefund(), now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptInconsistent, got.Verdict)
	assert.Contains(t, got.Reasons, capability.ReceiptReasonBlastRadiusUnstated)

	// With no quantified declaration there is nothing the silence fails to cover.
	unquantified := &capability.ResolvedEffect{Class: capability.EffectCompensable, CompensatingAction: "tool:reverse_refund", Annotated: true}
	got = v.Verify(block, "refund", unquantified, now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptVerified, got.Verdict)
}

// TestEffectReceiptSilentAboutTheDeclaredClass is the class twin of the magnitude case
// above, and it closes the asymmetry between them. Class is omitempty and every comparison
// in receiptInconsistencies was gated on the field being PRESENT, so a receipt carrying only
// tool + iat tripped nothing and recorded `verified` — for an attestation that never covered
// the dimension the contract bounded.
func TestEffectReceiptSilentAboutTheDeclaredClass(t *testing.T) {
	s := newReceiptSigner(t, "k")
	v := newVerifier(t, s)
	now := time.Now()

	// The concrete failure: the contract says compensable, the server omits `class`, and the
	// receipt says nothing about whether the action it performed was undoable at all.
	silent := s.sign(t, &capability.EffectReceiptClaims{Tool: "refund", IssuedAt: now.Unix()})
	got := v.Verify(silent, "refund", declaredRefund(), now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptInconsistent, got.Verdict)
	assert.Contains(t, got.Reasons, capability.ReceiptReasonClassUnstated)

	// At the top of the vocabulary there is nothing silence could hide: an unstated class
	// cannot exceed `irreversible`, so flagging it would report an inconsistency against a
	// declaration no receipt could contradict.
	topDeclared := &capability.ResolvedEffect{Class: capability.EffectIrreversible, Annotated: true}
	got = v.Verify(silent, "refund", topDeclared, now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptVerified, got.Verdict)
	assert.NotContains(t, got.Reasons, capability.ReceiptReasonClassUnstated)

	// And an honest receipt that STATES a class within the declaration keeps verifying.
	stated := s.sign(t, &capability.EffectReceiptClaims{
		Tool: "refund", Class: capability.EffectCompensable,
		CompensatingAction: "tool:reverse_refund", IssuedAt: now.Unix(),
	})
	unquantified := &capability.ResolvedEffect{Class: capability.EffectCompensable, CompensatingAction: "tool:reverse_refund", Annotated: true}
	got = v.Verify(stated, "refund", unquantified, now)
	require.NotNil(t, got)
	assert.Equal(t, capability.ReceiptVerified, got.Verdict)
}

// TestEffectReceiptKeySetIsBounded pins the kid-less fan-out bound. A receipt carrying no
// kid is trialled against every configured key, so an unbounded key set is an unbounded
// amount of signature verification a hostile upstream can force on the response path of
// every single call — the same reason the JWKS cache caps a fetched key set.
func TestEffectReceiptKeySetIsBounded(t *testing.T) {
	keys := make([]jose.JSONWebKey, 0, capability.MaxReceiptKeys+1)
	for i := 0; i <= capability.MaxReceiptKeys; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		keys = append(keys, jose.JSONWebKey{Key: pub, KeyID: fmt.Sprintf("k%d", i), Algorithm: string(jose.EdDSA), Use: "sig"})
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	require.NoError(t, err)
	_, err = capability.NewEffectReceiptVerifier(jwks, 0, 0)
	require.ErrorContains(t, err, "more than the")
}

// TestEffectReceiptZeroValueVerifierFailsClosed pins that a verifier built as a zero value
// — the natural spelling for an embedder or a test double, since the fields are unexported
// — refuses rather than panicking the dispatch goroutine on attacker-influenced upstream
// output.
func TestEffectReceiptZeroValueVerifierFailsClosed(t *testing.T) {
	s := newReceiptSigner(t, "k")
	block := s.sign(t, &capability.EffectReceiptClaims{Tool: "refund", IssuedAt: time.Now().Unix()})
	assert.Nil(t, (&capability.EffectReceiptVerifier{}).Verify(block, "refund", nil, time.Now()))
}
