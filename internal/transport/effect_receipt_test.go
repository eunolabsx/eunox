// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// The transport half of the effect-receipt surface: the verdict must land on the
// tamper-evident tape, the response the host receives must be untouched, and a route that
// configured no key domain must pay nothing at all.

// receiptFixture is a signing key, the JWKS file written for it, and the verifier a route
// would build from that file.
type receiptFixture struct {
	signer   jose.Signer
	verifier *capability.EffectReceiptVerifier
	jwksPath string
}

func newReceiptFixture(t *testing.T) *receiptFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: priv, KeyID: "k1"}}, nil)
	require.NoError(t, err)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "k1", Algorithm: string(jose.EdDSA), Use: "sig"}}})
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "receipt-jwks.json")
	require.NoError(t, os.WriteFile(path, jwks, 0o600))
	// Built through the production loader, so the test exercises the same path a route
	// takes rather than a second construction that could accept what that one refuses.
	v, err := LoadEffectReceiptVerifier(path)
	require.NoError(t, err)
	require.NotNil(t, v)
	return &receiptFixture{signer: signer, verifier: v, jwksPath: path}
}

// toolResult renders a tools/call result carrying a signed receipt in its `_meta`.
func (f *receiptFixture) toolResult(t *testing.T, claims capability.EffectReceiptClaims) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	obj, err := f.signer.Sign(payload)
	require.NoError(t, err)
	compact, err := obj.CompactSerialize()
	require.NoError(t, err)
	result, err := json.Marshal(map[string]interface{}{
		"content": []map[string]string{{"type": "text", "text": "ok"}},
		"_meta":   map[string]interface{}{capability.MetaKeyEffectReceipt: capability.EffectReceipt{JWS: compact}},
	})
	require.NoError(t, err)
	return result
}

// runToolCall drives one tools/call through the shared dispatcher against an upstream
// returning result, with the given receipt verifier wired, and returns the audit records.
func runToolCall(t *testing.T, rec *fwdRecorder, verifier *capability.EffectReceiptVerifier, result json.RawMessage) mcp.RPCMsg {
	t.Helper()
	dp := newTestManifestPDP(capability.Constraint{Target: "tool:refund", Actions: []string{"call"}})
	d := dispatchParams{
		forwardParams: forwardParams{
			rec:       rec,
			sessionID: "s",
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: result}, nil
			},
		},
		pdp:      dp,
		receipts: verifier,
	}
	msg := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"refund","arguments":{}}`),
	}
	out := dispatchRequest(context.Background(), d, msg)
	if out.Error != nil {
		t.Fatalf("tools/call returned an error: %+v", out.Error)
	}
	return out
}

// receiptRecord returns the audit record carrying a receipt verdict, or nil.
func receiptRecord(rec *fwdRecorder) map[string]interface{} {
	for i := range rec.records {
		if _, ok := rec.records[i].details["effect_receipt"]; ok {
			return rec.records[i].details
		}
	}
	return nil
}

// TestEffectReceiptVerdictReachesTheTape is the wiring case: a verified receipt is recorded
// alongside the call it attests to, so an auditor can reconstruct both what was authorized
// and what the server then said it did.
func TestEffectReceiptVerdictReachesTheTape(t *testing.T) {
	f := newReceiptFixture(t)
	rec := &fwdRecorder{}
	result := f.toolResult(t, capability.EffectReceiptClaims{
		Tool: "refund", Class: capability.EffectReversible, BlastRadius: receiptNum("1"), IssuedAt: time.Now().Unix(),
	})
	runToolCall(t, rec, f.verifier, result)

	details := receiptRecord(rec)
	require.NotNil(t, details, "the receipt verdict must land on the tape")
	assert.Equal(t, "verified", details["effect_receipt"])
}

// TestEffectReceiptIsPostHocNeverRetroactive pins the non-negotiable that the surface can
// never turn into a late denial. A receipt whose own account contradicts the declaration is
// recorded as evidence, and the host still receives the upstream's response verbatim — the
// call already ran, so refusing it now would be a decision taken after the side effect.
func TestEffectReceiptIsPostHocNeverRetroactive(t *testing.T) {
	f := newReceiptFixture(t)
	rec := &fwdRecorder{}
	// The manifest declares nothing about this tool's effect, so it resolves to the
	// fail-closed default (irreversible, unquantified); a receipt naming another TOOL is
	// inconsistent regardless of the declaration.
	result := f.toolResult(t, capability.EffectReceiptClaims{
		Tool: "some_other_tool", Class: capability.EffectIrreversible, IssuedAt: time.Now().Unix(),
	})
	out := runToolCall(t, rec, f.verifier, result)

	details := receiptRecord(rec)
	require.NotNil(t, details)
	assert.Equal(t, "inconsistent", details["effect_receipt"])
	assert.Contains(t, details["effect_receipt_inconsistent"], capability.ReceiptReasonTool)

	require.Nil(t, out.Error, "an inconsistent receipt must not turn the answered call into a refusal")
	assert.Contains(t, string(out.Result), "ok", "the host receives the upstream's response verbatim")
}

// TestEffectReceiptForgedEarnsNothingOnTheTape pins the fail-closed-on-trust rule at the
// transport boundary: an unverifiable receipt records as unverified and puts NONE of its
// claims on the signed tape, where a later reader could mistake them for checked facts.
func TestEffectReceiptForgedEarnsNothingOnTheTape(t *testing.T) {
	real := newReceiptFixture(t)
	forger := newReceiptFixture(t)
	rec := &fwdRecorder{}

	// Signed by a key outside the configured domain, claiming a harmless action.
	result := forger.toolResult(t, capability.EffectReceiptClaims{
		Tool: "refund", Class: capability.EffectReversible, IssuedAt: time.Now().Unix(),
	})
	runToolCall(t, rec, real.verifier, result)

	details := receiptRecord(rec)
	require.NotNil(t, details)
	assert.Equal(t, "unverified", details["effect_receipt"])
	assert.NotContains(t, details, "effect_receipt_class",
		"an unverified claim must never reach the tape as a fact about what the server did")
}

// TestEffectReceiptCostsNothingWhenUnconfigured pins the zero-cost rule. With no key domain
// for the route, a result carrying a receipt is neither parsed nor recorded, so the tape is
// byte-identical to one from before the surface existed.
func TestEffectReceiptCostsNothingWhenUnconfigured(t *testing.T) {
	f := newReceiptFixture(t)
	rec := &fwdRecorder{}
	result := f.toolResult(t, capability.EffectReceiptClaims{Tool: "refund", IssuedAt: time.Now().Unix()})

	runToolCall(t, rec, nil, result)
	assert.Nil(t, receiptRecord(rec), "an unconfigured route must record no receipt verdict at all")

	// And a configured route whose upstream simply does not participate records nothing
	// either — the surface needs no ecosystem coordination.
	rec2 := &fwdRecorder{}
	runToolCall(t, rec2, f.verifier, json.RawMessage(`{"content":[]}`))
	assert.Nil(t, receiptRecord(rec2), "a server that publishes no receipt produces no verdict")
}

// TestLoadEffectReceiptVerifier covers the loader's contract: an empty path disables the
// surface, and a configured-but-unusable key set is an ERROR rather than a route that
// silently records every receipt as unverifiable — which would be indistinguishable from a
// server that stopped signing.
func TestLoadEffectReceiptVerifier(t *testing.T) {
	v, err := LoadEffectReceiptVerifier("")
	require.NoError(t, err)
	assert.Nil(t, v, "an unconfigured key domain disables the surface")

	_, err = LoadEffectReceiptVerifier(filepath.Join(t.TempDir(), "absent.json"))
	require.Error(t, err, "a configured-but-missing key set must be fatal")

	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`{"keys":[]}`), 0o600))
	_, err = LoadEffectReceiptVerifier(bad)
	require.ErrorContains(t, err, "no keys")

	// A symlinked key set is refused: a key set is a trust anchor, and following a link to
	// one is how a local attacker substitutes it.
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.json")
	require.NoError(t, os.WriteFile(realPath, []byte(`{"keys":[]}`), 0o600))
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(realPath, link); err == nil {
		_, err = LoadEffectReceiptVerifier(link)
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "symbolic link"), "want a symlink refusal, got %v", err)
	}
}

// receiptNum builds a *json.Number for a receipt magnitude.
func receiptNum(s string) *json.Number {
	n := json.Number(s)
	return &n
}
