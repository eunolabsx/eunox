// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestEffectReceiptRecordSignAndVerifyRoundTrip is the audit-discipline half of the
// effect-receipt surface: the verdict a receipt produces is a claim about a privileged
// call, so it has to be covered by the tamper-evident chain like every other recorded
// fact — signed on write, and verifying on read.
//
// The verdict rides `details` rather than a new top-level field on purpose: the signed
// record shape is load-bearing (audit-verify rejects unknown fields), and a verdict is a
// property of the call being described, not a new dimension of the record. This drives a
// real sink through a real key so the round trip covers the encoding, the HMAC and the
// chain rather than the struct alone.
func TestEffectReceiptRecordSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// One record per verdict, so the whole closed vocabulary is exercised through the
	// signing path — including the failure verdicts, which are exactly the records an
	// investigator would be reading when they most need the chain to hold.
	verdicts := []*capability.ReceiptResult{
		{
			Verdict: capability.ReceiptVerified,
			Claims: &capability.EffectReceiptClaims{
				Class: capability.EffectCompensable, Unit: "usd",
				BlastRadius: receiptNumber("100.50"), CompensatingAction: "tool:reverse_refund",
			},
		},
		{Verdict: capability.ReceiptUnverified},
		{Verdict: capability.ReceiptMalformed},
		{
			Verdict: capability.ReceiptInconsistent,
			Reasons: []string{capability.ReceiptReasonClass, capability.ReceiptReasonBlastRadius},
			Claims:  &capability.EffectReceiptClaims{Class: capability.EffectIrreversible},
		},
	}
	for _, v := range verdicts {
		sink.RecordAllow(context.Background(), "sess", "refund", capability.MethodToolsCall, v.AuditDetails(), nil, true, nil, nil)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != len(verdicts) {
		t.Fatalf("want %d records, got %d", len(verdicts), len(lines))
	}

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(lines, []byte("\n"))), verifierFor(t, keyPath), VerifyOptions{Out: &sb})
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() {
		t.Fatalf("receipt-verdict records must verify cleanly; output:\n%s\nresult: %+v", sb.String(), res)
	}

	// The verdicts survive the round trip in the shape a SIEM rule selects on: one stable
	// key per record, and the claims present only where they were verified.
	for i, want := range []string{"verified", "unverified", "malformed", "inconsistent"} {
		var rec struct {
			Details map[string]interface{} `json:"details"`
		}
		if err := json.Unmarshal(lines[i], &rec); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if got := rec.Details["effect_receipt"]; got != want {
			t.Fatalf("record %d: effect_receipt = %v, want %q", i, got, want)
		}
	}

	var verified, unverified struct {
		Details map[string]interface{} `json:"details"`
	}
	if err := json.Unmarshal(lines[0], &verified); err != nil {
		t.Fatalf("unmarshal verified record: %v", err)
	}
	if got := verified.Details["effect_receipt_blast_radius"]; got != "100.50" {
		t.Fatalf("a verified receipt's magnitude must round-trip exactly, got %v", got)
	}
	if err := json.Unmarshal(lines[1], &unverified); err != nil {
		t.Fatalf("unmarshal unverified record: %v", err)
	}
	if _, present := unverified.Details["effect_receipt_class"]; present {
		t.Fatal("an unverified receipt must put none of its claims on the signed tape")
	}
}

// receiptNumber builds a *json.Number for a receipt magnitude.
func receiptNumber(s string) *json.Number {
	n := json.Number(s)
	return &n
}

// TestVelocityDenialFieldsSignAndVerifyRoundTrip is the same audit-discipline check for the
// cumulative blastRadius denial's four fields. They are the only NUMERIC detail values the
// effect layer produces (a window in int, a running total in float64, a retry hint in
// int64), and numeric details are exactly where the chain has bitten before: VerifyRecord's
// JSON round trip decodes them back as float64, so a correctly-signed record can fail its
// own HMAC unless the verifier re-encodes them the way the signer did.
func TestVelocityDenialFieldsSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	details := map[string]interface{}{
		"effect":                      true,
		"effect_class":                capability.EffectCompensable,
		"annotated":                   true,
		"blast_radius":                "1999.99",
		"blast_radius_unit":           "usd",
		"blast_radius_max_total":      "2000",
		"blast_radius_window_seconds": 3600,
		"blast_radius_total":          1999.99,
		"retry_after_seconds":         int64(2718),
	}
	sink.RecordDeny(context.Background(), "sess", "refund", capability.MethodToolsCall,
		capability.ErrCodeConditionFailed, capability.ConditionTypeBlastRadius, details, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 1 {
		t.Fatalf("want 1 record, got %d", len(lines))
	}
	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(lines, []byte("\n"))), verifierFor(t, keyPath), VerifyOptions{Out: &sb})
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a cumulative blastRadius denial must verify cleanly; output:\n%s\nresult: %+v", sb.String(), res)
	}

	var rec struct {
		Details map[string]interface{} `json:"details"`
	}
	if err := json.Unmarshal(lines[0], &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"blast_radius_max_total", "blast_radius_window_seconds", "blast_radius_total", "retry_after_seconds"} {
		if _, present := rec.Details[key]; !present {
			t.Fatalf("the signed record must carry %q; got details %v", key, rec.Details)
		}
	}
}

// TestRateLimitedDenialFieldsSignAndVerifyRoundTrip is the same check for the OTHER quota refusal,
// whose two time-valued keys were renamed to the spelling above (retryAfter -> retry_after_seconds,
// window -> window_seconds). A renamed key is a byte sequence no signed record has carried, and this
// is where a numeric detail's signer/verifier disagreement shows up rather than in the map the
// engine returns — which is all the enforcement-side tests can see.
func TestRateLimitedDenialFieldsSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	details := map[string]interface{}{
		"limit":               10,
		"current":             int64(11),
		"window_seconds":      3600,
		"retry_after_seconds": int64(2718),
	}
	sink.RecordDeny(context.Background(), "sess", "export", capability.MethodToolsCall,
		capability.ErrCodeRateLimited, capability.ConditionTypeMaxCalls, details, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 1 {
		t.Fatalf("want 1 record, got %d", len(lines))
	}
	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(lines, []byte("\n"))), verifierFor(t, keyPath), VerifyOptions{Out: &sb})
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a RATE_LIMITED denial must verify cleanly; output:\n%s\nresult: %+v", sb.String(), res)
	}

	var rec struct {
		Details map[string]interface{} `json:"details"`
	}
	if err := json.Unmarshal(lines[0], &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"limit", "current", "window_seconds", "retry_after_seconds"} {
		if _, present := rec.Details[key]; !present {
			t.Fatalf("the signed record must carry %q; got details %v", key, rec.Details)
		}
	}
}
