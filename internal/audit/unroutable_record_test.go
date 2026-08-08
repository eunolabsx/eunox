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
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestUnroutableRecordSignAndVerifyRoundTrip is the audit-discipline check for the reserved
// detail key naming a refusal as eunox's OWN routing rather than a policy verdict.
//
// The refusal records AUTHORIZATION_FAILED — a genuine policy code — for a message no policy
// evaluated, so this marker is the only thing separating the two on the tape. It therefore has
// to survive the tamper-evident chain, not merely reach the sink: its value is a nested object,
// the shape that has bitten before (objects on the way in, map[string]interface{} back out of
// VerifyRecord's own JSON round trip).
//
// The record also carries NO target for a method that resolves a target type, which is the
// other half of the shape — an operator correlating on target must find nothing rather than a
// resource literally named after the method.
func TestUnroutableRecordSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	marker := func(reason string) map[string]interface{} {
		return map[string]interface{}{
			UnroutableKey: map[string]interface{}{"reason": reason, "revision": capability.Revision20260728.String()},
		}
	}
	ctx := capability.WithProtocolRevision(context.Background(), capability.Revision20260728)
	// The two shapes the transport renders: a method that resolves a target type (identifier
	// dropped) and one that does not (identifier kept).
	sink.RecordDeny(ctx, "sess", "", capability.MethodResourcesSubscribe,
		capability.ErrCodeAuthorizationFailed, "", marker(UnroutableRemovedInRevision), false)
	sink.RecordDeny(ctx, "sess", "agents/delegate", "agents/delegate",
		capability.ErrCodeAuthorizationFailed, "", marker(UnroutableUnknownMethod), false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("want 2 records, got %d", len(lines))
	}
	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(lines, []byte("\n"))), verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() {
		t.Fatalf("routing-refusal records must verify cleanly; output:\n%s\nresult: %+v", sb.String(), res)
	}

	wantReasons := []string{UnroutableRemovedInRevision, UnroutableUnknownMethod}
	for i, line := range lines {
		var rec struct {
			Target  string                 `json:"target"`
			Details map[string]interface{} `json:"details"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		got, ok := rec.Details[UnroutableKey].(map[string]interface{})
		if !ok {
			t.Fatalf("record %d: %s = %#v, want a {reason, revision} object", i, UnroutableKey, rec.Details[UnroutableKey])
		}
		if got["reason"] != wantReasons[i] {
			t.Errorf("record %d: reason = %v, want %q", i, got["reason"], wantReasons[i])
		}
		if got["revision"] != capability.Revision20260728.String() {
			t.Errorf("record %d: revision = %v, want %q", i, got["revision"], capability.Revision20260728)
		}
	}
	// The first record's method resolves a target type; with the identifier dropped, the tape
	// must name no target rather than one derived from the method.
	var first struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatalf("record 0: %v", err)
	}
	if first.Target != "" {
		t.Errorf("target = %q, want empty — a routing refusal names no policy target", first.Target)
	}
}

// TestUnroutableKeyIsReserved: the marker rides a DENY today, but the reserved namespace is
// what keeps it out of `eunox suggest`'s argument mining if it ever rides an allow — the same
// rule every other key eunox injects follows.
func TestUnroutableKeyIsReserved(t *testing.T) {
	t.Parallel()
	if !IsReservedDetailKey(UnroutableKey) {
		t.Errorf("%q is not reserved, so a miner would read it as a caller-supplied argument", UnroutableKey)
	}
	if !strings.HasPrefix(UnroutableKey, "_eunox_") {
		t.Errorf("%q is outside the reserved prefix a caller argument cannot forge past quarantineReservedArgs", UnroutableKey)
	}
}
