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

// TestHandlerFaultRecordSignAndVerifyRoundTrip is the audit-discipline check for the reserved
// detail key that reports a repaired condition-handler fault. The report is the only signal an
// absorbed fault produces, so it has to survive the tamper-evident chain rather than merely
// reach the sink.
//
// Its value is the shape numeric details have bitten on before: a []string on the way in,
// decoded as []interface{} by VerifyRecord's own JSON round trip. It verifies today; without
// this, a later change to the canonical form would break it silently.
func TestHandlerFaultRecordSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	faults := []string{capability.ConditionTypeMaxCalls, capability.ConditionTypeBlastRadius}
	// Both records the fault can ride: the allow it was decided on, and the deny a route
	// running --audit forwards anyway.
	sink.RecordAllow(context.Background(), "sess", "read_file", capability.MethodToolsCall,
		map[string]interface{}{HandlerFaultKey: faults}, nil, true, nil, nil)
	sink.RecordDeny(context.Background(), "sess", "read_file", capability.MethodToolsCall,
		capability.ErrCodeConditionFailed, capability.ConditionTypeBlastRadius,
		map[string]interface{}{HandlerFaultKey: faults}, true)
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
		t.Fatalf("handler-fault records must verify cleanly; output:\n%s\nresult: %+v", sb.String(), res)
	}

	for i, line := range lines {
		var rec struct {
			Details map[string]interface{} `json:"details"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		got, ok := rec.Details[HandlerFaultKey].([]interface{})
		if !ok {
			t.Fatalf("record %d: %s = %#v, want an array of condition types", i, HandlerFaultKey, rec.Details[HandlerFaultKey])
		}
		if len(got) != len(faults) || got[0] != faults[0] || got[1] != faults[1] {
			t.Fatalf("record %d: %s = %v, want %v", i, HandlerFaultKey, got, faults)
		}
	}

	// Reserved, so `eunox suggest` skips it rather than drafting it as a tool argument name.
	if !IsReservedDetailKey(HandlerFaultKey) {
		t.Fatalf("%s must be in the reserved namespace", HandlerFaultKey)
	}
}
