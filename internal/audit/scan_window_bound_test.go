// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordFieldBound is one field's contribution to a serialized record: the cap applied to
// it, and whether that cap counts MARSHALED bytes or raw ones. The distinction is the
// whole reason this is computed rather than eyeballed — the slice caps are measured after
// encoding while boundFieldTo measures the string before it, and a control- or `<`-dense
// value expands sixfold on the way to disk.
type recordFieldBound struct {
	cap     int
	encoded bool
	where   string
}

// contribution is the field's worst-case byte cost in a serialized record.
func (b recordFieldBound) contribution() int {
	if b.encoded {
		return b.cap
	}
	return b.cap * maxJSONStringExpansion
}

// maxJSONStringExpansion is what one raw byte can become in a JSON string: \u00XX. Every
// byte encoding/json escapes at all escapes to at most this.
const maxJSONStringExpansion = 6

// boundedRecordFields declares where every variable-length field of auditRecord is capped
// and how big it can get. Fields whose width this build fixes are declared in
// fixedWidthRecordFields instead (queue_budget_test.go), which this guard reuses rather
// than restating.
var boundedRecordFields = map[string]recordFieldBound{
	"SessionID":     {auditSessionIDCap, false, "Record: the client-controlled Mcp-Session-Id"},
	"AgentID":       {auditEnvelopeFieldCap, false, "Record: a validated JWT claim of unchecked length"},
	"TaskID":        {auditEnvelopeFieldCap, false, "Record: a validated JWT claim of unchecked length"},
	"UserID":        {auditEnvelopeFieldCap, false, "Record: the JWT subject"},
	"TokenID":       {auditEnvelopeFieldCap, false, "Record: a validated JWT claim of unchecked length"},
	"Upstream":      {auditEnvelopeFieldCap, false, "BoundEnvelopeField at routeSink construction"},
	"PolicyVersion": {auditEnvelopeFieldCap, false, "BoundEnvelopeField at routeSink construction"},
	"PolicySHA256":  {auditEnvelopeFieldCap, false, "BoundEnvelopeField at routeSink construction"},
	"Target":        {auditEnvelopeFieldCap, false, "deriveTargetFields: the caller's tool name or resource URI"},
	"Method":        {auditEnvelopeFieldCap, false, "deriveTargetFields: an unrecognized method is preserved raw"},
	"DenialCode":    {auditEnvelopeFieldCap, false, "Record: operator-supplied for an external PolicyEvaluator"},
	"ConditionType": {auditEnvelopeFieldCap, false, "Record: operator-supplied for an external PolicyEvaluator"},
	"Details":       {auditDetailsTotalCap, true, "marshalAndBoundDetails"},
	"Obligations":   {auditObligationsTotalCap, true, "boundAuditObligations"},
	"LabelsOut":     {auditLabelsTotalCap, true, "boundAuditLabels"},
	"CarriedLabels": {auditLabelsTotalCap, true, "boundAuditLabels"},
	"TargetType":    {32, false, "deriveTargetFields: capability.MethodTargetType, a closed set"},
}

// TestScanWindow_EveryVariableFieldIsBoundedAndTheSumFits is the guard the
// auditScanBufferBytes comment cannot be. The window invariant — every record fits the
// 4 MiB line buffer every reader uses — was argued in prose from a hand-kept list of
// caps, and that is exactly how it broke: labels_out/carried_labels were COUNTED by
// queueSize, so the reflective queue-budget guard beside this one stayed green while the
// two fields went to disk unbounded. A record over the window is not merely large; it
// aborts the whole verify/stats/suggest pass with no per-record finding, and as a tail it
// takes the window-clipped resume path on every restart.
//
// Two halves, both structural. A new variable-length field must be DECLARED — bounded
// with its cap, or fixed-width with the reason it cannot grow — and the declared caps must
// still sum under the window, with raw-byte caps charged at what they cost once encoded.
func TestScanWindow_EveryVariableFieldIsBoundedAndTheSumFits(t *testing.T) {
	t.Parallel()

	for name, b := range boundedRecordFields {
		require.NotEmptyf(t, b.where, "%s declares a cap without saying where it is applied", name)
		require.Positivef(t, b.cap, "%s declares a non-positive cap", name)
	}

	rawMessage := reflect.TypeOf(json.RawMessage(nil))
	stringSlice := reflect.TypeOf([]string(nil))
	typ := reflect.TypeOf(auditRecord{})
	declared := 0
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.String && f.Type != stringSlice && f.Type != rawMessage {
			continue
		}
		_, bounded := boundedRecordFields[f.Name]
		_, fixed := fixedWidthRecordFields[f.Name]
		assert.Truef(t, bounded || fixed,
			"%s can carry variable-length bytes to disk but is declared in neither boundedRecordFields "+
				"nor fixedWidthRecordFields, so nothing keeps a record inside the %d-byte scan window. "+
				"Bound it and declare the cap, or declare why its width is fixed.", f.Name, auditScanBufferBytes)
		assert.Falsef(t, bounded && fixed, "%s is declared both bounded and fixed-width", f.Name)
		if bounded {
			declared++
		}
	}
	require.NotZero(t, declared, "no bounded field was walked; the guard is asserting nothing")

	// The envelope allowance covers the fixed-width fields plus the JSON punctuation, key
	// names and the numeric members, generously: those are tens of bytes against a budget
	// measured in MiB.
	const envelopeAllowance = 4 << 10
	worst := envelopeAllowance
	for _, b := range boundedRecordFields {
		worst += b.contribution()
	}
	assert.Lessf(t, worst, auditScanBufferBytes,
		"the declared caps sum to %d encoded bytes, at or over the %d-byte scan window: a record at "+
			"every cap at once would abort every reader of the tape. Lower a cap or raise the window.",
		worst, auditScanBufferBytes)
}
