// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// signedTestLine builds one canonical signed record line under key, with rec's
// chain fields already stamped by the caller. It is the writer's own splice, so a
// line it returns is byte-identical to what writeRecord would have emitted.
func signedTestLine(t *testing.T, key []byte, rec auditRecord) []byte {
	t.Helper()
	rec.HMAC = ""
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	line, err := signedRecordLine(body, recordMAC(key, body))
	if err != nil {
		t.Fatalf("signedRecordLine: %v", err)
	}
	return line
}

// baseTestRecord is a minimal well-formed genesis record for the decode tests.
func baseTestRecord(key []byte) auditRecord {
	return auditRecord{
		ClassUID: 6003, CategoryUID: 6, ActivityID: 1,
		Time: "2026-01-01T00:00:00Z", Seq: 1, RequestID: "r1", SessionID: "s1",
		TargetType: "tool", Target: "read_file", Method: "tools/call",
		Decision: "allow", PrevHMAC: auditGenesisPrev, KeyID: hmacKeyID(key),
	}
}

// TestDecodeAuditRecord_LenientAndStrictVerdicts pins the two verdicts one decode
// pass now yields, and that they stay DIFFERENT where they must. A line carrying an
// unknown top-level field is still a record — it is counted and it holds its place
// in the chain — while being one no verifier may accept, because the HMAC is
// recomputed over the re-marshaled struct and the unknown field would not be covered
// by it. Collapsing the two verdicts into one would either stop counting such a line
// or start verifying it.
func TestDecodeAuditRecord_LenientAndStrictVerdicts(t *testing.T) {
	t.Parallel()
	key := nonZeroTestKey()
	clean := signedTestLine(t, key, baseTestRecord(key))

	tests := []struct {
		name           string
		line           []byte
		wantWellFormed bool
		wantVerifyErr  string // substring; "" means the strict decode must succeed
		// wantSeq is the seq the returned record carries. It is NOT the gate on
		// entering the chain — wellFormed is — and a rejected line is not reliably
		// empty: a trailing-data line decodes its leading object before More() rejects
		// it, so it comes back populated and must be kept out of the chain on the flag.
		wantSeq uint64
	}{
		{
			name:           "clean record decodes under both tolerances",
			line:           clean,
			wantWellFormed: true,
			wantSeq:        1,
		},
		{
			// The lenient view keeps every modeled field, so the chain still sees this
			// record's seq and _hmac; the strict view refuses it.
			name:           "unknown top-level field is a record but never verifiable",
			line:           append([]byte(`{"operator_override":"approved",`), clean[1:]...),
			wantWellFormed: true,
			wantVerifyErr:  "unknown field",
			wantSeq:        1,
		},
		{
			name:           "malformed JSON fails both",
			line:           []byte(`{"seq":1,`),
			wantWellFormed: false,
			wantVerifyErr:  "malformed",
		},
		{
			// Decode stops at the first value, so only the More() guard catches this.
			name:           "trailing data fails both",
			line:           append(append([]byte{}, clean...), []byte("GARBAGE")...),
			wantWellFormed: false,
			wantVerifyErr:  "trailing data",
			wantSeq:        1, // decoded, but !wellFormed keeps it out of the chain
		},
		{
			// Both defects at once: the strict pass reports the one it hits first, and
			// the lenient pass still rejects the line, so it never reaches the chain.
			name:           "unknown field plus trailing data is not well-formed",
			line:           append(append([]byte(`{"operator_override":"approved",`), clean[1:]...), []byte("GARBAGE")...),
			wantWellFormed: false,
			wantVerifyErr:  "unknown field",
			wantSeq:        1, // as above: populated, but not well-formed
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec, dec := decodeAuditRecord(tc.line)
			if dec.wellFormed != tc.wantWellFormed {
				t.Errorf("wellFormed = %v, want %v", dec.wellFormed, tc.wantWellFormed)
			}
			switch {
			case tc.wantVerifyErr == "" && dec.verifyErr != nil:
				t.Errorf("verifyErr = %v, want nil", dec.verifyErr)
			case tc.wantVerifyErr != "" && dec.verifyErr == nil:
				t.Errorf("verifyErr = nil, want one containing %q", tc.wantVerifyErr)
			case tc.wantVerifyErr != "" && !strings.Contains(dec.verifyErr.Error(), tc.wantVerifyErr):
				t.Errorf("verifyErr = %v, want one containing %q", dec.verifyErr, tc.wantVerifyErr)
			}
			if rec.Seq != tc.wantSeq {
				t.Errorf("decoded seq = %d, want %d", rec.Seq, tc.wantSeq)
			}
		})
	}
}

// TestStrictDecodeAuditRecord_ZeroesRecordOnError pins that a rejected line yields
// NO partially-populated record. Whether encoding/json fills a struct before
// reporting an unknown field is its own business, not a property to build on: the
// caller that wants a usable record on that path must go through the lenient decode,
// and this keeps that the only way to get one.
func TestStrictDecodeAuditRecord_ZeroesRecordOnError(t *testing.T) {
	t.Parallel()
	key := nonZeroTestKey()
	clean := signedTestLine(t, key, baseTestRecord(key))
	tampered := append([]byte(`{"operator_override":"approved",`), clean[1:]...)

	rec, err := strictDecodeAuditRecord(tampered)
	if err == nil {
		t.Fatal("strictDecodeAuditRecord accepted an unknown top-level field")
	}
	// auditRecord holds a json.RawMessage, so it is not comparable; compare the
	// marshaled forms instead, which is an equally exact equality here.
	got, mErr := json.Marshal(rec)
	if mErr != nil {
		t.Fatalf("marshal decoded record: %v", mErr)
	}
	want, mErr := json.Marshal(auditRecord{})
	if mErr != nil {
		t.Fatalf("marshal zero record: %v", mErr)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("record on error = %s, want the zero value %s", got, want)
	}
}

// TestVerifyLog_UnknownFieldMatchesVerifyRecord pins the equivalence the single
// decode rests on: the chain walk hands verifyDecodedRecord a record it decoded
// itself, so its verdict on every line must be the one a standalone VerifyRecord
// reaches from the raw bytes. An injected unknown field is the case where the two
// paths hold DIFFERENT records (the walk's is lenient, VerifyRecord's is strict), so
// it is where a divergence would show up first.
func TestVerifyLog_UnknownFieldMatchesVerifyRecord(t *testing.T) {
	t.Parallel()
	key := nonZeroTestKey()
	verifier := &Sink{key: key, keyID: hmacKeyID(key)}

	clean := signedTestLine(t, key, baseTestRecord(key))
	tampered := append([]byte(`{"operator_override":"approved",`), clean[1:]...)

	ok, standaloneErr := verifier.VerifyRecord(tampered)
	if ok || standaloneErr == nil {
		t.Fatalf("VerifyRecord(unknown field): ok=%v err=%v, want false/non-nil", ok, standaloneErr)
	}

	var out strings.Builder
	res, err := VerifyLog(bytes.NewReader(tampered), verifier, "", time.Time{}, &out)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.OK() {
		t.Fatal("VerifyLog passed a record carrying an injected unknown field")
	}
	// Counted as tampering, not as corruption: the line IS a record, so it lands in
	// Invalid via the verification error rather than the malformed-JSON branch.
	if res.Total != 1 || res.Invalid != 1 {
		t.Errorf("result = %+v, want Total=1 Invalid=1", res)
	}
	// The walk reports the very error VerifyRecord returns, not a paraphrase of it.
	if !strings.Contains(out.String(), standaloneErr.Error()) {
		t.Errorf("VerifyLog output %q does not carry VerifyRecord's error %q", out.String(), standaloneErr)
	}
	// The record kept its place in the chain: seq 1 was adopted, so it is reported
	// against its own seq rather than as an anonymous malformed line.
	if !strings.Contains(out.String(), "seq 1") {
		t.Errorf("VerifyLog output %q does not name the record's seq", out.String())
	}
}

// TestVerifyLog_ChainStateSurvivesAnUnverifiableRecord confirms the lenient decode
// still feeds the chain: an unknown-field record in the middle of a log holds its
// place, so its successor links cleanly against it and the only findings are the
// ones the tampered record itself causes. If the walk had started skipping such a
// record, the successor would report a spurious seq gap and point an investigator at
// the wrong line.
func TestVerifyLog_ChainStateSurvivesAnUnverifiableRecord(t *testing.T) {
	t.Parallel()
	key := nonZeroTestKey()
	verifier := &Sink{key: key, keyID: hmacKeyID(key)}

	first := baseTestRecord(key)
	line1 := signedTestLine(t, key, first)
	var decoded1 auditRecord
	if err := json.Unmarshal(line1, &decoded1); err != nil {
		t.Fatalf("unmarshal first line: %v", err)
	}

	second := baseTestRecord(key)
	second.Seq = 2
	second.PrevHMAC = decoded1.HMAC
	line2 := signedTestLine(t, key, second)
	var decoded2 auditRecord
	if err := json.Unmarshal(line2, &decoded2); err != nil {
		t.Fatalf("unmarshal second line: %v", err)
	}

	third := baseTestRecord(key)
	third.Seq = 3
	third.PrevHMAC = decoded2.HMAC
	line3 := signedTestLine(t, key, third)

	// Inject the unknown field into the MIDDLE record, leaving its _hmac and every
	// signed field byte-for-byte unchanged.
	tampered2 := append([]byte(`{"operator_override":"approved",`), line2[1:]...)

	var out strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join([][]byte{line1, tampered2, line3}, []byte("\n"))),
		verifier, "", time.Time{}, &out)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.Total != 3 || res.Valid != 2 || res.Invalid != 1 {
		t.Errorf("result = %+v, want Total=3 Valid=2 Invalid=1", res)
	}
	// One chain break, and it is the deliberate one: the record after a failed
	// verification cannot trust that record's _hmac as an anchor. No SEQ GAP, which is
	// what a dropped record would have produced.
	if res.ChainBreaks != 1 {
		t.Errorf("ChainBreaks = %d, want 1 (the untrustworthy-anchor break only)", res.ChainBreaks)
	}
	if strings.Contains(out.String(), "SEQ GAP") {
		t.Errorf("unverifiable record was dropped from the chain: %s", out.String())
	}
}
