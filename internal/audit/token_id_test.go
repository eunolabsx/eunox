// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestRecord_TokenIDSignAndVerify is the required sign-and-verify round-trip for the
// token_id field.
//
// What it closes: agent_id and user_id say which IDENTITY made a call; neither says which
// CREDENTIAL authorized it. After a token is revoked, an auditor asking "what did the leaked
// token do" has no way to separate its calls from the same agent's calls on a token that was
// never compromised — the records are identical. token_id is the only field that answers it,
// and it has to be in the SIGNED body for the answer to be worth anything, which is what the
// tamper leg below asserts.
func TestRecord_TokenIDSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Two calls by the SAME agent on DIFFERENT credentials, which is the pair the field
	// exists to tell apart, plus one request carrying no token at all.
	sink, err := Open(logPath, keyPath, 0, 0, WithIdentity(func(ctx context.Context) Identity {
		switch ctx.Value(tokenIDTestKey{}) {
		case "leaked":
			return Identity{AgentID: "agent-1", UserID: "user@example.com", TokenID: "jti-leaked"}
		case "clean":
			return Identity{AgentID: "agent-1", UserID: "user@example.com", TokenID: "jti-clean"}
		default:
			return Identity{}
		}
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	leaked := context.WithValue(context.Background(), tokenIDTestKey{}, "leaked")
	clean := context.WithValue(context.Background(), tokenIDTestKey{}, "clean")
	sink.RecordAllow(leaked, "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.RecordAllow(clean, "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.RecordDeny(context.Background(), "sess-1", "read_file", "tools/call",
		capability.ErrCodeAuthorizationFailed, "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 3 {
		t.Fatalf("expected 3 records, got %d", len(lines))
	}
	fromLeaked, fromClean, noToken := lines[0], lines[1], lines[2]

	if !bytes.Contains(fromLeaked, []byte(`"token_id":"jti-leaked"`)) {
		t.Fatalf("token_id missing/wrong on the leaked-credential record: %s", fromLeaked)
	}
	if !bytes.Contains(fromClean, []byte(`"token_id":"jti-clean"`)) {
		t.Fatalf("token_id missing/wrong on the second credential's record: %s", fromClean)
	}
	// The point of the field, stated as an assertion: these two records are otherwise
	// identical in every identity dimension, so without token_id an incident response could
	// not tell which credential made which call.
	if !bytes.Contains(fromLeaked, []byte(`"agent_id":"agent-1"`)) || !bytes.Contains(fromClean, []byte(`"agent_id":"agent-1"`)) {
		t.Fatal("both records must name the same agent, or they are distinguishable without token_id and this test proves nothing")
	}
	// A request with no token omits the field rather than emitting an empty one: an existing
	// deployment's records stay byte-identical until its IdP issues jti.
	if bytes.Contains(noToken, []byte("token_id")) {
		t.Fatalf("a record with no validated token must omit token_id entirely: %s", noToken)
	}

	verifier := verifierFor(t, keyPath)
	for i, line := range [][]byte{fromLeaked, fromClean, noToken} {
		if ok, verr := verifier.VerifyRecord(line); !ok || verr != nil {
			t.Fatalf("record %d must verify: ok=%v err=%v", i, ok, verr)
		}
	}

	// Tamper: relabel the leaked credential's call as the clean one's, which is exactly the
	// edit someone covering for a compromised token would make. A signed top-level field
	// makes it fail.
	tampered := bytes.Replace(fromLeaked, []byte(`"token_id":"jti-leaked"`), []byte(`"token_id":"jti-clean"`), 1)
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a rewritten token_id must break the record HMAC")
	}
}

// The token id is IdP-supplied and structure-validated but not length-bounded at the source,
// so it takes the same envelope cap as agent_id/task_id/user_id. Without it a misconfigured
// or hostile IdP could push a record past the scanner buffer that reads the tape back — which
// would cost the ability to VERIFY the log, not merely to read one record.
func TestRecord_TokenIDIsBounded(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	huge := strings.Repeat("j", auditEnvelopeFieldCap*4)
	sink, err := Open(logPath, keyPath, 0, 0, WithIdentity(func(context.Context) Identity {
		return Identity{TokenID: huge}
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	line := logLines(t, logPath)[0]
	if len(line) > auditEnvelopeFieldCap*2 {
		t.Fatalf("an unbounded token_id reached the record: %d bytes", len(line))
	}
	if bytes.Contains(line, []byte(huge)) {
		t.Fatal("the full IdP-supplied token id was written verbatim; it must be bounded like every other envelope field")
	}
	if ok, verr := verifierFor(t, keyPath).VerifyRecord(line); !ok || verr != nil {
		t.Fatalf("the bounded record must still verify: ok=%v err=%v", ok, verr)
	}
}

// tokenIDTestKey selects which credential this test's identity extractor reports, without
// depending on the pdp package (which audit must not import).
type tokenIDTestKey struct{}
