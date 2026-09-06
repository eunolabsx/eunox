// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSequenceBlock_NilTargetEmptyName_BlockedToolIsUnknown pins: when
// the blocked request carries neither a ToolName nor a Target (a reachable state
// for direct ValidateAction/EvaluateConditions callers, or future MCP method
// types that do not populate Target), the sequenceBlock denial detail
// "blockedTool" must NOT be the misleading namespace-only sentinel "tool:". It is
// reported as "(unknown)" so a SIEM rule parsing blockedTool as namespace:name
// does not extract an empty name and silently drop or misattribute the event.
func TestSequenceBlock_NilTargetEmptyName_BlockedToolIsUnknown(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))

	// Arm the block: record an allowed "read_credentials" antecedent so the later
	// Peek finds it. A bare ToolName defaults to the "tool" namespace, matching how
	// the blocked sequenceBlock entry resolves its antecedent.
	antecedent := &capability.Constraint{Target: "tool:read_credentials", Actions: []string{"call"}}
	antReq := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "read_credentials"}
	resp := engine.EvaluateConditions(context.Background(), antReq, antecedent)
	require.Equal(t, capability.DecisionAllow, resp.Decision)

	// The blocked request: ToolName empty AND Target nil. The sequenceBlock fires
	// because read_credentials ran, but the blocked target cannot be named.
	blocked := &capability.Constraint{
		Target:  "tool:write_external",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
		},
	}
	blockedReq := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "", // no name on either field
		Target:     nil,
	}
	resp = engine.EvaluateConditions(context.Background(), blockedReq, blocked)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ConditionTypeSequenceBlock, resp.Denial.ConditionType)
	// The crux: blockedTool is "(unknown)", never the bare "tool:" sentinel.
	assert.Equal(t, "(unknown)", resp.Denial.Details["blockedTool"])
	assert.NotEqual(t, "tool:", resp.Denial.Details["blockedTool"])
	// The antecedent is still named in namespace:name form (regression guard).
	assert.Equal(t, "tool:read_credentials", resp.Denial.Details["afterTool"])
}

// TestSequenceBlock_NamedBlockedToolStillReported is the positive companion to
// the fix: when the blocked request DOES carry a name, blockedTool still
// reports the namespace:name form. The "(unknown)" substitution must apply only
// to the nameless edge case.
func TestSequenceBlock_NamedBlockedToolStillReported(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))

	antecedent := &capability.Constraint{Target: "tool:read_credentials", Actions: []string{"call"}}
	antReq := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "read_credentials"}
	engine.EvaluateConditions(context.Background(), antReq, antecedent)

	blocked := &capability.Constraint{
		Target:  "tool:write_external",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
		},
	}
	blockedReq := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "write_external"}
	resp := engine.EvaluateConditions(context.Background(), blockedReq, blocked)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, "tool:write_external", resp.Denial.Details["blockedTool"])
}

// TestSequenceBlock_NamespacePrefixedAntecedentName_BothSpellingsMatch pins the fix
// for the silent fail-OPEN where a target whose NAME itself begins with a recognized
// namespace token — a tool literally named "system:foo" — was recorded verbatim under
// (tool, "system:foo") but a natural afterTools: ["system:foo"] resolves (via the
// lookup's prefix split) to (system, foo), so the gate never fired. RecordSessionCall
// now also writes a secondary marker keyed the way the bare spelling parses, so BOTH
// the bare "system:foo" and the explicit "tool:system:foo" spellings trip the gate.
func TestSequenceBlock_NamespacePrefixedAntecedentName_BothSpellingsMatch(t *testing.T) {
	t.Parallel()

	armAndBlock := func(t *testing.T, afterTools []string) capability.Decision {
		t.Helper()
		engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))

		// Antecedent: a tool literally NAMED "system:foo" (Target.Type "tool",
		// Target.Name "system:foo"), recorded verbatim by the allow path.
		antReq := &capability.EnforceRequest{
			SessionID:  "sess",
			TargetName: "system:foo",
			Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "system:foo"},
		}
		ant := &capability.Constraint{Target: "tool:system:foo", Actions: []string{"call"}}
		resp := engine.EvaluateConditions(context.Background(), antReq, ant)
		require.Equal(t, capability.DecisionAllow, resp.Decision)

		blocked := &capability.Constraint{
			Target:  "tool:write_external",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.SequenceBlockCondition{AfterTools: afterTools},
			},
		}
		blockedReq := &capability.EnforceRequest{
			SessionID:  "sess",
			TargetName: "write_external",
			Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "write_external"},
		}
		resp = engine.EvaluateConditions(context.Background(), blockedReq, blocked)
		return resp.Decision
	}

	t.Run("bare system:foo spelling blocks (was a fail-open)", func(t *testing.T) {
		assert.Equal(t, capability.DecisionDeny, armAndBlock(t, []string{"system:foo"}))
	})
	t.Run("explicit tool:system:foo spelling blocks", func(t *testing.T) {
		assert.Equal(t, capability.DecisionDeny, armAndBlock(t, []string{"tool:system:foo"}))
	})
}

// TestSequenceBlock_PlainAntecedentName_WritesSingleMarker pins that the secondary
// marker is NOT written for an ordinary antecedent whose name carries no recognized
// namespace prefix: a plain "read_file" must not also trip an afterTools entry that
// resolves to a different (type, name) pair, and the bare/explicit spellings stay
// distinct as before.
func TestSequenceBlock_PlainAntecedentName_WritesSingleMarker(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))

	antReq := &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "read_file",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_file"},
	}
	ant := &capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}}
	resp := engine.EvaluateConditions(context.Background(), antReq, ant)
	require.Equal(t, capability.DecisionAllow, resp.Decision)

	// A prompt-namespaced afterTools entry naming "read_file" must NOT match the tool
	// antecedent — recording stays namespace-distinct (no spurious secondary marker).
	blocked := &capability.Constraint{
		Target:  "tool:write_external",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.SequenceBlockCondition{AfterTools: []string{"prompt:read_file"}},
		},
	}
	blockedReq := &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "write_external",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "write_external"},
	}
	resp = engine.EvaluateConditions(context.Background(), blockedReq, blocked)
	assert.Equal(t, capability.DecisionAllow, resp.Decision, "a prompt-namespaced antecedent must not match a tool of the same bare name")
}

// TestSequenceBlock_BlockedTargetNamedWithARecognizedToken_ReportsTheRealName is the
// regression for a signed-tape field naming a target that does not exist.
//
// The blocked-target resolution took req.Target.Name only as a FALLBACK for an empty prefix
// split, inverting the rule every sibling applies (sessionTargetName/resolveRequestTarget prefer
// Target.Name VERBATIM, precisely because a target whose own name begins with a recognized token
// would otherwise have that token stripped). So a resource named "system:config" was denied and
// recorded as blockedTool "resource:config" — a target no manifest names and no bucket is keyed
// on — in the HMAC-signed audit detail and in the operator-facing message.
//
// The decision was never affected; the name on the record was.
func TestSequenceBlock_BlockedTargetNamedWithARecognizedToken_ReportsTheRealName(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	ctx := context.Background()

	require.NoError(t, engine.RecordSessionCall(ctx, &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "read_credentials",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_credentials"},
	}))

	// A resource whose NAME begins with the recognized "system" token. Both fields carry it,
	// which is what every ManifestPDP entry point builds.
	blockedReq := &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "system:config",
		Target:     &capability.EnforceRequestTarget{Type: "resource", Name: "system:config"},
	}
	blocked := &capability.Constraint{
		Target:  "resource:system:config",
		Actions: []string{"read"},
		Conditions: []capability.Condition{
			&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
		},
	}
	resp := engine.EvaluateConditions(ctx, blockedReq, blocked)
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, "resource:system:config", resp.Denial.Details["blockedTool"],
		"the signed detail must name the target that was blocked, not one with its leading token stripped")
	assert.Contains(t, resp.Denial.Message, `"system:config"`,
		"the operator-facing message must name the same target the detail does")
}

// And the property behind that name, stated without naming a literal: whatever blockedTool
// reports must be the spelling that ADDRESSES the target's own history — an afterTools entry
// copied verbatim off the record has to trip the gate. That is what makes a signed field name a
// target that exists rather than a plausible-looking string, and it is what the inverted
// resolution broke: "resource:config" addresses nothing.
func TestSequenceBlock_ReportedBlockedNameIsTheNameTheHistoryIsKeyedOn(t *testing.T) {
	t.Parallel()
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	ctx := context.Background()

	resource := func() *capability.EnforceRequest {
		return &capability.EnforceRequest{
			SessionID:  "sess",
			TargetName: "system:config",
			Target:     &capability.EnforceRequestTarget{Type: "resource", Name: "system:config"},
		}
	}
	// Arm a block ON the resource to read the name it is reported under...
	require.NoError(t, engine.RecordSessionCall(ctx, &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "read_credentials",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "read_credentials"},
	}))
	resp := engine.EvaluateConditions(ctx, resource(), &capability.Constraint{
		Target:  "resource:system:config",
		Actions: []string{"read"},
		Conditions: []capability.Condition{
			&capability.SequenceBlockCondition{AfterTools: []string{"read_credentials"}},
		},
	})
	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	reported, _ := resp.Denial.Details["blockedTool"].(string)
	require.NotEmpty(t, reported)

	// ...then record that same resource as an ANTECEDENT and address it with the reported name.
	require.NoError(t, engine.RecordSessionCall(ctx, resource()))
	resp = engine.EvaluateConditions(ctx, &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "write_external",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "write_external"},
	}, &capability.Constraint{
		Target:  "tool:write_external",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.SequenceBlockCondition{AfterTools: []string{reported}},
		},
	})
	assert.Equal(t, capability.DecisionDeny, resp.Decision,
		"an afterTools entry copied verbatim from blockedTool (%q) must address the same target's history", reported)
}

// extCaps builds a single tool:read_file capability gated by an allowedExtensions
// condition on the "path" argument with the given allowlist.
func extCaps(extensions []string) []capability.Constraint {
	return []capability.Constraint{
		{
			Target:  "tool:read_file",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.AllowedExtensionsCondition{Argument: "path", Extensions: extensions},
			},
		},
	}
}

// callExt drives one read_file call with the given path argument and returns the
// decision.
func callExt(t *testing.T, engine *enforcement.Engine, caps []capability.Constraint, path string) capability.EnforceResponse {
	t.Helper()
	req := &capability.EnforceRequest{
		SessionID:  "s",
		TargetName: "read_file",
		Arguments:  map[string]interface{}{"path": path},
	}
	resp := engine.ValidateAction(context.Background(), req, caps)
	return resp
}

// TestAllowedExtensions_PercentEncodingDecodedView asserts handleAllowedExtensions
// matches the file name an upstream actually resolves after percent-decoding, in
// lock-step with MatchValueGlob's confinement guard. %2e is folded to a dot and
// %2f to a separator before the file-name/extension is derived, and a malformed
// percent-escape fails closed.
func TestAllowedExtensions_PercentEncodingDecodedView(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()

	cases := []struct {
		name string
		path string
		want capability.Decision
	}{
		// %2e decodes to '.', so "report%2epdf" is the file "report.pdf" the
		// upstream opens — allowed against [".pdf"].
		{"percent-dot extension allowed", "report%2epdf", capability.DecisionAllow},
		// A %2f directory smuggle: the real final element is "evil" (no extension),
		// so matching the decoded file name denies it rather than latching onto the
		// ".pdf" directory component.
		{"percent-slash directory smuggle denied", "report.pdf%2fevil", capability.DecisionDeny},
		// A literal '%' that is not a valid escape is a legal filename character for
		// an upstream that does not percent-decode. The extension allowlist is not a
		// confinement guard, so it must check the extension on the literal form
		// instead of denying outright. "report_50%_off.pdf" ends in an allowed
		// ".pdf", so it is allowed.
		{"literal percent in name allowed", "report_50%_off.pdf", capability.DecisionAllow},
		// An embedded NUL (percent-encoded or literal) is a truncation vector: a
		// NUL-truncating upstream opens the pre-NUL file ("evil.exe"), so the ".pdf"
		// suffix the allowlist sees is not the suffix it resolves. Fail closed.
		{"percent-encoded NUL truncation denied", "evil.exe%00.pdf", capability.DecisionDeny},
		{"literal NUL truncation denied", "evil.exe\x00.pdf", capability.DecisionDeny},
		// A literal NUL paired with a MALFORMED percent-escape must still fail
		// closed. url.PathUnescape errors on the "%." so the decode short-circuits to
		// errPathMalformedEscape; the lenient literal fallback would then see
		// "evil.exe\x00report%.pdf" end in an allowed ".pdf" and admit it, even though
		// a NUL-truncating upstream opens "evil.exe". The pre-decode NUL check now
		// wins, so this denies.
		{"literal NUL with malformed escape denied", "evil.exe\x00report%.pdf", capability.DecisionDeny},
		// The ENCODED NUL paired with a malformed escape is the case the pre-decode
		// check cannot reach: url.PathUnescape fails whole on the "%zz", so "%00" was
		// never decoded to a NUL and the post-decode check never ran either. The lenient
		// literal fallback then saw an allowed ".pdf" suffix on a path a NUL-truncating
		// upstream resolves as "evil.exe". MatchValueGlob's slashless fallback carries
		// the identical guard, so the two stay in lock-step.
		{"encoded NUL with malformed escape denied", "evil.exe%00x%zz.pdf", capability.DecisionDeny},
		// Same for an encoded SEPARATOR alongside a bad escape: the decoded view would
		// have made "evil" the final segment (no extension), so the literal fallback
		// admitting it on the ".pdf" directory component is the same misread.
		{"encoded separator with malformed escape denied", "report.pdf%2fevil%zz", capability.DecisionDeny},
		// The literal-'%' allowance must survive: a '%' that forms no encoded token is a
		// legal filename character for a non-decoding upstream, and the extension
		// allowlist is not a confinement guard.
		{"literal percent with bad escape still allowed", "report_50%_off%zz.pdf", capability.DecisionAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := callExt(t, engine, extCaps([]string{".pdf"}), tc.path)
			assert.Equalf(t, tc.want, resp.Decision, "path=%q", tc.path)
			if tc.want == capability.DecisionDeny {
				require.NotNil(t, resp.Denial)
				assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
			}
		})
	}
}

// TestAllowedExtensions_CompoundSuffixDocumentedBehavior asserts the documented
// HasSuffix-on-a-dot-boundary semantics of
// handleAllowedExtensions, so the behavior is pinned and a future change to the
// runtime matching surfaces as a test failure:
//
//   - a SINGLE-segment entry (".gz") matches BOTH "file.gz" AND "archive.tar.gz",
//     because ".gz" is a suffix of ".tar.gz" on a dot boundary;
//   - a COMPOUND entry (".tar.gz") matches ONLY the compound "archive.tar.gz",
//     never the bare "file.gz".
//
// This is allow-only matching, so there is no way to allow ".gz" while denying
// ".tar.gz" with the extension alone. The runtime semantics deliberately remain
// HasSuffix; the load-time warning for single-segment entries lives in the
// capability/config validation layer, not in this handler.
func TestAllowedExtensions_CompoundSuffixDocumentedBehavior(t *testing.T) {
	t.Parallel()
	engine := enforcement.New()

	cases := []struct {
		name       string
		extensions []string
		path       string
		want       capability.Decision
	}{
		// Single-segment ".gz" admits both the bare and the compound file.
		{"single gz allows bare gz", []string{".gz"}, "file.gz", capability.DecisionAllow},
		{"single gz also allows compound tar.gz", []string{".gz"}, "archive.tar.gz", capability.DecisionAllow},
		// Compound ".tar.gz" admits only the compound file, denying the bare one.
		{"compound allows compound", []string{".tar.gz"}, "archive.tar.gz", capability.DecisionAllow},
		{"compound denies bare gz", []string{".tar.gz"}, "file.gz", capability.DecisionDeny},
		// A wholly unrelated extension is denied either way.
		{"single gz denies txt", []string{".gz"}, "notes.txt", capability.DecisionDeny},
		// Malformed input: a path with no extension at all is denied fail-closed.
		{"no extension denied", []string{".gz"}, "README", capability.DecisionDeny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := callExt(t, engine, extCaps(tc.extensions), tc.path)
			assert.Equalf(t, tc.want, resp.Decision,
				"extensions=%v path=%q", tc.extensions, tc.path)
			if tc.want == capability.DecisionDeny {
				require.NotNil(t, resp.Denial)
				assert.Equal(t, capability.ConditionTypeAllowedExtensions, resp.Denial.ConditionType)
			}
		})
	}
}

// TestOperationVerb covers the shared verb extractor used by both the engine's
// handleAllowedOperations and the JWT shorthand PDP: the uppercased first
// whitespace-delimited word, or "" for empty/blank input.
func TestOperationVerb(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"select * from t", "SELECT"},
		{"  Delete   from x", "DELETE"},
		{"INSERT", "INSERT"},
		{"\tupdate\n", "UPDATE"},
		{"", ""},
		{"   ", ""},
		{"\t\n", ""},
	}
	for _, tc := range cases {
		if got := enforcement.OperationVerb(tc.in); got != tc.want {
			t.Errorf("OperationVerb(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMatchAllowedOperation covers the shared case-insensitive membership matcher:
// "*" is a literal (rejected as a wildcard at manifest load), not a catch-all.
func TestMatchAllowedOperation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		allowed []string
		op      string
		want    bool
	}{
		{"exact match", []string{"SELECT", "INSERT"}, "SELECT", true},
		{"case-insensitive", []string{"select"}, "SELECT", true},
		{"mixed case both ways", []string{"SeLeCt"}, "sElEcT", true},
		{"not present", []string{"SELECT"}, "DROP", false},
		{"empty allowed set", nil, "SELECT", false},
		{"star is literal not wildcard", []string{"*"}, "SELECT", false},
		{"star matches literal star", []string{"*"}, "*", true},
		{"empty op never matches", []string{"SELECT"}, "", false},
		// Surrounding whitespace on an allowlist entry is tolerated: the entry is
		// trimmed before comparison so a padded manifest value still matches.
		{"trailing space on entry tolerated", []string{"SELECT "}, "SELECT", true},
		{"leading space on entry tolerated", []string{" insert"}, "INSERT", true},
	}
	for _, tc := range cases {
		if got := capability.MatchOperation(tc.allowed, tc.op); got != tc.want {
			t.Errorf("%s: MatchOperation(%v, %q) = %v, want %v", tc.name, tc.allowed, tc.op, got, tc.want)
		}
	}
}

// TestHandleAllowedTables_WhitespaceEntryStillMatches verifies that an
// allowedTables entry carrying surrounding whitespace (e.g. " users") is trimmed
// before comparison, so the matching request is allowed and a non-matching one
// is still denied on the merits. The padded entry bypasses the manifest
// validator by being constructed in-process.
func TestHandleAllowedTables_WhitespaceEntryStillMatches(t *testing.T) {
	t.Parallel()
	cond := &capability.AllowedTablesCondition{Argument: "table", Tables: []string{" users"}}

	// Matching request: table "users" is allowed despite the padded entry.
	allowResp := runCondition(t, enforcement.New(), cond,
		map[string]interface{}{"table": "users"}, "")
	assert.Equal(t, capability.DecisionAllow, allowResp.Decision)

	// Non-matching request: table "secrets" is still denied with CONDITION_FAILED.
	denyResp := runCondition(t, enforcement.New(), cond,
		map[string]interface{}{"table": "secrets"}, "")
	assert.Equal(t, capability.DecisionDeny, denyResp.Decision)
	require.NotNil(t, denyResp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, denyResp.Denial.Code)
}

// TestHandleAllowedTables_UncompiledCollisionFailsClosed pins the handler's own fail-closed exit
// for a condition that never compiled.
//
// The accessor used to build the lookup maps on the spot, silently, having no channel for an
// error — so a pair of 'columns' keys that Compile REFUSES as an ambiguous ACL was resolved here
// instead and enforced. The handler now compiles a local copy (the shape its timeWindow and
// ipRange siblings already take) and denies with a fault code: nothing evaluated the ACL, so
// there is no verdict for an observing route to forward in its place.
func TestHandleAllowedTables_UncompiledCollisionFailsClosed(t *testing.T) {
	t.Parallel()
	cond := &capability.AllowedTablesCondition{
		Argument: "table",
		Tables:   []string{"users"},
		Columns:  map[string][]string{"Users": {"id", "ssn"}, "users": {"id"}},
	}

	resp := runCondition(t, enforcement.New(), cond, map[string]interface{}{"table": "users"}, "")
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code)
	assert.False(t, resp.Denial.Downgradable())
	assert.Contains(t, resp.Denial.Message, "could not be compiled")
}

// An uncompiled but UNAMBIGUOUS condition still matches exactly what a loaded one matches: the
// local compile is the same Compile the loader runs.
func TestHandleAllowedTables_UncompiledStillMatches(t *testing.T) {
	t.Parallel()
	cond := &capability.AllowedTablesCondition{
		Argument: "table",
		Tables:   []string{"users"},
		Columns:  map[string][]string{"Users": {"id"}},
	}
	resp := runCondition(t, enforcement.New(), cond,
		map[string]interface{}{"table": map[string]interface{}{"table": "USERS", "columns": []interface{}{"ID"}}}, "")
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

// TestHandleRecipientDomain_WhitespaceEntryStillMatches verifies that a
// recipientDomain entry carrying surrounding whitespace (e.g. "example.com ") is
// trimmed before comparison, so a recipient at that domain is allowed and a
// recipient at a different domain is still denied.
func TestHandleRecipientDomain_WhitespaceEntryStillMatches(t *testing.T) {
	t.Parallel()
	cond := &capability.RecipientDomainCondition{Argument: "to", Domains: []string{"example.com "}}

	// Matching recipient: u@example.com is allowed despite the padded entry.
	allowResp := runCondition(t, enforcement.New(), cond,
		map[string]interface{}{"to": "u@example.com"}, "")
	assert.Equal(t, capability.DecisionAllow, allowResp.Decision)

	// Non-matching recipient: a different domain is still denied with CONDITION_FAILED.
	denyResp := runCondition(t, enforcement.New(), cond,
		map[string]interface{}{"to": "u@evil.com"}, "")
	assert.Equal(t, capability.DecisionDeny, denyResp.Decision)
	require.NotNil(t, denyResp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, denyResp.Denial.Code)
}
