// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

// The operator-facing half of the `auto` opener question. eunox does not probe for an
// upstream's revision — that changes what every existing upstream sees at session start and
// is ADR-0006's call — so the one thing an operator hitting that wall gets is the failure
// text, and it has to name the leg it actually opened and the remedy that closes it.

import (
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestWrapUpstreamOpenFailure_NamesTheOpenerTheLegUsed pins the fix for a failure line that
// contradicted itself: all three transports wrapped this as "upstream initialize", so a leg
// opened with server/discover produced "upstream initialize: upstream server/discover
// rejected ..." and an operator could not tell which method eunox had actually sent.
func TestWrapUpstreamOpenFailure_NamesTheOpenerTheLegUsed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		rev      capability.Revision
		wantsRev string
		wants    string
		forbids  string
	}{
		{capability.Revision20251125, "2025-11-25", mcp.MethodInitialize, mcp.MethodServerDiscover},
		{capability.Revision20260728, "2026-07-28", mcp.MethodServerDiscover, mcp.MethodInitialize},
		// An unset revision opens at the handshake revision, the same resolution every other
		// empty carrier takes; the failure must name that rather than an empty string.
		{capability.Revision(""), "2025-11-25", mcp.MethodInitialize, mcp.MethodServerDiscover},
	}
	for _, tc := range cases {
		t.Run(tc.wantsRev, func(t *testing.T) {
			got := wrapUpstreamOpenFailure(tc.rev, errStub{"upstream down"}).Error()
			if !strings.Contains(got, tc.wantsRev) {
				t.Errorf("error = %q, want it to name the revision %s", got, tc.wantsRev)
			}
			if !strings.Contains(got, tc.wants) {
				t.Errorf("error = %q, want it to name the opener %s", got, tc.wants)
			}
			if strings.Contains(got, tc.forbids) {
				t.Errorf("error = %q, must not name %s: that is not the method this leg sent", got, tc.forbids)
			}
			if !strings.Contains(got, "upstream down") {
				t.Errorf("error = %q, want the wrapped cause preserved", got)
			}
		})
	}
}

// TestOpenerRejection_MethodNotFoundNamesThePinRemedy is the diagnostic that stands in for the
// probe. -32601 on the opener is the one upstream answer that says the method is ABSENT rather
// than failing, and it is exactly the negative an operator pointed at an upstream on the other
// revision hits at startup.
func TestOpenerRejection_MethodNotFoundNamesThePinRemedy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		rev      capability.Revision
		wantPin  string
		wantSent string
	}{
		{"auto against a declaring-only upstream", capability.Revision(""), "2026-07-28", mcp.MethodInitialize},
		{"pinned new against a handshake-only upstream", capability.Revision20260728, "2025-11-25", mcp.MethodServerDiscover},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := openerResult(tc.rev, openerFor(tc.rev).method, mcp.RPCMsg{
				JSONRPC: "2.0",
				ID:      mcp.RawJSON("1"),
				Error:   &mcp.RPCError{Code: mcp.CodeMethodNotFound, Message: "method not found: " + tc.wantSent},
			})
			if err == nil {
				t.Fatal("a -32601 on the opener must fail the open")
			}
			got := err.Error()
			for _, want := range []string{"protocolVersion", tc.wantPin, "does not probe"} {
				if !strings.Contains(got, want) {
					t.Errorf("error = %q, want it to contain %q", got, want)
				}
			}
		})
	}
}

// TestOpenerRejection_OtherCodesCarryNoPinHint is the negative control: the remedy is only
// honest for the one code that means the method is absent. An upstream that rejects the opener
// for any other reason (unauthorized, internal error, a bad protocolVersion offer) is not on
// another revision, and telling an operator to pin one would send them the wrong way.
func TestOpenerRejection_OtherCodesCarryNoPinHint(t *testing.T) {
	t.Parallel()

	for _, code := range []int{-32000, -32602, -32603, capability.JSONRPCCodeAuthorizationFailed} {
		_, err := openerResult(capability.Revision20251125, mcp.MethodInitialize, mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      mcp.RawJSON("1"),
			Error:   &mcp.RPCError{Code: code, Message: "nope"},
		})
		if err == nil {
			t.Fatalf("code %d: an upstream rejection must return an error", code)
		}
		if strings.Contains(err.Error(), "protocolVersion") {
			t.Errorf("code %d: error = %q, must not suggest a pin — this code does not mean the opener is absent", code, err.Error())
		}
	}
}

// TestAlternativeOpenerRevisions_NamesOnlyADifferentOpener pins the derivation the hint rests
// on. A revision that shares this one's opener is no remedy for the opener being absent, and a
// third published revision must reach the hint without this code being edited.
func TestAlternativeOpenerRevisions_NamesOnlyADifferentOpener(t *testing.T) {
	t.Parallel()

	for _, rev := range capability.PublishedRevisions() {
		got := alternativeOpenerRevisions(rev)
		if len(got) == 0 {
			t.Errorf("%s: no alternative opener revision — the -32601 hint would be silent", rev)
		}
		for _, name := range got {
			if name == rev.String() {
				t.Errorf("%s: named itself as the alternative", rev)
			}
			alt, ok := capability.ParseRevision(name)
			if !ok {
				t.Fatalf("%s: alternative %q is not a published revision", rev, name)
			}
			if openerRegistry[alt].method == openerRegistry[rev].method {
				t.Errorf("%s: named %s, whose opener is the same method — that is no remedy", rev, name)
			}
		}
	}
}

// errStub is a minimal error so the wrapper test does not depend on any real open failure.
type errStub struct{ msg string }

func (e errStub) Error() string { return e.msg }
