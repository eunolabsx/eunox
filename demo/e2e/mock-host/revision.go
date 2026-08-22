// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The 2026-07-28 half of the mock host, and the interop-matrix suites.
//
// A new-revision host differs from the old one in exactly two ways on the wire, and this file
// is both of them: it opens no session (the handshake is gone) and it carries
// `io.modelcontextprotocol/protocolVersion` in the `_meta` of every request. Everything else —
// the connection, the id matching, the assertion helpers — is shared with the old host, which
// is what makes a matrix cell's result attributable to the revision rather than to the client.
//
// # What the matrix asserts, and why the mismatched cells are the interesting ones
//
// ADR-0006 draws a boundary: translate the stateless-safe subset across a mismatched pair,
// refuse the rest. This build translates NOTHING, so the whole boundary is currently the
// refusal — every mismatched pair is -32022, in both directions. That is an assertion, not an
// absence: the refusal is the shipped behaviour, and pinning it here is what makes activating
// translation later a visible change to this file rather than a silent widening.

package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	revisionHandshake = "2025-11-25"
	revisionDeclaring = "2026-07-28"

	// metaKeyProtocolVersion mirrors capability.MetaKeyProtocolVersion. Spelled out rather
	// than imported for the reason the mock server spells it out: a black-box peer that
	// imported the proxy's own constant would agree with a typo in it.
	metaKeyProtocolVersion = "io.modelcontextprotocol/protocolVersion"

	// codeUnsupportedProtocolVersion is the spec's -32022, the refusal both mismatched cells
	// of the matrix must produce.
	codeUnsupportedProtocolVersion = -32022
	// codeUnroutableMethod is eunox's -32001, what a method outside the peer's revision table
	// falls to.
	codeUnroutableMethod = -32001
)

// declareRevision returns params with the per-request revision declaration merged into
// `_meta`, leaving anything already there in place.
//
// Merged rather than overwritten because a host's `_meta` is its own: eunox forwards it
// verbatim, and a mock that replaced the block would stop exercising that.
func declareRevision(params interface{}, revision string) interface{} {
	if revision != revisionDeclaring {
		return params
	}
	fields := map[string]interface{}{}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return params
		}
		if err := json.Unmarshal(raw, &fields); err != nil {
			return params
		}
	}
	meta, _ := fields["_meta"].(map[string]interface{})
	if meta == nil {
		meta = map[string]interface{}{}
	}
	meta[metaKeyProtocolVersion] = revision
	fields["_meta"] = meta
	return fields
}

// resultField reads a top-level string member off a result, or "" when it is absent or not a
// string. Deliberately does not distinguish those: every caller is asserting a specific value,
// so any other answer is a failure and naming which kind would not change the verdict.
func resultField(m rpcMsg, key string) string { //nolint:gocritic // hugeParam: rpcMsg by value mirrors the proxy convention.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(m.Result, &raw); err != nil {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw[key], &value); err != nil {
		return ""
	}
	return value
}

// expectRevisionRefusal asserts the -32022 boundary: the request is refused, under the spec's
// code, with a message naming both sides of the mismatch.
//
// The message is asserted, not just the code, because -32022 is also what a host declaring an
// unknown version gets. A cell that accepted any -32022 would pass if eunox refused for the
// wrong reason, which on a mismatched pair is the failure most likely to look like a success.
func (s *suite) expectRevisionRefusal(desc, wantHostRev, wantLegRev string, m rpcMsg, err error) { //nolint:gocritic // hugeParam: rpcMsg by value mirrors the proxy convention.
	if err != nil {
		s.bad(desc, "transport error: "+err.Error())
		return
	}
	if m.Error == nil {
		s.bad(desc, "expected a -32022 refusal, got a result")
		return
	}
	if m.Error.Code != codeUnsupportedProtocolVersion {
		s.bad(desc, fmt.Sprintf("code = %d, want %d", m.Error.Code, codeUnsupportedProtocolVersion))
		return
	}
	for _, want := range []string{wantHostRev, wantLegRev} {
		if !strings.Contains(m.Error.Message, want) {
			s.bad(desc, fmt.Sprintf("message %q does not name %q", m.Error.Message, want))
			return
		}
	}
	s.ok(desc)
}

// runInteropMatched drives a matched pair: the host and the upstream speak the same revision,
// so the full enforced surface must work.
//
// It is deliberately a SUBSET of runStdioFull rather than a second copy of it. What a matched
// cell proves is that the revision boundary is crossed correctly — the leg opens, the
// declaration reaches the upstream, filtering and enforcement still apply. The exhaustive
// condition matrix is runStdioFull's job and does not become a different assertion by being
// re-run under another revision.
func runInteropMatched(c *stdioConn, s *suite, revision string) {
	m, err := c.call("tools/list", nil)
	s.expectAllow("tools/list serves a matched "+revision+" pair", m, err)
	names := listNames(m, "tools", "name")
	if contains(names, "read_file") && !contains(names, "write_file") {
		s.ok("tools/list is still policy-filtered under " + revision)
	} else {
		s.bad("tools/list is still policy-filtered under "+revision,
			fmt.Sprintf("got %v; want read_file present and write_file absent", names))
	}

	if revision == revisionDeclaring {
		// The upstream volunteers `cacheScope: "public"` on this list, which is the wrong answer
		// for a response the proxy filtered per caller identity — a shared cache downstream
		// honouring it could serve one identity's narrowed view to another. The proxy clamps it.
		// Asserted here rather than trusted because the mock's `public` and the host's `private`
		// are the two halves of one property, and only the pair proves the clamp ran: a mock
		// that sent `private` would read the same whether or not it did.
		if got := resultField(m, "cacheScope"); got != "private" {
			s.bad("a filtered list is clamped to cacheScope private under "+revision,
				fmt.Sprintf("cacheScope = %q, want \"private\" (the upstream sent \"public\")", got))
		} else {
			s.ok("a filtered list is clamped to cacheScope private under " + revision)
		}
	}

	m, err = c.call(toolCall("read_file", map[string]interface{}{"path": "/reports/q3.pdf"}))
	s.expectAllow("tools/call ALLOW under "+revision, m, err)
	if !strings.Contains(toolText(m), "/reports/q3.pdf") {
		s.bad("tools/call ALLOW returns the upstream result under "+revision, "unexpected text: "+toolText(m))
	} else {
		s.ok("tools/call ALLOW returns the upstream result under " + revision)
	}

	m, err = c.call(toolCall("write_file", map[string]interface{}{"path": "/etc/x", "content": "y"}))
	s.expectDeny("tools/call deny-by-default under "+revision, "AUTHORIZATION_FAILED", "", m, err)

	m, err = c.call(toolCall("query_db", map[string]interface{}{"query": "DELETE FROM t"}))
	s.expectDeny("a condition still denies under "+revision, "OPERATION_NOT_PERMITTED", "allowedOperations", m, err)

	m, err = c.call("resources/read", map[string]interface{}{"uri": "file:///data/reports/q3.pdf"})
	s.expectAllow("resources/read ALLOW under "+revision, m, err)

	m, err = c.call("resources/read", map[string]interface{}{"uri": "file:///data/secret.txt"})
	s.expectDeny("resources/read deny-by-default under "+revision, "AUTHORIZATION_FAILED", "", m, err)

	m, err = c.call("prompts/get", map[string]interface{}{"name": "code_review"})
	s.expectAllow("prompts/get ALLOW under "+revision, m, err)

	m, err = c.call("prompts/get", map[string]interface{}{"name": "internal_secret_prompt"})
	s.expectDeny("prompts/get deny-by-default under "+revision, "AUTHORIZATION_FAILED", "", m, err)
}

// runInteropDeclaringMethodSet asserts the method set a 2026-07-28 peer actually reaches.
//
// The methods this revision ADDS (server/discover, subscriptions/listen, tasks/*) have no
// responder in this build and are deliberately absent from the proxy's registry, so they must
// deny fail-closed. Asserting that here is what keeps "not implemented yet" from quietly
// becoming "routed to something" — the registry comment says they deny; this proves it over a
// real transport.
func runInteropDeclaringMethodSet(c *stdioConn, s *suite) {
	// Every entry here must be one 2026-07-28 actually REMOVED and 2025-11-25 has — i.e. one
	// declared `In: {2025-11-25}` in the proxy's methodRegistry. completion/complete was in this
	// list and did not belong: it has no registry entry under EITHER revision, so it answers
	// UNROUTABLE_METHOD identically for both peers and the cell would not change outcome under
	// any regression of the removal it claimed to cover. runStdioFull already asserts it under
	// 2025-11-25, where it is an ordinary unmapped method.
	removed := []string{"ping", "resources/subscribe", "resources/unsubscribe"}
	for _, method := range removed {
		m, err := c.call(method, map[string]interface{}{})
		s.expectErrorCode(method+" (removed in 2026-07-28) is unroutable", codeUnroutableMethod, m, err)
	}
	unimplemented := []string{"server/discover", "subscriptions/listen", "tasks/get", "tasks/update", "tasks/cancel"}
	for _, method := range unimplemented {
		m, err := c.call(method, map[string]interface{}{})
		s.expectErrorCode(method+" (no responder yet) denies fail-closed", codeUnroutableMethod, m, err)
	}
}

// runInteropMismatch drives a mismatched pair and asserts the ADR-0006 refusal in both
// directions. hostRev is what this host declares; legRev is what the proxy addresses its
// upstream as.
func runInteropMismatch(c *stdioConn, s *suite, hostRev, legRev string) {
	desc := fmt.Sprintf("host %s x upstream %s", hostRev, legRev)

	// A handshake-revision host opens with `initialize`, and against a declaring leg that is
	// the most explicit statement of the boundary eunox puts on the wire: it names both
	// revisions AND says translation is what it would take. Asserted separately from the
	// enforced methods below because it is the only message that says so.
	if hostRev == revisionHandshake {
		m, err := c.call("initialize", map[string]interface{}{
			"protocolVersion": hostRev,
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "e2e-mock-host", "version": "1.0"},
		})
		s.expectRevisionRefusal(desc+": initialize refused -32022", hostRev, legRev, m, err)
		if m.Error != nil && !strings.Contains(m.Error.Message, "translating a mismatched pair") {
			s.bad(desc+": the initialize refusal names translation as what it would take",
				"message did not say so: "+m.Error.Message)
		} else if m.Error != nil {
			s.ok(desc + ": the initialize refusal names translation as what it would take")
		}
	}

	m, err := c.call("tools/list", nil)
	s.expectRevisionRefusal(desc+": tools/list refused -32022", hostRev, legRev, m, err)

	m, err = c.call(toolCall("read_file", map[string]interface{}{"path": "/reports/q3.pdf"}))
	s.expectRevisionRefusal(desc+": an allowed tools/call is still refused", hostRev, legRev, m, err)

	// The refusal must precede enforcement, not follow it: a call the policy would DENY has to
	// come back as the revision refusal too, or the proxy decided a request it cannot honor.
	m, err = c.call(toolCall("write_file", map[string]interface{}{"path": "/etc/x", "content": "y"}))
	s.expectRevisionRefusal(desc+": a denied tools/call is refused on revision, not policy", hostRev, legRev, m, err)
}
