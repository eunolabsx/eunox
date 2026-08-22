// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Which MCP revision this mock serves, and everything that follows from it.
//
// One flag, one variable, and every per-revision difference read off it — the same shape
// the proxy's own upstream-opener registry uses, ported rather than copied: this mock is
// deliberately minimal (three tools, one transport) and models only what the demo
// walkthrough exercises.
//
// A mock that served BOTH openers would be useless for the thing the demo is for. The
// boundary between the revisions is what an operator needs to see, so serving the revision
// this mock is not started at means answering -32601, exactly as a real single-revision
// server does.
package main

import (
	"encoding/json"
	"fmt"
)

const (
	// revisionHandshake negotiates its version once, through initialize.
	revisionHandshake = "2025-11-25"
	// revisionDeclaring removed the handshake: server/discover opens the leg, and every
	// request carries the protocol version in its own `_meta`.
	revisionDeclaring = "2026-07-28"

	// metaKeyProtocolVersion is the `_meta` member a declaring peer states its revision under.
	metaKeyProtocolVersion = "io.modelcontextprotocol/protocolVersion"

	// listCacheTTLMs is the freshness hint the declaring revision pairs with cacheScope.
	listCacheTTLMs = 60000
)

// protocolRevision is the revision this process serves, set once from --protocol-version
// before any message is read.
var protocolRevision = revisionHandshake

// parseProtocolRevision validates a --protocol-version value. Unknown values are refused
// rather than defaulted: a typo that silently served the old revision would make the
// mismatch cells of a demo pass for the wrong reason.
func parseProtocolRevision(v string) (string, error) {
	switch v {
	case revisionHandshake, revisionDeclaring:
		return v, nil
	default:
		return "", fmt.Errorf("unknown --protocol-version %q (want %s or %s)", v, revisionHandshake, revisionDeclaring)
	}
}

// declaring reports whether this process serves the revision that declares its version per
// request instead of negotiating one.
func declaring() bool { return protocolRevision == revisionDeclaring }

// openerMethod is the method that opens a leg at the served revision. The other revision's
// opener is answered -32601, which is what makes the boundary observable.
func openerMethod() string {
	if declaring() {
		return "server/discover"
	}
	return "initialize"
}

// openerResult is the reply to the opener. The declaring revision negotiates no version, so
// a conforming reply carries none — volunteering one would state a disagreement the proxy
// checks for.
func openerResult() map[string]interface{} {
	result := map[string]interface{}{
		"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
		"serverInfo": map[string]interface{}{
			"name":    serverName,
			"version": serverVersion,
		},
	}
	if !declaring() {
		result["protocolVersion"] = protocolRevision
	}
	return withResultShape(result)
}

// withResultShape adds the members the declaring revision requires of every result, and
// nothing at all under the handshake revision — which has no such members, so old-revision
// output stays byte-identical to what this mock has always sent.
func withResultShape(result map[string]interface{}) map[string]interface{} {
	if declaring() {
		result["resultType"] = "complete"
	}
	return result
}

// withListCaching adds the caching members the declaring revision requires of a list result.
//
// `cacheScope: "public"` is deliberately the WRONG answer for a response the proxy filters
// per caller. eunox clamps a filtered list to `private`, and a mock that volunteered
// `private` could not tell a working clamp from an absent one — the demo's `stateless-list`
// target reads the scope off the proxy's answer, so this has to be the value that fails if
// the clamp ever stops applying.
func withListCaching(result map[string]interface{}) map[string]interface{} {
	if declaring() {
		result["cacheScope"] = "public"
		result["ttlMs"] = listCacheTTLMs
	}
	return withResultShape(result)
}

// checkDeclaration returns a non-empty message when msg does not carry the per-request
// protocol declaration the served revision requires of every request.
//
// Only the declaring revision requires one; under the handshake revision the version was
// agreed once and a request carrying no `_meta` is conforming. Enforcing it is the point of
// the mock: it proves the proxy declares on the requests it originates (its opener and its
// drift probe) and forwards a host's own declaration untouched.
func checkDeclaration(params json.RawMessage) string {
	if !declaring() {
		return ""
	}
	var fields struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &fields); err != nil {
			return "invalid params: not a JSON object"
		}
	}
	raw, ok := fields.Meta[metaKeyProtocolVersion]
	if !ok {
		return fmt.Sprintf("invalid request: %s requires every request to declare %q in params._meta",
			revisionDeclaring, metaKeyProtocolVersion)
	}
	var declared string
	if err := json.Unmarshal(raw, &declared); err != nil || declared != protocolRevision {
		return fmt.Sprintf("invalid request: declared protocol version %s, but this server speaks %s",
			string(raw), protocolRevision)
	}
	return ""
}
