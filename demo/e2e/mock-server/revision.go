// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The 2026-07-28 half of the mock upstream.
//
// One binary serves both revisions because the interop matrix needs the SAME upstream
// behaviour on either side of the revision boundary: a cell that differed in its catalog or
// its tool results would prove the catalog differed, not that the revision did. So the
// catalog, the tool dispatch and the transports are shared, and everything a revision
// actually changes lives here — which method opens the leg, which methods exist at all, and
// what shape a result carries.
//
// The declaration gate is the load-bearing part. A declaring upstream REFUSES a request that
// does not carry `io.modelcontextprotocol/protocolVersion` in its `_meta`, rather than
// serving it anyway, so the matrix proves eunox declares the revision on every request it
// sends a declaring leg. A permissive mock would pass whether or not the proxy declared
// anything, which is the assertion this file exists to make impossible to fake.

package main

import (
	"encoding/json"
	"fmt"
)

const (
	// revisionHandshake is the revision whose initialize/notifications/initialized pair opens
	// a leg; revisionDeclaring is the one that removes the handshake and carries the version
	// in every request's `_meta`.
	revisionHandshake = "2025-11-25"
	revisionDeclaring = "2026-07-28"

	// metaKeyProtocolVersion is the `_meta` member a declaring peer states its revision under,
	// mirroring capability.MetaKeyProtocolVersion. Spelled here rather than imported: the mock
	// is a black-box peer, and importing the proxy's own constant would let a typo in the
	// constant pass the matrix by agreeing with itself.
	metaKeyProtocolVersion = "io.modelcontextprotocol/protocolVersion"
)

// serverRevision is the revision this process speaks, set once from --protocol-version.
var serverRevision = revisionHandshake

// declaring reports whether this process speaks the revision that carries its version in
// every request rather than negotiating it once.
func declaring() bool { return serverRevision == revisionDeclaring }

// methodRemovedInDeclaring lists the methods 2026-07-28 removes. A declaring upstream answers
// -32601 for each, which is what lets the matrix assert that eunox never sends them to such a
// leg — a mock that quietly served `ping` would hide exactly that regression.
var methodRemovedInDeclaring = map[string]bool{
	"initialize":            true,
	"ping":                  true,
	"resources/subscribe":   true,
	"resources/unsubscribe": true,
	"completion/complete":   true,
}

// methodAddedInDeclaring lists the methods only 2026-07-28 has. The handshake revision
// answers -32601 for them, which is the reply eunox's own opener gets when an operator pins a
// revision the upstream does not actually speak.
var methodAddedInDeclaring = map[string]bool{
	"server/discover": true,
}

// discoverResult is the declaring revision's replacement for the initialize result.
//
// It deliberately does NOT carry `protocolVersion`. A declaring leg negotiates no version, so
// a conforming server answers with none, and eunox's checkNegotiatedRevision treats a
// volunteered one as a disagreement to report. Answering with the field would make the mock a
// non-conforming server and the matrix would be asserting against the wrong peer.
func discoverResult() map[string]interface{} {
	result := initializeResult()
	delete(result, "protocolVersion")
	// The subscribe capability belongs to the resources/subscribe pair this revision removes;
	// subscriptions/listen replaces it and no responder exists on either side yet.
	result["capabilities"] = map[string]interface{}{
		"tools":     map[string]interface{}{"listChanged": true},
		"resources": map[string]interface{}{"listChanged": true},
		"prompts":   map[string]interface{}{"listChanged": true},
	}
	return result
}

// checkDeclaration refuses a request that reached a declaring upstream without the per-request
// revision declaration, or with one naming a different revision.
//
// Notifications are exempt: eunox forwards a host's notifications verbatim and originates
// none of its own on a declaring leg, so requiring a declaration there would refuse a message
// on the strength of what the HOST omitted rather than what the proxy did.
func checkDeclaration(msg *rpcMsg) *rpcError {
	if !declaring() || !msg.isRequest() {
		return nil
	}
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return &rpcError{Code: -32600, Message: "params are not a JSON object on a declaring leg"}
		}
	}
	raw, ok := params.Meta[metaKeyProtocolVersion]
	if !ok {
		return &rpcError{Code: -32600, Message: fmt.Sprintf(
			"request %q carries no %s declaration; %s requires one on every request",
			msg.Method, metaKeyProtocolVersion, revisionDeclaring)}
	}
	var declared string
	if err := json.Unmarshal(raw, &declared); err != nil {
		return &rpcError{Code: -32600, Message: "protocol version declaration is not a JSON string"}
	}
	if declared != serverRevision {
		return &rpcError{Code: -32600, Message: fmt.Sprintf(
			"request declares protocol version %q; this server speaks %s", declared, serverRevision)}
	}
	return nil
}

// checkMethodExists refuses a method the running revision does not have, so each revision's
// method set is enforced by the peer rather than assumed by the test.
func checkMethodExists(method string) *rpcError {
	missing := methodAddedInDeclaring[method]
	if declaring() {
		missing = methodRemovedInDeclaring[method]
	}
	if missing {
		return &rpcError{Code: -32601, Message: "method not found: " + method}
	}
	return nil
}

// stampResultShape adds the 2026-07-28 result-shape members to a result the declaring
// revision is returning.
//
// `resultType: "complete"` is the terminal variant — this mock never opens a multi
// round-trip exchange, so every result it produces is complete by construction.
// `cacheScope: "public"` on the list results is deliberately the WRONG answer for a filtered
// response: eunox clamps it to `private` on anything it filtered, and a mock that volunteered
// `private` could not tell a working clamp from an absent one. The host asserts the clamped
// value, so this is the upstream half of that assertion rather than a value nobody reads.
func stampResultShape(method string, result interface{}) interface{} {
	if !declaring() {
		return result
	}
	fields, ok := result.(map[string]interface{})
	if !ok {
		return result
	}
	fields["resultType"] = "complete"
	switch method {
	case "tools/list", "resources/list", "prompts/list":
		fields["cacheScope"] = "public"
		fields["ttlMs"] = 60000
	}
	return fields
}
