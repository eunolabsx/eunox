// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The `forwardClientHeaders` allowlist: which of a host's HTTP headers eunox relays to an
// upstream, and why the default is none of them.
//
// # The posture
//
// 2026-07-28 blesses custom client headers as a passthrough mechanism. Through a PROXY that is
// a smuggling surface: every header a host can set becomes a channel to an upstream that eunox
// does not police, carrying whatever the host wants past a boundary whose whole job is that
// nothing crosses unexamined. So nothing crosses by default, in either direction, and an
// operator opts a NAMED header in per upstream. There is no wildcard — a wildcard is the
// default this posture exists to refuse, spelled as a configuration.
//
// The RESPONSE direction has no key at all. eunox builds its host-facing response itself and
// copies no upstream header into it, which is a stronger posture than an allowlist and needs no
// per-upstream question: an upstream header reaching the host would be a second party setting
// cookies, cache directives and auth challenges on eunox's own connection, and there is no
// legitimate form of that a named-header list would let through.
//
// # Why some names can never be listed
//
// A forwarded header that collides with one eunox sets on the same request is not a
// passthrough, it is an override — of the credential the operator configured, of the protocol
// version the leg negotiated, of the routing headers eunox derives from the body it is
// forwarding. Every one of those is a control eunox is accountable for, so the collision is
// refused at STARTUP, where an operator can see it, rather than resolved at request time by
// whichever assignment happens to run last.

package config

import (
	"fmt"
	"net/textproto"
	"sort"
	"strings"
)

// ReservedUpstreamHeaders names the headers eunox itself controls on an upstream request, each
// with the reason it may not be forwarded. Keys are canonical MIME header names.
//
// The transport proves this covers reality rather than intent: a test there drives a real
// upstream call and fails if eunox sends a header this table does not name, so a new header on
// the outbound leg cannot silently become forwardable.
var ReservedUpstreamHeaders = map[string]string{
	"Authorization":        "the upstream credential is 'upstreamAuthHeader'; forwarding the host's would let a caller present its own to the upstream",
	"Proxy-Authorization":  "a credential for the hop itself, never the host's to set",
	"Mcp-Protocol-Version": "the revision the leg negotiated, which a host may not restate",
	"Mcp-Session-Id":       "the UPSTREAM's session, which eunox owns; the host's own session id is a different namespace",
	"Mcp-Method":           "derived from the body eunox is forwarding, and required to be byte-exact with it",
	"Mcp-Name":             "derived from the body eunox is forwarding, and required to be byte-exact with it",
	"Content-Type":         "the forwarded body is JSON-RPC that eunox marshalled",
	"Content-Length":       "describes the body eunox marshalled, not the one it received",
	"Accept":               "eunox must advertise both JSON and SSE to read either answer",
	"Accept-Encoding":      "the transfer coding of eunox's own connection to the upstream",
	"Host":                 "names the upstream the operator configured; a host-supplied one is a routing override",
	"User-Agent":           "identifies eunox to the upstream, which is what an upstream's own logs attribute the call to",
	"Cookie":               "ambient authority: a credential that travels without being named at the call site, which is what the allowlist exists to prevent",
	"Connection":           "hop-by-hop; forwarding it corrupts eunox's own connection to the upstream",
	"Keep-Alive":           "hop-by-hop; forwarding it corrupts eunox's own connection to the upstream",
	"Proxy-Authenticate":   "hop-by-hop; forwarding it corrupts eunox's own connection to the upstream",
	"Te":                   "hop-by-hop; forwarding it corrupts eunox's own connection to the upstream",
	"Trailer":              "hop-by-hop; forwarding it corrupts eunox's own connection to the upstream",
	"Transfer-Encoding":    "hop-by-hop; forwarding it corrupts eunox's own connection to the upstream",
	"Upgrade":              "hop-by-hop; forwarding it corrupts eunox's own connection to the upstream",
}

// validateForwardClientHeaders checks one upstream's allowlist, refusing anything that is not a
// header name, is one eunox controls, or collides with this route's own configured credential.
//
// authHeaderLine is the route's `upstreamAuthHeader`; the name it sets is reserved for this
// route even when it is not in the table above, since an operator may configure any header as
// the credential and forwarding the host's copy of it would replace the one they configured.
func validateForwardClientHeaders(name string, allow []string, authHeaderLine string) error {
	seen := make(map[string]string, len(allow))
	for _, raw := range allow {
		h := strings.TrimSpace(raw)
		switch {
		case h == "":
			return fmt.Errorf("upstream %q: 'forwardClientHeaders' has an empty entry; remove it, or name the header to forward", name)
		case h == "*":
			return fmt.Errorf("upstream %q: 'forwardClientHeaders' does not accept a wildcard — forwarding every header a host sends is the passthrough this key exists to replace; name each header", name)
		case !validHeaderFieldName(h):
			return fmt.Errorf("upstream %q: 'forwardClientHeaders' entry %q is not a valid HTTP header name", name, h)
		}
		canonical := textproto.CanonicalMIMEHeaderKey(h)
		if prior, dup := seen[canonical]; dup {
			return fmt.Errorf("upstream %q: 'forwardClientHeaders' names %q twice (as %q and %q); header names are case-insensitive", name, canonical, prior, h)
		}
		seen[canonical] = h
		if why, reserved := ReservedUpstreamHeaders[canonical]; reserved {
			return fmt.Errorf("upstream %q: 'forwardClientHeaders' may not name %q — %s", name, canonical, why)
		}
		if credential, ok := authHeaderName(authHeaderLine); ok && canonical == credential {
			return fmt.Errorf("upstream %q: 'forwardClientHeaders' may not name %q — this route's 'upstreamAuthHeader' sets it, and a forwarded copy would replace the credential you configured", name, canonical)
		}
	}
	return nil
}

// authHeaderName returns the canonical header name an `upstreamAuthHeader` line sets.
//
// Parsed here rather than shared with the transport's splitHeaderLine: this layer needs only
// the NAME, and importing the transport would invert the dependency direction the config
// package is defined by.
func authHeaderName(line string) (string, bool) {
	name, _, ok := strings.Cut(line, ":")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return "", false
	}
	return textproto.CanonicalMIMEHeaderKey(name), true
}

// validHeaderFieldName reports whether s is an RFC 9110 field name (a token).
//
// Checked rather than assumed because the value reaches net/http, which panics on some
// malformed names and silently canonicalizes others — either way an operator's typo would
// surface as something other than "that is not a header name".
func validHeaderFieldName(s string) bool {
	if s == "" {
		return false
	}
	const tokenSpecials = "!#$%&'*+-.^_`|~"
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte(tokenSpecials, c) >= 0:
		default:
			return false
		}
	}
	return true
}

// CanonicalForwardClientHeaders returns a route's allowlist in the canonical form the transport
// matches on, sorted so a route's configuration reads the same however it was authored.
//
// Canonicalized once here rather than at each header lookup: net/http stores headers under
// canonical keys, and a per-request canonicalization of operator-fixed strings is work on the
// hot path for an answer that cannot change.
func CanonicalForwardClientHeaders(allow []string) []string {
	if len(allow) == 0 {
		return nil
	}
	out := make([]string, 0, len(allow))
	seen := make(map[string]bool, len(allow))
	for _, h := range allow {
		canonical := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(h))
		if canonical == "" || seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out
}

// assertReservedNamesAreCanonical keeps the table usable as a lookup: an entry authored in
// non-canonical form would never match a canonicalized name and would silently permit the
// header it is there to reserve.
func init() {
	for name := range ReservedUpstreamHeaders {
		if got := textproto.CanonicalMIMEHeaderKey(name); got != name {
			panic(fmt.Sprintf("config: ReservedUpstreamHeaders key %q is not canonical (%q); it would never match", name, got))
		}
	}
}
