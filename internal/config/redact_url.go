// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// URL credential redaction for the OPERATOR-FACING surfaces — the doctor support bundle's
// URL-bearing config fields and its audit-tail targets. Keeps the path, and the NAME of a query
// parameter that unambiguously has one (the detail an operator reading their own bundle needs);
// a LOG-facing surface uses the stricter capability.RedactURLForLog instead, which keeps only
// scheme://host.

package config

import (
	"fmt"
	"net/url"
	"strings"
)

// RedactURL replaces userinfo (user:pass@) and every query value with a placeholder, leaving
// scheme/host/path and the name of an unambiguous NAME=VALUE parameter intact. Any other query
// segment is replaced WHOLE, name included, being indistinguishable from a bare credential token
// (see splitQueryPair). On a url.Parse failure the raw value is never returned (a malformed URL
// can still carry a credential); falls back to a conservative textual redaction instead.
func RedactURL(s string) string {
	if s == "" {
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		return redactURLFallback(s)
	}
	changed := false
	if u.User != nil {
		u.User = url.UserPassword("REDACTED", "REDACTED")
		changed = true
	}
	if u.RawQuery != "" {
		// url.URL.String() emits RawQuery verbatim, so the placeholder stays unencoded.
		parts := strings.Split(u.RawQuery, "&")
		queryChanged := false
		for i, p := range parts {
			if p == "" {
				continue // empty segment (e.g. trailing "&"): nothing to redact
			}
			queryChanged = true
			if name, val, ok := splitQueryPair(p); ok {
				parts[i] = name + "=" + redactedPlaceholder(val)
				continue
			}
			// Not a pair, so the whole segment is one opaque token: see splitQueryPair.
			parts[i] = redactedPlaceholder(p)
		}
		if queryChanged {
			u.RawQuery = strings.Join(parts, "&")
			changed = true
		}
	}
	// The fragment is a credential location too (OAuth 2.0 implicit flow's #access_token=...);
	// drop it entirely rather than parse it, since its structure is not guaranteed key=value.
	if u.Fragment != "" || u.RawFragment != "" {
		u.Fragment = ""
		u.RawFragment = ""
		changed = true
	}
	// url.Parse's opaque/scheme-less credentialed forms land userinfo in u.Opaque, not
	// u.User, so the scrubs above miss it; redactURLFallback's "://"-anchored heuristic
	// can also miss a credential sitting before a later "://" in the opaque data, so an
	// opaque value carrying '@' is redacted wholesale instead of deferred to it.
	if u.Opaque != "" {
		if strings.Contains(u.Opaque, "@") {
			return "<redacted unparseable URL>"
		}
		return redactURLFallback(s)
	}
	if u.Scheme != "" && u.OmitHost && strings.Contains(u.Path, "@") {
		// A single-slash scheme typo ("https:/alice:SECRET@host/mcp") puts the whole
		// credentialed authority in u.Path, unreached by the scrubs above; redact wholesale
		// rather than defer to redactURLFallback, whose "://"-anchored scan could sit past
		// the credential. OmitHost (not a substring scan) is what distinguishes this from a
		// legitimate '@' in a path like "file:///home/a@b/x", where OmitHost is false.
		return "<redacted unparseable URL>"
	}
	if !changed {
		// Authority credentials always populate u.User (handled above), so a bare '@' left
		// in the path here is not a credential.
		return s
	}
	return u.String()
}

// splitQueryPair splits a query segment into a parameter name and value, reporting whether the
// segment is UNAMBIGUOUSLY one name=value pair — the only shape whose name is safe to keep.
//
// A bare token is a credential ("?sk_live_abcdef"), so a segment that is not a pair is redacted
// whole, name included. Deciding that on the first literal '=' is what let a padded credential
// through: base64 pads with '=' whenever a token's byte length is not a multiple of three, so
// "?dG9rZW4=" read as a valueless "key=" and passed through, while "?c2VjcmV0dA==" split at its
// first pad byte and left the secret standing as the name.
//
// A pair therefore requires a non-empty value carrying no '=' of its OWN, decoded first — a
// percent-encoded pad ("?c2VjcmV0dA=%3D") is the same credential spelled differently, and the
// server reads it that way. Everything else is one token: a padded credential in any spelling, a
// valueless "?flag=", and a token with an interior '=' that no shape rule can tell from a name.
//
// The cost is that "?flag=" and a genuine value containing '=' ("?next=a%3Db") lose their names.
// They are indistinguishable from the credential shapes above, and this redactor errs toward
// redacting.
func splitQueryPair(p string) (name, val string, ok bool) {
	name, val, ok = strings.Cut(p, "=")
	if !ok {
		return "", "", false
	}
	decoded := val
	if d, derr := url.QueryUnescape(val); derr == nil {
		decoded = d
	}
	if decoded == "" || strings.Contains(decoded, "=") {
		return "", "", false
	}
	return name, val, true
}

// redactedPlaceholder renders one redacted span, reporting its DECODED byte count so the number
// matches what redactConfigValue prints for the same secret in plain config (and falling back to
// the raw count for an unparseable escape).
//
// ONE implementation for both spans a segment can be redacted over — a pair's value, and a whole
// bare token — so what "length" means has one home rather than two arms to keep in step. For a
// bare token the span IS the segment, name bytes included, there being no name to hold apart.
func redactedPlaceholder(v string) string {
	n := len(v)
	if decoded, derr := url.QueryUnescape(v); derr == nil {
		n = len(decoded)
	}
	return fmt.Sprintf("<redacted len=%d>", n)
}

// redactURLFallback conservatively strips userinfo from a URL string url.Parse could not
// handle, replacing the whole value with a placeholder when the credential's location
// cannot be determined safely.
func redactURLFallback(s string) string {
	const sep = "://"
	schemeEnd := strings.Index(s, sep)
	if schemeEnd < 0 {
		if strings.Contains(s, "@") {
			return "<redacted unparseable URL>"
		}
		return redactRawQuery(s)
	}
	authStart := schemeEnd + len(sep)
	rest := s[authStart:]
	authority := rest
	tail := ""
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		authority = rest[:end]
		tail = rest[end:]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		// An '@' past the authority boundary cannot be located safely; replace the whole value.
		if strings.Contains(tail, "@") {
			return "<redacted unparseable URL>"
		}
		return redactRawQuery(s)
	}
	return redactRawQuery(s[:authStart] + "REDACTED@" + authority[at+1:] + tail)
}

// redactRawQuery replaces the query AND fragment components of a raw (possibly
// unparseable) URL wholesale, including parameter names: an unparseable query cannot be
// safely tokenized on '='/'&' (an encoded '%26' could split differently than the server
// reads it). A non-empty fragment is dropped entirely, matching RedactURL's u.Fragment scrub.
func redactRawQuery(s string) string {
	// Split the fragment off first so it is redacted whether or not a query exists.
	fragMarker := ""
	if h := strings.IndexByte(s, '#'); h >= 0 {
		if h == len(s)-1 {
			fragMarker = "#" // bare '#', nothing to redact; preserved like RedactURL
		}
		// A non-empty fragment is dropped entirely (fragMarker stays ""), mirroring
		// RedactURL's u.Fragment = "".
		s = s[:h]
	}
	q := strings.IndexByte(s, '?')
	if q < 0 || q == len(s)-1 {
		// No query, or an empty "?" trailer: leave the query span untouched.
		return s + fragMarker
	}
	return s[:q] + "?<redacted query>" + fragMarker
}
