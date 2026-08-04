// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// URL credential redaction for the OPERATOR-FACING surfaces — the doctor support bundle's
// URL-bearing config fields and its audit-tail targets. Keeps the path and query parameter
// NAMES (the detail an operator reading their own bundle needs); a LOG-facing surface uses
// the stricter capability.RedactURLForLog instead, which keeps only scheme://host.

package config

import (
	"fmt"
	"net/url"
	"strings"
)

// RedactURL replaces userinfo (user:pass@) and every non-empty query value with a placeholder,
// leaving scheme/host/path and query parameter names intact. On a url.Parse failure the raw
// value is never returned (a malformed URL can still carry a credential); falls back to a
// conservative textual redaction instead.
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
		// Length is the decoded byte count (QueryUnescape), falling back to the raw count.
		parts := strings.Split(u.RawQuery, "&")
		queryChanged := false
		for i, p := range parts {
			if p == "" {
				continue // empty segment (e.g. trailing "&"): nothing to redact
			}
			eq := strings.IndexByte(p, '=')
			if eq < 0 {
				// A bare token with no "=" can be a credential too (e.g. "?sk_live_abcdef");
				// redact the whole token rather than pass it through unredacted.
				n := len(p)
				if decoded, derr := url.QueryUnescape(p); derr == nil {
					n = len(decoded)
				}
				parts[i] = fmt.Sprintf("<redacted len=%d>", n)
				queryChanged = true
				continue
			}
			if eq == len(p)-1 {
				continue // flag-style param with empty value (key=): nothing to redact
			}
			val := p[eq+1:]
			n := len(val)
			if decoded, derr := url.QueryUnescape(val); derr == nil {
				n = len(decoded)
			}
			parts[i] = p[:eq+1] + fmt.Sprintf("<redacted len=%d>", n)
			queryChanged = true
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
