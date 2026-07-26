// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// URL credential redaction for the OPERATOR-FACING surfaces — today the doctor support
// bundle's URL-bearing config fields and its audit-tail targets — so a userinfo
// credential or a ?token=/#access_token= secret cannot leak through any of them. It
// handles the hierarchical, opaque, scheme-less, and unparseable forms and fails safe
// (never returns the raw value) on anything url.Parse cannot handle.
//
// The surface rule, stated once here: this redactor keeps the path and the query
// parameter NAMES, which is the detail an operator reading their own bundle needs.
// Anything that reaches a LOG — a startup banner, a validation error, a runtime warning,
// all of which land in the systemd journal, container stdout, or a CI log — uses the
// stricter capability.RedactURLForLog instead, which keeps only scheme://host. Neither is
// a fallback for the other: picking by surface is what keeps one process from redacting
// the same URL two ways.

package config

import (
	"fmt"
	"net/url"
	"strings"
)

// RedactURL replaces userinfo (user:pass@) and every non-empty query value with a
// placeholder, leaving scheme/host/path and query parameter names intact — a
// credential is as likely in ?api_key=/?token= as in userinfo. A URL with neither is
// returned unchanged. On a url.Parse failure the raw value is NOT returned (a malformed
// URL can still carry a credential); a conservative textual redaction is used instead.
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
		// Replace each non-empty query value with a length-tagged placeholder,
		// preserving parameter order and names. url.URL.String() emits RawQuery
		// verbatim, so the placeholder stays unencoded. The length is the decoded byte
		// count (via QueryUnescape), falling back to the raw count on a malformed escape.
		parts := strings.Split(u.RawQuery, "&")
		queryChanged := false
		for i, p := range parts {
			if p == "" {
				continue // empty segment (e.g. trailing "&"): nothing to redact
			}
			eq := strings.IndexByte(p, '=')
			if eq < 0 {
				// A bare token with no "=" is a value with no name (e.g. "?sk_live_abcdef"
				// or "?<jwt>"); it can be a credential just as readily as a key=value pair.
				// Redact the whole token to a length-tagged placeholder rather than passing
				// it through (the redactURLFallback sibling drops such tokens entirely, so
				// the parseable path must not be strictly less safe).
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
	// The fragment is a credential location too: the OAuth 2.0 implicit flow returns
	// #access_token=... in the fragment, and other schemes stash bearer tokens there.
	// u.String() re-emits it verbatim, so drop it entirely (its structure is not
	// guaranteed key=value, so a whole-component drop is the safe scrub).
	if u.Fragment != "" || u.RawFragment != "" {
		u.Fragment = ""
		u.RawFragment = ""
		changed = true
	}
	// url.Parse accepts opaque ("custom:user:pass@host") and scheme-less
	// ("user:pass@host/path") credentialed forms, where the userinfo lands in u.Opaque
	// rather than u.User and the query never populates u.RawQuery, so the userinfo/query
	// scrubs above cannot reach it. An opaque form has NO "scheme://" authority, so it must
	// NOT be handed verbatim to redactURLFallback's authority heuristic: that anchors on
	// the FIRST "://" and scans for the credential's '@' only AFTER it, but a "://"
	// appearing later inside the opaque data (e.g. "scheme:user:pass@host://x") sits past
	// the credential, so the scan would miss it and return the value unredacted. When the
	// opaque part carries an '@' (a possible userinfo credential), redact wholesale;
	// otherwise the textual fallback still strips any query/fragment on the raw string.
	if u.Opaque != "" {
		if strings.Contains(u.Opaque, "@") {
			return "<redacted unparseable URL>"
		}
		return redactURLFallback(s)
	}
	if u.Host == "" && !strings.Contains(s, "//") && strings.Contains(u.Path, "@") {
		// No authority marker anywhere in the value, yet the path carries an '@'. Two
		// shapes land here, and neither can be echoed: a single-slash scheme typo
		// ("https:/alice:SECRET@host/mcp" — url.Parse puts the WHOLE credentialed
		// authority in u.Path, which no scrub above inspects, so `changed` stayed false
		// and the raw credential was returned verbatim), and the scheme-less
		// "user@host/path" form. Hand both to the conservative fallback, which cannot
		// locate the credential boundary in either and replaces the whole value.
		//
		// Keyed on the ABSENT "//" rather than on u.Host alone so a genuine authority-less
		// hierarchical URL ("file:///home/a@b/x") keeps its path: there the '@' really is a
		// path character, and the empty authority is explicit rather than a typo.
		return redactURLFallback(s)
	}
	if !changed {
		// A hierarchical "scheme://host/..." with authority credentials always populates
		// u.User (handled above), so a bare '@' in the path of an opaque-free,
		// fragment-free URL is not a credential and is correctly returned unchanged
		// (redacting it would needlessly mangle a legitimate value).
		return s
	}
	return u.String()
}

// redactURLFallback conservatively strips userinfo from a URL string url.Parse could
// not handle. It locates the authority (after "scheme://", up to the first '/', '?', or
// '#') and replaces anything before its last '@' with "REDACTED". If an '@' still
// appears past the authority boundary (a malformed URL where the credential cannot be
// located safely), or the string has no "scheme://" but contains an '@', the whole value
// is replaced with a placeholder.
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
		// No userinfo in the authority — but this fallback only runs because url.Parse
		// failed, so an '@' past the authority boundary (credentials hidden after an
		// unescaped '/') cannot be located safely; replace the whole value.
		if strings.Contains(tail, "@") {
			return "<redacted unparseable URL>"
		}
		return redactRawQuery(s)
	}
	return redactRawQuery(s[:authStart] + "REDACTED@" + authority[at+1:] + tail)
}

// redactRawQuery replaces the query AND fragment components of a raw (possibly
// unparseable) URL, so a ?api_key=/?token= or #access_token= credential cannot leak
// through the url.Parse-failure path. The query runs from the first '?' to '#' or end;
// scheme/host/path are preserved and an empty "?" is left as-is. A non-empty fragment is
// DROPPED ENTIRELY (delimiter included), matching how the parse-success path (RedactURL)
// scrubs u.Fragment, so the same #fragment renders identically regardless of which path
// handled it; a bare '#' is preserved.
//
// Unlike RedactURL's per-value scrub, this drops the whole query including parameter
// names: since the URL would not parse, the query cannot be safely tokenized on '='/'&'
// (an encoded '%26' could split differently than the server reads it), so wholesale
// redaction is the safe tradeoff. The same reasoning applies to the fragment.
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
