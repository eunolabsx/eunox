// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"net/url"
	"strings"
)

// redactedPath replaces a non-empty URL path in the log-facing redactions below.
const redactedPath = "/[redacted]"

// RedactURLForLog returns u with every credential-bearing component removed, for embedding
// in a log line or an error message. Only scheme://host survives; a non-empty path is
// replaced with "/[redacted]".
//
// Deliberately STRICTER than the operator-facing redactor used by the doctor support bundle
// (config.RedactURL), which preserves query parameter names, secret lengths, and the path —
// appropriate there since the bundle's audit tail needs the path as content, but a length
// oracle and credential leak in a startup banner or CI log, a commonly lower protection tier
// than the config file the secret came from.
//
// The path is dropped because for whole families of endpoints the path IS the credential (a
// Slack webhook, a Telegram bot URL, a presigned object URL): stripping userinfo/query while
// echoing the path verbatim would leak the whole secret, and the likeliest way such a URL
// reaches a validation error is a scheme typo that leaves the path intact.
//
// An unparseable input is not echoed back — that would leak exactly the credentialed URLs
// most likely to be malformed. It is reduced to everything before the first "?"/"#" with
// userinfo stripped and the path replaced, falling back to a fixed placeholder otherwise.
func RedactURLForLog(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return coarseRedactURLForLog(raw)
	}
	// An opaque URL (no "//" authority, e.g. "mailto:") has no structured host to keep and
	// its opaque part may itself carry credentials; reduce it to the scheme alone.
	if u.Opaque != "" {
		return u.Scheme + ":<redacted>"
	}
	// No authority (u.Host == "") — most often a scheme-less value like
	// "hooks.slack.com/services/…". url.Parse puts host and path together in u.Path, so
	// replacing it wholesale would erase the one identifying detail the message needs; hand
	// it to the textual splitter, which cuts at the first "/" instead.
	if u.Host == "" {
		return coarseRedactURLForLog(raw)
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	// RawPath must be overwritten too, not just Path: url.URL.String() emits RawPath
	// whenever it validly encodes Path, so a stale RawPath from percent-escaped input would
	// print the original path and defeat the replacement. Setting both to the same literal
	// also keeps String() from re-escaping '['/']' into "%5Bredacted%5D". A bare "/" is left
	// alone so a host-root URL isn't made to look like it had a path.
	if u.Path != "" && u.Path != "/" {
		u.Path = redactedPath
		u.RawPath = redactedPath
	}
	return u.String()
}

// coarseRedactURLForLog handles input url.Parse rejected, and the parse-succeeded but
// authority-less case above. It keeps only the portion before the first query/fragment
// delimiter, strips any "user:pass@" authority segment, and replaces the path.
func coarseRedactURLForLog(raw string) string {
	cut := raw
	if i := strings.IndexAny(cut, "?#"); i >= 0 {
		cut = cut[:i]
	}
	// Split off the "scheme://" prefix, if any, so the rest is the authority plus path.
	prefix, rest := "", cut
	if i := strings.Index(cut, "//"); i >= 0 {
		prefix, rest = cut[:i+2], cut[i+2:]
		// Strip userinfo: everything up to the last "@" before the authority ends (the
		// first "/").
		end := len(rest)
		if s := strings.IndexByte(rest, '/'); s >= 0 {
			end = s
		}
		if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
			rest = rest[at+1:]
		}
	}
	// A residual "@" means a credential we could NOT locate — most concretely a userinfo
	// containing "/" ("//svc:pa/ss@host/x"), which puts the authority boundary inside the
	// password so the strip above finds no "@" before it. Bail to the fixed placeholder.
	//
	// Must run BEFORE the path replacement below: that replacement drops everything from
	// the first "/" onward, which for this shape DELETES the very "@" the check keys on.
	if strings.ContainsAny(rest, "@") {
		return "<redacted url>"
	}
	// Replace the path. A bare "/" is kept verbatim (nothing to leak). The boundary is the
	// first "/", which also covers scheme-less input and a path-only value, where the whole
	// string is the path and the result is a bare "/[redacted]".
	if i := strings.IndexByte(rest, '/'); i >= 0 && rest[i:] != "/" {
		rest = rest[:i] + redactedPath
	}
	if cut = prefix + rest; cut == "" {
		return "<redacted url>"
	}
	return cut
}
