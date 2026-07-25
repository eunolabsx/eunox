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
// It is deliberately STRICTER than the operator-facing redactor used by the doctor support
// bundle (config.RedactURL), which preserves query parameter NAMES, reports each secret's
// decoded length, and keeps the path. That detail is appropriate for a bundle the operator
// asked for and reads themselves — its audit tail is a record of which resource URIs were
// allowed and denied, so the path there IS the content. It is a length oracle and a
// credential leak in a startup banner or a validation error, which lands in the systemd
// journal, container stdout, or a CI log — commonly a lower protection tier than the config
// file the secret came from.
//
// The path is dropped because for whole families of endpoints the path IS the credential:
// a Slack incoming webhook (https://hooks.slack.com/services/T…/B…/<secret>), a Telegram
// bot API URL (https://api.telegram.org/bot<token>/…), a presigned object URL. Stripping
// userinfo and the query while echoing those verbatim leaks the whole secret — and the
// most likely way such a URL reaches a validation error is a scheme typo, which parses
// fine and fails the scheme check with the path intact. scheme://host still identifies
// which endpoint the message is about, which is what a log line needs.
//
// An unparseable input is not echoed back: returning the raw string on a parse failure
// would leak exactly the credentialed URLs most likely to be malformed. Such input is
// reduced to everything before the first "?" or "#" with any userinfo segment stripped and
// any path replaced, and falls back to a fixed placeholder if even that cannot be done
// safely.
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
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	// Drop any path-embedded secret. RawPath must be overwritten too, not just Path:
	// url.URL.String() emits RawPath whenever it is a valid encoding of Path, so a
	// stale RawPath from a percent-escaped input would print the original path and
	// silently defeat the replacement. Setting both to the same literal keeps String()
	// on the RawPath branch (net/url's validEncoded admits '[' and ']' verbatim), so
	// the placeholder is not re-escaped into "%5Bredacted%5D". A bare "/" carries
	// nothing and is left alone so a host-root URL is not made to look like it had a
	// path.
	if u.Path != "" && u.Path != "/" {
		u.Path = redactedPath
		u.RawPath = redactedPath
	}
	return u.String()
}

// coarseRedactURLForLog handles input url.Parse rejected. It keeps only the portion before
// the first query/fragment delimiter, strips any "user:pass@" authority segment, and
// replaces any path with "/[redacted]" for the reasons on RedactURLForLog.
func coarseRedactURLForLog(raw string) string {
	cut := raw
	if i := strings.IndexAny(cut, "?#"); i >= 0 {
		cut = cut[:i]
	}
	// Strip userinfo: everything between "//" and the last "@" of the authority, then
	// replace whatever path follows the authority.
	if i := strings.Index(cut, "//"); i >= 0 {
		authStart := i + 2
		rest := cut[authStart:]
		end := len(rest)
		if s := strings.IndexByte(rest, '/'); s >= 0 {
			end = s
		}
		if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
			rest = rest[at+1:]
			end -= at + 1
		}
		authority := rest[:end]
		// rest[end:] is the path (empty, or "/..."). A bare "/" is kept verbatim: it
		// carries nothing to leak.
		if path := rest[end:]; path != "" && path != "/" {
			cut = cut[:authStart] + authority + redactedPath
		} else {
			cut = cut[:authStart] + authority + path
		}
	} else if i := strings.IndexByte(cut, '/'); i > 0 {
		// Scheme-less/authority-less input ("hooks.slack.com/services/T/B/secret"):
		// there is no "//" to anchor on, so treat the first "/" as the path boundary.
		cut = cut[:i] + redactedPath
	}
	if strings.ContainsAny(cut, "@") || cut == "" {
		return "<redacted url>"
	}
	return cut
}
