// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"net/url"
	"strings"
)

// RedactURLForLog returns u with every credential-bearing component removed, for embedding
// in a log line or an error message.
//
// It is deliberately STRICTER than the operator-facing redactor used by the doctor support
// bundle, which preserves query parameter NAMES and reports each secret's decoded length so
// an operator can tell which parameters are set. That detail is appropriate for a bundle
// the operator asked for and reads themselves; it is a length oracle in a startup banner or
// a validation error, which lands in the systemd journal, container stdout, or a CI log —
// commonly a lower protection tier than the config file the secret came from. This form
// drops userinfo, the whole query, and the fragment, leaving only scheme://host/path.
//
// An unparseable input is not echoed back: returning the raw string on a parse failure
// would leak exactly the credentialed URLs most likely to be malformed. Such input is
// reduced to everything before the first "?" or "#" with any userinfo segment stripped, and
// falls back to a fixed placeholder if even that cannot be done safely.
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
	return u.String()
}

// coarseRedactURLForLog handles input url.Parse rejected. It keeps only the portion before
// the first query/fragment delimiter and strips any "user:pass@" authority segment.
func coarseRedactURLForLog(raw string) string {
	cut := raw
	if i := strings.IndexAny(cut, "?#"); i >= 0 {
		cut = cut[:i]
	}
	// Strip userinfo: everything between "//" and the last "@" of the authority.
	if i := strings.Index(cut, "//"); i >= 0 {
		authStart := i + 2
		rest := cut[authStart:]
		end := len(rest)
		if s := strings.IndexByte(rest, '/'); s >= 0 {
			end = s
		}
		if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
			cut = cut[:authStart] + rest[at+1:]
		}
	}
	if strings.ContainsAny(cut, "@") || cut == "" {
		return "<redacted url>"
	}
	return cut
}
