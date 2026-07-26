// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"testing"
)

// TestRedactURLForLog_StripsEveryCredentialBearingComponent pins that the log-safe redactor
// leaks neither the secret nor its length, on both the parseable and unparseable paths.
//
// The path cases are the reason this redactor drops the path outright: for a Slack
// incoming webhook, a Telegram bot URL, or a presigned object URL the path IS the
// credential, and the most likely way such a URL reaches a validation error is a scheme
// typo — which parses cleanly and would otherwise print the whole secret to stderr.
func TestRedactURLForLog_StripsEveryCredentialBearingComponent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, in string
		mustNot  []string
	}{
		{"userinfo and query", "https://svc:s3cr3t@idp.internal/keys?api_key=AKIA123", []string{"s3cr3t", "AKIA123", "api_key"}},
		{"query only", "https://idp.internal/keys?token=abcdef", []string{"abcdef", "token"}},
		{"fragment", "https://idp.internal/keys#frag-secret", []string{"frag-secret"}},
		{"unparseable with credentials", "ht tp://svc:s3cr3t@idp.internal/keys?api_key=AKIA123", []string{"s3cr3t", "AKIA123"}},
		{"opaque", "mailto:svc:s3cr3t@example.com", []string{"s3cr3t"}},
		{"slack webhook path", "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXsecret", []string{"T00000000", "B00000000", "XXXXXXXXXXXXsecret"}},
		{"telegram bot path", "https://api.telegram.org/bot123456:AAH-secret-token/sendMessage", []string{"AAH-secret-token", "123456"}},
		{"scheme typo keeps path secret out", "htps://hooks.slack.com/services/T0/B0/webhooksecret", []string{"webhooksecret"}},
		{"percent-escaped path", "https://api.internal/v1/%73%65%63%72%65%74/go", []string{"%73%65%63%72%65%74", "secret"}},
		{"scheme-less path", "hooks.slack.com/services/T0/B0/webhooksecret", []string{"webhooksecret"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := RedactURLForLog(tc.in)
			for _, bad := range tc.mustNot {
				if strings.Contains(got, bad) {
					t.Errorf("RedactURLForLog(%q) = %q, must not contain %q", tc.in, got, bad)
				}
			}
		})
	}
}

// TestRedactURLForLog_KeepsEnoughToIdentifyTheEndpoint pins the other half of the
// contract: scheme, host, and port survive so a log line still says WHICH endpoint it is
// about, and a path-less URL is not made to look as though it had a path.
func TestRedactURLForLog_KeepsEnoughToIdentifyTheEndpoint(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, in, want string }{
		{"host port survive, path redacted", "https://svc:pw@idp.internal:8443/keys?k=v", "https://idp.internal:8443" + redactedPath},
		{"no path", "https://idp.internal", "https://idp.internal"},
		{"root path only", "https://idp.internal/", "https://idp.internal/"},
		{"empty stays empty", "", ""},
		{"unparseable host survives", "ht tp://idp.internal/keys", "ht tp://idp.internal" + redactedPath},
		{"unparseable root path only", "ht tp://idp.internal/", "ht tp://idp.internal/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RedactURLForLog(tc.in); got != tc.want {
				t.Errorf("RedactURLForLog(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRedactURLForLog_UnlocatableCredentialFallsBackToPlaceholder pins the fail-safe
// that catches a credential the userinfo strip cannot locate.
//
// A userinfo containing "/" (a generated password, most often) puts the authority
// boundary INSIDE the credential, so the "last @ before the first /" strip finds
// nothing. The residual-"@" check must therefore run BEFORE the path replacement: the
// replacement drops everything from the first "/" onward, which for this shape deletes
// the very "@" the check keys on, and a half-stripped credential would sail through.
func TestRedactURLForLog_UnlocatableCredentialFallsBackToPlaceholder(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"http://svc:pw/1@10.0.0.5:8080/mcp",
		"https://admin:s3cr3t/x@mcp.internal/mcp",
		"https://user:pa%zz/ss@hooks.example.com/x",
	} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got := RedactURLForLog(in)
			if got != "<redacted url>" {
				t.Errorf("RedactURLForLog(%q) = %q, want the fixed placeholder", in, got)
			}
		})
	}
}

// TestRedactURLForLog_AuthorityLessInput pins that a value with no "//" authority still
// gets its path redacted AND keeps whatever identifies the endpoint.
//
// A scheme-less upstreamUrl is the commonest form of the mistake this redactor meets
// (url.Parse ACCEPTS it, putting host and path together in u.Path), so replacing u.Path
// wholesale would reduce the message to a bare "/[redacted]" — no host, nothing for the
// operator to act on. A genuinely path-only value has no host to keep and reduces fully.
func TestRedactURLForLog_AuthorityLessInput(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, in, want string }{
		{"scheme-less keeps the host", "hooks.slack.com/services/T0/B0/SECRET", "hooks.slack.com" + redactedPath},
		{"scheme-less, no path", "hooks.slack.com", "hooks.slack.com"},
		{"path-only reduces fully", "/services/T0/B0/SECRET", redactedPath},
		{"path-only, malformed escape", "/services/T0/B0/SECRET%zz", redactedPath},
		{"scheme with empty authority", "https://", "https://"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RedactURLForLog(tc.in); got != tc.want {
				t.Errorf("RedactURLForLog(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
