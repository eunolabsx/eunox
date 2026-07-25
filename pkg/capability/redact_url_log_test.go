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
