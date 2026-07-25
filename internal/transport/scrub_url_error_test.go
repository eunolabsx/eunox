// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestScrubURLError_RedactsCredentialedURL verifies the live-probe
// error surfaces a *url.Error whose URL carries a userinfo credential and a query token.
// net/http strips only the password, so the username and query leak to stderr and the
// doctor bundle. scrubURLError must redact the whole credentialed URL while preserving
// the operation and the wrapped cause (errors.Is must still match).
func TestScrubURLError_RedactsCredentialedURL(t *testing.T) {
	cause := errors.New("dial tcp: connection refused")
	ue := &url.Error{
		Op:  "Post",
		URL: "https://alice:SECRETPW@host:1/mcp?api_key=SECRETKEY",
		Err: cause,
	}
	// Wrap as the production path does (http_remote.go), then re-wrap once more.
	wrapped := fmt.Errorf("initialize: %w", fmt.Errorf("upstream HTTP: %w", scrubURLError(ue)))
	s := wrapped.Error()

	for _, secret := range []string{"SECRETPW", "SECRETKEY", "alice"} {
		if strings.Contains(s, secret) {
			t.Errorf("scrubbed error still leaks %q: %s", secret, s)
		}
	}
	// The wrapped cause must remain discoverable for classification.
	if !errors.Is(wrapped, cause) {
		t.Errorf("scrubbed error lost the wrapped cause (errors.Is failed): %s", s)
	}
	if !strings.Contains(s, "connection refused") {
		t.Errorf("scrubbed error dropped the cause text: %s", s)
	}
	// A non-URL error passes through unchanged.
	plain := errors.New("some non-url error")
	if scrubURLError(plain) != plain {
		t.Error("scrubURLError must return a non-*url.Error unchanged")
	}
}
