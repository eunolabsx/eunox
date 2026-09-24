// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eunolabs/eunox/internal/transport"
)

// TestCmdKill_DoesNotFollowRedirects pins that whatever holds the loopback port cannot bounce
// the token-bearing request elsewhere: net/http copies a custom header across a cross-host
// hop, and a 307 re-sends the body through GetBody. The 3xx must be reported as a failure.
func TestCmdKill_DoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var reached atomic.Bool
			elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(transport.ControlTokenHeader) != "" {
					reached.Store(true)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer elsewhere.Close()

			bouncer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, elsewhere.URL+"/steal", status)
			}))
			defer bouncer.Close()

			addr := bouncer.Listener.Addr().String()
			portStr := addr[strings.LastIndex(addr, ":")+1:]
			code := -1
			stderr := captureStderr(t, func() {
				code = cmdKill([]string{"--port", portStr, "--control-token", "test-token-xyz", "all"})
			})
			if code != 1 {
				t.Errorf("exit code = %d, want 1: a redirect is not a successful kill", code)
			}
			if !strings.Contains(stderr, "proxy returned") {
				t.Errorf("stderr = %q, want the 3xx reported as the non-200 it is", stderr)
			}
			if reached.Load() {
				t.Fatal("the control token followed the redirect to another listener")
			}
		})
	}
}
