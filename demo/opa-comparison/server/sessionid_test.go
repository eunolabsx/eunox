// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// TestNewSessionIDUnpredictable guards against predictable session IDs: they were generated
// from a process-global counter (opa-cmp-1, opa-cmp-2, ...). The Streamable HTTP
// session header gates access to a client's server-side session, so a peer that
// observed or guessed the counter could address another client's session, and the
// IDs repeated after every process restart. IDs must now be cryptographically
// random and unique.
func TestNewSessionIDUnpredictable(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := newSessionID()
		if strings.HasPrefix(id, "opa-cmp-") {
			t.Fatalf("session ID still uses the predictable counter scheme: %q", id)
		}
		if len(id) < 16 {
			t.Fatalf("session ID %q is too short to be cryptographically unique", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate session ID generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}
