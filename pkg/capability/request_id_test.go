// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"sync"
	"testing"
)

func TestIDGenerator_FormatAndMonotonicCounter(t *testing.T) {
	g := NewIDGenerator("dec", 6)

	first := g.Next()
	// "<prefix>-<nonce>-<counter>": prefix, a 12-hex-char nonce (6 bytes), and a
	// hex counter starting at 1.
	parts := strings.Split(first, "-")
	if len(parts) != 3 {
		t.Fatalf("Next() = %q, want three '-'-separated parts", first)
	}
	if parts[0] != "dec" {
		t.Errorf("prefix = %q, want %q", parts[0], "dec")
	}
	if len(parts[1]) != 12 {
		t.Errorf("nonce = %q (%d chars), want 12 hex chars", parts[1], len(parts[1]))
	}
	if parts[2] != "1" {
		t.Errorf("first counter = %q, want %q", parts[2], "1")
	}
	if got := g.Next(); !strings.HasSuffix(got, "-2") {
		t.Errorf("second Next() = %q, want counter 2", got)
	}
}

func TestIDGenerator_StableNoncePerGenerator(t *testing.T) {
	g := NewIDGenerator("req", 4)
	a, b := g.Next(), g.Next()
	// Same generator: identical nonce (middle field), distinct counter.
	if strings.Split(a, "-")[1] != strings.Split(b, "-")[1] {
		t.Errorf("nonce changed within one generator: %q vs %q", a, b)
	}
	if a == b {
		t.Errorf("two Next() calls returned the same id %q", a)
	}
	// A second generator draws its own nonce.
	if strings.Split(NewIDGenerator("req", 4).Next(), "-")[1] == strings.Split(a, "-")[1] {
		t.Errorf("independent generators unexpectedly shared a nonce (%q)", a)
	}
}

func TestIDGenerator_ConcurrentUnique(t *testing.T) {
	g := NewIDGenerator("dec", 6)
	const n = 500
	var wg sync.WaitGroup
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i] = g.Next()
		}(i)
	}
	wg.Wait()

	seen := make(map[string]struct{}, n)
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id under concurrency: %q", id)
		}
		seen[id] = struct{}{}
	}
}
