// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The loader selects a condition's field set by its `type`, and that lookup was byte-exact
// while every decoder under it folds. A `Type:` spelling therefore matched nothing, read as an
// unknown type, and had its per-type key walk SKIPPED — after which a fold-equivalent sibling
// of a real field decided the policy last-wins, from a file that loaded clean. The
// substitution is refused by pkg/capability now; this pins the loader's own half, which is
// what keeps the path and the "did you mean" in the message and stops the next check hung off
// checkObjectKeys inheriting the silent skip.
func TestManifestKeyWalk_DiscriminatorIsMatchedTheWayTheDecoderBindsIt(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "m.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	const head = `schemaVersion: "0.1"
name: m
version: 1.0.0
capabilities:
  - target: tool:send
    actions: [call]
    conditions:
      - `

	t.Run("a case-varied type no longer skips the key walk", func(t *testing.T) {
		_, err := LoadManifest(write(t, head+`{Type: recipientDomain, argument: to, domains: ["corp.com"], bogusKey: 1}`))
		if err == nil {
			t.Fatal("an unknown key under a case-varied discriminator must still be refused")
		}
		if !strings.Contains(err.Error(), "conditions[0]") {
			t.Fatalf("the refusal must name the path the walk exists to report, got: %v", err)
		}
	})

	t.Run("two binding spellings of type are refused, not resolved", func(t *testing.T) {
		_, err := LoadManifest(write(t, head+`{type: recipientDomain, Type: maxCalls, argument: to, domains: ["corp.com"]}`))
		if err == nil {
			t.Fatal("two spellings of the discriminator must be refused")
		}
	})

	t.Run("the substitution itself is refused", func(t *testing.T) {
		_, err := LoadManifest(write(t, head+`{Type: maxCalls, count: 5, windowSeconds: 60, windowseconds: 86400}`))
		if err == nil {
			t.Fatal("a fold-equivalent sibling of a real field must not load")
		}
	})

	t.Run("the canonical spelling still loads", func(t *testing.T) {
		m, err := LoadManifest(write(t, head+`{type: recipientDomain, argument: to, domains: ["corp.com"]}`))
		if err != nil {
			t.Fatalf("a well-formed manifest must load: %v", err)
		}
		if len(m.Capabilities) != 1 || len(m.Capabilities[0].Conditions) != 1 {
			t.Fatalf("loaded %+v", m.Capabilities)
		}
	})
}
