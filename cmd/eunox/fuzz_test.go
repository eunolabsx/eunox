// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eunolabs/eunox/internal/config"
)

// FuzzLoadManifest exercises the manifest loader (YAML→JSON→struct, schema-version
// gate, key check, validation) against arbitrary bytes via both the YAML and JSON
// paths. The loader must always return a manifest or an error, never panic.
func FuzzLoadManifest(f *testing.F) {
	f.Add([]byte("schemaVersion: \"1.0\"\nname: m\nversion: 0.1.0\ncapabilities: []\n"))
	f.Add([]byte(`{"schemaVersion":"1.0","name":"m","version":"0.1.0","capabilities":[]}`))
	f.Add([]byte("capabilities:\n  - target: tool:x\n    actions: [call]\n"))
	f.Add([]byte(": : :"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		for _, ext := range []string{".yaml", ".json"} {
			p := filepath.Join(dir, "manifest"+ext)
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatalf("write temp manifest: %v", err)
			}
			// Return value intentionally ignored; the property under test is "never
			// panics", and the result is unused.
			_, _ = config.LoadManifest(p)
		}
	})
}
