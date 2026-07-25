// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
)

// TestExpandEnvInStrings_ConfigTreeHasNoUnhandledKinds pins the invariant
// expandEnvInStrings relies on: the GatewayConfig type tree contains only the kinds the
// walk descends into (structs, slices/arrays, strings, and non-string pointers/scalars).
// A map or interface field would be SILENTLY skipped — and since secrets are the use case
// (a future map[string]string of per-upstream custom headers, say), a ${TOKEN} in such a
// field would be handed to the upstream as the literal text "${TOKEN}" with no auth
// applied. Fail loudly here the moment such a field is added so expandEnvInStrings is
// extended (maps need SetMapIndex, not a free fall-through) rather than silently leaking
// the reference.
//
// This lives in the same package as the walker on purpose. It previously sat in the
// binary's test file, two packages away, while internal/config is designed to build and
// test standalone: anyone adding a map field here and running `go test ./internal/config/`
// got a green run and a silently un-expanded secret reference — the exact failure the
// guard exists to prevent.
func TestExpandEnvInStrings_ConfigTreeHasNoUnhandledKinds(t *testing.T) {
	t.Parallel()
	var bad []string
	seen := map[reflect.Type]bool{}
	var walk func(path string, ty reflect.Type)
	walk = func(path string, ty reflect.Type) {
		switch ty.Kind() {
		case reflect.Map, reflect.Interface:
			bad = append(bad, fmt.Sprintf("%s (%s)", path, ty.Kind()))
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(path+"[]", ty.Elem())
		case reflect.Struct:
			if seen[ty] {
				return // guard against a (hypothetical) recursive type
			}
			seen[ty] = true
			for i := 0; i < ty.NumField(); i++ {
				f := ty.Field(i)
				walk(path+"."+f.Name, f.Type)
			}
		}
	}
	walk("GatewayConfig", reflect.TypeOf(GatewayConfig{}))
	if len(bad) > 0 {
		t.Fatalf("expandEnvInStrings silently skips map/interface kinds, so env refs in these fields would not be "+
			"expanded — extend the walk (e.g. SetMapIndex for maps) before adding them: %v", bad)
	}
}
