// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// The published effect-contract schema and the Go structs the loader actually parses are
// two descriptions of one format, and nothing but this file keeps them in agreement.
//
// The repo convention is that a schema change ships with a roundtrip test; the gateway
// config has had one (TestGatewaySchema_MatchesStructs) since it was published. Without
// the equivalent here, adding a field to Contract or to capability.EffectContract leaves
// the published schema silently stale — and because every object declares
// additionalProperties:false, every editor and CI job validating against it then REJECTS
// the new, valid key. The failure lands on contributors, not on the author of the change.

const effectSchemaPath = "../../schemas/eunox-effect-contract.schema.json"

// loadEffectSchema reads and decodes the published contract schema.
func loadEffectSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(effectSchemaPath)
	if err != nil {
		t.Fatalf("read schema %s: %v", effectSchemaPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	return doc
}

// jsonTagSet returns the JSON property names a struct type binds, mirroring yamlTagSet in
// the gateway-schema test. The corpus format is JSON, so the tags are `json` rather than
// `yaml`.
func jsonTagSet(ty reflect.Type) map[string]bool {
	for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Array {
		ty = ty.Elem()
	}
	out := map[string]bool{}
	if ty.Kind() != reflect.Struct {
		return out
	}
	for i := range ty.NumField() {
		f := ty.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := f.Name
		if tag != "" {
			if n := strings.Split(tag, ",")[0]; n != "" {
				name = n
			}
		}
		out[name] = true
	}
	return out
}

// schemaNodeAt navigates the schema by successive object keys, resolving a local $ref at
// each step so a $defs-shared node compares as the object it stands for.
func schemaNodeAt(t *testing.T, root map[string]any, path ...string) map[string]any {
	t.Helper()
	node := root
	for _, seg := range path {
		next, ok := node[seg].(map[string]any)
		if !ok {
			t.Fatalf("schema path %v: segment %q is absent or not an object", path, seg)
		}
		node = resolveRef(t, root, next)
	}
	return node
}

// resolveRef follows a local "#/$defs/x" reference to the node it names.
func resolveRef(t *testing.T, root, node map[string]any) map[string]any {
	t.Helper()
	ref, ok := node["$ref"].(string)
	if !ok {
		return node
	}
	const prefix = "#/$defs/"
	if !strings.HasPrefix(ref, prefix) {
		t.Fatalf("schema carries a non-local $ref %q; the schema must be self-contained", ref)
	}
	defs, ok := root["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("schema has a $ref %q but no $defs", ref)
	}
	target, ok := defs[strings.TrimPrefix(ref, prefix)].(map[string]any)
	if !ok {
		t.Fatalf("schema $ref %q names no $defs entry", ref)
	}
	return target
}

// schemaProps returns the property names an object node declares.
func schemaProps(t *testing.T, node map[string]any) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	props, ok := node["properties"].(map[string]any)
	if !ok {
		return out
	}
	for k := range props {
		out[k] = true
	}
	return out
}

// missingKeys returns the keys of a that b does not have, sorted for a stable message.
func missingKeys(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestEffectContractSchema_MatchesStructs pins the published schema against the Go types
// the loader parses, object by object and parent-qualified — a flat name comparison would
// miss a property declared on the wrong parent, which is a real way for the two to drift
// while both look complete.
func TestEffectContractSchema_MatchesStructs(t *testing.T) {
	doc := loadEffectSchema(t)

	// The `effect` block deliberately omits `ref`: a corpus entry IS the thing a ref
	// points at, and Validate refuses one that carries its own. The schema documents that
	// by not declaring the property, so the comparison subtracts it here rather than
	// letting the two disagree.
	effectFields := jsonTagSet(reflect.TypeOf(capability.EffectContract{}))
	delete(effectFields, "ref")

	cases := []struct {
		name string
		want map[string]bool
		node map[string]any
	}{
		{"root", jsonTagSet(reflect.TypeOf(Contract{})), doc},
		{"server", jsonTagSet(reflect.TypeOf(ServerRef{})), schemaNodeAt(t, doc, "properties", "server")},
		{"attestation", jsonTagSet(reflect.TypeOf(Attestation{})), schemaNodeAt(t, doc, "properties", "attestation")},
		{"effect", effectFields, schemaNodeAt(t, doc, "properties", "effect")},
		{"effect.blastRadius", jsonTagSet(reflect.TypeOf(capability.BlastRadiusSpec{})),
			schemaNodeAt(t, doc, "$defs", "blastRadius")},
		{"effect.byArgument", jsonTagSet(reflect.TypeOf(capability.EffectByArgument{})),
			schemaNodeAt(t, doc, "$defs", "effectContract", "properties", "byArgument")},
		{"effectCase", jsonTagSet(reflect.TypeOf(capability.EffectCase{})),
			schemaNodeAt(t, doc, "$defs", "effectCase")},
		// The signature object lives under an ARRAY, so it is reached through "items"
		// rather than through a "properties" child. Without a case here a renamed or added
		// Signature field would ship undetected — which is exactly the drift the rest of
		// this table exists to catch, and the walk below cannot see it either (see the
		// items recursion added there).
		{"signatures[*]", jsonTagSet(reflect.TypeOf(Signature{})),
			schemaNodeAt(t, doc, "properties", "signatures", "items")},
	}

	for _, c := range cases {
		got := schemaProps(t, c.node)
		if missing := missingKeys(c.want, got); len(missing) > 0 {
			t.Errorf("object %q: struct fields missing from schema (add them under the right parent in %s): %v",
				c.name, effectSchemaPath, missing)
		}
		if extra := missingKeys(got, c.want); len(extra) > 0 {
			t.Errorf("object %q: schema properties with no matching struct field on this object (stale, typo'd, or on the wrong parent): %v",
				c.name, extra)
		}
	}
}

// TestEffectContractSchema_EveryObjectForbidsAdditionalProperties pins the closed-schema
// invariant. A corpus entry is a security artifact: a key nothing models must be a
// validation error, not silently-carried data that a reader assumes was checked.
func TestEffectContractSchema_EveryObjectForbidsAdditionalProperties(t *testing.T) {
	doc := loadEffectSchema(t)
	var walk func(path string, node map[string]any)
	walk = func(path string, node map[string]any) {
		if props, ok := node["properties"].(map[string]any); ok {
			if closed, ok := node["additionalProperties"].(bool); !ok || closed {
				t.Errorf("%s declares properties but does not set additionalProperties:false", path)
			}
			for name, raw := range props {
				if child, ok := raw.(map[string]any); ok {
					walk(path+"."+name, child)
				}
			}
		}
		// A map-valued node (byArgument.cases) constrains its VALUES, not its keys, so it
		// is walked through additionalProperties rather than being required to close.
		if child, ok := node["additionalProperties"].(map[string]any); ok {
			walk(path+"[*]", child)
		}
		// An ARRAY node constrains its element schema through "items". Without this the
		// walk never descended into one, so an object nested under an array — the
		// signatures entry — was exempt from the closed-schema invariant every other object
		// in the document is held to.
		if child, ok := node["items"].(map[string]any); ok {
			walk(path+"[]", child)
		}
	}
	walk("root", doc)
	if defs, ok := doc["$defs"].(map[string]any); ok {
		for name, raw := range defs {
			if node, ok := raw.(map[string]any); ok {
				walk("$defs."+name, node)
			}
		}
	}
}

// TestShippedCorpusUsesOnlySchemaDeclaredKeys checks the corpus against the published
// schema's key sets — the check an editor or a CI validator would run. The Go loader
// already rejects an unknown key, but that only proves the corpus matches the STRUCTS; a
// schema that omits a field the structs have would still reject every valid entry for
// everyone validating against the published file.
func TestShippedCorpusUsesOnlySchemaDeclaredKeys(t *testing.T) {
	doc := loadEffectSchema(t)
	paths, err := os.ReadDir("../../registry/contracts")
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	for _, entry := range paths {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile("../../registry/contracts/" + entry.Name())
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		checkKeys(t, entry.Name(), "root", obj, schemaProps(t, doc))
		for _, sub := range []struct{ key, node string }{{"server", "server"}, {"attestation", "attestation"}, {"effect", "effect"}} {
			if body, ok := obj[sub.key]; ok {
				var child map[string]json.RawMessage
				if err := json.Unmarshal(body, &child); err != nil {
					t.Fatalf("%s.%s: %v", entry.Name(), sub.key, err)
				}
				checkKeys(t, entry.Name(), sub.key, child,
					schemaProps(t, schemaNodeAt(t, doc, "properties", sub.node)))
			}
		}
	}
}

// checkKeys reports any key in obj the schema does not declare for that object.
func checkKeys(t *testing.T, file, object string, obj map[string]json.RawMessage, allowed map[string]bool) {
	t.Helper()
	var extra []string
	for k := range obj {
		if !allowed[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("%s: object %q carries key(s) the published schema does not declare: %v (%s)",
			file, object, extra, fmt.Sprintf("add them to %s or remove them from the entry", effectSchemaPath))
	}
}
