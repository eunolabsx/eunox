// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/pkg/capability"
)

var manifestSchemaPath = filepath.Join("..", "..", "schemas", "eunox-capability-manifest.schema.json")

func loadManifestSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(manifestSchemaPath)
	if err != nil {
		t.Fatalf("read schema %s: %v", manifestSchemaPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	return doc
}

func TestManifestSchema_WellFormed(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	for _, key := range []string{"$schema", "$id", "title", "type", "properties", "$defs"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("schema missing top-level %q", key)
		}
	}
	if doc["type"] != "object" {
		t.Errorf(`schema "type" = %v, want "object"`, doc["type"])
	}
	if doc["additionalProperties"] != false {
		t.Errorf(`schema "additionalProperties" = %v, want false — an open manifest schema would accept the misspelled key the loader rejects`, doc["additionalProperties"])
	}
}

// TestManifestSchema_MatchesRootStruct guards the top-level object against drift from
// config.LocalManifest, the struct the loader actually parses. A field present in one and
// not the other is either an undocumented grammar token or a stale schema property that
// an author's editor would accept and the loader then refuses.
func TestManifestSchema_MatchesRootStruct(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	want := jsonTagSet(reflect.TypeOf(config.LocalManifest{}))
	got := schemaPropNames(t, doc)
	if missing := diffKeys(want, got); len(missing) > 0 {
		t.Errorf("LocalManifest fields missing from the schema root: %v", missing)
	}
	if extra := diffKeys(got, want); len(extra) > 0 {
		t.Errorf("schema root properties with no matching LocalManifest field: %v", extra)
	}
}

// TestManifestSchema_MatchesConstraintStruct does the same for one capability entry
// against capability.Constraint.
func TestManifestSchema_MatchesConstraintStruct(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	want := jsonTagSet(reflect.TypeOf(capability.Constraint{}))
	got := schemaPropNames(t, schemaObjectAt(t, doc, "$defs", "capability"))
	if missing := diffKeys(want, got); len(missing) > 0 {
		t.Errorf("Constraint fields missing from $defs.capability: %v", missing)
	}
	if extra := diffKeys(got, want); len(extra) > 0 {
		t.Errorf("$defs.capability properties with no matching Constraint field: %v", extra)
	}
}

// TestManifestSchema_CoversEveryConditionType is the strongest of the drift guards: it
// walks the condition PROTOTYPE REGISTRY — the one place a condition type is registered —
// and asserts the schema declares a branch for each, with exactly that type's JSON fields.
//
// Deriving the expectation from the registry rather than a hand-written list is the point.
// A hand-written mirror is a second table to update per new condition type, and one that
// fails silently: a type missing from it is simply not checked, so the grammar could grow
// a predicate the published schema never mentions.
func TestManifestSchema_CoversEveryConditionType(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	branches := schemaOneOfByConst(t, schemaObjectAt(t, doc, "$defs", "condition"))

	for _, condType := range capability.KnownConditionTypes() {
		proto, ok := capability.NewConditionPrototype(condType)
		if !ok {
			t.Fatalf("condition type %q is advertised but has no prototype", condType)
		}
		branch, declared := branches[condType]
		if !declared {
			t.Errorf("schema declares no branch for condition type %q (add one under $defs.condition.oneOf)", condType)
			continue
		}
		want := jsonTagSet(reflect.TypeOf(proto))
		want["type"] = true
		got := schemaPropNames(t, branch)
		if missing := diffKeys(want, got); len(missing) > 0 {
			t.Errorf("condition %q: struct fields missing from the schema branch: %v", condType, missing)
		}
		if extra := diffKeys(got, want); len(extra) > 0 {
			t.Errorf("condition %q: schema branch properties with no matching struct field: %v", condType, extra)
		}
		if branch["additionalProperties"] != false {
			t.Errorf("condition %q: branch must set additionalProperties:false", condType)
		}
	}
	if len(branches) != len(capability.KnownConditionTypes()) {
		t.Errorf("schema declares %d condition branches for %d known types — a branch names a type the grammar does not have",
			len(branches), len(capability.KnownConditionTypes()))
	}
}

// TestManifestSchema_CoversEveryDirectiveType mirrors the condition walk for directives,
// deriving its expectation from the directive registry for the same reason: a hand-written
// mirror is a second table to update per new directive, and one that fails silently.
func TestManifestSchema_CoversEveryDirectiveType(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	branches := schemaOneOfByConst(t, schemaObjectAt(t, doc, "$defs", "directive"))

	want := map[string]any{}
	for _, dirType := range capability.KnownDirectiveTypes() {
		proto, ok := capability.NewDirectivePrototype(dirType)
		if !ok {
			t.Fatalf("directive type %q is advertised but has no prototype", dirType)
		}
		want[dirType] = proto
	}
	for dirType, proto := range want {
		branch, declared := branches[dirType]
		if !declared {
			t.Errorf("schema declares no branch for directive type %q", dirType)
			continue
		}
		fields := jsonTagSet(reflect.TypeOf(proto))
		fields["type"] = true
		got := schemaPropNames(t, branch)
		if missing := diffKeys(fields, got); len(missing) > 0 {
			t.Errorf("directive %q: struct fields missing from the schema branch: %v", dirType, missing)
		}
		if extra := diffKeys(got, fields); len(extra) > 0 {
			t.Errorf("directive %q: schema branch properties with no matching struct field: %v", dirType, extra)
		}
	}
	if len(branches) != len(want) {
		t.Errorf("schema declares %d directive branches, want %d", len(branches), len(want))
	}
}

// TestManifestSchema_ClosedVocabularies pins the enum sets against the constants the
// engine enforces, so the published schema and the runtime cannot disagree about what the
// closed vocabularies contain. A schema that accepted a label the engine rejects would
// hand an author a manifest their proxy refuses to load.
func TestManifestSchema_ClosedVocabularies(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)

	if got, want := schemaEnum(t, schemaObjectAt(t, doc, "$defs", "flowLabel")), capability.FlowLabelVocabulary(); !sameStrings(got, want) {
		t.Errorf("flowLabel enum = %v, want the native vocabulary %v", got, want)
	}
	if got, want := schemaEnum(t, schemaObjectAt(t, doc, "$defs", "effectClass")), capability.EffectClassVocabulary(); !sameStrings(got, want) {
		t.Errorf("effectClass enum = %v, want the closed reversibility set %v", got, want)
	}
	onExceed := schemaEnum(t, schemaObjectAt(t, doc, "$defs", "effectCeiling", "properties", "onExceed"))
	if !sameStrings(onExceed, []string{capability.OnExceedEscalate, capability.OnExceedDeny}) {
		t.Errorf("onExceed enum = %v, want [escalate deny]", onExceed)
	}
	enforcement := schemaEnum(t, schemaObjectAt(t, doc, "$defs", "capability", "properties", "enforcement"))
	if !sameStrings(enforcement, []string{capability.EnforcementEnforce, capability.EnforcementAudit}) {
		t.Errorf("enforcement enum = %v, want [enforce audit]", enforcement)
	}
	principal := schemaPropNames(t, schemaObjectAt(t, doc, "$defs", "capability", "properties", "principal"))
	wantPrincipal := map[string]bool{}
	for _, c := range capability.SupportedPrincipalClaimNames() {
		wantPrincipal[c] = true
	}
	if missing := diffKeys(wantPrincipal, principal); len(missing) > 0 {
		t.Errorf("principal claims missing from the schema: %v", missing)
	}
	if extra := diffKeys(principal, wantPrincipal); len(extra) > 0 {
		t.Errorf("schema principal claims the loader does not support: %v", extra)
	}
}

// TestManifestSchema_SchemaVersionEnum pins that the schema advertises exactly the
// grammar revisions this build parses — including that the retired draft string is NOT
// among them.
func TestManifestSchema_SchemaVersionEnum(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	got := schemaEnum(t, schemaObjectAt(t, doc, "properties", "schemaVersion"))
	want := []string{config.ManifestSchemaVersion01, config.ManifestSchemaVersion02}
	if !sameStrings(got, want) {
		t.Fatalf("schemaVersion enum = %v, want %v", got, want)
	}
	for _, v := range got {
		if v == "0.2-draft" {
			t.Fatal("the retired draft version must not be advertised — it is removed, not aliased")
		}
	}
}

// TestManifestSchema_VersionPatternMatchesLoader exercises the semver pattern the schema
// publishes against the same accepted/rejected forms the loader enforces on `version`, so
// an author-time check and the runtime agree on what a valid version looks like. The
// loader runs no JSON-Schema validation, so this compiles the declared pattern and drives
// it directly rather than pulling in a json-schema dependency.
func TestManifestSchema_VersionPatternMatchesLoader(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	pat, ok := schemaObjectAt(t, doc, "properties", "version")["pattern"].(string)
	if !ok {
		t.Fatal("version has no string \"pattern\"")
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		t.Fatalf("version pattern is not a valid regexp: %v", err)
	}
	for _, v := range []string{"0.0.0", "0.1.0", "1.2.3", "10.20.30"} {
		if !re.MatchString(v) {
			t.Errorf("version pattern rejected valid version %q", v)
		}
	}
	for _, v := range []string{"1.2.3-rc", "1.2.3+build", "1.2", "1.2.3.4", "v1.2.3", "01.2.3", "1.2.03", " 1.2.3", "1.2.3 ", ""} {
		if re.MatchString(v) {
			t.Errorf("version pattern accepted invalid version %q", v)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// jsonTagSet returns the JSON field names of a struct type, skipping "-" and
// unexported fields. Mirrors yamlTagSet in the gateway-config schema test.
func jsonTagSet(t reflect.Type) map[string]bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := map[string]bool{}
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := cutComma(tag)
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = true
	}
	return out
}

func cutComma(s string) (before, after string, found bool) {
	for i := range len(s) {
		if s[i] == ',' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// schemaPropNames returns the property names declared on a schema object node.
func schemaPropNames(t *testing.T, node map[string]any) map[string]bool {
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

// schemaOneOfByConst indexes a discriminated-union node's oneOf branches by the const
// value of their "type" property, which is how every condition/directive branch is keyed.
func schemaOneOfByConst(t *testing.T, node map[string]any) map[string]map[string]any {
	t.Helper()
	branches, ok := node["oneOf"].([]any)
	if !ok {
		t.Fatal("node has no oneOf array")
	}
	out := make(map[string]map[string]any, len(branches))
	for i, b := range branches {
		branch, ok := b.(map[string]any)
		if !ok {
			t.Fatalf("oneOf[%d] is not an object", i)
		}
		props, ok := branch["properties"].(map[string]any)
		if !ok {
			t.Fatalf("oneOf[%d] has no properties", i)
		}
		typeNode, ok := props["type"].(map[string]any)
		if !ok {
			t.Fatalf("oneOf[%d] has no \"type\" property", i)
		}
		discriminator, ok := typeNode["const"].(string)
		if !ok {
			t.Fatalf("oneOf[%d].properties.type has no string const", i)
		}
		out[discriminator] = branch
	}
	return out
}

// schemaEnum returns a node's enum values as strings, sorted.
func schemaEnum(t *testing.T, node map[string]any) []string {
	t.Helper()
	raw, ok := node["enum"].([]any)
	if !ok {
		t.Fatal("node has no enum array")
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("enum member %v is not a string", v)
		}
		out = append(out, s)
	}
	return out
}

// sameStrings compares two string sets irrespective of order.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// TestManifestSchema_GatesTheFlowEffectTokensByRevision is the correspondence test between
// the published schema and the loader on the one rule an author is most likely to trip:
// that "0.1" is a strict subset. It walks the same token list against BOTH — the schema
// must name each in its 0.1 exclusion, and the loader must refuse each under 0.1 — so the
// two cannot silently disagree about which revision admits a token.
//
// Without it, the schema's flat schemaVersion enum certified as valid exactly the manifest
// the proxy then refused to boot on: an authoring aid that green-lights the error it exists
// to catch is worse than none.
func TestManifestSchema_GatesTheFlowEffectTokensByRevision(t *testing.T) {
	t.Parallel()
	doc := loadManifestSchema(t)
	all, ok := doc["allOf"].([]any)
	if !ok || len(all) != 1 {
		t.Fatal("schema has no single-entry allOf carrying the 0.1 subset rule")
	}
	gate, ok := all[0].(map[string]any)
	if !ok {
		t.Fatal("allOf[0] is not an object")
	}
	then, ok := gate["then"].(map[string]any)
	if !ok {
		t.Fatal("the 0.1 subset rule has no \"then\"")
	}
	item := schemaObjectAt(t, then, "properties", "capabilities", "items")

	// The root-level and per-capability structural exclusions.
	if req, _ := schemaObjectAt(t, then, "not")["required"].([]any); len(req) != 1 || req[0] != "effectCeiling" {
		t.Errorf("the 0.1 arm must exclude the top-level effectCeiling, got %v", req)
	}
	if req, _ := schemaObjectAt(t, item, "not")["required"].([]any); len(req) != 1 || req[0] != "effect" {
		t.Errorf("the 0.1 arm must exclude a capability's effect contract, got %v", req)
	}

	condExcluded := schemaNotEnum(t, schemaObjectAt(t, item, "properties", "conditions", "items", "properties", "type"))
	dirExcluded := schemaNotEnum(t, schemaObjectAt(t, item, "properties", "directives", "items", "properties", "type"))
	varExcluded := schemaNotEnum(t, schemaObjectAt(t, item, "properties", "conditions", "items", "properties", "values", "items"))

	wantCond := []string{capability.ConditionTypeFlowLabel, capability.ConditionTypeEffectClass, capability.ConditionTypeBlastRadius}
	wantDir := []string{capability.DirectiveTypeLabelOutput, capability.DirectiveTypeDeclassify}
	var wantVar []string
	for _, n := range capability.TaskVarNames() {
		wantVar = append(wantVar, "${"+n+"}")
	}
	if !sameStrings(condExcluded, wantCond) {
		t.Errorf("0.1 condition exclusion = %v, want %v", condExcluded, wantCond)
	}
	if !sameStrings(dirExcluded, wantDir) {
		t.Errorf("0.1 directive exclusion = %v, want %v", dirExcluded, wantDir)
	}
	if !sameStrings(varExcluded, wantVar) {
		t.Errorf("0.1 task-variable exclusion = %v, want %v", varExcluded, wantVar)
	}

	// The other half of the correspondence: the LOADER refuses every one of them under
	// 0.1. A schema exclusion the loader does not enforce (or vice versa) is the drift
	// this test exists to catch.
	bodies := map[string]string{
		"effectCeiling":     "effectCeiling:\n  maxEffectClass: reversible\ncapabilities:\n  - target: tool:t\n    actions: [call]\n",
		"effect contract":   "capabilities:\n  - target: tool:t\n    actions: [call]\n    effect:\n      class: reversible\n",
		"flowLabel":         "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: flowLabel\n        allow: [public]\n",
		"effectClass":       "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: effectClass\n        allow: [reversible]\n",
		"blastRadius":       "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        max: 5\n",
		"labelOutput":       "capabilities:\n  - target: tool:t\n    actions: [call]\n    directives:\n      - type: labelOutput\n        labels: [pii]\n",
		"declassify":        "capabilities:\n  - target: tool:t\n    actions: [call]\n    directives:\n      - type: declassify\n        labels: [pii]\n",
		"${task.id}":        "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: allowedValues\n        argument: a\n        values: [\"${task.id}\"]\n",
		"${task.agent}":     "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: allowedValues\n        argument: a\n        values: [\"${task.agent}\"]\n",
		"${task.principal}": "capabilities:\n  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: allowedValues\n        argument: a\n        values: [\"${task.principal}\"]\n",
	}
	for name, body := range bodies {
		t.Run("loader refuses "+name+" under 0.1", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "m.yaml")
			if err := os.WriteFile(path, []byte("schemaVersion: \"0.1\"\nname: m\nversion: \"1.0.0\"\n"+body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := config.LoadManifest(path)
			if err == nil {
				t.Fatalf("%s must be refused under the 0.1 grammar", name)
			}
			if !strings.Contains(err.Error(), "schemaVersion \"0.2\"") {
				t.Fatalf("%s: err = %v, want it to name the introducing revision", name, err)
			}
		})
	}
}

// schemaNotEnum returns the enum a node excludes via {"not": {"enum": [...]}}.
func schemaNotEnum(t *testing.T, node map[string]any) []string {
	t.Helper()
	return schemaEnum(t, schemaObjectAt(t, node, "not"))
}

// TestComputeAuditStats_CountsDeclassifications pins the operator-facing half of the
// declassification path: `eunox stats` counts an approved clear separately, as the other
// side of the approval queue the escalate count reports.
//
// The count is what an operator watches for a sanitizing step that has quietly become
// routine, so it must key on labels_cleared (the fact the record asserts) and must not
// bucket a declassification away from the allows it belongs with — the call ran.
func TestComputeAuditStats_CountsDeclassifications(t *testing.T) {
	t.Parallel()
	tape := strings.Join([]string{
		`{"decision":"allow","target":"read_file","method":"tools/call"}`,
		`{"decision":"allow","target":"sanitize","method":"tools/call","labels_cleared":["pii"],"approver":"alice"}`,
		`{"decision":"allow","target":"sanitize","method":"tools/call","labels_cleared":["confidential"],"approver":"bob"}`,
		`{"decision":"escalate","target":"drop_table","method":"tools/call","denial_code":"ESCALATION_REQUIRED"}`,
	}, "\n")

	got, err := computeAuditStats(strings.NewReader(tape))
	if err != nil {
		t.Fatalf("computeAuditStats: %v", err)
	}
	if got.allowed != 3 {
		t.Errorf("allowed = %d, want 3 — a declassification is an allow, not a separate bucket", got.allowed)
	}
	if got.declassified != 2 {
		t.Errorf("declassified = %d, want 2", got.declassified)
	}
	if got.escalated != 1 {
		t.Errorf("escalated = %d, want 1", got.escalated)
	}
	if got.allowed+got.blocked+got.observed+got.other != got.total {
		t.Errorf("buckets do not reconcile with total %d", got.total)
	}
}

// TestComputeAuditStats_CountsDeclassifyFaults covers the three declassification facts that
// live in `details` rather than in a signed top-level field, none of which this tool could
// see at all before — it decoded six fields and never touched details, so an approved clear
// that failed to apply was byte-indistinguishable from an ordinary allow, and a refused
// declassification from an ordinary UPSTREAM_ERROR deny.
//
// Each is counted separately because each sends an operator somewhere different: a failed
// commit means the flow store faulted on a call that really ran (the session is now
// over-tainted and later sinks over-block); a not-applied clear means the call was refused
// and nothing moved; a spent grant means a one-shot approval is gone and has to be reissued.
func TestComputeAuditStats_CountsDeclassifyFaults(t *testing.T) {
	t.Parallel()
	tape := strings.Join([]string{
		// A clean declassification: cleared, and the single-use grant it spent is named.
		`{"decision":"allow","target":"sanitize","method":"tools/call","labels_cleared":["pii"],"approver":"alice",` +
			`"details":{"` + audit.DeclassifySpentApprovalKey + `":"apr-1"}}`,
		// The call ran; the clear did not land.
		`{"decision":"allow","target":"sanitize","method":"tools/call",` +
			`"details":{"` + audit.DeclassifyCommitFailedKey + `":["pii"],"` + audit.DeclassifySpentApprovalKey + `":"apr-2"}}`,
		// The call was refused below the decision, so the clear was never made.
		`{"decision":"deny","target":"sanitize","method":"tools/call","denial_code":"UPSTREAM_ERROR",` +
			`"details":{"flow":true,"` + audit.DeclassifyNotAppliedKey + `":["pii"],"` + audit.DeclassifySpentApprovalKey + `":"apr-3"}}`,
		// An ordinary allow whose details are the caller's arguments: no declassify facts,
		// and nothing here may be mistaken for one.
		`{"decision":"allow","target":"read_file","method":"tools/call","details":{"path":"/tmp/x"}}`,
	}, "\n")

	got, err := computeAuditStats(strings.NewReader(tape))
	if err != nil {
		t.Fatalf("computeAuditStats: %v", err)
	}
	if got.declassifyCommitFailed != 1 {
		t.Errorf("declassifyCommitFailed = %d, want 1 — the one an operator must act on", got.declassifyCommitFailed)
	}
	if got.declassifyNotApplied != 1 {
		t.Errorf("declassifyNotApplied = %d, want 1", got.declassifyNotApplied)
	}
	if got.spentApprovals != 3 {
		t.Errorf("spentApprovals = %d, want 3 — a grant is spent on a clean clear, a failed commit and a refusal alike", got.spentApprovals)
	}
	if got.declassified != 1 {
		t.Errorf("declassified = %d, want 1 — only the clear that actually changed something", got.declassified)
	}
	if got.allowed+got.blocked+got.observed+got.other != got.total {
		t.Errorf("buckets do not reconcile with total %d", got.total)
	}

	// The commit failure is CALLED OUT, not merely tallied: it is the only one of the three
	// that means a session is not in the state the policy describes.
	var out strings.Builder
	printAuditStats(&out, got)
	if !strings.Contains(out.String(), "ATTENTION") {
		t.Errorf("printAuditStats did not call out the failed commit:\n%s", out.String())
	}
	for _, want := range []string{"single-use approvals spent = 3", "declassify-not-applied = 1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("printAuditStats is missing %q:\n%s", want, out.String())
		}
	}
}

// TestComputeAuditStats_DeclassifyProbeMatchesTheProducer pins the substring pre-filter the
// details scan uses. It is an optimization with a security-adjacent failure mode: a prefix
// that no longer matches the producer's keys makes every declassification fault silently
// invisible again, which is exactly the state this counting was added to fix.
func TestComputeAuditStats_DeclassifyProbeMatchesTheProducer(t *testing.T) {
	t.Parallel()
	for _, key := range []string{
		audit.DeclassifySpentApprovalKey,
		audit.DeclassifyNotAppliedKey,
		audit.DeclassifyCommitFailedKey,
	} {
		if !strings.HasPrefix(key, audit.DeclassifyDetailPrefix) {
			t.Errorf("key %q does not carry the prefix %q the stats probe filters on", key, audit.DeclassifyDetailPrefix)
		}
		if !audit.IsReservedDetailKey(key) {
			t.Errorf("key %q is not reserved, so `eunox suggest` would mine it as a tool argument", key)
		}
	}
}
