// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"unicode/utf8"

	"github.com/eunolabs/eunox/pkg/capability"
)

// patternCache memoizes compiled regexps keyed by source pattern. argumentSchema
// patterns are static (manifest-loaded, never JWT-supplied), so the map is bounded
// and never sees attacker input; caching removes a regexp.Compile from the
// per-request hot path.
var patternCache sync.Map // map[string]*regexp.Regexp

// compilePattern returns the compiled form of pattern, memoizing successful
// compilations in patternCache. A pattern that fails to compile is not cached
// (it is rejected at manifest load by CompileSchemaPatterns, so the enforcement
// path never sees one; the error is still returned here for direct callers).
func compilePattern(pattern string) (*regexp.Regexp, error) {
	if v, ok := patternCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// LoadOrStore collapses a concurrent first-compile race to one shared instance.
	actual, _ := patternCache.LoadOrStore(pattern, re)
	return actual.(*regexp.Regexp), nil
}

// CompileSchemaPatterns walks an argument schema tree and compiles every `pattern`
// it carries, at manifest load time: a malformed pattern is rejected up front
// rather than as a per-request denial, and each valid one is primed into
// patternCache so the hot path is a cache hit. Returns the first error in
// deterministic order.
//
// schemaPath roots the error message (e.g. "capabilities[0].argumentSchema");
// nested subschemas extend it with ".properties.<name>" and ".items" to match the
// load-time keyword validator. A nil schema is a no-op.
func CompileSchemaPatterns(schemaPath string, schema *capability.ArgumentSchema) error {
	return compileSchemaPatterns(schemaPath, schema)
}

func compileSchemaPatterns(schemaPath string, s *capability.ArgumentSchema) error {
	if s == nil {
		return nil
	}
	if s.Pattern != "" {
		if _, err := compilePattern(s.Pattern); err != nil {
			return fmt.Errorf("%s: invalid pattern %q: %w", schemaPath, s.Pattern, err)
		}
	}
	// Sort property names so a manifest with several bad patterns reports the same
	// one deterministically.
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := compileSchemaPatterns(schemaPath+".properties."+name, s.Properties[name]); err != nil {
			return err
		}
	}
	if s.Items != nil {
		if err := compileSchemaPatterns(schemaPath+".items", s.Items); err != nil {
			return err
		}
	}
	return nil
}

// ValidateArgumentSchema validates args against a JSON Schema subset.
// Returns nil if valid, or an error describing the first violation found.
// A nil schema is always valid.
//
// Supported keywords: properties, required, additionalProperties, enum,
// pattern, minLength, maxLength, minimum, maximum, items, minItems, maxItems.
func ValidateArgumentSchema(args map[string]interface{}, schema *capability.ArgumentSchema) error {
	if schema == nil {
		return nil
	}
	return schemaValidateValue("$", args, schema)
}

func schemaValidateValue(jsonPath string, val interface{}, schema *capability.ArgumentSchema) error {
	if schema == nil {
		return nil
	}

	// The enum check runs against the ORIGINAL, un-coerced value so a json.Number is
	// compared at full int64 precision by numericEqual; flattening to float64 first
	// (as the keyword checks below require) would round an integer above 2^53 into a
	// different enum entry. The float coercion is therefore done after this block.
	if len(schema.Enum) > 0 {
		matched := false
		for _, allowed := range schema.Enum {
			// numericEqual bridges bare-int enum values and json.Number/float64
			// request arguments, matching handleAllowedValues.
			if reflect.DeepEqual(allowed, val) || numericEqual(allowed, val) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: value not in enum", jsonPath)
		}
		// An enum match does NOT exempt the value from the type/keyword checks
		// below: in JSON Schema enum and type are independent and must all hold.
	}

	// The un-coerced argument is retained so schemaValidateNumber can compare an
	// integral value against an integral minimum/maximum at full int64 precision
	// rather than the rounded float64 below (an integer >= 2^53 rounds during
	// coercion and would otherwise slip past a bound it actually exceeds).
	original := val

	// Normalize a non-float64 numeric argument to float64 — the type the number
	// keyword checks, schemaCheckType, and the type switch below expect. A
	// json.Number or a programmatic bare int/uint/float32 would otherwise match no
	// case and silently pass minimum/maximum/type (a fail-open). The enum check
	// above deliberately precedes this so large integers keep full precision.
	if _, isFloat := val.(float64); !isFloat {
		if f, ok := toFloat64(val); ok {
			val = f
		}
	}

	// Fail closed on a json.Number whose magnitude overflows float64 (e.g. 1e400):
	// it survives the coercion above and, not being a type-switch arm below, would
	// fall through to "return nil" and silently bypass minimum/maximum.
	if n, isNum := val.(json.Number); isNum {
		return fmt.Errorf("%s: numeric value %q out of representable range", jsonPath, n.String())
	}

	// Fail closed on a non-finite float. strconv.ParseFloat (and therefore toFloat64)
	// accepts "NaN"/"Inf"/"Infinity", so a programmatic or relaxed-decoder argument
	// can coerce to NaN, which satisfies neither v < min nor v > max and would bypass
	// both bounds. Reject every non-finite value uniformly, like the overflow guard.
	if f, ok := val.(float64); ok && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return fmt.Errorf("%s: non-finite numeric value", jsonPath)
	}

	// Enforce schema.Type before keyword checks to catch mismatches that would
	// otherwise silently pass (e.g. a number where maxLength is declared).
	if !schema.Type.IsZero() {
		if err := schemaCheckType(jsonPath, val, schema.Type); err != nil {
			return err
		}
	}

	switch v := val.(type) {
	case string:
		return schemaValidateString(jsonPath, v, schema)
	case float64:
		return schemaValidateNumber(jsonPath, v, original, schema)
	case map[string]interface{}:
		return schemaValidateObject(jsonPath, v, schema)
	case []interface{}:
		return schemaValidateArray(jsonPath, v, schema)
	case bool, nil:
		// Booleans and JSON null carry no length/range keyword to enforce.
		return nil
	default:
		// A value that is none of the JSON-decoded shapes above is something only a
		// direct (library) caller of the exported ValidateArgumentSchema can hand-build
		// — e.g. a native []string / []int / map[string]int. Without this arm it would
		// fall through and silently pass declared items/minItems/maxItems (and object)
		// keywords (a fail-open); normalize and route it through the same validators the
		// JSON shape uses so the restriction is enforced.
		return schemaValidateNativeComposite(jsonPath, val, schema)
	}
}

// schemaValidateNativeComposite normalizes a Go value that is none of the
// JSON-decoded types schemaValidateValue's type switch models — the native
// composites a direct ValidateArgumentSchema caller can pass (e.g. []string, []int,
// map[string]int) — and routes it through the array/object validators so its
// items/minItems/maxItems (or object) keywords are enforced rather than silently
// skipped. A slice/array becomes []interface{}; a string-keyed map becomes
// map[string]interface{}. A non-string map key cannot model a JSON object, so it
// fails closed. Any other kind (a struct, a pointer, a channel) carries no schema
// keyword this validator checks and passes, matching the prior behavior for
// non-composite values.
func schemaValidateNativeComposite(jsonPath string, val interface{}, schema *capability.ArgumentSchema) error {
	rv := reflect.ValueOf(val)
	switch nativeCompositeJSONType(val) {
	case "array":
		arr := make([]interface{}, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			arr[i] = rv.Index(i).Interface()
		}
		return schemaValidateArray(jsonPath, arr, schema)
	case "object":
		m := make(map[string]interface{}, rv.Len())
		for _, k := range rv.MapKeys() {
			// nativeCompositeJSONType admits a string-KINDED key; a named string type
			// (type K string) is not assignable to interface{}.(string), so guard it and
			// fail closed rather than pass an unrepresentable object.
			ks, ok := k.Interface().(string)
			if !ok {
				return fmt.Errorf("%s: object key is not a string", jsonPath)
			}
			m[ks] = rv.MapIndex(k).Interface()
		}
		return schemaValidateObject(jsonPath, m, schema)
	default:
		// A non-string-keyed map cannot model a JSON object; reject it rather than silently
		// pass, matching schemaJSONTypeOf classifying it "unknown". Any other kind (struct,
		// pointer, channel) carries no array/object keyword to enforce and passes.
		if rv.Kind() == reflect.Map {
			return fmt.Errorf("%s: object key is not a string", jsonPath)
		}
		return nil
	}
}

// schemaCheckType verifies that val's JSON type matches typ.
func schemaCheckType(jsonPath string, val interface{}, typ capability.SchemaType) error {
	got := schemaJSONTypeOf(val)
	if typ.Single != "" {
		if !schemaTypeCompatible(got, typ.Single, val) {
			// A fractional number reports JSON type "number", so a generic "expected
			// integer, got number" would mislead (42 is "number" yet passes). Surface
			// the fractional part as the cause.
			if typ.Single == "integer" && got == "number" {
				return fmt.Errorf("%s: expected integer, got non-integer number %g", jsonPath, val.(float64))
			}
			return fmt.Errorf("%s: expected type %q, got %q", jsonPath, typ.Single, got)
		}
		return nil
	}
	for _, t := range typ.Multiple {
		if schemaTypeCompatible(got, t, val) {
			return nil
		}
	}
	return fmt.Errorf("%s: value type %q does not match any of %v", jsonPath, got, typ.Multiple)
}

func schemaJSONTypeOf(val interface{}) string {
	switch val.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "array"
	case nil:
		return "null"
	}
	// A direct ValidateArgumentSchema caller can pass a native Go composite (e.g.
	// []string, []int, map[string]int) that none of the JSON-decoded cases above model.
	// Classify it through the SAME helper schemaValidateNativeComposite uses, so the
	// up-front schemaCheckType agrees with the validator that normalizes and validates
	// these. Absent this, a schema that declares type: array/object — the standard way to
	// write such a schema — rejects a valid native composite as "unknown" before the
	// native-composite path is ever reached, making schemaValidateNativeComposite dead code
	// for any typed schema. Anything the helper does not recognize (a struct, a pointer, a
	// non-string-keyed map) stays "unknown" and fails closed at the type check.
	if t := nativeCompositeJSONType(val); t != "" {
		return t
	}
	return "unknown"
}

// nativeCompositeJSONType classifies a native Go composite — a value none of the
// JSON-decoded shapes model — by the JSON type it represents: "array" for a slice or
// array, "object" for a string-keyed map. It returns "" for anything else (a scalar,
// struct, pointer, or non-string-keyed map). schemaJSONTypeOf and
// schemaValidateNativeComposite both classify through this single helper, so the up-front
// type check and the validator dispatch cannot drift apart about which native value is an
// array versus an object — the exact agreement the typed-schema fix depends on.
func nativeCompositeJSONType(val interface{}) string {
	switch rv := reflect.ValueOf(val); rv.Kind() {
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Map:
		if rv.Type().Key().Kind() == reflect.String {
			return "object"
		}
	}
	return ""
}

func schemaTypeCompatible(gotType, schemaType string, val interface{}) bool {
	if gotType == schemaType {
		return true
	}
	// JSON has a single numeric type (both 42 and 3.14 are "number"). A number
	// satisfies "integer" only when it has no fractional part, else e.g. LIMIT 3.14
	// would slip through.
	if schemaType == "integer" && gotType == "number" {
		f, ok := val.(float64)
		return ok && f == math.Trunc(f)
	}
	return false
}

func schemaValidateString(p, v string, s *capability.ArgumentSchema) error {
	if s.Pattern != "" {
		re, err := compilePattern(s.Pattern)
		if err != nil {
			return fmt.Errorf("%s: invalid pattern %q: %w", p, s.Pattern, err)
		}
		if !re.MatchString(v) {
			return fmt.Errorf("%s: value does not match pattern %q", p, s.Pattern)
		}
	}
	runeLen := utf8.RuneCountInString(v)
	if s.MinLength != nil && runeLen < *s.MinLength {
		return fmt.Errorf("%s: string length %d is less than minLength %d", p, runeLen, *s.MinLength)
	}
	if s.MaxLength != nil && runeLen > *s.MaxLength {
		return fmt.Errorf("%s: string length %d exceeds maxLength %d", p, runeLen, *s.MaxLength)
	}
	return nil
}

// schemaValidateNumber enforces minimum/maximum. raw is the argument before the
// float64 coercion in schemaValidateValue; v is that coercion. When both the
// argument and the bound are exact int64 integers the comparison runs at int64
// precision (see compareToBound), so an integer >= 2^53 is not first rounded into a
// neighbouring value that would let an over-bound argument pass.
func schemaValidateNumber(p string, v float64, raw interface{}, s *capability.ArgumentSchema) error {
	if s.Minimum != nil && compareToBound(raw, v, *s.Minimum) < 0 {
		return fmt.Errorf("%s: value %g is less than minimum %g", p, v, *s.Minimum)
	}
	if s.Maximum != nil && compareToBound(raw, v, *s.Maximum) > 0 {
		return fmt.Errorf("%s: value %g exceeds maximum %g", p, v, *s.Maximum)
	}
	return nil
}

// compareToBound orders a numeric argument against a minimum/maximum bound,
// returning -1, 0, or 1. raw is the un-coerced argument and f its float64 coercion.
// When raw is an exact int64 and bound is a whole int64-representable value the
// comparison is exact; otherwise it falls back to the float64 comparison.
func compareToBound(raw interface{}, f, bound float64) int {
	if ri, ok := asInt64(raw); ok {
		if bi, ok := floatToInt64(bound); ok {
			switch {
			case ri < bi:
				return -1
			case ri > bi:
				return 1
			default:
				return 0
			}
		}
	}
	switch {
	case f < bound:
		return -1
	case f > bound:
		return 1
	default:
		return 0
	}
}

func schemaValidateObject(p string, v map[string]interface{}, s *capability.ArgumentSchema) error {
	for _, req := range s.Required {
		if _, ok := v[req]; !ok {
			return fmt.Errorf("%s: missing required field %q", p, req)
		}
	}
	// Sort property names so a multi-violation object surfaces the same
	// (lexicographically-first) violation every run, rather than a flaky one from
	// nondeterministic map iteration. compileSchemaPatterns sorts for the same reason.
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		propVal, ok := v[name]
		if !ok {
			continue
		}
		if err := schemaValidateValue(p+"."+name, propVal, s.Properties[name]); err != nil {
			return err
		}
	}
	if s.AdditionalProperties != nil && !*s.AdditionalProperties {
		// Collect the extra keys and sort so the same (lexicographically-first)
		// disallowed property is reported every run.
		var extras []string
		for name := range v {
			if _, ok := s.Properties[name]; !ok {
				extras = append(extras, name)
			}
		}
		sort.Strings(extras)
		if len(extras) > 0 {
			return fmt.Errorf("%s: additional property %q is not allowed", p, extras[0])
		}
	}
	return nil
}

func schemaValidateArray(p string, v []interface{}, s *capability.ArgumentSchema) error {
	if s.MinItems != nil && len(v) < *s.MinItems {
		return fmt.Errorf("%s: array length %d is less than minItems %d", p, len(v), *s.MinItems)
	}
	if s.MaxItems != nil && len(v) > *s.MaxItems {
		return fmt.Errorf("%s: array length %d exceeds maxItems %d", p, len(v), *s.MaxItems)
	}
	if s.Items != nil {
		for i, item := range v {
			if err := schemaValidateValue(fmt.Sprintf("%s[%d]", p, i), item, s.Items); err != nil {
				return err
			}
		}
	}
	return nil
}
