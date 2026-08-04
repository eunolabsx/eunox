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

// patternCache memoizes compiled regexps keyed by source pattern. Patterns are static
// (manifest-loaded, never JWT-supplied), so the map is bounded and never sees attacker
// input; caching removes a regexp.Compile from the per-request hot path.
var patternCache sync.Map // map[string]*regexp.Regexp

// compilePattern returns the compiled form of pattern, memoizing successful compilations.
// A pattern that fails to compile is not cached — CompileSchemaPatterns rejects it at
// manifest load, so the enforcement path never sees one.
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

// CompileSchemaPatterns walks an argument schema tree and compiles every `pattern` at
// manifest load time, so a malformed pattern is rejected up front and each valid one is
// primed into patternCache for a hot-path cache hit. Returns the first error in
// deterministic order. A nil schema is a no-op.
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

	// Unwrap a NAMED scalar type (type Path string) to its predeclared underlying type: it
	// is not assignable to interface{}.(string), so it matches no type-switch arm below,
	// silently skipping every declared keyword (fail-open) under a typeless schema. Only a
	// direct library caller can produce one. Named composites are normalized further down.
	val = unwrapNamedScalar(val)

	// Runs before the FLOAT COERCION below so a json.Number is compared at full int64
	// precision; flattening to float64 first would round an integer above 2^53 into a
	// different enum entry.
	if len(schema.Enum) > 0 {
		matched := false
		for _, allowed := range schema.Enum {
			// Unwrap the ENTRY too: DeepEqual is type-identity-sensitive, so unwrapping only
			// the argument would break a match against a named-type enum entry.
			allowed = unwrapNamedScalar(allowed)
			// numericEqual bridges bare-int enum values and json.Number/float64
			// request arguments, matching EvaluateAllowedValues.
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

	// Retained un-coerced so schemaValidateNumber can compare an integral value against
	// an integral minimum/maximum at full int64 precision rather than the rounded float64
	// below (an integer >= 2^53 would otherwise slip past a bound it exceeds).
	original := val

	// Normalize a non-float64 numeric to float64: without this a json.Number or bare
	// int/uint/float32 matches no type-switch arm and silently passes minimum/maximum/type.
	if _, isFloat := val.(float64); !isFloat {
		if f, ok := toFloat64(val); ok {
			val = f
		}
	}

	// Fail closed on a json.Number whose magnitude overflows float64 (e.g. 1e400): it
	// would otherwise fall through to "return nil", bypassing minimum/maximum.
	if n, isNum := val.(json.Number); isNum {
		return fmt.Errorf("%s: numeric value %q out of representable range", jsonPath, n.String())
	}

	// Fail closed on a non-finite float (toFloat64 accepts "NaN"/"Inf"), which would
	// otherwise satisfy neither v < min nor v > max and bypass both bounds.
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
		// A value that is none of the JSON-decoded shapes above (a native []string,
		// []int, map[string]int from a direct library caller) would otherwise silently
		// pass declared items/minItems/maxItems keywords (fail-open).
		return schemaValidateNativeComposite(jsonPath, val, schema)
	}
}

// schemaValidateNativeComposite normalizes a native Go value schemaValidateValue's type
// switch does not model, routing it through the array/object validators so its
// items/minItems/maxItems keywords are enforced rather than silently skipped. A
// non-string map key cannot model a JSON object, so it fails closed.
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
		// A non-string-keyed map cannot model a JSON object; reject rather than silently
		// pass. Any other kind carries no array/object keyword to enforce and passes.
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
	// Classify a native Go composite through the SAME helper schemaValidateNativeComposite
	// uses: without this, a schema declaring type: array/object rejects a valid native
	// composite as "unknown" before reaching the native-composite path, making that path
	// dead code for any typed schema.
	if t := nativeCompositeJSONType(val); t != "" {
		return t
	}
	return "unknown"
}

// unwrapNamedScalar returns val converted to the predeclared type underlying its named
// scalar type (type Path string -> string), or val unchanged when it is not one.
// json.Number is excluded: it carries NUMERIC semantics the enum comparison and float
// coercion downstream already model exactly, which flattening to string would lose.
// Integers unwrap to int64 (unsigned to uint64) so compareToBound keeps its int64-exact
// path for values at or above 2^53.
func unwrapNamedScalar(val interface{}) interface{} {
	switch val.(type) {
	case nil, string, bool, float64, json.Number, map[string]interface{}, []interface{}:
		// Every shape the proxy's own JSON path produces exits here without touching
		// reflect, including the two composites: schemaValidateValue recurses into every
		// node, so leaving them to the reflect probe below would cost two reflect calls
		// per node just to learn there is nothing to unwrap.
		return val
	}
	rt := reflect.TypeOf(val)
	// A predeclared type reports Name() == Kind().String(); a named type reports its own
	// name. An unnamed type falls through to the kind switch, which has no composite arm.
	if rt == nil || rt.Name() == rt.Kind().String() {
		return val // predeclared: nothing to unwrap
	}
	rv := reflect.ValueOf(val)
	switch rv.Kind() {
	case reflect.String:
		return rv.String()
	case reflect.Bool:
		return rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint()
	case reflect.Float32, reflect.Float64:
		return rv.Float()
	}
	// A named composite (type Tags []string) or anything else: left for
	// schemaValidateNativeComposite, which routes it through the array/object validators.
	return val
}

// nativeCompositeJSONType classifies a native Go composite by the JSON type it
// represents ("array"/"object", "" otherwise). Shared by schemaJSONTypeOf and
// schemaValidateNativeComposite so the up-front type check and the validator dispatch
// cannot drift on which native value is an array versus an object.
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
// When both the argument and the bound are integers the comparison is exact at any
// magnitude — int64 within that range, an exact rational beyond it. Only a genuinely
// FRACTIONAL operand falls back to the float64 comparison.
func compareToBound(raw interface{}, f, bound float64) int {
	if ri, ok := asInt64(raw); ok {
		if bi, ok := capability.FloatToInt64(bound); ok {
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
	// Both sides are integers but outside int64 range, so the float64 fallback would
	// round them together (9223372036854775809 vs a maximum of 9223372036854775808
	// would compare equal). Integers only, like numericEqual's exact arm: a fractional
	// bound's float64 coercion is a different rational and must not be compared exactly.
	if rr, ok := exactIntegerRat(raw); ok {
		if br, ok := exactIntegerRat(bound); ok {
			return rr.Cmp(br)
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
