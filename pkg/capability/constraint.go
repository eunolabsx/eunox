// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"path"
	"sort"
	"strconv"
	"strings"
)

// TargetType is the namespace prefix for a capability resource field.
// Every resource field in a manifest must begin with one of the four
// recognized prefixes; the proxy rejects any unprefixed value at load time.
type TargetType string

// TargetType constants for the four recognized namespace prefixes.
const (
	TargetTypeTool     TargetType = "tool"
	TargetTypeResource TargetType = "resource"
	TargetTypePrompt   TargetType = "prompt"
	TargetTypeSystem   TargetType = "system"
)

// MethodSamplingCreateMessage is the MCP method name for server-initiated
// sampling requests. Defined once so the literal isn't repeated (and can't
// silently typo-diverge) across the audit, PDP, and transport packages —
// pkg/capability is their common dependency, so every consumer can reach it
// (internal/audit in particular depends only on pkg/capability and the
// stdlib, never internal/mcp).
const MethodSamplingCreateMessage = "sampling/createMessage"

// Enforced */list method names. Defined in pkg/capability (the common dependency
// of internal/pdp and internal/transport) so the transport dispatch map and the
// PDP's list accounting switch on the SAME constants and cannot silently diverge:
// a divergence would let dispatchList filter a flavor whose entries the PDP's
// CountListEntries scores as 0 (or vice versa), skewing the upstream_count /
// suppressed_count audit fields operators use to detect policy pruning.
const (
	MethodToolsList     = "tools/list"
	MethodResourcesList = "resources/list"
	MethodPromptsList   = "prompts/list"
)

// Enforced request method names — the methods that require a PDP decision
// before being forwarded to the upstream. Defined here, alongside the */list
// method names above, so every consumer (internal/audit, internal/transport,
// internal/pdp) switches on the SAME constants and cannot silently diverge.
const (
	MethodToolsCall          = "tools/call"
	MethodResourcesRead      = "resources/read"
	MethodResourcesSubscribe = "resources/subscribe"
	MethodPromptsGet         = "prompts/get"
)

// MethodTargetType maps an MCP method name to its TargetType. It is the single
// source of truth for the method->namespace mapping, shared by internal/audit
// (deriving structured target fields for the tamper-evident log) and any future
// consumer, so a method added to the transport dispatch map cannot silently
// diverge from the audit layer's classification of it. ok is false for a method
// with no TargetType mapping.
func MethodTargetType(method string) (TargetType, bool) {
	switch method {
	case MethodToolsCall, MethodToolsList:
		return TargetTypeTool, true
	case MethodResourcesRead, MethodResourcesSubscribe, MethodResourcesList:
		return TargetTypeResource, true
	case MethodPromptsGet, MethodPromptsList:
		return TargetTypePrompt, true
	case MethodSamplingCreateMessage:
		return TargetTypeSystem, true
	default:
		return "", false
	}
}

// List result envelope array keys — the JSON field under which each */list flavor
// carries its entry array. Paired with the method names above via ListResultKey.
const (
	ListKeyTools     = "tools"
	ListKeyResources = "resources"
	ListKeyPrompts   = "prompts"
)

// ListResultKey maps a */list method to its result-envelope entry-array key, or
// "" for a non-list method. The single source of truth binding each list method
// to its key, shared by the PDP's CountListEntries and filter helpers so the two
// layers cannot disagree on which methods are lists or where their entries live.
func ListResultKey(method string) string {
	switch method {
	case MethodToolsList:
		return ListKeyTools
	case MethodResourcesList:
		return ListKeyResources
	case MethodPromptsList:
		return ListKeyPrompts
	default:
		return ""
	}
}

var validTargetTypes = map[TargetType]bool{
	TargetTypeTool:     true,
	TargetTypeResource: true,
	TargetTypePrompt:   true,
	TargetTypeSystem:   true,
}

// IsTargetType reports whether prefix is a recognized namespace prefix
// (tool, resource, prompt, system). It is the single source of truth for the
// prefix set — the enforcement engine's splitEnginePrefix consults it — so the
// loader and runtime can never disagree about what counts as a namespace.
func IsTargetType(prefix string) bool {
	return validTargetTypes[TargetType(prefix)]
}

// validActionsFor returns the set of valid action keywords for a given target type.
// The wildcard "*" is always valid.
func validActionsFor(t TargetType) []string {
	switch t {
	case TargetTypeTool:
		return []string{"call", "*"}
	case TargetTypeResource:
		return []string{"read", "*"}
	case TargetTypePrompt:
		return []string{"get", "*"}
	case TargetTypeSystem:
		return []string{"allow", "*"}
	default:
		return []string{"*"}
	}
}

// ParseTarget splits a target field on the first ':' and validates the prefix.
// It returns the TargetType, the bare name after the prefix, and an error if
// the prefix is absent or unrecognized.
//
// Valid forms:
//
//	"tool:read_file"                   → (TargetTypeTool, "read_file", nil)
//	"resource:file:///data/reports/*"  → (TargetTypeResource, "file:///data/reports/*", nil)
//	"prompt:code_review"               → (TargetTypePrompt, "code_review", nil)
//	"system:sampling/createMessage"    → (TargetTypeSystem, "sampling/createMessage", nil)
func ParseTarget(s string) (TargetType, string, error) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("target %q must begin with a namespace prefix (tool:, resource:, prompt:, or system:)", s)
	}
	prefix := TargetType(s[:idx])
	bare := s[idx+1:]
	if !validTargetTypes[prefix] {
		return "", "", fmt.Errorf("target %q has unrecognized namespace prefix %q — valid prefixes are: tool, resource, prompt, system", s, prefix)
	}
	if bare == "" {
		return "", "", fmt.Errorf("target %q must have a non-empty name after the namespace prefix", s)
	}
	return prefix, bare, nil
}

// GlobMetaChars is the set of glob metacharacters ('*', '?', '[', '\') that make
// a value a pattern rather than a literal. It is the single source of the
// target-glob character set: ContainsGlobMeta (is-this-a-glob),
// internal/config.literalPrefix (mandatory-literal-prefix extraction), and the
// suggest subcommand's inertness check all read it, so the set cannot drift between
// the classifier and the prefix logic. It must stay in sync with the matcher
// (enforcement.matchesResource -> path.Match): path.Match treats '\' as an escape
// metacharacter on every platform (unlike filepath.Match, which disables escaping
// on Windows), so omitting it would classify a backslash-bearing target as an exact
// literal while the matcher reads it as a pattern (consuming the '\' to escape the
// next byte) — a classifier/matcher disagreement (e.g. the descriptionHash pin gate
// and drift literal-vs-glob branching would treat it as pinnable while path.Match
// matches a different name).
const GlobMetaChars = `*?[\`

// ContainsGlobMeta reports whether s contains a glob metacharacter, i.e. whether s
// is a glob pattern rather than a literal value. Shared by manifest drift detection
// and (*Constraint).IsPinnedExactTool.
func ContainsGlobMeta(s string) bool {
	return strings.ContainsAny(s, GlobMetaChars)
}

// ValidateActionForTargetType reports whether action is valid for the given
// target type. Returns an error with a clear message if not.
func ValidateActionForTargetType(targetType TargetType, action string) error {
	valid := validActionsFor(targetType)
	for _, a := range valid {
		if a == action {
			return nil
		}
	}
	return fmt.Errorf("invalid action %q for target type %q — valid actions are %v", action, targetType, valid)
}

// Constraint describes the target, actions, schema, conditions, and directives granted by a capability.
type Constraint struct {
	Target  string   `json:"target"`
	Actions []string `json:"actions"`
	// Enforcement selects how a denial produced by this constraint is handled.
	// "" or "enforce" (the default) denies normally; "audit" downgrades the
	// denial to an observed allow — logged but forwarded — for staged rollout.
	// See the MCP Capability Manifest spec § 3.2.
	Enforcement string `json:"enforcement,omitempty"`
	// DescriptionHash is an optional "sha256:<hex>" pin for the named tool's
	// description as reported by the upstream's tools/list. Supported only on
	// exact-name tool: targets (the loader rejects it on resource:, prompt:, and
	// glob targets). When set, the proxy verifies the live description at startup
	// and during validate --live; a mismatch aborts startup unconditionally (not
	// gated by --strict-drift). eunox init --pin-descriptions populates it.
	DescriptionHash string          `json:"descriptionHash,omitempty"`
	ArgumentSchema  *ArgumentSchema `json:"argumentSchema,omitempty"`
	// Principal optionally scopes this constraint to requests whose validated JWT
	// identity matches. Each key is a supported identity claim (see
	// SupportedPrincipalClaims), each value a list of allowed patterns (exact or
	// path.Match glob). A request matches when EVERY listed claim is present and
	// satisfies one of its patterns (AND across claims, OR within a claim's list).
	// An empty/absent Principal applies to every principal. A non-matching
	// principal-scoped constraint is skipped during selection like a target
	// mismatch (fail closed). Needs a validated token, so it only takes effect
	// under JWT mode (--jwks-uri).
	Principal  map[string][]string `json:"principal,omitempty"`
	Conditions []Condition         `json:"conditions,omitempty"`
	// Directives are post-allow obligations applied to the upstream response.
	// Unlike Conditions (boolean predicates), directives mutate the response
	// and MUST NOT affect the allow/deny decision.
	Directives []Directive `json:"directives,omitempty"`
}

// Enforcement modes for a Constraint.
const (
	// EnforcementEnforce enforces the constraint's verdict normally. It is the
	// default when the field is empty.
	EnforcementEnforce = "enforce"
	// EnforcementAudit puts the constraint in observe mode: a denial it produces
	// (action, argumentSchema, or conditions) is logged and the call is forwarded
	// rather than blocked. It never opens the allowlist (a target matching no
	// constraint is still denied) and never downgrades a kill-switch or
	// JWT-intersection denial.
	EnforcementAudit = "audit"
)

// IsAuditOnly reports whether this constraint is in audit (observe) mode, i.e.
// a denial it produces should be logged but not enforced.
func (c *Constraint) IsAuditOnly() bool {
	return c.Enforcement == EnforcementAudit
}

// supportedPrincipalClaims is the set of validated JWT identity claims a
// constraint's `principal` may match on — the identity dimensions eunox models
// and stamps into the audit log. Arbitrary custom claims are not supported here;
// gate on a non-standard claim with a `policy` condition, which sees every claim
// via input.claims. The loader rejects any unrecognized principal key so a typo
// never silently fails to match. Unexported and read only through the accessors
// below: an exported mutable map let any code in the process widen or narrow the
// accepted identity dimensions.
var supportedPrincipalClaims = map[string]bool{
	"agent_id": true,
	"task_id":  true,
	"sub":      true,
	"iss":      true,
}

// IsSupportedPrincipalClaim reports whether name is a principal claim a constraint
// may match on, without exposing the underlying map for mutation.
func IsSupportedPrincipalClaim(name string) bool { return supportedPrincipalClaims[name] }

// SupportedPrincipalClaimNames returns the supported principal claim names sorted
// for stable error messages. A fresh slice each call, so a caller cannot mutate the
// package's accepted set.
func SupportedPrincipalClaimNames() []string {
	names := make([]string, 0, len(supportedPrincipalClaims))
	for k := range supportedPrincipalClaims {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// HasPrincipal reports whether this constraint is scoped to a principal.
func (c *Constraint) HasPrincipal() bool {
	return len(c.Principal) > 0
}

// PrincipalMatches reports whether claims satisfy this constraint's principal
// requirement. An empty/absent Principal matches every request. Otherwise every
// named claim must be present as a string and match (exact or path.Match glob) at
// least one of its patterns (AND across claims, OR within a claim's list). A
// missing claim, non-string value, or no match fails closed; nil claims (no
// validated token) never satisfy a non-empty principal.
func (c *Constraint) PrincipalMatches(claims map[string]interface{}) bool {
	if len(c.Principal) == 0 {
		return true
	}
	for claimName, patterns := range c.Principal {
		raw, ok := claims[claimName]
		if !ok {
			return false
		}
		value, ok := raw.(string)
		if !ok {
			return false
		}
		if !matchesAnyPattern(value, patterns) {
			return false
		}
	}
	return true
}

// matchesAnyPattern reports whether value equals (exact-first) or glob-matches
// (path.Match) any of the patterns. Matching is exact-first-then-glob: a pattern equal
// to value matches even when it is a malformed glob (e.g. the literal "agent-["), and a
// malformed pattern that does NOT equal value is skipped by path.Match's error branch
// rather than erroring. A manifest loaded through the loader never carries a malformed
// pattern (config's validatePrincipal runs path.Match against each at load time), so
// the malformed case only matters for a programmatically built Constraint — where the
// exact-equality branch means it still matches its own literal text, never widening the
// scope beyond that literal. (This exact-first order differs from
// enforcement.MatchAllowedValue, which is glob-only so a literal pattern cannot bypass a
// glob; principal patterns are IdP-issued identities where matching the literal is the
// desired behavior.)
//
// Principal matching deliberately uses plain [path.Match] (single-segment glob:
// '*' does NOT cross '/'), distinct from the engine's two other matchers:
// enforcement.MatchesResource (target names, ':'-namespaced) and
// enforcement.MatchValueGlob (argument values, with '**'/segment semantics). The
// divergence is intentional, not drift to reconcile: a principal is a flat identity
// string (an agent id, a subject, an email like "*@corp.com"), not a '/'-structured
// path or URI, so it must NOT inherit the '**' / '/'-segment / encoded-separator
// handling MatchValueGlob applies to file-path and URI values. A metachar change to
// MatchValueGlob therefore neither does nor should propagate here.
func matchesAnyPattern(value string, patterns []string) bool {
	for _, p := range patterns {
		if p == value {
			return true
		}
		if matched, err := path.Match(p, value); err == nil && matched {
			return true
		}
	}
	return false
}

// ArgumentSchema is a JSON-Schema subset for argument validation.
type ArgumentSchema struct {
	Type                 SchemaType                 `json:"type,omitempty"`
	Properties           map[string]*ArgumentSchema `json:"properties,omitempty"`
	Required             []string                   `json:"required,omitempty"`
	AdditionalProperties *bool                      `json:"additionalProperties,omitempty"`
	Enum                 []interface{}              `json:"enum,omitempty"`
	// Pattern is a regular expression the string value must match. It compiles with
	// Go's regexp (RE2 syntax, not ECMA-262), so lookaround and backreferences are
	// rejected at manifest load. Matching is UNANCHORED (as in JSON Schema): the
	// regex need only be found somewhere in the value, so "[0-9]{4}" admits
	// "abc1234". For a security policy that is rarely intended — anchor with ^...$.
	// The engine does not anchor for you because a "starts-with" idiom like "^[A-Z]"
	// is legitimate.
	Pattern     string          `json:"pattern,omitempty"`
	MinLength   *int            `json:"minLength,omitempty"`
	MaxLength   *int            `json:"maxLength,omitempty"`
	Minimum     *float64        `json:"minimum,omitempty"`
	Maximum     *float64        `json:"maximum,omitempty"`
	Items       *ArgumentSchema `json:"items,omitempty"`
	MaxItems    *int            `json:"maxItems,omitempty"`
	MinItems    *int            `json:"minItems,omitempty"`
	Description string          `json:"description,omitempty"`
}

// MarshalJSON serializes ArgumentSchema, omitting "type" entirely when it has no
// value. omitempty is a no-op on the struct-typed Type field and
// SchemaType.MarshalJSON renders the zero value as null, so without this a
// typeless leaf schema (only pattern/enum/minLength) would serialize as
// "type":null, tripping strict JSON-Schema consumers. The alias type drops the
// method set to avoid recursion; the shallower *SchemaType field shadows the
// embedded "type" key so omitempty can elide an absent type.
func (a ArgumentSchema) MarshalJSON() ([]byte, error) { //nolint:gocritic // hugeParam: value receiver required for json.Marshaler
	type alias ArgumentSchema
	aux := struct {
		Type *SchemaType `json:"type,omitempty"`
		alias
	}{alias: alias(a)}
	if !a.Type.IsZero() {
		aux.Type = &a.Type
	}
	return json.Marshal(aux)
}

// UnmarshalJSON decodes an ArgumentSchema while capturing the numeric minimum/maximum
// bounds as json.Number (number-preserving) so an integer bound above 2^53 is rejected
// at manifest load rather than silently rounded into a neighbouring float64. A plain
// *float64 decode of `minimum: 1700000000000000001` stores 1700000000000000000, and the
// exact-int64 argument comparison (compareToBound) then admits an argument strictly below
// the written minimum — a silent widening of a numeric argument constraint (fail-open on a
// boundary). enum literals already get UseNumber treatment (see Constraint.UnmarshalJSON);
// this extends the same exact-decode guarantee to the bounds.
func (a *ArgumentSchema) UnmarshalJSON(data []byte) error {
	// alias drops ArgumentSchema's method set (so this does not recurse) while keeping
	// its fields; the outer json.Number minimum/maximum shadow the alias's *float64 ones
	// (shallower field wins), capturing the raw literals before any float64 coercion.
	type alias ArgumentSchema
	aux := struct {
		Minimum json.Number `json:"minimum,omitempty"`
		Maximum json.Number `json:"maximum,omitempty"`
		*alias
	}{alias: (*alias)(a)}
	dec := json.NewDecoder(bytes.NewReader(data))
	// UseNumber so enum literals above 2^53 stay json.Number here too, matching the
	// Constraint decoder that would otherwise have provided it.
	dec.UseNumber()
	if err := dec.Decode(&aux); err != nil {
		return err
	}
	lower, err := exactFloatBound(aux.Minimum)
	if err != nil {
		return fmt.Errorf("minimum: %w", err)
	}
	upper, err := exactFloatBound(aux.Maximum)
	if err != nil {
		return fmt.Errorf("maximum: %w", err)
	}
	a.Minimum = lower
	a.Maximum = upper
	return nil
}

// exactFloatBound converts a json.Number bound to *float64, rejecting any literal whose
// float64 representation is not exact (an integer above 2^53, or a value that overflows
// float64). An absent bound (empty json.Number) yields a nil pointer. Returning an error
// fails the manifest load closed rather than enforcing a silently-shifted boundary.
func exactFloatBound(n json.Number) (*float64, error) {
	if n == "" {
		return nil, nil
	}
	f, err := n.Float64()
	if err != nil {
		// Overflow (|value| too large for float64) or a malformed literal.
		return nil, fmt.Errorf("bound %q is not representable as a 64-bit float: %w", n.String(), err)
	}
	orig, ok := new(big.Rat).SetString(n.String())
	if !ok {
		return nil, fmt.Errorf("bound %q is not a valid number", n.String())
	}
	// Round-trip exactness is required whenever EITHER of two things is true:
	//
	//  - orig.IsInt(): the literal was written as an integer, at ANY magnitude
	//    (including beyond int64 range). This is the original check: an
	//    out-of-precision integer bound must never load silently rounded, since
	//    that is a "silently-shifted boundary" regardless of which comparison
	//    path (exact-int64 or float64-fallback) later reads it.
	//  - wholeInt64Float(f): the enforcement comparison (compareToBound) switches
	//    to EXACT int64 precision whenever the bound's float64 value f happens to
	//    be a whole number in int64 range — regardless of whether the manifest
	//    author wrote the literal with a decimal point. So round-trip exactness
	//    cannot be checked only for bounds written as integers: a FRACTIONAL
	//    literal whose magnitude is large enough that float64 rounds away its
	//    fractional part (e.g. minimum: 9007199254740993.5 rounding to
	//    9007199254740994.0) would silently become an exact-int64 bound
	//    different from the one written, admitting an argument at that rounded
	//    whole-number boundary the author never wrote.
	//
	// A bound that is neither — a fractional literal whose rounding stays
	// fractional, or whose rounding lands outside int64 range without itself
	// being written as an integer — is compared in float64 on both sides
	// (compareToBound's fallback), where its float64 approximation is
	// consistent, so it is accepted as before.
	if orig.IsInt() || wholeInt64Float(f) {
		rf := new(big.Rat).SetFloat64(f)
		if rf == nil || rf.Cmp(orig) != 0 {
			return nil, fmt.Errorf("bound %q cannot be represented exactly as a 64-bit float; it would round to %s, silently shifting the enforced boundary away from what the manifest wrote", n.String(), strconv.FormatFloat(f, 'f', -1, 64))
		}
	}
	return &f, nil
}

// minInt64Float and twoTo63Float bound the range of float64 values exactly
// representable as int64, mirroring pkg/enforcement's identical constants
// (handlers.go) — the half-open interval [minInt64Float, twoTo63Float) is exactly
// the range int64(f) converts without wraparound.
const (
	minInt64Float = -9223372036854775808.0 // -2^63
	twoTo63Float  = 9223372036854775808.0  // 2^63 (one past math.MaxInt64)
)

// wholeInt64Float reports whether f is a whole number representable exactly as
// an int64 — the same condition pkg/enforcement's compareToBound (via
// floatToInt64) uses to switch a bound comparison to exact-integer precision.
// Duplicated here rather than imported to avoid a capability -> enforcement
// dependency; the two must be kept in sync.
func wholeInt64Float(f float64) bool {
	if f < minInt64Float || f >= twoTo63Float {
		return false
	}
	i := int64(f)
	return float64(i) == f
}

// SchemaType can be a single type string or an array of type strings.
type SchemaType struct {
	Single   string
	Multiple []string
}

type constraintJSON struct {
	Target          string          `json:"target"`
	Actions         []string        `json:"actions"`
	Enforcement     string          `json:"enforcement,omitempty"`
	DescriptionHash string          `json:"descriptionHash,omitempty"`
	ArgumentSchema  *ArgumentSchema `json:"argumentSchema,omitempty"`
	// Principal must round-trip: dropping it silently widens the constraint to match
	// every caller rather than only the intended sub/iss/agent_id/task_id.
	Principal  map[string][]string `json:"principal,omitempty"`
	Conditions []ConditionWrapper  `json:"conditions,omitempty"`
	Directives []DirectiveWrapper  `json:"directives,omitempty"`
}

// MarshalJSON serializes Constraint while preserving polymorphic conditions and directives.
// Value receiver is required so json.Marshal works on both Constraint and *Constraint values.
func (c Constraint) MarshalJSON() ([]byte, error) { //nolint:gocritic // hugeParam: value receiver required for json.Marshaler
	var conditions []ConditionWrapper
	if c.Conditions != nil {
		conditions = make([]ConditionWrapper, 0, len(c.Conditions))
		for _, condition := range c.Conditions {
			conditions = append(conditions, ConditionWrapper{Condition: condition})
		}
	}

	var directives []DirectiveWrapper
	if c.Directives != nil {
		directives = make([]DirectiveWrapper, 0, len(c.Directives))
		for _, directive := range c.Directives {
			directives = append(directives, DirectiveWrapper{Directive: directive})
		}
	}

	return json.Marshal(constraintJSON{
		Target:          c.Target,
		Actions:         c.Actions,
		Enforcement:     c.Enforcement,
		DescriptionHash: c.DescriptionHash,
		ArgumentSchema:  c.ArgumentSchema,
		Principal:       c.Principal,
		Conditions:      conditions,
		Directives:      directives,
	})
}

// UnmarshalJSON deserializes Constraint while restoring concrete condition and directive types.
func (c *Constraint) UnmarshalJSON(data []byte) error {
	var aux constraintJSON
	// Decode with UseNumber so numeric literals in argumentSchema.enum stay
	// json.Number rather than being widened to float64 (which rounds integers above
	// 2^53). The enum check in pkg/enforcement compares the preserved value exactly.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&aux); err != nil {
		return err
	}

	c.Target = aux.Target
	c.Actions = aux.Actions
	c.Enforcement = aux.Enforcement
	c.DescriptionHash = aux.DescriptionHash
	c.ArgumentSchema = aux.ArgumentSchema
	c.Principal = aux.Principal

	// Always reassign Conditions and Directives so unmarshalling into a reused
	// Constraint cannot retain stale policy objects: a reload that clears them
	// (JSON null or absent key) must not keep enforcing the old configuration.
	// nil in => nil out, matching JSON null semantics.
	if aux.Conditions == nil {
		c.Conditions = nil
	} else {
		c.Conditions = make([]Condition, 0, len(aux.Conditions))
		for _, cw := range aux.Conditions {
			c.Conditions = append(c.Conditions, cw.Condition)
		}
	}

	if aux.Directives == nil {
		c.Directives = nil
	} else {
		c.Directives = make([]Directive, 0, len(aux.Directives))
		for _, dw := range aux.Directives {
			c.Directives = append(c.Directives, dw.Directive)
		}
	}

	return nil
}

// IsZero reports whether SchemaType has neither a single nor multi-value representation.
func (s SchemaType) IsZero() bool {
	return s.Single == "" && len(s.Multiple) == 0
}

// MarshalJSON serializes SchemaType as either a string, array, or null.
func (s SchemaType) MarshalJSON() ([]byte, error) {
	switch {
	case len(s.Multiple) > 0:
		return json.Marshal(s.Multiple)
	case s.Single != "":
		return json.Marshal(s.Single)
	default:
		return []byte("null"), nil
	}
}

// UnmarshalJSON deserializes SchemaType from a string, array, or null.
func (s *SchemaType) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = SchemaType{}
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = SchemaType{Single: single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		*s = SchemaType{Multiple: multiple}
		return nil
	}

	return fmt.Errorf("schema type must be string, array of strings, or null: %s", string(data))
}
