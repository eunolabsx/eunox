// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"fmt"
	"sort"
	"strings"
)

// Task-context variables let a manifest bind an argument to the CALLER's own verified
// identity instead of to a literal — written once rather than once per task. The surface is
// three properties of the validated JWT, and it is closed:
//
//	${task.id}        the mcp.task_id claim
//	${task.agent}     the mcp.agent_id claim
//	${task.principal} the token subject (sub)
//
// Three rules make them safe, each load-enforced rather than left to convention:
//
//  1. A reference must be the WHOLE value ("job-${task.id}" is a load error) — interpolating
//     into surrounding text would build a glob pattern partly from an IdP-supplied claim.
//  2. A resolved value is compared by EXACT equality, never as a glob, so a claim value of
//     "*" cannot become an allow-anything wildcard the token holder chose for themselves.
//  3. An unresolvable reference DENIES rather than falling back to the literal text or
//     matching empty: "there is no identity" is not a match.
const (
	// TaskVarID resolves to the validated token's mcp.task_id claim.
	TaskVarID = "task.id"
	// TaskVarAgent resolves to the validated token's mcp.agent_id claim.
	TaskVarAgent = "task.agent"
	// TaskVarPrincipal resolves to the validated token's subject (sub) — the human or
	// service identity the token was minted for.
	TaskVarPrincipal = "task.principal"
)

// taskVarClaims maps each variable to the flat input.claims key it reads. Those three keys
// are RESERVED in the claims map (see the PDP's reservedClaimKeys): filled authoritatively
// from the validated token's canonical fields, so a same-named custom claim cannot shadow
// them and point a reference at attacker-chosen data.
var taskVarClaims = map[string]string{
	TaskVarID:        "task_id",
	TaskVarAgent:     "agent_id",
	TaskVarPrincipal: "sub",
}

// TaskVarNames returns the closed variable set in a stable order, for validation error
// messages and docs.
func TaskVarNames() []string {
	out := make([]string, 0, len(taskVarClaims))
	for name := range taskVarClaims {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ContainsVariableRef reports whether s carries a "${...}" reference anywhere. Deliberately
// broader than ParseVariableRef: the LOADER uses it to find every value that wants to be a
// variable, so a misspelled or embedded one is a load error instead of a literal string that
// silently never matches.
//
// Applied ONLY under the grammar revision that defines the variable surface — under "0.1" a
// "${" is an ordinary character with no glob meaning, so applying this check there would
// turn an existing, valid document into a startup failure over a surface it doesn't have.
func ContainsVariableRef(s string) bool {
	return strings.Contains(s, "${")
}

// IsTaskVarRef reports whether s is EXACTLY one recognized task-context variable — the
// narrow test the RUNTIME matchers use, where ContainsVariableRef is the wide test the
// loader uses.
//
// A value that merely looks reference-ish and names nothing in the closed set (e.g.
// "${STAGE}" in a caller's JWT capability claim) is a LITERAL that must keep matching
// itself: those values never pass through the manifest loader, so treating them as
// references would void a grant with no error anywhere to grep for.
func IsTaskVarRef(s string) bool {
	name, ok := ParseVariableRef(s)
	if !ok {
		return false
	}
	_, known := taskVarClaims[name]
	return known
}

// TaskVarClaimKey returns the flat input.claims key a variable reads, and whether the name
// is in the closed set. It is IsTaskVarRef's second half, exposed so a caller that has
// ALREADY parsed the reference can finish classifying without re-parsing.
func TaskVarClaimKey(name string) (string, bool) {
	key, known := taskVarClaims[name]
	return key, known
}

// ParseVariableRef returns the variable name when s is EXACTLY one reference
// ("${task.id}" -> "task.id", true). Anything else — an embedded reference, an unclosed
// brace, plain text — returns ("", false).
func ParseVariableRef(s string) (string, bool) {
	if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") {
		return "", false
	}
	name := s[2 : len(s)-1]
	if name == "" || strings.ContainsAny(name, "${}") {
		return "", false
	}
	return name, true
}

// ValidateVariableRef checks a manifest string value that contains a "${" and reports why
// it is not a usable reference, or nil when it is one — the closed-grammar gate that makes a
// misspelled `${task.identifier}` a LOAD ERROR rather than an inert literal that quietly
// denies every call at runtime.
func ValidateVariableRef(s string) error {
	name, ok := ParseVariableRef(s)
	if !ok {
		return fmt.Errorf("value %q contains a ${...} reference but is not one: a task-context variable must be the ENTIRE value (%q), never interpolated into surrounding text — an interpolated value would be glob-matched text built partly from a token claim", s, "${"+TaskVarID+"}")
	}
	if _, known := taskVarClaims[name]; !known {
		return fmt.Errorf("unknown task-context variable %q — the closed set is %s", "${"+name+"}", strings.Join(bracketed(TaskVarNames()), ", "))
	}
	return nil
}

// bracketed renders variable names in their reference spelling for error messages.
func bracketed(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, "${"+n+"}")
	}
	return out
}

// ResolveTaskVar returns the value a variable resolves to from the request's validated
// claims. ok is false when the variable is unknown, there is no token, the claim is absent,
// or it is empty/non-string — every case the caller must turn into a DENY, never a match
// against "".
func ResolveTaskVar(name string, claims map[string]interface{}) (string, bool) {
	key, known := taskVarClaims[name]
	if !known || claims == nil {
		return "", false
	}
	v, present := claims[key]
	if !present {
		return "", false
	}
	s, isString := v.(string)
	if !isString || strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}
