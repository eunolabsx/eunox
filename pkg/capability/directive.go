// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

// DirectiveTypeRedactFields is the discriminator for redact-fields directives.
const DirectiveTypeRedactFields = "redactFields"

// Directive is the interface for all capability directives.
// Directives are post-allow obligations applied to the upstream response.
// Unlike conditions (which are boolean predicates), directives mutate the
// response and MUST NOT affect the allow/deny decision.
//
// Every concrete Directive must implement ToObligation so the enforcement engine
// can translate it without a type switch. A new directive type that only
// implements DirectiveType (not ToObligation) will not compile.
type Directive interface {
	DirectiveType() string
	// ToObligation translates the directive into the obligation the engine
	// passes to the forward core. It is always called on a non-nil receiver.
	ToObligation() Obligation
}

// RedactFieldsDirective masks the listed fields in a tools/call result: each matched field
// keeps its key but its value is replaced with "[redacted]". Fields are dot-path strings
// (e.g. "user.ssn", "$.result.secret"); the leading "$." is optional, and a path landing on
// an array field redacts it in every element. Array-index notation ("users[0].ssn") is NOT
// supported and rejected at manifest load — each segment is a literal object key, so an
// indexed segment would silently match nothing.
//
// Redaction recurses through nested objects/arrays across every JSON text content item and
// structuredContent; non-JSON content (images, resource links, _meta) is preserved. A text
// item that looks like JSON but fails to parse passes through UNREDACTED (silent, not
// fail-closed) — such content must be redacted upstream. Directives apply only to tool:
// targets; any other target type is rejected at load.
type RedactFieldsDirective struct {
	Fields []string `json:"fields"`
}

// DirectiveType returns the redact-fields discriminator.
func (RedactFieldsDirective) DirectiveType() string { return DirectiveTypeRedactFields }

// ToObligation translates the directive into a redactFields obligation.
func (d RedactFieldsDirective) ToObligation() Obligation {
	return Obligation{Type: DirectiveTypeRedactFields, Paths: d.Fields}
}

// IsRedactFieldsDirective reports whether d is a redactFields directive (value or pointer
// form). Single-sourced alongside IsLabelOutputDirective and NIL-SAFE, which is the point:
// DirectiveType has a VALUE receiver, so a typed-nil *RedactFieldsDirective boxed in the
// interface survives a `d != nil` check and panics on the auto-generated dereference — the
// shape an in-process manifest can carry and the one enforcement.CollectObligations already
// guards. AsValueOrPointer answers without dereferencing.
func IsRedactFieldsDirective(d Directive) bool {
	_, ok := AsValueOrPointer[RedactFieldsDirective](d)
	return ok
}

// ConstraintHasResponseDirective reports whether c carries a RESPONSE-mutating directive —
// today redactFields, the only one. Single-sourced so the engine's collect-time skip and the
// PDP's fail-closed guard cannot drift on what counts as one. Nil-safe on both the constraint
// and its entries.
func ConstraintHasResponseDirective(c *Constraint) bool {
	if c == nil {
		return false
	}
	for _, d := range c.Directives {
		if IsRedactFieldsDirective(d) {
			return true
		}
	}
	return false
}
