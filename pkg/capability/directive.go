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

// RedactFieldsDirective masks the listed fields in a tools/call result: each
// matched field keeps its key but has its value replaced by the placeholder string
// "[redacted]" (the key's presence is retained; only the value is hidden).
// Fields are dot-path strings (e.g. "user.ssn", "$.result.secret"); the leading
// "$." or "$" is optional. A path's final segment that names a field inside array
// elements redacts it in every element ("users.ssn" masks ssn in each object
// in the users array). Array-index notation ("users[0].ssn") is NOT supported and
// is rejected at manifest load: each segment is treated as a literal object key,
// so an indexed segment would silently match nothing. Redaction recurses through
// nested objects and array elements, applying to every JSON text content item and
// to structuredContent; an absent field is a no-op and non-JSON content (images,
// resource links, _meta) is preserved.
//
// Directives apply only to tool: targets; one on any other target type is
// rejected at manifest load.
//
// Free-form text (an error string, a "[ERROR] ..." log line) is forwarded
// unchanged — a dot-path addresses JSON object keys, which such text has none of.
// A text item that looks like a JSON object (leading '{') but fails to parse —
// or JSON embedded in surrounding prose — is NOT a clean container: it passes
// through unredacted (a silent pass, not fail-closed), so such content must be
// redacted upstream. The response *envelope*, by contrast, fails closed when
// unparseable.
type RedactFieldsDirective struct {
	Fields []string `json:"fields"`
}

// DirectiveType returns the redact-fields discriminator.
func (RedactFieldsDirective) DirectiveType() string { return DirectiveTypeRedactFields }

// ToObligation translates the directive into a redactFields obligation.
func (d RedactFieldsDirective) ToObligation() Obligation {
	return Obligation{Type: DirectiveTypeRedactFields, Paths: d.Fields}
}
