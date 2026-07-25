// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"fmt"
	"net"
	"time"
)

// Condition type discriminator values.
const (
	ConditionTypeTimeWindow        = "timeWindow"
	ConditionTypeIPRange           = "ipRange"
	ConditionTypeAllowedOperations = "allowedOperations"
	ConditionTypeAllowedExtensions = "allowedExtensions"
	ConditionTypeAllowedTables     = "allowedTables"
	ConditionTypeMaxCalls          = "maxCalls"
	ConditionTypeRecipientDomain   = "recipientDomain"
	ConditionTypeAllowedValues     = "allowedValues"
	ConditionTypeSequenceBlock     = "sequenceBlock"
	ConditionTypePolicy            = "policy"
	ConditionTypeCustom            = "custom"
)

// Condition is the interface for all capability conditions.
// All conditions have a Type() method returning the discriminator string.
type Condition interface {
	ConditionType() string
}

// TimeWindowCondition limits use to a not-before and not-after time window.
type TimeWindowCondition struct {
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`

	// compiled holds NotBefore / NotAfter pre-parsed (as UTC) by Compile at load
	// time, so the hot path compares ready time.Time values instead of re-parsing
	// the RFC3339 strings every request. Held behind a pointer (not two inline
	// time.Time values) to keep the struct small enough that the value-receiver
	// MarshalJSON does not become a heavy copy. Unexported, so it never serializes;
	// nil on an uncompiled condition (e.g. one built directly in a test), so the
	// handler falls back to per-request parsing. A blank bound stays the zero Time
	// and is ignored — the handler keys off NotBefore/NotAfter being non-empty.
	compiled *compiledTimeWindow
}

// compiledTimeWindow caches the parsed bounds of a TimeWindowCondition.
type compiledTimeWindow struct {
	notBefore time.Time
	notAfter  time.Time
}

// IPRangeCondition limits use to requests originating from the provided CIDRs.
type IPRangeCondition struct {
	CIDRs []string `json:"cidrs"`

	// parsed holds the CIDRs pre-compiled into networks by Compile at load time,
	// so the hot path matches ready *net.IPNet values instead of re-parsing per
	// request. Unexported, so it never serializes; an uncompiled condition leaves
	// it nil and the handler falls back to per-request parsing.
	parsed []*net.IPNet
}

// AllowedOperationsCondition limits use to the listed operations (SQL verb,
// action keyword, etc.).
//
// Argument names the tool parameter carrying the operation string (e.g. the SQL
// query); the proxy checks its first word against Operations. Argument is
// required in manifest policies — empty fails closed — except for the JWT v0.2
// "op=" shorthand, which leaves it empty and scans every string argument.
//
// SCOPE LIMIT — this is a coarse first-token verb gate, not a SQL parser, and the
// gap is an under-block, not a false denial: only the FIRST whitespace-delimited
// word is inspected, so Operations ["SELECT"] admits "SELECT 1; DROP TABLE users"
// and the trailing statement executes upstream if the driver permits multiple
// statements per call. (A leading CTE/EXPLAIN/SET prefix is the harmless converse:
// the first token is not the effective verb, so the call is over-denied.) Denying
// on a bare ';' is not an option — it false-positives on any quoted literal
// containing one — so the boundary is documented rather than widened. Treat this
// as defense-in-depth over a read-only database role plus multi-statement
// execution disabled at the driver, and pair it with argumentSchema or an external
// policy evaluator for untrusted SQL; never make it the sole control. Kept in
// lock-step with docs/capability-manifest-guide.md's allowedOperations section.
type AllowedOperationsCondition struct {
	Argument   string   `json:"argument,omitempty"`
	Operations []string `json:"operations"`
}

// AllowedExtensionsCondition limits file access to the listed extensions.
//
// Argument names the tool parameter carrying the file path or paths (array, e.g.
// read_multiple_files' `paths`). Argument is required — empty fails closed — and
// when it is an array every path must pass the allowlist.
type AllowedExtensionsCondition struct {
	Argument   string   `json:"argument,omitempty"`
	Extensions []string `json:"extensions"`
}

// AllowedTablesCondition limits database access to the listed tables and columns.
//
// Argument names the tool parameter carrying the table name or names. Argument is
// required — empty fails closed.
type AllowedTablesCondition struct {
	Argument string              `json:"argument,omitempty"`
	Tables   []string            `json:"tables"`
	Columns  map[string][]string `json:"columns,omitempty"`
}

// MaxCallsCondition limits the number of calls within a rolling window.
type MaxCallsCondition struct {
	Count         int `json:"count"`
	WindowSeconds int `json:"windowSeconds"`
}

// RecipientDomainCondition limits recipients to the listed email domains.
//
// Argument names the tool parameter carrying the recipient address or addresses.
// Argument is required — empty fails closed.
type RecipientDomainCondition struct {
	Argument string   `json:"argument,omitempty"`
	Domains  []string `json:"domains"`
}

// PolicyCondition delegates evaluation to a named policy backend.
type PolicyCondition struct {
	Backend string      `json:"backend"`
	Config  interface{} `json:"config,omitempty"`
	Input   interface{} `json:"input,omitempty"`
}

// CustomCondition carries an implementation-specific condition payload.
type CustomCondition struct {
	Name   string      `json:"name"`
	Config interface{} `json:"config"`
}

// AllowedValuesCondition limits a named argument (Argument, a key in
// EnforceRequest.Arguments) to a fixed set of scalar Values (string, number,
// boolean, or null).
//
// Non-string values match by exact equality. String values match ONLY as a glob,
// never by exact equality first, so values: ["[0-9]"] admits a single digit
// rather than the literal text "[0-9]". Glob semantics:
//
//   - "*" and "**" alone match ANY string value (including one containing '/'),
//     so values: ["*"] is an explicit allow-any-string wildcard.
//   - "**" crosses '/', so "/reports/**" matches "/reports/q3.pdf" and
//     "/reports/sub/q3.pdf".
//   - a single "*" does NOT cross '/', so "/reports/*" matches "/reports/q3.pdf"
//     but not "/reports/sub/q3.pdf".
//
// The engine implements these in MatchValueGlob.
type AllowedValuesCondition struct {
	Argument string        `json:"argument"`
	Values   []interface{} `json:"values"`
}

// SequenceBlockCondition denies the call when any tool named in AfterTools was
// already invoked (and allowed) earlier in the same session. It expresses
// cross-tool sequencing ("deny B after A"), which a stateless per-evaluation
// policy engine (OPA, Envoy ext_authz) cannot represent.
//
// AfterTools is required and non-empty (an empty list fails closed). Each entry
// is a bare tool name; a leading namespace prefix (e.g. "tool:") is stripped
// before matching. An entry that strips to empty (e.g. "", "tool:", "  ") also
// fails closed rather than being silently skipped, so a list whose every entry is
// empty cannot pass unconditionally. Call history is keyed by session ID, so one
// session's activity never gates another's.
//
// Example — block any external write once credentials have been read:
//
//	capabilities:
//	  - target: tool:write_external
//	    actions: [call]
//	    conditions:
//	      - type: sequenceBlock
//	        afterTools: [read_credentials]
type SequenceBlockCondition struct {
	AfterTools []string `json:"afterTools"`
}

// ConditionType returns the time window discriminator.
func (TimeWindowCondition) ConditionType() string { return ConditionTypeTimeWindow }

// ConditionType returns the IP range discriminator.
func (IPRangeCondition) ConditionType() string { return ConditionTypeIPRange }

// ConditionType returns the allowed operations discriminator.
func (AllowedOperationsCondition) ConditionType() string { return ConditionTypeAllowedOperations }

// ConditionType returns the allowed extensions discriminator.
func (AllowedExtensionsCondition) ConditionType() string { return ConditionTypeAllowedExtensions }

// ConditionType returns the allowed tables discriminator.
func (AllowedTablesCondition) ConditionType() string { return ConditionTypeAllowedTables }

// ConditionType returns the max calls discriminator.
func (MaxCallsCondition) ConditionType() string { return ConditionTypeMaxCalls }

// ConditionType returns the recipient domain discriminator.
func (RecipientDomainCondition) ConditionType() string { return ConditionTypeRecipientDomain }

// ConditionType returns the policy discriminator.
func (PolicyCondition) ConditionType() string { return ConditionTypePolicy }

// ConditionType returns the custom discriminator.
func (CustomCondition) ConditionType() string { return ConditionTypeCustom }

// ConditionType returns the allowedValues discriminator.
func (AllowedValuesCondition) ConditionType() string { return ConditionTypeAllowedValues }

// ConditionType returns the sequenceBlock discriminator.
func (SequenceBlockCondition) ConditionType() string { return ConditionTypeSequenceBlock }

// ArgumentNamer is implemented by every condition type that pins a named tool
// argument (its `argument` field), so callers like the startup drift check can
// enumerate referenced argument names without a closed type switch that would
// silently drop a new argument-carrying condition type. A condition that names no
// argument simply does not implement this interface.
type ArgumentNamer interface {
	// ArgumentName returns the raw `argument` field value (possibly a "$."
	// reference); callers normalize it via ArgumentRootKey. An empty string means
	// no argument is pinned (e.g. the JWT "op=" shorthand).
	ArgumentName() string
}

// ArgumentName returns the allowedValues argument pin.
func (c AllowedValuesCondition) ArgumentName() string { return c.Argument }

// ArgumentName returns the allowedOperations argument pin.
func (c AllowedOperationsCondition) ArgumentName() string { return c.Argument }

// ArgumentName returns the allowedExtensions argument pin.
func (c AllowedExtensionsCondition) ArgumentName() string { return c.Argument }

// ArgumentName returns the allowedTables argument pin.
func (c AllowedTablesCondition) ArgumentName() string { return c.Argument }

// ArgumentName returns the recipientDomain argument pin.
func (c RecipientDomainCondition) ArgumentName() string { return c.Argument }

// Compile-time assertions that every argument-carrying condition type implements
// ArgumentNamer, so a missing or dropped method breaks the build rather than
// silently degrading drift coverage. TestEveryArgumentCarryingConditionIsNamer
// adds a reflection guard for a type that gains an `Argument` field but forgets
// the method.
var (
	_ ArgumentNamer = AllowedValuesCondition{}
	_ ArgumentNamer = AllowedOperationsCondition{}
	_ ArgumentNamer = AllowedExtensionsCondition{}
	_ ArgumentNamer = AllowedTablesCondition{}
	_ ArgumentNamer = RecipientDomainCondition{}
)

// MarshalJSON serializes TimeWindowCondition with its discriminator.
func (c TimeWindowCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes IPRangeCondition with its discriminator.
func (c IPRangeCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes AllowedOperationsCondition with its discriminator.
func (c AllowedOperationsCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes AllowedExtensionsCondition with its discriminator.
func (c AllowedExtensionsCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes AllowedTablesCondition with its discriminator.
func (c AllowedTablesCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes MaxCallsCondition with its discriminator.
func (c MaxCallsCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes RecipientDomainCondition with its discriminator.
func (c RecipientDomainCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes PolicyCondition with its discriminator.
func (c PolicyCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes CustomCondition with its discriminator.
func (c CustomCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes AllowedValuesCondition with its discriminator.
func (c AllowedValuesCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes SequenceBlockCondition with its discriminator.
func (c SequenceBlockCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// Compile parses each CIDR into a *net.IPNet and caches the result on the
// condition, so the hot path matches ready networks instead of re-parsing. It is
// idempotent and commits only once every CIDR has parsed, so a mid-list error
// leaves any prior result untouched; it returns the first parse error.
func (c *IPRangeCondition) Compile() error {
	parsed := make([]*net.IPNet, 0, len(c.CIDRs))
	for _, cidr := range c.CIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		parsed = append(parsed, network)
	}
	c.parsed = parsed
	return nil
}

// Networks returns the pre-compiled networks populated by Compile. The boolean is
// false when Compile has not run, signalling the caller to parse the CIDRs itself.
func (c *IPRangeCondition) Networks() ([]*net.IPNet, bool) {
	return c.parsed, c.parsed != nil
}

// Compile parses NotBefore / NotAfter into time.Time (UTC) and caches them on the
// condition, so the hot path compares ready times instead of re-parsing RFC3339
// per request (mirrors IPRangeCondition.Compile). A blank bound is left as the
// zero Time, which the handler ignores. It is idempotent and commits the compiled
// flag only once both bounds parse, so a malformed bound leaves any prior compiled
// result untouched; it returns the first parse error.
func (c *TimeWindowCondition) Compile() error {
	var w compiledTimeWindow
	if c.NotBefore != "" {
		t, err := time.Parse(time.RFC3339Nano, c.NotBefore)
		if err != nil {
			return fmt.Errorf("invalid notBefore time %q: %w", c.NotBefore, err)
		}
		w.notBefore = t.UTC()
	}
	if c.NotAfter != "" {
		t, err := time.Parse(time.RFC3339Nano, c.NotAfter)
		if err != nil {
			return fmt.Errorf("invalid notAfter time %q: %w", c.NotAfter, err)
		}
		w.notAfter = t.UTC()
	}
	c.compiled = &w
	return nil
}

// Window returns the pre-parsed bounds populated by Compile. The boolean is false
// when Compile has not run, signalling the caller to parse the strings itself. A
// bound whose source string is empty is the zero Time; the caller must key off
// NotBefore/NotAfter being non-empty to decide whether the bound applies.
func (c *TimeWindowCondition) Window() (notBefore, notAfter time.Time, ok bool) {
	if c.compiled == nil {
		return time.Time{}, time.Time{}, false
	}
	return c.compiled.notBefore, c.compiled.notAfter, true
}
