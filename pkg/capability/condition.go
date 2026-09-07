// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"fmt"
	"net"
	"strings"
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

// Several conditions cache a normalized allowlist, built once by Compile at manifest load.
// Those caches have NO invalidation: mutating the source field after Compile keeps
// enforcing the pre-edit allowlist, silently and fail-open if the edit was a narrowing.
// Build a new condition instead of mutating a compiled one.

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
// action keyword, etc.). Argument names the tool parameter carrying the operation
// string; required except for the JWT v0.2 "op=" shorthand, which scans every
// string argument.
//
// SCOPE LIMIT (security): a coarse first-token verb gate, not a SQL parser — only
// the FIRST whitespace-delimited word is checked, so Operations ["SELECT"] admits
// "SELECT 1; DROP TABLE users" if the driver permits multiple statements per call.
// Treat as defense-in-depth over a read-only DB role with multi-statement execution
// disabled, never as the sole control. See docs/capability-manifest-guide.md.
type AllowedOperationsCondition struct {
	Argument   string   `json:"argument,omitempty"`
	Operations []string `json:"operations"`

	// compiled holds Operations with each entry pre-trimmed by Compile at load time,
	// so the hot path compares ready strings instead of re-trimming the whole
	// allowlist on every enforced call. It stays a SLICE compared with EqualFold
	// rather than a lookup set: keying a map on a case MAPPING does not reproduce
	// EqualFold's Unicode case folding (the Kelvin sign folds to "K" but does not
	// upper- or lower-case to it), so that switch would silently narrow which
	// manifests match, and the fold that does reproduce it — canonicalCaseFold —
	// would have to run over the request's operation to probe the map, per enforced
	// call, in place of the scan it replaces. Unexported, so it never
	// serializes; nil on an uncompiled condition (e.g. one built directly in a test),
	// where AllowsOperation trims as it scans instead.
	compiled []string
}

// Compile pre-trims each entry of Operations once at load, so the hot path stops
// re-trimming the allowlist per request. It is idempotent and cannot fail; the error
// return matches the other compiled conditions so the loader treats them alike.
func (c *AllowedOperationsCondition) Compile() error {
	trimmed := make([]string, len(c.Operations))
	for i, op := range c.Operations {
		trimmed[i] = strings.TrimSpace(op)
	}
	c.compiled = trimmed
	return nil
}

// AllowsOperation reports whether op is in the allowlist, compared
// case-insensitively against each entry with surrounding whitespace trimmed. It
// prefers the pre-trimmed slice Compile built and otherwise trims as it scans, so a
// programmatically built condition matches exactly what a loaded one matches.
//
// A "*" entry is NOT a wildcard: it is rejected at manifest load
// (validateAllowedOperations), so a literal "*" only ever matches the operation "*".
func (c *AllowedOperationsCondition) AllowsOperation(op string) bool {
	// One implementation for both paths: MatchOperation trims as it scans, and
	// TrimSpace on an already-trimmed entry is a no-op, so handing it the compiled
	// slice is exactly the uncompiled rule with the trimming already done. Open-coding
	// the loop here would make the compiled path — the one EVERY manifest-loaded
	// condition takes — a second copy of the matching rule that no production caller
	// exercises against the first.
	if c.compiled != nil {
		return MatchOperation(c.compiled, op)
	}
	return MatchOperation(c.Operations, op)
}

// MatchOperation reports whether op is in the allowed operations set, compared
// case-insensitively after trimming each entry. Entries are trimmed because the
// request verb arrives already whitespace-trimmed: an allowlist entry written as
// "SELECT " would otherwise never match and would silently deny every call.
//
// It is the uncompiled matcher, shared by AllowedOperationsCondition.AllowsOperation's
// fallback and by callers holding a bare operation slice with no condition to compile
// — notably the JWT shorthand PDP, whose operation claims never pass through the
// manifest loader. Keeping one implementation is what lets the compiled and
// uncompiled paths stay in agreement.
func MatchOperation(allowed []string, op string) bool {
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), op) {
			return true
		}
	}
	return false
}

// AllowedExtensionsCondition limits file access to the listed extensions.
//
// Argument names the tool parameter carrying the file path or paths (array, e.g.
// read_multiple_files' `paths`). Argument is required — empty fails closed — and
// when it is an array every path must pass the allowlist.
type AllowedExtensionsCondition struct {
	Argument   string   `json:"argument,omitempty"`
	Extensions []string `json:"extensions"`

	// compiled holds Extensions normalized by Compile at load time (lowercased,
	// dot-prefixed, blanks dropped, duplicates collapsed), so the hot path matches a
	// ready list instead of rebuilding it — and its dedupe map — on every enforced
	// call. Unexported, so it never serializes; nil on an uncompiled condition, where
	// MatchExtensions normalizes per call instead.
	compiled []string
}

// Compile normalizes Extensions once at load so the hot path stops rebuilding the
// list per request. It is idempotent and cannot fail; the error return matches the
// other compiled conditions so the loader treats them alike.
func (c *AllowedExtensionsCondition) Compile() error {
	c.compiled = normalizeExtensions(c.Extensions)
	return nil
}

// MatchExtensions returns the allowlist in matched form: lowercased, each entry a
// dotted suffix, blanks dropped and duplicates collapsed. It prefers what Compile
// cached and otherwise normalizes on the spot, so a programmatically built condition
// matches exactly what a loaded one matches.
//
// The result is READ-ONLY. On the compiled path it is the live policy shared by every
// session on this manifest, read concurrently by every in-flight request with no lock
// — writing through it would silently redefine what is permitted process-wide and
// race those readers. Capacity is clipped to length so an append is forced to copy,
// but that only closes the accidental case; do not write to the elements.
func (c *AllowedExtensionsCondition) MatchExtensions() []string {
	if c.compiled != nil {
		return c.compiled
	}
	return normalizeExtensions(c.Extensions)
}

// normalizeExtensions lowercases each entry and adds a leading dot only when the
// entry does not already start with one, so every entry is a dotted suffix matched
// on a dot boundary (".gz" matches "data.gz", not "datagz"). It does not collapse
// extra leading dots an entry already carries — "..gz" stays two dots and so only
// matches a name literally ending in "..gz". Blank entries are skipped and
// duplicates collapsed; an empty allowlist denies every path.
//
// Single source of the normalization for both the compiled and uncompiled paths.
func normalizeExtensions(exts []string) []string {
	out := make([]string, 0, len(exts))
	seen := make(map[string]struct{}, len(exts))
	for _, ext := range exts {
		n := strings.ToLower(strings.TrimSpace(ext))
		if n == "" {
			continue
		}
		if !strings.HasPrefix(n, ".") {
			n = "." + n
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	// Clip capacity to length. Skipped blanks and collapsed duplicates leave spare
	// capacity, so a caller doing `x := c.MatchExtensions(); x = append(x, ...)` would
	// otherwise write into the backing array of the COMPILED, process-lifetime policy —
	// silently widening the extension allowlist for every session, and racing every
	// concurrent reader while doing it. With cap == len, that append always copies.
	return out[:len(out):len(out)]
}

// AllowedTablesCondition limits database access to the listed tables and columns.
//
// Argument names the tool parameter carrying the table name or names. Argument is
// required — empty fails closed.
type AllowedTablesCondition struct {
	Argument string              `json:"argument,omitempty"`
	Tables   []string            `json:"tables"`
	Columns  map[string][]string `json:"columns,omitempty"`

	// compiled holds the case-folded lookup structures built by Compile at load time,
	// so the hot path indexes ready maps instead of rebuilding the table set, the
	// column-restriction index, AND a per-table column set on every enforced call.
	// Unexported, so it never serializes; nil on an uncompiled condition, which TableLookup
	// REPORTS rather than building on the spot, so the handler can compile a local copy and
	// fail closed on an error this field's accessor has no channel for.
	compiled *compiledTables
}

// compiledTables caches the case-folded lookup structures of an
// AllowedTablesCondition. Table and column names are matched case-insensitively
// because many databases (MySQL, SQL Server) treat identifiers that way, so a
// case-sensitive match would let "Password_Hash" slip past a column ACL written as
// "password_hash". Entries are trimmed for the same reason the other allowlists trim:
// request names arrive already trimmed, so a manifest entry padded with whitespace
// (" users") would never match and would silently deny every call.
type compiledTables struct {
	// tables holds every allowed table name, lowercased and trimmed.
	tables map[string]bool
	// columnsByTable maps a lowercased, trimmed table name to its allowed columns in
	// ORIGINAL case, so denial details echo the manifest as written.
	columnsByTable map[string][]string
	// columnSets maps a lowercased, trimmed table name to its allowed columns
	// lowercased and trimmed for matching.
	columnSets map[string]map[string]bool
}

// Compile builds the case-folded table and column lookup maps once at load, so the
// hot path stops rebuilding them per request. It is idempotent, and refuses two 'columns'
// keys that address the same table, the way every other case-variant ambiguity in this
// codebase is refused rather than resolved (see validateEffectByArgument): one allowlist
// would shadow the other, and picking a side means enforcing a column ACL its author never
// wrote. The manifest loader refuses the same shape first, so this is the exit for a
// condition built through the API.
func (c *AllowedTablesCondition) Compile() error {
	if err := checkColumnKeyCollision(c.Columns); err != nil {
		return err
	}
	c.compiled = compileTables(c.Tables, c.Columns)
	return nil
}

// checkColumnKeyCollision refuses two Columns keys that fold onto one table.
//
// The fold has to be the one the MATCHER applies or the certificate this issues is worthless:
// compileTables and the handler both key on ToLower after TrimSpace, so this does too — NOT
// canonicalCaseFold, which folds pairs ToLower leaves distinct.
func checkColumnKeyCollision(columns map[string][]string) error {
	seen := make(map[string]string, len(columns))
	for table := range columns {
		key := strings.ToLower(strings.TrimSpace(table))
		prior, dup := seen[key]
		if !dup {
			seen[key] = table
			continue
		}
		// Name the pair in a stable order: the map is ranged in Go's randomized order, and an
		// error that names the same two keys differently per run cannot be diffed or tested.
		if table < prior {
			prior, table = table, prior
		}
		return fmt.Errorf("allowedTables 'columns' has case-colliding keys %+q and %+q, which address the same table (names are trimmed and lowercased, the same rule the matcher applies); one column allowlist would shadow the other, so merge them under a single key", prior, table)
	}
	return nil
}

// TableLookup returns the case-folded lookup structures Compile cached, reporting whether the
// condition was compiled at all. It reports rather than building on the spot, so the handler
// can take the same shape its siblings do (Window, Networks): compile a LOCAL copy — the engine
// must not cache state onto a condition it does not own — and turn a compile error into a
// fail-closed denial. Building here silently swallowed that error, since this signature has no
// channel for one, which left the uncompiled path with no fail-closed exit for the next
// validation compileTables grows.
//
// allowedColumns is nil when the condition declares no column restrictions at all,
// which the handler distinguishes from an empty restriction.
//
// All three results are READ-ONLY, and unlike the slice accessors these are maps, so
// nothing structural stops a write. On the compiled path they are the live policy
// shared by every session on this manifest: inserting one key (a table, or a column
// on a table) permanently widens the enforced ACL for the life of the process, with
// no manifest change and no audit trace, and doing it from a request goroutine is an
// unsynchronized write concurrent with every other request's reads — which crashes
// the process with "concurrent map read and map write". Copy before mutating.
func (c *AllowedTablesCondition) TableLookup() (allowedTables map[string]bool, allowedColumns map[string][]string, columnSets map[string]map[string]bool, ok bool) {
	if c.compiled == nil {
		return nil, nil, nil, false
	}
	return c.compiled.tables, c.compiled.columnsByTable, c.compiled.columnSets, true
}

// compileTables is the single source of the table/column normalization, reached only through
// Compile — by the loader for a manifest condition, and by the handler for a local copy of one
// built through the API.
func compileTables(tables []string, columns map[string][]string) *compiledTables {
	out := &compiledTables{tables: make(map[string]bool, len(tables))}
	for _, t := range tables {
		out.tables[strings.ToLower(strings.TrimSpace(t))] = true
	}
	if columns == nil {
		// Left nil deliberately: "no column restrictions declared" is a distinct state
		// from "an empty restriction", and only the former skips the column ACL.
		return out
	}
	out.columnsByTable = make(map[string][]string, len(columns))
	out.columnSets = make(map[string]map[string]bool, len(columns))
	// No fold tiebreak: Compile is the only way in and it refuses a collision first, so no two
	// keys here can address one table. The tiebreak this replaced existed for the accessor's
	// build-on-the-spot path, which resolved an ambiguity the loader refuses rather than failing
	// closed on it; that path is gone (see TableLookup).
	for table, cols := range columns {
		key := strings.ToLower(strings.TrimSpace(table))
		out.columnsByTable[key] = cols
		set := make(map[string]bool, len(cols))
		for _, col := range cols {
			set[strings.ToLower(strings.TrimSpace(col))] = true
		}
		out.columnSets[key] = set
	}
	return out
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

	// compiled holds Domains lowercased and trimmed into a lookup set by Compile at
	// load time, so the hot path does a map lookup instead of rebuilding the set on
	// every enforced call. Unexported, so it never serializes; nil on an uncompiled
	// condition, where MatchDomains builds it on the spot.
	compiled map[string]bool
}

// Compile builds the case-folded domain set once at load, so the hot path stops
// rebuilding it per request. It is idempotent and cannot fail; the error return
// matches the other compiled conditions so the loader treats them alike.
func (c *RecipientDomainCondition) Compile() error {
	c.compiled = normalizeDomains(c.Domains)
	return nil
}

// MatchDomains returns the allowlist as a lowercased, trimmed lookup set. It prefers
// what Compile cached and otherwise builds it on the spot, so a programmatically
// built condition matches exactly what a loaded one matches.
//
// The result is READ-ONLY, and it is a map, so nothing structural stops a write. See
// TableLookup: on the compiled path this is the live policy shared by every session,
// so inserting a domain widens the enforced allowlist process-wide and races every
// concurrent reader. Copy before mutating.
func (c *RecipientDomainCondition) MatchDomains() map[string]bool {
	if c.compiled != nil {
		return c.compiled
	}
	return normalizeDomains(c.Domains)
}

// normalizeDomains is the single source of the domain normalization for both the
// compiled and uncompiled paths. Entries are trimmed because recipients arrive
// already whitespace-trimmed, so a manifest entry padded with whitespace
// ("example.com ") would never match and would silently deny every call.
func normalizeDomains(domains []string) map[string]bool {
	set := make(map[string]bool, len(domains))
	for _, d := range domains {
		set[strings.ToLower(strings.TrimSpace(d))] = true
	}
	return set
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
// already invoked (and allowed) earlier under the same state anchor — the session by
// default; see the anchoring note below. It expresses
// cross-tool sequencing ("deny B after A"), which a stateless per-evaluation
// policy engine (OPA, Envoy ext_authz) cannot represent.
//
// AfterTools is required and non-empty (an empty list fails closed). Each entry
// is a bare tool name; a leading namespace prefix (e.g. "tool:") is stripped
// before matching. An entry that strips to empty (e.g. "", "tool:", "  ") also
// fails closed rather than being silently skipped, so a list whose every entry is
// empty cannot pass unconditionally. Call history is keyed by session ID, so one
// session's activity never gates another's — unless the engine runs under
// enforcement.WithTaskAnchoredState, where history follows the validated task id and
// deliberately spans the sessions sharing it, exactly as the flow-label set does
// (FlowLabelCondition).
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
