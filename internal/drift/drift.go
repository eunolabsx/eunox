// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package drift holds the startup manifest-drift-comparison policy — FM-1
// through FM-6.
//
// After the MCP initialize handshake the proxy fetches tools/list from the
// upstream and compares the live tool set against the capability manifest.
// These failure modes are detected:
//
//	FM-1  A new upstream tool is matched by a manifest glob — silent over-permission.
//	FM-2  A manifest resource entry matches no live upstream tool — dead reference.
//	FM-3  A condition/argumentSchema argument name is absent from the live inputSchema — silent bypass risk.
//	FM-4  The live server version does not satisfy the manifest's serverVersion pin.
//	FM-5  A live tool's description or parameter descriptions do not match the manifest's descriptionHash pin.
//	FM-6  The live inputSchema diverges structurally from a constraint's argumentSchema (added-under-closed-schema or retyped parameter).
//
// In non-strict mode findings are emitted as structured log lines to stderr and
// the session continues — EXCEPT FM-5 (description-hash mismatch) and Fm2Pinned (a
// description-pinned tool absent from the live list), which both abort startup
// UNCONDITIONALLY (see hasCriticalDrift). With --strict-drift, FM-1, FM-2, FM-4,
// and FM-6 findings (IsFatal) also abort session establishment. FM-3 and
// "uncovered" are always advisory.
//
// The comparison is pure (no I/O beyond the stderr log emission). It is shared
// by two consumers: the transport runtime drives it through the injected
// CheckFunc hook at session start (MakeDriftCheck), and `validate --live`
// renders the same findings as an operator report. The package depends only on
// internal/{config,mcp,pdp} + pkg/{capability,enforcement} + stdlib — never on
// internal/transport (which imports it), so there is no cycle.

package drift

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// CheckFunc is the manifest-drift comparison injected into a transport, so the
// runtime can run the session-start drift check without referencing the policy
// logic. The transport probes the upstream tool list (it owns the connection) and
// hands the raw result, server version, and any probe error to the hook, which
// parses, compares against the manifest, and returns a non-nil error when startup
// must abort. A nil CheckFunc means no drift checking.
type CheckFunc func(rawToolsListResult json.RawMessage, serverVersion string, probeErr error) error

// matchResource reports whether the resource pattern (its namespace prefix
// stripped) matches the bare target name. Delegates to
// enforcement.MatchesResource so the matching semantics live in one place.
func matchResource(pattern, name string) bool {
	return enforcement.MatchesResource(pdp.StripNamespacePrefix(pattern), name)
}

// resSpecificity scores how specific a resource pattern (prefix stripped) is
// against name, via enforcement.ResourceSpecificity — the same algorithm the
// engine uses, so the two can never rank overlapping globs differently.
func resSpecificity(pattern, name string) int {
	return enforcement.ResourceSpecificity(pdp.StripNamespacePrefix(pattern), name)
}

// UpstreamTool describes one tool returned by the upstream tools/list response.
type UpstreamTool struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
	// Title, Annotations, and OutputSchema are model-facing tool metadata folded
	// into the FM-5 description-hash pin (see capability.ToolHashParams).
	Title        string
	Annotations  map[string]interface{}
	OutputSchema map[string]interface{}
}

// UpstreamTool must stay field-for-field identical to mcp.ToolEntry, which is where the
// wire decode lives. This assertion is the compiler check for that: a struct conversion
// compiles only between types with identical fields, so ADDING a field to either one
// without the other breaks the build here rather than silently leaving the new field
// zero in ParseToolsListResult's named-field copy — and a zero field means every FM-5
// descriptionHash is computed over data the upstream actually sent something for. The
// named copy in ParseToolsListResult covers the other direction (a same-type REORDER,
// which a conversion would accept while transposing values), so the two together make
// both failure modes compile errors.
var _ = UpstreamTool(mcp.ToolEntry{})

// Kind classifies a drift finding.
type Kind string

// truncatedPaginationHint is the explanation Fm2 and Fm2Pinned's LogLine text
// share for an absent manifest entry: an upstream ending pagination early (an
// empty nextCursor on a non-final page) hides a tool identically to a
// genuinely removed/renamed one, so both Kinds name it as a possible cause.
// Factored into one constant so refining the wording can update both Kinds at
// once rather than risk one LogLine case drifting from the other.
const truncatedPaginationHint = "truncated pagination — an empty nextCursor on a non-final page — hiding it from this session's tools/list"

const (
	// Fm1 — upstream tool matched by a manifest glob (FM-1, silent over-permission).
	Fm1 Kind = "fm1"
	// Fm2 — manifest resource entry matches no live upstream tool (FM-2, dead reference).
	Fm2 Kind = "fm2"
	// Fm3 — condition argument not found in live inputSchema (FM-3, silent bypass risk).
	Fm3 Kind = "fm3"
	// Fm4 — live server version does not satisfy the manifest's serverVersion pin (FM-4).
	Fm4 Kind = "fm4"
	// Fm5 — live tool description does not match the manifest's descriptionHash pin
	// (FM-5). Always fatal (regardless of --strict-drift): a poisoned description can
	// steer the model even within the allowed tool set.
	Fm5 Kind = "fm5"
	// Fm2Pinned — a description-pinned exact tool: entry matches no live tool. The
	// critical variant of FM-2: with the tool absent from tools/list its pin was
	// never verified, so a later direct call by name could be accepted with an
	// unverified description. Like FM-5, always fatal.
	Fm2Pinned Kind = "fm2_pinned"
	// Fm6 — the live inputSchema's parameter surface diverges from the manifest's
	// argumentSchema in a way FM-3 does not cover: a parameter appears that a closed
	// schema (additionalProperties:false) did not declare, or a declared parameter
	// changed type. Warn (fatal only under --strict-drift): unlike the description
	// pin, benign schema evolution is common, so a structural change must not abort
	// startup unconditionally. The disappearance of a declared parameter is FM-3, not
	// FM-6.
	Fm6 Kind = "fm6"
	// Uncovered — upstream tool has no manifest entry (informational; denied by default).
	Uncovered Kind = "uncovered"
	// SchemaAbsent — a covering constraint pins one or more arguments, but the live tool
	// published NO inputSchema at all, so FM-3/FM-6 could not run and those pins went
	// UNVERIFIED this session. Advisory (never fatal): request-time enforcement of the
	// pinned arguments is unaffected — only the startup drift signal is absent — and a
	// tool that omits its inputSchema block may still enforce, so this cannot be treated
	// as a dropped parameter (a false FM-3). It exists so the gap is visible rather than
	// silent.
	SchemaAbsent Kind = "schema_absent"
)

// Warning is one finding produced by CheckManifestDrift.
type Warning struct {
	Kind          Kind
	Tool          string // upstream tool name (empty for FM-2, FM-4)
	Resource      string // manifest resource pattern (empty for uncovered); version constraint for FM-4
	Argument      string // condition/parameter argument name (FM-3 and FM-6)
	VersionActual string // actual server version reported in initialize (FM-4 only)
	HashExpected  string // manifest descriptionHash pin (FM-5 only)
	HashActual    string // sha256 of the live description (FM-5 only)
	Detail        string // human-readable structural-change description (FM-6 only)
	// LiveToolCount and ExpectedToolCount (Fm2 and Fm2Pinned only) are the
	// session-wide distinct live tool count and distinct manifest exact-tool
	// count, so an operator reading one absent-entry finding can judge whether
	// the WHOLE live list came up short (consistent with truncated pagination)
	// or just this one entry is stale — the aggregate signal a per-target finding
	// cannot otherwise convey. Identical across every Fm2/Fm2Pinned Warning from
	// one CheckManifestDrift call.
	LiveToolCount     int
	ExpectedToolCount int
}

// IsFatal reports whether this finding aborts session establishment under
// --strict-drift: FM-1, FM-2, FM-4, FM-6, and Fm2Pinned. FM-3 and uncovered are
// advisory. Note that FM-5 AND Fm2Pinned are ALSO unconditionally fatal via
// hasCriticalDrift (independent of --strict-drift); Fm2Pinned appears in both sets,
// so a strict run reaches it here and a non-strict run still aborts on it there.
func (w Warning) IsFatal() bool {
	return w.Kind == Fm1 || w.Kind == Fm2 || w.Kind == Fm4 || w.Kind == Fm6 || w.Kind == Fm2Pinned
}

// severity returns the log-level label for this finding. Every LogLine case routes
// through it, so a change to the mapping cannot silently skip a kind — two cases used to
// hardcode "WARN" instead, and they were the two UNCONDITIONALLY fatal ones.
//
// FM-5 and Fm2Pinned are ERROR precisely because they abort startup on their own (see
// hasCriticalDrift, which is not gated by --strict-drift): a mismatched or unverifiable
// tool description may carry steering instructions injected into what the model reads,
// and the one line an operator greps for after a refused boot must not sit at the same
// level as advisory FM-3.
func (w Warning) severity() string {
	switch {
	case w.Kind == Uncovered:
		return "INFO"
	case w.Kind == Fm5 || w.Kind == Fm2Pinned:
		return "ERROR"
	default:
		return "WARN"
	}
}

// LogLine formats the finding as a single structured stderr line.
func (w Warning) LogLine() string {
	switch w.Kind {
	case Fm1:
		return fmt.Sprintf(
			`[eunox] %s drift=fm1 tool=%q resource=%q — upstream tool admitted by a manifest glob rather than an exact entry; verify this is intentional before deploying`,
			w.severity(), w.Tool, w.Resource,
		)
	case Fm2:
		return fmt.Sprintf(
			`[eunox] %s drift=fm2 resource=%q — manifest entry matches no live upstream tool (tool removed or renamed, or %s; this session saw %d live tool name(s) against %d exact tool(s) named in the manifest)`,
			w.severity(), w.Resource, truncatedPaginationHint, w.LiveToolCount, w.ExpectedToolCount,
		)
	case Fm2Pinned:
		return fmt.Sprintf(
			`[eunox] %s drift=fm2_pinned resource=%q — description-pinned tool is absent from the live tools/list; its descriptionHash could not be verified (upstream may be hiding a poisoned tool, or %s; this session saw %d live tool name(s) against %d exact tool(s) named in the manifest)`,
			w.severity(), w.Resource, truncatedPaginationHint, w.LiveToolCount, w.ExpectedToolCount,
		)
	case Fm3:
		return fmt.Sprintf(
			`[eunox] %s drift=fm3 resource=%q tool=%q argument=%q — pinned argument not in live inputSchema; the pin may not enforce if the upstream renamed it`,
			w.severity(), w.Resource, w.Tool, w.Argument,
		)
	case Fm4:
		actual := w.VersionActual
		if actual == "" {
			actual = "(unknown)"
		}
		return fmt.Sprintf(
			`[eunox] %s drift=fm4 serverVersion=%q actual=%q — server version does not satisfy manifest pin; server may have been updated`,
			w.severity(), w.Resource, actual,
		)
	case Fm5:
		return fmt.Sprintf(
			`[eunox] %s drift=fm5 resource=%q tool=%q — description hash mismatch; tool description may have been modified (expected %s, got %s)`,
			w.severity(), w.Resource, w.Tool, w.HashExpected, w.HashActual,
		)
	case Fm6:
		return fmt.Sprintf(
			`[eunox] %s drift=fm6 resource=%q tool=%q argument=%q — %s; review whether the argumentSchema still constrains this tool as intended`,
			w.severity(), w.Resource, w.Tool, w.Argument, w.Detail,
		)
	case Uncovered:
		return fmt.Sprintf(
			`[eunox] %s drift=uncovered tool=%q — not covered by manifest; no allowlist entry matches it (denied in enforce mode)`,
			w.severity(), w.Tool,
		)
	case SchemaAbsent:
		return fmt.Sprintf(
			`[eunox] %s drift=schema_absent resource=%q tool=%q argument=%q — tool published no inputSchema, so pinned arguments could not be verified this session (request-time enforcement is unaffected)`,
			w.severity(), w.Resource, w.Tool, w.Argument,
		)
	default:
		// A Kind with no case of its own: still route the level through severity() so an
		// unmapped kind cannot be the one line that hardcodes a level.
		return fmt.Sprintf(`[eunox] %s drift=%s tool=%q resource=%q`, w.severity(), w.Kind, w.Tool, w.Resource)
	}
}

// CheckManifestDrift compares the manifest against the live upstream tool list and
// server version, returning all drift findings (nil when none). serverVersion is
// from the upstream initialize response (empty if unreported). Pure (no I/O).
func CheckManifestDrift(manifest *config.LocalManifest, tools []UpstreamTool, serverVersion string) []Warning {
	if manifest == nil {
		return nil
	}

	var warnings []Warning

	// ── FM-4: server version pin ──────────────────────────────────────────────

	if w := serverVersionDrift(manifest, serverVersion); w != nil {
		warnings = append(warnings, *w)
	}

	// ── Per-tool checks: FM-1, FM-3, FM-5, FM-6, and uncovered ────────────────────
	// Compare each live tool against the constraints the engine could actually select
	// for it — the maximum-specificity tier (coveringConstraints), the set FM-1, FM-3,
	// FM-5, and FM-6 all reason about. coveringConstraints is computed ONCE per tool
	// and shared across the four checks (each previously re-scanned the manifest), and
	// a single dedupe set spans them: a Warning's Kind is part of its identity, so
	// findings of different kinds never collide, while a duplicate probe entry or two
	// variants pinning the same value still report once. Each check's helper documents
	// why it inspects every covering entry rather than a single best pick.
	seen := make(map[Warning]struct{})
	add := func(ws ...Warning) {
		for i := range ws {
			w := ws[i]
			if _, dup := seen[w]; dup {
				continue
			}
			seen[w] = struct{}{}
			warnings = append(warnings, w)
		}
	}
	for _, tool := range tools {
		covering := coveringConstraints(manifest, tool.Name)
		if len(covering) == 0 {
			// Not covered by any tool: entry — denied by default; informational only.
			add(Warning{Kind: Uncovered, Tool: tool.Name})
			continue
		}
		// liveProps drives FM-3/FM-6; actualHash drives FM-5. Each is derived once per
		// tool, not once per covering constraint.
		//
		// A present-but-property-less schema (e.g. {"type":"object"} with no
		// "properties" block) is the STRONGEST pinned-argument-absent case: the upstream
		// dropped its entire declared parameter set, so every pinned argument is now
		// absent. Treat the live parameter set as empty and still run FM-3/FM-6 — only a
		// wholly absent inputSchema (nil) leaves the set genuinely unknown and skips
		// them. NOTE: this skip is NOT fail-closed — the pinned arguments simply go
		// UNVERIFIED this session. The check cannot distinguish a genuinely dropped
		// parameter from a tool that omits its inputSchema block yet still enforces, so
		// it emits no finding rather than a false FM-3. (Request-time enforcement of the
		// pinned arguments is unaffected; only the startup drift signal is absent.) When
		// hasProps is false, liveProps is nil; a nil-map read is safe (every lookup
		// reports not-present), so the empty case needs no separate map, and FM-6 over an
		// empty set correctly emits nothing (a disappeared declared parameter is FM-3,
		// not FM-6).
		liveProps, _ := SchemaProperties(tool.InputSchema)
		// SchemaProperties reports hasProps==true only for a non-nil schema, so
		// "hasProps || InputSchema != nil" reduces to "InputSchema != nil": the schema
		// is known unless it is wholly absent.
		schemaKnown := tool.InputSchema != nil
		actualHash := capability.ComputeToolHash(tool.Description, capability.ToolHashParams(tool.Title, tool.Annotations, tool.InputSchema, tool.OutputSchema))
		for _, c := range covering {
			add(fm1Warnings(tool, c)...)
			add(fm5Warnings(tool, c, actualHash)...)
			if schemaKnown {
				add(fm3Warnings(tool, c, liveProps)...)
				add(fm6Warnings(tool, c, liveProps)...)
			} else {
				// The live tool published no inputSchema, so FM-3/FM-6 were skipped above.
				// Surface an advisory when the constraint actually pins arguments, so the
				// unverified pins are visible rather than silently skipped.
				add(schemaAbsentWarnings(tool, c)...)
			}
		}
	}

	// ── FM-2: each tool: manifest entry must match at least one live tool ─────
	// Non-tool entries (resource:, prompt:, system:) are not verified here —
	// they refer to MCP primitives other than tools/call and have no live
	// counterpart in the tools/list response.
	//
	// Resolve one Kind per distinct absent target BEFORE emitting: the config layer
	// intentionally permits duplicate tool: target values within a manifest (a plain
	// probe entry alongside a descriptionHash-pinned one for the same name), and Kind
	// is part of a Warning's identity, so routing two differently-Kinded findings for
	// the same absent target through the seen-based dedup above would let both survive
	// — one CRITICAL Fm2Pinned and one advisory Fm2 for the same tool, a contradictory
	// verdict for the operator (see buildLiveReport, which files a target into either
	// bucket, never both). A first pass over the covering capabilities decides, per
	// target, whether ANY of them pins it; pinned wins, so the single Warning emitted
	// below always reflects the worse-case verdict for that target regardless of
	// manifest order.
	// targetKind holds the resolved Kind for each distinct absent target, keyed by
	// target name; the same map serves double duty as the order-tracking set: a
	// target's first appearance (comma-ok "not yet present") appends it to
	// absentOrder, and its value tracks the worst-case Kind seen for it so far.
	// Kind's zero value ("") is distinct from both Fm2 and Fm2Pinned, so an
	// explicit Fm2 write for an unpinned entry is never confused with "not yet seen".
	targetKind := make(map[string]Kind)
	var absentOrder []string
	for i := range manifest.Capabilities {
		c := &manifest.Capabilities[i]
		if targetType, _, err := capability.ParseTarget(c.Target); err != nil || targetType != capability.TargetTypeTool {
			continue
		}
		if anyToolMatches(c.Target, tools) {
			continue
		}
		if _, seen := targetKind[c.Target]; !seen {
			absentOrder = append(absentOrder, c.Target)
		}
		// A description-pinned tool absent from the live list never had its hash
		// verified, so escalate to the always-fatal Fm2Pinned variant: otherwise an
		// upstream could hide the pinned tool yet still accept a direct call by name.
		// Pinned always wins and is never downgraded, so one pinned entry for a
		// target outranks any number of unpinned duplicates regardless of scan order.
		if c.IsPinnedExactTool() {
			targetKind[c.Target] = Fm2Pinned
		} else if _, ok := targetKind[c.Target]; !ok {
			targetKind[c.Target] = Fm2
		}
	}
	if len(absentOrder) > 0 {
		// Only compute the session-wide counts when at least one target is absent —
		// every manifest entry matching cleanly (the common case) has no Fm2/Fm2Pinned
		// finding to attach them to, so the counts would go unused.
		liveCount, expectedCount := liveAndExpectedToolCounts(manifest, tools)
		for _, target := range absentOrder {
			add(Warning{
				Kind:              targetKind[target],
				Resource:          target,
				LiveToolCount:     liveCount,
				ExpectedToolCount: expectedCount,
			})
		}
	}

	return warnings
}

// liveAndExpectedToolCounts returns the distinct live tool-name count and the
// distinct manifest exact-tool-name count, the two numbers an Fm2/Fm2Pinned
// LogLine cites so an operator can judge whether a single manifest entry went
// stale or the WHOLE live list came up short (the pattern a truncated
// tools/list response — an empty nextCursor on a non-final page — produces).
// Deliberately simple: unlike the deleted truncation-floor guard this fed, it
// backs a diagnostic message only, not a fatal-abort decision, so it needs no
// per-route caching, no strict/non-strict variant, and no pinned/unpinned
// partitioning — just two counts computed once per CheckManifestDrift call.
func liveAndExpectedToolCounts(manifest *config.LocalManifest, tools []UpstreamTool) (live, expected int) {
	liveNames := make(map[string]struct{}, len(tools))
	for i := range tools {
		liveNames[tools[i].Name] = struct{}{}
	}
	expectedNames := make(map[string]struct{})
	for i := range manifest.Capabilities {
		c := &manifest.Capabilities[i]
		if !c.IsExactTool() {
			continue
		}
		if _, name, err := capability.ParseTarget(c.Target); err == nil {
			expectedNames[name] = struct{}{}
		}
	}
	return len(liveNames), len(expectedNames)
}

// fm1Warnings returns the FM-1 over-permission finding for one (tool, covering
// constraint) pair, or nil. A glob match is a potential silent over-permission
// (exact-name matches are intentional). Inspecting EVERY covering entry — not a
// single best pick — surfaces both of two equal-specificity globs (e.g. tool:read_*
// and tool:*_file both matching read_file), each reachable for some caller. Checks
// the bare name so "tool:read_*" triggers it.
func fm1Warnings(tool UpstreamTool, c *capability.Constraint) []Warning {
	if !capability.ContainsGlobMeta(pdp.StripNamespacePrefix(c.Target)) {
		return nil
	}
	return []Warning{{Kind: Fm1, Tool: tool.Name, Resource: c.Target}}
}

// fm3Warnings returns the FM-3 findings for one (tool, covering constraint) pair:
// each pinned argument name (a condition argument or an argumentSchema property)
// absent from the live inputSchema, so the pin silently stops enforcing if the
// upstream renamed or dropped it. The caller inspects every covering entry, not a
// single best pick, so a drift on either of two equal-specificity variants is
// caught. liveProps is the tool's live "properties" map; it is nil/empty when the
// live schema declares no properties, in which case every pinned argument is reported
// absent (nil-map reads are safe).
func fm3Warnings(tool UpstreamTool, c *capability.Constraint, liveProps map[string]interface{}) []Warning {
	var out []Warning
	for _, argName := range pinnedArgumentNames(c) {
		if _, found := liveProps[argName]; found {
			continue
		}
		out = append(out, Warning{Kind: Fm3, Tool: tool.Name, Resource: c.Target, Argument: argName})
	}
	return out
}

// schemaAbsentWarnings returns a single advisory SchemaAbsent finding for one (tool,
// covering constraint) pair when the constraint pins arguments but the live tool
// published no inputSchema (so FM-3/FM-6 could not run for it), or nil when the
// constraint pins nothing (nothing went unverified, so no advisory). It reports the
// FIRST unverified argument as a representative in Argument; the finding is about the
// wholly-absent schema, not a specific missing parameter, so one per (tool,
// constraint) rather than one per pinned argument.
func schemaAbsentWarnings(tool UpstreamTool, c *capability.Constraint) []Warning {
	pinned := pinnedArgumentNames(c)
	if len(pinned) == 0 {
		return nil
	}
	return []Warning{{Kind: SchemaAbsent, Tool: tool.Name, Resource: c.Target, Argument: pinned[0]}}
}

// fm5Warnings returns the FM-5 description-hash-mismatch finding for one (tool,
// covering constraint) pair, or nil. Only exact-name entries carrying a
// descriptionHash are checked (a glob's hash could be from any tool it expands to,
// and the glob is already FM-1). Inspecting every covering entry — not a single
// best pick — verifies both of two equal-specificity pins, each enforced for some
// caller; skipping the second would be a fail-open for the tool-poisoning defense.
func fm5Warnings(tool UpstreamTool, c *capability.Constraint, actualHash string) []Warning {
	if !c.IsPinnedExactTool() || actualHash == c.DescriptionHash {
		return nil
	}
	return []Warning{{
		Kind:         Fm5,
		Tool:         tool.Name,
		Resource:     c.Target,
		HashExpected: c.DescriptionHash,
		HashActual:   actualHash,
	}}
}

// fm6Warnings returns the FM-6 structural-drift findings for one (tool, covering
// constraint) pair. A constraint's argumentSchema declares the parameter surface
// the operator reviewed; FM-6 covers the two divergences FM-3 does not — a
// parameter that APPEARS under a closed schema (additionalProperties:false — the
// schema asserted these were all the args, so a new one is a silent new sink), and
// a declared parameter whose TYPE changed (the constraint may now match or reject
// the wrong shape). Exact tools only (like FM-5): a glob's single argumentSchema
// cannot be a closed enumeration of every matched tool's parameters, so the
// added-parameter check against it produces systematic false positives — fatal
// under --strict-drift; the glob is already surfaced by FM-1. liveProps is the
// tool's live "properties" map; it is nil/empty when the live schema declares no
// properties (FM-6 then emits nothing — a disappeared declared parameter is FM-3).
func fm6Warnings(tool UpstreamTool, c *capability.Constraint, liveProps map[string]interface{}) []Warning {
	if c.ArgumentSchema == nil || !c.IsExactTool() {
		return nil
	}
	return structuralDrift(tool.Name, c, liveProps)
}

// structuralDrift returns the FM-6 findings for one tool/constraint pair: live
// parameters not declared by a closed argumentSchema, and declared parameters
// whose live type changed. liveProps is the tool's live inputSchema "properties"
// map. The disappearance of a declared parameter is deliberately NOT reported here
// — that is FM-3.
func structuralDrift(toolName string, c *capability.Constraint, liveProps map[string]interface{}) []Warning {
	// Arguments a condition names count as reviewed even when a closed argumentSchema
	// does not list them, mirroring FM-3's pinnedArgumentNames so the two checks
	// agree on what the operator pinned. conditionArgumentNames already returns
	// top-level root keys (the granularity the proxy resolves a condition argument
	// at), so the exclusion applies at the top level only.
	reviewed := make(map[string]bool)
	for _, name := range conditionArgumentNames(c.Conditions) {
		reviewed[name] = true
	}

	var warnings []Warning
	collectStructuralDrift(toolName, c.Target, c.ArgumentSchema, liveProps, "", reviewed, &warnings)

	// Deterministic order so dedupe and output are stable across map iteration.
	sort.Slice(warnings, func(i, j int) bool {
		if warnings[i].Argument != warnings[j].Argument {
			return warnings[i].Argument < warnings[j].Argument
		}
		return warnings[i].Detail < warnings[j].Detail
	})
	return warnings
}

// collectStructuralDrift walks a declared argumentSchema against the live
// inputSchema properties at one nesting level and recurses into declared object
// properties, so a nested closed schema or a nested type change is checked too.
// prefix is the dotted argument path to this level ("" at the top); reviewed holds
// top-level argument names a condition references (applied only at the top level,
// where the proxy can resolve a condition argument).
func collectStructuralDrift(toolName, target string, schema *capability.ArgumentSchema, liveProps map[string]interface{}, prefix string, reviewed map[string]bool, out *[]Warning) {
	if schema == nil {
		return
	}

	// Added parameter under a closed schema: additionalProperties:false asserts the
	// declared set is exhaustive, so a live parameter outside it is a new, ungated
	// surface the operator did not review. A top-level argument a condition names is
	// already reviewed and is skipped.
	if schema.AdditionalProperties != nil && !*schema.AdditionalProperties {
		for liveName := range liveProps {
			if _, declared := schema.Properties[liveName]; declared {
				continue
			}
			if prefix == "" && reviewed[liveName] {
				continue
			}
			*out = append(*out, Warning{
				Kind:     Fm6,
				Tool:     toolName,
				Resource: target,
				Argument: joinArgPath(prefix, liveName),
				Detail:   "live parameter is not declared by the closed argumentSchema (additionalProperties:false) — a new, unreviewed tool argument",
			})
		}
	}

	for declName, declSchema := range schema.Properties {
		if declSchema == nil {
			continue
		}
		liveProp, present := liveProps[declName]
		if !present {
			continue // disappearance is FM-3
		}
		full := joinArgPath(prefix, declName)

		// Type change on a declared parameter: only flagged when both the manifest
		// and the live schema name a single concrete type and the change is not
		// type-compatible. Unions/nullable types and absent types are left alone to
		// avoid false positives.
		if want, ok := singleConcreteType(declSchema.Type); ok {
			if got, ok := liveSingleType(liveProp); ok && !typesCompatible(want, got) {
				*out = append(*out, Warning{
					Kind:     Fm6,
					Tool:     toolName,
					Resource: target,
					Argument: full,
					Detail:   fmt.Sprintf("declared parameter type %q no longer matches the live type %q", want, got),
				})
			}
		}

		// Recurse into a declared object parameter so a nested closed schema or a
		// nested type change is checked at the next level.
		if len(declSchema.Properties) > 0 || (declSchema.AdditionalProperties != nil && !*declSchema.AdditionalProperties) {
			if nested, ok := liveObjectProperties(liveProp); ok {
				collectStructuralDrift(toolName, target, declSchema, nested, full, reviewed, out)
			}
		}
	}
}

// joinArgPath builds the dotted argument path to a nested parameter ("" prefix →
// the bare name; "options" + "mode" → "options.mode").
func joinArgPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// singleConcreteType returns a SchemaType's lone concrete type, or ("", false)
// when it names none or a union (which FM-6 does not compare).
func singleConcreteType(t capability.SchemaType) (string, bool) {
	if len(t.Multiple) > 0 || t.Single == "" {
		return "", false
	}
	return t.Single, true
}

// liveSingleType returns a live inputSchema property's lone concrete "type", or
// ("", false) when it is absent or a union (an array of types).
func liveSingleType(prop interface{}) (string, bool) {
	pm, ok := prop.(map[string]interface{})
	if !ok {
		return "", false
	}
	if s, ok := pm["type"].(string); ok && s != "" {
		return s, true
	}
	return "", false
}

// liveObjectProperties returns the "properties" map of a live inputSchema object
// property, or (nil, false) when the property is not an object schema declaring
// properties (so there is nothing nested to compare).
func liveObjectProperties(prop interface{}) (map[string]interface{}, bool) {
	pm, ok := prop.(map[string]interface{})
	if !ok {
		return nil, false
	}
	props, ok := pm["properties"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	return props, true
}

// typesCompatible reports whether a live JSON-Schema type is policy-compatible
// with the declared type, so a benign change is not flagged as FM-6 drift. Equal
// types are compatible; integer and number are mutually compatible because an
// integer value validates against a number schema and neither direction widens
// what the manifest's argumentSchema accepts in a policy-relevant way — flagging
// it would be exactly the false-positive that trains operators to disable the pin.
func typesCompatible(want, got string) bool {
	if want == got {
		return true
	}
	numeric := map[string]bool{"number": true, "integer": true}
	return numeric[want] && numeric[got]
}

// hasFatalDrift reports whether warnings contains any finding that should
// abort session establishment under --strict-drift.
func hasFatalDrift(warnings []Warning) bool {
	for i := range warnings {
		w := &warnings[i]
		if w.IsFatal() {
			return true
		}
	}
	return false
}

// hasCriticalDrift reports whether warnings contains an FM-5 or Fm2Pinned finding.
// Both abort startup unconditionally (not gated by --strict-drift): a mismatched
// or unverifiable description may carry steering instructions injected into the
// tool description the model sees.
func hasCriticalDrift(warnings []Warning) bool {
	for i := range warnings {
		w := &warnings[i]
		if w.Kind == Fm5 || w.Kind == Fm2Pinned {
			return true
		}
	}
	return false
}

// manifestHasPinnedDescriptions reports whether any exact-name tool: constraint
// in the manifest carries a non-empty descriptionHash. When true, a tools/list
// fetch failure at startup must be treated as fatal: without the live tool list
// there is no way to verify the pinned hashes, so fail-closed requires an abort.
func manifestHasPinnedDescriptions(manifest *config.LocalManifest) bool {
	for i := range manifest.Capabilities {
		if manifest.Capabilities[i].IsPinnedExactTool() {
			return true
		}
	}
	return false
}

// evaluateDrift runs CheckManifestDrift against the fetched tool list, emits all
// findings to stderr, and returns a non-nil error when any finding requires
// aborting startup: FM-5 and Fm2Pinned (unconditionally, via hasCriticalDrift) or
// FM-1/2/4/6 (only when strict, via IsFatal).
func evaluateDrift(manifest *config.LocalManifest, tools []UpstreamTool, serverVersion string, strict bool) error {
	warnings := CheckManifestDrift(manifest, tools, serverVersion)
	emitDriftWarnings(warnings)
	if hasCriticalDrift(warnings) {
		return fmt.Errorf("startup aborted: description integrity check failed — a pinned description mismatched or a description-pinned tool is missing from the live tool list (see warnings above)")
	}
	if strict && hasFatalDrift(warnings) {
		// "strict drift", not "--strict-drift": strictness can come from the flag OR
		// from `strictDrift:` in a gateway config (per route or under defaults), and an
		// operator who set it in YAML should not be sent looking for a flag they never
		// passed.
		return fmt.Errorf("startup aborted by strict drift checking: manifest drift detected (see warnings above)")
	}
	return nil
}

// emitDriftWarnings writes each finding's log line to stderr.
func emitDriftWarnings(warnings []Warning) {
	for i := range warnings {
		fmt.Fprintln(os.Stderr, warnings[i].LogLine())
	}
}

// anyToolMatches reports whether any tool name in tools matches resource.
func anyToolMatches(resource string, tools []UpstreamTool) bool {
	for _, t := range tools {
		if matchResource(resource, t.Name) {
			return true
		}
	}
	return false
}

// BestManifestConstraint returns the highest-specificity tool: constraint whose
// pattern matches toolName, or nil if none. Only tool: entries are considered.
// Exported for the validate --live COVERED report, which needs the covering
// constraint for a clean tool (CheckManifestDrift surfaces no warning for one).
func BestManifestConstraint(manifest *config.LocalManifest, toolName string) *capability.Constraint {
	// coveringConstraints returns every REACHABLE match, which since the principal-scope
	// fix can span more than one specificity tier — so narrow to the top tier here
	// rather than assuming the caller did it. Prefer a descriptionHash-pinned member on
	// a tie purely for what the REPORT displays: the sole caller is validate --live's
	// COVERED line, which uses the result only for its Target string, and naming the
	// pinned entry is the more informative answer when several equally-specific
	// constraints cover the tool. Nothing enforcement-relevant rides on this pick —
	// CheckManifestDrift runs the FM-5 hash verification for EVERY covering constraint,
	// not just the one chosen here, so a pin cannot be skipped by tie-breaking the other
	// way.
	covering := coveringConstraints(manifest, toolName)
	if len(covering) == 0 {
		return nil
	}
	// Seeded from the first candidate rather than a sentinel, so `top` is non-empty for
	// ANY scoring resSpecificity could return. A sentinel seed made the non-empty
	// precondition of the top[0] below depend on every future score staying above it —
	// an unguarded index resting on a property nothing states.
	top := []*capability.Constraint{covering[0]}
	best := resSpecificity(covering[0].Target, toolName)
	for _, c := range covering[1:] {
		switch s := resSpecificity(c.Target, toolName); {
		case s > best:
			best = s
			top = append(top[:0], c)
		case s == best:
			top = append(top, c)
		}
	}
	for _, c := range top {
		if c.IsPinnedExactTool() {
			return c
		}
	}
	return top[0]
}

// coveringConstraints returns every tool: constraint matching toolName that some
// caller can actually be governed by — the set whose drift must be checked. FM-3 uses
// it (rather than a single best pick) so a pinned-argument drift on any reachable
// variant is caught, and FM-1/FM-2/FM-6 are fatal under strict drift, so a reachable
// entry left out of this set is a strict deployment believing it verified drift it did
// not. Returns nil when nothing matches.
//
// Reachability is NOT "maximum specificity", because the engine filters by principal
// BEFORE it scores (FindMatchingCapability skips a principal-scoped constraint whose
// claims do not match, exactly like a target mismatch). A more-specific entry
// therefore shadows a less-specific one only when it applies to every caller — that
// is, only when it is UNSCOPED. Given
//
//	tool:read_file  {principal: {sub: [alice]}}   (exact, scoped)
//	tool:read_*                                   (glob, unscoped)
//
// every caller who is not alice is governed by the glob, yet a maximum-specificity
// rule sees only the exact entry and never runs the glob's checks.
//
// So the cutoff is the highest specificity among the UNSCOPED matches: anything below
// it is shadowed for every caller and genuinely unreachable, and everything at or
// above it is reachable for some caller. With no unscoped match at all nothing
// universally shadows anything, so every match is kept. Over-inclusion here costs at
// most an extra warning about an entry that turns out to be unreachable; under-
// inclusion silently skips a fatal check.
func coveringConstraints(manifest *config.LocalManifest, toolName string) []*capability.Constraint {
	type match struct {
		c     *capability.Constraint
		score int
	}
	var matches []match
	// Sentinel below every real specificity score, so "no unscoped match" keeps
	// everything rather than filtering against an unset cutoff.
	cutoff := -(1 << 30)
	for i := range manifest.Capabilities {
		c := &manifest.Capabilities[i]
		if targetType, _, err := capability.ParseTarget(c.Target); err != nil || targetType != capability.TargetTypeTool {
			continue
		}
		if !matchResource(c.Target, toolName) {
			continue
		}
		s := resSpecificity(c.Target, toolName)
		matches = append(matches, match{c: c, score: s})
		if !c.HasPrincipal() && s > cutoff {
			cutoff = s
		}
	}
	var out []*capability.Constraint
	for _, m := range matches {
		if m.score >= cutoff {
			out = append(out, m.c)
		}
	}
	return out
}

// SchemaProperties extracts the "properties" map from a JSON Schema. The second
// return is true when the schema declares a "properties" object (even empty),
// meaning the parameter set is known and a pinned argument can be verified against
// it; false when "properties" is missing or not an object (set unknown). Exported so
// the CLI's manifest scaffolder (init) shares this one definition rather than keeping
// a package-main copy that can drift.
func SchemaProperties(schema map[string]interface{}) (map[string]interface{}, bool) {
	if schema == nil {
		return nil, false
	}
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	return props, true
}

// pinnedArgumentNames returns every argument name a manifest entry pins to a
// specific upstream parameter: the argument of each condition plus every
// top-level property (and required name) declared in an argumentSchema. The
// result is deduplicated and order-stable so FM-3 reports are deterministic.
func pinnedArgumentNames(c *capability.Constraint) []string {
	seen := make(map[string]bool)
	var names []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, n := range conditionArgumentNames(c.Conditions) {
		add(n)
	}
	if c.ArgumentSchema != nil {
		for argName := range c.ArgumentSchema.Properties {
			add(argName)
		}
		for _, req := range c.ArgumentSchema.Required {
			add(req)
		}
	}
	// Property map iteration is unordered; sort for deterministic FM-3 output.
	sort.Strings(names)
	return names
}

// conditionArgumentNames returns the explicit argument field values from all
// conditions in the list.  Empty argument fields are omitted.  Duplicates are
// deduplicated.
func conditionArgumentNames(conditions []capability.Condition) []string {
	var names []string
	seen := make(map[string]bool)
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	// Enumerate via the capability.ArgumentNamer interface, not a closed type
	// switch: every argument-carrying condition implements it (value receiver, so
	// both forms satisfy), so a future argument-pinning condition is picked up
	// automatically, closing the silent-FM-3-bypass trap a hand-maintained switch
	// had. A condition naming no argument does not implement it and is skipped.
	for _, cond := range conditions {
		if n, ok := cond.(capability.ArgumentNamer); ok {
			add(capability.ArgumentRootKey(n.ArgumentName()))
		}
	}
	return names
}

// ─── tools/list fetch helpers ─────────────────────────────────────────────────

// Pagination bounds for the startup tools/list probe. MCP list responses are
// paginated via nextCursor; the drift probe follows the cursor to exhaustion so
// manifest entries, description pins, and reports cover every page, not just page
// one. The bounds defend against a malicious upstream that paginates forever or
// returns an unbounded catalog.
const (
	maxToolsListPages = 1000
	maxToolsListTools = 100000
	// maxToolsListBytes bounds the total size of accumulated raw tool pages. The
	// page and tool-count ceilings above still permit up to 1000 pages at the 4
	// MiB per-message limit already enforced by the transport (jsonrpc.go), i.e.
	// close to 4 GiB retained in memory during a single startup probe; 64 MiB is
	// generous for any real-world tool catalog while keeping that worst case bounded.
	maxToolsListBytes = 64 << 20
)

// toolsListPage is one page of a tools/list result: the tools array plus the
// optional nextCursor used to request the following page.
type toolsListPage struct {
	Tools      []json.RawMessage `json:"tools"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

// toolsListCursorParams builds the params for one paginated tools/list request: the
// first page (empty cursor) carries no params; subsequent pages carry
// {"cursor":"..."} per the MCP pagination model.
//
// Unexported: ToolsListRequest is the seam every probe uses (both transport drift
// probes and the CLI live-upstream probes), and it builds the WHOLE request, so a
// caller assembling a bare params blob would be bypassing the id/method half of the
// single-sourcing rather than participating in it.
func toolsListCursorParams(cursor string) json.RawMessage {
	if cursor == "" {
		return nil
	}
	// json.Marshal of a map[string]string cannot fail for a plain string value.
	raw, _ := json.Marshal(map[string]string{"cursor": cursor})
	return raw
}

// ToolsListRequest builds a complete JSON-RPC tools/list request for one pagination
// page: the given JSON-RPC id plus the cursor params. Single-sourced here so every
// drift/CLI probe (the two transport session-start probes and the two CLI
// live-upstream probes) issues an identical request, differing only in the id,
// instead of hand-building the same literal at four sites.
func ToolsListRequest(id *json.RawMessage, cursor string) mcp.RPCMsg {
	return mcp.RPCMsg{JSONRPC: "2.0", ID: id, Method: capability.MethodToolsList, Params: toolsListCursorParams(cursor)}
}

// FetchAllToolPages drives tools/list pagination to exhaustion and returns a
// single merged {"tools":[...]} result, dropping the cursor. fetchPage sends one
// request with the given cursor ("" for the first page). Page/tool counts and
// total accumulated bytes are bounded and a repeated cursor is rejected so a
// malicious upstream cannot induce infinite pagination or unbounded memory
// retention. Shared by the HTTP, stdio, and CLI paths.
func FetchAllToolPages(fetchPage func(cursor string) (json.RawMessage, error)) (json.RawMessage, error) {
	var all []json.RawMessage
	seen := make(map[string]bool)
	cursor := ""
	totalBytes := 0
	for page := 0; page < maxToolsListPages; page++ {
		raw, err := fetchPage(cursor)
		if err != nil {
			return nil, err
		}
		// Check the raw page against the remaining byte budget BEFORE unmarshaling,
		// so a single oversized page from a malicious upstream cannot force an
		// unbounded allocation while being decoded.
		if len(raw) > maxToolsListBytes-totalBytes {
			return nil, fmt.Errorf("tools/list accumulated more than %d bytes; refusing to page further", maxToolsListBytes)
		}
		totalBytes += len(raw)
		var p toolsListPage
		if len(raw) > 0 {
			// Reject an envelope whose top-level "tools" key is ambiguous (duplicated,
			// case-variant, or shadowed by a case-variant sibling) BEFORE the plain
			// json.Unmarshal below, which would silently resolve it to one array with no
			// error. Without this, a poisoned catalog could pass the drift comparison
			// (and its unconditionally-fatal FM-5 descriptionHash check) cleanly at
			// startup, only to be caught later — and more disruptively, as a mid-session
			// poisonAllPinned — once the runtime list filter (which already refuses this
			// same shape) saw the identical bytes.
			if pdp.ToolsKeyAmbiguous(raw) {
				return nil, fmt.Errorf("tools/list page carries an ambiguous \"tools\" key (duplicated, case-variant, or both); refusing to trust the decode")
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, fmt.Errorf("parsing tools/list page: %w", err)
			}
		}
		// Bound the cumulative tool count across pages before appending, so a long tail
		// of pages cannot grow "all" past maxToolsListTools. (This page's own size is
		// already bounded by the maxToolsListBytes check above, before the Unmarshal that
		// materializes p.Tools.)
		if len(p.Tools) > maxToolsListTools-len(all) {
			return nil, fmt.Errorf("tools/list returned more than %d tools; refusing to page further", maxToolsListTools)
		}
		all = append(all, p.Tools...)
		if p.NextCursor == "" {
			return json.Marshal(toolsListPage{Tools: all})
		}
		if seen[p.NextCursor] {
			return nil, fmt.Errorf("tools/list pagination repeated cursor %q; refusing possible infinite pagination", p.NextCursor)
		}
		seen[p.NextCursor] = true
		cursor = p.NextCursor
	}
	return nil, fmt.Errorf("tools/list exceeded %d pages; refusing to page further", maxToolsListPages)
}

// ParseToolsListResult decodes the raw JSON result from a tools/list response.
//
// It screens the envelope and every entry itself rather than assuming a screened
// caller. Every in-tree caller today feeds it the merged output of FetchAllToolPages,
// which already rejected an ambiguous envelope per page and then re-marshaled the
// result — so for those callers the envelope gate below can never fire. It is kept
// anyway, and the tradeoff was made deliberately rather than by omission: this is an
// exported function documented as taking "the raw JSON result from a tools/list
// response", so the precondition a caller would have to satisfy is invisible at the
// call site, and getting it wrong reopens a catalog-substitution bypass rather than
// producing an obvious failure. A guard whose absence is silent belongs on the
// boundary, not in a comment telling future callers to pre-screen.
//
// The guard's cost is accepted rather than offset. Folding the entry screen and the
// decode into one per-entry pass was tried and measured slower (encoding/json validates
// before it decodes, so per-entry decodes re-scan the same bytes and add a decoder setup
// and a heap-escaping value each), so the straightforward shape below stands.
func ParseToolsListResult(raw json.RawMessage) ([]UpstreamTool, error) {
	if raw == nil {
		return nil, nil
	}
	// The ENVELOPE is screened before it is decoded, for the reason given at the function:
	// raw bytes carrying a case-variant "Tools" or a duplicated "tools" decode silently to
	// ONE array here — Go binds by a case-folding match and keeps the last — which is the
	// same catalog-substitution bypass ToolsKeyAmbiguous was exported to close on the
	// runtime list path. The per-entry gate is applied below, on each entry's own bytes.
	//
	// Surfacing either as a parse error routes it through driftProbeUnavailable, which is
	// exactly the right policy: fatal when the manifest carries descriptionHash pins
	// (integrity cannot be verified), an observable skip otherwise.
	//
	// ToolsKeyAmbiguous also reports true on bytes it cannot even walk (truncated JSON, a
	// non-object top level) — deliberately: this gate must fail closed on uncertainty, not
	// just on a confirmed duplicate. The message below is worded to match that: it says the
	// key "could not be verified", not "is ambiguous", so a truncated upstream response is
	// not misreported to an operator as a duplicate-key attack when it is a transport fault.
	if pdp.ToolsKeyAmbiguous(raw) {
		return nil, fmt.Errorf("tools/list result's \"tools\" key could not be verified as unambiguous (malformed JSON, or a duplicated/case-variant key); refusing to trust the decode")
	}
	var envelope struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("parsing tools/list result: %w", err)
	}
	// Reject an entry whose bytes are ambiguous BEFORE decoding them into the struct the
	// descriptionHash is computed over. A plain Unmarshal binds object keys to fields by a
	// case-folding match and keeps the LAST, so an upstream serving both "description" and
	// "deſcription" (U+017F — already lower case, so a ToLower-based check misses it)
	// hashes CLEAN against the pin while a case-sensitive host renders the injected value:
	// the FM-5 startup refusal this whole comparison exists to trigger never fires. The
	// runtime list filter applies the same gate per entry; sharing pdp.EntryKeysAmbiguous
	// keeps the two layers from drifting apart on what "believable" means.
	for i, entry := range envelope.Tools {
		if pdp.EntryKeysAmbiguous(entry) {
			return nil, fmt.Errorf("tools/list entry %d carries duplicate or case-variant keys, so its description cannot be verified against a descriptionHash pin", i)
		}
	}

	// One whole-envelope decode, NOT a per-entry json.Unmarshal over the RawMessages the
	// screen above already holds. That rewrite looks like it removes a redundant pass and
	// measurably does not: encoding/json validates before it decodes, so N per-entry
	// decodes re-scan the same total byte volume the bulk decode would have, and add N
	// decoder setups plus a heap-escaping ToolEntry each. Benchmarked on a 50-tool catalog
	// it cost ~380 more allocations and ~10 KB more per call for no time saving. The
	// envelope gate above is therefore paid for honestly rather than offset.
	var result mcp.ToolsListResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parsing tools/list result: %w", err)
	}
	tools := make([]UpstreamTool, len(result.Tools))
	for i, t := range result.Tools {
		// Field by field, by NAME, rather than a positional UpstreamTool(t) struct
		// conversion. The two types share three string fields and two
		// map[string]interface{} fields, so a same-type reorder in mcp.ToolEntry would
		// still compile as a conversion while silently transposing values into the wrong
		// fields — and every FM-5 descriptionHash comparison is computed over exactly
		// these fields. Named assignment makes that mapping compiler-checked.
		tools[i] = UpstreamTool{
			Name:         t.Name,
			Description:  t.Description,
			InputSchema:  t.InputSchema,
			Title:        t.Title,
			Annotations:  t.Annotations,
			OutputSchema: t.OutputSchema,
		}
	}
	return tools, nil
}

// MakeDriftCheck builds the drift-comparison hook for a route/proxy, or nil when
// manifest is nil. The returned CheckFunc parses the probed tools/list and runs
// evaluateDrift; a probe or parse failure is handled by driftProbeUnavailable.
//
// A truncated tools/list (an upstream ending pagination early — an empty nextCursor
// on a non-final page) is NOT special-cased here: a manifest exact tool: entry hidden
// by truncation is absent from the live list exactly like a removed/renamed one, so it
// surfaces through the normal FM-2 path below — Fm2Pinned (unconditionally fatal) when
// the entry is descriptionHash-pinned, or Fm2 (fatal only under --strict-drift)
// otherwise — with the LogLine text naming truncated pagination as a possible cause.
func MakeDriftCheck(manifest *config.LocalManifest, strict bool) CheckFunc {
	if manifest == nil {
		return nil
	}
	return func(rawToolsListResult json.RawMessage, serverVersion string, probeErr error) error {
		if probeErr != nil {
			// serverVersion comes from the completed initialize handshake, not the
			// tools/list probe, so the FM-4 pin can still be verified even when the probe
			// failed. Surface it explicitly — otherwise a manifest that pins only
			// serverVersion would have its one pin silently unverified whenever the probe
			// fails, and the generic drift=skipped warning would not mention the version.
			emitServerVersionDrift(manifest, serverVersion)
			return driftProbeUnavailable(manifest, strict, probeErr)
		}
		tools, err := ParseToolsListResult(rawToolsListResult)
		if err != nil {
			// A parse failure loses the live tool list just like a probe failure, but
			// serverVersion still comes from the completed initialize handshake and is
			// verifiable — so run the same FM-4 emit here rather than let the one pin on a
			// serverVersion-only manifest go silently unchecked.
			emitServerVersionDrift(manifest, serverVersion)
			return driftProbeUnavailable(manifest, strict, err)
		}
		return evaluateDrift(manifest, tools, serverVersion, strict)
	}
}

// driftProbeUnavailable maps a tools/list probe (or parse) failure to
// fatal-or-skip. It is fatal when the manifest has descriptionHash pins (they
// cannot be verified without the live list) or strict is set (an unreachable probe
// is indistinguishable from drift). Otherwise it is a logged best-effort skip.
func driftProbeUnavailable(manifest *config.LocalManifest, strict bool, err error) error {
	if manifestHasPinnedDescriptions(manifest) {
		return fmt.Errorf("tools/list unavailable and manifest has descriptionHash pins: cannot verify description integrity: %w", err)
	}
	if strict {
		// Names the mode, not the flag: strictDrift: in a gateway config sets it too.
		return fmt.Errorf("tools/list unavailable under strict drift checking: cannot verify manifest drift; an unreachable probe is indistinguishable from drift: %w", err)
	}
	// Glob-only manifest, non-strict: the skip stays non-blocking, but make it
	// OBSERVABLE so an operator never mistakes "probe skipped, drift unknown" for
	// "probe succeeded, no drift detected". Structured (drift=skipped) and explicit
	// that NO drift was verified this session — a glob entry may now cover upstream
	// tools added since the manifest was written, and any FM-1..FM-6 finding would go
	// undetected — naming the probe-failure reason.
	fmt.Fprintf(os.Stderr,
		"[eunox] WARN drift=skipped tools/list unavailable — manifest drift was NOT verified this session; glob entries may now cover upstream tools added since the manifest was written and any drift would go undetected: %v\n",
		err)
	return nil
}

// serverVersionDrift returns the FM-4 warning when the live serverVersion does not
// satisfy the manifest's serverVersion pin, or nil when there is no pin or it is
// satisfied. Split out so the pin can be checked both on the normal path
// (CheckManifestDrift) and on the probe-failure path (MakeDriftCheck): serverVersion
// comes from the initialize handshake, so a failed tools/list probe does not prevent
// FM-4 verification.
func serverVersionDrift(manifest *config.LocalManifest, serverVersion string) *Warning {
	if manifest.ServerVersion == "" || matchServerVersion(manifest.ServerVersion, serverVersion) {
		return nil
	}
	return &Warning{
		Kind:          Fm4,
		Resource:      manifest.ServerVersion,
		VersionActual: serverVersion,
	}
}

// emitServerVersionDrift logs the FM-4 warning to stderr when the live serverVersion
// violates the manifest pin. Shared by both MakeDriftCheck probe-unavailable branches
// (probe error and tools/list parse failure): serverVersion comes from the completed
// initialize handshake, so it stays verifiable even when the live tool list is lost.
func emitServerVersionDrift(manifest *config.LocalManifest, serverVersion string) {
	if w := serverVersionDrift(manifest, serverVersion); w != nil {
		fmt.Fprintln(os.Stderr, w.LogLine())
	}
}

// matchServerVersion reports whether actual satisfies constraint.
// constraint is a dot-separated version string where any component may be "*"
// to wildcard that position and everything beyond it:
//
//	"1.2.3"  — exact match
//	"1.2.*"  — major 1, minor 2, any patch
//	"1.*"    — major 1, any minor and patch
//	"*"      — any version
//
// An empty constraint always matches (no pinning configured).
func matchServerVersion(constraint, actual string) bool {
	if constraint == "" {
		return true
	}
	// An absent version never satisfies a non-empty constraint, even "*". FM-4 exists
	// to surface an upstream that reports no version at all, and "*" is the natural
	// "don't care" value operators reach for — but strings.Split("", ".") returns
	// [""] (len 1, NOT an empty slice), so without this guard a trailing-"*" constraint
	// would see one (empty) component and match, silently swallowing the FM-4 warning.
	if actual == "" {
		return false
	}
	cParts := strings.Split(constraint, ".")
	aParts := strings.Split(actual, ".")
	for i, c := range cParts {
		if c == "*" {
			// A TRAILING "*" matches this component and everything after it; a
			// NON-trailing "*" matches only its own component and comparison
			// continues. (Short-circuiting on any "*" would let "*.0" or "1.*.3"
			// match every version, defeating the FM-4 guard.)
			if i == len(cParts)-1 {
				// "any value AT this position and beyond" still requires the actual
				// version to HAVE a component here, so "1.2.*" does not match a bare
				// "1.2".
				return i < len(aParts)
			}
			if i >= len(aParts) {
				return false // constraint pins a component the actual version lacks
			}
			continue
		}
		if i >= len(aParts) || aParts[i] != c {
			return false
		}
	}
	// All constraint parts matched; actual must have the same number of parts
	// so that "1.2.3" does not match "1.2.3.4".
	return len(aParts) == len(cParts)
}
