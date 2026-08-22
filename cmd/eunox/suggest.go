// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The `suggest` subcommand (cmdSuggest) and the draft-manifest generator behind it.
// Where `init` scaffolds a deny-all from a live tool list, `suggest` reads the local audit
// tape — what the agent actually did — and mines observed argument values into
// `allowedValues` conditions. The output is a draft, not vetted policy: the sensitive
// sampling opt-in is always commented out, and the manifest carries a REVIEW banner.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// suggestMaxValuesDefault bounds how many distinct observed values an argument may have
// before `suggest` proposes a concrete allowedValues condition; beyond it the argument is
// surfaced as a review comment instead.
const suggestMaxValuesDefault = 20

// resolveMaxValues normalizes a --max-values flag value: non-positive means "use the
// default", not "zero values allowed". Shared by computeSuggestions and
// renderSuggestedManifest so the collection cap and the render-time cutoff cannot diverge.
func resolveMaxValues(maxValues int) int {
	if maxValues <= 0 {
		return suggestMaxValuesDefault
	}
	return maxValues
}

// observedArg accumulates the distinct string values seen for one tool argument.
// Non-string values can't form a useful allowedValues set, so they are tracked
// only via nonString. calls counts how many allowed calls carried this argument,
// so render can distinguish an always-present argument (safe to constrain) from
// an optional one — constraining the latter would deny the calls that omitted it.
type observedArg struct {
	values    map[string]struct{}
	nonString bool
	calls     int
	// truncated: at least one call carried this argument with a per-value-truncation
	// placeholder, so its full value set is unknowable — leave it unconstrained.
	truncated bool
	// overflowed: the distinct-value set exceeded maxValues+1 and was cleared, stopping a
	// high-cardinality argument (request IDs, paths) from growing without bound.
	overflowed bool
}

// observedTarget accumulates everything the tape reveals about one enforcement
// target (a tool, resource, prompt, or the sampling system primitive).
type observedTarget struct {
	namespace string // "tool" | "resource" | "prompt" | "system"
	name      string // bare name: tool name, resource URI, prompt name, or "sampling/createMessage"
	allow     int
	deny      int
	// escalate counts calls the effect ceiling refused pending human approval — tracked
	// apart from deny since the remediation differs, but it is still a refusal.
	escalate int
	// nonTruncatedAllow counts allowed calls whose detail map was NOT replaced wholesale by
	// the truncation marker — the correct denominator for the "argument is optional" check,
	// since counting whole-map-truncated calls would mislabel an always-present argument.
	nonTruncatedAllow int
	args              map[string]*observedArg
	// wholeTruncated: at least one call's details were replaced wholesale by the audit
	// truncation marker; render surfaces a tool-level note instead of a phantom argument.
	wholeTruncated bool
}

// suggestionSet is the aggregated, transport-agnostic view of the tape that
// renderSuggestedManifest turns into YAML. It is produced by computeSuggestions
// and is deliberately free of any I/O so it can be unit-tested directly.
type suggestionSet struct {
	targets  map[string]*observedTarget // keyed by "<namespace>:<name>"
	records  int
	allow    int
	deny     int
	escalate int
	// unknownDecision counts mined records carrying a decision this build does not model;
	// without it the banner's breakdown silently fails to add up to the printed total.
	unknownDecision int
	sessions        map[string]struct{}
}

// resolveTarget determines an audit record's enforcement namespace and bare
// target name from the structured target_type/target fields. Returns ("", "")
// when the record carries no recognized enforcement target (e.g. a pre-dispatch
// JWT rejection or unmapped-method denial).
func resolveTarget(targetType, target string) (namespace, bare string) {
	if capability.IsTargetType(targetType) && target != "" {
		return targetType, target
	}
	return "", ""
}

// computeSuggestions scans an audit JSONL stream and aggregates per-target observations.
// Malformed and blank lines are SKIPPED (unlike computeAuditStats, which counts them in
// "other") since a line it cannot decode names no target to propose anything about.
// maxValues must match the value later passed to renderSuggestedManifest.
func computeSuggestions(r io.Reader, maxValues int) (suggestionSet, error) {
	maxValues = resolveMaxValues(maxValues)
	out := suggestionSet{
		targets:  make(map[string]*observedTarget),
		sessions: make(map[string]struct{}),
	}
	scanner := audit.NewLineScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec struct {
			TargetType string          `json:"target_type"`
			Target     string          `json:"target"`
			Method     string          `json:"method"`
			Decision   string          `json:"decision"`
			DenialCode string          `json:"denial_code"`
			SessionID  string          `json:"session_id"`
			AuditOnly  bool            `json:"audit_only"`
			Details    json.RawMessage `json:"details"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		// details is decoded separately, as raw JSON first: a schema-drifted tape may
		// carry a scalar/array there, and decoding it on the outer struct would fail the
		// WHOLE record and discard an otherwise-parseable target/decision/method.
		var details map[string]interface{}
		if len(bytes.TrimSpace(rec.Details)) > 0 {
			_ = json.Unmarshal(rec.Details, &details) // non-object details: leave nil, still count target/decision
		}
		// Skip */list enumeration records: governed by automatic list filtering, not a
		// capability grant, so mining one would emit a phantom target.
		if capability.ListResultKey(rec.Method) != "" {
			continue
		}
		// Skip upstream-failure denials: transport noise, not policy signals.
		if rec.Decision == "deny" && transport.IsInfraDenialCode(rec.DenialCode) {
			continue
		}
		ns, bare := resolveTarget(rec.TargetType, rec.Target)
		if bare == "" {
			continue
		}
		out.records++
		if rec.SessionID != "" {
			out.sessions[rec.SessionID] = struct{}{}
		}
		key := ns + ":" + bare
		t := out.targets[key]
		if t == nil {
			t = &observedTarget{namespace: ns, name: bare, args: make(map[string]*observedArg)}
			out.targets[key] = t
		}

		switch rec.Decision {
		case "allow":
			out.allow++
			t.allow++
			// audit_only distinguishes an audit/wiretap allow (missing map = zero
			// arguments) from an enforce-mode allow (missing map = no visibility).
			if ns == "tool" {
				mineArgs(t, details, rec.AuditOnly, maxValues)
			}
		case "deny":
			out.deny++
			t.deny++
		case audit.DecisionEscalate:
			// Counting this keeps an escalate-only target in the draft: without it, a tape
			// whose refusals were ALL escalations would falsely report "no tool calls found".
			out.escalate++
			t.escalate++
		default:
			// A decision this build does not model. Counted (not dropped), so the
			// banner's arithmetic still reconciles against the record total.
			out.unknownDecision++
		}
	}
	if err := scanner.Err(); err != nil {
		return suggestionSet{}, err
	}
	return out, nil
}

// mineArgs folds one observed argument map into the target's accumulator,
// recording distinct string values, flagging non-string-valued arguments, and
// counting how many calls carried each argument (calls) so render can
// distinguish an always-present argument from an optional one. maxValues caps
// how many distinct values are retained per argument (see observedArg.overflowed).
func mineArgs(t *observedTarget, details map[string]interface{}, auditOnly bool, maxValues int) {
	if details == nil {
		// audit_only distinguishes why the map is absent: audit/wiretap (true) means the
		// call genuinely carried zero arguments, so it counts as a real denominator —
		// otherwise a zero-arg call would get mislabeled and denied by an allowedValues
		// condition. Enforce-mode (false) means zero VISIBILITY, not zero arguments, so
		// skip it to avoid mislabeling an always-present argument as optional.
		if auditOnly {
			t.nonTruncatedAllow++
		}
		return
	}
	if _, whole := details[audit.TruncatedKey]; whole {
		// The whole map was replaced by this marker; mining it would emit a condition on a
		// phantom argument. Record the loss for writeTargetEntry — without counting this
		// call in nonTruncatedAllow, so an always-present argument isn't mislabeled optional.
		t.wholeTruncated = true
		return
	}
	// eunox injects its own reserved, underscore-prefixed keys into details; mining one as
	// an argument would deny every real call to the tool, so they're skipped as a SET so a
	// newly added key is excluded by construction. A caller argument spelled the same way is
	// not a problem: the transport quarantines it under audit.ReservedArgumentsKey first.
	args := details
	realArgCount := len(args)
	for name := range args {
		if audit.IsReservedDetailKey(name) {
			realArgCount--
		}
	}
	if realArgCount == 0 {
		// Mirrors the nil-details branch above: audit-mode is a real zero-argument
		// observation, enforce-mode is zero visibility.
		if auditOnly {
			t.nonTruncatedAllow++
		}
		return
	}
	// Real arguments are visible; count this call as the denominator for the
	// optional-argument check.
	t.nonTruncatedAllow++
	for name, raw := range args {
		if audit.IsReservedDetailKey(name) {
			continue
		}
		a := t.args[name]
		if a == nil {
			a = &observedArg{values: make(map[string]struct{})}
			t.args[name] = a
		}
		// Count PRESENCE before the value short-circuits below, or a.calls would
		// undercount and mislabel an always-present-but-truncated argument as optional.
		a.calls++

		if s, ok := raw.(string); ok && (audit.IsOverCapValuePlaceholder(s) || enforcement.IsDenialDetailElided(s) || enforcement.IsDenialDetailSliceElided(s)) {
			// Just this value was replaced. Flag per-argument truncation and skip the
			// value (presence already counted) so writeTargetEntry emits the honest
			// truncation note rather than a glob-metacharacter note on the placeholder text.
			// Matched via each producer's own placeholder detector, so a genuine value that
			// merely starts with "[eunox: omitted " is mined as the real value it is.
			a.truncated = true
			continue
		}
		if s, ok := raw.(string); ok {
			// Only maxValues+1 distinct values are ever needed to prove "too many to
			// allowlist" at render; once reached, stop growing and drop what was collected
			// (render uses the overflowed flag instead of the incomplete count).
			if !a.overflowed {
				if _, exists := a.values[s]; !exists && len(a.values) > maxValues {
					a.overflowed = true
					a.values = nil
				} else {
					a.values[s] = struct{}{}
				}
			}
		} else {
			a.nonString = true
		}
	}
}

// renderSuggestedManifest turns an aggregated suggestionSet into a draft YAML manifest.
// A non-positive maxValues falls back to the default, not "zero values allowed".
func renderSuggestedManifest(s suggestionSet, manifestName string, maxValues int) string {
	maxValues = resolveMaxValues(maxValues)

	var sb strings.Builder
	writeSuggestBanner(&sb, s)
	sb.WriteString("schemaVersion: \"0.1\"\n")
	fmt.Fprintf(&sb, "name: %s\n", yamlScalar(manifestName))
	sb.WriteString("version: \"0.1.0\"\n\n")

	// Split targets into allowed (allow > 0) and deny-only. Allowed targets become
	// the active draft; deny-only targets are surfaced commented so a
	// previously-blocked call is never silently allowlisted.
	var allowed, denyOnly []*observedTarget
	for _, t := range s.targets {
		switch {
		case t.allow > 0:
			allowed = append(allowed, t)
		case t.deny > 0 || t.escalate > 0:
			denyOnly = append(denyOnly, t)
		}
	}
	sort.Slice(allowed, func(i, j int) bool { return targetLess(allowed[i], allowed[j]) })
	sort.Slice(denyOnly, func(i, j int) bool { return targetLess(denyOnly[i], denyOnly[j]) })

	if len(allowed) == 0 && len(denyOnly) == 0 {
		sb.WriteString("capabilities: [] # no tool calls found in the audit log\n")
		return sb.String()
	}

	sb.WriteString("capabilities:\n")
	sb.WriteString("  # REVIEW each entry below. It reflects observed usage, not intended policy.\n")

	first := true
	for _, t := range allowed {
		if !first {
			sb.WriteString("  #\n")
		}
		first = false
		writeTargetEntry(&sb, t, maxValues)
	}

	if len(denyOnly) > 0 {
		sb.WriteString("  #\n")
		sb.WriteString("  # ── Seen only as refusals ─────────────────────────────────────────────\n")
		sb.WriteString("  # The agent attempted these but was refused. Uncomment only the ones you\n")
		sb.WriteString("  # deliberately intend to permit. An ESCALATION is not a policy defect: the\n")
		sb.WriteString("  # action was permitted but its consequence exceeded the effect ceiling and it\n")
		sb.WriteString("  # was held for human approval — allowlisting the target does NOT change that.\n")
		for _, t := range denyOnly {
			fmt.Fprintf(&sb, "  # - target: %s\n", yamlScalar(t.namespace+":"+t.name))
			fmt.Fprintf(&sb, "  #   actions: [%s]   # observed %s\n", actionForNamespace(t.namespace), refusalTally(t))
		}
	}

	return sb.String()
}

// refusalTally renders a target's refusal counts for the commented draft entry. Denials
// and escalations are reported separately since the remediation differs: a denial says
// policy forbade the call, an escalation says the CONSEQUENCE needs a human.
func refusalTally(t *observedTarget) string {
	switch {
	case t.deny > 0 && t.escalate > 0:
		return fmt.Sprintf("%d denial(s), %d escalation(s)", t.deny, t.escalate)
	case t.escalate > 0:
		return fmt.Sprintf("%d escalation(s)", t.escalate)
	default:
		return fmt.Sprintf("%d denial(s)", t.deny)
	}
}

// writeSuggestBanner emits the leading comment block: provenance (so the draft
// is traceable to a tape) and the review warning.
func writeSuggestBanner(sb *strings.Builder, s suggestionSet) {
	sb.WriteString("# Draft manifest generated by `eunox suggest`.\n")
	// "mined" rather than a bare count: records only counts those resolving to a
	// capability target, so it stays smaller than `eunox stats`' total with an explanation.
	fmt.Fprintf(sb, "# Source: %d mined audit record(s) — %d allow, %d deny, %d escalate — across %d session(s).\n",
		s.records, s.allow, s.deny, s.escalate, len(s.sessions))
	if s.unknownDecision > 0 {
		fmt.Fprintf(sb, "#   (%d of those carry a decision this build does not model and shaped no entry below.)\n", s.unknownDecision)
	}
	sb.WriteString("# (Records that name no capability target — infrastructure denials, unmapped\n")
	sb.WriteString("#  methods — are not mined and are not counted above.)\n")
	sb.WriteString("#\n")
	sb.WriteString("# REVIEW BEFORE ENFORCING. These entries describe what the agent *did* during\n")
	sb.WriteString("# the observed sessions, not necessarily what it *should* be allowed to do — a\n")
	sb.WriteString("# tape can capture calls driven by prompt injection or mistakes. Tighten every\n")
	sb.WriteString("# entry, then:  eunox validate <this file>  and point your config's policy: at it.\n")
}

// writeTargetEntry emits one uncommented capability entry for an allowed target,
// with allowedValues conditions inferred from observed string arguments.
func writeTargetEntry(sb *strings.Builder, t *observedTarget, maxValues int) {
	// The sampling opt-in is a deliberate, security-relevant channel: never emit
	// it as an active entry even when the tape shows it. Surface it commented.
	if t.namespace == "system" {
		fmt.Fprintf(sb, "  # - target: %s\n", yamlScalar("system:"+t.name))
		sb.WriteString("  #   actions: [allow]   # server-initiated sampling observed — uncomment ONLY if you intend to permit it (sensitive)\n")
		return
	}

	fmt.Fprintf(sb, "  - target: %s\n", yamlScalar(t.namespace+":"+t.name))
	fmt.Fprintf(sb, "    actions: [%s]\n", actionForNamespace(t.namespace))

	if t.namespace != "tool" {
		return
	}

	// Emitted only when the WHOLE arguments map was dropped for some call; per-value
	// truncation gets an argument-specific note in the loop below instead.
	var truncNote string
	if t.wholeTruncated {
		truncNote = fmt.Sprintf("    # NOTE: arguments were truncated in the audit log for some calls to %q (exceeded the audit detail cap) — values could not be mined; constrain manually if needed", t.name)
	}

	if len(t.args) == 0 {
		if truncNote != "" {
			sb.WriteString(truncNote)
			sb.WriteString("\n")
		}
		return
	}

	// Emit an allowedValues condition ONLY when it cannot reject a call the tape showed as
	// allowed: present on every allowed call, and observed only as strings. Anything
	// failing either test becomes a review comment.
	argNames := sortedKeys(t.args)
	var conditions []string // rendered condition blocks (already indented)
	var notes []string      // review comments for args we did not constrain

	for _, name := range argNames {
		a := t.args[name]
		vals := sortedKeys(a.values)
		switch {
		case name == "":
			// {"": "x"} is legal MCP JSON; both the loader and engine reject an
			// allowedValues with an empty name, so emitting one denies the observed call.
			notes = append(notes, fmt.Sprintf("    # argument %q: empty argument name — left unconstrained, since a condition would be rejected at load and deny the observed call; constrain manually", name))
		case a.truncated:
			// This argument's values were truncated, so the full set is unknowable.
			notes = append(notes, fmt.Sprintf("    # argument %q: value(s) were truncated in the audit log (exceeded the audit detail cap) — left unconstrained; constrain manually if needed", name))
		case t.wholeTruncated:
			// Another call's WHOLE map was truncated, so this argument may have carried a
			// hidden value there too; a.calls == nonTruncatedAllow so the optional-argument
			// arm below can't catch it.
			notes = append(notes, fmt.Sprintf("    # argument %q: another call to this tool had its whole argument map truncated in the audit log, so this argument's full value set is unknowable — left unconstrained; constrain manually", name))
		case capability.IsArgumentPath(name):
			// The engine reads a "$."-prefixed name as a nested JSON path, not a literal
			// key, so a condition here would resolve a different argument.
			notes = append(notes, fmt.Sprintf("    # argument %q: name uses the reserved \"$.\" nested-path prefix — left unconstrained, since a condition would resolve a different argument and deny the observed call; constrain manually", name))
		case capability.IsEscapedArgumentLiteral(name):
			// The engine unescapes "$$." to a different literal key before lookup.
			notes = append(notes, fmt.Sprintf("    # argument %q: name uses the reserved \"$$.\" escape prefix — left unconstrained, since the engine unescapes it to a different key and a condition would resolve a different argument and deny the observed call; constrain manually", name))
		case a.calls < t.nonTruncatedAllow:
			// Optional: an allowedValues would make it mandatory and deny calls that
			// omitted it. Denominator is nonTruncatedAllow, not allow, or a
			// whole-truncated call would mislabel an always-present argument.
			notes = append(notes, fmt.Sprintf("    # argument %q: present on %d of %d observed call(s) with mineable arguments — left unconstrained, since a condition would deny the calls that omit it", name, a.calls, t.nonTruncatedAllow))
		case a.overflowed:
			// Checked BEFORE the nonString cases: overflow cleared vals, so an empty vals
			// would otherwise trip the "no string values ever seen" case below.
			notes = append(notes, fmt.Sprintf("    # argument %q: more than %d distinct values observed — too many to allowlist; constrain manually if needed", name, maxValues))
		case a.nonString && len(vals) == 0:
			notes = append(notes, fmt.Sprintf("    # argument %q: non-string values observed — add a typed condition manually if it needs constraining", name))
		case a.nonString:
			// Kept ahead of len(vals) > maxValues so a mixed-type argument gets this more
			// specific guidance instead of the generic "too many" note.
			notes = append(notes, fmt.Sprintf("    # argument %q: both string and non-string values observed — left unconstrained, since a string allowedValues would deny the non-string calls; add a typed condition manually", name))
		case len(vals) > maxValues:
			notes = append(notes, fmt.Sprintf("    # argument %q: %d distinct values observed — too many to allowlist; constrain manually if needed", name, len(vals)))
		case !valuesSelfMatch(vals):
			// allowedValues is matched ONLY as a glob, so a value with glob metacharacters
			// ("report[2024].pdf") need not match its own literal.
			notes = append(notes, fmt.Sprintf("    # argument %q: observed value(s) contain glob metacharacters that do not match their own literal text — left unconstrained, since an allowedValues glob would deny the observed call; constrain manually", name))
		case !valuesGlobInert(vals):
			// Self-matches but is ALSO a widening glob ("*", "a*b"): emitting it would
			// widen access beyond the observed literal.
			notes = append(notes, fmt.Sprintf("    # argument %q: observed value(s) contain glob metacharacters and would widen the allowlist beyond the observed literal — left unconstrained; constrain manually", name))
		default:
			conditions = append(conditions, renderAllowedValues(name, vals))
		}
	}

	if truncNote != "" {
		notes = append(notes, truncNote)
	}

	if len(conditions) > 0 {
		sb.WriteString("    conditions:\n")
		for _, c := range conditions {
			sb.WriteString(c)
		}
	}
	for _, n := range notes {
		sb.WriteString(n)
		sb.WriteString("\n")
	}
}

// renderAllowedValues renders one allowedValues condition block, listing observed values
// and — when they share a directory-style prefix — a commented glob the operator can swap
// in. Name and values are emitted through yamlScalar (not Go's %q — the tape can carry
// bytes that aren't valid UTF-8, which %q and YAML would read back differently), so a
// YAML-significant character never produces an invalid or misparsed manifest.
func renderAllowedValues(argument string, values []string) string {
	var sb strings.Builder
	sb.WriteString("      - type: allowedValues\n")
	fmt.Fprintf(&sb, "        argument: %s\n", yamlScalar(argument))
	sb.WriteString("        values:\n")
	for _, v := range values {
		fmt.Fprintf(&sb, "          - %s\n", yamlScalar(v))
	}
	if glob := commonPrefixGlob(values); glob != "" {
		fmt.Fprintf(&sb, "        # consider generalizing the values above to: [%s]\n", yamlScalar(glob))
	}
	return sb.String()
}

// valuesSelfMatch reports whether every observed value would match its own
// literal text once emitted as an allowedValues glob entry. Since the entry is
// matched ONLY as a glob, a value with glob metacharacters can fail to re-admit
// its own call ("report[2024].pdf" does not self-match; "data[" is malformed).
func valuesSelfMatch(values []string) bool {
	for _, v := range values {
		if !enforcement.MatchValueGlob(v, v) {
			return false
		}
	}
	return true
}

// valuesGlobInert reports whether every value is "glob-inert" — matches ONLY its own
// literal text, catching the opposite widening direction from valuesSelfMatch ("*",
// "a*b" self-match but also match other strings). Backslash is included since
// MatchValueGlob's path.Match treats it as an escape on every platform.
func valuesGlobInert(values []string) bool {
	for _, v := range values {
		if strings.ContainsAny(v, capability.GlobMetaChars) {
			return false
		}
	}
	return true
}

// commonPrefixGlob returns a "<dir>/*" glob when every value shares a directory
// prefix (a path-like string containing "/"), or "" when no useful
// generalization exists. It is only a hint — emitted as a comment, never as the
// active condition — so over-generalization can never silently widen access.
func commonPrefixGlob(values []string) string {
	if len(values) < 2 {
		return ""
	}
	prefix := values[0]
	for _, v := range values[1:] {
		prefix = commonStringPrefix(prefix, v)
		if prefix == "" {
			return ""
		}
	}
	idx := strings.LastIndex(prefix, "/")
	if idx < 0 {
		return ""
	}
	candidate := prefix[:idx+1] + "*"
	// A single "*" does not cross "/"; suppress the hint unless the candidate admits
	// every observed value, so it never proposes a glob that rejects an allowed call.
	for _, v := range values {
		if !enforcement.MatchValueGlob(candidate, v) {
			return ""
		}
	}
	return candidate
}

func commonStringPrefix(a, b string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return a[:i]
}

// actionForNamespace returns the canonical action keyword for a namespace, so a
// generated entry pairs the right action with its target type.
func actionForNamespace(ns string) string {
	switch ns {
	case "resource":
		return "read"
	case "prompt":
		return "get"
	case "system":
		return "allow"
	default:
		return "call"
	}
}

// targetLess orders targets by namespace then bare name for stable output.
func targetLess(a, b *observedTarget) bool {
	if a.namespace != b.namespace {
		return a.namespace < b.namespace
	}
	return a.name < b.name
}

// suggestUsageExit is suggest's exit code for a usage, config, or audit-log-read error,
// matching the binary's proxy/validate/stats/audit-verify convention (2 = usage error, so it
// reads as distinguishable from an operation-specific failure — here, --output write
// failure, exit 1). Was the other way around; pre-1.0 permits the clean swap over a
// compat shim. `kill` is the one deliberate exception, documented in its own usage block.
const suggestUsageExit = 2

// cmdSuggest runs the `suggest` subcommand, returning the exit code (rather than calling
// os.Exit) so tests can drive every branch.
func cmdSuggest(args []string) int {
	fs := flag.NewFlagSet("suggest", flag.ContinueOnError)
	fs.Usage = func() {
		w := usageWriter(args)
		_, _ = fmt.Fprint(w, `Usage: eunox suggest [flags]

Generate a draft capability manifest from the local audit log. Unlike 'init'
(which scaffolds a deny-all from a live tool list), 'suggest' reads what the
agent actually did: it emits one entry per observed target and, for tool
arguments seen with a bounded set of string values, an allowedValues condition
grounded in those values.

Capture a tape first with a wiretap, then suggest:
  eunox proxy --audit -- <the command that launches your MCP server>
  # …use the agent for real work, then:
  eunox suggest --output manifest.yaml

The output is a DRAFT describing observed usage, not vetted policy. Review and
tighten every entry, then 'eunox validate' it before enforcing.

Exit codes:
  0  Draft manifest generated (to stdout or --output).
  1  --output was set but writing the file failed.
  2  Usage, config, or audit-log-read error.

Flags:
`)
		fs.SetOutput(w)
		fs.PrintDefaults()
	}
	auditLogPath := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")
	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the configured audit.log is\nused as the default for --audit-log.")
	name := fs.String("name", "suggested-manifest", "Value for the manifest name field.")
	output := fs.String("output", "", "Path to write the draft manifest (default: stdout).")
	force := fs.Bool("force", false, "Overwrite --output if it already exists (default: refuse to clobber). An\noverwrite also re-tightens the file mode to 0600.")
	maxValues := fs.Int("max-values", suggestMaxValuesDefault, "Max distinct values an argument may have before allowedValues is downgraded to a review comment.\n0 or negative falls back to the default (20).")

	logPath, code, done := parseAndResolveAuditLog("suggest", fs, args, configPath, auditLogPath, suggestUsageExit)
	if done {
		return code
	}
	r, closeChain, code, done := openAuditChainOrExit("suggest", logPath, suggestUsageExit)
	if done {
		return code
	}
	defer closeChain()

	resolvedMaxValues := resolveMaxValues(*maxValues)
	suggestions, err := computeSuggestions(r, resolvedMaxValues)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox suggest: reading log: %v\n", err)
		return suggestUsageExit
	}
	manifest := renderSuggestedManifest(suggestions, *name, resolvedMaxValues)

	if *output == "" {
		fmt.Print(manifest)
		return 0
	}
	if err := writeGeneratedFile(*output, manifest, *force); err != nil {
		fmt.Fprintf(os.Stderr, "eunox suggest: %v\n", err)
		// 2, matching init's identical failure and every other reader's file-error code:
		// a refused --output is not a finding about the tape.
		return suggestUsageExit
	}
	fmt.Fprintf(os.Stderr, "Generated draft manifest %s from %d audit record(s) — review and tighten each entry, then run: eunox validate %s\n",
		*output, suggestions.records, *output)
	return 0
}
