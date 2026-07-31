// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Draft-manifest generator for the `suggest` subcommand.
//
// Where `init` reads a live upstream's tool list and emits a deny-all starter,
// `suggest` reads the local audit tape — what the agent actually did — and emits
// grounded, uncommented draft entries. In wiretap mode every allowed tools/call
// records its argument map in `details`; `suggest` mines those values to propose
// `allowedValues` conditions.
//
// The output is a draft of observed usage, not vetted policy — the tape may
// include calls driven by prompt injection or mistakes, so the manifest carries a
// REVIEW banner and the sensitive sampling opt-in is always commented out. The
// operator reviews, runs `validate`, then points a config's `policy:` at it.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// suggestMaxValuesDefault bounds how many distinct observed values an argument
// may have before `suggest` proposes a concrete allowedValues condition. Beyond
// it, enumerating every value over-fits the tape (and bloats the manifest), so
// the argument is surfaced as a comment for the operator to constrain manually.
const suggestMaxValuesDefault = 20

// resolveMaxValues normalizes a --max-values flag value: non-positive means
// "use the default" rather than "zero values allowed". Shared by
// computeSuggestions and renderSuggestedManifest so both apply the identical
// cutoff — a caller passing mismatched values between the two would fail the
// collection cap's invariant that render never sees more than it collected.
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
	// placeholder, so its full value set is unknowable. Leave it unconstrained even
	// if other values were observed — a partial allowedValues would deny the
	// truncated call.
	truncated bool
	// overflowed: the distinct-value set exceeded maxValues+1 during collection and
	// was cleared, so its full value set is not retained. render already downgrades
	// any argument past maxValues distinct values to a review comment, so the only
	// purpose collection cap serves is to stop accumulating a value set that will
	// never be rendered — for a high-cardinality argument (request IDs, timestamps,
	// paths) that otherwise grows without bound over a large audit tape.
	overflowed bool
}

// observedTarget accumulates everything the tape reveals about one enforcement
// target (a tool, resource, prompt, or the sampling system primitive).
type observedTarget struct {
	namespace string // "tool" | "resource" | "prompt" | "system"
	name      string // bare name: tool name, resource URI, prompt name, or "sampling/createMessage"
	allow     int
	deny      int
	// nonTruncatedAllow counts allowed calls whose detail map was NOT replaced
	// wholesale by the audit truncation marker — i.e. the calls whose arguments
	// could actually be mined. It is the correct denominator for the "argument is
	// optional" check: comparing against allow (which includes whole-map-truncated
	// calls, where every argument is invisible) would mislabel an always-present
	// argument as optional whenever any call's detail map was truncated.
	nonTruncatedAllow int
	args              map[string]*observedArg
	// wholeTruncated: at least one call's details were replaced wholesale by the
	// audit truncation marker, so its arguments could not be mined at all. render
	// surfaces a tool-level review note instead of treating the marker as a real
	// argument. Per-value truncation (a single argument's value replaced) is tracked
	// on observedArg.truncated and produces an argument-specific note instead.
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
	sessions map[string]struct{}
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

// computeSuggestions scans an audit JSONL stream and aggregates per-target
// observations. Malformed and blank lines are SKIPPED so a partial or schema-drifted
// tape still yields a draft. That is deliberately not what computeAuditStats does with
// a malformed line — stats counts it in its "other" bucket, because its job is to make
// the totals reconcile against the tape, while this one's job is to propose policy and
// a line it cannot decode names no target to propose anything about.
// maxValues bounds how many distinct values mineArgs retains per argument
// during collection (see resolveMaxValues); it must match the value later
// passed to renderSuggestedManifest so the collection cap and the render-time
// "too many to allowlist" cutoff agree.
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
		// details is decoded separately, as raw JSON first: the producer always
		// writes an object, but a schema-drifted tape may carry a scalar or array
		// there instead. Decoding straight into map[string]interface{} on the outer
		// struct would fail the WHOLE record on that type mismatch and discard an
		// otherwise-parseable target/decision/method — the opposite of the "a
		// schema-drifted tape still yields a draft" contract above. A non-object
		// (or absent) details is treated as "no mineable arguments", not a parse
		// failure.
		var details map[string]interface{}
		if len(bytes.TrimSpace(rec.Details)) > 0 {
			_ = json.Unmarshal(rec.Details, &details) // non-object details: leave nil, still count target/decision
		}
		// Skip */list enumeration records: list access is governed by automatic list
		// filtering, not a capability grant, so a */list record would otherwise emit a
		// phantom "<namespace>:<method>" target. capability.ListResultKey returns ""
		// for a non-list method.
		if capability.ListResultKey(rec.Method) != "" {
			continue
		}
		// Skip upstream-failure denials (timeouts, transport errors, cancellations):
		// transport noise, not policy signals, that would surface as spurious
		// deny-only targets.
		if rec.Decision == "deny" && transport.IsInfraDenialCode(rec.DenialCode) {
			continue
		}
		// resolveTarget returns "" for any unrecognized target_type, so this also drops
		// post-dispatch infrastructure denials (e.g. unmapped methods) whose target
		// carries no capability gap a manifest entry could address.
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
			// Only allowed tools/call records carry the caller's argument map in
			// details; mine values from those. audit_only distinguishes an audit/wiretap
			// allow (a missing map means a genuine zero-argument call) from an enforce-mode
			// allow (a missing map means no argument visibility) — see mineArgs.
			if ns == "tool" {
				mineArgs(t, details, rec.AuditOnly, maxValues)
			}
		case "deny":
			out.deny++
			t.deny++
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
		// No argument map on the record. The producer records the caller's arguments for
		// a tool allow exactly when the same (audit-mode or per-constraint observe)
		// condition that stamps audit_only holds AND at least one argument was present, so
		// audit_only distinguishes the two reasons the map is absent:
		//   - audit/wiretap allow (auditOnly true): arguments WOULD have been recorded had
		//     any been present, so a missing map means the call carried ZERO arguments. It
		//     is a real call and DOES count as a denominator — otherwise a tool observed
		//     both with zero args and with an argument makes that argument satisfy
		//     a.calls == t.nonTruncatedAllow, get emitted as an allowedValues condition,
		//     and then deny the zero-argument calls the tape showed as allowed
		//     (MISSING_CONTEXT).
		//   - enforce-mode allow (auditOnly false): arguments are never recorded at all, so
		//     a missing map is zero visibility, not zero arguments. Counting it would make a
		//     genuinely always-present argument satisfy a.calls < t.nonTruncatedAllow and be
		//     mislabeled optional, suppressing its allowedValues condition. Skip it.
		if auditOnly {
			t.nonTruncatedAllow++
		}
		return
	}
	if _, whole := details[audit.TruncatedKey]; whole {
		// The whole arguments map was replaced by this marker (exceeded the
		// per-record detail cap). It is not a real argument: mining it would emit a
		// condition on a phantom argument no call carries, so the draft would deny
		// every call to this tool. Record the loss for writeTargetEntry and skip —
		// crucially without counting this call in nonTruncatedAllow, so a genuinely
		// always-present argument is not mislabeled optional just because some calls
		// had truncated detail maps.
		t.wholeTruncated = true
		return
	}
	// The transport merges the reserved audit-only key audit.UpstreamErrorCodeKey
	// (underscore-prefixed, so it can't collide with any ORDINARY caller-supplied tool
	// argument name) into a tools/call allow record's details when the upstream call
	// itself errored. It is a flat merge in the common case. On the vanishingly rare
	// call whose real argument is literally named the reserved key's own string, the
	// transport nests the caller's args under "arguments" instead of overwriting them
	// (see dispatch.go's dispatchToolsCall) — resolve that shape here too, exactly as
	// the pre-rename code did, just keyed on the new reserved name.
	args := details
	skipReserved := true
	if inner, ok := details["arguments"].(map[string]interface{}); ok {
		if _, hasCode := details[audit.UpstreamErrorCodeKey]; hasCode && len(details) == 2 {
			// Shape alone is not sufficient to conclude this is the nested-collision
			// wrapper: a call that never errored upstream produces details == the
			// caller's real top-level arguments verbatim, so a tool genuinely called
			// with two real top-level arguments named "arguments" and the reserved
			// key's string produces this exact same shape. Disambiguate using the one
			// fact that distinguishes them: the transport's collide branch fires
			// exactly when the caller's real arguments already contained the reserved
			// key — so in the true nested shape, the inner map necessarily carries its
			// own copy of it.
			//
			// When the inner map does NOT carry it, this is not the nested wrapper. The
			// far likelier producer of that shape is the ORDINARY flat merge on a call
			// whose one real argument is a map named "arguments" (a plausible argument
			// name) that then errored upstream; the alternative needs a caller argument
			// literally named the reserved key, the case this comment calls vanishingly
			// rare. So keep the flat reading: mine details as-is with the reserved key
			// still skipped, rather than fabricating a phantom argument for it and
			// skewing the presence accounting of the real "arguments" argument.
			if _, innerHasCode := inner[audit.UpstreamErrorCodeKey]; innerHasCode {
				args = inner
				skipReserved = false
			}
		}
	}
	realArgCount := len(args)
	if skipReserved {
		if _, hasReserved := args[audit.UpstreamErrorCodeKey]; hasReserved {
			realArgCount--
		}
	}
	if realArgCount == 0 {
		// No real caller argument was observed — either a genuine zero-argument call or
		// an upstream-errored allow whose only detail is the reserved code. Mirror the
		// nil-details branch above: an audit-mode record is a real zero-argument
		// observation (counts as the denominator), an enforce-mode record is zero
		// visibility (does not). Counting an enforce-mode reserved-key-only record would
		// mislabel a genuinely always-present argument on other records as optional.
		if auditOnly {
			t.nonTruncatedAllow++
		}
		return
	}
	// Real arguments are visible; count this call as the denominator for the
	// optional-argument check.
	t.nonTruncatedAllow++
	for name, raw := range args {
		if skipReserved && name == audit.UpstreamErrorCodeKey {
			continue
		}
		a := t.args[name]
		if a == nil {
			a = &observedArg{values: make(map[string]struct{})}
			t.args[name] = a
		}
		// Count PRESENCE before the value short-circuits below: the call carried the
		// argument regardless of whether its value survived truncation. Counting
		// after the truncation continue would make a.calls < t.allow and mislabel an
		// always-present-but-truncated argument as optional.
		a.calls++

		if s, ok := raw.(string); ok && audit.IsOverCapValuePlaceholder(s) {
			// Just this value was replaced (not the whole map). The real value is
			// lost: mining the placeholder would trip the glob-metacharacter note
			// instead of the honest truncation note. Flag only the per-argument
			// truncation (not the tool-level wholeTruncated) and skip the value
			// (presence already counted) so writeTargetEntry emits an
			// argument-specific note rather than the generic whole-tool NOTE.
			//
			// Detect via the audit layer's own matcher (audit.IsOverCapValuePlaceholder),
			// which matches the placeholder's FULL structured form. A genuine argument
			// value that merely begins with "[eunox: omitted " is therefore mined as the
			// real value it is, not misread as truncated — so a legitimate value is never
			// suppressed from the allowedValues draft by a prefix collision.
			a.truncated = true
			continue
		}
		if s, ok := raw.(string); ok {
			// Only maxValues+1 distinct values are ever needed to prove "too many to
			// allowlist" at render — once that's reached, stop growing the set (a
			// high-cardinality argument like a request ID or path would otherwise
			// accumulate one entry per distinct value for the whole audit tape) and
			// drop what was collected, since render will use the overflowed flag
			// instead of the (now-incomplete) value count.
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

// renderSuggestedManifest turns an aggregated suggestionSet into a draft YAML
// manifest. maxValues bounds how many distinct values an argument may have
// before its allowedValues proposal is downgraded to a review comment. A
// non-positive maxValues falls back to the default (documented in the --max-values
// flag help), rather than meaning "zero values allowed".
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
		if t.allow > 0 {
			allowed = append(allowed, t)
		} else if t.deny > 0 {
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
		sb.WriteString("  # ── Seen only as denials ──────────────────────────────────────────────\n")
		sb.WriteString("  # The agent attempted these but a policy blocked them. Uncomment only the\n")
		sb.WriteString("  # ones you deliberately intend to permit.\n")
		for _, t := range denyOnly {
			fmt.Fprintf(&sb, "  # - target: %s\n", yamlScalar(t.namespace+":"+t.name))
			fmt.Fprintf(&sb, "  #   actions: [%s]   # observed %d denial(s)\n", actionForNamespace(t.namespace), t.deny)
		}
	}

	return sb.String()
}

// writeSuggestBanner emits the leading comment block: provenance (so the draft
// is traceable to a tape) and the review warning.
func writeSuggestBanner(sb *strings.Builder, s suggestionSet) {
	sb.WriteString("# Draft manifest generated by `eunox suggest`.\n")
	// "mined" rather than a bare count: records is incremented only for records that
	// resolved to a capability target, so infrastructure denials and any record whose
	// target_type is unrecognized are excluded. Reporting it as the tape's record count
	// overstated the evidence behind the draft -- an operator comparing it against
	// `eunox stats` would see a smaller number here with no explanation.
	fmt.Fprintf(sb, "# Source: %d mined audit record(s) — %d allow, %d deny — across %d session(s).\n",
		s.records, s.allow, s.deny, len(s.sessions))
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

	// A tool-level truncation note is emitted only when the WHOLE arguments map was
	// dropped by the audit cap for some call, so the operator knows the draft is
	// under-constrained for this tool with no minable arguments to attribute it to.
	// Per-value truncation (a single argument's value replaced) is reported by an
	// argument-specific note in the loop below instead.
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

	// Emit an allowedValues condition ONLY when it cannot reject a call the tape
	// showed as allowed: the argument must be (a) present on every allowed call
	// (else a missing-argument deny rejects the calls that omitted it) and (b)
	// observed only as strings (a string allowlist is glob-matched and never matches
	// a non-string value). An argument failing either test, or with too many
	// distinct values, becomes a review comment.
	argNames := sortedKeys(t.args)
	var conditions []string // rendered condition blocks (already indented)
	var notes []string      // review comments for args we did not constrain

	for _, name := range argNames {
		a := t.args[name]
		vals := sortedKeys(a.values)
		switch {
		case name == "":
			// An empty argument name (MCP arguments are an arbitrary JSON object, so
			// {"": "x"} is legal and survives into the mined args). Both the manifest
			// loader (validateAllowedValues) and the engine (handleAllowedValues ->
			// CONDITION_FAILED) reject an allowedValues with an empty argument name, so
			// emitting one would yield an unloadable draft that denies the observed
			// call. Leave it unconstrained, like the other "would deny the observed
			// call" arms. Placed first so it wins regardless of truncation/value state.
			notes = append(notes, fmt.Sprintf("    # argument %q: empty argument name — left unconstrained, since a condition would be rejected at load and deny the observed call; constrain manually", name))
		case a.truncated:
			// At least one of THIS argument's values was truncated, so the full set is
			// unknowable; a partial allowedValues would deny the truncated call. Emit an
			// argument-specific note (the tool-level NOTE only fires for whole-map
			// truncation, which hides every argument).
			notes = append(notes, fmt.Sprintf("    # argument %q: value(s) were truncated in the audit log (exceeded the audit detail cap) — left unconstrained; constrain manually if needed", name))
		case t.wholeTruncated:
			// Another call to this tool had its WHOLE argument map truncated by the
			// audit cap (audit.TruncatedKey), so this still-visible argument's full
			// value set is unknowable: the truncated call may have carried the same
			// argument with a different value that is now hidden. An enumerated
			// allowedValues would then deny that observed-allowed call. Mirror the
			// a.truncated arm and leave it unconstrained. The optional-argument arm
			// below cannot catch this because mineArgs returns before incrementing
			// nonTruncatedAllow for a whole-truncated call, so a.calls == nonTruncatedAllow.
			notes = append(notes, fmt.Sprintf("    # argument %q: another call to this tool had its whole argument map truncated in the audit log, so this argument's full value set is unknowable — left unconstrained; constrain manually", name))
		case capability.IsArgumentPath(name):
			// The reserved "$." nested-path prefix is a property of the NAME, not the
			// values, so it is checked regardless of how many values were observed. The
			// engine reads a "$."-prefixed argument name as a nested JSON path, not a
			// literal top-level key, so an allowedValues here would resolve a different
			// argument (or none) and deny the observed call. Leave it unconstrained,
			// mirroring the other "would deny the observed call" arms.
			notes = append(notes, fmt.Sprintf("    # argument %q: name uses the reserved \"$.\" nested-path prefix — left unconstrained, since a condition would resolve a different argument and deny the observed call; constrain manually", name))
		case capability.IsEscapedArgumentLiteral(name):
			// The reserved "$$." (2+ leading '$' then '.') escape is a property of the
			// NAME, so it is checked regardless of how many values were observed. The
			// engine unescapes such a name to a DIFFERENT literal key before lookup
			// (ArgumentLiteralKey strips one '$': "$$.x" -> "$.x"), so an allowedValues
			// written on this name would resolve a different (absent) argument and deny
			// the observed call with MISSING_CONTEXT. Leave it unconstrained, mirroring
			// the IsArgumentPath / empty-name arms.
			notes = append(notes, fmt.Sprintf("    # argument %q: name uses the reserved \"$$.\" escape prefix — left unconstrained, since the engine unescapes it to a different key and a condition would resolve a different argument and deny the observed call; constrain manually", name))
		case a.calls < t.nonTruncatedAllow:
			// Optional: omitted from at least one allowed call whose arguments were
			// visible. An allowedValues makes the argument mandatory (missing →
			// MISSING_CONTEXT deny), rejecting the calls that left it out. The
			// denominator is nonTruncatedAllow, not allow: whole-map-truncated calls
			// hide every argument, so counting them would mislabel an always-present
			// argument as optional.
			notes = append(notes, fmt.Sprintf("    # argument %q: present on %d of %d observed call(s) with mineable arguments — left unconstrained, since a condition would deny the calls that omit it", name, a.calls, t.nonTruncatedAllow))
		case a.overflowed:
			// Overflow means many string values WERE observed (collection stopped only
			// after exceeding the cap), and mineArgs cleared vals — so this must be
			// checked BEFORE the nonString cases: an empty vals would otherwise satisfy
			// `a.nonString && len(vals) == 0` and emit "no string values were ever
			// seen", which is the opposite of what overflow means. The exact count is
			// unknown (collection stopped early), so only the cap is nameable. The
			// analogous but count-known case, `len(vals) > maxValues` without overflow,
			// is handled after the nonString cases below, where a genuinely mixed-type
			// argument still reports the more specific mixed-type guidance.
			notes = append(notes, fmt.Sprintf("    # argument %q: more than %d distinct values observed — too many to allowlist; constrain manually if needed", name, maxValues))
		case a.nonString && len(vals) == 0:
			// Only non-string values: no useful string allowlist.
			notes = append(notes, fmt.Sprintf("    # argument %q: non-string values observed — add a typed condition manually if it needs constraining", name))
		case a.nonString:
			// Mixed string/non-string: a glob-matched string allowlist would deny the
			// observed non-string calls. Kept ahead of the plain len(vals) > maxValues
			// case below so a mixed argument with more than maxValues distinct string
			// values still gets this more specific type-mixing guidance rather than the
			// generic "too many to allowlist" note.
			notes = append(notes, fmt.Sprintf("    # argument %q: both string and non-string values observed — left unconstrained, since a string allowedValues would deny the non-string calls; add a typed condition manually", name))
		case len(vals) > maxValues:
			notes = append(notes, fmt.Sprintf("    # argument %q: %d distinct values observed — too many to allowlist; constrain manually if needed", name, len(vals)))
		case !valuesSelfMatch(vals):
			// allowedValues is matched ONLY as a glob, so a value with glob
			// metacharacters need not match its own literal ("report[2024].pdf" does
			// not; "data[" is malformed and would fail the load). Either way an
			// enumerated condition would reject the call the tape showed as allowed.
			notes = append(notes, fmt.Sprintf("    # argument %q: observed value(s) contain glob metacharacters that do not match their own literal text — left unconstrained, since an allowedValues glob would deny the observed call; constrain manually", name))
		case !valuesGlobInert(vals):
			// Self-matches but is ALSO a widening glob ("*", "a*b", "file?.txt"):
			// emitting it would widen access beyond the observed literal. Leave
			// unconstrained.
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

// renderAllowedValues renders one allowedValues condition block, listing the
// observed values and — when they share a directory-style prefix — a commented
// glob the operator can swap in. The caller only reaches here for an argument
// observed solely as strings on every call.
//
// Argument name and values are emitted through yamlScalar, the same renderer the init
// scaffolder uses, so a YAML-significant character (colon-space, leading "*"/"&", bare
// "null") cannot produce an invalid or misparsed manifest.
//
// Not Go's %q: these strings are mined from the audit TAPE, so they can carry bytes
// that are not valid UTF-8, and %q renders such a byte as \xNN — which Go reads back
// as that raw byte but YAML reads as the code point U+00NN. The draft entry would then
// target a string that is not the one observed, i.e. a nonexistent tool or argument,
// and the operator would see a rule that silently matches nothing. yamlScalar detects
// exactly that non-round-trip and falls back to a !!binary scalar.
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

// valuesGlobInert reports whether every value is "glob-inert" — matches ONLY its
// own literal text. valuesSelfMatch catches values that fail to match themselves;
// this catches the opposite widening direction ("*", "a*b", "file?.txt"
// self-match but also match other strings). A value is glob-inert iff it carries
// no glob metacharacter (* ? [ \). MatchValueGlob delegates to the stdlib
// path.Match (not filepath.Match), which treats backslash as an escape on every
// platform, so backslash is glob-significant and included here. In practice a
// backslash-bearing value never reaches this check — escaping breaks its literal
// self-match, so valuesSelfMatch (evaluated first) already excludes it — and even
// if it did, escaping can only restrict, never widen. Including '\' in
// capability.GlobMetaChars keeps the inertness test self-contained rather than
// reliant on that upstream guard.
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
	// A single "*" does not cross "/", so "/srv/data/*" fails to match a sub-directory
	// value like "/srv/data/logs/b.pdf". Suppress the hint unless the candidate
	// admits every observed value, so it never proposes a glob that rejects an
	// allowed call.
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
