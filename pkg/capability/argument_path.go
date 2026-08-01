// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import "strings"

// ArgumentPathPrefix marks a condition's `argument` value as a dotted path into
// nested object arguments rather than a literal top-level key: "$.a.b" reads
// args["a"]["b"], whereas "a.b" is an exact top-level key. The sentinel keeps a
// literal dotted key exact-matching, so the manifest never silently matches an
// alternative argument (a load-bearing invariant).
const ArgumentPathPrefix = "$."

// ArgumentEscapePrefix is the SHORTEST escape that names a literal top-level
// argument beginning with the "$." traversal sentinel: "$$.x" names the literal
// key "$.x", never a traversal into args["x"]. Without an escape, a tool argument
// literally named "$.x" (a legal JSON object key) could never be referenced —
// IsArgumentPath treats every "$."-prefixed ref as traversal, so the sentinel
// would silently resolve to a different argument than the one named (see the
// same load-bearing invariant ArgumentPathPrefix protects).
//
// The escape generalizes past this shortest case: IsEscapedArgumentLiteral
// matches ANY run of two or more leading '$' immediately followed by '.', and
// ArgumentLiteralKey always unescapes by stripping exactly ONE leading '$'. A
// literal key with N (N >= 1) leading dollars then a dot is therefore referenced
// by writing N+1 leading dollars ("$$.x" -> "$.x", "$$$.x" -> "$$.x", ...) — a
// bijection between the escaped-ref space (2+ dollars) and the literal-key space
// it targets (1+ dollars), so no key of this shape is ever unreachable OR
// ambiguous. A fixed single-prefix escape (matching only "$$." exactly) would
// itself collide with a literal key actually named "$$.x": that text would
// always mean "the escaped form of $.x", with no way to write "the literal key
// $$.x" — reproducing, one level up, the exact silent-wrong-argument bug this
// escape exists to close.
const ArgumentEscapePrefix = "$$."

// IsArgumentPath reports whether ref uses the nested-path syntax ("$.…"). An
// escaped ref (IsEscapedArgumentLiteral) is a literal top-level key, not a path:
// it always has a second byte of '$', never '.', so it can never match here.
func IsArgumentPath(ref string) bool {
	return strings.HasPrefix(ref, ArgumentPathPrefix)
}

// IsEscapedArgumentLiteral reports whether ref uses the escape for a literal
// top-level key that itself begins with one or more '$' followed by '.': two or
// more leading '$' characters immediately followed by '.' (e.g. "$$.x", "$$$.x").
func IsEscapedArgumentLiteral(ref string) bool {
	i := 0
	for i < len(ref) && ref[i] == '$' {
		i++
	}
	return i >= 2 && i < len(ref) && ref[i] == '.'
}

// ArgumentLiteralKey returns the literal top-level argument key ref addresses,
// unescaping one leading '$' when ref uses the IsEscapedArgumentLiteral form
// ("$$.x" -> "$.x", "$$$.x" -> "$$.x"). For every other ref (including a "$."
// traversal path, which callers must check with IsArgumentPath first) it returns
// ref unchanged — the existing "a.b" literal behavior.
func ArgumentLiteralKey(ref string) string {
	if IsEscapedArgumentLiteral(ref) {
		return ref[1:] // drop exactly one leading '$'
	}
	return ref
}

// ArgumentPathSegments returns the dot-separated segments of a "$." path
// ("$.a.b" → ["a","b"]). It returns nil for a non-path reference and for a
// malformed path (empty body "$.", empty segment "$.a..b", trailing dot "$.a."),
// so a caller fails closed rather than matching something unintended.
func ArgumentPathSegments(ref string) []string {
	if !IsArgumentPath(ref) {
		return nil
	}
	rest := ref[len(ArgumentPathPrefix):]
	if rest == "" {
		return nil
	}
	segs := strings.Split(rest, ".")
	for _, s := range segs {
		if s == "" {
			return nil
		}
	}
	return segs
}

// ArgumentRootKey returns the top-level argument key a reference depends on: the
// first segment of a "$." path ("$.a.b" → "a"), or the literal key itself
// otherwise (unescaping one ArgumentEscapePrefix layer, so "$$.x" reports "$.x",
// the actual inputSchema property name — not the escaped ref text). Drift
// detection checks this against a tool's live top-level inputSchema properties;
// the nested remainder is below the schema granularity the proxy can see.
func ArgumentRootKey(ref string) string {
	if segs := ArgumentPathSegments(ref); len(segs) > 0 {
		return segs[0]
	}
	return ArgumentLiteralKey(ref)
}

// ResolveArgument returns the value a condition's or contract's `argument`
// reference addresses, resolving the "$." nested-path syntax.
//
// "$." is a dotted path into nested object arguments: "$.a.b" reads
// args["a"].(map)["b"]. A reference beginning with "$$." is the escaped literal form
// of a top-level key that itself starts with "$.": "$$.x" reads the literal key
// args["$.x"], not a traversal into args["x"].
//
// It lives HERE, in the package that already owns the path grammar, rather than in
// pkg/enforcement, because both layers need it: the argument-matching conditions
// (allowedValues, allowedOperations, allowedExtensions, allowedTables,
// recipientDomain) resolve through enforcement.ResolveArgument, which delegates here,
// and the effect layer's contract resolution (ResolveEffect) resolves through it
// directly — pkg/capability cannot import pkg/enforcement, so a copy in each was the
// alternative, and a copy is exactly how one layer silently stops honoring a syntax
// the other documents.
//
// Fail closed: a malformed "$." path, a segment that lands on a non-object, or a
// missing key all return (nil, false) — exactly the "argument missing" signal a
// missing flat key produces, which every caller already denies on.
func ResolveArgument(args map[string]interface{}, ref string) (interface{}, bool) {
	if !IsArgumentPath(ref) {
		v, ok := args[ArgumentLiteralKey(ref)]
		return v, ok
	}
	segs := ArgumentPathSegments(ref)
	if segs == nil {
		return nil, false // malformed path: fail closed
	}
	var cur interface{} = args
	for _, seg := range segs {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// OperationVerb returns the leading whitespace-delimited token of s, upper-cased —
// the coarse first-verb rule allowedOperations applies to a SQL-ish argument.
//
// It splits on strings.Fields, so ANY whitespace separates (a newline- or
// tab-formatted statement, which is the norm from a model, resolves the same verb as
// a single-line one). It lives here for the same reason ResolveArgument does: the
// effect layer's argument-parameterized contract falls back to this same rule, and a
// second implementation is how "the same rule" quietly becomes two rules that
// disagree on exactly the multi-line input a real agent sends.
func OperationVerb(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToUpper(fields[0])
}
