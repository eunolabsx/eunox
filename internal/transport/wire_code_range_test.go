// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"go/ast"
	"go/token"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
)

// The range pin: no code eunox puts on the wire may sit in the band the MCP specification
// reserved for itself.
//
// Why this is a guard over SOURCE rather than a table of the constants: the failure it exists to
// catch is a code that does not exist yet. A list of today's constants re-checked against
// today's rule asserts nothing about tomorrow's addition, and tomorrow's addition is the whole
// hazard — a reserved code ships, the spec later assigns that integer a meaning, and every host
// that learns the new meaning silently reads an eunox denial as that protocol error. There is no
// version to notice it and no error anywhere.
//
// So the enumeration is derived two ways, and both have to hold:
//
//   - Every symbolic denial code maps through DenialWireCode to a mintable integer. That covers
//     the vocabulary a denial is built from.
//   - Every integer CONSTANT anywhere in the module whose value falls in JSON-RPC's reserved
//     -32768..-32000 is mintable. That covers the codes the transports mint directly, which the
//     denial vocabulary never sees.

// TestWireCodes_EveryDenialCodeMintsIntoAPermittedBand pins the symbolic vocabulary.
//
// Enumerated from capability.AllDenialCodes, which is already held complete by
// TestDenialWireCode_CoversEveryCode — so a new ErrCode* is covered here the moment it is
// covered there, rather than the day someone remembers this test exists.
func TestWireCodes_EveryDenialCodeMintsIntoAPermittedBand(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, capability.AllDenialCodes, "the vocabulary is empty; this pin is checking nothing")
	for _, code := range capability.AllDenialCodes {
		wire, mapped := capability.DenialWireCode(code)
		require.Truef(t, mapped, "%s has no wire mapping", code)
		ok, why := capability.MintableWireCode(wire)
		assert.Truef(t, ok, "%s mints %d, which eunox may not put on the wire: %s", code, wire, why)
	}
}

// TestWireCodes_ReservedBandIsOnlyReachedByASpecAssignedCode is the half the band check alone
// does not give: that the ONE reserved code eunox emits is emitted because the specification
// assigned it, not because the integer was convenient.
//
// Asserted individually, as the plan asks, because membership in SpecAssignedWireCodes is a claim
// about the spec that no range arithmetic can check. A second entry appearing there is a claim a
// reviewer has to read, and this test is where they are made to.
func TestWireCodes_ReservedBandIsOnlyReachedByASpecAssignedCode(t *testing.T) {
	t.Parallel()
	assert.Equal(t, map[int]string{
		capability.JSONRPCCodeUnsupportedProtocolVersion: "the peer's protocol revision could not be established or could not be bridged",
	}, capability.SpecAssignedWireCodes,
		"a code added here is eunox claiming the MCP specification already assigned it this meaning; that claim is reviewed, not derived")

	assert.Equal(t, capability.WireCodeBandSpecReserved,
		capability.ClassifyWireCode(capability.JSONRPCCodeUnsupportedProtocolVersion),
		"-32022 is in the reserved band, which is exactly why it needs the explicit assignment")

	for _, code := range capability.AllDenialCodes {
		wire, _ := capability.DenialWireCode(code)
		if capability.ClassifyWireCode(wire) != capability.WireCodeBandSpecReserved {
			continue
		}
		_, assigned := capability.SpecAssignedWireCodes[wire]
		assert.Truef(t, assigned,
			"%s mints %d from the band reserved for the specification without naming the assignment it is emitting", code, wire)
	}
}

// wireCodeConstant is one integer constant this module declares inside JSON-RPC's reserved range,
// with where it was found — the position being the whole value of the failure message, since the
// point is to send a contributor to the line they just wrote.
type wireCodeConstant struct {
	name  string
	value int
	where string
}

// TestWireCodes_NoModuleConstantDriftsIntoReservedSpace is the guard the plan's exit criterion
// names: a future code addition cannot drift into reserved space.
//
// It walks EVERY package in the module rather than the two that declare wire codes today. The
// narrow walk is the one that goes stale: a third package minting its own error code is exactly
// the addition that would not think to update a list, and the whole point is that it does not
// have to.
//
// Only CONSTANTS are examined. A bare literal in a struct field would slip past — that gap is
// closed by the sibling guard below rather than by widening this one, because the two want
// different things from the AST and one walk doing both reports neither clearly.
func TestWireCodes_NoModuleConstantDriftsIntoReservedSpace(t *testing.T) {
	t.Parallel()
	found, sawPartitionFile := collectReservedRangeConstants(t)
	require.NotEmpty(t, found,
		"no wire-code constant was found anywhere in the module; the guard passed by walking nothing")
	require.True(t, sawPartitionFile,
		"the exempted partition file was not among the walked sources; a rename would otherwise disable the exemption AND leave the guard reporting green")

	for _, c := range found {
		ok, why := capability.MintableWireCode(c.value)
		assert.Truef(t, ok, "%s: %s = %d is in the %s band and eunox may not mint it: %s",
			c.where, c.name, c.value, capability.ClassifyWireCode(c.value), why)
	}
}

// wireCodePartitionFile is the one file exempt from the constant pin: it DEFINES the partition,
// so its band boundaries (-32768, -32099, -32020) are the rule rather than codes measured against
// it. Holding the definition to itself is circular, and the circularity is not harmless — every
// boundary constant reports as a violation, which is a permanently red guard nobody can read.
//
// A whole-file exemption rather than a per-name one because a boundary is the only kind of
// constant that file holds, and its existence is ASSERTED (sawPartitionFile) so a rename cannot
// quietly turn the exemption into a hole.
const wireCodePartitionFile = "wirecode.go"

// collectReservedRangeConstants finds every integer constant in the module whose value lands in
// JSON-RPC's reserved -32768..-32000, and reports whether the exempted partition file was seen.
//
// Keyed on the VALUE rather than on the name, deliberately: a constant called `retryBudget` set
// to -32021 is on the wire the moment something assigns it to an error code, and a name-shaped
// filter (`*Code*`) would miss it while looking like it covered the question. The value is what
// a peer sees.
func collectReservedRangeConstants(t *testing.T) (found []wireCodeConstant, sawPartitionFile bool) {
	t.Helper()
	for _, dir := range moduleGoPackageDirs(t) {
		for _, src := range packageSourcesIn(t, dir) {
			if src.name == wireCodePartitionFile {
				sawPartitionFile = true
				continue
			}
			for _, decl := range src.file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range value.Names {
						if i >= len(value.Values) {
							// An iota run or a repeated-expression const: no literal of its own to
							// read, and no way for one to carry a wire code.
							continue
						}
						n, ok := reservedRangeIntLiteral(value.Values[i])
						if !ok {
							continue
						}
						found = append(found, wireCodeConstant{
							name:  name.Name,
							value: n,
							where: src.fset.Position(name.Pos()).String(),
						})
					}
				}
			}
		}
	}
	return found, sawPartitionFile
}

// reservedRangeIntLiteral reads a negated integer literal (`-32002`, which parses as a unary
// expression rather than a literal) and reports whether it falls in JSON-RPC's reserved range.
//
// Only the literal form is read. A constant computed from an expression is not resolved: doing
// that means evaluating arbitrary Go, and the alternative to under-reporting there is a guard
// nobody can reason about. Every wire code in this module is written as a literal, which is the
// convention this leans on — and the sibling literal guard fails a computed one at the use site.
func reservedRangeIntLiteral(expr ast.Expr) (int, bool) {
	unary, ok := expr.(*ast.UnaryExpr)
	if !ok || unary.Op != token.SUB {
		return 0, false
	}
	lit, ok := unary.X.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	magnitude, err := strconv.Atoi(lit.Value)
	if err != nil {
		return 0, false
	}
	n := -magnitude
	if n < -32768 || n > -32000 {
		return 0, false
	}
	return n, true
}

// TestWireCodes_NoBareLiteralMintsAnUnmintableCode closes the gap the constant guard leaves: a
// code written straight into an error rather than declared first.
//
// It is the shape that would defeat the other guard entirely — `&mcp.RPCError{Code: -32025}`
// declares no constant to walk.
//
// It forbids an UNMINTABLE value, not every literal. Requiring a constant for its own sake would
// be style enforcement, and it would fail the demo mocks for writing JSON-RPC's own -32600 inline
// — which is a conforming server saying `invalid request` in the language JSON-RPC assigned it,
// exactly what a mock upstream is for. What is not anyone's to write inline, or at all, is an
// integer the specification has reserved.
func TestWireCodes_NoBareLiteralMintsAnUnmintableCode(t *testing.T) {
	t.Parallel()
	walked := 0
	for _, dir := range moduleGoPackageDirs(t) {
		for _, src := range packageSourcesIn(t, dir) {
			walked++
			ast.Inspect(src.file, func(n ast.Node) bool {
				kv, ok := n.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "Code" {
					return true
				}
				value, ok := reservedRangeIntLiteral(kv.Value)
				if !ok {
					return true
				}
				if mintable, _ := capability.MintableWireCode(value); mintable {
					return true
				}
				t.Errorf("%s: an error Code is the bare literal %d, which is in the %s band and may not go on the wire",
					src.fset.Position(kv.Pos()), value, capability.ClassifyWireCode(value))
				return true
			})
		}
	}
	require.NotZero(t, walked, "no sources were walked; the guard is asserting nothing")
}
