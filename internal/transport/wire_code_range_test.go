// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
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
//   - Every integer LITERAL anywhere in the module whose value falls in JSON-RPC's reserved
//     -32768..-32000 is mintable — a named constant, a positional call argument, a struct field,
//     anywhere. That covers the codes the transports mint directly, which the denial vocabulary
//     never sees.

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

// TestWireCodes_NoModuleLiteralDriftsIntoReservedSpace is the guard the plan's exit criterion
// names: a future code addition cannot drift into reserved space.
//
// It walks EVERY package in the module rather than the two that declare wire codes today. The
// narrow walk is the one that goes stale: a third package minting its own error code is exactly
// the addition that would not think to update a list, and the whole point is that it does not
// have to.
//
// It examines every reserved-range integer LITERAL, wherever it appears — not just the value of a
// named constant, and not just a `Code:` struct field. Both narrower shapes were tried and both
// had the same hole: `mcp.ErrorResponse(id, -32025, "…")` is the module's most common way to mint
// an error, and it is a positional call argument, so it declares no constant and fills no keyed
// field. A guard that misses the commonest construction site while claiming to close the hazard
// is worse than none.
//
// Keyed on the VALUE rather than on a name, deliberately: a constant called `retryBudget` set to
// -32021 is on the wire the moment something assigns it to an error code, and a name-shaped
// filter (`*Code*`) would miss it while looking like it covered the question. The value is what a
// peer sees.
//
// What it CANNOT see is a code computed rather than written — `base - offset`. Resolving that
// means evaluating arbitrary Go, and the alternative to under-reporting there is a guard nobody
// can reason about. Every wire code in this module is a literal, which is the convention this
// leans on.
func TestWireCodes_NoModuleLiteralDriftsIntoReservedSpace(t *testing.T) {
	t.Parallel()
	found, sawPartitionFile := collectReservedRangeLiterals(t)
	require.NotEmpty(t, found,
		"no wire-code literal was found anywhere in the module; the guard passed by walking nothing")
	require.True(t, sawPartitionFile,
		"the exempted partition file was not among the walked sources; a rename would otherwise disable the exemption AND leave the guard reporting green")

	for _, c := range found {
		ok, why := capability.MintableWireCode(c.value)
		assert.Truef(t, ok, "%s: %d is in the %s band and eunox may not mint it: %s",
			c.where, c.value, capability.ClassifyWireCode(c.value), why)
	}
}

// wireCodeLiteral is one reserved-range integer literal this module writes, with where it was
// found — the position being the whole value of the failure message, since the point is to send a
// contributor to the line they just wrote.
type wireCodeLiteral struct {
	value int
	where string
}

// wireCodePartitionFile is the one file exempt from the pin: it DEFINES the partition, so its
// band boundaries (-32768, -32099, -32020) are the rule rather than codes measured against it.
// Holding the definition to itself is circular, and the circularity is not harmless — every
// boundary constant reports as a violation, which is a permanently red guard nobody can read.
//
// Matched on the PATH, not the basename. A basename match would silently exempt any future
// `wirecode.go` in any package — and `sawPartitionFile` would still pass, because the real file
// was also walked, so the hole would be invisible from here.
//
// A whole-file exemption rather than a per-name one because a boundary is the only kind of code
// that file holds, and its existence is ASSERTED so a rename cannot quietly turn it into a hole.
const wireCodePartitionFile = "pkg/capability/wirecode.go"

// collectReservedRangeLiterals finds every integer literal in the module whose value lands in
// JSON-RPC's reserved -32768..-32000, and reports whether the exempted partition file was seen.
func collectReservedRangeLiterals(t *testing.T) (found []wireCodeLiteral, sawPartitionFile bool) {
	t.Helper()
	for _, dir := range moduleGoPackageDirs(t) {
		for _, src := range packageSourcesIn(t, dir) {
			if isWireCodePartitionFile(src.path) {
				sawPartitionFile = true
				continue
			}
			ast.Inspect(src.file, func(n ast.Node) bool {
				value, ok := reservedRangeIntLiteral(n)
				if !ok {
					return true
				}
				found = append(found, wireCodeLiteral{
					value: value,
					where: src.fset.Position(n.Pos()).String(),
				})
				return true
			})
		}
	}
	return found, sawPartitionFile
}

// isWireCodePartitionFile matches the partition file by its path within the module, normalized so
// the walk's leading "../.." and the platform separator do not decide the answer.
func isWireCodePartitionFile(path string) bool {
	return strings.HasSuffix(filepath.ToSlash(filepath.Clean(path)), wireCodePartitionFile)
}

// reservedRangeIntLiteral reads a negated integer literal (`-32002`, which parses as a unary
// expression rather than a literal) and reports whether it falls in JSON-RPC's reserved range.
//
// Only the NEGATED form is read, which is every wire code: JSON-RPC's error space is entirely
// negative, so a bare positive literal cannot be one.
func reservedRangeIntLiteral(n ast.Node) (int, bool) {
	unary, ok := n.(*ast.UnaryExpr)
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
	value := -magnitude
	if value < -32768 || value > -32000 {
		return 0, false
	}
	return value, true
}
