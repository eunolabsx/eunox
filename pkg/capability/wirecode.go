// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The JSON-RPC server-error partition 2026-07-28 introduced, and which of its bands eunox may
// mint an error code into.
//
// # Why a proxy has to care
//
// JSON-RPC reserves -32768..-32000 and pre-defines a handful inside it; everything else in that
// range was "implementation-defined" and free for anyone. 2026-07-28 subdivides what was free:
// -32000..-32019 stays implementation-defined, and -32020..-32099 becomes the SPEC's, to assign
// as the protocol grows.
//
// That makes an integer eunox mints today into a claim about the future. A code in the reserved
// band is one the specification may later assign a meaning to, at which point every host that
// learned the new meaning reads eunox's denial as that protocol error instead — silently, with
// no version anywhere to notice the collision. It is not a hypothetical: it is what already
// happened in the other direction under 2025-11-25, where eunox's -32001/-32002/-32003 collided
// with that revision's own HeaderMismatch, resource-not-found and
// MissingRequiredClientCapability, so a host could not tell an eunox denial from a protocol
// error. The partition is the fix, and staying inside it is eunox's half of it.
//
// So the bands are vocabulary here rather than a range check in a test: the question "may this
// integer go on the wire" has one answer, and the reason travels with it.

package capability

// WireCodeBand is which part of the JSON-RPC error space a code falls in under the 2026-07-28
// partition.
type WireCodeBand uint8

const (
	// WireCodeBandApplication is outside JSON-RPC's reserved -32768..-32000 entirely: an
	// application's own space, which neither JSON-RPC nor MCP will ever assign.
	WireCodeBandApplication WireCodeBand = iota
	// WireCodeBandPredefined is one of JSON-RPC 2.0's own pre-defined codes. Their meanings are
	// fixed by JSON-RPC rather than by MCP, so a revision cannot reassign one and eunox may use
	// them for what they mean.
	WireCodeBandPredefined
	// WireCodeBandImplementationDefined is -32000..-32019: the band 2026-07-28 leaves to
	// implementations. Everything eunox invents belongs here.
	WireCodeBandImplementationDefined
	// WireCodeBandSpecReserved is -32020..-32099: reserved for the MCP specification. eunox mints
	// into it only where the spec has ALREADY assigned the code and eunox is emitting that
	// assigned meaning — see SpecAssignedWireCodes.
	WireCodeBandSpecReserved
	// WireCodeBandUnassignedReserved is the rest of JSON-RPC's reserved range (-32768..-32100,
	// minus the pre-defined codes). Not MCP's to assign and not eunox's to use; it exists as its
	// own band so a code landing there is reported as what it is rather than as an application
	// code.
	WireCodeBandUnassignedReserved
)

// String names the band for a test failure or an operator-facing message.
func (b WireCodeBand) String() string {
	switch b {
	case WireCodeBandApplication:
		return "application"
	case WireCodeBandPredefined:
		return "JSON-RPC pre-defined"
	case WireCodeBandImplementationDefined:
		return "implementation-defined"
	case WireCodeBandSpecReserved:
		return "reserved for the MCP specification"
	case WireCodeBandUnassignedReserved:
		return "reserved by JSON-RPC and unassigned"
	default:
		return "unknown"
	}
}

// The partition's boundaries, inclusive at both ends. Named rather than written into
// ClassifyWireCode's comparisons so the numbers an operator reads in the docs and the ones the
// classification uses are the same tokens.
const (
	wireCodeReservedLow        = -32768
	wireCodeReservedHigh       = -32000
	wireCodeImplementationLow  = -32019
	wireCodeImplementationHigh = -32000
	wireCodeSpecReservedLow    = -32099
	wireCodeSpecReservedHigh   = -32020
)

// jsonRPCPredefinedCodes are JSON-RPC 2.0's own, whose meanings the MCP specification does not
// get to reassign.
//
// -32000..-32099 is ALSO described by JSON-RPC as "server error", which is exactly the range MCP
// then partitioned; all five listed here sit outside it, so there is no overlap to resolve and
// the two rules do not have to be ordered against each other.
var jsonRPCPredefinedCodes = map[int]string{
	-32700: "parse error",
	-32600: "invalid request",
	-32601: "method not found",
	-32602: "invalid params",
	-32603: "internal error",
}

// ClassifyWireCode reports which band code falls in.
//
// The pre-defined codes are checked FIRST, because -32600..-32603 would otherwise be read
// against the server-error range's arithmetic; they are individually assigned by JSON-RPC and
// belong to no band the MCP partition defines.
func ClassifyWireCode(code int) WireCodeBand {
	if _, ok := jsonRPCPredefinedCodes[code]; ok {
		return WireCodeBandPredefined
	}
	if code > wireCodeReservedHigh || code < wireCodeReservedLow {
		return WireCodeBandApplication
	}
	if code >= wireCodeImplementationLow && code <= wireCodeImplementationHigh {
		return WireCodeBandImplementationDefined
	}
	if code >= wireCodeSpecReservedLow && code <= wireCodeSpecReservedHigh {
		return WireCodeBandSpecReserved
	}
	return WireCodeBandUnassignedReserved
}

// SpecAssignedWireCodes are the reserved-band codes eunox emits, each mapped to the meaning the
// specification assigned it.
//
// Membership is a claim that the spec has ALREADY given the code this meaning and eunox is
// emitting exactly that meaning — never that eunox found the integer convenient. That is the
// whole difference between using a reserved code and squatting on one: the first is
// interoperability, the second is the collision the partition exists to prevent.
//
// A code enters this map only alongside the emission that needs it, which is why it is short: a
// pre-registered entry with no emitter would be this file asserting a spec fact nothing checks.
var SpecAssignedWireCodes = map[int]string{
	JSONRPCCodeUnsupportedProtocolVersion: "the peer's protocol revision could not be established or could not be bridged",
}

// MintableWireCode reports whether eunox may put code in a JSON-RPC error it produces, and why
// not when it may not.
//
// The permitted set is deliberately narrow: what eunox INVENTS goes in the implementation-defined
// band, what it means in JSON-RPC's own terms uses JSON-RPC's own code, and a reserved code is
// permitted only where the spec already assigned it the meaning eunox is sending. Anything else
// is a future collision, so it is refused at build time rather than found by a host.
//
// The reason is returned rather than left to the caller to compose, because the one caller that
// matters is a test failing on a constant somebody just added, and the useful failure names the
// band and the rule rather than the integer they can already see.
func MintableWireCode(code int) (ok bool, why string) {
	switch ClassifyWireCode(code) {
	case WireCodeBandImplementationDefined, WireCodeBandPredefined:
		return true, ""
	case WireCodeBandSpecReserved:
		if meaning, assigned := SpecAssignedWireCodes[code]; assigned {
			return true, meaning
		}
		return false, "the MCP specification reserves -32020..-32099 for itself; a code it has not assigned is one it may assign later, and every host that learns the new meaning would then read this denial as that protocol error"
	case WireCodeBandApplication:
		return false, "JSON-RPC error codes outside -32768..-32000 are an application's own space; a proxy speaking the protocol has no standing to mint one"
	default:
		return false, "JSON-RPC reserves -32768..-32100 and assigns no meaning there; eunox's own codes belong in the implementation-defined band"
	}
}

// ResourceNotFoundWireCode is the integer a revision spells resource-not-found with.
//
// The two revisions disagree, which is the whole reason this is a function. 2025-11-25 assigns
// -32002; 2026-07-28 moves it to -32602, JSON-RPC's own invalid-params code, freeing -32002 into
// the implementation-defined band. A proxy bridging the two has to know both spellings or it
// hands a host an integer from the other revision's dictionary.
//
// Note what the newer spelling COSTS, because it bounds what a translation can honestly do:
// under 2026-07-28 the same -32602 means both "resource not found" and JSON-RPC's own "invalid
// params", so the integer no longer distinguishes them. Old to new is therefore a widening a
// proxy can perform, and new to old a narrowing it cannot — see the boundary's own translation.
func ResourceNotFoundWireCode(rev Revision) int {
	if rev == Revision20260728 {
		return JSONRPCCodeInvalidParams
	}
	return JSONRPCCodeResourceNotFound20251125
}

// JSONRPCCodeResourceNotFound20251125 is 2025-11-25's resource-not-found, spelled out here
// rather than reached for as JSONRPCCodeCapabilityDenied.
//
// The two are the same integer, and that is precisely the collision the partition removed: under
// that revision a host receiving -32002 cannot tell eunox's capability denial from an upstream's
// missing resource. Naming the spec's meaning separately is what keeps a reader of the
// translation from concluding eunox translates its OWN denials, which it does not — the boundary
// wraps the upstream call, so every code it sees came from the upstream.
//
// Revision-suffixed because the value is a fact about one revision. 2026-07-28 gives this meaning
// a different integer, and a bare name would invite exactly the misuse the suffix forecloses.
const JSONRPCCodeResourceNotFound20251125 = -32002
