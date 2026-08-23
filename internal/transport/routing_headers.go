// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The 2026-07-28 routing headers: `Mcp-Method` and `Mcp-Name` on a Streamable HTTP POST, and
// why a proxy is the component that has to check them against the body.
//
// # What they are for, and why the disagreement is the hazard
//
// The revision requires both so an intermediary can route, meter and log a POST WITHOUT parsing
// its body. That is a real convenience and a real hazard in one: the moment anything downstream
// acts on the header instead of the body, a request whose two halves disagree is metered,
// logged and rate-limited as one call while being EXECUTED as another.
//
// eunox is precisely the gateway those headers exist for, and its own decision has never been
// affected — it has always decided on the body. So the risk here is not that eunox is confused;
// it is that eunox FORWARDS a request whose halves disagree, to an upstream or a sidecar that
// trusts the cheap half. Refusing the pair is the only place the disagreement can be caught
// once and for all downstream readers.
//
// The refusal is therefore an ENFORCEMENT-CONFUSION attempt, not a parse error, and is recorded
// as one: `HEADER_MISMATCH` rather than `INVALID_REQUEST`, so an operator grepping the tape for
// someone probing the boundary finds it under its own name.
//
// # Why the wire code is the specification's
//
// -32020 sits in the band 2026-07-28 reserved for itself, which eunox otherwise never mints
// into (see pkg/capability/wirecode.go). It is admissible for exactly the reason that band's
// exemption exists: the spec has ALREADY assigned this integer to this meaning, and eunox is
// emitting that assigned meaning rather than finding the number convenient.
//
// # Scope
//
// Checked only for a peer whose resolved revision DEFINES the headers. A 2025-11-25 POST is
// unchanged — that revision has no such headers, so requiring or reading them would refuse
// ordinary traffic and break the release's own regression invariant.

package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// The routing headers 2026-07-28 requires on a Streamable HTTP POST.
const (
	// RoutingHeaderMethod carries the JSON-RPC method the body invokes.
	RoutingHeaderMethod = "Mcp-Method"
	// RoutingHeaderName carries the TARGET the body addresses — a tool name, a resource URI,
	// a prompt name. A method that addresses nothing named carries no value to agree with.
	RoutingHeaderName = "Mcp-Name"
)

// maxRoutingHeaderBytes bounds what a mismatch refusal will quote back.
//
// The header is caller-supplied and Go's own header limits are generous, so an unbounded quote
// would let a peer size the refusal's message — and with it the audit record's detail, on the
// path an attacker probing this boundary is already on. Far past any real method name or URI.
const maxRoutingHeaderBytes = 256

// routingHeaderTarget is the narrow view of a request's params the header check needs: the one
// field that names what the call addresses.
//
// Decoded through mcp.DecodeParams, the same strict decoder the dispatch handlers use on the
// same bytes, so the two cannot disagree about the name — which is the whole point of checking.
// It carries no `DisallowUnknownFields`, so this narrower struct sees exactly what the fuller
// one does for the field they share.
type routingHeaderTarget struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

// headerMismatch describes a refused routing-header pair: which header disagreed and how.
//
// A typed value rather than a bare error so the audit detail and the host-facing message are
// built from the same facts — a refusal an operator greps for is only useful if the record and
// the wire say the same thing about it.
type headerMismatch struct {
	// header is the one that disagreed, for the audit detail.
	header string
	// reason completes "the <header> header …" and is composed from this build's own
	// vocabulary plus, at most, a bounded quote of what the peer sent.
	reason string
	// target is what the BODY addresses, carried so the record can name it. auditIdentity
	// cannot: it holds only the method, and blanks the identifier for exactly the
	// target-resolving methods an Mcp-Name mismatch is reachable on. Empty for a method that
	// addresses nothing named, and for params this build could not read.
	target string
}

func (m headerMismatch) Error() string {
	return fmt.Sprintf("the %s header %s", m.header, m.reason)
}

// checkRoutingHeaders reports whether r's routing headers agree with the parsed body, for a peer
// on a revision that defines them. It returns nil for every other peer and for an agreeing pair.
//
// Both halves are checked against the SAME decode of the same bytes the dispatcher will act on.
// Re-reading the headers later, or re-decoding the params to compare against, would reintroduce
// exactly the differential this exists to close.
func checkRoutingHeaders(rev capability.Revision, r *http.Request, msg mcp.RPCMsg) error {
	if !declaresPerRequestRevision(rev) {
		return nil
	}
	// A RESPONSE carries no method to route on, so the revision requires no routing headers for
	// one and there is nothing to disagree with. Checked on the shape rather than on the
	// absence of a method string, so a malformed frame that happens to omit `method` is not
	// mistaken for a response.
	if msg.IsResponse() {
		return nil
	}
	// Decoded ONCE, here, and shared by both halves and by the record. The name check needs it
	// to compare against; the method check needs it only so a Mcp-Method refusal can still name
	// the target its body addressed. Non-target and list-shaped methods return before any decode
	// happens, so the common path is unchanged.
	target, named, decodeErr := routingTargetOf(msg)
	if err := checkMethodHeader(r, msg, target); err != nil {
		return err
	}
	return checkNameHeader(r, target, named, decodeErr)
}

// checkMethodHeader holds Mcp-Method to the body's own method.
//
// Required unconditionally: every request and notification names a method, so an absent header
// is a peer omitting something its revision requires, and a downstream reader that routed on it
// would route on nothing.
func checkMethodHeader(r *http.Request, msg mcp.RPCMsg, target string) error {
	fail := func(reason string) error {
		return headerMismatch{header: RoutingHeaderMethod, reason: reason, target: target}
	}
	got := r.Header.Get(RoutingHeaderMethod)
	if got == "" {
		return fail("is required on this revision and was not sent")
	}
	if !headerExpressible(msg.Method) {
		return fail(fmt.Sprintf("cannot describe this body: the method it invokes (%q) does not survive an HTTP header field verbatim",
			boundRoutingHeader(msg.Method)))
	}
	if got != msg.Method {
		// The BODY's method is not quoted: it is the peer's too, but quoting both doubles what
		// a refusal reflects for no added diagnosis — the header is what disagreed.
		return fail(fmt.Sprintf("says %q, which is not the method this body invokes", boundRoutingHeader(got)))
	}
	return nil
}

// checkNameHeader holds Mcp-Name to the target the body addresses.
//
// Required only for a method that ADDRESSES something named, and verified whenever it is
// present. The asymmetry is deliberate: `tools/list` names no target, so demanding a value
// would be eunox inventing a requirement, while a value sent anyway is still a claim about this
// request that a downstream reader may act on — so it must agree or be refused.
//
// A method whose target this build cannot extract is treated as naming nothing rather than
// refused: the extractable set is the enforced methods, and a future method that names a target
// in a shape this file does not know would otherwise be refused for eunox's ignorance rather
// than for a disagreement.
func checkNameHeader(r *http.Request, want string, named bool, decodeErr error) error {
	if decodeErr != nil {
		// Unreadable params are not this check's refusal to make: the dispatcher decodes the
		// same bytes and denies them with a target-bearing INVALID_REQUEST, which says more.
		// Refusing here would replace that with a header complaint about a malformed body.
		return nil
	}
	fail := func(reason string) error {
		return headerMismatch{header: RoutingHeaderName, reason: reason, target: want}
	}
	got := r.Header.Get(RoutingHeaderName)
	if !named {
		if got == "" {
			return nil
		}
		return fail(fmt.Sprintf("says %q, but this method addresses nothing named", boundRoutingHeader(got)))
	}
	if !headerExpressible(want) {
		return fail(fmt.Sprintf("cannot describe this body: the target it addresses (%q) does not survive an HTTP header field verbatim",
			boundRoutingHeader(want)))
	}
	if got == "" {
		return fail("is required for this method and was not sent")
	}
	if got != want {
		return fail(fmt.Sprintf("says %q, which is not the target this body addresses", boundRoutingHeader(got)))
	}
	return nil
}

// routingTargetOf returns the target a message addresses, whether it addresses one at all, and
// an error when the params cannot be read.
//
// The method set is DERIVED from capability.MethodTargetType — the same mapping the audit layer
// stamps `target_type` from — so a method that starts addressing a target is covered here
// without this being remembered. What stays local is which FIELD carries the name per type,
// which is a fact about the params shape rather than about the target.
func routingTargetOf(msg mcp.RPCMsg) (target string, named bool, err error) {
	targetType, ok := capability.MethodTargetType(msg.Method)
	if !ok {
		return "", false, nil
	}
	// An enumeration names its namespace, not an entry in it: `tools/list` addresses the whole
	// catalog, so there is nothing for Mcp-Name to agree with.
	if listShapedResult(msg.Method) {
		return "", false, nil
	}
	var params routingHeaderTarget
	if derr := mcp.DecodeParams(msg.Params, &params); derr != nil {
		return "", false, derr
	}
	switch targetType {
	case capability.TargetTypeResource:
		return params.URI, params.URI != "", nil
	case capability.TargetTypeTool, capability.TargetTypePrompt:
		return params.Name, params.Name != "", nil
	default:
		// TargetTypeSystem (sampling) is upstream-initiated and never arrives as a host POST.
		return "", false, nil
	}
}

// boundRoutingHeader renders a caller-supplied header value for an operator-facing message: a
// length bound and the control-and-line-terminator strip every foreign value takes before it
// becomes part of an error string.
//
// Its own bound rather than BoundConsoleDetail's, which is sized for an upstream's error BODY.
// A routing header names a method or a target, so a value past this length is already not one —
// and the refusal it lands in is on a path a peer probing this boundary controls the rate of.
func boundRoutingHeader(v string) string {
	return capability.SanitizeControlRunes(capability.TruncateUTF8(strings.TrimSpace(v), maxRoutingHeaderBytes))
}

// headerMismatchDetail is the structured audit detail a refused pair records: which header
// disagreed, never the value it carried.
//
// The VALUE is deliberately absent from the tape. It is caller-supplied and bounded only for
// the console; the record already names the method and target the body actually carried, which
// is what an operator correlates on, and putting an attacker-chosen string into a signed
// structured field buys nothing the wire message does not already say.
func headerMismatchDetail(err error) map[string]interface{} {
	var m headerMismatch
	if !asHeaderMismatch(err, &m) {
		return nil
	}
	return map[string]interface{}{detailMismatchedHeader: strings.ToLower(m.header)}
}

// detailMismatchedHeader is the audit detail key naming which routing header disagreed.
const detailMismatchedHeader = "mismatched_header"

// asHeaderMismatch unwraps err into a headerMismatch, reporting whether it was one.
func asHeaderMismatch(err error, out *headerMismatch) bool {
	m, ok := err.(headerMismatch) //nolint:errorlint // headerMismatch is never wrapped: it is built and consumed inside this file.
	if ok {
		*out = m
	}
	return ok
}

// refuseHeaderMismatch records the refused pair and builds the host-facing error, mirroring
// refuseHostRevision: one code on the tape and on the wire, so a host branching on
// `error.data.code` and a SIEM rule reading the record are never told different things.
//
// The record names the method and target the BODY carried, not the header's — the body is what
// eunox would have acted on, and an operator correlating this refusal with the surrounding
// traffic needs the real one. Which header disagreed rides in the structured detail.
func refuseHeaderMismatch(ctx context.Context, rec auditRecorder, sessionID string, msg mcp.RPCMsg, err error) mcp.RPCMsg {
	if rec != nil {
		identifier, method := headerRefusalIdentity(msg, err)
		rec.RecordDeny(ctx, sessionID, identifier, method,
			capability.ErrCodeHeaderMismatch, "", headerMismatchDetail(err), false)
	}
	// A notification carries no id, so JSON-RPC forbids a reply: it is refused — never
	// forwarded — and acked bodyless, the same disposition every other envelope-level refusal
	// on this transport gives one.
	if !msg.IsRequest() {
		return mcp.RPCMsg{}
	}
	return mcp.HeaderMismatchResponse(msg.ID, err.Error())
}

// setRoutingHeaders stamps the routing headers on an outbound upstream POST, for a leg whose
// revision defines them, and refuses the send when a header cannot be made byte-exact with the
// body it describes.
//
// # Why eunox emits its own rather than forwarding the host's
//
// The values are DERIVED from the message actually being sent, through routingTargetOf — the
// same derivation the inbound check holds a host's headers to. A host header is never relayed:
// the request eunox forwards is not always the one it received (a `*/list` may be filtered, a
// stdio host's message never had headers at all, and the opener and drift probe are eunox's
// own), so relaying would propagate a claim about a different body. Deriving means the pair the
// upstream reads describes the bytes the upstream got, which is the property this whole check
// exists for — asserted downstream rather than merely demanded upstream.
//
// # Why an unsendable value is a refusal and not a truncation
//
// A header value is either byte-exact with the body or it is not sent at all. Trimming,
// escaping or truncating a target to fit would MANUFACTURE the disagreement this file refuses
// on the inbound side — an upstream routing on the header would act on a different target than
// the body names, with eunox's own signature on the discrepancy. So a target carrying a byte no
// header field value may hold fails the call before it leaves.
func setRoutingHeaders(req *http.Request, rev capability.Revision, msg mcp.RPCMsg) error {
	if !declaresPerRequestRevision(rev) {
		return nil
	}
	// Gated on there being a method to route ON, where the inbound check gates on the response
	// SHAPE. The polarity differs because the questions do: the check must not let a malformed
	// frame pass as a response, while emission cannot state a route it does not have — a
	// forwarded host response and a frame with no method are both nothing to claim.
	if msg.Method == "" {
		return nil
	}
	if err := setRoutingHeader(req, RoutingHeaderMethod, msg.Method); err != nil {
		return err
	}
	target, named, err := routingTargetOf(msg)
	if err != nil || !named {
		// Unreadable params or a method addressing nothing named: no target to claim. The
		// upstream decodes the same bytes and reaches its own conclusion, which is exactly
		// what a fabricated header would come between.
		return nil
	}
	return setRoutingHeader(req, RoutingHeaderName, target)
}

// setRoutingHeader sets one routing header, or reports why the value could not be sent.
//
// The rejected value is quoted through boundRoutingHeader, not raw: it is the caller's, the
// error reaches an operator's console, and the reason it was rejected is precisely that it
// holds bytes that drive a terminal.
func setRoutingHeader(req *http.Request, name, value string) error {
	if !headerExpressible(value) {
		return fmt.Errorf("cannot forward: %s would have to carry %q, which does not survive an HTTP header field verbatim; the header must be byte-exact with the body and eunox will not alter it to fit", name, boundRoutingHeader(value))
	}
	req.Header.Set(name, value)
	return nil
}

// headerExpressible reports whether v survives an HTTP header field BYTE-EXACT, in both
// directions.
//
// Two rules, and the second is the one that is easy to miss. net/http refuses to write a value
// holding a control byte — that is sendableHeaderValue below. It also TRIMS leading and trailing
// spaces and tabs off every value it writes, while Go's server trims them off every value it
// reads. So a target with surrounding whitespace survives in NEITHER direction: emitting one
// would put a header on the wire that no longer names what the body names, and comparing an
// inbound one against the body would refuse a conformant host over a difference its own HTTP
// stack created.
//
// Neither difference is one eunox may paper over, so both directions refuse rather than trim: a
// value eunox altered to fit would be a header that describes a different call than the body
// does, manufactured by the component whose job is to catch exactly that. A target that cannot
// be described by the header its revision requires is one this proxy does not forward.
func headerExpressible(v string) bool {
	return sendableHeaderValue(v) && v == textproto.TrimString(v)
}

// sendableHeaderValue reports whether v may be sent as an HTTP header field value at all.
//
// Byte-wise and no laxer than net/http's own rule, which the transport would apply anyway —
// stated here so the refusal names the header and the reason instead of surfacing as a generic
// write failure from inside the client, and so it happens before any part of the request goes
// out. High bytes are permitted, as they are there: a UTF-8 tool name is sendable. It is the
// WRITABILITY half alone; byte-exactness is headerExpressible's question.
func sendableHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if b := v[i]; (b < 0x20 && b != '\t') || b == 0x7f {
			return false
		}
	}
	return true
}

// headerRefusalIdentity names a refused message on the tape: the target its BODY addresses when
// one was read, and auditIdentity's answer otherwise.
//
// auditIdentity deliberately blanks the identifier for a method that RESOLVES a target type — it
// holds only the method name, and stamping that would name a tool after the method it was called
// by. This refusal is where that limitation bites hardest: every method an `Mcp-Name` mismatch is
// reachable on is a target-resolving one, so the record was landing with no target at all. It is
// also the one place the target is already in hand, carried on the mismatch by the check that
// compared against it — so what the record names is exactly what was compared, not a second
// decode that could answer differently.
//
// Supplying it is what makes the record correlate with the surrounding traffic, which is the
// reason the header's own attacker-chosen value is left off it.
func headerRefusalIdentity(msg mcp.RPCMsg, err error) (identifier, method string) {
	identifier, method = auditIdentity(msg)
	if identifier != "" {
		return identifier, method
	}
	var m headerMismatch
	if asHeaderMismatch(err, &m) && m.target != "" {
		// Bounded and control-stripped like every other foreign value that reaches a record:
		// this one is the caller's too, and the tape is signed.
		return boundRoutingHeader(m.target), method
	}
	return identifier, method
}
