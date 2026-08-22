// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The 2026-07-28 result shape: the members that revision requires of every result, and the one
// variant eunox refuses to forward.
//
// # Why this is a proxy's problem at all
//
// eunox does not merely relay results — it FILTERS them (`*/list`), REDACTS them
// (`redactFields`), and decides whether the call that produced them was permitted. A revision
// that adds required members to a result therefore adds them to something eunox re-emits, and a
// revision that adds a result VARIANT adds one eunox has to be able to enforce.
//
// Two rules, and they are opposites on purpose:
//
//   - What eunox can supply, it SUPPLIES. A member whose value follows from what eunox already
//     knows — `resultType: "complete"` for a reply that finished, `cacheScope: "private"` for a
//     list it filtered per caller — is added where the upstream omitted it, because a peer on a
//     revision that requires the member gets a conforming result either way.
//   - What eunox cannot model, it REFUSES. An unrecognized `resultType` is not a member eunox
//     can supply a value for; it is a claim about the exchange that eunox has no way to check.
//
// # Why it is applied at the upstream call
//
// One seam, reached by every result a host receives: the enforced forward core's ALLOW tail and
// the `*/list` dispatcher both go through `callUpstream`, and nothing else produces a result
// from an upstream. Applying it at each of them instead would be two call sites to keep in step
// — and the one that drifts is a result reaching a peer without the members its revision
// requires, which fails at that peer with an error naming eunox's own omission as the
// upstream's.
//
// Placing it AT the call rather than at the dispatcher's return also puts the refusal ahead of
// the audit record: a refused result is recorded as a refusal, not as an allow followed by a
// contradiction.
//
// # Why an old-revision peer is untouched
//
// The first branch returns before reading anything. `resultType` and `cacheScope` are members
// 2025-11-25 does not define, so adding either to a result bound for such a peer would be this
// proxy inventing wire content its host has no way to interpret — and the release's own
// regression invariant is that nothing changes for those peers. Held structurally rather than
// by test, though the sweep test asserts it too.

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// errUnenforceableResultShape marks a result eunox will not forward because it cannot model
// what the upstream is claiming about the exchange.
//
// Classified through upstreamErrInfo as an ENFORCEMENT_ERROR rather than an upstream outage:
// the upstream is reachable and answered, and what failed is eunox's ability to reach a verdict
// about the answer. That is the same class the malformed-`*/list`-response refusal already
// records under, and for the same reason.
var errUnenforceableResultShape = errors.New("upstream result carries a variant this proxy cannot enforce")

// applyResultShape returns resp with the members rev requires of a result, or an error for a
// result rev makes eunox responsible for enforcing and eunox cannot.
//
// method selects the members that apply: only the list-shaped results carry cache directives.
func applyResultShape(rev capability.Revision, method string, resp mcp.RPCMsg) (mcp.RPCMsg, error) {
	// A revision that does not define these members gets a byte-identical reply. See the file
	// comment: supplying them would be inventing wire content for a peer that cannot read it.
	if !declaresPerRequestRevision(rev) || len(resp.Result) == 0 {
		return resp, nil
	}
	fields := map[string]json.RawMessage{}
	if err := mcp.DecodeParams(resp.Result, &fields); err != nil {
		// Fails closed on the two shapes a plain Unmarshal reads as successes: a duplicate key
		// (which mcp.DecodeParams refuses, where last-wins would let an upstream show eunox one
		// `resultType` and its host another) and anything that is not an object.
		return mcp.RPCMsg{}, fmt.Errorf("%w: the %s result is not a readable JSON object: %w",
			errUnenforceableResultShape, method, err)
	}
	// A JSON `null` result decodes into a NIL map with no error. Refused rather than replaced
	// with an object: manufacturing a result shape around a value the upstream sent as null
	// invents content, which is the half of this file's rule that does not apply to it.
	if fields == nil {
		return mcp.RPCMsg{}, fmt.Errorf("%w: the %s result is JSON null, which has no place to carry the members %s requires",
			errUnenforceableResultShape, method, rev)
	}
	if err := checkResultTypeEnforceable(rev, method, fields); err != nil {
		return mcp.RPCMsg{}, err
	}
	changed := supplyResultType(fields)
	if listShapedResult(method) && supplyCacheScope(fields) {
		changed = true
	}
	if !changed {
		// The upstream already conforms. Return its own bytes rather than a re-encoding of
		// them: re-marshalling reorders members and re-escapes strings, and a proxy that
		// rewrites a conforming payload for no gain is a proxy whose output a peer cannot
		// diff against its upstream's.
		return resp, nil
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return mcp.RPCMsg{}, fmt.Errorf("%w: re-encoding the %s result: %w", errUnenforceableResultShape, method, err)
	}
	resp.Result = encoded
	return resp, nil
}

// checkResultTypeEnforceable refuses a result whose `resultType` names a variant eunox does not
// model.
//
// The refusal is the point of the open union. `input_required` is the variant that exists today
// and the one that shows why: it means the upstream is WAITING, with `inputRequests` the caller
// must answer, and forwarding it as though the call had finished desynchronizes the exchange
// with no error anywhere. eunox has no response-path enforcement for it yet, so it cannot be
// carried; a variant published after this build has the same property and is refused for the
// same reason rather than being read as complete.
func checkResultTypeEnforceable(rev capability.Revision, method string, fields map[string]json.RawMessage) error {
	variant, present, err := resultTypeOf(fields)
	if err != nil {
		return fmt.Errorf("%w: the %s result's %s member is not a JSON string",
			errUnenforceableResultShape, method, capability.ResultKeyResultType)
	}
	if capability.ResultTypeForwardable(variant, present) {
		return nil
	}
	return fmt.Errorf("%w: the %s result declares %s %q, which this build does not model; forwarding it would tell a %s host the exchange finished when the upstream is still waiting",
		errUnenforceableResultShape, method, capability.ResultKeyResultType,
		capability.BoundResultType(variant), rev)
}

// resultTypeOf reads the `resultType` member, reporting absence for a member that is missing,
// empty, or an explicit JSON null.
//
// Null reads as ABSENT because that is what every other decoder in this codebase does with it —
// `"cursor": null` asks for the first page exactly as an omitted key does, and a null protocol
// declaration inherits its context rather than naming a revision. Treating it as a present
// value instead would leave the member on the wire as null, which is not a value the revision
// defines, so the peer would get a result eunox had declared conforming.
func resultTypeOf(fields map[string]json.RawMessage) (variant string, present bool, err error) {
	raw, ok := fields[capability.ResultKeyResultType]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return "", false, nil
	}
	if err := json.Unmarshal(raw, &variant); err != nil {
		return "", false, err
	}
	return variant, true, nil
}

// supplyResultType adds the terminal variant where the upstream omitted it, reporting whether
// it changed anything.
//
// `complete` is the honest value and the only one available: a reply that reached here is one
// eunox is about to hand the host, and any variant meaning otherwise was refused above.
func supplyResultType(fields map[string]json.RawMessage) bool {
	if _, present, _ := resultTypeOf(fields); present {
		return false
	}
	// Through resultTypeOf, not a bare key probe: a member present as JSON null is ABSENT by
	// this package's reading, and a key probe would leave that null on the wire — a value the
	// revision does not define, in a result eunox had just declared conforming. The error is
	// discarded because an unreadable member was already refused above; reaching here means it
	// is absent or a string.
	fields[capability.ResultKeyResultType] = jsonStringConst(capability.ResultTypeComplete)
	return true
}

// supplyCacheScope adds `private` to a list result that carries no scope, reporting whether it
// changed anything.
//
// This is the SET half of the clamp in internal/pdp, which narrows a scope an upstream DID
// state. The two are split because they need different things: the clamp needs the one encoder
// every filter path reaches, and this needs the revision — which the filter layer does not
// hold. Together they are the whole property: every list eunox emits to a peer on a revision
// that defines the member says `private`, whether the upstream over-shared, under-shared, or
// said nothing.
//
// `private` because eunox filters every list it emits per caller identity, so the entries are
// the ones THIS caller may see. `ttlMs` is deliberately not supplied: it is a freshness hint the
// upstream did not offer, and inventing a lifetime for someone else's data is the fabrication
// the supply half of this file's rule stops short of.
func supplyCacheScope(fields map[string]json.RawMessage) bool {
	if _, present := fields[capability.ResultKeyCacheScope]; present {
		return false
	}
	fields[capability.ResultKeyCacheScope] = jsonStringConst(capability.CacheScopePrivate)
	return true
}

// jsonStringConst encodes a build-time constant as a JSON string. Only ever called with values
// from this build's own closed vocabulary, which is why it can skip the error return every
// general-purpose encoder needs.
func jsonStringConst(value string) json.RawMessage {
	return json.RawMessage(`"` + value + `"`)
}

// listShapedResult reports whether method's result carries the cache directives 2026-07-28
// defines for list-shaped results.
//
// Derived from the registry's own LocalForwards flag rather than a second list of the three
// `*/list` methods, so a fourth enumerating method cannot be added with this half forgotten.
func listShapedResult(method string) bool {
	return methodRegistry[method].LocalForwards
}

// withResultShape wraps a leg's upstream call so every result a host receives crosses the shape
// rules once. See the file comment for why this is the seam.
func withResultShape(inner func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error)) func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
	if inner == nil {
		// nil is a MODE the forward core and dispatchList both read (a leg with no upstream), so
		// it must survive wrapping rather than becoming a non-nil func that fails on use.
		return nil
	}
	return func(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
		resp, err := inner(ctx, msg)
		if err != nil {
			return resp, err
		}
		return applyResultShape(requestRevision(ctx), msg.Method, resp)
	}
}
