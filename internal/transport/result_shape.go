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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
// observe marks the `--audit` wiretap posture, which exempts the cache scope (see
// supplyCacheScope).
//
// # Why this reads the body itself rather than decoding it
//
// The obvious implementation — decode to a map, add what is missing, re-marshal — is wrong
// twice over, and both were live before this comment existed.
//
// It over-refuses. eunox's strict decoder rejects fold-equal duplicate keys at EVERY nesting
// depth, which is right for host params forwarded verbatim into a struct-binding upstream and
// wrong here: a conforming upstream answering `{"structuredContent":{"id":1,"ID":2}}` is
// carrying two legal sibling fields in ITS OWN payload, and hard-refusing that after the tool
// has already run turns a proxy into a compatibility hazard. The differential eunox actually
// has to care about is at the TOP level, in the two members it reads and writes — so that is
// where the duplicate check sits, and nothing below it is eunox's business.
//
// And it rewrites payloads gratuitously. Re-marshalling reorders members, re-escapes strings
// and costs a full walk of a body that may be megabytes, on every call, for the sake of one
// short member. Splicing the member in front of the upstream's own bytes preserves them
// exactly and costs one copy.
func applyResultShape(rev capability.Revision, method string, observe bool, resp mcp.RPCMsg) (mcp.RPCMsg, error) {
	// A revision that does not define these members gets a byte-identical reply. See the file
	// comment: supplying them would be inventing wire content for a peer that cannot read it.
	if !declaresPerRequestRevision(rev) || len(resp.Result) == 0 {
		return resp, nil
	}
	members, err := scanResultMembers(resp.Result)
	if err != nil {
		return mcp.RPCMsg{}, fmt.Errorf("%w: the %s result %s", errUnenforceableResultShape, method, err)
	}
	if err := checkResultTypeEnforceable(rev, method, members); err != nil {
		return mcp.RPCMsg{}, err
	}
	body := resp.Result
	var add []string
	// Three cases for the variant, and the middle one is the reason this is not a bare
	// "is the key there" test: a member present as an explicit JSON null is ABSENT by this
	// package's reading, but its bytes are still on the wire, so it is OVERWRITTEN where it
	// sits. Splicing a second copy in front of it would leave the body carrying the member
	// twice, with a last-wins host reading the null. The overwrite shifts nothing before
	// bodyStart, so the splice below still works on unchanged offsets.
	switch _, stated, _ := members.resultType(); {
	case stated:
		// The upstream said something this build models; its bytes stand.
	case members.resultTypePresent:
		body = replaceRange(body, members.resultTypeAt, `"`+capability.ResultTypeComplete+`"`)
	default:
		add = append(add, memberLiteral(capability.ResultKeyResultType, capability.ResultTypeComplete))
	}
	if supplyCacheScope(method, observe, members) {
		add = append(add, memberLiteral(capability.ResultKeyCacheScope, capability.CacheScopePrivate))
	}
	if len(add) == 0 {
		// Either the upstream already conformed — its own bytes go on untouched — or the only
		// change was the null overwrite above.
		resp.Result = body
		return resp, nil
	}
	resp.Result = spliceMembers(body, members, add)
	return resp, nil
}

// replaceRange returns body with the half-open byte range at replaced by value, leaving every
// other byte of the upstream's payload exactly as it arrived.
func replaceRange(body json.RawMessage, at [2]int, value string) json.RawMessage {
	out := make([]byte, 0, len(body)-(at[1]-at[0])+len(value))
	out = append(out, body[:at[0]]...)
	out = append(out, value...)
	return append(out, body[at[1]:]...)
}

// resultMembers is what one top-level pass over a result body establishes: whether each member
// eunox reads or writes is present, what `resultType` says, and where the upstream's own
// members begin so a splice can go in front of them.
type resultMembers struct {
	resultTypePresent bool
	// resultTypeRaw is the member's value bytes, empty when absent, and resultTypeAt is the
	// half-open byte range those bytes occupy in the original body — so a member present with a
	// value the revision does not define (a JSON null) can be REPLACED in place rather than
	// having a second copy spliced in front of it, which would leave the body carrying the
	// member twice and a last-wins host reading the null.
	resultTypeRaw     json.RawMessage
	resultTypeAt      [2]int
	cacheScopePresent bool
	// bodyStart indexes the byte after the opening brace; empty reports an object with no
	// members, which needs no separating comma when a member is spliced in.
	bodyStart int
	empty     bool
}

// scanResultMembers walks the TOP LEVEL of a result object once, without descending into any
// value.
//
// Duplicates are refused for the two members eunox acts on, in FOLD space — an upstream sending
// both `resultType` and `ResultType` is showing eunox one variant and a case-insensitive host
// another, which is the parser differential the strict decoder exists to close. It is checked
// here rather than by that decoder because the decoder's version reaches every nesting depth,
// and a duplicate three levels down inside `structuredContent` is the upstream's own payload
// rather than anything eunox reads.
//
// Errors are phrased as sentence fragments that complete "the <method> result …" and NEVER
// embed the offending key or the decoder's message: an upstream must not be able to size or
// style a host-facing error through a name it chose.
func scanResultMembers(result json.RawMessage) (resultMembers, error) {
	var m resultMembers
	dec := json.NewDecoder(bytes.NewReader(result))
	tok, err := dec.Token()
	if err != nil {
		return m, errors.New("is not readable JSON")
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return m, errors.New("is not a JSON object")
	}
	m.bodyStart = int(dec.InputOffset())
	m.empty = true
	// One buffer for every member's value. json.RawMessage's decoder appends into the existing
	// slice, so after the first member this reuses capacity instead of allocating per member —
	// which on a catalog with many top-level fields was most of the pass's cost. The one value
	// that outlives the loop is COPIED out below, since the next member overwrites this.
	var raw json.RawMessage
	for dec.More() {
		m.empty = false
		keyTok, err := dec.Token()
		if err != nil {
			return m, errors.New("has an unreadable member name")
		}
		key, ok := keyTok.(string)
		if !ok {
			return m, errors.New("has a non-string member name")
		}
		// The value is consumed as RAW bytes: this is what keeps the pass shallow, and what
		// keeps a legal duplicate inside a nested object out of eunox's way.
		if err := dec.Decode(&raw); err != nil {
			return m, errors.New("has an unreadable member value")
		}
		// InputOffset lands exactly past the value, and Decode captured exactly the value's
		// bytes, so the difference is where they start — true regardless of the whitespace the
		// upstream chose around the colon.
		end := int(dec.InputOffset())
		// strings.EqualFold rather than capability.FoldJSONKey: that function's own contract is
		// that the two agree exactly ("canonicalCaseFold(a) == canonicalCaseFold(b) exactly when
		// strings.EqualFold(a, b) reports true"), and EqualFold allocates nothing where folding
		// a key mints a string per member on a path every call takes.
		switch {
		case strings.EqualFold(key, capability.ResultKeyResultType):
			if m.resultTypePresent {
				return m, errors.New("declares its result variant twice, so this proxy and the host could read different ones")
			}
			// Copied, not aliased: the buffer above is reused by the next member.
			m.resultTypePresent = true
			m.resultTypeRaw = append(json.RawMessage(nil), raw...)
			m.resultTypeAt = [2]int{end - len(raw), end}
		case strings.EqualFold(key, capability.ResultKeyCacheScope):
			if m.cacheScopePresent {
				return m, errors.New("declares its cache scope twice, so this proxy and the host could read different ones")
			}
			m.cacheScopePresent = true
		}
	}
	return m, nil
}

// spliceMembers inserts add in front of the upstream's own members, leaving every byte of the
// original body after the opening brace untouched — no reordering, no re-escaping, one copy.
func spliceMembers(result json.RawMessage, m resultMembers, add []string) json.RawMessage {
	joined := strings.Join(add, ",")
	out := make([]byte, 0, len(result)+len(joined)+1)
	out = append(out, result[:m.bodyStart]...)
	out = append(out, joined...)
	if !m.empty {
		out = append(out, ',')
	}
	return append(out, result[m.bodyStart:]...)
}

// memberLiteral renders one JSON object member from this build's own closed vocabulary, which
// is why it needs no escaping and no error return.
func memberLiteral(key, value string) string {
	return `"` + key + `":"` + value + `"`
}

// checkResultTypeEnforceable refuses a result whose `resultType` names a variant eunox does not
// model.
//
// The refusal is the point of the open union. `input_required` is the variant that exists today
// and the one that shows why: it means the upstream is WAITING, with `inputRequests` the caller
// must answer, so forwarding it as though the call had finished desynchronizes the exchange
// with no error anywhere. eunox has no response-path enforcement for it yet, so it cannot be
// carried; a variant published after this build has the same property and is refused for the
// same reason rather than being read as complete.
func checkResultTypeEnforceable(rev capability.Revision, method string, m resultMembers) error {
	variant, present, err := m.resultType()
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

// resultType decodes the scanned member, reporting absence for a member that is missing or an
// explicit JSON null.
//
// Null reads as ABSENT because that is what every other decoder in this codebase does with it —
// `"cursor": null` asks for the first page exactly as an omitted key does, and a null protocol
// declaration inherits its context. Treating it as a present value instead would leave the
// member on the wire as null, which is not a value the revision defines, so the peer would get
// a result eunox had declared conforming.
func (m resultMembers) resultType() (variant string, present bool, err error) {
	if !m.resultTypePresent || len(m.resultTypeRaw) == 0 || string(m.resultTypeRaw) == "null" {
		return "", false, nil
	}
	if err := json.Unmarshal(m.resultTypeRaw, &variant); err != nil {
		return "", false, err
	}
	return variant, true, nil
}

// supplyCacheScope reports whether `private` should be added to this result.
//
// This is the SET half of the clamp in internal/pdp, which narrows a scope an upstream DID
// state. The two are split because they need different things: the clamp needs the one encoder
// every filter path reaches, and this needs the revision — which the filter layer does not
// hold. Together they are the whole property: every list eunox FILTERS says `private`, whether
// the upstream over-shared, under-shared, or said nothing.
//
// `private` because eunox filters every list it emits per caller identity, so the entries are
// the ones THIS caller may see. `ttlMs` is deliberately not supplied: it is a freshness hint the
// upstream did not offer, and inventing a lifetime for someone else's data is the fabrication
// the supply half of this file's rule stops short of.
//
// The `--audit` wiretap is EXEMPT, matching pdp.passThroughList: that posture forwards the
// upstream's whole catalog, identical for every caller, so nothing about the response depended
// on who asked and there is no narrowed view for a shared cache to leak. Stamping `private`
// there would contradict the exemption the clamp, the conformance table and threat-model L-6 all
// state — and it is a claim about the response that would not be true. `resultType` is NOT
// exempt: it describes the exchange, not who the response was for, and a peer on this revision
// requires it either way.
func supplyCacheScope(method string, observe bool, m resultMembers) bool {
	return listShapedResult(method) && !observe && !m.cacheScopePresent
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
//
// observe is the leg's `--audit` posture, which the wrapper must be TOLD: it sits at the
// upstream call, below the dispatcher that knows it, and the one member the wiretap exempts
// would otherwise be stamped onto a catalog that is identical for every caller.
//
// Built per message rather than hoisted onto the session, deliberately. Hoisting would save a
// closure — tens of bytes against the ~2 KB the shape pass itself moves on the same call — at
// the cost of the source guard that keeps every construction site wrapped, which would have to
// start reasoning about a stored field's provenance instead of a call it can see. The
// invariant is worth more than the allocation.
func withResultShape(observe bool, inner func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error)) func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
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
		return applyResultShape(requestRevision(ctx), msg.Method, observe, resp)
	}
}
