// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// MCP protocol revisions: the closed set of wire revisions this build speaks, the `_meta`
// key a peer declares one under, and the per-request carrier the audit tape reads.
//
// It lives here rather than in internal/mcp because three layers that may not import that
// package need it: internal/config parses the operator's per-upstream pin, internal/audit
// stamps the decided revision on every record, and internal/pdp is revision-aware without
// taking an internal/mcp dependency. The method-name constants already live here for the
// same reason.

package capability

import (
	"context"
	"slices"
)

// Revision is one published MCP protocol revision, spelled as it appears on the wire.
type Revision string

const (
	// Revision20251125 is the handshake-bearing revision: initialize plus
	// notifications/initialized open a protocol-level session, the server may initiate
	// requests, and a standalone GET carries the server stream.
	Revision20251125 Revision = "2025-11-25"
	// Revision20260728 is the stateless revision: no handshake, the protocol version and
	// client capabilities ride each request's `_meta`, server/discover is mandatory, and
	// subscriptions/listen replaces the resources/subscribe pair.
	Revision20260728 Revision = "2026-07-28"
)

// DefaultRevision is the revision a context that never declared one is served under.
//
// It is deliberately the OLDER revision: omission must land on the surface eunox already
// shipped, so no peer reaches a different method table by leaving a declaration out. A
// newer revision is only ever reached by declaring it.
const DefaultRevision = Revision20251125

// HandshakeRevision returns the revision whose method set defines the `initialize` handshake —
// the one a peer opens a protocol-level session with, and the one every revision after it
// removes in favour of a per-request declaration.
//
// It lives here because two layers that may not import internal/transport need it: the config
// loader, which must refuse a per-upstream pin the host leg could never match, and anything
// else reasoning about which revisions can open a session at all. internal/transport keeps its
// own copy DERIVED from the method registry and asserts the two agree, so the registry stays
// the operational source and this stays the fact other layers may ask for.
func HandshakeRevision() Revision { return Revision20251125 }

// publishedRevisions lists every revision this build speaks, in publication order — the one
// place the sequence is written down, mirroring publishedSchemaVersions. The ordering is
// DATA, not a comparison over date strings; a revision absent from it fails closed.
var publishedRevisions = []Revision{Revision20251125, Revision20260728}

// PublishedRevisions returns the protocol revisions this build speaks, in publication
// order, as a fresh copy so a caller cannot reorder the sequence negotiation reads from it.
func PublishedRevisions() []Revision { return slices.Clone(publishedRevisions) }

// PublishedRevisionNames renders the revisions this build speaks for an operator-facing
// message, in publication order.
//
// One renderer rather than a loop per caller: the config loader's accepted-value error, the
// -32022 refusal's `supported` array and the upstream-handshake notice all name the same set,
// and three copies is three edits (and three chances to disagree) per published revision.
func PublishedRevisionNames() []string {
	revs := publishedRevisions
	names := make([]string, 0, len(revs))
	for _, rev := range revs {
		names = append(names, rev.String())
	}
	return names
}

// ParseRevision resolves a wire protocol-version string to a Revision. ok is false for
// anything this build does not speak — including the empty string — and every caller must
// treat that as a refusal rather than a default.
func ParseRevision(s string) (Revision, bool) {
	rev := Revision(s)
	if rev.Supported() {
		return rev, true
	}
	return "", false
}

// Supported reports whether r is one of the revisions this build speaks. The zero Revision
// is not.
func (r Revision) Supported() bool { return slices.Contains(publishedRevisions, r) }

// String returns the wire spelling of the revision.
func (r Revision) String() string { return string(r) }

// MetaKeyProtocolVersion is the request `_meta` key a 2026-07-28 peer declares its protocol
// revision under. Required on every request of that revision, which is what makes an
// absent or unrecognized value a refusal rather than a negotiation.
const MetaKeyProtocolVersion = "io.modelcontextprotocol/protocolVersion"

// MetaKeyClientCapabilities is the request `_meta` key a 2026-07-28 client states its own
// capabilities under, the per-request replacement for the handshake's `capabilities` object.
//
// eunox only ever WRITES it, on the leg it opens itself, and writes the empty object its
// `initialize` params already offer: a proxy advertises no capabilities of its own to an
// upstream. It is never read off a host message — what a host declares is forwarded verbatim
// like the rest of `_meta`.
const MetaKeyClientCapabilities = "io.modelcontextprotocol/clientCapabilities"

// ResultKeyCacheScope is the `*/list` result member a 2026-07-28 server states the
// cacheability of the response under, and CacheScopePublic/CacheScopePrivate are the two
// values it takes.
//
// eunox only ever CLAMPS it. Every list it emits from an enforced route is
// authorization-context-specific — the entries are the ones this caller may see — so a shared
// cache downstream of the proxy that honored a `public` scope could serve one identity's
// narrowed view to another. The clamp lives at the one encoder every filter path reaches
// (internal/pdp), not here; what lives here is the spelling, because the member is part of a
// revision's result shape and `internal/pdp` may not import the transport package that owns
// the rest of the revision vocabulary.
const (
	ResultKeyCacheScope = "cacheScope"
	CacheScopePublic    = "public"
	CacheScopePrivate   = "private"
)

// ResultKeyResultType is the result member a 2026-07-28 server states the variant of its reply
// under, and ResultTypeComplete is the terminal variant — the exchange finished in this reply.
//
// The member is an OPEN union, which is why only the terminal value is named here. An ABSENT
// member reads as complete (the spec's rule for a server on an earlier revision, and the shape
// every 2025-11-25 upstream produces); a value this build does not recognize is an ambiguity
// rather than a parse detail, and is refused wherever it would have to be acted on, because a
// variant eunox cannot model is one whose loss it cannot bound.
//
// Here for ResultKeyCacheScope's reason: it is part of a revision's result shape, and the
// layers that read or write it may not import the transport package that owns the rest of the
// revision vocabulary.
const (
	ResultKeyResultType = "resultType"
	ResultTypeComplete  = "complete"
)

// BoundResultType renders a peer-supplied `resultType` for an operator-facing message.
//
// The value reaches eunox from an upstream and can be any string the JSON permits, so it takes
// the same treatment every other foreign value that becomes part of an error string takes: a
// length bound and the control-and-line-terminator strip, so an upstream cannot forge log lines
// or drive the operator's terminal through a member eunox quotes back.
func BoundResultType(variant string) string {
	return SanitizeControlRunes(TruncateUTF8(variant, maxReflectedResultTypeBytes))
}

// maxReflectedResultTypeBytes bounds a reflected `resultType`. Generous for any plausible
// variant name and far below anything that would flood a console.
const maxReflectedResultTypeBytes = 64

// revisionCtxKey is the unexported context key the decided revision travels under, so no
// package outside this one can plant a revision the transports did not resolve.
type revisionCtxKey struct{}

// WithProtocolRevision returns ctx carrying the revision this request was decided under.
// The transports set it once, right after negotiation, so every record written downstream
// stamps the same value the dispatch table was chosen by.
func WithProtocolRevision(ctx context.Context, rev Revision) context.Context {
	return context.WithValue(ctx, revisionCtxKey{}, rev)
}

// ProtocolRevisionFromContext returns the revision the request was decided under, or the
// empty Revision when none was resolved (a refusal recorded before negotiation ran).
func ProtocolRevisionFromContext(ctx context.Context) Revision {
	rev, _ := ctx.Value(revisionCtxKey{}).(Revision)
	return rev
}
