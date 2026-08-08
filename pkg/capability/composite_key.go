// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strconv"
	"strings"
)

// CompositeKey joins prefix and the variadic parts into ONE key whose encoding is
// injective for arbitrary byte content: each part is length-prefixed
// (":" + decimal byte length + ":" + raw bytes), so a caller-supplied ":" or NUL in a
// part (a session id, a tool name, a grant target) can never forge another tuple's key.
// The prefix itself is emitted verbatim (no length tag) to preserve the disjoint
// "seq:"/"maxcalls:"/"declassify:" namespaces the callcounter backends rely on.
//
// It is the repo's ONE anti-forgery key encoding, kept here rather than duplicated
// beside each caller (DeclassifyApproval.LedgerID used to reproduce it by hand): a
// hardening change landing in only one copy would make the two address different
// buckets for what an operator wrote as one grant.
func CompositeKey(prefix string, parts ...string) string {
	return CompositeKeyJoin(prefix, parts, nil)
}

// CompositeKeyJoin is CompositeKey with the parts supplied as two groups rather than one
// variadic list, for a caller that already holds them apart: a fixed head and a
// bucket-specific tail (pkg/enforcement's anchoredKey, which builds a route namespace plus an
// anchor plus a per-bucket suffix). Flattening the two into a third slice first cost one heap
// allocation per key built, on a path that runs per quota bucket and per sequenceBlock lookup.
//
// The encoding is CompositeKey's, byte for byte — that function IS this one with an empty
// head — because the key is shared with the in-memory and Redis backends and a divergence
// would silently address a different bucket.
func CompositeKeyJoin(prefix string, head, tail []string) string {
	// Pre-sized; over-estimating only wastes a few bytes of backing array.
	size := len(prefix)
	for _, p := range head {
		size += len(p) + 8
	}
	for _, p := range tail {
		size += len(p) + 8
	}
	var b strings.Builder
	b.Grow(size)
	b.WriteString(prefix)
	writeCompositeParts(&b, head)
	writeCompositeParts(&b, tail)
	return b.String()
}

// writeCompositeParts writes the length-prefixed encoding of parts. The one implementation of
// that encoding, so the two groups above cannot be tagged differently.
func writeCompositeParts(b *strings.Builder, parts []string) {
	for _, p := range parts {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
}
