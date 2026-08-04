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
	// Pre-sized; over-estimating only wastes a few bytes of backing array.
	size := len(prefix)
	for _, p := range parts {
		size += len(p) + 8
	}
	var b strings.Builder
	b.Grow(size)
	b.WriteString(prefix)
	for _, p := range parts {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	return b.String()
}
