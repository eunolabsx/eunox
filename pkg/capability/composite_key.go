// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strconv"
	"strings"
)

// CompositeKey joins prefix and the variadic parts into ONE key whose encoding is
// injective for arbitrary byte content: each part is emitted length-prefixed
// (":" + decimal byte length + ":" + raw bytes), so no ":" or NUL a part contains can
// forge another tuple's key. A plain delimiter join ("seq:"+sessionID+":"+tool) cannot
// promise that, because every component here — a session id, a tool name, an approval id,
// a grant's target — is caller- or host-supplied with no enforced format.
//
// The prefix is emitted VERBATIM, with no length tag, which is what preserves the
// disjoint "seq:" / "maxcalls:" / "declassify:" namespaces the callcounter backends rely
// on. Callers pass colon-free literals at a fixed arity.
//
// It lives in this package, rather than beside the counter keys it was written for,
// because it is the repo's ONE anti-forgery key encoding and it had grown a second
// implementation: DeclassifyApproval.LedgerID built the byte-identical string with a
// fmt.Sprintf of its own, unable to reach an unexported helper in another package. Two
// copies of one encoding means a hardening change to it — escaping, an oversized-component
// hash, a version prefix — lands in one and silently not the other, and the two then
// address different buckets for what an operator wrote as one grant. pkg/enforcement
// already imports this package, so there is one encoder and both call it.
func CompositeKey(prefix string, parts ...string) string {
	// Pre-size the buffer: this runs on every recorded call and every quota check.
	// Over-estimating only sizes the backing array slightly large.
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
