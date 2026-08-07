// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"context"
	"testing"
)

func TestParseRevision(t *testing.T) {
	t.Parallel()
	for _, rev := range PublishedRevisions() {
		got, ok := ParseRevision(rev.String())
		if !ok || got != rev {
			t.Errorf("ParseRevision(%q) = %q, %v; want %q, true", rev, got, ok, rev)
		}
	}
	// Fail closed on everything else: a revision this build cannot speak must never resolve
	// to a Revision a dispatch table can be selected by.
	for _, bad := range []string{"", "auto", "2026-07-27", "2099-01-01", " 2025-11-25", "2025-11-25 ", "latest"} {
		if got, ok := ParseRevision(bad); ok {
			t.Errorf("ParseRevision(%q) = %q, true; want a refusal", bad, got)
		}
	}
}

// TestPublishedRevisions_CallerCannotReorder: the slice is publication order, and the
// negotiation and the refusal payload both read it, so a caller must not be able to
// reorder the sequence in place.
func TestPublishedRevisions_CallerCannotReorder(t *testing.T) {
	t.Parallel()
	first := PublishedRevisions()
	first[0] = "tampered"
	second := PublishedRevisions()
	if second[0] != Revision20251125 {
		t.Errorf("PublishedRevisions()[0] = %q after a caller mutated an earlier copy; want %q", second[0], Revision20251125)
	}
}

func TestRevision_Supported(t *testing.T) {
	t.Parallel()
	if Revision("").Supported() {
		t.Error("the zero Revision must not be Supported: it is 'never negotiated', not a revision")
	}
	if !DefaultRevision.Supported() {
		t.Error("DefaultRevision must itself be a published revision")
	}
	if DefaultRevision != Revision20251125 {
		t.Errorf("DefaultRevision = %q, want the OLDER revision %q: omission must land on the surface eunox already shipped, never on a newer method set", DefaultRevision, Revision20251125)
	}
}

func TestProtocolRevisionContext(t *testing.T) {
	t.Parallel()
	if got := ProtocolRevisionFromContext(context.Background()); got != "" {
		t.Errorf("a context with no revision resolved to %q, want the empty Revision", got)
	}
	ctx := WithProtocolRevision(context.Background(), Revision20260728)
	if got := ProtocolRevisionFromContext(ctx); got != Revision20260728 {
		t.Errorf("ProtocolRevisionFromContext = %q, want %q", got, Revision20260728)
	}
}

// TestUnsupportedProtocolVersion_WireCode pins the one spec-assigned code eunox emits.
// DenialWireCode's fallback is CAPABILITY_DENIED (-32002), so a missing case here would ship
// a policy code for a problem that never reached policy.
func TestUnsupportedProtocolVersion_WireCode(t *testing.T) {
	t.Parallel()
	wire, ok := DenialWireCode(ErrCodeUnsupportedProtocolVersion)
	if !ok {
		t.Fatal("UNSUPPORTED_PROTOCOL_VERSION has no explicit wire mapping; it would ship as CAPABILITY_DENIED")
	}
	if wire != JSONRPCCodeUnsupportedProtocolVersion {
		t.Errorf("wire code = %d, want JSONRPCCodeUnsupportedProtocolVersion (%d)", wire, JSONRPCCodeUnsupportedProtocolVersion)
	}
	// Pinned as a literal too: the constant is only correct if it holds the number the
	// specification assigned, and a test that only compares it to itself proves nothing.
	if JSONRPCCodeUnsupportedProtocolVersion != -32022 {
		t.Errorf("JSONRPCCodeUnsupportedProtocolVersion = %d, want -32022 (assigned by the specification, not chosen by eunox)", JSONRPCCodeUnsupportedProtocolVersion)
	}
}
