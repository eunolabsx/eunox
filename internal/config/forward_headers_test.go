// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net/textproto"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every way an allowlist can be wrong, refused at startup where an operator can see it.
//
// The refusal is the point of the key: an allowlist whose bad entries were tolerated and
// silently ignored would read as a granted passthrough that does nothing, which is the failure
// mode an operator only discovers when the upstream behaves as if the header never arrived.
func TestForwardClientHeaders_RefusedEntries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		allow      []string
		authHeader string
		wantErr    string
	}{
		{"wildcard", []string{"*"}, "", "does not accept a wildcard"},
		{"empty entry", []string{"X-Ok", ""}, "", "has an empty entry"},
		{"whitespace entry", []string{"  "}, "", "has an empty entry"},
		{"not a header name", []string{"X Tenant"}, "", "is not a valid HTTP header name"},
		{"colon in name", []string{"X-Tenant: acme"}, "", "is not a valid HTTP header name"},
		{"newline in name", []string{"X-Tenant\r\nX-Evil"}, "", "is not a valid HTTP header name"},
		{"duplicate, same spelling", []string{"X-Tenant-Id", "X-Tenant-Id"}, "", "twice"},
		{"duplicate, different case", []string{"X-Tenant-Id", "x-tenant-id"}, "", "twice"},
		{"reserved: eunox derives it", []string{"Mcp-Name"}, "", "byte-exact"},
		{"reserved, lowercased", []string{"mcp-method"}, "", "byte-exact"},
		{"reserved: the credential", []string{"Authorization"}, "", "upstreamAuthHeader"},
		{"reserved: ambient authority", []string{"Cookie"}, "", "ambient authority"},
		{"reserved: hop-by-hop", []string{"Connection"}, "", "hop-by-hop"},
		{"reserved: the negotiated revision", []string{"MCP-Protocol-Version"}, "", "may not restate"},
		{"this route's own credential", []string{"X-Api-Key"}, "X-Api-Key: ${SECRET}", "replace the credential you configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateForwardClientHeaders("upstream-a", tc.allow, tc.authHeader)
			require.Error(t, err, "the allowlist was accepted")
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Contains(t, err.Error(), "upstream-a", "the error must name the route an operator has to fix")
		})
	}
}

// The entries an operator is meant to write, accepted.
//
// Not vacuous alongside the refusal table: a validator that refused everything would satisfy
// every cell above while making the key unusable.
func TestForwardClientHeaders_AcceptedEntries(t *testing.T) {
	t.Parallel()
	for _, allow := range [][]string{
		nil,
		{},
		{"X-Tenant-Id"},
		{"X-Mcp-Trace", "X-Request-Id", "X-Tenant-Id"},
		{"  X-Tenant-Id  "}, // trimmed, since YAML makes trailing space easy to author
		{"X-Mcp-Header-Tenant"},
	} {
		t.Run(strings.Join(allow, ","), func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, validateForwardClientHeaders("upstream-a", allow, ""))
		})
	}
}

// A route with no `upstreamAuthHeader` has no credential name to collide with, and a malformed
// one names no header — neither may turn into a spurious refusal of a legitimate allowlist.
func TestForwardClientHeaders_CredentialCollisionNeedsARealCredential(t *testing.T) {
	t.Parallel()
	for _, line := range []string{"", "   ", "no-colon-here", ": novalue"} {
		assert.NoError(t, validateForwardClientHeaders("upstream-a", []string{"X-Tenant-Id"}, line),
			"upstreamAuthHeader %q names no header, so it can collide with nothing", line)
	}
}

// CanonicalForwardClientHeaders produces the form net/http keys on, so a lookup at request time
// is a map hit rather than a per-header case-insensitive walk.
func TestForwardClientHeaders_CanonicalizesDedupesAndSorts(t *testing.T) {
	t.Parallel()
	got := CanonicalForwardClientHeaders([]string{"x-tenant-id", "X-Request-ID", " X-Tenant-Id ", "", "x-mcp-trace"})
	assert.Equal(t, []string{"X-Mcp-Trace", "X-Request-Id", "X-Tenant-Id"}, got)
	assert.Nil(t, CanonicalForwardClientHeaders(nil))
	assert.Nil(t, CanonicalForwardClientHeaders([]string{}))
}

// Every reserved name states WHY it is reserved, and states it in the canonical form the lookup
// uses. An entry that fails either is a reservation that never fires or an error an operator
// cannot act on.
func TestForwardClientHeaders_ReservedTableIsUsable(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, ReservedUpstreamHeaders)
	for name, why := range ReservedUpstreamHeaders {
		assert.Equal(t, textproto.CanonicalMIMEHeaderKey(name), name,
			"a non-canonical key would never match a canonicalized lookup")
		assert.NotEmpty(t, why, "%s is reserved with no reason; the operator's error would say nothing", name)
	}
}
