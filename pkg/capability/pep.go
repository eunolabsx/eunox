// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Enforcement-point identity: the protocol binding a policy-enforcement point enforces at,
// the operator's name for the instance, and the single stamp the audit tape carries for the
// pair.
//
// It lives here for the reason the protocol-revision vocabulary does: internal/config parses
// the operator's name and internal/audit stamps the resolved value on every record, and
// neither of those may import the other.

package capability

import (
	"fmt"
	"regexp"
)

// Binding names the protocol surface a policy-enforcement point enforces at.
//
// It is half of the enforcement-point stamp rather than an assumed constant because the
// surface is what makes two tapes joinable: an agent reaching a tool through MCP on one hop
// and through a different binding on the next has crossed a boundary that the operator's
// instance name alone does not describe.
type Binding string

// BindingMCP is the MCP tool-call boundary — the only binding this build enforces at.
const BindingMCP Binding = "mcp"

// String returns the wire spelling of the binding.
func (b Binding) String() string { return string(b) }

// enforcementPointIDRe constrains an enforcement point's operator-chosen name, following
// routeNameRe's rule with '.' added for the dotted names hosts and regions carry.
//
// It excludes the ':' the stamp joins on, so the two halves stay separable, and every other
// byte an operator could smuggle in: an unexpanded "$VAR" (an env reference whose variable
// was never set survives expansion as literal text, and a tape stamped with it names an
// enforcement point that does not exist), whitespace, and anything a terminal or a SIEM
// query would have to escape.
var enforcementPointIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// MaxEnforcementPointIDBytes bounds an enforcement point's name. It is stamped on EVERY
// record of the tape, so its cost is per record rather than per configuration; 128 bytes is
// far past any name an operator reads back in an alert and far short of the envelope cap
// that exists for values eunox does not choose.
const MaxEnforcementPointIDBytes = 128

// EnforcementPoint is the audit tape's identity for one policy-enforcement point: the
// binding it enforces at and the operator's name for the instance, joined as
// "<binding>:<id>" (the shape policy_sha256 and prev_hmac already use, where a value names
// its own domain).
//
// One value rather than two fields because the pair is only meaningful jointly — the same
// instance name at two bindings is two enforcement points, and a reconstruction keying on
// the name alone would fuse them — and because a single value cannot be half-stamped, where
// two could put a binding on the tape with no instance behind it.
type EnforcementPoint string

// NewEnforcementPoint validates an operator-supplied enforcement-point name and returns the
// stamp for it at the binding this build enforces.
//
// The binding is pinned here rather than taken as a parameter: eunox enforces at the MCP
// boundary and nowhere else, so a stamp naming a surface no code in this build polices would
// be an unfalsifiable claim on a signed tape.
func NewEnforcementPoint(id string) (EnforcementPoint, error) {
	switch {
	case id == "":
		return "", fmt.Errorf("enforcement-point name must not be empty (omit it entirely to stamp no enforcement point)")
	case len(id) > MaxEnforcementPointIDBytes:
		return "", fmt.Errorf("enforcement-point name is %d bytes, over the %d-byte limit; it is stamped on every audit record, so it must stay short enough to read back in an alert", len(id), MaxEnforcementPointIDBytes)
	case !enforcementPointIDRe.MatchString(id):
		return "", fmt.Errorf("enforcement-point name %q must match %s (an unset ${VAR} reference or a stray ':' is refused rather than stamped onto the signed tape)", id, enforcementPointIDRe.String())
	}
	return EnforcementPoint(BindingMCP.String() + ":" + id), nil
}

// String returns the stamp as it appears on the tape, or "" when no enforcement point is
// configured.
func (p EnforcementPoint) String() string { return string(p) }
