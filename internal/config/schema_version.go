// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Schema-version negotiation for the documents this proxy loads.
//
// A manifest and a gateway config each declare their grammar via a required
// `schemaVersion` field. An absent or unrecognized version is refused at load
// (fail-closed) rather than parsed under a grammar this build may not model —
// silently dropping unmodeled fields would weaken enforcement.
//
// `schemaVersion` is the grammar version (two-part, e.g. "0.1"), distinct from a
// manifest's policy-content `version` (three-part semver, pinned via
// expectVersion). A build may understand several grammar versions at once; the
// sets below enumerate them.

package config

import (
	"fmt"
	"sort"
	"strings"
)

var (
	// supportedManifestSchemaVersions enumerates the manifest grammar versions
	// this build can parse. Keep in sync with the spec's published
	// schemas/<version>/ directories.
	supportedManifestSchemaVersions = map[string]bool{"0.1": true}

	// supportedGatewaySchemaVersions enumerates the gateway-config grammar
	// versions this build can parse. Keep in sync with
	// schemas/eunox-gateway-config.schema.json.
	supportedGatewaySchemaVersions = map[string]bool{"0.1": true}
)

// validateManifestSchemaVersion fails closed unless v is a manifest grammar
// version this build understands.
func validateManifestSchemaVersion(v string) error {
	return validateSchemaVersion("manifest", v, supportedManifestSchemaVersions)
}

// validateGatewaySchemaVersion fails closed unless v is a gateway-config grammar
// version this build understands.
func validateGatewaySchemaVersion(v string) error {
	return validateSchemaVersion("gateway config", v, supportedGatewaySchemaVersions)
}

func validateSchemaVersion(kind, v string, supported map[string]bool) error {
	// Trim once and use the trimmed value for BOTH the empty check and the membership
	// lookup. Keying the empty check off the trimmed value but membership off the raw
	// value diverged on a padded scalar: a quoted " 0.1" passed the empty check then
	// failed membership with a "0.1 vs 0.1" message that gave no whitespace hint, and
	// a whitespace-only "  " was reported as if the field were absent. (Unquoted YAML
	// strips surrounding whitespace; an explicitly quoted scalar survives both load
	// paths, so this is reachable.) Fail-closed posture is unchanged — a padded
	// version is still only accepted when it trims to a supported one.
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return fmt.Errorf("%s 'schemaVersion' is required and must be one of [%s]", kind, supportedVersionList(supported))
	case !supported[v]:
		return fmt.Errorf("unsupported %s schemaVersion %q (this build understands [%s])", kind, v, supportedVersionList(supported))
	}
	return nil
}

func supportedVersionList(supported map[string]bool) string {
	vs := make([]string, 0, len(supported))
	for v := range supported {
		vs = append(vs, v)
	}
	sort.Strings(vs)
	return strings.Join(vs, ", ")
}
