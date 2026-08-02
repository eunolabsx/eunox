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

// ManifestSchemaVersion01 is the base published grammar: deny-by-default capability
// authorization over the original closed condition/directive vocabulary. It remains
// supported and remains CLOSED — none of the flow+effect tokens introduced by "0.2"
// is part of it, and a "0.1" manifest that uses one is refused at load.
const ManifestSchemaVersion01 = "0.1"

// ManifestSchemaVersion02 is the published flow+effect grammar revision. It adds the
// information-flow tokens (the flowLabel condition, the labelOutput and declassify
// directives), the effect layer (the effectClass and blastRadius conditions, a
// constraint's effect contract, the top-level effectCeiling), and the claim-populated
// ${task.*} variables — landed as ONE batched bump rather than one token at a time, so
// the grammar has exactly two published revisions rather than a version per predicate.
//
// It replaces the draft staging vehicle those tokens shipped behind while the batch was
// being assembled. There is no compatibility alias: pre-1.0, a draft is a staging vehicle
// that is REMOVED once it folds into a published revision, so a manifest still declaring
// the old draft string is refused, with the supported list naming this version. Leaving
// the draft accepted as a synonym would leave two spellings of one grammar in the wild
// and a second version string every future gate has to remember.
const ManifestSchemaVersion02 = "0.2"

var (
	// supportedManifestSchemaVersions enumerates the manifest grammar versions
	// this build can parse. Keep in sync with the published
	// schemas/eunox-capability-manifest.schema.json. A build understands both
	// revisions at once; which tokens a document may use is decided per revision by
	// tokenGrammarVersions, not by this set.
	supportedManifestSchemaVersions = map[string]bool{ManifestSchemaVersion01: true, ManifestSchemaVersion02: true}

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
