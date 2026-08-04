// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Schema-version negotiation for the documents this proxy loads.
//
// A manifest and a gateway config each declare their grammar via a required `schemaVersion`
// field (two-part, e.g. "0.1", distinct from a manifest's three-part semver `version`). An
// absent or unrecognized version is refused at load rather than parsed under an unmodeled
// grammar, since silently dropping unmodeled fields would weaken enforcement.

package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ManifestSchemaVersion01 is the base published grammar: deny-by-default capability
// authorization over the original closed condition/directive vocabulary. Remains CLOSED — a
// "0.1" manifest using a "0.2" flow+effect token is refused at load. Sourced from
// pkg/capability, whose prototype registry declares each token's introducing revision.
const ManifestSchemaVersion01 = capability.SchemaVersion01

// ManifestSchemaVersion02 is the published flow+effect grammar revision: the information-flow
// tokens, the effect layer, and the claim-populated ${task.*} variables, landed as ONE batched
// bump rather than one token at a time. It replaces the draft staging string those tokens
// shipped behind with no compatibility alias — pre-1.0, a draft is removed once it folds into
// a published revision, so a manifest still declaring the old draft string is refused.
const ManifestSchemaVersion02 = capability.SchemaVersion02

var (
	// supportedManifestSchemaVersions enumerates the manifest grammar versions this build can
	// parse, in publication order. DERIVED from pkg/capability's published sequence rather
	// than restated, so "which revisions parse" and "which revision inherits which token"
	// (an index into this same slice — see revisionAdmits) cannot disagree.
	supportedManifestSchemaVersions = capability.PublishedSchemaVersions()

	// supportedGatewaySchemaVersions enumerates the gateway-config grammar versions this
	// build can parse. No token grammar to order, unlike the manifest set — only membership.
	supportedGatewaySchemaVersions = []string{"0.1"}
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

func validateSchemaVersion(kind, v string, supported []string) error {
	// Trim once and use the trimmed value for both checks: keying the empty check off the
	// trimmed value but membership off the raw one diverged on a padded quoted scalar like " 0.1".
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return fmt.Errorf("%s 'schemaVersion' is required and must be one of [%s]", kind, supportedVersionList(supported))
	case !slices.Contains(supported, v):
		return fmt.Errorf("unsupported %s schemaVersion %q (this build understands [%s])", kind, v, supportedVersionList(supported))
	}
	return nil
}

// supportedVersionList renders the supported set for an error message, in PUBLICATION order
// rather than sorted — sorting version strings is the wrong ordering revisionAdmits avoids.
func supportedVersionList(supported []string) string {
	return strings.Join(supported, ", ")
}

// revisionAdmits reports whether a manifest declaring revision `declared` may carry a token
// introduced by revision `since`: it may when `declared` is `since` or any revision published
// after it. It indexes the published SEQUENCE rather than comparing version strings (which
// breaks on a non-lexical order like "0.10" vs "0.2") or hardcoding the two-revision case (which
// breaks the moment a third, semantics-only revision exists). An unrecognized revision on
// either side admits nothing — fail closed, matching checkTokenRevision's own posture.
func revisionAdmits(declared, since string) bool {
	di := slices.Index(supportedManifestSchemaVersions, declared)
	si := slices.Index(supportedManifestSchemaVersions, since)
	if di < 0 || si < 0 {
		return false
	}
	return di >= si
}
