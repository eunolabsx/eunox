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
	"slices"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ManifestSchemaVersion01 is the base published grammar: deny-by-default capability
// authorization over the original closed condition/directive vocabulary. It remains
// supported and remains CLOSED — none of the flow+effect tokens introduced by "0.2"
// is part of it, and a "0.1" manifest that uses one is refused at load.
//
// The string comes from pkg/capability rather than being spelled again here: the vocabulary's
// prototype registry declares each token's introducing revision, and the loader's gate
// compares a manifest's declared version against it. Two literals for one revision is one
// more place for the gate's two sides to disagree.
const ManifestSchemaVersion01 = capability.SchemaVersion01

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
//
// Single-sourced from pkg/capability for the same reason as the base revision above.
const ManifestSchemaVersion02 = capability.SchemaVersion02

var (
	// supportedManifestSchemaVersions enumerates the manifest grammar versions this build
	// can parse, in publication order. Keep in sync with the published
	// schemas/eunox-capability-manifest.schema.json. A build understands every published
	// revision at once; which tokens a document may use is decided per revision by each
	// token's own capability.TokenSince against this order, not by membership alone.
	//
	// DERIVED from pkg/capability's published sequence rather than restated, so "which
	// revisions parse" and "which revision inherits which token" cannot disagree — the second
	// is an index into this same slice (see revisionAdmits). It is a package var rather than
	// a call per use so a test can publish a synthetic revision and drive the whole loader
	// under it, which is the only way to cover a third revision before there is one.
	supportedManifestSchemaVersions = capability.PublishedSchemaVersions()

	// supportedGatewaySchemaVersions enumerates the gateway-config grammar
	// versions this build can parse. Keep in sync with
	// schemas/eunox-gateway-config.schema.json. The gateway config has no token grammar,
	// so it needs no ordering — only membership.
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
	case !slices.Contains(supported, v):
		return fmt.Errorf("unsupported %s schemaVersion %q (this build understands [%s])", kind, v, supportedVersionList(supported))
	}
	return nil
}

// supportedVersionList renders the supported set for an error message. The versions are
// listed in PUBLICATION order rather than sorted: the sequence is what a reader needs (it is
// what decides which tokens each revision admits), and sorting version strings is the same
// wrong ordering the gate itself deliberately avoids.
func supportedVersionList(supported []string) string {
	return strings.Join(supported, ", ")
}

// revisionAdmits reports whether a manifest declaring revision `declared` may carry a token
// introduced by revision `since`: it may when `declared` is `since` or any revision published
// after it. A revision therefore inherits every earlier revision's vocabulary and stays CLOSED
// against every later one's, which is the gate's whole job.
//
// It indexes the published SEQUENCE (supportedManifestSchemaVersions, derived from
// pkg/capability's list) rather than comparing the version strings, and rather than spelling
// the two-revision case as a boolean. Both alternatives break silently on the third revision:
// a string compare inverts the first time a revision is not orderable lexically ("0.10" sorts
// before "0.2"), and "the base grammar plus an exact match" refused every `0.2` token under a
// semantics-only `0.3` that introduced none. Publishing a revision is an append to one
// ordered list; nothing here is re-derived for it.
//
// An unrecognized revision on either side admits nothing — the fail-closed direction, and the
// same one checkTokenRevision takes for a token this build cannot classify at all.
func revisionAdmits(declared, since string) bool {
	di := slices.Index(supportedManifestSchemaVersions, declared)
	si := slices.Index(supportedManifestSchemaVersions, since)
	if di < 0 || si < 0 {
		return false
	}
	return di >= si
}
