#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/build-mcpb.sh — pack ONE Claude Desktop extension (.mcpb) for eunox.
#
# A .mcpb bundle is a plain zip with a manifest.json at its root (the MCP Bundle
# format, https://github.com/modelcontextprotocol/mcpb). We assemble it with
# `zip` directly rather than the Node `mcpb` CLI so no extra toolchain enters the
# release path — matching the repo's minimal-dependency, pinned-tooling posture.
#
# Invoked once per built target:
#   - by the goreleaser build post-hook (.goreleaser.yml) against each freshly
#     built binary, so the bundles land in dist/ BEFORE the checksum/release
#     stages and ride the same signed checksums.txt, SBOM set, and provenance as
#     the archives; and
#   - by `make mcpb` for the host platform (local testing).
#
# The set of platforms is therefore goreleaser's build matrix — the single
# source of truth. An unknown GOOS is a hard error, so adding a release target
# without a mapping here fails the build loudly instead of silently shipping no
# bundle for it.
#
# Usage:
#   scripts/build-mcpb.sh <version> <goos> <goarch> <binary-path> <out-dir>
#
# Produces <out-dir>/eunox_<version>_<goos>_<goarch>.mcpb, plus a
# <bundle>.sbom.json when syft is available (required when MCPB_REQUIRE_SBOM=1,
# which the release sets so every shipped bundle carries an SBOM like every other
# release artifact).

set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <version> <goos> <goarch> <binary-path> <out-dir>" >&2
  exit 2
fi

# Strip a leading v so a "v0.1.0" tag yields a SemVer manifest version.
VERSION="${1#v}"
OS="$2"
ARCH="$3"
SRC="$4"
OUT="$5"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/../packaging/mcpb/manifest.json.tmpl"

for tool in jq zip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is required" >&2; exit 1; }
done
[ -f "$TEMPLATE" ] || { echo "error: manifest template not found: $TEMPLATE" >&2; exit 1; }
[ -f "$SRC" ]      || { echo "error: binary not found: $SRC" >&2; exit 1; }

# Map a GOOS to the MCPB platform id (Node process.platform value) and the
# bundled binary name. An unmapped GOOS is fatal — see the header note on the
# single source of truth.
case "$OS" in
  linux)   platform="linux";  binary="eunox" ;;
  darwin)  platform="darwin"; binary="eunox" ;;
  windows) platform="win32";  binary="eunox.exe" ;;
  *) echo "error: unsupported GOOS '$OS' — add a mapping in $(basename "$0") (did the goreleaser build matrix change?)" >&2; exit 1 ;;
esac

mkdir -p "$OUT"
OUT_ABS="$(cd "$OUT" && pwd)"
out_file="$OUT_ABS/eunox_${VERSION}_${OS}_${ARCH}.mcpb"

echo "==> packing $(basename "$out_file") (platform=$platform)"

bundle="$(mktemp -d)"
trap 'rm -rf "$bundle"' EXIT

cp "$SRC" "$bundle/$binary"
# Desktop hosts execute the bundled binary in place; keep it executable so the
# mode survives in the zip's stored unix attributes (matters on macOS/Linux).
[ "$OS" = "windows" ] || chmod 0755 "$bundle/$binary"

# Escape sed replacement metacharacters (\, &, and the | delimiter) so a value
# is substituted as literal text — defence in depth (a valid SemVer version /
# the controlled platform+binary names never contain these, but a malformed
# value would otherwise corrupt the substitution or abort sed).
sed_repl() { printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'; }

# {{BINARY}} fills entry_point (the literal bundled filename, e.g. eunox.exe
# on windows). mcp_config.command is intentionally the base name "eunox" in
# the template, NOT {{BINARY}}: per the MCPB spec the host appends ".exe" itself
# on Windows, so a literal "...eunox.exe" command risks resolving to
# "eunox.exe.exe". The base name is correct on every platform.
sed -e "s|{{VERSION}}|$(sed_repl "$VERSION")|g" \
    -e "s|{{PLATFORM}}|$(sed_repl "$platform")|g" \
    -e "s|{{BINARY}}|$(sed_repl "$binary")|g" \
    "$TEMPLATE" > "$bundle/manifest.json"

# Fail closed on a botched substitution: any surviving {{...}} marker (a renamed
# placeholder, a sed no-op) must abort rather than ship a bundle with a literal
# "{{VERSION}}" in a field that happens to be truthy.
if grep -q '{{' "$bundle/manifest.json"; then
  echo "error: un-substituted {{...}} placeholder remains in manifest.json" >&2
  cat "$bundle/manifest.json" >&2
  exit 1
fi

# Structural validation: required fields present, binary server wired the way the
# launcher expects, and the user_config key the args reference exists.
jq -e '
  .manifest_version and .name and .version and .description
  and (.author.name)
  and (.server.type == "binary")
  and (.server.entry_point | length > 0)
  and (.server.mcp_config.command | startswith("${__dirname}/"))
  and (.user_config.config_path != null)
' "$bundle/manifest.json" >/dev/null \
  || { echo "error: rendered manifest.json failed validation" >&2; cat "$bundle/manifest.json" >&2; exit 1; }

rm -f "$out_file"
( cd "$bundle" && zip -q -r "$out_file" manifest.json "$binary" )

# SBOM for the binary the bundle ships, mirroring goreleaser's per-archive SBOMs
# so the .mcpb is not the one release artifact without one. syft is present in
# the release job; for local `make mcpb` it is optional unless explicitly
# required.
if command -v syft >/dev/null 2>&1; then
  syft scan "file:$SRC" -o "spdx-json=${out_file}.sbom.json" -q
  echo "    + $(basename "$out_file").sbom.json"
elif [ "${MCPB_REQUIRE_SBOM:-0}" = "1" ]; then
  echo "error: MCPB_REQUIRE_SBOM=1 but syft is not installed" >&2
  exit 1
fi

rm -rf "$bundle"
trap - EXIT
echo "Built $out_file"
