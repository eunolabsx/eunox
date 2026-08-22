#!/usr/bin/env bash
# demo/scripts/mcp-call-stateless.sh — run a single MCP message through the eunox
# stdio proxy against a mock-mcp-server-stdio pinned to the 2026-07-28 revision.
#
# Usage:
#   bash scripts/mcp-call-stateless.sh <message-json>
#
# The stateless twin of mcp-call-stdio.sh. Three differences, all of them the
# revision's:
#
#   1. No handshake. 2026-07-28 removed `initialize` and `notifications/initialized`,
#      so the conversation is the one message and nothing else.
#   2. Every request declares its own protocol version in `params._meta`. The mock
#      refuses a request that does not, which is what proves eunox declares on the
#      requests it originates and forwards a host's declaration untouched.
#   3. The upstream is pinned with `protocolVersion: "2026-07-28"`, which selects the
#      opener (`server/discover`). eunox does not probe for an upstream's revision.
#
# STDIO ONLY, deliberately. An HTTP session is opened by `initialize`, which this
# revision does not have, so `eunox` refuses a 2026-07-28 pin over the HTTP host
# transport outright. The Docker walkthrough gains its stateless variant when
# session creation stops being anchored on the handshake.
#
# No Docker required. First run compiles both binaries via go run; set EUNOX_BIN /
# STDIO_SERVER_BIN (after `make build`) to use pre-built ones.

set -eo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
POLICY="$REPO_ROOT/demo/manifest.yaml"
AUDIT_LOG="$REPO_ROOT/demo/audit/audit.jsonl"
AUDIT_KEY="$REPO_ROOT/demo/audit/audit.key"
CALL_BODY="${1:?usage: mcp-call-stateless.sh <message-json>}"
REVISION="2026-07-28"

EUNOX_BIN="${EUNOX_BIN:-}"
STDIO_SERVER_BIN="${STDIO_SERVER_BIN:-}"

mkdir -p "$(dirname "$AUDIT_LOG")"

# mcp_pipeline — send the single message through the proxy and print the response.
#
# Reads PROXY_ARGV and SERVER_ARGV (arrays) from the caller, so a REPO_ROOT
# containing spaces or other IFS characters survives across the call.
mcp_pipeline() {
  local config_file
  config_file=$(mktemp)
  # shellcheck disable=SC2064
  trap "rm -f '$config_file'" RETURN

  local server_bin="${SERVER_ARGV[0]}"
  local args_yaml=""
  local first=1
  local a
  # The mock's own --protocol-version is appended here rather than baked into
  # SERVER_ARGV, so the `go run` and pre-built-binary forms carry it identically.
  for a in "${SERVER_ARGV[@]:1}" --protocol-version "$REVISION"; do
    if [[ $first -eq 1 ]]; then args_yaml="\"$a\""; first=0
    else args_yaml="$args_yaml, \"$a\""
    fi
  done

  cat >"$config_file" <<EOF
schemaVersion: "0.1"
transport: stdio
audit:
  log: "$AUDIT_LOG"
  keyPath: "$AUDIT_KEY"
upstreams:
  - name: mock
    transport: stdio
    command: "$server_bin"
    args: [$args_yaml]
    protocolVersion: "$REVISION"
    policy:
      - "$POLICY"
EOF

  printf '%s\n' "$CALL_BODY" \
    | "${PROXY_ARGV[@]}" proxy --config "$config_file" \
        2>/dev/null \
    | while IFS= read -r line; do
        # Any response at all is the one we sent: the conversation is one message.
        if command -v jq &>/dev/null; then
          printf '%s' "$line" | jq .
        else
          printf '%s\n' "$line"
        fi
        break
      done
}

if [[ -n "$EUNOX_BIN" && -n "$STDIO_SERVER_BIN" ]]; then
  PROXY_ARGV=( "$EUNOX_BIN" )
  SERVER_ARGV=( "$STDIO_SERVER_BIN" )
else
  PROXY_ARGV=( go run "$REPO_ROOT/cmd/eunox" )
  SERVER_ARGV=( go run "$REPO_ROOT/demo/mock-mcp-server-stdio" )
fi
mcp_pipeline
