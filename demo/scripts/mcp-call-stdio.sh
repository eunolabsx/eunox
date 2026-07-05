#!/usr/bin/env bash
# demo/scripts/mcp-call-stdio.sh — run a single MCP tool call through the
# eunox stdio proxy backed by mock-mcp-server-stdio.
#
# Usage:
#   bash scripts/mcp-call-stdio.sh <call-body-json>
#
# No Docker required.  The script pipes three messages through the proxy's
# stdin (initialize → notifications/initialized → tools/call) and prints the
# tool-call response.
#
# First run compiles both binaries via go run (~3 s); subsequent runs use the
# Go build cache and are nearly instant.  Run `make build` in the repo root
# and set EUNOX_BIN / STDIO_SERVER_BIN to use pre-built binaries.

set -eo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
POLICY="$REPO_ROOT/demo/manifest.yaml"
AUDIT_LOG="$REPO_ROOT/demo/audit/audit.jsonl"
AUDIT_KEY="$REPO_ROOT/demo/audit/audit.key"
CALL_BODY="${1:?usage: mcp-call-stdio.sh <call-body-json>}"

EUNOX_BIN="${EUNOX_BIN:-}"
STDIO_SERVER_BIN="${STDIO_SERVER_BIN:-}"

mkdir -p "$(dirname "$AUDIT_LOG")"

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"demo-client","version":"1.0"}}}'
INITIALIZED='{"jsonrpc":"2.0","method":"notifications/initialized"}'

# mcp_pipeline — send the three-message conversation through the proxy and
# print the tool-call response (the message with id=2).
#
# Reads PROXY_ARGV and SERVER_ARGV (arrays) from the caller, so a REPO_ROOT
# containing spaces or other IFS characters survives across the call.
mcp_pipeline() {
  # The proxy is now config-only; synthesize a one-upstream stdio config so
  # the dynamic server command (and dev-time `go run` path) doesn't need a
  # committed YAML. Cleaned up on function return.
  local config_file
  config_file=$(mktemp)
  # shellcheck disable=SC2064
  trap "rm -f '$config_file'" RETURN

  local server_bin="${SERVER_ARGV[0]}"
  local args_yaml=""
  local first=1
  local a
  for a in "${SERVER_ARGV[@]:1}"; do
    if [[ $first -eq 1 ]]; then args_yaml="\"$a\""; first=0
    else args_yaml="$args_yaml, \"$a\""
    fi
  done

  {
    cat <<EOF
schemaVersion: "0.1"
transport: stdio
audit:
  log: "$AUDIT_LOG"
  keyPath: "$AUDIT_KEY"
upstreams:
  - name: mock
    transport: stdio
    command: "$server_bin"
    policy:
      - "$POLICY"
EOF
    if [[ -n "$args_yaml" ]]; then
      printf '    args: [%s]\n' "$args_yaml"
    fi
  } >"$config_file"

  {
    printf '%s\n' "$INIT"
    printf '%s\n' "$INITIALIZED"
    printf '%s\n' "$CALL_BODY"
  } | "${PROXY_ARGV[@]}" proxy --config "$config_file" \
      2>/dev/null \
      | while IFS= read -r line; do
          # Branch BEFORE touching jq so the no-jq fallback is actually
          # reachable: with jq we parse the id and pretty-print; without it we
          # match the id=2 response with a plain grep and emit the raw line.
          if command -v jq &>/dev/null; then
            id=$(printf '%s' "$line" | jq -r '.id // empty' 2>/dev/null)
            if [[ "$id" == "2" ]]; then
              printf '%s' "$line" | jq .
              break
            fi
          elif printf '%s' "$line" | grep -Eq '"id"[[:space:]]*:[[:space:]]*2([^0-9]|$)'; then
            printf '%s\n' "$line"
            break
          fi
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
