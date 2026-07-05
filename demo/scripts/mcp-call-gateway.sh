#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/scripts/mcp-call-gateway.sh — initialize a session on a gateway route,
# then make a single tool call against that route.
#
# Usage:
#   bash scripts/mcp-call-gateway.sh <route> <call-body-json> [bearer-token]
#
# Arguments:
#   route            Gateway route name → POSTs to http://localhost:3000/mcp/<route>.
#   call-body-json   Full JSON-RPC tools/call request body.
#   bearer-token     Optional. If set, passed as Authorization: Bearer <token>.

set -eo pipefail

HOST="${MCP_HOST:-http://localhost:3000}"
ROUTE="${1:?usage: mcp-call-gateway.sh <route> <call-body-json> [token]}"
CALL_BODY="${2:?usage: mcp-call-gateway.sh <route> <call-body-json> [token]}"
BEARER="${3:-}"
URL="$HOST/mcp/$ROUTE"

mcp_curl() {
  if [[ -n "$BEARER" ]]; then
    curl "$@" -H "Authorization: Bearer $BEARER"
  else
    curl "$@"
  fi
}

# ── Step 1: initialize a session on /mcp/<route> ──────────────────────────────
INIT_RESP=$(mcp_curl -si \
  -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"demo-client","version":"1.0"}}}')

HTTP_STATUS=$(echo "$INIT_RESP" | head -1 | awk '{print $2}')
if [[ "$HTTP_STATUS" != "200" ]]; then
  echo "ERROR: initialize on /mcp/$ROUTE failed with HTTP $HTTP_STATUS" >&2
  echo "$INIT_RESP" >&2
  exit 1
fi

SESSION_ID=$(echo "$INIT_RESP" | grep -i "^Mcp-Session-Id:" | tr -d '\r' | awk '{print $2}')
if [[ -z "$SESSION_ID" ]]; then
  echo "ERROR: no Mcp-Session-Id in initialize response" >&2
  echo "$INIT_RESP" >&2
  exit 1
fi

# ── Step 2: tool call on the same route ───────────────────────────────────────
# Without --fail, curl exits 0 even on HTTP 5xx, so a server error would be printed
# as if it were a result and the helper would exit 0. Capture the status code on its
# own trailing line via -w, then split it back off (the body may contain newlines,
# so the LAST line is the status and everything before it is the body).
RESPONSE=$(mcp_curl -sS \
  -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -w $'\n%{http_code}' \
  -d "$CALL_BODY")
HTTP_STATUS=${RESPONSE##*$'\n'}
RESULT=${RESPONSE%$'\n'*}

pretty() { if command -v jq &>/dev/null; then echo "$1" | jq . 2>/dev/null || echo "$1"; else echo "$1"; fi; }

if [[ "$HTTP_STATUS" != 2[0-9][0-9] ]]; then
  echo "ERROR: tools/call on /mcp/$ROUTE failed with HTTP $HTTP_STATUS" >&2
  pretty "$RESULT" >&2
  exit 1
fi

pretty "$RESULT"
