#!/usr/bin/env bash
# demo/scripts/get-jwt.sh — obtain a test JWT from the local Keycloak instance.
#
# The token carries MCP capability claims injected by the eunox-demo realm:
#   "mcp.v":            "0.2"
#   "mcp.capabilities": ["tool:read_file?path=/reports/*", "tool:query_db?op=SELECT"]
#   "mcp.task_id":      "demo-task-001"
#   "mcp.agent_id":     "demo-agent"
#   "aud":                "eunox"
#
# Usage:
#   TOKEN=$(bash scripts/get-jwt.sh)
#   bash scripts/mcp-call.sh '<body>' "$TOKEN"
#
# Or just print the JWT:
#   bash scripts/get-jwt.sh
#
# Prerequisites: Keycloak must be running (make up or make up-jwt).
# The token endpoint is http://localhost:8081/realms/eunox-demo/protocol/openid-connect/token.

set -euo pipefail

KC_HOST="${KEYCLOAK_HOST:-http://localhost:8081}"
REALM="eunox-demo"
CLIENT_ID="demo-agent"
CLIENT_SECRET="demo-secret"
TOKEN_ENDPOINT="$KC_HOST/realms/$REALM/protocol/openid-connect/token"

RESPONSE=$(curl -sf \
  -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET" \
  2>&1) || {
  echo "ERROR: failed to reach Keycloak at $TOKEN_ENDPOINT" >&2
  echo "       Is Keycloak running?  Try: make up-jwt" >&2
  exit 1
}

TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
if [[ -z "$TOKEN" ]]; then
  echo "ERROR: no access_token in response:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi

echo "$TOKEN"
