#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/scripts/ci-test-jwt.sh — JWT-mode integration test
#
# Asserts that eunox enforces demo/manifest.yaml with JWT capability
# claims issued by the local Keycloak instance (JWT schema v0.2):
#   JWT carries: mcp.v = "0.2"
#                mcp.capabilities = ["tool:read_file?path=/reports/*", "tool:query_db?op=SELECT"]
#
#   - initialize without JWT              → DENY  (HTTP 401 — JWT is required)
#   - read_file /reports/q3.pdf   (JWT)   → ALLOW (JWT + manifest both allow)
#   - read_file /reports/summary.csv (JWT)→ ALLOW (another path under /reports/)
#   - read_file /etc/shadow       (JWT)   → DENY  (path outside /reports/*)
#   - write_file /etc/passwd      (JWT)   → DENY  (absent from JWT capabilities)
#   - query_db SELECT * FROM reports (JWT)→ ALLOW (SELECT in JWT + manifest)
#   - query_db DELETE FROM reports   (JWT)→ DENY  (only SELECT permitted)
#
# Exits 0 if all assertions pass, non-zero otherwise.
# Requires: curl, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo/scripts/ci-test-common.sh
source "$SCRIPT_DIR/ci-test-common.sh"

HOST="${EUNOX_HOST:-http://localhost:3000}"
KC_HOST="${KEYCLOAK_HOST:-http://localhost:8081}"
pass=0
fail=0

# ── helpers ───────────────────────────────────────────────────────────────────

# get_jwt — obtain a Bearer JWT from Keycloak via client-credentials flow.
get_jwt() {
  local resp token
  resp=$(curl -sf \
    -X POST "$KC_HOST/realms/eunox-demo/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=demo-agent&client_secret=demo-secret") || {
    echo "ERROR: failed to reach Keycloak at $KC_HOST (is the JWT stack running?)" >&2
    exit 1
  }
  token=$(echo "$resp" | jq -r '.access_token // empty')
  if [[ -z "$token" ]]; then
    echo "ERROR: no access_token in Keycloak response: $resp" >&2
    exit 1
  fi
  echo "$token"
}

# new_session_jwt <bearer-token> — initialize a fresh MCP session with a JWT.
new_session_jwt() {
  local token="$1" resp sid
  resp=$(curl -si -X POST "$HOST/mcp/mock" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $token" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ci-test-jwt","version":"1.0"}}}')
  sid=$(echo "$resp" | grep -i "^Mcp-Session-Id:" | tr -d '\r' | awk '{print $2}')
  if [[ -z "$sid" ]]; then
    echo "ERROR: failed to initialize JWT MCP session (is eunox running at $HOST?)" >&2
    echo "$resp" >&2
    exit 1
  fi
  echo "$sid"
}

# check_jwt <description> <session-id> <token> <tool-call-body> <want: allow|deny>
# Thin wrapper over the shared strict assertion helper (ci-test-common.sh). The
# tool-call bodies in this script all use request id 2. A deny here must still
# be a DOCUMENTED policy denial (the JWT/manifest intersection yields the same
# structured error codes as manifest-only mode), so unknown-session/auth/
# transport errors are correctly counted as failures.
check_jwt() {
  local desc="$1" sid="$2" token="$3" body="$4" want="$5"
  eunox_assert "$desc" "$want" 2 "$HOST/mcp/mock" \
    -H "Content-Type: application/json" \
    -H "Mcp-Session-Id: $sid" \
    -H "Authorization: Bearer $token" \
    -d "$body"
}

# check_no_jwt <description> — initialize without a JWT; expect HTTP 401.
check_no_jwt() {
  local desc="$1" resp status
  resp=$(curl -si -X POST "$HOST/mcp/mock" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ci-test-nojwt","version":"1.0"}}}')
  status=$(echo "$resp" | head -1 | awk '{print $2}')
  if [[ "$status" == "401" || "$status" == "403" ]]; then
    printf 'PASS  %s\n' "$desc"
    ((pass++)) || true
  else
    printf 'FAIL  %s  (want HTTP 401/403 without JWT, got HTTP %s)\n' "$desc" "$status"
    printf '      response: %s\n' "$(echo "$resp" | tail -5)"
    ((fail++)) || true
  fi
}

# ── tests ─────────────────────────────────────────────────────────────────────

echo "==> eunox demo: JWT-mode integration tests"
echo ""

# Verify that JWT mode rejects unauthenticated requests outright.
check_no_jwt \
  "initialize without JWT → DENY (HTTP 401 — JWT required)"

# Obtain a JWT from Keycloak and exercise the authenticated paths.
TOKEN=$(get_jwt)
SID=$(new_session_jwt "$TOKEN")

check_jwt \
  "read_file /reports/q3.pdf → ALLOW (JWT + manifest allow /reports/* glob)" \
  "$SID" "$TOKEN" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}' \
  allow

check_jwt \
  "read_file /reports/summary.csv → ALLOW (another path under /reports/)" \
  "$SID" "$TOKEN" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/summary.csv"}}}' \
  allow

check_jwt \
  "read_file /etc/shadow → DENY (path outside /reports/*)" \
  "$SID" "$TOKEN" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}' \
  deny

check_jwt \
  "write_file /etc/passwd → DENY (absent from JWT capabilities)" \
  "$SID" "$TOKEN" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"x"}}}' \
  deny

check_jwt \
  "query_db SELECT * FROM reports → ALLOW (SELECT in JWT + manifest)" \
  "$SID" "$TOKEN" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"SELECT * FROM reports"}}}' \
  allow

check_jwt \
  "query_db DELETE FROM reports → DENY (only SELECT permitted)" \
  "$SID" "$TOKEN" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}' \
  deny

# ── audit HMAC verification ────────────────────────────────────────────────

echo ""
echo "==> Verifying audit log HMAC signatures ..."

COMPOSE_FILE="$(dirname "$SCRIPT_DIR")/docker-compose.yml"

vt_exit=0
vt_out=$(docker compose -f "$COMPOSE_FILE" run --rm --no-deps \
  eunox audit-verify \
  --audit-log /audit/audit.jsonl \
  --audit-key-path /audit/audit.key) || vt_exit=$?

summary=$(printf '%s\n' "$vt_out" | grep '^Checked' || true)

if [[ $vt_exit -eq 0 && -n "$summary" ]]; then
  printf 'PASS  audit-verify: %s\n' "$summary"
  ((pass++)) || true
else
  printf '%s\n' "$vt_out"
  printf 'FAIL  audit-verify: %s\n' "${summary:-no summary output}"
  ((fail++)) || true
fi

# ── results ───────────────────────────────────────────────────────────────────

echo ""
printf 'Results: %d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
