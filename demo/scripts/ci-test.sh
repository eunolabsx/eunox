#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/scripts/ci-test.sh — manifest-only integration test
#
# Asserts that eunox enforces demo/manifest.yaml correctly:
#   - read_file /reports/*       → ALLOW  (allowedValues glob)
#   - read_file outside /reports → DENY   (path not in allowed set)
#   - write_file                 → DENY   (tool absent from manifest)
#   - query_db SELECT            → ALLOW  (allowedOperations)
#   - query_db DELETE            → DENY   (operation not permitted)
#
# Exits 0 if all assertions pass, non-zero otherwise.
# Requires: curl, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo/scripts/ci-test-common.sh
source "$SCRIPT_DIR/ci-test-common.sh"

HOST="${EUNOX_HOST:-http://localhost:3000}"
pass=0
fail=0

# new_session — initialize a fresh MCP session, print the session ID.
new_session() {
  local resp
  resp=$(curl -si -X POST "$HOST/mcp/mock" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
  local sid
  sid=$(echo "$resp" | grep -i "^Mcp-Session-Id:" | tr -d '\r' | awk '{print $2}')
  if [[ -z "$sid" ]]; then
    echo "ERROR: failed to initialize MCP session (is eunox running at $HOST?)" >&2
    echo "$resp" >&2
    exit 1
  fi
  echo "$sid"
}

# check <description> <session-id> <tool-call-body> <want: allow|deny>
# Thin wrapper over the shared strict assertion helper (ci-test-common.sh). The
# tool-call bodies in this script all use request id 2.
check() {
  local desc="$1" sid="$2" body="$3" want="$4"
  eunox_assert "$desc" "$want" 2 "$HOST/mcp/mock" \
    -H "Content-Type: application/json" \
    -H "Mcp-Session-Id: $sid" \
    -d "$body"
}

# ── tests ─────────────────────────────────────────────────────────────────────

echo "==> eunox demo: manifest-only integration tests"
echo ""

SID=$(new_session)

check \
  "read_file /reports/q3.pdf → ALLOW (path matches /reports/* glob)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}' \
  allow

check \
  "read_file /reports/summary.csv → ALLOW (another path under /reports/)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/summary.csv"}}}' \
  allow

check \
  "read_file /etc/shadow → DENY (path outside /reports/*)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}' \
  deny

check \
  "read_file /internal/secrets.txt → DENY (path outside /reports/*)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/internal/secrets.txt"}}}' \
  deny

check \
  "write_file /etc/passwd → DENY (tool absent from manifest)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"x"}}}' \
  deny

check \
  "query_db SELECT * FROM reports → ALLOW (SELECT in allowedOperations)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"SELECT * FROM reports"}}}' \
  allow

check \
  "query_db DELETE FROM reports → DENY (only SELECT permitted)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}' \
  deny

check \
  "query_db DROP TABLE reports → DENY (only SELECT permitted)" \
  "$SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DROP TABLE reports"}}}' \
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
