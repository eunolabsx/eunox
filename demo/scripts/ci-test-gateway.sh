#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/scripts/ci-test-gateway.sh — gateway-mode integration test.
#
# One gateway fronts two upstreams, each with its own versioned manifest:
#   /mcp/files  (files-policy 0.1.0): read_file /reports/* only
#   /mcp/db     (db-policy   0.2.0): query_db SELECT only
#
# Asserts per-route enforcement, route isolation, unknown-route 404, the new
# audit stamping (upstream / policy_version / policy_sha256), and HMAC integrity.
#
# Exits 0 if all assertions pass, non-zero otherwise. Requires: curl, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo/scripts/ci-test-common.sh
source "$SCRIPT_DIR/ci-test-common.sh"

HOST="${EUNOX_HOST:-http://localhost:3000}"
pass=0
fail=0

# new_session <route> — initialize a fresh MCP session on /mcp/<route>, print sid.
new_session() {
  local route="$1" resp sid
  resp=$(curl -si -X POST "$HOST/mcp/$route" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
  sid=$(echo "$resp" | grep -i "^Mcp-Session-Id:" | tr -d '\r' | awk '{print $2}')
  if [[ -z "$sid" ]]; then
    echo "ERROR: failed to initialize session on /mcp/$route (is the gateway up at $HOST?)" >&2
    echo "$resp" >&2
    exit 1
  fi
  echo "$sid"
}

# check <description> <route> <session-id> <tool-call-body> <want: allow|deny>
# Thin wrapper over the shared strict assertion helper (ci-test-common.sh). The
# tool-call bodies in this script all use request id 2.
check() {
  local desc="$1" route="$2" sid="$3" body="$4" want="$5"
  eunox_assert "$desc" "$want" 2 "$HOST/mcp/$route" \
    -H "Content-Type: application/json" \
    -H "Mcp-Session-Id: $sid" \
    -d "$body"
}

# check_status <description> <route> <want-http-status>
# Sends a bare initialize and asserts the HTTP status (used for unknown-route 404).
check_status() {
  local desc="$1" route="$2" want="$3" code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/mcp/$route" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
  if [[ "$code" == "$want" ]]; then
    printf 'PASS  %s\n' "$desc"
    ((pass++)) || true
  else
    printf 'FAIL  %s  (want=%s got=%s)\n' "$desc" "$want" "$code"
    ((fail++)) || true
  fi
}

echo "==> eunox gateway demo: per-route integration tests"
echo ""

# ── /mcp/files — files-policy 0.1.0 (read_file /reports/* only) ────────────────
FILES_SID=$(new_session files)

check "files: read_file /reports/q3.pdf → ALLOW (matches /reports/*)" \
  files "$FILES_SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}' \
  allow

check "files: read_file /etc/shadow → DENY (path outside /reports/*)" \
  files "$FILES_SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}' \
  deny

check "files: query_db SELECT → DENY (query_db absent from files-policy)" \
  files "$FILES_SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"SELECT 1"}}}' \
  deny

# ── /mcp/db — db-policy 0.2.0 (query_db SELECT only) ───────────────────────────
DB_SID=$(new_session db)

check "db: query_db SELECT * FROM reports → ALLOW (SELECT permitted)" \
  db "$DB_SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"SELECT * FROM reports"}}}' \
  allow

check "db: query_db DELETE FROM reports → DENY (only SELECT permitted)" \
  db "$DB_SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}' \
  deny

check "db: read_file /reports/q3.pdf → DENY (read_file absent from db-policy)" \
  db "$DB_SID" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}' \
  deny

# ── routing ───────────────────────────────────────────────────────────────────
check_status "unknown route /mcp/bogus → 404" bogus 404

# ── audit stamping: every record carries upstream + policy_version ─────────────
echo ""
echo "==> Verifying per-route audit stamping ..."

AUDIT_LOG="$(dirname "$SCRIPT_DIR")/audit/audit.jsonl"

# read_audit prints the shared audit log. The gateway container runs as root
# (user "0:0") so it can write to the bind-mounted ./audit dir, which leaves the
# log root-owned and mode 0600. On the Linux CI runner the unprivileged user
# cannot read it directly, so fall back to passwordless sudo; on Docker Desktop
# (macOS) the bind mount is host-readable and plain cat works without sudo.
read_audit() {
  if [[ -r "$AUDIT_LOG" ]]; then
    cat "$AUDIT_LOG"
  elif command -v sudo >/dev/null 2>&1; then
    sudo cat "$AUDIT_LOG"
  else
    cat "$AUDIT_LOG"
  fi
}

assert_stamp() {
  local desc="$1" upstream="$2" want_ver="$3" got_ver
  got_ver=$(read_audit | jq -r --arg u "$upstream" 'select(.upstream == $u) | .policy_version' 2>/dev/null | sort -u | head -1) || true
  if [[ "$got_ver" == "$want_ver" ]]; then
    printf 'PASS  %s (upstream=%s policy_version=%s)\n' "$desc" "$upstream" "$got_ver"
    ((pass++)) || true
  else
    printf 'FAIL  %s (upstream=%s want policy_version=%s got=%s)\n' "$desc" "$upstream" "$want_ver" "${got_ver:-<none>}"
    ((fail++)) || true
  fi
}

if [[ -f "$AUDIT_LOG" ]]; then
  assert_stamp "files route records stamped" files "0.1.0"
  assert_stamp "db route records stamped" db "0.2.0"
  # policy_sha256 present on at least one record.
  if [[ -n "$(read_audit | jq -r 'select(.policy_sha256 != null) | .policy_sha256' 2>/dev/null | head -1 || true)" ]]; then
    printf 'PASS  records carry policy_sha256 digest\n'
    ((pass++)) || true
  else
    printf 'FAIL  no record carries a policy_sha256 digest\n'
    ((fail++)) || true
  fi
else
  printf 'FAIL  audit log not found at %s\n' "$AUDIT_LOG"
  ((fail++)) || true
fi

# ── audit HMAC verification ────────────────────────────────────────────────────
echo ""
echo "==> Verifying audit log HMAC signatures ..."

COMPOSE_FILE="$(dirname "$SCRIPT_DIR")/docker-compose.gateway.yml"
vt_exit=0
vt_out=$(docker compose -f "$COMPOSE_FILE" run --rm --no-deps \
  eunox-gateway audit-verify \
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

echo ""
printf 'Results: %d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
