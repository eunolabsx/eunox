#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/scripts/ci-test-stdio.sh — stdio integration test
#
# Asserts that eunox enforces demo/manifest.yaml correctly when running
# in stdio transport mode (proxy spawns mock-mcp-server-stdio as a subprocess):
#   - read_file /reports/*       → ALLOW  (allowedValues glob)
#   - read_file outside /reports → DENY   (path not in allowed set)
#   - write_file                 → DENY   (tool absent from manifest)
#   - query_db SELECT            → ALLOW  (allowedOperations)
#   - query_db DELETE            → DENY   (operation not permitted)
#
# Exits 0 if all assertions pass, non-zero otherwise.
# Requires: go, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POLICY="$REPO_ROOT/demo/manifest.yaml"
AUDIT_LOG="$REPO_ROOT/demo/audit/audit.jsonl"
AUDIT_KEY="$REPO_ROOT/demo/audit/audit.key"

PROXY_BIN="$REPO_ROOT/bin/eunox"
STDIO_SERVER_BIN="$REPO_ROOT/bin/mock-mcp-server-stdio"

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ci-client","version":"1.0"}}}'
INITIALIZED='{"jsonrpc":"2.0","method":"notifications/initialized"}'

pass=0
fail=0

# ── build ─────────────────────────────────────────────────────────────────────

echo "==> Building eunox and mock-mcp-server-stdio ..."
mkdir -p "$REPO_ROOT/bin"
go build -o "$PROXY_BIN" "$REPO_ROOT/cmd/eunox"
go build -o "$STDIO_SERVER_BIN" "$REPO_ROOT/demo/mock-mcp-server-stdio"
echo ""

# ── generate a transport: stdio config that points at the local subprocess ───
# The proxy's `--config` flag now carries upstream wiring; we synthesize a
# tiny one-upstream config so the script doesn't have to track absolute paths
# in a committed YAML.
CONFIG_FILE=$(mktemp)
trap 'rm -f "$CONFIG_FILE"' EXIT
cat >"$CONFIG_FILE" <<EOF
schemaVersion: "0.1"
transport: stdio
audit:
  log: "$AUDIT_LOG"
  keyPath: "$AUDIT_KEY"
upstreams:
  - name: mock
    transport: stdio
    command: "$STDIO_SERVER_BIN"
    policy:
      - "$POLICY"
EOF

# ── helpers ───────────────────────────────────────────────────────────────────

# call_stdio <call-body-json> — pipe initialize → initialized → tool call through
# the proxy and print the raw JSON-RPC response for the tool call (id=2).
# Writes proxy output to a temp file so the proxy can exit cleanly before we
# parse, avoiding SIGPIPE when only two responses are expected.
call_stdio() {
  local call_body="$1"
  local tmpout
  tmpout=$(mktemp)
  # shellcheck disable=SC2064
  trap "rm -f '$tmpout'" RETURN

  {
    printf '%s\n' "$INIT"
    printf '%s\n' "$INITIALIZED"
    printf '%s\n' "$call_body"
  } | "$PROXY_BIN" proxy --config "$CONFIG_FILE" \
      2>/dev/null >"$tmpout"

  while IFS= read -r line; do
    local id
    id=$(printf '%s' "$line" | jq -r '.id // empty' 2>/dev/null)
    if [[ "$id" == "2" ]]; then
      printf '%s' "$line"
      return
    fi
  done <"$tmpout"
}

# Reuse the strict classifier vocabulary from the HTTP suite so the stdio suite
# does not provide weaker coverage for the same behavior. Sourcing only defines
# functions/vars (it requires curl only when its post helpers are called, which
# this script never does).
# shellcheck source=demo/scripts/ci-test-common.sh
source "$SCRIPT_DIR/ci-test-common.sh"

# check <description> <call-body-json> <want: allow|deny>
#
# Strict classification mirroring eunox_assert in ci-test-common.sh: the response
# must be a valid JSON-RPC object echoing id 2; an allow requires a real non-null
# result with no error and no isError flag; a deny requires a JSON-RPC error
# carrying a DOCUMENTED policy-denial code in error.data.code. Missing, malformed,
# or null output is a test FAILURE, never a default-allow.
check() {
  local desc="$1" call_body="$2" want="$3"
  local resp

  resp=$(call_stdio "$call_body")

  if [[ -z "$resp" ]]; then
    printf 'FAIL  %s  (no JSON-RPC response for id 2)\n' "$desc"
    ((fail++)) || true
    return
  fi

  # Must be a JSON object with jsonrpc=="2.0" and id==2. A parse failure or a
  # wrong/absent envelope is a failure, not a silent allow.
  local envelope_ok
  envelope_ok=$(printf '%s' "$resp" | jq -r \
    '(type == "object" and .jsonrpc == "2.0" and ((.id | tostring) == "2"))' \
    2>/dev/null || echo "false")
  if [[ "$envelope_ok" != "true" ]]; then
    printf 'FAIL  %s  (response is not a valid JSON-RPC envelope for id 2)\n' "$desc"
    printf '      response: %s\n' "$resp"
    ((fail++)) || true
    return
  fi

  local has_error has_result result_is_error
  has_error=$(printf '%s' "$resp" | jq -r 'has("error") and (.error != null)' 2>/dev/null || echo "false")
  has_result=$(printf '%s' "$resp" | jq -r 'has("result") and (.result != null)' 2>/dev/null || echo "false")
  result_is_error=$(printf '%s' "$resp" | jq -r '(.result.isError // false) == true' 2>/dev/null || echo "false")

  if [[ "$want" == "allow" ]]; then
    if [[ "$has_error" == "false" && "$has_result" == "true" && "$result_is_error" == "false" ]]; then
      printf 'PASS  %s\n' "$desc"
      ((pass++)) || true
    else
      printf 'FAIL  %s  (want=allow, response was not a clean result)\n' "$desc"
      printf '      response: %s\n' "$resp"
      ((fail++)) || true
    fi
    return
  fi

  # want == deny: require a JSON-RPC error carrying a documented policy-denial code.
  if [[ "$has_error" != "true" ]]; then
    printf 'FAIL  %s  (want=deny, but no JSON-RPC error present)\n' "$desc"
    printf '      response: %s\n' "$resp"
    ((fail++)) || true
    return
  fi
  local denial_code
  denial_code=$(printf '%s' "$resp" | jq -r '.error.data.code // empty' 2>/dev/null || echo "")
  if [[ -n "$denial_code" ]] && _is_policy_denial_code "$denial_code"; then
    printf 'PASS  %s  (denied: %s)\n' "$desc" "$denial_code"
    ((pass++)) || true
  else
    printf 'FAIL  %s  (want=deny, error.data.code=%s is not a documented policy denial)\n' "$desc" "${denial_code:-<none>}"
    printf '      response: %s\n' "$resp"
    ((fail++)) || true
  fi
}

# ── tests ─────────────────────────────────────────────────────────────────────

echo "==> eunox demo: stdio integration tests"
echo ""

check \
  "read_file /reports/q3.pdf → ALLOW (path matches /reports/* glob)" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}' \
  allow

check \
  "read_file /reports/summary.csv → ALLOW (another path under /reports/)" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/summary.csv"}}}' \
  allow

check \
  "read_file /etc/shadow → DENY (path outside /reports/*)" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}' \
  deny

check \
  "read_file /internal/secrets.txt → DENY (path outside /reports/*)" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/internal/secrets.txt"}}}' \
  deny

check \
  "write_file /etc/passwd → DENY (tool absent from manifest)" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"x"}}}' \
  deny

check \
  "query_db SELECT * FROM reports → ALLOW (SELECT in allowedOperations)" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"SELECT * FROM reports"}}}' \
  allow

check \
  "query_db DELETE FROM reports → DENY (only SELECT permitted)" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}' \
  deny

check \
  "query_db DROP TABLE reports → DENY (only SELECT permitted)" \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DROP TABLE reports"}}}' \
  deny

# ── audit HMAC verification ────────────────────────────────────────────────────

echo ""
echo "==> Verifying audit log HMAC signatures ..."

vt_exit=0
vt_out=$("$PROXY_BIN" audit-verify \
  --audit-log "$AUDIT_LOG" \
  --audit-key-path "$AUDIT_KEY") || vt_exit=$?

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
