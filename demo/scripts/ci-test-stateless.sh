#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/scripts/ci-test-stateless.sh — stdio integration test against a 2026-07-28 upstream
#
# The stateless twin of ci-test-stdio.sh. It asserts three separate things:
#
#   1. The SAME policy decisions hold across the revision change. Every allow/deny
#      case ci-test-stdio.sh makes over 2025-11-25 is made again here, over a leg
#      opened with `server/discover` and driven by a host that declares its protocol
#      version per request. A policy that stopped applying on the newer revision
#      would show up as a decision flip, not as a startup failure.
#   2. The revision boundary is real. `auto` against this upstream must FAIL at
#      startup naming the pin as the remedy — eunox does not probe for an upstream's
#      revision, and the diagnostic is what an operator gets instead.
#   3. A filtered `tools/list` never carries `cacheScope: public`. The mock emits
#      `public` deliberately, so reading `private` off the proxy's reply is reading a
#      working clamp rather than an upstream that said nothing (threat model L-6).
#
# Stdio only, deliberately: an HTTP session is opened by `initialize`, which this
# revision does not have, so eunox refuses a 2026-07-28 pin over the HTTP host
# transport outright.
#
# Exits 0 if all assertions pass, non-zero otherwise.
# Requires: go, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POLICY="$REPO_ROOT/demo/manifest.yaml"
AUDIT_LOG="$REPO_ROOT/demo/audit/audit-stateless.jsonl"
AUDIT_KEY="$REPO_ROOT/demo/audit/audit-stateless.key"

PROXY_BIN="$REPO_ROOT/bin/eunox"
STDIO_SERVER_BIN="$REPO_ROOT/bin/mock-mcp-server-stdio"

REVISION="2026-07-28"
# META is the per-request declaration every 2026-07-28 request carries. The mock
# refuses a request without it, so every call body below has to include it — which
# is the point: it proves the declaration survives the proxy verbatim.
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}'

pass=0
fail=0

# ── build ─────────────────────────────────────────────────────────────────────

echo "==> Building eunox and mock-mcp-server-stdio ..."
mkdir -p "$REPO_ROOT/bin" "$(dirname "$AUDIT_LOG")"
go build -o "$PROXY_BIN" "$REPO_ROOT/cmd/eunox"
go build -o "$STDIO_SERVER_BIN" "$REPO_ROOT/demo/mock-mcp-server-stdio"
echo ""

# A fresh tape per run: the assertions below read the whole file, and a tape left
# over from an earlier run would make the revision stamp check pass on old records.
rm -f "$AUDIT_LOG" "$AUDIT_KEY"

# ── configs ───────────────────────────────────────────────────────────────────
# Two of them: the pinned one every decision test runs through, and an `auto` one
# used once, to assert the startup diagnostic.

CONFIG_FILE=$(mktemp)
AUTO_CONFIG_FILE=$(mktemp)
trap 'rm -f "$CONFIG_FILE" "$AUTO_CONFIG_FILE"' EXIT

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
    args: ["--protocol-version", "$REVISION"]
    protocolVersion: "$REVISION"
    policy:
      - "$POLICY"
EOF

# Identical but for the pin, so the difference the diagnostic reports is the only
# difference between the two runs.
sed '/^    protocolVersion:/d' "$CONFIG_FILE" >"$AUTO_CONFIG_FILE"

# ── helpers ───────────────────────────────────────────────────────────────────

# call_stateless <message-json> — pipe one message through the proxy and print the
# JSON-RPC response. There is no handshake to send first: the revision removed it.
call_stateless() {
  local body="$1"
  local tmpout
  tmpout=$(mktemp)
  # shellcheck disable=SC2064
  trap "rm -f '$tmpout'" RETURN

  printf '%s\n' "$body" | "$PROXY_BIN" proxy --config "$CONFIG_FILE" 2>/dev/null >"$tmpout"

  while IFS= read -r line; do
    local id
    id=$(printf '%s' "$line" | jq -r '.id // empty' 2>/dev/null)
    if [[ -n "$id" ]]; then
      printf '%s' "$line"
      return
    fi
  done <"$tmpout"
}

# Same strict classifier vocabulary the other suites use, so this suite does not
# provide weaker coverage for the same behavior.
# shellcheck source=demo/scripts/ci-test-common.sh
source "$SCRIPT_DIR/ci-test-common.sh"

record() {
  local ok="$1" desc="$2" detail="${3:-}"
  if [[ "$ok" == "true" ]]; then
    printf 'PASS  %s\n' "$desc"
    ((pass++)) || true
  else
    printf 'FAIL  %s\n' "$desc"
    [[ -n "$detail" ]] && printf '      %s\n' "$detail"
    ((fail++)) || true
  fi
}

# check <description> <tool-call-args-json> <want: allow|deny>
check() {
  local desc="$1" call_args="$2" want="$3"
  local body resp
  body="{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{$META,$call_args}}"
  resp=$(call_stateless "$body")

  if [[ -z "$resp" ]]; then
    record false "$desc" "no JSON-RPC response"
    return
  fi

  local envelope_ok
  envelope_ok=$(printf '%s' "$resp" | jq -r \
    '(type == "object" and .jsonrpc == "2.0" and ((.id | tostring) == "2"))' 2>/dev/null || echo "false")
  if [[ "$envelope_ok" != "true" ]]; then
    record false "$desc" "response is not a valid JSON-RPC envelope for id 2: $resp"
    return
  fi

  local has_error has_result result_is_error
  has_error=$(printf '%s' "$resp" | jq -r 'has("error") and (.error != null)' 2>/dev/null || echo "false")
  has_result=$(printf '%s' "$resp" | jq -r 'has("result") and (.result != null)' 2>/dev/null || echo "false")
  result_is_error=$(printf '%s' "$resp" | jq -r '(.result.isError // false) == true' 2>/dev/null || echo "false")

  if [[ "$want" == "allow" ]]; then
    if [[ "$has_error" == "false" && "$has_result" == "true" && "$result_is_error" == "false" ]]; then
      record true "$desc"
    else
      record false "$desc" "want=allow, response was not a clean result: $resp"
    fi
    return
  fi

  if [[ "$has_error" != "true" ]]; then
    record false "$desc" "want=deny, but no JSON-RPC error present: $resp"
    return
  fi
  local denial_code
  denial_code=$(printf '%s' "$resp" | jq -r '.error.data.code // empty' 2>/dev/null || echo "")
  if [[ -n "$denial_code" ]] && _is_policy_denial_code "$denial_code"; then
    record true "$desc (denied: $denial_code)"
  else
    record false "$desc" "want=deny, error.data.code=${denial_code:-<none>} is not a documented policy denial: $resp"
  fi
}

# ── 1. the same policy decisions, over the newer revision ─────────────────────

echo "==> eunox demo: stateless ($REVISION) integration tests"
echo ""

check "read_file /reports/q3.pdf → ALLOW (path matches /reports/* glob)" \
  '"name":"read_file","arguments":{"path":"/reports/q3.pdf"}' allow

check "read_file /etc/shadow → DENY (path outside /reports/*)" \
  '"name":"read_file","arguments":{"path":"/etc/shadow"}' deny

check "write_file /etc/passwd → DENY (tool absent from manifest)" \
  '"name":"write_file","arguments":{"path":"/etc/passwd","content":"x"}' deny

check "query_db SELECT * FROM reports → ALLOW (SELECT in allowedOperations)" \
  '"name":"query_db","arguments":{"query":"SELECT * FROM reports"}' allow

check "query_db DROP TABLE reports → DENY (only SELECT permitted)" \
  '"name":"query_db","arguments":{"query":"DROP TABLE reports"}' deny

# ── 2. the filtered list, and the cacheScope clamp ────────────────────────────

echo ""
list_resp=$(call_stateless "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{$META}}")

names=$(printf '%s' "$list_resp" | jq -r '[.result.tools[].name] | sort | join(",")' 2>/dev/null || echo "")
if [[ "$names" == "query_db,read_file" ]]; then
  record true "tools/list is filtered to the manifest (write_file removed)"
else
  record false "tools/list is filtered to the manifest (write_file removed)" "got: ${names:-<none>}"
fi

# The mock answers `public` on purpose. Reading `private` here is reading the clamp.
scope=$(printf '%s' "$list_resp" | jq -r '.result.cacheScope // empty' 2>/dev/null || echo "")
if [[ "$scope" == "private" ]]; then
  record true "a filtered tools/list is clamped to cacheScope: private (threat model L-6)"
else
  record false "a filtered tools/list is clamped to cacheScope: private (threat model L-6)" \
    "got cacheScope=${scope:-<absent>} — the upstream sent \"public\", so this is the clamp not applying"
fi

# ttlMs is a freshness hint, not an authorization statement: the clamp must leave it.
ttl=$(printf '%s' "$list_resp" | jq -r '.result.ttlMs // empty' 2>/dev/null || echo "")
if [[ "$ttl" == "60000" ]]; then
  record true "ttlMs survives the clamp as a freshness hint"
else
  record false "ttlMs survives the clamp as a freshness hint" "got ttlMs=${ttl:-<absent>}"
fi

# ── 3. the revision boundary: `auto` fails, and says how to fix it ────────────

echo ""
auto_out=$(printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{$META}}" \
  | "$PROXY_BIN" proxy --config "$AUTO_CONFIG_FILE" 2>&1 >/dev/null || true)

if printf '%s' "$auto_out" | grep -q 'method not found: initialize' \
   && printf '%s' "$auto_out" | grep -q "protocolVersion: \"$REVISION\""; then
  record true "an unpinned leg against a $REVISION-only upstream fails naming the pin as the remedy"
else
  record false "an unpinned leg against a $REVISION-only upstream fails naming the pin as the remedy" \
    "stderr: $auto_out"
fi

# ── 4. every decision is stamped with the revision it was made under ──────────

echo ""
stamped=$(jq -sr '[.[] | select(.protocol_revision != null)] | length' <"$AUDIT_LOG" 2>/dev/null || echo 0)
wrong=$(jq -sr --arg rev "$REVISION" '[.[] | select(.protocol_revision != null and .protocol_revision != $rev)] | length' <"$AUDIT_LOG" 2>/dev/null || echo 0)
if [[ "$stamped" -gt 0 && "$wrong" -eq 0 ]]; then
  record true "every stamped audit record names $REVISION ($stamped records)"
else
  record false "every stamped audit record names $REVISION" \
    "stamped=$stamped, records naming another revision=$wrong"
fi

# ── audit HMAC verification ───────────────────────────────────────────────────

echo ""
echo "==> Verifying audit log HMAC signatures ..."

vt_exit=0
vt_out=$("$PROXY_BIN" audit-verify \
  --audit-log "$AUDIT_LOG" \
  --audit-key-path "$AUDIT_KEY") || vt_exit=$?

summary=$(printf '%s\n' "$vt_out" | grep '^Checked' || true)

if [[ $vt_exit -eq 0 && -n "$summary" ]]; then
  record true "audit-verify: $summary"
else
  printf '%s\n' "$vt_out"
  record false "audit-verify" "${summary:-no summary output}"
fi

# ── results ───────────────────────────────────────────────────────────────────

echo ""
printf 'Results: %d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
