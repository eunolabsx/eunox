#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/opa-comparison/scripts/common.sh
# Shared helpers sourced by scenario scripts.

set -euo pipefail

EUNOX_HOST="${EUNOX_HOST:-http://localhost:3000}"
OPA_HOST="${OPA_HOST:-http://localhost:8181}"

# Verdict contract shared by mcp_call (and asserted by expect_allow/expect_deny):
#   0  → ALLOW       policy permitted the call
#   1  → DENY        policy denied the call
#   2  → INFRA_ERROR transport failure, non-200 HTTP status, empty body, or a
#                    body that is not a well-formed JSON-RPC response envelope.
# The infra-error status is deliberately DISTINCT from a policy denial so that a
# broken harness (HTTP 500 page, empty body, malformed JSON) can never be
# mistaken for a genuine ALLOW or DENY verdict.
MCP_ALLOW=0
MCP_DENY=1
MCP_INFRA_ERR=2

# ── color / formatting ───────────────────────────────────────────────────────
# Use $'...' ANSI-C quoting so the variables hold the actual ESC byte.
# Plain `echo` (no -e flag) then renders them correctly in any bash version.
# Colors are suppressed in CI (GitHub Actions sets CI=true), when stdout is
# not a terminal, or when TERM=dumb.
if [[ -z "${CI:-}" && -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
  RED=$'\033[0;31m'
  GRN=$'\033[0;32m'
  YLW=$'\033[0;33m'
  BLU=$'\033[0;34m'
  CYN=$'\033[0;36m'
  BOLD=$'\033[1m'
  RST=$'\033[0m'
else
  RED='' GRN='' YLW='' BLU='' CYN='' BOLD='' RST=''
fi

print_header() {
  local title="$1"
  echo ""
  echo "${BOLD}${BLU}══════════════════════════════════════════════════════════════${RST}"
  echo "${BOLD}${BLU}  ${title}${RST}"
  echo "${BOLD}${BLU}══════════════════════════════════════════════════════════════${RST}"
}

print_step() {
  echo ""
  echo "${CYN}▶  $*${RST}"
}

print_ok() {
  echo "${GRN}✔  $*${RST}"
}

print_denied() {
  echo "${RED}✘  $*${RST}"
}

print_note() {
  echo "${YLW}ℹ  $*${RST}"
}

# ── prerequisites ─────────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  echo "${RED}ERROR: jq is required but not installed.${RST}" >&2
  echo "       Install: https://jqlang.github.io/jq/download/" >&2
  exit 1
fi

# ── OPA query ─────────────────────────────────────────────────────────────────
# opa_check <package> <tool> [extra-json-fields]
# Queries POST /v1/data/<package>/allow and prints the decision.
# extra-json-fields: additional comma-separated JSON key:value pairs merged into input.
#
# Uses the SAME three-way verdict contract as mcp_call so a transport/response
# failure can never be mistaken for a genuine policy decision:
#   ${MCP_ALLOW}     (0) → OPA returned a boolean allow=true
#   ${MCP_DENY}      (1) → OPA returned a boolean allow=false
#   ${MCP_INFRA_ERR} (2) → curl failure, non-200 HTTP, empty body, malformed
#                          JSON, or a result that is not a JSON boolean
opa_check() {
  local pkg="$1"
  local tool="$2"
  local extra="${3:-}"

  local input_json
  if [[ -n "$extra" ]]; then
    input_json="{\"tool\":\"${tool}\",${extra}}"
  else
    input_json="{\"tool\":\"${tool}\"}"
  fi

  # Capture body and HTTP status separately (no -f) so a non-200 is surfaced as an
  # infra error rather than a generic curl failure indistinguishable from a deny.
  local raw status resp
  if ! raw=$(curl -s -o - -w $'\n%{http_code}' \
    -X POST "${OPA_HOST}/v1/data/${pkg}/allow" \
    -H "Content-Type: application/json" \
    -d "{\"input\":${input_json}}" 2>/dev/null); then
    print_denied "OPA [${pkg}] tool=${tool} → INFRA ERROR: curl transport failure reaching ${OPA_HOST}"
    return "${MCP_INFRA_ERR}"
  fi

  status="${raw##*$'\n'}"
  resp="${raw%$'\n'*}"

  if [[ "$status" != "200" ]]; then
    print_denied "OPA [${pkg}] tool=${tool} → INFRA ERROR: HTTP ${status} from ${OPA_HOST}"
    return "${MCP_INFRA_ERR}"
  fi
  if [[ -z "${resp//[[:space:]]/}" ]]; then
    print_denied "OPA [${pkg}] tool=${tool} → INFRA ERROR: empty response body (HTTP 200)"
    return "${MCP_INFRA_ERR}"
  fi

  # The result MUST be a JSON boolean. A missing/non-boolean .result (e.g. OPA
  # returned {} for an undefined decision, or an error document) is an infra error,
  # never a silent deny.
  local decision
  decision=$(printf '%s' "$resp" | jq -r '
    if type != "object" then "invalid"
    elif (.result | type) == "boolean" then (.result | tostring)
    else "invalid"
    end' 2>/dev/null) || decision="invalid"

  case "$decision" in
    true)
      print_ok "OPA [${pkg}] tool=${tool} → ALLOW"
      return "${MCP_ALLOW}" ;;
    false)
      print_denied "OPA [${pkg}] tool=${tool} → DENY"
      return "${MCP_DENY}" ;;
    *)
      local preview="${resp:0:120}"
      print_denied "OPA [${pkg}] tool=${tool} → INFRA ERROR: result is not a JSON boolean: ${preview}"
      return "${MCP_INFRA_ERR}" ;;
  esac
}

# ── MCP session ───────────────────────────────────────────────────────────────
# mcp_init — initialize a session and export MCP_SESSION_ID.
mcp_init() {
  local resp
  resp=$(curl -si \
    -X POST "${EUNOX_HOST}/mcp/mock" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"opa-cmp-demo","version":"1.0"}}}')

  local status
  status=$(echo "$resp" | head -1 | awk '{print $2}')
  if [[ "$status" != "200" ]]; then
    echo "ERROR: eunox initialize failed with HTTP ${status}" >&2
    echo "$resp" >&2
    exit 1
  fi

  MCP_SESSION_ID=$(echo "$resp" | grep -i "^Mcp-Session-Id:" | tr -d '\r' | awk '{print $2}')
  if [[ -z "$MCP_SESSION_ID" ]]; then
    echo "ERROR: no Mcp-Session-Id in response" >&2
    exit 1
  fi
  export MCP_SESSION_ID
}

# mcp_call <tool> <args-json>
# Issues a tools/call against eunox and prints the outcome.
# Prints ALLOW with a preview of the result text, or DENY with the reason.
# Returns ${MCP_ALLOW} on allow, ${MCP_DENY} on deny, or ${MCP_INFRA_ERR} on any
# infrastructure failure (transport error, non-200 HTTP, malformed/invalid
# JSON-RPC envelope) — see the verdict contract at the top of this file.
mcp_call() {
  local tool="$1"
  local args="$2"

  local body
  body=$(printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s}}' \
    "$tool" "$args")

  # Capture the response body and the HTTP status separately. The body goes to
  # stdout; we append the status code on its own trailing line so a single curl
  # invocation yields both. --write-out runs only on a successful transport;
  # curl's own non-zero exit (connection refused, timeout, DNS failure) is
  # caught here and surfaced as an infra error rather than an empty "ALLOW".
  local raw status resp
  if ! raw=$(curl -s -o - -w $'\n%{http_code}' \
    -X POST "${EUNOX_HOST}/mcp/mock" \
    -H "Content-Type: application/json" \
    -H "Mcp-Session-Id: ${MCP_SESSION_ID}" \
    -d "$body" 2>/dev/null); then
    print_denied "eunox [tool=${tool}] → INFRA ERROR: curl transport failure reaching ${EUNOX_HOST}"
    return "${MCP_INFRA_ERR}"
  fi

  status="${raw##*$'\n'}"   # last line: HTTP status code
  resp="${raw%$'\n'*}"      # everything before it: response body

  if [[ "$status" != "200" ]]; then
    print_denied "eunox [tool=${tool}] → INFRA ERROR: HTTP ${status} from ${EUNOX_HOST}"
    return "${MCP_INFRA_ERR}"
  fi

  # An empty body is never a verdict — fail closed before jq (which would treat
  # empty input as null/no-output and could be mistaken for a missing field).
  if [[ -z "${resp//[[:space:]]/}" ]]; then
    print_denied "eunox [tool=${tool}] → INFRA ERROR: empty response body (HTTP 200)"
    return "${MCP_INFRA_ERR}"
  fi

  # The body must parse as JSON and be a well-formed JSON-RPC 2.0 response: an
  # object carrying "jsonrpc":"2.0", an "id" matching the request id (1, the only id
  # this helper issues), and EXACTLY ONE of non-null "error" or non-null "result"
  # (XOR). Anything else — an HTML error page, truncated JSON, a missing envelope
  # field, a body carrying both error and result, or a stale response for a different
  # id — is an infra error, NOT a verdict. Enforcing the full shape stops a malformed
  # error+result body from counting as a deny and a stale id from counting as an allow.
  # jq -e plus the explicit "invalid" fallback means only a literal "error" or "result"
  # verdict is allowed to proceed.
  local envelope
  envelope=$(printf '%s' "$resp" | jq -r '
    if type != "object" then "invalid"
    elif (.jsonrpc != "2.0") then "invalid"
    elif (.id != 1) then "invalid"
    elif ((has("error") and (.error != null)) and ((has("result") and (.result != null)) | not)) then "error"
    elif ((has("result") and (.result != null)) and ((has("error") and (.error != null)) | not)) then "result"
    else "invalid"
    end' 2>/dev/null) || envelope="invalid"

  if [[ "$envelope" != "error" && "$envelope" != "result" ]]; then
    local preview="${resp:0:120}"
    print_denied "eunox [tool=${tool}] → INFRA ERROR: response is not a valid JSON-RPC envelope: ${preview}"
    return "${MCP_INFRA_ERR}"
  fi

  # JSON-RPC protocol-level error (e.g. unknown session, parse error).
  if [[ "$envelope" == "error" ]]; then
    local rpc_err
    rpc_err=$(echo "$resp" | jq -r '.error.message // "unknown error"')
    print_denied "eunox [tool=${tool}] → DENY: ${rpc_err}"
    return "${MCP_DENY}"
  fi

  # eunox wraps policy denials as isError:true inside the MCP result envelope.
  local is_err
  is_err=$(echo "$resp" | jq -r '.result.isError // false')
  if [[ "$is_err" == "true" ]]; then
    # The content text is a JSON object with a "message" field.
    local inner msg
    inner=$(echo "$resp" | jq -r '.result.content[0].text // ""')
    msg=$(echo "$inner" | jq -r '.message // "denied"' 2>/dev/null || echo "denied")
    print_denied "eunox [tool=${tool}] → DENY: ${msg}"
    return "${MCP_DENY}"
  fi

  # Successful tool call — show a preview of the result text.
  local text preview
  text=$(echo "$resp" | jq -r '.result.content[0].text // ""')
  preview="${text:0:80}"
  [[ ${#text} -gt 80 ]] && preview="${preview}…"
  print_ok "eunox [tool=${tool}] → ALLOW: ${preview}"
  return "${MCP_ALLOW}"
}

# ── assertion helpers ─────────────────────────────────────────────────────────
# expect_allow / expect_deny wrap mcp_call and FAIL (exit non-zero) when the
# captured verdict is not the one the scenario expects. An infra error
# (${MCP_INFRA_ERR}) always fails: it is never silently treated as the expected
# verdict. These are the only sanctioned way for a scenario to invoke an eunox
# call it asserts on — never `mcp_call ... || true`, which discards the verdict.
#
# Usage: expect_allow <tool> <args-json>
#        expect_deny  <tool> <args-json>
expect_allow() {
  local tool="$1"
  local args="$2"
  local rc=0
  mcp_call "$tool" "$args" || rc=$?
  case "$rc" in
    "${MCP_ALLOW}") return 0 ;;
    "${MCP_DENY}")
      print_denied "ASSERTION FAILED: expected ALLOW for tool=${tool}, got DENY"
      exit 1 ;;
    *)
      print_denied "ASSERTION FAILED: expected ALLOW for tool=${tool}, got INFRA ERROR (rc=${rc})"
      exit 1 ;;
  esac
}

expect_deny() {
  local tool="$1"
  local args="$2"
  local rc=0
  mcp_call "$tool" "$args" || rc=$?
  case "$rc" in
    "${MCP_DENY}") return 0 ;;
    "${MCP_ALLOW}")
      print_denied "ASSERTION FAILED: expected DENY for tool=${tool}, got ALLOW"
      exit 1 ;;
    *)
      print_denied "ASSERTION FAILED: expected DENY for tool=${tool}, got INFRA ERROR (rc=${rc})"
      exit 1 ;;
  esac
}

# expect_opa_allow / expect_opa_deny — same idea for the stateless OPA side, so
# scenarios assert the OPA verdict instead of swallowing it with `|| true`.
#
# Usage: expect_opa_allow <package> <tool> [extra-json-fields]
#        expect_opa_deny  <package> <tool> [extra-json-fields]
expect_opa_allow() {
  local rc=0
  opa_check "$1" "$2" "${3:-}" || rc=$?
  case "$rc" in
    "${MCP_ALLOW}") return 0 ;;
    "${MCP_DENY}")
      print_denied "ASSERTION FAILED: expected OPA ALLOW for [$1] tool=$2, got DENY"
      exit 1 ;;
    *)
      print_denied "ASSERTION FAILED: expected OPA ALLOW for [$1] tool=$2, got INFRA ERROR (rc=${rc})"
      exit 1 ;;
  esac
}

expect_opa_deny() {
  local rc=0
  opa_check "$1" "$2" "${3:-}" || rc=$?
  # Only an EXPLICIT policy DENY satisfies the assertion. An infra error (OPA
  # outage, malformed response) must never count as a confirmed denial.
  case "$rc" in
    "${MCP_DENY}") return 0 ;;
    "${MCP_ALLOW}")
      print_denied "ASSERTION FAILED: expected OPA DENY for [$1] tool=$2, got ALLOW"
      exit 1 ;;
    *)
      print_denied "ASSERTION FAILED: expected OPA DENY for [$1] tool=$2, got INFRA ERROR (rc=${rc})"
      exit 1 ;;
  esac
}
