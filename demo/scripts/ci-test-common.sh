# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# demo/scripts/ci-test-common.sh — shared strict assertion helpers for the
# HTTP demo integration tests (ci-test.sh, ci-test-gateway.sh, ci-test-jwt.sh).
#
# Sourced, not executed. Requires: curl, jq. Callers own `pass` and `fail`.
#
# The classification here is deliberately strict so that forwarding or denial
# regressions cannot stay green:
#
#   ALLOW  — requires a transport-level success (curl ok, 2xx, non-empty body),
#            a valid JSON-RPC envelope echoing the request id, a non-null
#            `result`, NO `error`, and `result.isError` not true.
#
#   DENY   — requires a valid JSON-RPC envelope echoing the request id carrying
#            an `error` whose structured `error.data.code` is one of the
#            DOCUMENTED policy-denial codes below. Auth/session/transport/
#            upstream/internal JSON-RPC errors (e.g. -32603 with no policy
#            denial payload, or "unknown session") are treated as FAILURES,
#            not as successful policy enforcement.
#
# Documented policy-denial codes (see pkg/capability/errors.go and
# cmd/eunox/jsonrpc.go denialToJSONRPCCode): the proxy stamps every policy
# denial with error.data.code drawn from this set.
EUNOX_POLICY_DENIAL_CODES='AUTHORIZATION_FAILED CAPABILITY_DENIED CONDITION_FAILED VALUE_NOT_PERMITTED OPERATION_NOT_PERMITTED RATE_LIMITED MISSING_CONTEXT KILL_SWITCH KILL_SWITCH_ERROR NO_JWT_CLAIMS INVALID_PARAMS'

# _is_policy_denial_code <code> — return 0 if <code> is a documented policy
# denial code, 1 otherwise.
_is_policy_denial_code() {
  local code="$1" known
  for known in $EUNOX_POLICY_DENIAL_CODES; do
    [[ "$code" == "$known" ]] && return 0
  done
  return 1
}

# eunox_post <url> [extra curl args...] — perform a POST, capturing the
# response body and the HTTP status on a trailing line. Sets the globals:
#   EUNOX_HTTP_STATUS  — integer HTTP status (000 on curl failure)
#   EUNOX_BODY         — response body (without the status trailer)
#   EUNOX_CURL_RC      — curl exit code
# Always returns 0 so the caller (under set -e) can inspect the globals.
eunox_post() {
  local url="$1"; shift
  local raw rc
  # -w writes the status on its own trailing line so we can split it off the
  # body. -s silences progress; we deliberately do NOT use -f so that a non-2xx
  # body is still captured for the assertion to reject.
  set +e
  raw=$(curl -s -w $'\n%{http_code}' -X POST "$url" "$@")
  rc=$?
  set -e
  EUNOX_CURL_RC=$rc
  if [[ $rc -ne 0 ]]; then
    EUNOX_BODY=""
    EUNOX_HTTP_STATUS="000"
    return 0
  fi
  EUNOX_HTTP_STATUS="${raw##*$'\n'}"
  EUNOX_BODY="${raw%$'\n'*}"
  return 0
}

# eunox_assert <description> <want: allow|deny> <want-id> <url> [extra curl args...]
# Sends the request body (passed as a -d argument inside the extra args) and
# strictly classifies the response. Increments the caller's `pass`/`fail`.
eunox_assert() {
  local desc="$1" want="$2" want_id="$3" url="$4"; shift 4

  eunox_post "$url" "$@"

  local body="$EUNOX_BODY" status="$EUNOX_HTTP_STATUS"

  # Transport-level failures are always test failures, never silent allows.
  if [[ "$EUNOX_CURL_RC" -ne 0 ]]; then
    printf 'FAIL  %s  (curl failed, rc=%s)\n' "$desc" "$EUNOX_CURL_RC"
    ((fail++)) || true
    return
  fi
  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    printf 'FAIL  %s  (non-2xx HTTP status %s)\n' "$desc" "$status"
    printf '      response: %s\n' "$body"
    ((fail++)) || true
    return
  fi
  if [[ -z "$body" ]]; then
    printf 'FAIL  %s  (empty response body)\n' "$desc"
    ((fail++)) || true
    return
  fi

  # Body must be a JSON object echoing the expected request id. A parse failure
  # is a failure, never a default-allow.
  local got_id
  got_id=$(jq -re '.id | tostring' <<<"$body" 2>/dev/null) || {
    printf 'FAIL  %s  (response is not valid JSON-RPC)\n' "$desc"
    printf '      response: %s\n' "$body"
    ((fail++)) || true
    return
  }
  if [[ "$got_id" != "$want_id" ]]; then
    printf 'FAIL  %s  (response id mismatch: want=%s got=%s)\n' "$desc" "$want_id" "$got_id"
    printf '      response: %s\n' "$body"
    ((fail++)) || true
    return
  fi

  local has_error result_is_error
  has_error=$(jq -r 'has("error") and (.error != null)' <<<"$body" 2>/dev/null || echo "false")
  result_is_error=$(jq -r '(.result.isError // false) == true' <<<"$body" 2>/dev/null || echo "false")

  if [[ "$want" == "allow" ]]; then
    # An allow requires a real, non-null result, no error, and no isError flag.
    local has_result
    has_result=$(jq -r 'has("result") and (.result != null)' <<<"$body" 2>/dev/null || echo "false")
    if [[ "$has_error" == "false" && "$has_result" == "true" && "$result_is_error" == "false" ]]; then
      printf 'PASS  %s\n' "$desc"
      ((pass++)) || true
    else
      printf 'FAIL  %s  (want=allow, response was not a clean result)\n' "$desc"
      printf '      response: %s\n' "$body"
      ((fail++)) || true
    fi
    return
  fi

  # want == deny: require a JSON-RPC error carrying a DOCUMENTED policy-denial
  # code in error.data.code. Reject errors without that structured payload
  # (auth/session/transport/upstream/internal errors) as test failures.
  if [[ "$has_error" != "true" ]]; then
    printf 'FAIL  %s  (want=deny, but no JSON-RPC error present)\n' "$desc"
    printf '      response: %s\n' "$body"
    ((fail++)) || true
    return
  fi

  local denial_code
  denial_code=$(jq -r '.error.data.code // empty' <<<"$body" 2>/dev/null || echo "")
  if [[ -z "$denial_code" ]]; then
    printf 'FAIL  %s  (want=deny, error lacks structured policy-denial code in error.data.code)\n' "$desc"
    printf '      response: %s\n' "$body"
    ((fail++)) || true
    return
  fi
  if _is_policy_denial_code "$denial_code"; then
    printf 'PASS  %s  (denied: %s)\n' "$desc" "$denial_code"
    ((pass++)) || true
  else
    printf 'FAIL  %s  (want=deny, error.data.code=%s is not a documented policy denial)\n' "$desc" "$denial_code"
    printf '      response: %s\n' "$body"
    ((fail++)) || true
  fi
}
