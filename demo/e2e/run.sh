#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/e2e/run.sh — end-to-end integration suite for eunox.
#
# Builds the REAL eunox binary plus the e2e mock-server and mock-host, then
# drives the proxy as a black box across both transports and asserts the policy
# outcome of every enforced MCP method (positive, negative, and edge cases):
#
#   1. [stdio] full enforcement matrix — every target type, condition, and the
#      redactFields directive; server-initiated sampling round-trip (ALLOW).
#   2. [stdio] sampling DENY — a manifest without the opt-in denies sampling.
#   3. [http]  transport, session isolation, kill-switch, malformed
#      body, 404 route, and per-route policy isolation through an HTTP gateway.
#   4. audit-verify — the HMAC chain over the SHARED audit tape stays intact
#      across all three proxy invocations (cross-restart continuity).
#   5. audit record assertions — decisions, denial codes, condition types,
#      target types, and obligations are recorded as expected.
#
# All legs share one signed audit tape so step 4 exercises chain continuity
# across separate proxy processes. No Docker required; needs only Go + curl.
#
# Usage:  bash demo/e2e/run.sh           # from the repo root
# Env:    E2E_PORT_MAIN (8190) E2E_PORT_DB (8191) E2E_PORT_PROXY (3100)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PORT_MAIN="${E2E_PORT_MAIN:-8190}"
PORT_DB="${E2E_PORT_DB:-8191}"
PORT_PROXY="${E2E_PORT_PROXY:-3100}"

PROXY_BIN="$REPO_ROOT/bin/eunox"
SERVER_BIN="$REPO_ROOT/bin/e2e-mock-server"
HOST_BIN="$REPO_ROOT/bin/e2e-mock-host"

WORK="$(mktemp -d)"
AUDIT_LOG="$WORK/audit.jsonl"
AUDIT_KEY="$WORK/audit.key"

BG_PIDS=()
overall=0

cleanup() {
  for pid in "${BG_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

note() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
[ -n "${CI:-}" ] && note() { printf '\n== %s ==\n' "$1"; }

# ── build ───────────────────────────────────────────────────────────────────
note "Building eunox, e2e mock-server, e2e mock-host"
mkdir -p "$REPO_ROOT/bin"
go build -o "$PROXY_BIN"  "$REPO_ROOT/cmd/eunox"     || exit 1
go build -o "$SERVER_BIN" "$REPO_ROOT/demo/e2e/mock-server" || exit 1
go build -o "$HOST_BIN"   "$REPO_ROOT/demo/e2e/mock-host"   || exit 1

# ── config generation (absolute paths; nothing committed needs editing) ──────
gen_stdio_config() {
  local out="$1"; shift
  {
    cat <<EOF
schemaVersion: "0.1"
transport: stdio
audit:
  log: "$AUDIT_LOG"
  keyPath: "$AUDIT_KEY"
upstreams:
  - name: main
    transport: stdio
    command: "$SERVER_BIN"
    args: ["--transport", "stdio"]
    policy:
EOF
    local p
    for p in "$@"; do
      echo "      - \"$REPO_ROOT/demo/e2e/$p\""
    done
  } >"$out"
}

# The stdio leg enforces sampling, so it layers the sampling opt-in overlay on
# top of the comprehensive policy. The HTTP gateway (below) cannot enforce
# sampling, so it loads policy.yaml alone — which the proxy now requires (an
# opt-in on an http upstream is rejected at load).
gen_stdio_config "$WORK/stdio-full.yaml"       policy.yaml policy-sampling.yaml
gen_stdio_config "$WORK/stdio-nosampling.yaml" policy-no-sampling.yaml

cat >"$WORK/gateway.yaml" <<EOF
schemaVersion: "0.1"
listen:
  bind: 127.0.0.1
  port: $PORT_PROXY
audit:
  log: "$AUDIT_LOG"
  keyPath: "$AUDIT_KEY"
defaults:
  upstreamTimeoutMs: 15000
upstreams:
  - name: main
    transport: http
    upstreamUrl: http://127.0.0.1:$PORT_MAIN
    policy: ["$REPO_ROOT/demo/e2e/policy.yaml"]
  - name: db
    transport: http
    upstreamUrl: http://127.0.0.1:$PORT_DB
    policy: ["$REPO_ROOT/demo/e2e/policy-db.yaml"]
EOF

# ── 1 + 2: stdio legs (the host spawns the proxy itself) ─────────────────────
note "[stdio] full enforcement matrix"
"$HOST_BIN" --mode stdio --suite full \
  --proxy-bin "$PROXY_BIN" --config "$WORK/stdio-full.yaml" || overall=1

note "[stdio] sampling DENY"
"$HOST_BIN" --mode stdio --suite sampling-deny \
  --proxy-bin "$PROXY_BIN" --config "$WORK/stdio-nosampling.yaml" || overall=1

# ── 3: http leg (start upstreams + gateway, drive, tear down) ────────────────
note "[http] transport, sessions, kill-switch, per-route isolation"
"$SERVER_BIN" --transport http --port "$PORT_MAIN" >"$WORK/up-main.log" 2>&1 &
BG_PIDS+=("$!")
"$SERVER_BIN" --transport http --port "$PORT_DB" >"$WORK/up-db.log" 2>&1 &
BG_PIDS+=("$!")
"$PROXY_BIN" proxy --config "$WORK/gateway.yaml" --control-token-path "$WORK/control.token" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
BG_PIDS+=("$PROXY_PID")

ready=0
for _ in $(seq 1 60); do
  if curl -sf -o /dev/null -X POST "http://127.0.0.1:$PORT_PROXY/mcp/main" \
       -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'; then
    ready=1
    break
  fi
  sleep 0.25
done
if [ "$ready" -ne 1 ]; then
  echo "FAIL  http gateway did not become ready"
  cat "$WORK/proxy.log"
  overall=1
else
  "$HOST_BIN" --mode http --url "http://127.0.0.1:$PORT_PROXY" --control-token-path "$WORK/control.token" || overall=1
fi

# Stop the gateway so its audit drainer flushes before we verify the tape.
kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true

# ── 4: audit-verify the shared, cross-restart HMAC chain ─────────────────────
note "audit-verify (HMAC chain across all three proxy invocations)"
if vt_out="$("$PROXY_BIN" audit-verify --audit-log "$AUDIT_LOG" --audit-key-path "$AUDIT_KEY" 2>&1)"; then
  summary="$(printf '%s\n' "$vt_out" | grep -i '^Checked' || true)"
  echo "PASS  audit-verify: ${summary:-ok}"
else
  echo "FAIL  audit-verify"
  printf '%s\n' "$vt_out"
  overall=1
fi

# ── 5: audit record content assertions ──────────────────────────────────────
note "audit record assertions"
"$HOST_BIN" --mode audit --audit-log "$AUDIT_LOG" || overall=1

# ── result ──────────────────────────────────────────────────────────────────
note "e2e result"
if [ "$overall" -eq 0 ]; then
  echo "ALL E2E LEGS PASSED"
else
  echo "E2E FAILURES DETECTED"
fi
exit "$overall"
