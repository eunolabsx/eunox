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
#   3. [stdio] protocol-revision interop matrix — {host 2025-11-25, 2026-07-28}
#      x {upstream 2025-11-25, 2026-07-28}. Matched pairs serve the enforced
#      surface; mismatched pairs are refused -32022 in both directions.
#   4. [cli]   init and validate --live open a 2026-07-28-only upstream through
#      the revision-selected opener, and the handshake opener is refused there.
#   5. [http]  transport, session isolation, kill-switch, malformed
#      body, 404 route, and per-route policy isolation through an HTTP gateway.
#   6. audit-verify — the HMAC chain over the SHARED audit tape stays intact
#      across every proxy invocation (cross-restart continuity).
#   7. audit record assertions — decisions, denial codes, condition types,
#      target types, and obligations are recorded as expected.
#
# All legs share one signed audit tape so step 6 exercises chain continuity
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
# gen_stdio_config OUT UPSTREAM_REVISION POLICY...
#
# UPSTREAM_REVISION sets BOTH sides of the upstream leg: the mock is launched speaking it,
# and the proxy is pinned to address it as that revision. They are one parameter because a
# config where the two disagree tests a misconfiguration, not a revision — and the interop
# matrix needs the disagreement to be between the HOST and the leg, never inside the leg.
gen_stdio_config() {
  local out="$1" upstream_rev="$2"; shift 2
  local pin=""
  # `auto` (no pin) is the handshake revision, and leaving the key out for it is what keeps
  # the old-revision cells byte-identical to the config every release so far generated.
  if [ "$upstream_rev" != "2025-11-25" ]; then
    pin="    protocolVersion: \"$upstream_rev\""
  fi
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
    args: ["--transport", "stdio", "--protocol-version", "$upstream_rev"]
${pin:+$pin}
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
gen_stdio_config "$WORK/stdio-full.yaml"       2025-11-25 policy.yaml policy-sampling.yaml
gen_stdio_config "$WORK/stdio-nosampling.yaml" 2025-11-25 policy-no-sampling.yaml

# The interop matrix drives one config per upstream revision, both on the comprehensive
# policy so a cell's outcome is attributable to the revision and nothing else.
gen_stdio_config "$WORK/stdio-up-old.yaml" 2025-11-25 policy.yaml
gen_stdio_config "$WORK/stdio-up-new.yaml" 2026-07-28 policy.yaml

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

# ── 3: protocol-revision interop matrix ─────────────────────────────────────
#
# Four cells over stdio, where all four are reachable today. The matrix is NOT run over
# HTTP: a 2026-07-28 host has no `initialize` to open a session with, and HTTP session
# creation is still anchored on that handshake, so the two new-host cells would be
# asserting the absence of a feature rather than the revision boundary. Both remain
# outstanding on the HTTP transport.
#
# The blocker has NARROWED, though, and the distinction matters for whoever enables these
# next: such a host now gets past NEGOTIATION over HTTP (its first request establishes a
# context rather than contradicting an asserted one), and is refused 501 by the arm that
# will mint its session. What is missing is creation itself, not the revision boundary —
# so these cells become runnable over HTTP the moment that lands, with no change here
# beyond dropping this note.
#
# The mismatched cells assert the refusal because refusal is the whole of the boundary
# this build implements: no method is translated across a mismatched pair, in either
# direction. When translation is activated, the cells that stop refusing are the diff.
run_matrix_cell() {
  local host_rev="$1" up_rev="$2" suite="$3" config="$4"
  "$HOST_BIN" --mode stdio --suite "$suite" \
    --host-protocol-version "$host_rev" --upstream-protocol-version "$up_rev" \
    --proxy-bin "$PROXY_BIN" --config "$config" || overall=1
}

note "[interop] host 2025-11-25 x upstream 2025-11-25 (matched)"
run_matrix_cell 2025-11-25 2025-11-25 interop-matched  "$WORK/stdio-up-old.yaml"

note "[interop] host 2026-07-28 x upstream 2026-07-28 (matched)"
run_matrix_cell 2026-07-28 2026-07-28 interop-matched  "$WORK/stdio-up-new.yaml"

note "[interop] host 2026-07-28 x upstream 2025-11-25 (mismatched)"
run_matrix_cell 2026-07-28 2025-11-25 interop-mismatch "$WORK/stdio-up-old.yaml"

note "[interop] host 2025-11-25 x upstream 2026-07-28 (mismatched)"
run_matrix_cell 2025-11-25 2026-07-28 interop-mismatch "$WORK/stdio-up-new.yaml"

# ── 4: CLI probes against a 2026-07-28-only upstream ────────────────────────
#
# `init`, `validate --live` and the session-start drift check all open an upstream leg
# through the same revision-selected opener the proxy uses. The matrix above covers the
# proxy's leg; this covers the CLI's, against an upstream that speaks ONLY the declaring
# revision — the case where opening with `initialize` would fail outright, so a passing
# probe is evidence the pin selected the opener rather than the default surviving.
note "[cli] init / validate --live against a 2026-07-28-only upstream"

cli_probe_ok() {
  local desc="$1"; shift
  if out="$("$@" 2>&1)"; then
    echo "PASS  $desc"
  else
    echo "FAIL  $desc"
    printf '%s\n' "$out" | tail -20
    overall=1
  fi
}

cli_probe_ok "eunox init introspects a 2026-07-28-only upstream" \
  "$PROXY_BIN" init --transport stdio --upstream-protocol-version 2026-07-28 \
  -- "$SERVER_BIN" --transport stdio --protocol-version 2026-07-28

cli_probe_ok "eunox validate --live walks a 2026-07-28-only route" \
  "$PROXY_BIN" validate --config "$WORK/stdio-up-new.yaml" --live

# The negative that gives the two above their meaning: the same upstream, probed with the
# handshake opener, must FAIL. Without it a probe that silently fell back to `initialize`
# would pass every assertion here.
#
# The OUTPUT is asserted, not just the exit status. `eunox init` exits non-zero for a renamed
# flag, a spawn failure, or any usage error, so an exit-code-only check would print PASS while
# the property it exists to establish — that `auto` selects the `initialize` opener rather than
# probing `server/discover` — went untested. Naming the rejected opener is what pins that, and
# it survives the mock reordering its own gates: whether it refuses `initialize` for the missing
# declaration or for not existing, the message names `initialize` either way.
desc="the handshake opener is refused by a 2026-07-28-only upstream"
if out="$("$PROXY_BIN" init --transport stdio --upstream-protocol-version auto \
       -- "$SERVER_BIN" --transport stdio --protocol-version 2026-07-28 2>&1)"; then
  echo "FAIL  $desc (it succeeded)"
  printf '%s\n' "$out" | tail -5
  overall=1
elif ! printf '%s' "$out" | grep -q 'initialize'; then
  echo "FAIL  $desc — it failed, but not by having its opener rejected"
  printf '%s\n' "$out" | tail -5
  overall=1
elif printf '%s' "$out" | grep -q 'server/discover'; then
  echo "FAIL  $desc — the probe reached server/discover, so \`auto\` did not select the handshake opener"
  printf '%s\n' "$out" | tail -5
  overall=1
else
  echo "PASS  $desc"
fi

# ── 5: http leg (start upstreams + gateway, drive, tear down) ────────────────
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

# ── 6: audit-verify the shared, cross-restart HMAC chain ─────────────────────
note "audit-verify (HMAC chain across every proxy invocation)"
if vt_out="$("$PROXY_BIN" audit-verify --audit-log "$AUDIT_LOG" --audit-key-path "$AUDIT_KEY" 2>&1)"; then
  summary="$(printf '%s\n' "$vt_out" | grep -i '^Checked' || true)"
  echo "PASS  audit-verify: ${summary:-ok}"
else
  echo "FAIL  audit-verify"
  printf '%s\n' "$vt_out"
  overall=1
fi

# ── 7: audit record content assertions ──────────────────────────────────────
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
