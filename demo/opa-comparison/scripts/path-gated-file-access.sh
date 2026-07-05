#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 2 — Path-gated file access: OPA cannot express per-tool call-rate
#              limits at all.
#
# Ten tools each restricted to /reports/** paths, plus maxCalls:5 per minute.
# Both engines enumerate the tools; eunox declares the shared gate once (a YAML
# anchor) and adds a per-tool rate limit that plain OPA has no state to enforce.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

print_header "Scenario 2 — Path-Gated File Access (10 tools)"
echo ""
echo "  Policy intent: all file tools restricted to /reports/** paths."
echo "  Rate limit: max 5 calls per tool per minute."
echo ""
echo "  OPA policy:   path-gated-file-access.rego — one startswith rule (no maxCalls)"
echo "  eunox policy: manifests/path-gated-file-access.yaml — 10 tools, one shared anchored gate"

# ── OPA: allowed path ─────────────────────────────────────────────────────────
print_step "OPA: read_file /reports/q3.pdf (expect: ALLOW)"
expect_opa_allow "path_gated_file_access" "read_file" '"arguments":{"path":"/reports/q3.pdf"}'

print_step "OPA: write_file /reports/output.csv (expect: ALLOW)"
expect_opa_allow "path_gated_file_access" "write_file" '"arguments":{"path":"/reports/output.csv"}'

print_step "OPA: read_file /reports/sub/q3.pdf (expect: ALLOW — nested path under /reports/)"
expect_opa_allow "path_gated_file_access" "read_file" '"arguments":{"path":"/reports/sub/q3.pdf"}'

# ── OPA: denied path ─────────────────────────────────────────────────────────
print_step "OPA: read_file /etc/passwd (expect: DENY)"
expect_opa_deny "path_gated_file_access" "read_file" '"arguments":{"path":"/etc/passwd"}'

# ── OPA: cannot count ─────────────────────────────────────────────────────────
print_step "OPA: calling read_file 6 times (all 6 expect: ALLOW — OPA has no counter)"
for i in $(seq 1 6); do
  expect_opa_allow "path_gated_file_access" "read_file" '"arguments":{"path":"/reports/q3.pdf"}'
done
print_note "OPA allowed all 6 calls.  maxCalls enforcement is impossible without external state."

# ── eunox enforcement ─────────────────────────────────────────────────────────
print_step "Initializing eunox MCP session …"
mcp_init
echo "  Session ID: ${MCP_SESSION_ID}"

# Every eunox call below is asserted; a wrong verdict or an infra error aborts
# the script (and fails CI) rather than being swallowed by `|| true`.
print_step "eunox: read_file /reports/q3.pdf (expect: ALLOW)"
expect_allow "read_file" '{"path":"/reports/q3.pdf"}'

print_step "eunox: read_file /reports/sub/q3.pdf (expect: ALLOW — nested path under /reports/**, parity with OPA's startswith)"
expect_allow "read_file" '{"path":"/reports/sub/q3.pdf"}'

print_step "eunox: read_file /etc/passwd (expect: DENY — path not in /reports/**)"
expect_deny "read_file" '{"path":"/etc/passwd"}'

print_step "eunox: calling read_file 3 more times to reach the maxCalls:5 budget …"
# Calls 3 through 5 of read_file: together with the two allowed reads above
# (/reports/q3.pdf and /reports/sub/q3.pdf) they exhaust the per-tool 5-call window.
# The denied /etc/passwd read does not consume the budget — it fails the path gate
# before the maxCalls counter commits. maxCalls keys per (session, tool), so both
# the flat and nested reads count against the same read_file window.
for i in $(seq 3 5); do
  print_note "  call ${i}/5"
  expect_allow "read_file" '{"path":"/reports/q3.pdf"}'
done

print_step "eunox: call 6 of read_file (expect: DENY — maxCalls:5 exceeded)"
expect_deny "read_file" '{"path":"/reports/q3.pdf"}'

echo ""
print_header "Scenario 2 — Summary"
echo ""
# Reaching this line means every assertion above held: OPA allowed the in-path
# reads and all 6 counted calls but denied /etc/passwd; eunox gated the path and
# enforced maxCalls:5. The narrative below is therefore a confirmed result.
print_ok "All verdicts confirmed by the assertions above."
echo ""
echo "  eunox manifest (path-gated-file-access.yaml)  —  the shared gate, declared once:"
echo ""
echo "    capabilities:"
echo "      - target: \"tool:read_file\""
echo "        actions: [call]"
echo "        conditions: &path-policy   # ← anchor: write the gate once"
echo "          - type: allowedValues"
echo "            argument: path"
echo "            values: [\"/reports/**\"]"
echo "          - type: maxCalls         # ← impossible in plain OPA"
echo "            count: 5"
echo "            windowSeconds: 60"
echo "      - target: \"tool:write_file\""
echo "        actions: [call]"
echo "        conditions: *path-policy   # ← reuse it for the other 9 tools"
echo "      # … 8 more tools, each: conditions: *path-policy"
echo ""
echo "  The spec rejects a bare tool:* as too broad, so both engines enumerate the"
echo "  tools.  eunox's durable edge is the per-tool maxCalls rate limit: enforcing"
echo "  it in plain OPA is impossible without an external state store — i.e. a custom"
echo "  enforcement engine bolted onto OPA."
echo ""
