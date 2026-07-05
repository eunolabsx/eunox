#!/usr/bin/env bash
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 3 — Short-lived cloud token reuse attack
#
# get_aws_token returns a 900-second STS credential.
# get_github_token returns a 600-second token.
#
# OPA can check the tool name but cannot enforce "issue at most one token
# per hour".  An agent running in a loop accumulates a pool of live
# credentials — all valid for their full TTL — enabling a sliding-window
# privilege-escalation attack.
#
# eunox maxCalls:1 (windowSeconds:3600) stops this at the enforcement layer.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

print_header "Scenario 3 — Short-Lived Cloud Token Reuse"
echo ""
echo "  Policy intent: agent may obtain one AWS STS token and one GitHub"
echo "  token per hour.  Token TTLs: AWS=900s, GitHub=600s."
echo ""
echo "  OPA policy:   token-reuse.rego — stateless allow-list"
echo "  eunox policy: manifests/token-reuse.yaml — maxCalls:1 per token tool"

# ── OPA: accumulation attack ──────────────────────────────────────────────────
# Assert each verdict (expect_opa_allow) so a policy regression or OPA outage
# fails the scenario instead of the hard-coded summary table papering over it.
print_step "OPA: get_aws_token call 1 (expect: ALLOW)"
expect_opa_allow "token_reuse" "get_aws_token"

print_step "OPA: get_aws_token call 2 (expect: ALLOW — OPA does not count)"
expect_opa_allow "token_reuse" "get_aws_token"

print_step "OPA: get_aws_token call 3 (expect: ALLOW — OPA does not count)"
expect_opa_allow "token_reuse" "get_aws_token"

print_note "OPA granted 3 separate 900-second STS tokens. All remain valid."
print_note "An attacker polling every 895 s would hold perpetual live credentials."

print_step "OPA: get_github_token — 3 calls (expect: all ALLOW)"
for i in 1 2 3; do
  expect_opa_allow "token_reuse" "get_github_token"
done
print_note "OPA granted 3 GitHub tokens (each valid 600 s). No limit enforced."

# ── eunox: single-use enforcement ────────────────────────────────────────────
print_step "Initializing eunox MCP session …"
mcp_init
echo "  Session ID: ${MCP_SESSION_ID}"

# Assert every eunox verdict (no blanket `|| true`): the summary table is only
# reachable after all four assertions pass, so a policy regression that lets a
# second token request through fails the scenario instead of being masked.
print_step "eunox: get_aws_token call 1 (expect: ALLOW)"
expect_allow "get_aws_token" '{"role":"arn:aws:iam::123456789012:role/DemoRole"}'

print_step "eunox: get_aws_token call 2 (expect: DENY — maxCalls:1 exceeded)"
expect_deny "get_aws_token" '{"role":"arn:aws:iam::123456789012:role/DemoRole"}'

print_step "eunox: get_github_token call 1 (expect: ALLOW)"
expect_allow "get_github_token" '{"scope":"repo:read"}'

print_step "eunox: get_github_token call 2 (expect: DENY — maxCalls:1 exceeded)"
expect_deny "get_github_token" '{"scope":"repo:read"}'

echo ""
print_header "Scenario 3 — Summary"
echo ""
echo "  ┌──────────────────────────────┬───────────────┬──────────────────┐"
echo "  │ Call                         │ OPA           │ eunox            │"
echo "  ├──────────────────────────────┼───────────────┼──────────────────┤"
echo "  │ get_aws_token    (1st)       │ ✔ ALLOW       │ ✔ ALLOW          │"
echo "  │ get_aws_token    (2nd)       │ ✔ ALLOW       │ ✘ DENY           │"
echo "  │ get_aws_token    (3rd)       │ ✔ ALLOW       │ (not reached)    │"
echo "  │ get_github_token (1st)       │ ✔ ALLOW       │ ✔ ALLOW          │"
echo "  │ get_github_token (2nd)       │ ✔ ALLOW       │ ✘ DENY           │"
echo "  │ get_github_token (3rd)       │ ✔ ALLOW       │ (not reached)    │"
echo "  └──────────────────────────────┴───────────────┴──────────────────┘"
echo ""
echo "  OPA never sees prior calls — stateless by design."
echo "  eunox increments a per-session counter and blocks after maxCalls:1."
echo "  The attack surface (15-minute credential pool) is eliminated entirely."
echo ""
