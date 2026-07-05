# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 3 — Short-lived cloud token reuse: OPA policy
#
# The agent is allowed to fetch one AWS STS token and one GitHub token per
# task run.  The token server returns credentials that expire in 900 s (AWS)
# and 600 s (GitHub).
#
# OPA can gate which tools are callable, but it cannot enforce "at most once
# per session".  An agent that calls get_aws_token five times will receive
# five different 900-second STS tokens — each perfectly valid.  OPA has no
# way to detect or prevent this accumulation.
#
# Query: POST /v1/data/token_reuse/allow
# Input:
#   {"input": {"tool": "get_aws_token", "session_id": "abc123"}}

package token_reuse

import rego.v1

allowed_tools := {"get_aws_token", "get_github_token"}

default allow := false

allow if {
	input.tool in allowed_tools
}

# ── What OPA CANNOT do ──────────────────────────────────────────────────────
# Because each OPA evaluation is independent there is no counter the policy
# can check.  An agent running in a loop would be allowed to accumulate an
# unbounded pool of live STS credentials — each expiring 15 minutes after
# issue — enabling a sliding-window privilege-escalation attack.
#
# eunox expresses single-use enforcement as:
#   conditions:
#     - type: maxCalls
#       count: 1
#       windowSeconds: 3600
