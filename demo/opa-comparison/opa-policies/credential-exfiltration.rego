# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 1 — Credential exfiltration: OPA policy
#
# The agent may read credentials, and it may write externally, but it must not
# do both IN SEQUENCE (read-then-write exfiltrates the secrets).  OPA can
# express the tool allow-list but it is stateless: it evaluates each request in
# isolation and has no memory of what the agent already called this session, so
# it cannot tie a write to the earlier read.  Both calls pass.
#
# Query: POST /v1/data/credential_exfiltration/allow
# Input:
#   {"input": {"tool": "read_credentials", "session_id": "abc123"}}

package credential_exfiltration

import rego.v1

# Allowed tool names — OPA can only check identity, not frequency.
allowed_tools := {"read_credentials", "write_external"}

default allow := false

allow if {
	input.tool in allowed_tools
}

# ── What OPA CANNOT do ──────────────────────────────────────────────────────
# OPA has no persistent state between policy evaluations.  There is no way to
# express "deny write_external if read_credentials already ran this session" in
# plain OPA without an external state store — at which point you are building a
# bespoke enforcement engine, not using OPA alone.
#
# eunox expresses this as a session-aware condition on write_external:
#   conditions:
#     - type: sequenceBlock
#       afterTools: [read_credentials]
