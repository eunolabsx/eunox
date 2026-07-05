# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 2 — Path-gated file access: OPA policy
#
# Ten tools, each restricted to paths under /reports/.
# OPA can enforce path prefixes, but:
#   1. Each tool needs its own rule — this file would need to grow linearly.
#   2. There is still no way to enforce a per-tool call-rate limit.
#
# Query: POST /v1/data/path_gated_file_access/allow
# Input:
#   {"input": {"tool": "read_file", "arguments": {"path": "/reports/q3.pdf"}}}

package path_gated_file_access

import rego.v1

# Tools that accept a "path" argument.
path_gated_tools := {
	"read_file",
	"write_file",
	"read_config",
	"update_config",
	"read_log",
	"delete_file",
	"stat_file",
	"read_secret",
	"write_secret",
	"read_backup",
}

default allow := false

allow if {
	input.tool in path_gated_tools
	startswith(input.arguments.path, "/reports/")
}

# ── OPA vs eunox ─────────────────────────────────────────────────────────────
# Both engines enumerate the ten tools — eunox's spec rejects a bare tool:* as
# too broad (SPEC § 3.2.1) — but eunox declares the shared gate once and reuses
# it across every tool with a YAML anchor, so the gate is written in one place:
#
#   capabilities:
#     - target: "tool:read_file"
#       actions: [call]
#       conditions: &path-policy        # write the gate once …
#         - type: allowedValues
#           argument: path
#           values: ["/reports/**"]
#     - target: "tool:write_file"
#       actions: [call]
#       conditions: *path-policy        # … reuse it for the rest
#
# The decisive difference is the rate limit: enforcing maxCalls in OPA is
# impossible without external state.  eunox adds it as one more condition:
#   - type: maxCalls
#     count: 5
#     windowSeconds: 60
