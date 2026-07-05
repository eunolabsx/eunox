// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package mcptest holds MCP message shapes used only by tests to assemble
// mock-upstream fixtures. They live here, out of the production internal/mcp
// surface, because the proxy never decodes them: a tools/call RESULT is forwarded
// (and redacted over its raw bytes via JSONPath) but never parsed into a struct, so
// modeling ToolCallResult/Content as production types would misrepresent what
// internal/mcp actually enforces.
package mcptest

// ToolCallResult is a `tools/call` result, used by tests to build mock-upstream
// responses.
type ToolCallResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Content is a single content item in a `tools/call` result.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}
