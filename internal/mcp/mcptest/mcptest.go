// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package mcptest holds MCP message shapes used only by tests to assemble
// mock-upstream fixtures. They live here, out of the production internal/mcp
// surface, because the proxy never decodes them: a tools/call RESULT is forwarded
// (and redacted over its raw bytes via JSONPath) but never parsed into a struct, so
// modeling ToolCallResult/Content as production types would misrepresent what
// internal/mcp actually enforces.
//
// The resources/list and prompts/list result shapes are here for the same reason.
// Their entries ARE filtered in production, but by list filters in internal/pdp that
// decode their own inline structs (pdp carries no internal/mcp dependency) and
// preserve unknown fields over the raw bytes; nothing in the tree decodes these
// structs outside tests.
package mcptest

import "encoding/json"

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

// ResourcesListResult is the result field of a `resources/list` response, used by
// tests to build mock-upstream responses and to decode a filtered one.
type ResourcesListResult struct {
	Resources []ResourceEntry `json:"resources"`
}

// ResourceEntry is one resource in a `resources/list` result.
type ResourceEntry struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// PromptsListResult is the result field of a `prompts/list` response, used by tests
// to build mock-upstream responses and to decode a filtered one.
type PromptsListResult struct {
	Prompts []PromptEntry `json:"prompts"`
}

// PromptEntry is one prompt in a `prompts/list` result.
type PromptEntry struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
}
