// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package mcptest holds MCP message shapes used only by tests to assemble mock-upstream
// fixtures, kept out of internal/mcp because production never decodes them: a tools/call
// result is redacted over its raw bytes, not parsed into a struct, and resources/list and
// prompts/list entries are filtered by internal/pdp's own inline structs instead.
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
