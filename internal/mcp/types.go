// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package mcp holds the JSON message data-transfer types for the MCP (Model
// Context Protocol) methods the proxy enforces: the params and result shapes of
// initialize, tools/call, tools/list, resources/read, resources/list,
// prompts/get, and prompts/list. They are pure JSON structs with no methods,
// shared by the proxy's transports and policy decision points.
package mcp

import "encoding/json"

// InitResult is the result field of an `initialize` response.
type InitResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      map[string]interface{} `json:"serverInfo"`
	Instructions    string                 `json:"instructions,omitempty"`
}

// ToolCallParams is the params field of a `tools/call` request.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ToolsListResult is the result field of a tools/list response.
type ToolsListResult struct {
	Tools []ToolEntry `json:"tools"`
}

// ToolEntry is one tool in the tools/list result. Title, Annotations, and
// OutputSchema are model-facing metadata (common hosts render a tool's title,
// annotations, and output-schema parameter descriptions to the model alongside its
// description), so they are carried here to be covered by the FM-5 description-hash
// pin — an upstream that rewrites them to inject instructions would otherwise evade
// a pin that hashes only description + input-parameter descriptions.
type ToolEntry struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description,omitempty"`
	InputSchema  map[string]interface{} `json:"inputSchema,omitempty"`
	Title        string                 `json:"title,omitempty"`
	Annotations  map[string]interface{} `json:"annotations,omitempty"`
	OutputSchema map[string]interface{} `json:"outputSchema,omitempty"`
}

// ResourceReadParams is the params field of a `resources/read` request.
// Also used for `resources/subscribe` which has the same wire shape.
type ResourceReadParams struct {
	URI string `json:"uri"`
}

// ResourcesListResult is the result field of a `resources/list` response.
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

// PromptsListResult is the result field of a `prompts/list` response.
type PromptsListResult struct {
	Prompts []PromptEntry `json:"prompts"`
}

// PromptEntry is one prompt in a `prompts/list` result.
type PromptEntry struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
}

// PromptGetParams is the params field of a `prompts/get` request.
type PromptGetParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}
