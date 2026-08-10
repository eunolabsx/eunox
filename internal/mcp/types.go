// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package mcp holds the JSON message data-transfer types for the MCP shapes production
// code actually decodes: initialize/tools/call/resources-read(-subscribe/-unsubscribe)/
// prompts/get params, plus initialize and tools/list results. Pure JSON structs, no
// methods.
//
// Deliberately scoped to those decoders, not protocol symmetry: resources/list and
// prompts/list result shapes live in internal/mcp/mcptest instead, since the list
// filters in internal/pdp decode their own inline structs (pdp has no internal/mcp
// dependency) and the transports never parse those results at all.
package mcp

import "encoding/json"

// InitResult is the result field of an `initialize` response.
type InitResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      map[string]interface{} `json:"serverInfo"`
	Instructions    string                 `json:"instructions,omitempty"`
}

// DiscoverResult is the result field of a `server/discover` response — the 2026-07-28 way a
// leg is opened.
//
// It carries no protocolVersion: that revision negotiates none, the client declares one on
// every request, so there is no field here for an upstream to answer with. The rest is the
// same server description `initialize` returns, which is what lets one UpstreamHandshake serve
// both openers.
type DiscoverResult struct {
	Capabilities map[string]interface{} `json:"capabilities"`
	ServerInfo   map[string]interface{} `json:"serverInfo"`
	Instructions string                 `json:"instructions,omitempty"`
}

// ToolCallParams is the params field of a `tools/call` request.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
	// Meta carries the request's `_meta` block, left as raw JSON per key so an
	// unmodeled key is neither decoded nor disturbed; params are forwarded upstream
	// verbatim regardless (see capability.MetaKeyContextManifest for the one key read).
	Meta map[string]json.RawMessage `json:"_meta,omitempty"`
}

// ToolsListResult is the result field of a tools/list response.
type ToolsListResult struct {
	Tools []ToolEntry `json:"tools"`
}

// ToolEntry is one tool in the tools/list result. Title, Annotations, and OutputSchema
// are model-facing metadata carried here so the FM-5 description-hash pin covers them
// too — otherwise an upstream could rewrite them to inject instructions and evade a pin
// that hashed only description + input-parameter descriptions.
type ToolEntry struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description,omitempty"`
	InputSchema  map[string]interface{} `json:"inputSchema,omitempty"`
	Title        string                 `json:"title,omitempty"`
	Annotations  map[string]interface{} `json:"annotations,omitempty"`
	OutputSchema map[string]interface{} `json:"outputSchema,omitempty"`
}

// ResourceReadParams is the params field of a `resources/read` request.
// Also used for `resources/subscribe` and `resources/unsubscribe`, which have the
// same wire shape.
type ResourceReadParams struct {
	URI string `json:"uri"`
}

// PromptGetParams is the params field of a `prompts/get` request.
type PromptGetParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}
