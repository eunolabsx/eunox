// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package mcp holds the JSON message data-transfer types for the MCP (Model
// Context Protocol) shapes production code actually decodes: the params of
// initialize, tools/call, resources/read (and its identical resources/subscribe and
// resources/unsubscribe twins), and prompts/get, plus the results of initialize and tools/list. They are
// pure JSON structs with no methods.
//
// The set is deliberately scoped to those decoders rather than to protocol
// symmetry. The resources/list and prompts/list result shapes are NOT here: the
// list filters in internal/pdp decode their own inline structs by design (pdp has
// no internal/mcp dependency) and the transports never parse those results at all,
// so the fixture shapes tests need live in internal/mcp/mcptest alongside the other
// test-only message types.
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
	// Meta carries the request's `_meta` block, left as raw JSON per namespaced key so a
	// key eunox does not model is neither decoded nor disturbed. Today the proxy reads
	// exactly one key from it — the attribution interface's context manifest (see
	// capability.MetaKeyContextManifest) — and the params are forwarded upstream
	// VERBATIM regardless, so a key meant for the upstream still reaches it untouched.
	Meta map[string]json.RawMessage `json:"_meta,omitempty"`
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
