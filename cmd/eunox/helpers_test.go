// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

// Shared package-main test helpers, fixtures, and doubles. These are consolidated
// from the former jwt_test_helpers_test.go, manifest_helpers_test.go, and
// transport_doubles_test.go.
//
// JWT helpers: for the package-main tests that exercise the proxy through the
// exported pdp API. These are intentional duplicates of the white-box helpers of
// the same name in internal/pdp/jwt_test.go: the white-box tests there build
// tokens with the package-private claim structs, while this package can only
// reach pdp through its exported surface, so the token builders here emit the
// same claim JSON via local types instead.
//
// Manifest helpers: the manifest loader and validators now live in
// internal/config, so these package-main copies serve the integration tests that
// load fixtures through config.LoadManifest; the config package keeps its own
// copy for the white-box loader tests.
//
// Transport doubles: duplicated from internal/transport for the package-main
// tests that still exercise the proxy through the exported transport API. The
// transport runtime — and these doubles' authoritative copies — moved to
// internal/transport; a package-main test cannot reach an unexported transport
// helper, so the doubles it needs are duplicated here.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/mcp/mcptest"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/capability"
)

// ---------------------------------------------------------------------------
// JWT test helpers
// ---------------------------------------------------------------------------

// mcpClaimVersionForTest mirrors the only accepted mcp.v value ("0.2"); it is a
// local copy of the pdp-internal mcpClaimVersion so this package can mint
// current-version tokens without importing the internal constant.
const mcpClaimVersionForTest = "0.2"

// testKey holds an ECDSA key pair for signing test JWTs.
type testKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newTestKey(t *testing.T, kid string) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return testKey{priv: priv, kid: kid}
}

// makeJWKSServer returns a test JWKS HTTP server serving the public key.
func makeJWKSServer(t *testing.T, keys ...testKey) *httptest.Server {
	t.Helper()
	jwks := jose.JSONWebKeySet{}
	for _, k := range keys {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   k.priv.Public(),
			KeyID: k.kid,
			Use:   "sig",
		})
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
}

// mcpClaimSetForTest is a local mirror of the pdp-internal mcpClaimSet, used only
// to serialize the mcp claim block when minting test tokens.
type mcpClaimSetForTest struct {
	Version      string    `json:"v"`
	Capabilities *[]string `json:"capabilities,omitempty"` // nil ⟹ field absent
	TaskID       string    `json:"task_id"`
	AgentID      string    `json:"agent_id"`
}

// idpJWTPayloadForTest is a local mirror of the pdp-internal idpJWTPayload.
type idpJWTPayloadForTest struct {
	MCP mcpClaimSetForTest `json:"mcp"`
}

// makeIDPToken signs an IdP JWT using the current mcp claim version ("0.2").
func makeIDPToken(t *testing.T, key testKey, caps []string, iss, aud, sub string, exp time.Time) string {
	t.Helper()
	return makeIDPTokenVersion(t, key, caps, mcpClaimVersionForTest, iss, aud, sub, exp)
}

// makeIDPTokenVersion signs an IdP JWT with an explicit mcp.v value.
func makeIDPTokenVersion(t *testing.T, key testKey, caps []string, version, iss, aud, sub string, exp time.Time) string {
	t.Helper()

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	now := time.Now()
	stdClaims := jwt.Claims{
		Issuer:   iss,
		Subject:  sub,
		Audience: jwt.Audience{aud},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(exp),
	}
	// Use a pointer so that a non-nil caps slice (even empty) marshals the
	// "capabilities" field and a nil caps slice omits it entirely (§ 5.2).
	mcpClaims := mcpClaimSetForTest{Version: version}
	if caps != nil {
		mcpClaims.Capabilities = &caps
	}
	payload := idpJWTPayloadForTest{MCP: mcpClaims}
	token, err := jwt.Signed(sig).Claims(stdClaims).Claims(payload).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

// makeJWTPDP creates a pdp.JWTPDP pointing at the given httptest.Server JWKS endpoint.
// Tests that pass "" for iss/aud are not exercising issuer/audience validation:
// AllowAnyIssuer/AllowAnyAudience are set automatically so the empty-issuer and
// empty-audience fail-closed fixes (which reject every token when nothing is
// pinned) do not break unrelated tests.
func makeJWTPDP(t *testing.T, srv *httptest.Server, iss, aud string, inner pdp.PolicyDecisionPoint) *pdp.JWTPDP {
	t.Helper()
	return pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:          srv.URL + "/",
		Issuer:           iss,
		AllowAnyIssuer:   iss == "",
		Audience:         aud,
		AllowAnyAudience: aud == "",
		Inner:            inner,
		CacheTTL:         5 * time.Second,
		// The mcp.capabilities schema is experimental and OFF by default; opt in so these
		// tests exercise the v0.2 enforcement logic.
		ExperimentalCapabilities: true,
	})
}

// Note: makeJWTPDPWithInner, makeJWTCtx, and makeJWTToken are defined only in the
// package-transport copy of these helpers (internal/transport/jwt_test_helpers_test.go)
// — their callers (the HTTP JWT-mode transport tests, the gateway JWT-intersection
// tests) moved there with the transport runtime, leaving no package-main user.

// ---------------------------------------------------------------------------
// Manifest fixtures
// ---------------------------------------------------------------------------

// writeManifestFile writes content to a temp file with a .yaml extension and
// returns its path. The file is removed at test cleanup. The manifest loader and
// validators now live in internal/config, so this package-main copy serves the
// integration tests (drift_test.go, pdp_test.go, init_manifest_test.go) that load
// fixtures through config.LoadManifest; the config package keeps its own copy for
// the white-box loader tests.
func writeManifestFile(t *testing.T, content string) string {
	t.Helper()
	// These content-focused fixtures omit the required schemaVersion for brevity;
	// inject a supported one so each test reaches its actual assertion. The
	// schemaVersion gate itself is covered by TestLoadManifest_SchemaVersion.
	if !strings.Contains(content, "schemaVersion") {
		content = "schemaVersion: \"0.1\"\n" + content
	}
	f, err := os.CreateTemp(t.TempDir(), "manifest-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

// manifestWith builds a config.LocalManifest from the given constraints. The
// drift-comparison logic moved to internal/drift (which keeps its own white-box
// copy), but several package-main integration tests (drift_test.go,
// validate_live_test.go, integration_test.go) still construct manifests this way,
// so the helper stays here as a shared package-main fixture builder.
func manifestWith(caps ...capability.Constraint) *config.LocalManifest {
	return &config.LocalManifest{
		Name:         "test-policy",
		Version:      "1.0.0",
		Capabilities: caps,
	}
}

// ---------------------------------------------------------------------------
// Fake upstream MCP server
// ---------------------------------------------------------------------------

// fakeRequest records a single HTTP request received by the fake upstream.
type fakeRequest struct {
	Method    string
	SessionID string
	Body      mcp.RPCMsg
}

// fakeUpstream is a minimal MCP HTTP server for testing.
// It handles initialize + notifications/initialized correctly, and returns
// configurable responses for tools/call.
type fakeUpstream struct {
	mu       sync.Mutex
	received []fakeRequest

	toolResult json.RawMessage // returned for tools/call; defaults to a text result

	// toolCallback, when non-nil, is called instead of using toolResult.
	// It receives the tool name and arguments and returns a raw JSON result.
	toolCallback func(name string, args map[string]interface{}) json.RawMessage
}

func newFakeUpstream() *fakeUpstream {
	defaultResult, _ := json.Marshal(mcptest.ToolCallResult{
		Content: []mcptest.Content{{Type: "text", Text: `{"ok":true}`}},
	})
	return &fakeUpstream{toolResult: defaultResult}
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg mcp.RPCMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.received = append(f.received, fakeRequest{
		Method:    msg.Method,
		SessionID: r.Header.Get(transport.SessionHeader),
		Body:      msg,
	})
	f.mu.Unlock()

	switch msg.Method {
	case "initialize":
		w.Header().Set(transport.SessionHeader, "upstream-sess-1")
		w.Header().Set("Content-Type", "application/json")
		caps, _ := json.Marshal(map[string]interface{}{"tools": map[string]interface{}{}})
		result := mcp.InitResult{
			ProtocolVersion: transport.MCPProtocolVersion,
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      map[string]interface{}{"name": "fake-upstream", "version": "0.0.1"},
		}
		_ = caps
		resp, _ := mcp.SuccessResponse(msg.ID, result)
		_ = json.NewEncoder(w).Encode(resp)

	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)

	case "tools/call":
		var params mcp.ToolCallParams
		_ = json.Unmarshal(msg.Params, &params)

		var resultBytes json.RawMessage
		f.mu.Lock()
		if f.toolCallback != nil {
			resultBytes = f.toolCallback(params.Name, params.Arguments)
		} else {
			resultBytes = f.toolResult
		}
		f.mu.Unlock()

		resp := mcp.RPCMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  resultBytes,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)

	default:
		// Forward all other methods: echo back a generic success.
		resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{"method": msg.Method})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Received returns a copy of all requests received so far.
func (f *fakeUpstream) Received() []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]fakeRequest, len(f.received))
	copy(cp, f.received)
	return cp
}

// CountByMethod returns the number of requests with the given method.
func (f *fakeUpstream) CountByMethod(method string) int {
	received := f.Received()
	n := 0
	for i := range received {
		if received[i].Body.Method == method {
			n++
		}
	}
	return n
}

// denyAllPDP always denies every request (tools, resources, prompts).
type denyAllPDP struct{}

func (denyAllPDP) Decide(_ context.Context, _ string, target pdp.EnforceTarget, _ map[string]interface{}, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    "CAPABILITY_DENIED",
			Message: "denied by test policy: " + target.Name,
		},
	}
}

func (denyAllPDP) DecideResourceRead(_ context.Context, _, uri, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: "CAPABILITY_DENIED", Message: "denied by test policy: " + uri},
	}
}

func (denyAllPDP) DecideResourceCancel(_ context.Context, _, uri, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: "CAPABILITY_DENIED", Message: "denied by test policy: " + uri},
	}
}

func (denyAllPDP) DecidePromptGet(_ context.Context, _, promptName, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: "CAPABILITY_DENIED", Message: "denied by test policy: " + promptName},
	}
}

func (denyAllPDP) DecideSampling(_ context.Context, _, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    "SAMPLING_DENIED",
			Message: "denied by test policy: sampling",
		},
	}
}

// HardenRefusal is the identity: a deny-all test PDP holds no pin, no ceiling and no
// obligations, so it has nothing to contribute to another layer's refusal.
func (denyAllPDP) HardenRefusal(_ context.Context, _ string, r capability.EnforceResponse, _ pdp.EnforceTarget, _ map[string]interface{}) capability.EnforceResponse {
	return r
}

func (denyAllPDP) FilterToolsList(_ context.Context, result json.RawMessage) pdp.ListFilterResult {
	return pdp.ListFilterResult{Result: result}
}

func (denyAllPDP) FilterResourcesList(_ context.Context, result json.RawMessage) pdp.ListFilterResult {
	return pdp.ListFilterResult{Result: result}
}

func (denyAllPDP) FilterPromptsList(_ context.Context, result json.RawMessage) pdp.ListFilterResult {
	return pdp.ListFilterResult{Result: result}
}

func (denyAllPDP) CheckKill(_ context.Context, _ string) *capability.EnforceResponse {
	return nil
}

func (denyAllPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}
func (denyAllPDP) RecordObservedToolHashes(_ context.Context, _ json.RawMessage) int { return 0 }
func (denyAllPDP) ReleaseSession(_ context.Context, _ string)                        {}
func (denyAllPDP) RestoreDeclassified(_ context.Context, _ string, l []string) (bool, error) {
	return len(l) == 0, nil
}

// fakeUpstreamWithTools extends fakeUpstream to respond to tools/list.
type fakeUpstreamWithTools struct {
	*fakeUpstream
	tools []mcp.ToolEntry
}

func newFakeUpstreamWithTools(tools []mcp.ToolEntry) *fakeUpstreamWithTools {
	return &fakeUpstreamWithTools{fakeUpstream: newFakeUpstream(), tools: tools}
}

func (f *fakeUpstreamWithTools) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var msg mcp.RPCMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.received = append(f.received, fakeRequest{
		Method: msg.Method, SessionID: r.Header.Get(transport.SessionHeader), Body: msg,
	})
	f.mu.Unlock()

	switch msg.Method {
	case "initialize":
		w.Header().Set(transport.SessionHeader, "upstream-sess-1")
		w.Header().Set("Content-Type", "application/json")
		result := mcp.InitResult{
			ProtocolVersion: transport.MCPProtocolVersion,
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      map[string]interface{}{"name": "fake", "version": "0.0.1"},
		}
		resp, _ := mcp.SuccessResponse(msg.ID, result)
		_ = json.NewEncoder(w).Encode(resp)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		result := mcp.ToolsListResult{Tools: f.tools}
		resp, _ := mcp.SuccessResponse(msg.ID, result)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	default:
		resp, _ := mcp.SuccessResponse(msg.ID, map[string]interface{}{"method": msg.Method})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// staticPDP is a PolicyDecisionPoint that always returns a fixed decision.
type staticPDP struct {
	decision capability.EnforceResponse
}

func (s *staticPDP) Decide(_ context.Context, _ string, _ pdp.EnforceTarget, _ map[string]interface{}, _ string) capability.EnforceResponse {
	return s.decision
}

func (s *staticPDP) DecideResourceRead(_ context.Context, _, _, _ string) capability.EnforceResponse {
	return s.decision
}

func (s *staticPDP) DecideResourceCancel(_ context.Context, _, _, _ string) capability.EnforceResponse {
	return s.decision
}

func (s *staticPDP) DecidePromptGet(_ context.Context, _, _, _ string) capability.EnforceResponse {
	return s.decision
}

func (*staticPDP) DecideSampling(_ context.Context, _, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    "SAMPLING_DENIED",
			Message: "staticPDP: sampling deny-by-default",
		},
	}
}

// HardenRefusal is the identity: a fixed-decision test PDP holds no pin, no ceiling and
// no obligations, so it has nothing to contribute to another layer's refusal.
func (*staticPDP) HardenRefusal(_ context.Context, _ string, r capability.EnforceResponse, _ pdp.EnforceTarget, _ map[string]interface{}) capability.EnforceResponse {
	return r
}

func (*staticPDP) FilterToolsList(_ context.Context, result json.RawMessage) pdp.ListFilterResult {
	return pdp.ListFilterResult{Result: result}
}

func (*staticPDP) FilterResourcesList(_ context.Context, result json.RawMessage) pdp.ListFilterResult {
	return pdp.ListFilterResult{Result: result}
}

func (*staticPDP) FilterPromptsList(_ context.Context, result json.RawMessage) pdp.ListFilterResult {
	return pdp.ListFilterResult{Result: result}
}

func (*staticPDP) CheckKill(_ context.Context, _ string) *capability.EnforceResponse {
	return nil
}

func (*staticPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}
func (*staticPDP) RecordObservedToolHashes(_ context.Context, _ json.RawMessage) int { return 0 }
func (*staticPDP) ReleaseSession(_ context.Context, _ string)                        {}
func (*staticPDP) RestoreDeclassified(_ context.Context, _ string, l []string) (bool, error) {
	return len(l) == 0, nil
}
