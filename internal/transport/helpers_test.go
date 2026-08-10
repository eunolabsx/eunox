// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Stderr-capture stubs for the transport-side drift-integration tests.
//
// The authoritative drift-comparison logic lives in internal/drift
// (drift.CheckManifestDrift, drift.MakeDriftCheck, …). The transport runtime
// deliberately does not depend on the comparison itself — it receives an opaque
// drift.CheckFunc. The integration tests that drive the
// transport's session-start path with a real drift hook now import internal/drift
// directly (drift.MakeDriftCheck / drift.CheckManifestDrift / …), so the faithful
// copy of the algorithm this file once carried is gone — the duplication the
// The duplication that the relocation introduced is deleted now that internal/drift is importable
// from both package main and this package.
//
// What remains are three no-op stderr-capture shims the HTTP drift integration
// tests still call: those tests verify behavior via upstream request counts and
// session outcomes rather than captured log output, so os.Stderr is not actually
// intercepted here.

// overrideStderr is a no-op placeholder: the HTTP drift integration tests verify
// behavior via upstream request counts and session outcomes rather than captured
// log output.
func overrideStderr(buf *bytes.Buffer) *bytes.Buffer { return buf }

// restoreStderr is a no-op for the same reason.
func restoreStderr(_ *bytes.Buffer) {}

// waitForLog is a no-op placeholder (os.Stderr is not intercepted in these
// tests); the surrounding assertions confirm the drift check ran.
func waitForLog(t *testing.T, _ *bytes.Buffer, _ string) {
	t.Helper()
}

// syncBuffer is a mutex-guarded bytes.Buffer for tests that inject a writer into an
// HTTPProxy/StdioProxy (via HTTPGatewayOptions.Stderr / StdioProxyOptions.Stderr) and then
// read it back: a proxy's diagnostic lines can be written from a background goroutine (session
// reaping, cleanup) concurrently with the test's own read of the captured text, which a plain
// bytes.Buffer does not allow under -race. Replaces captureStderr's process-global os.Stderr
// swap: the proxy under test gets its own writer at construction instead of racing every
// other test in the package over the same global.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// JWT test helpers for the package-transport tests that exercise the proxy
// through the exported pdp API (the HTTP JWT-mode transport tests, the gateway
// JWT-intersection tests, and the JWT-mode benchmarks). These are intentional
// duplicates of the white-box helpers of the same name in
// internal/pdp/jwt_test.go (and the package-main copy in
// cmd/eunox/jwt_test_helpers_test.go): the white-box tests there build
// tokens with the package-private claim structs, while this package can only
// reach pdp through its exported surface, so the token builders here emit the
// same claim JSON via local types instead. Keeping a copy in each package is the
// documented cost of the package split — neither helper set can serve all
// packages.

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
func makeJWTPDP(t *testing.T, srv *httptest.Server, iss, aud string, inner pdp.PolicyDecisionPoint) *pdp.JWTPDP {
	t.Helper()
	return pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:  srv.URL + "/",
		Issuer:   iss,
		Audience: aud,
		Inner:    inner,
		CacheTTL: 5 * time.Second,
		// The mcp.capabilities schema is experimental and OFF by default; transport JWT
		// tests exercise the v0.2 enforcement, so opt in.
		ExperimentalCapabilities: true,
	})
}

// makeJWTPDPWithInner builds a pdp.JWTPDP over a fresh JWKS server for key,
// wrapping inner, and returns it with the server's cleanup. AllowAnyIssuer and
// AllowAnyAudience are set so callers that mint tokens without an iss/aud (e.g.
// allowlist tests) are not rejected by the issuer/audience guard.
func makeJWTPDPWithInner(t *testing.T, key testKey, inner pdp.PolicyDecisionPoint) (validator *pdp.JWTPDP, cleanup func()) {
	t.Helper()
	srv := makeJWKSServer(t, key)
	return pdp.NewJWTPDP(pdp.JWTPDPOptions{
		JWKSURI:                  srv.URL + "/",
		AllowAnyIssuer:           true,
		AllowAnyAudience:         true,
		Inner:                    inner,
		CacheTTL:                 5 * time.Second,
		ExperimentalCapabilities: true,
	}), srv.Close
}

// makeJWTCtx validates token through p and returns the resulting claims context.
func makeJWTCtx(t *testing.T, p *pdp.JWTPDP, token string) context.Context {
	t.Helper()
	ctx, err := p.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	return ctx
}

// makeJWTToken mints a token for the gateway tests.
func makeJWTToken(t *testing.T, key testKey, caps []string) string {
	t.Helper()
	return makeIDPToken(t, key, caps, "", "", "agent-g", time.Now().Add(time.Hour))
}

// PDP-construction test helpers for the package-transport tests that exercise
// the proxy through the exported pdp API (the enforcement-gap coverage, the
// unmapped-method denials, the adversarial and benchmark suites). These are
// intentional duplicates of the helpers of the same name in
// cmd/eunox/pdp_test.go, where the package-main PDP/redaction tests still
// live: neither helper set can serve both packages once the transport runtime
// moved out of package main, so each package keeps its own copy. This is the
// documented cost of the package split.

// newTestManifestPDP builds a ManifestPDP with the given capabilities.
// No ActionResolver is attached; tests rely on generic "call"/"*" actions.
func newTestManifestPDP(caps ...capability.Constraint) *pdp.ManifestPDP {
	return newTestManifestPDPWithKS(killswitch.NewInMemory(), caps...)
}

// newTestManifestPDPWithKS is newTestManifestPDP with a caller-supplied
// kill-switch manager, for tests that pre-arm kills or share the manager
// with a JWT wrapper.
func newTestManifestPDPWithKS(ks killswitch.Manager, caps ...capability.Constraint) *pdp.ManifestPDP {
	manifest := &config.LocalManifest{
		Name:         "test-policy",
		Version:      "1.0.0",
		Capabilities: caps,
	}
	return pdp.NewManifestPDP(manifest.Capabilities, enforcement.New(), ks)
}

// auditToolEntry is a tool entry in audit mode whose allowedValues condition
// only permits paths under /allowed — so a non-matching path "would deny".
func auditToolEntry() capability.Constraint {
	return capability.Constraint{
		Target:      "tool:read_file",
		Actions:     []string{"call"},
		Enforcement: capability.EnforcementAudit,
		Conditions: []capability.Condition{
			&capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/allowed/*"}},
		},
	}
}

func intPtr(i int) *int { return &i }

// httpProxyOptions configures a single-upstream test HTTPProxy. Production builds
// routes via BuildRoutes and calls NewHTTPProxyGateway; this test helper synthesizes
// one ""-keyed route and routes through the SAME NewHTTPProxyGateway constructor, so
// a field newly wired into the gateway constructor is exercised by these tests too
// instead of silently diverging from production.
type httpProxyOptions struct {
	Command        string
	Args           []string
	PDP            pdp.PolicyDecisionPoint
	JWTPDP         *pdp.JWTPDP            // non-nil when --jwks-uri is configured
	OAuthMeta      *OAuthResourceMetadata // RFC 9728 metadata document; nil when JWT auth is not configured
	OAuthMetaURL   string                 // absolute URL for resource_metadata in challenges
	Sink           *audit.Sink
	KS             killswitch.Manager
	ShutdownMs     int
	UpstreamTimeMs int
	AuthToken      string
	// ControlToken authenticates POST /control/kill (loopback only). Generated at
	// startup by the proxy command; required independently of AuthToken/JWT mode.
	ControlToken      string
	TrustFwdFor       bool
	TrustedProxyCIDRs []string
	Port              int
	Bind              string

	// MaxSessions caps concurrent sessions (0 = unlimited); SessionIdleMs reaps
	// sessions idle for that many milliseconds (0 = no reaping).
	MaxSessions   int
	SessionIdleMs int

	// AllowedOrigins is the operator-configured full-origin allowlist, accepted in
	// addition to the built-in loopback names and bind host. See checkOrigin.
	AllowedOrigins []string

	// Remote upstream options. When UpstreamURL is non-empty the proxy routes
	// requests to the named HTTP MCP server instead of spawning a subprocess.
	UpstreamURL           string // base URL of remote MCP server, e.g. https://mcp.stripe.com
	UpstreamAuthHeader    string // header line forwarded to upstream, e.g. "Authorization: Bearer sk-..."
	UpstreamTLSSkipVerify bool   // skip TLS verification (dev only; logs a loud warning)
	// UpstreamProtocolVersion is the route's revision pin, which selects how the upstream leg
	// is opened. Empty opens with the handshake, as `auto` does.
	UpstreamProtocolVersion capability.Revision

	Audit              bool // observe mode: evaluate and log, but forward instead of block
	RequireAuditStrict bool // --require-audit=strict: deny forwards once the audit trail degrades

	// DriftCheck is the injected drift hook; nil = no drift checking.
	DriftCheck drift.CheckFunc

	// Stderr, when set, captures this proxy's diagnostic lines instead of the real
	// os.Stderr — the injectable-writer seam a test asserting on a startup/lifecycle line
	// uses instead of swapping the process-global (see HTTPProxy.stderr).
	Stderr io.Writer
}

// newHTTPProxy builds a single-upstream test HTTPProxy. It synthesizes one route
// keyed by "" (served at /mcp) exactly as the binary's single-upstream path does and
// hands it to NewHTTPProxyGateway, so tests construct the proxy the same way
// production does.
func newHTTPProxy(opts httpProxyOptions) *HTTPProxy {
	// Fail closed: an omitted PDP denies every request. (Gateway mode leaves the
	// proxy-level PDP nil and enforces per-route; tests opt into passthrough via
	// AlwaysAllowPDP.)
	if opts.PDP == nil {
		opts.PDP = pdp.DenyAllPDP{}
	}
	transport := "stdio"
	if opts.UpstreamURL != "" {
		transport = "http"
	}
	route := &UpstreamRoute{
		name:                    "",
		transport:               transport,
		command:                 opts.Command,
		args:                    opts.Args,
		upstreamURL:             opts.UpstreamURL,
		upstreamAuthHeader:      opts.UpstreamAuthHeader,
		upstreamTLSSkipVerify:   opts.UpstreamTLSSkipVerify,
		upstreamProtocolVersion: opts.UpstreamProtocolVersion,
		pdp:                     opts.PDP,
		audit:                   opts.Audit,
		driftCheck:              opts.DriftCheck,
		sink:                    &routeSink{sink: opts.Sink},
	}
	return NewHTTPProxyGateway(HTTPGatewayOptions{
		Routes:             map[string]*UpstreamRoute{"": route},
		Sink:               opts.Sink,
		KS:                 opts.KS,
		JWTPDP:             opts.JWTPDP,
		OAuthMeta:          opts.OAuthMeta,
		OAuthMetaURL:       opts.OAuthMetaURL,
		ShutdownMs:         opts.ShutdownMs,
		UpstreamTimeMs:     opts.UpstreamTimeMs,
		AuthToken:          opts.AuthToken,
		ControlToken:       opts.ControlToken,
		TrustFwdFor:        opts.TrustFwdFor,
		TrustedProxyCIDRs:  opts.TrustedProxyCIDRs,
		Bind:               opts.Bind,
		Port:               opts.Port,
		MaxSessions:        opts.MaxSessions,
		SessionIdleMs:      opts.SessionIdleMs,
		AllowedOrigins:     opts.AllowedOrigins,
		RequireAuditStrict: opts.RequireAuditStrict,
		Stderr:             opts.Stderr,
	})
}

// errKillSwitchFailed is the sentinel error transport tests inject from a
// kill-switch double's failing method (see http_test.go's killWriteErrSwitch).
var errKillSwitchFailed = &ksTestError{"kill switch backend unavailable"}

type ksTestError struct{ msg string }

func (e *ksTestError) Error() string { return e.msg }
