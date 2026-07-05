// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// OAuth 2.0 Protected Resource Metadata (RFC 9728) for the HTTP transport.
//
// eunox is an OAuth 2.0 resource server: it consumes Bearer JWTs issued by an
// IdP (--jwks-uri) but never participates in the OAuth flow itself. RFC 9728
// requires a resource server to advertise *where to get a token* via:
//
//  1. A metadata document at /.well-known/oauth-protected-resource (and the
//     per-route path-inserted variants for each /mcp/<name> route).
//  2. A WWW-Authenticate challenge on every 401, pointing at that document.
//
// The stdio transport has no HTTP surface and is therefore unchanged.

package transport

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// OAuthResourceMetadata is the RFC 9728 protected-resource metadata document
// served at /.well-known/oauth-protected-resource. Fields with zero values
// are omitted so the document stays minimal when not fully configured.
type OAuthResourceMetadata struct {
	// Resource is the URI of this protected resource, set via --oauth-resource
	// or listen.oauthResource. Never derived from the request Host header.
	Resource string `json:"resource,omitempty"`
	// AuthorizationServers lists the OAuth 2.0 authorization servers that
	// issue tokens for this resource. Defaults to --jwt-issuer.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
}

// metadataBasePath is the RFC 9728 well-known URI path.
const metadataBasePath = "/.well-known/oauth-protected-resource"

// BuildOAuthMetadataURL returns the URL the protected-resource metadata document
// is published at, per RFC 9728 §3.1: the well-known segment is inserted between
// the authority and the resource's path, not appended after the whole identifier.
// So https://proxy.example.com/mcp/github yields
// https://proxy.example.com/.well-known/oauth-protected-resource/mcp/github
// (exactly the path the proxy serves it at). A path-less resource yields
// https://host/.well-known/oauth-protected-resource. The advertised URL must
// match the served one, or a client following the challenge fetches a 404.
func BuildOAuthMetadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" {
		// resource is validated at startup; defensive fallback only.
		return strings.TrimRight(resource, "/") + metadataBasePath
	}
	// Use the ESCAPED path, not the decoded u.Path: the result is both advertised in
	// the WWW-Authenticate challenge AND registered as a net/http ServeMux pattern. A
	// decoded path containing a space, tab, or "{"/"}" (e.g. from a "%20"/"%7B"
	// resource path) is grammar-special in the Go 1.22+ ServeMux pattern syntax and
	// would panic mux.HandleFunc at startup; the escaped form carries only "%XX" bytes,
	// which is a valid pattern and matches the re-encoded path a client sends.
	return u.Scheme + "://" + u.Host + metadataBasePath + strings.TrimRight(u.EscapedPath(), "/")
}

// oauthMetadataPathSuffix returns the served-path suffix after metadataBasePath
// for a path-bearing resource (e.g. .../oauth-protected-resource/mcp -> "/mcp"),
// or "" for a path-less resource (covered by the bare metadataBasePath
// registration). metaURL is a BuildOAuthMetadataURL value, keeping the registered
// served path in lockstep with the advertised one.
func oauthMetadataPathSuffix(metaURL string) string {
	u, err := url.Parse(metaURL)
	if err != nil {
		return ""
	}
	// Use EscapedPath so the registered ServeMux pattern keeps any "%XX" bytes
	// BuildOAuthMetadataURL preserved (rather than re-decoding them into grammar-special
	// characters that panic mux.HandleFunc). metadataBasePath has no escapable bytes, so
	// it is a clean prefix of the escaped path. Guard the prefix: BuildOAuthMetadataURL's
	// defensive fallback (malformed resource) can place metadataBasePath elsewhere, and a
	// bare TrimPrefix would then no-op and return the whole path, which the caller would
	// re-prepend with metadataBasePath (doubling it). Return no suffix in that case.
	escaped := u.EscapedPath()
	if !strings.HasPrefix(escaped, metadataBasePath) {
		return ""
	}
	return strings.TrimPrefix(escaped, metadataBasePath)
}

// buildWWWAuthenticate returns the WWW-Authenticate header value for a 401.
// credPresented (a rejected credential was sent) adds error="invalid_token".
// metaURL, when non-empty, is included as resource_metadata so clients can
// discover the authorization server.
func buildWWWAuthenticate(credPresented bool, metaURL string) string {
	var b strings.Builder
	b.WriteString(`Bearer realm="eunox"`)
	if credPresented {
		b.WriteString(`, error="invalid_token"`)
	}
	if metaURL != "" {
		// Defense-in-depth: --oauth-resource is validated at startup, but escape per
		// RFC 7235 quoted-string rules here too so this builder never emits a
		// malformed challenge regardless of how metaURL was produced.
		escaped := strings.ReplaceAll(metaURL, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		b.WriteString(`, resource_metadata="`)
		b.WriteString(escaped)
		b.WriteString(`"`)
	}
	return b.String()
}

// serveOAuthMetadata handles GET /.well-known/oauth-protected-resource (and
// the per-route path variants registered in gateway mode for each /mcp/<name>
// route). All paths serve the same global document.
//
// The endpoint is unauthenticated by design: the document contains only
// authorization-server pointers, never policy or manifest content.
func (p *HTTPProxy) serveOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	// HEAD is handled like GET but without a body (RFC 7231 §4.3.2). Go's ServeMux
	// does not auto-translate HEAD to GET, so rejecting it with 405 would break
	// discovery existence-checks and cache validation.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.oauthMeta == nil {
		http.NotFound(w, r)
		return
	}
	doc, err := json.Marshal(p.oauthMeta)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return // headers sent; HEAD carries no body
	}
	_, _ = w.Write(doc)
}
