// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// OAuth 2.0 Protected Resource Metadata (RFC 9728) for the HTTP transport.
//
// eunox is a resource server only (consumes Bearer JWTs via --jwks-uri, never
// participates in the OAuth flow), so RFC 9728 requires it to advertise where to get a
// token: a metadata document at /.well-known/oauth-protected-resource (plus per-route
// variants) and a WWW-Authenticate challenge pointing at it on every 401.

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

// BuildOAuthMetadataURL returns the URL the protected-resource metadata document is
// published at, per RFC 9728 §3.1: the well-known segment is inserted between the
// authority and the resource's path (e.g. .../mcp/github ->
// .../.well-known/oauth-protected-resource/mcp/github), not appended after it — the
// advertised URL must match the served one or a client following the challenge 404s.
func BuildOAuthMetadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" {
		// resource is validated at startup; defensive fallback only.
		return strings.TrimRight(resource, "/") + metadataBasePath
	}
	// Use the ESCAPED path, not decoded u.Path: this also becomes a ServeMux pattern, and a
	// decoded space/tab/"{"/"}" (from "%20"/"%7B") is grammar-special there and would panic
	// mux.HandleFunc at startup.
	return u.Scheme + "://" + u.Host + metadataBasePath + strings.TrimRight(u.EscapedPath(), "/")
}

// oauthMetadataPathSuffix returns the served-path suffix after metadataBasePath for a
// path-bearing resource (e.g. .../oauth-protected-resource/mcp -> "/mcp"), or "" for a
// path-less one. metaURL is a BuildOAuthMetadataURL value, keeping the registered served
// path in lockstep with the advertised one.
func oauthMetadataPathSuffix(metaURL string) string {
	u, err := url.Parse(metaURL)
	if err != nil {
		return ""
	}
	// EscapedPath keeps any "%XX" bytes BuildOAuthMetadataURL preserved. Guard the prefix:
	// its defensive fallback can place metadataBasePath elsewhere, and an unguarded
	// TrimPrefix would then no-op and let the caller double-prepend metadataBasePath.
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
		// Defense-in-depth: escape per RFC 7235 quoted-string rules here too, even though
		// --oauth-resource is validated at startup.
		escaped := strings.ReplaceAll(metaURL, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		b.WriteString(`, resource_metadata="`)
		b.WriteString(escaped)
		b.WriteString(`"`)
	}
	return b.String()
}

// serveOAuthMetadata handles GET /.well-known/oauth-protected-resource (and the
// per-route variants in gateway mode); all paths serve the same document. Unauthenticated
// by design: the document contains only authorization-server pointers, never policy content.
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
