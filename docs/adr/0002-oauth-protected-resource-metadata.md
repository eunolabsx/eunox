# ADR-0002: Serve OAuth protected-resource metadata in HTTP and gateway modes

- **Status:** Draft
- **Date:** 2026-06-11
- **Deciders:** eunox maintainers

## Context

The MCP authorization spec builds on OAuth 2.1 and requires a resource server
to tell clients *where to get a token*: publish OAuth 2.0 Protected Resource
Metadata (RFC 9728) at a well-known URI, and answer unauthorized requests with
a `WWW-Authenticate` challenge whose `resource_metadata` parameter points at
it. The client discovers the authorization server from that document and runs
the OAuth flow against it — the resource server never participates in the flow
itself.

eunox's HTTP transport already *consumes* the result of that flow: with
`--jwks-uri` set, every request must carry a valid Bearer JWT
([jwt.go](../../internal/pdp/jwt.go)). But both unauthorized paths
return a bare-text 401 with no challenge header — the static-token check
([http_security.go](../../internal/transport/http_security.go)) and the JWT
pre-validation failure ([http_routing.go](../../internal/transport/http_routing.go)) — and no metadata
endpoint exists. A spec-conforming MCP client pointed at an eunox proxy
therefore cannot discover how to authenticate; it can only fail. Gateway mode,
which fronts remote OAuth-era upstreams at `/mcp/<name>`, is where this bites
hardest.

## Decision

We will implement the resource-server discovery surface in the HTTP/gateway
transport:

- Serve RFC 9728 metadata at `/.well-known/oauth-protected-resource` and, in
  gateway mode, at the path-inserted variants RFC 9728 section 3.1 derives for
  each route (`/.well-known/oauth-protected-resource/mcp/<name>`). All paths
  serve one global document, mirroring the fact that a single JWT
  configuration wraps every route
  ([route.go](../../internal/transport/route.go)).
- Add a `WWW-Authenticate: Bearer` challenge to every 401 the transport
  issues, with `error="invalid_token"` when a credential was presented and
  rejected, and with the `resource_metadata` parameter when JWT auth is
  configured.
- `authorization_servers` defaults to the configured `--jwt-issuer` and can be
  overridden explicitly. The `resource` identifier comes from explicit
  configuration only — it is never derived from the request `Host` header.
- The stdio transport is unchanged; it has no HTTP surface to discover.

## Alternatives considered

- **Per-route JWT config with per-route metadata.** Rejected for the first
  cut: today one validator and one shared JWKS cache serve all routes;
  per-route issuers are a real but orthogonal feature, and the discovery
  surface should not block on it.
- **Deriving `resource` from the request `Host` header.** Rejected: the header
  is attacker-influenced, and the resource identifier participates in audience
  binding downstream. Explicit configuration only.
- **Deferring until eunox participates in OAuth flows end-to-end.** Rejected:
  the spec requires the metadata surface of every resource server regardless,
  and clients depend on discovery to even start the flow.

## Consequences

- New configuration keys (CLI flags and gateway-config keys) plus a JSON
  Schema change in `schemas/`, which carries the standing obligations of a
  schema roundtrip test and a `docs/` update in the same PR.
- The 401 response shape changes (challenge header, possibly a structured
  body). Pre-1.0 this is a clean break; no compatibility shim.
- The well-known endpoint is deliberately unauthenticated — metadata is public
  by design. It must only ever serve authorization-server pointers; policy and
  manifest contents stay out of it.
- The July-2026 OIDC-alignment work gets a natural landing spot: discovery
  additions extend this endpoint instead of inventing a new surface.
