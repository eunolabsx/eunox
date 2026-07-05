# Reference policy library

Drop-in capability manifests for the MCP servers people actually run. Each
file in this directory is a `eunox validate`-clean YAML manifest you can
copy into your repo, point a route at, and tighten from there.

These are **starting points, not blanket allowlists.** Every file is
deny-by-default (anything the manifest doesn't name is refused), but the
*shape* of safe varies enormously by environment — a path that's harmless on a
laptop is a disaster in a CI runner. Read the comments at the top of each
file, then narrow the conditions to your data.

## Index

| Upstream | Policy | What it constrains |
|---|---|---|
| `@modelcontextprotocol/server-filesystem` | [`filesystem.yaml`](./filesystem.yaml) | Writes confined to a sandbox; executable extensions blocked; reads kept off `.env`, `.pem`, `.key`. |
| `@modelcontextprotocol/server-github` | [`github.yaml`](./github.yaml) | Reads broad, writes narrow and rate-limited; no admin / repo-deletion tools. |
| `@modelcontextprotocol/server-postgres` | [`postgres.yaml`](./postgres.yaml) | `SELECT`-only; per-session call cap; pair with a read-only DB role. |
| `@modelcontextprotocol/server-sqlite` | [`sqlite.yaml`](./sqlite.yaml) | Read-only against the DB; `query` SQL restricted to `SELECT`. |
| `@modelcontextprotocol/server-slack` | [`slack.yaml`](./slack.yaml) | DMs blocked; posts limited to an allowlist of channel IDs; per-session rate cap. |
| `mcp-server-fetch` | [`fetch.yaml`](./fetch.yaml) | HTTPS-only plus rate limiting; private/metadata hostnames are NOT excluded by the default glob — narrow it yourself, see the policy header. |
| `@modelcontextprotocol/server-git` | [`git.yaml`](./git.yaml) | Read-mostly: history inspection plus rate-limited `add`, `commit`, branch creation; no `push`, `reset`, `clean`, force-deletes. |
| `@modelcontextprotocol/server-brave-search` | [`brave-search.yaml`](./brave-search.yaml) | Rate-capped only; no argument constraint on query content or length. |
| `@modelcontextprotocol/server-puppeteer` | [`puppeteer.yaml`](./puppeteer.yaml) | Navigation restricted to an allowlist of domains; `evaluate` blocked. |
| `@modelcontextprotocol/server-memory` | [`memory.yaml`](./memory.yaml) | All ops allowed; documents the audit-only posture for a stateless server. |
| `@stripe/mcp` | [`stripe.yaml`](./stripe.yaml) | Read-only by default; the side that moves money is denied. |
| Audit-only template | [`audit-only.yaml`](./audit-only.yaml) | Observe an unknown server before writing a real policy. |

## How to use one

The policy is referenced from a route's `policy:` field. Minimal example:

```yaml
# eunox.yaml
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: local
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    policy:
      - ./examples/policies/filesystem.yaml
```

```bash
eunox validate ./examples/policies/filesystem.yaml
eunox proxy --config ./eunox.yaml
```

In gateway mode (one HTTP listener fronting many upstreams), each route
references its own policy file. See [`demo/gateway.yaml`](../../demo/gateway.yaml)
for a worked multi-upstream example.

## Conventions used in every file

- **`schemaVersion: "0.1"`** is mandatory; manifests without it are refused
  fail-closed at load.
- **`version`** is the policy-content semver — increment it on every change.
  Each audit record stamps the in-force `policy_version` and a SHA-256 of the
  manifest, so a deployed change is traceable to an exact file.
- **`tool:` / `resource:` / `prompt:` / `system:` prefixes are required**
  on every `target`. Cross-namespace authorization is impossible by design.
- **Comments explain the threat each entry addresses**, not the syntax —
  the syntax is in [`docs/capability-manifest-guide.md`](../../docs/capability-manifest-guide.md).
- Every constraint that's plausibly bypassable through SQL grammar quirks
  (`allowedOperations`, `allowedTables`) is paired with a `maxCalls` cap so a
  successful bypass is also rate-limited.

## Contributing a policy

If you run a popular MCP server that isn't in this list, a PR adding a
reviewed manifest for it is one of the highest-leverage contributions you can
make. The bar:

1. The upstream is real and publicly available (npm, PyPI, registry).
2. The policy is **deny-by-default** — every permitted tool is listed
   explicitly, and the file's header comment lists the tools it intentionally
   does not permit and why.
3. `eunox validate examples/policies/<name>.yaml` is clean.
4. A short rationale paragraph at the top names the threats addressed.

See [`CONTRIBUTING.md`](../../CONTRIBUTING.md) for the PR workflow.
