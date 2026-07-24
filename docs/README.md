# eunox Documentation Index

Design and operational documentation for `eunox`.

---

## Start here

| Doc | What it is |
| --- | ---------- |
| [../README.md](../README.md) | Project README — value prop, quick start, commands. |
| [repo-guide.md](./repo-guide.md) | Repository structure, build / lint / test, contributor setup. |
| [client-integration.md](./client-integration.md) | Wiring eunox into MCP clients: Claude Desktop, Claude Code, Cursor, VS Code + Copilot, Cline, Roo Code, Windsurf. |
| [integrations/](./integrations/) | Wiring eunox into platforms, orchestrators, and AI gateways: LiteLLM, Dify, n8n, Conductor, Temporal, Flowise — insertion patterns, shared gateway setup, and a per-platform reference each. |

## Architecture and design

| Doc | What it is |
| --- | ---------- |
| [architecture.md](./architecture.md) | Overall architecture: layering, request lifecycle, transports, PDPs, audit pipeline, extension points. |
| [conformance.md](./conformance.md) | MCP 2025-11-25 conformance matrix: per-method enforcement status, OAuth/IdP boundary, known gaps, IdP integration examples. |
| [adr/](./adr/) | Architecture Decision Records — why specific load-bearing decisions were made, one short file per decision. |
| [capability-manifest-guide.md](./capability-manifest-guide.md) | Manifest authoring: structure, conditions, anti-patterns. |
| [threat-model-mcp.md](./threat-model-mcp.md) | Security threat model for the `eunox` proxy. |
| [deployment-hardening.md](./deployment-hardening.md) | Making eunox a mandatory enforcement chokepoint: credential, network, and endpoint controls that prevent direct-to-upstream bypass. |
| [whitepaper/deploymentwhitepaper.pdf](./whitepaper/deploymentwhitepaper.pdf) | Deployment whitepaper (PDF) — the printable companion to `deployment-hardening.md`. |
| [Capability Manifest Specification](https://github.com/eunolabs/agent-capability-manifest) | The normative spec — published as a standalone vendor-neutral repo (Apache-2.0). |

## Performance

| Doc | What it is |
| --- | ---------- |
| [benchmarks.md](./benchmarks.md) | Latency baselines for enforcement overhead, JWT PDP, Redis kill-switch. |

---

## Maintenance

Update the matching doc in the same PR when behavior changes.
All doc filenames use **lowercase kebab-case**. `README.md` files are the only exception.
