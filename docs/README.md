# eunox Documentation Index

Design and operational documentation for `eunox`.

---

## Start here

| Doc | What it is |
| --- | ---------- |
| [../README.md](../README.md) | Project README — value prop, quick start, commands. |
| [repo-guide.md](./repo-guide.md) | Repository structure, build / lint / test, contributor setup. |
| [client-integration.md](./client-integration.md) | Wiring eunox into MCP clients: Claude Desktop, Claude Code, Cursor, VS Code + Copilot, Cline, Roo Code, Windsurf. |

## Architecture and design

| Doc | What it is |
| --- | ---------- |
| [architecture.md](./architecture.md) | Overall architecture: layering, request lifecycle, transports, PDPs, audit pipeline, extension points. |
| [conformance.md](./conformance.md) | MCP 2025-11-25 conformance matrix: per-method enforcement status, OAuth/IdP boundary, known gaps, IdP integration examples. |
| [adr/](./adr/) | Architecture Decision Records — why specific load-bearing decisions were made, one short file per decision. |
| [capability-manifest-guide.md](./capability-manifest-guide.md) | Manifest authoring: structure, conditions, anti-patterns. |
| [effect-contracts.md](./effect-contracts.md) | The effect layer (experimental, `0.2-draft`): effect contracts, the `effectClass`/`blastRadius` conditions, the tool-agnostic `effectCeiling`, and the `escalate` outcome. Deliberately outside the manifest guide until the tokens are published. |
| [attribution-interface.md](./attribution-interface.md) | The attribution interface (experimental): how a cooperating client attributes a call's inputs in `_meta`, and why the interface only ever adds labels. |
| [interface-pinning-tier2.md](./interface-pinning-tier2.md) | Tier-2 interface pinning: auto-baselining every advertised tool surface per session and denying mid-session drift, plus the honest limit on what metadata comparison cannot catch. |
| [../registry/README.md](../registry/README.md) | The effect-contract registry: corpus format, trust model (package signing, not behavioral verification), and how a manifest pins an entry. |
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
