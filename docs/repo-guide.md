# eunox — repository guide

> **Looking for a quick overview?** See the project [README](../README.md).
> This document covers how the repo is laid out, how to build it, and how to
> test changes.

## Overview

eunox is a Go repository for `eunox`, a policy-enforcement proxy for MCP servers,
built on the [Model Context Protocol](https://spec.modelcontextprotocol.io/).

## Prerequisites

- Go 1.26.4+
- golangci-lint v2.12+
- Docker (for integration tests and local deployment)

## Build & Test

```bash
# Build eunox
make build

# Run all tests with race detector
make test

# Run linter (go vet + golangci-lint)
make lint

# Generate coverage report
make coverage

# Check Apache-2.0 license headers
make check-license
```

## Repository Layout

```
eunox/
├── cmd/
│   └── eunox/              # eunox proxy binary: CLI subcommands + wiring (Apache-2.0)
├── internal/               # Subsystems factored out of the binary (module-private)
│   ├── audit/              # Tamper-evident audit log (writer, rotation, verifier)
│   ├── config/             # Config + manifest loading, schema-version negotiation
│   ├── drift/              # Startup manifest-drift comparison policy
│   ├── mcp/                # MCP message types + JSON-RPC envelope/framing layer
│   ├── pdp/                # Policy decision points (ManifestPDP, JWTPDP, ...)
│   └── transport/          # stdio + HTTP/gateway transport runtime
├── pkg/                    # Importable packages
│   ├── capability/         # Constraint types, conditions, JWKS verification
│   ├── callcounter/        # Rate-limit call counting (in-memory and Redis)
│   ├── circuitbreaker/     # Circuit-breaker (guards JWKS endpoint fetches)
│   ├── enforcement/        # PDP enforcement engine
│   └── killswitch/         # Emergency kill switch (in-memory and Redis)
├── schemas/                # JSON Schemas for the gateway config / manifest
├── demo/                   # Runnable demo stack (Docker Compose + scripts)
├── deploy/docker/          # Dockerfiles for eunox
├── docs/                   # Documentation
└── scripts/                # Development scripts (benchmarks, etc.)
```

The dependency direction is strictly inward — `cmd/` → `internal/` → `pkg/` —
and never back; nothing in `internal/` or `pkg/` imports the binary. See
[architecture.md](./architecture.md) for the full layering.

## CI

The GitHub Actions workflow (`.github/workflows/go-ci.yml`) runs:

- `go vet` + `golangci-lint`
- Tests with race detector and 80% coverage threshold for `pkg/`
- Apache-2.0 license header check
- Cross-compilation (linux/amd64, linux/arm64, darwin/arm64, windows/amd64, windows/arm64)

## Local Development Stack

```bash
# Start local demo stack
docker compose -f demo/docker-compose.yml up --build
```

## License

All code is licensed under the Apache License 2.0. See [`cmd/eunox/LICENSE`](../cmd/eunox/LICENSE).
