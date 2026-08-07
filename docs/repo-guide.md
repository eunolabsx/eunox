# eunox — repository guide

> **Looking for a quick overview?** See the project [README](../README.md).
> This document covers how the repo is laid out, how to build it, and how to
> test changes.

## Overview

eunox is a Go repository for `eunox`, a policy-enforcement proxy for MCP servers,
built on the [Model Context Protocol](https://spec.modelcontextprotocol.io/).

## Prerequisites

- Go 1.26.5+
- Docker (for integration tests and local deployment)

golangci-lint is not a prerequisite: `make lint` resolves the exact version CI runs
(`GOLANGCI_LINT_VERSION` in the Makefile, which the workflow reads via
`make print-lint-version`) and installs it if no binary on `PATH` matches. A different
version already installed is ignored rather than used — one built with an older Go
toolchain than `go.mod` targets refuses to lint at all, which looks like "the linter is
unavailable here" while CI fails on findings no local run could surface.

A sandbox whose local Go toolchain is older than `go.mod` targets is not actually stuck: the
`golangci-lint.sh` wrapper's own `go install` there may resolve to a `golangci-lint` build
still too old to lint this repo, since `go install` follows the *installed package's* own
toolchain requirement, not this repo's. Fetch the pinned release binary directly instead —
`https://github.com/golangci/golangci-lint/releases/download/v<GOLANGCI_LINT_VERSION>/golangci-lint-<version>-linux-amd64.tar.gz`
(match `GOLANGCI_LINT_VERSION` in the Makefile) — and run it with a new-enough `go` on
`PATH`. `go build`/`go test` in this repo already trigger `GOTOOLCHAIN`'s auto-download of
the `go.mod`-pinned toolchain into `$(go env GOMODCACHE)/golang.org/toolchain@v0.0.1-go<N>.*/bin/go`;
put that directory ahead of the system `go` on `PATH` and the downloaded `golangci-lint`
binary will lint against it. Either way, treat "lint couldn't run locally" as a prompt to
check the PR's actual CI `Lint` conclusion before merging, not as license to skip the check.

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
│   ├── registry/           # Effect-contract corpus format + loader/verifier
│   └── transport/          # stdio + HTTP/gateway transport runtime
├── pkg/                    # Importable packages
│   ├── capability/         # Constraint types, conditions, effect contracts, JWKS verification
│   ├── callcounter/        # Rate-limit call counting (in-memory and Redis)
│   ├── circuitbreaker/     # Circuit-breaker (guards JWKS endpoint fetches)
│   ├── durationsentinel/   # Distinguishes an unset duration from an explicit zero
│   ├── enforcement/        # PDP enforcement engine
│   ├── flowlabelstore/     # Session-scoped information-flow label state (in-memory and Redis)
│   └── killswitch/         # Emergency kill switch (in-memory and Redis)
├── schemas/                # JSON Schemas for the gateway config and the effect-contract corpus
├── registry/               # Effect-contract corpus (data + its own README)
├── examples/               # Example config, policies, and the attribution client stub
├── demo/                   # Runnable demo stack (Docker Compose + scripts)
├── deploy/docker/          # Dockerfiles for eunox
├── docs/                   # Documentation
├── site/                   # Project website sources
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
