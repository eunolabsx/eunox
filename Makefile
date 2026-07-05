# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0

VERSION ?= 0.1.0
GO ?= go
GOFLAGS ?= -race
GOLANGCI_LINT_VERSION ?= v2.12.2

# Version stamped into `make build` binaries. Prefer git's tag/commit so a local
# build reports a real version instead of the "dev" default; fall back to
# $(VERSION) when git metadata is unavailable (e.g. a source tarball). The
# release path stamps its own version via goreleaser/Docker ldflags.
GIT_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null)
BUILD_VERSION ?= $(if $(GIT_VERSION),$(GIT_VERSION),$(VERSION))

IMAGE_REPO    ?= ghcr.io/eunolabs/eunox
DOCKERFILE_MCP     := deploy/docker/Dockerfile.mcp
DOCKERFILE_MCP_WIN := deploy/docker/Dockerfile.mcp.windows

.PHONY: all build test lint generate clean coverage check-license check-notice check-fmt fmt vet \
        check-go-version check-cross-compile mcpb \
        docker-build-mcp docker-build-mcp-multi docker-push-mcp

all: lint test build

## Build the eunox binary to ./bin/
## CGO_ENABLED=0 + -trimpath match the release closure (.goreleaser.yml,
## deploy/docker/Dockerfile.mcp) so `make build` produces the same statically
## linked binary instead of dynamically linking libc on hosts with a C toolchain.
build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-X main.version=$(BUILD_VERSION)" -o bin/eunox ./cmd/eunox

## Run tests with race detector
test:
	$(GO) test $(GOFLAGS) -count=1 ./...

## Run tests with coverage report
coverage:
	$(GO) test $(GOFLAGS) -count=1 -coverprofile=coverage.out -covermode=atomic ./pkg/...
	$(GO) tool cover -func=coverage.out
	@echo "---"
	@echo "Coverage report: coverage.out"

## Run linter
lint: vet
	@GOLANGCI_LINT=$$(command -v golangci-lint 2>/dev/null || true); \
	if [ -z "$$GOLANGCI_LINT" ]; then \
		echo "Installing golangci-lint..."; \
		$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
		GOLANGCI_LINT="$$($(GO) env GOPATH)/bin/golangci-lint"; \
	fi; \
	"$$GOLANGCI_LINT" run ./...

## Run go vet
vet:
	$(GO) vet ./...

## Format all Go files in place with gofmt.
fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

## Check gofmt formatting — every Go file must be gofmt-clean (CI-enforced).
check-fmt:
	@echo "Checking gofmt formatting..."
	@unformatted=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$unformatted" ]; then \
		echo "The following files are not gofmt-formatted (run 'make fmt'):"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "All Go files are gofmt-formatted."

## Run code generation (oapi-codegen, etc.)
generate:
	$(GO) generate ./...

## Check license headers — all Go files must carry Apache-2.0.
check-license:
	@echo "Checking license headers..."
	@fail=0; \
	for f in $$(find . -name '*.go' -not -path './vendor/*'); do \
		if ! head -2 "$$f" | grep -q "SPDX-License-Identifier: Apache-2.0"; then \
			echo "MISSING APACHE LICENSE HEADER: $$f"; \
			fail=1; \
		fi; \
	done; \
	if [ $$fail -eq 1 ]; then exit 1; fi
	@echo "All files have correct license headers."

## Verify NOTICE lists exactly the third-party modules linked into the binary
## (non-test build closure). Stale or missing entries fail the build; the
## license/copyright text stays hand-curated. See scripts/check-notice.sh.
check-notice:
	@./scripts/check-notice.sh

## Verify the Docker builder stages pin the same Go patch as go.mod, so released
## images are built with the exact toolchain the binary was tested against (and
## not a different, untested one). CI-enforced.
check-go-version:
	@echo "Checking Dockerfile Go versions match go.mod..."
	@gomod_go=$$(awk '/^go /{print $$2; exit}' go.mod); \
	if [ -z "$$gomod_go" ]; then echo "could not read 'go' directive from go.mod"; exit 1; fi; \
	fail=0; \
	for df in $(DOCKERFILE_MCP) $(DOCKERFILE_MCP_WIN); do \
		df_go=$$(grep -oE 'golang:[0-9]+\.[0-9]+\.[0-9]+' "$$df" | head -1 | cut -d: -f2); \
		if [ -z "$$df_go" ]; then echo "no 'golang:X.Y.Z' builder image found in $$df"; fail=1; continue; fi; \
		if [ "$$df_go" != "$$gomod_go" ]; then \
			echo "Go version mismatch in $$df: builder uses $$df_go, go.mod declares $$gomod_go"; \
			fail=1; \
		fi; \
	done; \
	if [ $$fail -eq 1 ]; then \
		echo "Pin the Docker builder FROM line to golang:$$gomod_go (or move go.mod + CI together)."; \
		exit 1; \
	fi; \
	echo "Dockerfile Go versions match go.mod ($$gomod_go)."

## Cross-compile internal/audit for plan9 — the canonical lock_other build target.
## It guards the build-tag-portable hard-link errno seam (audit_hardlink_*.go):
## plan9's syscall package defines neither ENOSYS nor EXDEV, so a shared reference
## to them would break this build. Only packages expected to compile on plan9 are
## checked (the transport/binary layers use unix-only syscalls). CI-enforced.
check-cross-compile:
	@echo "Cross-compiling internal/audit for plan9 (lock_other build-tag guard)..."
	@GOOS=plan9 GOARCH=amd64 $(GO) build ./internal/audit
	@echo "internal/audit cross-compiles for plan9."


## Pack a Claude Desktop extension (.mcpb) for the host platform into dist-mcpb/.
## A .mcpb is a zip with a manifest.json front-ending the eunox binary. The
## release packs one per shipped platform via the same script, driven by a
## goreleaser build post-hook (.goreleaser.yml) so the bundles ride the release
## checksums/SBOM/signature/provenance. This target is the fast local path for
## testing the bundle (SBOM emitted only if syft is on PATH).
##
## Builds the binary stamped with $(VERSION) (not the git-describe BUILD_VERSION)
## so the binary's reported version matches the manifest's, which must be SemVer.
mcpb:
	@$(MAKE) --no-print-directory build BUILD_VERSION=$(VERSION)
	@os=$$($(GO) env GOOS); arch=$$($(GO) env GOARCH); \
	./scripts/build-mcpb.sh $(VERSION) $$os $$arch bin/eunox dist-mcpb

## Build the eunox Docker image for the local platform (fast, no QEMU).
docker-build-mcp:
	docker build \
		--build-arg VERSION=$(VERSION) \
		-f $(DOCKERFILE_MCP) \
		-t $(IMAGE_REPO):$(VERSION) \
		-t $(IMAGE_REPO):latest \
		.

## Build the eunox Docker image for linux/amd64 + linux/arm64 using buildx.
## Requires: docker buildx, QEMU (docker run --rm --privileged tonistiigi/binfmt --install all).
## Loads the result into the local image store (--load pushes only one platform at a time;
## omit --load and add --push to publish directly to Docker Hub instead).
docker-build-mcp-multi:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-f $(DOCKERFILE_MCP) \
		-t $(IMAGE_REPO):$(VERSION) \
		-t $(IMAGE_REPO):latest \
		.

## Push the locally built eunox image to Docker Hub.
## Run docker-build-mcp (or docker-build-mcp-multi --push) before this target.
docker-push-mcp:
	docker push $(IMAGE_REPO):$(VERSION)
	docker push $(IMAGE_REPO):latest

## Remove build artifacts
clean:
	rm -rf bin/ dist-mcpb/
	rm -f coverage.out
	$(GO) clean ./...
