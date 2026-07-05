# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/opa-comparison/Makefile
#
# Usage (from repo root):
#   make -C demo/opa-comparison credential-exfiltration
#   make -C demo/opa-comparison path-gated-file-access
#   make -C demo/opa-comparison token-reuse
#   make -C demo/opa-comparison down
#
# Or from this directory:
#   make credential-exfiltration
#   make path-gated-file-access
#   make token-reuse

SHELL    := /usr/bin/env bash
DEMO_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DC       := docker compose -f "$(DEMO_DIR)docker-compose.yml"

.PHONY: credential-exfiltration path-gated-file-access token-reuse up down logs help _audit-dir

# _run-scenario <manifest> <script>
# Starts the stack, runs the script, and always tears down afterwards.
# The exit status of the script is preserved so make reports failure correctly.
define _run-scenario
	@mkdir -p "$(DEMO_DIR)audit" && chmod 777 "$(DEMO_DIR)audit"
	@echo "==> Starting stack with $(1) manifest …"
	@EUNOX_MANIFEST=$(1) $(DC) up --build --force-recreate -d --wait \
	  && bash "$(DEMO_DIR)scripts/$(2)"; STATUS=$$?; \
	  $(DC) down --remove-orphans; exit $$STATUS
endef

## credential-exfiltration: OPA allows the read-then-write sequence; eunox blocks it with sequenceBlock
credential-exfiltration:
	$(call _run-scenario,credential-exfiltration.yaml,credential-exfiltration.sh)

## path-gated-file-access: OPA cannot rate-limit; eunox reuses one anchored gate
path-gated-file-access:
	$(call _run-scenario,path-gated-file-access.yaml,path-gated-file-access.sh)

## token-reuse: OPA allows accumulation of short-lived tokens; eunox blocks after maxCalls:1
token-reuse:
	$(call _run-scenario,token-reuse.yaml,token-reuse.sh)

## up: Start the stack with the credential-exfiltration manifest (default) in the foreground.
##     Override: EUNOX_MANIFEST=path-gated-file-access.yaml make up
up: _audit-dir
	EUNOX_MANIFEST=$${EUNOX_MANIFEST:-credential-exfiltration.yaml} $(DC) up --build

## down: Stop and remove the stack.
down:
	$(DC) down --remove-orphans

## logs: Tail all container logs.
logs:
	$(DC) logs -f

## help: Show this help.
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'

# Internal: ensure audit dir exists and is world-writable.
_audit-dir:
	@mkdir -p "$(DEMO_DIR)audit"
	@chmod 777 "$(DEMO_DIR)audit"
