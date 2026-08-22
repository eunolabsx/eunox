# demo/Makefile — single-command demo for eunox.
#
# Run from the repo root:
#   make -C demo up      # start the stack (manifest-only mode)
#   make -C demo allow   # allowed tool call
#   make -C demo deny    # denied tool call
#   make -C demo audit   # tail the audit log
#
# Or from inside the demo/ directory:
#   cd demo && make up

.PHONY: up up-jwt down allow deny deny-path deny-op audit jwt jwt-allow jwt-deny logs ci-test ci-test-jwt \
        stdio-allow stdio-deny stdio-deny-path stdio-deny-op ci-test-stdio flow-exfil ci-test-flow \
        stateless-allow stateless-deny stateless-deny-path stateless-list stateless-audit ci-test-stateless \
        effect-escalate ci-test-effect \
        gateway-up gateway-down gw-files-allow gw-files-deny gw-db-allow gw-db-deny gw-cross-deny gw-404 \
        gateway-audit ci-test-gateway ci-test-e2e e2e trifecta trifecta-audit help

DEMO_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# ─────────────────────────────────────────────────────────────────────────────
# Stack lifecycle
# ─────────────────────────────────────────────────────────────────────────────

## Start the demo stack in manifest-only mode (no JWT required).
up:
	@mkdir -p "$(DEMO_DIR)audit"
	@chmod 777 "$(DEMO_DIR)audit"
	docker compose -f "$(DEMO_DIR)docker-compose.yml" up --build -d
	@echo ""
	@echo "  eunox proxy : http://localhost:3000/mcp"
	@echo "  mock-mcp-server : http://localhost:8080/mcp"
	@echo ""
	@echo "  Next: make -C demo allow   # allowed tool call"
	@echo "        make -C demo deny    # policy denial"
	@echo "        make -C demo audit   # live audit log"

## Start the demo stack in JWT + manifest intersection mode.
up-jwt:
	@mkdir -p "$(DEMO_DIR)audit"
	@chmod 777 "$(DEMO_DIR)audit"
	docker compose \
	  --profile jwt \
	  -f "$(DEMO_DIR)docker-compose.yml" \
	  -f "$(DEMO_DIR)docker-compose.jwt.yml" \
	  up --build -d
	@echo ""
	@echo "  eunox (JWT mode) : http://localhost:3000/mcp"
	@echo "  Keycloak             : http://localhost:8081 (admin / admin)"
	@echo ""
	@echo "  Next: make -C demo jwt       # get a test JWT"
	@echo "        make -C demo jwt-allow # JWT-authenticated allowed call"
	@echo "        make -C demo jwt-deny  # JWT-authenticated denied call"

## Stop and remove all demo containers.
down:
	docker compose -f "$(DEMO_DIR)docker-compose.yml" down --remove-orphans

# ─────────────────────────────────────────────────────────────────────────────
# Manifest-only demo (no JWT required)
# ─────────────────────────────────────────────────────────────────────────────

## ALLOW: read_file /reports/q3.pdf → permitted by manifest (AllowedValues /reports/*)
allow:
	@echo ">>> read_file /reports/q3.pdf  [expect: ALLOWED]"
	@bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}'

## DENY: write_file → absent from manifest, denied by default
deny:
	@echo ">>> write_file /etc/passwd  [expect: DENIED — not in manifest]"
	@bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"hacked"}}}'

## DENY-PATH: read_file outside /reports/ → denied by AllowedValues condition
deny-path:
	@echo ">>> read_file /etc/shadow  [expect: DENIED — path not in /reports/*]"
	@bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}'

## DENY-OP: query_db with DELETE → denied by AllowedOperations condition
deny-op:
	@echo ">>> query_db DELETE FROM reports  [expect: DENIED — only SELECT permitted]"
	@bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}'

# ─────────────────────────────────────────────────────────────────────────────
# JWT demo (requires: make up-jwt)
# ─────────────────────────────────────────────────────────────────────────────

## Print a test JWT from the local Keycloak instance (client-credentials flow).
## JWT carries: mcp.capabilities = ["tool:read_file?path=/reports/*", "tool:query_db?op=SELECT"]
jwt:
	@echo ">>> Fetching JWT from Keycloak (eunox-demo realm, demo-agent client)..."
	@bash "$(DEMO_DIR)scripts/get-jwt.sh"

## JWT-ALLOW: read_file with JWT carrying matching capability claim.
jwt-allow:
	@echo ">>> [JWT mode] read_file /reports/q3.pdf  [expect: ALLOWED]"
	@TOKEN=$$(bash "$(DEMO_DIR)scripts/get-jwt.sh") && \
	 bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	   '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}' \
	   "$$TOKEN"

## JWT-DENY: write_file — absent from JWT capabilities (and from manifest).
jwt-deny:
	@echo ">>> [JWT mode] write_file /tmp/x.txt  [expect: DENIED — not in JWT capabilities]"
	@TOKEN=$$(bash "$(DEMO_DIR)scripts/get-jwt.sh") && \
	 bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	   '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/x.txt","content":"hello"}}}' \
	   "$$TOKEN"

# ─────────────────────────────────────────────────────────────────────────────
# Gateway demo — one process, many upstreams (docker-compose.gateway.yml)
# ─────────────────────────────────────────────────────────────────────────────

## gateway-up: Start the gateway stack — one proxy fronting two upstreams (/mcp/files, /mcp/db).
gateway-up:
	@mkdir -p "$(DEMO_DIR)audit"
	@chmod 777 "$(DEMO_DIR)audit"
	docker compose -f "$(DEMO_DIR)docker-compose.gateway.yml" up --build -d
	@echo ""
	@echo "  eunox-gateway : http://localhost:3000"
	@echo "    /mcp/files  → mock-files  (files.yaml @ 0.1.0 — read_file /reports/*)"
	@echo "    /mcp/db     → mock-db     (db.yaml    @ 0.2.0 — query_db SELECT)"
	@echo ""
	@echo "  Next: make -C demo gw-files-allow   # read_file on /mcp/files → ALLOWED"
	@echo "        make -C demo gw-cross-deny    # read_file on /mcp/db    → DENIED (per-route policy)"
	@echo "        make -C demo gw-db-allow      # query_db SELECT on /mcp/db → ALLOWED"
	@echo "        make -C demo gateway-audit    # shared tape, stamped per upstream"

## gateway-down: Stop and remove the gateway stack.
gateway-down:
	docker compose -f "$(DEMO_DIR)docker-compose.gateway.yml" down --remove-orphans

## gw-files-allow: read_file /reports/q3.pdf on /mcp/files → permitted by files-policy.
gw-files-allow:
	@echo ">>> [/mcp/files] read_file /reports/q3.pdf  [expect: ALLOWED]"
	@bash "$(DEMO_DIR)scripts/mcp-call-gateway.sh" files \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}'

## gw-files-deny: read_file outside /reports on /mcp/files → denied by allowedValues.
gw-files-deny:
	@echo ">>> [/mcp/files] read_file /etc/shadow  [expect: DENIED — path not in /reports/*]"
	@bash "$(DEMO_DIR)scripts/mcp-call-gateway.sh" files \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}'

## gw-db-allow: query_db SELECT on /mcp/db → permitted by db-policy.
gw-db-allow:
	@echo ">>> [/mcp/db] query_db SELECT * FROM reports  [expect: ALLOWED]"
	@bash "$(DEMO_DIR)scripts/mcp-call-gateway.sh" db \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"SELECT * FROM reports"}}}'

## gw-db-deny: query_db DELETE on /mcp/db → denied by allowedOperations.
gw-db-deny:
	@echo ">>> [/mcp/db] query_db DELETE FROM reports  [expect: DENIED — only SELECT permitted]"
	@bash "$(DEMO_DIR)scripts/mcp-call-gateway.sh" db \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}'

## gw-cross-deny: read_file on /mcp/db → denied (read_file absent from db-policy) — per-route manifests in action.
gw-cross-deny:
	@echo ">>> [/mcp/db] read_file /reports/q3.pdf  [expect: DENIED — read_file not in db-policy]"
	@bash "$(DEMO_DIR)scripts/mcp-call-gateway.sh" db \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}'

## gw-404: call an undeclared route → HTTP 404.
gw-404:
	@echo ">>> POST /mcp/bogus  [expect: HTTP 404 — no such route]"
	@curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST http://localhost:3000/mcp/bogus \
	  -H 'Content-Type: application/json' \
	  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

## gateway-audit: tail the shared audit tape, projecting the per-route version stamps.
gateway-audit:
	@tail -f "$(DEMO_DIR)audit/audit.jsonl" | jq '{time, upstream, policy_version, policy_sha256, target_type, target, method, decision, denial_code}'

## ci-test-gateway: Run gateway integration tests in CI (starts stack, tests, tears down).
ci-test-gateway:
	@mkdir -p "$(DEMO_DIR)audit" && chmod 777 "$(DEMO_DIR)audit"
	@echo "==> Starting gateway stack for CI tests ..."
	@docker compose -f "$(DEMO_DIR)docker-compose.gateway.yml" \
	  up --build --force-recreate -d --wait \
	  && bash "$(DEMO_DIR)scripts/ci-test-gateway.sh"; STATUS=$$?; \
	  docker compose -f "$(DEMO_DIR)docker-compose.gateway.yml" down --remove-orphans; \
	  exit $$STATUS

# ─────────────────────────────────────────────────────────────────────────────
# Observability
# ─────────────────────────────────────────────────────────────────────────────

## Tail the OCSF audit log (requires jq).
audit:
	@tail -f "$(DEMO_DIR)audit/audit.jsonl" | jq .

## Follow container logs for eunox.
logs:
	docker compose -f "$(DEMO_DIR)docker-compose.yml" logs -f eunox

# ─────────────────────────────────────────────────────────────────────────────
# CI integration tests (start stack → test → always tear down)
# ─────────────────────────────────────────────────────────────────────────────

## ci-test: Run manifest-only integration tests in CI (starts stack, tests, tears down).
## Keycloak is excluded entirely via the "jwt" profile — its image is never pulled.
ci-test:
	@mkdir -p "$(DEMO_DIR)audit" && chmod 777 "$(DEMO_DIR)audit"
	@echo "==> Starting manifest-only stack for CI tests (Keycloak excluded by profile) ..."
	@docker compose -f "$(DEMO_DIR)docker-compose.yml" \
	  up --build --force-recreate -d --wait \
	  && bash "$(DEMO_DIR)scripts/ci-test.sh"; STATUS=$$?; \
	  docker compose -f "$(DEMO_DIR)docker-compose.yml" down --remove-orphans; \
	  exit $$STATUS

## ci-test-jwt: Run JWT-mode integration tests in CI (starts full stack, tests, tears down).
ci-test-jwt:
	@mkdir -p "$(DEMO_DIR)audit" && chmod 777 "$(DEMO_DIR)audit"
	@echo "==> Starting JWT-mode stack for CI tests (Keycloak + eunox) ..."
	@docker compose \
	  --profile jwt \
	  -f "$(DEMO_DIR)docker-compose.yml" \
	  -f "$(DEMO_DIR)docker-compose.jwt.yml" \
	  up --build --force-recreate -d --wait \
	  && bash "$(DEMO_DIR)scripts/ci-test-jwt.sh"; STATUS=$$?; \
	  docker compose \
	    --profile jwt \
	    -f "$(DEMO_DIR)docker-compose.yml" \
	    -f "$(DEMO_DIR)docker-compose.jwt.yml" \
	    down --remove-orphans; \
	  exit $$STATUS

# ─────────────────────────────────────────────────────────────────────────────
# Stdio demo (no Docker required — runs proxy + upstream as local processes)
# ─────────────────────────────────────────────────────────────────────────────

## stdio-allow: read_file /reports/q3.pdf → permitted by manifest (AllowedValues /reports/*)
stdio-allow:
	@mkdir -p "$(DEMO_DIR)audit"
	@echo ">>> [stdio] read_file /reports/q3.pdf  [expect: ALLOWED]"
	@bash "$(DEMO_DIR)scripts/mcp-call-stdio.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}'

## stdio-deny: write_file → absent from manifest, denied by default
stdio-deny:
	@mkdir -p "$(DEMO_DIR)audit"
	@echo ">>> [stdio] write_file /etc/passwd  [expect: DENIED — not in manifest]"
	@bash "$(DEMO_DIR)scripts/mcp-call-stdio.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"hacked"}}}'

## stdio-deny-path: read_file outside /reports/ → denied by AllowedValues condition
stdio-deny-path:
	@mkdir -p "$(DEMO_DIR)audit"
	@echo ">>> [stdio] read_file /etc/shadow  [expect: DENIED — path not in /reports/*]"
	@bash "$(DEMO_DIR)scripts/mcp-call-stdio.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}'

## stdio-deny-op: query_db DELETE → denied by AllowedOperations condition
stdio-deny-op:
	@mkdir -p "$(DEMO_DIR)audit"
	@echo ">>> [stdio] query_db DELETE FROM reports  [expect: DENIED — only SELECT permitted]"
	@bash "$(DEMO_DIR)scripts/mcp-call-stdio.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}'

## ci-test-stdio: Run stdio integration tests (no Docker — builds binaries locally, requires go + jq).
ci-test-stdio:
	@mkdir -p "$(DEMO_DIR)audit"
	@bash "$(DEMO_DIR)scripts/ci-test-stdio.sh"

# ─────────────────────────────────────────────────────────────────────────────
# Stateless demo — the same walkthrough against a 2026-07-28 upstream
#
# The 2026-07-28 revision removed the `initialize` handshake and the protocol
# session: `server/discover` opens the leg and every request declares its own
# protocol version in `params._meta`. These targets run the allow/deny walkthrough
# against a mock pinned to that revision, so the policy decisions are demonstrably
# the same ones across a revision change.
#
# Stdio only. An HTTP session is opened by `initialize`, which this revision does
# not have, so eunox refuses a 2026-07-28 pin over the HTTP host transport. The
# Docker targets gain their stateless variant when session creation stops being
# anchored on the handshake.
# ─────────────────────────────────────────────────────────────────────────────

## stateless-allow: [2026-07-28] read_file /reports/q3.pdf → permitted by manifest.
stateless-allow:
	@mkdir -p "$(DEMO_DIR)audit"
	@echo ">>> [2026-07-28] read_file /reports/q3.pdf  [expect: ALLOWED]"
	@bash "$(DEMO_DIR)scripts/mcp-call-stateless.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}'

## stateless-deny: [2026-07-28] write_file → absent from manifest, denied by default.
stateless-deny:
	@mkdir -p "$(DEMO_DIR)audit"
	@echo ">>> [2026-07-28] write_file /etc/passwd  [expect: DENIED — not in manifest]"
	@bash "$(DEMO_DIR)scripts/mcp-call-stateless.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"name":"write_file","arguments":{"path":"/etc/passwd","content":"hacked"}}}'

## stateless-deny-path: [2026-07-28] read_file outside /reports/ → denied by allowedValues.
stateless-deny-path:
	@mkdir -p "$(DEMO_DIR)audit"
	@echo ">>> [2026-07-28] read_file /etc/shadow  [expect: DENIED — path not in /reports/*]"
	@bash "$(DEMO_DIR)scripts/mcp-call-stateless.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"name":"read_file","arguments":{"path":"/etc/shadow"}}}'

## stateless-list: [2026-07-28] tools/list → filtered catalog, and cacheScope clamped to private.
stateless-list:
	@mkdir -p "$(DEMO_DIR)audit"
	@echo ">>> [2026-07-28] tools/list  [expect: write_file filtered out; cacheScope clamped public -> private]"
	@bash "$(DEMO_DIR)scripts/mcp-call-stateless.sh" \
	  '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}'

## stateless-audit: tail the audit tape, projecting the revision each decision was made under.
stateless-audit:
	@tail -f "$(DEMO_DIR)audit/audit.jsonl" | jq '{time, protocol_revision, method, target, decision, denial_code}'

## ci-test-stateless: Run the stateless walkthrough as a test (no Docker; requires go + jq).
ci-test-stateless:
	@mkdir -p "$(DEMO_DIR)audit"
	@bash "$(DEMO_DIR)scripts/ci-test-stateless.sh"

## flow-exfil: Demo (a) — within-scope exfil blocked by source->sink flow policy (no Docker; go + python3).
flow-exfil:
	@bash "$(DEMO_DIR)scripts/flow-exfil.sh"

## ci-test-flow: Determinism gate for Demo (a) — 20 identical runs + verified tape (no Docker; go + python3).
ci-test-flow:
	@bash "$(DEMO_DIR)scripts/ci-test-flow.sh"

## effect-escalate: Demo (b) — untrusted-influenced destructive action escalated by the effect ceiling (no Docker; go + python3).
effect-escalate:
	@bash "$(DEMO_DIR)scripts/effect-escalate.sh"

## ci-test-effect: Determinism gate for Demo (b) — 20 identical runs + verified tape (no Docker; go + python3).
ci-test-effect:
	@bash "$(DEMO_DIR)scripts/ci-test-effect.sh"

# ─────────────────────────────────────────────────────────────────────────────
# Full end-to-end suite (demo/e2e) — mock host + mock server drive the REAL
# proxy across stdio and HTTP, covering every enforced MCP method (positive,
# negative, edge), redaction, sampling, kill-switch, and audit-tape integrity.
# No Docker required — builds binaries locally; requires go + curl.
# ─────────────────────────────────────────────────────────────────────────────

## trifecta: The lethal-trifecta hero demo — eunox blocks credential exfiltration (read->write) via sequenceBlock.
trifecta:
	@bash "$(DEMO_DIR)trifecta/run.sh"

## trifecta-audit: Trifecta with a persistent signed tape (demo/trifecta/audit/) — raw records, cross-run chain verification, live tamper detection.
trifecta-audit:
	@bash "$(DEMO_DIR)trifecta/run.sh" --persist

## e2e: Run the full end-to-end MCP enforcement suite (alias for ci-test-e2e).
e2e: ci-test-e2e

## ci-test-e2e: Build the proxy + e2e mock host/server and run the whole battery.
ci-test-e2e:
	@bash "$(DEMO_DIR)e2e/run.sh"

## Print this help.
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
