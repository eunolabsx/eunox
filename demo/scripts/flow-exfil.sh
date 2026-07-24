#!/usr/bin/env bash
# demo/scripts/flow-exfil.sh — Demo (a): within-scope exfil blocked by source->sink
# flow policy, deterministically and with zero LLM in the decision path.
#
# No Docker. The scenario runs entirely through the eunox stdio proxy backed by
# mock-mcp-server-stdio, driven by a fully scripted, SERIALIZED message sequence
# (each call waits for its response before the next is sent — the compliant MCP
# request/response model, which is what makes the source's label deterministically
# precede the sink's check):
#
#   Tainted session (one MCP session, two calls):
#     read_file  (sensitive source)  -> ALLOW, output labeled `confidential`
#     write_file (egress sink)       -> DENY,  flowLabel blocks a confidential flow
#
#   Contrast session (a fresh, clean session):
#     write_file (egress sink)       -> ALLOW, the identical call with no tainted read
#
# The decision sequence is reconstructed from the signed audit tape alone and printed
# normalized (no timestamps/nonces), so 20 runs produce identical output; the tape is
# HMAC-verified with `eunox audit-verify`. This script is the acceptance artifact —
# see `make -C demo flow-exfil` and `make -C demo ci-test-flow`.
set -eo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MANIFEST="$REPO_ROOT/demo/manifest-flow.yaml"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/audit.jsonl"
KEY="$WORK/audit.key"
BIN="$WORK/eunox"
MOCK="$WORK/mock-stdio"

echo ">>> building eunox + mock (hermetic, one-time)"
go build -o "$BIN" "$REPO_ROOT/cmd/eunox"
go build -o "$MOCK" "$REPO_ROOT/demo/mock-mcp-server-stdio"

CONFIG="$WORK/flow.stdio.yaml"
cat >"$CONFIG" <<EOF
schemaVersion: "0.1"
transport: stdio
audit:
  log: "$LOG"
  keyPath: "$KEY"
upstreams:
  - name: mock
    transport: stdio
    command: "$MOCK"
    policy:
      - "$MANIFEST"
EOF

# The interactive driver owns the (demo-specific) message sequences and sends each
# message only after the previous request's response has been read — serialized
# request/response, the compliant MCP model and the serialization point that makes the
# source's label deterministically precede the sink's check. argv: BIN CONFIG SCENARIO
# (SCENARIO is "tainted" or "clean"). Keeping the JSON messages in Python avoids any
# shell quoting of the embedded JSON-RPC.
DRIVER="$WORK/driver.py"
cat >"$DRIVER" <<'PY'
import json, subprocess, sys

bin_path, config, scenario = sys.argv[1], sys.argv[2], sys.argv[3]

def tc(id_, name, args):
    return (json.dumps({"jsonrpc": "2.0", "id": id_, "method": "tools/call",
                        "params": {"name": name, "arguments": args}}), id_)

init = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "flow-demo", "version": "1.0"}}}), 1)
initialized = (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}), None)

if scenario == "tainted":
    steps = [init, initialized,
             tc(2, "read_file", {"path": "/reports/customers.csv"}),   # sensitive source
             tc(3, "write_file", {"path": "/tmp/exfil.txt", "content": "leak"})]  # egress sink
elif scenario == "clean":
    steps = [init, initialized,
             tc(2, "write_file", {"path": "/tmp/ok.txt", "content": "hello"})]  # egress, clean session
else:
    sys.exit("unknown scenario %r" % scenario)

p = subprocess.Popen([bin_path, "proxy", "--config", config],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, text=True, bufsize=1)
try:
    for msg, expect in steps:
        p.stdin.write(msg + "\n")
        p.stdin.flush()
        if expect is None:
            continue
        while True:  # read until the matching response id — the serialization point
            line = p.stdout.readline()
            if not line:
                sys.exit("proxy closed before responding to id %r" % expect)
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("id") == expect:
                break
finally:
    p.stdin.close()
    p.wait(timeout=30)
PY

drive_session() { python3 "$DRIVER" "$BIN" "$CONFIG" "$1"; }

echo ">>> tainted session: read sensitive source, then attempt egress (serialized)"
drive_session tainted

echo ">>> contrast session (clean): attempt the identical egress with no tainted read"
drive_session clean

echo ">>> verifying the signed audit tape"
"$BIN" audit-verify --audit-log "$LOG" --audit-key-path "$KEY"

echo ""
echo "=== decision sequence (reconstructed from the audit tape, normalized) ==="
# One deterministic line per tools/call decision: volatile fields (time, seq,
# request_id, hmac) are excluded, so repeated runs are byte-identical.
python3 - "$LOG" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if r.get("method") != "tools/call":
            continue
        target = r.get("target", "")
        if r.get("decision") == "allow":
            lo = ",".join(r.get("labels_out") or []) or "-"
            cl = ",".join(r.get("carried_labels") or []) or "-"
            print(f"{target:22} ALLOW  labels_out={lo:14} carried_labels={cl}")
        else:
            det = r.get("details") or {}
            print(f"{target:22} DENY   {r.get('condition_type','')} blockedLabel={det.get('blockedLabel','-')}")
PY

echo ""
echo "Result: the egress write is DENIED in the tainted session (a confidential source"
echo "flowed in) but ALLOWED in the clean session — same capability, decided by the flow."
