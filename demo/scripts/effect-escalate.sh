#!/usr/bin/env bash
# demo/scripts/effect-escalate.sh — Demo (b): an untrusted-influenced destructive action
# is ESCALATED regardless of held permission, deterministically and with zero LLM in the
# decision path.
#
# No Docker. The scenario runs entirely through the eunox stdio proxy backed by
# mock-mcp-server-stdio, driven by a fully scripted, SERIALIZED message sequence (each
# call waits for its response before the next is sent — the compliant MCP
# request/response model, which is what makes the untrusted read's label deterministically
# precede the destructive call's decision):
#
#   Tainted session (one MCP session, three calls):
#     read_file  /inbox/ticket-4471.txt  -> ALLOW, output labeled `untrusted`
#     query_db   "SELECT ..."            -> ALLOW, reversible: under the effect ceiling
#     query_db   "DROP TABLE customers"  -> ESCALATE, irreversible with no compensation
#
# The agent HOLDS the capability: query_db is in the allowlist and DROP is explicitly in
# its allowedOperations. Per-call authorization has nothing left to say. What refuses the
# call is its CONSEQUENCE, and the SELECT in the same session is the contrast leg proving
# it is the consequence and not the tool, the session, or the taint that decided it.
#
# The decision sequence is reconstructed from the signed audit tape alone and printed
# normalized (no timestamps/nonces), so repeated runs are byte-identical; the tape is
# HMAC-verified with `eunox audit-verify`. This script is the acceptance artifact — see
# `make -C demo effect-escalate` and `make -C demo ci-test-effect`.
set -eo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MANIFEST="$REPO_ROOT/demo/manifest-effect.yaml"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/audit.jsonl"
KEY="$WORK/audit.key"
BIN="$WORK/eunox"
MOCK="$WORK/mock-stdio"

echo ">>> building eunox + mock (hermetic, one-time)"
go build -o "$BIN" "$REPO_ROOT/cmd/eunox"
go build -o "$MOCK" "$REPO_ROOT/demo/mock-mcp-server-stdio"

CONFIG="$WORK/effect.stdio.yaml"
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

# The interactive driver owns the message sequence and sends each message only after the
# previous request's response has been read — serialized request/response, the compliant
# MCP model and the serialization point that makes the untrusted label deterministically
# precede the destructive call's decision. argv: BIN CONFIG
DRIVER="$WORK/driver.py"
cat >"$DRIVER" <<'PY'
import json, subprocess, sys

bin_path, config = sys.argv[1], sys.argv[2]

def tc(id_, name, args):
    return (json.dumps({"jsonrpc": "2.0", "id": id_, "method": "tools/call",
                        "params": {"name": name, "arguments": args}}), id_)

init = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "effect-demo", "version": "1.0"}}}), 1)
initialized = (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}), None)

steps = [init, initialized,
         # An untrusted, customer-submitted support ticket. Its content carries the
         # injection; the proxy never reads it — policy asserts the provenance.
         tc(2, "read_file", {"path": "/inbox/ticket-4471.txt"}),
         # The contrast leg: the same tool, in the same tainted session, doing something
         # reversible. Allowed.
         tc(3, "query_db", {"query": "SELECT id FROM customers LIMIT 10"}),
         # The injected instruction, within granted capabilities. Escalated.
         tc(4, "query_db", {"query": "DROP TABLE customers"})]

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

echo ">>> tainted session: read the untrusted ticket, then a SELECT, then the injected DROP (serialized)"
python3 "$DRIVER" "$BIN" "$CONFIG"

echo ">>> verifying the signed audit tape"
"$BIN" audit-verify --audit-log "$LOG" --audit-key-path "$KEY"

echo ""
echo "=== decision sequence (reconstructed from the audit tape, normalized) ==="
# One deterministic line per tools/call decision: volatile fields (time, seq, request_id,
# hmac) are excluded, so repeated runs are byte-identical.
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
        decision = r.get("decision", "")
        det = r.get("details") or {}
        carried = ",".join(r.get("carried_labels") or []) or "-"
        if decision == "allow":
            lo = ",".join(r.get("labels_out") or []) or "-"
            print(f"{target:10} ALLOW     labels_out={lo:10} carried_labels={carried}")
        elif decision == "escalate":
            reasons = ",".join(det.get("ceiling_exceeded") or [])
            # An escalation carries the accumulated flow labels in its structured details
            # (the top-level carried_labels field is reserved for allow records), so the
            # provenance that produced the refusal is on the one record a human reviews.
            carried = ",".join(det.get("carried_labels") or []) or "-"
            print(f"{target:10} ESCALATE  effect_class={det.get('effect_class','-'):13} "
                  f"carried_labels={carried} exceeded={reasons}")
        else:
            print(f"{target:10} DENY      {r.get('condition_type','')} {r.get('denial_code','')}")
PY

echo ""
echo "Result: the DROP is ESCALATED — not because query_db is forbidden (it is granted,"
echo "and DROP is explicitly in its allowedOperations) but because the action it would"
echo "perform is irreversible with no compensating action, which exceeds the policy's"
echo "effect ceiling. The SELECT through the SAME tool in the SAME tainted session is"
echo "allowed, so it is the consequence that decided it. The escalated record carries"
echo "carried_labels=untrusted, tying the refusal to the untrusted provenance that"
echo "produced it: one tape, one enforcement point, both axes."
