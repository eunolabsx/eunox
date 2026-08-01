#!/usr/bin/env bash
# demo/scripts/ci-test-effect.sh — determinism gate for Demo (b) (effect-escalate).
#
# Asserts the acceptance bar: the consequence-gated escalation scenario produces a
# byte-identical normalized decision sequence across N runs (default 20), the tape
# HMAC-verifies on every run, and the sequence is the EXPECTED one — an untrusted source
# read allowed and labeled, a reversible SELECT through the same tool allowed in the same
# tainted session, and the irreversible DROP escalated with the consequence inputs on the
# record. No Docker; requires go + python3.
set -eo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNS="${EFFECT_RUNS:-20}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BIN="$WORK/eunox"
MOCK="$WORK/mock"
DRIVER="$WORK/driver.py"

echo ">>> [ci-test-effect] building eunox + mock"
go build -o "$BIN" "$REPO_ROOT/cmd/eunox"
go build -o "$MOCK" "$REPO_ROOT/demo/mock-mcp-server-stdio"

cat >"$DRIVER" <<'PY'
import json, subprocess, sys
bin_path, config = sys.argv[1:3]
def tc(i, n, a):
    return (json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                        "params": {"name": n, "arguments": a}}), i)
init = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "x", "version": "1"}}}), 1)
ini = (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}), None)
steps = [init, ini,
         tc(2, "read_file", {"path": "/inbox/ticket-4471.txt"}),
         tc(3, "query_db", {"query": "SELECT id FROM customers LIMIT 10"}),
         tc(4, "query_db", {"query": "DROP TABLE customers"})]
p = subprocess.Popen([bin_path, "proxy", "--config", config], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
try:
    for m, e in steps:
        p.stdin.write(m + "\n"); p.stdin.flush()
        if e is None:
            continue
        while True:
            l = p.stdout.readline()
            if not l:
                sys.exit("proxy closed before id %r" % e)
            try:
                r = json.loads(l)
            except json.JSONDecodeError:
                continue
            if r.get("id") == e:
                break
finally:
    p.stdin.close(); p.wait(timeout=30)
PY

normalize() {
	python3 - "$1" <<'PY'
import json, sys
for l in open(sys.argv[1]):
    r = json.loads(l)
    if r.get("method") != "tools/call":
        continue
    d = r.get("details") or {}
    # Explicit key=value pairs so the assertions below match a field, not a column
    # position: a normalized line whose empty middle fields collapse would otherwise make
    # a grep for one field silently match a neighbouring one.
    print("target=%s decision=%s code=%s class=%s exceeded=%s out=%s carried=%s" % (
        r.get("target"), r.get("decision"), r.get("denial_code", "-"),
        d.get("effect_class", "-"), ",".join(d.get("ceiling_exceeded") or []) or "-",
        ",".join(r.get("labels_out") or []) or "-",
        ",".join(r.get("carried_labels") or d.get("carried_labels") or []) or "-"))
PY
}

run_once() {
	local w="$WORK/run"
	rm -rf "$w"; mkdir -p "$w"
	cat >"$w/c.yaml" <<EOF
schemaVersion: "0.1"
transport: stdio
audit: {log: "$w/a.jsonl", keyPath: "$w/a.key"}
upstreams: [{name: mock, transport: stdio, command: "$MOCK", policy: ["$REPO_ROOT/demo/manifest-effect.yaml"]}]
EOF
	python3 "$DRIVER" "$BIN" "$w/c.yaml"
	if ! "$BIN" audit-verify --audit-log "$w/a.jsonl" --audit-key-path "$w/a.key" >/dev/null; then
		echo "FAIL: audit-verify failed" >&2
		exit 1
	fi
	normalize "$w/a.jsonl"
}

echo ">>> [ci-test-effect] running the scenario $RUNS times"
first=""
for i in $(seq "$RUNS"); do
	seq_out="$(run_once)"
	if [[ -z "$first" ]]; then
		first="$seq_out"
	elif [[ "$seq_out" != "$first" ]]; then
		echo "FAIL: run $i decision sequence differs from run 1 (nondeterministic)" >&2
		echo "--- run 1 ---"; echo "$first"
		echo "--- run $i ---"; echo "$seq_out"
		exit 1
	fi
done

# Assert the stable sequence is the EXPECTED outcome, not merely stable-but-wrong.
assert() { # pattern description
	if ! grep -qE "$1" <<<"$first"; then
		echo "FAIL: expected outcome missing ($2)" >&2
		echo "--- got ---"; echo "$first"
		exit 1
	fi
}
assert 'target=read_file decision=allow .*out=untrusted'  "untrusted source read allowed and labeled"
assert 'target=query_db decision=allow .*carried=untrusted' "the reversible SELECT is allowed in the SAME tainted session — the contrast leg"
assert 'target=query_db decision=escalate code=ESCALATION_REQUIRED class=irreversible' "the DROP escalates on its effect class, not on the tool"
assert 'decision=escalate .*exceeded=effect_class,no_compensating_action' "the escalation names the consequence-gate inputs that fired"
assert 'decision=escalate .*carried=untrusted'             "the escalated record carries the untrusted provenance that produced it"

# Exactly one of each decision line (no duplicates/misses), and — the load-bearing
# negative — the DROP is NEVER a plain allow.
[[ "$(grep -c 'target=query_db decision=allow' <<<"$first")" == 1 ]]    || { echo "FAIL: want exactly one query_db allow"    >&2; exit 1; }
[[ "$(grep -c 'target=query_db decision=escalate' <<<"$first")" == 1 ]] || { echo "FAIL: want exactly one query_db escalate" >&2; exit 1; }
[[ "$(grep -c 'decision=deny' <<<"$first")" == 0 ]]                     || { echo "FAIL: no call in this scenario is a plain deny" >&2; exit 1; }

echo "PASS: $RUNS/$RUNS runs produced the identical expected decision sequence; tape verified each run."
echo "$first"
