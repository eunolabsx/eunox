#!/usr/bin/env bash
# demo/scripts/ci-test-flow.sh — determinism gate for Demo (a) (flow-exfil).
#
# Asserts the acceptance bar: the source->sink flow scenario produces a
# byte-identical normalized decision sequence across N runs (default 20), the tape
# HMAC-verifies on every run, and the sequence is the expected one — a labeled source
# read allowed, the egress denied by flowLabel in the tainted session, and the
# identical egress allowed in a clean session. No Docker; requires go + python3.
set -eo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNS="${FLOW_RUNS:-20}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BIN="$WORK/eunox"
MOCK="$WORK/mock"
DRIVER="$WORK/driver.py"

echo ">>> [ci-test-flow] building eunox + mock"
go build -o "$BIN" "$REPO_ROOT/cmd/eunox"
go build -o "$MOCK" "$REPO_ROOT/demo/mock-mcp-server-stdio"

cat >"$DRIVER" <<'PY'
import json, subprocess, sys
bin_path, config, scen = sys.argv[1:4]
def tc(i, n, a):
    return (json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                        "params": {"name": n, "arguments": a}}), i)
init = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "x", "version": "1"}}}), 1)
ini = (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}), None)
steps = ([init, ini, tc(2, "read_file", {"path": "/reports/c.csv"}),
          tc(3, "write_file", {"path": "/tmp/x", "content": "y"})] if scen == "tainted"
         else [init, ini, tc(2, "write_file", {"path": "/tmp/ok", "content": "h"})])
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
    print(r.get("target"), r.get("decision"), r.get("condition_type", ""),
          ",".join(r.get("labels_out") or []), ",".join(r.get("carried_labels") or []),
          d.get("blockedLabel", ""))
PY
}

run_once() {
	local w="$WORK/run"
	rm -rf "$w"; mkdir -p "$w"
	cat >"$w/c.yaml" <<EOF
schemaVersion: "0.1"
transport: stdio
audit: {log: "$w/a.jsonl", keyPath: "$w/a.key"}
upstreams: [{name: mock, transport: stdio, command: "$MOCK", policy: ["$REPO_ROOT/demo/manifest-flow.yaml"]}]
EOF
	python3 "$DRIVER" "$BIN" "$w/c.yaml" tainted
	python3 "$DRIVER" "$BIN" "$w/c.yaml" clean
	if ! "$BIN" audit-verify --audit-log "$w/a.jsonl" --audit-key-path "$w/a.key" >/dev/null; then
		echo "FAIL: audit-verify failed" >&2
		exit 1
	fi
	normalize "$w/a.jsonl"
}

echo ">>> [ci-test-flow] running the scenario $RUNS times"
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

# Assert the stable sequence is the EXPECTED flow outcome, not merely stable-but-wrong:
# a labeled source read allowed, the egress denied by flowLabel on the confidential
# label, and the identical egress allowed in the clean session.
assert() { # pattern description
	if ! grep -qE "$1" <<<"$first"; then
		echo "FAIL: expected outcome missing ($2)" >&2
		echo "--- got ---"; echo "$first"
		exit 1
	fi
}
assert 'read_file allow .*confidential'          "source read allowed and labeled confidential"
assert 'write_file deny flowLabel .*confidential' "tainted egress denied by flowLabel on confidential"
assert 'write_file allow'                          "clean egress allowed"

# Exactly one of each decision line (no duplicates/misses).
[[ "$(grep -c 'read_file allow' <<<"$first")" == 1 ]]  || { echo "FAIL: want exactly one read_file allow"  >&2; exit 1; }
[[ "$(grep -c 'write_file deny' <<<"$first")" == 1 ]]  || { echo "FAIL: want exactly one write_file deny"  >&2; exit 1; }
[[ "$(grep -c 'write_file allow' <<<"$first")" == 1 ]] || { echo "FAIL: want exactly one write_file allow" >&2; exit 1; }

echo "PASS: $RUNS/$RUNS runs produced the identical expected decision sequence; tape verified each run."
echo "$first"
