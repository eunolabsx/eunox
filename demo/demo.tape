# demo/demo.tape — VHS script for img/demo.gif (the README hero).
#
# Prerequisite (run once before recording):
#   make -C demo up      # bring the manifest-only stack online
#
# Then render the GIF from the repo root:
#   vhs demo/demo.tape   # writes img/demo.gif
#
# When you're done:
#   make -C demo down
#
# What the GIF shows: the proxy denying a DROP TABLE and a .pem read in
# real time, against the manifest at demo/manifest.yaml.

Output img/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1100
Set Height 640
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0
Set WindowBar Colorful

# ── opener ────────────────────────────────────────────────────────────────
Type "# eunox: deny-by-default capability firewall for MCP servers"
Sleep 600ms
Enter
Type "# manifest: read_file locked to /reports/*  |  query_db locked to SELECT"
Sleep 600ms
Enter
Enter
Sleep 800ms

# ── deny 1: read a private key ────────────────────────────────────────────
Type "# (1) agent attempts to read a private key"
Enter
Sleep 500ms
Type `bash demo/scripts/mcp-call.sh '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/ssh/host_ed25519_key.pem"}}}'`
Sleep 400ms
Enter
Sleep 2500ms

# ── deny 2: DROP TABLE ────────────────────────────────────────────────────
Type "# (2) agent attempts DROP TABLE"
Enter
Sleep 500ms
Type `bash demo/scripts/mcp-call.sh '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DROP TABLE users;"}}}'`
Sleep 400ms
Enter
Sleep 2500ms

# ── audit tape proof ──────────────────────────────────────────────────────
Type "# every decision recorded to a tamper-evident audit log"
Enter
Sleep 500ms
Type `tail -2 demo/audit/audit.jsonl | jq -c '{target, decision, why: .condition_type, value: (.details.value // .details.operation)}'`
Sleep 400ms
Enter
Sleep 3500ms
