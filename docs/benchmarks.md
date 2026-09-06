# eunox Performance Benchmarks

This document records the performance baseline for `eunox`.
All numbers were measured on **Apple M4 (arm64, darwin)** with **Go 1.25**.

## How to reproduce

```sh
# Install benchstat (one-time)
go install golang.org/x/perf/cmd/benchstat@latest

# Quick run (3 samples per benchmark)
./scripts/bench.sh | tee bench.txt

# Statistical analysis with p99 estimate
benchstat bench.txt

# More samples for tighter confidence intervals
COUNT=10 ./scripts/bench.sh | tee bench-10.txt
benchstat bench-10.txt
```

Or run directly:

```sh
go test -run='^$' -bench=. -benchtime=3s -benchmem -count=3 ./internal/... ./pkg/... \
    2>&1 | grep -v '^\[eunox\]'
```

## Targets and measured results

The table below shows the mean of 3 × 3s runs on the reference machine.

### 1. Policy evaluation — pure CPU, no I/O

| Benchmark | Mean ns/op | Allocs/op | **Target** | **Status** |
|---|---|---|---|---|
| ManifestPDP / Decide_Allow_SimpleRule | 354 ns | 7 | < 1 ms | ✅ |
| ManifestPDP / Decide_Deny_AbsentTool | 173 ns | 4 | < 1 ms | ✅ |
| ManifestPDP / Decide_Allow_WithGlobCondition | 420 ns | 7 | < 1 ms | ✅ |
| ManifestPDP / Decide_Allow_50Rules | **2 004 ns** | 7 | < 1 ms | ✅ |
| ManifestPDP / Decide_Deny_50Rules | 1 763 ns | 4 | < 1 ms | ✅ |
| ManifestPDP / Decide_Allow_WithAllowedOperations | 449 ns | 8 | < 1 ms | ✅ |
| ManifestPDP / Decide_Allow_WithArgumentSchema | 464 ns | 8 | < 1 ms | ✅ |
| ManifestPDP / Decide_Deny_FailsArgumentSchema | 194 ns | 5 | < 1 ms | ✅ |
| JWTPDP / Decide_CachedClaims_Allow | 229 ns | 9 | < 1 ms | ✅ |
| JWTPDP / Decide_CachedClaims_Deny | 352 ns | 8 | < 1 ms | ✅ |
| JWTPDP / ValidateToken_Memoized | — ¹ | — ¹ | — | — |
| JWTPDP / ValidateToken_Verified | — ¹ | — ¹ | — | — |
| JWTPDP / ValidateToken_Refused_Memoized | — ¹ | — ¹ | — | — |
| JWTPDP / ValidateToken_Refused_Verified | — ¹ | — ¹ | — | — |

¹ These four replace a single `ValidateToken_CachedJWKS` row whose figure was recorded as an
ECDSA P-256 signature verification and was in fact a verified-token cache HIT: the benchmark
reused one token, so every iteration after the first skipped the crypto entirely. The split
measures the same call on either side of each cache — `_Memoized` is the hit, `_Verified` runs
with the caches disarmed and pays the full `ParseSigned` + ECDSA verify + payload decodes; the
`Refused_` pair is the same split for a token the validator refuses for a reason no elapsed
time can change. `ValidateToken` runs on **every** request through the HTTP transport, not once
per session. No numbers are carried over: the old figure measured a different thing, and one
cut on another machine is what a reader mistakes for a baseline. Run `./scripts/bench.sh` and
read each `_Verified` row against its `_Memoized` sibling — the gap is roughly two orders of
magnitude in both ns/op and allocs/op, which is the whole reason both caches exist.

### 2. Full HTTP round-trip — stateless mode (no audit)

The **baseline** column is `Baseline_DirectUpstream` — a direct POST to the
in-process `httptest.Server` with no proxy in the path.  **Overhead** is the
added latency introduced by the eunox proxy layer.

| Benchmark | Total ns/op | Baseline ns/op | **Overhead** | **Target** | **Status** |
|---|---|---|---|---|---|
| HTTPProxy / Baseline_DirectUpstream | 31 900 ns | — | — | — | — |
| HTTPProxy / ManifestPDP_Allow | 39 530 ns | 31 900 | **7.6 µs** | < 2 ms | ✅ |
| HTTPProxy / ManifestPDP_Deny (blocked inline) | 3 533 ns | — | < 3.6 µs ² | < 2 ms | ✅ |
| HTTPProxy / ManifestPDP_Allow_WithAudit | 43 980 ns | 31 900 | **12.1 µs** | — ³ | — |
| HTTPProxy / ManifestPDP_50Rules_Allow | 41 330 ns | 31 900 | **9.4 µs** | < 2 ms | ✅ |
| HTTPProxy / ManifestPDP_Allow_WithRedact | 43 536 ns | 31 900 | **11.6 µs** | — ⁴ | — |

² Deny is short-circuited before the upstream call, so total latency is lower than baseline.  
³ Audit adds synchronous HMAC-SHA256 + file write. Overhead varies by storage medium
(tmpfs ~12 µs, SSD ~200 µs). No target defined for audited mode.  
⁴ `redactFields` directive: the ~4 µs over the plain-allow path covers JSON parse + field
masking + re-marshal of the upstream response. No target defined; cost scales with response size.

### 3. Full HTTP round-trip — JWT PDP mode (JWKS cached)

Every `tools/call` request includes a Bearer JWT. The JWKS is fetched once
during session initialization and cached; subsequent calls verify only via the
in-memory key set.

| Benchmark | Total ns/op | Baseline ns/op | **Overhead** | **Target** | **Status** |
|---|---|---|---|---|---|
| HTTPProxy_JWTPDP / Allow_JWTOnly | 90 753 ns | 31 900 | **58.9 µs** | < 3 ms | ✅ |
| HTTPProxy_JWTPDP / Allow_JWTAndManifest | 92 194 ns | 31 900 | **60.3 µs** | < 3 ms | ✅ |
| HTTPProxy_JWTPDP / Deny_AbsentFromJWT | 51 902 ns | — | < 52 µs ² | < 3 ms | ✅ |

The ~59 µs JWT overhead is dominated by ECDSA P-256 signature verification (see
`ValidateToken_Verified` above). It is the cost of a token the validator has not seen within
the cache TTL; a repeat of the same token, and a token refused for a reason that cannot change,
are both served from cache instead. No further optimization is needed to meet the 3 ms target.

### 4. Redis kill-switch overhead

The Redis kill switch (`killswitch.NewRedis`) caches kill/revive state
in-memory and refreshes it via pub/sub. The `ShouldBlock()` call on the hot
path is a `sync.RWMutex` read + map lookup — not a Redis round-trip. Redis is
only contacted on state changes (`KillSession`, `ActivateGlobal`).

| Benchmark | Total ns/op | Non-Redis baseline | **Overhead** | **Target** | **Status** |
|---|---|---|---|---|---|
| HTTPProxy_RedisKS / ManifestPDP_Allow_RedisKS | 40 871 ns | 39 530 | **~1.3 µs** | < 5 ms | ✅ |

The in-memory hot path adds effectively zero overhead. In production, the Redis
RTT (typically < 1 ms on the same LAN) applies only when a session is killed or
the global switch is toggled — not on every request.

### 5. Stdio transport round-trip

The stdio transport is used by IDE integrations and agent runtimes (e.g. Claude
Desktop, Cursor).  Messages are newline-delimited JSON-RPC on stdin/stdout rather
than HTTP.  The in-process upstream is connected via `io.Pipe` — there is no TCP
stack involved, so the baseline reflects pure framing overhead.

The **baseline** column is `Baseline_DirectPipe` — a direct pipe write/read with
no proxy in the path.  **Overhead** is the additional cost introduced by the
eunox proxy layer (PDP evaluation + channel dispatch + framing).

| Benchmark | Total ns/op | Baseline ns/op | **Overhead** | **Target** | **Status** |
|---|---|---|---|---|---|
| StdioProxy / Baseline_DirectPipe | 4 087 ns | — | — | — | — |
| StdioProxy / ManifestPDP_Allow | 6 722 ns | 4 087 | **2.6 µs** | < 2 ms | ✅ |
| StdioProxy / ManifestPDP_Deny (blocked inline) | 1 216 ns | — | < 1.3 µs ² | < 2 ms | ✅ |

The stdio baseline is ~4 µs vs the HTTP baseline of ~32 µs — the difference is
the TCP loopback RTT eliminated by the in-process pipe.  The proxy overhead
(2.6 µs) is comparable to HTTP mode (7.6 µs) minus the TCP stack cost, which is
expected since both share the same PDP hot path.

### 6. Decision path — the engine itself

`internal/`'s `BenchmarkManifestPDP` above measures a decision end to end, dominated by
manifest matching and JSON work. These isolate what `pkg/enforcement` does inside it: the
per-condition dispatch loop, the two-pass structure a quota-carrying constraint takes, and the
anchored-key builders every piece of accumulated state routes through.

Read the condition cells against each other rather than against a target. The property worth
holding is that **allocs/op is constant in n** — dispatch itself allocates nothing, so a
refactor that starts allocating per condition shows up as a rising column while every test
still passes. `PureAndCommitting` minus `PureConditions/n=4` is what deferral, bucket
derivation and the atomic admission cost on an in-memory counter.

| Benchmark | What it isolates |
|---|---|
| ValidateAction / NoConditions | The floor: matching, target resolution, allow tail |
| ValidateAction / PureConditions (n=1,4,8) | Per-condition dispatch; allocs must not grow with n |
| ValidateAction / PureAndCommitting | The second pass: deferral + `AdmitAll` |
| AnchoredKey (session, task) | The key builder on every quota bucket and history lookup |
| ClaimMembers (Clean, Unwatched, Variant, Decode) | The JWT claim-name scan every token pays twice, against a plain decode of the same bytes |

No numbers are recorded here on purpose: unlike the tables above, these have no target to
meet, and a figure copied from one machine into a document is the thing a reader mistakes for
a baseline. Run them and compare against your own `benchstat` output.

## Benchmark methodology

- **Framework**: standard `testing.B` from the Go toolchain — reproducible, CI-friendly, no external tooling required for basic runs.
- **Isolation**: all benchmarks use `httptest.NewServer` in-process; no external services. The Redis benchmark uses `miniredis` (in-process Redis).
- **Transport coverage**: both the Streamable HTTP transport and the stdio transport (`transport: stdio`) are benchmarked. The stdio benchmark uses in-process `io.Pipe` pairs in place of a subprocess, so it measures framing overhead without TCP stack noise.
- **HTTP keep-alive**: the bench upstream drains request bodies before responding and the client drains response bodies before `Close()` — ensuring the HTTP/1.1 connection pool is fully utilized across iterations.
- **Measurement window**: `b.ResetTimer()` is called after setup (server start, session initialization, key generation) so setup costs are excluded from the measurement.
- **Allocation tracking**: `b.ReportAllocs()` is called in every benchmark; `allocs/op` values are reported by the Go runtime GC instrumentation.
- **Multiple counts**: `-count=3` provides three independent runs per benchmark so `benchstat` can compute mean ± variance. Use `-count=10` for tighter p99 estimates.
- **p99 extraction**: `benchstat` computes geometric mean and CI from multi-count runs; with `-count=10` it also reports the 95th-percentile confidence interval, which serves as a p99 proxy.

## How to read the overhead column

The "overhead" figure is:

```
overhead = round_trip_with_proxy - Baseline_DirectUpstream
```

This isolates the eunox proxy layer (PDP evaluation + session lookup +
JSON marshal/unmarshal) from the in-process loopback TCP cost that is common
to both the baseline and proxied cases.

In production, absolute latencies will be higher because of real network RTT
to the upstream MCP server. The *overhead* added by the proxy should remain
in the same range (it is CPU-bound, not network-bound).
