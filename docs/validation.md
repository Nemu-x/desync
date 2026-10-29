# Validation and measurement scope

## Commands

Run from a clean repository checkout. Network fixtures own their loopback servers;
there are no implicit probes to YouTube, Discord or another public service. The
`desync-probe` default site list is contacted only when a person runs that tool;
its tests use loopback servers and an injected resolver.

```sh
go test -count=1 -timeout=3m ./...
go vet ./...
go test -race -count=1 -timeout=3m ./...
go test ./controller -shuffle=on -count=30 -timeout=2m
go test ./controller -run '^$' -bench '^BenchmarkControllerSelect$' -benchmem -cpu=1 -benchtime=300ms -count=3
```

Race detection requires a supported platform/toolchain and C compiler. Linux race
tests do not validate Windows syscalls. Native unsupported methods return explicit
errors/skips; they are not silently tested as another strategy.

Fuzz one target at a time:

```sh
go test -run '^$' -fuzz '^FuzzClientHelloFraming$' -fuzztime=30s -fuzzminimizetime=1s -parallel=2
go test -run '^$' -fuzz '^FuzzClientHelloAssembly$' -fuzztime=30s -fuzzminimizetime=1s -parallel=2
go test -run '^$' -fuzz '^FuzzRandomCuts$' -fuzztime=30s -fuzzminimizetime=1s -parallel=2
go test ./controller -run '^$' -fuzz '^FuzzControllerTarget$' -fuzztime=15s -fuzzminimizetime=1s -parallel=2
```

The CI workflow (`.github/workflows/ci.yml`) runs gofmt, `go mod tidy -diff` and
vet for Linux, Windows and macOS; tests with coverage on Windows, Linux and macOS
with Go 1.26, each followed by a verbose run of the native capability tests
(capabilities, ACK observation, `ProbeConn`, `SIO_TCP_INFO` layout, disorder,
OOB, the Linux fake and the UDP burst; no root needed); Linux race
tests; a 30-second smoke run of each fuzz target; Go 1.20.14 minimum-version
checks on Linux and on Windows (the native fake TCP/UDP backends); and builds of the library, `desync-socks` and `desync-probe` for Windows, Linux and macOS
(amd64/arm64), Linux armv7 and Android arm64. The `CI` job passes only when every
other job does, so it is the one check to require on `main`. This describes the
workflow configuration; inspect the actual Actions result for a given revision.
The separate `Binaries` workflow (`.github/workflows/binaries.yml`) builds both
commands for windows, linux and darwin (amd64, arm64) and android/arm64 on every
push to `main` (artifact `desync-binaries`, with `SHA256SUMS`) and attaches them
to the GitHub release of a `v*` tag.
The module's declared minimum remains Go 1.20 and it uses only the standard library.

## Real-network measurements with desync-probe

Loopback tests show that a strategy is applied correctly, not that it gets past
a filter. Real-network results come from `desync-probe` reports sent by testers
(see [testing on your network](../README.md#testing-on-your-network)). Read a
report with these limits in mind:

- One report describes one network at one time; filters differ by provider,
  region, IPv4/IPv6 and time of day. Compare reports by `strategies[].id`
  (derived from `Options.Key()`), not by name.
- `works` needs an HTTP response from a server whose certificate verified for
  the name; `fails` with `reset`, `timeout` or `eof` at the `tls` stage is the
  usual sign of SNI filtering, while a `dial` failure or a `failed` DNS status
  points at address or DNS blocking that no ClientHello strategy changes.
- A target whose `address` is `non-public` was answered by a local proxy, VPN
  or DNS filter; its results do not describe the provider's network.
- `flaky` pairs and random presets need more repetitions (`-repeat`) before a
  conclusion. The order of attempts is interleaved, but rate limiting by a site
  can still look like filtering.
- The probe measures one HEAD request on a fresh connection. It does not show
  that a long video stream, a Discord voice session or QUIC traffic works.

Loopback coverage of the tool, 2026-10-29: every preset this OS supports
completes a verified HTTP/1.1 and HTTP/2 exchange (the TCP fake presets
complete on Linux, where the receiver reads the rewritten page, and fail at
the TLS stage on Windows, where the server receives the fake bytes since no
router drops them); error classes for a reset after the ClientHello, a silent
server, a normal close, a wrong certificate, a silent HTTP server and a
refused port; an emulated filter that resets connections whose first segment
carries the server name; concurrency and budget bounds; and a report scanned
for loopback, interface and MAC addresses, the host name and the user name.

## Local verification, 2026-10-29 (desync-probe)

- Windows 11 26200: `go test ./...` on Go 1.26.10 (`-shuffle=on`) and Go 1.20.14;
  `go vet ./...` for windows, linux and darwin on both.
- Linux in Docker: `go vet` and `go test ./...` on Go 1.26.9 and 1.20.14,
  `go test -race ./...`, and the tool's package three more times with `-race`.
- Builds of both commands for windows, linux and darwin (amd64, arm64),
  android/arm64, linux/arm, freebsd/amd64 and js/wasm; the binaries workflow
  build loop was run locally; `actionlint` on both workflows.
- Not verified: the workflow on GitHub (artifact upload and release
  publishing), macOS and Android runtime of the tool, the Termux resolver
  fallback, double-click behavior on Windows, and any real filtered network.

## Local verification, 2026-10-29 (cross-platform methods)

- Windows 11 26200: `go test ./...` on Go 1.26.10 and Go 1.20.14, including
  disorder, OOB and disoob over IPv4/IPv6 with every split combination, the
  urgent byte read inline with `SO_OOBINLINE`, hop-limit recording per write
  and restoration after failures, deadlines, timeouts and Close.
- Linux in Docker (WSL 2 kernel): tests on Go 1.26.9 and 1.20.14, `-race` for
  all packages. The Linux fake, disorder and disoob were checked against a
  server-side BPF filter dropping low-hop segments: the server read the
  original stream after one retransmission, also with a fake of different
  bytes; with the page rewrite disabled the server read the fake bytes. The
  UDP burst and the `IP_RECVERR` suppression were checked with a loopback
  port-unreachable reply. File descriptors and fake slots return to their
  previous counts.
- `go vet ./...` for GOOS windows, linux and darwin on Go 1.26.10 and 1.20.14,
  plus freebsd and linux/386, linux/arm; builds for linux/386, linux/arm,
  linux/arm64, linux/riscv64, android/arm64, darwin/amd64, darwin/arm64,
  freebsd/amd64, windows/386, windows/arm64 and js/wasm.
- Not verified locally: any macOS runtime behaviour (disorder, OOB, the UDP
  burst, the dual-stack hop-limit restore; CI runs those tests), Android,
  real networks and DPI effectiveness, and a route whose device lacks
  scatter-gather.

## Local verification, 2026-10-29 (platform ACK capabilities)

- Windows: `go test ./...` on Go 1.26.10 (with `-shuffle=on`) and Go 1.20.14; on
  Go 1.20.14 the native fake TCP/UDP tests failed before this change with
  `read fake TTL: not supported by windows` and pass after it.
- `go vet ./...` for GOOS windows, linux and darwin on Go 1.26.10 and 1.20.14;
  builds for freebsd/amd64, android/arm64, linux/arm, linux/386, windows/386,
  windows/arm64, darwin/arm64 and js/wasm.
- Linux in Docker: tests and vet on Go 1.26.9 and 1.20.14, `-race` for all
  packages, and the split-wait tests 20 times with `-race`.
- Not verified locally: macOS runtime (only vet/build here; CI runs the tests),
  Android, real-network paths and Windows versions before 10 1703.

## Completed local verification, 2026-10-28

- Full Windows tests/vet on Go 1.26.10, including native TCP/UDP protections.
- Full Linux tests with race/vet on Go 1.26.9, in a cached Docker image with external
  networking disabled. New framing scenarios repeated 20 times; controller scenarios
  repeated 30 times with race. Windows controller repeated 50 times.
- Verified local TLS 1.2/1.3 over IPv4/IPv6, multi-record/fragmented/coalesced input,
  invalid vectors, incomplete/oversized input, deadlines and close/partial-write cases.
- Two framing/assembly fuzz targets: 1,126,427 and 1,061,903 displayed executions in
  the final bounded runs. Controller-key fuzz: 352,861 executions. No failures found.
- Existing manifest-patched Mihomo adapter/routing/probe/TCP-budget tests with only
  a temporary library dependency override, including the roughly 78-second sustained
  UDP binding regression. No production manifest or installed core was updated.
- Controller statement coverage 94.1%, owned HTTPS application-probe example and
  Darwin arm64 compile. No local macOS runtime or native Windows race run is claimed.

## Split wait latency, 2026-10-29

Loopback only; this measures the cost of observing the socket, not a network.
Intel i7-14700K, Windows 11 26200 (host) and Linux in Docker Desktop (WSL 2
kernel, Go 1.26.9). Each sample is the duration of the first `Write` of a 517-byte
ClientHello split into four pieces (three waits) on a fresh connection, 1,000
connections per row. Windows times use `QueryPerformanceCounter`, because Go's
monotonic clock there advances in steps of about 0.5 ms. Reproduce with
`DESYNC_MEASURE=1 go test -run TestMeasureSplitWait -v .`

| Platform | Mode | p50 | p95 | p99 |
| --- | --- | ---: | ---: | ---: |
| Windows, Go 1.26.10 | none | 40.2 µs | 56.4 µs | 83.4 µs |
| Windows, Go 1.26.10 | sent | 48.4 µs | 63.1 µs | 99.4 µs |
| Windows, Go 1.26.10 | acked | 48.9 µs | 62.9 µs | 83.4 µs |
| Windows, Go 1.20.14 | none | 59.0 µs | 85.2 µs | 118.2 µs |
| Windows, Go 1.20.14 | sent | 68.7 µs | 94.9 µs | 120.4 µs |
| Windows, Go 1.20.14 | acked | 67.1 µs | 88.8 µs | 130.2 µs |
| Linux, Go 1.26.9 | none | 17.9 µs | 25.9 µs | 65.6 µs |
| Linux, Go 1.26.9 | sent | 21.2 µs | 35.3 µs | 112.8 µs |
| Linux, Go 1.26.9 | acked | 21.2 µs | 32.8 µs | 46.3 µs |

On loopback the acknowledgement is usually already there at the first poll, so
these rows show the query cost: about 3–10 µs per Write on both systems. On a
real path each wait lasts at least one round trip, plus the polling delay below.

Polling delay: a condition that becomes true 0–4.9 ms after the wait starts
(500 samples, a stub observer, so only the wrapper's polling is measured) was
noticed after:

| Platform | p50 | p95 | p99 | max |
| --- | ---: | ---: | ---: | ---: |
| Windows, Go 1.26.10 | 0.37 ms | 1.33 ms | 1.49 ms | 1.57 ms |
| Windows, Go 1.20.14 | 12.6 ms | 15.0 ms | 15.4 ms | 15.9 ms |
| Linux, Go 1.26.9 | 0.58 ms | 1.05 ms | 1.09 ms | 1.40 ms |

The Go 1.20 Windows row reflects that toolchain's timer resolution (about
15.6 ms); newer Go versions use high-resolution timers on Windows. The wait
keeps no goroutine, timer or native handle after it returns. macOS was not
measured locally; CI runs its functional tests.

ACK observation evidence on loopback: with the peer not reading and a 32 KiB
receive buffer, Linux reported 983,094 bytes unacknowledged and unsent and
both modes unmet, then zero after the peer read. On Windows both modes stayed
unmet while blocked, and were met after the read, but `BytesOut` reached
1,375,590 for a 1 MiB write (and 100,040 for a 100,000-byte write) with
`BytesRetrans` zero. Writes up to 16 KiB were counted exactly. This is why the
Windows observation is reported as not reliable.

## Measured local overhead

These are dated local measurements, not universal performance promises. CPU:
Intel i7-14700K. Controller benchmarks use `-cpu=1`, three repetitions at 300 ms and
an immediate mock application proof. Medians below are medians of benchmark means,
not individual connection percentiles.

| Platform | Cold/refresh selection | Warm selection | Cold memory | Warm memory | Cold/warm callbacks |
| --- | ---: | ---: | --- | --- | --- |
| Windows | 2,575 ns/op | 190.2 ns/op | 1,848 B / 21 allocs | 0 B / 0 allocs | 1 / 0 |
| Linux | 4,483 ns/op | 220.8 ns/op | 1,848 B / 21 allocs | 0 B / 0 allocs | 1 / 0 |

These results establish controller overhead and avoided repeat probes, not real
network setup time. A cold selection waits for the actual configured probe result.
Raw repetitions are in [controller benchmark data](benchmarks/controller-2026-10-28.json).

The earlier same-binary framing comparison used the original UDP pin, lifecycle
slice and full-framing implementation, identical capturing sinks and an 8078-byte
synthetic hello. Three repetitions, CPU=1, Windows 200 ms / Linux 100 ms:

| One-byte writes | Original allocated bytes/op | New allocated bytes/op | Original/new allocations |
| --- | ---: | ---: | --- |
| Windows | 34,946,576 | 33,456 | 8,136 / 21 |
| Linux | 34,946,576 | 33,456 | 8,136 / 21 |

This is cumulative allocation including the fixture sink, not retained heap/RSS.
On a small complete 517-byte hello, Windows CPU increased from about 381 to 741 ns
for stronger validation while retaining 944 B / 7 allocations. Later writes remain
allocation-free. The comparison harness is an audit experiment, not the controller
benchmark command above; [full result data](benchmarks/clienthello-2026-10-28.json)
records all variants/chunk sizes.

Owned loopback full certificate-verified TLS matrices comprised 3,600 connections
per OS plus 1,500 Windows native-adapter connections, with zero observed failures.
They include explicit record/Write fragmentation and IPv4/IPv6. They do not cover
provider filtering, DNS variation, browser startup or sustained Discord sessions.
Direct versus new TLS timings were close and noisy; no real-network speedup is
claimed from them. The [remaining benchmark plan](vnext.md#5-real-network-validation-and-release)
requires comparable connection p50/p95/p99 and real application outcomes.

## Compatibility notes

- Prefer keyed `Options` literals; the optional `ClientHello` field was added.
- `ParseHello` now reports incomplete handshake input explicitly.
- Buffered Write acceptance is not delivery/ACK. Native fake errors can conservatively
  report zero even after transmission started; never infer replay safety from that.
- The controller only returns IDs and proofs; consumers must supply their catalog,
  application contracts and persistence. Manual choices are unverified.
- Randomization is opt-in through `Options.Random`; `Options.Key()` identifies a
  strategy including its policy and seed. Seeded draws are tied to the key version.
- `Options.SplitWait` observes the socket's send queue; it is not a timing
  heuristic. Options without it keep their previous `Key()`.
- `Options.Disorder` and `Options.OOB` are appended to `Key()` only when set,
  so existing keys are unchanged. `Capabilities` gained fields; compare its
  fields rather than the whole struct (it now holds a map).
- No new named Mihomo outbound, subscriber reserve implementation or client
  migration was added by these library stages.
