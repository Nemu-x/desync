# Validation and measurement scope

## Commands

Run from a clean repository checkout. Network fixtures own their loopback servers;
there are no implicit probes to YouTube, Discord or another public service.

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
with Go 1.26; Linux race tests; a 30-second smoke run of each fuzz target; a Go
1.20.14 minimum-version check; and builds for Windows, Linux and macOS
(amd64/arm64), Linux armv7 and Android arm64. The `CI` job passes only when every
other job does, so it is the one check to require on `main`. This describes the
workflow configuration; inspect the actual Actions result for a given revision.
The module's declared minimum remains Go 1.20 and it uses only the standard library.

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
- No ACK timing heuristic, new named Mihomo outbound, subscriber
  reserve implementation or client migration was added by these library stages.
