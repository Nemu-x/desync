# Architecture and source-backed audit

Audit date: 2026-10-28. The library findings below were reproduced before changes.
The consumer findings describe pinned snapshots, not a claim about every future
SlothClash or Mihomo version. No production route or installed client was changed.

## Evidence revisions

| Component | Audited source |
| --- | --- |
| Desync original main | [`3fa5a43`](https://github.com/Nemu-x/desync/tree/3fa5a43f2e74c66b654e7627557370281c261280) |
| Desync actual UDP consumer pin | [`3d47171`](https://github.com/Nemu-x/desync/tree/3d471713bd2e8c3c265d929bfc24a84e04b4b94a) |
| SlothClash | [`ed0abca`](https://github.com/Nemu-x/SlothClash/tree/ed0abca5ea274177017b5d48ca95f2084447f3e4) |
| Patched Mihomo consumer | Base [`3f27ef3`](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8), plus the 22 patches in the [pinned consumer manifest](https://github.com/Nemu-x/SlothClash/blob/ed0abca5ea274177017b5d48ca95f2084447f3e4/core/mihomo/manifest.json) |
| Prizrak comparison | [`657c9de`](https://github.com/legiz-ru/Prizrak-Core/tree/657c9de1f24bcfe1ce1ae32ee8ef662cf35d3454), the branch containing freedom/fragment |

The three completed library slices are independently reviewable:
[lifecycle](https://github.com/Nemu-x/desync/commit/a2bf018960ee354dec81231892c82d4082e703b4),
[ClientHello](https://github.com/Nemu-x/desync/commit/ebad7bc72a79649ad6de32fa4e8d496624b034f7),
[controller](https://github.com/Nemu-x/desync/commit/fd43f25b3c71c2a851fde504766bdffb039c832b).

## Current consumer request lifecycle

Control plane: DesyncPanel/useDesyncStatus → settings/preferences → runtime config
overlay → named candidates and selector groups → core API selection. Service IPC
starts/stops the privileged process; it does not forward application payload.

Data plane: application/TUN or mixed inbound → Mihomo metadata/rules → selected
named direct.desync candidate → native DNS/dial/socket → Desync wrapper → first
ClientHello transformation → destination → ordinary response forwarding.

The existing route is already native. `cmd/desync-socks` is an optional development
tool, not an extra hop in this SlothClash path. A future dedicated outbound improves
configuration/isolation but cannot alone fix parsing, search cost or socket lifetime.

Pinned source entry points (paths below the SlothClash desktop app unless noted):

| Step | Source / function |
| --- | --- |
| UI/settings | `frontend/src/components/DesyncPanel.tsx:35`; `frontend/src/hooks/queries/useDesyncStatus.ts:70`; `desync_settings.go:153` SetDesyncSettings |
| Config generation | `runtime_config.go:16`; `internal/runtimecfg/subscription_overlay.go:328`; `internal/runtimecfg/desync_overlay.go:18` |
| Candidate catalog | `internal/desync/candidates.go:98`; `desync_candidates.go:26` network/build fingerprint |
| Search/selection | `desync_auto.go:376` chooseDesyncTCP; `:294` selector API; `:632` session workers |
| Consumer core adapter | Reconstructed patched core: `adapter/parser.go:134` NewDirectWithDesyncOption; `adapter/outbound/direct.go:38` DialContext; `adapter/outbound/direct_desync.go:40` wrapper facade |
| Original transformation | UDP pin `conn.go:88` Write; `clienthello.go:63` parser; `pos.go:42` positions |
| Reserve/standalone | `desync_reserve.go:129`; `internal/runtimecfg/desync_only.go:25` |

The adapter paths/line numbers refer to the manifest-reconstructed tree, not to
unpatched upstream files. Rebuild that exact manifest before comparing those lines.

## Verified findings and disposition

| Finding | Evidence and significance | Disposition |
| --- | --- | --- |
| First record mistaken for full ClientHello | Original parser/Write lost SNI across records; regression reproduced valid multi-record input being left untransformed | Fixed by full handshake framing/scatter parsing |
| Incomplete-byte writes copied accumulated input repeatedly | Synthetic 8078-byte hello in one-byte writes allocated about 35 MB/op before; new bounded geometric assembly about 33 KB/op in the same capturing fixture | Fixed; benchmark scope is allocation totals, not browser memory |
| Buffered writes/lifecycle and transformed progress gaps | Close/expired deadline acceptance, split-wait interruption and partial progress were reproduced in isolated fixtures | Fixed with regression tests; native fake error counts remain deliberately conservative |
| Repeated serial service probes | Audited catalog: 6 YouTube TCP, 34 Discord TCP, 39 voice candidates; passing TCP checks use 2 YouTube / 4 Discord URL tests, serial within a search | Independent bounded controller implemented; consumer migration still pending |
| Cache freshness/negative-result limitations | Consumer cache has six network/build entries with shared 24-hour timestamp; new sessions revalidate winners; no reusable per-candidate ranking/negative cache | New controller has per-target proof timestamps, cooldowns, ranking and snapshots; not wired into client |
| Unverified initial candidate can serve normal connections | Normal requests are not blocked behind calibration; the first/cached choice is selected immediately | Source-proven class of startup failure; not proven cause of a particular user incident |
| Status mutex covers selector IPC | A mocked 40 ms core operation blocked status for approximately the same duration | Consumer lock-scope refactor remains pending |
| IPC latency | Owned local pipe benchmark p95 about 0.126 ms | No evidence that IPC alone explains multi-second failures |
| Native fake contention | Windows TCP fake has a process-wide two-transmission limit shared by probes and real traffic | Preserve resource bounds; actual provider queue impact remains unmeasured |
| Windows IPv6 fake TTL selection | Original backend read IPv4 TTL on an IPv6 socket, then setting it failed; reproduced against unchanged UDP pin | Fixed peer-family option selection/restoration |

The existing URLTest performs verified TLS and a HEAD response check with an
expected HTTP status. It does not classify a bare dial as success. It also cannot
prove video playback or Discord media stability. The new controller explicitly
requires a caller-supplied sufficient proof; its correctness depends on that probe
contract being implemented honestly.

A core/config reload does not unconditionally close every established stream.
Existing native UDP binding/source-port handover logic is important and should
not be deleted during TCP cleanup. Process restart/cache migration and an explicit
core-instance identity remain consumer integration concerns.

## Component boundaries after this change

- Root package: deterministic connection transformations, framing, bounds,
  deadlines, native resource lifetime and platform capability checks.
- `controller`: generic cache/discovery lifecycle, opaque candidate IDs, injected
  application prober, observed results and caller-owned snapshots. No GUI, core,
  dialer, hardcoded probe URL or application request replay.
- Mihomo adapter (later): routing/dial contexts, direct socket ownership, explicit
  options/cache consumption, protocol compatibility and truthful diagnostics.
- Client (later migration): persisted user preferences, candidate catalog/probe
  configuration, network identity, presentation and subscription reserve policy.

Prizrak's freedom adapter was an architectural comparison. Its first-record
buffering and timing-based ACK assumptions were not copied. There is no new ACK
synchronization or randomization implementation in this stage.

See the [ordered remaining plan](vnext.md) and [validation record](validation.md).
