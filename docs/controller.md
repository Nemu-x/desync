# Optional strategy controller

`github.com/Nemu-x/desync/controller` is an independent, standard-library-only
package. The root Desync transformer does not import it. The controller selects
opaque IDs from a caller-owned immutable strategy catalog; it does not know about
Mihomo, SlothClash, GUI settings, proxies or UDP media sessions. It never opens a
socket by itself. Existing TCP/UDP users are unchanged unless they opt in.

## Connection boundary

1. The consumer supplies a normalized destination, network fingerprint, policy
   version, candidate IDs and explicit application probe contract.
2. `Select` returns a verified cached choice or performs bounded shared discovery.
3. The consumer maps the returned ID to `desync.Options`, dials and wraps its own
   outgoing socket before the first ClientHello.
4. Application traffic is sent once. A later observed failure can be reported
   with `Invalidate`; the consumer decides whether retrying that operation is safe.

Cold `Select` waits for a sufficient result or its deadline. Warm cache hits do
not wait for revalidation. A consumer that needs a nonblocking cold path must
explicitly choose its startup/fallback policy or manual override; this package
does not silently choose an unverified strategy. A manual selection returns
`Source="manual"`, `Level=Unknown` and no verification timestamps.

No automatic failover or replay of a POST, stream, call, user TLS session or other
application traffic occurs. Updating a cached selection affects future selections,
not already established connections. Discovery cannot prove that an unrelated
application operation will succeed.

## Probe contract and cache identity

`Prober.Probe(ctx, target, strategyID)` must honor context cancellation, perform an
idempotent out-of-band check and close every resource it owns. It must apply the
identified strategy to its own connection, validate the intended TLS peer, and
check the configured application response before returning `Application` proof.
`TLS` proof is sufficient only when the target explicitly opts into `Required=TLS`.
A successful dial or `Proof{Level:TCP}` is always insufficient. A nil error without
a sufficient proof is also a failed probe. The controller trusts this contract;
an incorrectly implemented callback cannot be made application-aware by the cache.

There are no built-in URLs or third-party public probe targets. `ProbeID` is an
opaque contract version, not a URL. The runnable
[`ExampleController_Select`](../controller/example_test.go) owns a local HTTPS
server, verifies its certificate and expected HEAD response, disables redirects,
applies record splitting and demonstrates a subsequent cache hit.

The key includes `Target{Network,Host,Port,ProbeID,Required}`. Hostnames are trimmed,
lowercased and lose final dots; IP addresses are canonicalized (IPv4-mapped
addresses unmap to IPv4; IPv6 zones retain case). URL/credential characters,
control characters, empty identities, zero ports and TCP-only requirements are
rejected. The caller must supply a new network identity when its relevant route
changes, and a new `PolicyVersion` when options or probe semantics change. The
candidate slice is copied; corresponding option values remain caller-owned.

IDs are purely consumer-defined, so derive each ID (or the `PolicyVersion`) from
`desync.Options.Key()`. The key covers every transformation field, including the
randomization policy and seed, and carries a version prefix that changes if an
unchanged value would behave differently, so a cached ID never silently changes
meaning. An unseeded random policy is one strategy: its key identifies the
distribution, not one connection's cuts.

## Defaults and bounds

| Setting | Default | Hard limit |
| --- | --- | --- |
| Positive cache TTL | 30 minutes | 7 days |
| Negative result/candidate cooldown TTL | 30 seconds | 1 hour |
| Stale TTL | disabled | 24 hours, explicit opt-in |
| Probe timeout, including semaphore queue | 2 seconds | 1 minute |
| Discovery timeout, including all attempts/queues | 10 seconds | 5 minutes |
| Distinct attempts per discovery | 8 | 256 |
| Global callback slots | 2 | 64 |
| Parallel attempts per foreground discovery | 2 | 16 |
| Concurrent discoveries | 64 | 1024 |
| Entries | 512 | 16384 |
| Attempt history | 64 | 4096 |
| Candidate catalog size | caller supplied | 256 |
| Background discoveries | disabled; limit 1 when enabled | 64 |

Zero fields choose defaults, except `StaleTTL` and booleans. Negative durations or
limits are rejected. Background revalidation defaults to half the positive TTL
when enabled. Each background discovery runs only one candidate at a time and
uses the same global callback slots as foreground work; it is not a periodic scan
of unused destinations. Failed refreshes are throttled by the negative TTL.

## Discovery and ranking

Concurrent requests for the same key share one discovery. Canceling a waiter
detaches only that waiter; foreground work is canceled when no waiters remain.
An opted-in background discovery is owned by the controller instead. Different
destinations remain subject to the global callback and discovery caps.

The last-known-good candidate gets one confirmation attempt before parallel
search widens. Remaining eligible candidates rank by smoothed observed success /
failure counts, then successful probe-duration EWMA where available; equal scores
retain catalog order. This is a prioritization heuristic, not a measured success
percentage. The first sufficient result wins and cancels unnecessary attempts.
One candidate is attempted at most once in a discovery; the budget can leave
untried candidates for later discoveries. Fresh cache hits create no probes unless
background revalidation was explicitly enabled. Negative candidate cooldowns and
aggregate failure/deadline caching prevent repeated per-connection searches.

`SelectOptions{Refresh:true}` bypasses cache and cooldowns within the same finite
budget and still shares an already running discovery. A background failure does
not erase a still-valid last-known-good selection. Stale results are returned
only with a configured stale TTL and are clearly labeled `Source="stale"` and
`Stale=true`; revalidation additionally requires `BackgroundRevalidate=true`.
`DisableDiscovery=true` allows only a usable restored/cached or manual choice and
requires no prober. Unknown manual IDs fail explicitly.

`Invalidate` records feedback, clears a matching choice, increments its generation
and cancels stale discovery. A late callback cannot publish that invalidated result.
It does not launch another discovery or mutate a global selector.

## Cancellation and resource lifetime

Metadata locks never cover network callbacks or channel waits. Waiters, semaphore
queues, probes and discoveries have cancellation paths. `Close` cancels all work;
`Shutdown(ctx)` optionally waits for callbacks to return. A callback that ignores
its context cannot be killed in Go: the caller's wait still ends, but that callback
retains its global slot until it actually returns. Releasing the slot on timeout
would allow unbounded stuck callbacks and is deliberately avoided. A discovery
deadline is negative-cached even when its callback has not returned. A late proof
after its deadline/close/invalidation never becomes a cached success.

There are no retry sleeps or ACK-detection heuristics. Timeouts use monotonic Go
contexts. Optional `Config.Now` affects cache timestamps only and must be fast,
nonblocking, concurrent-safe and must not reenter the controller.

## Diagnostics and persistence

`Selection` reports strategy/source, proof level, verified/expiry timestamps,
cache/stale flags, winning callback duration, semaphore queue duration, total
discovery duration and scheduled attempts (including attempts canceled in queue).
A cache hit has zero new attempts/discovery duration; its probe duration belongs
to the historical verification, not a newly observed TLS handshake.

`Status` returns bounded attempt history and entry/discovery/active-slot counts.
Attempts contain outcome, stable code, proof level, callback and queue durations.
`Export` includes each selection, last negative reason/cooldown and per-candidate
success/failure/cancellation counts, last verified time and latency EWMA. Raw error
text is not retained. Callbacks/feedback must supply short stable diagnostic codes.
No TLS-only success is reported as application proof, and no fabricated success
percentage is exposed. Stream health and the consumer's own connection/TLS
timings must be instrumented by that consumer.

`Export` / `Restore` are versioned caller-owned persistence with no filesystem I/O.
Snapshots require the same policy version and known IDs, validate normalized keys,
proof levels and timestamps, and clamp expiry/cooldowns to current TTLs. Restore
validates the entire snapshot before replacing state and rejects active discovery.
Serialization and durable storage are the caller's responsibility. A restored
result is historical evidence, not a new network test. Cache storage is trusted
consumer state; validation does not authenticate a forged proof. Snapshots include
destination/network identities, so a consumer should redact them before sharing.

## Verification scope

Tests use deterministic mocks and an owned loopback HTTPS server. They exercise
cache expiry, negative caching, budgets, rankings, manual/off modes, bounded
parallelism, singleflight, independent waiter cancellation, cancellation of losers,
late/noncooperative callbacks, invalidation, LRU capacity, background/stale behavior,
snapshot validation and close/shutdown. Benchmarks separately report cold/warm
selection overhead and actual callback counts. They do not establish real-network
DPI effectiveness or stability of Discord media. Mihomo and SlothClash still need
an explicit later integration; importing the root transformer alone changes no
controller behavior.
