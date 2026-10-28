# desync

[![CI](https://github.com/Nemu-x/desync/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Nemu-x/desync/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Nemu-x/desync.svg)](https://pkg.go.dev/github.com/Nemu-x/desync)
[![Go 1.20+](https://img.shields.io/badge/go-1.20%2B-00ADD8?logo=go)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

A Go library that adapts direct TCP and UDP connections to networks with deep packet inspection.

`desync` wraps a socket your program already owns and reshapes how the first TLS ClientHello goes out on the wire. The server still receives the exact same handshake. It is not a VPN or a proxy service, needs no driver or administrator rights, and depends only on the Go standard library.

```go
conn := desync.WrapConn(raw, desync.Options{
    TLSRec: []desync.Pos{{Offset: 1, FromSNI: true}}, // split the ClientHello right after the start of the server name
})
```

## Why

A filter on the path and the destination server can read the same bytes differently. Where the TLS records end, how the bytes are split into writes, and what the first transmission of a segment contains can change what the filter sees, while the server reassembles an identical handshake.

## Methods

| Method | What it does | Windows | Linux | macOS |
| --- | --- | :---: | :---: | :---: |
| TLS record fragmentation (`TLSRec`) | Splits the ClientHello into several valid TLS records | ✓ | ✓ | ✓ |
| TCP write splitting (`Split`, `SplitDelay`) | Sends the ClientHello in separate writes, optionally with a pause | ✓ | ✓ | ✓ |
| Split wait (`SplitWait`) | Before each further piece, waits until the kernel reports the previous bytes as sent or acknowledged | sent, acked¹ | sent, acked | acked |
| Low-TTL fake prefix (`Fake`) | First transmission of a prefix carries other bytes with a short hop limit; a retransmission carries the original | ✓ | — | — |
| Low-TTL UDP burst (`WrapPacketConn`) | Bounded low-TTL datagrams before the first datagrams to each peer; originals are unchanged | ✓ | — | — |

¹ Inferred from counters, not reliable; see [platform capabilities](#platform-capabilities-and-split-wait).

Only a connection that starts with a TLS ClientHello is transformed. Any other traffic, and everything after the ClientHello, passes through untouched. Unsupported methods return an explicit error, never a silent fallback to another method. `PlatformCapabilities()` reports what this build implements on the current OS, and `ProbeConn` checks an actual socket.

## Install

```sh
go get github.com/Nemu-x/desync
```

## Usage

Wrap the connection before the first TLS byte is written:

```go
func connect(ctx context.Context, address, serverName string) (*tls.Conn, error) {
    raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
    if err != nil {
        return nil, err
    }

    opts := desync.Options{
        TLSRec: []desync.Pos{{Offset: 3, FromSNI: true}},
    }
    if err := opts.Validate(); err != nil {
        raw.Close()
        return nil, err
    }

    conn := tls.Client(desync.WrapConn(raw, opts), &tls.Config{ServerName: serverName})
    if err := conn.HandshakeContext(ctx); err != nil {
        conn.Close()
        return nil, err
    }
    return conn, nil
}
```

`WrapConn` returns the connection itself when no method is enabled. Options are copied on wrap, so changing them later does not affect an existing connection. Buffered and partial writes, deadlines and closing are specified in [connection I/O contracts](docs/connection-io.md).

### Positions

| Value | `ParsePos` | Meaning |
| --- | --- | --- |
| `Pos{Offset: 3}` | `"3"` | Byte 3 of the TLS input, counting from the first record header |
| `Pos{Offset: 1, FromSNI: true}` | `"1+s"` | One handshake byte after the start of the server name |
| `Pos{Offset: -2, FromSNI: true}` | `"-2+s"` | Two bytes before the server name |

SNI-relative positions skip existing record headers. Positions without an SNI, outside the ClientHello, or on an existing record boundary are ignored. `TLSRec` positions choose record boundaries; `Split` positions choose write boundaries.

### Random cuts

`Options.Random` adds bounded random record and write cuts on top of the fixed positions; nil keeps a strategy fully deterministic. Each `RandomCut` draws `Count` cuts uniformly from the inclusive range `From`..`To` (both absolute or both SNI-relative), at least `MinPiece` bytes apart:

```go
opts := desync.Options{
    TLSRec: []desync.Pos{{Offset: 1, FromSNI: true}},
    Random: &desync.RandomOptions{
        TLSRec: []desync.RandomCut{{From: desync.Pos{Offset: -8, FromSNI: true}, To: desync.Pos{Offset: 8, FromSNI: true}, Count: 2, MinPiece: 2}},
        Split:  []desync.RandomCut{{From: desync.Pos{Offset: 1}, To: desync.Pos{Offset: 120}}},
        Seed:   0, // 0: a new seed per connection; nonzero: the same cuts on every connection
    },
}
```

Random cuts never change handshake bytes, create empty records or writes, or add delays beyond `SplitDelay`. A nonzero `Seed` reproduces a test or a bug report. `opts.Key()` is a stable description of every option, the random policy and seed included: derive cached strategy IDs from it so an ID never silently changes meaning.

A ClientHello may arrive across several records and `Write` calls. Assembly is bounded by default to a 64 KiB handshake, 256 records and a 5-second timeout for incomplete input; `Options.ClientHello` changes these limits. A complete ClientHello written at once starts no timer.

### Platform capabilities and split wait

```go
caps := desync.PlatformCapabilities()
// windows: {FakeTCP:true FakeUDP:true TTLControl:true Ack:{Mechanism:SIO_TCP_INFO Sent:true Acked:true Reliable:false}}
// linux:   {Ack:{Mechanism:SIOCOUTQ/SIOCOUTQNSD Sent:true Acked:true Reliable:true}}
// darwin:  {Ack:{Mechanism:SO_NWRITE Acked:true Reliable:true}}

opts := desync.Options{
    Split:            []desync.Pos{{Offset: 1, FromSNI: true}},
    SplitWait:        desync.SplitWaitAcked, // or SplitWaitSent
    SplitWaitTimeout: time.Second,           // per wait; default 2 s
}
if err := opts.Validate(); errors.Is(err, desync.ErrSplitWaitUnsupported) {
    // this OS cannot observe it; choose another strategy explicitly
}
```

`SplitWait` reads the socket's send queue between pieces: `SplitWaitSent` waits until every byte written so far was transmitted at least once, `SplitWaitAcked` until the peer acknowledged it. The wait ends as soon as the kernel reports the condition. It is not a delay, and it is never replaced by one: an OS or socket that cannot observe the condition fails `Validate` or the first `Write` with `ErrSplitWaitUnsupported` / `ErrSplitWaitRequiresTCP` before anything is sent. `SplitDelay` remains the separate, explicit pause and runs after the wait when both are set.

| OS | Interface | Sent | Acked | Reliable |
| --- | --- | :---: | :---: | :---: |
| Linux, Android | `ioctl` `SIOCOUTQ` (unacknowledged bytes), `SIOCOUTQNSD` (unsent bytes) | ✓ | ✓ | ✓ |
| macOS | `SO_NWRITE` (send-buffer bytes, kept until acknowledged; same value as `TCP_CONNECTION_INFO.tcpi_snd_sbbytes`) | — | ✓ | ✓ |
| Windows 10 1703+ | `SIO_TCP_INFO` counters (`BytesOut`, `BytesRetrans`, `BytesInFlight`) | ✓ | ✓ | — |

Reliable means the kernel's own queue state is read. Windows has no unsent-bytes value, so the wait compares counter growth with the bytes written; on loopback `BytesOut` exceeded the written bytes for large writes, so the wait can end early. Close, write deadlines (including changes to them) and `SplitWaitTimeout` bound every wait; a timeout returns `ErrSplitWaitTimeout` and closes the connection. Where the observation is reliable, `SplitWaitAcked` writes a piece only after every earlier byte was transmitted and acknowledged, so no segment carries bytes of two pieces; with `SplitWaitSent` a retransmission can still combine them. The OS still divides a piece into segments. Details and measurements: [connection I/O](docs/connection-io.md#split-wait), [validation](docs/validation.md#split-wait-latency-2026-10-29).

### Low-TTL fake prefix (Windows)

```go
opts := desync.Options{
    TLSRec: []desync.Pos{{Offset: 1, FromSNI: true}},
    Fake:   &desync.FakeOptions{TTL: 4, Prefix: -1},
}
```

- `TTL` must expire after the filter and before the server. It depends on the route; 4 is an example, not a default.
- `Prefix` is measured after record fragmentation. Negative values count from the end; `-1` leaves the last byte for a normal write.
- `Payload` replaces the bytes of the first transmission; by default an embedded TLS template is used, padded or truncated to the prefix.
- `Timeout` (default 3 s) bounds the native waits. Write deadlines on the wrapper bound normal writes; `Close` interrupts both.

The backend sends the prefix with `TransmitFile` from a delete-on-close temporary file, then puts the original bytes in the file cache for the retransmission and restores the socket's hop limits. Native resources are kept until the operation completes or is cancelled. An error after a transformed send is terminal for the connection. Fake can be combined with `TLSRec`, not with `Split`.

### Low-TTL UDP burst (Windows)

```go
pc, err := net.ListenPacket("udp", ":0")
if err != nil {
    return err
}
packets, err := desync.WrapPacketConn(pc, desync.UDPOptions{TTL: 4, Repeats: 6, Packets: 3})
if err != nil {
    pc.Close()
    return err
}
defer packets.Close()

_, err = packets.WriteTo(datagram, peer)
```

- Needs an **unconnected** UDP socket that exposes `SyscallConn`. The wrapper owns all writes to it.
- `Repeats` (1–16, default 6) low-TTL datagrams go before each of the first `Packets` (1–8, default 3) datagrams to a peer. The default payload is 64 zero bytes.
- Originals keep their content, order and source port. The hop limit is restored before every original; if it cannot be restored, the socket is closed.
- Up to 64 peers per socket are tracked, with a 2-minute idle expiry; further peers pass through unchanged.
- TTL-expired ICMP replies are suppressed on the socket (`SIO_UDP_NETRESET`), so they do not surface as receive errors.
- `Counters()` reports original and fake datagrams, errors and peers. A shared `*UDPCounters` aggregates several sockets. Counters show what was sent, not whether it helped.

## Strategy controller

The optional [`controller`](docs/controller.md) package picks a verified strategy for a destination and network and caches it. It runs caller-supplied application probes with bounded concurrency, attempts and deadlines, shares discovery between callers, keeps negative results and a last-known-good ranking, and supports manual override and background revalidation. The connection wrapper does not depend on it, and it ships no probe targets of its own. A runnable example with a local HTTPS server is in [`controller/example_test.go`](controller/example_test.go).

## desync-socks

A minimal SOCKS5 CONNECT proxy for trying methods on a real network:

```sh
go run ./cmd/desync-socks -listen 127.0.0.1:10802 -tlsrec 3+s
go run ./cmd/desync-socks -listen 127.0.0.1:10802 -split 1+s -split-wait acked
go run ./cmd/desync-socks -listen 127.0.0.1:10802 -tlsrec 1+s -fake -1 -ttl 4   # Windows
```

Point the application under test at the SOCKS endpoint. It does not change system proxy settings, has no authentication and no UDP.

## Effectiveness

Whether a method works depends on the route and the filtering equipment. Test on the network you target, compare strategies on fresh connections (an established connection keeps its handshake), and keep the ordinary route available as a way back.

## Development

```sh
go test -count=1 -timeout=3m ./...
go vet ./...
go test -race -count=1 ./...
```

Fuzz targets, benchmarks and what has been verified are listed in [validation](docs/validation.md). Design notes: [architecture](docs/architecture.md), [roadmap](docs/vnext.md).

## License

MIT, see [LICENSE](LICENSE). The default fake TLS template comes from ByeDPI (MIT); its notice is in [third_party](third_party).
