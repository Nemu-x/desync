# desync

A Go library for adapting direct TCP and UDP traffic to networks that use deep packet inspection.

`desync` runs inside the application that owns the connection. It transforms the first outgoing TLS ClientHello while preserving the handshake seen by the destination server. It does not provide a VPN tunnel or a remote proxy service.

## Why it exists

A network filter and the destination server can interpret the same connection differently. TLS record boundaries, TCP write boundaries and the first transmission of selected bytes can influence what the filter sees without changing the final TLS handshake delivered to the server.

The library exposes these transformations as a small `net.Conn` wrapper, so proxy cores and other Go applications can apply them to selected connections. Routing, service selection and configuration remain under the application's control.

## Methods

| Method | Behaviour | Platforms |
| --- | --- | --- |
| TLS record fragmentation | Splits the ClientHello across multiple valid TLS records. | Windows, Linux, macOS |
| TCP write splitting | Sends the ClientHello in separate writes, optionally with a delay. TCP segmentation is ultimately controlled by the operating system. | Windows, Linux, macOS |
| Low-TTL fake prefix | Sends an alternate initial prefix with a short hop limit and restores the original bytes for TCP retransmission. | Windows |
| Low-TTL UDP fake burst | Sends bounded extra datagrams before initial application datagrams and restores the normal hop limit before the unchanged original payload. | Windows |

The TCP wrapper transforms only a connection starting with a TLS ClientHello. Other TCP traffic and later application writes pass through normally. UDP is an independent opt-in wrapper. The library does not intercept system traffic, install a network driver, or require administrator privileges by itself.

## Install

```sh
go get github.com/Nemu-x/desync
```

The module uses the Go standard library and has no external runtime dependencies.

## Use from Go

Wrap an established connection before starting TLS:

```go
package example

import (
    "context"
    "crypto/tls"
    "net"

    "github.com/Nemu-x/desync"
)

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

    conn := tls.Client(desync.WrapConn(raw, opts), &tls.Config{
        ServerName: serverName,
        MinVersion: tls.VersionTLS12,
    })
    if err := conn.HandshakeContext(ctx); err != nil {
        conn.Close()
        return nil, err
    }
    return conn, nil
}
```

`WrapConn` returns the original connection when all methods are disabled. Options are copied, including slices and the fake payload, so changing the caller's configuration does not alter an existing wrapper.

See [connection I/O contracts](docs/connection-io.md) for buffered/partial writes, deadlines, closing and current parser limitations.

### Positions

`Pos{Offset: 3}` means byte 3 of the original record. `Pos{Offset: 1, FromSNI: true}` means one byte after the start of the server name. `ParsePos("1+s")` parses the same position from text.

`TLSRec` positions choose record boundaries. `Split` positions choose write boundaries; `SplitDelay` adds a delay between writes.

### Windows fake prefix

```go
opts := desync.Options{
    TLSRec: []desync.Pos{{Offset: 1, FromSNI: true}},
    Fake: &desync.FakeOptions{
        TTL:    4,
        Prefix: -1,
    },
}
if err := opts.Validate(); err != nil {
    return err
}
conn := desync.WrapConn(tcpConn, opts)
```

The Windows backend uses a temporary delete-on-close file and native asynchronous socket operations. It restores the original file-cache contents and socket hop limits, submits the remaining normal bytes, and retains native resources until completion or cancellation.

`Prefix` is measured after TLS record fragmentation. Negative values count from the end; `-1` leaves the last byte for a normal write. `Payload` optionally supplies alternate bytes; otherwise an embedded TLS template is used. It is padded or truncated to the prefix length.

`Timeout` defaults to three seconds for native queue and completion waits. Set write deadlines on the returned wrapper to bound normal socket writes too. `Close` interrupts outstanding native waits. An error after a transformed send is terminal for that connection.

Use `SupportsFake()` to check platform availability. The backend requires a connection exposing `SyscallConn`; unsupported platforms or connection types return an explicit error. Combining fake with TLS record fragmentation is supported; combining fake with TCP write splitting is currently rejected.

### Windows UDP fake burst

```go
raw, err := net.ListenPacket("udp", ":0")
if err != nil {
    return err
}
packets, err := desync.WrapPacketConn(raw, desync.UDPOptions{
    TTL: 4, Repeats: 6, Packets: 3,
})
if err != nil {
    raw.Close()
    return err
}
defer packets.Close()
_, err = packets.WriteTo(originalDatagram, destinationUDPAddr)
```

This requires an **unconnected UDP socket** exposing `SyscallConn`; check `SupportsUDPFake()` for platform availability. The default fake payload is 64 zero bytes. `Repeats` is bounded to 1–16 and `Packets` to the first 1–8 application datagrams per peer (defaults: six repeats for the first three). Originals retain their contents, order and source socket. The wrapper owns all writes to the socket; never write directly to the underlying socket concurrently. Peer state is limited to 64 entries per socket with two-minute idle expiry; additional peers pass through while that table is full.

TTL/hop-limit is restored before sending the original datagram, including after a failed fake send. Deadlines remain resettable; `Close` unblocks socket I/O. An inability to restore the hop limit closes the socket. On Windows the owned socket suppresses TTL-expiry ICMP notifications using [`SIO_UDP_NETRESET`](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls#sio_udp_netreset), so intentional expiry does not appear as a receive failure. IPv4, IPv6-only and dual-stack IPv4 destinations are covered by native tests.

`packets.Counters()` returns original/fake datagrams, fake errors and tracked peer sessions. A shared `*UDPCounters` in the options aggregates sockets belonging to an outbound. These counters prove injection attempts, not effectiveness against a particular filter. UDP media such as [Discord voice](https://docs.discord.com/developers/topics/voice-connections) still requires a real application/network test; this wrapper does not implement Discord signalling or media encryption.

## Try a local SOCKS proxy

The repository includes a small SOCKS5 CONNECT proxy for development and integration checks:

```sh
go run ./cmd/desync-socks -listen 127.0.0.1:10802 -tlsrec 3+s
```

On Windows:

```sh
go run ./cmd/desync-socks -listen 127.0.0.1:10802 -tlsrec 1+s -fake -1 -ttl 4
```

Configure the application being tested to use that SOCKS endpoint. The command does not change system proxy settings. It supports TCP CONNECT without authentication; it does not implement UDP association.

## Integration and testing

A proxy core should wrap the outgoing direct TCP socket before any TLS bytes are written. Apply strategies through explicit routing rules and keep a way to switch back to the ordinary route. Existing connections retain their original handshake; reconnect the application when comparing strategies.

Network effectiveness depends on the route and the filtering equipment. Values such as TTL 4 are configuration examples, not universal defaults for every provider. TCP record transformations and UDP fake bursts are separate methods; neither supplies a remote proxy or implements application protocols.

```sh
go test -count=1 -timeout=2m ./...
go vet ./...
```

Tests cover parsing, record and write transformations, stream integrity, TLS handshakes, deadlines and cancellation. Windows tests also exercise native resource lifetime, hop-limit restoration, concurrency, pending-transfer behaviour, and UDP datagram order/source ports/fake limits/IPv4/IPv6. A real network check is still needed for the intended route and application.

## License

MIT. See [LICENSE](LICENSE). Notices for included third-party material are retained in [third_party](third_party).
