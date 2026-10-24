# desync

User-space DPI desynchronisation for Go proxies: it reshapes the first TLS
record of an outgoing connection (the ClientHello) so that a DPI box that
classifies traffic by the server name stops recognising it, while the server
still receives the same handshake. No kernel driver, no administrator rights,
the same code on Windows, macOS and Linux.

It is meant to be embedded in a proxy core (a `DIRECT`-style outbound that
rules send selected sites to), and is used by the SlothClash and ClashFest
mihomo cores.

## Methods

| Option | What goes on the wire |
|---|---|
| `TLSRec` | the ClientHello split into several TLS records at the given positions |
| `Split` | the (record-split) ClientHello sent in separate TCP writes |

Positions use ByeDPI's notation: `3` is byte 3 of the record, `1+s` is one
byte past the start of the server name.

```go
c, _ := net.Dial("tcp", "www.youtube.com:443")
c = desync.WrapConn(c, desync.Options{TLSRec: []desync.Pos{{Offset: 1, FromSNI: true}}})
```

Only a connection whose first bytes are a TLS ClientHello is touched, and only
its first record; everything else passes through unchanged.

## Measuring

`cmd/desync-socks` is a minimal SOCKS5 proxy around the library, to try the
methods against a real network from any machine:

```bash
go run ./cmd/desync-socks -listen 127.0.0.1:10802 -tlsrec 1+s
```

## License

MIT
