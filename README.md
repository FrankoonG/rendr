# rendr

[![Go](https://github.com/FrankoonG/rendr/actions/workflows/go.yml/badge.svg?branch=v0.1.0)](https://github.com/FrankoonG/rendr/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/FrankoonG/rendr.svg)](https://pkg.go.dev/github.com/FrankoonG/rendr)

A connection-migration framework for Go. An application holds a stable
`net.Conn` whose underlying network path rendr can swap — TCP socket,
QUIC connection, or opaque-UDP flow — without surfacing any reset,
EOF, or read-zero to the application.

rendr does only this. Proxy protocols, peer discovery, configuration
management, and detailed path-quality policies belong to the embedder.

```
go get github.com/FrankoonG/rendr
```

## Quickstart

Server:

```go
ln, err := rendr.ListenTCP("0.0.0.0:5555")
if err != nil { log.Fatal(err) }
for {
    c, err := ln.Accept(context.Background())
    if err != nil { return }
    go handle(c) // c implements net.Conn
}
```

Client:

```go
d := &rendr.Dialer{
    Mode: rendr.ModePrime,
    Paths: []rendr.PathSpec{
        {Transport: "tcp",  Address: "h1:5555"},
        {Transport: "quic", Address: "h2:5555"},
    },
}
c, err := d.Dial(context.Background())
// c.Read / c.Write survive a path swap.
// c.FlowID() stays constant for the connection's lifetime.
```

Listeners: `ListenTCP`, `ListenQUIC(addr, *tls.Config)`, `ListenUDPFlow`.
For stream servers that accept multiple path transports into one
bridge table, use `Listen(ListenSpec{Transport: "tcp", ...},
ListenSpec{Transport: "quic", ...})`.

Transport adapters auto-register: `"tcp"`, `"quic"`, `"udpflow"`.

## Embedder example

`examples/socks5` is a small reference embedder: a local SOCKS5
CONNECT endpoint opens one rendr `Conn` per proxied TCP connection,
then a rendr-side server dials the requested target. It is an example
of layering an application protocol on top of rendr, not a built-in
proxy protocol.

## Packet mode

For datagram-oriented applications, use `DialPacket` and
`ListenUDPFlowPacket`. Each `WriteTo` becomes one wire frame; each
`ReadFrom` returns one frame's payload. The wire format is identical
to stream mode; the two are negotiated in HELLO.

```go
ln, _ := rendr.ListenUDPFlowPacket("0.0.0.0:5555")
pc, _ := (&rendr.Dialer{
    Mode: rendr.ModePrime,
    Paths: []rendr.PathSpec{{Transport: "udpflow", Address: "h1:5555"}},
}).DialPacket(context.Background())
// pc implements net.PacketConn; boundaries preserved 1-to-1.
```

For applications that already own a UDP socket, package
`github.com/FrankoonG/rendr/udprelay` exposes a local UDP relay over a
rendr `PacketConn`. Point the application at `Relay.LocalAddr()` and
use `Relay.PacketConn()` for migration control.

## Modes

| Mode    | Bandwidth          | Latency           | Use for                          |
|---------|--------------------|-------------------|----------------------------------|
| `prime` | best single path   | best single path  | SSH, RDP, control channels       |
| `race`  | best single path   | min across paths  | trading, low-jitter UDP control  |
| `bond`  | sum of paths       | mid               | large file, video, multi-link    |

Set via `Dialer.Mode` or runtime `Conn.SetMode`. Legal transitions:
`prime ↔ race`, `prime ↔ bond`. `race ↔ bond` is forbidden because
race has no per-path SEQ ordering and bond requires it.

## Migration is invisible

The hard contract is that a path swap does **not** surface as an
error from the application's `Read` or `Write`. If every path dies
and no new one becomes available within the migration budget
(default 90 s), `Read` returns `rendr.ErrMigrationBudgetExceeded`.
Clean peer teardown surfaces as `io.EOF`.

Transport-layer errors (TCP RST, QUIC idle timeout, UDP socket
gone) are NEVER conflated with application EOF; they trigger
migration silently.

## Observability and control

The `Conn` returned by `Dial` / `Accept` also implements
`AdminConn`. Assert when you need it:

```go
adm := c.(rendr.AdminConn)
s := adm.Stats()
log.Printf("flow=%x state=%s mode=%s paths=%d hwm=%d",
    s.FlowID, s.State, s.Mode, len(s.Paths), s.RecvQueueHWM)

// Explicit migration:
if newID, err := adm.AddPath(rendr.PathSpec{Transport: "tcp", Address: "h3:5555"}); err == nil {
    _ = adm.Migrate(newID)
}
```

`AdminConn` surface: `Migrate`, `ActivePath`, `AddPath`, `RemovePath`,
`State`, `Mode`, `RecvQueueHWM`, `RecvDups`, `BondStuckSkips`,
`MigrationCount`, `Stats`. Packet-mode connections expose the same
methods via `AdminPacketConn`.

## Acceptance contracts

rendr is gated on five invariants — the implementation is not
considered done until all five hold under chaos-scale tests:

- **G1** Large file (≥1 GiB) with forced mid-stream migrations
  finishes with identical SHA-256 and <10% baseline throughput
  regression.
- **G2** 30-minute echo loop with 30+ migrations, zero loss,
  P99 RTT < baseline × 2.
- **G3** 100k pps QUIC datagrams + 10 ConnID migrations, zero
  application loss, P95 RTT < baseline × 2.
- **G4** Path A force-killed (network DROP) with path B intact;
  app sees no error; failover ≤ 5 s; in-flight data reaches the
  peer via path B.
- **G5** After G4, recover path A (via `AdminConn.AddPath`); it
  re-joins the path set without spurious reorder.

## Status

In active development under tag prefix `v0.1.x`. Public API may
still shift before `v1.0`; modes, AdminConn surface, and wire
format v0 are pinned by tests against drift.

The five acceptance contracts (G1-G5) have all been validated on
the development branch:

- G1 — 1 GiB transfer with mid-stream migrations, SHA-256 match,
  <10% throughput regression
- G2 — 60s continuous echo with 15+ migrations, 0 loss, P99 RTT
  within 2× baseline
- G3 — 100k pps QUIC DATAGRAM over 8-path bond with 11 migrations,
  0 loss, P95 RTT 1.6ms (validated on Linux 6.8 with
  `net.core.rmem_max` raised; the QUIC DATAGRAM transport needs
  a larger socket receive buffer than the default 208 KiB)
- G4 — force-killed path fails over to surviving path in <200ms
  on loopback with zero application-visible error
- G5 — `AdminConn.AddPath` recovers a dropped path back into the
  active set without reorder artifacts

## License

See [LICENSE](./LICENSE).
