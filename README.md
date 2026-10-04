# rendr

rendr is a Go library that keeps one application connection alive across
many underlying connections ("carriers") between two rendr instances. The
application on each side holds an ordinary `net.Conn`; rendr carries its
bytes over any number of carriers and moves them when a carrier dies,
degrades or is replaced. The application never sees a reset, an error or a
lost byte because a carrier changed, and it never has to reconnect.

rendr is a userspace session layer: session identity, byte offsets,
acknowledgement = delivered to the receiving application, bounded
retransmission and reordering, and the scheduling of a session over its
carriers (one active carrier with failover and quality switching, or all
carriers bonded for throughput). Carriers are rendr-to-rendr connections
that the embedder supplies as `net.Conn` factories — typically L7 tunnels —
or the built-in plaintext TCP carrier.

```
dialer (decides scheduling for both directions)          passive (follows)
app ── net.Conn ── session ══ carrier × N ══ session ── net.Conn ── app
                     (a carrier may cross the embedder's relays or proxies;
                      rendr treats them as opaque byte pipes)
```

## Status

**rendr 2.0 is a ground-up rewrite in progress** on the `v2` branch
(module `github.com/FrankoonG/rendr/v2`); it is not compatible with earlier
releases, their API or their wire format. The current checkpoint is M1b,
the 2.0 core: stream sessions, selector and bond scheduling, the wire
format, admission and the API below. The API is meant to be frozen at the
end of M1b but may still change before v2.0.0. Packet sessions, datagram
and QUIC carriers (M2), race scheduling and carrier multiplexing (M3), and an
L4 TCP module (M4) follow.

Supported platforms are Linux and Windows; Windows has no real-network
regression in 2.0.0 (see [Not in 2.0.0](#not-in-200)). macOS and arm64 are
compiled but not tested at run time. The root module depends only on the
standard library (and `golang.org/x/sys` where needed).

## Security model

rendr provides **no confidentiality and no authentication**. It is a
transport layer meant to run inside the embedder's own protocol:

- A rendr listener must only be reachable through an authenticated,
  encrypted channel that the embedder controls (mutual TLS, an SSH tunnel,
  an authenticated L7 tunnel, ...).
- A rendr `InstanceID` identifies a running instance for routing only. It is
  random but travels in clear on the wire: it is not a secret, **not an
  identity**, and proves nothing.
- The built-in TCP carrier (`carrier/tcp`) is plaintext. Its listener and
  dialer accept only loopback addresses unless `Options.AllowNonLoopback` is
  set; enable that only on a trusted network or inside an authenticated
  encrypted channel.
- [`examples/mtls`](examples/mtls) shows mutually authenticated TLS carriers
  built with the standard library's `crypto/tls`: the passive side verifies
  the client certificate before a carrier ever reaches rendr.

Every frame on every carrier carries a frame sequence number and a CRC32C,
and every carrier is bound to one peer instance. A carrier that violates the
protocol is killed and its data is retransmitted on another carrier; the
session survives. These checks catch accidents and misbehaving relays; they
are not a security mechanism.

## Embedding contract

1. **Security.** See above: rendr does not encrypt or authenticate, the
   `InstanceID` is not an identity, listeners are reachable only through the
   embedder's authenticated encrypted channel, and the built-in raw
   listeners accept only loopback addresses unless `AllowNonLoopback` is set.
2. **Relays.** A relay on a carrier's path may only forward rendr bytes
   opaquely or fail explicitly by closing the connection. It must not
   terminate the session, buffer and replay bytes, or splice a connection
   onto another upstream midway. (Datagram relays, from M2, forward one
   datagram per datagram: no coalescing, no fragmentation, within the MTU.)
3. **Same instance.** All carriers of one `Peer` must reach the same rendr
   instance. Load-balancing carriers of one Peer across instances violates
   the contract; such carriers are refused (`instance_mismatch`).
4. **Liveness timers.** rendr's own PING is the only liveness authority. The
   keepalive and idle timeouts of the embedder's carriers must be longer
   than the passive side's retention, `PassiveRetain = NoPathGrace +
   PingIdle + DeadMax + 5 s` (34 s with the defaults), and therefore longer
   than `NoPathGrace`. The built-in TCP carrier disables TCP keepalive on
   both ends for this reason.
5. **Fate groups** (from M3). Carriers that share a first hop or a relay are
   declared by the embedder as one fate group, so that bonding does not count
   them as independent capacity and failover prefers another group.
6. **Safety net, not a contract substitute.** The fseq, CRC32C and instance
   checks kill a carrier damaged by a misbehaving relay, but they do not
   replace items 1–5.

Capacity hint: probe carriers of a dialer are sessionless and count against
the passive's `Sessionless.PerInstance` limit (16 per dialer instance). A
dialer Runtime that opens many Peers to the same destination instance needs
a passive limit of at least Peers × carrier factories.

## Deployment patterns

- **End-to-end sessions (recommended).** The local rendr instance opens a
  session directly to the destination rendr instance; relays and proxies are
  just segments of individual carriers. A relay failure is a carrier failure,
  and rendr's lossless guarantee covers the whole path.
- **Chained sessions.** One session per hop, spliced together at
  intermediate nodes. Each hop's guarantee is independent: if an
  intermediate node crashes, the bytes it held are lost. Do not use chaining
  where end-to-end losslessness matters. This is a deployment pattern, not a
  rendr option.

## Usage

```go
import (
	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
)

// Passive side (destination): admit sessions and serve them.
srv, err := rendr.NewRuntime(rendr.Config{})
raw, err := tcp.Listen("tcp", "127.0.0.1:7000", tcp.Options{})
ln, err := srv.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(raw)}})
for {
	pc, err := ln.Accept(ctx)     // a pending session: ID, Mode, Metadata, PeerInstance
	if err != nil {
		break
	}
	conn, err := pc.Confirm()     // or pc.Reject(code, msg)
	go serve(conn)                // *rendr.Conn is a net.Conn (plus CloseWrite, Status)
}

// Dialer side: one Peer per destination instance, one factory per path.
cli, err := rendr.NewRuntime(rendr.Config{})
peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
	tcp.Carrier("direct", "tcp", "127.0.0.1:7000", tcp.Options{}),
	rendr.StreamCarrier{Name: "tunnel", Dial: dialMyTunnel}, // any func(ctx) (net.Conn, error)
}})
conn, err := peer.Dial(ctx, rendr.DialOptions{Mode: rendr.ModeSelector, Metadata: []byte("app-defined")})
```

Semantics in brief:

- `Read` returns `io.EOF` only when the peer's FIN reached the contiguous
  delivery point. A carrier failure never surfaces as EOF or as an error.
- With no usable carrier for `NoPathGrace` (15 s by default, counted from the
  death of the last carrier) every call fails with `rendr.ErrNoPath`. Other
  typed errors: `ErrSessionLost` (the peer instance restarted or forgot the
  session), `*AbortError` (the peer reset the session), `*RejectError`,
  `ErrCapacity`, `ErrVersion`, `ErrProtocol`, `ErrMetadataTooLarge`,
  `ErrIdleTimeout`. Deadlines behave as for any `net.Conn`.
- `Close` returns at once; written data is still delivered in the background
  within `Linger`. `CloseWrite` sends a FIN and keeps reading.
- Selector mode keeps one active carrier, fails over on carrier death and
  switches for quality only on probe evidence, with hysteresis (band, dwell,
  cooldown). Bond mode sends on all carriers in proportion to their measured
  drain rate. No migration is ever triggered by the application's own traffic
  pattern.
- `Runtime.Status`, `Conn.Status` and `Peer.Status` report sessions,
  carriers, death causes, migrations and buffer use; `Config.OnEvent`
  delivers carrier, migration and session events.

### Selector self-load guard: limitation

Probe samples taken while the Peer's own traffic saturates a path are
excluded from quality comparison, so a bulk transfer does not make the
selector flee from the queueing it causes itself. The price: a path that
degrades while this Peer's own traffic saturates it, in either direction,
cannot be told apart from self-induced queueing. The selector then keeps the
last unloaded measurement and leaves the path only through death detection
(PING timeout within `DeadMax`, or a write stall), or after the traffic
becomes application-limited again. A candidate path saturated by another
session of the same Peer cannot become a quality target. Traffic of other
Peers on a shared bottleneck is genuine congestion from this Peer's point of
view.

## Testing

Package [`rendrtest`](rendrtest) provides in-memory carriers with fault
injection (delay and jitter, rate limits with a shared bottleneck, blackhole,
stall, kill with buffer loss, frame-aware corruption, drops and injection,
misbehaving factories and connections), far-end behaviours, a strict stream
verifier and goroutine-leak assertions. It works inside `testing/synctest`
bubbles and is used by rendr's own tests.

## Not in 2.0.0

- Carrier pools, warm standby carriers, carrier priorities and changing a
  running session's carrier set. Every session snapshots its Peer's factories
  at `Dial` and only redials those; replacing a factory affects new sessions
  only. Selector failover therefore dials a new carrier, probe carriers are
  never adopted by sessions, and the failover time an expensive (L7)
  carrier dial adds is quantified only before the 2.0.0 release.
- Nested scheduling groups and peak-transfer modes.
- L4 UDP, L3 and L2 payload modules (the L4 module of M4 is TCP only).
- Stream sessions over raw datagram carriers (use QUIC streams or a reliable
  embedder connection instead).
- Retransmission of packet-session datagrams (packet sessions never
  retransmit).
- Optional quality triggers, re-probe hooks and embedder quality callbacks.
- A graceful `Runtime.Shutdown(ctx)`: only `Close` (GOAWAY and reset).
- A real-network regression on Windows: Windows is covered by unit tests,
  in-process scenario tests and cross-compilation only.
- Run-time testing on macOS and arm64 (compile-only).

## License

GNU General Public License v3.0; see [LICENSE](LICENSE).
