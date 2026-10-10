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
carriers (one active carrier with failover and quality switching, all
carriers bonded for throughput, or every byte raced over every carrier).
Carriers are rendr-to-rendr connections that the embedder supplies as
`net.Conn` or `net.PacketConn` factories — typically L7 tunnels — or the
built-in plaintext TCP and UDP carriers, or the QUIC carriers of the nested
module `github.com/FrankoonG/rendr/v2/quic`.
Besides byte-stream sessions (`net.Conn`), rendr carries packet sessions
(`net.PacketConn`): datagrams delivered at most once, never retransmitted.

```
dialer (decides scheduling for both directions)          passive (follows)
app ── net.Conn ── session ══ carrier × N ══ session ── net.Conn ── app
                     (a carrier may cross the embedder's relays or proxies;
                      rendr treats them as opaque byte pipes)
```

## Status

**rendr 2.0 is a ground-up rewrite in progress** on the `v2` branch
(module `github.com/FrankoonG/rendr/v2`); it is not compatible with earlier
releases, their API or their wire format. The current checkpoint is M3:
the 2.0 core (stream sessions, selector and bond scheduling, the wire
format, admission), packet sessions, datagram carriers (the raw UDP
carrier `carrier/udp` and embedder `net.PacketConn` carriers), the QUIC
stream and datagram carriers of the nested `quic` module, race
scheduling, carrier properties (`Props`), shared carriers (rendr mux) on
stream and datagram carriers, and parked idle sessions. Milestone M4 (the
L4 TCP module `l4`, `examples/socks5` and early return with early data)
is in progress. The API may still change before v2.0.0.

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
- The built-in TCP and UDP carriers (`carrier/tcp`, `carrier/udp`) are
  plaintext. Their listeners and dialers accept only loopback addresses
  unless `Options.AllowNonLoopback` is set; enable that only on a trusted
  network or inside an authenticated encrypted channel. The UDP carrier's
  random flow ID keeps blind off-path injection out but is no
  authentication: anyone who sees the traffic can kill or retire a carrier.
- The QUIC carriers (module `github.com/FrankoonG/rendr/v2/quic`) always
  encrypt, but encryption is not authentication: they authenticate only
  what the embedder's `tls.Config` verifies.
- [`examples/mtls`](examples/mtls) shows mutually authenticated TLS carriers
  built with the standard library's `crypto/tls`: the passive side verifies
  the client certificate before a carrier ever reaches rendr.
- An `l4.Server` dials whatever target a dialer names, its own loopback and
  private networks included, unless its `Dial` hook refuses; anyone who can
  open a session to it can reach every address the passive host can (see
  [L4 TCP forwarding](#l4-tcp-forwarding-package-l4)).

Every frame on every carrier carries a frame sequence number and a CRC32C,
and every carrier is bound to one peer instance. A carrier that violates the
protocol is killed and its data is retransmitted on another carrier; the
session survives (on a shared carrier, every session on it migrates). These
checks catch accidents and misbehaving relays; they are not a security
mechanism. Two limits follow: a relay or peer that re-frames the traffic
and recomputes CRC and frame sequence numbers can inject plausible bytes
into any session on its carrier, and in race mode a copy that differs from
the first copy is detected only while the first copy is still buffered (a
copy of bytes the application already read is dropped uncompared).

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
5. **Fate groups.** Factories whose carriers share a first hop, a relay or a
   transport connection are declared by the embedder as one fate group
   (`Props.FateGroup`), so that bond and race keep at most one member of the
   group and selector failover tries another group first (see
   [Carrier properties](#carrier-properties)).
6. **Safety net, not a contract substitute.** The fseq, CRC32C and instance
   checks kill a carrier damaged by a misbehaving relay, but they do not
   replace items 1–5.

Capacity hints: probe carriers of a dialer are sessionless and count against
the passive's `Sessionless.PerInstance` limit (16 per dialer instance). A
dialer Runtime that opens many Peers to the same destination instance needs
a passive limit of at least Peers × carrier factories. A bond session dials
one member per factory, up to `MaxCarriersPerSession`: give a Peer used for
bond sessions no more factories than the passive's `MaxCarriersPerSession`,
or the passive refuses the surplus members and the dialer redials them
about every `RejoinBackoffMax` for the session's whole life. Better, leave
the passive one carrier more than a session holds (a bond: its factories;
a selector: 2). Otherwise, when the dialer loses a carrier that the passive
still holds, the replacement is refused until the passive's own liveness
check drops the old one, up to `PingIdle` + `DeadMax` (14 s) later, which
leaves little of the default 15 s `NoPathGrace`.

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
	if err != nil {
		continue // the dialer withdrew, AcceptTimeout answered, or the Listener closed
	}
	go serve(conn)                // *rendr.Conn is a net.Conn (plus CloseWrite, Done, Status)
}

// Dialer side: one Peer per destination instance, one factory per path.
cli, err := rendr.NewRuntime(rendr.Config{})
peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
	tcp.Carrier("direct", "tcp", "127.0.0.1:7000", tcp.Options{}),
	rendr.StreamCarrier{Name: "tunnel", Dial: dialMyTunnel}, // any func(ctx) (net.Conn, error)
}})
conn, err := peer.Dial(ctx, rendr.DialOptions{Mode: rendr.ModeSelector, Metadata: []byte("app-defined")})
```

Packet sessions use the same Runtime, Peer and Listener. A listening UDP
socket is a `rendr.FromPacketConn` source, and a datagram factory joins the
Peer's carriers:

```go
sock, err := udp.Listen("udp", addr, udp.Options{}) // package carrier/udp
ln, err := srv.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}})
pp, err := ln.AcceptPacket(ctx)  // Accept returns stream sessions only
pc, err := pp.Confirm()          // *rendr.PacketConn is a net.PacketConn

peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
	udp.Carrier("udp", "udp", addr, udp.Options{}),
}})
pc, err := peer.DialPacket(ctx, rendr.DialOptions{Mode: rendr.ModeSelector})
n, err := pc.WriteTo(datagram, nil) // one datagram of at most pc.MaxPayload() bytes
```

`WriteTo` never waits: each datagram is queued and sent at most once,
possibly reordered, and lost only in flight on a carrier that dies or when a
bounded queue drops it (counted in the session's packet counters).
`ReadFrom` returns one datagram per call and `io.EOF` only after the peer
closed its end and the datagrams already received were read. A larger
datagram fails with `ErrPacketTooLarge`. A carrier change is as invisible as
for a stream session. With `Config.IdleTimeout`, every successful `WriteTo`,
every received datagram and every datagram `ReadFrom` returns keeps a packet
session alive.

Semantics in brief:

- `Read` returns `io.EOF` only when the peer's FIN reached the contiguous
  delivery point. A carrier failure never surfaces as EOF or as an error.
- With no usable carrier for `NoPathGrace` (15 s by default, counted from the
  death of the last carrier) every call fails with `rendr.ErrNoPath`. Other
  typed errors: `ErrSessionLost` (the peer instance restarted or forgot the
  session), `*AbortError` (the session was reset; a reset that arrives once
  both FINs were delivered and this side has sent its final confirmation
  ends the session with `io.EOF` instead), `*RejectError`, `ErrCapacity`,
  `ErrVersion`, `ErrProtocol`, `ErrMetadataTooLarge`, `ErrIdleTimeout`.
  Deadlines behave as for any `net.Conn`.
- `Close` returns at once; written data is still delivered in the background
  within `Linger`. `CloseWrite` sends a FIN and keeps reading. `Done` returns
  a channel that is closed once the session has ended: `Status().State` is
  then `StateEnded` and `Status().Err` final (`io.EOF` after a clean
  finish).
- `Runtime.Close` resets every session that has not ended, including closed
  ones still finishing in the background (they end with `net.ErrClosed`;
  their peers end with `*AbortError`, or with `io.EOF` if both FINs had
  already been delivered and only the final confirmation was outstanding).
  For a clean end on both sides, read until `io.EOF`, `Close`, wait for
  `Done` (bounded by your own context), and only then call `Runtime.Close`,
  as [`examples/mtls`](examples/mtls) does:

  ```go
  _, err = io.Copy(dst, conn) // until the peer's FIN (Read returned io.EOF)
  conn.Close()                // this side's FIN, unless CloseWrite sent it
  select {
  case <-conn.Done(): // ended; conn.Status().Err is io.EOF after a clean finish
  case <-ctx.Done():
  }
  cli.Close() // the Runtime: resets every session that has not ended
  ```
- Selector mode keeps one active carrier, fails over on carrier death and
  switches for quality only on probe evidence, with hysteresis (band, dwell,
  cooldown). Bond mode sends on all carriers in proportion to their measured
  drain rate. Race mode sends every byte or datagram on every member carrier
  and the receiver keeps the first copy: each byte arrives over whichever
  member delivers it first, but throughput is the fastest member's (never
  the sum), and the wire bytes and the sender's CPU grow with the member
  count. A passive without race (a 2.0 build before M3) refuses it with
  `ErrProtocol`. No migration is ever triggered by the application's own
  traffic pattern.
- `Runtime.Status`, `Conn.Status` and `Peer.Status` report sessions,
  carriers, death causes, migrations and buffer use; `Config.OnEvent`
  delivers carrier, migration and session events. A session's byte and
  datagram counters count each unit once; in race mode
  `SessionStatus.Race` (sender) and `DupBytes` (receiver) count the copies,
  and each `CarrierStatus` counts what its carrier moved, copies included.

### Early return

`DialOptions{EarlyReturn: true}` gives `Peer.Dial` the semantics of TCP Fast
Open, for protocols whose client speaks first (a TLS ClientHello, an HTTP
request):

```go
conn, err := peer.Dial(ctx, rendr.DialOptions{EarlyReturn: true}) // no network I/O yet
_, err = conn.Write(clientHello) // opens the session; up to 64 KiB travel with the OPEN
_, err = conn.Read(buf)          // a refusal or ErrNoPath arrives here instead of from Dial
```

- `Dial` returns after its local checks, before any network I/O and
  without the cold-start wait for probe samples. The session opens with
  its first `Write`, `Read` or `CloseWrite`; a `Close` before any of them
  sends nothing.
- The first bytes written, up to `Handshake.EarlyDataMax` (64 KiB; 0–64 KiB),
  leave in the same carrier write as the OPEN when the session dials a
  carrier of its own, so the first answer arrives about one round trip
  sooner. Until the peer answers, `Write` accepts at most `EarlyDataMax`
  bytes in all and then waits (deadlines apply).
- Every outcome `Dial` would have returned (`*RejectError`, `ErrCapacity`,
  `ErrNoPath`, ...) becomes the error of the next `Read` and `Write`, ends
  the session (`Done` closes) and is reported in `EventSessionEnd`; the early
  bytes are then discarded on both sides. The passive application reads
  them only after it confirmed the session; the passive holds at most
  64 KiB of them per pending session.
- Write before you read: a `Read` that comes first opens the session
  without early bytes. Do not use it when the peer must answer before your
  first byte (a SOCKS5 reply, for example).
- Until the peer answers, `Status().State` is `StatePending` and
  `PeerInstance` and `RemoteAddr` report the zero `InstanceID`; the bound
  instance never changes afterwards. `Status().EarlyBytes` shows how many
  bytes travelled early on both ends.
- A session that opens on a carrier shared with other sessions of the Peer
  (rendr mux) sends no early data: its bytes follow the answer, which costs
  the same round trip as early data on a fresh carrier. `DialPacket`
  refuses `EarlyReturn` with `ErrProtocol`.

### L4 TCP forwarding (package l4)

Package [`l4`](l4) carries TCP connections over stream sessions. The
dialer names the target in the OPEN's metadata; the passive dials it while
the session is still pending, confirms only once the target connected and
rejects with a typed code otherwise (refused, unreachable, timeout, name
not found, ...); then both ends forward:

```go
// Passive side: serve the L4 sessions of a Listener.
go l4.Serve(ctx, ln) // or (&l4.Server{Dial: policyDial, MaxConns: 1000}).Serve(ctx, ln)

// Dialer side: one session per accepted TCP connection.
local, err := tcpListener.Accept()
conn, err := l4.Dial(ctx, peer, "example.com:443", rendr.DialOptions{EarlyReturn: true})
if err != nil { // with EarlyReturn: a local error only; l4.CodeOf tells the refusals
	local.Close()
	return
}
res := l4.Forward(ctx, conn, local) // both directions, then closes both; res tells how it ended
```

- Half-closes cross in both directions; a reset or failure on either side
  becomes a reset on the other, never a clean end of stream; a carrier
  change is invisible to both sockets. When a session ends, its socket is
  released at once, also when the socket's peer ignores FIN or never reads.
- Sessions made by `l4.Dial` and served by `l4.Server` are idle-limited to
  `l4.DefaultIdleTimeout` (10 minutes) unless changed (`Conn.SetIdleTimeout`,
  `Server.IdleTimeout`).
- A domain is resolved by the passive. The destination travels only in the
  OPEN; the whole metadata stays within `Handshake.MaxMetadata`.
- The Server has no authentication and no address policy of its own: give
  it a `Dial` hook that refuses what must not be reached (`l4.ErrDenied`)
  and checks the resolved address (`net.Dialer.Control`). Its `MaxConns`
  (10,000 by default) bounds the forwarded connections; each costs three
  goroutines and 64 KiB of buffers on top of its session's windows.
- [`examples/socks5`](examples/socks5) is a loopback-only, no-auth SOCKS5
  CONNECT front end; it dials without `EarlyReturn`, because the SOCKS
  reply must wait for the passive's answer.

### Carrier properties

Each factory (`StreamCarrier`, `DatagramCarrier`) carries `Props`:

- `FateGroup` names factories whose carriers fail together (a shared first
  hop, relay or transport connection). Bond and race keep at most one member
  per group, the best-ranked factory of it; selector failover tries
  candidates outside the dead carrier's group first. `""` puts a factory in
  a group of its own. At most 64 bytes; compared within one Peer.
- `HoLCoupled` marks a group whose carriers share one in-order pipe (streams
  of one TCP or TLS connection): rendr never moves a write-blocked carrier's
  acknowledgement or scheduling duty onto a coupled sibling while another
  carrier exists. It requires a `FateGroup`, and the factories of one group
  must agree on it.
- `CheapSubflow` says that opening a carrier is cheap (a native subflow), so
  every session dials its own carriers of that factory. Without it (the
  default) the sessions of one Peer share the factory's live carriers (rendr
  mux): a new session or a failover uses a live carrier instead of dialling,
  and a carrier closes when its last session ends (no idle retention, no
  warm standby). Sessions on one carrier share its head-of-line blocking and
  its fate: its death migrates every one of them. On a carrier that was
  already live, the passive's first bytes for a new session leave about one
  round trip later than on a fresh carrier, because the passive waits for
  the dialer's first frame for that session. Carriers are never shared
  between Peers.

`NewPeer` rejects invalid `Props` with an error naming the factory.

### Memory

`Config.MaxBufferedBytes` (1 GiB by default) is the budget for session data
buffers. Send buffers stay within it: `Write` waits while it is used up.
Receive buffers are bounded by the advertised windows instead: once the
budget is more than 75 % used, newly advertised windows shrink (to 0 when
it is full), but a window once advertised is never taken back. Receive
memory is therefore bounded by about `MaxSessions × 2 × Window` (10,000 ×
2 × 8 MiB ≈ 156 GiB with the defaults), not by the budget: size
`MaxSessions` and `Window` to the memory you have. Every carrier other
than a bare `carrier/tcp` connection (TLS or a tunnel, for example) also
copies each batch it writes into a buffer of up to 512 KiB, held while the
conn's `Write` runs. That buffer is charged to the budget unconditionally:
it counts toward the 75 % threshold and can take the budget past its
limit. Carrier reader stages add about 16 KiB per live carrier outside the
budget; `Status.BufferedBytes` reports both.

An idle session costs about 70 KiB per side with one carrier of its own
(selector) and about 170–190 KiB per side as a three-member bond, mostly
the carriers' reader stages, write batches and goroutine stacks. A session
that shares a live carrier (rendr mux) adds about 7 KiB per side and no
goroutine: the carrier's cost is paid once, by all of its sessions. Each
side runs two goroutines per carrier and one per busy session: a session's
scheduler parks after about a second without work and holds no goroutine
until its next event or deadline (`Status.Actors` counts the running
ones). While idle, a session's carriers wake about every `PingIdle` to
send and answer liveness PINGs, and every dialer session of a Peer with two
or more factories is woken once per probe sample of the Peer (90 times a
minute with three factories at the default 2 s `Probe.Interval`); a wakeup
that changes nothing parks again at once.

### Selector self-load guard: limitation

Probe samples that this Peer's own traffic loads are excluded from quality
comparison, so a bulk transfer does not make the selector flee from the
queueing it causes itself. A sample is loaded when the Peer's session
carriers on that path are backlogged (data queued for writing at either
end) with 64 KiB or more in flight while the probe is out, or when they
move 64 KiB or more during the probe's round trip without that traffic
already flowing before it (less than 64 KiB moved since the previous probe
or since the last backlog ended).

The price: a path that degrades while this Peer's own traffic saturates it,
in either direction, cannot be told apart from self-induced queueing. The
selector then keeps the last unloaded measurement and leaves the path only
through death detection (PING timeout within `DeadMax`, or a write stall),
or after the traffic becomes application-limited again. A candidate path
saturated by another session of the same Peer cannot become a quality
target. Traffic of other Peers on a shared bottleneck is genuine congestion
from this Peer's point of view.

Two gaps remain. Other traffic of this Peer on the path at about 32 KiB/s or
more (with the default 2 s `Probe.Interval`) counts as already flowing, so
the first sample of a transfer that starts at a probe can be taken as
unloaded. And after an RTT rise, an application-limited flow can switch a
probe interval or two later.

Packet sessions have no self-load gauge on datagram carriers: those
carriers keep no bytes in flight, so the guard sees only a packet session's
traffic on stream carriers. A packet session that saturates its own
datagram path loads that path's probe samples unnoticed; the selector may
then leave the path on a quality switch and return to it after `Cooldown`,
once the samples recover.

## Testing

Package [`rendrtest`](rendrtest) provides in-memory carriers with fault
injection (delay and jitter, rate limits with a shared bottleneck, blackhole,
stall, kill with buffer loss, frame-aware corruption, drops and injection,
misbehaving factories and connections), far-end behaviours, a strict stream
verifier and goroutine-leak assertions. It works inside `testing/synctest`
bubbles and is used by rendr's own tests.

## Not in 2.0.0

- Warm standby carriers, idle carrier retention, carrier priorities and
  changing a running session's carrier set. Every session snapshots its
  Peer's factories at `Dial` and only redials those; replacing a factory
  affects new sessions only. Selector failover dials a new carrier unless
  the Peer has a live shared carrier of the failover factory, probe
  carriers are never adopted by sessions, and the failover time an
  expensive (L7) carrier dial adds is quantified only before the 2.0.0
  release.
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
