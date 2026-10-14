# rendr

rendr is a Go library that keeps one application connection alive across
many underlying connections ("carriers") between two rendr instances. The
application on each side holds an ordinary `net.Conn` (or a
`net.PacketConn`); rendr carries its bytes over any number of carriers and
moves them when a carrier dies, degrades or is replaced. The application
never sees a reset, an error or a lost byte because a carrier changed, and
it never has to reconnect.

```
dialer (dials carriers, decides scheduling for both directions)      passive (follows)
app ── net.Conn ── session ══ carrier × N ══ session ── net.Conn ── app / real target
                     (a carrier may cross the embedder's relays or proxies;
                      rendr treats them as opaque byte pipes)
```

Contents: [What rendr is](#what-rendr-is) ·
[Install](#install-modules-and-platforms) · [Quick start](#quick-start) ·
[Carriers and scheduling](#carriers-modes-and-failover) ·
[Embedding](#embedding-contract-and-security-model) ·
[Configuration](#configuration-errors-status-and-memory) ·
[Datagram I/O](#datagram-io-and-batching) · [Performance](#performance) ·
[Testing](#testing) · [Limitations](#known-limitations-and-what-is-not-in-200) ·
[Compatibility](#compatibility-and-licence)

## What rendr is

rendr 2.0 is a userspace session layer between a local rendr instance (the
dialer) and a destination rendr instance (the passive side). Its core does
five things: session identity, byte offsets, acknowledgement = delivered to
the receiving application, bounded retransmission and reordering, and the
scheduling of a session over its carriers — one active carrier with
failover and quality switching (selector), every carrier carrying data for
throughput (bond), or every byte raced over every carrier (race).

| Layer | Job | Provided by |
|---|---|---|
| ingress / egress | accepts the user's traffic; reaches the real target | the embedder, or a payload module |
| payload module | maps one kind of traffic onto sessions: L4 TCP (`l4`) | an optional rendr package |
| core session | stream and packet sessions; selector, bond, race; rendr mux; health probing; no-path grace | rendr |
| carrier | one rendr-to-rendr connection handed to the core as a `net.Conn` (stream) or `net.PacketConn` (datagram) | mostly the embedder (L7 tunnels); also the built-in plaintext TCP and UDP carriers and the QUIC module |

Besides byte-stream sessions (`*rendr.Conn`, a `net.Conn`), rendr carries
packet sessions (`*rendr.PacketConn`, a `net.PacketConn`): datagrams
delivered at most once, never retransmitted.

**What rendr is not.** It does not use VPNs or L3 tunnels as carriers; it
does not encrypt or authenticate (that is the embedder's job, see the
[security model](#security-model)); it implements no proxy protocol and no
relay (relays are downstream projects; `examples/socks5` is an example, not
a product); it has no mesh or node discovery, no kernel data plane, no
TCP_REPAIR, gVisor or socket migration, and no configuration UI. It does not
convert a stream contract into a packet contract or back. It does not load
balance one Peer across several instances: every carrier of a Peer must
reach the same rendr instance.

**Deployment patterns.**

- **End-to-end sessions (recommended).** The local rendr instance opens a
  session directly to the destination rendr instance; relays and proxies
  are just segments of individual carriers. A relay failure is a carrier
  failure, and rendr's lossless guarantee covers the whole path.
- **Chained sessions.** One session per hop, spliced together at
  intermediate nodes. Each hop's guarantee is independent: if an
  intermediate node crashes, the bytes it held are lost. Do not chain where
  end-to-end losslessness matters. This is a deployment pattern, not a
  rendr option.

## Install, modules and platforms

```
go get github.com/FrankoonG/rendr/v2
go get github.com/FrankoonG/rendr/quic/v2   # only for the QUIC carriers
```

| Module | Packages | Dependencies |
|---|---|---|
| `github.com/FrankoonG/rendr/v2` | `rendr` (the core), `carrier/tcp`, `carrier/udp`, `l4`, `rendrtest` | the standard library and `golang.org/x/sys` |
| `github.com/FrankoonG/rendr/quic/v2` | `quic` (QUIC stream and datagram carriers) | rendr, `github.com/quic-go/quic-go` |

Both modules declare `go 1.26.3`, the minimum Go version.

Platforms: **Linux and Windows** are supported. On Linux every test layer
runs (unit, in-process scenarios, real-network scenarios, long runs and
performance); on Windows the unit tests and the in-process scenario tests
run and the code is cross-compiled, but there is no real-network
regression. Linux, Windows and macOS on amd64 and arm64 are
cross-compiled; macOS and the arm64 architecture are not tested at run
time. Batched datagram I/O is used on Linux amd64 and arm64
only (see [Datagram I/O](#datagram-io-and-batching)).

## Quick start

These are the package's runnable examples (`go test -run Example`), on the
loopback address. Errors are fatal here for brevity.

**A stream session over `carrier/tcp`** (`ExamplePeer_Dial`):

```go
// Passive side: a Runtime, a carrier listener and a rendr Listener.
srv, err := rendr.NewRuntime(rendr.Config{})
defer srv.Close()
raw, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
ln, err := srv.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(raw)}})
go func() {
	pc, err := ln.Accept(ctx) // a pending session: ID, Mode, Metadata, PeerInstance
	if err != nil {
		return
	}
	conn, err := pc.Confirm() // or pc.Reject(code, msg)
	if err != nil {
		return
	}
	io.Copy(conn, conn) // echo until the dialer's FIN
	conn.Close()        // this side's FIN
	<-conn.Done()
}()

// Dialer side: one Peer per destination instance, one factory per path.
cli, err := rendr.NewRuntime(rendr.Config{})
defer cli.Close()
peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
	tcp.Carrier("direct", "tcp", raw.Addr().String(), tcp.Options{}),
	// more paths: rendr.StreamCarrier{Name: "tunnel", Dial: dialMyTunnel}, ...
}})
conn, err := peer.Dial(ctx, rendr.DialOptions{Mode: rendr.ModeSelector})
conn.Write([]byte("hello, rendr"))
conn.CloseWrite()              // FIN after the bytes written
reply, err := io.ReadAll(conn) // until the passive's FIN
conn.Close()
<-conn.Done() // ended; conn.Status().Err is io.EOF after a clean finish
```

**A packet session over `carrier/udp`** (`ExamplePeer_DialPacket`): a
listening socket from `carrier/udp` is a `FromPacketConn` source, and a
`carrier/udp` factory joins the Peer.

```go
sock, err := udp.Listen("udp", "127.0.0.1:0", udp.Options{})
ln, err := srv.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}})
pp, err := ln.AcceptPacket(ctx) // Accept returns stream sessions only
pc, err := pp.Confirm()         // *rendr.PacketConn is a net.PacketConn

peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
	udp.Carrier("udp", "udp", sock.LocalAddr().String(), udp.Options{}),
}})
pc, err := peer.DialPacket(ctx, rendr.DialOptions{Mode: rendr.ModeSelector})
n, err := pc.WriteTo([]byte("ping"), nil) // one datagram of at most pc.MaxPayload() bytes
n, _, err = pc.ReadFrom(buf)              // one datagram; send again if none arrives in time
```

**Confirm and Reject** (`ExampleListener_Accept`): the passive application
decides every session from its OPEN metadata; a rejected `Dial` returns a
`*rendr.RejectError` with the code and message passed to `Reject`
(application codes are at least 256).

**TCP forwarding with `l4`** (`l4.ExampleDial`): the passive runs an
`l4.Server`, which dials the target named by the dialer and confirms once it
connected; the dialer gets a `*rendr.Conn` that is its connection to the
target.

```go
go (&l4.Server{Dial: policyDial}).Serve(ctx, ln) // passive
conn, err := l4.Dial(ctx, peer, "example.com:443", rendr.DialOptions{}) // dialer
res := l4.Forward(ctx, conn, local) // or forward an accepted local TCP conn both ways
```

`quic.Example` shows the QUIC carriers (it needs TLS material, so it is
compiled, not run).

## Carriers, modes and failover

A carrier is one rendr-to-rendr connection. The dialer dials every carrier;
the passive never dials. A carrier is immutable from attach to death: rendr
never swaps the socket under it.

| Carrier | Package | Kind | Notes |
|---|---|---|---|
| plaintext TCP | `carrier/tcp` | stream | keepalive off, `TCP_NODELAY`; loopback only unless `Options.AllowNonLoopback`; vectored writes |
| plaintext raw UDP | `carrier/udp` | datagram | a 9-byte flow header per datagram; one listening socket serves many carriers; don't-fragment; batched I/O on Linux amd64/arm64; loopback only unless `AllowNonLoopback` |
| QUIC stream, QUIC DATAGRAM | `quic` (nested module) | stream, datagram | one QUIC connection per carrier; TLS required; ALPN `rendr/2-q1` |
| the embedder's own | `rendr.StreamCarrier`, `rendr.DatagramCarrier`; passive `Listener.Handle`, `Listener.HandlePacket` | stream, datagram | any `net.Conn` or `net.PacketConn`, typically an L7 tunnel; `StreamCarrier.DialEarly` puts rendr's first bytes into the embedder's own open request |

Stream sessions run on stream carriers only. Packet sessions prefer
datagram carriers and fall back to stream carriers. rendr treats every
embedder conn as untrusted: factory calls are bounded by `DialTimeout`,
panics are contained, byte counts are validated, a late conn is closed
exactly once.

**Carrier properties.** Each factory carries `Props`; each live carrier
reports its kind and, for datagram carriers, its MTU (`CarrierStatus.Kind`,
`CarrierStatus.MTU`; `DatagramCarrier.MTU` is the factory's offer):

- `FateGroup` names factories whose carriers fail together (a shared first
  hop, relay or transport connection). Bond and race keep at most one
  member per group, the best-ranked factory of it; selector failover tries
  candidates outside the dead carrier's group first. `""` puts a factory in
  a group of its own. At most 64 bytes; compared within one Peer.
- `HoLCoupled` marks a group whose carriers share one in-order pipe
  (streams of one TCP or TLS connection): rendr never moves a write-blocked
  carrier's acknowledgement or scheduling duty onto a coupled sibling while
  another carrier exists. It requires a `FateGroup`, and the factories of
  one group must agree on it.
- `CheapSubflow` says that opening a carrier is cheap (a native subflow),
  so every session dials its own carriers of that factory. Without it (the
  default) the sessions of one Peer share the factory's live carriers —
  **rendr mux** — each carrier carrying sessions of one kind: a new session
  or a failover uses a live carrier instead of dialling, and a carrier
  closes when its last session ends (no idle retention, no warm standby).
  Sessions on one carrier share its head-of-line blocking and its fate: its
  death migrates every one of them. On a carrier that was already live, the
  passive's first bytes for a new session leave about one round trip later
  than on a fresh carrier, because the passive waits for the dialer's first
  frame for that session. Carriers are never shared between Peers.

`NewPeer` rejects invalid `Props` with an error naming the factory.

**Modes** (`DialOptions.Mode`, fixed at OPEN):

- **Selector** (`ModeSelector`, the default) keeps one active carrier,
  fails over on carrier death and switches for quality only on probe
  evidence, with hysteresis (`Selector.Band`, `Floor`, `Dwell`,
  `Cooldown`). A Peer with two or more factories keeps one sessionless
  probe carrier per factory while in use and pings on each every
  `Probe.Interval`. Probe samples that this Peer's own traffic loads are
  never compared (the self-load guard; see the `SelectorPolicy`
  documentation for its rules and gaps).
- **Bond** (`ModeBond`) sends on every member carrier in proportion to its
  measured drain rate, one member per factory up to
  `MaxCarriersPerSession`.
- **Race** (`ModeRace`) sends every byte or datagram on every member
  carrier and the receiver keeps the first copy: each byte arrives over
  whichever member delivers it first, but throughput is the fastest
  member's (never the sum), and the wire bytes and the sender's CPU grow
  with the member count. Members are chosen as for bond.

No migration is ever triggered by the application's own traffic pattern.

**Failover model.**

- *Bond and race:* the other members are alive. The dead member's
  unacknowledged ranges are requeued on the survivors at once; the passive
  switches to a surviving member locally, without waiting for a control
  round trip; the dialer redials the dead member's factory at once (no
  backoff), and the new carrier rejoins.
- *Selector:* the session has one active carrier. On its death the dialer
  at once starts candidates concurrently, staggered by `JoinStagger`; the
  first to complete its JOIN wins and the others retire without penalty.
  If the Peer has a live shared carrier of a candidate factory (rendr mux),
  the JOIN uses it and no dial is needed. Until a carrier arrives the
  passive has none and waits.
- *Detection:* a carrier is declared dead by a transport error, a PING
  unanswered beyond the death deadline (`DeadMin`–`DeadMax`), a write stall
  (`WriteStall`), a protocol violation or an instance mismatch. With no
  usable carrier for `NoPathGrace` (15 s by default, counted from the death
  of the last carrier) the session fails with `ErrNoPath`.

## Embedding contract and security model

### Security model

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
  random 64-bit flow ID keeps blind off-path injection out but is no
  authentication: anyone who sees the traffic can kill or retire a carrier
  (the `carrier/udp` package documentation has the threat model).
- The QUIC carriers always encrypt, but **encryption is not
  authentication**: they authenticate only what the embedder's
  `tls.Config` verifies.
- [`examples/mtls`](examples/mtls) shows mutually authenticated TLS carriers
  built with the standard library's `crypto/tls` over `carrier/tcp`: the
  passive side verifies the client certificate before a carrier ever
  reaches rendr.
- An `l4.Server` dials whatever target a dialer names, its own loopback and
  private networks included, unless its `Dial` hook refuses; anyone who can
  open a session to it can reach every address the passive host can.

Every frame on every carrier carries a frame sequence number and a CRC32C,
and every carrier is bound to one peer instance. A carrier that violates the
protocol is killed and its data is retransmitted on another carrier; the
session survives (on a shared carrier, every session on it migrates). These
checks catch accidents and misbehaving relays; they are not a security
mechanism. A relay or peer that re-frames the traffic and recomputes CRC and
frame sequence numbers can inject plausible bytes into any session on its
carrier, and in race mode a copy that differs from the first copy is
detected only while the first copy is still buffered (a copy of bytes the
application already read is dropped uncompared).

Admission is bounded before anything is trusted: handshake slots
(`Handshake.MaxConcurrent`, `Handshake.Timeout`), the accept backlog per
session kind, `MaxSessions`, the sessionless probe carriers per dialer
instance, and, on a raw-UDP listening socket, per-address quotas for flows
that have not yet proven they receive the passive's datagrams. A source
that does prove it is bounded like a stream client and can fill the packet
`AcceptBacklog`; the embedder's authentication and Accept policy are the
defence.

### Embedding contract

1. **Security.** As above: rendr does not encrypt or authenticate, the
   `InstanceID` is not an identity, listeners are reachable only through
   the embedder's authenticated encrypted channel, and the built-in raw
   listeners accept only loopback addresses unless `AllowNonLoopback` is
   set.
2. **Relays.** A relay on a carrier's path may only forward rendr bytes
   opaquely or fail explicitly by closing the connection. It must not
   terminate the session, buffer and replay bytes, or splice a connection
   onto another upstream midway. Datagram relays forward one datagram per
   datagram: no coalescing, no fragmentation, within the MTU.
3. **Same instance.** All carriers of one `Peer` must reach the same rendr
   instance. Carriers that reach another instance are refused
   (`instance_mismatch`).
4. **Liveness timers.** rendr's own PING is the only liveness authority.
   The keepalive and idle timeouts of the embedder's carriers must be
   longer than the passive side's retention, `PassiveRetain = NoPathGrace +
   PingIdle + DeadMax + 5 s` (34 s with the defaults), and therefore longer
   than `NoPathGrace`. The built-in TCP carrier disables TCP keepalive on
   both ends, and the QUIC carriers turn QUIC keepalives off and keep QUIC's
   idle timeout above every possible `PassiveRetain`.
5. **Fate groups.** Factories whose carriers share a first hop, a relay or a
   transport connection are declared by the embedder as one fate group
   (`Props.FateGroup`).
6. **Safety net, not a substitute.** The frame sequence, CRC32C and instance
   checks kill a carrier damaged by a misbehaving relay, but they do not
   replace items 1–5.

Capacity hints: probe carriers of a dialer are sessionless and count
against the passive's `Sessionless.PerInstance` limit (16 per dialer
instance), so a dialer Runtime that opens many Peers to the same
destination instance needs a passive limit of at least Peers × carrier
factories. A bond session dials one member per factory, up to
`MaxCarriersPerSession`: give a Peer used for bond sessions no more
factories than the passive's `MaxCarriersPerSession`, or the passive
refuses the surplus members and the dialer redials them about every
`RejoinBackoffMax` for the session's whole life. Better, leave the passive
one carrier more than a session holds (a bond: its factories; a selector:
2): otherwise, when the dialer loses a carrier that the passive still
holds, the replacement is refused until the passive's own liveness check
drops the old one, up to `PingIdle` + `DeadMax` (14 s) later, which leaves
little of the default 15 s `NoPathGrace`.

### L4 TCP forwarding (package `l4`)

Package [`l4`](l4) carries TCP connections over stream sessions. The
dialer names the target in the OPEN's metadata; the passive dials it while
the session is still pending, confirms only once the target connected and
rejects with a typed code otherwise (refused, unreachable, timeout, name
not found, not allowed, capacity, ...; `l4.CodeOf`); then both ends forward
with `l4.Forward`:

- Half-closes cross in both directions; a reset or failure on either side
  becomes a reset on the other, never a clean end of stream; a carrier
  change is invisible to both sockets. When a session ends, its socket is
  released at once, also when the socket's peer ignores FIN or never reads.
  A reset decided on the dialer while no carrier is alive reaches the
  passive only as `ErrNoPath` once its `PassiveRetain` runs out (34 s with
  the defaults): late, but never a clean end.
- Sessions made by `l4.Dial` and served by `l4.Server` are idle-limited to
  `l4.DefaultIdleTimeout` (10 minutes) unless changed
  (`Conn.SetIdleTimeout`, `Server.IdleTimeout`).
- A domain is resolved by the passive. The destination travels only in the
  OPEN; the whole metadata stays within `Handshake.MaxMetadata`.
- The Server has no authentication and no address policy of its own: give
  it a `Dial` hook that refuses what must not be reached (`l4.ErrDenied`)
  and checks the resolved address (`net.Dialer.Control`). Its `MaxConns`
  (10,000 by default) bounds the forwarded connections; each costs three
  goroutines and 64 KiB of buffers on top of its session's windows.

[`examples/socks5`](examples/socks5) is a loopback-only, no-authentication
SOCKS5 CONNECT front end over `l4`: `socks5 server` on the passive host,
`socks5 client` (one `-rendr` address per path) on the dialer's. It dials
without `EarlyReturn`, because the SOCKS reply must wait for the passive's
answer, and a refused target becomes a SOCKS failure reply.

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
  the session (`Done` closes) and is reported in `EventSessionEnd`; the
  early bytes are then discarded on both sides. The passive application
  reads them only after it confirmed the session; the passive holds at most
  64 KiB of them per pending session.
- Write before you read: a `Read` that comes first opens the session
  without early bytes. Do not use it when the peer must answer before your
  first byte (a SOCKS5 reply, for example). `l4.Forward` handles this for a
  pending session: it reads the session only after the client's first
  bytes were written, after the client's direction ended, or after 20 ms.
- Until the peer answers, `Status().State` is `StatePending` and
  `PeerInstance` and `RemoteAddr` report the zero `InstanceID`; the bound
  instance never changes afterwards. `Status().EarlyBytes` shows how many
  bytes travelled early on both ends.
- A session that opens on a carrier shared with other sessions of the Peer
  (rendr mux) sends no early data: its bytes follow the answer, which costs
  the same round trip as early data on a fresh carrier. `DialPacket`
  refuses `EarlyReturn` with `ErrProtocol`.

## Configuration, errors, Status and memory

### Configuration

`rendr.Config` configures a Runtime. The zero value of every field selects
its default; an out-of-range value is clamped, never rejected, and every
clamp is recorded in `Status.ConfigAdjustments` as `"Field: old → new
(reason)"`. Configuration is frozen when the Runtime is built; each session
also snapshots it at Dial or OPEN. The protocol invariants (EOF only from
the peer's FIN, transparent migration, versioned wire, bounded resources,
`net.Conn` deadlines, killing a violating carrier) are not configurable.

| Field | Default | Range | Meaning |
|---|---|---|---|
| `NoPathGrace` | 15 s | 3–300 s | time without a usable carrier, from the last death, before `ErrNoPath`; per session `DialOptions.NoPathGrace` |
| `RejoinBackoffMax` | 4 s | 1–8 s, ≤ `NoPathGrace`/2 | redial backoff cap: the first redial is immediate, then min(0.5 s · 2ⁿ, cap) × U[0.8, 1.2) |
| `JoinStagger` | 1 s | 0.1–10 s | stagger of the selector's concurrent failover candidates |
| `RetireGrace` | 2 s | 0–30 s | bound on the old carrier's retirement after a planned switch |
| `Selector.Band` / `.Floor` | 25 % / 5 ms | 5–90 % / 0–1 s | a challenger's RTT must be ≤ active × (1 − Band) and at least Floor lower |
| `Selector.Dwell` / `.Cooldown` | 3 s / 15 s | 0.5–60 s / 1–600 s | qualified this long; at least this long between quality switches (death switches bypass both) |
| `PingBusy` / `PingIdle` | 50 ms / 10 s | 10–500 ms, ≤ `DeadMin`/4 / 1–60 s | PING cadence with data in flight / on an idle carrier |
| `DeadMin` / `DeadMax` | 3 s / 4 s | 0.5–10 s / `DeadMin`–30 s | bounds of the death deadline for an unanswered PING |
| `WriteStall` | 2 s | 0.5 s–`DeadMax` | lower bound of the write-stall window |
| `Probe.Interval` / `.Fresh` | 2 s / 10 s | 0.5–30 s / 2 × Interval–120 s | probe PING cadence; sample freshness |
| `Probe.BackoffMax` / `.DialWait` | 4 s / 800 ms | 1–8 s / 0–5 s | probe redial cap; how long a cold Dial waits for first samples |
| `DialTimeout` | 10 s | 1–60 s | bound of one factory call and one dial attempt, also when the factory ignores ctx |
| `Linger` | 30 s | 1–300 s | background delivery bound after `Close`; then a reset |
| `IdleTimeout` | off | 0, or 10 s–24 h | ends a session without application progress (`ErrIdleTimeout`); per session `Conn.SetIdleTimeout` |
| `Window` | 8 MiB | 256 KiB–64 MiB | receive window per session and direction |
| `MaxCarriersPerSession` | 6 | 1–16 | carriers per session; a passive refuses more |
| `MaxSessions` | 10,000 | 1–1,000,000 | open, pending, lingering and orphaned sessions of both roles |
| `MaxBufferedBytes` | 1 GiB | 64 MiB–64 GiB | budget of the session data buffers (see [Memory](#memory-and-bounds)) |
| `Handshake.Timeout` / `.MaxConcurrent` | 10 s / 256 | 1–60 s / 1–65,536 | PREFACE + first frame + verdict; handshake slots (the oldest is evicted) |
| `Handshake.MaxMetadata` | 4 KiB | 0–65,535 B | OPEN metadata |
| `Handshake.EarlyDataMax` | 64 KiB | 0–64 KiB | early data of an `EarlyReturn` session |
| `Sessionless.PerInstance` / `.Total` / `.Idle` | 16 / 1024 / 30 s | 1–1024 / 1–65,536 / ≥ 3 × max(`PingIdle`, `Probe.Interval`) | probe carriers a passive keeps per dialer instance, in all, and without a PING |
| `PacketPing` | 1 s | 0.2–10 s, ≤ `DeadMin`/2 | PING cadence of an active datagram carrier; delay of a packet session's accounting frame |
| `Packet.Queue` | 1 MiB | 64 KiB–64 MiB | datagram bytes queued per direction (and Queue/64 datagrams); a full queue drops its oldest |
| `Packet.MaxAge` | 100 ms | 10 ms–2 s | a datagram not handed to a carrier within `MaxAge` of its `WriteTo` is dropped; one a dying carrier hands back unwritten keeps that age |
| `Packet.MaxPayload` | 65,507 B | 512–65,507 B | the largest datagram offered or accepted; a session fixes its limit at OPEN |
| `OnEvent` | nil | — | event callback, on one worker goroutine fed by a bounded queue (256) |

`PassiveRetain`, the time a passive keeps a session without carriers, is
derived: `NoPathGrace + PingIdle + DeadMax + 5 s` of the dialer, sent with
the OPEN (at most 400 s). `ListenConfig` adds `AcceptBacklog` (128;
1–65,536, per Listener and session kind) and `AcceptTimeout` (10 s;
0.1–60 s; then the dialer gets `ErrCapacity`). `l4.Server` has its own
defaults: `DialTimeout` 5 s (0.5–30 s), `IdleTimeout` 10 minutes,
`MaxConns` 10,000. `carrier/udp.Options` has `MaxDatagram` (1232; 546–65,507),
the socket buffers (4 MiB read, 1 MiB write) and `MaxBatch` (32; 1–64).

### Errors

| What happened | What the application sees |
|---|---|
| the peer's FIN reached the contiguous delivery point | `Read` returns `io.EOF` — the only source of EOF |
| a carrier's EOF, reset, timeout, read or write error, protocol violation, write stall or instance mismatch | nothing: rendr moves the session to another carrier |
| no carrier for `NoPathGrace` (passive: `PassiveRetain`) | `ErrNoPath` |
| the bound instance answered UNKNOWN_SESSION, or the peer restarted | `ErrSessionLost`; but when both ends negotiated the optional end-code feature bit on a stream carrier, a JOIN refused for a session the peer had reset returns that reset's `*AbortError` (`ErrAborted`, `Remote` true) instead |
| the peer reset the session (its linger expired, its `Runtime.Close`, its idle timeout, `Conn.Abort`) | `ErrAborted`; `errors.As` gives `*AbortError{Code, Msg, Remote}` |
| Dial: the peer application called `Reject` | `ErrRejected`; `*RejectError{Code, Msg}` |
| Dial: the peer's capacity, backlog, accept timeout or shutdown; local `MaxSessions` | `ErrCapacity` |
| Dial: the peer speaks another wire version or lacks a required feature | `ErrVersion` |
| Dial: the peer answered BAD_REQUEST (for example race to a passive without race), or an invalid local argument | `ErrProtocol` |
| Dial: metadata beyond either side's `Handshake.MaxMetadata` | `ErrMetadataTooLarge` |
| Dial: ctx ended | `ctx.Err()`, wrapping the last carrier error |
| a deadline passed | `os.ErrDeadlineExceeded` (`Timeout()` is true); the session is unaffected |
| calls after `Close`, `Write` after `CloseWrite`, calls after `Runtime.Close` | `net.ErrClosed` |
| `IdleTimeout` expired | `ErrIdleTimeout` (the peer gets `*AbortError` with `AbortIdle`) |
| `WriteTo` above `MaxPayload` / to another address | `ErrPacketTooLarge` / `ErrPacketDestinationMismatch`; nothing else changes |
| `ReadFrom` with a short buffer | `(len(b), addr, io.ErrShortBuffer)`; the rest of the datagram is discarded |

Every error matches with `errors.Is`; the coded ones also with `errors.As`.
Every sentinel and `*AbortError` and `*RejectError` implement `net.Error`
with `Timeout()` false. When `Write` returns `(n, err)`, n is what the
session accepted: after a deadline those bytes are delivered, after a
session failure they are not guaranteed. With `EarlyReturn`, Dial's
outcomes are returned by the first `Read` and `Write` instead.

### Ending a session cleanly

`Close` returns at once; written data is still delivered in the background
within `Linger`. `CloseWrite` sends a FIN and keeps reading. `Done` returns
a channel that is closed once the session has ended (`Status().State` is
then `StateEnded` and `Status().Err` final: `io.EOF` after a clean finish).
`Runtime.Close` resets every session that has not ended, including closed
ones still finishing in the background. For a clean end on both sides, read
until `io.EOF`, `Close`, wait for `Done` (bounded by your own context), and
only then call `Runtime.Close`, as the examples and
[`examples/mtls`](examples/mtls) do. A packet session has no half-close:
`PacketConn.Close` sends what is queued (while younger than
`Packet.MaxAge`) and the peer's `ReadFrom` returns `io.EOF` after the
datagrams it holds.

### Status and events

`Runtime.Status` (instance counters: sessions by state, handshakes,
backlogs, buffered bytes, datagram sockets, shared carriers, running
actors), `Conn.Status` and `PacketConn.Status` (one session: state, mode,
migrations by cause, byte and datagram counters, every live carrier and the
last 8 dead ones with RTT, rate, in-flight bytes and death cause) and
`Peer.Status` (probe evidence per factory) are the diagnostic surface.
`Config.OnEvent` delivers carrier up and down, migration, no-path start and
end and session end events in order; a full queue drops and counts
(`Status.EventsDropped`). A session's counters count each byte or datagram
once; in race mode `SessionStatus.Race` (sender) and `DupBytes` (receiver)
count the copies, and each `CarrierStatus` counts what its carrier moved,
copies included.

### Memory and bounds

Every resource is bounded: windows, the reorder and send buffers, the
packet queues, the backlogs, the handshake slots, the sessionless
carriers, the flows of a raw-UDP socket, the event queue and the
goroutines.

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
conn's `Write` runs; that buffer is charged to the budget unconditionally
and can take the use past its limit. Carrier reader stages add about
16 KiB per live carrier outside the budget; `Status.BufferedBytes` reports
both.

An idle session costs about 70 KiB per side with one carrier of its own
(selector) and about 170–190 KiB per side as a three-member bond, mostly
the carriers' reader stages, write batches and goroutine stacks; a session
that shares a live carrier (rendr mux) adds about 7 KiB per side and no
goroutine. (Method: `TestIdleSessionMemory` opens a few hundred idle
sessions of each shape over in-memory carriers and divides the live heap
plus the growth of the goroutine stacks, after garbage collection, by the
sessions and the two sides; it fails when a figure grows by more than
about a third.) Each side runs two goroutines per carrier and one per busy
session: a session's scheduler parks after about a second without work and
holds no goroutine until its next event or deadline (`Status.Actors`
counts the running ones). While idle, a session's carriers wake about every
`PingIdle` to send and answer liveness PINGs, and every dialer session of a
Peer with two or more factories is woken once per probe sample of the Peer
(90 times a minute with three factories at the default 2 s
`Probe.Interval`); a wakeup that changes nothing parks again at once.

## Datagram I/O and batching

Packet sessions carry datagrams. `WriteTo` never waits: each datagram is
queued and sent at most once, possibly reordered, and lost only in flight
(dropped by the network, or on a carrier that dies) or when a bounded
queue or budget drops it. A packet session counts its own drops in the
`Drop*` counters of `SessionStatus.Packet`; a datagram a carrier or a
raw-UDP flow drops counts in `Status.Datagram`, `CarrierStatus.Dropped` or
a QUIC carrier's `Counters` and, like a loss in flight, in the sender's
`Sent - PeerReceived` (as far as the peer has reported: during traffic it
also holds the datagrams in flight). `ReadFrom` returns one datagram per
call and `io.EOF` only after the peer closed its end and the datagrams
already received were read. A datagram larger than `PacketConn.MaxPayload`
fails with `ErrPacketTooLarge`; the limit is fixed at OPEN from the
carriers' budgets (1,198 bytes over `carrier/udp` with its default
`MaxDatagram`, 1,127 bytes over QUIC DATAGRAM). With `Config.IdleTimeout`,
every successful `WriteTo`, every received datagram and every datagram
`ReadFrom` returns keeps a packet session alive.

**Batched system calls.** On Linux amd64 and arm64, rendr's own UDP
sockets move several datagrams per system call: `sendmmsg` for the
datagrams a carrier writer has when it wakes, `recvmmsg` for the datagrams
the kernel has queued. rendr's own sockets are the ones `carrier/udp`
creates — every dialer carrier's socket and every `udp.Listen` socket served
through `rendr.FromPacketConn`. Every other socket uses one system call per
datagram: an embedder's `net.PacketConn` (a `DatagramCarrier` of your own,
`Listener.HandlePacket`, or any other conn given to `FromPacketConn`),
the QUIC carriers (quic-go does its own socket I/O), and every socket on
Windows, macOS and the other architectures.

- `udp.Options.MaxBatch` is the most datagrams one call moves: 0 selects
  32, 1 moves one datagram per call, values above 64 become 64; a listening
  socket reads at most 32 per call. Batching never delays a datagram: a
  writer sends what it has when it wakes, and a read returns what is
  queued. A dialer carrier's reader starts at one datagram per call and
  doubles its depth while calls come back full (up to `MaxBatch`); a
  `udp.Listen` socket reads at a fixed depth of min(`MaxBatch`, 32) from
  its first read on. Either reader holds its extra receive buffers while
  datagrams arrive (a listening socket from its first read), charged to
  `MaxBufferedBytes` and counted, with their message headers, in
  `Status.BufferedBytes` (about 70 KiB for a listening socket at the
  defaults), and returns them one to two seconds after the last datagram
  (a listening socket that received none: after its first read); it then
  reads one datagram per call until the next one arrives.
- Datagram contents, order, error handling and death rules are the same
  with batching on or off; only the number of system calls changes.
- **Fallback.** When the kernel or a sandbox (a seccomp policy) refuses
  `sendmmsg` or `recvmmsg`, the socket moves to one datagram per call for
  the rest of its life, redoing the refused call that way; nothing is lost
  or reordered by the switch. `Status.Datagram.BatchFallbacks` counts the
  sockets that switched. rendr also checks once per process, before its
  first batched socket, whether the batch calls are permitted; if they are
  not, every socket starts with one datagram per call and `BatchFallbacks`
  stays 0. In that case `SentDatagrams / SendCalls` and
  `RecvDatagrams / RecvCalls` stay at 1 under load.
- **Reading `Status.Datagram`.** `SendCalls` and `RecvCalls` count the
  system calls on rendr's own sockets that moved at least one datagram,
  `SentDatagrams` and `RecvDatagrams` the datagrams they moved:
  `SentDatagrams / SendCalls > 1` shows that sends were batched, and the
  same ratio on the receive side shows how many datagrams the kernel had
  queued per wakeup. `ChargeRefused` counts receive buffers the memory
  budget refused (a dialer carrier keeps its depth; a listening socket
  reads with the buffers it got). Each counter is read on its own, so a
  snapshot taken under load can be off by the calls in progress.
  QUIC and embedder sockets are not counted.

**Sizing for high packet rates.** Size `Packet.Queue` and the UDP read
buffer (`udp.Options.ReadBuffer`) for at least 50 ms of the expected peak
packet rate. At 100,000 datagrams a second of about 1 KB, that is
`Packet.Queue` = 8 MiB (about 80 ms; the default 1 MiB holds about 10 ms)
and `ReadBuffer` = 16 MiB (the kernel charges more than the payload per
datagram; the default 4 MiB holds about 20 ms), with `WriteBuffer` = 4 MiB.
On Linux a buffer above `net.core.rmem_max` / `wmem_max` takes effect only
when the process may force it (`CAP_NET_ADMIN`); otherwise the kernel caps
it at that limit. The defaults stay small because they apply to every
session and socket of a Runtime with up to 10,000 sessions.

rendr 2.0.0 uses no UDP segmentation or receive offloads (GSO, GRO).

## Performance

Every figure below names its method; none comes from the Windows
development host. The authoritative figures are measured on idle Linux
virtual machines of the private test pool, with every other workload
stopped.

**Stream throughput (BENCH-E2E-1).** One process hosts both ends with
`GOMAXPROCS(8)`; exactly one carrier, a loopback TCP connection; the sender
writes a deterministic ChaCha8 stream in 64-KiB calls (1 GiB per transfer),
the receiver reads with a 64-KiB buffer and checks a CRC-32C of the stream;
the timer covers the transfer only; one 64-MiB warm-up and 5 measured
transfers per run. Implementations run alternately in pairs, and the result
is the median of the per-pair ratios; the A/A noise band is the spread of
rendr-against-rendr pairs.

<!-- FIGURE: BENCH-E2E-1 median of per-pair ratios, rendr 2.0.0 / rendr v0.3.0 and rendr 2.0.0 / raw TCP, with the A/A noise band, the pair count and the date; method: BENCH-E2E-1 as described, at least 5 alternating pairs per comparison on an idle Linux VM; source case: G7 (BENCH-E2E-1) at the M5 gate -->
On BENCH-E2E-1, rendr 2.0.0 reaches {ratio-v030} × the throughput of rendr
v0.3.0 and {ratio-raw} × that of a raw TCP connection over the same
loopback path (median of per-pair ratios over {pairs} alternating pairs,
A/A noise band {noise} %, {date}).

**Packet rate.** A packet session over `carrier/udp` with one carrier,
1,000-byte datagrams, one direction at a time, on a single path through a
router namespace with no shaping (MTU 1500): the rate steps up from 50,000
to 300,000 datagrams a second (50, 80, 100, 125, 150, 200, 250 and 300
thousand) in 12-s steps (10 s measured). A step passes when the receiver
got at least 99 % and the generator sent at least 98 % of the datagrams the
step's rate calls for; the ceiling is the highest passing step, capped at
the ceiling of a raw-UDP reference ramp on the same path, and a direction
stops after two failed steps. "A → B" is the dialer sending on its own
socket to the passive's listening socket; "B → A" the passive sending
through its listening socket to the dialer.

<!-- FIGURE: packet-rate ceiling per direction (A → B, B → A) with MaxBatch default (32) and MaxBatch 1, plus the raw-UDP reference ceiling and the CPU microseconds per datagram per role, and the date; method: the ramp described above on an idle Linux VM; source case: perf/pps-ceiling at the M5 gate -->
The packet-rate ceiling is {ceiling-ab} datagrams a second from A to B and
{ceiling-ba} from B to A with the default `MaxBatch` ({ceiling-ab-1} and
{ceiling-ba-1} with `MaxBatch` 1; raw UDP on the same path: {raw-ab} and
{raw-ba}; {date}).

**100,000 datagrams a second with failover (G3).** A packet session sends
1,000-byte datagrams at 100,000 a second for 5 minutes over two paths while
at least ten switching events, 30 s apart, close the active carrier or
degrade its path (selector) or close a member (bond, race); the criteria:
at least 95 % of what the generator sent delivered, no corrupt or
duplicate datagram, losses only within 200 ms of a switching event, and
every arrival gap caused by a switch under 200 ms. Sessions use the sizing
of [Datagram I/O](#datagram-io-and-batching).

<!-- FIGURE: G3 at 100 kpps, A → B, per mode (selector, bond, race): delivered fraction, worst switch gap, losses outside the event windows, and the date; method: G3 as described, 2 runs per mode; source cases: gold/G3-sel-100k, gold/G3-bond-100k, gold/G3-race-100k at the M5 gate -->
At 100,000 datagrams a second, selector, bond and race sessions delivered
{g3-sel}, {g3-bond} and {g3-race} of the datagrams sent, with the longest
switch gap {g3-gap} ms and {g3-out} losses outside the event windows
({date}).

**Bond aggregation (G8).** A bond session moves 2 GiB from B to A over
three independent links between two virtual machines (50, 100 and
100 Mbit/s; 10, 40 and 80 ms round trip), one `carrier/tcp` factory per
link; steady goodput (the first 2 s excluded) is compared with the sum of
the links' calibrated raw rates.

<!-- FIGURE: G8 3-path steady goodput as a fraction of the summed calibrated link rates, the SHA-256 match, the longest zero-delivery gap, and the date; method: G8 as described, 2 runs; source case: gold/G8-3path at the M5 gate -->
A three-path bond reached {g8-ratio} of the summed link rates (criterion:
at least 85 %), with the longest zero-delivery gap {g8-gap} ms ({date}).

**Failover with an expensive carrier dial (G4-dialcost).** Two paths of
100 Mbit/s and 150 ms round trip, each carrier a TLS-over-TCP dial that
takes about three round trips; a stream transfer is in flight when every
packet of the active path is silently dropped.

<!-- FIGURE: G4-dialcost recovery from the DROP to the first new byte at the receiver, split into detection, dial, JOIN and first byte, and the date; method: G4-dialcost as described, 2 runs; source case: gold/G4-dialcost at the M5 gate -->
Recovery took {g4dc-total} s from the drop to the first new byte
(detection {g4dc-detect} s, dial {g4dc-dial} s, JOIN and first byte
{g4dc-join} s; criterion: at most 5 s; {date}).

## Testing

The public test suite (`go test ./...` in both modules) is the unit layer:

- logic and timing tests in `testing/synctest` bubbles (grace, dwell,
  cooldown, death deadlines and backoffs in virtual time, with a free
  goroutine-leak check at every bubble's end), and an end-of-package leak
  check in the root package;
- in-process scenario tests (`internal/scenario/...`) over the fault
  injection of package [`rendrtest`](rendrtest): stream and datagram links
  with delay, jitter, rate limits with a shared bottleneck, loss,
  duplication, reordering, blackhole, stall and kill with buffer loss; a
  frame-aware tamper (bit flips, drops, duplicates, replays, splices
  across carriers); misbehaving factories and conns; a shared raw-UDP
  socket with rebinding, spoofing, replay and floods; in-process TCP
  targets with FIN and reset accounting. Scenario tests assert that the
  stimulus happened, that the load was reached and that the bytes arrived
  intact (strict stream and datagram verifiers);
- real-socket tests on loopback (TCP resets, keepalive, half-close, Windows
  close semantics, raw UDP with batching on and off);
- fuzz targets and golden vectors for every wire structure, and allocation
  gates for the steady-state data paths.

Package `rendrtest` is exported so that embedders can test their own code
against the same faults. Test names carry the tags of the lessons of
rendr's earlier generations that they guard (for example `_L07`).

Scenario, long-run, multi-machine and performance testing ran on a private
pool of Linux virtual machines with a private harness. Results are PASS,
FAIL, INVALID (the stimulus or the facility failed, proven by its own
checks) or FLAKY, nothing else. The gold criteria every release passes:

| Gold | What it proves |
|---|---|
| G1 | a 1-GiB transfer survives three hard carrier kills (and relay failures) with the SHA-256 intact, no zero-delivery gap over 500 ms, within 1.10 × an unkilled control run |
| G2 | a 30-minute interactive echo under kills and quality switches: no loss, duplicate or reorder; P99 within 2 × baseline or + 20 ms |
| G3 | packet sessions at 10,000 and 100,000 datagrams a second across switching events (see [Performance](#performance)) |
| G4 | a silent path death (drop, loss, stall, deep queues, random offsets, an expensive dial, a relay): new bytes within 5 s, nothing written before it lost |
| G5 | a recovered path is used again: rejoin or failover within a computed bound, no loss |
| G6 | 30 minutes of churn through a NAT (short, long, rejected, failing and timed-out sessions, kills, a conntrack flush): resources return to baseline |
| G7 | stream throughput (BENCH-E2E-1) at least that of rendr v0.3.0 |
| G8 | bond aggregation: at least 85 % of the summed path rates |
| G9 | selector stability: one switch on a real degradation, at most two under equal jitter, at most one switch back |

Each gold criterion runs in variants (selector, bond, race, rendr mux,
packet sessions, `l4`, QUIC), together with the lesson cases.

<!-- FIGURE: the M5 gate's result counts (rows PASS, FAIL, INVALID, FLAKY) on the release candidate commit, and the date; method: the cumulative M5 gate, every gold variant and lesson case of M1c-M5; source: the M5 gate run -->
At the 2.0.0 release candidate, {gate-pass} gate rows passed, with
{gate-fail} FAIL and {gate-flaky} FLAKY ({date}).

## Known limitations and what is not in 2.0.0

The main limitations; [`CHANGELOG.md`](CHANGELOG.md) lists every known
limitation of 2.0.0 with its consequence.

- **QUIC DATAGRAM carriers on reordering paths.** quic-go's congestion
  control (Reno, packet threshold 3, no undo of spurious loss detection, no
  option to change it) treats reordering as loss; on a path that reorders
  by 3 packets or more a constant-rate packet session loses datagrams.
  quic-go also drops received DATAGRAM frames beyond 128 per connection
  (a fixed limit rendr cannot prevent from overflowing when the receiving
  process stalls); the carrier counts them in `Counters.IngressDrops` from
  the gaps in its per-DATAGRAM sequence numbers. When DATAGRAMs arrive in
  order that count is exact, except that a datagram lost in the network
  during such an overflow counts too. On a path that reorders it is no
  bound: it can be too high (a datagram reordered during an overflow
  counts and is still delivered) or too low (a late datagram the full
  queue dropped after a later one was queued is missed, and once the
  queue has drained, a late datagram numbered above every one received
  hides the overflow's drops numbered above it). Use `carrier/udp` or the
  QUIC stream carrier on reordering paths.
- **Synchronous-Write carriers at `GOMAXPROCS=1`.** A carrier conn whose
  `Write` returns only after the far end read the bytes (a `net.Pipe`-like
  in-process tunnel) may give no probe RTT evidence on one P: a cold Dial
  then waits the whole `Probe.DialWait`, and selection falls back to the
  configured factory order.
- **A sighted source can fill the packet `AcceptBacklog`.** On a raw-UDP
  listening socket the per-address quota stops blind floods only; a source
  that answers the address check is bounded like a stream client. The
  embedder's authentication and Accept policy are the defence.
- **Embedder conns are not drained gracefully.** A retiring carrier is
  half-closed and drained only on `carrier/tcp` connections; an embedder
  `net.Conn` is closed at the drain bound, so a peer that stalls reading
  can see its transport reset (the session has already moved off it).
- **Wildcard UDP listeners are single-homed.** rendr does not use
  `IP_PKTINFO`: a `udp.Listen` on a wildcard address answers from the
  source address the routing table chooses. Bind a specific address on a
  multi-homed host.
- **Batching only on Linux amd64/arm64 and rendr's own sockets.** Other
  platforms and embedder sockets use one system call per datagram.
- **No UDP offloads.** 2.0.0 uses neither GSO nor GRO.
- **The selector's self-load guard.** Probe samples loaded by the Peer's
  own traffic are not compared, so a path that degrades while this Peer's
  own traffic saturates it cannot be told apart from self-induced queueing:
  the selector leaves it only on death detection or once the traffic is
  application-limited again. Packet sessions on datagram carriers have no
  self-load gauge. The `SelectorPolicy` documentation states the rules and
  their gaps.

**Not in 2.0.0** (the behaviour of 2.0.0 and its consequence):

- No warm standby carriers, idle carrier retention, carrier priorities,
  carrier sharing between Peers or changing a running session's carrier
  set. Every session snapshots its Peer's factories at `Dial` and only
  redials those; replacing a factory affects new sessions only. Selector
  failover dials a new carrier unless the Peer has a live shared carrier
  of the failover factory, and probe carriers are never adopted by
  sessions, so an expensive (L7) carrier dial adds its full cost to
  failover (see G4-dialcost under [Performance](#performance)).
- No nested scheduling groups and no peak-transfer modes (scheduling is
  flat).
- No L4 UDP, L3 or L2 payload modules (`l4` is TCP only); no SOCKS5 BIND,
  UDP ASSOCIATE or authentication and no HTTP CONNECT in
  `examples/socks5`.
- No stream sessions over raw datagram carriers (raw UDP, QUIC DATAGRAM):
  that would need a congestion controller of its own. Use the QUIC stream
  carrier or a reliable embedder connection.
- No retransmission of packet-session datagrams.
- No optional quality triggers, re-probe hooks or embedder quality
  callbacks: nothing reacts to traffic patterns or external hints.
- No graceful `Runtime.Shutdown(ctx)`: only `Close` (GOAWAY and reset).
  For a clean end, finish each session first (see
  [Ending a session cleanly](#ending-a-session-cleanly)).
- No early data on a shared carrier, after the first flight or in a JOIN.
- No real-network regression on Windows (unit and in-process scenario
  tests and cross-compilation only), and no run-time testing on macOS or
  on arm64 (compiled only).

## Compatibility and licence

**Wire format.** Every carrier starts with a versioned PREFACE (magic
`RND2`, major version 2, minor version, required and optional feature
bits). The wire format is frozen at 2.0.0 and covered by golden vectors:
later 2.x releases extend it only with optional feature bits, which an
older peer ignores, or with a new minor version; a feature a peer must
understand is a required bit, and a peer that lacks it answers FEATURE,
which the dialer reports as `ErrVersion`. A handshake that does not start
with the `RND2` magic (rendr v1's, for example) is refused cleanly.

**API.** The module path is `github.com/FrankoonG/rendr/v2`. rendr 2.0 is
a rewrite: it shares no API, wire format or module path with rendr v0.x or
v1, and there is no in-place upgrade — both ends of a session must run
rendr 2.x. Within 2.x the public API follows semantic versioning.

**Licence.** GNU General Public License v3.0; see [LICENSE](LICENSE). The
session core began as a port of `internal/msess` from the same author's
hy2scale project, also under GPL-3.0. The QUIC module's dependencies are
under the MIT licence (quic-go) and the BSD-3-Clause licence
(`golang.org/x/crypto`, `x/net`, `x/sys`), all compatible with GPL-3.0.
