# Changelog

<!-- FIGURE: the release date (YYYY-MM-DD) of the v2.0.0 tag; source: the release commit F (Part R step R6) -->
## v2.0.0 — {date}

rendr 2.0 is a Go library that keeps one application connection alive
across many underlying carriers between two rendr instances: a userspace
session layer with session identity, byte offsets, acknowledgement =
delivered to the receiving application, bounded retransmission and
reordering, and selector, bond and race scheduling. Carriers are
rendr-to-rendr connections supplied as `net.Conn` or `net.PacketConn` — the
embedder's L7 tunnels, the built-in plaintext TCP and UDP carriers, or the
QUIC carriers of the nested module. rendr does not encrypt or authenticate;
that is the embedder's job.

### A new major version

rendr 2.0 is a ground-up rewrite. It breaks with rendr v0.x and v1 in every
respect:

- **Module path** `github.com/FrankoonG/rendr/v2` (and
  `github.com/FrankoonG/rendr/quic/v2` for QUIC). The old module path
  `github.com/FrankoonG/rendr` has no release tags; its code stays on its
  branches and is reachable by pseudo-version.
- **API**: new; nothing of the v0.x or v1 API remains.
- **Wire format**: version 2 (PREFACE magic `RND2`); it does not interoperate
  with v0.x or v1, whose handshakes are refused cleanly.
- **No in-place upgrade**: both ends of a session must run rendr 2.x;
  upgrade the dialers and passives of a deployment together, or run 2.x
  beside the old version on other addresses.
- **Removed concepts** of v1: TCP_REPAIR and kernel socket migration, leaf
  mobility, TUN/L3 data planes, the kernel feature matrix; rendr's core is
  userspace only and portable.

### Features

Sessions:

- Stream sessions: `*rendr.Conn` is a `net.Conn` with `CloseWrite`, `Done`,
  `Abort`, `SetIdleTimeout` and `Status`. `io.EOF` only from the peer's FIN
  at the contiguous delivery point; a carrier failure never surfaces as an
  error, a reset or a zero read; deadlines follow `net.Conn`.
- Packet sessions: `*rendr.PacketConn` is a `net.PacketConn`; datagrams
  delivered at most once, possibly reordered, never retransmitted, with
  bounded queues and an age limit; every loss is counted on one side.
- `Runtime` (one instance), `Peer` (one destination instance and its
  carrier factories), `Listener` with `Accept`/`AcceptPacket` and
  `Confirm`/`Reject` of pending sessions, `PendingConn.Context`.
- `NoPathGrace` (15 s by default) from the last carrier's death before
  `ErrNoPath`; typed errors (`ErrSessionLost`, `*AbortError`,
  `*RejectError`, `ErrCapacity`, `ErrVersion`, `ErrProtocol`,
  `ErrMetadataTooLarge`, `ErrIdleTimeout`, ...), all `net.Error`.
- Bounded everything: windows, buffers (`MaxBufferedBytes`), backlogs,
  handshake slots, sessionless probe carriers, flows, events, goroutines;
  idle sessions hold no goroutine.
- Configuration with defaults and clamps (`Status.ConfigAdjustments`
  records every clamp); `Status`, per-session and per-carrier counters,
  and ordered events (`Config.OnEvent`).

Scheduling:

- Selector: one active carrier, racing failover on death (`JoinStagger`),
  quality switching only on probe evidence with band, floor, dwell and
  cooldown, and a self-load guard against the session's own queueing.
- Bond: every member carries data in proportion to its drain rate; a dead
  member's data is requeued at once and the member redialled at once.
- Race: every byte or datagram on every member; the receiver keeps the
  first copy.
- Peer health layer: one sessionless probe carrier per factory while a
  multi-factory Peer is in use; factories ranked by RTT evidence.

Carriers:

- `carrier/tcp`: plaintext TCP, keepalive off, `TCP_NODELAY`, vectored
  writes, loopback only unless `AllowNonLoopback`.
- `carrier/udp`: plaintext raw UDP with a 9-byte flow header; one listening
  socket (`rendr.FromPacketConn`) serves many carriers; don't-fragment with
  MTU probing; NAT rebinding behind a nonce check; per-address admission
  quotas; loopback only unless `AllowNonLoopback`.
- Embedder carriers: `StreamCarrier` (with `DialEarly` to put rendr's first
  bytes into the embedder's own open request) and `DatagramCarrier`; the
  passive's `Listener.Handle` and `Listener.HandlePacket`. Every embedder
  conn is treated as untrusted (bounded calls, contained panics, validated
  counts).
- The QUIC module (`github.com/FrankoonG/rendr/quic/v2`): a stream carrier
  and a DATAGRAM carrier over quic-go, TLS required, ALPN `rendr/2-q1`, QUIC
  keepalives off, a bounded egress queue so rendr's writer never blocks on
  QUIC's congestion control.
- Carrier properties (`Props`): `FateGroup` (bond and race keep one member
  per group; selector failover prefers other groups), `HoLCoupled`,
  `CheapSubflow`; datagram carriers report their MTU.
- rendr mux: by default the sessions of one Peer share the live carriers
  of a factory, on stream and datagram carriers; a new session or a
  failover uses a live carrier instead of dialling.
- When a shared carrier dies at one end for a reason the other end cannot
  see (a transport error, a PING timeout, a local close), that end reports
  it with one DOWN frame on each of its other shared carriers to the same
  instance that were dialled in the same direction, ahead of the sessions'
  own route updates; the peer ends its end when the DOWN arrives (cause
  `peer_down`), so the sessions on the carrier move about one one-way delay
  after the death instead of after the peer's death deadline, however many
  sessions the carrier carried (the exceptions are under Known
  limitations).
- Every frame carries a frame sequence number and a CRC32C; a carrier that
  violates the protocol is killed and the session survives.

L4 and early return:

- Package `l4`: TCP connections over stream sessions. `l4.Dial` names the
  target in the OPEN; `l4.Server` dials it while the session is pending,
  confirms on success or rejects with a typed code (`l4.CodeOf`);
  `l4.Forward` maps half-closes and resets both ways. A `Dial` hook for
  address policy; `MaxConns`; idle sessions end after 10 minutes by
  default.
- `DialOptions.EarlyReturn`: TCP Fast Open semantics for `Peer.Dial`; up to
  `Handshake.EarlyDataMax` (64 KiB) of the first bytes travel with the
  OPEN, saving one round trip for client-first protocols.
- `examples/socks5`: a loopback-only SOCKS5 CONNECT front end over `l4`;
  `examples/mtls`: mutually authenticated TLS carriers with the standard
  library.

Datagram I/O:

- Batched system calls (`sendmmsg`, `recvmmsg`) on rendr's own UDP sockets
  on Linux amd64 and arm64, up to `udp.Options.MaxBatch` (32 by default)
  datagrams per call; batching never delays a datagram; a one-way runtime
  fallback to one call per datagram when the kernel or a sandbox refuses
  the calls; `Status.Datagram` counts the calls and the datagrams they
  moved.

Testing:

- Package `rendrtest`: in-memory stream and datagram links with fault
  injection, a frame-aware tamper, a shared raw-UDP socket model, far-end
  behaviours, in-process TCP targets, strict verifiers and leak
  assertions; usable inside `testing/synctest`.

### Requirements and platforms

- Go 1.26.3 or later (both modules declare `go 1.26.3`).
- The root module depends only on the standard library and
  `golang.org/x/sys` (v0.47.0).
- Linux and Windows are supported. Linux runs every test layer; Windows
  runs the unit and in-process scenario tests (no real-network
  regression). Linux, Windows and macOS on amd64 and arm64 are
  cross-compiled; macOS and arm64 are not tested at run time. Batched
  datagram I/O is used on Linux amd64 and arm64 only.

### Performance

Measured on idle Linux virtual machines; the methods are in the README's
"Performance" section.

<!-- FIGURE: BENCH-E2E-1 ratios rendr 2.0.0 / v0.3.0 and rendr 2.0.0 / raw TCP (median of per-pair ratios, pair count, A/A noise band); source case: G7 (BENCH-E2E-1) at the M5 gate -->
- Stream throughput (BENCH-E2E-1, one loopback TCP carrier, 1-GiB
  transfers, alternating pairs): {ratio-v030} × rendr v0.3.0 and
  {ratio-raw} × raw TCP (A/A noise band {noise} %).

<!-- FIGURE: packet-rate ceiling per direction with MaxBatch default and 1, relative to the raw-UDP reference on the same path; source case: perf/pps-ceiling at the M5 gate -->
- Packet rate (1,000-byte datagrams, one `carrier/udp` carrier, a 12-s
  step ramp per direction; a step passes when 99 % of its datagrams
  arrive and 98 % were sent; capped at the raw-UDP reference): a ceiling
  of {ceiling-ab} datagrams a second from dialer to passive and
  {ceiling-ba} back, {raw-share-ab} and {raw-share-ba} of raw UDP on the
  same path.

<!-- FIGURE: G3 at 100 kpps per mode: delivered fraction and worst switch gap; source cases: gold/G3-sel-100k, gold/G3-bond-100k, gold/G3-race-100k at the M5 gate -->
- 100,000 datagrams a second across ten switching events (G3): selector,
  bond and race delivered {g3-sel}, {g3-bond} and {g3-race} of the
  datagrams sent; the longest switch gap was {g3-gap} ms.

<!-- FIGURE: G8 3-path bond goodput as a fraction of the summed calibrated link rates; source case: gold/G8-3path at the M5 gate -->
- Bond aggregation over three independent links between two machines
  (G8): {g8-ratio} of the summed link rates.

### Wire format notes

- Wire format version 2.0, frozen at this release: golden vectors cover
  every structure, and after 2.0.0 a frozen vector changes only with a new
  wire minor version, an optional PREFACE feature bit (an older peer
  ignores it), or a new version of a versioned payload format such as the
  L4 metadata. A peer that needs a feature the other lacks is answered
  FEATURE, reported as `ErrVersion`.
- Shared carriers carry the carrier-level frame DOWN (type 0x37, a 4-byte
  CarrierID): the carrier it names, between the same two instances and
  dialled in the same direction, died at the sender's end. It is legal only
  on a shared carrier and inside the reliable sublayer on datagram
  carriers; a DOWN on any other carrier, or one naming the carrier it
  arrives on, is a protocol violation, and one naming an unknown, ended or
  retiring carrier is ignored.
- The QUIC carriers' encapsulation is versioned by the ALPN `rendr/2-q1`
  and frozen with the wire format: each DATAGRAM payload is a 4-byte
  big-endian per-direction sequence number followed by one rendr datagram;
  a QUIC peer offering another ALPN is refused.
- Optional feature bits in 2.0.0: bit 0, rendr mux (shared carriers);
  bit 1, the end code of an ended session in a JOIN refusal.
- A JOIN refusal (JOIN_ACK UNKNOWN_SESSION) carries the ended session's end
  code only when both ends negotiated the optional end-code feature bit;
  otherwise the refusal carries no code, the dialer ends the session with
  `ErrSessionLost`, and only the passive's status shows why it ended. The
  bit is offered on stream carriers only, not on datagram carriers.

### Known limitations

QUIC and carriers:

- QUIC DATAGRAM carriers on reordering paths: quic-go v0.63's congestion
  control (Reno, packet threshold 3, no undo of spurious loss detection, no
  option) shrinks the window on a path that reorders by 3 packets or more,
  and a constant-rate packet session loses datagrams to the 250-ms egress
  age; use `carrier/udp` or the QUIC stream carrier on such paths.
- quic-go drops received DATAGRAM frames beyond 128 per connection
  without a signal, and rendr cannot prevent it: a receiving carrier whose
  pump does not run while more than 128 DATAGRAMs arrive (12.8 ms at
  10,000 datagrams a second) loses the excess. The DATAGRAM carrier puts
  a 4-byte sequence number before each datagram and counts these drops in
  `Counters.IngressDrops` from the gaps, when the next datagram arrives.
  When DATAGRAMs arrive in order the count is exact, except that a network
  loss or a drop by quic-go's 256-packet unprocessed-packet queue during
  such an overflow counts too; while the carrier keeps up, either stays an
  uncounted transport loss. On a path that reorders the count is no bound:
  it can be too high (a datagram reordered during an overflow counts and
  is still delivered) or too low (a late datagram the full queue dropped
  after a later one was queued is missed, and once the queue has drained,
  a late datagram numbered above every one received hides the overflow's
  drops numbered above it).
- A QUIC carrier costs about 7–8 goroutines (quic-go's own included), and
  QUIC's late stream close holds one goroutine per handed datagram
  connection.
- A carrier conn whose `Write` returns only after the far end read the bytes
  (a `net.Pipe`-like in-process tunnel) gives no probe RTT evidence at
  `GOMAXPROCS=1`: a cold Dial waits the whole `Probe.DialWait` and ranking
  falls back to the configured order.
- A retiring carrier is drained through a half-close only on `carrier/tcp`
  connections; an embedder `net.Conn` is closed at the drain bound, so a
  peer that stalls reading can see its transport reset.
- Wildcard `carrier/udp` listeners are single-homed (no `IP_PKTINFO`):
  replies leave from the routing-chosen source address; bind a specific
  address on multi-homed hosts.
- Batching only on Linux amd64/arm64 and rendr's own sockets: other
  platforms and embedder sockets use one system call per datagram.
- No UDP segmentation or receive offloads (GSO, GRO) in 2.0.0.

Raw-UDP admission and NAT:

- A source that answers the raw-UDP address check is bounded like a stream
  client and can fill the packet `AcceptBacklog` for `AcceptTimeout`; later
  packet OPENs then get CAPACITY. The embedder's authentication and Accept
  policy are the defence.
- A flow whose every address-check answer is lost stays in its address's
  admission quota until its verdict or removal.
- A NAT rebinding in the last 2 s or so of an attempt's `Handshake.Timeout`
  is not seen by that attempt; the next attempt opens a fresh flow.
- A holder of a raw-UDP flow ID who can inject window-valid frames can
  start and redirect a rebind challenge; authentication is the defence.
- A genuine frame-sequence jump of 1,024 frames or more on a datagram
  carrier loses the frames that arrive before the jump is proven (at most
  about rate × (2 RTT + 10 ms) per direction); sessionless probe carriers
  cannot prove a jump; a foreign frame landing less than 1,024 frames ahead
  is still accepted (about 2^-22 per frame); a foreign replay from a new
  address can draw rate-limited challenge PINGs.
- On a Peer that mixes datagram budgets with a black hole between 537 bytes
  and the larger budget, the MTU probe can flap; and on Linux a
  `SOCK_DESTROY` of an idle listening raw-UDP socket stops its source.

Packet sessions:

- A packet session's later OPEN carriers with smaller clamped budgets keep
  the first OPEN's `MaxPayload`; datagrams too large for such a carrier
  count `DropTooLarge` on it.
- A race copy that arrives 16,384 datagrams or more behind the newest
  accepted one counts as `DropLate`, not `Duplicates` (members more than
  about 330 ms apart at 50,000 datagrams a second); every datagram is still
  delivered once.
- On a shared datagram carrier, when the passive writes first and its
  OPEN_ACK or its first frame for the session is lost, the passive is held
  for one control retransmission timeout and datagrams it wrote right after
  `Confirm` can age out (about 1–2 % of such openings at 1 % loss).
- A shared datagram carrier whose reliable control window (eight frames)
  is already full when another shared carrier of the pair dies sends its
  DOWN only after the oldest of them is acknowledged: the peer then moves
  off the dead carrier up to one round trip later. The sessions' own route
  updates (SCHED) still pass that window eight at a time, so a session's
  `SchedEpoch` can settle ⌈k / 8⌉ round trips after a carrier death when
  k sessions shared it; their traffic has moved by then.
- When k shared carriers of the pair die together, each surviving datagram
  carrier sends their DOWNs eight per round trip (its reliable control
  window, in which its sessions' own control frames then wait), every
  survivor in the same order, so the peer learns the last of them about
  ⌈k / 8⌉ round trips later; a surviving stream carrier sends them at once.
  A surviving carrier holds at most 32 unsent DOWNs and drops the oldest
  beyond that: the peer learns those deaths as it would without DOWN (at
  the latest at its own death deadline).
- A datagram in flight toward the peer on a shared carrier that has just
  died is lost if the DOWN, sent on another carrier, reaches the peer
  before the peer has read it (the peer then ends its end of the dead
  carrier): mainly those written in the instant of the death or, when the
  dead carrier's path is the longer one, less than the difference of the
  two paths' one-way delays before it. They count in the sender's `Sent` −
  `PeerReceived`, as any datagram lost in flight on a dead carrier.
<!-- CHECK at C-B: the M4 C3 packet-loss gap below (escalated; a failing-first row was proposed); drop or reword it if M5 fixed it -->
- Replies a packet session sends on a carrier that a stimulus has just
  ended can be lost with no loss counter moving on either end.

Scheduling and estimation:

- Race: a slow member that does not lead keeps its in-flight data at its
  cap with copies the leader already delivered, so after the leader's death
  the takeover gap is about (in-flight + cap) / rate + 2 × one-way delay +
  50 ms of the slow member (in-process race scenarios: up to about 2 s for
  a 128 KiB/s member at 20 ms).
- Race ACK copies add one frame per extra member per acknowledgement.
<!-- CHECK at C-B: the estimator items below (two-way bulk overestimate, small-buffer residuals) are M5 performance items; update them from the gate's figures -->
- Under two-way bulk on deep bottlenecks the rate estimate runs 1–3 × high,
  so in-flight caps grow to about 6.5 × (BDP + buffer) and round trips
  settle at 0.5–1.03 s on 20-ms links; an interactive session sharing a
  carrier with bulk sessions waits about cap / rate (in-process scenarios
  at 4 MiB/s and 20 ms: echo P99 237 ms).
- Estimator residuals: with socket or link buffers below one 256-KiB batch
  a PONG waits behind the peer's write (0.41–0.63 of the link at 1 MiB/s);
  one way, with blocking writes below a rate of one batch / (minRTT +
  2 × PingBusy + 100 ms) (256 KiB / 220 ms ≈ 1.14 MiB/s at a 20-ms minRTT
  with the default PingBusy), a flow reaches about 0.6–0.8 of the link;
  two-way bulk over buffers shallower than a batch at 1.5–2 MiB/s with a
  30–40 ms RTT can still leave one direction
  below 85 % of the link in some interleavings; low rates with deep
  buffers vary between 0.62 and 0.98 of the link per run; a one-way flow
  at 1 MiB/s and 100 ms reaches about 0.8 of the link;
  a peer clock drift of 0.2–0.5 % at 2 MiB/s exceeds the latency bound by
  up to 25 % (in-process scenarios).
- A shared carrier that is write-blocked is not used for new sessions, so
  a session that opens during a short stall pays a fresh dial.
- When no JOIN waits, OPEN waiters still dial beside a slow OPEN claimant,
  so a carrier kill can draw more than one opening dial per factory.
- Each carrier attempt in flight holds one session goroutine that no Status
  field counts.
<!-- CHECK at C-B: the throughput items below were M5 P0 questions; replace them with the gate's findings -->
- In one process with two long-lived Runtimes, single-session throughput
  dropped about 8 % after a burst of 64 sessions and stayed there (cause
  not found; in-process loopback benchmark).
- Single-stream throughput and CPU per GiB moved by about 3 % and 5 %
  between two 2.0 development milestones (paired BENCH-E2E-1 runs); not
  explained.

Sessions and L4:

- A reset the dialer decides while no carrier is alive (its local
  connection resets during an outage, or its idle timeout fires while
  every carrier is down, as after a NAT flush) reaches the passive only as
  `ErrNoPath` once `PassiveRetain` runs out (34 s with the defaults): late,
  but never a clean end.
- After an `l4.Forward`'s local side sent its FIN, a later close of that
  side is not observable; such a session ends when the far side ends it,
  at its idle limit, or when the context ends.
- A refusal that an `l4.Server` repeats for an OPEN retried on a shared
  carrier carries the code only, with an empty message.
- On datagram carriers a JOIN refusal carries no end code (the end-code
  bit is offered on stream carriers only), so a session whose RST was lost
  with every carrier and that rejoins over a datagram carrier ends on the
  dialer with `ErrSessionLost` instead of its `*AbortError`; only the
  passive's status shows the reason.
- A duplicate JOIN on a dedicated carrier, or for the first session of a
  shared one, is answered BAD_REQUEST without a code.
- Abandoned `l4.Server` Dial hook calls may outlive `Serve` (counted in
  `ServerStatus.Abandoned`).

Test coverage:

- Two deliberately injected race-mode defects go undetected by the
  race-mode scenario tests, and replayed-frame tests reach the edges of
  the receive window only by chance.
- The scenario packages' flake sweeps were smaller than planned.

### Dependencies

The root module: `golang.org/x/sys` v0.47.0 (BSD-3-Clause).

The QUIC module (`github.com/FrankoonG/rendr/quic/v2`):

| Dependency | Version | Licence |
|---|---|---|
| `github.com/quic-go/quic-go` | v0.63.0 | MIT |
| `golang.org/x/crypto` | v0.54.0 | BSD-3-Clause |
| `golang.org/x/net` | v0.56.0 | BSD-3-Clause |
| `golang.org/x/sys` | v0.47.0 | BSD-3-Clause |

All are compatible with rendr's GPL-3.0.

### Upgrading

There is no in-place upgrade from rendr v1 or v0.x: the module path, the
API and the wire format are new, and a 2.x end does not talk to an older
one. Port the embedding to the 2.0 API (one `Runtime` per instance, a
`Peer` per destination, carrier factories, `Listener` with `Confirm` and
`Reject`) and deploy both ends together.
