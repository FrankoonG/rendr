package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The packet data plane (M2 design §A5.1–§A5.6; M2-D1, M2-D32…M2-D45). A
// packet session is a Session whose pk is set: the actor, lanes, SCHED,
// death handling, no-path episodes, pending verdicts, deadlines, the
// DONE-based termination and the status snapshot are the stream session's;
// the generic stream fields (closed/ended/endErr, fin, peerFin*,
// finDelivSent, doneQueued/doneSent/peerDone/doneSentAt, rstIn, exhausted,
// facts, lastData, the waiters, the deadlines, the ACK-duty machinery —
// which places PACK — order, echoIn) serve both kinds. Everything below is
// (S): written by data-path code under Session.mu.
//
// File map (WP6a): pkt_queue.go the packed queue (pring); pkt_app.go
// WriteTo and ReadFrom; pkt_fill.go Fill, the wake policy and the routing
// helpers; pkt_recv.go the DGRAM hand-over; pkt_pack.go PACK placement,
// cadence and receipt; pkt_end.go Close, the peer's FIN, the end and
// ageing.

// packet is a packet session's data-plane state.
type packet struct {
	maxPayload int // fixed when the OPEN exchange completed (immutable afterwards; read without the lock)

	tx    pring // datagrams accepted by WriteTo, not yet placed (M2-D32)
	txBig pring // mixed bond: datagrams above every live datagram lane's DgramMax, pulled by stream lanes only (M2-D43)
	rx    pring // datagrams accepted from carriers, not yet returned by ReadFrom

	nextSeq uint64         // next seq to assign at placement (M2-D34)
	dedup   wire.SeqWindow // receive dedup (M2-D36)
	ctr     PacketCounters // this side's counters (Status)
	rxHigh  uint64         // highest seq accepted (valid when rxCount > 0): PACK.highestSeq
	rxCount uint64         // distinct seqs accepted: PACK.received
	rxSince int            // datagrams accepted since the last PACK placed (PackEvery)
	peerHi  uint64         // merged PACK highestSeq of the peer (max)

	finWaitAt time.Time    // EOF straggler bound after the peer's FIN (M2-D40)
	noPathEnd time.Time    // end of the latest no-path episode: DropNoPath vs DropAge (M2-D35)
	finPlaced bool         // our FIN was placed once: st.fin.off holds the final seq
	dgMax     int          // the largest DgramMax over live datagram data lanes (0: none; routing, M2-D43, M2-D45)
	dgMin     int          // the smallest DgramMax over live datagram data lanes (0: none): pdesc.wide (W4-REL-5)
	mixed     bool         // bond with live datagram data lanes and a stream member (a data lane, or one awaiting its SCHED): WriteTo puts datagrams above dgMax in txBig
	bigHeld   bool         // mixed by stream members awaiting their SCHED only: txBig waits for one, aged by the actor (C4-F2)
	rcopy     *carrier.Buf // a datagram ReadFrom detached and copies outside the lock (L07: released at its commit)
	copies    uint64       // race sender: extra placements of datagrams another lane already placed (Race.Copies, M3-D35)

	base        time.Time // immutable: the origin of pdesc.at (monotonic)
	stale       *lane     // bond minimum share (R1-19): the lane found stale, remembered until it places a DGRAM
	staleScanAt time.Time // when the stale scan last ran (at most once per PacketPing/8)
}

// pring is a packed datagram queue (M2-D32): datagrams copied once into
// refcounted 64 KiB chunks (Env.Bufs, ChunkSize class, charged to
// Env.Budget with TryGet) and described by a power-of-two descriptor ring
// that grows to at most Queue/64 entries and never shrinks during the
// session. Its own charge is Σ max(len, 64) over queued descriptors against
// Packet.Queue. A datagram of 16 KiB or more is copied outside the lock
// into its own Buf (ext). Its methods live in pkt_queue.go.
type pring struct {
	chunks []*carrier.Buf // chunk ring; chunk numbers are absolute (cbase + index)
	cbase  uint32         // absolute number of chunks[chead]
	chead  int
	cn     int
	tail   int // bytes used in the newest chunk

	desc []pdesc // descriptor ring
	head int
	n    int

	// Race (M3-D32; pkt_race.go): pos is the absolute position of the head
	// descriptor (the descriptors popped so far), the frame of the lanes'
	// cursors; seq, parallel to desc and allocated by a race session's
	// first Fill only, holds 1 + the seq a descriptor got at its first
	// placement (0: never placed), which its copies reuse.
	pos uint64
	seq []uint64

	charge int64 // Σ max(len, 64) of queued descriptors
	bytes  int64 // Σ len of queued descriptors (pendingBytes)
	max    int64 // Packet.Queue
	maxN   int   // Packet.Queue / 64
}

// pdesc describes one queued datagram.
type pdesc struct {
	chunk uint32       // absolute chunk number (an ext datagram carries the newest chunk's number at its push, so the numbers never decrease along the queue)
	off   uint32       // offset in the chunk
	n     uint32       // length (0 is a legal empty datagram)
	wide  bool         // tx: above the smallest live datagram data lane's DgramMax at its push (pk.dgMin): a mixed-budget head, not one a budget shrink left behind (W4-REL-5)
	at    int64        // enqueue time, ns since the session's base
	ext   *carrier.Buf // a big datagram in its own Buf (B is exactly the datagram)
}

// plane is the carrier.PacketEndpoint of a packet session's lane (M2-D2):
// the lane value under another method set, so stream lanes keep their
// methods and both dispatch statically.
type plane lane

var _ carrier.PacketEndpoint = (*plane)(nil)

// Handle implements carrier.Endpoint.
func (p *plane) Handle() uint32 { return wire.SessionHandle }

// Fill implements carrier.Endpoint: the packet Fill (M2 design §A5.2).
func (p *plane) Fill(c *carrier.Conn, b *carrier.Batch) {
	l := (*lane)(p)
	s := l.s
	s.mu.Lock()
	s.fillPacketLocked(l, b)
	s.mu.Unlock()
}

// Data implements carrier.Endpoint: DATA on a packet session is a
// violation of the delivering carrier (buf released).
func (p *plane) Data(c *carrier.Conn, off uint64, d []byte, buf *carrier.Buf) error {
	buf.Release()
	return errDataOnPacket
}

// Datagram implements carrier.PacketEndpoint (M2 design §A5.3).
func (p *plane) Datagram(c *carrier.Conn, seq uint64, d []byte, buf *carrier.Buf) error {
	s := p.s
	s.mu.Lock()
	err := s.datagramLocked(seq, d, buf)
	s.mu.Unlock()
	return err
}

// Control implements carrier.Endpoint: PACK, FIN, RST and (passive) SCHED;
// ACK is a violation.
func (p *plane) Control(c *carrier.Conn, h wire.Header, d []byte) error {
	s := p.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.ended {
		return nil // the session is over; its carriers are being retired
	}
	if h.Type == wire.TypeRst {
		return s.rstLocked(d)
	}
	if s.pendingLocked() {
		return errDataBeforeOpen // only RST may precede the verdict
	}
	switch h.Type {
	case wire.TypePack:
		pa, err := wire.ParsePack(d)
		if err != nil {
			return err
		}
		return s.packLocked(h.Flags, &pa)
	case wire.TypeFin:
		final, err := wire.ParseFin(d)
		if err != nil {
			return err
		}
		return s.pktFinLocked(final)
	case wire.TypeSched:
		return s.schedLocked(h.Flags, d)
	case wire.TypeAck:
		return errAckOnPacket
	}
	return errUnexpectedFrame
}

// WriteBlocked implements carrier.Endpoint, as lane.WriteBlocked (the PACK
// duty moves).
func (p *plane) WriteBlocked(c *carrier.Conn) {
	l := (*lane)(p)
	s := l.s
	s.mu.Lock()
	st := &s.st
	if st.ackLane == l {
		if n := s.chooseAckLaneLocked(l); n != nil && !n.port.WriteBlocked() {
			st.ackLane = n
			if n.ackSent != st.ackGen || !st.ackDelayAt.IsZero() {
				n.idle = false
				n.port.Wake()
			}
		}
	}
	if s.p.Mode.members() && !st.ended {
		s.pktWakeLocked(time.Now()) // queued datagrams go to the other members
	}
	st.facts |= factWriteBlocked
	s.mu.Unlock()
	s.ringActor()
}

// endpoint returns the carrier endpoint of lane l (M2-D2): (*plane)(l) for
// a packet session, l itself for a stream session. Every Conn.Start of a
// session lane passes it.
func (s *Session) endpoint(l *lane) carrier.Endpoint {
	if s.pk != nil {
		return (*plane)(l)
	}
	return l
}

// pktPort is the part of a datagram carrier the packet plane reads on a
// lane's port: *carrier.Conn implements it (a stream Conn reports
// KindStream), and so do the packet tests' fake ports. A port without it
// (the stream tests' fakes) is a stream lane.
type pktPort interface {
	Kind() wire.CarrierKind
	DgramMax() int
	RelRoom() int
}

// pktDgramLane returns l's datagram view when l rides a datagram carrier.
func pktDgramLane(l *lane) (pktPort, bool) {
	if pp, ok := l.port.(pktPort); ok && pp.Kind() == wire.KindDatagram {
		return pp, true
	}
	return nil, false
}

// Packet parameter defaults: Params is normalized by package rendr; these
// keep a partially filled PacketParams (unit tests) well defined.
const (
	defPacketQueue  = 1 << 20
	defPacketMaxAge = 100 * time.Millisecond
	defPacketPing   = time.Second
	defPackEvery    = 256
	defFinWaitMax   = time.Second
	// finWaitMin is the lower clamp of the EOF straggler wait (M2-D40).
	finWaitMin = 50 * time.Millisecond
	// pktChargeMin is the least a queued datagram is charged (Q5).
	pktChargeMin = 64
)

func (s *Session) pktPing() time.Duration {
	if v := s.p.Packet.PacketPing; v > 0 {
		return v
	}
	return defPacketPing
}

func (s *Session) pktMaxAge() time.Duration {
	if v := s.p.Packet.MaxAge; v > 0 {
		return v
	}
	return defPacketMaxAge
}

func (s *Session) pktPackEvery() int {
	if v := s.p.Packet.PackEvery; v > 0 {
		return v
	}
	return defPackEvery
}

func (s *Session) pktFinWaitMax() time.Duration {
	if v := s.p.Packet.FinWaitMax; v > 0 {
		return v
	}
	return defFinWaitMax
}

// The WP6a functions WP6b's actor code calls (M2 design §A5.1, §A11.5 and
// Revision 1, R1-20, R1-22). Each is called with s.mu held.

// initPacketLocked initialises the packet plane after initStreamLocked's
// generic part: rings with max = Queue and maxN = Queue/64, the dedup
// storage (DedupBits/64 words), nextSeq = FirstSeq; maxPayload from
// PassiveSpec.MaxPayload on the passive (R1-32) or 0 on the dialer until
// its OPEN_ACK fixed it. The passive's value arrives as
// Params.Packet.MaxPayload (the accepted value, types.go). It allocates
// s.pk when the caller has not.
func (s *Session) initPacketLocked() {
	if s.pk == nil {
		s.pk = &packet{}
	}
	pk := s.pk
	q := int64(s.p.Packet.Queue)
	if q <= 0 {
		q = defPacketQueue
	}
	maxN := int(max(q/pktChargeMin, 1))
	pk.tx.init(q, maxN)
	pk.txBig.init(q, maxN)
	pk.rx.init(q, maxN)
	bits := wire.DefaultSeqWindowBits
	if v := s.p.Packet.DedupBits; v > 0 {
		bits = 1024
		for bits < v {
			bits <<= 1
		}
	}
	pk.dedup.Init(make([]uint64, bits/64))
	pk.nextSeq = s.p.Packet.FirstSeq
	if s.p.Role == RolePassive {
		pk.maxPayload = s.p.Packet.MaxPayload
	}
	pk.base = time.Now()
}

// pktWakeLocked wakes the data lanes the wake policy selects for queued
// datagrams (§A5.2 with R1-19's minimum share in bond mode). The body is
// in pkt_fill.go.
func (s *Session) pktWakeLocked(now time.Time) {
	s.pktWakeDataLocked(now)
}

// pktRecomputeLocked recomputes pk.dgMax, pk.mixed and pk.bigHeld from
// the live lanes (every routing change, and when a passive bond member is
// confirmed; §A5.2) and drops txBig when no stream member is left.
func (s *Session) pktRecomputeLocked() {
	s.pktRouteLocked()
}

// pktMemberConfirmedLocked is called by lanesConfirmedLocked when a lane
// that joined an open passive session was confirmed (its JOIN_ACK placed;
// Status lists it as a member from this step). A packet bond member carries data only from the
// dialer's SCHED that lists it (plan:147); until then it awaits it
// (awaitSched) and the datagrams only a stream lane can carry wait for it
// in txBig within MaxAge (C4-F2, pktRouteLocked) instead of being dropped
// as too large. The routing summary changes in the same step as the
// Status (L27).
func (s *Session) pktMemberConfirmedLocked(l *lane) {
	if s.pk == nil || s.p.Mode != ModeBond || s.st.ended {
		return
	}
	l.awaitSched = true
	s.pktRouteLocked()
}

// pktCloseLocked is Session.Close for a packet session (§A5.6): requests
// the FIN, discards the receive queue, wakes both waiters and the lanes.
func (s *Session) pktCloseLocked(now time.Time) {
	s.pktCloseAppLocked(now)
}

// pktEndLocked releases the packet rings at the session's end (a datagram
// a ReadFrom detached stays with it), counts still-queued tx datagrams as
// DropQueue and wakes every waiter (§A5.1 endLocked).
func (s *Session) pktEndLocked() {
	s.pktReleaseLocked()
}

// pktPeerFinCheckLocked delivers the peer's FIN once nothing more can come
// (§A5.6, L40): the receive queue is empty and every seq below the final
// one was accepted, or finWaitAt passed.
func (s *Session) pktPeerFinCheckLocked(now time.Time) {
	s.pktFinCheckLocked(now)
}

// pktPackCadenceLocked accounts one accepted datagram for the PACK
// cadence (§A5.5): urgent at PackEvery, else armed PacketPing after the
// first unreported datagram.
func (s *Session) pktPackCadenceLocked() {
	s.packCadenceLocked()
}

// pktDgramRecentLocked reports whether lane l placed a DGRAM within the
// last PacketPing (bond death counting, M2-D44; laneGoneLocked).
func (s *Session) pktDgramRecentLocked(l *lane, now time.Time) bool {
	return !l.lastDgramAt.IsZero() && now.Sub(l.lastDgramAt) < s.pktPing()
}

// pktAgeLocked drops the queued tx datagrams older than MaxAge (DropNoPath
// or DropAge per M2-D35) and returns when the next queued one ages out
// (zero: none queued). The actor calls it while no data lane exists and
// arms a deadline at the returned time (§A5.2, R1-22).
func (s *Session) pktAgeLocked(now time.Time) time.Time {
	return s.pktAgeOutLocked(now)
}

// fillPackLocked is the packet branch of fillControlLocked's duty-lane
// step (§A5.5): places the PACK when due, REL-wrapped when reliable; a
// reliable PACK that a datagram batch refused for lack of REL room
// (b.Datagram() && b.RelRoom() == 0: a stream batch reports no REL room
// whatever it holds, and its refusal never moves the duty) hands the duty
// to a live lane with REL room (R1-17, as amended at integration 1).
func (s *Session) fillPackLocked(l *lane, b *carrier.Batch) {
	s.placePackLocked(l, b)
}

// Kind returns the session kind (wire.KindStream or wire.KindDatagram).
func (s *Session) Kind() wire.CarrierKind {
	if s.pk != nil {
		return wire.KindDatagram
	}
	return wire.KindStream
}

// MaxPayload returns a packet session's MaxPayload, fixed by the OPEN
// exchange (M2-D49); 0 for stream sessions.
func (s *Session) MaxPayload() int {
	if s.pk == nil {
		return 0
	}
	return s.pk.maxPayload
}

// WriteTo queues p as one datagram (M2 design §A5.2) and returns at once:
// (len(p), nil) also when a bound dropped a datagram (counted, L40);
// (0, ErrPacketTooLarge) above MaxPayload; net.ErrClosed after Close or
// after the peer's FIN; the end error after the end; (0,
// os.ErrDeadlineExceeded) past the write deadline, with nothing queued
// (L06). The root checks the destination address first. The body is in
// pkt_app.go.
func (s *Session) WriteTo(p []byte) (int, error) {
	return s.writeTo(p)
}

// ReadFrom copies the next datagram into p (M2 design §A5.3): (n, nil);
// (len(p), io.ErrShortBuffer) when it is longer, the rest discarded (L36);
// io.EOF once the peer's FIN was delivered and the queue is empty (plan
// §6); net.ErrClosed after Close; the end error after a failure;
// os.ErrDeadlineExceeded after the read deadline. The copy runs outside the
// session lock and a commit decides "ReadFrom won / Close won" as Read does
// (L07, M2-D38). The body is in pkt_app.go.
func (s *Session) ReadFrom(p []byte) (int, error) {
	return s.readFrom(p)
}
