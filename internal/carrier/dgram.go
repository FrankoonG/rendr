package carrier

import (
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// newDatagramConn returns an unstarted datagram carrier over io (M2-D3; M2
// design Revision 1, R1-7): newConn without an embedder net.Conn whose
// closer, deadline part and last-resort close act on io through ncClose,
// so no close of a datagram Conn ever goes through a nil conn. The
// handshakes (dgestablish.go, dghello.go) build every datagram Conn with
// it and then fill dg: budget and receive limit, windows, the REL start
// values of R1-3, the handshake bytes and, on the dialer, the response
// datagram's tail (R1-1).
func newDatagramConn(env *Env, io PacketIO, id uint32, peer [16]byte, factory int, name string, dialer bool) *Conn {
	c := newConn(env, nil, id, peer, factory, name, dialer)
	c.ncClose.nc = io
	c.dg = &dgState{io: io}
	return c
}

// dgState is the datagram half of a Conn (M2-D3): set by the datagram
// handshakes, nil on stream carriers. The Conn's lifecycle, death record,
// joins, closer, watchdog, PING records and estimator are shared with
// stream carriers; the reader (dgread.go), the writer's packing and
// physical write (dgwrite.go), the REL sublayer (rel.go), the MTU probe and
// the rebind challenge (dgprobe.go) and the handshakes (dgestablish.go,
// dghello.go) live in their own files. Ownership marks: (I) immutable after
// the handshake, (R) reader goroutine, (W) writer goroutine, (M) under
// Conn.mu, (A) atomic.
//
// The sub-state types are declared empty by the M2 skeleton in the files of
// the work packages that fill them (M2 design §A11): dgHandshake in
// dghello.go, relState in rel.go, dgProbe and dgChallenge in dgprobe.go.
type dgState struct {
	io        PacketIO     // (I) the transport; ncClose closes it exactly once (R1-7)
	recvLimit int          // (I) the negotiated cmtu: the reader accepts datagrams up to it (io.SetLimit; buffer io.ReadSize() = recvLimit + Headroom + 1, R1-6)
	budget    atomic.Int32 // (A) the send frame budget: the negotiated cmtu, only ever lowered (M2-D25)

	// tail (dialer, I until Start, then R) holds the rendr bytes that
	// followed the response frame in the response datagram — frames the
	// passive packed behind its first response (a first PING, DGRAMs that
	// Confirm released): Establish copies them here and the reader walks
	// them as the rest of that datagram (header, CRC, fseq window,
	// dispatch) before its first ReadDatagram, so nothing the passive sent
	// with its response is lost (M2 design Revision 1, R1-1). Nil after.
	tail []byte

	rwin          wire.FseqWindow // (R) receive anti-replay window (M2-D13)
	peerClosed    bool            // (R) the peer's CLOSE was dispatched (M2-D30)
	peerCloseFseq uint32          // (R) its fseq: later non-RACK frames are dropped

	// The datagram retirement (M2-D31, R1-4): it completes when our CLOSE
	// was RACKed, the peer's CLOSE was dispatched and a datagram carrying a
	// RACK that covers the peer's CLOSE was written.
	peerCloseSeen   bool          // (M) the peer's CLOSE was dispatched
	peerCloseCseq   uint32        // (M) its cseq
	peerCloseRacked bool          // (M) a written datagram carried a RACK covering it
	peerCloseReason atomic.Uint32 // (A) its reason (R1-3; 0: none yet)

	held atomic.Bool // (A) a held passive carrier has not placed its first response yet (M2-D22, R1-14)

	lastDgram atomic.Int64 // (A) ns after Conn.base of the last DGRAM written or read: packet activity (M2-D23)

	hs    dgHandshake // (I/M) stored PREFACE / PREFACE_ACK / H2 bytes, H2 repeat flag (M2-D19)
	rel   relState    // (M) REL sender and receiver (M2-D16, M2-D17)
	probe dgProbe     // (M) MTU probe bookkeeping and PING retry (M2-D23, M2-D24)
	chal  dgChallenge // (M) rebind challenge (passive flows) and the challenge-PONG slot (M2-D27)
	ctr   dgCounters  // (A) per-carrier datagram counters (Stats)
}

// dgCounters are a datagram carrier's counters, reported through Stats.
type dgCounters struct {
	datagrams   atomic.Uint64 // datagrams written
	datagramsRx atomic.Uint64 // datagrams read and handed over
	dropped     atomic.Uint64 // datagrams and frames dropped (M2-D14)
	truncated   atomic.Uint64 // of dropped: truncated or oversize
	refused     atomic.Uint64 // DGRAMs lost in datagrams the transport refused as too large
	retransmits atomic.Uint64 // REL and H1 retransmissions
	rebinds     atomic.Uint64 // committed rebinds
}

// PeerCloseReason returns the reason of the peer's CLOSE once the reader
// dispatched it, and true; false before (M2 design Revision 1, R1-3). A
// datagram probe carrier learns a CLOSE(capacity) only after Establish
// returned on the probe's PONG, so the health layer reads it here to record
// the probe failure with reason "capacity" (plan:175). Stream carriers
// learn a capacity refusal as Establish's response and report false.
func (c *Conn) PeerCloseReason() (wire.CloseReason, bool) {
	if c.dg == nil {
		return 0, false
	}
	r := c.dg.peerCloseReason.Load()
	return wire.CloseReason(r), r != 0
}

// dgDropped counts n dropped datagrams or frames (M2-D14) on the carrier
// and in the Runtime-wide counters.
func (c *Conn) dgDropped(n uint64) {
	c.dg.ctr.dropped.Add(n)
	if s := c.env.Dgram; s != nil {
		s.Dropped.Add(n)
	}
}

// dgTruncated counts one truncated or oversize datagram (a drop too).
func (c *Conn) dgTruncated() {
	c.dg.ctr.truncated.Add(1)
	if s := c.env.Dgram; s != nil {
		s.Truncated.Add(1)
	}
	c.dgDropped(1)
}

// dgReadError counts one transient read error (ReadNoise).
func (c *Conn) dgReadError() {
	if s := c.env.Dgram; s != nil {
		s.ReadErrors.Add(1)
	}
}

// dgSince returns the nanoseconds after Conn.base at now, at least 1 (0
// marks "never" in the activity clocks).
func (c *Conn) dgSince(now time.Time) int64 {
	return max(int64(now.Sub(c.base)), 1)
}

// packetActive reports whether the carrier is packet-active at now (M2-D23):
// a DGRAM was written or read within PacketActive, or the carrier is
// younger than packetYouth.
func (c *Conn) packetActive(now time.Time) bool {
	age := now.Sub(c.base)
	if age < packetYouth {
		return true
	}
	last := c.dg.lastDgram.Load()
	return last != 0 && age-time.Duration(last) < c.tm.PacketActive
}

// packetYouth keeps a new datagram carrier on the PacketPing cadence for its
// first seconds (M2-D23: "or the carrier younger than 5 s").
const packetYouth = 5 * time.Second
