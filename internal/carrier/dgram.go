package carrier

import (
	"sync/atomic"

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
	panic("unimplemented: M2")
}
