package carrier

import (
	"sync/atomic"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

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
	io        PacketIO     // (I) the transport
	recvLimit int          // (I) the negotiated cmtu: the reader accepts datagrams up to it (buffer recvLimit + Headroom + 1)
	budget    atomic.Int32 // (A) the send frame budget: the negotiated cmtu, only ever lowered (M2-D25)

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
