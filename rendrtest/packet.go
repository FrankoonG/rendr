package rendrtest

import (
	"net"
	"sync/atomic"
	"time"
)

// Packet behaviours and the packet verifier (M2 design §A8.1). A test
// datagram is a 24-byte header — seq u64, send time u64 (ns of the test
// clock), length u32, CRC-32C u32 of the whole datagram with this field
// zeroed — followed by a PRNG body derived from (seed, seq). The verifier
// checks exact sizes (L36), content, duplicates and missing seqs (L39).

// PacketHeaderLen is the size of a test datagram's header; the smallest
// test datagram.
const PacketHeaderLen = 24

// PacketBehaviour is a far-end behaviour on a packet session (a
// *rendr.PacketConn is a net.PacketConn).
type PacketBehaviour func(pc net.PacketConn) error

// PacketEcho returns each datagram unchanged to its source until the
// session ends; io.EOF is a clean end.
func PacketEcho() PacketBehaviour { panic("unimplemented: M2") }

// PacketSink reads and counts datagrams until io.EOF.
func PacketSink(count *atomic.Int64) PacketBehaviour { panic("unimplemented: M2") }

// PacketGenConfig configures PacketGen.
type PacketGenConfig struct {
	Seed  uint64
	Size  int     // datagram size, ≥ PacketHeaderLen
	Count int     // datagrams to send
	Rate  float64 // datagrams per second (0: as fast as WriteTo returns)
}

// PacketGen sends Count test datagrams to pc's peer at Rate, recording
// every WriteTo result, then returns; it never closes pc.
func PacketGen(cfg PacketGenConfig, pc net.PacketConn, peer net.Addr) PacketGenResult {
	panic("unimplemented: M2")
}

// PacketGenResult is what PacketGen did.
type PacketGenResult struct {
	Sent     int           // WriteTo calls that returned (n, nil)
	Errors   int           // WriteTo calls that returned an error
	FirstErr error         // the first such error
	MaxWrite time.Duration // the longest WriteTo call (L40: never blocks)
}

// PacketPayload fills dst[:size] with test datagram seq of seed sent at t
// and returns it.
func PacketPayload(dst []byte, seed, seq uint64, size int, t time.Time) []byte {
	panic("unimplemented: M2")
}

// PacketVerifier checks received test datagrams of one generator.
type PacketVerifier struct {
	seed uint64
}

// NewPacketVerifier returns a verifier for datagrams of seed.
func NewPacketVerifier(seed uint64) *PacketVerifier { return &PacketVerifier{seed: seed} }

// Add verifies one received datagram (b exactly as ReadFrom returned it)
// arriving at t; it returns an error for a corrupt or wrongly sized one and
// counts duplicates.
func (v *PacketVerifier) Add(b []byte, t time.Time) error { panic("unimplemented: M2") }

// Result returns the verdict so far.
func (v *PacketVerifier) Result() PacketResult { panic("unimplemented: M2") }

// PacketResult is a PacketVerifier's verdict.
type PacketResult struct {
	Unique, Duplicates, Corrupt, BadSize uint64
	Highest                              uint64     // the highest seq received
	Missing                              []SeqRange // seqs below Highest never received, ascending
	MaxGap                               time.Duration
}

// SeqRange is the closed range [From, To] of seqs.
type SeqRange struct{ From, To uint64 }
