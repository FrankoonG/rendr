package rendrtest

import (
	"context"
	"net"
	"time"
)

// M2 frame types for frame-targeted controls (values equal the wire
// format's type bytes). A datagram control matching FrameRel matches every
// REL; matching a wrapped type (FrameFin, FrameSched, FrameOpenAck, …) also
// looks inside REL frames.
const (
	FrameDgram FrameType = 0x20
	FramePack  FrameType = 0x21
	FrameRel   FrameType = 0x34
	FrameRack  FrameType = 0x35
)

// DialNilAddr makes a datagram factory return (pc, nil, nil): rendr must
// close pc once and count a failed dial (L51).
const DialNilAddr DialBehavior = 8

// MTUMode selects what a datagram link does with a datagram above its MTU.
type MTUMode uint8

// MTU modes.
const (
	MTUDrop   MTUMode = 1 // the datagram is silently lost (a path MTU black hole)
	MTURefuse MTUMode = 2 // WriteTo returns a *wire.DatagramTooLargeError{Max: MTU} (an embedder conn that knows its limit)
)

// DatagramLinkConfig configures a DatagramLink.
type DatagramLinkConfig struct {
	// Name is the link's name (and its jitter and loss seed).
	Name string
	// Accept receives the passive end of every new carrier, typically
	// (*rendr.Listener).HandlePacket. It must return; on an error (or when
	// nil) the passive end is closed.
	Accept func(pc net.PacketConn, peer net.Addr) error
	// MTU is the largest datagram carried (default 65,507); see SetMTU.
	MTU int
	// Queue is how many datagrams per direction may wait in the link
	// (default 1024); more are tail-dropped and counted as lost.
	Queue int
}

// DatagramLink is an in-memory datagram path (M2 design §A8.1; plan:637):
// every Dial creates one carrier, a pair of net.PacketConns built from
// channels and timers with distinct fake *net.UDPAddr addresses, whose
// passive end is pushed into Accept. Each direction applies delay and
// jitter (reordering allowed: datagrams are independent), a rate limit
// shared by the link's carriers, random or targeted loss, duplication,
// reordering, an MTU, blackhole and stall; conn misbehaviour (scripted
// write counts, read faults, truncation, foreign sources) and factory
// misbehaviour (DialBehavior, DialNilAddr) test rendr's distrust of
// embedder conns. Every control is counted (Stats), split into all, session
// and probe carriers (classified by the first datagram: PREFACE ‖ REL{OPEN
// or JOIN} = session, PREFACE ‖ PING = probe) for stimulus proofs (L63).
//
// Create a DatagramLink inside the synctest bubble that uses it; Close it
// before the bubble ends. Datagrams carry no flow header: a DatagramLink
// serves Listener.HandlePacket. DatagramHub serves FromPacketConn.
type DatagramLink struct {
	cfg DatagramLinkConfig
}

// NewDatagramLink returns a link; nothing runs until the first Dial.
func NewDatagramLink(cfg DatagramLinkConfig) *DatagramLink {
	panic("unimplemented: M2")
}

// Name returns the link's name.
func (l *DatagramLink) Name() string { return l.cfg.Name }

// Dial is a rendr.DatagramCarrier.Dial (tests build rendr.DatagramCarrier{
// Name, Dial: l.Dial, MTU} themselves: rendrtest never imports rendr).
func (l *DatagramLink) Dial(ctx context.Context) (net.PacketConn, net.Addr, error) {
	panic("unimplemented: M2")
}

// SetDelay sets the one-way delay and jitter of direction d (per datagram;
// reordering follows from the jitter).
func (l *DatagramLink) SetDelay(d Dir, delay, jitter time.Duration) { panic("unimplemented: M2") }

// SetRate limits direction d to bytesPerSec (0: unlimited), one bottleneck
// shared by the link's carriers.
func (l *DatagramLink) SetRate(d Dir, bytesPerSec float64) { panic("unimplemented: M2") }

// SetLoss drops each datagram of direction d with probability p (seeded).
func (l *DatagramLink) SetLoss(d Dir, p float64) { panic("unimplemented: M2") }

// SetDuplicate delivers each datagram of direction d twice with probability p.
func (l *DatagramLink) SetDuplicate(d Dir, p float64) { panic("unimplemented: M2") }

// SetReorder delays each datagram of direction d by extra with probability p.
func (l *DatagramLink) SetReorder(d Dir, p float64, extra time.Duration) { panic("unimplemented: M2") }

// SetMTU sets the largest datagram both directions carry and what happens
// to a larger one.
func (l *DatagramLink) SetMTU(n int, mode MTUMode) { panic("unimplemented: M2") }

// Blackhole drops (on) or passes (off) every datagram of direction d.
func (l *DatagramLink) Blackhole(d Dir, on bool) { panic("unimplemented: M2") }

// Stall holds (on) or releases (off) direction d: datagrams queue up to
// Queue, WriteTo keeps returning.
func (l *DatagramLink) Stall(d Dir, on bool) { panic("unimplemented: M2") }

// Kill fails every current carrier of the link: both conns return
// net.ErrClosed from then on.
func (l *DatagramLink) Kill() { panic("unimplemented: M2") }

// Refuse makes later Dials fail (on) or succeed (off).
func (l *DatagramLink) Refuse(on bool) { panic("unimplemented: M2") }

// SetDialBehavior makes later Dials misbehave (DialBehavior, DialNilAddr).
func (l *DatagramLink) SetDialBehavior(b DialBehavior) { panic("unimplemented: M2") }

// Release ends a hanging Dial (DialHang, DialHangForever, DialLateSuccess).
func (l *DatagramLink) Release() { panic("unimplemented: M2") }

// DropNext drops the next n datagrams of direction d that carry a frame of
// type t (inside REL as well).
func (l *DatagramLink) DropNext(d Dir, t FrameType, n int) { panic("unimplemented: M2") }

// CorruptNext flips one bit of the next datagram of direction d.
func (l *DatagramLink) CorruptNext(d Dir) { panic("unimplemented: M2") }

// InjectRaw delivers b as one datagram in direction d on the newest
// carrier.
func (l *DatagramLink) InjectRaw(d Dir, b []byte) { panic("unimplemented: M2") }

// CaptureNext returns a copy of the next datagram of direction d that
// carries a frame of type t.
func (l *DatagramLink) CaptureNext(d Dir, t FrameType) <-chan []byte { panic("unimplemented: M2") }

// ScriptWrites makes the next WriteTo calls of side d's conns (Up = the
// dialer's) return the given results, as Link.ScriptWrites (L42).
func (l *DatagramLink) ScriptWrites(d Dir, rs ...WriteResult) { panic("unimplemented: M2") }

// ReadFaults makes the next ReadFrom calls of side d's conns return the
// given errors before any datagram (ICMP-class or permanent, L58).
func (l *DatagramLink) ReadFaults(d Dir, errs ...error) { panic("unimplemented: M2") }

// TruncateNext makes the next ReadFrom of side d report a truncated
// datagram: Linux style (n == len(p), nil) or Windows style (n == len(p)
// with a *net.OpError wrapping syscall.Errno(10040), WSAEMSGSIZE, on every
// OS: rendr classifies embedder errors by one platform-independent table,
// M2 design Revision 1, R1-28).
func (l *DatagramLink) TruncateNext(d Dir, windows bool) { panic("unimplemented: M2") }

// ForeignNext delivers the next datagram of direction d from another
// address (L59).
func (l *DatagramLink) ForeignNext(d Dir) { panic("unimplemented: M2") }

// Stats returns the link's counters.
func (l *DatagramLink) Stats() DatagramStats { panic("unimplemented: M2") }

// Close kills every carrier and joins every goroutine the link started.
func (l *DatagramLink) Close() error { panic("unimplemented: M2") }

// DatagramCounts count one class of carriers of a datagram link or hub.
type DatagramCounts struct {
	Sent, Delivered, Lost, Duplicated, Reordered uint64
	Oversize, Injected, Corrupted, Truncated     uint64
	Foreign, ScriptedWrites, ReadFaults          uint64
}

// DatagramStats are a datagram link's or hub's counters.
type DatagramStats struct {
	All, Session, Probe DatagramCounts
	Dials, DialFailures uint64
	Carriers            int // carriers created
	Rebinds, Spoofed    uint64
}

// DatagramHubConfig configures a DatagramHub.
type DatagramHubConfig struct {
	Name  string
	MTU   int // largest datagram (default 65,507)
	Queue int // datagrams queued per client and direction (default 1024)
}

// DatagramHub is an in-memory shared datagram socket (M2 design §A8.1):
// PacketConn is the passive socket for rendr.FromPacketConn; every Dial is
// a client endpoint with its own fake address whose conn adds rendr's
// raw-UDP flow header (a fresh flow ID per Dial) to every datagram it sends
// and strips it from every datagram it receives, as carrier/udp's sockets
// do. Rebind, Spoof, Replay and Flood exercise the demultiplexer inside a
// synctest bubble (L58, L59); real-socket twins of those tests run outside
// bubbles.
type DatagramHub struct {
	cfg DatagramHubConfig
}

// NewDatagramHub returns a hub.
func NewDatagramHub(cfg DatagramHubConfig) *DatagramHub {
	panic("unimplemented: M2")
}

// PacketConn returns the hub's passive socket (pass it to
// rendr.FromPacketConn).
func (h *DatagramHub) PacketConn() net.PacketConn { panic("unimplemented: M2") }

// Dial is a rendr.DatagramCarrier.Dial: a new client endpoint.
func (h *DatagramHub) Dial(ctx context.Context) (net.PacketConn, net.Addr, error) {
	panic("unimplemented: M2")
}

// SetLoss drops datagrams of direction d with probability p.
func (h *DatagramHub) SetLoss(d Dir, p float64) { panic("unimplemented: M2") }

// SetDelay sets the one-way delay and jitter of direction d.
func (h *DatagramHub) SetDelay(d Dir, delay, jitter time.Duration) { panic("unimplemented: M2") }

// Rebind makes later datagrams of client i (in Dial order) arrive from a
// new address, as a NAT rebinding; replies to the old address are lost.
func (h *DatagramHub) Rebind(i int) { panic("unimplemented: M2") }

// Spoof delivers b to the passive socket from a fresh foreign address.
func (h *DatagramHub) Spoof(b []byte) { panic("unimplemented: M2") }

// Replay re-delivers the k-th datagram client i sent (0 = its first) from
// a fresh foreign address (L59: a replay must not move the reply address).
func (h *DatagramHub) Replay(i, k int) { panic("unimplemented: M2") }

// FloodMix is the share of each datagram class of a flood (percent).
// Preface is a valid OPEN first datagram, Join a valid JOIN first datagram
// (random session and flow IDs; R1-21: JOIN and probe flows have their own
// per-source quota).
type FloodMix struct {
	Random, BadCRC, Preface, Join int
}

// Flood sends rate datagrams per second to the passive socket from
// rotating foreign addresses: random bytes, valid flow headers with a bad
// frame CRC, and valid first datagrams (OPEN or JOIN) with random IDs
// (L58). stop ends it.
func (h *DatagramHub) Flood(rate float64, mix FloodMix) (stop func()) {
	panic("unimplemented: M2")
}

// Stats returns the hub's counters.
func (h *DatagramHub) Stats() DatagramStats { panic("unimplemented: M2") }

// Close closes every endpoint and joins every goroutine the hub started.
func (h *DatagramHub) Close() error { panic("unimplemented: M2") }
