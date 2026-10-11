package carrier

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// OwnedUDP is a datagram carrier on a rendr-owned, unconnected UDP socket:
// one per carrier/udp dialer carrier, constructed only by package
// carrier/udp (an ownership token, never an interface assertion on embedder
// values: L57). It is the net.PacketConn a rendr.DatagramCarrier.Dial of
// carrier/udp returns, and the core recognises its exact type and then uses
// it as a PacketIO: ReadMsgUDPAddrPort reads (truncation by MSG_TRUNC on
// Linux, WSAEMSGSIZE on Windows, n == len everywhere), an exact source
// filter (one AddrPort compare), the flow header written and checked by the
// token itself (Headroom wire.FlowHeaderLen), WriteToUDPAddrPort writes —
// no allocation per datagram (M2-D4, M2-D66). Once its carrier starts it
// also is the carrier's BatchIO (M5 design §A4.3, §A4.4): through a
// udpsocket.Conn its writes and reads move up to MaxBatch datagrams per
// system call on Linux amd64/arm64 (one elsewhere), counted in the
// Runtime's DgramStats.IO, with each datagram classified exactly as a
// single call's.
//
// Its net.PacketConn methods exist for the factory signature, tests and
// diagnostics: ReadFrom strips and WriteTo adds the flow header, and a
// transient error is a Temporary() error that wraps ErrNoise and the
// socket's own error (an embedder that wraps the token reaches the core
// through NewPacketIO, which classifies it as noise). Close closes the
// socket exactly once.
type OwnedUDP struct {
	u        *net.UDPConn
	peer     netip.AddrPort
	flow     uint64
	limit    int // MaxDatagram: the largest UDP payload, flow header included
	recv     int // the receive limit in rendr bytes: limit − 9 until SetLimit lowers it (R1-6)
	maxBatch int // carrier/udp Options.MaxBatch, normalised: 1 … udpsocket.MaxMsgs

	// hdr is the carrier's flow header, built once: every datagram the
	// token writes starts with it, and a datagram it reads belongs to the
	// flow iff it starts with it (M2 design §A3.4: ver u8 = 2 · flow u64,
	// big-endian, frozen; the token writes and checks it itself).
	hdr [wire.FlowHeaderLen]byte

	// The batched I/O (M5 design §A4.3, §A4.4): bound once, by the
	// carrier's writer or reader goroutine, whichever starts first (bind).
	// Until then — the handshake — the token reads and writes with single
	// calls of its own, not counted.
	bindOnce sync.Once
	bat      atomic.Pointer[ownedBatch]

	// The reader half (the carrier's reader goroutine; after Start).
	one    [1]udpsocket.Msg // a read of one datagram (slot 0)
	cur    []udpsocket.Msg  // the messages of the latest readDepth
	relHdr *ioHdr           // the extras of the latest successful lend: the idle release returns them
	relFn  func(*ioHdr)     // the reader's release of a header's slots and charge (onRelease)

	// The writer half: a write of one datagram.
	wone [1]udpsocket.Msg
}

// ownedBatch is the batched I/O of a bound OwnedUDP: the socket's
// udpsocket.Conn, counted in the Runtime's DgramStats.IO, the reader's
// udpsocket.Reader (the four-state word of R1-5) and the account its
// headers are charged to.
type ownedBatch struct {
	uc     *udpsocket.Conn
	rd     *udpsocket.Reader
	stages *Budget
}

// DefaultMaxBatch is the datagrams one system call moves at most when
// carrier/udp's Options.MaxBatch is 0 (M5-D16).
const DefaultMaxBatch = 32

// NewOwnedUDP returns the token for u, a socket carrier/udp opened toward
// peer for one carrier, with that carrier's flow ID (≠ 0, crypto/rand) and
// MaxDatagram (546–65,507; carrier/udp has already clamped it to the MTU of
// the interface the route to peer uses, M2 design Revision 1, R1-16), moving
// up to DefaultMaxBatch datagrams per system call (NewOwnedUDPBatch).
// Ownership of u moves to the token. It panics for flow 0 or a MaxDatagram
// out of range (programming errors of carrier/udp).
func NewOwnedUDP(u *net.UDPConn, peer netip.AddrPort, flow uint64, maxDatagram int) *OwnedUDP {
	return NewOwnedUDPBatch(u, peer, flow, maxDatagram, 0)
}

// NewOwnedUDPBatch is NewOwnedUDP with carrier/udp's Options.MaxBatch: the
// most datagrams one sendmmsg or recvmmsg moves on Linux amd64/arm64 (0 or
// negative: DefaultMaxBatch; above udpsocket.MaxMsgs: that; 1: one
// datagram per call). Other platforms move one datagram per call whatever
// it says (M5-D16).
func NewOwnedUDPBatch(u *net.UDPConn, peer netip.AddrPort, flow uint64, maxDatagram, maxBatch int) *OwnedUDP {
	if flow == 0 {
		panic("rendr/carrier: OwnedUDP with flow ID 0")
	}
	checkMaxDatagram(maxDatagram)
	o := &OwnedUDP{u: u, peer: unmapAddrPort(peer), flow: flow, limit: maxDatagram, recv: maxDatagram - wire.FlowHeaderLen, maxBatch: normMaxBatch(maxBatch)}
	o.hdr[0] = wire.FlowVersion
	binary.BigEndian.PutUint64(o.hdr[1:], flow)
	return o
}

// normMaxBatch normalises an Options.MaxBatch: 0 or negative selects
// DefaultMaxBatch, values above udpsocket.MaxMsgs become that (M5-D16).
func normMaxBatch(n int) int {
	if n <= 0 {
		return DefaultMaxBatch
	}
	return min(n, udpsocket.MaxMsgs)
}

// bind starts the token's batched I/O with env's counters and stage
// account. The carrier's writer and reader goroutines call it when they
// start (writerInit, dgReadLoop); the first call binds, later ones return
// at once. A socket whose udpsocket.Conn cannot be built (its RawConn
// failed) keeps the single calls.
func (o *OwnedUDP) bind(env *Env) {
	o.bindOnce.Do(func() {
		var ctr *udpsocket.Counters
		if env.Dgram != nil {
			ctr = &env.Dgram.IO
		}
		uc, err := udpsocket.New(o.u, o.maxBatch, ctr)
		if err != nil {
			return
		}
		ob := &ownedBatch{uc: uc, stages: env.stageBudget()}
		ob.rd = udpsocket.NewReader(uc, o.releaseExtras)
		o.bat.Store(ob)
	})
}

// MaxBatch implements BatchIO: the configured MaxBatch while the bound
// socket batches (Linux amd64/arm64, ModeBatch), else 1 — before bind, on
// other platforms and after the socket fell back to single calls (M5-D15).
func (o *OwnedUDP) MaxBatch() int {
	if ob := o.bat.Load(); ob != nil && ob.uc.Mode() == udpsocket.ModeBatch {
		return ob.uc.MaxBatch()
	}
	return 1
}

// WriteDatagrams implements BatchIO: the flow header written into each
// datagram's Headroom, then ds to the peer in order — one sendmmsg per
// MaxBatch datagrams while the socket batches, one WriteToUDPAddrPort each
// otherwise — with a pooled header held for the call only. ds[:n] were
// sent; err, if any, is ds[n]'s, classified as WriteDatagram classifies
// one (too large, noise — a local filter's drop included, R1-3 — or
// death); a count the socket misreports is death (L42).
func (o *OwnedUDP) WriteDatagrams(ds [][]byte) (int, error) {
	ob := o.bat.Load()
	if ob == nil || len(ds) == 1 || ob.uc.Mode() != udpsocket.ModeBatch {
		for i, d := range ds {
			if err := o.WriteDatagram(d); err != nil {
				return i, err
			}
		}
		return len(ds), nil
	}
	h := getHdr(len(ds), ob.stages)
	ms := h.ms[:len(ds)]
	for i, d := range ds {
		*(*[wire.FlowHeaderLen]byte)(d) = o.hdr
		ms[i] = udpsocket.Msg{Buf: d, Addr: o.peer}
	}
	n, err := ob.uc.WriteBatch(h.b, ms)
	h.put()
	if n < 0 || n > len(ds) || (err == nil) != (n == len(ds)) {
		return 0, errUDPWriteCount // a full count with an error included (L42)
	}
	if err != nil {
		return n, udpWriteResult(0, 1, err, false)
	}
	return n, nil
}

// ReadDatagrams implements BatchIO for a caller that holds its slots: rs[i]
// is read into rs[i].buf (each at least ReadSize() bytes), at most
// MaxBatch() per call, with a pooled header held for the call. The
// carrier's own reader uses readDepth instead, whose header outlives a
// call (R1-5).
func (o *OwnedUDP) ReadDatagrams(rs []ReadResult) (int, error) {
	if len(rs) == 0 {
		return 0, errNoSlots
	}
	size := o.ReadSize()
	k := min(len(rs), o.MaxBatch())
	if k == 1 {
		data, src, ev, err := o.ReadDatagram(rs[0].buf.B)
		if err != nil {
			return 0, err
		}
		rs[0].Data, rs[0].Src, rs[0].Ev = data, src, ev
		return 1, nil
	}
	ob := o.bat.Load()
	h := getHdr(k, ob.stages)
	ms := h.ms[:k]
	for i := range ms {
		ms[i].Buf = rs[i].buf.B[:size]
	}
	n, err := ob.uc.ReadBatch(h.b, ms)
	for i := range n {
		rs[i].Data, rs[i].Src, rs[i].Ev = o.msgResult(&ms[i])
	}
	h.put()
	if err != nil {
		data, src, ev, err := o.readResult(nil, 0, 0, netip.AddrPort{}, err)
		if err != nil {
			return 0, err
		}
		rs[0].Data, rs[0].Src, rs[0].Ev = data, src, ev
		return 1, nil
	}
	return n, nil
}

// msgResult classifies one datagram a batched read moved, as readResult
// classifies a single read's: truncated (MSG_TRUNC, or a full slot), empty,
// foreign, without the flow's header, or the rendr bytes after it,
// aliasing m.Buf.
func (o *OwnedUDP) msgResult(m *udpsocket.Msg) ([]byte, PeerKey, ReadEvent) {
	if m.Trunc {
		return nil, PeerKey{}, ReadTruncated
	}
	data, key, ev, _ := o.readResult(m.Buf, m.N, 0, m.Addr, nil)
	return data, key, ev
}

// The depthIO side of the token (dgread.go): the dialer reader's adaptive
// depth over the socket's udpsocket.Reader (§A4.4; R1-4, R1-5).

// depthMax implements depthIO: MaxBatch.
func (o *OwnedUDP) depthMax() int { return o.MaxBatch() }

// readDepth implements depthIO: one datagram into slot0, or — while the
// reader holds the lent extras h — up to h.k into slot0 and h's slots,
// through the Reader (a release that won while the read was parked leaves
// one datagram in slot 0). A transient error is a datagram-less event;
// every other error is returned.
func (o *OwnedUDP) readDepth(slot0 *Buf, h *ioHdr) (int, ReadEvent, error) {
	size := o.ReadSize()
	ob := o.bat.Load()
	ms := o.one[:]
	if ob != nil && h != nil && ob.rd.Held() {
		ms = h.ms[:h.k]
		for i := 1; i < h.k; i++ {
			ms[i] = udpsocket.Msg{Buf: h.slots[i].B[:size]}
		}
	}
	ms[0] = udpsocket.Msg{Buf: slot0.B[:size]}
	o.cur = ms
	var n int
	var err error
	if ob == nil {
		var flags int
		m := &ms[0]
		m.N, _, flags, m.Addr, err = o.u.ReadMsgUDPAddrPort(m.Buf, nil)
		m.Trunc = flags&udpMsgTrunc != 0 || m.N == len(m.Buf)
		n = 1
	} else {
		n, err = ob.rd.ReadBatch(ms)
	}
	if err != nil {
		_, _, ev, err := o.readResult(nil, 0, 0, netip.AddrPort{}, err)
		return 0, ev, err
	}
	if n < 1 || n > len(ms) || ms[0].N < 0 || ms[0].N > size {
		return 0, ReadOK, errUDPReadCount
	}
	return n, ReadOK, nil
}

// result implements depthIO: the i-th datagram of the latest readDepth.
func (o *OwnedUDP) result(i int) ([]byte, PeerKey, ReadEvent) { return o.msgResult(&o.cur[i]) }

// lend implements depthIO: the Reader takes h's Batch as its extras.
func (o *OwnedUDP) lend(h *ioHdr) bool {
	ob := o.bat.Load()
	if ob == nil {
		return false
	}
	if _, ok := ob.rd.Hold(h.b); !ok {
		return false
	}
	o.relHdr = h // after Hold: no release runs before the reader parks again
	return true
}

// held implements depthIO.
func (o *OwnedUDP) held() bool {
	ob := o.bat.Load()
	return ob != nil && ob.rd.Held()
}

// reclaim implements depthIO: the Reader gives the extras back.
func (o *OwnedUDP) reclaim() bool {
	ob := o.bat.Load()
	if ob == nil || ob.rd.Drop() == nil {
		return false
	}
	o.relHdr = nil // the token keeps no reference to a header it no longer holds
	return true
}

// parks implements depthIO.
func (o *OwnedUDP) parks() uint64 {
	if ob := o.bat.Load(); ob != nil {
		return ob.rd.Parks()
	}
	return 0
}

// holding implements depthIO.
func (o *OwnedUDP) holding() bool {
	ob := o.bat.Load()
	return ob != nil && ob.rd.Holding()
}

// tryRelease implements depthIO.
func (o *OwnedUDP) tryRelease(seq uint64) bool {
	ob := o.bat.Load()
	return ob != nil && ob.rd.TryRelease(seq)
}

// onRelease implements depthIO (before the first lend).
func (o *OwnedUDP) onRelease(f func(*ioHdr)) { o.relFn = f }

// releaseExtras is the Reader's release (on the idle-release timer's
// goroutine, while the Reader is releasing): the lent header's slots and
// charge go back through the reader's function.
func (o *OwnedUDP) releaseExtras(b *udpsocket.Batch) {
	if h := o.relHdr; h != nil && h.b == b && o.relFn != nil {
		o.relFn(h)
		o.relHdr = nil // before the Reader's idle store: the next lend sets it again
	}
}

// errNoSlots: ReadDatagrams without a result slot.
var errNoSlots = errors.New("rendr/carrier: ReadDatagrams without a slot")

// Flow returns the carrier's flow ID.
func (o *OwnedUDP) Flow() uint64 { return o.flow }

// ReadFrom reads one datagram of the flow and returns its rendr bytes.
// Datagrams that ReadDatagram would not hand over — empty, truncated, from
// another source, without this flow's header — are skipped; a transient
// (noise) error is returned as a noise error (Temporary(), wrapping
// ErrNoise and the socket's error), any other error as is. p shorter than
// the rendr bytes receives their prefix. The address is always the peer's.
// For tests and diagnostics: it allocates a read buffer per call.
func (o *OwnedUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, o.ReadSize())
	for {
		b := buf[:o.ReadSize()]
		n, _, flags, src, rerr := o.u.ReadMsgUDPAddrPort(b, nil)
		data, _, ev, err := o.readResult(b, n, flags, src, rerr)
		switch {
		case err != nil:
			return 0, nil, err
		case ev == ReadNoise:
			return 0, nil, &noiseError{rerr}
		case ev != ReadOK:
			continue
		}
		return copy(p, data), net.UDPAddrFromAddrPort(o.peer), nil
	}
}

// WriteTo sends p, prefixed with the flow header, to addr (a *net.UDPAddr;
// the net package unmaps an IPv4-mapped address for an IPv4 socket and maps
// an IPv4 one for an IPv6 socket). Errors follow WriteDatagram's
// classification, a transient one returned as a noise error (Temporary(),
// wrapping ErrNoise and the socket's error); on success it returns len(p).
// For tests and diagnostics: it allocates the datagram per call.
func (o *OwnedUDP) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua == nil {
		return 0, &net.OpError{Op: "write", Net: "udp", Source: o.u.LocalAddr(), Addr: addr, Err: syscall.EINVAL}
	}
	b := make([]byte, wire.FlowHeaderLen+len(p))
	copy(b, o.hdr[:])
	copy(b[wire.FlowHeaderLen:], p)
	n, err := o.u.WriteToUDPAddrPort(b, ua.AddrPort())
	if werr := viewWriteResult(n, len(b), err); werr != nil {
		return 0, werr
	}
	return len(p), nil
}

// viewWriteResult is udpWriteResult for the net.PacketConn view of a dialer
// socket: a transient error becomes a noise error instead of the bare
// ErrNoise the PacketIO methods return.
func viewWriteResult(n, want int, err error) error {
	werr := udpWriteResult(n, want, err, false)
	if werr == ErrNoise {
		return &noiseError{err}
	}
	return werr
}

// noiseError is a transient socket error as the net.PacketConn view of an
// OwnedUDP returns it: Temporary(), never a timeout, matching ErrNoise and
// the socket's own error (errors.Is, errors.As). An embedder that wraps the
// token and returns it from a DatagramCarrier factory reaches the core
// through NewPacketIO, whose one table classifies Temporary() errors as
// noise on every OS (M2 design §A6.4, Revision 1, R1-28): the datagram is
// lost, never the carrier.
type noiseError struct{ err error }

func (e *noiseError) Error() string   { return ErrNoise.Error() + ": " + e.err.Error() }
func (e *noiseError) Unwrap() []error { return []error{ErrNoise, e.err} }
func (e *noiseError) Temporary() bool { return true }
func (e *noiseError) Timeout() bool   { return false }

// Close closes the socket.
func (o *OwnedUDP) Close() error { return o.u.Close() }

// LocalAddr returns the socket's local address.
func (o *OwnedUDP) LocalAddr() net.Addr { return o.u.LocalAddr() }

// SetDeadline sets the socket's deadlines.
func (o *OwnedUDP) SetDeadline(t time.Time) error { return o.u.SetDeadline(t) }

// SetReadDeadline sets the socket's read deadline.
func (o *OwnedUDP) SetReadDeadline(t time.Time) error { return o.u.SetReadDeadline(t) }

// SetWriteDeadline sets the socket's write deadline.
func (o *OwnedUDP) SetWriteDeadline(t time.Time) error { return o.u.SetWriteDeadline(t) }

// SyscallConn exposes the raw socket for socket-option tests (don't-fragment
// and buffer sizes), as OwnedTCP's does.
func (o *OwnedUDP) SyscallConn() (syscall.RawConn, error) { return o.u.SyscallConn() }

// ReadSize implements PacketIO: the receive limit + the flow header + 1
// (MaxDatagram + 1 until SetLimit).
func (o *OwnedUDP) ReadSize() int { return o.recv + wire.FlowHeaderLen + 1 }

// SetLimit implements PacketIO: the receive limit in rendr bytes, at most
// Limit() (called before Start only).
func (o *OwnedUDP) SetLimit(n int) { o.recv = min(n, o.Limit()) }

// ReadDatagram implements PacketIO: one ReadMsgUDPAddrPort into exactly the
// first ReadSize() bytes of buf, classified by readResult (M2 design §A6.1,
// §A6.4).
func (o *OwnedUDP) ReadDatagram(buf []byte) ([]byte, PeerKey, ReadEvent, error) {
	b := buf[:o.ReadSize()]
	if ob := o.bat.Load(); ob != nil {
		// Bound: through the socket's udpsocket.Conn, counted (R1-2).
		o.one[0] = udpsocket.Msg{Buf: b}
		_, err := ob.uc.ReadBatch(nil, o.one[:])
		if err != nil {
			return o.readResult(b, 0, 0, netip.AddrPort{}, err)
		}
		data, key, ev := o.msgResult(&o.one[0])
		return data, key, ev, nil
	}
	n, _, flags, src, err := o.u.ReadMsgUDPAddrPort(b, nil)
	return o.readResult(b, n, flags, src, err)
}

// readResult maps one read of the dialer socket into b to the PacketIO
// contract, in the order of M2 design §A6.1: a datagram longer than the
// receive limit (Windows WSAEMSGSIZE, MSG_TRUNC, or n filling b, which is
// one byte longer than the largest datagram accepted) is ReadTruncated; an
// empty one ReadEmpty; one from any source but the peer ReadForeign (L59);
// one without this flow's header ReadBadEnvelope (L58); the header alone
// ReadEmpty; else the rendr bytes after the header, aliasing b. Noise
// errors are ReadNoise with a nil error; every other error is returned and
// ends the carrier — ECONNABORTED included: an administrative abort
// unhashes the auto-bound port, so the socket can never receive again
// (§A6.4). An expired read deadline is returned for the caller to judge.
func (o *OwnedUDP) readResult(b []byte, n, flags int, src netip.AddrPort, err error) ([]byte, PeerKey, ReadEvent, error) {
	if err != nil {
		switch udpErrClass(err) {
		case udpMsgSize:
			return nil, PeerKey{}, ReadTruncated, nil
		case udpNoise:
			return nil, PeerKey{}, ReadNoise, nil
		}
		return nil, PeerKey{}, ReadOK, err
	}
	if n < 0 || n > len(b) {
		return nil, PeerKey{}, ReadOK, errUDPReadCount
	}
	if flags&udpMsgTrunc != 0 || n == len(b) {
		return nil, PeerKey{}, ReadTruncated, nil
	}
	key := PeerKey{AP: unmapAddrPort(src)}
	switch {
	case n == 0:
		return nil, key, ReadEmpty, nil
	case key.AP != o.peer:
		return nil, key, ReadForeign, nil
	case n < wire.FlowHeaderLen || [wire.FlowHeaderLen]byte(b[:wire.FlowHeaderLen]) != o.hdr:
		return nil, key, ReadBadEnvelope, nil
	case n == wire.FlowHeaderLen:
		return nil, key, ReadEmpty, nil // the flow's header and no rendr bytes: nothing to hand over
	}
	return b[wire.FlowHeaderLen:n], key, ReadOK, nil
}

// Release implements PacketIO (no-op).
func (o *OwnedUDP) Release() {}

// Headroom implements PacketIO: the flow header.
func (o *OwnedUDP) Headroom() int { return wire.FlowHeaderLen }

// WriteDatagram implements PacketIO: it writes the flow header into
// b[:Headroom()] and sends b to the peer with one WriteToUDPAddrPort.
// EMSGSIZE and WSAEMSGSIZE are a *wire.DatagramTooLargeError with Max 0
// (after carrier/udp's interface-MTU clamp only a route change produces
// them; the MTU probe then decides, R1-16); noise errors — a local packet
// filter's refusal (EPERM on Unix) included — ErrNoise; a count other than
// len(b) an error (L42: the carrier dies, never retried on it); every other
// error, ECONNABORTED included, is returned (death).
func (o *OwnedUDP) WriteDatagram(b []byte) error {
	*(*[wire.FlowHeaderLen]byte)(b) = o.hdr
	if ob := o.bat.Load(); ob != nil {
		// Bound: through the socket's udpsocket.Conn, counted (R1-2).
		o.wone[0] = udpsocket.Msg{Buf: b, Addr: o.peer}
		n, err := ob.uc.WriteBatch(nil, o.wone[:])
		o.wone[0].Buf = nil
		if err != nil {
			return udpWriteResult(0, 1, err, false)
		}
		if n != 1 {
			return errUDPWriteCount
		}
		return nil
	}
	n, err := o.u.WriteToUDPAddrPort(b, o.peer)
	return udpWriteResult(n, len(b), err, false)
}

// WriteDatagramTo implements PacketIO: a dialer socket never rebinds.
func (o *OwnedUDP) WriteDatagramTo(b []byte, dst PeerKey) error { return ErrNoRebind }

// SetPeer implements PacketIO: a dialer socket never rebinds.
func (o *OwnedUDP) SetPeer(dst PeerKey) error { return ErrNoRebind }

// Limit implements PacketIO: MaxDatagram − 9.
func (o *OwnedUDP) Limit() int { return o.limit - wire.FlowHeaderLen }

var (
	_ net.PacketConn = (*OwnedUDP)(nil)
	_ PacketIO       = (*OwnedUDP)(nil)
)

// OwnedUDPSocket is a rendr-owned listening UDP socket (carrier/udp Listen)
// for rendr.FromPacketConn: package udpflow reads and writes it with
// AddrPort calls and truncation detection, without an allocation per
// datagram (M2-D66). Any other net.PacketConn given to FromPacketConn is
// used through its interface methods only (L57). Constructed only by
// carrier/udp.
type OwnedUDPSocket struct {
	u        *net.UDPConn
	limit    int // MaxDatagram
	maxBatch int // carrier/udp Options.MaxBatch, normalised: 1 … udpsocket.MaxMsgs
}

// NewOwnedUDPSocket returns the token for u with its MaxDatagram and
// DefaultMaxBatch (NewOwnedUDPSocketBatch). Ownership of u moves to the
// token. It panics for a MaxDatagram out of range (546–65,507; a
// programming error of carrier/udp).
func NewOwnedUDPSocket(u *net.UDPConn, maxDatagram int) *OwnedUDPSocket {
	return NewOwnedUDPSocketBatch(u, maxDatagram, 0)
}

// NewOwnedUDPSocketBatch is NewOwnedUDPSocket with carrier/udp's
// Options.MaxBatch, normalised as NewOwnedUDPBatch normalises it (the
// Source reads at most 32 per call whatever it says, M5 design R1-6).
func NewOwnedUDPSocketBatch(u *net.UDPConn, maxDatagram, maxBatch int) *OwnedUDPSocket {
	checkMaxDatagram(maxDatagram)
	return &OwnedUDPSocket{u: u, limit: maxDatagram, maxBatch: normMaxBatch(maxBatch)}
}

// MaxDatagram returns the largest UDP payload the socket reads and writes.
func (s *OwnedUDPSocket) MaxDatagram() int { return s.limit }

// MaxBatch returns the socket's normalised Options.MaxBatch (1 … 64).
func (s *OwnedUDPSocket) MaxBatch() int { return s.maxBatch }

// NewBatchConn returns the batched I/O of the socket (package udpflow's
// owned Source, M5 design §A4.4, §A4.5): a udpsocket.Conn moving up to
// MaxBatch datagrams per call, counted in ctr (the Runtime's
// DgramStats.IO). Ownership of the socket stays with the token.
func (s *OwnedUDPSocket) NewBatchConn(ctr *udpsocket.Counters) (*udpsocket.Conn, error) {
	return udpsocket.New(s.u, s.maxBatch, ctr)
}

// ClassifyMsg classifies one datagram a batched read of the socket moved,
// as ReadAddrPort classifies a single read's: ReadTruncated, ReadEmpty or
// ReadOK with its length and unmapped source.
func (s *OwnedUDPSocket) ClassifyMsg(m *udpsocket.Msg) (n int, src netip.AddrPort, ev ReadEvent) {
	if m.Trunc {
		return 0, netip.AddrPort{}, ReadTruncated
	}
	n, src, ev, _ = s.readResult(m.Buf, m.N, 0, m.Addr, nil)
	return n, src, ev
}

// ClassifyRead classifies the error of a batched read of the socket, as
// ReadAddrPort classifies a single read's: ReadTruncated or ReadNoise for
// a transient error (no datagram), else err itself (permanent).
func (s *OwnedUDPSocket) ClassifyRead(err error) (ReadEvent, error) {
	_, _, ev, err := s.readResult(nil, 0, 0, netip.AddrPort{}, err)
	return ev, err
}

// ClassifyWrite classifies the error a batched write of the socket
// reported for one datagram, as WriteAddrPort classifies a single write's
// (too large, noise — a filter's drop and an abort included — or as is);
// nil stays nil.
func (s *OwnedUDPSocket) ClassifyWrite(err error) error {
	if err == nil {
		return nil
	}
	return udpWriteResult(0, 1, err, true)
}

// ReadAddrPort reads one datagram into p (len(p) ≥ MaxDatagram + 1) and
// returns its length and source; ev is ReadTruncated, ReadEmpty or
// ReadNoise for a datagram or error that is not handed over (M2 design
// §A6.4); err is a permanent socket error.
func (s *OwnedUDPSocket) ReadAddrPort(p []byte) (n int, src netip.AddrPort, ev ReadEvent, err error) {
	b := p[:s.limit+1]
	n, _, flags, src, err := s.u.ReadMsgUDPAddrPort(b, nil)
	return s.readResult(b, n, flags, src, err)
}

// readResult maps one read of the listening socket into b as OwnedUDP's
// does, without the source and flow checks (package udpflow demultiplexes
// by flow ID and source). The source is unmapped (an IPv4 client of a
// dual-stack socket appears as IPv4), so it compares equal to the AddrPort
// of a *net.UDPAddr source and writes back to the same client. ECONNABORTED
// is ReadNoise here: the socket is bound explicitly and keeps receiving
// after an administrative abort, which must not end every flow (§A6.1).
func (s *OwnedUDPSocket) readResult(b []byte, n, flags int, src netip.AddrPort, err error) (int, netip.AddrPort, ReadEvent, error) {
	if err != nil {
		switch udpErrClass(err) {
		case udpMsgSize:
			return 0, netip.AddrPort{}, ReadTruncated, nil
		case udpNoise, udpAbort:
			return 0, netip.AddrPort{}, ReadNoise, nil
		}
		return 0, netip.AddrPort{}, ReadOK, err
	}
	if n < 0 || n > len(b) {
		return 0, netip.AddrPort{}, ReadOK, errUDPReadCount
	}
	if flags&udpMsgTrunc != 0 || n == len(b) {
		return 0, netip.AddrPort{}, ReadTruncated, nil
	}
	src = unmapAddrPort(src)
	if n == 0 {
		return 0, src, ReadEmpty, nil
	}
	return n, src, ReadOK, nil
}

// WriteAddrPort sends p as one datagram to dst. EMSGSIZE and WSAEMSGSIZE are
// a *wire.DatagramTooLargeError with Max 0 (with the interface-MTU clamp of
// R1-16 only a route change produces them; the MTU probe then decides);
// ICMP-class errors, a local packet filter's refusal and an abort ErrNoise.
func (s *OwnedUDPSocket) WriteAddrPort(p []byte, dst netip.AddrPort) error {
	n, err := s.u.WriteToUDPAddrPort(p, dst)
	return udpWriteResult(n, len(p), err, true)
}

// ReadFrom implements net.PacketConn (tests and diagnostics).
func (s *OwnedUDPSocket) ReadFrom(p []byte) (int, net.Addr, error) { return s.u.ReadFrom(p) }

// WriteTo implements net.PacketConn (tests and diagnostics).
func (s *OwnedUDPSocket) WriteTo(p []byte, addr net.Addr) (int, error) { return s.u.WriteTo(p, addr) }

// Close closes the socket.
func (s *OwnedUDPSocket) Close() error { return s.u.Close() }

// LocalAddr returns the socket's local address.
func (s *OwnedUDPSocket) LocalAddr() net.Addr { return s.u.LocalAddr() }

// SetDeadline sets the socket's deadlines.
func (s *OwnedUDPSocket) SetDeadline(t time.Time) error { return s.u.SetDeadline(t) }

// SetReadDeadline sets the socket's read deadline.
func (s *OwnedUDPSocket) SetReadDeadline(t time.Time) error { return s.u.SetReadDeadline(t) }

// SetWriteDeadline sets the socket's write deadline.
func (s *OwnedUDPSocket) SetWriteDeadline(t time.Time) error { return s.u.SetWriteDeadline(t) }

// SyscallConn exposes the raw socket for socket-option tests (don't-fragment
// and buffer sizes), as OwnedTCP's does.
func (s *OwnedUDPSocket) SyscallConn() (syscall.RawConn, error) { return s.u.SyscallConn() }

var _ net.PacketConn = (*OwnedUDPSocket)(nil)

// udpClass classifies an error of rendr's own UDP sockets (M2 design
// §A6.4; the errno sets are per OS: owned_udp_unix.go,
// owned_udp_windows.go, owned_udp_other.go).
type udpClass uint8

const (
	udpOther    udpClass = iota // returned to the caller: a permanent error (death), a closed socket, or the caller's deadline
	udpNoise                    // ICMP class, ENOBUFS, Temporary(): the datagram or read is lost, the carrier lives
	udpMsgSize                  // EMSGSIZE, WSAEMSGSIZE: a write refused as too large; on Windows also a truncated read
	udpAbort                    // ECONNABORTED, WSAECONNABORTED: death on a dialer socket, noise on a listening one
	udpFiltered                 // EPERM (Unix): a local packet filter dropped a datagram on send — noise on a write, death on a read
)

// udpErrClass classifies err. The caller's deadline comes first (an
// expired deadline is Temporary() too, and must reach the caller as a
// timeout: handshakes, closers and the write-stall watchdog rely on it),
// then the platform's errno table, then Temporary().
func udpErrClass(err error) udpClass {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return udpOther
	}
	if c := udpErrnoClass(err); c != udpOther {
		return c
	}
	var t interface{ Temporary() bool }
	if errors.As(err, &t) && t.Temporary() {
		return udpNoise
	}
	return udpOther
}

// udpWriteResult maps one write of a datagram of want bytes to the PacketIO
// contract: too large → errUDPTooLarge; noise and a local filter's refusal →
// ErrNoise (the datagram is lost: loss is never death, M2-D14; a refusal
// that persists starves the carrier of PONGs, which ends it by ping_timeout
// as any persistent loss does); an abort → ErrNoise on a listening socket
// (the shared socket stays bound and in use); a count other than want →
// errUDPWriteCount (L42); anything else as is.
func udpWriteResult(n, want int, err error, listening bool) error {
	if err != nil {
		switch udpErrClass(err) {
		case udpMsgSize:
			return errUDPTooLarge
		case udpNoise, udpFiltered:
			return ErrNoise
		case udpAbort:
			if listening {
				return ErrNoise
			}
		}
		return err
	}
	if n != want {
		return errUDPWriteCount
	}
	return nil
}

var (
	// errUDPTooLarge is the refusal of rendr's own sockets: the size the
	// path carries now is unknown (Max 0), so it lowers no budget and the
	// MTU probe decides (M2-D25, R1-16). One shared value, never modified:
	// a refusal allocates nothing.
	errUDPTooLarge error = &wire.DatagramTooLargeError{}
	// errUDPWriteCount: a datagram write that reported another count than
	// the datagram's length (L42, PA-19).
	errUDPWriteCount = errors.New("rendr/carrier: UDP datagram write returned an invalid count")
	// errUDPReadCount: a datagram read that reported a count outside the
	// buffer (L42).
	errUDPReadCount = errors.New("rendr/carrier: UDP datagram read returned an invalid count")
)

// checkMaxDatagram panics unless n is a valid MaxDatagram: room for the
// flow header and the smallest frame budget, and at most a UDP payload.
func checkMaxDatagram(n int) {
	if n < wire.MinFrameBudget+wire.FlowHeaderLen || n > wire.MaxDatagram {
		panic("rendr/carrier: UDP MaxDatagram out of range")
	}
}

// unmapAddrPort returns ap with an IPv4-mapped IPv6 address unmapped.
func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
