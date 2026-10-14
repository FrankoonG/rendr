package udpflow

import (
	"net"
	"net/netip"
	"unsafe"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Batched I/O of rendr's own listening socket (M5 design §A4.4, §A4.5;
// M5-D13, M5-D14, Revision 1 R1-4, R1-5, R1-6, R1-14).

const (
	// srcMaxDepth is the most datagrams one read of a Source moves: a
	// Source reads at depth min(MaxBatch, srcMaxDepth) (R1-6).
	srcMaxDepth = 32
	// defaultMaxBatch is carrier/udp's Options.MaxBatch default (M5-D16).
	defaultMaxBatch = 32
	// batchMsgBytes is what one message of a udpsocket.Batch holds — an
	// mmsghdr, an iovec and a socket address (R1-5's ≈ 112 B) — plus its
	// udpsocket.Msg: the forced Env.Stages charge of a held Batch, per
	// message (R1-5 rule 1).
	batchMsgBytes = 112 + 72
)

// batchIdleRelease is how long a Source's reader may stay parked holding
// its extras — slots 1 … D−1 and its Batch — before the idle release
// returns them (plan:774; M5 design R1-5 rule 3, the dialer reader's
// period and mechanism, which srcidle applies to the passive Source): an
// idle Source holds what it held at M4 — slot 0, uncharged — within
// 2 × batchIdleRelease of its last datagram, or of its start if it never
// read one. It is the shared udpsocket.IdleRelease, internal/carrier's
// batchIdleRelease too, by which the root package's
// TestIdlePacketListenerBufferedBytesZero_plan774 bounds its waits;
// TestBatchIdleReleaseShared in both packages pins it. A Source takes it
// at NewSource; tests lower it.
var batchIdleRelease = udpsocket.IdleRelease

// sockIO is how a Source moves datagrams on rendr's own socket: a
// *udpsocket.Conn (several datagrams per system call on Linux amd64/arm64,
// counted in Env.Dgram.IO) or, for a token that does not expose its socket,
// tokenIO. Tests substitute fakes. Errors are the socket's own, classified
// by the Source as one datagram's would be (ownedReadClass,
// ownedWriteErr).
type sockIO interface {
	ReadBatch(b *udpsocket.Batch, ms []udpsocket.Msg) (int, error)
	WriteBatch(b *udpsocket.Batch, ms []udpsocket.Msg) (int, error)
	Mode() udpsocket.Mode
	MaxBatch() int
}

// srcReader is how a Source reads rendr's own socket at depth D ≥ 2: the
// dialer reader's udpsocket.Reader over the Source's Conn — its four-state
// word (idle, held, parked, releasing) says who owns the extras, so the
// idle release can take them from a read parked in the netpoller (M5
// design R1-5 rule 3, R3-10; srcidle) — or a seam fake with the same
// protocol. One goroutine (the Source's reader) calls ReadBatch, Hold,
// Held and Drop; the idle-release timer calls Parks, Holding and
// TryRelease.
type srcReader interface {
	ReadBatch(ms []udpsocket.Msg) (int, error)
	Hold(b *udpsocket.Batch) (old *udpsocket.Batch, ok bool)
	Held() bool
	Drop() *udpsocket.Batch
	Parks() uint64
	Holding() bool
	TryRelease(seq uint64) bool
}

var _ srcReader = (*udpsocket.Reader)(nil)

// readerIO is a seam sockIO that brings its own srcReader (tests).
type readerIO interface {
	newReader(release func(*udpsocket.Batch)) srcReader
}

// newSrcReader returns the srcReader of io, whose idle release returns the
// extras through release (on the timer's goroutine): a udpsocket.Reader
// for rendr's own Conn, a seam's own, or nil — tokenIO reads one datagram
// per call and holds no extras.
func newSrcReader(io sockIO, release func(*udpsocket.Batch)) srcReader {
	switch c := io.(type) {
	case *udpsocket.Conn:
		return udpsocket.NewReader(c, release)
	case readerIO:
		return c.newReader(release)
	}
	return nil
}

// batchToken is the part of *carrier.OwnedUDPSocket a batched Source needs
// (M5 WP2's accessor): a udpsocket.Conn over the listening socket at its
// normalised Options.MaxBatch, counted in ctr. It is asserted on the
// ownership token only, never on an embedder conn (L57, M5-D10).
// TestSourceAdoptsTokenSocket fails when the token has a NewBatchConn of
// any other signature, so a mismatch cannot silently keep rendr's own
// socket at one datagram per call.
type batchToken interface {
	NewBatchConn(ctr *udpsocket.Counters) (*udpsocket.Conn, error)
}

// rendr's own listening socket is a batchToken: a change of either side's
// signature fails the build instead of leaving every rendr-owned Source on
// tokenIO (R3-25).
var _ batchToken = (*carrier.OwnedUDPSocket)(nil)

// ownedIO returns the sockIO of rendr's own listening socket: the token's
// udpsocket.Conn, counted in env.Dgram.IO, or — for a token without the
// accessor, or one whose socket refuses it — tokenIO (one datagram per
// call, uncounted; M2's path).
func ownedIO(own *carrier.OwnedUDPSocket, env *carrier.Env) sockIO {
	if t, ok := any(own).(batchToken); ok {
		var ctr *udpsocket.Counters
		if env.Dgram != nil {
			ctr = &env.Dgram.IO
		}
		if c, err := t.NewBatchConn(ctr); err == nil {
			return c
		}
	}
	return tokenIO{own}
}

// addrPortIO is the single-datagram I/O of an ownership token
// (*carrier.OwnedUDPSocket; tests substitute fakes).
type addrPortIO interface {
	ReadAddrPort(p []byte) (n int, src netip.AddrPort, ev carrier.ReadEvent, err error)
	WriteAddrPort(p []byte, dst netip.AddrPort) error
}

// tokenIO moves one datagram per call through the token's own AddrPort
// methods and their classification (M2): a noise read is carrier.ErrNoise,
// a truncated one a Msg with Trunc.
type tokenIO struct{ own addrPortIO }

func (t tokenIO) ReadBatch(_ *udpsocket.Batch, ms []udpsocket.Msg) (int, error) {
	m := &ms[0]
	n, src, ev, err := t.own.ReadAddrPort(m.Buf)
	switch {
	case err != nil:
		return 0, err
	case ev == carrier.ReadNoise:
		return 0, carrier.ErrNoise
	}
	m.N, m.Addr, m.Trunc = n, src, ev == carrier.ReadTruncated
	return 1, nil
}

func (t tokenIO) WriteBatch(_ *udpsocket.Batch, ms []udpsocket.Msg) (int, error) {
	for i := range ms {
		if err := t.own.WriteAddrPort(ms[i].Buf, ms[i].Addr); err != nil {
			return i, err
		}
	}
	return len(ms), nil
}

func (tokenIO) Mode() udpsocket.Mode { return udpsocket.ModePlain }
func (tokenIO) MaxBatch() int        { return 1 }

// setIO makes io the Source's socket path (NewSource for rendr's own
// socket; tests). It runs before Run.
//
// The Source's two pools are the recorded exception to "every held buffer
// is visible in BufferedBytes" (R1-5 rule 1, M5 design R3-28): an idle
// Batch resting in one is not charged. The garbage collector may reclaim
// it at any time, and a Batch in use is charged to Env.Stages — a
// writer's for its call (writeBatch), the reader's while it holds its
// extras (reader.hold). wpool holds the writers' call state (wbatch, a
// Batch of MaxBatch messages), idle ones numbering at most the flows that
// wrote at once; rpool the reader's Batch of min(MaxBatch, 32) messages,
// the depth of its reads (R1-6): one is held while the Source reads, and
// its idle release, a fall to depth 1, its exit or a refused Hold puts it
// back (srcidle). The idle Batches of both pools are uncharged and
// reclaimed by the garbage collector; until a collection their number is
// bounded only by the pool's per-P caches. A regrow (reader.hold)
// allocates a Batch only when its P's pool holds none — after a release
// still in flight, whose Batch is not back yet, or when the reader runs
// on another P than the one a Batch went back to — and steady-state reads
// allocate nothing per datagram.
func (s *Source) setIO(io sockIO) {
	s.bio = io
	mb := io.MaxBatch()
	s.wpool.New = func() any {
		w := &wbatch{ms: make([]udpsocket.Msg, mb)}
		if mb >= 2 {
			w.b, w.bytes = udpsocket.NewBatch(mb), int64(mb)*batchMsgBytes
		}
		return w
	}
	d := min(mb, srcMaxDepth)
	s.rpool.New = func() any { return udpsocket.NewBatch(d) }
}

// wbatch is a flow writer's call state on the shared socket: the messages
// of one WriteBatch and, for MaxBatch ≥ 2, the Batch. Writers take one
// from the Source's pool per call and return it at the call's end, so an
// idle flow holds none (R1-5 rule 2); a Batch in use is charged to
// Env.Stages.
type wbatch struct {
	b     *udpsocket.Batch
	ms    []udpsocket.Msg
	bytes int64
}

// readDepth returns the depth of the next read: min(MaxBatch, 32) while
// the socket batches, else 1 (R1-6; a socket that fell back reads one per
// call).
func (s *Source) readDepth() int {
	if s.bio.Mode() != udpsocket.ModeBatch {
		return 1
	}
	return min(s.bio.MaxBatch(), srcMaxDepth)
}

// writeBatch sends ds in order, each one datagram to dst (addr: the
// foreign conn's address value), and returns how many left: ds[:n]; err,
// if any, is ds[n]'s, classified as a single datagram's (the datagram I/O
// contract, M2 design §A6.4). On rendr's own socket one call moves up to
// MaxBatch datagrams with the writer's pooled Batch; the socket serialises
// the calls of all flows, and none holds it longer than one call (R1-14).
// A foreign conn gets one WriteTo per datagram (L57).
func (s *Source) writeBatch(ds [][]byte, dst netip.AddrPort, addr *net.UDPAddr) (int, error) {
	if s.halted.Load() {
		return 0, errSourceClosed
	}
	if s.bio == nil {
		for i, b := range ds {
			if err := s.writeForeign(b, addr); err != nil {
				return i, err
			}
		}
		return len(ds), nil
	}
	w := s.wpool.Get().(*wbatch)
	var b *udpsocket.Batch
	if len(ds) > 1 && w.b != nil && s.bio.Mode() == udpsocket.ModeBatch {
		b = w.b // a plain socket writes one call per datagram: no Batch, no charge
		s.stages.Acquire(w.bytes)
	}
	n := 0
	var err error
	for n < len(ds) && err == nil {
		c := min(len(ds)-n, len(w.ms))
		for i := range c {
			w.ms[i] = udpsocket.Msg{Buf: ds[n+i], Addr: dst}
		}
		k, werr := s.bio.WriteBatch(b, w.ms[:c])
		clear(w.ms[:c])
		n += k
		if werr != nil {
			err = ownedWriteErr(werr)
		}
	}
	if b != nil {
		s.stages.Release(w.bytes)
	}
	s.wpool.Put(w)
	return n, err
}

// ownedWriteErr classifies the error of one datagram written to rendr's
// own listening socket as M2 does: too large (EMSGSIZE, WSAEMSGSIZE) →
// a refusal without a size (Max 0: the MTU probe decides, M2-D25); noise
// (ICMP class, ENOBUFS, a local filter's EPERM, Temporary()) and an abort
// of the shared socket → carrier.ErrNoise; anything else as is (the
// carrier dies) — an invalid count (L42) included: udpsocket.ErrInvalidCount
// stays itself, so the carrier's writer hands back none of the datagrams
// the misreporting call was given.
func ownedWriteErr(err error) error {
	switch carrier.ClassifyPacketErr(err, true) {
	case carrier.PacketErrNoise, carrier.PacketErrAbort:
		return carrier.ErrNoise
	case carrier.PacketErrSize:
		return errTooLarge
	}
	return err
}

// MaxBatch implements carrier.BatchIO: the socket's Options.MaxBatch on
// rendr's own socket; 1 on a foreign conn, which moves one datagram per
// call (L57, M5-D10).
func (f *Flow) MaxBatch() int {
	if s := f.src; s.bio != nil {
		return s.bio.MaxBatch()
	}
	return 1
}

// WriteDatagrams implements carrier.BatchIO: ds to the flow's current
// peer, each with the flow header written into its first Headroom()
// bytes. ds[:n] were sent; err, if any, is ds[n]'s, classified as
// WriteDatagram's would be. A shared socket has no per-flow write
// deadline: the carrier writer's watchdog bounds a stuck call (R1-14).
func (f *Flow) WriteDatagrams(ds [][]byte) (int, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return 0, net.ErrClosed
	}
	dst, addr := f.peer, f.peerAddr
	f.mu.Unlock()
	for _, d := range ds {
		*(*[wire.FlowHeaderLen]byte)(d) = f.hdr
	}
	return f.src.writeBatch(ds, dst, addr)
}

// ReadDatagrams implements carrier.BatchIO: it waits as ReadDatagram does
// and then drains up to min(len(rs), MaxBatch()) inbox datagrams in
// arrival order under one lock (no system call), each what ReadDatagram
// would have returned for it. The call ends at its first ReadCandidate
// (BatchIO; M5 design R3-14): the carrier's reader handles it — its
// challenge answer may commit the rebind (SetPeer) — before a later
// datagram is classified against the peer, so a datagram from another
// source behind it in the inbox cannot replace the candidate first. The
// buffers stay valid until the next ReadDatagrams or ReadDatagram call or
// Release.
//
// A call of two or more holds its datagrams in a slice the flow keeps for
// its life (no allocation per call). The slice is charged when it is
// allocated and returned at Close, so BufferedBytes sees it (R3-28). The
// charge is a holding for the flow's life, so it goes to the stage account
// (Env.Stages, forced; design §0.14 B2, R3-28 option (b)), not to
// MaxBufferedBytes: idle flows never shrink the advertised windows or the
// send chunks' room, and the charge is never refused. A call of one
// datagram holds it as ReadDatagram does and takes no slice.
func (f *Flow) ReadDatagrams(rs []carrier.ReadResult) (int, error) {
	k := min(len(rs), f.MaxBatch())
	if k < 1 {
		return 0, errNoResults
	}
	f.mu.Lock()
	if err := f.waitLocked(); err != nil {
		f.mu.Unlock()
		return 0, err
	}
	if k == 1 {
		e, key, ev := f.popLocked()
		if ev != carrier.ReadTruncated {
			f.cur = e
		}
		rs[0] = carrier.ReadResult{Data: e.data, Src: key, Ev: ev}
		f.mu.Unlock()
		return 1, nil
	}
	f.heldRoomLocked(k)
	n := 0
	for n < k && f.n > 0 {
		e, key, ev := f.popLocked()
		if ev != carrier.ReadTruncated {
			f.held = append(f.held, e)
		}
		rs[n] = carrier.ReadResult{Data: e.data, Src: key, Ev: ev}
		n++
		if ev == carrier.ReadCandidate {
			break // the call ends at its first candidate (R3-14)
		}
	}
	f.mu.Unlock()
	return n, nil
}

// heldEntryBytes is what one entry of a flow's held slice costs the stage
// account (R3-28).
const heldEntryBytes = int64(unsafe.Sizeof(entry{}))

// heldRoomLocked makes the held slice (empty: the caller waited, which
// returned its datagrams) able to hold k entries: a new slice is charged
// to the Source's stage account (forced) and the old one's charge goes
// back.
func (f *Flow) heldRoomLocked(k int) {
	if cap(f.held) >= k {
		return
	}
	nb := int64(k) * heldEntryBytes
	st := f.src.stages
	st.Acquire(nb)
	st.Release(f.heldBytes)
	f.held, f.heldBytes = make([]entry, 0, k), nb
}

var _ carrier.BatchIO = (*Flow)(nil)
