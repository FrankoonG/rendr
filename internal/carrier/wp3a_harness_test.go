package carrier

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP3a test harness: an in-memory datagram transport pair (fakeIO), a
// packet endpoint (dEP), datagram Conns built as the handshakes build them
// (newDatagramConn, the REL start values of R1-3, the fseq windows), and a
// scripted raw peer that writes and reads rendr datagrams. Everything is
// built from mutexes, cap-1 channels and timers, so it is durable inside
// testing/synctest bubbles; the handshakes (WP3b) are not used.

// fakeAddr returns a PeerKey for test address n.
func fakeAddr(n byte) PeerKey {
	return PeerKey{AP: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, n}), 4000+uint16(n))}
}

// dgItem is one datagram (or a scripted read result) in a fakeIO inbox.
type dgItem struct {
	b   []byte
	src PeerKey
	ev  ReadEvent // forced event; ReadOK: classified by source
	err error     // a scripted read error
}

// fakeIO is one end of an in-memory datagram link: a PacketIO with an
// inbox ring, its own address, a current peer, optional rebinding, a write
// script, a loss filter, a one-way delay and write recording.
type fakeIO struct {
	mu     sync.Mutex
	ring   [256]dgItem
	head   int
	n      int
	wake   chan struct{}
	done   chan struct{}
	closed bool
	rdl    time.Time

	other  *fakeIO
	addr   PeerKey // this end's address as the other end sees it
	cur    PeerKey // the current peer
	rebind bool    // a passive raw-UDP flow: other sources are ReadCandidate, SetPeer works
	hr     int
	limit  int
	recv   int

	out     func(d []byte) error // the write's result (nil: sent); it may block
	post    func(d []byte)       // runs after a sent datagram was delivered, before the write returns
	hang    chan struct{}        // non-nil: ReadDatagram ignores Close and deadlines until it is closed
	filter  func(d []byte) bool  // false: the datagram is lost on the way
	delay   time.Duration
	link    chan dgItem // delayed delivery, FIFO (delay > 0)
	endless ReadEvent   // non-zero: every read returns it at once
	zombie  bool        // endless mode goes on after Close (a transport that ignores it)
	spinAt  time.Time   // endless mode: reads at one instant of (virtual) time
	spins   int
	rec     bool
	writes  []dgWrite
	sets    []PeerKey

	nwrites, nreads, closes, lost atomic.Int64
}

// dgWrite is a recorded write: the rendr bytes, the destination and when.
type dgWrite struct {
	b   []byte
	dst PeerKey
	at  time.Time
}

// newFakeIOPair returns the two ends of a lossless link: a (address 1) and
// b (address 2), each with limit as Limit and receive limit.
func newFakeIOPair(limit int) (a, b *fakeIO) {
	a = &fakeIO{wake: make(chan struct{}, 1), done: make(chan struct{}), addr: fakeAddr(1), limit: limit, recv: limit}
	b = &fakeIO{wake: make(chan struct{}, 1), done: make(chan struct{}), addr: fakeAddr(2), limit: limit, recv: limit}
	a.other, b.other = b, a
	a.cur, b.cur = b.addr, a.addr
	for _, f := range []*fakeIO{a, b} {
		for i := range f.ring {
			f.ring[i].b = make([]byte, 0, limit+wire.FlowHeaderLen+1) // no growth in steady state
		}
	}
	return a, b
}

func (f *fakeIO) ReadSize() int { return f.recv + f.hr + 1 }

func (f *fakeIO) SetLimit(n int) {
	f.mu.Lock()
	f.recv = n
	f.mu.Unlock()
}

func (f *fakeIO) Limit() int { return f.limit }

func (f *fakeIO) Headroom() int { return f.hr }

func (f *fakeIO) Release() {}

// push appends a datagram to the inbox (a full inbox drops it).
func (f *fakeIO) push(it dgItem) {
	f.mu.Lock()
	if f.closed || f.n == len(f.ring) {
		f.mu.Unlock()
		f.lost.Add(1)
		return
	}
	s := &f.ring[(f.head+f.n)%len(f.ring)]
	s.b = append(s.b[:0], it.b...)
	s.src, s.ev, s.err = it.src, it.ev, it.err
	f.n++
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// inject puts a datagram from src into the inbox (a raw peer, a forger).
func (f *fakeIO) inject(src PeerKey, d []byte) { f.push(dgItem{b: d, src: src}) }

// injectEvent puts a scripted read result into the inbox.
func (f *fakeIO) injectEvent(ev ReadEvent, err error) { f.push(dgItem{ev: ev, err: err}) }

func (f *fakeIO) ReadDatagram(buf []byte) ([]byte, PeerKey, ReadEvent, error) {
	f.nreads.Add(1)
	f.mu.Lock()
	hang := f.hang
	short := len(buf) < f.recv+f.hr+1
	f.mu.Unlock()
	if short {
		// The reader must pass ReadSize() bytes: recvLimit + Headroom + 1, so
		// a datagram one byte over the limit is seen as truncated (R1-6).
		return nil, PeerKey{}, 0, errShortBuf
	}
	if hang != nil {
		<-hang
		return nil, PeerKey{}, 0, net.ErrClosed
	}
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		f.mu.Lock()
		if f.endless != 0 && (!f.closed || f.zombie) {
			ev := f.endless
			now := time.Now()
			if now.Equal(f.spinAt) {
				f.spins++
			} else {
				f.spinAt, f.spins = now, 0
			}
			spun := f.spins > spinLimit
			f.mu.Unlock()
			if spun {
				return nil, PeerKey{}, 0, errSpin // a reader that never backs off never lets time advance
			}
			return nil, PeerKey{}, ev, nil
		}
		if f.n > 0 {
			s := &f.ring[f.head]
			f.head = (f.head + 1) % len(f.ring)
			f.n--
			if s.err != nil || s.ev != ReadOK {
				ev, err := s.ev, s.err
				f.mu.Unlock()
				return nil, PeerKey{}, ev, err
			}
			ev := ReadOK
			if s.src != f.cur {
				ev = ReadForeign
				if f.rebind {
					ev = ReadCandidate
				}
			}
			if len(s.b) > f.recv {
				ev = ReadTruncated
			}
			k := copy(buf[:min(len(buf), f.recv+f.hr+1)], s.b)
			src := s.src
			f.mu.Unlock()
			return buf[:k], src, ev, nil
		}
		if f.closed {
			f.mu.Unlock()
			return nil, PeerKey{}, 0, net.ErrClosed
		}
		var dl <-chan time.Time
		if !f.rdl.IsZero() {
			d := time.Until(f.rdl)
			if d <= 0 {
				f.mu.Unlock()
				return nil, PeerKey{}, 0, os.ErrDeadlineExceeded
			}
			if timer == nil {
				timer = time.NewTimer(d)
			} else {
				timer.Reset(d)
			}
			dl = timer.C
		}
		f.mu.Unlock()
		select {
		case <-f.wake:
		case <-f.done:
		case <-dl:
		}
	}
}

// tryRead pops one datagram without blocking (a raw peer's reads).
func (f *fakeIO) tryRead() ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n == 0 {
		return nil, false
	}
	s := &f.ring[f.head]
	f.head = (f.head + 1) % len(f.ring)
	f.n--
	return bytes.Clone(s.b), true
}

func (f *fakeIO) WriteDatagram(b []byte) error {
	f.mu.Lock()
	dst := f.cur
	f.mu.Unlock()
	return f.send(b[f.hr:], dst)
}

func (f *fakeIO) WriteDatagramTo(b []byte, dst PeerKey) error {
	if !f.rebind {
		return ErrNoRebind
	}
	return f.send(b[f.hr:], dst)
}

func (f *fakeIO) send(d []byte, dst PeerKey) error {
	f.nwrites.Add(1)
	f.mu.Lock()
	out, filter, rec, closed := f.out, f.filter, f.rec, f.closed
	if rec {
		f.writes = append(f.writes, dgWrite{b: bytes.Clone(d), dst: dst, at: time.Now()})
	}
	f.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if out != nil {
		if err := out(d); err != nil {
			return err
		}
	}
	o := f.other
	if filter != nil && !filter(d) {
		f.lost.Add(1)
		return nil
	}
	o.mu.Lock()
	at := o.addr
	o.mu.Unlock()
	if dst != at {
		f.lost.Add(1) // nobody listens at the old address
		return nil
	}
	f.mu.Lock()
	src, link, post := f.addr, f.link, f.post
	f.mu.Unlock()
	if link != nil {
		link <- dgItem{b: bytes.Clone(d), src: src}
	} else {
		o.push(dgItem{b: d, src: src})
	}
	if post != nil {
		post(d)
	}
	return nil
}

// setDelay delays every later datagram of this direction by d (FIFO), on a
// goroutine that ends when the receiving end closes.
func (f *fakeIO) setDelay(d time.Duration) {
	link := make(chan dgItem, 4096)
	f.mu.Lock()
	f.delay, f.link = d, link
	f.mu.Unlock()
	gone := f.other.done // datagrams in flight still arrive after the sender closed
	go func() {
		for {
			select {
			case <-gone:
				return
			case it := <-link:
				select {
				case <-gone:
					return
				case <-time.After(d):
				}
				f.other.push(it)
			}
		}
	}()
}

func (f *fakeIO) SetPeer(dst PeerKey) error {
	if !f.rebind {
		return ErrNoRebind
	}
	f.mu.Lock()
	f.cur = dst
	f.sets = append(f.sets, dst)
	f.mu.Unlock()
	return nil
}

func (f *fakeIO) SetDeadline(t time.Time) error      { return f.SetReadDeadline(t) }
func (f *fakeIO) SetWriteDeadline(t time.Time) error { return nil }

func (f *fakeIO) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.rdl = t
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeIO) Close() error {
	f.closes.Add(1)
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		close(f.done)
	}
	f.mu.Unlock()
	return nil
}

// setPost sets the hook run after a datagram was delivered.
func (f *fakeIO) setPost(post func(d []byte)) {
	f.mu.Lock()
	f.post = post
	f.mu.Unlock()
}

// setOut, setFilter and setRec change the write script, the loss filter and
// write recording.
func (f *fakeIO) setOut(out func(d []byte) error) {
	f.mu.Lock()
	f.out = out
	f.mu.Unlock()
}

func (f *fakeIO) setFilter(filter func(d []byte) bool) {
	f.mu.Lock()
	f.filter = filter
	f.mu.Unlock()
}

func (f *fakeIO) setRec(on bool) {
	f.mu.Lock()
	f.rec = on
	f.mu.Unlock()
}

// recorded returns the recorded writes.
func (f *fakeIO) recorded() []dgWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dgWrite(nil), f.writes...)
}

// moveTo changes this end's address (a NAT rebind of the dialer).
func (f *fakeIO) moveTo(a PeerKey) {
	f.mu.Lock()
	f.addr = a
	f.mu.Unlock()
}

// lossy returns a filter that loses each datagram with probability p from a
// seeded generator (deterministic per direction: one writer goroutine), and
// counts the losses in n.
func lossy(p float64, seed uint64, n *atomic.Int64) func([]byte) bool {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	return func([]byte) bool {
		if r.Float64() < p {
			n.Add(1)
			return false
		}
		return true
	}
}

// dgFrames decodes the frames of rendr bytes d (payloads cloned); ok is
// false when the datagram does not decode exactly.
func dgDecode(d []byte) (fs []wire.Frame, ok bool) {
	for len(d) > 0 {
		f, n, err := wire.DecodeFrame(d)
		if err != nil {
			return fs, false
		}
		f.Payload = bytes.Clone(f.Payload)
		fs = append(fs, f)
		d = d[n:]
	}
	return fs, true
}

// hasType reports whether rendr bytes d carry a frame of type t (REL: also
// the inner type when inner is non-zero).
func hasType(d []byte, t wire.Type) bool {
	fs, _ := dgDecode(d)
	for _, f := range fs {
		if f.Type == t {
			return true
		}
	}
	return false
}

// relInnerTypes returns the cseq and inner type of every REL in d.
func relsOf(d []byte) (out []wire.RelHead) {
	fs, _ := dgDecode(d)
	for _, f := range fs {
		if f.Type == wire.TypeRel {
			if h, _, err := wire.ParseRel(f.Payload); err == nil {
				out = append(out, h)
			}
		}
	}
	return out
}

// racksOf returns every RACK in d.
func racksOf(d []byte) (out []wire.Rack) {
	fs, _ := dgDecode(d)
	for _, f := range fs {
		if f.Type == wire.TypeRack {
			if r, err := wire.ParseRack(f.Payload); err == nil {
				out = append(out, r)
			}
		}
	}
	return out
}

// pingsOf returns every PING (pong false) or PONG (pong true) in d.
func pingsOf(d []byte, pong bool) (out []wire.Ping) {
	t := wire.TypePing
	if pong {
		t = wire.TypePong
	}
	fs, _ := dgDecode(d)
	for _, f := range fs {
		if f.Type == t {
			if p, err := wire.ParsePing(f.Payload); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// dEP is a packet endpoint: hEP plus DGRAM records and an optional hook
// run at every Control call (it may block).
type dEP struct {
	hEP
	dmu   sync.Mutex
	dgs   []dgRec
	dgErr error
	hook  func(h wire.Header, p []byte)
	ctrlN atomic.Int32
	cps   []ctrlRec // every Control call: header and payload copy (under dmu)
}

type ctrlRec struct {
	h wire.Header
	p []byte
}

type dgRec struct {
	seq   uint64
	n     int
	byRef bool
}

func (e *dEP) Datagram(c *Conn, seq uint64, p []byte, buf *Buf) error {
	e.dmu.Lock()
	e.dgs = append(e.dgs, dgRec{seq: seq, n: len(p), byRef: buf != nil})
	err := e.dgErr
	e.dmu.Unlock()
	buf.Release()
	return err
}

func (e *dEP) Control(c *Conn, h wire.Header, p []byte) error {
	e.mu.Lock()
	hook := e.hook
	e.mu.Unlock()
	if hook != nil {
		hook(h, p)
	}
	e.dmu.Lock()
	e.cps = append(e.cps, ctrlRec{h: h, p: bytes.Clone(p)})
	e.dmu.Unlock()
	e.ctrlN.Add(1)
	return e.hEP.Control(c, h, p)
}

func (e *dEP) setHook(h func(h wire.Header, p []byte)) {
	e.mu.Lock()
	e.hook = h
	e.mu.Unlock()
}

func (e *dEP) datagrams() []dgRec {
	e.dmu.Lock()
	defer e.dmu.Unlock()
	return append([]dgRec(nil), e.dgs...)
}

func (e *dEP) controls() []wire.Header {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]wire.Header(nil), e.ctrl...)
}

// dgEnv is hEnv with the datagram pool, the Runtime-wide datagram counters
// and a stage account.
func dgEnv() *Env {
	env := hEnv()
	env.DBufs = NewDatagramBufPool()
	env.Dgram = &DgramStats{}
	env.Stages = NewBudget(1 << 30)
	return env
}

// dgConn builds an unstarted datagram Conn over io as the handshakes do:
// budget and receive limit cmtu, both directions numbered from the preset
// first fseq, and the REL start values send = recvCum + 1 = first cseq
// (the probe variant of R1-3: neither direction's handshake carried a REL).
func dgConn(env *Env, io PacketIO, cmtu int, dialer bool) *Conn {
	factory, name := 0, "d0"
	if !dialer {
		factory, name = -1, ""
	}
	c := newDatagramConn(env, io, 7, hPeerInst, factory, name, dialer)
	c.SetBudget(cmtu)
	c.dg.rwin.Init(env.Presets.firstFseq())
	f := env.Presets.firstCseq()
	c.dg.rel.initSend(f)
	c.dg.rel.initRecv(f - 1)
	return c
}

// dgSide is one end of a carrier pair.
type dgSide struct {
	env  *Env
	io   *fakeIO
	c    *Conn
	ep   *dEP
	bell *hBell
}

// dgPair returns two unstarted datagram carriers over a lossless in-memory
// link with frame budget cmtu: a (dialer) and b (passive). Cleanup kills
// both and waits for Done.
func dgPair(t testing.TB, cmtu int) (a, b *dgSide) { return dgPairWith(t, cmtu, nil) }

// dgPairWith is dgPair with mod applied to both sides' Env before the
// carriers are built (Presets: the first fseq and cseq, L14 wrap rows).
func dgPairWith(t testing.TB, cmtu int, mod func(*Env)) (a, b *dgSide) {
	ia, ib := newFakeIOPair(cmtu)
	a = &dgSide{env: dgEnv(), io: ia, ep: &dEP{}, bell: &hBell{}}
	b = &dgSide{env: dgEnv(), io: ib, ep: &dEP{}, bell: &hBell{}}
	if mod != nil {
		mod(a.env)
		mod(b.env)
	}
	a.c = dgConn(a.env, ia, cmtu, true)
	b.c = dgConn(b.env, ib, cmtu, false)
	t.Cleanup(func() {
		for _, s := range []*dgSide{a, b} {
			s.c.Kill(CauseLocalClose, "test cleanup")
			<-s.c.Done()
		}
	})
	return a, b
}

// start starts the side's carrier with its endpoint (nil ep: none).
func (s *dgSide) start(o StartOptions) {
	if s.ep == nil {
		s.c.Start(nil, s.bell, o)
		return
	}
	s.c.Start(s.ep, s.bell, o)
}

// rawPeer is a scripted peer on a fakeIO end: it writes datagrams of frames
// numbered from its own fseq counter and reads what the carrier wrote.
type rawPeer struct {
	io   *fakeIO
	fseq uint32
}

// rawFrame is one frame for rawPeer.send.
type rawFrame struct {
	t       wire.Type
	flags   uint8
	handle  uint32
	payload []byte
}

// datagram builds rendr bytes of frames numbered from the peer's next fseq.
func (p *rawPeer) datagram(frames ...rawFrame) []byte {
	var d []byte
	for _, f := range frames {
		d = wire.AppendFrame(d, wire.Header{Type: f.t, Flags: f.flags, Fseq: p.fseq, Handle: f.handle}, f.payload)
		p.fseq++
	}
	return d
}

// send writes one datagram of frames to the carrier.
func (p *rawPeer) send(frames ...rawFrame) {
	_ = p.io.WriteDatagram(p.datagram(frames...))
}

// read returns every datagram the carrier wrote so far (call after
// synctest.Wait).
func (p *rawPeer) read() [][]byte {
	var out [][]byte
	for {
		d, ok := p.io.tryRead()
		if !ok {
			return out
		}
		out = append(out, d)
	}
}

// rawPair returns a started-ready datagram carrier c over the first end of
// a link and a raw peer on the other end (the peer's datagrams come from
// the carrier's current peer address).
func rawPair(t testing.TB, cmtu int, dialer bool) (*dgSide, *rawPeer) {
	return rawPairWith(t, cmtu, dialer, nil)
}

// rawPairWith is rawPair with mod applied to the carrier's Env first.
func rawPairWith(t testing.TB, cmtu int, dialer bool, mod func(*Env)) (*dgSide, *rawPeer) {
	ia, ib := newFakeIOPair(cmtu)
	s := &dgSide{env: dgEnv(), io: ia, ep: &dEP{}, bell: &hBell{}}
	if mod != nil {
		mod(s.env)
	}
	s.c = dgConn(s.env, ia, cmtu, dialer)
	p := &rawPeer{io: ib, fseq: s.env.Presets.firstFseq()}
	t.Cleanup(func() {
		s.c.Kill(CauseLocalClose, "test cleanup")
		<-s.c.Done()
	})
	return s, p
}

// relPayload builds a REL payload around an inner frame.
func relPayloadOf(cseq uint32, t wire.Type, flags uint8, handle uint32, inner []byte) []byte {
	p := make([]byte, wire.RelHeadLen+len(inner))
	wire.PutRelHead(p, &wire.RelHead{Cseq: cseq, Type: t, Flags: flags, Handle: handle})
	copy(p[wire.RelHeadLen:], inner)
	return p
}

// relFrame is a REL rawFrame.
func relFrame(cseq uint32, t wire.Type, flags uint8, handle uint32, inner []byte) rawFrame {
	return rawFrame{t: wire.TypeRel, payload: relPayloadOf(cseq, t, flags, handle, inner)}
}

// finInner is a FIN payload for offset off.
func finInner(off uint64) []byte {
	p := make([]byte, wire.FinLen)
	wire.PutFin(p, off)
	return p
}

// rackFrame is a RACK rawFrame.
func rackFrame(cum, sack uint32) rawFrame {
	p := make([]byte, wire.RackLen)
	wire.PutRack(p, &wire.Rack{CumAck: cum, Sack: sack})
	return rawFrame{t: wire.TypeRack, payload: p}
}

// pingFrame is a PING (or PONG) rawFrame.
func pingFrame(t wire.Type, p wire.Ping) rawFrame {
	b := make([]byte, wire.PingFixedLen+p.Pad)
	wire.PutPing(b, &p)
	return rawFrame{t: t, payload: b}
}

// finFill returns a Fill that places one FIN (offset 0, 1, …) per call
// while *want > 0 (a reliable frame per round: one REL per round).
func finFill(want *atomic.Int32, next *atomic.Uint64) func(c *Conn, b *Batch) {
	return func(c *Conn, b *Batch) {
		if want.Load() <= 0 {
			return
		}
		if b.AddFin(wire.SessionHandle, next.Load()) {
			next.Add(1)
			want.Add(-1)
		}
	}
}

// finOffsets returns the offsets of the FINs an endpoint received, in order.
func finOffsets(e *dEP) []uint64 {
	e.dmu.Lock()
	defer e.dmu.Unlock()
	var out []uint64
	for _, r := range e.cps {
		if r.h.Type == wire.TypeFin {
			off, _ := wire.ParseFin(r.p)
			out = append(out, off)
		}
	}
	return out
}

// spinLimit bounds the reads an endless fakeIO answers at one instant
// before it reports errSpin.
const spinLimit = 10000

// errSpin: the reader read spinLimit times without time advancing.
var errSpin = errors.New("test: the reader spins")

// errShortBuf: the reader passed a buffer shorter than ReadSize().
var errShortBuf = errors.New("test: read buffer shorter than ReadSize")

// wrapPresets numbers both directions so that the fseqs and the REL cseqs
// wrap within the first frames (L14): the first two RELs are 0xFFFFFFFF
// and 0.
func wrapPresets(env *Env) {
	env.Presets.FirstFseq = 0xFFFFFFF0
	env.Presets.FirstCseq = 0xFFFFFFFF
}

// errNotNoise is a transport error that is neither noise nor a size
// refusal: the carrier dies.
var errNotNoise = errors.New("test: the transport failed")
