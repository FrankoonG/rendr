package carrier

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Harness of the WP8 mux tests (M3 design §A5): MUX trunks over net.Pipe
// (stream) and the in-memory datagram link (datagram), as pairs of real
// trunks or as one trunk against a scripted raw-wire peer, test endpoints
// that answer, place go frames and move patterned data per view, and a
// frame tap on a trunk's writes. Everything runs inside testing/synctest
// bubbles.

var mPassiveInst = [16]byte{0xcc, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xcc}

// openPayload returns an OPEN payload of a stream (or packet) session.
func mOpenPayload(sid byte, packet bool) []byte {
	o := wire.Open{SID: [16]byte{sid, 0xaa, 15: sid}, Kind: wire.KindStream, Mode: 1, Window: 1 << 20}
	if packet {
		o.Kind, o.Window, o.PMTU = wire.KindDatagram, 0, 1200
	}
	b := make([]byte, wire.OpenFixedLen)
	n := wire.PutOpen(b, &o)
	return b[:n]
}

// joinPayload returns a JOIN payload.
func mJoinPayload(sid byte) []byte {
	b := make([]byte, wire.JoinLen)
	wire.PutJoin(b, &wire.Join{SID: [16]byte{sid, 0xbb, 15: sid}, Mode: 1})
	return b
}

// okAck returns an OK response payload of type typ.
func okAck(typ wire.Type) []byte {
	if typ == wire.TypeJoinAck {
		b := make([]byte, wire.JoinAckLen)
		wire.PutJoinAck(b, &wire.JoinAck{Status: wire.StatusOK})
		return b
	}
	b := make([]byte, wire.OpenAckFixedLen)
	n := wire.PutOpenAck(b, &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20})
	return b[:n]
}

// detachPayload encodes DETACH(h, r).
func detachPayload(h uint32, r wire.DetachReason) []byte {
	b := make([]byte, wire.DetachLen)
	wire.PutDetach(b, &wire.Detach{Handle: h, Reason: r})
	return b
}

// ackPayload is an ACK payload.
func ackPayload() []byte {
	b := make([]byte, wire.AckLen)
	wire.PutAck(b, &wire.Ack{Window: 1 << 20})
	return b
}

// vSource is a per-view endpoint behaviour: a first response (passive),
// the go frame (dialer, M3-D8), queued control frames, then patterned DATA
// for the view's own handle within b.Room() and — capAware — the trunk's
// shared capacity, Capacity() − Inflight() − Taken() (M3-D11).
type vSource struct {
	mu       sync.Mutex
	resp     wire.Type // OPEN_ACK or JOIN_ACK to place first (0: none)
	respSt   wire.AckStatus
	ctl      []hFrame // control frames placed before data
	chunk    *Buf
	next     uint64
	end      uint64
	seg      int
	capAware bool
	noGo     bool // place no go frame (a broken dialer)
	fills    atomic.Int64
	placed   atomic.Int64 // DATA bytes placed
	hook     func(c *Conn, b *Batch)
}

func newVSource(env *Env) *vSource {
	s := &vSource{chunk: env.Bufs.Get(ChunkSize, nil), seg: 16 << 10}
	for i := range s.chunk.B {
		s.chunk.B[i] = byte(i*7 + 3)
	}
	return s
}

func (s *vSource) offer(n uint64) {
	s.mu.Lock()
	s.end += n
	s.mu.Unlock()
}

func (s *vSource) addCtl(f hFrame) {
	s.mu.Lock()
	s.ctl = append(s.ctl, f)
	s.mu.Unlock()
}

func (s *vSource) pending() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.end - s.next
}

func (s *vSource) fill(c *Conn, b *Batch) {
	s.fills.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	h := c.Handle()
	if s.resp != 0 {
		var ok bool
		if s.resp == wire.TypeJoinAck {
			ok = b.AddJoinAck(h, &wire.JoinAck{Status: s.respSt})
		} else {
			ok = b.AddOpenAck(h, &wire.OpenAck{Status: s.respSt, Window: 1 << 20})
		}
		if !ok {
			return
		}
		s.resp = 0
	}
	if c.NeedGo() && !s.noGo {
		if b.Datagram() {
			if !b.AddPack(h, 0, &wire.Pack{}, false) {
				return
			}
		} else if !b.AddAck(h, 0, &wire.Ack{Window: 1 << 20}) {
			return
		}
	}
	if s.hook != nil {
		s.hook(c, b)
	}
	for len(s.ctl) > 0 {
		f := s.ctl[0]
		ok, skip := b.addLast(f.t, f.flags, h, f.payload)
		if !ok && !skip {
			return
		}
		s.ctl = s.ctl[1:]
	}
	appended := 0
	for s.next < s.end && !b.Datagram() {
		if s.capAware && c.Inflight()+int64(b.Taken()+appended) >= c.Capacity() {
			b.MarkCapBlocked()
			return
		}
		in := int(s.next % ChunkSize)
		n := min(s.seg, int(s.end-s.next), ChunkSize-in, b.Room())
		if s.capAware {
			n = min(n, int(c.Capacity()-c.Inflight())-b.Taken()-appended)
		}
		if n <= 0 || !b.AddData(h, s.next, s.chunk.B[in:in+n], s.chunk, false) {
			return
		}
		s.next += uint64(n)
		appended += n
		s.placed.Add(int64(n))
	}
}

// mView is one view of a test trunk with its endpoint and doorbell.
type mView struct {
	c    *Conn
	ep   *dEP
	src  *vSource
	bell *hBell
	done *hBell // OnDone
}

// muxSide is one end of a test trunk: view 1 and the views admitted or
// opened on it.
type muxSide struct {
	env   *Env
	c     *Conn // view 1
	v1    *mView
	tap   *frameTap
	mu    sync.Mutex
	views map[uint32]*mView
	// admit decides what the passive does with an admitted view; nil: the
	// default (start it with a source that answers OK).
	admit func(s *muxSide, v *Conn, h wire.Header, p []byte)
}

func (s *muxSide) view(h uint32) *mView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.views[h]
}

func (s *muxSide) add(mv *mView) {
	s.mu.Lock()
	s.views[mv.c.Handle()] = mv
	s.mu.Unlock()
}

// startAdmitted starts an admitted view with a source answering st.
func (s *muxSide) startAdmitted(v *Conn, h wire.Header, st wire.AckStatus) *mView {
	mv := &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
	mv.src.resp, mv.src.respSt = respTypeOf(h.Type), st
	mv.ep.fill = mv.src.fill
	v.OnDone(mv.done)
	s.add(mv)
	v.Start(mv.ep, mv.bell, StartOptions{})
	return mv
}

// muxEnv is the harness Env of one side.
func muxEnv(mod func(*Env)) *Env {
	env := dgEnv()
	if mod != nil {
		mod(env)
	}
	return env
}

// newMuxSide builds a started MUX trunk over nc (role dialer or passive)
// whose view 1 runs a vSource.
func newMuxSide(t testing.TB, env *Env, nc net.Conn, dialer bool) *muxSide {
	s := &muxSide{env: env, views: make(map[uint32]*mView)}
	var c *Conn
	if dialer {
		c = newConn(env, nc, 7, mPassiveInst, 0, "f0", true)
	} else {
		c = newConn(env, nc, 7, hPeerInst, -1, "", false)
	}
	c.mux = true
	s.c = c
	if !dialer {
		env.Admit = func(v *Conn, h wire.Header, p []byte) {
			if s.admit != nil {
				s.admit(s, v, h, p)
				return
			}
			s.startAdmitted(v, h, wire.StatusOK)
		}
	}
	s.v1 = &mView{c: c, ep: &dEP{}, src: newVSource(env), bell: &hBell{}, done: &hBell{}}
	s.v1.ep.fill = s.v1.src.fill
	s.views[wire.SessionHandle] = s.v1
	t.Cleanup(func() {
		c.KillTrunk(CauseLocalClose, "test cleanup")
		<-c.trunk.tdone
	})
	return s
}

// start starts view 1.
func (s *muxSide) start() {
	s.c.Start(s.v1.ep, s.v1.bell, StartOptions{})
	s.c.OnDone(s.v1.done)
}

// muxPair returns a started dialer and passive MUX trunk over net.Pipe
// (stream): every frame each writes is tapped.
func muxPair(t testing.TB, mod func(*Env)) (d, p *muxSide) {
	a, b := net.Pipe()
	ta, tb := newFrameTap(a), newFrameTap(b)
	d = newMuxSide(t, muxEnv(mod), ta, true)
	p = newMuxSide(t, muxEnv(mod), tb, false)
	d.tap, p.tap = ta, tb
	t.Cleanup(ta.release)
	t.Cleanup(tb.release)
	d.start()
	p.start()
	return d, p
}

// open opens a view of kind (OPEN or JOIN) on the dialer side d, waits for
// its response and starts it with a fresh source (the go frame first).
func (s *muxSide) open(t testing.TB, kind wire.Type, sid byte) (*mView, *Established) {
	t.Helper()
	p := mOpenPayload(sid, s.c.dg != nil) // a packet session on a datagram trunk (M3-D24)
	if kind == wire.TypeJoin {
		p = mJoinPayload(sid)
	}
	v, err := s.c.openView(kind, p, uintptr(sid))
	if err != nil {
		t.Fatalf("openView: %v", err)
	}
	est, err := v.awaitResponse(context.Background(), nil)
	if err != nil {
		t.Fatalf("awaitResponse(%d): %v", v.Handle(), err)
	}
	mv := &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
	mv.ep.fill = mv.src.fill
	v.OnDone(mv.done)
	s.add(mv)
	if wire.AckStatus(est.Payload[0]) == wire.StatusOK {
		v.Start(mv.ep, mv.bell, StartOptions{})
	}
	return mv, est
}

// frameTap is a net.Conn whose Writes are parsed into frames (one record
// per frame, in wire order, with the Write it came in): the frame log of
// one direction of a stream trunk (the role of rendrtest.Tamper's Log in
// the carrier package's own tests).
type frameTap struct {
	net.Conn
	mu     sync.Mutex
	buf    []byte
	frames []tapRec
	writes int
	block  chan struct{} // non-nil: Writes wait until it is closed
}

type tapRec struct {
	h     wire.Header
	write int         // index of the Write that carried it
	inner wire.Header // REL inner (datagram taps)
	p     []byte
}

func newFrameTap(nc net.Conn) *frameTap { return &frameTap{Conn: nc} }

func (f *frameTap) Write(p []byte) (int, error) {
	f.mu.Lock()
	blk := f.block
	f.mu.Unlock()
	if blk != nil {
		<-blk
	}
	f.mu.Lock()
	f.writes++
	w := f.writes
	f.buf = append(f.buf, p...)
	for {
		fr, n, err := wire.DecodeFrame(f.buf)
		if err != nil {
			break
		}
		f.frames = append(f.frames, tapRec{h: fr.Header, write: w, p: append([]byte(nil), fr.Payload[:min(len(fr.Payload), 64)]...)})
		f.buf = f.buf[n:]
	}
	f.mu.Unlock()
	return f.Conn.Write(p)
}

// hold makes Writes block until release.
func (f *frameTap) hold() {
	f.mu.Lock()
	f.block = make(chan struct{})
	f.mu.Unlock()
}

func (f *frameTap) release() {
	f.mu.Lock()
	if f.block != nil {
		close(f.block)
		f.block = nil
	}
	f.mu.Unlock()
}

func (f *frameTap) log() []tapRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tapRec(nil), f.frames...)
}

// forHandle returns the session frames of handle h and the DETACHes naming
// it, in wire order.
func forHandle(log []tapRec, h uint32) []tapRec {
	var out []tapRec
	for _, r := range log {
		if r.h.Handle == h && r.h.Handle != 0 {
			out = append(out, r)
		} else if r.h.Type == wire.TypeDetach {
			if d, err := wire.ParseDetach(r.p); err == nil && d.Handle == h {
				out = append(out, r)
			}
		}
	}
	return out
}

// muxRawPassive returns a started passive MUX trunk whose dialer is a
// scripted raw-wire peer.
func muxRawPassive(t testing.TB, mod func(*Env)) (*muxSide, *wirePeer) {
	a, b := net.Pipe()
	tap := newFrameTap(a)
	s := newMuxSide(t, muxEnv(mod), tap, false)
	s.tap = tap
	t.Cleanup(tap.release)
	p := startPeer(b, s.env.Presets.firstFseq())
	t.Cleanup(p.close)
	s.start()
	return s, p
}

// muxRawDialer returns a started dialer MUX trunk whose passive is a
// scripted raw-wire peer.
func muxRawDialer(t testing.TB, mod func(*Env)) (*muxSide, *wirePeer) {
	a, b := net.Pipe()
	tap := newFrameTap(a)
	s := newMuxSide(t, muxEnv(mod), tap, true)
	s.tap = tap
	t.Cleanup(tap.release)
	p := startPeer(b, s.env.Presets.firstFseq())
	t.Cleanup(p.close)
	s.start()
	return s, p
}

// openRaw opens view kind on dialer side s against a raw peer: it returns
// the view and a function that waits for the attempt's result.
func (s *muxSide) openRaw(t testing.TB, kind wire.Type, sid byte) (*Conn, func() (*Established, error)) {
	t.Helper()
	p := mOpenPayload(sid, s.c.dg != nil) // a packet session on a datagram trunk (M3-D24)
	if kind == wire.TypeJoin {
		p = mJoinPayload(sid)
	}
	v, err := s.c.openView(kind, p, uintptr(sid))
	if err != nil {
		t.Fatalf("openView: %v", err)
	}
	type res struct {
		est *Established
		err error
	}
	ch := make(chan res, 1)
	go func() {
		est, err := v.awaitResponse(context.Background(), nil)
		ch <- res{est, err}
	}()
	return v, func() (*Established, error) { r := <-ch; return r.est, r.err }
}

// attach starts a view with a fresh source (the go frame first) and records it.
func (s *muxSide) attach(v *Conn) *mView {
	mv := &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
	mv.ep.fill = mv.src.fill
	v.OnDone(mv.done)
	s.add(mv)
	v.Start(mv.ep, mv.bell, StartOptions{})
	return mv
}

// isDone reports whether ch is closed.
func isDone(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// waitDone waits (virtual time) for ch.
func waitDone(t testing.TB, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Minute):
		t.Fatalf("%s not done", what)
	}
}

// viewState returns v's state under mx.
func viewStateOf(v *Conn) viewState {
	v.mx.Lock()
	defer v.mx.Unlock()
	return v.state
}

// The datagram flavour.

// dgMuxSide builds a started datagram MUX trunk over io.
func newDgMuxSide(t testing.TB, env *Env, io *fakeIO, cmtu int, dialer bool) *muxSide {
	s := &muxSide{env: env, views: make(map[uint32]*mView)}
	c := dgConn(env, io, cmtu, dialer)
	if dialer {
		c.peer = mPassiveInst
	}
	c.mux = true
	s.c = c
	if !dialer {
		env.Admit = func(v *Conn, h wire.Header, p []byte) {
			if s.admit != nil {
				s.admit(s, v, h, p)
				return
			}
			s.startAdmitted(v, h, wire.StatusOK)
		}
	}
	s.v1 = &mView{c: c, ep: &dEP{}, src: newVSource(env), bell: &hBell{}, done: &hBell{}}
	s.v1.ep.fill = s.v1.src.fill
	s.views[wire.SessionHandle] = s.v1
	t.Cleanup(func() {
		c.KillTrunk(CauseLocalClose, "test cleanup")
		<-c.trunk.tdone
	})
	return s
}

// dgMuxPair returns a started datagram MUX trunk pair over a lossless
// in-memory link with frame budget cmtu.
func dgMuxPair(t testing.TB, cmtu int, mod func(*Env)) (d, p *muxSide, ia, ib *fakeIO) {
	ia, ib = newFakeIOPair(cmtu)
	d = newDgMuxSide(t, muxEnv(mod), ia, cmtu, true)
	p = newDgMuxSide(t, muxEnv(mod), ib, cmtu, false)
	d.start()
	p.start()
	return d, p, ia, ib
}

// dgMuxRaw returns a started datagram MUX trunk (dialer or passive) and a
// raw peer on the other end of its link.
func dgMuxRaw(t testing.TB, cmtu int, dialer bool, mod func(*Env)) (*muxSide, *rawPeer) {
	ia, ib := newFakeIOPair(cmtu)
	s := newDgMuxSide(t, muxEnv(mod), ia, cmtu, dialer)
	p := &rawPeer{io: ib, fseq: s.env.Presets.firstFseq()}
	s.start()
	return s, p
}

// relSeq hands out the raw peer's REL cseqs.
type relSeq struct{ next uint32 }

func (r *relSeq) rel(t wire.Type, flags uint8, h uint32, inner []byte) rawFrame {
	if r.next == 0 {
		r.next = wire.FirstCseq
	}
	f := relFrame(r.next, t, flags, h, inner)
	r.next++
	return f
}

// dgFramesOf decodes every frame of the datagrams d wrote, unwrapping REL:
// each record is (outer header, inner header for a REL).
func dgFramesOf(ds [][]byte) []tapRec {
	var out []tapRec
	for _, d := range ds {
		fs, _ := dgDecode(d)
		for _, f := range fs {
			r := tapRec{h: f.Header, p: append([]byte(nil), f.Payload...)}
			if f.Type == wire.TypeRel {
				if rh, inner, err := wire.ParseRel(f.Payload); err == nil {
					r.inner = wire.Header{Type: rh.Type, Flags: rh.Flags, Handle: rh.Handle, Len: uint32(len(inner))}
					r.p = append([]byte(nil), inner...)
				}
			}
			out = append(out, r)
		}
	}
	return out
}

// eff returns the frame's effective header: the inner one of a REL.
func (r tapRec) eff() wire.Header {
	if r.h.Type == wire.TypeRel {
		return r.inner
	}
	return r.h
}

// nwrites returns the Writes so far.
func (f *frameTap) nwrites() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}
