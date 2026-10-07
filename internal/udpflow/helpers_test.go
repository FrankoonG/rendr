package udpflow

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// fakeConn is the in-package fake shared socket: a foreign net.PacketConn
// built from a mutex-guarded queue and cap-1 wake channels, so every wait
// of the demux on it is durable inside a synctest bubble (M2 design §A4.4).
type fakeConn struct {
	mu       sync.Mutex
	in       []fakeDgram
	wakeCh   chan struct{}
	closedCh chan struct{}
	closed   bool
	closes   int
	out      []fakeDgram
	wErrs    []fakeWrite // results of the next writes
	reads    int         // ReadFrom calls
	empty    bool        // every read returns (0, addr, nil) (R1-27)
	emptyCap int         // with empty: reads past this count block until Close (0: no cap)
	panicked bool        // the next read panics
	deaf     bool        // a waiting ReadFrom ignores Close until release is closed, WriteTo ignores it (L50)
	release  chan struct{}
	discard  bool // writes are not recorded (allocation gates)
}

type fakeDgram struct {
	b    []byte
	from net.Addr
	err  error
}

type fakeWrite struct {
	n   int // -1: len(p)
	err error
}

func newFakeConn() *fakeConn {
	return &fakeConn{wakeCh: make(chan struct{}, 1), closedCh: make(chan struct{}), release: make(chan struct{})}
}

// queued returns the number of datagrams and errors not read yet.
func (c *fakeConn) queued() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.in)
}

// send queues one datagram from addr.
func (c *fakeConn) send(b []byte, from net.Addr) {
	c.mu.Lock()
	c.in = append(c.in, fakeDgram{b: append([]byte(nil), b...), from: from})
	c.mu.Unlock()
	c.kick()
}

// fail queues one read error.
func (c *fakeConn) fail(err error) {
	c.mu.Lock()
	c.in = append(c.in, fakeDgram{err: err})
	c.mu.Unlock()
	c.kick()
}

func (c *fakeConn) kick() {
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}

func (c *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		c.reads++
		switch {
		case c.closed && !c.deaf:
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		case c.panicked:
			c.panicked = false
			c.mu.Unlock()
			panic("fake ReadFrom panic")
		case c.empty && (c.emptyCap == 0 || c.reads <= c.emptyCap):
			c.mu.Unlock()
			return 0, udpAddr(9, 9), nil
		case c.empty:
			// A reader past the cap spins: block until Close, so that fake
			// time can advance and the test can count the reads.
			c.mu.Unlock()
			<-c.closedCh
			return 0, nil, net.ErrClosed
		case len(c.in) > 0:
			d := c.in[0]
			c.in = c.in[1:]
			c.mu.Unlock()
			if d.err != nil {
				return 0, nil, d.err
			}
			return copy(p, d.b), d.from, nil
		}
		deaf := c.deaf
		c.mu.Unlock()
		if deaf {
			<-c.release
			// The late return delivers a datagram queued meanwhile, if any
			// (a read that completes after the close started).
			c.mu.Lock()
			defer c.mu.Unlock()
			if len(c.in) > 0 {
				d := c.in[0]
				c.in = c.in[1:]
				return copy(p, d.b), d.from, nil
			}
			return 0, nil, net.ErrClosed
		}
		select {
		case <-c.wakeCh:
		case <-c.closedCh:
		}
	}
}

func (c *fakeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.wErrs) > 0 {
		w := c.wErrs[0]
		c.wErrs = c.wErrs[1:]
		if w.n < 0 {
			w.n = len(p)
		}
		return w.n, w.err
	}
	if c.closed && !c.deaf {
		return 0, net.ErrClosed
	}
	if c.discard {
		return len(p), nil
	}
	c.out = append(c.out, fakeDgram{b: append([]byte(nil), p...), from: addr})
	return len(p), nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	if !c.closed {
		c.closed = true
		close(c.closedCh)
	}
	return nil
}

func (c *fakeConn) written() []fakeDgram {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]fakeDgram(nil), c.out...)
}

func (c *fakeConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

func (c *fakeConn) LocalAddr() net.Addr              { return udpAddr(1, 4000) }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

// udpAddr returns a loopback test address of host h (built from bytes:
// no address literal).
func udpAddr(h byte, port uint16) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(apOf(h, port))
}

func apOf(h byte, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, h}), port)
}

// otherAddr is a net.Addr that is not a *net.UDPAddr (L57).
type otherAddr struct{}

func (otherAddr) Network() string { return "other" }
func (otherAddr) String() string  { return "other" }

// testLocal is the passive's InstanceID in the tests.
var testLocal = [16]byte{0xa1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// testEnv returns an Env whose Budget holds budget bytes.
func testEnv(budget int64) *carrier.Env {
	return &carrier.Env{
		Local:   testLocal,
		Timing:  carrier.Timing{AbandonWait: time.Second},
		Abandon: carrier.NewAbandonPool(256),
		Budget:  carrier.NewBudget(budget),
		Stages:  carrier.NewBudget(1 << 40),
		DBufs:   carrier.NewDatagramBufPool(),
		Dgram:   &carrier.DgramStats{},
	}
}

// harness runs one Source over a fakeConn; admitted flows are recorded,
// and admitFn (if set) runs for each on the demux goroutine.
type harness struct {
	t       *testing.T
	env     *carrier.Env
	c       *fakeConn
	s       *Source
	mu      sync.Mutex
	flows   []*Flow
	admitFn func(f *Flow)
}

func newHarness(t *testing.T, env *carrier.Env, lim Limits) *harness {
	h := &harness{t: t, env: env, c: newFakeConn()}
	h.s = NewSource(env, h.c, lim)
	go h.s.Run(h.admit)
	return h
}

func (h *harness) admit(f *Flow) {
	h.mu.Lock()
	h.flows = append(h.flows, f)
	fn := h.admitFn
	h.mu.Unlock()
	if fn != nil {
		fn(f)
	}
}

// admittedFlows returns the flows admitted so far.
func (h *harness) admittedFlows() []*Flow {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*Flow(nil), h.flows...)
}

// last returns the last admitted flow (nil if none).
func (h *harness) last() *Flow {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.flows) == 0 {
		return nil
	}
	return h.flows[len(h.flows)-1]
}

// shutdown aborts the source, closes every flow and waits for Done.
func (h *harness) shutdown() {
	h.s.Abort()
	for _, f := range h.admittedFlows() {
		f.Release()
		f.Close()
	}
	<-h.s.Done()
}

// prefaceBytes returns a PREFACE of kind k for carrier ID cid.
func prefaceBytes(k wire.CarrierKind, cid uint32) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPreface(b, &wire.Preface{Kind: k, Instance: [16]byte{7, 7, 7}, CarrierID: cid})
	return b
}

// h1 returns a complete valid first datagram of flow id: the flow header,
// a PREFACE of kind datagram (carrier ID cid) and REL{FirstCseq, t} for t
// OPEN or JOIN, or a bare PING for t PING (a probe).
func h1(id uint64, t wire.Type, cid uint32) []byte {
	b := make([]byte, wire.FlowHeaderLen, 256)
	wire.PutFlowHeader(b, id)
	pre := prefaceBytes(wire.KindDatagram, cid)
	b = append(b, pre...)
	return wire.AppendFrame(b, h1Header(t, wire.PrefaceFseq(pre)), h1Payload(t, wire.FirstCseq))
}

func h1Header(t wire.Type, fseq uint32) wire.Header {
	if t == wire.TypePing {
		return wire.Header{Type: wire.TypePing, Fseq: fseq}
	}
	return wire.Header{Type: wire.TypeRel, Fseq: fseq}
}

// h1Payload is the first frame's payload: REL{cseq, t} or a PING.
func h1Payload(t wire.Type, cseq uint32) []byte {
	var p [wire.RelHeadLen + wire.OpenFixedLen]byte
	sid := [16]byte{9, 9, 9}
	switch t {
	case wire.TypePing:
		n := wire.PutPing(p[:], &wire.Ping{ID: 1, Nonce: 77})
		return p[:n]
	case wire.TypeJoin:
		n := wire.PutJoin(p[wire.RelHeadLen:], &wire.Join{SID: sid, Mode: 1, RxNext: 1223})
		wire.PutRelHead(p[:], &wire.RelHead{Cseq: cseq, Type: wire.TypeJoin, Handle: wire.SessionHandle})
		return p[:wire.RelHeadLen+n]
	default:
		n := wire.PutOpen(p[wire.RelHeadLen:], &wire.Open{SID: sid, Kind: wire.KindDatagram, Mode: 1, Window: 1223, PMTU: 1198})
		wire.PutRelHead(p[:], &wire.RelHead{Cseq: cseq, Type: t, Handle: wire.SessionHandle})
		return p[:wire.RelHeadLen+n]
	}
}

// dg returns a datagram of flow id carrying frames.
func dg(id uint64, frames ...[]byte) []byte {
	b := make([]byte, wire.FlowHeaderLen, 2048)
	wire.PutFlowHeader(b, id)
	for _, f := range frames {
		b = append(b, f...)
	}
	return b
}

// pingFrame returns a PING frame at fseq.
func pingFrame(fseq uint32) []byte {
	var p [wire.PingFixedLen]byte
	wire.PutPing(p[:], &wire.Ping{ID: fseq, Nonce: 5})
	return wire.AppendFrame(nil, wire.Header{Type: wire.TypePing, Fseq: fseq}, p[:])
}

// rackFrame returns a RACK frame at fseq.
func rackFrame(fseq uint32) []byte {
	var p [wire.RackLen]byte
	wire.PutRack(p[:], &wire.Rack{CumAck: 1})
	return wire.AppendFrame(nil, wire.Header{Type: wire.TypeRack, Fseq: fseq}, p[:])
}

// dgramFrame returns a DGRAM frame at fseq with n application bytes.
func dgramFrame(fseq uint32, n int) []byte {
	p := make([]byte, wire.DgramPrefixLen+n)
	wire.PutDgramSeq(p, uint64(fseq))
	return wire.AppendFrame(nil, wire.Header{Type: wire.TypeDgram, Fseq: fseq, Handle: wire.SessionHandle}, p)
}

// readOne reads the flow's next datagram within d (fake time in a bubble)
// and returns a copy of its bytes.
func readOne(t *testing.T, f *Flow, d time.Duration) ([]byte, carrier.PeerKey, carrier.ReadEvent) {
	t.Helper()
	if err := f.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	b, src, ev, err := f.ReadDatagram(nil)
	if err != nil {
		t.Fatalf("flow %x: ReadDatagram: %v", f.ID(), err)
	}
	out := append([]byte(nil), b...)
	f.Release()
	return out, src, ev
}

// expectNoRead asserts that the flow has nothing to read within d.
func expectNoRead(t *testing.T, f *Flow, d time.Duration) {
	t.Helper()
	if err := f.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	b, _, ev, err := f.ReadDatagram(nil)
	if err == nil {
		f.Release()
		t.Fatalf("flow %x: unexpected datagram (%d bytes, event %d)", f.ID(), len(b), ev)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("flow %x: ReadDatagram: %v, want the deadline", f.ID(), err)
	}
}

// parseAnswer decodes a stateless answer datagram: flow ID and
// PREFACE_ACK.
func parseAnswer(t *testing.T, b []byte) (uint64, wire.PrefaceAck) {
	t.Helper()
	id, rest, err := wire.ParseFlowHeader(b)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	if len(rest) != wire.PrefaceLen {
		t.Fatalf("answer: %d rendr bytes, want %d", len(rest), wire.PrefaceLen)
	}
	ack, err := wire.ParsePrefaceAck(rest)
	if err != nil {
		t.Fatalf("answer: ParsePrefaceAck: %v", err)
	}
	return id, ack
}

// u32 reads a big-endian uint32.
func u32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

// errDeadlineExceeded is the error of an expired read deadline.
var errDeadlineExceeded = os.ErrDeadlineExceeded
