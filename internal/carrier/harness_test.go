package carrier

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Test harness of the carrier runtime: a fake Endpoint, a bulk data source
// endpoint, a counting doorbell, a hookable net.Conn and a scripted raw-wire
// peer that speaks golden frames on the other end of a net.Pipe. Everything
// here runs inside testing/synctest bubbles (no real sockets) except where
// a test says otherwise.

var hPeerInst = [16]byte{0xbb, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xbb}

func hTiming() Timing {
	return Timing{
		PingBusy: 50 * time.Millisecond, PingIdle: 10 * time.Second,
		DeadMin: 3 * time.Second, DeadMax: 4 * time.Second, WriteStall: 2 * time.Second,
		DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second,
		ProbeInterval: 2 * time.Second, SessionlessIdle: 30 * time.Second, AbandonWait: time.Second,
		Window: 8 << 20, CapFloor: 128 << 10, BatchBudget: 256 << 10, Segment: ChunkSize,
	}
}

// hEnv returns the package tests' Env. Its preset first fseq lets scripted
// peers number their frames from wire.FirstFseq; production derives each
// direction's first fseq from its PREFACE or PREFACE_ACK (§0.13 A6), which
// TestPrefaceDerivedFseq_L43 covers with Presets left zero.
func hEnv() *Env {
	local := [16]byte{0xaa, 15: 0xaa}
	return &Env{
		Local:   local,
		Timing:  hTiming(),
		IDs:     NewIDAllocator(0),
		Abandon: NewAbandonPool(256),
		Bufs:    NewBufPool(),
		Budget:  NewBudget(1 << 30),
		Presets: Presets{FirstFseq: wire.FirstFseq},
	}
}

// hConn returns an unstarted carrier over nc as if its handshake had
// completed without counting frames: both directions start at the first
// fseq.
func hConn(env *Env, nc net.Conn) *Conn {
	return newConn(env, nc, 7, hPeerInst, 0, "f0", false)
}

// hWait waits for the carrier's Done (inside a bubble the wait is virtual).
func hWait(t testing.TB, c *Conn) {
	t.Helper()
	select {
	case <-c.Done():
	case <-time.After(time.Minute):
		t.Fatalf("carrier %d not done", c.ID())
	}
}

func hCause(c *Conn) Cause {
	_, cause, _, _ := c.Death()
	return cause
}

// hBell counts rings.
type hBell struct{ n atomic.Int32 }

func (b *hBell) Ring() { b.n.Add(1) }

// hEP is a fake Endpoint: Fill runs an optional function, Data and Control
// record what arrived (DATA bytes copied, buffers released), WriteBlocked
// is counted.
type hEP struct {
	mu       sync.Mutex
	fill     func(c *Conn, b *Batch)
	data     []hData
	ctrl     []wire.Header
	dataErr  error
	ctrlErr  error
	keepData bool // copy DATA bytes (else only offsets and lengths)
	rxBytes  atomic.Int64
	fills    atomic.Int64
	blocked  atomic.Int32
}

type hData struct {
	off   uint64
	n     int
	b     []byte
	byRef bool
}

func (e *hEP) Handle() uint32 { return wire.SessionHandle }

func (e *hEP) Fill(c *Conn, b *Batch) {
	e.fills.Add(1)
	e.mu.Lock()
	f := e.fill
	e.mu.Unlock()
	if f != nil {
		f(c, b)
	}
}

func (e *hEP) setFill(f func(c *Conn, b *Batch)) {
	e.mu.Lock()
	e.fill = f
	e.mu.Unlock()
}

func (e *hEP) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	d := hData{off: off, n: len(p), byRef: buf != nil}
	e.mu.Lock()
	if e.keepData {
		d.b = bytes.Clone(p)
	}
	e.data = append(e.data, d)
	err := e.dataErr
	e.mu.Unlock()
	e.rxBytes.Add(int64(len(p)))
	buf.Release()
	return err
}

func (e *hEP) Control(c *Conn, h wire.Header, p []byte) error {
	e.mu.Lock()
	e.ctrl = append(e.ctrl, h)
	err := e.ctrlErr
	e.mu.Unlock()
	return err
}

func (e *hEP) WriteBlocked(c *Conn) { e.blocked.Add(1) }

func (e *hEP) received() []hData {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]hData(nil), e.data...)
}

// hSource is a bulk DATA source: Fill appends DATA frames of seg bytes for
// stream offsets [next, end), cut at chunk boundaries and referencing one
// patterned 64 KiB chunk, within b.Room() and — when capAware — the
// carrier's capacity (marking the batch cap-blocked when data waits on it),
// like the session's Fill (design §4.3 step 5).
type hSource struct {
	hEP
	smu      sync.Mutex
	chunk    *Buf
	next     uint64
	end      uint64
	seg      int
	capAware bool
	budget   int
}

func newSource(env *Env, seg int, capAware bool) *hSource {
	s := &hSource{chunk: env.Bufs.Get(ChunkSize, nil), seg: seg, capAware: capAware, budget: env.Timing.withDefaults().BatchBudget}
	for i := range s.chunk.B {
		s.chunk.B[i] = byte(i*7 + 3)
	}
	s.fill = s.fillData
	return s
}

// offer makes n more bytes available.
func (s *hSource) offer(n uint64) {
	s.smu.Lock()
	s.end += n
	s.smu.Unlock()
}

func (s *hSource) pending() uint64 {
	s.smu.Lock()
	defer s.smu.Unlock()
	return s.end - s.next
}

func (s *hSource) fillData(c *Conn, b *Batch) {
	s.smu.Lock()
	defer s.smu.Unlock()
	for s.next < s.end {
		if s.capAware && c.Inflight()+int64(s.budget-b.Room()) >= c.Capacity() {
			b.MarkCapBlocked()
			return
		}
		in := int(s.next % ChunkSize)
		n := min(s.seg, int(s.end-s.next), ChunkSize-in, b.Room())
		if n <= 0 || !b.AddData(wire.SessionHandle, s.next, s.chunk.B[in:in+n], s.chunk, false) {
			return
		}
		s.next += uint64(n)
	}
}

// hPattern is the byte at stream offset off of an hSource stream.
func hPattern(off uint64) byte { return byte(int(off%ChunkSize)*7 + 3) }

// hookConn wraps a net.Conn; every hook is optional.
type hookConn struct {
	net.Conn
	onWrite            func(nc net.Conn, p []byte) (int, error)
	onRead             func(nc net.Conn, p []byte) (int, error)
	onClose            func(nc net.Conn) error
	onSetDeadline      func(nc net.Conn, t time.Time) error
	onSetWriteDeadline func(nc net.Conn, t time.Time) error
	writes, reads      atomic.Int32
	closes             atomic.Int32
}

func (h *hookConn) Write(p []byte) (int, error) {
	h.writes.Add(1)
	if h.onWrite != nil {
		return h.onWrite(h.Conn, p)
	}
	return h.Conn.Write(p)
}

func (h *hookConn) Read(p []byte) (int, error) {
	h.reads.Add(1)
	if h.onRead != nil {
		return h.onRead(h.Conn, p)
	}
	return h.Conn.Read(p)
}

func (h *hookConn) Close() error {
	h.closes.Add(1)
	if h.onClose != nil {
		return h.onClose(h.Conn)
	}
	return h.Conn.Close()
}

func (h *hookConn) SetDeadline(t time.Time) error {
	if h.onSetDeadline != nil {
		return h.onSetDeadline(h.Conn, t)
	}
	return h.Conn.SetDeadline(t)
}

func (h *hookConn) SetWriteDeadline(t time.Time) error {
	if h.onSetWriteDeadline != nil {
		return h.onSetWriteDeadline(h.Conn, t)
	}
	return h.Conn.SetWriteDeadline(t)
}

// wirePeer is a scripted raw-wire peer on the other end of a carrier: its
// reader goroutine decodes every frame the carrier writes (strict fseq),
// records it and runs an optional handler; send writes golden frames with
// the peer's own fseq. PONGs can be answered automatically after a delay by
// one ordered delayer goroutine.
type wirePeer struct {
	nc       net.Conn
	keepData bool

	wmu    sync.Mutex
	txFseq uint32

	mu      sync.Mutex
	rxFseq  uint32
	frames  []wire.Frame
	dataN   int64
	handler func(f wire.Frame)
	err     error

	done   chan struct{}
	quit   chan struct{}
	delay  chan delayed
	dwg    sync.WaitGroup
	closed atomic.Bool
}

type delayed struct {
	at time.Time
	f  func()
}

func startPeer(nc net.Conn, first uint32) *wirePeer {
	p := &wirePeer{nc: nc, txFseq: first, rxFseq: first, done: make(chan struct{}), quit: make(chan struct{}), delay: make(chan delayed, 1<<12)}
	go p.readLoop()
	p.dwg.Add(1)
	go p.delayLoop()
	return p
}

// keep makes the peer record DATA bytes (else only their offsets).
func (p *wirePeer) keep() {
	p.mu.Lock()
	p.keepData = true
	p.mu.Unlock()
}

func (p *wirePeer) setHandler(h func(f wire.Frame)) {
	p.mu.Lock()
	p.handler = h
	p.mu.Unlock()
}

func (p *wirePeer) readLoop() {
	defer close(p.done)
	base := make([]byte, 0, 4<<20)
	buf := base
	tmp := make([]byte, 256<<10)
	for {
		n, err := p.nc.Read(tmp)
		buf = append(buf, tmp[:n]...)
		for {
			f, k, derr := wire.DecodeFrame(buf)
			if errors.Is(derr, wire.ErrShort) {
				break
			}
			p.mu.Lock()
			if derr == nil && f.Fseq != p.rxFseq {
				derr = fmt.Errorf("peer: fseq %d, want %d", f.Fseq, p.rxFseq)
			}
			if derr != nil {
				p.err = derr
				p.mu.Unlock()
				return
			}
			p.rxFseq++
			cp := wire.Frame{Header: f.Header}
			if f.Type != wire.TypeData || p.keepData {
				cp.Payload = bytes.Clone(f.Payload)
			} else {
				cp.Payload = bytes.Clone(f.Payload[:wire.DataPrefixLen])
			}
			if f.Type == wire.TypeData {
				p.dataN += int64(len(f.Payload) - wire.DataPrefixLen)
			}
			p.frames = append(p.frames, cp)
			h := p.handler
			p.mu.Unlock()
			if h != nil {
				h(cp)
			}
			buf = buf[k:]
		}
		if len(buf) == 0 {
			buf = base[:0]
		} else if cap(buf)-len(buf) < len(tmp) {
			buf = append(base[:0], buf...)
		}
		if err != nil {
			p.mu.Lock()
			if p.err == nil {
				p.err = err
			}
			p.mu.Unlock()
			return
		}
	}
}

// delayLoop runs delayed sends in submission order.
func (p *wirePeer) delayLoop() {
	defer p.dwg.Done()
	for {
		select {
		case <-p.quit:
			return
		case d := <-p.delay:
			if w := time.Until(d.at); w > 0 {
				select {
				case <-p.quit:
					return
				case <-time.After(w):
				}
			}
			d.f()
		}
	}
}

// later runs f after d on the delayer (in submission order).
func (p *wirePeer) later(d time.Duration, f func()) {
	p.delay <- delayed{at: time.Now().Add(d), f: f}
}

// close closes the peer's end and joins its goroutines.
func (p *wirePeer) close() {
	if p.closed.CompareAndSwap(false, true) {
		close(p.quit)
		p.nc.Close()
	}
	<-p.done
	p.dwg.Wait()
}

func (p *wirePeer) send(t wire.Type, flags uint8, handle uint32, payload []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	b := wire.AppendFrame(nil, wire.Header{Type: t, Flags: flags, Fseq: p.txFseq, Handle: handle}, payload)
	p.txFseq++
	_, err := p.nc.Write(b)
	return err
}

// hFrame is one frame for sendFrames.
type hFrame struct {
	t       wire.Type
	flags   uint8
	handle  uint32
	payload []byte
}

// sendFrames writes frames with consecutive fseq in one Write, so a reader
// can receive several of them in one Read (net.Pipe never joins Writes).
func (p *wirePeer) sendFrames(frames ...hFrame) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	var b []byte
	for _, f := range frames {
		b = wire.AppendFrame(b, wire.Header{Type: f.t, Flags: f.flags, Fseq: p.txFseq, Handle: f.handle}, f.payload)
		p.txFseq++
	}
	_, err := p.nc.Write(b)
	return err
}

// dataPayload is a DATA payload at off whose n bytes follow hPattern.
func dataPayload(off uint64, n int) []byte {
	b := make([]byte, wire.DataPrefixLen+n)
	wire.PutDataOffset(b, off)
	for i := range n {
		b[wire.DataPrefixLen+i] = hPattern(off + uint64(i))
	}
	return b
}

// sendRaw writes bytes as they are (fseq not advanced).
func (p *wirePeer) sendRaw(b []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_, err := p.nc.Write(b)
	return err
}

func pingPayload(pg wire.Ping) []byte {
	b := make([]byte, wire.PingFixedLen+pg.Pad)
	wire.PutPing(b, &pg)
	return b
}

func (p *wirePeer) ping(id uint32, busy bool) error {
	var flags uint8
	if busy {
		flags = wire.FlagPingBusy
	}
	return p.send(wire.TypePing, flags, 0, pingPayload(wire.Ping{ID: id, Nonce: uint64(id) * 977}))
}

func (p *wirePeer) pong(pg wire.Ping) error {
	return p.send(wire.TypePong, 0, 0, pingPayload(pg))
}

// autoPong answers every PING with its PONG after delay(id) (at least
// 1 µs), in order.
func (p *wirePeer) autoPong(delay func(id uint32) time.Duration) {
	p.setHandler(func(f wire.Frame) {
		if f.Type != wire.TypePing {
			return
		}
		pg, err := wire.ParsePing(f.Payload)
		if err != nil {
			return
		}
		var d time.Duration
		if delay != nil {
			d = delay(pg.ID)
		}
		if d <= 0 {
			d = time.Microsecond // a real round trip is never zero: the PONG never races its PING's own write
		}
		p.later(d, func() { _ = p.pong(pg) })
	})
}

func (p *wirePeer) received() []wire.Frame {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]wire.Frame(nil), p.frames...)
}

func (p *wirePeer) count(t wire.Type) int {
	n := 0
	for _, f := range p.received() {
		if f.Type == t {
			n++
		}
	}
	return n
}

func (p *wirePeer) dataBytes() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dataN
}

func (p *wirePeer) readErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// sendBuf models a kernel send buffer in front of a conn: Write copies into
// a bounded queue of chunks and returns once everything is queued (as TCP's
// Write returns once the socket buffer took the bytes); a pump goroutine
// writes the queue out in order. Close stops the pump and joins it.
type sendBuf struct {
	net.Conn
	q        chan []byte
	done     chan struct{}
	pumpDone chan struct{}
	once     sync.Once
}

func newSendBuf(nc net.Conn, chunks int) *sendBuf {
	s := &sendBuf{Conn: nc, q: make(chan []byte, chunks), done: make(chan struct{}), pumpDone: make(chan struct{})}
	go s.pump()
	return s
}

func (s *sendBuf) pump() {
	defer close(s.pumpDone)
	for {
		select {
		case b := <-s.q:
			if _, err := s.Conn.Write(b); err != nil {
				s.stop()
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *sendBuf) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		k := min(len(p), 16<<10)
		select {
		case s.q <- bytes.Clone(p[:k]):
		case <-s.done:
			return n, net.ErrClosed
		}
		n += k
		p = p[k:]
	}
	return n, nil
}

func (s *sendBuf) stop() { s.once.Do(func() { close(s.done) }) }

func (s *sendBuf) Close() error {
	s.stop()
	err := s.Conn.Close()
	<-s.pumpDone
	return err
}

// hPair builds a carrier over one end of a net.Pipe (optionally wrapped)
// and a wirePeer on the other end. A cleanup kills the carrier and closes
// the peer, so a failed test still leaves its bubble without goroutines.
func hPair(t testing.TB, env *Env, wrap func(net.Conn) net.Conn) (*Conn, *wirePeer) {
	a, b := net.Pipe()
	var nc net.Conn = a
	if wrap != nil {
		nc = wrap(a)
	}
	c := hConn(env, nc)
	p := startPeer(b, env.Presets.firstFseq())
	hCleanup(t, c, p)
	return c, p
}

// hCleanup kills c and closes p (if non-nil) when the test ends.
func hCleanup(t testing.TB, c *Conn, p *wirePeer) {
	t.Cleanup(func() {
		c.Kill(CauseLocalClose, "test cleanup")
		<-c.Done()
		if p != nil {
			p.close()
		}
	})
}
