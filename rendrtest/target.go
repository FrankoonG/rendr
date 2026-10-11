package rendrtest

import (
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// TCP-like target fakes for package l4 and its scenario tests (M4 design
// §A2.4, M4-D49): an in-memory duplex with half-close and reset, target
// behaviours with counters, and scripted dial outcomes. Standard library
// only, synctest-safe: every wait is a sync.Cond wait or a timer, so a
// goroutine blocked in a TargetConn is durably blocked inside a bubble.
// The dial functions take the address as a string, so rendrtest needs no
// l4 import; tests adapt them with a one-line closure.

// ErrReset is the error a TargetConn's Read and Write return after the
// other end reset the connection (SetLinger(0) then Close, or a Close with
// unread bytes). It matches syscall.ECONNRESET with errors.Is.
var ErrReset error = resetError{}

type resetError struct{}

func (resetError) Error() string        { return "rendrtest: connection reset by peer" }
func (resetError) Is(target error) bool { return target == errConnReset }

// errWriteShut is a Write after the writer's own CloseWrite.
var errWriteShut = errors.New("rendrtest: write after CloseWrite")

// defaultTargetBuf is a TargetPipe's per-direction buffer when buf < 1.
const defaultTargetBuf = 64 << 10

// TargetPipe returns the two ends of an in-memory TCP-like connection:
// Read and Write with a bounded buffer per direction (a writer blocks while
// the other end does not read), deadlines, CloseWrite (the other end reads
// io.EOF after the buffered bytes), Close, and SetLinger(0) followed by
// Close (the other end's Read and Write then return ErrReset, which
// matches syscall.ECONNRESET with errors.Is). As TCP: a Close after
// CloseWrite with nothing unread is invisible to the other end; a Close
// with unread bytes is a reset.
//
// The rest of the model: a Close that is not a reset sends a FIN behind
// the buffered bytes; a Write to an end whose peer closed is accepted and
// answered with a reset (the next Read or Write returns ErrReset); a reset
// discards the bytes in flight both ways, and every later Read and Write
// of the reset end returns ErrReset. Calls on an end after its own Close
// return net.ErrClosed. buf < 1 means 64 KiB; the buffers are allocated on
// first use and released once both ends are closed.
func TargetPipe(buf int) (client, server *TargetConn) {
	if buf < 1 {
		buf = defaultTargetBuf
	}
	p := &pipe{size: buf}
	p.cond.L = &p.mu
	return &TargetConn{p: p, side: 0}, &TargetConn{p: p, side: 1}
}

// TargetConn is one end of a TargetPipe: a net.Conn with CloseWrite and
// SetLinger.
type TargetConn struct {
	p    *pipe
	side int // 0 the client end, 1 the server end
}

var _ net.Conn = (*TargetConn)(nil)

// pipe is the state of both ends; one lock and one condition cover it.
type pipe struct {
	mu      sync.Mutex
	cond    sync.Cond
	size    int
	dir     [2]half // dir[i] carries side i's bytes to side 1-i
	end     [2]endState
	st      [2]*connStats // a Target's counters of that side, or nil
	onClose [2]func()     // called once at that side's first Close
}

// half is one direction's ring buffer and FIN.
type half struct {
	buf  []byte
	r, n int
	fin  bool // the writer sent its FIN (behind the buffered bytes)
}

// endState is one end's own state.
type endState struct {
	closed, wshut, reset, linger0 bool
	rdl, wdl                      time.Time
	rt, wt                        *time.Timer
}

// put copies as much of b as fits and returns the count.
func (h *half) put(b []byte, size int) int {
	if h.buf == nil {
		h.buf = make([]byte, size)
	}
	if free := len(h.buf) - h.n; len(b) > free {
		b = b[:free]
	}
	w := (h.r + h.n) % len(h.buf)
	k := copy(h.buf[w:], b)
	copy(h.buf, b[k:])
	h.n += len(b)
	return len(b)
}

// get moves up to len(b) buffered bytes into b and returns the count.
func (h *half) get(b []byte) int {
	if len(b) > h.n {
		b = b[:h.n]
	}
	k := copy(b, h.buf[h.r:])
	copy(b[k:], h.buf)
	h.r = (h.r + len(b)) % len(h.buf)
	h.n -= len(b)
	return len(b)
}

// finLocked sends side i's FIN once.
func (p *pipe) finLocked(i int) {
	if p.dir[i].fin {
		return
	}
	p.dir[i].fin = true
	p.st[i].mark(flagFINOut)
	p.st[1-i].mark(flagFINIn)
}

// resetLocked resets side j (its peer sent the RST): the bytes in flight
// both ways are gone.
func (p *pipe) resetLocked(j int) {
	p.end[j].reset = true
	p.dir[0] = half{fin: p.dir[0].fin}
	p.dir[1] = half{fin: p.dir[1].fin}
	p.st[j].mark(flagRSTIn)
	p.st[1-j].mark(flagRSTOut)
}

func expired(dl time.Time) bool { return !dl.IsZero() && !time.Now().Before(dl) }

// Read implements net.Conn.
func (c *TargetConn) Read(b []byte) (int, error) {
	p, i := c.p, c.side
	p.mu.Lock()
	defer p.mu.Unlock()
	e, in := &p.end[i], &p.dir[1-i]
	for {
		switch {
		case e.closed:
			return 0, net.ErrClosed
		case e.reset:
			return 0, ErrReset
		case expired(e.rdl):
			return 0, os.ErrDeadlineExceeded
		case in.n > 0:
			n := in.get(b)
			if n > 0 {
				p.st[i].read(b[:n])
				p.cond.Broadcast()
			}
			return n, nil
		case in.fin:
			return 0, io.EOF
		case len(b) == 0:
			return 0, nil
		}
		p.cond.Wait()
	}
}

// Write implements net.Conn.
func (c *TargetConn) Write(b []byte) (int, error) {
	p, i := c.p, c.side
	p.mu.Lock()
	defer p.mu.Unlock()
	e, out := &p.end[i], &p.dir[i]
	n := 0
	for {
		switch {
		case e.closed:
			return n, net.ErrClosed
		case e.reset:
			return n, ErrReset
		case e.wshut:
			return n, errWriteShut
		case expired(e.wdl):
			return n, os.ErrDeadlineExceeded
		case n == len(b):
			return n, nil
		case p.end[1-i].closed:
			// The peer is gone: the bytes leave, and its stack answers
			// them with a reset.
			p.st[i].wrote(b[n:])
			p.resetLocked(i)
			p.cond.Broadcast()
			return len(b), nil
		}
		if k := out.put(b[n:], p.size); k > 0 {
			p.st[i].wrote(b[n : n+k])
			n += k
			p.cond.Broadcast()
			continue
		}
		p.cond.Wait()
	}
}

// Close implements net.Conn: with unread bytes, or after SetLinger(0), a
// reset of the other end.
func (c *TargetConn) Close() error {
	p, i, j := c.p, c.side, 1-c.side
	p.mu.Lock()
	e := &p.end[i]
	if e.closed {
		p.mu.Unlock()
		return net.ErrClosed
	}
	e.closed = true
	stopTimer(e.rt)
	stopTimer(e.wt)
	if !e.reset {
		switch {
		case !e.linger0 && p.dir[j].n == 0:
			p.finLocked(i)
		case p.end[j].closed:
			// The RST still leaves (as TCP), though nobody is there to
			// observe it.
			p.st[i].mark(flagRSTOut)
		default:
			p.resetLocked(j)
		}
	}
	if p.end[j].closed {
		// Both ends are gone: release the buffers (a Target keeps its
		// connections' records).
		p.dir[0] = half{fin: p.dir[0].fin}
		p.dir[1] = half{fin: p.dir[1].fin}
	}
	p.st[i].mark(flagClosed)
	onClose := p.onClose[i]
	p.onClose[i] = nil
	p.cond.Broadcast()
	p.mu.Unlock()
	if onClose != nil {
		onClose()
	}
	return nil
}

// CloseWrite half-closes: the other end reads io.EOF after the buffered
// bytes.
func (c *TargetConn) CloseWrite() error {
	p, i := c.p, c.side
	p.mu.Lock()
	defer p.mu.Unlock()
	e := &p.end[i]
	switch {
	case e.closed:
		return net.ErrClosed
	case e.reset:
		return ErrReset
	}
	e.wshut = true
	p.finLocked(i)
	p.cond.Broadcast()
	return nil
}

// SetLinger(0) makes the next Close a reset (as *net.TCPConn); any other
// value restores the graceful Close.
func (c *TargetConn) SetLinger(sec int) error {
	p := c.p
	p.mu.Lock()
	defer p.mu.Unlock()
	e := &p.end[c.side]
	if e.closed {
		return net.ErrClosed
	}
	e.linger0 = sec == 0
	return nil
}

// LocalAddr implements net.Conn.
func (c *TargetConn) LocalAddr() net.Addr { return targetAddr("target") }

// RemoteAddr implements net.Conn.
func (c *TargetConn) RemoteAddr() net.Addr { return targetAddr("target") }

// SetDeadline implements net.Conn.
func (c *TargetConn) SetDeadline(t time.Time) error { return c.setDeadline(t, true, true) }

// SetReadDeadline implements net.Conn.
func (c *TargetConn) SetReadDeadline(t time.Time) error { return c.setDeadline(t, true, false) }

// SetWriteDeadline implements net.Conn.
func (c *TargetConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }

func (c *TargetConn) setDeadline(t time.Time, r, w bool) error {
	p := c.p
	p.mu.Lock()
	defer p.mu.Unlock()
	e := &p.end[c.side]
	if e.closed {
		return net.ErrClosed
	}
	if r {
		e.rdl = t
		p.arm(&e.rt, t)
	}
	if w {
		e.wdl = t
		p.arm(&e.wt, t)
	}
	p.cond.Broadcast()
	return nil
}

// arm makes *tm wake the waiters at t (a zero t disarms it).
func (p *pipe) arm(tm **time.Timer, t time.Time) {
	stopTimer(*tm)
	if t.IsZero() {
		return
	}
	d := time.Until(t)
	if d <= 0 {
		return // the caller's broadcast wakes the waiters
	}
	if *tm == nil {
		*tm = time.AfterFunc(d, p.wake)
		return
	}
	(*tm).Reset(d)
}

func (p *pipe) wake() {
	p.mu.Lock()
	p.cond.Broadcast()
	p.mu.Unlock()
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// waitGone blocks until this end is closed or reset.
func (c *TargetConn) waitGone() {
	p, e := c.p, &c.p.end[c.side]
	p.mu.Lock()
	for !e.closed && !e.reset {
		p.cond.Wait()
	}
	p.mu.Unlock()
}

// waitGoneFor waits up to d for this end to be closed or reset and
// reports whether it was.
func (c *TargetConn) waitGoneFor(d time.Duration) bool {
	p, e := c.p, &c.p.end[c.side]
	tm := time.AfterFunc(d, p.wake)
	defer tm.Stop()
	until := time.Now().Add(d)
	p.mu.Lock()
	defer p.mu.Unlock()
	for !e.closed && !e.reset && time.Now().Before(until) {
		p.cond.Wait()
	}
	return e.closed || e.reset
}

// waitDrained blocks until the other end read every byte this end sent,
// or either end is gone.
func (c *TargetConn) waitDrained() {
	p, i := c.p, c.side
	p.mu.Lock()
	for p.dir[i].n > 0 && !p.end[i].closed && !p.end[i].reset && !p.end[1-i].closed {
		p.cond.Wait()
	}
	p.mu.Unlock()
}

// takeBuffered reads, without blocking, every byte buffered toward this
// end.
func (c *TargetConn) takeBuffered() {
	p, i := c.p, c.side
	var buf [4096]byte
	p.mu.Lock()
	defer p.mu.Unlock()
	for in := &p.dir[1-i]; in.n > 0 && !p.end[i].closed && !p.end[i].reset; {
		n := in.get(buf[:])
		p.st[i].read(buf[:n])
	}
	p.cond.Broadcast()
}

// resetTakingInput resets the other end (SetLinger(0), Close) after it
// read every byte buffered toward this end (TargetRSTAfter): what the
// client's Writes accepted before the reset counts as read, however the
// discarding goroutine was scheduled.
func (c *TargetConn) resetTakingInput() {
	c.takeBuffered()
	c.SetLinger(0)
	c.Close()
}

// setOnClose installs f, called once at this end's first Close.
func (c *TargetConn) setOnClose(f func()) {
	c.p.mu.Lock()
	c.p.onClose[c.side] = f
	c.p.mu.Unlock()
}

// targetAddr is a TargetConn's logical address.
type targetAddr string

func (a targetAddr) Network() string { return "rendrtest-target" }
func (a targetAddr) String() string  { return string(a) }

// Target serves the server ends of TargetPipes with one behaviour and
// counts Accepted, Open (now), FINIn, FINOut, RSTIn, RSTOut, BytesIn,
// BytesOut and the SHA-256 of each direction per connection.
type Target struct {
	mu     sync.Mutex
	b      TargetBehaviour
	buf    int
	conns  []*connStats
	closed bool
	wg     sync.WaitGroup // one per behaviour goroutine
}

// NewTarget returns a Target whose connections run b, each direction
// buffering buf bytes (TargetPipe's buf). It panics on the zero
// TargetBehaviour.
func NewTarget(b TargetBehaviour, buf int) *Target {
	if b.kind == 0 {
		panic("rendrtest: NewTarget: zero TargetBehaviour")
	}
	return &Target{b: b, buf: buf}
}

// Dial returns a new client end whose server end runs the Target's
// behaviour; addr is recorded, not used. A done ctx, or a closed Target,
// fails the dial and accepts nothing.
func (t *Target) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: targetAddr(addr), Err: err}
	}
	cli, srv := TargetPipe(t.buf)
	s := &connStats{mu: &t.mu, addr: addr, srv: srv, hin: sha256.New(), hout: sha256.New(), open: true}
	srv.p.st[1] = s
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, dialError(addr, errConnRefused)
	}
	t.conns = append(t.conns, s)
	t.wg.Add(1)
	t.mu.Unlock()
	go func() {
		defer t.wg.Done()
		t.b.run(srv)
		srv.Close()
	}()
	return cli, nil
}

// Close resets every connection the Target still holds (as a server that
// exits with SO_LINGER 0), refuses later dials and waits until every
// behaviour goroutine ended. A test calls it to end connections whose
// clients went away silently (a Close after CloseWrite, R1-3).
func (t *Target) Close() {
	t.mu.Lock()
	t.closed = true
	var held []*TargetConn
	for _, s := range t.conns {
		if s.srv != nil {
			held = append(held, s.srv)
		}
	}
	t.mu.Unlock()
	for _, c := range held {
		c.SetLinger(0) // net.ErrClosed if it closed meanwhile
		c.Close()
	}
	t.wg.Wait()
}

// Counts returns a snapshot of the Target's counters.
func (t *Target) Counts() TargetCounts {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := TargetCounts{Accepted: len(t.conns), Conns: make([]TargetConnCounts, len(t.conns))}
	for k, s := range t.conns {
		cc := TargetConnCounts{
			Addr: s.addr, BytesIn: s.bytesIn, BytesOut: s.bytesOut,
			FINIn: s.finIn, FINOut: s.finOut, RSTIn: s.rstIn, RSTOut: s.rstOut, Open: s.open,
		}
		s.hin.Sum(cc.SHAIn[:0])
		s.hout.Sum(cc.SHAOut[:0])
		c.Conns[k] = cc
		c.BytesIn += cc.BytesIn
		c.BytesOut += cc.BytesOut
		c.Open += b2i(cc.Open)
		c.FINIn += b2i(cc.FINIn)
		c.FINOut += b2i(cc.FINOut)
		c.RSTIn += b2i(cc.RSTIn)
		c.RSTOut += b2i(cc.RSTOut)
	}
	return c
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TargetCounts is a Target's counters: totals over its connections (FIN
// and RST "In" as the target saw them from its client, "Out" as it sent
// them) and one record per connection in accept order.
type TargetCounts struct {
	Accepted, Open    int                // connections accepted; open now
	FINIn, FINOut     int                // FINs received from clients; FINs sent
	RSTIn, RSTOut     int                // resets received from clients; resets sent
	BytesIn, BytesOut int64              // bytes read and written
	Conns             []TargetConnCounts // one per connection, in accept order
}

// TargetConnCounts is one connection of a Target. FINIn: the client's FIN
// reached the target (its CloseWrite, or a Close that was not a reset),
// whether or not the behaviour read up to it. RSTIn: the target's end was
// reset (the client reset it, or answered a write after its Close).
// RSTOut: the target reset the client (SetLinger(0) or unread bytes at its
// Close, or its stack answering a client write after that Close). FINOut
// and RSTOut also record what a target's Close sends after its client
// closed (as TCP), although the client no longer observes it. Open: the
// target has not closed its end yet.
type TargetConnCounts struct {
	Addr              string   // the address Dial was called with
	BytesIn, BytesOut int64    // bytes the target read and wrote
	SHAIn, SHAOut     [32]byte // SHA-256 of each direction
	FINIn, FINOut     bool     // see the type documentation
	RSTIn, RSTOut     bool     // see the type documentation
	Open              bool     // the target has not closed its end yet
}

// connStats is one connection's counters, guarded by its Target's lock
// (taken under the pipe's lock, never the reverse).
type connStats struct {
	mu                                 *sync.Mutex
	addr                               string
	srv                                *TargetConn
	bytesIn, bytesOut                  int64
	hin, hout                          hash.Hash
	finIn, finOut, rstIn, rstOut, open bool
}

const (
	flagFINIn = iota
	flagFINOut
	flagRSTIn
	flagRSTOut
	flagClosed
)

// mark records one event; s may be nil (a plain TargetPipe).
func (s *connStats) mark(f int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	switch f {
	case flagFINIn:
		s.finIn = true
	case flagFINOut:
		s.finOut = true
	case flagRSTIn:
		s.rstIn = true
	case flagRSTOut:
		s.rstOut = true
	case flagClosed:
		s.open = false
		s.srv = nil // the record outlives the pipe
	}
	s.mu.Unlock()
}

// read records bytes the target read; s may be nil.
func (s *connStats) read(b []byte) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.bytesIn += int64(len(b))
	s.hin.Write(b)
	s.mu.Unlock()
}

// wrote records bytes the target sent; s may be nil.
func (s *connStats) wrote(b []byte) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.bytesOut += int64(len(b))
	s.hout.Write(b)
	s.mu.Unlock()
}

// TargetBehaviour is what a Target does with each connection. Every
// behaviour closes its end when it is done; a behaviour that holds a
// connection holds it until its end is reset (or Target.Close).
type TargetBehaviour struct {
	kind    int
	n, resp int64
	seed    uint64
	_       [0]func()
}

const (
	behEcho = iota + 1
	behGen
	behSink
	behStall
	behNoRead
	behRSTAfter
	behHalf
	behReqResp
	behIgnoreFIN
)

// ignoreFINChunk and ignoreFINEvery are TargetIgnoreFIN's sending pattern
// after the FIN (the I of M4 design R1-22).
const (
	ignoreFINChunk = 1 << 10
	ignoreFINEvery = 100 * time.Millisecond
)

// TargetEcho echoes every byte and answers the client's FIN with its own.
func TargetEcho() TargetBehaviour { return TargetBehaviour{kind: behEcho} }

// TargetGen sends n bytes of the seeded stream (PRNG(seed)), then FIN; it
// reads and discards what the client sends, and closes after the client's
// FIN.
func TargetGen(n int64, seed uint64) TargetBehaviour {
	return TargetBehaviour{kind: behGen, n: n, seed: seed}
}

// TargetSink reads and discards to FIN, then FINs back.
func TargetSink() TargetBehaviour { return TargetBehaviour{kind: behSink} }

// TargetStall reads to FIN, then holds the connection open.
func TargetStall() TargetBehaviour { return TargetBehaviour{kind: behStall} }

// TargetNoRead never reads.
func TargetNoRead() TargetBehaviour { return TargetBehaviour{kind: behNoRead} }

// TargetRSTAfter resets the connection after sending n bytes (PRNG(0)'s
// stream) once the client has read them; it reads and discards what the
// client sends, including what is buffered at the reset.
func TargetRSTAfter(n int64) TargetBehaviour { return TargetBehaviour{kind: behRSTAfter, n: n} }

// TargetHalf reads to FIN, sends n bytes (PRNG(0)'s stream), then FIN.
func TargetHalf(n int64) TargetBehaviour { return TargetBehaviour{kind: behHalf, n: n} }

// TargetReqResp reads req bytes, answers resp bytes (PRNG(0)'s stream),
// then FIN; it discards anything more up to the client's FIN. A FIN before
// req bytes is answered with a FIN alone.
func TargetReqResp(req, resp int64) TargetBehaviour {
	return TargetBehaviour{kind: behReqResp, n: req, resp: resp}
}

// TargetIgnoreFIN reads to FIN, then keeps sending 1 KiB (PRNG(0)'s
// stream) every 100 ms and never FINs back (the msess target that ignores
// FIN; R1-22) until its end is reset (it notices at once, between
// chunks) or a write fails.
func TargetIgnoreFIN() TargetBehaviour { return TargetBehaviour{kind: behIgnoreFIN} }

// run is the behaviour on the server end c; the caller closes c.
func (b TargetBehaviour) run(c *TargetConn) {
	switch b.kind {
	case behEcho:
		buf := make([]byte, 32<<10)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err == io.EOF {
				c.CloseWrite()
				return
			}
			if err != nil {
				return
			}
		}
	case behGen:
		done := discardAsync(c)
		if sendN(c, PRNG(b.seed), b.n) == nil {
			c.CloseWrite()
		}
		<-done
	case behSink:
		if discard(c) == io.EOF {
			c.CloseWrite()
		}
	case behStall:
		if discard(c) == io.EOF {
			c.waitGone()
		}
	case behNoRead:
		c.waitGone()
	case behRSTAfter:
		done := discardAsync(c)
		if sendN(c, PRNG(0), b.n) == nil {
			c.waitDrained()
		}
		c.resetTakingInput()
		<-done
	case behHalf:
		if discard(c) == io.EOF && sendN(c, PRNG(0), b.n) == nil {
			c.CloseWrite()
		}
	case behReqResp:
		got, err := readUpTo(c, b.n)
		if got == b.n {
			if sendN(c, PRNG(0), b.resp) != nil {
				return
			}
			c.CloseWrite()
			discard(c)
			return
		}
		if err == io.EOF {
			c.CloseWrite()
		}
	case behIgnoreFIN:
		if discard(c) != io.EOF {
			return
		}
		src, chunk := PRNG(0), make([]byte, ignoreFINChunk)
		for {
			src.Read(chunk)
			if _, err := c.Write(chunk); err != nil || c.waitGoneFor(ignoreFINEvery) {
				return
			}
		}
	}
}

// discard reads to the end and returns the error that ended it (io.EOF at
// the client's FIN).
func discard(c *TargetConn) error {
	buf := make([]byte, 32<<10)
	for {
		if _, err := c.Read(buf); err != nil {
			return err
		}
	}
}

// discardAsync runs discard in a goroutine; the channel closes when it
// ended.
func discardAsync(c *TargetConn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		discard(c)
	}()
	return done
}

// readUpTo reads until it has n bytes or Read fails; bytes beyond n in the
// last Read are read and dropped.
func readUpTo(c *TargetConn, n int64) (int64, error) {
	buf := make([]byte, 32<<10)
	var got int64
	for got < n {
		k, err := c.Read(buf)
		got += int64(k)
		if err != nil {
			return min(got, n), err
		}
	}
	return n, nil
}

// sendN writes n bytes of src with plain Writes.
func sendN(c *TargetConn, src io.Reader, n int64) error {
	buf := make([]byte, 32<<10)
	for n > 0 {
		k := int(min(n, int64(len(buf))))
		src.Read(buf[:k])
		if _, err := c.Write(buf[:k]); err != nil {
			return err
		}
		n -= int64(k)
	}
	return nil
}

// DialOutcome is one scripted result of a ScriptedDial call.
type DialOutcome struct {
	kind int
	d    time.Duration
	t    *Target
	_    [0]func()
}

const (
	outRefuse = iota + 1
	outNetUnreachable
	outHostUnreachable
	outHang
	outIgnoreCtx
	outLate
	outDNSNotFound
	outDNSFailure
	outPanic
	outGoexit
	outNilNil
	outOK
)

// OutcomeRefuse fails like a target that answered the SYN with RST (this
// OS's connection-refused errno inside a *net.OpError).
func OutcomeRefuse() DialOutcome { return DialOutcome{kind: outRefuse} }

// OutcomeNetUnreachable fails with this OS's network-unreachable errno.
func OutcomeNetUnreachable() DialOutcome { return DialOutcome{kind: outNetUnreachable} }

// OutcomeHostUnreachable fails with this OS's host-unreachable errno.
func OutcomeHostUnreachable() DialOutcome { return DialOutcome{kind: outHostUnreachable} }

// OutcomeHang blocks until ctx ends, then returns ctx's error (inside a
// *net.OpError, as the net package's dialer).
func OutcomeHang() DialOutcome { return DialOutcome{kind: outHang} }

// OutcomeIgnoreCtx ignores ctx and fails after d.
func OutcomeIgnoreCtx(d time.Duration) DialOutcome { return DialOutcome{kind: outIgnoreCtx, d: d} }

// OutcomeLate ignores ctx and returns a conn after d (after ctx ended: the
// caller must close it). The conn's far end neither reads nor writes.
func OutcomeLate(d time.Duration) DialOutcome { return DialOutcome{kind: outLate, d: d} }

// OutcomeDNSNotFound fails with a *net.DNSError whose IsNotFound is set.
func OutcomeDNSNotFound() DialOutcome { return DialOutcome{kind: outDNSNotFound} }

// OutcomeDNSFailure fails with a *net.DNSError of a failed resolution.
func OutcomeDNSFailure() DialOutcome { return DialOutcome{kind: outDNSFailure} }

// OutcomePanic panics.
func OutcomePanic() DialOutcome { return DialOutcome{kind: outPanic} }

// OutcomeGoexit calls runtime.Goexit.
func OutcomeGoexit() DialOutcome { return DialOutcome{kind: outGoexit} }

// OutcomeNilNil returns (nil, nil).
func OutcomeNilNil() DialOutcome { return DialOutcome{kind: outNilNil} }

// OutcomeOK returns a new client end of t.
func OutcomeOK(t *Target) DialOutcome { return DialOutcome{kind: outOK, t: t} }

// errIgnoredCtx is OutcomeIgnoreCtx's failure.
var errIgnoredCtx = errors.New("rendrtest: scripted dial failed after ignoring its context")

// ScriptedDial returns a dial function with one scripted outcome per call
// (the last one repeats once the script is used up) and its counters.
// Without outcomes every call fails.
func ScriptedDial(outcomes ...DialOutcome) (dial func(ctx context.Context, addr string) (net.Conn, error), counts *DialCounts) {
	counts = &DialCounts{}
	dial = func(ctx context.Context, addr string) (net.Conn, error) {
		k := counts.calls.Add(1) - 1
		if len(outcomes) == 0 {
			return nil, errors.New("rendrtest: ScriptedDial without outcomes")
		}
		return outcomes[min(k, int64(len(outcomes)-1))].dial(ctx, addr, counts)
	}
	return dial, counts
}

func (o DialOutcome) dial(ctx context.Context, addr string, counts *DialCounts) (net.Conn, error) {
	switch o.kind {
	case outRefuse:
		return nil, dialError(addr, errConnRefused)
	case outNetUnreachable:
		return nil, dialError(addr, errNetUnreach)
	case outHostUnreachable:
		return nil, dialError(addr, errHostUnreach)
	case outHang:
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: targetAddr(addr), Err: ctx.Err()}
	case outIgnoreCtx:
		time.Sleep(o.d)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: targetAddr(addr), Err: errIgnoredCtx}
	case outLate:
		time.Sleep(o.d)
		c, _ := TargetPipe(0)
		return counts.track(c), nil
	case outDNSNotFound:
		return nil, &net.DNSError{Err: "no such host", Name: hostOf(addr), IsNotFound: true}
	case outDNSFailure:
		return nil, &net.DNSError{Err: "server misbehaving", Name: hostOf(addr), IsTemporary: true}
	case outPanic:
		panic("rendrtest: scripted dial panic")
	case outGoexit:
		runtime.Goexit()
	case outNilNil:
		return nil, nil
	case outOK:
		c, err := o.t.Dial(ctx, addr)
		if err != nil {
			return nil, err
		}
		return counts.track(c.(*TargetConn)), nil
	}
	return nil, errors.New("rendrtest: zero DialOutcome")
}

// dialError is a connect failure as the net package's dialer reports it.
func dialError(addr string, errno error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Addr: targetAddr(addr), Err: os.NewSyscallError("connect", errno)}
}

// hostOf is addr's host, or addr when it has no port.
func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// DialCounts counts a ScriptedDial's calls and the conns it returned that
// were never closed.
type DialCounts struct {
	calls, unclosed atomic.Int64
}

// track counts conn as unclosed until its first Close.
func (c *DialCounts) track(conn *TargetConn) net.Conn {
	c.unclosed.Add(1)
	conn.setOnClose(func() { c.unclosed.Add(-1) })
	return conn
}

// Calls returns how many times the dial function was called.
func (c *DialCounts) Calls() int64 { return c.calls.Load() }

// Unclosed returns how many returned conns are not closed yet.
func (c *DialCounts) Unclosed() int64 { return c.unclosed.Load() }
