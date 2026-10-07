package carrier

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// WP3b test harness: the datagram handshakes between a dialer (Establish
// over a datagram factory) and a passive (NewPacketIO and
// ReadHelloDatagram, or a scripted raw passive) across a
// rendrtest.DatagramLink, and wbPC, a scripted net.PacketConn for the
// embedder adapter. Everything runs inside testing/synctest bubbles. Names
// use the wb prefix (WP3a's harness uses dg*, fake*, raw*).

// wbSID is the session ID of the harness's OPEN and JOIN payloads.
var wbSID = [16]byte{0x5e, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x5e}

// wbOpen returns a packet OPEN payload offering MaxPayload pmtu (its
// window, the cmtu offer, is written by Establish).
func wbOpen(pmtu uint16) []byte {
	p := make([]byte, wire.OpenFixedLen)
	wire.PutOpen(p, &wire.Open{SID: wbSID, Kind: wire.KindDatagram, Mode: 1, RetainMs: 30000, PMTU: pmtu})
	return p
}

// wbJoin returns a packet JOIN payload (its rxNext, the cmtu offer, is
// written by Establish).
func wbJoin() []byte {
	p := make([]byte, wire.JoinLen)
	wire.PutJoin(p, &wire.Join{SID: wbSID, Mode: 1})
	return p
}

// wbEnvs returns the dialer's and the passive's Env (distinct instances).
func wbEnvs() (d, p *Env) {
	d, p = dgEnv(), dgEnv()
	p.Local = hPassiveInst
	return d, p
}

// wbRig is a dialer Env and factory over a DatagramLink whose passive ends
// run pass on a goroutine of the rig (joined by the cleanup).
type wbRig struct {
	t    testing.TB
	denv *Env
	penv *Env
	link *rendrtest.DatagramLink
	f    Factory

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns []*Conn // every Conn of either side the rig must kill and join
	pass  func(r *wbRig, pc net.PacketConn, peer net.Addr)
}

// newWBRig builds the rig inside the caller's bubble: a factory of frame
// budget mtu over a link whose passive ends run pass. The cleanup kills
// and joins every recorded Conn, closes the link and joins the passive
// goroutines.
func newWBRig(t testing.TB, mtu int, pass func(r *wbRig, pc net.PacketConn, peer net.Addr)) *wbRig {
	r := &wbRig{t: t, pass: pass}
	r.denv, r.penv = wbEnvs()
	r.link = rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: "wb", Accept: func(pc net.PacketConn, peer net.Addr) error {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.pass(r, pc, peer)
		}()
		return nil
	}})
	r.f = Factory{Index: 0, Name: "wb0", Kind: wire.KindDatagram, DialPacket: r.link.Dial, MTU: mtu}
	t.Cleanup(func() {
		r.mu.Lock()
		cs := append([]*Conn(nil), r.conns...)
		r.mu.Unlock()
		for _, c := range cs {
			c.Kill(CauseLocalClose, "test cleanup")
			<-c.Done()
		}
		r.link.Close()
		r.wg.Wait()
	})
	return r
}

// keep records c for the cleanup.
func (r *wbRig) keep(c *Conn) {
	r.mu.Lock()
	r.conns = append(r.conns, c)
	r.mu.Unlock()
}

// establish runs one dialer attempt of first frame t.
func (r *wbRig) establish(ctx context.Context, t wire.Type, payload []byte) (*Established, error) {
	est, err := Establish(ctx, r.denv, r.f, r.denv.IDs.Next(), t, payload, nil)
	if est != nil {
		r.keep(est.Conn)
	}
	return est, err
}

// wbPassive is the real passive of a rig: NewPacketIO over the link's
// passive end, ReadHelloDatagram, then act (nil: the Hello is only
// recorded; the Conn is killed by the cleanup).
type wbPassive struct {
	gate func(*wire.Preface) wire.PrefaceStatus
	act  func(r *wbRig, h *Hello)

	mu     sync.Mutex
	hellos []*Hello
	errs   []error
}

func (p *wbPassive) run(r *wbRig, pc net.PacketConn, peer net.Addr) {
	io, err := NewPacketIO(r.penv, pc, peer, wire.MaxDatagram)
	if err != nil {
		pc.Close()
		return
	}
	var gate Gate
	if p.gate != nil {
		gate = p.gate
	}
	h, err := ReadHelloDatagram(r.penv, io, time.Now().Add(10*time.Second), 255, gate)
	p.mu.Lock()
	if err != nil {
		p.errs = append(p.errs, err)
	} else {
		p.hellos = append(p.hellos, h)
	}
	p.mu.Unlock()
	if err != nil {
		return
	}
	r.keep(h.Conn)
	if p.act != nil {
		p.act(r, h)
	}
}

func (p *wbPassive) helloList() []*Hello {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*Hello(nil), p.hellos...)
}

// wbOfferOf returns the cmtu offer an OPEN or JOIN Hello carries.
func wbOfferOf(h *Hello) int {
	switch h.First.Type {
	case wire.TypeOpen:
		return int(binary.BigEndian.Uint32(h.Payload[24:28]))
	case wire.TypeJoin:
		return int(binary.BigEndian.Uint64(h.Payload[17:25]))
	}
	return 0
}

// wbAdmit is a passive admission for OPEN and JOIN Hellos: SetBudget with
// min(offer, Limit) and Start held with ep, whose Fill places the first
// response (OPEN_ACK or JOIN_ACK OK) once and then runs extra (nil: none)
// in the same round. Probe Hellos start sessionless.
func wbAdmit(ep *dEP, extra func(c *Conn, b *Batch)) func(r *wbRig, h *Hello) {
	return func(r *wbRig, h *Hello) {
		if h.First.Type == wire.TypePing {
			h.Conn.Start(nil, nil, StartOptions{Sessionless: true})
			return
		}
		cmtu := min(wbOfferOf(h), h.Conn.dg.io.Limit())
		h.Conn.SetBudget(cmtu)
		var placed atomic.Bool
		typ := h.First.Type
		ep.setFill(func(c *Conn, b *Batch) {
			if !placed.Load() {
				ok := false
				if typ == wire.TypeOpen {
					ok = b.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK, Window: wire.PacketWindow(uint16(cmtu-wire.DgramOverhead), uint16(cmtu))})
				} else {
					ok = b.AddJoinAck(wire.SessionHandle, &wire.JoinAck{Status: wire.StatusOK, RxNext: uint64(cmtu)})
				}
				if !ok {
					return
				}
				placed.Store(true)
				if extra != nil {
					extra(c, b)
				}
			}
		})
		h.Conn.Start(ep, &hBell{}, StartOptions{Hold: true})
	}
}

// wbRaw is a scripted passive on a link's passive end: it records every
// datagram that arrives (with its arrival time) and writes what the test
// gives it.
type wbRaw struct {
	pc   net.PacketConn
	peer net.Addr
	mu   sync.Mutex
	got  []wbGot
	wake chan struct{}
	gone chan struct{}
}

type wbGot struct {
	b  []byte
	at time.Time
}

// newWBRaw starts the reader of a raw passive on pc (it ends when pc
// closes).
func newWBRaw(pc net.PacketConn, peer net.Addr) *wbRaw {
	w := &wbRaw{pc: pc, peer: peer, wake: make(chan struct{}, 1), gone: make(chan struct{})}
	return w
}

// loop reads until pc fails.
func (w *wbRaw) loop() {
	defer close(w.gone)
	buf := make([]byte, 1<<16)
	for {
		n, _, err := w.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		w.mu.Lock()
		w.got = append(w.got, wbGot{b: bytes.Clone(buf[:n]), at: time.Now()})
		w.mu.Unlock()
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
}

func (w *wbRaw) send(b []byte) { _, _ = w.pc.WriteTo(b, w.peer) }

func (w *wbRaw) received() []wbGot {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]wbGot(nil), w.got...)
}

// waitN waits (virtual time) until at least n datagrams arrived.
func (w *wbRaw) waitN(t testing.TB, n int) []wbGot {
	t.Helper()
	deadline := time.After(time.Minute)
	for {
		if g := w.received(); len(g) >= n {
			return g
		}
		select {
		case <-w.wake:
		case <-deadline:
			t.Fatalf("raw passive: %d datagrams, want %d", len(w.received()), n)
		}
	}
}

// wbRawRig returns a rig whose passive ends are raw passives, delivered on
// the returned channel (one per carrier).
func wbRawRig(t testing.TB, mtu int) (*wbRig, <-chan *wbRaw) {
	ch := make(chan *wbRaw, 16)
	r := newWBRig(t, mtu, func(r *wbRig, pc net.PacketConn, peer net.Addr) {
		w := newWBRaw(pc, peer)
		ch <- w
		w.loop()
	})
	return r, ch
}

// wbH2 builds H2 rendr bytes answering the PREFACE pre: PREFACE_ACK(OK) of
// the passive Env penv ‖ RACK{cum} at the PREFACE_ACK's first fseq, and
// returns the passive's next fseq.
func wbH2(penv *Env, pre []byte, cum uint32) ([]byte, uint32) {
	pf, _ := wire.ParsePreface(pre[:wire.PrefaceLen])
	ab := make([]byte, wire.PrefaceLen)
	wire.PutPrefaceAck(ab, &wire.PrefaceAck{Minor: wire.Minor, Status: wire.PrefaceOK, Instance: penv.Local, CarrierID: pf.CarrierID})
	first := penv.Presets.fseqFrom(ab)
	var rk [wire.RackLen]byte
	wire.PutRack(rk[:], &wire.Rack{CumAck: cum})
	return wire.AppendFrame(ab, wire.Header{Type: wire.TypeRack, Fseq: first}, rk[:]), first + 1
}

// wbFrame encodes one frame.
func wbFrame(t wire.Type, flags uint8, fseq, handle uint32, payload []byte) []byte {
	return wire.AppendFrame(nil, wire.Header{Type: t, Flags: flags, Fseq: fseq, Handle: handle}, payload)
}

// wbOpenAckOK is an OPEN_ACK(OK) payload for a packet session.
func wbOpenAckOK(pmtu, cmtu int) []byte {
	p := make([]byte, wire.OpenAckFixedLen)
	n := wire.PutOpenAck(p, &wire.OpenAck{Status: wire.StatusOK, Window: wire.PacketWindow(uint16(pmtu), uint16(cmtu))})
	return p[:n]
}

// wbPingPayload encodes a PING or PONG payload.
func wbPingPayload(p wire.Ping) []byte {
	b := make([]byte, wire.PingFixedLen+p.Pad)
	wire.PutPing(b, &p)
	return b
}

// wbRelsIn returns the RELs in rendr bytes d (after an optional PREFACE).
func wbRelsIn(d []byte) []wire.RelHead {
	if wire.IsPreface(d) {
		d = d[wire.PrefaceLen:]
	}
	return relsOf(d)
}

// wbPC is a scripted net.PacketConn (the embedder adapter's tests): reads
// return the queued results in order and block — honouring the read
// deadline unless ignoreDL — while none is queued; writes are recorded and
// answered by wfn (nil: written whole). Close ends every call once and
// counts.
type wbPC struct {
	mu       sync.Mutex
	reads    []wbRead
	writes   []wbWrite
	wfn      func(p []byte, addr net.Addr) (int, error)
	rdl      time.Time
	ignoreDL bool
	lastLen  int // len(p) of the latest ReadFrom
	wake     chan struct{}
	done     chan struct{}
	closed   bool
	closes   atomic.Int32
	deadSets atomic.Int32
}

type wbRead struct {
	b   []byte
	n   int // used when b is nil (a count of its own)
	src net.Addr
	err error
}

type wbWrite struct {
	b    []byte
	addr net.Addr
}

func newWBPC() *wbPC {
	return &wbPC{wake: make(chan struct{}, 1), done: make(chan struct{})}
}

func (c *wbPC) push(r wbRead) {
	c.mu.Lock()
	c.reads = append(c.reads, r)
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *wbPC) ReadFrom(p []byte) (int, net.Addr, error) {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		c.mu.Lock()
		c.lastLen = len(p)
		if c.closed {
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		if len(c.reads) > 0 {
			r := c.reads[0]
			c.reads = c.reads[1:]
			c.mu.Unlock()
			if r.b == nil {
				return r.n, r.src, r.err
			}
			return copy(p, r.b), r.src, r.err
		}
		var dl <-chan time.Time
		if !c.rdl.IsZero() && !c.ignoreDL {
			d := time.Until(c.rdl)
			if d <= 0 {
				c.mu.Unlock()
				return 0, nil, os.ErrDeadlineExceeded
			}
			if timer == nil {
				timer = time.NewTimer(d)
			} else {
				timer.Reset(d)
			}
			dl = timer.C
		}
		c.mu.Unlock()
		select {
		case <-c.wake:
		case <-c.done:
		case <-dl:
		}
	}
}

func (c *wbPC) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, wbWrite{b: bytes.Clone(p), addr: addr})
	fn := c.wfn
	c.mu.Unlock()
	if fn != nil {
		return fn(p, addr)
	}
	return len(p), nil
}

func (c *wbPC) Close() error {
	c.closes.Add(1)
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
	c.mu.Unlock()
	return nil
}

func (c *wbPC) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (c *wbPC) SetDeadline(t time.Time) error {
	c.deadSets.Add(1)
	return c.SetReadDeadline(t)
}

func (c *wbPC) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

func (c *wbPC) SetWriteDeadline(t time.Time) error { return nil }

func (c *wbPC) written() []wbWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]wbWrite(nil), c.writes...)
}

// wbCountPC counts the Close calls of a factory's conn.
type wbCountPC struct {
	net.PacketConn
	closes *atomic.Int32
}

func (c wbCountPC) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

// wbBubble runs f in a synctest bubble.
func wbBubble(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	synctest.Test(t, f)
}
