package session

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Packet-session actor test harness (M2 design §A11.3 WP6b: "actor
// harness"). It reuses the actor tests' world (acWorld: two sessions over
// real carrier.Conns on rendrtest.Links inside synctest bubbles) with a
// packet admission shim standing in for the root's (package rendr): a
// packet OPEN gets the M2-D49 passive values — on the stream carriers these
// links make, cmtu_acc is 0 and pmtu_acc = min(OPEN.pmtu, the passive's own
// Packet.MaxPayload) — and a packet session from NewPending. Packet
// sessions ride stream carriers here (DGRAM and PACK are ordinary frames
// on them, M2-D26); datagram carriers need the datagram handshakes (WP3b)
// and are exercised by the root's end-to-end rows (integ2_e2e*_test.go).
// Every package-level helper starts
// with "wp".

// wpPacketParams returns the actor-test Params template p as a packet
// session's, with maxPayload as its MaxPayload (dialer: the offer; passive:
// its own limit).
func wpPacketParams(p Params, maxPayload int) Params {
	p.Kind = wire.KindDatagram
	p.Packet = PacketParams{
		MaxPayload: maxPayload, Queue: 1 << 20, MaxAge: 100 * time.Millisecond,
		PacketPing: time.Second, PackEvery: 256, FinWaitMax: time.Second,
		DedupBits: wire.DefaultSeqWindowBits,
	}
	return p
}

// wpNewWorld is acNewWorld with the datagram buffer pools set.
func wpNewWorld(t testing.TB, hooks *testhooks.Hooks) *acWorld {
	w := acNewWorld(t, hooks)
	w.a.cenv.DBufs = carrier.NewDatagramBufPool()
	w.b.cenv.DBufs = carrier.NewDatagramBufPool()
	return w
}

// wpLink makes a link to the passive whose admission takes packet OPENs
// with own as the passive's Packet.MaxPayload.
func wpLink(w *acWorld, name string, own int) *rendrtest.Link {
	l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: wpAccept(w.b, own)})
	l.SetDelay(acLinkDelay, 0)
	w.links = append(w.links, l)
	return l
}

// wpAccept is acPassive.accept with the packet admission of wpAdmitOpen.
func wpAccept(p *acPassive, own int) func(net.Conn) error {
	return func(nc net.Conn) error {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			h, err := carrier.ReadHello(p.cenv, nc, time.Now().Add(2*time.Second), p.maxMeta, p.gate)
			if err != nil {
				return
			}
			switch h.First.Type {
			case wire.TypeOpen:
				wpAdmitOpen(p, h, own)
			case wire.TypeJoin:
				p.admitJoin(h)
			default:
				h.Conn.Kill(carrier.CauseLocalClose, "no sessionless carriers in actor tests")
				p.closed(h.Conn)
			}
		}()
		return nil
	}
}

// wpAdmitOpen admits an OPEN as the root does for packet sessions (M2
// design §A5.14 admitOpen on a stream carrier): a packet OPEN whose window
// is not 0 is BAD_REQUEST(CodeBadValue); PassiveSpec.MaxPayload =
// min(pmtu, own); a stream OPEN takes acPassive's admission.
func wpAdmitOpen(p *acPassive, h *carrier.Hello, own int) {
	o, err := wire.ParseOpen(h.Payload, p.maxMeta)
	if err != nil {
		p.answerOpen(h.Conn, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeBadValue})
		return
	}
	if o.Kind != wire.KindDatagram {
		p.admitOpen(h)
		return
	}
	if p.answer != nil {
		if oa, ok := p.answer(&o); ok {
			p.answerOpen(h.Conn, oa)
			return
		}
	}
	if o.Window != 0 {
		p.answerOpen(h.Conn, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeBadValue})
		return
	}
	p.mu.Lock()
	e := p.tab[o.SID]
	if e == nil {
		pp := wpPacketParams(p.p, own)
		pp.Role, pp.Mode = RolePassive, Mode(o.Mode)
		pp.Grace = min(max(time.Duration(o.RetainMs)*time.Millisecond, time.Second), 400*time.Second)
		spec := PassiveSpec{SID: o.SID, Params: pp, DialerInstance: h.Preface.Instance, PeerWindow: o.Window,
			Metadata: o.Metadata, MaxPayload: min(int(o.PMTU), own)}
		s := NewPending(p.env, spec, h.Conn)
		p.tab[o.SID] = &acEntry{s: s}
		p.mu.Unlock()
		s.Start()
		p.pending <- s
		return
	}
	s, tomb, v := e.s, e.tomb, e.v
	p.mu.Unlock()
	if tomb {
		p.answerOpen(h.Conn, v.OpenAck())
		return
	}
	if taken, v := s.AttachOpen(h.Conn); !taken {
		p.mu.Lock()
		p.openRefuse[[2]uint32{uint32(v.Status), v.Code}]++
		p.mu.Unlock()
		p.answerOpen(h.Conn, v.OpenAck())
	}
}

// wpSpec returns a packet DialSpec over links with offer as the MaxPayload
// offer.
func wpSpec(w *acWorld, mode Mode, offer int, links ...*rendrtest.Link) DialSpec {
	spec := w.spec(mode, links...)
	spec.Params = wpPacketParams(spec.Params, offer)
	return spec
}

// wpOpen dials spec and confirms the passive side.
func wpOpen(w *acWorld, spec DialSpec, h healthSource) (dialer, passive *Session) {
	w.t.Helper()
	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := w.dial(context.Background(), spec, h)
		ch <- res{s, err}
	}()
	passive = w.confirmNext()
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("Dial: %v", r.err)
	}
	return r.s, passive
}

// wpFlow is a datagram flow from one packet session to another: a writer
// that sends a numbered datagram every interval and a reader that counts
// distinct arrivals (dpPayload ids) and the longest gap between arrivals.
type wpFlow struct {
	sent, got atomic.Int64
	quit      chan struct{}
	wdone     chan struct{}
	rdone     chan struct{}

	mu      sync.Mutex
	seen    map[uint64]bool
	dups    int
	last    time.Time
	maxGap  time.Duration
	readErr error
}

// wpStartFlow starts a flow from → to of size-byte datagrams.
func wpStartFlow(from, to *Session, size int, every time.Duration) *wpFlow {
	f := &wpFlow{quit: make(chan struct{}), wdone: make(chan struct{}), rdone: make(chan struct{}), seen: make(map[uint64]bool)}
	go func() {
		defer close(f.wdone)
		t := time.NewTicker(every)
		defer t.Stop()
		for id := uint64(0); ; id++ {
			select {
			case <-f.quit:
				return
			case <-t.C:
			}
			if _, err := from.WriteTo(dpPayload(id, size)); err != nil {
				return
			}
			f.sent.Add(1)
		}
	}()
	go func() {
		defer close(f.rdone)
		buf := make([]byte, 1<<16)
		for {
			n, err := to.ReadFrom(buf)
			if err != nil {
				f.mu.Lock()
				f.readErr = err
				f.mu.Unlock()
				return
			}
			now := time.Now()
			f.mu.Lock()
			id := dpID(buf[:n])
			if f.seen[id] {
				f.dups++
			}
			f.seen[id] = true
			if !f.last.IsZero() {
				f.maxGap = max(f.maxGap, now.Sub(f.last))
			}
			f.last = now
			f.mu.Unlock()
			f.got.Add(1)
		}
	}()
	return f
}

// stop ends the writer and waits for it (the reader ends with its session).
func (f *wpFlow) stop() {
	select {
	case <-f.quit:
	default:
		close(f.quit)
	}
	<-f.wdone
}

// resetGap restarts the longest-gap measurement.
func (f *wpFlow) resetGap() {
	f.mu.Lock()
	f.maxGap, f.last = 0, time.Time{}
	f.mu.Unlock()
}

// gap returns the longest gap between arrivals since the last reset.
func (f *wpFlow) gap() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxGap
}

// duplicates returns the datagrams received more than once.
func (f *wpFlow) duplicates() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dups
}

// wpLocked runs fn under s.mu.
func wpLocked[T any](s *Session, fn func() T) T {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn()
}

// wpLaneByID returns s's lane with CarrierID id (nil if none), under s.mu.
func wpLaneByID(s *Session, id uint32) *lane {
	return wpLocked(s, func() *lane {
		for _, l := range s.lanes {
			if l.id == id {
				return l
			}
		}
		return nil
	})
}

// wpBudgetConn is a fake budgetConn: a carrier of a kind whose RecvLimit
// is its offer until SetBudget fixes the negotiated value.
type wpBudgetConn struct {
	kind   wire.CarrierKind
	limit  int
	set    int
	called bool
}

func (c *wpBudgetConn) Kind() wire.CarrierKind { return c.kind }
func (c *wpBudgetConn) RecvLimit() int         { return c.limit }
func (c *wpBudgetConn) SetBudget(cmtu int) {
	c.called, c.set = true, cmtu
	if c.kind == wire.KindDatagram {
		c.limit = cmtu
	}
}

var _ budgetConn = (*wpBudgetConn)(nil)
