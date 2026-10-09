package carrier

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP7 tests of the trunk/view split (M3 design §A5.1, §A3.1; M3-D1, M3-D3,
// M3-D41).

// hotEP is an l41EP whose deliveries signal got once rxEnd reaches want.
type hotEP struct {
	l41EP
	want   uint64
	got    chan struct{}
	gotOne sync.Once
	views  []*Conn // the Conn of every endpoint call (under l41EP.mu)
}

func (e *hotEP) Fill(c *Conn, b *Batch) {
	e.mu.Lock()
	e.views = append(e.views, c)
	e.mu.Unlock()
	e.l41EP.Fill(c, b)
}

func (e *hotEP) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	e.mu.Lock()
	e.views = append(e.views, c)
	done := off+uint64(len(p)) >= e.want
	e.mu.Unlock()
	err := e.l41EP.Data(c, off, p, buf)
	if done {
		e.gotOne.Do(func() { close(e.got) })
	}
	return err
}

func (e *hotEP) Control(c *Conn, h wire.Header, p []byte) error {
	e.mu.Lock()
	e.views = append(e.views, c)
	e.mu.Unlock()
	return e.l41EP.Control(c, h, p)
}

func newHotEP(env *Env, want uint64) *hotEP {
	return &hotEP{l41EP: l41EP{chunk: env.Bufs.Get(ChunkSize, nil)}, want: want, got: make(chan struct{})}
}

// TestTrunkOneViewHotPath (WP7, M3-D1, §A5.1): a carrier the handshakes
// built is view 1 of its trunk; a one-view trunk never builds the view
// table and never fills the last-hit cache, and its reader reaches the
// endpoint by comparing the frame's handle with view 1's alone — without
// the trunk lock: with trunk.mx held for the whole exchange, DATA (small
// and big, read by reference) and ACKs flow both ways and every endpoint
// call is made with view 1. route answers view 1 for handle 1 and nil for
// every other handle (a session frame for another handle on a dedicated
// carrier is a violation, §A3.2).
func TestTrunkOneViewHotPath(t *testing.T) {
	check := func(t *testing.T, c *Conn, ep *hotEP) {
		t.Helper()
		if c.trunk == nil || c.view1 != c || c.Handle() != wire.SessionHandle {
			t.Fatalf("the carrier is not view 1 of its trunk (trunk %p, view 1 %p, handle %d)", c.trunk, c.view1, c.Handle())
		}
		if c.views != nil || c.last.Load() != nil || c.nviews != 1 || c.Shared() != 1 || c.Mux() {
			t.Fatalf("one-view trunk: table %v, cache %p, %d views, Shared %d, Mux %v", c.views, c.last.Load(), c.nviews, c.Shared(), c.Mux())
		}
		for _, h := range []uint32{0, 2, 7, ^uint32(0)} {
			if v := c.route(h); v != nil {
				t.Fatalf("route(%d) = %p on a one-view trunk, want nil", h, v)
			}
		}
		if c.route(wire.SessionHandle) != c {
			t.Fatal("route(1) is not view 1")
		}
		ep.mu.Lock()
		defer ep.mu.Unlock()
		for i, v := range ep.views {
			if v != c {
				t.Fatalf("endpoint call %d with %p, want view 1 %p", i, v, c)
			}
		}
		if len(ep.views) == 0 {
			t.Fatal("no endpoint call")
		}
	}

	t.Run("view 1, no table, no cache", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			c, p := hPair(t, env, nil)
			ep := newHotEP(env, 21000)
			defer ep.chunk.Release()
			c.Start(ep, &hBell{}, StartOptions{})
			if err := p.send(wire.TypeData, 0, wire.SessionHandle, dataPayload(0, 1000)); err != nil {
				t.Fatal(err)
			}
			if err := p.send(wire.TypeData, 0, wire.SessionHandle, dataPayload(1000, 20000)); err != nil {
				t.Fatal(err)
			}
			var ack [wire.AckLen]byte
			wire.PutAck(ack[:], &wire.Ack{Window: 1 << 20})
			if err := p.send(wire.TypeAck, 0, wire.SessionHandle, ack[:]); err != nil {
				t.Fatal(err)
			}
			ep.offer(5000, false)
			c.Wake()
			synctest.Wait()
			if n := p.dataBytes(); n != 5000 {
				t.Fatalf("peer received %d DATA bytes, want 5000", n)
			}
			if got := ep.rxLog(); len(got) != 3*18 || got[18+17] != 1 || got[2*18] != 'C' {
				t.Fatalf("deliveries %x: want DATA, big DATA by reference, ACK", got)
			}
			check(t, c, ep)
		})
	})

	t.Run("no trunk lock", func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		c := hConn(env, a)
		p := startPeer(b, env.Presets.firstFseq())
		hCleanup(t, c, p)
		const want = 200 << 10
		sent := make(chan struct{})
		var once sync.Once
		p.setHandler(func(wire.Frame) {
			if p.dataBytes() >= want {
				once.Do(func() { close(sent) })
			}
		})
		ep := newHotEP(env, want)
		defer ep.chunk.Release()
		// Held for the whole exchange: a reader or writer that took the
		// trunk lock on the one-view path would stop here.
		c.mx.Lock()
		locked := true
		unlock := func() {
			if locked {
				locked = false
				c.mx.Unlock()
			}
		}
		t.Cleanup(unlock) // before the carrier's cleanup (LIFO)
		c.Start(ep, &hBell{}, StartOptions{})
		ep.offer(want, false)
		c.Wake()
		go func() {
			for off := uint64(0); off < want; off += 10000 {
				if p.send(wire.TypeData, 0, wire.SessionHandle, dataPayload(off, int(min(10000, want-off)))) != nil {
					return
				}
			}
		}()
		bound := time.After(10 * time.Second)
		for _, ch := range []chan struct{}{ep.got, sent} {
			select {
			case <-ch:
			case <-bound:
				_, cause, detail, _ := c.Death()
				t.Fatalf("no progress with the trunk lock held: %d bytes delivered, %d sent (death %v %s)", ep.rxLogLen(), p.dataBytes(), cause, detail)
			}
		}
		unlock()
		check(t, c, ep)
	})
}

func (e *l41EP) rxLogLen() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.log)
}

// TestZeroConnIdentity (WP7): a zero Conn — the bare identity component
// tests of the session build (&carrier.Conn{}) — has no trunk; every
// accessor the session calls on a lane's carrier reports a zero value
// instead of dereferencing it, Wake and OnDone do nothing, and its Done
// never closes.
func TestZeroConnIdentity(t *testing.T) {
	c := &Conn{}
	if c.ID() != 0 || c.Name() != "" || c.Factory() != 0 || c.PeerInstance() != ([16]byte{}) || c.Handle() != 0 {
		t.Fatalf("identity: id %d name %q factory %d", c.ID(), c.Name(), c.Factory())
	}
	if c.Kind() != wire.KindStream || c.MTU() != 0 || c.RecvLimit() != 0 || c.TransportLimit() != 0 || c.DgramMax() != wire.MaxPacketPayload {
		t.Fatalf("kind %v MTU %d", c.Kind(), c.MTU())
	}
	if dead, _, _, _ := c.Death(); dead || c.PeerClosed() || c.PeerGoAway() || c.CloseSent() || c.WriteBlocked() {
		t.Fatal("a zero Conn reports an event")
	}
	if c.SRTT() != 0 || c.Inflight() != 0 || c.Capacity() != 0 || c.Shared() != 0 || c.Mux() {
		t.Fatal("a zero Conn reports estimator values")
	}
	if st := c.Stats(); st != (Stats{Kind: wire.KindStream}) {
		t.Fatalf("Stats %+v", st)
	}
	c.Wake()
	var b hBell
	c.OnDone(&b)
	if c.Done() != nil || b.n.Load() != 0 {
		t.Fatal("a zero Conn's Done closed")
	}
}

// muxCase is one row of TestTrunkOptMuxNegotiation_L44's stream table.
// optUnknown is an optional PREFACE bit no rendr version defines.
const optUnknown uint32 = 1 << 7

type muxCase struct {
	name       string
	mux        bool      // the factory is mux-eligible (Factory.Mux)
	first      wire.Type // the first frame
	dialer     func(b []byte)
	passive    func(b []byte)
	prefOpt    uint32 // the OptMux bit the passive read in the PREFACE
	ackOpt     uint32 // the OptMux bit the dialer read in the PREFACE_ACK
	dialerMux  bool
	passiveMux bool
	violation  bool // Establish fails: an OptMux the dialer did not offer
}

// TestTrunkOptMuxNegotiation_L44 (WP7, §A3.1; M3-D3, M3-D41; L44: a
// semantic change needs both sides' bit): over the stream handshakes
// (Establish and ReadHello on a raw net.Pipe) and the datagram handshakes
// (Establish and ReadHelloDatagram on a link, and a raw passive) the
// dialer sets wire.OptMux in the PREFACE of a session carrier (OPEN, JOIN)
// of a mux-eligible factory only — never on a probe (PING) and never for a
// dedicated factory; the passive echoes it in PREFACE_ACK(OK) iff the
// PREFACE carried it; a carrier is a MUX trunk (Conn.Mux, and
// Established.Fresh on the dialer) iff both carried it, so one side alone
// (an M2 passive, a non-compliant probe) gives a dedicated carrier; and a
// PREFACE_ACK echoing an OptMux the dialer did not offer fails the attempt
// as a carrier error (protocol violation at stage "preface", never a
// version answer).
func TestTrunkOptMuxNegotiation_L44(t *testing.T) {
	setMux := func(b []byte) { b[15] |= byte(wire.OptMux) }
	clearOpt := func(b []byte) { b[12], b[13], b[14], b[15] = 0, 0, 0, 0 }
	setUnknown := func(b []byte) { b[15] |= byte(optUnknown) }
	cases := []muxCase{
		{name: "mux OPEN", mux: true, first: wire.TypeOpen, prefOpt: wire.OptMux, ackOpt: wire.OptMux, dialerMux: true, passiveMux: true},
		{name: "mux JOIN", mux: true, first: wire.TypeJoin, prefOpt: wire.OptMux, ackOpt: wire.OptMux, dialerMux: true, passiveMux: true},
		{name: "probe of a mux factory", mux: true, first: wire.TypePing},
		{name: "dedicated factory", first: wire.TypeOpen},
		{name: "passive without mux", mux: true, first: wire.TypeOpen, passive: clearOpt, prefOpt: wire.OptMux, passiveMux: true},
		{name: "probe offering mux", first: wire.TypePing, dialer: setMux, passive: clearOpt, prefOpt: wire.OptMux},
		{name: "unsolicited echo", first: wire.TypeOpen, passive: setMux, violation: true},
		// Unknown optional bits are ignored and never echoed (§A3.1): the
		// PREFACE_ACK carries exactly OptMux or nothing.
		{name: "unknown bit with mux", mux: true, first: wire.TypeOpen, dialer: setUnknown, prefOpt: wire.OptMux | optUnknown, ackOpt: wire.OptMux, dialerMux: true, passiveMux: true},
		{name: "unknown bit alone", first: wire.TypeOpen, dialer: setUnknown, prefOpt: optUnknown},
	}
	for _, tc := range cases {
		t.Run("stream/"+tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { muxStream(t, tc) })
		})
	}
	t.Run("datagram", func(t *testing.T) { muxDatagram(t) })
}

func muxStream(t *testing.T, tc muxCase) {
	envD, envP := phEnvs()
	a, b := net.Pipe()
	var dc, pc net.Conn = a, b
	if tc.dialer != nil {
		dc = phRewrite(a, tc.dialer)
	}
	if tc.passive != nil {
		pc = phRewrite(b, tc.passive)
	}
	answer := func(h *Hello) {
		switch h.First.Type {
		case wire.TypeOpen:
			h.Conn.Start(&phFirst{place: func(b *Batch) bool {
				return b.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20})
			}}, &hBell{}, StartOptions{Hold: true})
		case wire.TypeJoin:
			h.Conn.Start(&phFirst{place: func(b *Batch) bool {
				return b.AddJoinAck(wire.SessionHandle, &wire.JoinAck{Status: wire.StatusOK})
			}}, &hBell{}, StartOptions{Hold: true})
		default:
			h.Conn.Start(nil, &hBell{}, StartOptions{Sessionless: true})
		}
	}
	pass := phPassive(envP, pc, nil, answer)
	var payload []byte
	switch tc.first {
	case wire.TypeOpen:
		payload = openPayload(0)
	case wire.TypeJoin:
		payload = phJoin()
	}
	f := Factory{Name: "pipe", Mux: tc.mux, Dial: func(context.Context) (net.Conn, error) { return dc, nil }}
	est, err := Establish(context.Background(), envD, f, envD.IDs.Next(), tc.first, payload, nil)
	ph := <-pass
	if ph.h != nil {
		defer func() {
			ph.h.Conn.Kill(CauseLocalClose, "test end")
			hWait(t, ph.h.Conn)
		}()
	}
	if tc.violation {
		var ee *EstablishError
		if est != nil || !errors.As(err, &ee) {
			t.Fatalf("Establish: %v %v, want a carrier error", est, err)
		}
		if ee.Stage != "preface" || ee.Cause != CauseProtocolViolation || ee.Status != wire.PrefaceOK || ee.PrefaceOK {
			t.Fatalf("error %+v, want a protocol violation at stage preface without a status", ee)
		}
		return
	}
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() {
		est.Conn.Kill(CauseLocalClose, "test end")
		hWait(t, est.Conn)
	}()
	if ph.err != nil {
		t.Fatalf("ReadHello: %v", ph.err)
	}
	if ph.h.Preface.Opt != tc.prefOpt {
		t.Errorf("PREFACE opt %#x, want %#x", ph.h.Preface.Opt, tc.prefOpt)
	}
	if est.Ack.Opt != tc.ackOpt {
		t.Errorf("PREFACE_ACK opt %#x, want exactly %#x", est.Ack.Opt, tc.ackOpt)
	}
	if est.Conn.Mux() != tc.dialerMux || est.Fresh != tc.dialerMux {
		t.Errorf("dialer Mux %v Fresh %v, want %v", est.Conn.Mux(), est.Fresh, tc.dialerMux)
	}
	if ph.h.Conn.Mux() != tc.passiveMux {
		t.Errorf("passive Mux %v, want %v", ph.h.Conn.Mux(), tc.passiveMux)
	}
	if est.Conn.Handle() != wire.SessionHandle || ph.h.Conn.Handle() != wire.SessionHandle || est.Conn.Shared() != 1 {
		t.Errorf("handles %d/%d, Shared %d: want view 1 of a one-view trunk", est.Conn.Handle(), ph.h.Conn.Handle(), est.Conn.Shared())
	}
}

// muxDatagram is the datagram half of TestTrunkOptMuxNegotiation_L44.
func muxDatagram(t *testing.T) {
	type dgCase struct {
		name    string
		mux     bool
		first   wire.Type
		wantOpt uint32 // OptMux in the PREFACE and the PREFACE_ACK
		wantMux bool   // both sides
	}
	for _, tc := range []dgCase{
		{name: "mux OPEN", mux: true, first: wire.TypeOpen, wantOpt: wire.OptMux, wantMux: true},
		{name: "mux JOIN", mux: true, first: wire.TypeJoin, wantOpt: wire.OptMux, wantMux: true},
		{name: "probe of a mux factory", mux: true, first: wire.TypePing},
		{name: "dedicated factory", first: wire.TypeOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				pas := &wbPassive{}
				pas.act = wbAdmit(&dEP{}, nil)
				r := newWBRig(t, 1200, pas.run)
				r.f.Mux = tc.mux
				var payload []byte
				switch tc.first {
				case wire.TypeOpen:
					payload = wbOpen(1100)
				case wire.TypeJoin:
					payload = wbJoin()
				}
				est, err := r.establish(context.Background(), tc.first, payload)
				if err != nil {
					t.Fatalf("Establish: %v", err)
				}
				synctest.Wait()
				hs := pas.helloList()
				if len(hs) != 1 {
					t.Fatalf("%d Hellos, want 1", len(hs))
				}
				if hs[0].Preface.Opt != tc.wantOpt {
					t.Errorf("PREFACE opt %#x, want %#x", hs[0].Preface.Opt, tc.wantOpt)
				}
				if est.Ack.Opt != tc.wantOpt {
					t.Errorf("PREFACE_ACK opt %#x, want exactly %#x", est.Ack.Opt, tc.wantOpt)
				}
				if est.Conn.Mux() != tc.wantMux || est.Fresh != tc.wantMux || hs[0].Conn.Mux() != tc.wantMux {
					t.Errorf("dialer Mux %v Fresh %v, passive Mux %v; want %v", est.Conn.Mux(), est.Fresh, hs[0].Conn.Mux(), tc.wantMux)
				}
			})
		})
	}
	// A raw passive answers H1 with a PREFACE_ACK whose opt it chooses.
	raw := func(t *testing.T, mux bool, ackOpt uint32) (*Established, error, []byte) {
		r, raws := wbRawRig(t, 1200)
		r.f.Mux = mux
		type res struct {
			est *Established
			err error
		}
		ch := make(chan res, 1)
		go func() {
			est, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
			ch <- res{est, err}
		}()
		w := <-raws
		h1 := w.waitN(t, 1)[0].b
		pf, err := wire.ParsePreface(h1[:wire.PrefaceLen])
		if err != nil {
			t.Fatalf("H1: %v", err)
		}
		ab := make([]byte, wire.PrefaceLen)
		wire.PutPrefaceAck(ab, &wire.PrefaceAck{Minor: wire.Minor, Status: wire.PrefaceOK, Opt: ackOpt, Instance: r.penv.Local, CarrierID: pf.CarrierID})
		fs := r.penv.Presets.fseqFrom(ab)
		F := r.penv.Presets.firstCseq()
		var rk [wire.RackLen]byte
		wire.PutRack(rk[:], &wire.Rack{CumAck: F})
		h2 := wire.AppendFrame(ab, wire.Header{Type: wire.TypeRack, Fseq: fs}, rk[:])
		h2 = append(h2, wbFrame(wire.TypeRel, 0, fs+1, 0, relPayloadOf(F, wire.TypeOpenAck, 0, wire.SessionHandle, wbOpenAckOK(1100, 1200)))...)
		w.send(h2)
		x := <-ch
		return x.est, x.err, h1
	}
	t.Run("passive without mux", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			est, err, h1 := raw(t, true, 0)
			if err != nil {
				t.Fatalf("Establish: %v", err)
			}
			if pf, _ := wire.ParsePreface(h1[:wire.PrefaceLen]); pf.Opt&wire.OptMux == 0 {
				t.Errorf("H1 PREFACE opt %#x: a mux factory's OPEN offers OptMux", pf.Opt)
			}
			if est.Conn.Mux() || est.Fresh {
				t.Errorf("Mux %v Fresh %v with a passive that did not echo: want a dedicated carrier", est.Conn.Mux(), est.Fresh)
			}
		})
	})
	// A raw dialer sends an H1 whose PREFACE opt it chooses to the real
	// datagram passive (ReadHelloDatagram): the passive echoes exactly the
	// OptMux bit the PREFACE carried (§A3.1), never an unknown optional
	// bit, and its carrier is a MUX trunk only when the first frame is a
	// session's (M3-D41: a PING-first carrier never is, whatever the
	// PREFACE offered).
	for _, tc := range []struct {
		name    string
		opt     uint32
		first   wire.Type
		wantAck uint32
		wantMux bool
	}{
		{name: "probe offering mux", opt: wire.OptMux, first: wire.TypePing, wantAck: wire.OptMux},
		{name: "unknown bit with mux", opt: wire.OptMux | optUnknown, first: wire.TypeOpen, wantAck: wire.OptMux, wantMux: true},
		{name: "unknown bit alone", opt: optUnknown, first: wire.TypeOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				denv, penv := wbEnvs()
				a, b := newFakeIOPair(1500)
				defer a.Close()
				ch := wbReadHello(penv, b, nil)
				pre := make([]byte, wire.PrefaceLen)
				wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindDatagram, Opt: tc.opt, Instance: denv.Local, CarrierID: 9})
				first := denv.Presets.fseqFrom(pre)
				h1 := pre
				if tc.first == wire.TypePing {
					h1 = append(h1, wbFrame(wire.TypePing, 0, first, 0, wbPingPayload(wire.Ping{ID: 1, Nonce: 42}))...)
				} else {
					h1 = append(h1, wbFrame(wire.TypeRel, 0, first, 0, relPayloadOf(denv.Presets.firstCseq(), tc.first, 0, wire.SessionHandle, wbOpen(1100)))...)
				}
				if err := a.WriteDatagram(h1); err != nil {
					t.Fatalf("H1: %v", err)
				}
				r := <-ch
				if r.err != nil {
					t.Fatalf("ReadHelloDatagram: %v", r.err)
				}
				defer func() {
					r.h.Conn.Kill(CauseLocalClose, "test end")
					<-r.h.Conn.Done()
				}()
				if r.h.First.Type != tc.first || r.h.Preface.Opt != tc.opt {
					t.Fatalf("Hello first %v opt %#x, want %v %#x", r.h.First.Type, r.h.Preface.Opt, tc.first, tc.opt)
				}
				synctest.Wait()
				h2, ok := a.tryRead()
				if !ok || !wire.IsPreface(h2) {
					t.Fatalf("no H2 (%x)", h2)
				}
				ack, err := wire.ParsePrefaceAck(h2[:wire.PrefaceLen])
				if err != nil || ack.Status != wire.PrefaceOK {
					t.Fatalf("H2 PREFACE_ACK %+v, %v", ack, err)
				}
				if ack.Opt != tc.wantAck {
					t.Errorf("PREFACE_ACK opt %#x, want exactly %#x", ack.Opt, tc.wantAck)
				}
				if r.h.Conn.Mux() != tc.wantMux {
					t.Errorf("passive Mux %v, want %v", r.h.Conn.Mux(), tc.wantMux)
				}
			})
		})
	}
	t.Run("unsolicited echo", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			est, err, h1 := raw(t, false, wire.OptMux)
			if pf, _ := wire.ParsePreface(h1[:wire.PrefaceLen]); pf.Opt != 0 {
				t.Errorf("H1 PREFACE opt %#x from a dedicated factory", pf.Opt)
			}
			var ee *EstablishError
			if est != nil || !errors.As(err, &ee) {
				t.Fatalf("Establish: %v %v, want a carrier error", est, err)
			}
			if ee.Stage != "preface" || ee.Cause != CauseProtocolViolation || ee.Status != wire.PrefaceOK || ee.PrefaceOK {
				t.Fatalf("error %+v, want a protocol violation at stage preface without a status", ee)
			}
		})
	})
}
