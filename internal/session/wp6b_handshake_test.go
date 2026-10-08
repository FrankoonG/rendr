package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The packet handshake values (M2 design §A3.5, §A5.4; M2-D11, M2-D49,
// M2-D50; Revision 1, R1-5, R1-11, R1-32): what OPEN, OPEN_ACK, JOIN and
// JOIN_ACK carry for a packet session, how each side checks them and which
// carriers a session refuses.

const (
	kStream = wire.KindStream
	kDgram  = wire.KindDatagram
)

// TestPacketOpenAckFields_L37: the dialer checks every OPEN_ACK(OK) of a
// packet session per carrier — cmtu_acc 0 on a stream carrier and
// MinFrameBudget … that carrier's offer on a datagram carrier, pmtu_acc
// 512 … the session's offer — the first one fixes MaxPayload, a later one
// must repeat it, and a valid one sets the carrier's budget (L37: one
// MaxPayload for the whole session, every carrier's own budget). End to
// end, the passive's limit becomes the dialer's MaxPayload, and an answer
// outside the rules is a violation of its carrier, never the session's
// value.
func TestPacketOpenAckFields_L37(t *testing.T) {
	pw := wire.PacketWindow
	for _, tc := range []struct {
		name      string
		kind      wire.CarrierKind
		cmtuOffer int    // the carrier's offer (its RecvLimit before SetBudget)
		offer     int    // the session's MaxPayload offer
		fixed     int    // MaxPayload an earlier OPEN_ACK fixed (0: this is the first)
		window    uint32 // the OPEN_ACK's window
		err       error
		budget    int // SetBudget's value; -1: not called
		maxPay    int // the session's MaxPayload afterwards
	}{
		{"stream carrier, cmtu 0", kStream, 0, 1400, 0, pw(1250, 0), nil, 0, 1250},
		{"stream carrier, cmtu set", kStream, 0, 1400, 0, pw(1250, 1200), errPktCmtu, -1, 0},
		{"datagram carrier, cmtu = offer", kDgram, 1400, 1375, 0, pw(1375, 1400), nil, 1400, 1375},
		{"datagram carrier, cmtu below the offer", kDgram, 1400, 1375, 0, pw(1100, 1125), nil, 1125, 1100},
		{"datagram carrier, cmtu above the offer", kDgram, 1400, 1375, 0, pw(1375, 1401), errPktCmtu, -1, 0},
		{"datagram carrier, cmtu below MinFrameBudget", kDgram, 1400, 1375, 0, pw(512, wire.MinFrameBudget-1), errPktCmtu, -1, 0},
		{"datagram carrier, cmtu 0", kDgram, 1400, 1375, 0, pw(1375, 0), errPktCmtu, -1, 0},
		{"pmtu below 512", kStream, 0, 1400, 0, pw(511, 0), errPktPmtu, -1, 0},
		{"pmtu above the offer", kStream, 0, 1400, 0, pw(1401, 0), errPktPmtu, -1, 0},
		{"a later carrier repeats MaxPayload", kDgram, 1400, 1400, 1250, pw(1250, 1300), nil, 1300, 1250},
		{"a later carrier changes MaxPayload", kDgram, 1400, 1400, 1250, pw(1251, 1300), errPktPmtuChanged, -1, 1250},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dpSession(dpOpt{maxPayload: tc.offer})
			s.pk.maxPayload = tc.fixed
			c := &wpBudgetConn{kind: tc.kind, limit: tc.cmtuOffer}
			s.mu.Lock()
			err := s.pktOpenAckLocked(c, tc.window, tc.fixed == 0)
			s.mu.Unlock()
			if !errors.Is(err, tc.err) || (err == nil) != (tc.err == nil) {
				t.Fatalf("pktOpenAckLocked = %v, want %v", err, tc.err)
			}
			if got := s.MaxPayload(); got != tc.maxPay {
				t.Fatalf("MaxPayload %d, want %d", got, tc.maxPay)
			}
			if tc.budget < 0 && c.called {
				t.Fatalf("SetBudget(%d) on a refused answer", c.set)
			}
			if tc.budget >= 0 && (!c.called || c.set != tc.budget) {
				t.Fatalf("SetBudget called %v with %d, want %d", c.called, c.set, tc.budget)
			}
		})
	}

	t.Run("end to end: the passive's limit is the session's", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wpNewWorld(t, nil)
			defer w.teardown()
			l := wpLink(w, "p1", 1250)
			a, b := wpOpen(w, wpSpec(w, ModeSelector, 1400, l), nil)
			if a.MaxPayload() != 1250 || b.MaxPayload() != 1250 {
				t.Fatalf("MaxPayload dialer %d passive %d, want 1250 (min of the offer 1400 and the passive's 1250)", a.MaxPayload(), b.MaxPayload())
			}
			for _, s := range []*Session{a, b} {
				if n, err := s.WriteTo(make([]byte, 1251)); n != 0 || !errors.Is(err, ErrPacketTooLarge) {
					t.Fatalf("%v: WriteTo(1251) = %d, %v; want ErrPacketTooLarge", s.Role(), n, err)
				}
			}
			dpWrite(t, a, 7, 1250)
			buf := make([]byte, 2000)
			if n, err := b.ReadFrom(buf); n != 1250 || err != nil || dpID(buf) != 7 {
				t.Fatalf("ReadFrom = %d, %v (id %d); want the 1250-byte datagram 7", n, err, dpID(buf))
			}
		})
	})

	t.Run("end to end: an answer outside the rules is its carrier's violation", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wpNewWorld(t, nil)
			defer w.teardown()
			l := wpLink(w, "p1", 1250)
			answered := 0
			w.b.answer = func(o *wire.Open) (wire.OpenAck, bool) {
				answered++
				return wire.OpenAck{Status: wire.StatusOK, Window: wire.PacketWindow(1250, 1200)}, true // cmtu on a stream carrier
			}
			h := &wpMarkHealth{acHealth: acNewHealth(1, w.a.p.Selector.Fresh)}
			s, err := w.dial(context.Background(), wpSpec(w, ModeSelector, 1400, l), h)
			if s != nil || !errors.Is(err, ErrNoPath) || !errors.Is(err, errPktCmtu) {
				t.Fatalf("Dial = %v, %v; want ErrNoPath wrapping the carrier's cmtu violation", s, err)
			}
			if answered == 0 {
				t.Fatal("stimulus: no OPEN reached the scripted answer")
			}
			if !h.marked(0, carrier.CauseProtocolViolation.String()) {
				t.Fatalf("the factory was not marked failed as a protocol violation (marks %v)", h.list())
			}
			if errors.Is(err, io.EOF) {
				t.Fatal("a Dial error must never read as io.EOF")
			}
		})
	})
}

// TestPacketJoinFields: a packet session's JOIN carries the carrier's cmtu
// offer and its JOIN_ACK the accepted budget (M2-D11, M2-D50; the JOIN half
// of TestPassiveBudgetNegotiated_L37, R1-34): the passive refuses a stream
// session's JOIN on a datagram carrier, a packet JOIN with an offer on a
// stream carrier or outside 537 … 65,507 on a datagram carrier, and
// accepts min(offer, its transport's limit); the dialer checks the answer
// as an OPEN_ACK's cmtu and sets the carrier's budget. End to end, a packet
// bond's members JOIN over stream carriers with rxNext 0 and attach.
func TestPacketJoinFields(t *testing.T) {
	t.Run("passive", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			packet bool
			kind   wire.CarrierKind
			rxNext uint64
			limit  int
			cmtu   int
			ok     bool
		}{
			{"stream session, stream carrier (M1 rxNext)", false, kStream, 12345, 0, 0, true},
			{"stream session, datagram carrier", false, kDgram, 1200, 1400, 0, false},
			{"packet session, stream carrier, 0", true, kStream, 0, 0, 0, true},
			{"packet session, stream carrier, an offer", true, kStream, 1200, 0, 0, false},
			{"packet session, datagram carrier, below 537", true, kDgram, wire.MinFrameBudget - 1, 1400, 0, false},
			{"packet session, datagram carrier, above 65507", true, kDgram, wire.MaxDatagram + 1, 65507, 0, false},
			{"packet session, datagram carrier, offer below the limit", true, kDgram, 1200, 1400, 1200, true},
			{"packet session, datagram carrier, offer above the limit", true, kDgram, 1500, 1400, 1400, true},
			{"packet session, datagram carrier, the largest", true, kDgram, wire.MaxDatagram, wire.MaxDatagram, wire.MaxDatagram, true},
			{"packet session, datagram carrier, offer at the floor", true, kDgram, wire.MinFrameBudget, 1400, wire.MinFrameBudget, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cmtu, ok := pktJoinBudget(tc.packet, tc.kind, tc.rxNext, tc.limit)
				if ok != tc.ok || (ok && cmtu != tc.cmtu) {
					t.Fatalf("pktJoinBudget = %d, %v; want %d, %v", cmtu, ok, tc.cmtu, tc.ok)
				}
			})
		}
	})
	t.Run("dialer", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			kind   wire.CarrierKind
			offer  int
			rxNext uint64
			budget int // -1: refused
		}{
			{"stream carrier, 0", kStream, 0, 0, 0},
			{"stream carrier, a value", kStream, 0, 1200, -1},
			{"datagram carrier, below the offer", kDgram, 1400, 1200, 1200},
			{"datagram carrier, the offer", kDgram, 1400, 1400, 1400},
			{"datagram carrier, above the offer", kDgram, 1400, 1401, -1},
			{"datagram carrier, below the floor", kDgram, 1400, wire.MinFrameBudget - 1, -1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := dpSession(dpOpt{})
				c := &wpBudgetConn{kind: tc.kind, limit: tc.offer}
				s.mu.Lock()
				err := s.pktJoinAckLocked(c, tc.rxNext)
				s.mu.Unlock()
				if tc.budget < 0 {
					if !errors.Is(err, errPktCmtu) || c.called {
						t.Fatalf("pktJoinAckLocked = %v (SetBudget called %v); want errPktCmtu, no budget", err, c.called)
					}
					return
				}
				if err != nil || !c.called || c.set != tc.budget {
					t.Fatalf("pktJoinAckLocked = %v, SetBudget %v %d; want nil, %d", err, c.called, c.set, tc.budget)
				}
			})
		}
	})
	t.Run("end to end: bond members JOIN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wpNewWorld(t, nil)
			defer w.teardown()
			l1, l2 := wpLink(w, "p1", 1400), wpLink(w, "p2", 1400)
			a, b := wpOpen(w, wpSpec(w, ModeBond, 1400, l1, l2), nil)
			acWaitFor(t, time.Second, "both members attached", func() bool { return a.dataMembers() == 2 && b.dataMembers() == 2 })
			joins, _ := w.b.counts()
			if joins[wire.StatusOK] == 0 {
				t.Fatalf("stimulus: no member joined (JOIN answers %v)", joins)
			}
			if bad := joins[wire.StatusBadRequest]; bad != 0 {
				t.Fatalf("%d JOINs refused BAD_REQUEST: a packet JOIN on a stream carrier must carry rxNext 0", bad)
			}
			// A member that dies rejoins by JOIN as well.
			if l2.Kill() == 0 {
				t.Fatal("the kill hit no carrier")
			}
			acWaitFor(t, time.Second, "the member rejoined", func() bool { return a.Status().Rejoins >= 1 && a.dataMembers() == 2 })
			if joins, _ := w.b.counts(); joins[wire.StatusOK] < 2 || joins[wire.StatusBadRequest] != 0 {
				t.Fatalf("JOIN answers after the rejoin: %v", joins)
			}
			dpWrite(t, a, 1, 1400)
			buf := make([]byte, 2000)
			if n, err := b.ReadFrom(buf); n != 1400 || err != nil {
				t.Fatalf("ReadFrom = %d, %v", n, err)
			}
		})
	})
	t.Run("adopt: JOIN_ACK(OK) carries the carrier's cmtu_acc", func(t *testing.T) {
		// The adopted JOIN lane's JOIN_ACK answers the budget Join fixed on
		// its carrier (its RecvLimit after SetBudget), never rRead.
		s := dpSession(dpOpt{role: RolePassive})
		l, fp := dpAddLane(s, 1, false, true)
		s.mu.Lock()
		s.st.rRead = 777 // a stray offset must not leak into a packet JOIN_ACK
		s.mu.Unlock()
		for _, lim := range []int{1200, wire.MinFrameBudget, 0} {
			l.port = wpLimitPort{fp, lim}
			if got := wpLocked(s, func() uint64 { return s.joinAckRxLocked(l) }); got != uint64(lim) {
				t.Fatalf("packet JOIN_ACK rxNext %d, want the carrier's cmtu_acc %d", got, lim)
			}
		}
		ss := &Session{}
		ss.st.rRead = 777
		if got := ss.joinAckRxLocked(l); got != 777 {
			t.Fatalf("stream JOIN_ACK rxNext %d, want rRead 777", got)
		}
	})
	t.Run("end to end: a JOIN_ACK outside the rules is its carrier's violation", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wpNewWorld(t, nil)
			defer w.teardown()
			h := &wpMarkHealth{acHealth: acNewHealth(2, w.a.p.Selector.Fresh)}
			l1, l2 := wpLink(w, "p1", 1400), wpLink(w, "p2", 1400)
			a, b := wpOpen(w, wpSpec(w, ModeBond, 1400, l1, l2), h)
			acWaitFor(t, time.Second, "both members attached", func() bool { return a.dataMembers() == 2 && b.dataMembers() == 2 })
			var scripted atomic.Int32
			w.b.joinAnswer = func(*wire.Join) (wire.JoinAck, bool) {
				if scripted.Add(1) > 1 {
					return wire.JoinAck{}, false
				}
				return wire.JoinAck{Status: wire.StatusOK, RxNext: 1200}, true // a cmtu on a stream carrier
			}
			if l2.Kill() == 0 {
				t.Fatal("the kill hit no carrier")
			}
			acWaitFor(t, 3*time.Second, "the member rejoined", func() bool { return a.dataMembers() == 2 && b.dataMembers() == 2 })
			switch scripted.Load() {
			case 0:
				t.Fatal("stimulus: no JOIN was answered with the scripted cmtu")
			case 1:
				t.Fatal("the carrier whose JOIN_ACK carried a cmtu on a stream carrier became a member")
			}
			if !h.marked(1, carrier.CauseProtocolViolation.String()) {
				t.Fatalf("factory 1 not marked failed as a protocol violation (marks %v)", h.list())
			}
			for _, c := range a.Status().Carriers {
				if c.DeathCause == carrier.CauseProtocolViolation {
					t.Fatalf("the violating carrier became a lane: %+v", c)
				}
			}
			if st := a.Status(); st.State != StateOpen || a.MaxPayload() != 1400 {
				t.Fatalf("the session after the violation: %v, MaxPayload %d", st.State, a.MaxPayload())
			}
			dpWrite(t, a, 2, 1400)
			buf := make([]byte, 2000)
			if n, err := b.ReadFrom(buf); n != 1400 || err != nil || dpID(buf) != 2 {
				t.Fatalf("ReadFrom = %d, %v", n, err)
			}
		})
	})
}

// wpMarkHealth is acHealth recording every MarkFailedAt call as
// "factory:reason".
type wpMarkHealth struct {
	*acHealth
	mu    sync.Mutex
	marks []string
}

func (h *wpMarkHealth) MarkFailedAt(i int, reason string, at time.Time) {
	h.mu.Lock()
	h.marks = append(h.marks, fmt.Sprintf("%d:%s", i, reason))
	h.mu.Unlock()
	h.acHealth.MarkFailedAt(i, reason, at)
}

func (h *wpMarkHealth) list() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.marks)
}

func (h *wpMarkHealth) marked(i int, reason string) bool {
	return slices.Contains(h.list(), fmt.Sprintf("%d:%s", i, reason))
}

// TestPacketPassiveMaxPayload_L37 (M2-D49, R1-32): the passive's accepted
// MaxPayload — min(the dialer's offer, its own Packet.MaxPayload), from
// PassiveSpec.MaxPayload — is the session's from NewPending on (what
// PendingPacket.MaxPayload reports before Confirm), Confirm's OPEN_ACK
// carries it, and the dialer adopts it rather than its own offer: both ends
// accept exactly that size and refuse one byte more (L37 "对端 1250").
func TestPacketPassiveMaxPayload_L37(t *testing.T) {
	for _, tc := range []struct {
		name       string
		offer, own int
		want       int
	}{
		{"the passive's limit below the offer", 65507, 1250, 1250},
		{"the offer below the passive's limit", 1100, 65507, 1100},
		{"both small", 1100, 1250, 1100},
		{"the floor", 512, 512, 512},
		{"the largest", 65507, 65507, 65507},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := wpNewWorld(t, nil)
				defer w.teardown()
				l := wpLink(w, "p1", tc.own)
				spec := wpSpec(w, ModeSelector, tc.offer, l)
				ch := make(chan error, 1)
				var a *Session
				go func() {
					s, err := w.dial(context.Background(), spec, nil)
					a = s
					ch <- err
				}()
				b := <-w.b.pending
				w.sess = append(w.sess, b)
				if got := b.MaxPayload(); got != tc.want {
					t.Fatalf("pending passive MaxPayload %d before Confirm, want %d (R1-32)", got, tc.want)
				}
				if err := b.Confirm(); err != nil {
					t.Fatalf("Confirm: %v", err)
				}
				if err := <-ch; err != nil {
					t.Fatalf("Dial: %v", err)
				}
				if a.MaxPayload() != tc.want || b.MaxPayload() != tc.want {
					t.Fatalf("MaxPayload dialer %d passive %d, want %d", a.MaxPayload(), b.MaxPayload(), tc.want)
				}
				for _, pair := range [][2]*Session{{a, b}, {b, a}} {
					from, to := pair[0], pair[1]
					if n, err := from.WriteTo(make([]byte, tc.want+1)); n != 0 || !errors.Is(err, ErrPacketTooLarge) {
						t.Fatalf("%v: WriteTo(%d) = %d, %v; want ErrPacketTooLarge", from.Role(), tc.want+1, n, err)
					}
					dpWrite(t, from, 3, tc.want)
					buf := make([]byte, 1<<16)
					if n, err := to.ReadFrom(buf); n != tc.want || err != nil {
						t.Fatalf("%v: ReadFrom = %d, %v; want %d bytes", to.Role(), n, err, tc.want)
					}
				}
			})
		})
	}
}

// wpLimitPort is a fake lane port that reports a negotiated cmtu.
type wpLimitPort struct {
	*dpPort
	lim int
}

func (p wpLimitPort) RecvLimit() int { return p.lim }

// wpWindowPort wraps a passive lane's carrier: it reports a cmtu of its own
// and records the OPEN_ACK window pending on the lane when the lane is
// woken to place it (Confirm wakes each OPEN carrier under the session
// lock right after setting its first frame).
type wpWindowPort struct {
	*carrier.Conn
	lim int
	l   *lane
	win *uint32
}

func (p *wpWindowPort) RecvLimit() int { return p.lim }

func (p *wpWindowPort) Wake() {
	if f := p.l.first; f.t == wire.TypeOpenAck && *p.win == 0 {
		*p.win = f.openAck.Window
	}
	p.Conn.Wake()
}

// TestPacketOpenAckPerCarrier (R1-5): every OPEN carrier of a packet
// session is answered with its own budget — in Confirm and in a duplicate
// OPEN's adoption alike — and with the session's one MaxPayload; a
// dialer whose Confirm comes after JoinStagger has two OPEN carriers, and
// both attach, neither killed.
func TestPacketOpenAckPerCarrier(t *testing.T) {
	t.Run("each lane's window", func(t *testing.T) {
		s := dpSession(dpOpt{role: RolePassive, maxPayload: 1250})
		var ws []uint32
		for i, lim := range []int{1152, 0, 1400} {
			l, fp := dpAddLane(s, uint32(i+1), i == 0, lim != 0)
			l.port = wpLimitPort{fp, lim}
			s.mu.Lock()
			ws = append(ws, s.laneWindowLocked(l))
			s.mu.Unlock()
		}
		for i, lim := range []int{1152, 0, 1400} {
			if want := wire.PacketWindow(1250, uint16(lim)); ws[i] != want {
				pm, cm := wire.SplitPacketWindow(ws[i])
				t.Fatalf("lane %d: window (%d, %d), want (1250, %d)", i, pm, cm, lim)
			}
		}
	})

	t.Run("Confirm answers each OPEN carrier with its own budget", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wpNewWorld(t, nil)
			defer w.teardown()
			l1, l2 := wpLink(w, "p1", 1250), wpLink(w, "p2", 1250)
			spec := wpSpec(w, ModeSelector, 1400, l1, l2)
			ch := make(chan error, 1)
			go func() {
				_, err := w.dial(context.Background(), spec, nil)
				ch <- err
			}()
			b := <-w.b.pending
			w.sess = append(w.sess, b)
			acWaitFor(t, 2*time.Second, "the second OPEN carrier parked", func() bool {
				return wpLocked(b, func() int { return len(b.lanes) }) == 2
			})
			lims := []int{1152, 1400}
			wins := make([]uint32, 2)
			b.mu.Lock()
			for i, l := range b.lanes {
				l.port = &wpWindowPort{Conn: l.c, lim: lims[i], l: l, win: &wins[i]}
			}
			b.mu.Unlock()
			if err := b.Confirm(); err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			for i := range wins {
				if want := wire.PacketWindow(1250, uint16(lims[i])); wins[i] != want {
					pm, cm := wire.SplitPacketWindow(wins[i])
					t.Fatalf("OPEN carrier %d answered (%d, %d), want (1250, %d)", i, pm, cm, lims[i])
				}
			}
			// The forged budgets are invalid on the stream carriers these
			// links make: the dialer kills both and opens on a later OPEN,
			// whose duplicate-OPEN adoption answers with its real budget (0).
			select {
			case err := <-ch:
				if err != nil {
					t.Fatalf("Dial: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Dial did not return")
			}
		})
	})

	for _, mode := range []Mode{ModeSelector, ModeBond} {
		t.Run("both OPEN carriers attach, "+map[Mode]string{ModeSelector: "selector", ModeBond: "bond"}[mode], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := wpNewWorld(t, nil)
				defer w.teardown()
				l1, l2 := wpLink(w, "p1", 1250), wpLink(w, "p2", 1250)
				spec := wpSpec(w, mode, 1400, l1, l2)
				type res struct {
					s   *Session
					err error
				}
				ch := make(chan res, 1)
				go func() {
					s, err := w.dial(context.Background(), spec, nil)
					ch <- res{s, err}
				}()
				b := <-w.b.pending
				w.sess = append(w.sess, b)
				acWaitFor(t, 2*time.Second, "the second OPEN carrier parked", func() bool {
					return wpLocked(b, func() int { return len(b.lanes) }) == 2
				})
				if err := b.Confirm(); err != nil {
					t.Fatalf("Confirm: %v", err)
				}
				r := <-ch
				if r.err != nil {
					t.Fatalf("Dial: %v", r.err)
				}
				a := r.s
				acWaitFor(t, time.Second, "both OPEN carriers answered", func() bool { return len(a.Status().Carriers) >= 2 })
				for _, s := range []*Session{a, b} {
					for _, c := range s.Status().Carriers {
						if c.DeathCause == carrier.CauseProtocolViolation {
							t.Fatalf("%v: carrier %d killed as a violation: %+v", s.Role(), c.ID, c)
						}
					}
				}
				if a.MaxPayload() != 1250 {
					t.Fatalf("dialer MaxPayload %d, want 1250", a.MaxPayload())
				}
				if mode == ModeBond {
					acWaitFor(t, time.Second, "both members carry data", func() bool { return a.dataMembers() == 2 })
				}
			})
		})
	}
}

// wpRawHello dials link and writes a PREFACE of instance inst with carrier
// ID cid followed by one first frame of type t: a replayed or forged first
// datagram's content on a stream carrier. It returns the conn (the caller
// closes it).
func wpRawHello(t testing.TB, link *rendrtest.Link, inst [16]byte, cid uint32, typ wire.Type, payload []byte) interface{ Close() error } {
	t.Helper()
	nc, err := link.Dial(context.Background())
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	hello := make([]byte, wire.PrefaceLen)
	wire.PutPreface(hello, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Instance: inst, CarrierID: cid})
	hello = wire.AppendFrame(hello, wire.Header{Type: typ, Fseq: wire.PrefaceFseq(hello), Handle: wire.SessionHandle}, payload)
	if _, err := nc.Write(hello); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	return nc
}

// TestJoinKnownCarrierRefused (M2-D84; R1-11): a JOIN or a duplicate OPEN
// whose CarrierID the session already attached — a live lane's, or one of
// its last eight dead lanes' — is a replay (a correct dialer never reuses
// an ID) and is refused with BAD_REQUEST; it creates no lane and leaves the
// session as it was. A JOIN with a new ID is admitted.
func TestJoinKnownCarrierRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wpNewWorld(t, nil)
		defer w.teardown()
		la := wpLink(w, "a", 1400)
		lr := wpLink(w, "replay", 1400) // the replayer's path to the same passive
		a, b := wpOpen(w, wpSpec(w, ModeSelector, 1400, la), nil)
		live := acActive(a)
		if live == 0 {
			t.Fatal("no active carrier")
		}
		inst := w.a.cenv.Local
		var jp [wire.JoinLen]byte
		join := jp[:wire.PutJoin(jp[:], &wire.Join{SID: a.ID(), Mode: uint8(ModeSelector)})]
		op := make([]byte, wire.OpenFixedLen)
		open := op[:wire.PutOpen(op, &wire.Open{SID: a.ID(), Kind: wire.KindDatagram, Mode: uint8(ModeSelector), RetainMs: 10000, PMTU: 1400})]
		bad := func() int {
			j, _ := w.b.counts()
			return j[wire.StatusBadRequest]
		}
		badOpen := func() int {
			_, o := w.b.counts()
			return o[[2]uint32{uint32(wire.StatusBadRequest), wire.CodeBadValue}]
		}
		lanes := func() int { return wpLocked(b, func() int { return len(b.lanes) }) }

		c := wpRawHello(t, lr, inst, live, wire.TypeJoin, join)
		acWaitFor(t, time.Second, "the replayed JOIN answered", func() bool { return bad() == 1 })
		c.Close()
		c = wpRawHello(t, lr, inst, live, wire.TypeOpen, open)
		acWaitFor(t, time.Second, "the replayed OPEN answered", func() bool { return badOpen() == 1 })
		c.Close()
		if n := lanes(); n != 1 || acActive(b) != live {
			t.Fatalf("after the replays: %d passive lanes, active %d; want the one live lane %d", n, acActive(b), live)
		}

		// The live carrier dies; the dialer's redial attaches a new one. The
		// dead carrier's ID stays refused (the last eight dead lanes).
		if la.Kill() == 0 {
			t.Fatal("the kill hit no carrier")
		}
		acWaitFor(t, 2*time.Second, "the session recovered", func() bool {
			id := acActive(b)
			return id != 0 && id != live
		})
		c = wpRawHello(t, lr, inst, live, wire.TypeJoin, join)
		acWaitFor(t, time.Second, "the late JOIN of the dead carrier answered", func() bool { return bad() == 2 })
		c.Close()

		// Control: a fresh ID is admitted (the replay rule, not the JOIN, refused).
		okBefore, _ := w.b.counts()
		c = wpRawHello(t, lr, inst, 0x7FFF0001, wire.TypeJoin, join)
		acWaitFor(t, time.Second, "a JOIN with a new ID admitted", func() bool {
			j, _ := w.b.counts()
			return j[wire.StatusOK] == okBefore[wire.StatusOK]+1
		})
		c.Close()
		if bad() != 2 {
			t.Fatalf("%d JOINs refused BAD_REQUEST, want 2", bad())
		}
	})
}
