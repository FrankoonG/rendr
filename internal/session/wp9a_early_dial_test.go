package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The dialer's EarlyReturn (M4 design §A4.1 … §A4.3, Revision 1 R1-2 and
// R1-4; WP9a): the deferred opening, the pre-verdict admission cap, the
// one early span, the winning lane's in-flight span, and Close and Abort
// before the verdict. The tests run the actor harness (two sessions over
// rendrtest links in synctest bubbles) with an admission shim that admits
// EARLY OPENs (PassiveSpec.Early, AttachOpenEarly) and OPENs on views of
// live MUX trunks (carrier.Env.Admit), as package rendr's admission does.
// Every helper of these tests starts with "ea".

// eaNewWorld is acNewWorld with the EARLY- and view-aware admission shim on
// the passive; hooks go to the dialer's Runtime (nil: none).
func eaNewWorld(t testing.TB, hooks *testhooks.Hooks) *acWorld {
	w := acNewWorld(t, hooks)
	w.b.cenv.Admit = w.b.eaAdmitView
	return w
}

// eaLink makes a link to the passive through the EARLY-aware shim.
func (w *acWorld) eaLink(name string) *rendrtest.Link {
	l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: w.b.eaAccept})
	l.SetDelay(acLinkDelay, 0)
	w.links = append(w.links, l)
	return l
}

// eaSpec is a DialSpec over links with EarlyReturn and EarlyDataMax max.
func (w *acWorld) eaSpec(mode Mode, max int, links ...*rendrtest.Link) DialSpec {
	spec := w.spec(mode, links...)
	spec.EarlyReturn = true
	spec.Params.EarlyDataMax = max
	return spec
}

// eaDial runs an EarlyReturn Dial, which must return a session at once.
func (w *acWorld) eaDial(spec DialSpec) *Session {
	w.t.Helper()
	s, err := w.dial(context.Background(), spec, nil)
	if err != nil {
		w.t.Fatalf("EarlyReturn Dial: %v", err)
	}
	return s
}

// eaPending takes the next admitted pending session.
func (w *acWorld) eaPending() *Session {
	w.t.Helper()
	select {
	case s := <-w.b.pending:
		w.sess = append(w.sess, s)
		return s
	case <-time.After(10 * time.Second):
		w.t.Fatal("no session was admitted")
		return nil
	}
}

// eaAccept is acPassive.accept with EARLY-aware OPEN admission.
func (p *acPassive) eaAccept(nc net.Conn) error {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		h, err := carrier.ReadHello(p.cenv, nc, time.Now().Add(2*time.Second), p.maxMeta, p.gate)
		if err != nil {
			return
		}
		switch h.First.Type {
		case wire.TypeOpen:
			p.eaAdmitOpen(h.Conn, h.Preface.Instance, h.Payload)
		case wire.TypeJoin:
			p.admitJoin(h)
		default:
			h.Conn.Kill(carrier.CauseLocalClose, "no sessionless carriers in actor tests")
			p.closed(h.Conn)
		}
	}()
	return nil
}

// eaAdmitView is the passive's carrier.Env.Admit: an OPEN or JOIN for a
// new handle on a live MUX trunk (the root's admitView, without its
// trunk records). It never blocks.
func (p *acPassive) eaAdmitView(v *carrier.Conn, hdr wire.Header, pl []byte) {
	if hdr.Type == wire.TypeOpen {
		p.eaAdmitOpen(v, v.PeerInstance(), pl)
		return
	}
	j, err := wire.ParseJoin(pl)
	if s := p.session(j.SID); err == nil && s != nil {
		if taken, st := s.Join(v, &j); !taken {
			v.Refuse(v.Handle(), carrier.Answer{Type: wire.TypeJoinAck, Status: st})
		}
		return
	}
	v.Refuse(v.Handle(), carrier.Answer{Type: wire.TypeJoinAck, Status: wire.StatusUnknownSession})
}

// eaAdmitOpen admits an OPEN on c (a handshake's carrier or a view): a new
// session with PassiveSpec.Early from the OPEN's flags, or AttachOpenEarly
// for a duplicate, or the tombstone's answer.
func (p *acPassive) eaAdmitOpen(c *carrier.Conn, inst [16]byte, payload []byte) {
	o, err := wire.ParseOpen(payload, p.maxMeta)
	if err != nil {
		p.eaAnswer(c, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeBadValue})
		return
	}
	early := o.Flags&wire.OpenFlagEarly != 0
	p.mu.Lock()
	e := p.tab[o.SID]
	if e == nil {
		pp := p.p
		pp.Role, pp.Mode = RolePassive, Mode(o.Mode)
		pp.Grace = min(max(time.Duration(o.RetainMs)*time.Millisecond, time.Second), 400*time.Second)
		s := NewPending(p.env, PassiveSpec{SID: o.SID, Params: pp, DialerInstance: inst, PeerWindow: o.Window, Metadata: o.Metadata, Early: early}, c)
		p.tab[o.SID] = &acEntry{s: s}
		p.mu.Unlock()
		s.Start()
		p.pending <- s
		return
	}
	s, tomb, v := e.s, e.tomb, e.v
	p.mu.Unlock()
	if tomb {
		p.eaAnswer(c, v.OpenAck())
		return
	}
	if taken, v := s.AttachOpenEarly(c, early); !taken {
		p.mu.Lock()
		p.openRefuse[[2]uint32{uint32(v.Status), v.Code}]++
		p.mu.Unlock()
		p.eaAnswer(c, v.OpenAck())
	}
}

// eaAnswer refuses an OPEN on c: through the trunk's refusal ring on a
// view, as answerOpen on a handshake's carrier.
func (p *acPassive) eaAnswer(c *carrier.Conn, oa wire.OpenAck) {
	if c.Handle() > wire.SessionHandle {
		c.Refuse(c.Handle(), carrier.Answer{Type: wire.TypeOpenAck, Status: oa.Status, Code: oa.Code})
		return
	}
	p.answerOpen(c, oa)
}

// eaFlights records the k of every early first flight the dialer's
// Runtime writes (testhooks.BeforeFirstFlight), in order.
type eaFlights struct {
	mu sync.Mutex
	ks []int
}

func (f *eaFlights) hooks() *testhooks.Hooks {
	return &testhooks.Hooks{BeforeFirstFlight: func(k int) {
		f.mu.Lock()
		f.ks = append(f.ks, k)
		f.mu.Unlock()
	}}
}

func (f *eaFlights) get() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ks)
}

// eaEarly reads the passive's early facts under its lock: the bytes taken
// before the verdict and whether an adopted OPEN carried EARLY.
func eaEarly(s *Session) (early uint64, earlyOpen bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.earlyBytes, s.st.earlyOpen
}

// eaWaitEarly waits until the passive s holds n early bytes.
func eaWaitEarly(t testing.TB, s *Session, n uint64) {
	t.Helper()
	acWaitFor(t, 5*time.Second, "early bytes held by the passive", func() bool {
		e, _ := eaEarly(s)
		return e == n
	})
}

// eaAsync runs fn on its own goroutine; the channel receives its result.
func eaAsync(fn func() (int, error)) <-chan eaResult {
	ch := make(chan eaResult, 1)
	go func() {
		n, err := fn()
		ch <- eaResult{n, err, time.Now()}
	}()
	return ch
}

type eaResult struct {
	n   int
	err error
	at  time.Time
}

// eaReadAll reads s to io.EOF.
func eaReadAll(t testing.TB, s *Session) []byte {
	t.Helper()
	var out []byte
	buf := make([]byte, 32<<10)
	for {
		n, err := s.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(out), err)
		}
	}
}

// TestEarlyReturnNoNetworkBeforeFirstOp (M4-D9): Dial returns before any
// network I/O; no factory is called until the first Write, however long
// the application waits; that Write opens the session.
func TestEarlyReturnNoNetworkBeforeFirstOp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		time.Sleep(30 * time.Second) // beyond Grace: nothing runs before the trigger
		synctest.Wait()
		if d := l.Stats().Dials; d != 0 {
			t.Fatalf("%d factory calls before the first Write, want 0", d)
		}
		if st := s.State(); st != StatePending {
			t.Fatalf("state %v before the trigger, want pending", st)
		}
		msg := stPattern(0, 1000)
		if n, err := s.Write(msg); n != len(msg) || err != nil {
			t.Fatalf("Write = (%d, %v), want (%d, nil) before the verdict", n, err, len(msg))
		}
		p := w.eaPending()
		if d := l.Stats().Dials; d != 1 {
			t.Fatalf("%d factory calls after the first Write, want 1", d)
		}
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the passive read other bytes")
		}
	})
}

// TestEarlyFirstWriteRidesFirstFlight (M4-D9, M4-D4, M4-D18): the first
// Write's bytes are admitted before the trigger, so the first attempt's
// span carries them: one early first flight of exactly those bytes, held
// by the passive before its verdict, and delivered without a resend; the
// dialer's EarlyBytes is the winner's span.
func TestEarlyFirstWriteRidesFirstFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fl eaFlights
		w := eaNewWorld(t, fl.hooks())
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		// Time passes before the first Write: a session that opened at
		// Dial would have fixed an empty span by now (M4-D9).
		time.Sleep(time.Second)
		synctest.Wait()
		msg := []byte("hello")
		if _, err := s.Write(msg); err != nil {
			t.Fatal(err)
		}
		p := w.eaPending()
		eaWaitEarly(t, p, uint64(len(msg)))
		if ks := fl.get(); !slices.Equal(ks, []int{len(msg)}) {
			t.Fatalf("early first flights %v, want [%d]", ks, len(msg))
		}
		if _, eo := eaEarly(p); !eo {
			t.Fatal("the passive saw no EARLY OPEN")
		}
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatalf("the passive read %q, want %q", got, msg)
		}
		acWaitFor(t, 5*time.Second, "the dialer opened", func() bool { return s.State() == StateOpen })
		if st := s.Status(); st.EarlyBytes != uint64(len(msg)) || st.RetransmittedBytes != 0 {
			t.Fatalf("dialer EarlyBytes %d retransmitted %d, want %d and 0", st.EarlyBytes, st.RetransmittedBytes, len(msg))
		}
		if st := p.Status(); st.EarlyBytes != uint64(len(msg)) || st.DupBytes != 0 {
			t.Fatalf("passive EarlyBytes %d dups %d, want %d and 0", st.EarlyBytes, st.DupBytes, len(msg))
		}
	})
}

// TestEarlyReturnReadTriggersOpen (M4-D9): a Read that comes first opens
// the session without early bytes (an OPEN without EARLY, no first-flight
// DATA); a Write before the verdict is admitted and delivered after it.
func TestEarlyReturnReadTriggersOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fl eaFlights
		w := eaNewWorld(t, fl.hooks())
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		rd := eaAsync(func() (int, error) { return s.Read(make([]byte, 16)) })
		p := w.eaPending()
		if e, eo := eaEarly(p); e != 0 || eo {
			t.Fatalf("passive early %d, EARLY OPEN %v: want an OPEN without EARLY", e, eo)
		}
		if ks := fl.get(); len(ks) != 0 {
			t.Fatalf("early first flights %v, want none", ks)
		}
		if n, err := s.Write([]byte("abc")); n != 3 || err != nil {
			t.Fatalf("Write = (%d, %v)", n, err)
		}
		synctest.Wait()
		if e, _ := eaEarly(p); e != 0 {
			t.Fatalf("passive early %d after a pre-verdict Write on an opening without EARLY", e)
		}
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if got := stReadN(t, p, 3); string(got) != "abc" {
			t.Fatalf("passive read %q", got)
		}
		if _, err := p.Write([]byte("xyz")); err != nil {
			t.Fatal(err)
		}
		if r := <-rd; r.err != nil || r.n != 3 {
			t.Fatalf("dialer Read = (%d, %v)", r.n, r.err)
		}
		if st := s.Status(); st.EarlyBytes != 0 {
			t.Fatalf("dialer EarlyBytes %d, want 0", st.EarlyBytes)
		}
	})
}

// TestEarlyCloseBeforeTriggerSendsNothing (M4-D12, M4-D20): Close — or
// Abort — before any trigger ends the session locally: no factory call,
// no admitted session, Done closes, every later call returns
// net.ErrClosed, and the end is reported once (EventSessionEnd). A Read or
// CloseWrite right after the Close or Abort (before the actor's next step)
// is no trigger either.
func TestEarlyCloseBeforeTriggerSendsNothing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		abort bool
		then  string // "", "read" or "closewrite": called right after
	}{
		{"close", false, ""},
		{"abort", true, ""},
		{"close+read", false, "read"},
		{"close+closewrite", false, "closewrite"},
		{"abort+read", true, "read"},
		{"abort+closewrite", true, "closewrite"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := eaNewWorld(t, nil)
				defer w.teardown()
				l := w.eaLink("a")
				s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
				if tc.abort {
					if err := s.Abort(0x1000, "bye"); err != nil {
						t.Fatal(err)
					}
				} else if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				switch tc.then {
				case "read":
					if _, err := s.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("Read right after Close: %v, want net.ErrClosed", err)
					}
				case "closewrite":
					if err := s.CloseWrite(); err != nil {
						t.Fatal(err)
					}
				}
				acDone(t, s, time.Second)
				time.Sleep(60 * time.Second) // anything the trigger started would have run
				synctest.Wait()
				if d := l.Stats().Dials; d != 0 {
					t.Fatalf("%d factory calls, want 0", d)
				}
				select {
				case p := <-w.b.pending:
					w.sess = append(w.sess, p)
					t.Fatal("the passive admitted a session")
				default:
				}
				if _, err := s.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Write after Close: %v, want net.ErrClosed", err)
				}
				if _, err := s.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Read after Close: %v, want net.ErrClosed", err)
				}
				if st := s.Status(); st.State != StateEnded || !errors.Is(st.Err, net.ErrClosed) {
					t.Fatalf("state %v err %v, want ended with net.ErrClosed", st.State, st.Err)
				}
				if ev := w.a.ev.of(s.ID(), EventSessionEnd); len(ev) != 1 {
					t.Fatalf("%d SessionEnd events, want 1", len(ev))
				}
			})
		})
	}
}

// TestEarlyReturnRejected (plan:663, M4-D11): Reject with code X after the
// early bytes arrived: the dialer's next Read and next Write return
// *RejectError{X} (errors.Is ErrRejected), Done closes, the end is
// reported with that error; the passive application never reads an early
// byte; both Budgets are back at their baseline once both sessions are
// done.
func TestEarlyReturnRejected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		msg := stPattern(0, 3000)
		if _, err := s.Write(msg); err != nil {
			t.Fatal(err)
		}
		p := w.eaPending()
		eaWaitEarly(t, p, uint64(len(msg)))
		const code = 0x4C340007
		if err := p.Reject(code, "refused by policy"); err != nil {
			t.Fatal(err)
		}
		var re *RejectError
		if _, err := s.Read(make([]byte, 10)); !errors.As(err, &re) || re.Code != code || !errors.Is(err, ErrRejected) {
			t.Fatalf("Read after Reject: %v, want *RejectError{%#x}", err, code)
		}
		if n, err := s.Write([]byte("more")); n != 0 || !errors.As(err, &re) || re.Code != code {
			t.Fatalf("Write after Reject: (%d, %v), want (0, *RejectError{%#x})", n, err, code)
		}
		acDone(t, s, 5*time.Second)
		acDone(t, p, 5*time.Second)
		if n, err := p.Read(make([]byte, 10)); n != 0 || err == nil {
			t.Fatalf("passive Read after its Reject = (%d, %v), want no byte and an error", n, err)
		}
		if st := p.Status(); st.DeliveredBytes != 0 {
			t.Fatalf("the passive delivered %d bytes of a rejected session", st.DeliveredBytes)
		}
		ev := w.a.ev.of(s.ID(), EventSessionEnd)
		if len(ev) != 1 || !errors.As(ev[0].Err, &re) {
			t.Fatalf("SessionEnd events %+v, want one carrying the *RejectError", ev)
		}
		acWaitFor(t, 5*time.Second, "both Budgets back at the baseline", func() bool {
			return w.a.cenv.Budget.Used() == 0 && w.b.cenv.Budget.Used() == 0
		})
	})
}

// TestEarlyDataLimitBlocksWrite (plan:663, M4-D10): with EarlyDataMax 4 KiB
// a 10 KiB Write returns only after the OPEN_ACK, which the test delays by
// 3 virtual seconds; the first 4 KiB were on the wire (held by the passive)
// before it, and all 10 KiB arrive.
func TestEarlyDataLimitBlocksWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fl eaFlights
		w := eaNewWorld(t, fl.hooks())
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 4<<10, l))
		msg := stPattern(0, 10<<10)
		wr := eaAsync(func() (int, error) { return s.Write(msg) })
		p := w.eaPending()
		eaWaitEarly(t, p, 4<<10)
		time.Sleep(3 * time.Second)
		synctest.Wait()
		select {
		case r := <-wr:
			t.Fatalf("Write returned (%d, %v) before the verdict", r.n, r.err)
		default:
		}
		// The 3 s exceed HandshakeTimeout (2 s): the first attempt timed
		// out and its redial carried the same span (R1-2).
		if ks := fl.get(); len(ks) == 0 || slices.ContainsFunc(ks, func(k int) bool { return k != 4<<10 }) {
			t.Fatalf("early first flights %v, want each exactly 4096", ks)
		}
		if e, _ := eaEarly(p); e != 4<<10 {
			t.Fatalf("passive early %d, want 4096", e)
		}
		confirmed := time.Now()
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		r := <-wr
		if r.n != len(msg) || r.err != nil || r.at.Before(confirmed) {
			t.Fatalf("Write = (%d, %v) at %v, want (%d, nil) after the Confirm at %v", r.n, r.err, r.at, len(msg), confirmed)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the passive read other bytes")
		}
	})
}

// TestEarlyWriteDeadline_L06 (M4-D10, L06): a Write held by the early cap
// returns (4096, os.ErrDeadlineExceeded) at its 50 ms write deadline; the
// 4096 bytes it admitted are delivered after the Confirm, and nothing else.
func TestEarlyWriteDeadline_L06(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 4<<10, l))
		msg := stPattern(0, 10<<10)
		start := time.Now()
		if err := s.SetWriteDeadline(start.Add(50 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, err := s.Write(msg)
		if n != 4<<10 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write = (%d, %v), want (4096, os.ErrDeadlineExceeded)", n, err)
		}
		if d := time.Since(start); d != 50*time.Millisecond {
			t.Fatalf("the Write returned after %v, want at its 50 ms deadline", d)
		}
		p := w.eaPending()
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if err := s.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if got := eaReadAll(t, p); !bytes.Equal(got, msg[:4<<10]) {
			t.Fatalf("the passive read %d bytes, want the 4096 admitted ones", len(got))
		}
	})
}

// TestEarlyDataMaxZero (M4-D16): EarlyDataMax 0 keeps the early return
// without early bytes: the first Write opens the session but waits for the
// verdict; the OPEN carries no EARLY and no DATA precedes the verdict.
func TestEarlyDataMaxZero(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fl eaFlights
		w := eaNewWorld(t, fl.hooks())
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 0, l))
		msg := stPattern(0, 100)
		wr := eaAsync(func() (int, error) { return s.Write(msg) })
		p := w.eaPending()
		time.Sleep(time.Second)
		synctest.Wait()
		if e, eo := eaEarly(p); e != 0 || eo {
			t.Fatalf("passive early %d, EARLY OPEN %v: want none", e, eo)
		}
		if ks := fl.get(); len(ks) != 0 {
			t.Fatalf("early first flights %v, want none", ks)
		}
		select {
		case r := <-wr:
			t.Fatalf("Write returned (%d, %v) before the verdict", r.n, r.err)
		default:
		}
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if r := <-wr; r.n != len(msg) || r.err != nil {
			t.Fatalf("Write = (%d, %v)", r.n, r.err)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the passive read other bytes")
		}
	})
}
