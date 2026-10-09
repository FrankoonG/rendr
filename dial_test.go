package rendr

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// countReg is a session.Registry that counts its calls.
type countReg struct {
	mu    sync.Mutex
	ended []*session.Session
	other int // Opened, Lingering and Orphaned calls
}

func (r *countReg) Opened(*session.Session)          { r.count() }
func (r *countReg) Lingering(*session.Session, bool) { r.count() }
func (r *countReg) Orphaned(*session.Session, bool)  { r.count() }

func (r *countReg) count() {
	r.mu.Lock()
	r.other++
	r.mu.Unlock()
}

func (r *countReg) Ended(s *session.Session, _ session.Verdict) {
	r.mu.Lock()
	r.ended = append(r.ended, s)
	r.mu.Unlock()
}

func (r *countReg) calls() (ended []*session.Session, other int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*session.Session(nil), r.ended...), r.other
}

// TestSessionDialEntryContract pins the contract of session.Dial that
// Peer.Dial relies on to know whether a failed Dial left a session that
// withdraws in the background and that Runtime.Close must join (design
// §6.6, §6.8; the root learns it from the first Err call of the context it
// passes, entryCtx). When ctx is already done at that first Err call, or
// when the spec has no factory, session.Dial creates no session and makes
// no Registry call; otherwise the session it created calls Registry.Ended
// exactly once, also when Dial fails. Peer.open reports created
// accordingly: false for a done context, true for a failed Dial (and it
// counts a spec without factories, impossible from NewPeer, as no
// session). A change of this contract on the session side fails here.
func TestSessionDialEntryContract(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{NoPathGrace: 200 * time.Millisecond})
		f := &countingFactory{name: "f", err: errors.New("refused")}
		p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{f.carrier()}})
		if err != nil {
			t.Fatal(err)
		}
		reg := &countReg{}
		env := p.env
		env.Registry = reg
		spec := p.spec(SessionID(wpSID(1)), DialOptions{}, false)
		done, cancel := context.WithCancel(context.Background())
		cancel()

		// A context done at the entry check: no session, no Registry call.
		ec := &entryCtx{Context: done}
		if s, err := session.Dial(ec, &env, spec); s != nil || !errors.Is(err, context.Canceled) || ec.live.Load() {
			t.Fatalf("Dial with a done context = %v, %v (entry check live %v)", s, err, ec.live.Load())
		}
		// No factory: no session, no Registry call, although the context
		// was live at the entry check.
		ec = &entryCtx{Context: context.Background()}
		empty := spec
		empty.Factories = nil
		if s, err := session.Dial(ec, &env, empty); s != nil || !errors.Is(err, ErrNoPath) {
			t.Fatalf("Dial without a factory = %v, %v", s, err)
		}
		synctest.Wait()
		if ended, other := reg.calls(); len(ended) != 0 || other != 0 || f.calls.Load() != 0 {
			t.Fatalf("Dials that created no session: %d Ended, %d other Registry calls, %d factory calls", len(ended), other, f.calls.Load())
		}

		// A Dial that fails after it created its session (every attempt is
		// refused until the 200 ms grace): exactly one Ended, of that
		// session, once it withdrew.
		ec = &entryCtx{Context: context.Background()}
		if s, err := session.Dial(ec, &env, spec); s != nil || !errors.Is(err, ErrNoPath) || !ec.live.Load() {
			t.Fatalf("Dial with a refusing factory = %v, %v (entry check live %v)", s, err, ec.live.Load())
		}
		synctest.Wait()
		ended, _ := reg.calls()
		if len(ended) != 1 || f.calls.Load() == 0 {
			t.Fatalf("a failed Dial's session: %d Ended calls, %d factory calls; want exactly one Ended", len(ended), f.calls.Load())
		}
		select {
		case <-ended[0].Done():
		default:
			t.Fatal("the failed Dial's session is not done after it withdrew")
		}

		// Peer.open reports what Peer.Dial hands over to the session's Ended.
		if _, created, err := p.open(done, SessionID(wpSID(2)), DialOptions{}, false, &dialReg{rt: rt, sid: SessionID(wpSID(2))}); created || err == nil {
			t.Fatalf("open with a done context: created %v, %v", created, err)
		}
		dr := &dialReg{rt: rt, sid: SessionID(wpSID(3))}
		if _, created, err := p.open(context.Background(), SessionID(wpSID(3)), DialOptions{}, false, dr); !created || !errors.Is(err, ErrNoPath) {
			t.Fatalf("open with a refusing factory: created %v, %v", created, err)
		}
		synctest.Wait()
		dr.mu.Lock()
		endedOnce := dr.ended
		dr.mu.Unlock()
		if !endedOnce {
			t.Fatal("the created session never called its dialReg's Ended")
		}
		rt.Close()
		wpNoState(t, rt)
	})
}
