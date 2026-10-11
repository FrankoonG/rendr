package l4

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// msess's two target tests (plan:661; M4 design §A12.3, M4-D48, PA-49,
// PA-50, R1-22), synctest variants: one Link p1 of 20 ms RTT (d = 10 ms
// one way), a single factory (no probe carriers), default Props, the zero
// Config on both ends; the sessions are opened with l4.Dial and the test
// holds the dialer Conns directly (R1-3: the Linger bound is asserted only
// where the Conn is held).

// spyConn wraps the conn a Server's Forward gets toward a target and
// records the instants Forward wrote to it and closed it, and whether it
// reset it (SetLinger(0) before Close). It offers CloseWrite and SetLinger
// as the TargetConn it wraps does.
type spyConn struct {
	*rendrtest.TargetConn
	mu        sync.Mutex
	lastWrite time.Time // the last Write that moved bytes
	closedAt  time.Time
	closes    int
	linger0   bool
}

func (s *spyConn) Write(b []byte) (int, error) {
	n, err := s.TargetConn.Write(b)
	if n > 0 {
		s.mu.Lock()
		s.lastWrite = time.Now()
		s.mu.Unlock()
	}
	return n, err
}

func (s *spyConn) SetLinger(sec int) error {
	s.mu.Lock()
	s.linger0 = sec == 0
	s.mu.Unlock()
	return s.TargetConn.SetLinger(sec)
}

func (s *spyConn) Close() error {
	s.mu.Lock()
	s.closes++
	if s.closedAt.IsZero() {
		s.closedAt = time.Now()
	}
	s.mu.Unlock()
	return s.TargetConn.Close()
}

// state returns the recorded instants and calls.
func (s *spyConn) state() (lastWrite, closedAt time.Time, closes int, reset bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastWrite, s.closedAt, s.closes, s.linger0
}

// spies records the spyConn of every target connection by address.
type spies struct {
	mu sync.Mutex
	by map[string]*spyConn
}

// spied routes class to tg through a spyConn per connection.
func (w *world) spied(class string, tg *rendrtest.Target) *spies {
	sp := &spies{by: map[string]*spyConn{}}
	w.handle(class, func(ctx context.Context, addr string) (net.Conn, error) {
		c, err := tg.Dial(ctx, addr)
		if err != nil {
			return nil, err
		}
		s := &spyConn{TargetConn: c.(*rendrtest.TargetConn)}
		sp.mu.Lock()
		sp.by[addr] = s
		sp.mu.Unlock()
		return s, nil
	})
	return sp
}

// of returns the spyConn of addr (nil: none yet).
func (sp *spies) of(addr string) *spyConn {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return sp.by[addr]
}

// endOf returns the passive's EventSessionEnd of session id.
func endOf(l *eventLog, id rendr.SessionID) (rendr.Event, bool) {
	for _, ev := range l.ends() {
		if ev.Session == id {
			return ev, true
		}
	}
	return rendr.Event{}, false
}

// msessLinger is the default Linger the zero Config gives both ends.
const msessLinger = 30 * time.Second

// TestStalledTargetReleasedAfterClose (plan:661; msess's
// release_test.go shape; R1-22): 5 selector L4 sessions to stalled
// targets; each client writes an HTTP-like request and half-closes; the
// target reads it to the FIN and holds the connection.
//
// Sanity after 1 virtual s (the stimulus): 5 passive sessions open, 5
// open target connections, each having read its request and the FIN.
// Then every client Closes its Conn.
//
// PASS: every target is reset (SetLinger(0), then Close, exactly once)
// and every passive session ends in [Linger + d, Linger + d + 2 ms] after
// the Close (the dialer's RST(Linger) at Linger, one one-way delay on the
// wire), with *AbortError{AbortLinger} from the peer — never AbortIdle;
// afterwards Target.Open == 0 and ServerStatus.Live == 0, and nothing is
// left after Runtime.Close. Mutant "RST at Linger + idle" fails this row.
//
// Subtest "target keeps sending": the target ignores the FIN and sends
// 1 KiB every I = 100 ms (TargetIgnoreFIN); the dialer discards what
// arrives after its Close and answers it with RST(Closed): every target
// is reset and every passive session ends with AbortClosed within
// max(2d + A, I + d) + d + 1 ms of the Close (A = 20 ms, the ACK delay;
// R1-22).
func TestStalledTargetReleasedAfterClose(t *testing.T) {
	t.Run("stall", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stalledRelease(t, rendrtest.TargetStall(), msessLinger+oneWay, msessLinger+oneWay+2*time.Millisecond, rendr.AbortLinger)
		})
	})
	t.Run("target keeps sending", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const ackDelay, interval = 20 * time.Millisecond, 100 * time.Millisecond
			bound := max(2*oneWay+ackDelay, interval+oneWay) + oneWay + time.Millisecond
			stalledRelease(t, rendrtest.TargetIgnoreFIN(), 0, bound, rendr.AbortClosed)
		})
	})
}

// stalledRelease runs one variant: each target and passive session must
// be released in [lo, hi] after its client's Close, the passive ending
// with the peer's code.
func stalledRelease(t *testing.T, b rendrtest.TargetBehaviour, lo, hi time.Duration, code rendr.AbortCode) {
	const n = 5
	w := newWorld(t, worldOpts{}, linkSpec{name: "p1"})
	peer := w.peer("p1")
	tg := w.target("stall", b)
	sp := w.spied("stall", tg)
	cs := make([]*rendr.Conn, n)
	reqs := make([]string, n)
	for i := range cs {
		addr := fmt.Sprintf("stall-%d.test:80", i)
		c, err := l4.Dial(context.Background(), peer, addr, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("Dial %s: %v", addr, err)
		}
		req := fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: stall-%d.test\r\nUser-Agent: rendr-scenario\r\n\r\n", i, i)
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if err := c.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite %d: %v", i, err)
		}
		cs[i], reqs[i] = c, req
	}
	time.Sleep(time.Second)
	if sc := w.p.Status().Sessions; sc.Open != n {
		t.Fatalf("sanity: %d passive sessions open after 1 s, want %d: %+v", sc.Open, n, sc)
	}
	c := tg.Counts()
	if c.Accepted != n || c.Open != n || c.FINIn != n {
		t.Fatalf("sanity: target %+v after 1 s, want %d open connections that read the FIN", totals(c), n)
	}
	for _, cc := range c.Conns {
		var i int
		if _, err := fmt.Sscanf(cc.Addr, "stall-%d.test:80", &i); err != nil || i < 0 || i >= n {
			t.Fatalf("sanity: a target connection for %q", cc.Addr)
		}
		if cc.BytesIn != int64(len(reqs[i])) || cc.SHAIn != sha256.Sum256([]byte(reqs[i])) {
			t.Fatalf("sanity: target connection %s read %d bytes (intact %v), want its %d-byte request", cc.Addr, cc.BytesIn,
				cc.SHAIn == sha256.Sum256([]byte(reqs[i])), len(reqs[i]))
		}
	}
	if b := c.BytesOut; code == rendr.AbortClosed && b < n<<10 {
		t.Fatalf("stimulus: the targets sent %d bytes after the FIN, want ≥ %d", b, n<<10)
	}
	closed := time.Now()
	for _, c := range cs {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	waitFor(t, msessLinger+10*time.Second, "every target connection closed", func() bool { return tg.Counts().Open == 0 })
	waitFor(t, 10*time.Second, "every passive session ended", func() bool {
		for _, c := range cs {
			if _, ok := endOf(w.pev, c.ID()); !ok {
				return false
			}
		}
		return true
	})
	var first, last time.Duration
	for i, c := range cs {
		addr := fmt.Sprintf("stall-%d.test:80", i)
		s := sp.of(addr)
		if s == nil {
			t.Fatalf("%s: no target connection", addr)
		}
		_, at, closes, reset := s.state()
		if el := at.Sub(closed); closes != 1 || !reset || el < lo || el > hi {
			t.Errorf("%s: target closed %d times (reset %v) %v after the Close, want one reset in [%v, %v]", addr, closes, reset, el, lo, hi)
		}
		if el := at.Sub(closed); i == 0 || el < first {
			first = el
		}
		last = max(last, at.Sub(closed))
		ev, _ := endOf(w.pev, c.ID())
		got, remote, ok := abortOf(ev.Err)
		if el := ev.Time.Sub(closed); !ok || got != code || !remote || el < lo || el > hi {
			t.Errorf("%s: the passive session ended with %v %v after the Close, want the peer's %v in [%v, %v]", addr, ev.Err, el, code, lo, hi)
		}
		if ok && got == rendr.AbortIdle {
			t.Errorf("%s: the passive session ended AbortIdle", addr)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	waitFor(t, time.Second, "no live connection on the Server", func() bool { return w.srv.Status().Live == 0 })
	if c := tg.Counts(); c.RSTIn != n || c.Open != 0 {
		t.Fatalf("target %+v, want %d connections reset and none open", totals(c), n)
	}
	for _, c := range cs {
		select {
		case <-c.Done():
		case <-time.After(msessLinger):
			t.Fatalf("the dialer session %v did not end: %+v", c.ID(), c.Status())
		}
	}
	t.Logf("%d targets reset %v–%v after the Close (window [%v, %v]); the passive ends %v", n, first, last, lo, hi, code)
	w.noViolation()
	w.close()
}

// msessIdle is the L4 idle default both ends set (l4.Dial, l4.Server).
const msessIdle = l4.DefaultIdleTimeout

// msessDeadMax is the zero Config's DeadMax.
const msessDeadMax = 4 * time.Second

// TestIdleSessionExpires (plan:661; M4-D21, M4-D41): one L4 session; the
// client writes "hello" on its l4.Dial Conn; the stall target reads it;
// nothing else moves.
//
// Stimulus: the 5 bytes reached the target (the passive Forward's last
// Write to it, the reference instant r: the passive application's last
// read, which the dialer's last acknowledgement covers) and the dialer saw
// them acknowledged.
//
// PASS: both ends end in [r + 10 min, r + 10 min + DeadMax + 1 s] (virtual
// time; the idle limit l4.Dial and the Server set, DefaultIdleTimeout);
// the passive session count and Target.Open reach 0, the target having
// been reset; the client's Read, pending since the write, returns
// ErrIdleTimeout or *AbortError{AbortIdle} — never io.EOF — and not before
// r + 10 min; nothing is left after Runtime.Close. Mutants: Conn.SetIdleTimeout
// ignored (M4-D21) and no SetIdleTimeout in l4 (M4-D41) fail this row.
func TestIdleSessionExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{}, linkSpec{name: "p1"})
		tg := w.target("stall", rendrtest.TargetStall())
		sp := w.spied("stall", tg)
		const addr = "stall-1.test:80"
		c, err := l4.Dial(context.Background(), w.peer("p1"), addr, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		type readEnd struct {
			n   int
			err error
			at  time.Time
		}
		rd := make(chan readEnd, 1)
		go func() {
			n, err := c.Read(make([]byte, 64))
			rd <- readEnd{n, err, time.Now()}
		}()
		if _, err := io.WriteString(c, "hello"); err != nil {
			t.Fatalf("Write: %v", err)
		}
		waitFor(t, 10*time.Second, "hello acknowledged and at the target", func() bool {
			s := sp.of(addr)
			if s == nil {
				return false
			}
			lw, _, _, _ := s.state()
			return c.Status().AckedBytes == 5 && !lw.IsZero() && tg.Counts().BytesIn == 5
		})
		if got := tg.Counts().Conns[0].SHAIn; got != sha256.Sum256([]byte("hello")) {
			t.Fatal("integrity: the target did not read \"hello\"")
		}
		r, _, _, _ := sp.of(addr).state()
		lo, hi := r.Add(msessIdle), r.Add(msessIdle+msessDeadMax+time.Second)

		var re readEnd
		select {
		case re = <-rd:
		case <-time.After(msessIdle + time.Minute):
			t.Fatalf("the client's Read did not return within %v of the write: %+v", msessIdle+time.Minute, c.Status())
		}
		if re.n != 0 || re.err == io.EOF || re.at.Before(lo) {
			t.Fatalf("the client's Read returned (%d, %v) at r%+v, want an idle error not before r + %v", re.n, re.err, re.at.Sub(r), msessIdle)
		}
		if code, _, ok := abortOf(re.err); !errors.Is(re.err, rendr.ErrIdleTimeout) && !(ok && code == rendr.AbortIdle) {
			t.Fatalf("the client's Read returned %v, want ErrIdleTimeout or *AbortError{AbortIdle}", re.err)
		}
		select {
		case <-c.Done():
		case <-time.After(10 * time.Second):
			t.Fatalf("the dialer session did not end with its Read: %+v", c.Status())
		}
		// Both ends' EventSessionEnd: events reach OnEvent asynchronously
		// (L53), so the dialer's may come after its Done and after the
		// passive's.
		var pend, dend rendr.Event
		waitFor(t, 10*time.Second, "both sessions' EventSessionEnd", func() bool {
			var pok, dok bool
			pend, pok = endOf(w.pev, c.ID())
			dend, dok = endOf(w.dev, c.ID())
			return pok && dok
		})
		for i, ev := range []rendr.Event{dend, pend} {
			code, _, isAbort := abortOf(ev.Err)
			if ev.Time.Before(lo) || ev.Time.After(hi) || !errors.Is(ev.Err, rendr.ErrIdleTimeout) && !(isAbort && code == rendr.AbortIdle) {
				t.Fatalf("the %s ended with %v at r%+v, want an idle end in [r + %v, r + %v]", side(i), ev.Err, ev.Time.Sub(r), msessIdle, hi.Sub(r))
			}
		}
		waitFor(t, time.Second, "no passive session and no open target", func() bool {
			sc := w.p.Status().Sessions
			return sc.Open+sc.Pending+sc.Lingering+sc.Orphaned == 0 && tg.Counts().Open == 0 && w.srv.Status().Live == 0
		})
		if _, at, closes, reset := sp.of(addr).state(); closes != 1 || !reset || at.Before(lo) || at.After(hi) || tg.Counts().RSTIn != 1 {
			t.Fatalf("target closed %d times (reset %v) at r%+v, RSTIn %d; want one reset in the idle window", closes, reset, at.Sub(r), tg.Counts().RSTIn)
		}
		t.Logf("idle: dialer %v at r%+v, passive %v at r%+v", dend.Err, dend.Time.Sub(r), pend.Err, pend.Time.Sub(r))
		w.noViolation()
		w.close()
	})
}
