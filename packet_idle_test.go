package rendr

import (
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP1 (m6-design §A2.1, §A16.1; M6-D6): the root side of
// PacketConn.SetIdleTimeout, the packet twin of M4's Conn.SetIdleTimeout.
// Helpers start with "c6".

// c6Idle is a selector packet session between two Runtimes over one
// DatagramLink (1 ms each way), with an event log on each Runtime. Both
// Runtimes have PingIdle 1 min (the idle carrier's PING cadence, which
// never moves the idle clock), so that the rows that wait hours of
// virtual time stay cheap.
type c6Idle struct {
	e          *pePair
	dc, pc     *PacketConn
	dlog, plog *eventLog
}

// c6IdleOpen opens it with Config.IdleTimeout dIdle on the dialer's
// Runtime and pIdle on the passive's.
func c6IdleOpen(t *testing.T, dIdle, pIdle time.Duration) *c6Idle {
	t.Helper()
	c := &c6Idle{dlog: &eventLog{}, plog: &eventLog{}}
	dcfg := Config{IdleTimeout: dIdle, PingIdle: time.Minute, OnEvent: c.dlog.add}
	pcfg := Config{IdleTimeout: pIdle, PingIdle: time.Minute, OnEvent: c.plog.add}
	c.e = peNew(t, dcfg, pcfg, nil, 0, "a")
	l := c.e.links[0]
	l.SetDelay(rendrtest.Up, time.Millisecond, 0)
	l.SetDelay(rendrtest.Down, time.Millisecond, 0)
	c.dc, c.pc = peOpen(t, c.e.peer(peDatagramCarrier(l, 1400)), c.e.ln, DialOptions{})
	return c
}

// side returns the overriding end (the passive's when passive) with its
// Runtime's event log, then the other end.
func (c *c6Idle) side(passive bool) (on *PacketConn, log *eventLog, other *PacketConn) {
	if passive {
		return c.pc, c.plog, c.dc
	}
	return c.dc, c.dlog, c.pc
}

// c6Datagram writes one datagram of n bytes from w and reads it at r.
func c6Datagram(t *testing.T, w, r *PacketConn, n int) {
	t.Helper()
	if k, err := w.WriteTo(make([]byte, n), nil); k != n || err != nil {
		t.Fatalf("WriteTo = %d, %v", k, err)
	}
	r.SetReadDeadline(time.Now().Add(time.Second))
	defer r.SetReadDeadline(time.Time{})
	if k, _, err := r.ReadFrom(make([]byte, 2*n)); k != n || err != nil {
		t.Fatalf("ReadFrom = %d, %v; want the %d-byte datagram", k, err, n)
	}
}

// exchange moves one datagram each way and returns when the reply was
// read: the last activity of both ends.
func (c *c6Idle) exchange(t *testing.T) time.Time {
	t.Helper()
	c6Datagram(t, c.dc, c.pc, 64)
	c6Datagram(t, c.pc, c.dc, 64)
	return time.Now()
}

// c6EndEvent waits at most within for x's Done and returns the instant and
// error of its one EventSessionEnd in log (the end decision; Done closes
// after the joins), which is the error Status reports.
func c6EndEvent(t *testing.T, x *PacketConn, log *eventLog, within time.Duration) (time.Time, error) {
	t.Helper()
	select {
	case <-x.Done():
	case <-time.After(within):
		t.Fatalf("the session did not end within %v: %+v", within, x.Status())
	}
	synctest.Wait() // the event worker delivered what was queued
	var ends []Event
	for _, ev := range log.of(EventSessionEnd) {
		if ev.Session == x.ID() {
			ends = append(ends, ev)
		}
	}
	if len(ends) != 1 || ends[0].Err != x.Status().Err {
		t.Fatalf("SessionEnd events %+v, want one with the final error %v", ends, x.Status().Err)
	}
	return ends[0].Time, ends[0].Err
}

// c6AbortIdle reports whether err is the peer side of an idle expiry.
func c6AbortIdle(err error) bool {
	var ae *AbortError
	return errors.As(err, &ae) && ae.Code == AbortIdle && ae.Remote
}

// TestPacketConnSetIdleTimeout_L30 (M6-D6; L30, plan:277): on either role
// of a packet session, with Config.IdleTimeout off on both Runtimes unless
// a row sets the overriding side's, PacketConn.SetIdleTimeout replaces the
// idle limit from the call on, with Conn.SetIdleTimeout's clamp (10 s–24 h)
// and without restarting the clock. A quiet session then ends at the limit
// after its last datagram — no earlier, and no later than PacketPing after
// it (the move on accepted datagrams may lag that much) — with
// ErrIdleTimeout here and *AbortError{AbortIdle} at the peer; afterwards
// SetIdleTimeout returns net.ErrClosed on both ends. Raised at 20 s to
// 180 s it ends 180 s after the last datagram; 0 or a negative value turns
// expiry off, also over a Config.IdleTimeout (the session is open 2 h later
// and still carries datagrams both ways); a call on a session whose actors
// parked (Status.Actors 0, stimulus) re-arms them, at once when the new
// limit already passed. A FIN in flight is not cut: once this side's DONE
// left (it closed 750 ms before the deadline and the path toward it takes
// 500 ms) the session ends with io.EOF on both ends after the deadline;
// the control, closed 250 ms before the deadline, ends with
// ErrIdleTimeout because its DONE had not left.
func TestPacketConnSetIdleTimeout_L30(t *testing.T) {
	type call struct {
		at time.Duration // after the last datagram
		d  time.Duration // SetIdleTimeout's argument
	}
	const packetPing = time.Second // Config.PacketPing's default
	rows := []struct {
		name     string
		cfg      time.Duration // Config.IdleTimeout of the overriding side's Runtime (0: off)
		park     bool          // both Runtimes' actors must be parked at the first call
		calls    []call
		expireAt time.Duration // after the last datagram; 0: never (checked for 2 h)
	}{
		{name: "30 s", calls: []call{{0, 30 * time.Second}}, expireAt: 30 * time.Second},
		{name: "raised to 180 s at 20 s", calls: []call{{0, 30 * time.Second}, {20 * time.Second, 180 * time.Second}}, expireAt: 180 * time.Second},
		{name: "raised to the 10 s floor", calls: []call{{0, time.Second}}, expireAt: 10 * time.Second},
		{name: "lowered to the 24 h ceiling", calls: []call{{0, 48 * time.Hour}}, expireAt: 24 * time.Hour},
		{name: "Config alone (control)", cfg: 20 * time.Second, expireAt: 20 * time.Second},
		{name: "longer than Config", cfg: 20 * time.Second, calls: []call{{5 * time.Second, time.Minute}}, expireAt: time.Minute},
		{name: "zero turns it off", calls: []call{{0, 30 * time.Second}, {20 * time.Second, 0}}},
		{name: "zero over Config", cfg: 20 * time.Second, calls: []call{{5 * time.Second, 0}}},
		{name: "negative over Config", cfg: 20 * time.Second, calls: []call{{5 * time.Second, -time.Second}}},
		{name: "parked actors, in the future", park: true, calls: []call{{15 * time.Second, 30 * time.Second}}, expireAt: 30 * time.Second},
		{name: "parked actors, already past", park: true, calls: []call{{60 * time.Second, 30 * time.Second}}, expireAt: 60 * time.Second},
	}
	for _, r := range rows {
		for _, passive := range []bool{false, true} {
			role := "dialer"
			if passive {
				role = "passive"
			}
			t.Run(r.name+"/"+role, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var dIdle, pIdle time.Duration
					if passive {
						pIdle = r.cfg
					} else {
						dIdle = r.cfg
					}
					c := c6IdleOpen(t, dIdle, pIdle)
					on, log, other := c.side(passive)
					last := c.exchange(t)
					for i, k := range r.calls {
						time.Sleep(time.Until(last.Add(k.at)))
						if i == 0 && r.park {
							synctest.Wait()
							if a, b := c.e.d.Status().Actors, c.e.p.Status().Actors; a+b != 0 {
								t.Fatalf("stimulus: %d dialer and %d passive actors running %v after the last datagram, want both parked", a, b, k.at)
							}
						}
						if err := on.SetIdleTimeout(k.d); err != nil {
							t.Fatalf("SetIdleTimeout(%v): %v", k.d, err)
						}
					}
					if r.expireAt == 0 {
						select {
						case <-on.Done():
							t.Fatalf("the session ended with idle expiry off: %v", on.Status().Err)
						case <-other.Done():
							t.Fatalf("the peer ended with idle expiry off: %v", other.Status().Err)
						case <-time.After(time.Until(last.Add(2 * time.Hour))):
						}
						c.exchange(t)
						peEnd(t, c.dc, c.pc)
						for _, x := range []*PacketConn{c.dc, c.pc} {
							if err := x.Status().Err; err != io.EOF {
								t.Fatalf("end error %v after a clean close, want io.EOF", err)
							}
						}
						c.e.close()
						return
					}
					at, err := c6EndEvent(t, on, log, r.expireAt+time.Minute)
					t.Logf("ended %v after the last datagram (%v off %v)", at.Sub(last), at.Sub(last.Add(r.expireAt)), r.expireAt)
					if d := at.Sub(last.Add(r.expireAt)); d < -5*time.Millisecond || d > packetPing+10*time.Millisecond {
						t.Fatalf("the session ended %v off %v after its last datagram, want within [-5ms, PacketPing]", d, r.expireAt)
					}
					if !errors.Is(err, ErrIdleTimeout) {
						t.Fatalf("the expiring side ended with %v, want ErrIdleTimeout", err)
					}
					select {
					case <-other.Done():
					case <-time.After(5 * time.Second):
						t.Fatal("the peer did not end within 5 s of the idle expiry")
					}
					if err := other.Status().Err; !c6AbortIdle(err) {
						t.Fatalf("the peer ended with %v, want *AbortError{AbortIdle, Remote}", err)
					}
					for _, x := range []*PacketConn{on, other} {
						if err := x.SetIdleTimeout(time.Minute); !errors.Is(err, net.ErrClosed) {
							t.Fatalf("SetIdleTimeout after the end: %v, want net.ErrClosed", err)
						}
					}
					c.e.close()
				})
			})
		}
	}

	// The DONE rule wins over the idle rule (M2-D40; design §0.14 B4).
	for _, r := range []struct {
		name string
		lead time.Duration // how long before the idle deadline this side closes
		done bool          // its DONE leaves before the deadline
	}{
		{name: "DONE before the deadline", lead: 750 * time.Millisecond, done: true},
		{name: "DONE after the deadline (control)", lead: 250 * time.Millisecond},
	} {
		for _, passive := range []bool{false, true} {
			role := "dialer"
			if passive {
				role = "passive"
			}
			t.Run(r.name+"/"+role, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					const idle = 30 * time.Second
					c := c6IdleOpen(t, 0, 0)
					on, log, other := c.side(passive)
					// Only this side writes, so its idle clock is exactly
					// its WriteTo (no accepted datagram moves it).
					last := time.Now()
					c6Datagram(t, on, other, 64)
					if err := on.SetIdleTimeout(idle); err != nil {
						t.Fatal(err)
					}
					toward := rendrtest.Down // the path toward this side
					if passive {
						toward = rendrtest.Up
					}
					c.e.links[0].SetDelay(toward, 500*time.Millisecond, 0)
					time.Sleep(time.Until(last.Add(idle - r.lead)))
					if err := on.Close(); err != nil {
						t.Fatal(err)
					}
					at, err := c6EndEvent(t, on, log, time.Minute)
					select {
					case <-other.Done():
					case <-time.After(5 * time.Second):
						t.Fatal("the peer did not end within 5 s")
					}
					oerr := other.Status().Err
					deadline := last.Add(idle)
					t.Logf("ended %v after the deadline with %v (peer %v)", at.Sub(deadline), err, oerr)
					if r.done {
						// The peer's DONE arrives one path delay after ours left.
						if err != io.EOF || oerr != io.EOF || !at.After(deadline) || at.After(deadline.Add(500*time.Millisecond)) {
							t.Fatalf("ended %v after the deadline with %v (peer %v), want io.EOF on both ends when the peer's DONE arrived after the deadline", at.Sub(deadline), err, oerr)
						}
					} else if !errors.Is(err, ErrIdleTimeout) || !at.Equal(deadline) || !c6AbortIdle(oerr) {
						t.Fatalf("control: ended %v after the deadline with %v (peer %v), want ErrIdleTimeout at the deadline and AbortIdle at the peer", at.Sub(deadline), err, oerr)
					}
					c.e.close()
				})
			})
		}
	}
}
