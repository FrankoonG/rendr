package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"
)

// An EarlyReturn Conn that the application holds but never uses is idle
// like any other session (plan:277, plan:385; K21 candidate 1): its
// IdleTimeout counts from Dial, and at expiry it ends with ErrIdleTimeout,
// sends nothing (no OPEN was sent, so no RST either) and gives back its
// MaxSessions unit. Helpers of these tests start with "ei".

// eiIdle is the IdleTimeout of these rows: the clamp's floor.
const eiIdle = 10 * time.Second

// eiEndEvents returns the EventSessionEnd records of session sid.
func eiEndEvents(rec *erEvents, sid SessionID) []Event {
	var out []Event
	for _, ev := range rec.of(sid) {
		if ev.Kind == EventSessionEnd {
			out = append(out, ev)
		}
	}
	return out
}

// TestEarlyReturnUnusedIdleTimeout_plan277 (plan:277, plan:385; K21): an
// EarlyReturn session with no Write, Read or CloseWrite ends with
// ErrIdleTimeout exactly IdleTimeout after Dial, whether the limit comes
// from Config.IdleTimeout (no call rings the session's scheduler) or from
// Conn.SetIdleTimeout (l4.Dial's pattern), also when SetIdleTimeout comes
// later (the idle clock is not restarted). Stimulus proof: with MaxSessions
// 1 a second Dial before the deadline gets ErrCapacity (the unused session
// holds the unit). At the end: Read and Write return ErrIdleTimeout, one
// EventSessionEnd carries it, no factory was called and no byte crossed the
// link, the passive saw nothing, the dialer's table is empty, and a classic
// Dial on the same Runtime opens, exchanges and finishes cleanly.
func TestEarlyReturnUnusedIdleTimeout_plan277(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   time.Duration // Config.IdleTimeout
		set   time.Duration // SetIdleTimeout value (0: no call)
		setAt time.Duration // when SetIdleTimeout is called, after Dial
	}{
		{name: "Config.IdleTimeout", cfg: eiIdle},
		{name: "SetIdleTimeout at Dial", set: eiIdle},
		{name: "SetIdleTimeout later", set: eiIdle, setAt: 6 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var rec erEvents
				e := e2eNew(t, Config{IdleTimeout: tc.cfg, MaxSessions: 1, OnEvent: rec.add}, Config{}, nil, ListenConfig{}, "a")
				p := e.peer()
				dc := erDial(t, p, DialOptions{})
				dialed := time.Now()
				if tc.set != 0 {
					time.Sleep(tc.setAt)
					if err := dc.SetIdleTimeout(tc.set); err != nil {
						t.Fatalf("SetIdleTimeout: %v", err)
					}
				}
				deadline := dialed.Add(eiIdle)
				if _, err := p.Dial(context.Background(), DialOptions{EarlyReturn: true}); !errors.Is(err, ErrCapacity) {
					t.Fatalf("premise: a second Dial with MaxSessions 1: %v, want ErrCapacity (the unused session holds the unit)", err)
				}
				time.Sleep(time.Until(deadline) - time.Millisecond)
				synctest.Wait()
				if st := dc.Status(); st.State != StatePending || st.Err != nil {
					t.Fatalf("1 ms before the idle limit: state %v, err %v; want pending", st.State, st.Err)
				}
				e2eDone(t, dc, time.Second)
				if at := time.Now(); at.Before(deadline) || at.Sub(deadline) > 5*time.Millisecond {
					t.Fatalf("the session ended %v after Dial, want the idle limit %v", at.Sub(dialed), eiIdle)
				}
				if st := dc.Status(); st.State != StateEnded || !errors.Is(st.Err, ErrIdleTimeout) {
					t.Fatalf("end: state %v, err %v; want ended with ErrIdleTimeout", st.State, st.Err)
				}
				if n, err := dc.Read(make([]byte, 8)); n != 0 || !errors.Is(err, ErrIdleTimeout) {
					t.Fatalf("Read after the idle end = (%d, %v), want (0, ErrIdleTimeout)", n, err)
				}
				if n, err := dc.Write([]byte("late")); n != 0 || !errors.Is(err, ErrIdleTimeout) {
					t.Fatalf("Write after the idle end = (%d, %v), want (0, ErrIdleTimeout)", n, err)
				}
				synctest.Wait()
				if evs := eiEndEvents(&rec, dc.ID()); len(evs) != 1 || !errors.Is(evs[0].Err, ErrIdleTimeout) {
					t.Fatalf("SessionEnd events %+v, want one carrying ErrIdleTimeout", evs)
				}
				if st := e.links[0].Stats(); st.Dials != 0 || st.All.Bytes != 0 {
					t.Fatalf("the unused session sent something: %d factory calls, %d bytes", st.Dials, st.All.Bytes)
				}
				if st := e.p.Status(); st.Sessions != (SessionCounts{}) || st.AcceptBacklog != [2]int{} {
					t.Fatalf("the passive saw a session: %+v, backlog %v", st.Sessions, st.AcceptBacklog)
				}
				if st := e.d.Status(); st.Sessions != (SessionCounts{}) || e.d.table.inUse() != 0 || st.BufferedBytes != 0 {
					t.Fatalf("dialer after the idle end: %+v, %d MaxSessions units, %d buffered", st.Sessions, e.d.table.inUse(), st.BufferedBytes)
				}
				dc2, sc := e2eOpen(t, p, e.ln, DialOptions{})
				e2eExchange(t, dc2, sc, 64<<10, 21)
				e2eFinish(t, dc2, sc)
				e.close()
			})
		})
	}
}

// TestEarlyReturnUnusedIdleOff (plan:277; K21): without an idle limit an
// unused EarlyReturn session stays pending however long it waits — 0 in
// Config, or SetIdleTimeout(0) over a Config limit (the override counts) —
// and its first Write still opens it and delivers.
func TestEarlyReturnUnusedIdleOff(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  time.Duration
		off  bool // SetIdleTimeout(0) right after Dial
	}{
		{name: "Config 0", cfg: 0},
		{name: "SetIdleTimeout(0) over Config", cfg: eiIdle, off: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{IdleTimeout: tc.cfg}, Config{}, nil, ListenConfig{}, "a")
				dc := erDial(t, e.peer(), DialOptions{})
				if tc.off {
					if err := dc.SetIdleTimeout(0); err != nil {
						t.Fatalf("SetIdleTimeout(0): %v", err)
					}
				}
				select {
				case <-dc.s.Done():
					t.Fatalf("the unused session ended without an idle limit: %v", dc.Status().Err)
				case <-time.After(25 * time.Hour):
				}
				if st := dc.Status(); st.State != StatePending || e.links[0].Stats().Dials != 0 {
					t.Fatalf("after 25 h: state %v, %d factory calls; want pending and none", st.State, e.links[0].Stats().Dials)
				}
				msg := erPattern(0, 1000)
				if _, err := dc.Write(msg); err != nil {
					t.Fatalf("Write: %v", err)
				}
				sc := e2eConfirm(t, e.ln)
				erReadN(t, sc, 0, len(msg))
				erAnswered(t, dc)
				e2eFinish(t, dc, sc)
				e.close()
			})
		})
	}
}

// TestEarlyReturnUsedBeforeIdleLimit (plan:277; K21): the rule is for a
// session never used. A Write, or a Read, 9 s after Dial (IdleTimeout
// 10 s) opens the session; the passive confirms only at 11 s, so the
// opening spans Dial's idle mark and must survive it (an opening phase is
// bounded by NoPathGrace, never by IdleTimeout, as for a classic Dial).
// From the open on the session idles like any other: it ends
// ErrIdleTimeout (the passive *AbortError{AbortIdle}) IdleTimeout after its
// last progress, never earlier.
func TestEarlyReturnUsedBeforeIdleLimit(t *testing.T) {
	for _, read := range []bool{false, true} {
		name := "Write"
		if read {
			name = "Read"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{IdleTimeout: eiIdle}, Config{}, nil, ListenConfig{}, "a")
				dc := erDial(t, e.peer(), DialOptions{})
				dialed := time.Now()
				time.Sleep(9 * time.Second)
				msg := erPattern(0, 700)
				var rd <-chan error
				if read {
					rd = erReadAsync(dc, len(msg))
				} else if _, err := dc.Write(msg); err != nil {
					t.Fatalf("Write 9 s after Dial: %v", err)
				}
				pc := erAccept(t, e.ln)
				time.Sleep(time.Until(dialed.Add(eiIdle)) + time.Second)
				if st := dc.Status(); st.State != StatePending || st.Err != nil {
					t.Fatalf("1 s past Dial's idle mark, still opening: state %v, err %v; want pending", st.State, st.Err)
				}
				sc, err := pc.Confirm()
				if err != nil {
					t.Fatalf("Confirm at 11 s: %v", err)
				}
				if read {
					if _, err := sc.Write(msg); err != nil {
						t.Fatalf("passive Write: %v", err)
					}
					if err := <-rd; err != nil {
						t.Fatalf("dialer Read: %v", err)
					}
				} else {
					erReadN(t, sc, 0, len(msg))
				}
				erAnswered(t, dc)
				synctest.Wait()
				last := time.Now() // the last progress (a Read commit, or our bytes acknowledged within an ACK interval)
				e2eDone(t, dc, 2*eiIdle)
				if el := time.Since(last); el < eiIdle-time.Second {
					t.Fatalf("the open session ended %v after its last progress, before its idle limit %v", el, eiIdle)
				}
				if err := dc.Status().Err; !errors.Is(err, ErrIdleTimeout) {
					t.Fatalf("dialer end %v, want ErrIdleTimeout", err)
				}
				e2eDone(t, sc, 5*time.Second)
				var ae *AbortError
				if err := sc.Status().Err; !errors.As(err, &ae) || ae.Code != AbortIdle || !ae.Remote {
					t.Fatalf("passive end %v, want *AbortError{AbortIdle, Remote}", err)
				}
				e.close()
			})
		})
	}
}

// erReadAsync reads exactly n bytes of the pattern from 0 on its own
// goroutine; the channel carries the outcome.
func erReadAsync(c *Conn, n int) <-chan error {
	ch := make(chan error, 1)
	go func() {
		got := make([]byte, n)
		if _, err := io.ReadFull(c, got); err != nil {
			ch <- err
			return
		}
		if !bytes.Equal(got, erPattern(0, n)) {
			ch <- errors.New("the dialer read other bytes")
			return
		}
		ch <- nil
	}()
	return ch
}
