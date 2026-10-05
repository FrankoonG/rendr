package session

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestIdleClockCountsDelivery_L19 (design §0.14 B5; L19: a session is
// judged by the delivery of application data, never by control traffic
// alone): the IdleTimeout clock (st.lastData) restarts at every advance of
// the acknowledged front — an ACK, or a JOIN rxNext, that delivers new
// bytes of ours — at the time that advance was processed, as at every
// application commit. An ACK that delivers nothing new (a duplicate, a
// window update) leaves it alone, so a peer that stops reading still lets
// IdleTimeout expire. The actor reads the clock in terminationLocked;
// TestIdleTimeoutCountsDelivery_L19 in internal/scenario/lessons2 proves the
// end-to-end effect.
func TestIdleClockCountsDelivery_L19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const w = 1 << 20
		s := stSession(stOpt{window: w})
		l, _ := stAddLane(s, 1, true)
		s.mu.Lock()
		s.peerWindowLocked(w)
		s.mu.Unlock()
		start := time.Now()
		clock := func(what string, want time.Duration) {
			t.Helper()
			if got := stLocked(s, func(st *stream) time.Time { return st.lastData }); !got.Equal(start.Add(want)) {
				t.Fatalf("idle clock after %s = start%+v, want start%+v", what, got.Sub(start), want)
			}
		}

		if n, err := s.Write(stPattern(0, 64<<10)); n != 64<<10 || err != nil {
			t.Fatalf("Write = (%d, %v), want all 64 KiB", n, err)
		}
		_, b := stFill(l, start)
		b.ReleaseRefs()
		if sent := stLocked(s, func(st *stream) uint64 { return st.sNext }); sent != 64<<10 {
			t.Fatalf("Fill sent %d bytes, want 64 KiB", sent)
		}
		clock("the Write commit", 0)

		time.Sleep(5 * time.Second)
		if err := stSendAck(l, 0, 16<<10, w); err != nil {
			t.Fatal(err)
		}
		clock("an ACK delivering 16 KiB at 5 s", 5*time.Second)

		time.Sleep(3 * time.Second)
		if err := stSendAck(l, 0, 16<<10, w); err != nil { // a duplicate
			t.Fatal(err)
		}
		if err := stSendAck(l, 0, 16<<10, 2*w); err != nil { // a window update
			t.Fatal(err)
		}
		clock("ACKs delivering nothing new at 8 s", 5*time.Second)

		time.Sleep(2 * time.Second)
		s.mu.Lock()
		err := s.applyRxNextLocked(32 << 10) // a JOIN or JOIN_ACK rxNext
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		clock("an rxNext delivering 16 KiB more at 10 s", 10*time.Second)

		time.Sleep(time.Second)
		if err := stSendAck(l, 0, 64<<10, w); err != nil {
			t.Fatal(err)
		}
		clock("an ACK delivering the rest at 11 s", 11*time.Second)
		if base := stLocked(s, func(st *stream) uint64 { return st.sBase }); base != 64<<10 {
			t.Fatalf("acknowledged front %d, want 64 KiB", base)
		}
		stEnd(s, errClosed)
		if u := s.env.Carrier.Budget.Used(); u != 0 {
			t.Fatalf("Budget.Used = %d after the end", u)
		}
	})
}
