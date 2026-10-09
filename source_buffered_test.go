package rendr

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestIdleSourceBufferedBytes (R-C3-2; plan:774, gold/G6-mixed-nat's
// return_b_sessions): Status.BufferedBytes counts the MaxBufferedBytes
// budget and the reader stages of live carriers — not the read buffer a
// FromPacketConn source keeps for its socket. With a raw-UDP listener open
// and no session or carrier, BufferedBytes is 0: before any datagram, after
// junk datagrams the sources read and dropped (over real sockets:
// TestIdleUDPSourceBufferedBytes), and after a packet session whose
// datagrams were queued in its flow's inbox ended.
func TestIdleSourceBufferedBytes(t *testing.T) {
	t.Run("hub", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := peNewHub(t, Config{}, ListenConfig{}, nil)
			synctest.Wait()
			if st := h.p.Status(); st.Datagram.Sources != 1 || st.BufferedBytes != 0 {
				t.Fatalf("an idle FromPacketConn source: sources %d, BufferedBytes %d, want 1 and 0", st.Datagram.Sources, st.BufferedBytes)
			}
			// Load and integrity: a session over the source moves 200
			// datagrams each way through its flow's inbox, then ends.
			dc, pc := peOpen(t, h.peer(h.carrier("h0", 0, nil)), h.ln, DialOptions{})
			peSend(t, dc, 1, 0, 200, 700)
			if v := peRecv(t, pc, 1, 200, time.Second); v.Result().Unique != 200 {
				t.Fatalf("dialer → passive: %+v", v.Result())
			}
			peSend(t, pc, 2, 0, 200, 700)
			if v := peRecv(t, dc, 2, 200, time.Second); v.Result().Unique != 200 {
				t.Fatalf("passive → dialer: %+v", v.Result())
			}
			if h.p.Status().BufferedBytes == 0 {
				t.Fatal("stimulus: a live carrier holds no buffered bytes")
			}
			peEnd(t, dc, pc)
			peWait(t, 5*time.Second, "the flow's removal", func() bool { return h.p.Status().Datagram.Flows == 0 })
			synctest.Wait()
			if st := h.p.Status(); st.Datagram.Sources != 1 || st.Sessions.Open+st.Sessions.Pending+st.Sessions.Lingering != 0 || st.BufferedBytes != 0 {
				t.Fatalf("after the session, the listener open: sources %d, sessions %+v, BufferedBytes %d, want 0", st.Datagram.Sources, st.Sessions, st.BufferedBytes)
			}
			h.close()
		})
	})
}
