package rendr

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestEarlyReturnStatusDuringOpen (F-8): an EarlyReturn Conn is the
// application's before its session opens (M4-D12), so the application may
// call Status, PeerInstance and RemoteAddr while the session's scheduler
// completes the open of a first Write. The open binds the peer instance
// after Dial returned; before the fix Status read it unsynchronised against
// that write (a data race the race detector reported in
// TestEarlyReturnUnusedIdleOff, 1 of 3 race passes). A poller on its own
// goroutine reads all three for the whole open: under -race the row fails
// on such a race; in every build each reading is the unbound zero or the
// passive's instance, never anything else, a Status reports the instance
// exactly when its State is no longer Pending (the peer belongs to the
// same snapshot as the state), and once seen the instance never changes.
func TestEarlyReturnStatusDuringOpen(t *testing.T) {
	for range 20 {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			want := e.p.InstanceID()
			dc := erDial(t, e.peer(), DialOptions{})
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var bad []string
			wg.Go(func() {
				var seen InstanceID
				for {
					select {
					case <-stop:
						return
					default:
					}
					st := dc.Status()
					pi := dc.PeerInstance()
					ra, _ := dc.RemoteAddr().(Addr)
					switch {
					case st.State == StatePending && st.PeerInstance != (InstanceID{}):
						bad = append(bad, "Status pending with a peer instance")
					case st.State != StatePending && st.PeerInstance != want:
						bad = append(bad, "Status "+st.State.String()+" without the passive's instance")
					case pi != (InstanceID{}) && pi != want, ra.Instance != (InstanceID{}) && ra.Instance != want:
						bad = append(bad, "PeerInstance or RemoteAddr neither zero nor the passive's")
					case seen != (InstanceID{}) && (pi != seen || ra.Instance != seen):
						bad = append(bad, "the instance changed after it was seen")
					}
					if pi != (InstanceID{}) {
						seen = pi
					}
					// Block durably between polls, so the bubble's
					// virtual time advances.
					time.Sleep(10 * time.Microsecond)
				}
			})
			msg := erPattern(0, 1000)
			if _, err := dc.Write(msg); err != nil {
				t.Fatalf("Write: %v", err)
			}
			sc := e2eConfirm(t, e.ln)
			erReadN(t, sc, 0, len(msg))
			erAnswered(t, dc)
			close(stop)
			wg.Wait()
			if len(bad) != 0 {
				t.Fatalf("%d bad readings during the open, the first: %s", len(bad), bad[0])
			}
			if st := dc.Status(); st.PeerInstance != want || dc.PeerInstance() != want {
				t.Fatalf("open: Status().PeerInstance %v PeerInstance %v, want %v", st.PeerInstance, dc.PeerInstance(), want)
			}
			e2eFinish(t, dc, sc)
			e.close()
		})
	}
}
