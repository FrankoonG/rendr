package carrier

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// TestOnTrunkDone (M3-D22, F44: the passive owner's bookkeeping at the
// trunk's Done without a goroutine that waits for it): a hook registered
// on a running trunk runs once, after TrunkDone closed and not before; one
// registered after the Done runs at once; a later registration replaces
// one that has not run; a bare Conn and a nil hook do nothing.
func TestOnTrunkDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, _ := muxPair(t, nil)
		var first, second, late atomic.Int32
		d.c.OnTrunkDone(func() { first.Add(1) })
		d.c.OnTrunkDone(func() {
			select {
			case <-d.c.TrunkDone():
			default:
				t.Error("the hook ran before TrunkDone closed")
			}
			second.Add(1)
		})
		d.c.OnTrunkDone(nil) // ignored: keeps the second hook
		synctest.Wait()
		if second.Load() != 0 {
			t.Fatal("the hook ran on a running trunk")
		}
		d.c.KillTrunk(CauseLocalClose, "test")
		<-d.c.TrunkDone()
		synctest.Wait()
		if first.Load() != 0 || second.Load() != 1 {
			t.Fatalf("hooks ran first %d, second %d times; want 0 and 1 (a later registration replaces)", first.Load(), second.Load())
		}
		d.c.OnTrunkDone(func() { late.Add(1) })
		synctest.Wait()
		if late.Load() != 1 {
			t.Fatalf("a hook registered after the Done ran %d times, want 1", late.Load())
		}
		var bare Conn
		bare.OnTrunkDone(func() { t.Error("a bare Conn ran the hook") })
		synctest.Wait()
	})
}
