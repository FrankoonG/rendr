package carrier

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
)

// defaultIdleRelease is batchIdleRelease as the package set it, before any
// test lowered it (setIdleRelease).
var defaultIdleRelease = batchIdleRelease

// TestBatchIdleReleaseShared (M5 work item srcidle; one shared period):
// the dialer reader's idle release takes the shared
// udpsocket.IdleRelease — the passive Source's period too, which
// internal/udpflow's TestBatchIdleReleaseShared pins there — and that is
// 1 s (M5 design R1-5 rule 3), by which the root package's
// TestIdlePacketListenerBufferedBytesZero_plan774 bounds its waits. A
// reader given another default, or a shared value that moved, fails here.
func TestBatchIdleReleaseShared(t *testing.T) {
	if defaultIdleRelease != udpsocket.IdleRelease || udpsocket.IdleRelease != time.Second {
		t.Fatalf("batchIdleRelease %v, udpsocket.IdleRelease %v: the dialer reader takes the shared idle-release period, 1 s (R1-5 rule 3)",
			defaultIdleRelease, udpsocket.IdleRelease)
	}
}
