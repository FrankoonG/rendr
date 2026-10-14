package carrier

import (
	"testing"
	"time"
)

// defaultIdleRelease is batchIdleRelease as the package set it, before any
// test lowered it (setIdleRelease).
var defaultIdleRelease = batchIdleRelease

// TestBatchIdleReleaseShared (M5 work item srcidle): the dialer reader's
// idle release has the passive Source's period — internal/udpflow's
// batchIdleRelease, which that package's TestBatchIdleReleaseShared pins —
// and the root package's TestIdlePacketListenerBufferedBytesZero_plan774
// bounds its waits by 2 × that period (its idleRelease): all three are
// 1 s (M5 design R1-5 rule 3). A change of one fails here or there until
// the three agree again.
func TestBatchIdleReleaseShared(t *testing.T) {
	if defaultIdleRelease != time.Second {
		t.Fatalf("batchIdleRelease %v: internal/udpflow's batchIdleRelease and the root package's idleRelease are 1 s; change the three together",
			defaultIdleRelease)
	}
}
