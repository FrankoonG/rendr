package rendr

import (
	"testing"

	"github.com/FrankoonG/rendr/internal/engine"
)

func TestReplayStatsPublicProjectionIsExact(t *testing.T) {
	internal := engine.ReplayStats{
		FrameLimit: 8192, ByteLimit: 64 << 20,
		FramesInUse: 1024, BytesInUse: 1 << 20,
		FramesHighWater: 2048, BytesHighWater: 2 << 20,
		PublishedNext: 4096, AckNext: 3072,
		CreditWaiters: 3, BackpressureEvents: 7, Generation: 11,
	}
	got := replayStatsFromEngine(internal)
	want := ReplayStats{
		FrameLimit: 8192, ByteLimit: 64 << 20,
		FramesInUse: 1024, BytesInUse: 1 << 20,
		FramesHighWater: 2048, BytesHighWater: 2 << 20,
		PublishedNext: 4096, AckNext: 3072,
		CreditWaiters: 3, BackpressureEvents: 7, Generation: 11,
	}
	if got != want {
		t.Fatalf("public replay projection=%+v want %+v", got, want)
	}
}
