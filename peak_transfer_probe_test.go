package rendr

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func TestPeakTransferPassiveObservationNeedsDemandEvidence(t *testing.T) {
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "peak")
	c := &peakTransferController{
		opts: PeakTransfer{SaturationFor: time.Nanosecond},
		localTargets: peakTransferTargets{
			selectorID:     proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"),
			normalTargetID: normal, normalTargetIDs: []proto.TargetID{normal},
			peakTargetIDs: []proto.TargetID{peak},
		},
	}
	transitions := 0
	c.policyApplyForTest = func(_ bool, choice peakTransferChoice, targetID proto.TargetID, _ string) error {
		transitions++
		if choice != peakTransferPeak || targetID != peak {
			t.Fatalf("transition=(%v,%x), want peak %x", choice, targetID, peak)
		}
		return nil
	}
	now := time.Now()
	c.tx.normalBytes = defaultPeakMinBytes
	c.tx.normalPeakBps = 1 << 20
	c.tx.saturatedSince = now.Add(-time.Second)
	c.evaluatePassive(now, 1<<20, 0, 1<<20, defaultPeakWindow, normal, false)
	if transitions != 0 || c.tx.onPeak {
		t.Fatalf("app-limited observation promoted: transitions=%d state=%+v", transitions, c.tx)
	}
	c.tx.saturatedSince = now.Add(-time.Second)
	c.evaluatePassive(now, 1<<20, 1<<20, 1<<20, defaultPeakWindow, normal, false)
	if transitions != 1 || !c.tx.onPeak || c.tx.activePeakTarget != peak {
		t.Fatalf("demand-backed observation did not promote: transitions=%d state=%+v", transitions, c.tx)
	}
}

func TestPeakTransferNoTrafficIsInconclusive(t *testing.T) {
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "peak")
	c := &peakTransferController{}
	c.tx = peakTransferDirection{
		onPeak: true, activePeakTarget: peak, normalPeakBps: 1 << 20,
		peakStarted: time.Now().Add(-time.Second),
	}
	c.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
		t.Fatal("inconclusive observation attempted a policy transition")
		return nil
	}
	c.evaluatePassive(time.Now(), 0, 0, 0, defaultPeakWindow, peak, false)
	if observation := c.lastPeakObservation(false); observation.conclusive {
		t.Fatalf("idle observation became conclusive: %+v", observation)
	}
	if !c.tx.onPeak || c.tx.peakTargetSuppressed(peak, time.Now()) {
		t.Fatalf("idle observation rejected peak: %+v", c.tx)
	}
}

func TestPeakTransferPassiveBadCandidateRevertsAndSuppresses(t *testing.T) {
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "peak")
	c := &peakTransferController{
		localTargets: peakTransferTargets{
			selectorID:     proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"),
			normalTargetID: normal, normalTargetIDs: []proto.TargetID{normal},
			peakTargetIDs: []proto.TargetID{peak},
		},
	}
	c.tx = peakTransferDirection{onPeak: true, activePeakTarget: peak, normalPeakBps: 100}
	c.policyApplyForTest = func(_ bool, choice peakTransferChoice, targetID proto.TargetID, _ string) error {
		if choice != peakTransferNormal || targetID != normal {
			t.Fatalf("transition=(%v,%x), want normal %x", choice, targetID, normal)
		}
		return nil
	}
	now := time.Now()
	c.evaluatePassive(now, defaultPeakMinSampleBytes, defaultPeakMinSampleBytes, 10,
		defaultPeakWindow, peak, false)
	observation := c.lastPeakObservation(false)
	if !observation.conclusive || observation.success {
		t.Fatalf("slow passive observation=%+v", observation)
	}
	if c.tx.onPeak || !c.tx.peakTargetSuppressed(peak, now) {
		t.Fatalf("slow peak was not returned/suppressed: %+v", c.tx)
	}
}

func TestPeakTransferPendingSlowCandidateDoesNotLookIdleBeforeDemandEvidence(t *testing.T) {
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "peak")
	c := &peakTransferController{
		opts: PeakTransfer{ReturnFor: time.Nanosecond},
		localTargets: peakTransferTargets{
			selectorID:     proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"),
			normalTargetID: normal, normalTargetIDs: []proto.TargetID{normal},
			peakTargetIDs: []proto.TargetID{peak},
		},
	}
	c.tx = peakTransferDirection{
		onPeak: true, activePeakTarget: peak, normalPeakBps: 1 << 20,
		peakStarted: time.Now().Add(-time.Second),
	}
	transitions := 0
	c.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
		transitions++
		return nil
	}

	now := time.Now()
	for i := 0; i < 4; i++ {
		c.evaluatePassiveWithPending(
			now.Add(time.Duration(i)*defaultPeakWindow), 0, 0, 0,
			defaultPeakWindow, peak, true, false,
		)
	}
	if transitions != 0 || !c.tx.onPeak || !c.tx.returnSince.IsZero() {
		t.Fatalf("pending ACK-silent windows looked idle: transitions=%d state=%+v", transitions, c.tx)
	}

	c.evaluatePassiveWithPending(
		now.Add(4*defaultPeakWindow), defaultPeakMinSampleBytes,
		defaultPeakMinSampleBytes, 10, defaultPeakWindow, peak, false, false,
	)
	observation := c.lastPeakObservation(false)
	if transitions != 1 || c.tx.onPeak || !observation.conclusive || observation.success ||
		!c.tx.peakTargetSuppressed(peak, now.Add(4*defaultPeakWindow)) {
		t.Fatalf("demand-backed slow sample did not reject candidate: transitions=%d observation=%+v state=%+v",
			transitions, observation, c.tx)
	}
}
