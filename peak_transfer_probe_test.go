package rendr

import (
	"math"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
)

func TestPeakTransferPassiveObservationNeedsDemandEvidence(t *testing.T) {
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "peak")
	c := &peakTransferController{
		tuning: SelectorTuning{PeakPromoteAfter: time.Nanosecond},
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
	c.evaluatePassive(now.Add(defaultPeakWindow), defaultPeakMinSampleBytes, defaultPeakMinSampleBytes, 10,
		defaultPeakWindow, peak, false)
	observation := c.lastPeakObservation(false)
	if !observation.conclusive || observation.success {
		t.Fatalf("slow passive observation=%+v", observation)
	}
	if c.tx.onPeak || !c.tx.peakTargetSuppressed(peak, now) {
		t.Fatalf("slow peak was not returned/suppressed: %+v", c.tx)
	}
}

func TestPeakTransferSingleLowCapacityWindowDoesNotRejectCandidate(t *testing.T) {
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "peak")
	c := &peakTransferController{
		localTargets: peakTransferTargets{
			selectorID:     proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"),
			normalTargetID: normal, normalTargetIDs: []proto.TargetID{normal},
			peakTargetIDs: []proto.TargetID{peak},
		},
	}
	c.tx = peakTransferDirection{onPeak: true, activePeakTarget: peak, normalPeakBps: 8 << 20}
	transitions := 0
	c.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
		transitions++
		return nil
	}

	const offered = uint64(64 << 10)
	bps := float64(offered*8) / defaultPeakWindow.Seconds()
	now := time.Now()
	c.evaluatePassiveWithPending(now, offered, 0, bps, defaultPeakWindow, peak, false, false)
	if observation := c.lastPeakObservation(false); observation.conclusive {
		t.Fatalf("single low-capacity sample became conclusive: %+v", observation)
	}
	if transitions != 0 || !c.tx.onPeak || c.tx.peakTargetSuppressed(peak, now) {
		t.Fatalf("single low-capacity sample rejected candidate: transitions=%d state=%+v", transitions, c.tx)
	}

	c.evaluatePassiveWithPending(
		now.Add(defaultPeakWindow), offered, offered, bps,
		defaultPeakWindow, peak, true, false,
	)
	if transitions != 0 || !c.tx.onPeak {
		t.Fatalf("first backlogged capacity strike rejected candidate: transitions=%d state=%+v", transitions, c.tx)
	}
	c.evaluatePassiveWithPending(
		now.Add(2*defaultPeakWindow), offered, offered, bps,
		defaultPeakWindow, peak, true, false,
	)
	observation := c.lastPeakObservation(false)
	if transitions != 1 || c.tx.onPeak || !observation.conclusive || observation.success ||
		!c.tx.peakTargetSuppressed(peak, now.Add(2*defaultPeakWindow)) {
		t.Fatalf("backlogged low-capacity sample was not rejected: transitions=%d observation=%+v state=%+v",
			transitions, observation, c.tx)
	}
}

func TestPeakTransferLongLowCapacityWindowRejectsCandidate(t *testing.T) {
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "peak")
	c := &peakTransferController{
		localTargets: peakTransferTargets{
			selectorID:     proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"),
			normalTargetID: normal, normalTargetIDs: []proto.TargetID{normal},
			peakTargetIDs: []proto.TargetID{peak},
		},
	}
	c.tx = peakTransferDirection{onPeak: true, activePeakTarget: peak, normalPeakBps: 8 << 20}
	transitions := 0
	c.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
		transitions++
		return nil
	}

	const delivered = uint64(256 << 10)
	duration := defaultPeakSaturationFor
	bps := float64(delivered*8) / duration.Seconds()
	now := time.Now()
	c.evaluatePassiveWithPending(now, delivered, delivered, bps, duration, peak, true, false)
	observation := c.lastPeakObservation(false)
	if transitions != 1 || c.tx.onPeak || !observation.conclusive || observation.success ||
		!c.tx.peakTargetSuppressed(peak, now) {
		t.Fatalf("long low-capacity window was not rejected: transitions=%d observation=%+v state=%+v",
			transitions, observation, c.tx)
	}
}

func TestPeakCapacitySampleVerdictRejectsInvalidEvidence(t *testing.T) {
	tests := []struct {
		name      string
		bytes     uint64
		demand    uint64
		bps       float64
		duration  time.Duration
		normalBps float64
		pending   bool
		sampled   bool
		success   bool
	}{
		{
			name: "healthy candidate", bytes: 256 << 10, demand: 256 << 10,
			bps: 10 << 20, duration: defaultPeakWindow, normalBps: 8 << 20,
			sampled: true, success: true,
		},
		{
			name: "demand backed low window is a strike", bytes: 64 << 10, demand: 256 << 10,
			bps: 2 << 20, duration: defaultPeakWindow, normalBps: 8 << 20,
			sampled: true,
		},
		{
			name: "low offered demand is inconclusive", bytes: 64 << 10, demand: 0,
			bps: 2 << 20, duration: defaultPeakWindow, normalBps: 8 << 20,
		},
		{
			name: "backlog proves saturation despite low offered window", bytes: 64 << 10, demand: 64 << 10,
			bps: 2 << 20, duration: defaultPeakWindow, normalBps: 8 << 20,
			pending: true, sampled: true,
		},
		{
			name: "zero duration", bytes: 256 << 10, demand: 256 << 10,
			bps: 10 << 20, normalBps: 8 << 20,
		},
		{
			name: "nan throughput", bytes: 256 << 10, demand: 256 << 10,
			bps: math.NaN(), duration: defaultPeakWindow, normalBps: 8 << 20,
		},
		{
			name: "infinite baseline", bytes: 256 << 10, demand: 256 << 10,
			bps: 10 << 20, duration: defaultPeakWindow, normalBps: math.Inf(1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sampled, success := peakCapacitySampleVerdict(
				tt.bytes, tt.demand, tt.bps, tt.duration, tt.normalBps, tt.pending,
			)
			if sampled != tt.sampled || success != tt.success {
				t.Fatalf("verdict=(%t,%t), want=(%t,%t)", sampled, success, tt.sampled, tt.success)
			}
		})
	}
}

func TestPeakTransferPendingSlowCandidateDoesNotLookIdleBeforeDemandEvidence(t *testing.T) {
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "peak")
	c := &peakTransferController{
		tuning: SelectorTuning{PeakReturnAfter: time.Nanosecond},
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
	c.evaluatePassiveWithPending(
		now.Add(5*defaultPeakWindow), defaultPeakMinSampleBytes,
		defaultPeakMinSampleBytes, 10, defaultPeakWindow, peak, false, false,
	)
	observation := c.lastPeakObservation(false)
	if transitions != 1 || c.tx.onPeak || !observation.conclusive || observation.success ||
		!c.tx.peakTargetSuppressed(peak, now.Add(5*defaultPeakWindow)) {
		t.Fatalf("demand-backed slow sample did not reject candidate: transitions=%d observation=%+v state=%+v",
			transitions, observation, c.tx)
	}
}

func TestPeakTransferStableUnattributableTXIdleReturnsAfterReplayDrains(t *testing.T) {
	selector := proto.DeriveTargetID(proto.GraphNodeKindSelector, "root")
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "peak")
	eng := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	t.Cleanup(func() { _ = eng.Close() })
	var transitions int
	c := &peakTransferController{
		e:      eng,
		tuning: SelectorTuning{PeakReturnAfter: defaultPeakWindow},
		localTargets: peakTransferTargets{
			selectorID: selector, normalTargetID: normal,
			normalTargetIDs: []proto.TargetID{normal}, peakTargetIDs: []proto.TargetID{peak},
		},
		tx: peakTransferDirection{
			onPeak: true, activePeakTarget: peak, actualTarget: peak,
			actualSelectorGeneration: 7, normalPeakBps: 8 << 20,
		},
		policyApplyForTest: func(_ bool, choice peakTransferChoice, target proto.TargetID, cause string) error {
			if choice != peakTransferNormal || target != normal || cause != "peak-return" {
				t.Fatalf("transition choice/target/cause=%d/%x/%q", choice, target, cause)
			}
			transitions++
			return nil
		},
	}
	snapshot := engine.TargetDeliverySnapshot{
		TargetID: peak, SelectorID: selector, SelectorGeneration: 7,
		EvidenceEpoch: 11, Attributable: false,
	}
	started := time.Unix(100, 0)
	window := defaultPeakMaximumWindow
	c.observeUnattributableTXIdle(started, snapshot, 0)
	c.observeUnattributableTXIdle(started.Add(window-time.Nanosecond), snapshot, 0)
	if transitions != 0 {
		t.Fatalf("transitioned before a complete stable idle window: %d", transitions)
	}
	c.observeUnattributableTXIdle(started.Add(window), snapshot, 0)
	if transitions != 1 {
		t.Fatalf("stable drained replay transitions=%d want=1", transitions)
	}

	c.tx = peakTransferDirection{
		onPeak: true, activePeakTarget: peak, actualTarget: peak,
		actualSelectorGeneration: 7, normalPeakBps: 8 << 20,
	}
	transitions = 0
	c.observeUnattributableTXIdle(started, snapshot, 0)
	c.observeUnattributableTXIdle(started.Add(window), snapshot, 1)
	c.observeUnattributableTXIdle(started.Add(2*window), snapshot, 0)
	if transitions != 0 {
		t.Fatalf("pending payload did not reset idle proof: transitions=%d", transitions)
	}
	snapshot.EvidenceEpoch++
	c.observeUnattributableTXIdle(started.Add(3*window), snapshot, 0)
	if transitions != 0 {
		t.Fatalf("changed evidence epoch reused stale idle proof: transitions=%d", transitions)
	}
}
