package engine

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestRaceAggregateComplementaryChildMarginalsRemainUnknown(t *testing.T) {
	_, runtime, ids := newRaceAggregateFixture(t)
	base := time.Unix(1_800_000_000, 0)

	for round := 0; round < 4; round++ {
		now := base.Add(time.Duration(round) * time.Second)
		fastID, slowID := ids["a"], ids["b"]
		if round%2 != 0 {
			fastID, slowID = slowID, fastID
		}
		observations := map[proto.TargetID]pathEvidenceObservation{
			fastID: raceAggregatePathObservation(
				fastID, now, time.Millisecond, 500,
			),
			slowID: raceAggregatePathObservation(
				slowID, now, 100*time.Millisecond, 0,
			),
		}

		runtime.mu.Lock()
		evidence := runtime.aggregateTargetEvidenceLocked(
			ids["redundant"], proto.SenderDirectionClientToServer,
			observations, make(map[proto.TargetID]schedulingEvidence), now,
		)
		runtime.mu.Unlock()

		if !evidence.live {
			t.Fatalf("round %d: race with live children is not live", round)
		}
		if evidence.latency.state != qualityStateUnknown ||
			evidence.stability.state != qualityStateUnknown {
			t.Fatalf(
				"round %d: complementary child marginals manufactured race quality: latency=%+v stability=%+v",
				round, evidence.latency, evidence.stability,
			)
		}
	}
}

func TestRaceAggregateAlternatingACKDelaysDoNotCreateQuality(t *testing.T) {
	base := time.Unix(1_800_000_100, 0)
	installEngineNowForTest(t, func() time.Time { return base })
	e, runtime, ids := newRaceAggregateFixture(t)
	epoch := e.currentPathTopologyEpoch()
	delays := []time.Duration{
		time.Millisecond, 100 * time.Millisecond,
		time.Millisecond, 100 * time.Millisecond,
	}

	for seq, delay := range delays {
		frame := reserveRaceAggregateFrame(t, e, uint64(seq), 128)
		e.noteApplicationDispatchPlanAtEpoch(frame, raceAggregateRoutes(ids), epoch)
		proof := raceAggregateFrameProof(t, e, uint64(seq))
		acknowledgedAt := base.Add(time.Duration(seq)*200*time.Millisecond + delay)
		if valid, application := e.acknowledgeSendFramesAt(
			uint64(seq+1), proof, acknowledgedAt,
		); !valid || !application {
			t.Fatalf("ACK %d valid/application=%t/%t", seq+1, valid, application)
		}
	}

	now := base.Add(time.Second)
	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["a"]: raceAggregatePathObservation(
			ids["a"], now, time.Millisecond, 500,
		),
		ids["b"]: raceAggregatePathObservation(
			ids["b"], now, 100*time.Millisecond, 0,
		),
	}
	runtime.mu.Lock()
	evidence := runtime.aggregateTargetEvidenceLocked(
		ids["redundant"], proto.SenderDirectionClientToServer,
		observations, make(map[proto.TargetID]schedulingEvidence), now,
	)
	runtime.mu.Unlock()
	if evidence.latency.state != qualityStateUnknown ||
		evidence.stability.state != qualityStateUnknown {
		t.Fatalf(
			"alternating cumulative-ACK delays manufactured race quality: latency=%+v stability=%+v",
			evidence.latency, evidence.stability,
		)
	}
}

func TestRaceAggregateCumulativeACKKeepsExactEpochUniqueGoodput(t *testing.T) {
	base := time.Unix(1_800_000_200, 0)
	installEngineNowForTest(t, func() time.Time { return base })
	e, runtime, ids := newRaceAggregateFixture(t)
	epoch := e.currentPathTopologyEpoch()
	const frames = 2
	payloadBytes := selectorGoodputMinimumBytes / frames

	for seq := uint64(0); seq < frames; seq++ {
		frame := reserveRaceAggregateFrame(t, e, seq, payloadBytes)
		e.noteApplicationDispatchPlanAtEpoch(frame, raceAggregateRoutes(ids), epoch)
	}
	e.sendHistMu.Lock()
	state := e.sendHist.targetDelivery[ids["redundant"]]
	state.windowStart = base.Add(-time.Second)
	e.sendHist.targetDelivery[ids["redundant"]] = state
	proof := e.sendHistoryEntryLocked(frames - 1).proof
	e.sendHistMu.Unlock()

	if valid, application := e.acknowledgeSendFramesAt(frames, proof, base); !valid || !application {
		t.Fatalf("cumulative ACK valid/application=%t/%t", valid, application)
	}
	if valid, application := e.acknowledgeSendFramesAt(frames, proof, base); !valid || application {
		t.Fatalf("duplicate cumulative ACK valid/application=%t/%t", valid, application)
	}

	speeds, valid := e.targetDeliverySpeedsAtEpoch(base, epoch)
	if !valid {
		t.Fatal("current topology epoch rejected")
	}
	goodput := speeds[ids["redundant"]]
	if !goodput.fresh(1) || goodput.bytesPerSecond == 0 {
		t.Fatalf("race unique goodput=%+v", goodput)
	}
	if _, exists := speeds[ids["a"]]; exists {
		t.Fatal("race physical copy a received unique-goodput credit")
	}
	if _, exists := speeds[ids["b"]]; exists {
		t.Fatal("race physical copy b received unique-goodput credit")
	}
	e.sendHistMu.Lock()
	totalAcked := e.sendHist.targetDelivery[ids["redundant"]].totalAcked
	e.sendHistMu.Unlock()
	if totalAcked != selectorGoodputMinimumBytes {
		t.Fatalf("race totalAcked=%d want %d unique bytes", totalAcked, selectorGoodputMinimumBytes)
	}

	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["a"]: raceAggregatePathObservation(ids["a"], base, time.Millisecond, 0),
		ids["b"]: raceAggregatePathObservation(ids["b"], base, 2*time.Millisecond, 0),
		ids["redundant"]: {
			targetID: ids["redundant"], goodput: goodput, topologyEpoch: epoch,
		},
	}
	runtime.mu.Lock()
	evidence := runtime.aggregateTargetEvidenceLocked(
		ids["redundant"], proto.SenderDirectionClientToServer,
		observations, make(map[proto.TargetID]schedulingEvidence), base,
	)
	runtime.mu.Unlock()
	if evidence.speed.uniqueGoodput != goodput {
		t.Fatalf("race aggregate goodput=%+v want %+v", evidence.speed.uniqueGoodput, goodput)
	}
	if evidence.latency.state != qualityStateUnknown ||
		evidence.stability.state != qualityStateUnknown {
		t.Fatalf(
			"ACK-confirmed goodput leaked into race quality: latency=%+v stability=%+v",
			evidence.latency, evidence.stability,
		)
	}

	e.pathsMu.Lock()
	currentEpoch := e.advancePathTopologyEpochLocked()
	e.pathsMu.Unlock()
	if _, valid := e.targetDeliverySpeedsAtEpoch(base, epoch); valid {
		t.Fatal("prior topology epoch remained valid")
	}
	currentSpeeds, valid := e.targetDeliverySpeedsAtEpoch(base, currentEpoch)
	if !valid {
		t.Fatal("current topology epoch rejected after advance")
	}
	if _, exists := currentSpeeds[ids["redundant"]]; exists {
		t.Fatal("prior-epoch race goodput leaked into current topology")
	}
}

func newRaceAggregateFixture(
	t *testing.T,
) (*Engine, *executionRuntime, map[string]proto.TargetID) {
	t.Helper()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "direct", "redundant"),
		runtimeNode(proto.GraphNodeKindPath, "direct"),
		runtimeNode(proto.GraphNodeKindRace, "redundant", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	return e, e.localExecutionRuntime(), ids
}

func raceAggregateRoutes(ids map[string]proto.TargetID) []dispatchRoute {
	return []dispatchRoute{{targetID: ids["a"]}, {targetID: ids["b"]}}
}

func raceAggregatePathObservation(
	targetID proto.TargetID,
	at time.Time,
	rtt time.Duration,
	loss uint16,
) pathEvidenceObservation {
	return pathEvidenceObservation{
		targetID: targetID, live: true, topologyEpoch: 1,
		quality: transport.PathQuality{RTT: rtt, At: at},
		loss:    loss, lossAt: at, lossKnown: true,
		freshFor: selectorEvidenceFreshFor, probeLiveness: qualityStateFresh,
		dataProgress: 1,
	}
}

func reserveRaceAggregateFrame(
	t *testing.T,
	e *Engine,
	seq uint64,
	payloadBytes int,
) []byte {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+payloadBytes)
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: seq}).Encode(
		frame[:proto.HeaderSize],
	); err != nil {
		t.Fatal(err)
	}
	if err := e.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveOwnedSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	e.publishSendSeq(seq + 1)
	return frame
}

func raceAggregateFrameProof(t *testing.T, e *Engine, seq uint64) proto.AckProof {
	t.Helper()
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	entry := e.sendHistoryEntryLocked(seq)
	if entry == nil {
		t.Fatalf("send-history entry %d disappeared before ACK", seq)
	}
	return entry.proof
}
