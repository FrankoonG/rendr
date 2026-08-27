package engine

import (
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func TestSchedulingEvidenceSelectorPriorityConflicts(t *testing.T) {
	direction := proto.SenderDirectionClientToServer
	policy := selectorEvidencePolicy{
		latencyBandRatio:  0.25,
		latencyBandFloor:  2 * time.Millisecond,
		minimumConfidence: 5_000,
	}

	tests := []struct {
		name  string
		left  selectorCandidate
		right selectorCandidate
		want  string
	}{
		{
			name:  "latency outside band beats stability and speed",
			left:  metricsTestCandidate("low-latency", 0, 100*time.Millisecond, 8, 10),
			right: metricsTestCandidate("stable-fast", 1, 140*time.Millisecond, 0, 10_000),
			want:  "low-latency",
		},
		{
			name:  "stability wins inside latency band",
			left:  metricsTestCandidate("lower-latency", 0, 100*time.Millisecond, 7, 10_000),
			right: metricsTestCandidate("stable", 1, 120*time.Millisecond, 0, 10),
			want:  "stable",
		},
		{
			name:  "stability precedes speed",
			left:  metricsTestCandidate("stable", 0, 100*time.Millisecond, 0, 10),
			right: metricsTestCandidate("fast", 1, 100*time.Millisecond, 1, 10_000),
			want:  "stable",
		},
		{
			name:  "unique goodput breaks stability tie",
			left:  metricsTestCandidate("slow", 0, 100*time.Millisecond, 0, 10),
			right: metricsTestCandidate("fast", 1, 100*time.Millisecond, 0, 20),
			want:  "fast",
		},
		{
			name: "capacity breaks unique goodput tie",
			left: func() selectorCandidate {
				candidate := metricsTestCandidate("lower-capacity", 0, 100*time.Millisecond, 0, 20)
				candidate.evidence.speed.capacity.bytesPerSecond = 100
				return candidate
			}(),
			right: func() selectorCandidate {
				candidate := metricsTestCandidate("higher-capacity", 1, 100*time.Millisecond, 0, 20)
				candidate.evidence.speed.capacity.bytesPerSecond = 200
				return candidate
			}(),
			want: "higher-capacity",
		},
		{
			name:  "manifest order is final tie break",
			left:  metricsTestCandidate("later", 1, 100*time.Millisecond, 0, 20),
			right: metricsTestCandidate("earlier", 0, 100*time.Millisecond, 0, 20),
			want:  "earlier",
		},
		{
			name:  "absolute floor governs near-zero latency",
			left:  metricsTestCandidate("near-zero", 0, time.Millisecond, 5, 1_000),
			right: metricsTestCandidate("floor-feasible-stable", 1, 2500*time.Microsecond, 0, 10),
			want:  "floor-feasible-stable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected, ok := selectSelectorCandidate(direction, []selectorCandidate{test.left, test.right}, policy)
			if !ok {
				t.Fatal("selector found no live candidate")
			}
			if got := metricsTestTargetName(selected.targetID); got != test.want {
				t.Fatalf("selected %q, want %q", got, test.want)
			}
		})
	}
}

func TestSchedulingEvidenceSelectorUnknownStaleAndCurrent(t *testing.T) {
	direction := proto.SenderDirectionClientToServer
	policy := selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond}

	freshCurrent := metricsTestCandidate("current", 1, 10*time.Millisecond, 0, 100)
	freshCurrent.current = true
	earlier := metricsTestCandidate("challenger", 0, 9*time.Millisecond, 0, 200)

	tests := []struct {
		name       string
		current    selectorCandidate
		challenger selectorCandidate
		want       string
	}{
		{
			name:    "unknown latency is not zero",
			current: freshCurrent,
			challenger: func() selectorCandidate {
				candidate := earlier
				candidate.evidence.latency = latencyEvidence{state: qualityStateUnknown}
				return candidate
			}(),
			want: "current",
		},
		{
			name:    "stale low latency cannot evict fresh current",
			current: freshCurrent,
			challenger: func() selectorCandidate {
				candidate := earlier
				candidate.evidence.latency.state = qualityStateStale
				candidate.evidence.latency.ewma = time.Nanosecond
				candidate.evidence.latency.latest = time.Nanosecond
				candidate.evidence.latency.minimum = time.Nanosecond
				return candidate
			}(),
			want: "current",
		},
		{
			name:    "low-confidence latency is not fresh",
			current: freshCurrent,
			challenger: func() selectorCandidate {
				candidate := earlier
				candidate.evidence.latency.confidence = 0
				return candidate
			}(),
			want: "current",
		},
		{
			name:    "zero-sample latency is not fresh",
			current: freshCurrent,
			challenger: func() selectorCandidate {
				candidate := earlier
				candidate.evidence.latency.sampleCount = 0
				return candidate
			}(),
			want: "current",
		},
		{
			name:    "missing stability cannot skip to speed",
			current: freshCurrent,
			challenger: func() selectorCandidate {
				candidate := earlier
				candidate.evidence.stability = stabilityEvidence{state: qualityStateUnknown}
				return candidate
			}(),
			want: "current",
		},
		{
			name:    "missing speed cannot evict comparable current",
			current: freshCurrent,
			challenger: func() selectorCandidate {
				candidate := earlier
				candidate.evidence.speed = speedEvidence{}
				return candidate
			}(),
			want: "current",
		},
		{
			name: "comparable stability can evict current",
			current: func() selectorCandidate {
				candidate := freshCurrent
				candidate.evidence.stability.failures = 1
				return candidate
			}(),
			challenger: earlier,
			want:       "challenger",
		},
		{
			name: "fresh challenger can replace stale current",
			current: func() selectorCandidate {
				candidate := freshCurrent
				candidate.evidence.latency.state = qualityStateStale
				return candidate
			}(),
			challenger: earlier,
			want:       "challenger",
		},
		{
			name: "dead current has no protection",
			current: func() selectorCandidate {
				candidate := freshCurrent
				candidate.evidence.live = false
				return candidate
			}(),
			challenger: func() selectorCandidate {
				candidate := earlier
				candidate.evidence.latency = latencyEvidence{state: qualityStateUnknown}
				return candidate
			}(),
			want: "challenger",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected, ok := selectSelectorCandidate(direction, []selectorCandidate{test.current, test.challenger}, policy)
			if !ok {
				t.Fatal("selector found no live candidate")
			}
			if got := metricsTestTargetName(selected.targetID); got != test.want {
				t.Fatalf("selected %q, want %q", got, test.want)
			}
		})
	}

	t.Run("all unknown uses manifest order without numeric comparison", func(t *testing.T) {
		later := metricsTestCandidate("unknown-later", 1, 10*time.Millisecond, 0, 1)
		earlier := metricsTestCandidate("unknown-earlier", 0, 10*time.Millisecond, 0, 1)
		later.evidence.latency = latencyEvidence{state: qualityStateUnknown}
		earlier.evidence.latency = latencyEvidence{state: qualityStateUnknown}
		selected, ok := selectSelectorCandidate(direction, []selectorCandidate{later, earlier}, policy)
		if !ok || metricsTestTargetName(selected.targetID) != "unknown-earlier" {
			t.Fatalf("selected=%q ok=%v", metricsTestTargetName(selected.targetID), ok)
		}
	})
}

func TestSchedulingEvidenceAggregatesByNodeKind(t *testing.T) {
	direction := proto.SenderDirectionClientToServer
	first := metricsTestAggregateEvidence(direction, 10, 5, 8, 2, 100, 2, 1, 5, 3, 1, 100, 150, 9_000, 100, 0)
	second := metricsTestAggregateEvidence(direction, 20, 7, 16, 4, 200, 1, 2, 2, 4, 2, 80, 200, 8_000, 80, time.Second)
	children := []aggregateChildEvidence{
		{evidence: first, eligible: true},
		{evidence: second, eligible: true, active: true},
	}

	tests := []struct {
		name string
		kind proto.GraphNodeKind
		want schedulingEvidence
	}{
		{
			name: "selector exposes active child",
			kind: proto.GraphNodeKindSelector,
			want: second,
		},
		{
			name: "race leaves outcome quality unknown without direct samples",
			kind: proto.GraphNodeKindRace,
			want: schedulingEvidence{
				direction: direction,
				live:      true,
				speed: speedEvidence{
					uniqueGoodput: metricsTestSpeed(qualityStateFresh, 100, 8_000, 80, 0, speedSourceAggregate),
					capacity:      metricsTestSpeed(qualityStateFresh, 200, 8_000, 80, 0, speedSourceAggregate),
				},
			},
		},
		{
			name: "bond exposes completion and aggregate unique speed",
			kind: proto.GraphNodeKindBond,
			want: schedulingEvidence{
				direction: direction,
				live:      true,
				latency:   metricsTestLatency(qualityStateFresh, 20, 7, 16, 4, 8_000, 80, 0),
				stability: metricsTestStability(qualityStateFresh, 300, 3, 3, 7, 7, 3, 8_000, 80, 0),
				speed: speedEvidence{
					uniqueGoodput: metricsTestSpeed(qualityStateFresh, 180, 8_000, 80, 0, speedSourceAggregate),
					capacity:      metricsTestSpeed(qualityStateFresh, 350, 8_000, 80, 0, speedSourceAggregate),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := aggregateSchedulingEvidence(test.kind, direction, children)
			if !ok {
				t.Fatal("aggregate rejected valid children")
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("aggregate mismatch:\n got=%+v\nwant=%+v", got, test.want)
			}
		})
	}
}

func TestSchedulingEvidenceRaceDoesNotManufactureCrossChildSample(t *testing.T) {
	direction := proto.SenderDirectionClientToServer
	fast := metricsTestAggregateEvidence(direction, 12, 4, 8, 9, 10, 7, 5, 8, 6, 11, 50, 80, 9_000, 100, 0)
	stable := metricsTestAggregateEvidence(direction, 20, 2, 15, 1, 1_000_000, 0, 0, 0, 0, 0, 60, 90, 9_000, 100, 0)

	got, ok := aggregateSchedulingEvidence(proto.GraphNodeKindRace, direction, []aggregateChildEvidence{
		{evidence: fast, eligible: true},
		{evidence: stable, eligible: true},
	})
	if !ok {
		t.Fatal("race rejected valid children")
	}
	if got.latency.state != qualityStateUnknown || got.stability.state != qualityStateUnknown {
		t.Fatalf("race inferred target quality from children: latency=%+v stability=%+v", got.latency, got.stability)
	}
}

func TestSchedulingEvidenceLifetimeProgressDoesNotRankPaths(t *testing.T) {
	direction := proto.SenderDirectionClientToServer
	earlier := metricsTestCandidate("progress-earlier", 0, 10*time.Millisecond, 0, 100)
	later := metricsTestCandidate("progress-later", 1, 10*time.Millisecond, 0, 100)
	earlier.evidence.stability.progress = 1
	later.evidence.stability.progress = 1_000_000

	selected, ok := selectSelectorCandidate(direction, []selectorCandidate{later, earlier}, selectorEvidencePolicy{
		latencyBandRatio: 0.25,
		latencyBandFloor: time.Millisecond,
	})
	if !ok || selected.targetID != earlier.targetID {
		t.Fatalf("selected=%x ok=%v, want earlier target %x; lifetime progress must not outrank manifest order", selected.targetID, ok, earlier.targetID)
	}
}

func TestSchedulingEvidenceAggregateFreshness(t *testing.T) {
	direction := proto.SenderDirectionClientToServer
	fresh := metricsTestAggregateEvidence(direction, 10, 5, 8, 2, 100, 0, 0, 0, 0, 0, 100, 150, 9_000, 100, 0)
	stale := metricsTestAggregateEvidence(direction, 20, 7, 16, 4, 200, 1, 1, 1, 1, 1, 80, 200, 8_000, 80, time.Second)
	stale.latency.state = qualityStateStale
	stale.stability.state = qualityStateStale
	stale.speed.uniqueGoodput.state = qualityStateStale
	stale.speed.capacity.state = qualityStateStale
	unknown := schedulingEvidence{direction: direction, live: true}

	tests := []struct {
		name           string
		kind           proto.GraphNodeKind
		children       []aggregateChildEvidence
		latencyState   qualityState
		stabilityState qualityState
		goodputState   qualityState
	}{
		{
			name:           "race child freshness cannot create target outcomes",
			kind:           proto.GraphNodeKindRace,
			children:       []aggregateChildEvidence{{evidence: stale, eligible: true}, {evidence: fresh, eligible: true}},
			latencyState:   qualityStateUnknown,
			stabilityState: qualityStateUnknown,
			goodputState:   qualityStateFresh,
		},
		{
			name:           "race stale children still cannot create target outcomes",
			kind:           proto.GraphNodeKindRace,
			children:       []aggregateChildEvidence{{evidence: stale, eligible: true}, {evidence: unknown, eligible: true}},
			latencyState:   qualityStateUnknown,
			stabilityState: qualityStateUnknown,
			goodputState:   qualityStateStale,
		},
		{
			name:           "bond is stale when any contributing evidence is stale",
			kind:           proto.GraphNodeKindBond,
			children:       []aggregateChildEvidence{{evidence: fresh, eligible: true}, {evidence: stale, eligible: true}},
			latencyState:   qualityStateStale,
			stabilityState: qualityStateStale,
			goodputState:   qualityStateStale,
		},
		{
			name:           "bond is unknown when an aggregate component is unknown",
			kind:           proto.GraphNodeKindBond,
			children:       []aggregateChildEvidence{{evidence: fresh, eligible: true}, {evidence: unknown, eligible: true}},
			latencyState:   qualityStateUnknown,
			stabilityState: qualityStateUnknown,
			goodputState:   qualityStateUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := aggregateSchedulingEvidence(test.kind, direction, test.children)
			if !ok {
				t.Fatal("aggregate rejected valid children")
			}
			if got.latency.state != test.latencyState || got.stability.state != test.stabilityState || got.speed.uniqueGoodput.state != test.goodputState {
				t.Fatalf("states latency=%v stability=%v goodput=%v", got.latency.state, got.stability.state, got.speed.uniqueGoodput.state)
			}
		})
	}
}

func TestSchedulingEvidenceAggregationRejectsDirectionMixingAndInvalidShape(t *testing.T) {
	clientToServer := proto.SenderDirectionClientToServer
	serverToClient := proto.SenderDirectionServerToClient
	left := metricsTestAggregateEvidence(clientToServer, 10, 5, 8, 2, 1, 0, 0, 0, 0, 0, 1, 1, 9_000, 10, 0)
	right := metricsTestAggregateEvidence(serverToClient, 10, 5, 8, 2, 1, 0, 0, 0, 0, 0, 1, 1, 9_000, 10, 0)

	if _, ok := aggregateSchedulingEvidence(proto.GraphNodeKindRace, clientToServer, []aggregateChildEvidence{{evidence: left, eligible: true}, {evidence: right, eligible: true}}); ok {
		t.Fatal("race accepted mixed sender directions")
	}
	if _, ok := aggregateSchedulingEvidence(proto.GraphNodeKindSelector, clientToServer, []aggregateChildEvidence{{evidence: left, active: true}, {evidence: left, active: true}}); ok {
		t.Fatal("selector accepted multiple active children")
	}
	if got, ok := aggregateSchedulingEvidence(proto.GraphNodeKindSelector, clientToServer, nil); !ok || got.live || got.latency.state != qualityStateUnknown {
		t.Fatalf("suspended selector aggregate=%+v ok=%v", got, ok)
	}
}

func TestSchedulingEvidenceSelectorComparatorProperties(t *testing.T) {
	direction := proto.SenderDirectionClientToServer
	policy := selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: 2 * time.Millisecond}
	random := rand.New(rand.NewSource(1))
	property := func(latencyA, latencyB, latencyC uint16, failureA, failureB, failureC uint8, speedA, speedB, speedC uint16) bool {
		candidates := []selectorCandidate{
			metricsTestCandidate("property-a", 0, time.Duration(latencyA%200+1)*time.Millisecond, uint64(failureA), uint64(speedA)),
			metricsTestCandidate("property-b", 1, time.Duration(latencyB%200+1)*time.Millisecond, uint64(failureB), uint64(speedB)),
			metricsTestCandidate("property-c", 2, time.Duration(latencyC%200+1)*time.Millisecond, uint64(failureC), uint64(speedC)),
		}
		ctx := newSelectorComparisonContext(direction, candidates, policy)
		for i := range candidates {
			for j := range candidates {
				if metricsTestSign(compareSelectorCandidates(ctx, candidates[i], candidates[j])) != -metricsTestSign(compareSelectorCandidates(ctx, candidates[j], candidates[i])) {
					return false
				}
			}
		}
		for i := range candidates {
			for j := range candidates {
				for k := range candidates {
					if compareSelectorCandidates(ctx, candidates[i], candidates[j]) < 0 && compareSelectorCandidates(ctx, candidates[j], candidates[k]) < 0 && compareSelectorCandidates(ctx, candidates[i], candidates[k]) >= 0 {
						return false
					}
				}
			}
		}
		selected, ok := selectSelectorCandidate(direction, []selectorCandidate{candidates[2], candidates[0], candidates[1]}, policy)
		if !ok {
			return false
		}
		for i := range candidates {
			if compareSelectorCandidates(ctx, candidates[i], selected) < 0 {
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1_000, Rand: random}); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulingEvidenceSpeedAggregationProperties(t *testing.T) {
	direction := proto.SenderDirectionClientToServer
	random := rand.New(rand.NewSource(2))
	property := func(leftRate, rightRate uint64) bool {
		left := metricsTestAggregateEvidence(direction, 10, 5, 8, 2, 1, 0, 0, 0, 0, 0, leftRate, leftRate, 9_000, 10, 0)
		right := metricsTestAggregateEvidence(direction, 10, 5, 8, 2, 1, 0, 0, 0, 0, 0, rightRate, rightRate, 9_000, 10, 0)
		children := []aggregateChildEvidence{{evidence: left, eligible: true}, {evidence: right, eligible: true}}
		race, raceOK := aggregateSchedulingEvidence(proto.GraphNodeKindRace, direction, children)
		bond, bondOK := aggregateSchedulingEvidence(proto.GraphNodeKindBond, direction, children)
		return raceOK && bondOK &&
			race.speed.uniqueGoodput.bytesPerSecond == maxUint64(leftRate, rightRate) &&
			bond.speed.uniqueGoodput.bytesPerSecond == saturatingAddUint64(leftRate, rightRate)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1_000, Rand: random}); err != nil {
		t.Fatal(err)
	}
}

func metricsTestCandidate(name string, order uint16, latency time.Duration, failures, goodput uint64) selectorCandidate {
	evidence := metricsTestAggregateEvidence(proto.SenderDirectionClientToServer,
		uint64(latency/time.Millisecond),
		uint64((latency/2)/time.Millisecond),
		uint64(latency/time.Millisecond),
		1,
		100,
		failures,
		0,
		0,
		0,
		0,
		goodput,
		goodput*2,
		9_000,
		100,
		0,
	)
	// Preserve sub-millisecond durations used by the absolute-floor case.
	evidence.latency.latest = latency
	evidence.latency.ewma = latency
	evidence.latency.minimum = latency / 2
	if evidence.latency.minimum <= 0 {
		evidence.latency.minimum = time.Nanosecond
	}
	return selectorCandidate{
		targetID:      proto.DeriveTargetID(proto.GraphNodeKindPath, name),
		evidence:      evidence,
		manifestOrder: order,
	}
}

func metricsTestAggregateEvidence(
	direction proto.SenderDirection,
	latestMS, minimumMS, ewmaMS, jitterMS uint64,
	progress, failures, migrationFailures, loss, reorder, duplicates uint64,
	goodput, capacity uint64,
	confidence evidenceConfidence,
	samples uint64,
	timeOffset time.Duration,
) schedulingEvidence {
	return schedulingEvidence{
		direction: direction,
		live:      true,
		latency:   metricsTestLatency(qualityStateFresh, latestMS, minimumMS, ewmaMS, jitterMS, confidence, samples, timeOffset),
		stability: metricsTestStability(qualityStateFresh, progress, failures, migrationFailures, loss, reorder, duplicates, confidence, samples, timeOffset),
		speed: speedEvidence{
			uniqueGoodput: metricsTestSpeed(qualityStateFresh, goodput, confidence, samples, timeOffset, speedSourceDelivered),
			capacity:      metricsTestSpeed(qualityStateFresh, capacity, confidence, samples, timeOffset, speedSourceProbe),
		},
	}
}

func metricsTestLatency(state qualityState, latestMS, minimumMS, ewmaMS, jitterMS uint64, confidence evidenceConfidence, samples uint64, timeOffset time.Duration) latencyEvidence {
	return latencyEvidence{
		state:       state,
		latest:      time.Duration(latestMS) * time.Millisecond,
		minimum:     time.Duration(minimumMS) * time.Millisecond,
		ewma:        time.Duration(ewmaMS) * time.Millisecond,
		jitter:      time.Duration(jitterMS) * time.Millisecond,
		sampleTime:  metricsTestSampleTime().Add(timeOffset),
		confidence:  confidence,
		sampleCount: samples,
	}
}

func metricsTestStability(state qualityState, progress, failures, migrationFailures, loss, reorder, duplicates uint64, confidence evidenceConfidence, samples uint64, timeOffset time.Duration) stabilityEvidence {
	return stabilityEvidence{
		state:                state,
		progress:             progress,
		progressKnown:        true,
		failures:             failures,
		migrationFailures:    migrationFailures,
		loss:                 loss,
		reorder:              reorder,
		unexpectedDuplicates: duplicates,
		sampleTime:           metricsTestSampleTime().Add(timeOffset),
		confidence:           confidence,
		sampleCount:          samples,
	}
}

func metricsTestSpeed(state qualityState, bytesPerSecond uint64, confidence evidenceConfidence, samples uint64, timeOffset time.Duration, source speedEstimateSource) speedEstimate {
	return speedEstimate{
		state:          state,
		bytesPerSecond: bytesPerSecond,
		confidence:     confidence,
		source:         source,
		sampleTime:     metricsTestSampleTime().Add(timeOffset),
		sampleCount:    samples,
	}
}

func metricsTestSampleTime() time.Time {
	return time.Unix(1_700_000_000, 0)
}

func metricsTestTargetName(id proto.TargetID) string {
	for _, name := range []string{
		"low-latency", "stable-fast", "lower-latency", "stable", "fast", "slow",
		"lower-capacity", "higher-capacity", "later", "earlier", "near-zero",
		"floor-feasible-stable", "current", "challenger", "unknown-later", "unknown-earlier",
	} {
		if id == proto.DeriveTargetID(proto.GraphNodeKindPath, name) {
			return name
		}
	}
	return ""
}

func metricsTestSign(value int) int {
	if value < 0 {
		return -1
	}
	if value > 0 {
		return 1
	}
	return 0
}
