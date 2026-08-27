package engine

import (
	"math"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

// qualityState makes absence and expiry explicit. Numeric fields attached to
// unknown evidence are never scheduling inputs.
type qualityState uint8

const (
	qualityStateUnknown qualityState = iota
	qualityStateFresh
	qualityStateStale
)

// evidenceConfidence is expressed in basis points to keep aggregation and
// comparison deterministic and NaN-free.
type evidenceConfidence uint16

const evidenceConfidenceFull evidenceConfidence = 10_000

type latencyEvidence struct {
	state       qualityState
	latest      time.Duration
	minimum     time.Duration
	ewma        time.Duration
	jitter      time.Duration
	sampleTime  time.Time
	confidence  evidenceConfidence
	sampleCount uint64
}

// stabilityEvidence is a vector over one bounded scheduling window. Progress
// is preferred high only when both candidates have observed progress; absence
// of progress evidence is not equivalent to a measured zero. All other fields
// are adverse event counts and are preferred low.
type stabilityEvidence struct {
	state                qualityState
	progress             uint64
	progressKnown        bool
	failures             uint64
	migrationFailures    uint64
	loss                 uint64
	lossKnown            bool
	reorder              uint64
	unexpectedDuplicates uint64
	sampleTime           time.Time
	confidence           evidenceConfidence
	sampleCount          uint64
}

type speedEstimateSource uint8

const (
	speedSourceUnknown speedEstimateSource = iota
	speedSourceDelivered
	speedSourceProbe
	speedSourceTransport
	speedSourceAggregate
)

// speedEstimate always represents unique application payload bytes per
// second. Retransmissions and expected race copies are wire overhead, not
// goodput.
type speedEstimate struct {
	state          qualityState
	bytesPerSecond uint64
	confidence     evidenceConfidence
	source         speedEstimateSource
	sampleTime     time.Time
	sampleCount    uint64
}

type speedEvidence struct {
	uniqueGoodput speedEstimate
	capacity      speedEstimate
}

// schedulingEvidence is one immutable, sender-direction-specific snapshot for
// a path or aggregate target. It retains no samples or child references.
type schedulingEvidence struct {
	direction     proto.SenderDirection
	live          bool
	probeLiveness qualityState
	latency       latencyEvidence
	stability     stabilityEvidence
	speed         speedEvidence
}

// aggregateChildEvidence describes one immediate child. Input order is
// manifest order. Only selector consumes active; race and bond consume
// eligible children.
type aggregateChildEvidence struct {
	evidence schedulingEvidence
	eligible bool
	active   bool
}

// aggregateSchedulingEvidence projects immediate-child observations into the
// semantics visible to a parent. It uses constant auxiliary space and never
// retains the bounded child slice.
func aggregateSchedulingEvidence(kind proto.GraphNodeKind, direction proto.SenderDirection, children []aggregateChildEvidence) (schedulingEvidence, bool) {
	out := schedulingEvidence{direction: direction}
	if !direction.Valid() {
		return out, false
	}

	switch kind {
	case proto.GraphNodeKindSelector:
		found := false
		for i := range children {
			if !children[i].active {
				continue
			}
			if found || children[i].evidence.direction != direction {
				return out, false
			}
			out = children[i].evidence
			out.direction = direction
			found = true
		}
		return out, true

	case proto.GraphNodeKindRace, proto.GraphNodeKindBond:
		for i := range children {
			if !children[i].eligible {
				continue
			}
			if children[i].evidence.direction != direction {
				return out, false
			}
			out.live = out.live || children[i].evidence.live
		}
		out.probeLiveness = aggregateCompositeProbeLiveness(children)
		if kind == proto.GraphNodeKindRace {
			out.latency = aggregateRaceLatency(children)
			out.stability = aggregateRaceStability(children)
			out.speed.uniqueGoodput = aggregateRaceSpeed(children, false)
			out.speed.capacity = aggregateRaceSpeed(children, true)
		} else {
			out.latency = aggregateBondLatency(children)
			out.stability = aggregateBondStability(children)
			out.speed.uniqueGoodput = aggregateBondSpeed(children, false)
			out.speed.capacity = aggregateBondSpeed(children, true)
		}
		return out, true
	default:
		return out, false
	}
}

// A composite remains externally live while any eligible descendant has a
// fresh same-carrier probe. One stale bond/race leaf is degradation evidence,
// not proof that the parent target is blackholed.
func aggregateCompositeProbeLiveness(children []aggregateChildEvidence) qualityState {
	hasStale := false
	for i := range children {
		child := children[i]
		if !child.eligible || !child.evidence.live {
			continue
		}
		switch child.evidence.probeLiveness {
		case qualityStateFresh:
			return qualityStateFresh
		case qualityStateStale:
			hasStale = true
		}
	}
	if hasStale {
		return qualityStateStale
	}
	return qualityStateUnknown
}

type aggregateMeta struct {
	set         bool
	confidence  evidenceConfidence
	sampleTime  time.Time
	sampleCount uint64
}

func (m *aggregateMeta) include(confidence evidenceConfidence, sampleTime time.Time, sampleCount uint64) {
	if !m.set {
		m.set = true
		m.confidence = confidence
		m.sampleTime = sampleTime
		m.sampleCount = sampleCount
		return
	}
	if confidence < m.confidence {
		m.confidence = confidence
	}
	if sampleTime.Before(m.sampleTime) {
		m.sampleTime = sampleTime
	}
	if sampleCount < m.sampleCount {
		m.sampleCount = sampleCount
	}
}

func aggregateRaceLatency(children []aggregateChildEvidence) latencyEvidence {
	// First-arrival latency requires an observed winning delivery. Child RTTs
	// and cumulative ACKs do not identify that event.
	return latencyEvidence{}
}

func aggregateBondLatency(children []aggregateChildEvidence) latencyEvidence {
	var out latencyEvidence
	var meta aggregateMeta
	state := qualityStateFresh
	set := false
	for i := range children {
		child := children[i]
		if !child.eligible || !child.evidence.live {
			continue
		}
		value := child.evidence.latency
		if !value.observed() {
			return latencyEvidence{}
		}
		if value.state == qualityStateStale {
			state = qualityStateStale
		}
		if !set {
			out.latest = value.latest
			out.minimum = value.minimum
			out.ewma = value.ewma
			out.jitter = value.jitter
			set = true
		} else {
			out.latest = maxDuration(out.latest, value.latest)
			out.minimum = maxDuration(out.minimum, value.minimum)
			out.ewma = maxDuration(out.ewma, value.ewma)
			out.jitter = maxDuration(out.jitter, value.jitter)
		}
		meta.include(value.confidence, value.sampleTime, value.sampleCount)
	}
	if !set {
		return latencyEvidence{}
	}
	out.state = state
	out.confidence = meta.confidence
	out.sampleTime = meta.sampleTime
	out.sampleCount = meta.sampleCount
	return out
}

func aggregateRaceStability(children []aggregateChildEvidence) stabilityEvidence {
	// Joint race failure requires a closed logical outcome cohort. Marginal
	// child loss and successful cumulative ACKs cannot establish that cohort.
	return stabilityEvidence{}
}

func aggregateBondStability(children []aggregateChildEvidence) stabilityEvidence {
	var out stabilityEvidence
	var meta aggregateMeta
	state := qualityStateFresh
	set := false
	progressKnown := true
	lossKnown := true
	for i := range children {
		child := children[i]
		if !child.eligible {
			continue
		}
		value := child.evidence.stability
		if !value.observed() {
			return stabilityEvidence{}
		}
		lossKnown = lossKnown && value.lossKnown
		if value.state == qualityStateStale {
			state = qualityStateStale
		}
		if value.progressKnown {
			out.progress = saturatingAddUint64(out.progress, value.progress)
		} else {
			progressKnown = false
		}
		out.failures = saturatingAddUint64(out.failures, value.failures)
		out.migrationFailures = saturatingAddUint64(out.migrationFailures, value.migrationFailures)
		out.loss = saturatingAddUint64(out.loss, value.loss)
		out.reorder = saturatingAddUint64(out.reorder, value.reorder)
		out.unexpectedDuplicates = saturatingAddUint64(out.unexpectedDuplicates, value.unexpectedDuplicates)
		meta.include(value.confidence, value.sampleTime, value.sampleCount)
		set = true
	}
	if !set {
		return stabilityEvidence{}
	}
	out.state = state
	out.progressKnown = progressKnown
	out.lossKnown = lossKnown
	out.confidence = meta.confidence
	out.sampleTime = meta.sampleTime
	out.sampleCount = meta.sampleCount
	return out
}

func aggregateRaceSpeed(children []aggregateChildEvidence, capacity bool) speedEstimate {
	state := raceSpeedState(children, capacity)
	if state == qualityStateUnknown {
		return speedEstimate{}
	}

	var out speedEstimate
	var meta aggregateMeta
	set := false
	for i := range children {
		child := children[i]
		if !child.eligible || !child.evidence.live {
			continue
		}
		value := child.evidence.speed.uniqueGoodput
		if capacity {
			value = child.evidence.speed.capacity
		}
		if value.state != state || !value.observed() {
			continue
		}
		out.bytesPerSecond = maxUint64(out.bytesPerSecond, value.bytesPerSecond)
		meta.include(value.confidence, value.sampleTime, value.sampleCount)
		set = true
	}
	if !set {
		return speedEstimate{}
	}
	out.state = state
	out.confidence = meta.confidence
	out.source = speedSourceAggregate
	out.sampleTime = meta.sampleTime
	out.sampleCount = meta.sampleCount
	return out
}

func raceSpeedState(children []aggregateChildEvidence, capacity bool) qualityState {
	hasStale := false
	for i := range children {
		child := children[i]
		if !child.eligible || !child.evidence.live {
			continue
		}
		value := child.evidence.speed.uniqueGoodput
		if capacity {
			value = child.evidence.speed.capacity
		}
		if !value.observed() {
			continue
		}
		if value.state == qualityStateFresh {
			return qualityStateFresh
		}
		hasStale = true
	}
	if hasStale {
		return qualityStateStale
	}
	return qualityStateUnknown
}

func aggregateBondSpeed(children []aggregateChildEvidence, capacity bool) speedEstimate {
	var out speedEstimate
	var meta aggregateMeta
	state := qualityStateFresh
	set := false
	for i := range children {
		child := children[i]
		if !child.eligible || !child.evidence.live {
			continue
		}
		value := child.evidence.speed.uniqueGoodput
		if capacity {
			value = child.evidence.speed.capacity
		}
		if !value.observed() {
			return speedEstimate{}
		}
		if value.state == qualityStateStale {
			state = qualityStateStale
		}
		out.bytesPerSecond = saturatingAddUint64(out.bytesPerSecond, value.bytesPerSecond)
		meta.include(value.confidence, value.sampleTime, value.sampleCount)
		set = true
	}
	if !set {
		return speedEstimate{}
	}
	out.state = state
	out.confidence = meta.confidence
	out.source = speedSourceAggregate
	out.sampleTime = meta.sampleTime
	out.sampleCount = meta.sampleCount
	return out
}

func (l latencyEvidence) observed() bool {
	return observedMeta(l.state, l.sampleTime, l.confidence, l.sampleCount) &&
		l.latest > 0 && l.minimum > 0 && l.ewma > 0 && l.jitter >= 0 &&
		l.minimum <= l.latest && l.minimum <= l.ewma
}

func (l latencyEvidence) fresh(minimumConfidence evidenceConfidence) bool {
	return l.state == qualityStateFresh && l.observed() && l.confidence >= normalizedMinimumConfidence(minimumConfidence)
}

func (s stabilityEvidence) observed() bool {
	return observedMeta(s.state, s.sampleTime, s.confidence, s.sampleCount)
}

func (s stabilityEvidence) fresh(minimumConfidence evidenceConfidence) bool {
	return s.state == qualityStateFresh && s.observed() && s.confidence >= normalizedMinimumConfidence(minimumConfidence)
}

func (s speedEstimate) observed() bool {
	return observedMeta(s.state, s.sampleTime, s.confidence, s.sampleCount) && s.source != speedSourceUnknown
}

func (s speedEstimate) fresh(minimumConfidence evidenceConfidence) bool {
	return s.state == qualityStateFresh && s.observed() && s.confidence >= normalizedMinimumConfidence(minimumConfidence)
}

func observedMeta(state qualityState, sampleTime time.Time, confidence evidenceConfidence, sampleCount uint64) bool {
	return (state == qualityStateFresh || state == qualityStateStale) &&
		!sampleTime.IsZero() && confidence > 0 && confidence <= evidenceConfidenceFull && sampleCount > 0
}

func normalizedMinimumConfidence(confidence evidenceConfidence) evidenceConfidence {
	if confidence == 0 {
		return 1
	}
	return confidence
}

type selectorEvidencePolicy struct {
	latencyBandRatio  float64
	latencyBandFloor  time.Duration
	minimumConfidence evidenceConfidence
}

type selectorCandidate struct {
	targetID      proto.TargetID
	evidence      schedulingEvidence
	manifestOrder uint16
	current       bool
}

type selectorComparisonContext struct {
	direction         proto.SenderDirection
	bestLatency       time.Duration
	latencyLimit      time.Duration
	minimumConfidence evidenceConfidence
	hasFreshLatency   bool
}

// newSelectorComparisonContext establishes the latency-feasible set from all
// live candidates before any pairwise comparison. EWMA is the scheduling key;
// latest, minimum, and jitter remain explicit telemetry and aggregate fields.
func newSelectorComparisonContext(direction proto.SenderDirection, candidates []selectorCandidate, policy selectorEvidencePolicy) selectorComparisonContext {
	ctx := selectorComparisonContext{
		direction:         direction,
		minimumConfidence: normalizedMinimumConfidence(policy.minimumConfidence),
	}
	if !direction.Valid() {
		return ctx
	}
	for i := range candidates {
		candidate := candidates[i]
		if !selectorCandidateLive(ctx, candidate) || !candidate.evidence.latency.fresh(ctx.minimumConfidence) {
			continue
		}
		latency := candidate.evidence.latency.ewma
		if !ctx.hasFreshLatency || latency < ctx.bestLatency {
			ctx.bestLatency = latency
			ctx.hasFreshLatency = true
		}
	}
	if ctx.hasFreshLatency {
		ctx.latencyLimit = selectorLatencyLimit(ctx.bestLatency, policy.latencyBandFloor, policy.latencyBandRatio)
	}
	return ctx
}

// compareSelectorCandidates is a pure total ordering. Negative prefers left,
// positive prefers right, and zero means the graph supplied indistinguishable
// manifest positions. Missing lower-priority evidence cannot evict a live
// current candidate with fresh latency evidence.
func compareSelectorCandidates(ctx selectorComparisonContext, left, right selectorCandidate) int {
	leftLive := selectorCandidateLive(ctx, left)
	rightLive := selectorCandidateLive(ctx, right)
	if leftLive != rightLive {
		if leftLive {
			return -1
		}
		return 1
	}
	if !leftLive {
		return compareManifestOrder(left, right)
	}

	leftLatency := left.evidence.latency.fresh(ctx.minimumConfidence)
	rightLatency := right.evidence.latency.fresh(ctx.minimumConfidence)
	if leftLatency != rightLatency {
		if leftLatency {
			return -1
		}
		return 1
	}
	if !leftLatency {
		return compareIncomparable(ctx, left, right, false, false)
	}

	leftFeasible := !ctx.hasFreshLatency || left.evidence.latency.ewma <= ctx.latencyLimit
	rightFeasible := !ctx.hasFreshLatency || right.evidence.latency.ewma <= ctx.latencyLimit
	if leftFeasible != rightFeasible {
		if leftFeasible {
			return -1
		}
		return 1
	}
	if !leftFeasible {
		if left.evidence.latency.ewma != right.evidence.latency.ewma {
			if left.evidence.latency.ewma < right.evidence.latency.ewma {
				return -1
			}
			return 1
		}
		return compareManifestOrder(left, right)
	}

	leftStability := left.evidence.stability.fresh(ctx.minimumConfidence)
	rightStability := right.evidence.stability.fresh(ctx.minimumConfidence)
	if leftStability != rightStability {
		return compareIncomparable(ctx, left, right, leftStability, rightStability)
	}
	if !leftStability {
		return compareIncomparable(ctx, left, right, false, false)
	}
	if comparison := compareStabilityVector(left.evidence.stability, right.evidence.stability); comparison != 0 {
		return comparison
	}
	if left.evidence.latency.jitter != right.evidence.latency.jitter {
		if left.evidence.latency.jitter < right.evidence.latency.jitter {
			return -1
		}
		return 1
	}

	leftGoodput := left.evidence.speed.uniqueGoodput.fresh(ctx.minimumConfidence)
	rightGoodput := right.evidence.speed.uniqueGoodput.fresh(ctx.minimumConfidence)
	if leftGoodput != rightGoodput {
		return compareIncomparable(ctx, left, right, leftGoodput, rightGoodput)
	}
	if leftGoodput {
		if left.evidence.speed.uniqueGoodput.bytesPerSecond != right.evidence.speed.uniqueGoodput.bytesPerSecond {
			if left.evidence.speed.uniqueGoodput.bytesPerSecond > right.evidence.speed.uniqueGoodput.bytesPerSecond {
				return -1
			}
			return 1
		}
	}

	leftCapacity := left.evidence.speed.capacity.fresh(ctx.minimumConfidence)
	rightCapacity := right.evidence.speed.capacity.fresh(ctx.minimumConfidence)
	if leftCapacity != rightCapacity {
		return compareIncomparable(ctx, left, right, leftCapacity, rightCapacity)
	}
	if leftCapacity {
		if left.evidence.speed.capacity.bytesPerSecond != right.evidence.speed.capacity.bytesPerSecond {
			if left.evidence.speed.capacity.bytesPerSecond > right.evidence.speed.capacity.bytesPerSecond {
				return -1
			}
			return 1
		}
	}
	if !leftGoodput && !leftCapacity {
		return compareIncomparable(ctx, left, right, false, false)
	}
	return compareManifestOrder(left, right)
}

// selectSelectorCandidate applies the comparator without sorting or
// allocation. candidates may be in any iteration order because manifestOrder
// is the final deterministic key.
func selectSelectorCandidate(direction proto.SenderDirection, candidates []selectorCandidate, policy selectorEvidencePolicy) (selectorCandidate, bool) {
	ctx := newSelectorComparisonContext(direction, candidates, policy)
	var selected selectorCandidate
	found := false
	for i := range candidates {
		candidate := candidates[i]
		if !selectorCandidateLive(ctx, candidate) {
			continue
		}
		if !found || compareSelectorCandidates(ctx, candidate, selected) < 0 {
			selected = candidate
			found = true
		}
	}
	return selected, found
}

func selectorCandidateLive(ctx selectorComparisonContext, candidate selectorCandidate) bool {
	return ctx.direction.Valid() && candidate.evidence.direction == ctx.direction && candidate.evidence.live
}

func compareIncomparable(ctx selectorComparisonContext, left, right selectorCandidate, leftUsable, rightUsable bool) int {
	leftCurrent := protectedCurrent(ctx, left)
	rightCurrent := protectedCurrent(ctx, right)
	if leftCurrent != rightCurrent {
		if leftCurrent {
			return -1
		}
		return 1
	}
	if leftUsable != rightUsable {
		if leftUsable {
			return -1
		}
		return 1
	}
	return compareManifestOrder(left, right)
}

func protectedCurrent(ctx selectorComparisonContext, candidate selectorCandidate) bool {
	return candidate.current && selectorCandidateLive(ctx, candidate) && candidate.evidence.latency.fresh(ctx.minimumConfidence)
}

func compareStabilityVector(left, right stabilityEvidence) int {
	if left.failures != right.failures {
		if left.failures < right.failures {
			return -1
		}
		return 1
	}
	if left.migrationFailures != right.migrationFailures {
		if left.migrationFailures < right.migrationFailures {
			return -1
		}
		return 1
	}
	if left.loss != right.loss {
		if left.loss < right.loss {
			return -1
		}
		return 1
	}
	if left.reorder != right.reorder {
		if left.reorder < right.reorder {
			return -1
		}
		return 1
	}
	if left.unexpectedDuplicates != right.unexpectedDuplicates {
		if left.unexpectedDuplicates < right.unexpectedDuplicates {
			return -1
		}
		return 1
	}
	return 0
}

func compareManifestOrder(left, right selectorCandidate) int {
	if left.manifestOrder < right.manifestOrder {
		return -1
	}
	if left.manifestOrder > right.manifestOrder {
		return 1
	}
	return 0
}

func selectorLatencyLimit(best, floor time.Duration, ratio float64) time.Duration {
	if floor < 0 {
		floor = 0
	}
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 {
		ratio = 0
	}
	const maximumDuration = time.Duration(1<<63 - 1)
	ratioFloat := float64(best) * ratio
	ratioBand := time.Duration(0)
	if ratioFloat >= float64(maximumDuration) {
		ratioBand = maximumDuration
	} else if ratioFloat > 0 {
		ratioBand = time.Duration(ratioFloat)
	}
	band := maxDuration(floor, ratioBand)
	if band > maximumDuration-best {
		return maximumDuration
	}
	return best + band
}

func saturatingAddUint64(left, right uint64) uint64 {
	const maximum = ^uint64(0)
	if right > maximum-left {
		return maximum
	}
	return left + right
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}

func minUint64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

func maxUint64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}
