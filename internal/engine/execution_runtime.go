package engine

import (
	"errors"
	"fmt"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

var errExecutionRuntimeNotConfigured = errors.New("engine: execution runtime is not configured")

type dispatchRoute struct {
	targetID                      proto.TargetID
	bonded                        bool
	capacityQualification         bool
	capacityQualificationPressure bool
	capacityQualificationComplete bool
	reservationBranch             int
}

type dispatchTicket struct {
	routes                []dispatchRoute
	kind                  proto.ExecutionKind
	reservation           *dispatchSchedulingReservation
	reservationGeneration uint64
}

const noDispatchReservationBranch = -1

// finalizeScheduling commits scheduler debt only after physical queue custody
// exists. The boolean form is retained for single-route and test callers; the
// recursive dispatcher marks admitted routes individually before finalizing.
func (t *dispatchTicket) finalizeScheduling(admitted bool) {
	if t == nil || t.reservation == nil {
		return
	}
	if admitted {
		for index := range t.routes {
			t.markRouteAdmitted(index)
		}
	}
	t.reservation.finish(t.reservationGeneration, false)
	t.reservation = nil
	t.reservationGeneration = 0
}

func (t *dispatchTicket) markRouteAdmitted(index int) {
	if t == nil || t.reservation == nil || index < 0 || index >= len(t.routes) {
		return
	}
	t.reservation.admitBranch(t.reservationGeneration, t.routes[index].reservationBranch)
}

func (t *dispatchTicket) finalizeSchedulingAdmitted() {
	if t == nil || t.reservation == nil {
		return
	}
	t.reservation.finish(t.reservationGeneration, false)
	t.reservation = nil
	t.reservationGeneration = 0
}

func (t *dispatchTicket) finalizeSchedulingStale() {
	if t == nil || t.reservation == nil {
		return
	}
	t.reservation.finish(t.reservationGeneration, true)
	t.reservation = nil
	t.reservationGeneration = 0
}

type executionRuntime struct {
	plan             *executionPlan
	flatLeafSelector bool
	hasBond          bool
	bondRaceAncestor map[proto.TargetID]bool
	// flatSelectorCache contains only successful physical projections. A nil
	// route is never cached because a custody-only dispatch stall does not
	// advance the factual health epoch when it clears.
	flatSelectorCache [2]atomic.Pointer[flatSelectorDispatchCache]

	mu                     sync.Mutex
	selectors              map[proto.TargetID]*selectorExecutionState
	selectorRevision       uint64
	bonds                  map[proto.TargetID]*bondExecutionState
	bondEvidenceEpoch      uint64
	bondEvidenceRevision   uint64
	bondEvidenceObserved   time.Time
	bondEvidenceDelivered  map[proto.TargetID]speedEstimate
	bondEvidenceAcked      map[proto.TargetID]uint64
	bondEvidenceRebuilds   atomic.Uint64
	bondDispatchProjection *recursiveDispatchProjection
	aggregateScratch       []bondCapacityAggregate
	bondHotOperations      uint64
	bondRefreshOperations  uint64
	stuckSkips             atomic.Uint64
	reservation            dispatchSchedulingReservation
	routeScratch           []dispatchRoute
}

type dispatchSchedulingReservation struct {
	runtime    *executionRuntime
	generation uint64
	active     bool
	authority  *recursiveDispatchProjection
	mutations  []bondSchedulingMutation
}

type selectorExecutionState struct {
	desired               proto.TargetID
	effective             proto.TargetID
	generation            uint64
	peakHeld              bool
	qualityCandidate      proto.TargetID
	qualityCurrent        proto.TargetID
	qualityCandidateSpeed speedEvidence
	qualityCurrentSpeed   speedEvidence
	qualityTopologyEpoch  uint64
	qualitySince          time.Time
	lastQualityMove       time.Time
}

type flatSelectorDispatchCache struct {
	topologyEpoch uint64
	healthEpoch   uint64
	slot          *pathSlot
}

func (s *selectorExecutionState) clearQualityCandidate() {
	if s == nil {
		return
	}
	s.qualityCandidate = proto.TargetID{}
	s.qualityCurrent = proto.TargetID{}
	s.qualityCandidateSpeed = speedEvidence{}
	s.qualityCurrentSpeed = speedEvidence{}
	s.qualityTopologyEpoch = 0
	s.qualitySince = time.Time{}
}

type initialSelectorSelection struct {
	selectorID proto.TargetID
	targetID   proto.TargetID
}

type bondExecutionState struct {
	currentWeight                map[proto.TargetID]int64
	weightVector                 map[proto.TargetID]uint64
	domain                       bondDomainIdentity
	schedule                     []proto.TargetID
	schedulePhase                uint64
	cacheAuthority               *recursiveDispatchProjection
	cacheTopologyEpoch           uint64
	cacheHealthEpoch             uint64
	cacheCapacityRevision        uint64
	cacheSelectorRevision        uint64
	currentChild                 proto.TargetID
	pinLeft                      int
	qualification                map[proto.TargetID]*bondQualificationState
	qualificationCursor          int
	qualificationNormalFrames    int
	qualificationBurstChild      proto.TargetID
	qualificationBurstLeft       uint64
	qualificationMaintenanceWait uint64
	qualificationTokensUsed      uint64
	scratchAggregates            map[proto.TargetID]bondCapacityAggregate
	scratchIdentities            map[proto.TargetID]*bondQualificationIdentity
	scratchUnknown               []proto.TargetID
	scratchWeights               map[proto.TargetID]uint64
	scratchUnknownObservations   map[proto.TargetID]bondQualificationObservation
	scratchExcluded              map[proto.TargetID]bool
	scratchOrderedUnknown        []proto.TargetID
	scratchDomain                bondDomainIdentity
	scratchScheduleWeights       []uint64
	scratchScheduleRemainders    []uint64
	scratchScheduleCurrent       []int64
	scratchPreviousDomain        map[proto.TargetID]bondQualificationIdentity
}

type bondSchedulingMutation struct {
	state                        *bondExecutionState
	parent                       int
	commit                       bool
	currentChild                 proto.TargetID
	pinLeft                      int
	schedulePhase                uint64
	qualificationCursor          int
	qualificationNormalFrames    int
	qualificationBurstChild      proto.TargetID
	qualificationBurstLeft       uint64
	qualificationMaintenanceWait uint64
	qualificationTokensUsed      uint64
	qualificationTouched         bool
	qualificationChild           proto.TargetID
	qualificationValue           bondQualificationState
}

type bondQualificationState struct {
	lastAcknowledged uint64
	credit           uint64
	sentSinceACK     uint64
	totalSent        uint64
	identity         bondQualificationIdentity
}

type bondSelectorIdentity struct {
	selectorID proto.TargetID
	targetID   proto.TargetID
	generation uint64
}

// bondQualificationIdentity describes the exact effective descendant set of
// one immediate bond child. Keeping the selector lineage exact avoids carrying
// ACK progress across a selector cutover merely because the immediate child ID
// did not change.
type bondQualificationIdentity struct {
	leaves    []bondLeafIdentity
	selectors []bondSelectorIdentity
}

type bondLeafIdentity struct {
	targetID        proto.TargetID
	pathID          uint32
	owner           uint64
	generation      uint64
	routeGeneration uint64
}

type bondChildDomainIdentity struct {
	targetID proto.TargetID
	identity bondQualificationIdentity
}

type bondDomainIdentity struct {
	children []bondChildDomainIdentity
}

type bondQualificationObservation struct {
	acknowledged uint64
	identity     bondQualificationIdentity
}

type bondSchedulingContext struct {
	now              time.Time
	topologyEpoch    uint64
	healthEpoch      uint64
	capacityRevision uint64
	authority        *recursiveDispatchProjection
	evidenceSource   *Engine
	evidenceRevision uint64
	staticWeights    map[proto.TargetID]uint64
	effectiveWeights map[proto.TargetID]uint64
	observed         map[proto.TargetID]bool
	acknowledged     map[proto.TargetID]uint64
	leafIdentity     map[proto.TargetID]bondLeafIdentity
	evidenceAware    bool
}

type bondCapacityAggregate struct {
	static    uint64
	effective uint64
	observed  bool
	ambiguous bool
	acked     uint64
	identity  bondQualificationIdentity
}

const (
	maximumBondSchedulerWeight         uint64 = maxSessionPaths * ((1 << 16) - 1)
	bondQualificationMaximumCredit     uint64 = 64
	bondQualificationMaximumTokens     uint64 = 128
	bondQualificationPressureThreshold uint64 = 64
	bondQualificationMaximumBurst      uint64 = 8
	bondQualificationInterleaveFrames         = 1
	bondQualificationMaintenanceFrames uint64 = 64
	// A bounded smooth cycle gives each child 1/4096 share granularity while
	// keeping every cache-hit selection to one deterministic table lookup.
	bondScheduleMaximumSlots = 4096
)

func newExecutionRuntime(plan *executionPlan) *executionRuntime {
	runtime := &executionRuntime{
		plan:             plan,
		flatLeafSelector: isFlatLeafSelectorPlan(plan),
		selectors:        make(map[proto.TargetID]*selectorExecutionState),
		bonds:            make(map[proto.TargetID]*bondExecutionState),
		bondRaceAncestor: make(map[proto.TargetID]bool),
	}
	if plan != nil {
		runtime.aggregateScratch = make([]bondCapacityAggregate, len(plan.nodes)+1)
		runtime.routeScratch = make([]dispatchRoute, 0, len(plan.nodes))
		runtime.reservation.mutations = make([]bondSchedulingMutation, 0, len(plan.nodes))
		for _, targetID := range plan.nodeIDs {
			node, ok := plan.nodeView(targetID)
			if ok && node.kind == proto.GraphNodeKindBond {
				runtime.hasBond = true
				break
			}
		}
		var markRaceAncestors func(proto.TargetID, bool)
		markRaceAncestors = func(targetID proto.TargetID, underRace bool) {
			node, ok := plan.nodeView(targetID)
			if !ok {
				return
			}
			if node.kind == proto.GraphNodeKindBond && underRace {
				runtime.bondRaceAncestor[targetID] = true
			}
			if node.kind == proto.GraphNodeKindRace {
				underRace = true
			}
			for _, childID := range node.children {
				markRaceAncestors(childID, underRace)
			}
		}
		markRaceAncestors(plan.rootID, false)
	}
	return runtime
}

func (r *executionRuntime) beginDispatchSchedulingReservationLocked(
	authority *recursiveDispatchProjection,
) *dispatchSchedulingReservation {
	reservation := &r.reservation
	if reservation.active {
		panic("engine: overlapping dispatch scheduling reservation")
	}
	if reservation.generation == ^uint64(0) {
		panic("engine: dispatch scheduling reservation exhausted")
	}
	reservation.runtime = r
	reservation.generation++
	reservation.active = true
	reservation.authority = authority
	reservation.mutations = reservation.mutations[:0]
	return reservation
}

func newBondSchedulingMutation(
	state *bondExecutionState,
	parent int,
) bondSchedulingMutation {
	return bondSchedulingMutation{
		state:                        state,
		parent:                       parent,
		currentChild:                 state.currentChild,
		pinLeft:                      state.pinLeft,
		schedulePhase:                state.schedulePhase,
		qualificationCursor:          state.qualificationCursor,
		qualificationNormalFrames:    state.qualificationNormalFrames,
		qualificationBurstChild:      state.qualificationBurstChild,
		qualificationBurstLeft:       state.qualificationBurstLeft,
		qualificationMaintenanceWait: state.qualificationMaintenanceWait,
		qualificationTokensUsed:      state.qualificationTokensUsed,
	}
}

func (m *bondSchedulingMutation) apply() {
	if m == nil || m.state == nil {
		return
	}
	state := m.state
	state.currentChild = m.currentChild
	state.pinLeft = m.pinLeft
	state.schedulePhase = m.schedulePhase
	state.qualificationCursor = m.qualificationCursor
	state.qualificationNormalFrames = m.qualificationNormalFrames
	state.qualificationBurstChild = m.qualificationBurstChild
	state.qualificationBurstLeft = m.qualificationBurstLeft
	state.qualificationMaintenanceWait = m.qualificationMaintenanceWait
	state.qualificationTokensUsed = m.qualificationTokensUsed
	if !m.qualificationTouched {
		return
	}
	if state.qualification == nil {
		state.qualification = make(map[proto.TargetID]*bondQualificationState)
	}
	probe := state.qualification[m.qualificationChild]
	if probe == nil {
		probe = &bondQualificationState{}
		state.qualification[m.qualificationChild] = probe
	}
	*probe = m.qualificationValue
}

func (reservation *dispatchSchedulingReservation) appendMutation(
	mutation bondSchedulingMutation,
) int {
	if reservation == nil || !reservation.active {
		panic("engine: bond mutation outside scheduling reservation")
	}
	index := len(reservation.mutations)
	reservation.mutations = append(reservation.mutations, mutation)
	return index
}

func (reservation *dispatchSchedulingReservation) truncateMutations(length int) {
	if reservation == nil || length < 0 || length > len(reservation.mutations) {
		panic("engine: invalid bond mutation rollback mark")
	}
	for index := length; index < len(reservation.mutations); index++ {
		reservation.mutations[index] = bondSchedulingMutation{}
	}
	reservation.mutations = reservation.mutations[:length]
}

func (reservation *dispatchSchedulingReservation) admitBranch(generation uint64, branch int) {
	if reservation == nil || !reservation.active || reservation.generation != generation {
		panic("engine: stale dispatch scheduling reservation")
	}
	for branch != noDispatchReservationBranch {
		if branch < 0 || branch >= len(reservation.mutations) {
			panic("engine: invalid dispatch scheduling branch")
		}
		mutation := &reservation.mutations[branch]
		if mutation.commit {
			return
		}
		mutation.commit = true
		branch = mutation.parent
	}
}

func (reservation *dispatchSchedulingReservation) finish(generation uint64, stale bool) {
	if reservation == nil || !reservation.active || reservation.generation != generation || reservation.runtime == nil {
		panic("engine: stale dispatch scheduling reservation")
	}
	runtime := reservation.runtime
	for index := range reservation.mutations {
		mutation := &reservation.mutations[index]
		if stale {
			if mutation.state != nil && mutation.state.cacheAuthority == reservation.authority {
				mutation.state.cacheAuthority = nil
			}
		} else if mutation.commit {
			mutation.apply()
		}
		*mutation = bondSchedulingMutation{}
	}
	reservation.active = false
	reservation.authority = nil
	reservation.mutations = reservation.mutations[:0]
	runtime.mu.Unlock()
}

func cloneBondQualificationIdentity(id bondQualificationIdentity) bondQualificationIdentity {
	return bondQualificationIdentity{
		leaves:    append([]bondLeafIdentity(nil), id.leaves...),
		selectors: append([]bondSelectorIdentity(nil), id.selectors...),
	}
}

func cloneBondDomainIdentityInto(dst, src bondDomainIdentity) bondDomainIdentity {
	if cap(dst.children) < len(src.children) {
		dst.children = make([]bondChildDomainIdentity, len(src.children))
	} else {
		dst.children = dst.children[:len(src.children)]
	}
	for index := range src.children {
		leaves := dst.children[index].identity.leaves[:0]
		selectors := dst.children[index].identity.selectors[:0]
		dst.children[index].targetID = src.children[index].targetID
		dst.children[index].identity.leaves = append(leaves, src.children[index].identity.leaves...)
		dst.children[index].identity.selectors = append(selectors, src.children[index].identity.selectors...)
	}
	return dst
}

func cloneBondWeightsInto(dst map[proto.TargetID]uint64, src map[proto.TargetID]uint64) map[proto.TargetID]uint64 {
	if dst == nil {
		dst = make(map[proto.TargetID]uint64, len(src))
	} else {
		clear(dst)
	}
	for targetID, value := range src {
		dst[targetID] = value
	}
	return dst
}

func (r *executionRuntime) cachedBondDeliveryEvidence(
	topologyEpoch uint64,
	evidenceRevision uint64,
	now time.Time,
) (map[proto.TargetID]speedEstimate, map[proto.TargetID]uint64, bool) {
	if r == nil || !r.hasBond {
		return nil, nil, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if topologyEpoch == 0 || r.bondEvidenceEpoch != topologyEpoch ||
		r.bondEvidenceRevision != evidenceRevision ||
		r.bondEvidenceObserved.IsZero() || now.Before(r.bondEvidenceObserved) ||
		now.Sub(r.bondEvidenceObserved) >= selectorGoodputMinimumWindow {
		return nil, nil, false
	}
	// The cache TTL only bounds ledger lock traffic. Every estimate retains
	// its own factual lifetime and must remain valid at the instant it steers a
	// ticket, including when it crosses the freshness boundary inside 250 ms.
	for _, estimate := range r.bondEvidenceDelivered {
		if !bondCapacityEstimateFreshAt(estimate, now) {
			return nil, nil, false
		}
	}
	return r.bondEvidenceDelivered, r.bondEvidenceAcked, true
}

func (r *executionRuntime) cachedRecursiveDispatchProjection(
	topologyEpoch, healthEpoch, evidenceRevision, capacityRevision uint64,
	now time.Time,
) *recursiveDispatchProjection {
	if r == nil || !r.hasBond {
		return nil
	}
	r.mu.Lock()
	projection := r.bondDispatchProjection
	if !projection.currentAt(topologyEpoch, healthEpoch, evidenceRevision, capacityRevision, now) {
		projection = nil
	}
	r.mu.Unlock()
	return projection
}

func (r *executionRuntime) cachedRecursiveDispatchProjectionBase(
	topologyEpoch, healthEpoch, capacityRevision uint64,
	now time.Time,
) *recursiveDispatchProjection {
	if r == nil || !r.hasBond {
		return nil
	}
	r.mu.Lock()
	projection := r.bondDispatchProjection
	if !projection.reusableAt(topologyEpoch, healthEpoch, capacityRevision, now) {
		projection = nil
	}
	r.mu.Unlock()
	return projection
}

func (r *executionRuntime) cacheRecursiveDispatchProjection(projection *recursiveDispatchProjection) {
	if r == nil || !r.hasBond || projection == nil {
		return
	}
	r.mu.Lock()
	current := r.bondDispatchProjection
	if current == nil || current.topologyEpoch < projection.topologyEpoch ||
		(current.topologyEpoch == projection.topologyEpoch &&
			(current.healthEpoch < projection.healthEpoch ||
				(current.healthEpoch == projection.healthEpoch && current.evidenceRevision <= projection.evidenceRevision))) {
		r.bondDispatchProjection = projection
	}
	r.mu.Unlock()
}

func (r *executionRuntime) cacheBondDeliveryEvidence(
	topologyEpoch uint64,
	evidenceRevision uint64,
	now time.Time,
	delivered map[proto.TargetID]speedEstimate,
	acknowledged map[proto.TargetID]uint64,
) {
	if r == nil || !r.hasBond || topologyEpoch == 0 {
		return
	}
	fresh := make(map[proto.TargetID]speedEstimate, len(delivered))
	for targetID, estimate := range delivered {
		if bondCapacityEstimateFreshAt(estimate, now) {
			fresh[targetID] = estimate
		}
	}
	r.mu.Lock()
	r.bondEvidenceEpoch = topologyEpoch
	r.bondEvidenceRevision = evidenceRevision
	r.bondEvidenceObserved = now
	r.bondEvidenceDelivered = fresh
	r.bondEvidenceAcked = acknowledged
	r.mu.Unlock()
}

func bondCapacityEstimateFreshAt(estimate speedEstimate, now time.Time) bool {
	return estimate.source == speedSourceDelivered &&
		estimate.fresh(bondCapacityMinimumConfidence) &&
		!estimate.sampleTime.IsZero() && !now.Before(estimate.sampleTime) &&
		now.Sub(estimate.sampleTime) <= selectorEvidenceFreshFor
}

func isFlatLeafSelectorPlan(plan *executionPlan) bool {
	root, ok := plan.rootView()
	if !ok || root.kind != proto.GraphNodeKindSelector || len(root.children) == 0 {
		return false
	}
	for _, childID := range root.children {
		child, ok := plan.nodeView(childID)
		if !ok || child.kind != proto.GraphNodeKindPath {
			return false
		}
	}
	return true
}

func (r *executionRuntime) ownsFlatSelectorLeaf(targetID proto.TargetID) bool {
	if r == nil || !r.flatLeafSelector || targetID == (proto.TargetID{}) {
		return false
	}
	root, ok := r.plan.rootView()
	if !ok {
		return false
	}
	for _, childID := range root.children {
		if childID == targetID {
			return true
		}
	}
	return false
}

func (r *executionRuntime) bumpSelectorRevisionLocked() {
	if r.selectorRevision == ^uint64(0) {
		panic("engine: selector state epoch exhausted")
	}
	r.selectorRevision++
	r.flatSelectorCache[0].Store(nil)
	r.flatSelectorCache[1].Store(nil)
}

func (r *executionRuntime) setSelectorEffectiveLocked(
	state *selectorExecutionState,
	targetID proto.TargetID,
) {
	if state.effective == targetID {
		return
	}
	r.bumpSelectorRevisionLocked()
	state.effective = targetID
}

// flatSelectorDispatchLeaf resolves the sole leaf authorized by a flat
// selector. Physical path IDs are deliberately absent from this decision:
// they identify carrier incarnations, while the recursive runtime owns the
// logical target selection.
func (r *executionRuntime) flatSelectorDispatchLeaf(
	eligible, present map[proto.TargetID]bool,
) (proto.TargetID, bool) {
	if r == nil || !r.flatLeafSelector || r.plan == nil {
		return proto.TargetID{}, false
	}
	root, ok := r.plan.rootView()
	if !ok || root.kind != proto.GraphNodeKindSelector {
		return proto.TargetID{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.selectorDispatchChildLocked(
		root,
		func(id proto.TargetID) bool { return eligible[id] },
		func(id proto.TargetID) bool { return present[id] },
	)
}

func flatSelectorCacheIndex(requireBatch bool) int {
	if requireBatch {
		return 1
	}
	return 0
}

func (r *executionRuntime) cachedFlatSelectorDispatchSlot(
	topologyEpoch, healthEpoch uint64,
	requireBatch bool,
) (*pathSlot, bool) {
	if r == nil || !r.flatLeafSelector {
		return nil, false
	}
	cache := r.flatSelectorCache[flatSelectorCacheIndex(requireBatch)].Load()
	if cache == nil || cache.slot == nil || cache.topologyEpoch != topologyEpoch ||
		cache.healthEpoch != healthEpoch || cache.slot.dispatchStalled.Load() {
		return nil, false
	}
	return cache.slot, true
}

// resolveFlatSelectorDispatchSlot serializes cache publication with every
// selector mutation. bumpSelectorRevisionLocked clears both cache variants,
// so a stale builder cannot publish after a newer selector decision.
func (r *executionRuntime) resolveFlatSelectorDispatchSlot(
	eligible, present map[proto.TargetID]bool,
	latest map[proto.TargetID]*pathSlot,
	topologyEpoch, healthEpoch uint64,
	requireBatch bool,
) *pathSlot {
	if r == nil || !r.flatLeafSelector || r.plan == nil {
		return nil
	}
	root, ok := r.plan.rootView()
	if !ok || root.kind != proto.GraphNodeKindSelector {
		return nil
	}
	r.mu.Lock()
	targetID, selected := r.selectorDispatchChildLocked(
		root,
		func(id proto.TargetID) bool { return eligible[id] },
		func(id proto.TargetID) bool { return present[id] },
	)
	var slot *pathSlot
	if selected {
		slot = latest[targetID]
	}
	if slot != nil {
		r.flatSelectorCache[flatSelectorCacheIndex(requireBatch)].Store(
			&flatSelectorDispatchCache{
				topologyEpoch: topologyEpoch,
				healthEpoch:   healthEpoch,
				slot:          slot,
			},
		)
	}
	r.mu.Unlock()
	return slot
}

func (r *executionRuntime) selectChild(selectorID, childID proto.TargetID) error {
	if r == nil || r.plan == nil {
		return fmt.Errorf("engine: execution runtime is not configured")
	}
	selector, ok := r.plan.nodeView(selectorID)
	if !ok || selector.kind != proto.GraphNodeKindSelector {
		return fmt.Errorf("engine: execution target is not a selector")
	}
	if err := r.plan.validateImmediateChild(selectorID, childID); err != nil {
		return err
	}
	r.mu.Lock()
	state := r.selectors[selectorID]
	if state == nil {
		state = &selectorExecutionState{}
		r.selectors[selectorID] = state
	}
	if state.desired != childID {
		if r.selectorRevision == ^uint64(0) {
			r.mu.Unlock()
			return ErrSelectorStateEpochExhausted
		}
		r.bumpSelectorRevisionLocked()
		state.desired = childID
	}
	r.mu.Unlock()
	return nil
}

// commitSelectorChild validates and publishes one selector decision while the
// caller applies its physical observation projection under the same runtime
// lock. A failed projection restores the exact prior selector state, so a
// rejected policy transaction cannot leave DATA using an uncommitted target.
func (r *executionRuntime) commitSelectorChild(
	selectorID, childID proto.TargetID,
	attached map[proto.TargetID]bool,
	apply func(map[proto.TargetID]bool) error,
) error {
	return r.commitSelectorChildOrigin(selectorID, childID, attached, policySelectionExternal, apply)
}

func (r *executionRuntime) commitSelectorChildOrigin(
	selectorID, childID proto.TargetID,
	attached map[proto.TargetID]bool,
	origin policySelectionOrigin,
	apply func(map[proto.TargetID]bool) error,
) error {
	return r.commitSelectorChildOriginAtState(
		selectorID, childID, attached, origin, selectorStateExpectation{}, apply,
	)
}

func (r *executionRuntime) commitSelectorChildOriginAtState(
	selectorID, childID proto.TargetID,
	attached map[proto.TargetID]bool,
	origin policySelectionOrigin,
	expected selectorStateExpectation,
	apply func(map[proto.TargetID]bool) error,
) error {
	if r == nil || r.plan == nil {
		return errExecutionRuntimeNotConfigured
	}
	selector, ok := r.plan.nodeView(selectorID)
	if !ok || selector.kind != proto.GraphNodeKindSelector {
		return fmt.Errorf("engine: execution target is not a selector")
	}
	if err := r.plan.validateImmediateChild(selectorID, childID); err != nil {
		return err
	}
	available := r.targetAvailability(attached)
	if !available(childID) {
		return fmt.Errorf("engine: selected target has no attached path")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	state, existed := r.selectors[selectorID]
	if expected.bound && (expected.selectorID != selectorID || !existed ||
		state.desired != expected.desired || state.effective != expected.effective ||
		state.generation != expected.generation) {
		return errStaleSelectorEvidence
	}
	if !existed {
		state = &selectorExecutionState{}
		r.selectors[selectorID] = state
	}
	previous := *state
	changed := state.desired != childID
	if changed && state.generation == ^uint64(0) {
		if !existed {
			delete(r.selectors, selectorID)
		}
		return fmt.Errorf("engine: selector generation space exhausted")
	}
	stateChanges := state.desired != childID || state.effective != childID
	if stateChanges && r.selectorRevision == ^uint64(0) {
		if !existed {
			delete(r.selectors, selectorID)
		}
		return ErrSelectorStateEpochExhausted
	}
	state.desired = childID
	state.effective = childID
	if changed {
		state.generation++
	}
	switch origin {
	case policySelectionPeakPromote:
		state.peakHeld = true
	case policySelectionPeakReturn:
		state.peakHeld = false
	default:
		if !origin.isFactualFailure() || !selectorHasPeakCandidate(selector, childID) {
			state.peakHeld = false
		}
	}
	state.clearQualityCandidate()

	leaves := make(map[proto.TargetID]bool)
	r.collectEffectiveLeafSetLocked(r.plan.rootID, available, leaves)
	rollback := func() {
		if existed {
			*state = previous
		} else {
			delete(r.selectors, selectorID)
		}
	}
	if len(leaves) == 0 {
		rollback()
		return errNoExecutionRoute
	}
	if apply != nil {
		if err := apply(leaves); err != nil {
			rollback()
			return err
		}
	}
	if previous.desired != state.desired || previous.effective != state.effective ||
		previous.generation != state.generation {
		r.bumpSelectorRevisionLocked()
	}
	return nil
}

func selectorHasPeakCandidate(selector executionPlanNode, targetID proto.TargetID) bool {
	_, exists := selector.peakSet[targetID]
	return exists
}

func (r *executionRuntime) selectedChild(selectorID proto.TargetID) (desired, effective proto.TargetID, ok bool) {
	if r == nil {
		return proto.TargetID{}, proto.TargetID{}, false
	}
	r.mu.Lock()
	state := r.selectors[selectorID]
	if state != nil {
		desired, effective, ok = state.desired, state.effective, true
	}
	r.mu.Unlock()
	return desired, effective, ok
}

func (r *executionRuntime) selectorSelection(selectorID proto.TargetID) (desired, effective proto.TargetID, generation uint64, ok bool) {
	if r == nil {
		return proto.TargetID{}, proto.TargetID{}, 0, false
	}
	r.mu.Lock()
	state := r.selectors[selectorID]
	if state != nil {
		desired, effective, generation, ok = state.desired, state.effective, state.generation, true
	}
	r.mu.Unlock()
	return desired, effective, generation, ok
}

// rootPublicationAttribution snapshots the logical immediate child selected by
// the root selector. The caller serializes it with DATA publication through
// sendMu; nested selector activity is intentionally outside this cohort.
func (r *executionRuntime) rootPublicationAttribution() (
	selectorID, desired, effective proto.TargetID,
	generation uint64,
	ok bool,
) {
	if r == nil || r.plan == nil {
		return proto.TargetID{}, proto.TargetID{}, proto.TargetID{}, 0, false
	}
	root, exists := r.plan.rootView()
	if !exists || root.kind != proto.GraphNodeKindSelector {
		return proto.TargetID{}, proto.TargetID{}, proto.TargetID{}, 0, false
	}
	r.mu.Lock()
	state := r.selectors[root.targetID]
	if state != nil {
		desired = state.desired
		effective = state.effective
		generation = state.generation
	}
	r.mu.Unlock()
	return root.targetID, desired, effective, generation,
		state != nil && desired != (proto.TargetID{}) && generation != 0
}

// rootImmediateTarget returns the root selector child containing leafID. The
// graph is a tree, so exactly one immediate child can own a leaf.
func (r *executionRuntime) rootImmediateTarget(leafID proto.TargetID) (proto.TargetID, bool) {
	if r == nil || r.plan == nil || leafID == (proto.TargetID{}) {
		return proto.TargetID{}, false
	}
	root, ok := r.plan.rootView()
	if !ok || root.kind != proto.GraphNodeKindSelector {
		return proto.TargetID{}, false
	}
	for _, childID := range root.children {
		entry, exists := r.plan.nodes[childID]
		if !exists {
			continue
		}
		for _, descendant := range entry.leafIDs {
			if descendant == leafID {
				return childID, true
			}
		}
	}
	return proto.TargetID{}, false
}

func (r *executionRuntime) policySwitchLeaves(
	selectorID, targetID proto.TargetID,
	attached map[proto.TargetID]bool,
) map[proto.TargetID]bool {
	if r == nil || r.plan == nil {
		return nil
	}
	available := r.targetAvailability(attached)
	r.mu.Lock()
	defer r.mu.Unlock()
	selector, ok := r.plan.nodeView(selectorID)
	if !ok || selector.kind != proto.GraphNodeKindSelector {
		return nil
	}
	current, _ := r.selectorProjectionChildLocked(selector, available)
	if current == (proto.TargetID{}) || current == targetID {
		return nil
	}
	leaves := make(map[proto.TargetID]bool)
	r.collectEffectiveLeafSetLocked(current, available, leaves)
	r.collectEffectiveLeafSetLocked(targetID, available, leaves)
	return leaves
}

func (r *executionRuntime) effectiveLeafTargets(attached map[proto.TargetID]bool) map[proto.TargetID]bool {
	if r == nil || r.plan == nil {
		return nil
	}
	available := r.targetAvailability(attached)
	r.mu.Lock()
	defer r.mu.Unlock()
	leaves := make(map[proto.TargetID]bool)
	r.collectEffectiveLeafSetLocked(r.plan.rootID, available, leaves)
	return leaves
}

// selectorIsEffective reports whether selectorID participates in the current
// root projection. Selectors below an inactive selector branch are policy
// state only: changing them must not interrupt an unrelated active dispatch.
func (r *executionRuntime) selectorIsEffective(selectorID proto.TargetID, attached map[proto.TargetID]bool) bool {
	if r == nil || r.plan == nil {
		return false
	}
	available := r.targetAvailability(attached)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.selectorIsEffectiveLocked(selectorID, available)
}

func (r *executionRuntime) selectorIsEffectiveLocked(
	selectorID proto.TargetID,
	available func(proto.TargetID) bool,
) bool {
	var visit func(proto.TargetID) bool
	visit = func(id proto.TargetID) bool {
		if !available(id) {
			return false
		}
		if id == selectorID {
			return true
		}
		node, ok := r.plan.nodeView(id)
		if !ok || node.kind == proto.GraphNodeKindPath {
			return false
		}
		if node.kind == proto.GraphNodeKindSelector {
			childID, selected := r.selectorProjectionChildLocked(node, available)
			return selected && visit(childID)
		}
		for _, childID := range node.children {
			if visit(childID) {
				return true
			}
		}
		return false
	}
	return visit(r.plan.rootID)
}

// policySelectionChangesEffectiveRoute reports whether selecting targetID
// changes the current root data-plane projection. A selector below an inactive
// branch and a desired-state change that preserves the effective fallback are
// policy-only updates; neither may seize an unrelated dispatch for replay.
func (r *executionRuntime) policySelectionChangesEffectiveRoute(
	selectorID, targetID proto.TargetID,
	attached map[proto.TargetID]bool,
) bool {
	if r == nil || r.plan == nil || targetID == (proto.TargetID{}) {
		return false
	}
	available := r.targetAvailability(attached)
	r.mu.Lock()
	defer r.mu.Unlock()
	selector, ok := r.plan.nodeView(selectorID)
	if !ok || selector.kind != proto.GraphNodeKindSelector || !available(targetID) ||
		!r.selectorIsEffectiveLocked(selectorID, available) {
		return false
	}
	current, selected := r.selectorProjectionChildLocked(selector, available)
	return selected && current != (proto.TargetID{}) && current != targetID
}

func (r *executionRuntime) targetAvailability(attached map[proto.TargetID]bool) func(proto.TargetID) bool {
	available := make(map[proto.TargetID]bool, len(r.plan.nodes))
	known := make(map[proto.TargetID]bool, len(r.plan.nodes))
	var targetAvailable func(proto.TargetID) bool
	targetAvailable = func(id proto.TargetID) bool {
		if known[id] {
			return available[id]
		}
		known[id] = true
		node, ok := r.plan.nodeView(id)
		if !ok {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			available[id] = attached[id]
			return available[id]
		}
		for _, childID := range node.children {
			if targetAvailable(childID) {
				available[id] = true
			}
		}
		return available[id]
	}
	return targetAvailable
}

func (r *executionRuntime) collectEffectiveLeafSetLocked(
	id proto.TargetID,
	available func(proto.TargetID) bool,
	leaves map[proto.TargetID]bool,
) {
	node, ok := r.plan.nodeView(id)
	if !ok || !available(id) {
		return
	}
	if node.kind == proto.GraphNodeKindPath {
		leaves[id] = true
		return
	}
	if node.kind == proto.GraphNodeKindSelector {
		if childID, selected := r.selectorProjectionChildLocked(node, available); selected {
			r.collectEffectiveLeafSetLocked(childID, available, leaves)
		}
		return
	}
	for _, childID := range node.children {
		r.collectEffectiveLeafSetLocked(childID, available, leaves)
	}
}

// selectorProjectionChildLocked is the shared non-mutating selector resolver
// for policy/hold projections. It must match selectorChildLocked: a recovered
// desired child immediately outranks a stale fallback, followed by non-peak
// and peak children in manifest order.
func (r *executionRuntime) selectorProjectionChildLocked(
	node executionPlanNode,
	available func(proto.TargetID) bool,
) (proto.TargetID, bool) {
	state := r.selectors[node.targetID]
	if state != nil && state.desired != (proto.TargetID{}) && available(state.desired) {
		return state.desired, true
	}
	for _, peakPass := range []bool{false, true} {
		for _, childID := range node.children {
			_, peak := node.peakSet[childID]
			if peak == peakPass && available(childID) {
				return childID, true
			}
		}
	}
	return proto.TargetID{}, false
}

// initializeSelectorsForLeaf freezes the manifest branch that made a leaf's
// first physical generation usable. A committed selector branch may only be
// changed by the policy plane; the data plane must never silently route via a
// sibling when that branch is temporarily unavailable.
func (r *executionRuntime) initializeSelectorsForLeaf(leafID proto.TargetID) []initialSelectorSelection {
	return r.initializeSelectorsForLeafPolicy(leafID, nil)
}

func (r *executionRuntime) initializeSelectorsForLeafPolicy(
	leafID proto.TargetID,
	policySelections map[proto.TargetID]proto.TargetID,
) []initialSelectorSelection {
	if r == nil || r.plan == nil || leafID == (proto.TargetID{}) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	initialized := make([]initialSelectorSelection, 0)
	r.initializeSelectorBranchLocked(r.plan.rootID, leafID, policySelections, &initialized)
	return initialized
}

func (r *executionRuntime) initializeSelectorBranchLocked(
	id, leafID proto.TargetID,
	policySelections map[proto.TargetID]proto.TargetID,
	initialized *[]initialSelectorSelection,
) bool {
	node, ok := r.plan.nodeView(id)
	if !ok {
		return false
	}
	if node.kind == proto.GraphNodeKindPath {
		return id == leafID
	}
	for _, childID := range node.children {
		if !r.initializeSelectorBranchLocked(childID, leafID, policySelections, initialized) {
			continue
		}
		if node.kind == proto.GraphNodeKindSelector {
			state := r.selectors[node.targetID]
			if state == nil {
				state = &selectorExecutionState{}
				r.selectors[node.targetID] = state
			}
			if state.desired == (proto.TargetID{}) {
				r.bumpSelectorRevisionLocked()
				desired := policySelections[node.targetID]
				if desired == (proto.TargetID{}) {
					desired = childID
					*initialized = append(*initialized, initialSelectorSelection{
						selectorID: node.targetID,
						targetID:   childID,
					})
				}
				state.desired = desired
				state.effective = childID
				state.generation = 1
			}
		}
		return true
	}
	return false
}

func (r *executionRuntime) activeLeafTargets(attached map[proto.TargetID]bool) ([]proto.TargetID, proto.ExecutionKind, error) {
	if r == nil || r.plan == nil {
		return nil, 0, fmt.Errorf("engine: execution runtime is not configured")
	}
	var available func(proto.TargetID) bool
	available = func(id proto.TargetID) bool {
		node, ok := r.plan.nodeView(id)
		if !ok {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			return attached[id]
		}
		for _, childID := range node.children {
			if available(childID) {
				return true
			}
		}
		return false
	}
	root, ok := r.plan.rootView()
	if !ok || !available(root.targetID) {
		return nil, 0, errNoExecutionRoute
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kind := r.activeExecutionKindLocked(root.targetID, available)
	leaves := make([]proto.TargetID, 0)
	r.collectActiveLeavesLocked(root.targetID, available, &leaves)
	if len(leaves) == 0 {
		return nil, 0, errNoExecutionRoute
	}
	return leaves, kind, nil
}

func (r *executionRuntime) activeExecutionKindLocked(id proto.TargetID, available func(proto.TargetID) bool) proto.ExecutionKind {
	node, ok := r.plan.nodeView(id)
	if !ok {
		return proto.ExecutionKindSelector
	}
	if node.kind == proto.GraphNodeKindSelector {
		childID, selected := r.selectorChildLocked(node, available)
		if selected {
			return r.activeExecutionKindLocked(childID, available)
		}
		return proto.ExecutionKindSelector
	}
	switch node.kind {
	case proto.GraphNodeKindBond:
		return proto.ExecutionKindBond
	case proto.GraphNodeKindRace:
		return proto.ExecutionKindRace
	default:
		return proto.ExecutionKindSelector
	}
}

func (r *executionRuntime) collectActiveLeavesLocked(id proto.TargetID, available func(proto.TargetID) bool, leaves *[]proto.TargetID) {
	node, ok := r.plan.nodeView(id)
	if !ok || !available(id) {
		return
	}
	if node.kind == proto.GraphNodeKindPath {
		*leaves = append(*leaves, id)
		return
	}
	if node.kind == proto.GraphNodeKindSelector {
		if childID, selected := r.selectorChildLocked(node, available); selected {
			r.collectActiveLeavesLocked(childID, available, leaves)
		}
		return
	}
	for _, childID := range node.children {
		r.collectActiveLeavesLocked(childID, available, leaves)
	}
}

func (r *executionRuntime) buildTicket(attached map[proto.TargetID]bool, packetized bool, bondPinSize int) (dispatchTicket, error) {
	return r.buildTicketObserved(attached, nil, nil, packetized, bondPinSize, 0)
}

func (r *executionRuntime) buildTicketObserved(
	attached map[proto.TargetID]bool,
	qualities map[proto.TargetID]transport.PathQuality,
	capacities map[proto.TargetID]uint64,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) (dispatchTicket, error) {
	return r.buildTicketObservedPresence(
		attached, attached, qualities, capacities, packetized, bondPinSize, bondStuckMultiplier,
	)
}

func (r *executionRuntime) buildTicketObservedPresence(
	eligible map[proto.TargetID]bool,
	present map[proto.TargetID]bool,
	qualities map[proto.TargetID]transport.PathQuality,
	capacities map[proto.TargetID]uint64,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) (dispatchTicket, error) {
	return r.buildTicketScheduledPresence(
		eligible, present, qualities, bondSchedulingContext{
			now: nowFn(), staticWeights: capacities, effectiveWeights: capacities,
		}, packetized, bondPinSize, bondStuckMultiplier,
	)
}

func (r *executionRuntime) buildTicketScheduledPresence(
	eligible map[proto.TargetID]bool,
	present map[proto.TargetID]bool,
	qualities map[proto.TargetID]transport.PathQuality,
	scheduling bondSchedulingContext,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) (dispatchTicket, error) {
	ticket, err := r.reserveTicketScheduledPresence(
		eligible, present, qualities, scheduling, packetized, bondPinSize, bondStuckMultiplier,
	)
	if err != nil {
		return dispatchTicket{}, err
	}
	routes := append([]dispatchRoute(nil), ticket.routes...)
	ticket.finalizeScheduling(true)
	ticket.routes = routes
	return ticket, nil
}

func (r *executionRuntime) reserveTicketScheduledPresence(
	eligible map[proto.TargetID]bool,
	present map[proto.TargetID]bool,
	qualities map[proto.TargetID]transport.PathQuality,
	scheduling bondSchedulingContext,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) (dispatchTicket, error) {
	if r == nil || r.plan == nil {
		return dispatchTicket{}, fmt.Errorf("engine: execution runtime is not configured")
	}
	root, ok := r.plan.rootView()
	if !ok {
		return dispatchTicket{}, fmt.Errorf("engine: execution plan has no root")
	}
	available := make(map[proto.TargetID]bool, len(r.plan.nodes))
	known := make(map[proto.TargetID]bool, len(r.plan.nodes))
	var nodeAvailable func(proto.TargetID) bool
	nodeAvailable = func(id proto.TargetID) bool {
		if known[id] {
			return available[id]
		}
		known[id] = true
		node, exists := r.plan.nodeView(id)
		if !exists {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			available[id] = eligible[id]
			return available[id]
		}
		for _, childID := range node.children {
			if nodeAvailable(childID) {
				available[id] = true
				return true
			}
		}
		return false
	}
	if !nodeAvailable(root.targetID) {
		return dispatchTicket{}, errNoExecutionRoute
	}
	presentMemo := make(map[proto.TargetID]bool, len(r.plan.nodes))
	presentKnown := make(map[proto.TargetID]bool, len(r.plan.nodes))
	var nodePresent func(proto.TargetID) bool
	nodePresent = func(id proto.TargetID) bool {
		if presentKnown[id] {
			return presentMemo[id]
		}
		presentKnown[id] = true
		node, exists := r.plan.nodeView(id)
		if !exists {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			presentMemo[id] = present[id]
			return presentMemo[id]
		}
		for _, childID := range node.children {
			if nodePresent(childID) {
				presentMemo[id] = true
				return true
			}
		}
		return false
	}

	return r.reserveTicketLocked(
		root, nodeAvailable, nodePresent, qualities, scheduling,
		packetized, bondPinSize, bondStuckMultiplier,
	)
}

func (r *executionRuntime) reserveTicketFromProjection(
	projection *recursiveDispatchProjection,
	controlFallback bool,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) (dispatchTicket, error) {
	if r == nil || r.plan == nil || projection == nil {
		return dispatchTicket{}, fmt.Errorf("engine: execution runtime is not configured")
	}
	root, ok := r.plan.rootView()
	if !ok || !projection.eligibleNodes[root.targetID] {
		return dispatchTicket{}, errNoExecutionRoute
	}
	present := projection.presentNodes
	if controlFallback {
		present = projection.eligibleNodes
	}
	scheduling := projection.scheduling
	scheduling.authority = projection
	return r.reserveTicketLocked(
		root,
		func(id proto.TargetID) bool { return projection.eligibleNodes[id] },
		func(id proto.TargetID) bool { return present[id] },
		projection.qualities, scheduling,
		packetized, bondPinSize, bondStuckMultiplier,
	)
}

func (r *executionRuntime) reserveTicketLocked(
	root executionPlanNode,
	nodeAvailable func(proto.TargetID) bool,
	nodePresent func(proto.TargetID) bool,
	qualities map[proto.TargetID]transport.PathQuality,
	scheduling bondSchedulingContext,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) (dispatchTicket, error) {
	r.mu.Lock()
	reservation := r.beginDispatchSchedulingReservationLocked(scheduling.authority)
	r.routeScratch = r.routeScratch[:0]
	ok := r.buildNodeLocked(
		root.targetID, false, nodeAvailable, nodePresent, qualities, scheduling,
		packetized, bondPinSize, bondStuckMultiplier, noDispatchReservationBranch,
	)
	if !ok || len(r.routeScratch) == 0 {
		reservation.finish(reservation.generation, false)
		return dispatchTicket{}, errNoExecutionRoute
	}
	return dispatchTicket{
		routes:                r.routeScratch,
		kind:                  r.activeExecutionKindLocked(root.targetID, nodeAvailable),
		reservation:           reservation,
		reservationGeneration: reservation.generation,
	}, nil
}

func (r *executionRuntime) buildNodeLocked(
	id proto.TargetID,
	bonded bool,
	available func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
	qualities map[proto.TargetID]transport.PathQuality,
	scheduling bondSchedulingContext,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
	parentBranch int,
) bool {
	node, ok := r.plan.nodeView(id)
	if !ok || !available(id) {
		return false
	}
	switch node.kind {
	case proto.GraphNodeKindPath:
		r.routeScratch = append(r.routeScratch, dispatchRoute{
			targetID: id, bonded: bonded, reservationBranch: parentBranch,
		})
		return true
	case proto.GraphNodeKindSelector:
		childID, ok := r.selectorDispatchChildLocked(node, available, present)
		if !ok {
			return false
		}
		return r.buildNodeLocked(
			childID, bonded, available, present, qualities, scheduling,
			packetized, bondPinSize, bondStuckMultiplier, parentBranch,
		)
	case proto.GraphNodeKindBond:
		state := r.bonds[node.targetID]
		if state == nil {
			state = &bondExecutionState{}
			r.bonds[node.targetID] = state
		}
		if state.scratchExcluded == nil {
			state.scratchExcluded = make(map[proto.TargetID]bool, len(node.children))
		} else {
			clear(state.scratchExcluded)
		}
		tried := state.scratchExcluded
		for len(tried) < len(node.children) {
			childID, qualification, qualificationPressure, qualificationComplete, mutation, ok := r.bondChildLocked(
				node, available, present, qualities, scheduling, tried,
				packetized, bondPinSize, bondStuckMultiplier, parentBranch,
			)
			if !ok {
				return false
			}
			tried[childID] = true
			mutationMark := len(r.reservation.mutations)
			branch := r.reservation.appendMutation(mutation)
			routeMark := len(r.routeScratch)
			if built := r.buildNodeLocked(
				childID, true, available, present, qualities, scheduling,
				packetized, bondPinSize, bondStuckMultiplier, branch,
			); built {
				if qualification {
					for index := routeMark; index < len(r.routeScratch); index++ {
						r.routeScratch[index].capacityQualification = true
						r.routeScratch[index].capacityQualificationPressure = qualificationPressure
						r.routeScratch[index].capacityQualificationComplete = qualificationComplete
					}
				}
				return true
			}
			r.routeScratch = r.routeScratch[:routeMark]
			r.reservation.truncateMutations(mutationMark)
		}
		return false
	case proto.GraphNodeKindRace:
		routeMark := len(r.routeScratch)
		for _, childID := range node.children {
			if !available(childID) {
				continue
			}
			r.buildNodeLocked(
				childID, bonded, available, present, qualities, scheduling,
				packetized, bondPinSize, bondStuckMultiplier, parentBranch,
			)
		}
		return len(r.routeScratch) != routeMark
	default:
		return false
	}
}

func (r *executionRuntime) selectorChildLocked(node executionPlanNode, available func(proto.TargetID) bool) (proto.TargetID, bool) {
	state := r.selectors[node.targetID]
	if state == nil {
		state = &selectorExecutionState{}
		r.selectors[node.targetID] = state
	}
	if childID, selected := r.selectorProjectionChildLocked(node, available); selected {
		r.setSelectorEffectiveLocked(state, childID)
		return childID, true
	}
	r.setSelectorEffectiveLocked(state, proto.TargetID{})
	return proto.TargetID{}, false
}

// selectorDispatchChildLocked distinguishes a physically absent selected
// target from one that is merely excluded by a blocked writer. Hard absence
// may use the selector's immediate death fallback. A present-but-stalled
// target must wait for a policy-plane cutover so DATA can never reach a
// sibling while ActivePath still names the selected target.
func (r *executionRuntime) selectorDispatchChildLocked(
	node executionPlanNode,
	eligible func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
) (proto.TargetID, bool) {
	state := r.selectors[node.targetID]
	if state == nil {
		state = &selectorExecutionState{}
		r.selectors[node.targetID] = state
	}
	if state.desired != (proto.TargetID{}) {
		if eligible(state.desired) {
			r.setSelectorEffectiveLocked(state, state.desired)
			return state.desired, true
		}
		if present(state.desired) {
			// Writer admission is transient backpressure, not a factual route
			// change. Retain the committed effective child and let dispatch wait;
			// clearing it would make the next DATA publication surface a false
			// no-route error to the application.
			r.setSelectorEffectiveLocked(state, state.desired)
			return proto.TargetID{}, false
		}
	}
	for _, peakPass := range []bool{false, true} {
		for _, childID := range node.children {
			_, peak := node.peakSet[childID]
			if peak != peakPass || !eligible(childID) {
				continue
			}
			r.setSelectorEffectiveLocked(state, childID)
			return childID, true
		}
	}
	r.setSelectorEffectiveLocked(state, proto.TargetID{})
	return proto.TargetID{}, false
}

func (r *executionRuntime) bondChildLocked(
	node executionPlanNode,
	available func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
	qualities map[proto.TargetID]transport.PathQuality,
	scheduling bondSchedulingContext,
	excluded map[proto.TargetID]bool,
	packetized bool,
	pinSize int,
	stuckMultiplier float64,
	parentBranch int,
) (proto.TargetID, bool, bool, bool, bondSchedulingMutation, bool) {
	state := r.bonds[node.targetID]
	if state == nil {
		state = &bondExecutionState{}
		r.bonds[node.targetID] = state
	}
	if scheduling.now.IsZero() {
		scheduling.now = nowFn()
	}
	cacheCurrent := scheduling.authority != nil &&
		state.cacheAuthority != nil &&
		state.cacheTopologyEpoch == scheduling.topologyEpoch &&
		state.cacheHealthEpoch == scheduling.healthEpoch &&
		state.cacheCapacityRevision == scheduling.capacityRevision &&
		state.cacheSelectorRevision == r.selectorRevision
	if !cacheCurrent {
		r.refreshBondSchedulingLocked(node, available, present, scheduling, state)
	} else {
		state.cacheAuthority = scheduling.authority
	}
	mutation := newBondSchedulingMutation(state, parentBranch)
	if len(state.scratchUnknownObservations) != 0 {
		if qualificationID, pressure, complete, qualifying := mutation.bondQualificationChild(
			r, state, state.scratchUnknownObservations, scheduling, excluded, available,
		); qualifying {
			return qualificationID, true, pressure, complete, mutation, true
		}
	} else {
		mutation.qualificationBurstChild = proto.TargetID{}
		mutation.qualificationBurstLeft = 0
		mutation.qualificationNormalFrames = 0
	}
	childID, selected := mutation.selectBondSchedule(
		r, state, excluded, available, packetized, pinSize,
	)
	if !selected {
		mutation.currentChild = proto.TargetID{}
		mutation.pinLeft = 0
		return proto.TargetID{}, false, false, false, bondSchedulingMutation{}, false
	}
	_ = qualities
	_ = stuckMultiplier
	return childID, false, false, false, mutation, true
}

func (r *executionRuntime) refreshBondSchedulingLocked(
	node executionPlanNode,
	available func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
	scheduling bondSchedulingContext,
	state *bondExecutionState,
) {
	if state.scratchAggregates == nil {
		state.scratchAggregates = make(map[proto.TargetID]bondCapacityAggregate, len(node.children))
	} else {
		clear(state.scratchAggregates)
	}
	if state.scratchIdentities == nil {
		state.scratchIdentities = make(map[proto.TargetID]*bondQualificationIdentity, len(node.children))
	}
	aggregates := state.scratchAggregates
	unknown := state.scratchUnknown[:0]
	hasObserved := false
	ambiguous := r.bondRaceAncestor[node.targetID]
	for _, candidateID := range node.children {
		if !available(candidateID) {
			continue
		}
		r.bondRefreshOperations++
		aggregate := r.aggregateBondCapacityLocked(candidateID, available, present, scheduling)
		identity := state.scratchIdentities[candidateID]
		if identity == nil {
			identity = &bondQualificationIdentity{}
			state.scratchIdentities[candidateID] = identity
		}
		identity.leaves = append(identity.leaves[:0], aggregate.identity.leaves...)
		identity.selectors = append(identity.selectors[:0], aggregate.identity.selectors...)
		aggregate.identity = *identity
		aggregates[candidateID] = aggregate
		if aggregate.ambiguous {
			ambiguous = true
		}
		if aggregate.observed {
			hasObserved = true
		} else {
			unknown = append(unknown, candidateID)
		}
	}
	state.scratchUnknown = unknown

	if state.scratchWeights == nil {
		state.scratchWeights = make(map[proto.TargetID]uint64, len(node.children))
	} else {
		clear(state.scratchWeights)
	}
	weights := state.scratchWeights
	useDynamic := scheduling.evidenceAware && !ambiguous && hasObserved
	var unknownObservations map[proto.TargetID]bondQualificationObservation
	if state.scratchUnknownObservations == nil {
		state.scratchUnknownObservations = make(map[proto.TargetID]bondQualificationObservation, len(node.children))
	} else {
		clear(state.scratchUnknownObservations)
	}
	if useDynamic {
		var maximum uint64
		for _, aggregate := range aggregates {
			if aggregate.observed {
				if aggregate.effective > maximum {
					maximum = aggregate.effective
				}
			}
		}
		for candidateID, aggregate := range aggregates {
			if aggregate.observed {
				weights[candidateID] = scaleBondCapacityWeight(
					aggregate.effective, maximum, bondCapacityWeightScale,
				)
			}
		}
		if len(unknown) != 0 {
			unknownObservations = state.scratchUnknownObservations
			for _, candidateID := range unknown {
				aggregate := aggregates[candidateID]
				unknownObservations[candidateID] = bondQualificationObservation{
					acknowledged: aggregate.acked,
					identity:     aggregate.identity,
				}
			}
		}
	} else {
		for candidateID, aggregate := range aggregates {
			weights[candidateID] = aggregate.static
		}
	}
	for candidateID, weight := range weights {
		if weight == 0 {
			weight = 1
		}
		if weight > maximumBondSchedulerWeight {
			weight = maximumBondSchedulerWeight
		}
		weights[candidateID] = weight
	}
	domain := bondDomainIdentity{children: state.scratchDomain.children[:0]}
	for _, candidateID := range node.children {
		aggregate, exists := aggregates[candidateID]
		if !exists {
			continue
		}
		domain.children = append(domain.children, bondChildDomainIdentity{
			targetID: candidateID,
			identity: aggregate.identity,
		})
	}
	state.scratchDomain = domain
	state.installBondWeightVector(domain, weights)
	orderedUnknown := state.scratchOrderedUnknown[:0]
	for _, candidateID := range node.children {
		if _, exists := unknownObservations[candidateID]; exists {
			orderedUnknown = append(orderedUnknown, candidateID)
		}
	}
	state.scratchOrderedUnknown = orderedUnknown
	state.cacheAuthority = scheduling.authority
	state.cacheTopologyEpoch = scheduling.topologyEpoch
	state.cacheHealthEpoch = scheduling.healthEpoch
	state.cacheCapacityRevision = scheduling.capacityRevision
	state.cacheSelectorRevision = r.selectorRevision
}

func (m *bondSchedulingMutation) bondQualificationChild(
	r *executionRuntime,
	state *bondExecutionState,
	unknown map[proto.TargetID]bondQualificationObservation,
	scheduling bondSchedulingContext,
	excluded map[proto.TargetID]bool,
	available func(proto.TargetID) bool,
) (proto.TargetID, bool, bool, bool) {
	if m == nil || state == nil || len(unknown) == 0 {
		return proto.TargetID{}, false, false, false
	}
	if m.qualificationBurstLeft != 0 {
		childID := m.qualificationBurstChild
		observation, present := unknown[childID]
		if present && !excluded[childID] && available(childID) &&
			m.qualificationTokensUsed < bondQualificationMaximumTokens {
			observation.acknowledged = bondQualificationAcknowledgedAt(
				childID, observation.identity, scheduling,
			)
			probe := m.qualificationProbe(state, childID, observation)
			if probe.sentSinceACK < probe.credit {
				pressure, complete := m.noteBondQualificationSend(childID, probe)
				m.qualificationBurstLeft--
				if m.qualificationBurstLeft == 0 {
					m.qualificationBurstChild = proto.TargetID{}
					m.qualificationNormalFrames = bondQualificationInterleaveFrames
				}
				return childID, pressure, complete, true
			}
		}
		m.qualificationBurstChild = proto.TargetID{}
		m.qualificationBurstLeft = 0
	}
	if m.qualificationNormalFrames > 0 {
		m.qualificationNormalFrames--
		return proto.TargetID{}, false, false, false
	}
	orderedUnknown := state.scratchOrderedUnknown
	if len(orderedUnknown) == 0 {
		return proto.TargetID{}, false, false, false
	}
	for offset := 0; offset < len(orderedUnknown); offset++ {
		r.bondHotOperations++
		index := (m.qualificationCursor + offset) % len(orderedUnknown)
		childID := orderedUnknown[index]
		if excluded[childID] || !available(childID) ||
			m.qualificationTokensUsed >= bondQualificationMaximumTokens {
			continue
		}
		observation := unknown[childID]
		observation.acknowledged = bondQualificationAcknowledgedAt(
			childID, observation.identity, scheduling,
		)
		probe := m.qualificationProbe(state, childID, observation)
		if probe.sentSinceACK >= probe.credit {
			continue
		}
		pressure, complete := m.noteBondQualificationSend(childID, probe)
		m.qualificationCursor = (index + 1) % len(orderedUnknown)
		remainingCredit := probe.credit - probe.sentSinceACK
		remainingTokens := bondQualificationMaximumTokens - m.qualificationTokensUsed
		if remainingCredit > remainingTokens {
			remainingCredit = remainingTokens
		}
		m.qualificationBurstChild = childID
		m.qualificationBurstLeft = remainingCredit
		if m.qualificationBurstLeft >= bondQualificationMaximumBurst {
			m.qualificationBurstLeft = bondQualificationMaximumBurst - 1
		}
		if m.qualificationBurstLeft == 0 {
			m.qualificationBurstChild = proto.TargetID{}
			m.qualificationNormalFrames = bondQualificationInterleaveFrames
		}
		return childID, pressure, complete, true
	}
	m.qualificationMaintenanceWait = saturatingAddUint64(
		m.qualificationMaintenanceWait, 1,
	)
	if m.qualificationMaintenanceWait >= bondQualificationMaintenanceFrames {
		for offset := 0; offset < len(orderedUnknown); offset++ {
			r.bondHotOperations++
			index := (m.qualificationCursor + offset) % len(orderedUnknown)
			childID := orderedUnknown[index]
			if excluded[childID] || !available(childID) {
				continue
			}
			observation := unknown[childID]
			observation.acknowledged = bondQualificationAcknowledgedAt(
				childID, observation.identity, scheduling,
			)
			probe := m.qualificationProbe(state, childID, observation)
			pressure, complete := m.noteBondQualificationSend(childID, probe)
			m.qualificationCursor = (index + 1) % len(orderedUnknown)
			return childID, pressure, complete, true
		}
	}
	return proto.TargetID{}, false, false, false
}

func bondQualificationAcknowledgedAt(
	childID proto.TargetID,
	identity bondQualificationIdentity,
	scheduling bondSchedulingContext,
) uint64 {
	if scheduling.evidenceSource != nil {
		if acknowledged, valid := scheduling.evidenceSource.bondQualificationAcknowledgedAtRevision(
			childID, identity, scheduling.topologyEpoch, scheduling.evidenceRevision,
		); valid {
			return acknowledged
		}
	}
	if acknowledged, exists := scheduling.acknowledged[childID]; exists {
		return acknowledged
	}
	for index := len(identity.selectors) - 1; index >= 0; index-- {
		if acknowledged, exists := scheduling.acknowledged[identity.selectors[index].targetID]; exists {
			return acknowledged
		}
	}
	var acknowledged uint64
	for _, leaf := range identity.leaves {
		acknowledged = saturatingAddUint64(
			acknowledged, scheduling.acknowledged[leaf.targetID],
		)
	}
	return acknowledged
}

func (m *bondSchedulingMutation) qualificationProbe(
	state *bondExecutionState,
	childID proto.TargetID,
	observation bondQualificationObservation,
) bondQualificationState {
	probe := state.qualification[childID]
	if probe == nil || !probe.identity.equal(observation.identity) ||
		observation.acknowledged < probe.lastAcknowledged {
		return bondQualificationState{
			lastAcknowledged: observation.acknowledged,
			credit:           1,
			identity:         observation.identity.clone(),
		}
	}
	value := *probe
	if observation.acknowledged != value.lastAcknowledged {
		value.lastAcknowledged = observation.acknowledged
		value.sentSinceACK = 0
		if m.qualificationTokensUsed < bondQualificationMaximumTokens &&
			value.credit < bondQualificationMaximumCredit {
			value.credit *= 2
			if value.credit > bondQualificationMaximumCredit {
				value.credit = bondQualificationMaximumCredit
			}
		}
	}
	return value
}

func (m *bondSchedulingMutation) noteBondQualificationSend(
	childID proto.TargetID,
	probe bondQualificationState,
) (pressure bool, complete bool) {
	if m == nil {
		return false, false
	}
	probe.sentSinceACK = saturatingAddUint64(probe.sentSinceACK, 1)
	probe.totalSent = saturatingAddUint64(probe.totalSent, 1)
	if m.qualificationTokensUsed < bondQualificationMaximumTokens {
		m.qualificationTokensUsed++
	}
	m.qualificationMaintenanceWait = 0
	m.qualificationTouched = true
	m.qualificationChild = childID
	m.qualificationValue = probe
	pressure = probe.totalSent >= bondQualificationPressureThreshold
	complete = pressure && m.qualificationTokensUsed >= bondQualificationMaximumTokens
	return pressure, complete
}

func (m *bondSchedulingMutation) selectBondSchedule(
	r *executionRuntime,
	state *bondExecutionState,
	excluded map[proto.TargetID]bool,
	available func(proto.TargetID) bool,
	packetized bool,
	pinSize int,
) (proto.TargetID, bool) {
	if m.pinLeft > 0 && !excluded[m.currentChild] &&
		state.weightVector[m.currentChild] != 0 && available(m.currentChild) {
		m.pinLeft--
		return m.currentChild, true
	}
	for attempts := 0; attempts < len(state.schedule); attempts++ {
		r.bondHotOperations++
		index := bondScheduleIndex(m.schedulePhase, len(state.schedule))
		childID := state.schedule[index]
		m.schedulePhase = advanceBondSchedulePhase(m.schedulePhase, len(state.schedule))
		if excluded[childID] || !available(childID) {
			continue
		}
		pin := pinSize
		if pin <= 0 {
			pin = defaultBondPinSize
		}
		if packetized {
			pin = 1
		}
		m.currentChild = childID
		m.pinLeft = pin - 1
		return childID, true
	}
	return proto.TargetID{}, false
}

func bondScheduleIndex(phase uint64, length int) int {
	if length <= 1 {
		return 0
	}
	index, _ := bits.Mul64(phase, uint64(length))
	return int(index)
}

func advanceBondSchedulePhase(phase uint64, length int) uint64 {
	if length <= 1 {
		return phase
	}
	return phase + ^uint64(0)/uint64(length) + 1
}

func (id bondQualificationIdentity) clone() bondQualificationIdentity {
	return cloneBondQualificationIdentity(id)
}

func (id bondQualificationIdentity) equal(other bondQualificationIdentity) bool {
	if len(id.leaves) != len(other.leaves) || len(id.selectors) != len(other.selectors) {
		return false
	}
	for index := range id.leaves {
		if id.leaves[index] != other.leaves[index] {
			return false
		}
	}
	for index := range id.selectors {
		if id.selectors[index] != other.selectors[index] {
			return false
		}
	}
	return true
}

func (id bondDomainIdentity) equal(other bondDomainIdentity) bool {
	if len(id.children) != len(other.children) {
		return false
	}
	for index := range id.children {
		if id.children[index].targetID != other.children[index].targetID ||
			!id.children[index].identity.equal(other.children[index].identity) {
			return false
		}
	}
	return true
}

func (s *bondExecutionState) installBondWeightVector(
	domain bondDomainIdentity,
	weights map[proto.TargetID]uint64,
) {
	if s == nil {
		return
	}
	sameDomain := s.domain.equal(domain)
	sameMembership := s.weightVector != nil && len(s.weightVector) == len(weights)
	if sameMembership {
		for targetID := range weights {
			if _, exists := s.weightVector[targetID]; !exists {
				sameMembership = false
				break
			}
		}
	}
	unchanged := sameMembership
	if sameMembership {
		for targetID, weight := range weights {
			unchanged = unchanged && s.weightVector[targetID] == weight
		}
	}
	if sameDomain && unchanged {
		return
	}
	s.resetChangedBondQualificationChildren(domain)
	s.domain = cloneBondDomainIdentityInto(s.domain, domain)
	s.weightVector = cloneBondWeightsInto(s.weightVector, weights)
	s.currentWeight = nil
	s.buildBondSchedule(domain, weights)
	if !sameDomain || !sameMembership {
		s.currentChild = proto.TargetID{}
		s.pinLeft = 0
	}
}

// resetChangedBondQualificationChildren invalidates only causal state whose
// immediate membership or effective descendant identity actually changed.
// Bond-wide duty and every stable sibling's ACK/credit history survive.
func (s *bondExecutionState) resetChangedBondQualificationChildren(
	next bondDomainIdentity,
) {
	if s == nil || len(s.qualification) == 0 {
		return
	}
	if s.scratchPreviousDomain == nil {
		s.scratchPreviousDomain = make(map[proto.TargetID]bondQualificationIdentity, len(s.domain.children))
	} else {
		clear(s.scratchPreviousDomain)
	}
	for _, child := range s.domain.children {
		s.scratchPreviousDomain[child.targetID] = child.identity
	}
	reset := func(targetID proto.TargetID) {
		delete(s.qualification, targetID)
		if s.qualificationBurstChild == targetID {
			s.qualificationBurstChild = proto.TargetID{}
			s.qualificationBurstLeft = 0
		}
	}
	for _, child := range next.children {
		previous, existed := s.scratchPreviousDomain[child.targetID]
		if existed && previous.equal(child.identity) {
			delete(s.scratchPreviousDomain, child.targetID)
			continue
		}
		reset(child.targetID)
		delete(s.scratchPreviousDomain, child.targetID)
	}
	for targetID := range s.scratchPreviousDomain {
		reset(targetID)
	}
}

func (s *bondExecutionState) buildBondSchedule(
	domain bondDomainIdentity,
	weights map[proto.TargetID]uint64,
) {
	childCount := len(domain.children)
	if cap(s.scratchScheduleWeights) < childCount {
		s.scratchScheduleWeights = make([]uint64, childCount)
		s.scratchScheduleRemainders = make([]uint64, childCount)
		s.scratchScheduleCurrent = make([]int64, childCount)
	} else {
		s.scratchScheduleWeights = s.scratchScheduleWeights[:childCount]
		s.scratchScheduleRemainders = s.scratchScheduleRemainders[:childCount]
		s.scratchScheduleCurrent = s.scratchScheduleCurrent[:childCount]
		clear(s.scratchScheduleWeights)
		clear(s.scratchScheduleRemainders)
		clear(s.scratchScheduleCurrent)
	}
	var divisor uint64
	for index, child := range domain.children {
		weight := weights[child.targetID]
		s.scratchScheduleWeights[index] = weight
		if weight != 0 {
			divisor = greatestCommonDivisor(divisor, weight)
		}
	}
	if divisor == 0 {
		s.schedule = s.schedule[:0]
		return
	}
	var total uint64
	for index, weight := range s.scratchScheduleWeights {
		weight /= divisor
		s.scratchScheduleWeights[index] = weight
		total += weight
	}
	if total > bondScheduleMaximumSlots {
		rawTotal := sumBondWeights(weights)
		total = 0
		for index, child := range domain.children {
			weight := weights[child.targetID]
			scaled := weight * bondScheduleMaximumSlots
			quota := scaled / rawTotal
			if quota == 0 && weight != 0 {
				quota = 1
			}
			s.scratchScheduleWeights[index] = quota
			s.scratchScheduleRemainders[index] = scaled % rawTotal
			total += quota
		}
		for total > bondScheduleMaximumSlots {
			largest := -1
			for index, quota := range s.scratchScheduleWeights {
				if quota > 1 && (largest < 0 || quota > s.scratchScheduleWeights[largest]) {
					largest = index
				}
			}
			if largest < 0 {
				break
			}
			s.scratchScheduleWeights[largest]--
			total--
		}
		for total < bondScheduleMaximumSlots {
			largest := 0
			for index := 1; index < childCount; index++ {
				if s.scratchScheduleRemainders[index] > s.scratchScheduleRemainders[largest] {
					largest = index
				}
			}
			s.scratchScheduleWeights[largest]++
			s.scratchScheduleRemainders[largest] = 0
			total++
		}
	}
	if cap(s.schedule) < int(total) {
		s.schedule = make([]proto.TargetID, 0, total)
	} else {
		s.schedule = s.schedule[:0]
	}
	for slot := uint64(0); slot < total; slot++ {
		selected := -1
		var best int64
		for index, weight := range s.scratchScheduleWeights {
			if weight == 0 {
				continue
			}
			s.scratchScheduleCurrent[index] += int64(weight)
			if selected < 0 || s.scratchScheduleCurrent[index] > best {
				selected = index
				best = s.scratchScheduleCurrent[index]
			}
		}
		if selected < 0 {
			break
		}
		s.scratchScheduleCurrent[selected] -= int64(total)
		s.schedule = append(s.schedule, domain.children[selected].targetID)
	}
}

func greatestCommonDivisor(left, right uint64) uint64 {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}

func sumBondWeights(weights map[proto.TargetID]uint64) uint64 {
	var total uint64
	for _, weight := range weights {
		total += weight
	}
	return total
}

func (r *executionRuntime) aggregateBondCapacityLocked(
	id proto.TargetID,
	available func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
	scheduling bondSchedulingContext,
) bondCapacityAggregate {
	return r.aggregateBondCapacityScratchLocked(id, available, present, scheduling, 0)
}

func (r *executionRuntime) aggregateBondCapacityScratchLocked(
	id proto.TargetID,
	available func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
	scheduling bondSchedulingContext,
	depth int,
) bondCapacityAggregate {
	if !available(id) {
		return bondCapacityAggregate{}
	}
	node, ok := r.plan.nodeView(id)
	if !ok {
		return bondCapacityAggregate{}
	}
	if depth >= len(r.aggregateScratch) {
		// A validated graph is acyclic and cannot exceed its node count. Keep a
		// defensive slot for synthetic package fixtures that bypass compilation.
		r.aggregateScratch = append(r.aggregateScratch, make([]bondCapacityAggregate, depth-len(r.aggregateScratch)+1)...)
	}
	aggregate := &r.aggregateScratch[depth]
	leaves := aggregate.identity.leaves[:0]
	selectors := aggregate.identity.selectors[:0]
	*aggregate = bondCapacityAggregate{}
	aggregate.identity.leaves = leaves
	aggregate.identity.selectors = selectors
	if node.kind == proto.GraphNodeKindPath {
		static := scheduling.staticWeights[id]
		if static == 0 {
			static = uint64(node.weight)
		}
		if static == 0 {
			static = 1
		}
		effective := scheduling.effectiveWeights[id]
		if effective == 0 {
			effective = static
		}
		leafIdentity := scheduling.leafIdentity[id]
		if leafIdentity.targetID == (proto.TargetID{}) {
			leafIdentity.targetID = id
		}
		aggregate.static = static
		aggregate.effective = effective
		aggregate.observed = scheduling.evidenceAware && scheduling.observed[id]
		aggregate.acked = scheduling.acknowledged[id]
		aggregate.identity.leaves = append(aggregate.identity.leaves, leafIdentity)
		return *aggregate
	}
	if node.kind == proto.GraphNodeKindSelector {
		childID, ok := r.selectorDispatchChildLocked(node, available, present)
		if !ok {
			return bondCapacityAggregate{}
		}
		child := r.aggregateBondCapacityScratchLocked(childID, available, present, scheduling, depth+1)
		aggregate.static = child.static
		aggregate.effective = child.effective
		aggregate.observed = child.observed
		aggregate.ambiguous = child.ambiguous
		aggregate.acked = child.acked
		aggregate.identity.leaves = append(aggregate.identity.leaves, child.identity.leaves...)
		aggregate.identity.selectors = append(aggregate.identity.selectors, child.identity.selectors...)
		state := r.selectors[node.targetID]
		var generation uint64
		if state != nil {
			generation = state.generation
		}
		aggregate.identity.selectors = append(
			aggregate.identity.selectors,
			bondSelectorIdentity{
				selectorID: node.targetID,
				targetID:   childID,
				generation: generation,
			},
		)
		return *aggregate
	}
	allObserved := true
	hasChild := false
	for _, childID := range node.children {
		if !available(childID) {
			continue
		}
		hasChild = true
		child := r.aggregateBondCapacityScratchLocked(childID, available, present, scheduling, depth+1)
		aggregate.identity.leaves = append(aggregate.identity.leaves, child.identity.leaves...)
		aggregate.identity.selectors = append(
			aggregate.identity.selectors, child.identity.selectors...,
		)
		if child.ambiguous {
			aggregate.ambiguous = true
		}
		if !child.observed {
			allObserved = false
		}
		if node.kind == proto.GraphNodeKindRace {
			if child.static > aggregate.static {
				aggregate.static = child.static
			}
			if child.effective > aggregate.effective {
				aggregate.effective = child.effective
			}
			continue
		}
		aggregate.static = saturatingAddUint64(aggregate.static, child.static)
		aggregate.effective = saturatingAddUint64(aggregate.effective, child.effective)
		aggregate.acked = saturatingAddUint64(aggregate.acked, child.acked)
	}
	if node.kind == proto.GraphNodeKindRace && scheduling.evidenceAware {
		if scheduling.observed[id] && scheduling.effectiveWeights[id] != 0 {
			aggregate.effective = scheduling.effectiveWeights[id]
			aggregate.observed = true
			aggregate.ambiguous = false
			return *aggregate
		}
		aggregate.effective = aggregate.static
		aggregate.observed = false
		aggregate.ambiguous = true
		return *aggregate
	}
	aggregate.observed = scheduling.evidenceAware && hasChild && allObserved
	return *aggregate
}

func (r *executionRuntime) bondStuckChildren(
	node executionPlanNode,
	available func(proto.TargetID) bool,
	qualities map[proto.TargetID]transport.PathQuality,
	multiplier float64,
) map[proto.TargetID]bool {
	stuck := make(map[proto.TargetID]bool)
	if len(qualities) == 0 || multiplier >= 1_000_000 {
		return stuck
	}
	if multiplier <= 1 {
		multiplier = 3
	}
	rtts := make(map[proto.TargetID]time.Duration, len(node.children))
	var best time.Duration
	for _, childID := range node.children {
		if !available(childID) {
			continue
		}
		rtt := r.aggregateRTT(childID, available, qualities)
		rtts[childID] = rtt
		if rtt > 0 && (best == 0 || rtt < best) {
			best = rtt
		}
	}
	if best == 0 {
		return stuck
	}
	threshold := time.Duration(float64(best) * multiplier)
	usable := 0
	skipped := uint64(0)
	for _, childID := range node.children {
		if rtt := rtts[childID]; rtt > threshold {
			stuck[childID] = true
			skipped++
		} else if available(childID) {
			usable++
		}
	}
	if usable == 0 {
		return make(map[proto.TargetID]bool)
	}
	r.stuckSkips.Add(skipped)
	return stuck
}

func (r *executionRuntime) aggregateRTT(id proto.TargetID, available func(proto.TargetID) bool, qualities map[proto.TargetID]transport.PathQuality) time.Duration {
	node, ok := r.plan.nodeView(id)
	if !ok || !available(id) {
		return 0
	}
	if node.kind == proto.GraphNodeKindPath {
		return qualities[id].RTT
	}
	if node.kind == proto.GraphNodeKindSelector {
		childID, ok := r.selectorChildLocked(node, available)
		if !ok {
			return 0
		}
		return r.aggregateRTT(childID, available, qualities)
	}
	var aggregate time.Duration
	for _, childID := range node.children {
		rtt := r.aggregateRTT(childID, available, qualities)
		if rtt <= 0 {
			continue
		}
		if node.kind == proto.GraphNodeKindBond {
			if rtt > aggregate {
				aggregate = rtt
			}
		} else if aggregate == 0 || rtt < aggregate {
			aggregate = rtt
		}
	}
	return aggregate
}

var errNoExecutionRoute = fmt.Errorf("engine: no attached path for execution graph")
