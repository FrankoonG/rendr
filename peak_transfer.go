package rendr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
)

const (
	defaultPeakWindow         = 200 * time.Millisecond
	defaultPeakMaximumWindow  = 2 * time.Second
	defaultPeakACKDelay       = 10 * time.Millisecond
	defaultPeakSaturationFor  = 600 * time.Millisecond
	defaultPeakReturnFor      = 800 * time.Millisecond
	defaultPeakSuppressFor    = 5 * time.Second
	defaultPeakSaturation     = 0.95
	defaultPeakReturn         = 0.50
	defaultPeakMinGain        = 0.90
	defaultPeakMinBytes       = 256 << 10
	defaultPeakMinSampleBytes = 32 << 10
	defaultPeakFailureSamples = 2
	peakMaximumLossPP         = 50
	peakMaximumJitter         = 200 * time.Millisecond
	peakQualityFreshFor       = 5 * time.Second
)

type peakTransferController struct {
	e *engine.Engine

	tuning       SelectorTuning
	localTargets peakTransferTargets
	peerTargets  peakTransferTargets
	additional   []*peakTransferController

	mu sync.Mutex
	tx peakTransferDirection
	rx peakTransferDirection
	// peerInitializationErr is the currently active asynchronous initialization
	// failure. A successful retry or controller shutdown clears it.
	peerInitializationErr error
	// policyApplyForTest is installed before concurrent use.
	policyApplyForTest func(bool, peakTransferChoice, proto.TargetID, string) error
	// directionObserveForTest is installed before concurrent use.
	directionObserveForTest func(time.Time, bool)
	// policyRetryReservedForTest is installed before concurrent use.
	policyRetryReservedForTest func(bool, uint64)
	// peerInitializationForTest is installed before concurrent use.
	peerInitializationForTest func(context.Context, proto.TargetID, bool, string) (proto.TargetID, uint64, error)

	ctx      context.Context
	cancel   context.CancelFunc
	stopOnce sync.Once
	workers  sync.WaitGroup
}

type peakTransferChoice uint8

const (
	peakTransferNormal peakTransferChoice = iota + 1
	peakTransferPeak
)

type peakPolicyRetryIntent struct {
	choice             peakTransferChoice
	cause              string
	expectedTarget     proto.TargetID
	expectedGeneration uint64
	expectedPeakTarget proto.TargetID
}

func (intent peakPolicyRetryIntent) valid() bool {
	return (intent.choice == peakTransferNormal || intent.choice == peakTransferPeak) && intent.cause != ""
}

type peakTransferTargets struct {
	selectorID      proto.TargetID
	normalTargetID  proto.TargetID
	normalTargetIDs []proto.TargetID
	peakTargetIDs   []proto.TargetID
}

func peakTargetsFromManifest(manifest proto.GraphManifest) peakTransferTargets {
	root, ok := manifest.Node(manifest.RootID)
	if !ok {
		return peakTransferTargets{}
	}
	return peakTargetsForSelectorNode(root)
}

func peakTargetSetsFromManifest(manifest proto.GraphManifest) []peakTransferTargets {
	targets := make([]peakTransferTargets, 0)
	for _, node := range manifest.Nodes {
		compiled := peakTargetsForSelectorNode(node)
		if compiled.selectorID != (proto.TargetID{}) {
			targets = append(targets, compiled)
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		return bytes.Compare(targets[i].selectorID[:], targets[j].selectorID[:]) < 0
	})
	return targets
}

func orderedPeakTargetSets(manifest proto.GraphManifest) []peakTransferTargets {
	sets := peakTargetSetsFromManifest(manifest)
	root := peakTargetsFromManifest(manifest)
	if root.selectorID == (proto.TargetID{}) {
		return sets
	}
	ordered := make([]peakTransferTargets, 0, len(sets))
	ordered = append(ordered, root)
	for _, targets := range sets {
		if targets.selectorID != root.selectorID {
			ordered = append(ordered, targets)
		}
	}
	return ordered
}

func peakTargetsForSelectorNode(selector proto.GraphNode) peakTransferTargets {
	if selector.Kind != proto.GraphNodeKindSelector || len(selector.PeakCandidates) == 0 {
		return peakTransferTargets{}
	}
	peaks := make(map[proto.TargetID]struct{}, len(selector.PeakCandidates))
	for _, id := range selector.PeakCandidates {
		peaks[id] = struct{}{}
	}
	targets := peakTransferTargets{selectorID: selector.ID}
	for _, id := range selector.Children {
		if _, peak := peaks[id]; peak {
			targets.peakTargetIDs = append(targets.peakTargetIDs, id)
			continue
		}
		targets.normalTargetIDs = append(targets.normalTargetIDs, id)
		if targets.normalTargetID == (proto.TargetID{}) {
			targets.normalTargetID = id
		}
	}
	return targets
}

func (t peakTransferTargets) selection(choice peakTransferChoice) (proto.TargetID, proto.TargetID, bool) {
	if t.selectorID == (proto.TargetID{}) {
		return proto.TargetID{}, proto.TargetID{}, false
	}
	switch choice {
	case peakTransferNormal:
		return t.selectorID, t.normalTargetID, t.normalTargetID != (proto.TargetID{})
	case peakTransferPeak:
		if len(t.peakTargetIDs) != 0 {
			return t.selectorID, t.peakTargetIDs[0], true
		}
	}
	return proto.TargetID{}, proto.TargetID{}, false
}

type peakDeliveryCursor struct {
	valid              bool
	targetID           proto.TargetID
	selectorID         proto.TargetID
	selectorGeneration uint64
	evidenceEpoch      uint64
	bytes              uint64
	demandBytes        uint64
	at                 time.Time
}

type peakCapacityObservation struct {
	targetID   proto.TargetID
	bytes      uint64
	demand     uint64
	duration   time.Duration
	bps        float64
	conclusive bool
	success    bool
}

type peakTransferDirection struct {
	onPeak                   bool
	activePeakTarget         proto.TargetID
	actualTarget             proto.TargetID
	actualSelectorGeneration uint64
	phaseGeneration          uint64
	normalPeakBps            float64
	normalBytes              uint64
	peakVerified             bool
	peakStarted              time.Time
	peakStartedFromCommit    bool
	demandSuppressUntil      time.Time
	candidateSuppressUntil   map[proto.TargetID]time.Time
	policyRetryAfter         time.Time
	policyRetryDelay         time.Duration
	lastPolicyError          string
	saturatedSince           time.Time
	returnSince              time.Time
	policyOutcomeUncertain   bool
	promotionRetryPending    bool
	policyRetryIntent        peakPolicyRetryIntent
	cursor                   peakDeliveryCursor
	lastObservation          peakCapacityObservation
	capacityFailureTarget    proto.TargetID
	capacityFailureSamples   uint8
}

func newPeakTransferController(e *engine.Engine, plan compiledTarget) *peakTransferController {
	ctx, cancel := context.WithCancel(context.Background())
	c := &peakTransferController{
		e: e, tuning: plan.runtimeConfig.Selector,
		ctx: ctx, cancel: cancel,
	}
	localSets := orderedPeakTargetSets(plan.graph.manifest)
	peerSets := orderedPeakTargetSets(e.PeerGraphManifest())
	count := len(localSets)
	if len(peerSets) > count {
		count = len(peerSets)
	}
	for index := 0; index < count; index++ {
		member := c
		if index != 0 {
			member = &peakTransferController{
				e: e, tuning: plan.runtimeConfig.Selector, ctx: ctx, cancel: cancel,
			}
			c.additional = append(c.additional, member)
		}
		if index < len(localSets) {
			member.localTargets = localSets[index]
		}
		if index < len(peerSets) {
			member.peerTargets = peerSets[index]
		}
	}
	return c
}

func (c *peakTransferController) start() error {
	if c == nil || c.e == nil {
		return nil
	}
	members := c.members()
	active := false
	for _, member := range members {
		if selectorID, targetID, ok := member.localTargets.selection(peakTransferNormal); ok {
			active = true
			if err := c.e.InitializePolicySelection(selectorID, targetID, "selector"); err != nil {
				c.cancel()
				return fmt.Errorf("rendr: initialize local PeakTransfer selection: %w", err)
			}
		}
		if _, _, ok := member.peerTargets.selection(peakTransferNormal); ok {
			active = true
		}
	}
	if !active {
		return nil
	}
	c.e.SetPeerPolicyAdmission(c.admitPeerSelection)
	c.e.SetPeakPolicyObserver(c.observeCommittedPeakPolicy)
	c.e.StartSelector(0)
	for _, member := range members {
		if _, _, ok := member.localTargets.selection(peakTransferNormal); ok {
			c.workers.Add(1)
			go func(worker *peakTransferController) {
				defer c.workers.Done()
				worker.directionLoop(false, proto.TargetID{})
			}(member)
		}
		if peerSelectorID, _, ok := member.peerTargets.selection(peakTransferNormal); ok {
			c.workers.Add(1)
			go func(worker *peakTransferController, selectorID proto.TargetID) {
				defer c.workers.Done()
				worker.directionLoop(true, selectorID)
			}(member, peerSelectorID)
		}
	}
	return nil
}

func (c *peakTransferController) members() []*peakTransferController {
	if c == nil {
		return nil
	}
	members := make([]*peakTransferController, 0, 1+len(c.additional))
	members = append(members, c)
	members = append(members, c.additional...)
	return members
}

func (c *peakTransferController) stopLoop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.e != nil {
			c.e.SetPeerPolicyAdmission(nil)
			c.e.SetPeakPolicyObserver(nil)
		}
	})
	c.workers.Wait()
	for _, member := range c.members() {
		member.mu.Lock()
		member.peerInitializationErr = nil
		member.mu.Unlock()
	}
}

type peakPeerInitialization struct {
	selectorID      proto.TargetID
	phaseGeneration uint64
	retryDelay      time.Duration
	retryAt         time.Time
	active          bool
}

func (c *peakTransferController) directionLoop(rx bool, peerSelectorID proto.TargetID) {
	ticker := time.NewTicker(defaultPeakWindow)
	defer ticker.Stop()
	initialization := peakPeerInitialization{}
	if rx && peerSelectorID != (proto.TargetID{}) {
		initialization = peakPeerInitialization{
			selectorID:      peerSelectorID,
			phaseGeneration: c.directionPhase(true),
			retryDelay:      defaultPeakWindow,
			active:          true,
		}
		c.advancePeerInitialization(&initialization, time.Now())
	}
	for {
		select {
		case <-c.policyContext().Done():
			return
		case <-c.e.Closed():
			if c.cancel != nil {
				c.cancel()
			}
			return
		case <-ticker.C:
			now := time.Now()
			c.runDirectionTick(now, rx)
			if rx {
				c.advancePeerInitialization(&initialization, time.Now())
			}
		}
	}
}

func (c *peakTransferController) runDirectionTick(now time.Time, rx bool) {
	c.retryPendingPolicy(now, rx)
	if c.directionObserveForTest != nil {
		c.directionObserveForTest(now, rx)
		return
	}
	c.observeDelivery(now, rx)
}

func (c *peakTransferController) retryPendingPolicy(now time.Time, rx bool) bool {
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
	}
	intent := state.policyRetryIntent
	if !intent.valid() || now.Before(state.policyRetryAfter) {
		c.mu.Unlock()
		return false
	}
	if state.actualTarget != intent.expectedTarget ||
		state.actualSelectorGeneration != intent.expectedGeneration ||
		(intent.choice == peakTransferPeak && state.onPeak) ||
		(intent.choice == peakTransferNormal &&
			(!state.onPeak || state.activePeakTarget != intent.expectedPeakTarget)) {
		state.clearPolicyRetry()
		c.mu.Unlock()
		return false
	}
	excluded := make([]proto.TargetID, 0)
	if intent.choice == peakTransferPeak {
		targets := c.localTargets.peakTargetIDs
		if rx {
			targets = c.peerTargets.peakTargetIDs
		}
		for _, targetID := range targets {
			if state.peakTargetSuppressed(targetID, now) {
				excluded = append(excluded, targetID)
			}
		}
	}
	failedTarget := state.activePeakTarget
	state.policyRetryIntent = peakPolicyRetryIntent{}
	state.policyOutcomeUncertain = false
	intentPhase := c.reservePolicyIntentLocked(state, rx)
	c.mu.Unlock()
	if c.policyRetryReservedForTest != nil {
		c.policyRetryReservedForTest(rx, intentPhase)
	}

	var (
		err error
	)
	if intent.choice == peakTransferPeak {
		_, _, err = c.beginPeakObservationAtPhase(rx, excluded, intent.cause, intentPhase)
	} else {
		_, _, err = c.applyPolicyTransitionAtPhase(
			rx, peakTransferNormal, proto.TargetID{}, intent.cause, intentPhase,
		)
	}
	completedAt := time.Now()
	c.mu.Lock()
	state = &c.tx
	if rx {
		state = &c.rx
	}
	if state.phaseGeneration != intentPhase {
		c.mu.Unlock()
		return true
	}
	if err != nil {
		state.recordPolicyFailure(err, completedAt, intent.choice, intent.cause)
		if intent.choice == peakTransferPeak {
			state.promotionRetryPending = state.policyRetryIntent.valid()
		}
		c.mu.Unlock()
		return true
	}
	state.clearPolicyRetry()
	if intent.choice == peakTransferPeak {
		state.promotionRetryPending = false
		c.mu.Unlock()
		return true
	}
	state.resetAfterReturn()
	if peakVerificationFailed(intent.cause) {
		state.suppressPeakTarget(failedTarget, completedAt.Add(defaultPeakSuppressFor))
	} else {
		state.demandSuppressUntil = completedAt.Add(defaultPeakSuppressFor)
	}
	c.mu.Unlock()
	return true
}

func (c *peakTransferController) advancePeerInitialization(
	initialization *peakPeerInitialization,
	now time.Time,
) {
	if initialization == nil || !initialization.active {
		return
	}
	c.mu.Lock()
	if c.rx.phaseGeneration != initialization.phaseGeneration {
		initialization.active = false
		c.peerInitializationErr = nil
		c.mu.Unlock()
		return
	}
	if !initialization.retryAt.IsZero() && now.Before(initialization.retryAt) {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	targetID, generation, err := c.requestPeerInitialization(
		c.policyContext(), initialization.selectorID,
	)
	completedAt := time.Now()
	if c.policyContext().Err() != nil || (c.e != nil && c.e.IsClosed()) {
		initialization.active = false
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rx.phaseGeneration != initialization.phaseGeneration {
		initialization.active = false
		c.peerInitializationErr = nil
		return
	}
	if err == nil {
		notePeerPolicyCommitLocked(&c.rx, targetID, generation)
		initialization.active = false
		c.peerInitializationErr = nil
		return
	}
	c.peerInitializationErr = err
	if errors.Is(err, engine.ErrPolicyOutcomeUnknown) {
		initialization.active = false
		c.rx.policyOutcomeUncertain = true
		c.rx.policyRetryAfter = completedAt.Add(defaultPeakWindow)
		return
	}
	if errors.Is(err, engine.ErrPolicyRejected) && !engine.IsRetryablePolicyRejection(err) {
		initialization.active = false
		return
	}
	initialization.retryAt = completedAt.Add(initialization.retryDelay)
	if initialization.retryDelay < defaultPeakSuppressFor {
		initialization.retryDelay *= 2
		if initialization.retryDelay > defaultPeakSuppressFor {
			initialization.retryDelay = defaultPeakSuppressFor
		}
	}
}

func (c *peakTransferController) requestPeerInitialization(
	ctx context.Context,
	selectorID proto.TargetID,
) (proto.TargetID, uint64, error) {
	if c.peerInitializationForTest != nil {
		return c.peerInitializationForTest(ctx, selectorID, false, "selector-rx")
	}
	if c.e == nil {
		return proto.TargetID{}, 0, errors.New("rendr: peer selector is unavailable")
	}
	return c.e.RequestPeerSelectionClass(ctx, selectorID, false, "selector-rx")
}

func (c *peakTransferController) directionPhase(rx bool) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rx {
		return c.rx.phaseGeneration
	}
	return c.tx.phaseGeneration
}

func (c *peakTransferController) markPolicyIntent(rx bool) uint64 {
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
	}
	phase := c.reservePolicyIntentLocked(state, rx)
	c.mu.Unlock()
	return phase
}

func (c *peakTransferController) reservePolicyIntentLocked(
	state *peakTransferDirection,
	rx bool,
) uint64 {
	if rx {
		c.peerInitializationErr = nil
	}
	advancePeakDirectionPhaseLocked(state)
	return state.phaseGeneration
}

func advancePeakDirectionPhaseLocked(state *peakTransferDirection) {
	state.phaseGeneration++
	if state.phaseGeneration == 0 {
		state.phaseGeneration++
	}
}

func (c *peakTransferController) policyContext() context.Context {
	if c != nil && c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *peakTransferController) statusIssues() []StatusIssue {
	if c == nil {
		return nil
	}
	issues := make([]StatusIssue, 0)
	for _, member := range c.members() {
		member.mu.Lock()
		err := member.peerInitializationErr
		member.mu.Unlock()
		if err == nil {
			continue
		}
		id := StatusIssuePeerPolicyInitialization
		if errors.Is(err, engine.ErrPolicyOutcomeUnknown) {
			id = StatusIssuePeerPolicyOutcomeUnknown
		}
		issues = append(issues, StatusIssue{ID: id, LastError: err.Error()})
	}
	return issues
}

func (c *peakTransferController) admitPeerSelection(selectorID, targetID proto.TargetID, _ string) error {
	for _, member := range c.members() {
		if member.localTargets.selectorID != selectorID {
			continue
		}
		return member.admitPeerSelectionOne(selectorID, targetID)
	}
	return nil
}

func (c *peakTransferController) admitPeerSelectionOne(selectorID, targetID proto.TargetID) error {
	wantSelector, _, ok := c.localTargets.selection(peakTransferPeak)
	if !ok || selectorID != wantSelector || !c.localTargets.isPeakTarget(targetID) {
		return nil
	}
	c.mu.Lock()
	now := time.Now()
	suppressed := c.tx.policyOutcomeUncertain || now.Before(c.tx.demandSuppressUntil) ||
		c.tx.peakTargetSuppressed(targetID, now)
	c.mu.Unlock()
	if suppressed {
		return fmt.Errorf("rendr: local peak target is temporarily suppressed")
	}
	if !localPeakTransferTargetHealthy(c.e, targetID) {
		return fmt.Errorf("rendr: local peak target has no fresh healthy quality evidence")
	}
	return nil
}

type listenerPeakTransferAdmission struct {
	mu         sync.Mutex
	e          *engine.Engine
	targets    peakTransferTargets
	state      peakTransferDirection
	additional []*listenerPeakTransferAdmission
}

// installPeakTransferPeerAdmission gives a listener-owned sender the same
// factual peak-candidate health gate as a dialing sender. Class ranking and
// final target selection remain entirely owned by that peer engine.
func installPeakTransferPeerAdmission(e *engine.Engine) *listenerPeakTransferAdmission {
	if e == nil {
		return nil
	}
	targetSets := orderedPeakTargetSets(e.LocalGraphManifest())
	if len(targetSets) == 0 {
		return nil
	}
	admission := &listenerPeakTransferAdmission{e: e, targets: targetSets[0]}
	for _, targets := range targetSets[1:] {
		admission.additional = append(admission.additional, &listenerPeakTransferAdmission{
			e: e, targets: targets,
		})
	}
	e.SetPeerPolicyAdmission(admission.admit)
	e.SetPeakPolicyObserver(admission.observe)
	return admission
}

func (a *listenerPeakTransferAdmission) members() []*listenerPeakTransferAdmission {
	if a == nil {
		return nil
	}
	members := make([]*listenerPeakTransferAdmission, 0, 1+len(a.additional))
	members = append(members, a)
	members = append(members, a.additional...)
	return members
}

func (a *listenerPeakTransferAdmission) admit(
	selectorID, targetID proto.TargetID,
	_ string,
) error {
	for _, member := range a.members() {
		if selectorID == member.targets.selectorID {
			return member.admitOne(selectorID, targetID)
		}
	}
	return nil
}

func (a *listenerPeakTransferAdmission) admitOne(selectorID, targetID proto.TargetID) error {
	if selectorID != a.targets.selectorID || !a.targets.isPeakTarget(targetID) {
		return nil
	}
	if a.e != nil {
		_, effective, generation, ok := a.e.SelectorSelection(a.targets.selectorID)
		if ok {
			a.mu.Lock()
			reconcilePeakDirectionLocked(&a.state, a.targets, effective, generation)
			a.mu.Unlock()
		}
	}
	a.mu.Lock()
	suppressed := a.state.peakTargetSuppressed(targetID, time.Now())
	a.mu.Unlock()
	if suppressed {
		return fmt.Errorf("rendr: local peak target is temporarily suppressed")
	}
	if a.e != nil && !localPeakTransferTargetHealthy(a.e, targetID) {
		return fmt.Errorf("rendr: local peak target has no fresh healthy quality evidence")
	}
	return nil
}

func localPeakTransferTargetHealthy(e *engine.Engine, targetID proto.TargetID) bool {
	if e == nil || targetID == (proto.TargetID{}) {
		return false
	}
	manifest := e.LocalGraphManifest()
	pathNames := descendantPathNames(manifest, targetID)
	if len(pathNames) == 0 {
		return false
	}
	now := time.Now()
	attached := false
	measured := false
	for _, path := range e.Paths() {
		if !pathNames[pathSpecName(path.Spec)] {
			continue
		}
		attached = true
		quality := path.Quality
		if quality.At.IsZero() && quality.RTT == 0 && quality.Jitter == 0 && quality.LossPP == 0 {
			return true
		}
		measured = true
		if !quality.At.IsZero() &&
			(quality.At.After(now) || now.Sub(quality.At) > peakQualityFreshFor) {
			continue
		}
		if quality.LossPP <= peakMaximumLossPP && quality.Jitter <= peakMaximumJitter {
			return true
		}
	}
	return attached && !measured
}

func descendantPathNames(manifest proto.GraphManifest, targetID proto.TargetID) map[string]bool {
	paths := make(map[string]bool)
	seen := make(map[proto.TargetID]bool)
	pending := []proto.TargetID{targetID}
	for len(pending) != 0 {
		last := len(pending) - 1
		id := pending[last]
		pending = pending[:last]
		if seen[id] {
			continue
		}
		seen[id] = true
		node, ok := manifest.Node(id)
		if !ok {
			continue
		}
		if node.Kind == proto.GraphNodeKindPath {
			paths[node.Name] = true
			continue
		}
		pending = append(pending, node.Children...)
	}
	return paths
}

func (a *listenerPeakTransferAdmission) observe(
	selectorID, targetID proto.TargetID,
	selectorGeneration uint64,
	peak bool,
	cause string,
) {
	for _, member := range a.members() {
		if selectorID == member.targets.selectorID {
			member.observeOne(selectorID, targetID, selectorGeneration, peak, cause)
			return
		}
	}
}

func (a *listenerPeakTransferAdmission) observeOne(
	selectorID, targetID proto.TargetID,
	selectorGeneration uint64,
	peak bool,
	cause string,
) {
	a.mu.Lock()
	if !peakDirectionGenerationAccepts(&a.state, targetID, selectorGeneration) {
		a.mu.Unlock()
		return
	}
	failedTarget := a.state.activePeakTarget
	reconcilePeakDirectionLocked(&a.state, a.targets, targetID, selectorGeneration)
	if !peak && peakVerificationFailed(cause) {
		a.state.suppressPeakTarget(failedTarget, time.Now().Add(defaultPeakSuppressFor))
	}
	a.mu.Unlock()
}

func (c *peakTransferController) observeDelivery(now time.Time, rx bool) {
	if !rx {
		_, effective, generation, ok := c.e.SelectorSelection(c.localTargets.selectorID)
		if ok {
			c.reconcileActualTarget(false, c.localTargets.selectorID, effective, generation)
		}
	}
	var snapshot engine.TargetDeliverySnapshot
	if rx {
		snapshot = c.e.PeerTargetDeliveryForSelector(c.peerTargets.selectorID, proto.TargetID{})
	} else {
		snapshot = c.e.TargetApplicationDeliveryForSelector(c.localTargets.selectorID, proto.TargetID{})
	}
	if snapshot.SelectorID == (proto.TargetID{}) || snapshot.TargetID == (proto.TargetID{}) ||
		snapshot.SelectorGeneration == 0 || snapshot.EvidenceEpoch == 0 || !snapshot.Attributable {
		if !rx && snapshot.SelectorID != (proto.TargetID{}) && snapshot.TargetID != (proto.TargetID{}) &&
			snapshot.SelectorGeneration != 0 && snapshot.EvidenceEpoch != 0 {
			pending := c.e.ApplicationDelivery().PendingPayloadBytes
			c.observeUnattributableTXIdle(now, snapshot, pending)
			return
		}
		c.resetDeliveryCursor(rx)
		return
	}
	targets := c.localTargets
	if rx {
		targets = c.peerTargets
	}
	if snapshot.SelectorID != targets.selectorID {
		c.resetDeliveryCursor(rx)
		return
	}
	c.reconcileActualTarget(rx, snapshot.SelectorID, snapshot.TargetID, snapshot.SelectorGeneration)

	window := c.observationWindow(rx, snapshot.TargetID)
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
	}
	cursor := &state.cursor
	if !cursor.matches(snapshot) {
		*cursor = cursorFromDelivery(snapshot, now)
		if state.onPeak {
			state.returnSince = time.Time{}
		}
		c.mu.Unlock()
		return
	}
	elapsed := now.Sub(cursor.at)
	if elapsed < window {
		c.mu.Unlock()
		return
	}
	if snapshot.AckedBytes < cursor.bytes || snapshot.DemandBytes < cursor.demandBytes {
		*cursor = cursorFromDelivery(snapshot, now)
		c.mu.Unlock()
		return
	}
	bytes := snapshot.AckedBytes - cursor.bytes
	demand := snapshot.DemandBytes - cursor.demandBytes
	*cursor = cursorFromDelivery(snapshot, now)
	c.mu.Unlock()

	bps := 0.0
	if elapsed > 0 {
		bps = float64(bytes) * 8 / elapsed.Seconds()
	}
	c.evaluatePassiveWithPending(
		now, bytes, demand, bps, elapsed, snapshot.TargetID,
		snapshot.PublishedBytes > snapshot.AckedBytes, rx,
	)
}

// observeUnattributableTXIdle handles a narrow post-replay state: unique DATA
// was delivered, but cross-root replay correctly invalidated target-specific
// attribution. A stable identity/epoch plus an empty application replay ledger
// proves that demand is idle without pretending the replay belonged to the
// peak target. RX has no equivalent sender-side pending-byte proof and never
// enters this path.
func (c *peakTransferController) observeUnattributableTXIdle(
	now time.Time,
	snapshot engine.TargetDeliverySnapshot,
	pendingPayloadBytes uint64,
) {
	c.mu.Lock()
	state := &c.tx
	identityCurrent := state.onPeak && state.activePeakTarget == snapshot.TargetID &&
		state.actualTarget == snapshot.TargetID &&
		state.actualSelectorGeneration == snapshot.SelectorGeneration &&
		c.localTargets.selectorID == snapshot.SelectorID
	if !identityCurrent || pendingPayloadBytes != 0 {
		state.cursor = peakDeliveryCursor{}
		state.returnSince = time.Time{}
		c.mu.Unlock()
		return
	}
	if !state.cursor.matches(snapshot) {
		state.cursor = cursorFromDelivery(snapshot, now)
		state.returnSince = time.Time{}
		c.mu.Unlock()
		return
	}
	elapsed := now.Sub(state.cursor.at)
	if elapsed < c.observationWindow(false, snapshot.TargetID) {
		c.mu.Unlock()
		return
	}
	state.cursor = cursorFromDelivery(snapshot, now)
	c.mu.Unlock()
	c.evaluatePassiveWithPending(now, 0, 0, 0, elapsed, snapshot.TargetID, false, false)
}

func (c *peakTransferController) reconcileActualTarget(
	rx bool,
	selectorID, targetID proto.TargetID,
	selectorGeneration uint64,
) {
	targets := c.localTargets
	if rx {
		targets = c.peerTargets
	}
	if selectorID != targets.selectorID ||
		(!targets.isNormalTarget(targetID) && !targets.isPeakTarget(targetID)) {
		return
	}
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
	}
	changed := reconcilePeakDirectionLocked(state, targets, targetID, selectorGeneration)
	if changed {
		advancePeakDirectionPhaseLocked(state)
		if rx {
			c.peerInitializationErr = nil
		}
	}
	c.mu.Unlock()
}

func reconcilePeakDirectionLocked(
	state *peakTransferDirection,
	targets peakTransferTargets,
	targetID proto.TargetID,
	selectorGeneration uint64,
) bool {
	if state == nil || targetID == (proto.TargetID{}) {
		return false
	}
	if !peakDirectionGenerationAccepts(state, targetID, selectorGeneration) {
		return false
	}
	changed := state.actualTarget != targetID ||
		(selectorGeneration != 0 && state.actualSelectorGeneration != selectorGeneration)
	if changed {
		state.clearPolicyRetry()
	}
	if selectorGeneration != 0 {
		state.actualSelectorGeneration = selectorGeneration
	}
	state.actualTarget = targetID
	if targets.isPeakTarget(targetID) {
		if !state.onPeak || state.activePeakTarget != targetID {
			state.onPeak = true
			state.activePeakTarget = targetID
			state.peakVerified = false
			state.peakStarted = time.Now()
			state.peakStartedFromCommit = true
			state.returnSince = time.Time{}
			state.cursor = peakDeliveryCursor{}
			state.promotionRetryPending = false
			state.resetCapacityFailureEvidence()
			changed = true
		}
		return changed
	}
	if targets.isNormalTarget(targetID) && (state.onPeak || state.activePeakTarget != (proto.TargetID{})) {
		state.resetAfterReturn()
		changed = true
	}
	return changed
}

func peakDirectionGenerationAccepts(
	state *peakTransferDirection,
	targetID proto.TargetID,
	selectorGeneration uint64,
) bool {
	if state == nil || targetID == (proto.TargetID{}) {
		return false
	}
	if selectorGeneration == 0 {
		return state.actualSelectorGeneration == 0
	}
	if state.actualSelectorGeneration == 0 {
		return true
	}
	return selectorGeneration > state.actualSelectorGeneration ||
		(selectorGeneration == state.actualSelectorGeneration &&
			(state.actualTarget == (proto.TargetID{}) || state.actualTarget == targetID))
}

func notePeerPolicyCommitLocked(
	state *peakTransferDirection,
	targetID proto.TargetID,
	generation uint64,
) {
	if state == nil || targetID == (proto.TargetID{}) || generation == 0 ||
		(state.actualSelectorGeneration != 0 &&
			(generation < state.actualSelectorGeneration ||
				(generation == state.actualSelectorGeneration &&
					state.actualTarget != (proto.TargetID{}) && state.actualTarget != targetID))) {
		return
	}
	state.actualTarget = targetID
	state.actualSelectorGeneration = generation
}

func (c *peakTransferController) resetDeliveryCursor(rx bool) {
	c.mu.Lock()
	if rx {
		c.rx.cursor = peakDeliveryCursor{}
		c.rx.resetCapacityFailureEvidence()
	} else {
		c.tx.cursor = peakDeliveryCursor{}
		c.tx.resetCapacityFailureEvidence()
	}
	c.mu.Unlock()
}

func cursorFromDelivery(snapshot engine.TargetDeliverySnapshot, now time.Time) peakDeliveryCursor {
	return peakDeliveryCursor{
		valid: true, targetID: snapshot.TargetID, selectorID: snapshot.SelectorID,
		selectorGeneration: snapshot.SelectorGeneration, evidenceEpoch: snapshot.EvidenceEpoch,
		bytes: snapshot.AckedBytes, demandBytes: snapshot.DemandBytes, at: now,
	}
}

func (c peakDeliveryCursor) matches(snapshot engine.TargetDeliverySnapshot) bool {
	return c.valid && c.targetID == snapshot.TargetID && c.selectorID == snapshot.SelectorID &&
		c.selectorGeneration == snapshot.SelectorGeneration && c.evidenceEpoch == snapshot.EvidenceEpoch
}

func (c *peakTransferController) observationWindow(rx bool, targetID proto.TargetID) time.Duration {
	var rtt, jitter time.Duration
	var ok bool
	if rx {
		rtt, jitter, ok = c.e.PeerTargetTiming(targetID)
	} else {
		rtt, jitter, ok = c.e.LocalTargetTiming(targetID)
	}
	if !ok {
		return defaultPeakMaximumWindow
	}
	window := 4*rtt + 2*jitter + defaultPeakACKDelay
	if window < defaultPeakWindow {
		window = defaultPeakWindow
	}
	if window > defaultPeakMaximumWindow {
		window = defaultPeakMaximumWindow
	}
	return window
}

// evaluate is retained as a deterministic state-machine test surface. Real
// traffic uses evaluatePassive with engine-confirmed demand bytes.
func (c *peakTransferController) evaluate(now time.Time, bytes uint64, bps float64, rx bool) {
	c.evaluatePassive(now, bytes, bytes, bps, defaultPeakWindow, proto.TargetID{}, rx)
}

func (c *peakTransferController) evaluatePassive(
	now time.Time,
	bytes, demand uint64,
	bps float64,
	duration time.Duration,
	targetID proto.TargetID,
	rx bool,
) {
	c.evaluatePassiveWithPending(now, bytes, demand, bps, duration, targetID, false, rx)
}

func (c *peakTransferController) evaluatePassiveWithPending(
	now time.Time,
	bytes, demand uint64,
	bps float64,
	duration time.Duration,
	targetID proto.TargetID,
	pending bool,
	rx bool,
) {
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
	}
	if state.policyOutcomeUncertain {
		if state.policyRetryAfter.IsZero() || now.Before(state.policyRetryAfter) {
			c.mu.Unlock()
			return
		}
		// An unknown result is returned only after the bounded wire
		// transaction reaches its deadline. Re-entering after a short backoff
		// safely reconciles through either a stale-generation rejection or a
		// newly accepted transaction instead of freezing this direction.
		state.policyOutcomeUncertain = false
		state.lastPolicyError = ""
		state.policyRetryAfter = time.Time{}
	}
	if !state.onPeak {
		c.evaluateNormalLocked(now, bytes, demand, bps, duration, rx, state)
		return
	}
	c.evaluatePeakLocked(now, bytes, demand, bps, duration, targetID, pending, rx, state)
}

func (c *peakTransferController) evaluateNormalLocked(
	now time.Time,
	bytes, demand uint64,
	bps float64,
	duration time.Duration,
	rx bool,
	state *peakTransferDirection,
) {
	if demand == 0 || bytes == 0 || bps <= 0 {
		state.saturatedSince = time.Time{}
		state.promotionRetryPending = false
		c.mu.Unlock()
		return
	}
	state.normalBytes = saturatingAdd(state.normalBytes, demand)
	if state.normalPeakBps <= 0 {
		state.normalPeakBps = bps
	} else {
		state.normalPeakBps = 0.75*state.normalPeakBps + 0.25*bps
	}
	if state.normalBytes < defaultPeakMinBytes || demand < defaultPeakMinSampleBytes {
		c.mu.Unlock()
		return
	}
	ratio := defaultPeakSaturation
	if bps < state.normalPeakBps*ratio && !state.promotionRetryPending {
		state.saturatedSince = time.Time{}
		c.mu.Unlock()
		return
	}
	if state.saturatedSince.IsZero() {
		state.saturatedSince = now.Add(-duration)
	}
	needFor := c.tuning.PeakPromoteAfter
	if needFor <= 0 {
		needFor = defaultPeakSaturationFor
	}
	if now.Sub(state.saturatedSince) < needFor || now.Before(state.demandSuppressUntil) ||
		now.Before(state.policyRetryAfter) {
		c.mu.Unlock()
		return
	}
	targets := c.localTargets.peakTargetIDs
	if rx {
		targets = c.peerTargets.peakTargetIDs
	}
	excluded := make([]proto.TargetID, 0, len(targets))
	excludedSet := make(map[proto.TargetID]bool, len(targets))
	for _, candidate := range targets {
		if state.peakTargetSuppressed(candidate, now) {
			excluded = append(excluded, candidate)
			excludedSet[candidate] = true
			continue
		}
	}
	state.saturatedSince = time.Time{}
	c.mu.Unlock()
	if !rx && c.policyApplyForTest == nil {
		for _, candidate := range targets {
			if excludedSet[candidate] || localPeakTransferTargetHealthy(c.e, candidate) {
				continue
			}
			excluded = append(excluded, candidate)
			excludedSet[candidate] = true
		}
	}
	if len(excludedSet) == len(targets) {
		return
	}
	_, intentPhase, err := c.beginPeakObservation(rx, excluded, "peak-transfer")
	completedAt := time.Now()
	c.mu.Lock()
	state = &c.tx
	if rx {
		state = &c.rx
	}
	if state.phaseGeneration != intentPhase {
		c.mu.Unlock()
		return
	}
	if err != nil {
		state.recordPolicyFailure(err, completedAt, peakTransferPeak, "peak-transfer")
		state.promotionRetryPending = state.policyRetryIntent.valid()
		if state.promotionRetryPending {
			state.saturatedSince = completedAt.Add(-needFor)
		}
	} else {
		state.clearPolicyRetry()
	}
	c.mu.Unlock()
}

func (c *peakTransferController) evaluatePeakLocked(
	now time.Time,
	bytes, demand uint64,
	bps float64,
	duration time.Duration,
	targetID proto.TargetID,
	pending bool,
	rx bool,
	state *peakTransferDirection,
) {
	if targetID != (proto.TargetID{}) && state.activePeakTarget != (proto.TargetID{}) &&
		targetID != state.activePeakTarget {
		// observeDelivery already reconciled this sample with its exact wire
		// selector generation. A capacity window does not carry that proof, so
		// it may invalidate its cursor but must never overwrite factual policy
		// state with a stale target.
		state.cursor = peakDeliveryCursor{}
		c.mu.Unlock()
		return
	}
	if state.peakStarted.IsZero() {
		state.peakStarted = now.Add(-duration)
	}
	if state.peakStartedFromCommit && (demand != 0 || pending) {
		if now.Sub(state.peakStarted) < defaultPeakSaturationFor {
			state.returnSince = time.Time{}
			c.mu.Unlock()
			return
		}
	}
	sampled, success := peakCapacitySampleVerdict(bytes, demand, bps, duration, state.normalPeakBps, pending)
	conclusive := sampled && success
	if sampled && !success {
		if state.capacityFailureTarget != state.activePeakTarget {
			state.resetCapacityFailureEvidence()
			state.capacityFailureTarget = state.activePeakTarget
		}
		if state.capacityFailureSamples < ^uint8(0) {
			state.capacityFailureSamples++
		}
		conclusive = state.capacityFailureSamples >= defaultPeakFailureSamples ||
			duration >= defaultPeakSaturationFor
		state.lastObservation = peakCapacityObservation{
			targetID: state.activePeakTarget, bytes: bytes, demand: demand,
			duration: duration, bps: bps, conclusive: conclusive,
		}
		if !conclusive {
			// One low window can be the partial window immediately after a
			// policy cutover. It is active demand, not an idle-return signal.
			state.returnSince = time.Time{}
			c.mu.Unlock()
			return
		}
	} else if sampled {
		state.resetCapacityFailureEvidence()
	} else if !pending {
		state.resetCapacityFailureEvidence()
	}
	if conclusive {
		state.lastObservation = peakCapacityObservation{
			targetID: state.activePeakTarget, bytes: bytes, demand: demand,
			duration: duration, bps: bps, conclusive: true, success: success,
		}
		if !success {
			if now.Before(state.policyRetryAfter) {
				c.mu.Unlock()
				return
			}
			failedTarget := state.activePeakTarget
			state.policyRetryIntent = peakPolicyRetryIntent{}
			c.mu.Unlock()
			_, intentPhase, err := c.applyPolicyTransition(rx, peakTransferNormal, proto.TargetID{}, "peak-verify-failed")
			completedAt := time.Now()
			c.mu.Lock()
			state = &c.tx
			if rx {
				state = &c.rx
			}
			if state.phaseGeneration != intentPhase {
				c.mu.Unlock()
				return
			}
			if err != nil {
				state.recordPolicyFailure(
					err, completedAt, peakTransferNormal, "peak-verify-failed",
				)
				c.mu.Unlock()
				return
			}
			state.resetAfterReturn()
			state.suppressPeakTarget(failedTarget, completedAt.Add(defaultPeakSuppressFor))
			c.mu.Unlock()
			return
		}
		state.peakVerified = true
	}
	if !conclusive && pending {
		// Published-but-unacknowledged application DATA is active demand, not
		// evidence that demand fell. A slow candidate must get a demand-backed
		// capacity sample before an ACK-silent window can return it as idle.
		state.returnSince = time.Time{}
		c.mu.Unlock()
		return
	}
	if rx && bytes == 0 && demand == 0 && state.returnSince.IsZero() {
		// RX has no peer-published frontier, so a zero-progress window cannot
		// distinguish an idle sender from a blackholed demanded path. It may
		// continue a return already proven by delivered low-demand DATA, but it
		// must never start one and outrun the path-liveness decision.
		c.mu.Unlock()
		return
	}

	lowDemand := demand == 0 || (state.normalPeakBps > 0 && bps < state.normalPeakBps*c.returnRatio())
	if !lowDemand {
		state.returnSince = time.Time{}
		c.mu.Unlock()
		return
	}
	if state.returnSince.IsZero() {
		state.returnSince = now.Add(-duration)
	}
	if now.Sub(state.returnSince) < c.returnFor() || now.Before(state.policyRetryAfter) {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	_, intentPhase, err := c.applyPolicyTransition(rx, peakTransferNormal, proto.TargetID{}, "peak-return")
	completedAt := time.Now()
	c.mu.Lock()
	state = &c.tx
	if rx {
		state = &c.rx
	}
	if state.phaseGeneration != intentPhase {
		c.mu.Unlock()
		return
	}
	if err != nil {
		state.recordPolicyFailure(err, completedAt, peakTransferNormal, "peak-return")
		c.mu.Unlock()
		return
	}
	state.resetAfterReturn()
	state.demandSuppressUntil = completedAt.Add(defaultPeakSuppressFor)
	c.mu.Unlock()
}

// peakCapacitySampleVerdict validates one demand-backed capacity sample. A
// success is immediately useful; a failure is only a strike. The controller
// requires consecutive strikes because the first window after a policy cutover
// can contain only a fraction of the new path's steady-state traffic.
func peakCapacitySampleVerdict(
	bytes, demand uint64,
	bps float64,
	duration time.Duration,
	normalPeakBps float64,
	pending bool,
) (sampled, success bool) {
	if bytes == 0 || (!pending && demand < defaultPeakMinSampleBytes) || duration <= 0 ||
		bps < 0 || math.IsNaN(bps) || math.IsInf(bps, 0) ||
		normalPeakBps <= 0 || math.IsNaN(normalPeakBps) || math.IsInf(normalPeakBps, 0) {
		return false, false
	}

	minimumBps := normalPeakBps * defaultPeakMinGain
	if math.IsInf(minimumBps, 0) {
		return false, false
	}
	if bps >= minimumBps {
		return true, true
	}
	return true, false
}

func (c *peakTransferController) returnRatio() float64 {
	return defaultPeakReturn
}

func (c *peakTransferController) returnFor() time.Duration {
	if c.tuning.PeakReturnAfter > 0 {
		return c.tuning.PeakReturnAfter
	}
	return defaultPeakReturnFor
}

func (state *peakTransferDirection) resetAfterReturn() {
	state.onPeak = false
	state.activePeakTarget = proto.TargetID{}
	state.peakVerified = false
	state.peakStarted = time.Time{}
	state.peakStartedFromCommit = false
	state.returnSince = time.Time{}
	state.cursor = peakDeliveryCursor{}
	state.clearPolicyRetry()
	state.resetCapacityFailureEvidence()
}

func (state *peakTransferDirection) clearPolicyRetry() {
	state.policyRetryAfter = time.Time{}
	state.policyRetryDelay = 0
	state.policyOutcomeUncertain = false
	state.promotionRetryPending = false
	state.policyRetryIntent = peakPolicyRetryIntent{}
	state.lastPolicyError = ""
}

func (state *peakTransferDirection) recordPolicyFailure(
	err error,
	completedAt time.Time,
	choice peakTransferChoice,
	cause string,
) {
	state.lastPolicyError = err.Error()
	state.policyRetryIntent = peakPolicyRetryIntent{}
	switch {
	case errors.Is(err, engine.ErrPolicyOutcomeUnknown):
		state.policyOutcomeUncertain = true
		state.policyRetryAfter = completedAt.Add(state.nextPolicyRetryDelay())
	case peakPolicyDecisionRetryable(err):
		state.policyOutcomeUncertain = false
		state.policyRetryAfter = completedAt.Add(state.nextPolicyRetryDelay())
	default:
		state.policyOutcomeUncertain = false
		state.policyRetryDelay = 0
		state.policyRetryAfter = completedAt.Add(defaultPeakSuppressFor)
		return
	}
	state.policyRetryIntent = peakPolicyRetryIntent{
		choice:             choice,
		cause:              cause,
		expectedTarget:     state.actualTarget,
		expectedGeneration: state.actualSelectorGeneration,
		expectedPeakTarget: state.activePeakTarget,
	}
}

func (state *peakTransferDirection) nextPolicyRetryDelay() time.Duration {
	delay := state.policyRetryDelay
	if delay <= 0 {
		delay = defaultPeakWindow
	} else if delay < defaultPeakSuppressFor {
		delay *= 2
		if delay > defaultPeakSuppressFor {
			delay = defaultPeakSuppressFor
		}
	}
	state.policyRetryDelay = delay
	return delay
}

func (state *peakTransferDirection) resetCapacityFailureEvidence() {
	state.capacityFailureTarget = proto.TargetID{}
	state.capacityFailureSamples = 0
}

func (c *peakTransferController) beginPeakObservation(
	rx bool,
	excluded []proto.TargetID,
	cause string,
) (proto.TargetID, uint64, error) {
	intentPhase := c.markPolicyIntent(rx)
	return c.beginPeakObservationAtPhase(rx, excluded, cause, intentPhase)
}

func (c *peakTransferController) beginPeakObservationAtPhase(
	rx bool,
	excluded []proto.TargetID,
	cause string,
	intentPhase uint64,
) (proto.TargetID, uint64, error) {
	if !c.policyIntentCurrent(rx, intentPhase) {
		return proto.TargetID{}, intentPhase, nil
	}
	var (
		appliedTarget proto.TargetID
		err           error
	)
	if rx || c.policyApplyForTest != nil {
		targetID := proto.TargetID{}
		if c.policyApplyForTest != nil {
			excludedSet := make(map[proto.TargetID]struct{}, len(excluded))
			for _, excludedID := range excluded {
				excludedSet[excludedID] = struct{}{}
			}
			targets := c.localTargets.peakTargetIDs
			if rx {
				targets = c.peerTargets.peakTargetIDs
			}
			for _, candidate := range targets {
				if _, skip := excludedSet[candidate]; !skip {
					targetID = candidate
					break
				}
			}
		}
		appliedTarget, _, err = c.applyPolicyTransitionAtPhase(
			rx, peakTransferPeak, targetID, cause, intentPhase,
		)
	} else {
		appliedTarget, err = c.e.SelectBestLocalPeakTransferTarget(
			c.localTargets.selectorID, excluded, cause,
		)
	}
	if err != nil {
		return proto.TargetID{}, intentPhase, err
	}
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
	}
	if state.phaseGeneration != intentPhase {
		c.mu.Unlock()
		return appliedTarget, intentPhase, nil
	}
	state.onPeak = true
	state.activePeakTarget = appliedTarget
	state.peakVerified = false
	state.peakStarted = time.Time{}
	state.peakStartedFromCommit = false
	state.returnSince = time.Time{}
	state.cursor = peakDeliveryCursor{}
	state.promotionRetryPending = false
	state.resetCapacityFailureEvidence()
	c.mu.Unlock()
	return appliedTarget, intentPhase, nil
}

func (c *peakTransferController) observeCommittedPeakPolicy(
	selectorID, targetID proto.TargetID,
	selectorGeneration uint64,
	peak bool,
	cause string,
) {
	for _, member := range c.members() {
		if member.localTargets.selectorID != selectorID {
			continue
		}
		member.observeCommittedPeakPolicyOne(selectorID, targetID, selectorGeneration, peak, cause)
		return
	}
}

func (c *peakTransferController) observeCommittedPeakPolicyOne(
	selectorID, targetID proto.TargetID,
	selectorGeneration uint64,
	peak bool,
	cause string,
) {
	if selectorID != c.localTargets.selectorID {
		return
	}
	c.mu.Lock()
	if !peakDirectionGenerationAccepts(&c.tx, targetID, selectorGeneration) {
		c.mu.Unlock()
		return
	}
	failedTarget := c.tx.activePeakTarget
	if reconcilePeakDirectionLocked(
		&c.tx, c.localTargets, targetID, selectorGeneration,
	) {
		advancePeakDirectionPhaseLocked(&c.tx)
		c.tx.lastPolicyError = ""
	}
	if !peak && peakVerificationFailed(cause) {
		c.tx.suppressPeakTarget(failedTarget, time.Now().Add(defaultPeakSuppressFor))
	}
	c.mu.Unlock()
}

func peakVerificationFailed(cause string) bool {
	switch cause {
	case "peak-verify-failed", "peak-verify-failed-rx", "death",
		"probe-wire-timeout", "probe-starved-data", "probe-write-stalled":
		return true
	default:
		return false
	}
}

func peakPolicyDecisionRetryable(err error) bool {
	return errors.Is(err, engine.ErrSelectorDecisionUnavailable) ||
		engine.IsRetryablePolicyRejection(err)
}

func (c *peakTransferController) lastPeakObservation(rx bool) peakCapacityObservation {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rx {
		return c.rx.lastObservation
	}
	return c.tx.lastObservation
}

func (state *peakTransferDirection) peakTargetSuppressed(targetID proto.TargetID, now time.Time) bool {
	if state == nil || targetID == (proto.TargetID{}) || state.candidateSuppressUntil == nil {
		return false
	}
	until := state.candidateSuppressUntil[targetID]
	if until.IsZero() || !now.Before(until) {
		delete(state.candidateSuppressUntil, targetID)
		return false
	}
	return true
}

func (state *peakTransferDirection) suppressPeakTarget(targetID proto.TargetID, until time.Time) {
	if state == nil || targetID == (proto.TargetID{}) {
		return
	}
	if state.candidateSuppressUntil == nil {
		state.candidateSuppressUntil = make(map[proto.TargetID]time.Time)
	}
	state.candidateSuppressUntil[targetID] = until
}

func (c *peakTransferController) applyPolicy(rx bool, choice peakTransferChoice, cause string) error {
	_, _, err := c.applyPolicyTransition(rx, choice, proto.TargetID{}, cause)
	return err
}

func (c *peakTransferController) applyPolicyTransition(
	rx bool,
	choice peakTransferChoice,
	targetID proto.TargetID,
	cause string,
) (proto.TargetID, uint64, error) {
	intentPhase := c.markPolicyIntent(rx)
	return c.applyPolicyTransitionAtPhase(rx, choice, targetID, cause, intentPhase)
}

func (c *peakTransferController) applyPolicyTransitionAtPhase(
	rx bool,
	choice peakTransferChoice,
	targetID proto.TargetID,
	cause string,
	intentPhase uint64,
) (proto.TargetID, uint64, error) {
	if !c.policyIntentCurrent(rx, intentPhase) {
		return proto.TargetID{}, intentPhase, nil
	}
	if c.policyApplyForTest != nil {
		targets := c.localTargets
		if rx {
			targets = c.peerTargets
		}
		if targetID == (proto.TargetID{}) {
			if choice == peakTransferNormal {
				targetID = targets.normalTargetID
			} else if len(targets.peakTargetIDs) != 0 {
				targetID = targets.peakTargetIDs[0]
			}
		}
		if err := c.policyApplyForTest(rx, choice, targetID, cause); err != nil {
			return proto.TargetID{}, intentPhase, err
		}
		return targetID, intentPhase, nil
	}
	if rx {
		selectorID := c.peerTargets.selectorID
		if selectorID == (proto.TargetID{}) {
			return proto.TargetID{}, intentPhase, fmt.Errorf("rendr: peer peak-transfer target is unavailable")
		}
		if targetID == (proto.TargetID{}) {
			resolved, generation, err := c.e.RequestPeerSelectionClass(
				c.policyContext(), selectorID, choice == peakTransferPeak, cause+"-rx",
			)
			if err == nil {
				c.mu.Lock()
				notePeerPolicyCommitLocked(&c.rx, resolved, generation)
				c.mu.Unlock()
			}
			return resolved, intentPhase, err
		}
		if err := c.requestPeerSelection(c.policyContext(), choice, selectorID, targetID, cause+"-rx"); err != nil {
			return proto.TargetID{}, intentPhase, err
		}
		return targetID, intentPhase, nil
	}
	if choice == peakTransferNormal {
		targetID, err := c.e.SelectBestLocalPeakTransferNormalTarget(c.localTargets.selectorID, cause)
		return targetID, intentPhase, err
	} else if targetID == (proto.TargetID{}) {
		targetID, err := c.e.SelectBestLocalPeakTransferTarget(c.localTargets.selectorID, nil, cause)
		return targetID, intentPhase, err
	}
	if err := c.applyPolicyTarget(false, choice, targetID, cause); err != nil {
		return proto.TargetID{}, intentPhase, err
	}
	return targetID, intentPhase, nil
}

func (c *peakTransferController) policyIntentCurrent(rx bool, intentPhase uint64) bool {
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
	}
	current := state.phaseGeneration == intentPhase
	c.mu.Unlock()
	return current
}

func (c *peakTransferController) applyPolicyTarget(rx bool, choice peakTransferChoice, targetID proto.TargetID, cause string) error {
	if rx {
		selectorID := c.peerTargets.selectorID
		if selectorID == (proto.TargetID{}) || (choice == peakTransferPeak && !c.peerTargets.isPeakTarget(targetID)) {
			return fmt.Errorf("rendr: peer peak-transfer target is unavailable")
		}
		return c.requestPeerSelection(c.policyContext(), choice, selectorID, targetID, cause+"-rx")
	}
	selectorID := c.localTargets.selectorID
	if selectorID == (proto.TargetID{}) || (choice == peakTransferPeak && !c.localTargets.isPeakTarget(targetID)) {
		return fmt.Errorf("rendr: local peak-transfer target is unavailable")
	}
	return c.e.SelectPeakTransferTarget(selectorID, targetID, choice == peakTransferPeak, cause)
}

func (c *peakTransferController) requestPeerSelection(
	ctx context.Context,
	choice peakTransferChoice,
	selectorID, targetID proto.TargetID,
	cause string,
) error {
	wantSelector := c.peerTargets.selectorID
	if wantSelector == (proto.TargetID{}) {
		return fmt.Errorf("rendr: peer peak-transfer target is unavailable")
	}
	validTarget := c.peerTargets.isNormalTarget(targetID)
	if choice == peakTransferPeak {
		validTarget = c.peerTargets.isPeakTarget(targetID)
	}
	if selectorID != wantSelector || !validTarget {
		return fmt.Errorf("rendr: peer peak-transfer target does not match the negotiated peer graph")
	}
	selectorGeneration, err := c.e.RequestPeerSelectionGeneration(ctx, selectorID, targetID, cause)
	if err == nil {
		c.mu.Lock()
		notePeerPolicyCommitLocked(&c.rx, targetID, selectorGeneration)
		c.mu.Unlock()
	}
	return err
}

func (c *peakTransferController) peakHealthy() bool {
	_, ok := c.selectHealthyPeakTarget(false)
	return ok
}

func (targets peakTransferTargets) isPeakTarget(targetID proto.TargetID) bool {
	for _, id := range targets.peakTargetIDs {
		if id == targetID {
			return true
		}
	}
	return false
}

func (targets peakTransferTargets) isNormalTarget(targetID proto.TargetID) bool {
	for _, id := range targets.normalTargetIDs {
		if id == targetID {
			return true
		}
	}
	return false
}

func (c *peakTransferController) selectHealthyPeakTarget(rx bool) (proto.TargetID, bool) {
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
	}
	now := time.Now()
	targets := append([]proto.TargetID(nil), c.localTargets.peakTargetIDs...)
	if rx {
		targets = append([]proto.TargetID(nil), c.peerTargets.peakTargetIDs...)
	}
	excluded := make(map[proto.TargetID]struct{}, len(targets))
	for _, targetID := range targets {
		if state != nil && state.peakTargetSuppressed(targetID, now) {
			excluded[targetID] = struct{}{}
		}
	}
	forTest := c.policyApplyForTest != nil
	c.mu.Unlock()

	if forTest || rx {
		for _, targetID := range targets {
			if _, skip := excluded[targetID]; !skip {
				return targetID, true
			}
		}
		return proto.TargetID{}, false
	}
	excludedIDs := make([]proto.TargetID, 0, len(excluded))
	for targetID := range excluded {
		excludedIDs = append(excludedIDs, targetID)
	}
	ranked, err := c.e.RankLocalPeakTransferTargets(c.localTargets.selectorID, excludedIDs...)
	if err != nil {
		return proto.TargetID{}, false
	}
	for _, targetID := range ranked {
		if _, skip := excluded[targetID]; skip {
			continue
		}
		if !localPeakTransferTargetHealthy(c.e, targetID) {
			continue
		}
		return targetID, true
	}
	return proto.TargetID{}, false
}

func saturatingAdd(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
}
