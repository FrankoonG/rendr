package rendr

import (
	"context"
	"errors"
	"fmt"
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
	peakMaximumLossPP         = 50
	peakMaximumJitter         = 200 * time.Millisecond
	peakQualityFreshFor       = 5 * time.Second
)

type peakTransferController struct {
	e *engine.Engine

	normalIDs    []uint32
	peakIDs      []uint32
	opts         PeakTransfer
	tuning       SelectorTuning
	localTargets peakTransferTargets
	peerTargets  peakTransferTargets

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

type peakTransferTargets struct {
	selectorID      proto.TargetID
	normalTargetID  proto.TargetID
	normalTargetIDs []proto.TargetID
	peakTargetIDs   []proto.TargetID
}

func peakTargetsFromManifest(manifest proto.GraphManifest) peakTransferTargets {
	root, ok := manifest.Node(manifest.RootID)
	if !ok || root.Kind != proto.GraphNodeKindSelector || len(root.PeakCandidates) == 0 {
		return peakTransferTargets{}
	}
	peaks := make(map[proto.TargetID]struct{}, len(root.PeakCandidates))
	for _, id := range root.PeakCandidates {
		peaks[id] = struct{}{}
	}
	targets := peakTransferTargets{selectorID: root.ID}
	for _, id := range root.Children {
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
	demandSuppressUntil      time.Time
	candidateSuppressUntil   map[proto.TargetID]time.Time
	policyRetryAfter         time.Time
	lastPolicyError          string
	saturatedSince           time.Time
	returnSince              time.Time
	policyOutcomeUncertain   bool
	cursor                   peakDeliveryCursor
	lastObservation          peakCapacityObservation
}

func newPeakTransferController(e *engine.Engine, plan compiledTarget, pathIDs []uint32) *peakTransferController {
	ctx, cancel := context.WithCancel(context.Background())
	c := &peakTransferController{
		e: e, opts: plan.peakOptions, tuning: plan.runtimeConfig.Selector,
		ctx: ctx, cancel: cancel,
	}
	for i, id := range pathIDs {
		if id == 0 {
			continue
		}
		if i < len(plan.pathPeak) && plan.pathPeak[i] {
			c.peakIDs = append(c.peakIDs, id)
		} else {
			c.normalIDs = append(c.normalIDs, id)
		}
	}
	c.localTargets = peakTargetsFromManifest(plan.graph.manifest)
	c.peerTargets = peakTargetsFromManifest(e.PeerGraphManifest())
	return c
}

func (c *peakTransferController) start() error {
	if c == nil || c.e == nil || len(c.localTargets.normalTargetIDs) == 0 ||
		len(c.localTargets.peakTargetIDs) == 0 || c.localTargets.selectorID == (proto.TargetID{}) {
		return nil
	}
	if selectorID, targetID, ok := c.localTargets.selection(peakTransferNormal); ok {
		if err := c.e.InitializePolicySelection(selectorID, targetID, "selector"); err != nil {
			c.cancel()
			return fmt.Errorf("rendr: initialize local PeakTransfer selection: %w", err)
		}
	}
	c.e.SetPeerPolicyAdmission(c.admitPeerSelection)
	c.e.SetPeakPolicyObserver(c.observeCommittedPeakPolicy)
	c.e.StartSelector(0)
	peerSelectorID := proto.TargetID{}
	if selectorID, _, ok := c.peerTargets.selection(peakTransferNormal); ok {
		peerSelectorID = selectorID
	}
	c.workers.Add(2)
	go func() {
		defer c.workers.Done()
		c.directionLoop(false, proto.TargetID{})
	}()
	go func() {
		defer c.workers.Done()
		c.directionLoop(true, peerSelectorID)
	}()
	return nil
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
	c.mu.Lock()
	c.peerInitializationErr = nil
	c.mu.Unlock()
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
			if c.directionObserveForTest != nil {
				c.directionObserveForTest(now, rx)
			} else {
				c.observeDelivery(now, rx)
			}
			if rx {
				c.advancePeerInitialization(&initialization, time.Now())
			}
		}
	}
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

	_, err := c.e.RequestPeerSelectionClass(
		c.policyContext(), initialization.selectorID, false, "selector-rx",
	)
	completedAt := time.Now()
	if c.policyContext().Err() != nil || c.e.IsClosed() {
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
	initialization.retryAt = completedAt.Add(initialization.retryDelay)
	if initialization.retryDelay < defaultPeakSuppressFor {
		initialization.retryDelay *= 2
		if initialization.retryDelay > defaultPeakSuppressFor {
			initialization.retryDelay = defaultPeakSuppressFor
		}
	}
}

func (c *peakTransferController) directionPhase(rx bool) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rx {
		return c.rx.phaseGeneration
	}
	return c.tx.phaseGeneration
}

func (c *peakTransferController) markPolicyIntent(rx bool) {
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
		c.peerInitializationErr = nil
	}
	advancePeakDirectionPhaseLocked(state)
	c.mu.Unlock()
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
	c.mu.Lock()
	err := c.peerInitializationErr
	c.mu.Unlock()
	if err == nil {
		return nil
	}
	id := StatusIssuePeerPolicyInitialization
	if errors.Is(err, engine.ErrPolicyOutcomeUnknown) {
		id = StatusIssuePeerPolicyOutcomeUnknown
	}
	return []StatusIssue{{ID: id, LastError: err.Error()}}
}

func (c *peakTransferController) admitPeerSelection(selectorID, targetID proto.TargetID, _ string) error {
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
	mu      sync.Mutex
	e       *engine.Engine
	targets peakTransferTargets
	state   peakTransferDirection
}

// installPeakTransferPeerAdmission gives a listener-owned sender the same
// factual peak-candidate health gate as a dialing sender. Class ranking and
// final target selection remain entirely owned by that peer engine.
func installPeakTransferPeerAdmission(e *engine.Engine) {
	if e == nil {
		return
	}
	targets := peakTargetsFromManifest(e.LocalGraphManifest())
	if targets.selectorID == (proto.TargetID{}) || len(targets.peakTargetIDs) == 0 {
		return
	}
	admission := &listenerPeakTransferAdmission{e: e, targets: targets}
	e.SetPeerPolicyAdmission(admission.admit)
	e.SetPeakPolicyObserver(admission.observe)
}

func (a *listenerPeakTransferAdmission) admit(
	selectorID, targetID proto.TargetID,
	_ string,
) error {
	if a == nil || selectorID != a.targets.selectorID || !a.targets.isPeakTarget(targetID) {
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
	peak bool,
	cause string,
) {
	if a == nil || selectorID != a.targets.selectorID {
		return
	}
	a.mu.Lock()
	if peak {
		a.state.onPeak = true
		a.state.activePeakTarget = targetID
		a.mu.Unlock()
		return
	}
	failedTarget := a.state.activePeakTarget
	a.state.resetAfterReturn()
	if peakVerificationFailed(cause) {
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
		snapshot = c.e.PeerTargetDelivery(proto.TargetID{})
	} else {
		snapshot = c.e.TargetApplicationDelivery(proto.TargetID{})
	}
	if snapshot.SelectorID == (proto.TargetID{}) || snapshot.TargetID == (proto.TargetID{}) ||
		snapshot.SelectorGeneration == 0 || snapshot.EvidenceEpoch == 0 || !snapshot.Attributable {
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
			state.peakStarted = time.Time{}
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
		bps = float64(bytes*8) / elapsed.Seconds()
	}
	c.evaluatePassiveWithPending(
		now, bytes, demand, bps, elapsed, snapshot.TargetID,
		snapshot.PublishedBytes > snapshot.AckedBytes, rx,
	)
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
	if selectorGeneration != 0 && state.actualSelectorGeneration != 0 &&
		selectorGeneration < state.actualSelectorGeneration {
		return false
	}
	changed := state.actualTarget != targetID ||
		(selectorGeneration != 0 && state.actualSelectorGeneration != selectorGeneration)
	if selectorGeneration != 0 {
		state.actualSelectorGeneration = selectorGeneration
	}
	state.actualTarget = targetID
	if targets.isPeakTarget(targetID) {
		if !state.onPeak || state.activePeakTarget != targetID {
			state.onPeak = true
			state.activePeakTarget = targetID
			state.peakVerified = false
			state.peakStarted = time.Time{}
			state.returnSince = time.Time{}
			state.cursor = peakDeliveryCursor{}
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

func (c *peakTransferController) resetDeliveryCursor(rx bool) {
	c.mu.Lock()
	if rx {
		c.rx.cursor = peakDeliveryCursor{}
	} else {
		c.tx.cursor = peakDeliveryCursor{}
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
	ratio := c.opts.SaturationRatio
	if ratio <= 0 {
		ratio = defaultPeakSaturation
	}
	if bps < state.normalPeakBps*ratio {
		state.saturatedSince = time.Time{}
		c.mu.Unlock()
		return
	}
	if state.saturatedSince.IsZero() {
		state.saturatedSince = now.Add(-duration)
	}
	needFor := c.opts.SaturationFor
	if needFor <= 0 {
		needFor = c.tuning.PeakPromoteAfter
		if needFor <= 0 {
			needFor = defaultPeakSaturationFor
		}
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
	_, err := c.beginPeakObservation(rx, excluded, "peak-transfer")
	completedAt := time.Now()
	c.mu.Lock()
	state = &c.tx
	if rx {
		state = &c.rx
	}
	if err != nil {
		state.lastPolicyError = err.Error()
		if errors.Is(err, engine.ErrPolicyOutcomeUnknown) {
			state.policyOutcomeUncertain = true
			state.policyRetryAfter = completedAt.Add(defaultPeakWindow)
		} else if peakPolicyDecisionRetryable(err) {
			state.policyRetryAfter = completedAt.Add(defaultPeakWindow)
			state.saturatedSince = completedAt.Add(-needFor)
		} else {
			state.policyRetryAfter = completedAt.Add(defaultPeakSuppressFor)
		}
	} else {
		state.lastPolicyError = ""
		state.policyRetryAfter = time.Time{}
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
		targets := c.localTargets
		if rx {
			targets = c.peerTargets
		}
		if reconcilePeakDirectionLocked(state, targets, targetID, 0) {
			advancePeakDirectionPhaseLocked(state)
			if rx {
				c.peerInitializationErr = nil
			}
		} else {
			state.cursor = peakDeliveryCursor{}
		}
		c.mu.Unlock()
		return
	}
	if state.peakStarted.IsZero() {
		state.peakStarted = now.Add(-duration)
	}
	conclusive := demand >= defaultPeakMinSampleBytes && bytes != 0 && state.normalPeakBps > 0
	if conclusive {
		success := bps >= state.normalPeakBps*defaultPeakMinGain
		state.lastObservation = peakCapacityObservation{
			targetID: state.activePeakTarget, bytes: bytes, demand: demand,
			duration: duration, bps: bps, conclusive: true, success: success,
		}
		if !success {
			failedTarget := state.activePeakTarget
			c.mu.Unlock()
			_, err := c.applyPolicyTransition(rx, peakTransferNormal, proto.TargetID{}, "peak-verify-failed")
			completedAt := time.Now()
			c.mu.Lock()
			state = &c.tx
			if rx {
				state = &c.rx
			}
			if err != nil {
				state.lastPolicyError = err.Error()
				if errors.Is(err, engine.ErrPolicyOutcomeUnknown) {
					state.policyOutcomeUncertain = true
					state.policyRetryAfter = completedAt.Add(defaultPeakWindow)
				} else {
					state.policyRetryAfter = completedAt.Add(defaultPeakSuppressFor)
				}
				c.mu.Unlock()
				return
			}
			state.lastPolicyError = ""
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
	_, err := c.applyPolicyTransition(rx, peakTransferNormal, proto.TargetID{}, "peak-return")
	completedAt := time.Now()
	c.mu.Lock()
	state = &c.tx
	if rx {
		state = &c.rx
	}
	if err != nil {
		state.lastPolicyError = err.Error()
		if errors.Is(err, engine.ErrPolicyOutcomeUnknown) {
			state.policyOutcomeUncertain = true
			state.policyRetryAfter = completedAt.Add(defaultPeakWindow)
		} else {
			state.policyRetryAfter = completedAt.Add(defaultPeakSuppressFor)
		}
		c.mu.Unlock()
		return
	}
	state.lastPolicyError = ""
	state.resetAfterReturn()
	state.demandSuppressUntil = completedAt.Add(defaultPeakSuppressFor)
	c.mu.Unlock()
}

func (c *peakTransferController) returnRatio() float64 {
	if c.opts.ReturnRatio > 0 {
		return c.opts.ReturnRatio
	}
	return defaultPeakReturn
}

func (c *peakTransferController) returnFor() time.Duration {
	if c.opts.ReturnFor > 0 {
		return c.opts.ReturnFor
	}
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
	state.returnSince = time.Time{}
	state.cursor = peakDeliveryCursor{}
	state.policyRetryAfter = time.Time{}
	state.policyOutcomeUncertain = false
	state.lastPolicyError = ""
}

func (c *peakTransferController) beginPeakObservation(
	rx bool,
	excluded []proto.TargetID,
	cause string,
) (proto.TargetID, error) {
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
		appliedTarget, err = c.applyPolicyTransition(rx, peakTransferPeak, targetID, cause)
	} else {
		c.markPolicyIntent(false)
		appliedTarget, err = c.e.SelectBestLocalPeakTransferTarget(
			c.localTargets.selectorID, excluded, cause,
		)
	}
	if err != nil {
		return proto.TargetID{}, err
	}
	c.mu.Lock()
	state := &c.tx
	if rx {
		state = &c.rx
	}
	state.onPeak = true
	state.activePeakTarget = appliedTarget
	state.peakVerified = false
	state.peakStarted = time.Time{}
	state.returnSince = time.Time{}
	state.cursor = peakDeliveryCursor{}
	c.mu.Unlock()
	return appliedTarget, nil
}

func (c *peakTransferController) observeCommittedPeakPolicy(
	selectorID, targetID proto.TargetID,
	peak bool,
	cause string,
) {
	if selectorID != c.localTargets.selectorID {
		return
	}
	c.mu.Lock()
	if peak {
		c.tx.onPeak = true
		c.tx.activePeakTarget = targetID
		c.tx.lastPolicyError = ""
		c.tx.peakVerified = false
		c.tx.peakStarted = time.Time{}
		c.tx.returnSince = time.Time{}
		c.tx.cursor = peakDeliveryCursor{}
	} else {
		failedTarget := c.tx.activePeakTarget
		c.tx.resetAfterReturn()
		if peakVerificationFailed(cause) {
			c.tx.suppressPeakTarget(failedTarget, time.Now().Add(defaultPeakSuppressFor))
		}
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
		errors.Is(err, engine.ErrPolicyRejected)
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
	_, err := c.applyPolicyTransition(rx, choice, proto.TargetID{}, cause)
	return err
}

func (c *peakTransferController) applyPolicyTransition(
	rx bool,
	choice peakTransferChoice,
	targetID proto.TargetID,
	cause string,
) (proto.TargetID, error) {
	c.markPolicyIntent(rx)
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
			return proto.TargetID{}, err
		}
		return targetID, nil
	}
	if rx {
		selectorID := c.peerTargets.selectorID
		if selectorID == (proto.TargetID{}) {
			return proto.TargetID{}, fmt.Errorf("rendr: peer peak-transfer target is unavailable")
		}
		if targetID == (proto.TargetID{}) {
			resolved, err := c.e.RequestPeerSelectionClass(
				c.policyContext(), selectorID, choice == peakTransferPeak, cause+"-rx",
			)
			return resolved, err
		}
		if err := c.requestPeerSelection(c.policyContext(), choice, selectorID, targetID, cause+"-rx"); err != nil {
			return proto.TargetID{}, err
		}
		return targetID, nil
	}
	if choice == peakTransferNormal {
		return c.e.SelectBestLocalPeakTransferNormalTarget(c.localTargets.selectorID, cause)
	} else if targetID == (proto.TargetID{}) {
		return c.e.SelectBestLocalPeakTransferTarget(c.localTargets.selectorID, nil, cause)
	}
	if err := c.applyPolicyTarget(false, choice, targetID, cause); err != nil {
		return proto.TargetID{}, err
	}
	return targetID, nil
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
	return c.e.RequestPeerSelection(ctx, selectorID, targetID, cause)
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
