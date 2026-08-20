package engine

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

// nowFn is overridable in tests; production calls time.Now.
var nowFn = time.Now

// debugPathDeath gates a diagnostic stderr line inside onPathDeath.
// Enabled via RENDR_DEBUG_PATH_DEATH=1; used to bisect chaos-induced
// TCP failures (currently REG-T4 G1-T4-tcp at ~10 MiB under 50 Mbps
// tbf shaping where both paths die near-simultaneously and the
// migration budget exhausts).
var debugPathDeath = os.Getenv("RENDR_DEBUG_PATH_DEATH") != ""

type deferredPathDeath struct {
	slot  *pathSlot
	cause transport.DeathCause
	err   error
}

type pathDeparture struct {
	slot            *pathSlot
	event           PathDeathEvent
	cause           transport.DeathCause
	err             error
	explicitRemoval bool
	shouldReplay    bool
	replayCommitted bool
	migrated        bool
	zombieTrip      zombieTripTicket
	newActive       uint32
	hasPaths        bool
	peerRetirement  peerPathRetirementNotice
}

type zombieTripTicket struct {
	generation uint64
	valid      bool
}

// unwindFencedPathsLocked either makes a still-live predecessor dispatchable
// again or consumes the death callback that arrived while maintenance held it.
// Caller holds pathsMu and invokes processDeferredPathDeaths after unlocking.
func (e *Engine) unwindFencedPathsLocked(slots []*pathSlot) []deferredPathDeath {
	deaths := make([]deferredPathDeath, 0, len(slots))
	for _, slot := range slots {
		if current := e.paths[slot.id]; current != slot {
			continue
		}
		slot.maintenance.Store(false)
		if cause, err, ok := slot.takePendingDeath(); ok {
			deaths = append(deaths, deferredPathDeath{slot: slot, cause: cause, err: err})
			continue
		}
		slot.unfenceDispatch()
	}
	return deaths
}

func (e *Engine) processDeferredPathDeaths(deaths []deferredPathDeath) {
	for _, death := range deaths {
		e.onPathDeath(death.slot.id, death.slot.owner, death.cause, death.err)
	}
}

// onPathDeath is the OnDeath callback installed on every attached
// PathConn. It runs on the transport adapter's goroutine, so it
// keeps work brief and never blocks on locks held by the send path.
func (e *Engine) onPathDeath(id uint32, owner uint64, cause transport.DeathCause, err error) {
	if debugPathDeath {
		fmt.Fprintf(os.Stderr, "[rendr-engine] path %d died: cause=%v err=%v\n", id, cause, err)
	}
	runtime := e.localExecutionRuntime()
	e.pathsMu.Lock()
	if staged, ok := e.stagedPaths[id]; ok {
		if staged.owner != owner {
			e.pathsMu.Unlock()
			return
		}
		e.trackPathRetirementLocked(staged)
		delete(e.stagedPaths, id)
		var fallback *pathSlot
		for _, candidate := range e.paths {
			if sameBoundLeaf(staged, candidate) && (fallback == nil || candidate.gen > fallback.gen) {
				fallback = candidate
			}
		}
		if fallback == nil || !e.transferPathAdmissionLocked(id, fallback.id) {
			e.releasePathAdmissionLocked(id)
		}
		staged.closeQuit()
		e.pathsMu.Unlock()
		e.retirePathAsync(staged)
		e.firePathDeathHooks(PathDeathEvent{
			ID: id, Owner: staged.owner, Spec: staged.spec.Clone(),
			Binding: PathBinding{LocalTXTargetID: staged.localTXTargetID, PeerTXTargetID: staged.peerTXTargetID},
			Cause:   cause, Err: err,
		})
		return
	}
	if retained, ok := e.retainedPaths[id]; ok {
		if retained.owner != owner {
			e.pathsMu.Unlock()
			return
		}
		var peerRetirement peerPathRetirementNotice
		if cause != transport.CauseCleanClose {
			peerRetirement = peerPathRetirementNotice{
				localTargetID:   retained.localTXTargetID,
				peerTargetID:    retained.peerTXTargetID,
				routeGeneration: retained.routeGeneration.Load(),
				reason:          protoPathRetirementReason(false),
			}
		}
		e.trackPathRetirementLocked(retained)
		delete(e.retainedPaths, id)
		e.removePathPredecessorLocked(id)
		retained.closeQuit()
		e.pathsMu.Unlock()
		e.retirePathAsync(retained)
		e.queuePeerPathRetirement(peerRetirement)
		return
	}
	slot, ok := e.paths[id]
	if !ok {
		e.pathsMu.Unlock()
		return
	}
	if slot.owner != owner {
		e.pathsMu.Unlock()
		return
	}
	if slot.maintenance.Load() {
		slot.recordPendingDeath(cause, err)
		e.pathsMu.Unlock()
		return
	}
	departure := e.detachPathLocked(slot, runtime, cause, err, false)
	e.pathsMu.Unlock()
	e.finishPathDeparture(departure)
}

// detachPathLocked is the sole logical-departure transition for an active
// path generation. The caller holds pathsMu. Carrier shutdown, callbacks, and
// replay happen later in finishPathDeparture, after the topology commit.
func (e *Engine) detachPathLocked(slot *pathSlot, runtime *executionRuntime, cause transport.DeathCause, err error, explicitRemoval bool) pathDeparture {
	return e.detachPathLockedWithPeerNotification(slot, runtime, cause, err, explicitRemoval, true)
}

func (e *Engine) detachPathLockedWithPeerNotification(slot *pathSlot, runtime *executionRuntime, cause transport.DeathCause, err error, explicitRemoval, notifyPeer bool) pathDeparture {
	departure := pathDeparture{
		slot:            slot,
		cause:           cause,
		err:             err,
		explicitRemoval: explicitRemoval,
		shouldReplay:    explicitRemoval || cause != transport.CauseCleanClose,
		event: PathDeathEvent{
			ID:    slot.id,
			Owner: slot.owner,
			Spec:  slot.spec.Clone(),
			Binding: PathBinding{
				LocalTXTargetID: slot.localTXTargetID,
				PeerTXTargetID:  slot.peerTXTargetID,
			},
			Cause:          cause,
			Err:            err,
			Administrative: explicitRemoval,
		},
	}
	if notifyPeer && (explicitRemoval || cause != transport.CauseCleanClose) {
		departure.peerRetirement = peerPathRetirementNotice{
			localTargetID:   slot.localTXTargetID,
			peerTargetID:    slot.peerTXTargetID,
			routeGeneration: slot.routeGeneration.Load(),
			reason:          protoPathRetirementReason(explicitRemoval),
			deferUntil:      e.pathAdmissionOutcomeLocked(slot),
		}
	}
	slot.fenceDispatchForRetirement()
	e.trackPathRetirementLocked(slot)
	delete(e.paths, slot.id)
	// Ownership ends at the topology commit, not when asynchronous carrier
	// cleanup eventually runs. Published candidates must become stale before
	// RemovePath or a death callback can return.
	if !slot.requestMobilityClaimRetirement() {
		slot.closeQuit()
	}
	predecessorIDs := e.pathPredecessors[slot.id]
	delete(e.pathPredecessors, slot.id)
	var restored *pathSlot
	rollbackAllowed := slot.admissionRollback.Load()
	for _, predecessorID := range predecessorIDs {
		candidate := e.retainedPaths[predecessorID]
		if candidate == nil {
			continue
		}
		delete(e.retainedPaths, predecessorID)
		if !rollbackAllowed {
			e.trackPathRetirementLocked(candidate)
			candidate.closeQuit()
			e.retirePathAsync(candidate)
			continue
		}
		if restored == nil || candidate.gen > restored.gen {
			if restored != nil {
				e.trackPathRetirementLocked(restored)
				restored.closeQuit()
				e.retirePathAsync(restored)
			}
			restored = candidate
		} else {
			e.trackPathRetirementLocked(candidate)
			candidate.closeQuit()
			e.retirePathAsync(candidate)
		}
	}
	if restored != nil {
		restored.maintenance.Store(false)
		restored.unfenceDispatch()
		e.paths[restored.id] = restored
	}
	e.advancePathTopologyEpochLocked()
	if restored == nil || !e.transferPathAdmissionLocked(slot.id, restored.id) {
		e.releasePathAdmissionLocked(slot.id)
	}
	wasActive := e.activeID == slot.id
	migratedOk := false
	var newActive uint32
	if wasActive {
		if restored != nil {
			e.activeID = restored.id
			migratedOk = true
		} else if runtime != nil {
			e.activeID = e.projectRecursiveRepresentativeLocked(runtime)
		} else {
			// Path publication requires a frozen execution runtime. Keep this
			// defensive branch fail closed if that invariant is ever violated.
			e.activeID = 0
		}
		newActive = e.activeID
		if e.activeID == 0 {
			e.setState(BridgeMigrating)
		} else {
			migratedOk = true
			e.recordMigrationLocked()
			if !explicitRemoval && (cause == transport.CauseTransportError || cause == transport.CauseUnknown) {
				departure.zombieTrip = e.accountMigration()
			}
		}
	}
	departure.migrated = migratedOk
	departure.newActive = newActive
	departure.hasPaths = len(e.paths) > 0
	return departure
}

func (e *Engine) finishPathDeparture(departure pathDeparture) {
	if departure.slot == nil {
		return
	}
	selectorReplayScheduled := false
	e.firePathDeathHooks(departure.event)

	// A transport may report death while a concurrent Write is blocked and
	// only unblock that Write when Close is called. Close asynchronously: an
	// adapter is allowed to invoke OnDeath from inside its own Close method,
	// and recursively entering a sync.Once-backed Close would deadlock.
	e.retirePathAsync(departure.slot)
	if departure.peerRetirement.valid() {
		e.queuePeerPathRetirement(departure.peerRetirement)
	}
	if departure.shouldReplay && !departure.explicitRemoval && departure.hasPaths {
		if runtime := e.localExecutionRuntime(); runtime != nil {
			// Physical death commits an immediate data-plane fallback, but the
			// selector's desired child remains the policy truth until a factual
			// decision authorizes the move. Build that decision now rather than
			// waiting for the quality ticker. A successful selector transaction
			// owns the frozen replay prefix; only a failed transaction falls back
			// to the generic replay worker.
			selector := &selector{}
			decisions, now := selector.recursiveDecisions(e, runtime)
			for _, decision := range decisions {
				if decision.origin == policySelectionPathDeath {
					selectorReplayScheduled = true
					break
				}
			}
			if selectorReplayScheduled {
				replayCommitted := departure.replayCommitted
				go func() {
					if !selector.applyRecursiveDecisionsWithReplay(e, runtime, decisions, now, !replayCommitted) && !replayCommitted {
						e.requestReplay(e.sendAckNext.Load())
					}
				}()
			}
		}
	}
	if departure.explicitRemoval && departure.hasPaths && !departure.replayCommitted {
		// A local administrative removal is clean for lifecycle policy, but it
		// is not proof that every frame accepted by this carrier was ACKed.
		// RemovePath normally commits that frozen prefix before returning. A
		// failed synchronous publication, or a lower-level administrative
		// departure that did not own sendMu, falls back to the replay worker.
		e.requestReplay(e.sendAckNext.Load())
	}

	if departure.migrated {
		e.fireMigrateHooks(departure.slot.id, departure.newActive, "death")
	}

	if departure.explicitRemoval {
		// RemovePath commits only with a real survivor. If a concurrent fault
		// consumes that survivor immediately afterward, preserve transport-loss
		// semantics; an administrative action must never manufacture clean EOF.
		if !departure.hasPaths {
			go e.startMigrationBudget(departure.err)
		}
		return
	}

	switch departure.cause {
	case transport.CauseCleanClose:
		// Hard rule #2: only a clean close ends the engine. And only
		// if this was the last path; partial cleanCloses on a
		// non-final path are a no-op (the engine continues on
		// remaining paths).
		if !departure.hasPaths {
			e.setCloseErr(io.EOF)
			// OnDeath is allowed to run synchronously inside PathConn.Read.
			// Closing here would make the reaper wait for the reader goroutine
			// that is still executing this callback.
			e.requestClose()
		}
	case transport.CauseTransportError, transport.CauseUnknown:
		if departure.shouldReplay && departure.hasPaths && !selectorReplayScheduled {
			e.requestReplay(e.sendAckNext.Load())
		}
		// Accounting committed with the replacement topology. Only the
		// resulting close is deferred until after pathsMu is released.
		e.tripZombie(departure.zombieTrip)
		if !departure.hasPaths {
			go e.startMigrationBudget(departure.err)
		}
	}
}

func (e *Engine) drainDeadSlot(slot *pathSlot) {
	if slot == nil {
		return
	}
	batch := make([]recvFrame, 0, recvBatchSize)
	for {
		select {
		case frame := <-slot.recvQ:
			batch = append(batch, frame)
			if len(batch) == cap(batch) {
				e.onRecvBatch(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				e.onRecvBatch(batch)
			}
			return
		}
	}
}

// accountMigration decrements the zombie counter and reports whether zombie
// protection should trip. Callers hold pathsMu so this bookkeeping commits
// atomically with publication of the replacement active path. It never closes
// the engine.
//
// Cooldown semantics: if the gap since the last migration exceeds
// ZombieCooldown, refresh the counter before decrementing. This prevents
// infrequent legitimate migrations from accumulating into zombie territory.
func (e *Engine) accountMigration() zombieTripTicket {
	e.zombieMu.Lock()
	defer e.zombieMu.Unlock()
	now := nowFn()
	if !e.zombieLastMig.IsZero() && now.Sub(e.zombieLastMig) > e.limits.ZombieCooldown {
		e.zombieLeft = e.limits.ZombieMaxMigrations
	}
	e.zombieLeft--
	e.zombieLastMig = now
	e.zombieGeneration++
	return zombieTripTicket{
		generation: e.zombieGeneration,
		valid:      e.zombieLeft <= 0,
	}
}

// tripZombie performs the destructive half of zombie handling. Callers invoke
// it only after releasing pathsMu because Engine.Close takes pathsMu itself.
// A successful generation check and ticket consumption under zombieMu is the
// linearization point: payload credited before it invalidates the ticket;
// payload after it observes a close that has already committed.
func (e *Engine) tripZombie(ticket zombieTripTicket) bool {
	if !ticket.valid {
		return false
	}
	if hook := e.zombieBeforeTrip; hook != nil {
		hook()
	}
	e.zombieMu.Lock()
	if ticket.generation != e.zombieGeneration || e.zombieLeft > 0 {
		e.zombieMu.Unlock()
		return false
	}
	// Consume the exact decision and publish its terminal cause while payload
	// credit and competing terminal publishers are both excluded. Neither a
	// stale duplicate ticket nor a later protocol worker can win between these
	// two halves of the same decision.
	e.zombieGeneration++
	e.closeMu.Lock()
	if hook := e.zombieAtCommit; hook != nil {
		hook()
	}
	if e.closeErr == nil {
		e.closeErr = ErrZombie
	}
	e.closeMu.Unlock()
	e.zombieMu.Unlock()
	go func() { _ = e.Close() }()
	return true
}

// startMigrationBudget runs as a goroutine after the last path died.
// It either signals close (budget exceeded) or returns once a fresh
// path attaches.
func (e *Engine) startMigrationBudget(reason error) {
	deadline := nowFn().Add(e.limits.MigrationBudget)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-e.closed:
			return
		case <-tick.C:
			e.pathsMu.RLock()
			has := len(e.paths) > 0
			e.pathsMu.RUnlock()
			if has {
				return
			}
			if nowFn().After(deadline) {
				e.setCloseErr(ErrMigrationBudgetExceeded)
				_ = e.Close()
				return
			}
		}
	}
}

// waitForPath blocks until a path attaches or the budget elapses.
// Called from the send loop when there is no active path.
func (e *Engine) waitForPath() error {
	deadline := nowFn().Add(e.limits.MigrationBudget)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-e.closed:
			if err := e.CloseErr(); err != nil {
				return err
			}
			return nil
		case <-tick.C:
			e.pathsMu.RLock()
			id := e.activeID
			e.pathsMu.RUnlock()
			if id != 0 {
				return nil
			}
			if nowFn().After(deadline) {
				e.setCloseErr(ErrMigrationBudgetExceeded)
				e.requestClose()
				return ErrMigrationBudgetExceeded
			}
		}
	}
}
