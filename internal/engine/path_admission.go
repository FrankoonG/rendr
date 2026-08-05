package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

type pathAdmissionLeafKey struct {
	clientTX proto.TargetID
	serverTX proto.TargetID
}

type pathAdmissionReservation struct {
	pathID   uint32
	base     uint64
	advanced bool
	bound    bool
	binding  proto.PathAdmissionBinding
	deadline time.Time
}

type completedPathAdmission struct {
	binding       proto.PathAdmissionBinding
	key           pathAdmissionLeafKey
	requestPhase  proto.PathAdmissionPhase
	response      []byte
	expires       time.Time
	replayPending bool
	successor     PathRef
}

// completedAdmissionPredecessorsLocked identifies rollback carriers that a
// newer transaction may supersede. Discovery is side-effect free so a rejected
// PreparePathBound cannot destroy the last overlap of the completed admission.
func (e *Engine) completedAdmissionPredecessorsLocked(key pathAdmissionLeafKey) map[uint32]struct{} {
	predecessors := make(map[uint32]struct{})
	for _, completed := range e.completedPathAdmissions {
		if completed.key != key {
			continue
		}
		successor := e.paths[completed.successor.ID]
		if successor == nil || successor.owner != completed.successor.Owner {
			continue
		}
		for _, predecessorID := range e.pathPredecessors[successor.id] {
			if e.retainedPaths[predecessorID] != nil {
				predecessors[predecessorID] = struct{}{}
			}
		}
	}
	return predecessors
}

// retireCompletedAdmissionPredecessorsLocked ends the old overlap only after
// a newer transaction for the same logical leaf has reserved its candidate.
// The completed response remains replayable on its current successor until
// the original deadline; only its now-obsolete rollback carrier is retired.
func (e *Engine) retireCompletedAdmissionPredecessorsLocked(key pathAdmissionLeafKey) []*pathSlot {
	var retired []*pathSlot
	for _, completed := range e.completedPathAdmissions {
		if completed.key != key {
			continue
		}
		successor := e.paths[completed.successor.ID]
		if successor == nil || successor.owner != completed.successor.Owner {
			continue
		}
		retired = append(retired, e.releasePathPredecessorsLocked(successor.id, successor.gen)...)
	}
	return retired
}

func pathAdmissionKeyForWireBinding(binding proto.PathAdmissionBinding) pathAdmissionLeafKey {
	return pathAdmissionLeafKey{
		clientTX: binding.InitiatorTargetID,
		serverTX: binding.ResponderTargetID,
	}
}

// AdoptPathAdmissionBase applies the acceptor-assigned shared generation to
// the initiator's still-uncommitted reservation.
func (e *Engine) AdoptPathAdmissionBase(pathID uint32, base uint64) error {
	e.pathsMu.Lock()
	defer e.pathsMu.Unlock()
	key, ok := e.pathAdmissionByPath[pathID]
	if !ok {
		return fmt.Errorf("engine: path %d has no admission reservation", pathID)
	}
	reservation := e.pathAdmissionByLeaf[key]
	if reservation.pathID != pathID || reservation.advanced || reservation.bound {
		return fmt.Errorf("engine: path %d admission base is already frozen", pathID)
	}
	reservation.base = base
	e.pathLeafGeneration[key] = base
	e.pathAdmissionByLeaf[key] = reservation
	return nil
}

// BindPathAdmission freezes the complete wire identity before COMMIT.
func (e *Engine) BindPathAdmission(pathID uint32, binding proto.PathAdmissionBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	e.pathsMu.Lock()
	defer e.pathsMu.Unlock()
	key, ok := e.pathAdmissionByPath[pathID]
	if !ok {
		return fmt.Errorf("engine: path %d has no admission reservation", pathID)
	}
	reservation := e.pathAdmissionByLeaf[key]
	if reservation.pathID != pathID || reservation.base != binding.BaseLeafGeneration ||
		key.clientTX != binding.InitiatorTargetID || key.serverTX != binding.ResponderTargetID {
		return fmt.Errorf("engine: path %d admission identity does not match reserved leaf", pathID)
	}
	if reservation.bound {
		if reservation.binding == binding {
			return nil
		}
		return fmt.Errorf("engine: path %d admission identity mutation", pathID)
	}
	reservation.bound = true
	reservation.binding = binding
	e.pathAdmissionByLeaf[key] = reservation
	return nil
}

// beginPathAdmissionCommit freezes the transaction deadline. Retries and
// terminal replay share this one deadline; no duplicate control extends it.
func (e *Engine) beginPathAdmissionCommit(pathID uint32, binding proto.PathAdmissionBinding) (time.Time, error) {
	e.pathsMu.Lock()
	defer e.pathsMu.Unlock()
	key, ok := e.pathAdmissionByPath[pathID]
	if !ok {
		return time.Time{}, fmt.Errorf("engine: path %d has no live admission", pathID)
	}
	reservation := e.pathAdmissionByLeaf[key]
	if reservation.pathID != pathID || !reservation.bound || reservation.binding != binding {
		return time.Time{}, fmt.Errorf("engine: path %d admission commit token mismatch", pathID)
	}
	if reservation.deadline.IsZero() {
		reservation.deadline = nowFn().Add(e.limits.MigrationBudget)
		e.pathAdmissionByLeaf[key] = reservation
	}
	return reservation.deadline, nil
}

func (e *Engine) ensurePathAdmissionDeadlineLocked(pathID uint32) time.Time {
	key, ok := e.pathAdmissionByPath[pathID]
	if !ok {
		return nowFn().Add(e.limits.MigrationBudget)
	}
	reservation := e.pathAdmissionByLeaf[key]
	if reservation.pathID != pathID {
		return nowFn().Add(e.limits.MigrationBudget)
	}
	if reservation.deadline.IsZero() {
		reservation.deadline = nowFn().Add(e.limits.MigrationBudget)
		e.pathAdmissionByLeaf[key] = reservation
	}
	return reservation.deadline
}

func (e *Engine) pathAdmissionRouteLocked(binding proto.PathAdmissionBinding) (pathAdmissionLeafKey, pathAdmissionReservation, *pathSlot, bool) {
	key := pathAdmissionKeyForWireBinding(binding)
	reservation, ok := e.pathAdmissionByLeaf[key]
	if !ok || !reservation.bound || reservation.binding != binding {
		return pathAdmissionLeafKey{}, pathAdmissionReservation{}, nil, false
	}
	slot := e.pathSlotForAdmissionLocked(reservation.pathID)
	if slot == nil {
		return key, reservation, nil, false
	}
	return key, reservation, slot, true
}

func (e *Engine) admittedPathForBinding(binding proto.PathAdmissionBinding) (uint32, bool) {
	key := pathAdmissionKeyForWireBinding(binding)
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	for id, slot := range e.paths {
		slotKey, valid := pathAdmissionKey(e.side, PathBinding{
			LocalTXTargetID: slot.localTXTargetID,
			PeerTXTargetID:  slot.peerTXTargetID,
		})
		if valid && slotKey == key {
			return id, true
		}
	}
	return 0, false
}

// activatePathAdmissionRouteContext publishes a surviving staged successor or
// commits the same logical generation on an active fallback after the staged
// carrier died. In both cases the binding advances exactly once.
func (e *Engine) activatePathAdmissionRouteContext(ctx context.Context, binding proto.PathAdmissionBinding, retainPredecessor, rollbackAllowed bool) error {
	for {
		e.pathsMu.RLock()
		_, _, slot, live := e.pathAdmissionRouteLocked(binding)
		if !live || slot == nil {
			e.pathsMu.RUnlock()
			return fmt.Errorf("engine: path admission has no live activation route")
		}
		pathID := slot.id
		_, staged := e.stagedPaths[pathID]
		_, active := e.paths[pathID]
		e.pathsMu.RUnlock()

		if staged {
			if err := e.activateStagedPathContext(ctx, pathID, retainPredecessor, rollbackAllowed); err != nil {
				e.pathsMu.RLock()
				_, _, current, stillLive := e.pathAdmissionRouteLocked(binding)
				moved := stillLive && current != nil && current.id != pathID
				e.pathsMu.RUnlock()
				if moved {
					continue
				}
				return err
			}
			return nil
		}
		if !active {
			return fmt.Errorf("engine: path admission activation route %d is unavailable", pathID)
		}

		e.pathsMu.Lock()
		_, reservation, current, stillLive := e.pathAdmissionRouteLocked(binding)
		if !stillLive || current == nil || current.id != pathID || e.paths[pathID] != current {
			e.pathsMu.Unlock()
			continue
		}
		if !reservation.advanced {
			if _, err := e.advancePathAdmissionLocked(pathID); err != nil {
				e.pathsMu.Unlock()
				return err
			}
		}
		current.admissionRollback.Store(false)
		e.pathsMu.Unlock()
		return nil
	}
}

// transferPathAdmissionLocked preserves a bound transaction when its
// successor dies and a retained predecessor becomes the live route.
func (e *Engine) transferPathAdmissionLocked(fromPathID, toPathID uint32) bool {
	key, ok := e.pathAdmissionByPath[fromPathID]
	if !ok {
		return false
	}
	reservation := e.pathAdmissionByLeaf[key]
	to := e.paths[toPathID]
	if reservation.pathID != fromPathID || to == nil {
		return false
	}
	toKey, valid := pathAdmissionKey(e.side, PathBinding{
		LocalTXTargetID: to.localTXTargetID,
		PeerTXTargetID:  to.peerTXTargetID,
	})
	if !valid || toKey != key {
		return false
	}
	delete(e.pathAdmissionByPath, fromPathID)
	reservation.pathID = toPathID
	e.pathAdmissionByLeaf[key] = reservation
	e.pathAdmissionByPath[toPathID] = key
	return true
}

// promotePathAdmissionRoute makes the carrier that delivered terminal proof
// the DATA route on both peers. This is a protocol convergence transition, not
// a path-death notification: it must not start an external recovery dial.
func (e *Engine) promotePathAdmissionRoute(binding proto.PathAdmissionBinding, source PathRef) error {
	if source.ID == 0 || source.Owner == 0 {
		return fmt.Errorf("engine: terminal admission proof has no source route")
	}
	e.pathsMu.Lock()
	_, reservation, current, live := e.pathAdmissionRouteLocked(binding)
	if !live || current == nil {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: terminal admission route has no live transaction")
	}
	if reservation.pathID == source.ID {
		if current.owner != source.Owner {
			e.pathsMu.Unlock()
			return fmt.Errorf("%w: terminal source owner changed", errPathAdmissionRouteChanged)
		}
		e.pathsMu.Unlock()
		return nil
	}
	predecessor := e.retainedPaths[source.ID]
	if predecessor == nil || predecessor.owner != source.Owner || !sameBoundLeaf(current, predecessor) {
		e.pathsMu.Unlock()
		return fmt.Errorf("%w: terminal source %d is no longer a transaction route", errPathAdmissionRouteChanged, source.ID)
	}
	allowed := false
	for _, predecessorID := range e.pathPredecessors[current.id] {
		if predecessorID == source.ID {
			allowed = true
			break
		}
	}
	if !allowed {
		e.pathsMu.Unlock()
		return fmt.Errorf("%w: terminal source %d is outside the current transaction route", errPathAdmissionRouteChanged, source.ID)
	}

	delete(e.paths, current.id)
	delete(e.retainedPaths, predecessor.id)
	delete(e.pathPredecessors, current.id)
	current.closeQuit()
	predecessor.maintenance.Store(false)
	predecessor.unfenceDispatch()
	e.paths[predecessor.id] = predecessor
	if e.dispatchScope[current.id] {
		delete(e.dispatchScope, current.id)
		e.dispatchScope[predecessor.id] = true
	}
	wasActive := e.activeID == current.id
	if wasActive {
		e.activeID = predecessor.id
		e.migrationCount++
	}
	if !e.transferPathAdmissionLocked(current.id, predecessor.id) {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: terminal admission transaction did not follow predecessor")
	}
	e.pathsMu.Unlock()
	e.retirePathAsync(current)
	e.requestReplay(e.sendAckNext.Load())
	if wasActive {
		e.fireMigrateHooks(current.id, predecessor.id, "admission-terminal-route")
	}
	return nil
}

func pathAdmissionKey(side Side, binding PathBinding) (pathAdmissionLeafKey, bool) {
	if binding.LocalTXTargetID == (proto.TargetID{}) || binding.PeerTXTargetID == (proto.TargetID{}) {
		return pathAdmissionLeafKey{}, false
	}
	if side == SideClient {
		return pathAdmissionLeafKey{clientTX: binding.LocalTXTargetID, serverTX: binding.PeerTXTargetID}, true
	}
	return pathAdmissionLeafKey{clientTX: binding.PeerTXTargetID, serverTX: binding.LocalTXTargetID}, true
}

func (e *Engine) reservePathAdmissionLocked(pathID uint32, binding PathBinding) error {
	key, ok := pathAdmissionKey(e.side, binding)
	if !ok {
		return nil
	}
	if _, exists := e.pathAdmissionByLeaf[key]; exists {
		return ErrPathAttachInProgress
	}
	e.pathAdmissionByLeaf[key] = pathAdmissionReservation{
		pathID: pathID,
		base:   e.pathLeafGeneration[key],
	}
	e.pathAdmissionByPath[pathID] = key
	return nil
}

// PathAdmissionBaseGeneration returns the shared logical leaf generation
// reserved by PreparePathBound. It is independent from the local path-slot
// generation, which is an implementation detail and may differ by peer.
func (e *Engine) PathAdmissionBaseGeneration(pathID uint32) (uint64, error) {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	key, ok := e.pathAdmissionByPath[pathID]
	if !ok {
		return 0, fmt.Errorf("engine: path %d has no admission reservation", pathID)
	}
	reservation := e.pathAdmissionByLeaf[key]
	if reservation.pathID != pathID {
		return 0, fmt.Errorf("engine: stale admission reservation for path %d", pathID)
	}
	return reservation.base, nil
}

// ValidatePathAdmissionBase rejects a delayed COMMIT before any local state
// is advanced. Repeating the same transaction after local advancement is
// idempotent while its reservation remains live.
func (e *Engine) ValidatePathAdmissionBase(pathID uint32, base uint64) error {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	key, ok := e.pathAdmissionByPath[pathID]
	if !ok {
		return fmt.Errorf("engine: path %d has no admission reservation", pathID)
	}
	reservation := e.pathAdmissionByLeaf[key]
	if reservation.pathID != pathID || reservation.base != base {
		return fmt.Errorf("engine: admission base generation mismatch: path=%d base=%d", pathID, base)
	}
	if current := e.pathLeafGeneration[key]; current != base && !(reservation.advanced && current == base+1) {
		return fmt.Errorf("engine: admission generation changed: current=%d base=%d", current, base)
	}
	return nil
}

func (e *Engine) advancePathAdmissionLocked(pathID uint32) (uint64, error) {
	key, ok := e.pathAdmissionByPath[pathID]
	if !ok {
		return 0, nil
	}
	reservation := e.pathAdmissionByLeaf[key]
	if reservation.pathID != pathID {
		return 0, fmt.Errorf("engine: stale admission reservation for path %d", pathID)
	}
	if reservation.advanced {
		return reservation.base + 1, nil
	}
	if e.pathLeafGeneration[key] != reservation.base {
		return 0, fmt.Errorf("engine: admission generation changed: current=%d base=%d", e.pathLeafGeneration[key], reservation.base)
	}
	e.pathLeafGeneration[key] = reservation.base + 1
	reservation.advanced = true
	e.pathAdmissionByLeaf[key] = reservation
	return reservation.base + 1, nil
}

func (e *Engine) releasePathAdmissionLocked(pathID uint32) {
	key, ok := e.pathAdmissionByPath[pathID]
	if !ok {
		return
	}
	delete(e.pathAdmissionByPath, pathID)
	if reservation := e.pathAdmissionByLeaf[key]; reservation.pathID == pathID {
		delete(e.pathAdmissionByLeaf, key)
	}
}

// CompletePathAdmission releases the one-transaction-per-leaf reservation
// and closes any retained predecessor after peer activation is proven.
func (e *Engine) CompletePathAdmission(pathID uint32) {
	e.pathsMu.Lock()
	successor := e.paths[pathID]
	if successor == nil {
		e.pathsMu.Unlock()
		return
	}
	retired := e.releasePathPredecessorsLocked(pathID, successor.gen)
	e.releasePathAdmissionLocked(pathID)
	e.pathsMu.Unlock()
	e.retirePathSet(retired)
}

// CompletePathAdmissionBinding makes delayed completion messages token-safe.
func (e *Engine) CompletePathAdmissionBinding(pathID uint32, binding proto.PathAdmissionBinding) error {
	return e.completePathAdmissionBinding(binding, pathID, false)
}

func (e *Engine) completePathAdmissionBindingRoute(binding proto.PathAdmissionBinding, retainPredecessors bool) error {
	return e.completePathAdmissionBinding(binding, 0, retainPredecessors)
}

func (e *Engine) completePathAdmissionBinding(binding proto.PathAdmissionBinding, expectedPathID uint32, retainPredecessors bool) error {
	e.pathsMu.Lock()
	key := pathAdmissionKeyForWireBinding(binding)
	reservation, ok := e.pathAdmissionByLeaf[key]
	if !ok || !reservation.bound || reservation.binding != binding {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: admission completion token has no live transaction")
	}
	pathID := reservation.pathID
	if expectedPathID != 0 && pathID != expectedPathID {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: path %d admission completion moved to path %d", expectedPathID, pathID)
	}
	successor := e.paths[pathID]
	if successor == nil {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: path %d admission successor is unavailable", pathID)
	}
	var retired []*pathSlot
	if !retainPredecessors || len(e.pathPredecessors[pathID]) == 0 {
		retired = e.releasePathPredecessorsLocked(pathID, successor.gen)
	} else {
		// The responder keeps predecessors RX/control-capable for terminal
		// replay, but local successor death alone is not peer proof that the
		// initiator can still use one. DATA promotion requires a FINAL receipt
		// received on that exact predecessor route.
		successor.admissionRollback.Store(false)
	}
	e.releasePathAdmissionLocked(pathID)
	e.pathsMu.Unlock()
	e.retirePathSet(retired)
	return nil
}

func (e *Engine) completePathAdmissionGeneration(pathID uint32, generation uint64) {
	e.pathsMu.Lock()
	successor := e.paths[pathID]
	if successor == nil || successor.gen != generation {
		e.pathsMu.Unlock()
		return
	}
	retired := e.releasePathPredecessorsLocked(pathID, generation)
	e.releasePathAdmissionLocked(pathID)
	e.pathsMu.Unlock()
	e.retirePathSet(retired)
}

func (e *Engine) rememberCompletedPathAdmission(pathID uint32, binding proto.PathAdmissionBinding, requestPhase proto.PathAdmissionPhase, response []byte) error {
	e.pathsMu.Lock()
	slot := e.pathSlotForAdmissionLocked(pathID)
	if slot == nil {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: completed admission path %d is unavailable", pathID)
	}
	entry, err := e.rememberCompletedPathAdmissionLocked(slot, binding, requestPhase, response)
	e.pathsMu.Unlock()
	if err != nil {
		return err
	}
	go e.expireCompletedPathAdmission(binding, entry)
	return nil
}

func (e *Engine) rememberCompletedPathAdmissionRoute(binding proto.PathAdmissionBinding, requestPhase proto.PathAdmissionPhase, response []byte) error {
	e.pathsMu.Lock()
	_, _, slot, ok := e.pathAdmissionRouteLocked(binding)
	if !ok {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: completed admission binding has no live route")
	}
	entry, err := e.rememberCompletedPathAdmissionLocked(slot, binding, requestPhase, response)
	e.pathsMu.Unlock()
	if err != nil {
		return err
	}
	go e.expireCompletedPathAdmission(binding, entry)
	return nil
}

func (e *Engine) rememberCompletedPathAdmissionLocked(slot *pathSlot, binding proto.PathAdmissionBinding, requestPhase proto.PathAdmissionPhase, response []byte) (*completedPathAdmission, error) {
	key, valid := pathAdmissionKey(e.side, PathBinding{
		LocalTXTargetID: slot.localTXTargetID,
		PeerTXTargetID:  slot.peerTXTargetID,
	})
	if !valid || key != pathAdmissionKeyForWireBinding(binding) {
		return nil, fmt.Errorf("engine: completed admission binding does not match path %d", slot.id)
	}
	expires := nowFn().Add(e.limits.MigrationBudget)
	if reservation, ok := e.pathAdmissionByLeaf[key]; ok && reservation.pathID == slot.id &&
		reservation.bound && reservation.binding == binding && !reservation.deadline.IsZero() {
		expires = reservation.deadline
	}
	if !nowFn().Before(expires) {
		return nil, fmt.Errorf("engine: completed admission deadline already expired")
	}
	entry := &completedPathAdmission{
		binding:      binding,
		key:          key,
		requestPhase: requestPhase,
		response:     append([]byte(nil), response...),
		expires:      expires,
		successor:    PathRef{ID: slot.id, Owner: slot.owner},
	}
	for completedBinding, completed := range e.completedPathAdmissions {
		if completed.key == key {
			delete(e.completedPathAdmissions, completedBinding)
		}
	}
	e.completedPathAdmissions[binding] = entry
	return entry, nil
}

type completedPathAdmissionPromotion struct {
	retired   *pathSlot
	oldPathID uint32
	newPathID uint32
	migrated  bool
}

// promoteCompletedPathAdmissionRouteLocked validates and, when required,
// commits the replay route while pathsMu still owns both the tombstone and
// topology. Stale receipts are benign: the peer will retry on a live route or
// the original deadline will expire, so they must never close the session.
func (e *Engine) promoteCompletedPathAdmissionRouteLocked(entry *completedPathAdmission, source PathRef) (completedPathAdmissionPromotion, bool) {
	if entry == nil || source.ID == 0 || source.Owner == 0 {
		return completedPathAdmissionPromotion{}, false
	}
	if active := e.paths[source.ID]; active != nil && active.owner == source.Owner {
		key, valid := pathAdmissionKey(e.side, PathBinding{
			LocalTXTargetID: active.localTXTargetID,
			PeerTXTargetID:  active.peerTXTargetID,
		})
		// A delayed receipt may arrive on a newer active generation of the
		// same leaf. Replaying the old proof is harmless; changing DATA route
		// ownership to that unrelated generation is not.
		return completedPathAdmissionPromotion{}, valid && key == entry.key
	}
	current := e.paths[entry.successor.ID]
	predecessor := e.retainedPaths[source.ID]
	if current == nil || current.owner != entry.successor.Owner || predecessor == nil ||
		predecessor.owner != source.Owner || !sameBoundLeaf(current, predecessor) {
		return completedPathAdmissionPromotion{}, false
	}
	allowed := false
	for _, predecessorID := range e.pathPredecessors[current.id] {
		if predecessorID == source.ID {
			allowed = true
			break
		}
	}
	if !allowed {
		return completedPathAdmissionPromotion{}, false
	}
	delete(e.paths, current.id)
	delete(e.retainedPaths, predecessor.id)
	delete(e.pathPredecessors, current.id)
	current.closeQuit()
	predecessor.maintenance.Store(false)
	predecessor.unfenceDispatch()
	e.paths[predecessor.id] = predecessor
	if e.dispatchScope[current.id] {
		delete(e.dispatchScope, current.id)
		e.dispatchScope[predecessor.id] = true
	}
	wasActive := e.activeID == current.id
	if wasActive {
		e.activeID = predecessor.id
		e.migrationCount++
	}
	entry.successor = source
	return completedPathAdmissionPromotion{
		retired: current, oldPathID: current.id, newPathID: predecessor.id, migrated: wasActive,
	}, true
}

func (e *Engine) finishCompletedPathAdmissionPromotion(promotion completedPathAdmissionPromotion) {
	if promotion.retired == nil {
		return
	}
	e.retirePathAsync(promotion.retired)
	e.requestReplay(e.sendAckNext.Load())
	if promotion.migrated {
		e.fireMigrateHooks(promotion.oldPathID, promotion.newPathID, "admission-terminal-replay-route")
	}
}

func (e *Engine) expireCompletedPathAdmission(binding proto.PathAdmissionBinding, entry *completedPathAdmission) {
	delay := time.Until(entry.expires)
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-e.closed:
		return
	}
	e.pathsMu.Lock()
	if e.completedPathAdmissions[binding] == entry {
		delete(e.completedPathAdmissions, binding)
	}
	e.pathsMu.Unlock()
}

func (e *Engine) finishCompletedPathAdmissionReplay(binding proto.PathAdmissionBinding, entry *completedPathAdmission) {
	e.pathsMu.Lock()
	if e.completedPathAdmissions[binding] == entry {
		entry.replayPending = false
	}
	e.pathsMu.Unlock()
}
