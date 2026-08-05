package engine

import (
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
}

type completedPathAdmission struct {
	binding      proto.PathAdmissionBinding
	requestPhase proto.PathAdmissionPhase
	response     []byte
	expires      time.Time
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
	e.releasePathAdmissionLocked(pathID)
	e.pathsMu.Unlock()
	e.ReleasePathPredecessors(pathID)
}

// CompletePathAdmissionBinding makes delayed completion messages token-safe.
func (e *Engine) CompletePathAdmissionBinding(pathID uint32, binding proto.PathAdmissionBinding) error {
	e.pathsMu.Lock()
	key, ok := e.pathAdmissionByPath[pathID]
	if !ok {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: path %d has no live admission", pathID)
	}
	reservation := e.pathAdmissionByLeaf[key]
	if reservation.pathID != pathID || !reservation.bound || reservation.binding != binding {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: path %d admission completion token mismatch", pathID)
	}
	e.releasePathAdmissionLocked(pathID)
	e.pathsMu.Unlock()
	e.ReleasePathPredecessors(pathID)
	return nil
}

func (e *Engine) completePathAdmissionGeneration(pathID uint32, generation uint64) {
	e.pathsMu.Lock()
	successor := e.paths[pathID]
	if successor == nil || successor.gen != generation {
		e.pathsMu.Unlock()
		return
	}
	e.releasePathAdmissionLocked(pathID)
	e.pathsMu.Unlock()
	e.releasePathPredecessors(pathID, generation)
}

func (e *Engine) rememberCompletedPathAdmission(pathID uint32, binding proto.PathAdmissionBinding, requestPhase proto.PathAdmissionPhase, response []byte) error {
	entry := completedPathAdmission{
		binding:      binding,
		requestPhase: requestPhase,
		response:     append([]byte(nil), response...),
		expires:      nowFn().Add(e.limits.MigrationBudget),
	}
	e.pathsMu.Lock()
	slot := e.pathSlotForAdmissionLocked(pathID)
	if slot == nil {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: completed admission path %d is unavailable", pathID)
	}
	slot.completedAdmission = &entry
	e.pathsMu.Unlock()
	return nil
}

func (e *Engine) completedPathAdmission(pathID uint32) (completedPathAdmission, bool) {
	e.pathsMu.Lock()
	slot := e.pathSlotForAdmissionLocked(pathID)
	if slot == nil || slot.completedAdmission == nil {
		e.pathsMu.Unlock()
		return completedPathAdmission{}, false
	}
	entry := *slot.completedAdmission
	if nowFn().After(entry.expires) {
		if slot.completedAdmission != nil && slot.completedAdmission.binding == entry.binding {
			slot.completedAdmission = nil
		}
		e.pathsMu.Unlock()
		return completedPathAdmission{}, false
	}
	e.pathsMu.Unlock()
	entry.response = append([]byte(nil), entry.response...)
	return entry, true
}
