package engine

import (
	"context"
	"fmt"
	"math"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type packetPathCapacityRetirementKey struct {
	localTargetID   proto.TargetID
	peerTargetID    proto.TargetID
	routeGeneration uint64
}

func packetPathCapacityKeyForSlot(slot *pathSlot) packetPathCapacityRetirementKey {
	if slot == nil {
		return packetPathCapacityRetirementKey{}
	}
	return packetPathCapacityRetirementKey{
		localTargetID:   slot.localTXTargetID,
		peerTargetID:    slot.peerTXTargetID,
		routeGeneration: slot.routeGeneration.Load(),
	}
}

func packetPathCapacityKeyForLocalRetirement(payload proto.PathRetirementPayload) packetPathCapacityRetirementKey {
	return packetPathCapacityRetirementKey{
		localTargetID:   payload.SenderTargetID,
		peerTargetID:    payload.ReceiverTargetID,
		routeGeneration: payload.RouteGeneration,
	}
}

func packetPathCapacityKeyForPeerRetirement(payload proto.PathRetirementPayload) packetPathCapacityRetirementKey {
	return packetPathCapacityRetirementKey{
		localTargetID:   payload.ReceiverTargetID,
		peerTargetID:    payload.SenderTargetID,
		routeGeneration: payload.RouteGeneration,
	}
}

func (e *Engine) validatePacketPathFrameLimit(
	conn transport.PathConn,
	binding PathBinding,
	authority *externalPathCallbackOwner,
) (int, bool, error) {
	if e == nil || !e.Packetized() || conn == nil {
		return 0, false, nil
	}
	reporter, ok := conn.(transport.PacketPathConn)
	if !ok {
		return 0, false, fmt.Errorf(
			"%w: %T does not implement transport.PacketPathConn",
			ErrPacketPathCapacityUnavailable, conn,
		)
	}
	ctx, cancel := context.WithTimeout(context.Background(), externalPathValueCallbackTimeout)
	defer cancel()
	limit, err := invokeExternalPathValueCallbackAuthority(
		ctx, "PathConn.MaxFrameSize", reporter, authority, reporter.MaxFrameSize,
	)
	if err != nil {
		return 0, false, err
	}
	if err := e.validatePacketFrameCapacity(limit); err != nil {
		return 0, false, err
	}
	if uint32(limit) != binding.LocalReceiveFrameCapacity {
		return 0, false, fmt.Errorf(
			"%w: MaxFrameSize changed from negotiated %d to %d",
			ErrPacketPathCapacityUnavailable, binding.LocalReceiveFrameCapacity, limit,
		)
	}
	peerLimit := int(binding.PeerReceiveFrameCapacity)
	if err := e.validatePacketFrameCapacity(peerLimit); err != nil {
		return 0, false, fmt.Errorf("%w: peer capacity: %v", ErrPacketPathCapacityUnavailable, err)
	}
	if peerLimit < limit {
		limit = peerLimit
	}
	return limit, true, nil
}

// InspectPacketPathFrameCapacity obtains the factual complete-frame receive
// capacity before a packet handshake. Admission queries it again under exact
// cleanup authority and rejects a value that changed in between.
func (e *Engine) InspectPacketPathFrameCapacity(conn transport.PathConn) (uint32, error) {
	if e == nil || !e.Packetized() {
		return 0, nil
	}
	reporter, ok := conn.(transport.PacketPathConn)
	if !ok {
		return 0, fmt.Errorf("%w: %T does not implement transport.PacketPathConn", ErrPacketPathCapacityUnavailable, conn)
	}
	ctx, cancel := context.WithTimeout(context.Background(), externalPathValueCallbackTimeout)
	defer cancel()
	limit, err := invokeExternalPathValueCallbackContext(ctx, "PathConn.MaxFrameSize", reporter, reporter.MaxFrameSize)
	if err != nil {
		return 0, err
	}
	if err := e.validatePacketFrameCapacity(limit); err != nil {
		return 0, err
	}
	return uint32(limit), nil
}

func (e *Engine) validatePacketFrameCapacity(limit int) error {
	if limit <= 0 || uint64(limit) > math.MaxUint32 {
		return fmt.Errorf("%w: MaxFrameSize returned %d", ErrPacketPathCapacityUnavailable, limit)
	}
	required := mandatoryPacketControlFrameSize()
	if overhead := e.applicationPayloadOverhead(); overhead > required {
		required = overhead
	}
	if stateFrame := e.selectorStateControlFrameSize(); stateFrame > required {
		required = stateFrame
	}
	if limit < required {
		return fmt.Errorf("%w: packet path frame budget %d is smaller than session envelope %d", ErrPacketPathCapacityUnavailable, limit, required)
	}
	return nil
}

func validatePacketHandshakeFrame(code proto.CtrlCode, payload []byte, capacities ...uint32) error {
	frameSize := proto.HeaderSize + len(payload)
	for _, capacity := range capacities {
		if capacity == 0 {
			continue
		}
		if frameSize > int(capacity) {
			return fmt.Errorf("%w: %s handshake frame %d exceeds negotiated capacity %d", ErrPacketPathCapacityUnavailable, code, frameSize, capacity)
		}
	}
	return nil
}

func (e *Engine) preparedPacketPathCapacities(pathID uint32) (uint32, uint32, error) {
	if e == nil || !e.Packetized() {
		return 0, 0, nil
	}
	e.pathsMu.RLock()
	slot := e.pendingPaths[pathID]
	if slot == nil {
		slot = e.stagedPaths[pathID]
	}
	if slot == nil {
		slot = e.paths[pathID]
	}
	if slot == nil {
		e.pathsMu.RUnlock()
		return 0, 0, fmt.Errorf("engine: packet path %d has no prepared capacity binding", pathID)
	}
	local, peer := slot.localReceiveFrameCapacity, slot.peerReceiveFrameCapacity
	e.pathsMu.RUnlock()
	if local == 0 || peer == 0 {
		return 0, 0, fmt.Errorf("%w: packet path %d has incomplete capacity binding", ErrPacketPathCapacityUnavailable, pathID)
	}
	return local, peer, nil
}

func mandatoryPacketControlFrameSize() int {
	maximum := 0
	for code := proto.CtrlHello; code < proto.CtrlCodeLimit; code++ {
		bound, ok := proto.PacketControlFrameBoundFor(code, 0)
		if !ok {
			panic(fmt.Sprintf("engine: unclassified control code %d", code))
		}
		if bound.Class == proto.PacketControlRuntime && bound.MaxFrameSize > maximum {
			maximum = bound.MaxFrameSize
		}
	}
	return maximum
}

func (e *Engine) selectorStateControlFrameSize() int {
	if e == nil {
		return 0
	}
	binding := e.localGraphBinding()
	if !binding.configured || !binding.tracksSelectorState {
		return 0
	}
	selectors := 0
	for _, node := range binding.manifest.Nodes {
		if node.Kind == proto.GraphNodeKindSelector {
			selectors++
		}
	}
	bound, ok := proto.PacketControlFrameBoundFor(proto.CtrlSelectorState, selectors)
	if !ok {
		return 0
	}
	return bound.MaxFrameSize
}

// packetPathFrameLimitAdmission linearizes a narrower path admission against
// packet publication. A packet that has entered replay custody must fit every
// path admitted after it; otherwise a later migration could invalidate a
// successful application write. Raising the limit is a separate activation
// commit and requires peer-confirmed retirement of every narrower generation.
type packetPathFrameLimitAdmission struct {
	engine *Engine
	limit  int64
	done   bool
}

// beginPacketPathFrameLimitAdmission holds the packet-publication barrier only
// when this path would lower the session budget. The caller must commit or
// abort before returning. Prepare uses it only as a side-effect-free preflight;
// activation commits it in the same critical section that publishes the path.
func (e *Engine) beginPacketPathFrameLimitAdmission(limit int) (*packetPathFrameLimitAdmission, error) {
	if e == nil || limit == 0 {
		return nil, nil
	}
	if limit < 0 {
		return nil, fmt.Errorf("%w: frame budget %d", ErrPacketPathCapacityUnavailable, limit)
	}
	e.packetFrameLimitMu.Lock()

	current := e.packetFrameLimit.Load()
	if current != 0 && current <= int64(limit) {
		e.packetFrameLimitMu.Unlock()
		return nil, nil
	}

	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	for index := range e.sendHist.entries {
		entry := &e.sendHist.entries[index]
		if entry.control || len(entry.frame) <= limit {
			continue
		}
		e.packetFrameLimitMu.Unlock()
		return nil, fmt.Errorf(
			"%w: path frame budget %d cannot replay unacknowledged packet sequence %d (%d bytes)",
			ErrPacketTooLarge, limit, entry.seq, len(entry.frame),
		)
	}

	return &packetPathFrameLimitAdmission{engine: e, limit: int64(limit)}, nil
}

func (e *Engine) preflightPacketPathFrameLimit(limit int) error {
	admission, err := e.beginPacketPathFrameLimitAdmission(limit)
	if admission != nil {
		admission.abort()
	}
	return err
}

// commitPacketPathFrameLimitActivationLocked publishes a path's capacity at
// the same topology commit point as the path itself. Narrowing admissions
// already hold packetFrameLimitMu. A wider admission takes that barrier only
// after the slot is active and committed, so a staged path can never authorize
// an oversized packet and a confirmed predecessor retirement cannot leave the
// session permanently pinned to an obsolete limit. The caller holds pathsMu.
func (e *Engine) commitPacketPathFrameLimitActivationLocked(
	admission *packetPathFrameLimitAdmission,
	slot *pathSlot,
) {
	if admission != nil {
		admission.commit()
		return
	}
	if e == nil || slot == nil || !slot.packetCapacityCommitted {
		return
	}
	if hook := e.packetActivationBeforeBudgetRaise; hook != nil {
		hook()
	}
	e.packetFrameLimitMu.Lock()
	e.recomputePacketFrameLimitLocked()
	e.packetFrameLimitMu.Unlock()
}

// trackPacketPathCapacityRetirementLocked keeps a committed path's constraint
// live after local topology removal. The caller holds pathsMu; a later
// peer-confirmed retirement is the only event allowed to remove this entry.
func (e *Engine) trackPacketPathCapacityRetirementLocked(slot *pathSlot) {
	if e == nil || slot == nil || !slot.packetCapacityCommitted || slot.packetFrameLimit <= 0 {
		return
	}
	key := packetPathCapacityKeyForSlot(slot)
	e.packetFrameLimitMu.Lock()
	if current, exists := e.packetRetiredFrameLimits[key]; !exists || slot.packetFrameLimit < current {
		e.packetRetiredFrameLimits[key] = slot.packetFrameLimit
	}
	e.packetFrameLimitMu.Unlock()
}

func (e *Engine) confirmLocalPacketPathRetirement(payload proto.PathRetirementPayload) {
	if e == nil {
		return
	}
	e.pathsMu.Lock()
	e.confirmPacketPathCapacityKeyLocked(packetPathCapacityKeyForLocalRetirement(payload))
	e.pathsMu.Unlock()
}

func (e *Engine) confirmPeerPacketPathRetirementLocked(payload proto.PathRetirementPayload) {
	if e == nil {
		return
	}
	e.confirmPacketPathCapacityKeyLocked(packetPathCapacityKeyForPeerRetirement(payload))
}

func (e *Engine) confirmPacketPathCapacityRetirementsLocked(slots []*pathSlot) {
	if e == nil || len(slots) == 0 {
		return
	}
	e.packetFrameLimitMu.Lock()
	for _, slot := range slots {
		delete(e.packetRetiredFrameLimits, packetPathCapacityKeyForSlot(slot))
	}
	e.recomputePacketFrameLimitLocked()
	e.packetFrameLimitMu.Unlock()
}

func (e *Engine) confirmPacketPathCapacityKeyLocked(key packetPathCapacityRetirementKey) {
	e.packetFrameLimitMu.Lock()
	delete(e.packetRetiredFrameLimits, key)
	e.recomputePacketFrameLimitLocked()
	e.packetFrameLimitMu.Unlock()
}

// recomputePacketFrameLimitLocked raises the live session limit only when all
// active/retained and unconfirmed-retirement constraints permit it and every
// replay-custody frame fits. The caller holds pathsMu and packetFrameLimitMu.
func (e *Engine) recomputePacketFrameLimitLocked() {
	current := e.packetFrameLimit.Load()
	if current == 0 {
		return
	}
	candidate := int64(0)
	consider := func(limit int) {
		if limit <= 0 {
			return
		}
		if candidate == 0 || int64(limit) < candidate {
			candidate = int64(limit)
		}
	}
	for _, paths := range []map[uint32]*pathSlot{e.paths, e.retainedPaths} {
		for _, slot := range paths {
			if slot != nil && slot.packetCapacityCommitted {
				consider(slot.packetFrameLimit)
			}
		}
	}
	for _, limit := range e.packetRetiredFrameLimits {
		consider(limit)
	}
	if candidate <= current {
		return
	}
	e.sendHistMu.Lock()
	for index := range e.sendHist.entries {
		if len(e.sendHist.entries[index].frame) > int(candidate) {
			e.sendHistMu.Unlock()
			return
		}
	}
	e.packetFrameLimit.Store(candidate)
	e.sendHistMu.Unlock()
}

func (admission *packetPathFrameLimitAdmission) commit() {
	if admission == nil || admission.done {
		return
	}
	admission.done = true
	admission.engine.packetFrameLimit.Store(admission.limit)
	admission.engine.packetFrameLimitMu.Unlock()
}

func (admission *packetPathFrameLimitAdmission) abort() {
	if admission == nil || admission.done {
		return
	}
	admission.done = true
	admission.engine.packetFrameLimitMu.Unlock()
}

func (e *Engine) packetPayloadLimit() int {
	limit := MaxPayload
	if e == nil {
		return limit
	}
	frameLimit := e.packetFrameLimit.Load()
	if frameLimit == 0 {
		return limit
	}
	carrierLimit := int(frameLimit) - e.applicationPayloadOverhead()
	if carrierLimit < limit {
		limit = carrierLimit
	}
	if limit < 0 {
		return 0
	}
	return limit
}

func (e *Engine) validatePacketPayloadSize(payloadBytes int) error {
	limit := e.packetPayloadLimit()
	if payloadBytes <= limit {
		return nil
	}
	return fmt.Errorf(
		"%w: payload is %d bytes, session limit is %d bytes",
		ErrPacketTooLarge, payloadBytes, limit,
	)
}
