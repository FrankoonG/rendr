package engine

import (
	"errors"
	"fmt"
	"net"

	"github.com/FrankoonG/rendr/proto"
)

const selectorStateHistoryLimit = sendControlReserve + 1

var (
	errPeerSelectorStatePending           = errors.New("engine: peer selector state is pending")
	errSelectorStateControlCreditRequired = errors.New("engine: selector state control credit is required")
)

func (e *Engine) acquireSelectorStateControlSlot() error {
	select {
	case e.sendControlSlots <- struct{}{}:
		return nil
	default:
	}
	for {
		deadline, wake, expired := e.writeDeadlineSnapshot()
		if expired {
			return ErrWriteDeadlineExceeded
		}
		timer, timerC := writeDeadlineTimer(deadline)
		select {
		case e.sendControlSlots <- struct{}{}:
			stopDeadlineTimer(timer)
			return nil
		case <-wake:
			stopDeadlineTimer(timer)
		case <-timerC:
		case <-e.closed:
			stopDeadlineTimer(timer)
			return net.ErrClosed
		}
	}
}

// selectorStateRecord is immutable after publication. Many DATA ledger entries
// can therefore share one complete vector without copying every selector into
// the hot path.
type selectorStateRecord struct {
	payload    proto.SelectorStatePayload
	entries    map[proto.TargetID]proto.SelectorStateEntry
	wire       []byte
	controlSeq uint64
}

type recvSelectorStateRecord struct {
	state      *selectorStateRecord
	controlSeq uint64
	ready      bool
}

func newSelectorStateRecord(payload proto.SelectorStatePayload, wire []byte) *selectorStateRecord {
	entries := make(map[proto.TargetID]proto.SelectorStateEntry, len(payload.Entries))
	for _, entry := range payload.Entries {
		entries[entry.SelectorID] = entry
	}
	ownedEntries := append([]proto.SelectorStateEntry(nil), payload.Entries...)
	payload.Entries = ownedEntries
	return &selectorStateRecord{
		payload: payload,
		entries: entries,
		wire:    append([]byte(nil), wire...),
	}
}

func (s *selectorStateRecord) entry(selectorID proto.TargetID) (proto.SelectorStateEntry, bool) {
	if s == nil {
		return proto.SelectorStateEntry{}, false
	}
	entry, ok := s.entries[selectorID]
	return entry, ok
}

func (e *Engine) localSelectorStateRecord(runtime *executionRuntime) (*selectorStateRecord, bool, error) {
	binding := e.localGraphBinding()
	if !binding.configured {
		return nil, false, fmt.Errorf("engine: local graph is not configured")
	}
	if !binding.tracksSelectorState {
		return nil, false, nil
	}
	snapshot, ok := runtime.selectorStateSnapshot()
	if !ok {
		return nil, true, errNoExecutionRoute
	}
	payload := proto.SelectorStatePayload{
		SessionEpoch:  proto.SessionEpoch(e.FlowID()),
		Direction:     senderDirection(e.side),
		GraphRevision: binding.revision,
		GraphDigest:   binding.digest,
		StateEpoch:    snapshot.StateEpoch,
		Entries:       snapshot.Entries,
	}
	wire, err := proto.EncodeSelectorState(payload, binding.manifest, binding.protoBinding())
	if err != nil {
		return nil, true, fmt.Errorf("engine: encode local selector state: %w", err)
	}
	return newSelectorStateRecord(payload, wire), true, nil
}

// lockApplicationSendWithSelectorState acquires sendMu and, when necessary,
// one bounded control replay slot for the state vector that must immediately
// precede the DATA publication. It never waits for control credit while holding
// sendMu, so ACK processing and another completed publication can release the
// reservation it needs.
func (e *Engine) lockApplicationSendWithSelectorState(
	runtime *executionRuntime,
) (*selectorStateRecord, bool, error) {
	controlReserved := false
	releaseControl := func() {
		if controlReserved {
			e.releaseSendSlot(true, 0)
			controlReserved = false
		}
	}
	for {
		state, tracked, err := e.localSelectorStateRecord(runtime)
		if err != nil {
			releaseControl()
			return nil, false, err
		}
		if tracked && state.payload.StateEpoch > e.sendSelectorStateEpoch.Load() && !controlReserved {
			if err := e.acquireSelectorStateControlSlot(); err != nil {
				return nil, false, err
			}
			controlReserved = true
		}
		if err := e.sendMu.lockApplication(e); err != nil {
			releaseControl()
			return nil, false, err
		}

		current, currentTracked, err := e.localSelectorStateRecord(runtime)
		if err != nil {
			e.sendMu.Unlock()
			releaseControl()
			return nil, false, err
		}
		published := e.sendSelectorStateEpoch.Load()
		if currentTracked && current.payload.StateEpoch < published {
			e.sendMu.Unlock()
			releaseControl()
			return nil, false, fmt.Errorf("engine: selector state epoch regressed from %d to %d", published, current.payload.StateEpoch)
		}
		if currentTracked && current.payload.StateEpoch > published && !controlReserved {
			e.sendMu.Unlock()
			continue
		}
		if (!currentTracked || current.payload.StateEpoch == published) && controlReserved {
			releaseControl()
		}
		return current, controlReserved, nil
	}
}

func (e *Engine) buildAndPublishApplicationBundle(
	payload []byte,
	runtime *executionRuntime,
	selectorState *selectorStateRecord,
	controlReserved bool,
) (stateFrame, dataFrame []byte, err error) {
	releaseUnusedControl := func() {
		if controlReserved {
			e.releaseSendSlot(true, 0)
			controlReserved = false
		}
	}
	flags, wirePayload, attribution, err := e.encodeApplicationPayload(payload, runtime, selectorState)
	if err != nil {
		releaseUnusedControl()
		return nil, nil, err
	}

	needsState := selectorState != nil &&
		selectorState.payload.StateEpoch > e.sendSelectorStateEpoch.Load()
	if needsState && !controlReserved {
		return nil, nil, errSelectorStateControlCreditRequired
	}
	if needsState && e.Packetized() {
		limit := e.packetFrameLimit.Load()
		stateFrameBytes := proto.HeaderSize + len(selectorState.wire)
		if limit != 0 && int64(stateFrameBytes) > limit {
			releaseUnusedControl()
			return nil, nil, fmt.Errorf(
				"%w: selector state frame is %d bytes, session limit is %d bytes",
				ErrPacketTooLarge, stateFrameBytes, limit,
			)
		}
	}
	sequenceCount := uint64(1)
	if needsState {
		sequenceCount++
	}
	firstSeq := e.sendSeq
	if firstSeq > proto.MaxSeq-sequenceCount {
		releaseUnusedControl()
		e.beginSequenceExhaustionClose()
		return nil, nil, ErrSequenceExhausted
	}
	e.sendSeq += sequenceCount
	rollbackSequence := func() { e.sendSeq = firstSeq }

	dataSeq := firstSeq
	if needsState {
		stateFrame = make([]byte, proto.HeaderSize+len(selectorState.wire))
		stateHeader := proto.Header{
			Version: proto.Version,
			Type:    proto.FrameCtrl,
			Flags:   proto.FlagsForCtrl(proto.CtrlSelectorState),
			Seq:     firstSeq,
		}
		if err := stateHeader.Encode(stateFrame[:proto.HeaderSize]); err != nil {
			rollbackSequence()
			releaseUnusedControl()
			return nil, nil, err
		}
		copy(stateFrame[proto.HeaderSize:], selectorState.wire)
		dataSeq++
	}
	dataFrame = make([]byte, proto.HeaderSize+len(wirePayload))
	dataHeader := proto.Header{Version: proto.Version, Type: proto.FrameData, Flags: flags, Seq: dataSeq}
	if err := dataHeader.Encode(dataFrame[:proto.HeaderSize]); err != nil {
		rollbackSequence()
		releaseUnusedControl()
		return nil, nil, err
	}
	copy(dataFrame[proto.HeaderSize:], wirePayload)

	if needsState {
		if err := e.reserveOwnedSendFrame(stateFrame); err != nil {
			rollbackSequence()
			releaseUnusedControl()
			return nil, nil, err
		}
		controlReserved = false
	}
	if err := e.reserveOwnedApplicationFrame(dataFrame, attribution, len(payload)); err != nil {
		if needsState {
			e.rollbackReservedSendFrame(firstSeq)
		}
		rollbackSequence()
		releaseUnusedControl()
		return nil, nil, err
	}
	e.publishSendSeq(dataSeq + 1)
	if needsState {
		selectorState.controlSeq = firstSeq
		e.rememberSendSelectorStateLocked(selectorState)
	}
	return stateFrame, dataFrame, nil
}

func (e *Engine) dispatchSelectorStateFrame(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return err
	}
	// The bounded replay worker owns physical publication. Waiting here would
	// spend the entire migration budget on the internal state control before the
	// application DATA gets a chance to enter the same recovery path. DATA may
	// physically overtake the control, but the receiver retains it by StateEpoch
	// and cannot expose it until this exact control reaches custody.
	e.requestReplayRange(header.Seq, header.Seq+1)
	return nil
}

func (e *Engine) decodePeerSelectorState(wire []byte) (*selectorStateRecord, error) {
	binding := e.peerGraphBinding()
	if !binding.configured || !binding.tracksSelectorState {
		return nil, fmt.Errorf("engine: peer graph does not negotiate selector state")
	}
	payload, err := proto.DecodeSelectorState(wire, binding.manifest, binding.protoBinding())
	if err != nil {
		return nil, err
	}
	if payload.SessionEpoch != proto.SessionEpoch(e.FlowID()) {
		return nil, fmt.Errorf("selector state session epoch does not match the connection")
	}
	if payload.Direction != peerSenderDirection(e.side) {
		return nil, fmt.Errorf("selector state direction does not match the peer sender")
	}
	return newSelectorStateRecord(payload, wire), nil
}

// rememberSendSelectorStateLocked is called with sendMu held after the state
// control and its replay owner have been published.
func (e *Engine) rememberSendSelectorStateLocked(state *selectorStateRecord) {
	if state == nil || state.payload.StateEpoch == 0 {
		return
	}
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	e.sendSelectorState = state
	e.sendSelectorStateEpoch.Store(state.payload.StateEpoch)
	if e.sendSelectorStates == nil {
		e.sendSelectorStates = make(map[uint64]*selectorStateRecord)
	}
	if _, exists := e.sendSelectorStates[state.payload.StateEpoch]; !exists {
		e.sendSelectorStateOrder = append(e.sendSelectorStateOrder, state.payload.StateEpoch)
	}
	e.sendSelectorStates[state.payload.StateEpoch] = state
	for len(e.sendSelectorStateOrder) > selectorStateHistoryLimit {
		oldest := e.sendSelectorStateOrder[0]
		e.sendSelectorStateOrder = e.sendSelectorStateOrder[1:]
		if e.sendSelectorState == nil || oldest != e.sendSelectorState.payload.StateEpoch {
			delete(e.sendSelectorStates, oldest)
		}
	}
}

// rememberPeerSelectorStateLocked validates one custody-owned state control.
// recvMu is held. Epoch and outer SEQ must describe one strictly ordered
// publication stream even when physical paths deliver controls out of order.
func (e *Engine) rememberPeerSelectorStateLocked(state *selectorStateRecord, controlSeq uint64) error {
	if state == nil || state.payload.StateEpoch == 0 {
		return fmt.Errorf("empty selector state")
	}
	epoch := state.payload.StateEpoch
	if existing := e.recvSelectorStates[epoch]; existing != nil {
		if existing.controlSeq != controlSeq {
			return fmt.Errorf("selector state epoch %d was reused by sequence %d", epoch, controlSeq)
		}
		return nil
	}
	for otherEpoch, other := range e.recvSelectorStates {
		if other == nil {
			continue
		}
		if (epoch < otherEpoch) != (controlSeq < other.controlSeq) {
			return fmt.Errorf("selector state epoch %d and sequence %d are not monotonically ordered", epoch, controlSeq)
		}
	}

	var previous, next *selectorStateRecord
	var previousEpoch uint64
	var nextEpoch uint64 = ^uint64(0)
	for candidateEpoch, candidate := range e.recvSelectorStates {
		if candidateEpoch < epoch && candidateEpoch > previousEpoch && candidate != nil {
			previousEpoch = candidateEpoch
			previous = candidate.state
		}
		if candidateEpoch > epoch && candidateEpoch < nextEpoch && candidate != nil {
			nextEpoch = candidateEpoch
			next = candidate.state
		}
	}
	if err := validateSelectorStateTransition(previous, state); err != nil {
		return err
	}
	if err := validateSelectorStateTransition(state, next); err != nil {
		return err
	}

	state.controlSeq = controlSeq
	if e.recvSelectorStates == nil {
		e.recvSelectorStates = make(map[uint64]*recvSelectorStateRecord)
	}
	e.recvSelectorStates[epoch] = &recvSelectorStateRecord{state: state, controlSeq: controlSeq}
	e.recvSelectorStateOrder = append(e.recvSelectorStateOrder, epoch)
	if epoch > e.recvSelectorStateLatestEpoch {
		e.recvSelectorStateLatestEpoch = epoch
		e.recvSelectorStateLatestSeq = controlSeq
	}
	return e.prunePeerSelectorStatesLocked()
}

func validateSelectorStateTransition(before, after *selectorStateRecord) error {
	if before == nil || after == nil {
		return nil
	}
	for selectorID, entry := range after.entries {
		previous, ok := before.entry(selectorID)
		if !ok || entry.Generation < previous.Generation {
			return fmt.Errorf("selector %x generation regressed", selectorID)
		}
		if entry.Generation == previous.Generation {
			if entry.DesiredTargetID != previous.DesiredTargetID {
				return fmt.Errorf("selector %x changed desired target without advancing generation", selectorID)
			}
			// Effective execution is a factual availability projection. A hard
			// path failure can move it away from desired, and recovery can move it
			// back, without changing the policy generation.
		}
	}
	return nil
}

func (e *Engine) peerSelectorStateForDataLocked(epoch, dataSeq uint64) (*selectorStateRecord, error) {
	record := e.recvSelectorStates[epoch]
	if record == nil {
		return nil, errPeerSelectorStatePending
	}
	if dataSeq <= record.controlSeq {
		return nil, fmt.Errorf(
			"DATA sequence %d references selector state published at sequence %d",
			dataSeq, record.controlSeq,
		)
	}
	if !record.ready {
		return nil, errPeerSelectorStatePending
	}
	return record.state, nil
}

// activatePeerSelectorStateLocked authorizes DATA references only after the
// exact control joins the contiguous receive prefix. This proves that no
// missing earlier control can later invalidate the transition chain.
func (e *Engine) activatePeerSelectorStateLocked(epoch, controlSeq uint64) error {
	record := e.recvSelectorStates[epoch]
	if record == nil || record.state == nil || record.controlSeq != controlSeq {
		return fmt.Errorf("selector state epoch %d has no matching control", epoch)
	}
	if record.ready {
		return nil
	}
	var previous *selectorStateRecord
	var previousSeq uint64
	for _, candidate := range e.recvSelectorStates {
		if candidate == nil || !candidate.ready || candidate.controlSeq >= controlSeq ||
			candidate.controlSeq < previousSeq {
			continue
		}
		previous = candidate.state
		previousSeq = candidate.controlSeq
	}
	if err := validateSelectorStateTransition(previous, record.state); err != nil {
		return err
	}
	record.ready = true
	return nil
}

func (e *Engine) selectorStateReferencedLocked(epoch uint64) bool {
	for _, item := range e.recvQueue {
		if item.stateEpoch == epoch {
			return true
		}
	}
	for _, proof := range e.recvFrameProofs {
		if proof.stateEpoch == epoch {
			return true
		}
	}
	return false
}

func (e *Engine) prunePeerSelectorStatesLocked() error {
	for len(e.recvSelectorStateOrder) > selectorStateHistoryLimit {
		// The latest control below the contiguous receive frontier defines the
		// state that the missing frontier DATA may reference. Its control is
		// already cumulatively acknowledged and therefore cannot be replayed;
		// pruning it would turn ordinary reordering into a permanent wait.
		frontierEpoch := uint64(0)
		frontierSeq := uint64(0)
		frontierFound := false
		for epoch, record := range e.recvSelectorStates {
			if record == nil || record.controlSeq >= e.expectedRecvSeq ||
				frontierFound && record.controlSeq <= frontierSeq {
				continue
			}
			frontierEpoch = epoch
			frontierSeq = record.controlSeq
			frontierFound = true
		}
		oldestIndex := -1
		var oldestSeq uint64 = ^uint64(0)
		for index, epoch := range e.recvSelectorStateOrder {
			record := e.recvSelectorStates[epoch]
			if record == nil || epoch == e.recvSelectorStateLatestEpoch || epoch == frontierEpoch ||
				record.controlSeq >= e.expectedRecvSeq || e.selectorStateReferencedLocked(epoch) {
				continue
			}
			if record.controlSeq < oldestSeq {
				oldestSeq = record.controlSeq
				oldestIndex = index
			}
		}
		if oldestIndex < 0 {
			return fmt.Errorf("selector state history exceeds %d live epochs", selectorStateHistoryLimit)
		}
		epoch := e.recvSelectorStateOrder[oldestIndex]
		delete(e.recvSelectorStates, epoch)
		copy(e.recvSelectorStateOrder[oldestIndex:], e.recvSelectorStateOrder[oldestIndex+1:])
		e.recvSelectorStateOrder = e.recvSelectorStateOrder[:len(e.recvSelectorStateOrder)-1]
	}
	return nil
}
