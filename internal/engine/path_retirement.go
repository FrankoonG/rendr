package engine

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const (
	pathRetirementInboxSize = maxSessionPaths
	pathRetirementRetry     = 10 * time.Millisecond
)

var errPathRetirementInboxFull = errors.New("engine: path retirement inbox capacity exceeded")

type peerPathRetirementNotice struct {
	localTargetID   proto.TargetID
	peerTargetID    proto.TargetID
	routeGeneration uint64
	reason          proto.PathRetirementReason
	deferUntil      <-chan struct{}
}

func (n peerPathRetirementNotice) valid() bool {
	return n.localTargetID != (proto.TargetID{}) && n.peerTargetID != (proto.TargetID{}) &&
		n.routeGeneration != 0 && n.reason.Valid()
}

type pathRetirementWorkKind uint8

const (
	pathRetirementWorkInvalid pathRetirementWorkKind = iota
	pathRetirementWorkApply
	pathRetirementWorkPublish
)

type pathRetirementWork struct {
	kind       pathRetirementWorkKind
	payload    proto.PathRetirementPayload
	notice     peerPathRetirementNotice
	deferUntil <-chan struct{}
}

type pathRetirementWorkKey struct {
	kind            pathRetirementWorkKind
	localTargetID   proto.TargetID
	peerTargetID    proto.TargetID
	routeGeneration uint64
	reason          proto.PathRetirementReason
}

func (w pathRetirementWork) key() pathRetirementWorkKey {
	if w.kind == pathRetirementWorkApply {
		return pathRetirementWorkKey{
			kind:            w.kind,
			localTargetID:   w.payload.ReceiverTargetID,
			peerTargetID:    w.payload.SenderTargetID,
			routeGeneration: w.payload.RouteGeneration,
			reason:          w.payload.Reason,
		}
	}
	return pathRetirementWorkKey{
		kind:            w.kind,
		localTargetID:   w.notice.localTargetID,
		peerTargetID:    w.notice.peerTargetID,
		routeGeneration: w.notice.routeGeneration,
		reason:          w.notice.reason,
	}
}

func (w pathRetirementWork) valid() bool {
	switch w.kind {
	case pathRetirementWorkApply:
		return w.payload.Validate() == nil
	case pathRetirementWorkPublish:
		return w.notice.valid()
	default:
		return false
	}
}

func protoPathRetirementReason(administrative bool) proto.PathRetirementReason {
	if administrative {
		return proto.PathRetirementReasonAdministrative
	}
	return proto.PathRetirementReasonTransport
}

// pathAdmissionOutcomeLocked returns the live transaction token associated
// with slot. The token follows a retained fallback and closes for every
// terminal admission outcome. Caller holds pathsMu.
func (e *Engine) pathAdmissionOutcomeLocked(slot *pathSlot) <-chan struct{} {
	if slot == nil {
		return nil
	}
	key, ok := e.pathAdmissionByPath[slot.id]
	if !ok {
		return nil
	}
	reservation, ok := e.pathAdmissionByLeaf[key]
	if !ok || reservation.pathID != slot.id || reservation.token == nil {
		return nil
	}
	select {
	case <-reservation.token.done:
		return nil
	default:
		return reservation.token.done
	}
}

func (e *Engine) enqueuePathRetirementWork(work pathRetirementWork) error {
	if !work.valid() {
		return errors.New("engine: invalid path retirement work")
	}
	select {
	case <-e.closed:
		return net.ErrClosed
	default:
	}

	key := work.key()
	e.pathRetirementMu.Lock()
	if _, queued := e.pathRetirementQueued[key]; queued {
		e.pathRetirementMu.Unlock()
		return nil
	}
	if len(e.pathRetirementQueued) >= pathRetirementInboxSize {
		e.pathRetirementMu.Unlock()
		return errPathRetirementInboxFull
	}
	e.pathRetirementQueued[key] = struct{}{}
	e.pathRetirementMu.Unlock()

	select {
	case e.pathRetirementInbox <- work:
		return nil
	case <-e.closed:
		e.releasePathRetirementWork(key)
		return net.ErrClosed
	default:
		e.releasePathRetirementWork(key)
		return errPathRetirementInboxFull
	}
}

func (e *Engine) releasePathRetirementWork(key pathRetirementWorkKey) {
	e.pathRetirementMu.Lock()
	delete(e.pathRetirementQueued, key)
	e.pathRetirementMu.Unlock()
}

// enqueueSequencedPathRetirementLocked takes durable, bounded engine ownership
// of PATH_RETIRE while recvMu still prevents cumulative ACK publication.
func (e *Engine) enqueueSequencedPathRetirementLocked(payload []byte) bool {
	// Local teardown has already made this receive route terminal. Dropping a
	// late PATH_RETIRE is not a peer protocol violation, and no cumulative ACK
	// can be emitted after the engine-owned writers are closing anyway.
	if e.isClosed() {
		return true
	}
	retirement, err := proto.DecodePathRetirement(payload)
	if err == nil {
		err = e.validatePeerPathRetirement(retirement)
	}
	if err == nil {
		err = e.enqueuePathRetirementWork(pathRetirementWork{
			kind:    pathRetirementWorkApply,
			payload: retirement,
		})
	}
	if err == nil {
		return true
	}
	e.recvFinalErr = fmt.Errorf("%w: PATH_RETIRE enqueue failed: %w", ErrPeerProtocol, err)
	e.recvTerminal = true
	return false
}

func (e *Engine) queuePeerPathRetirement(notice peerPathRetirementNotice) {
	if !notice.valid() {
		return
	}
	err := e.enqueuePathRetirementWork(pathRetirementWork{
		kind:       pathRetirementWorkPublish,
		notice:     notice,
		deferUntil: notice.deferUntil,
	})
	if err == nil || errors.Is(err, net.ErrClosed) {
		return
	}
	e.setCloseErr(fmt.Errorf("engine: queue peer path retirement: %w", err))
	e.requestClose()
}

func pathRetirementReady(wait <-chan struct{}) bool {
	if wait == nil {
		return true
	}
	select {
	case <-wait:
		return true
	default:
		return false
	}
}

func (e *Engine) pathRetirementLoop() {
	deferred := make(map[pathRetirementWorkKey]pathRetirementWork)
	var retryTimer *time.Timer
	var retryC <-chan time.Time
	defer func() {
		if retryTimer != nil {
			retryTimer.Stop()
		}
	}()

	armRetry := func() {
		if len(deferred) == 0 || retryC != nil {
			return
		}
		if retryTimer == nil {
			retryTimer = time.NewTimer(pathRetirementRetry)
		} else {
			retryTimer.Reset(pathRetirementRetry)
		}
		retryC = retryTimer.C
	}

	process := func(work pathRetirementWork) bool {
		key := work.key()
		if !pathRetirementReady(work.deferUntil) {
			deferred[key] = work
			return true
		}
		work.deferUntil = nil

		var (
			wait <-chan struct{}
			err  error
		)
		switch work.kind {
		case pathRetirementWorkApply:
			wait, err = e.applyPeerPathRetirementOnce(work.payload)
		case pathRetirementWorkPublish:
			err = e.sendPeerPathRetirement(work.notice)
		default:
			err = errors.New("unknown path retirement work kind")
		}
		if wait != nil {
			work.deferUntil = wait
			deferred[key] = work
			return true
		}

		e.releasePathRetirementWork(key)
		if err == nil || errors.Is(err, net.ErrClosed) {
			return true
		}
		if work.kind == pathRetirementWorkApply {
			e.setCloseErr(fmt.Errorf("%w: invalid PATH_RETIRE: %v", ErrPeerProtocol, err))
		} else {
			e.setCloseErr(fmt.Errorf("engine: publish peer path retirement: %w", err))
		}
		e.requestClose()
		return false
	}

	for {
		select {
		case <-e.closed:
			return
		case work := <-e.pathRetirementInbox:
			if !process(work) {
				return
			}
			armRetry()
		case <-retryC:
			retryC = nil
			for key, work := range deferred {
				if !pathRetirementReady(work.deferUntil) {
					continue
				}
				delete(deferred, key)
				if !process(work) {
					return
				}
			}
			armRetry()
		}
	}
}

func (e *Engine) sendPeerPathRetirement(notice peerPathRetirementNotice) error {
	local := e.localGraphBinding()
	peer := e.peerGraphBinding()
	if !notice.valid() {
		return errors.New("engine: invalid peer path retirement notice")
	}
	if !local.configured || !peer.configured {
		return errors.New("engine: path retirement graph binding is unavailable")
	}
	if e.isClosed() {
		return net.ErrClosed
	}
	payload, err := (proto.PathRetirementPayload{
		SessionEpoch:          proto.SessionEpoch(e.FlowID()),
		Direction:             senderDirection(e.side),
		Reason:                notice.reason,
		SenderGraphRevision:   local.revision,
		SenderGraphDigest:     local.digest,
		SenderTargetID:        notice.localTargetID,
		ReceiverGraphRevision: peer.revision,
		ReceiverGraphDigest:   peer.digest,
		ReceiverTargetID:      notice.peerTargetID,
		RouteGeneration:       notice.routeGeneration,
	}).Encode()
	if err != nil {
		return err
	}
	frame, err := e.sendFrameTracked(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPathRetire), payload)
	if len(frame) != 0 {
		// The replay ledger owns the frame even when the first dispatch reports
		// a transport failure. Path recovery will publish the exact bytes.
		return nil
	}
	return err
}

func (e *Engine) validatePeerPathRetirement(p proto.PathRetirementPayload) error {
	if p.SessionEpoch != proto.SessionEpoch(e.FlowID()) || p.Direction != peerSenderDirection(e.side) {
		return fmt.Errorf("peer path retirement session or direction mismatch")
	}
	local := e.localGraphBinding()
	peer := e.peerGraphBinding()
	if !local.configured || !peer.configured ||
		p.SenderGraphRevision != peer.revision || p.SenderGraphDigest != peer.digest ||
		p.ReceiverGraphRevision != local.revision || p.ReceiverGraphDigest != local.digest {
		return fmt.Errorf("peer path retirement graph binding mismatch")
	}
	sender, senderOK := peer.manifest.Node(p.SenderTargetID)
	receiver, receiverOK := local.manifest.Node(p.ReceiverTargetID)
	if !senderOK || sender.Kind != proto.GraphNodeKindPath || !receiverOK || receiver.Kind != proto.GraphNodeKindPath {
		return fmt.Errorf("peer path retirement target is not a negotiated path")
	}
	return nil
}

type pathRetirementLocation uint8

const (
	pathRetirementLocationInvalid pathRetirementLocation = iota
	pathRetirementLocationActive
	pathRetirementLocationPending
	pathRetirementLocationStaged
	pathRetirementLocationRetained
)

type pathRetirementMatch struct {
	slot      *pathSlot
	location  pathRetirementLocation
	wait      <-chan struct{}
	mapPathID uint32
}

func (e *Engine) pathRetirementAdmissionLocked(slot *pathSlot, key pathAdmissionLeafKey) (uint64, <-chan struct{}, bool, error) {
	mappedKey, ok := e.pathAdmissionByPath[slot.id]
	if !ok {
		return 0, nil, false, nil
	}
	reservation, ok := e.pathAdmissionByLeaf[mappedKey]
	if !ok || mappedKey != key || reservation.pathID != slot.id || reservation.token == nil {
		return 0, nil, false, errors.New("engine: path retirement found inconsistent admission ownership")
	}
	expected := reservation.base + 1
	if expected == 0 {
		return 0, nil, false, errors.New("engine: path retirement admission generation overflow")
	}
	return expected, reservation.token.done, true, nil
}

func (e *Engine) findPeerPathRetirementLocked(p proto.PathRetirementPayload, key pathAdmissionLeafKey) (pathRetirementMatch, uint64, error) {
	currentGeneration := e.pathLeafGeneration[key]
	matches := make([]pathRetirementMatch, 0, 2)
	sets := []struct {
		location pathRetirementLocation
		paths    map[uint32]*pathSlot
	}{
		{pathRetirementLocationActive, e.paths},
		{pathRetirementLocationPending, e.pendingPaths},
		{pathRetirementLocationStaged, e.stagedPaths},
		{pathRetirementLocationRetained, e.retainedPaths},
	}
	for _, set := range sets {
		for mapPathID, slot := range set.paths {
			if slot == nil || mapPathID != slot.id {
				return pathRetirementMatch{}, currentGeneration, errors.New("engine: path retirement found corrupt path membership")
			}
			if slot.localTXTargetID != p.ReceiverTargetID || slot.peerTXTargetID != p.SenderTargetID {
				continue
			}
			expected, wait, admissionLive, err := e.pathRetirementAdmissionLocked(slot, key)
			if err != nil {
				return pathRetirementMatch{}, currentGeneration, err
			}
			exactGeneration := slot.routeGeneration.Load() == p.RouteGeneration
			expectedGeneration := admissionLive && expected == p.RouteGeneration
			if !exactGeneration && !expectedGeneration {
				continue
			}
			match := pathRetirementMatch{slot: slot, location: set.location, mapPathID: mapPathID}
			if expectedGeneration {
				match.wait = wait
			}
			matches = append(matches, match)
		}
	}
	if len(matches) > 1 {
		return pathRetirementMatch{}, currentGeneration, fmt.Errorf(
			"engine: path retirement identity matched %d local paths", len(matches),
		)
	}
	if len(matches) == 1 {
		return matches[0], currentGeneration, nil
	}
	return pathRetirementMatch{}, currentGeneration, nil
}

func (e *Engine) removePathPredecessorLocked(pathID uint32) {
	for successorID, predecessorIDs := range e.pathPredecessors {
		filtered := predecessorIDs[:0]
		for _, predecessorID := range predecessorIDs {
			if predecessorID != pathID {
				filtered = append(filtered, predecessorID)
			}
		}
		if len(filtered) == 0 {
			delete(e.pathPredecessors, successorID)
		} else {
			e.pathPredecessors[successorID] = filtered
		}
	}
}

func (e *Engine) applyPeerPathRetirementOnce(p proto.PathRetirementPayload) (<-chan struct{}, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := e.validatePeerPathRetirement(p); err != nil {
		return nil, err
	}
	binding := PathBinding{LocalTXTargetID: p.ReceiverTargetID, PeerTXTargetID: p.SenderTargetID}
	key, ok := pathAdmissionKey(e.side, binding)
	if !ok {
		return nil, fmt.Errorf("peer path retirement has no logical leaf key")
	}

	e.sendMu.Lock()
	runtime := e.localExecutionRuntime()
	e.pathsMu.Lock()
	if e.isClosed() {
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		return nil, net.ErrClosed
	}
	match, currentGeneration, err := e.findPeerPathRetirementLocked(p, key)
	if err != nil {
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		return nil, err
	}
	if match.wait != nil {
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		return match.wait, nil
	}
	if match.slot == nil {
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		if p.RouteGeneration > currentGeneration {
			return nil, fmt.Errorf("peer path retirement generation %d is ahead of local generation %d", p.RouteGeneration, currentGeneration)
		}
		return nil, nil
	}

	switch match.location {
	case pathRetirementLocationActive:
		cause := transport.CauseTransportError
		administrative := p.Reason == proto.PathRetirementReasonAdministrative
		if administrative {
			cause = transport.CauseCleanClose
		}
		departure := e.detachPathLockedWithPeerNotification(
			match.slot, runtime, cause,
			fmt.Errorf("peer retired path generation %d", p.RouteGeneration),
			administrative, false,
		)
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		e.finishPathDeparture(departure)
		return nil, nil

	case pathRetirementLocationRetained:
		match.slot.fenceDispatchForRetirement()
		e.trackPathRetirementLocked(match.slot)
		delete(e.retainedPaths, match.mapPathID)
		e.removePathPredecessorLocked(match.slot.id)
		if !match.slot.requestMobilityClaimRetirement() {
			match.slot.closeQuit()
		}
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		e.retirePathAsync(match.slot)
		return nil, nil

	case pathRetirementLocationPending, pathRetirementLocationStaged:
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		return nil, errors.New("engine: admission path became terminal without an admission outcome")

	default:
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		return nil, errors.New("engine: invalid path retirement match")
	}
}

// applyPeerPathRetirement is retained as a synchronous package-level helper
// for focused state-machine tests. Wire processing always uses the bounded
// worker and never blocks the receive sequencer on an admission outcome.
func (e *Engine) applyPeerPathRetirement(p proto.PathRetirementPayload) error {
	for {
		wait, err := e.applyPeerPathRetirementOnce(p)
		if err != nil || wait == nil {
			return err
		}
		select {
		case <-wait:
		case <-e.closed:
			return net.ErrClosed
		}
	}
}
