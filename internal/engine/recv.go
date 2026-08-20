package engine

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const (
	recvBatchSize         = 64
	recvAckFrameThreshold = 64
	recvAckMaxDelay       = 10 * time.Millisecond
)

const recvReorderWindowLimit = 16 * 1024

// streamRecvWindowFrames bounds bytes already admitted for a slow application
// reader. It is intentionally independent of the network replay/BDP budget:
// enlarging the latter must not silently enlarge application buffering.
const streamRecvWindowFrames = 256

// packetRecvWindowBits only needs to cover the sender's bounded unacknowledged
// ledger. A larger window lets a malicious peer pin the receive floor while
// forcing one frame-digest allocation per distant packet.
const packetRecvWindowBits = 16 * 1024

const recvAttributionHistoryLimit = sendHistoryWindow + sendControlReserve + sendPolicyFinalReserve + 1

// Keep transaction digests for the sender's entire bounded replay domain so an
// exact old phase can recover a lost receipt without being reclassified as an
// unsolicited new transaction.
const policyReplayDigestLimit = sendHistoryWindow + sendControlReserve + sendPolicyFinalReserve

// recvItem is one frame waiting in the reorder buffer. Data frames
// hold the payload bytes; ctrl frames hold the flags so the in-order
// drainer can dispatch them after the SEQ space catches up.
type recvItem struct {
	slot          *pathSlot
	topologyEpoch uint64
	isCtrl        bool
	ctrlApplied   bool
	flags         uint16
	cohort        rootDeliveryCohort
	attributable  bool
	demand        bool
	bytes         int
	payload       []byte
	digest        proto.FrameDigest
	// packet-mode data may be delivered as soon as the first copy
	// arrives; delivered tracks that early handoff so later SEQ-floor
	// advancement can retire the slot without delivering twice.
	delivered bool
}

type recvPolicyPhaseKey struct {
	kind          policyMessageKind
	phase         proto.PolicyAckPhase
	transactionID [16]byte
}

type recvPolicyPhaseReceipt struct {
	seq            uint64
	frameDigest    proto.FrameDigest
	proposalDigest proto.PolicyProposalDigest
}

// recvFrame is one decoded frame handed off by a path reader to the
// single recvLoop aggregator. Readers stay out of recvMu entirely;
// the aggregator batches reorder/dedup work so G3-scale fan-in no
// longer serialises four path goroutines on one mutex per frame.
type recvFrame struct {
	slot          *pathSlot
	topologyEpoch uint64
	hdr           proto.Header
	payload       []byte
	digest        proto.FrameDigest
}

type recvPacketProof struct {
	digest        proto.FrameDigest
	topologyEpoch uint64
	cohort        rootDeliveryCohort
	attributable  bool
	demand        bool
	bytes         int
	deliverySeen  bool
}

type recvPacketDelivery struct {
	payload       []byte
	topologyEpoch uint64
	cohort        rootDeliveryCohort
	attributable  bool
	demand        bool
	bytes         int
}

func (e *Engine) packetSeenCapLocked() uint64 {
	return uint64(len(e.recvSeenBits)) * 64
}

func (e *Engine) packetSeenIndexLocked(seq uint64) uint64 {
	cap := e.packetSeenCapLocked()
	if cap == 0 {
		return 0
	}
	return (e.recvSeenHead + (seq - e.expectedRecvSeq)) % cap
}

func (e *Engine) packetSeenLocked(seq uint64) bool {
	idx := e.packetSeenIndexLocked(seq)
	word := idx / 64
	bit := idx % 64
	return e.recvSeenBits[word]&(uint64(1)<<bit) != 0
}

func (e *Engine) packetMarkSeenLocked(seq uint64) {
	idx := e.packetSeenIndexLocked(seq)
	word := idx / 64
	bit := idx % 64
	e.recvSeenBits[word] |= uint64(1) << bit
}

func (e *Engine) packetHeadSeenLocked() bool {
	if len(e.recvSeenBits) == 0 {
		return false
	}
	idx := e.recvSeenHead
	word := idx / 64
	bit := idx % 64
	return e.recvSeenBits[word]&(uint64(1)<<bit) != 0
}

func (e *Engine) packetAdvanceHeadLocked() {
	cap := e.packetSeenCapLocked()
	if cap == 0 {
		return
	}
	e.recvSeenHead = (e.recvSeenHead + 1) % cap
}

func (e *Engine) packetConsumeHeadLocked() {
	if len(e.recvSeenBits) == 0 {
		return
	}
	idx := e.recvSeenHead
	word := idx / 64
	bit := idx % 64
	e.recvSeenBits[word] &^= uint64(1) << bit
	if item, ok := e.recvFrameProofs[e.expectedRecvSeq]; ok {
		e.recvProof = proto.AdvanceAckProof(e.recvProof, item.digest)
		e.rememberDeliveredDigestLocked(e.expectedRecvSeq, item.digest)
		if !item.deliverySeen {
			e.commitUniqueTargetDeliveryLocked(
				item.cohort, item.topologyEpoch,
				item.attributable, item.demand, item.bytes,
			)
		}
		delete(e.recvFrameProofs, e.expectedRecvSeq)
	}
	if e.recvPacketMarks > 0 {
		e.recvPacketMarks--
	}
	e.packetAdvanceHeadLocked()
}

// Recv reads up to len(buf) bytes from the engine into buf, blocking
// until at least one byte is available or the engine is dead.
//
// Hard rule #1: a migration in flight may block Recv but never
// returns an error caused by the migration. Recv returns:
//   - io.EOF if the peer issued BYE
//   - rendr.ErrMigrationBudgetExceeded if the budget tripped
//   - rendr.ErrZombie if zombie protection tripped
//   - net.ErrClosed if the engine itself was Close()d locally
func (e *Engine) Recv(buf []byte) (int, error) {
	e.recvMu.Lock()
	for {
		if len(e.recvDeliver) > 0 {
			n := copy(buf, e.recvDeliver)
			e.recvDeliver = e.recvDeliver[n:]
			e.consumeStreamDeliveryLocked(n)
			wokeReader := e.drainContiguousLocked(nil)
			ackNext, ackGap, ackProof := e.receiveAckStateLocked(e.recvTerminal || e.recvStreamEOF)
			finalErr := e.takeRecvFinalLocked()
			if wokeReader {
				e.recvCond.Broadcast()
			}
			e.recvMu.Unlock()
			e.finishReceiveProgress(ackNext, ackGap, ackProof, finalErr)
			return n, nil
		}
		if e.recvTerminal {
			err := e.recvFinalErr
			if err == nil {
				err = io.EOF
			}
			if errors.Is(err, io.EOF) && !e.peerNormalBye.Load() {
				e.recvCond.Wait()
				continue
			}
			e.recvMu.Unlock()
			return 0, err
		}
		if e.recvStreamEOF {
			e.recvMu.Unlock()
			return 0, io.EOF
		}
		if e.isClosed() {
			if err := e.CloseErr(); err != nil {
				e.recvMu.Unlock()
				return 0, err
			}
			e.recvMu.Unlock()
			return 0, net.ErrClosed
		}
		if e.recvDeadlineExceededLocked() {
			e.recvMu.Unlock()
			return 0, ErrReadDeadlineExceeded
		}
		e.recvCond.Wait()
	}
}

func (e *Engine) consumeStreamDeliveryLocked(n int) {
	for n > 0 && len(e.recvDeliverFrames) > 0 {
		if n < e.recvDeliverFrames[0] {
			e.recvDeliverFrames[0] -= n
			return
		}
		n -= e.recvDeliverFrames[0]
		copy(e.recvDeliverFrames, e.recvDeliverFrames[1:])
		e.recvDeliverFrames = e.recvDeliverFrames[:len(e.recvDeliverFrames)-1]
	}
}

func (e *Engine) validateTargetDeliveryCohortLocked(cohort rootDeliveryCohort) error {
	if cohort.targetID == (proto.TargetID{}) {
		return nil
	}
	if targetID, exists := e.recvRootTargets[cohort.generation]; exists {
		if targetID != cohort.targetID {
			return fmt.Errorf("selector generation %d changed target from %x to %x",
				cohort.generation, targetID, cohort.targetID)
		}
		return nil
	}
	e.recvRootTargets[cohort.generation] = cohort.targetID
	e.recvRootTargetOrder = append(e.recvRootTargetOrder, cohort.generation)
	for len(e.recvRootTargetOrder) > recvAttributionHistoryLimit {
		oldest := e.recvRootTargetOrder[0]
		e.recvRootTargetOrder = e.recvRootTargetOrder[1:]
		delete(e.recvRootTargets, oldest)
	}
	return nil
}

func (e *Engine) commitUniqueTargetDeliveryLocked(
	cohort rootDeliveryCohort,
	topologyEpoch uint64,
	attributable, demand bool,
	bytes int,
) {
	if bytes <= 0 {
		return
	}
	if cohort.targetID == (proto.TargetID{}) {
		e.recvUniqueBytes = saturatingAddUint64(e.recvUniqueBytes, uint64(bytes))
		return
	}
	currentTopologyEpoch := e.currentPathTopologyEpoch()
	if topologyEpoch == 0 || topologyEpoch != currentTopologyEpoch {
		e.recvUniqueBytes = saturatingAddUint64(e.recvUniqueBytes, uint64(bytes))
		return
	}
	if e.recvRootCohort.targetID != (proto.TargetID{}) {
		if cohort.selectorID != e.recvRootCohort.selectorID {
			return
		}
		switch {
		case cohort.generation < e.recvRootCohort.generation:
			// Packet delivery is intentionally out of order. Keep delivering a
			// valid older packet, but never let it move current capacity evidence
			// back to an obsolete selector generation.
			e.recvUniqueBytes = saturatingAddUint64(e.recvUniqueBytes, uint64(bytes))
			return
		}
	}
	e.recvUniqueBytes = saturatingAddUint64(e.recvUniqueBytes, uint64(bytes))
	if e.recvRootCohort != cohort || e.recvRootAttributable != attributable ||
		e.recvRootTopologyEpoch != topologyEpoch {
		e.recvRootCohort = cohort
		e.recvRootCohortBytes = 0
		e.recvRootDemandBytes = 0
		e.recvRootAttributable = attributable
		e.recvRootTopologyEpoch = topologyEpoch
		e.recvRootEvidenceEpoch++
		if e.recvRootEvidenceEpoch == 0 {
			e.recvRootEvidenceEpoch++
		}
	}
	if e.recvRootAttributable {
		e.recvRootCohortBytes = saturatingAddUint64(e.recvRootCohortBytes, uint64(bytes))
		if demand {
			e.recvRootDemandBytes = saturatingAddUint64(e.recvRootDemandBytes, uint64(bytes))
		}
	}
}

func (e *Engine) failTargetDeliveryAttributionLocked(err error) {
	if err == nil || e.recvTerminal {
		return
	}
	e.publishRecvTerminalLocked(fmt.Errorf("%w: invalid DATA target attribution: %v", ErrPeerProtocol, err))
}

// publishRecvTerminalLocked linearizes receive-terminal publication against
// policy handlers that may already have left the receive queue. Caller holds
// recvMu; policyTerminalMu must not already be held.
func (e *Engine) publishRecvTerminalLocked(err error) {
	e.policyTerminalMu.Lock()
	e.recvFinalErr = err
	e.recvTerminal = true
	e.policyTerminal.Store(true)
	e.policyTerminalMu.Unlock()
}

func (e *Engine) rememberDeliveredDigestLocked(seq uint64, digest proto.FrameDigest) {
	if _, exists := e.recvDeliveredDigests[seq]; exists {
		return
	}
	e.recvDeliveredDigests[seq] = digest
	e.recvDeliveredOrder = append(e.recvDeliveredOrder, seq)
	for len(e.recvDeliveredOrder) > recvAttributionHistoryLimit {
		oldest := e.recvDeliveredOrder[0]
		e.recvDeliveredOrder = e.recvDeliveredOrder[1:]
		delete(e.recvDeliveredDigests, oldest)
	}
}

// PeerTargetDelivery returns unique DATA accepted into bounded session
// delivery custody for one immediate child of the peer's root selector.
// Application read cadence, replay attempts, and race duplicates do not
// advance it.
func (e *Engine) PeerTargetDelivery(targetID proto.TargetID) TargetDeliverySnapshot {
	topologyEpoch := e.currentPathTopologyEpoch()
	e.recvMu.Lock()
	snapshot := e.peerTargetDeliveryAtEpochLocked(targetID, topologyEpoch)
	e.recvMu.Unlock()
	if e.currentPathTopologyEpoch() != topologyEpoch {
		snapshot.Attributable = false
		snapshot.PublishedBytes = 0
		snapshot.AckedBytes = 0
		snapshot.DemandBytes = 0
	}
	return snapshot
}

func (e *Engine) peerTargetDeliveryLocked(targetID proto.TargetID) TargetDeliverySnapshot {
	return e.peerTargetDeliveryAtEpochLocked(targetID, e.currentPathTopologyEpoch())
}

func (e *Engine) peerTargetDeliveryAtEpochLocked(
	targetID proto.TargetID,
	topologyEpoch uint64,
) TargetDeliverySnapshot {
	cohort := e.recvRootCohort
	snapshot := TargetDeliverySnapshot{
		SelectorID:         cohort.selectorID,
		TargetID:           targetID,
		SelectorGeneration: cohort.generation,
		EvidenceEpoch:      e.recvRootEvidenceEpoch,
		Attributable: e.recvRootAttributable &&
			topologyEpoch != 0 && e.recvRootTopologyEpoch == topologyEpoch,
		DemandBytes: e.recvRootDemandBytes,
	}
	if targetID == (proto.TargetID{}) {
		snapshot.TargetID = cohort.targetID
		targetID = cohort.targetID
	}
	if cohort.targetID == targetID && snapshot.Attributable {
		snapshot.AckedBytes = e.recvRootCohortBytes
		snapshot.PublishedBytes = snapshot.AckedBytes
	} else {
		snapshot.Attributable = false
	}
	return snapshot
}

// RecvPacket pops the oldest pending packet from the engine's packet
// queue. Blocks until at least one packet is available or the engine
// is dead. Only valid when SetPacketMode was called; callers using
// Recv on a packet-mode engine will deadlock because the drainer
// never appends to recvDeliver.
//
// If the engine closes during the wait, RecvPacket returns
// (nil, io.EOF) for a peer BYE or (nil, ErrMigrationBudgetExceeded)
// for a budget exhaustion - same shape as Recv.
func (e *Engine) RecvPacket() ([]byte, error) {
	for {
		select {
		case p := <-e.recvPacketCh:
			return p, nil
		default:
		}
		e.recvMu.Lock()
		deadline := e.recvDeadline
		terminal := e.recvTerminal
		terminalErr := e.recvFinalErr
		e.recvMu.Unlock()
		if terminal {
			if terminalErr == nil {
				terminalErr = io.EOF
			}
			if !errors.Is(terminalErr, io.EOF) || e.peerNormalBye.Load() {
				return nil, terminalErr
			}
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, ErrReadDeadlineExceeded
		}
		var (
			timer  *time.Timer
			timerC <-chan time.Time
		)
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerC = timer.C
		}
		select {
		case p := <-e.recvPacketCh:
			if timer != nil {
				timer.Stop()
			}
			return p, nil
		case <-e.recvPacketWake:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-e.closed:
			if timer != nil {
				timer.Stop()
			}
			select {
			case p := <-e.recvPacketCh:
				return p, nil
			default:
			}
			if err := e.CloseErr(); err != nil {
				return nil, err
			}
			return nil, net.ErrClosed
		case <-timerC:
			return nil, ErrReadDeadlineExceeded
		}
	}
}

// readerLoop is one goroutine per attached PathConn.
func (e *Engine) readerLoop(slot *pathSlot) {
	defer close(slot.doneR)

	buf := make([]byte, MaxPayload+proto.HeaderSize+proto.DataRootGenerationSize)
	for {
		select {
		case <-slot.quit:
			return
		default:
		}

		frameEndpointGeneration := slot.probeEndpointGen.Load()
		frame := buf[:0]
		owned := false
		var err error
		if reader, ok := slot.conn.(transport.OwnedFrameReader); ok {
			frame, err = reader.ReadOwnedFrame()
			owned = true
		} else {
			var n int
			n, err = slot.conn.Read(buf)
			frame = buf[:n]
		}
		if err != nil {
			return
		}
		frameTopologyEpoch := slot.topologyEpoch.Load()
		if slot.probeEndpointGen.Load() != frameEndpointGeneration {
			// A read spanning an in-place endpoint replacement remains valid
			// session data, but cannot prove which physical incarnation carried
			// it. Preserve delivery while excluding it from capacity evidence.
			frameTopologyEpoch = 0
		}
		// Stamp last-recv after a successful read but before any
		// version / framing rejection: from the path's perspective,
		// "something arrived" is the signal monitoring cares about.
		slot.noteRecv(nowFn())
		if len(frame) < proto.HeaderSize {
			return
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil {
			return
		}
		if hdr.Version != proto.Version {
			e.setCloseErr(ErrPeerProtoVersion)
			go e.Close()
			return
		}
		payload := frame[proto.HeaderSize:]
		if owned {
			// Prevent downstream append operations from overwriting bytes in
			// the frame header that precedes this payload subslice.
			payload = payload[:len(payload):len(payload)]
		} else {
			payload = append([]byte(nil), payload...)
		}

		// Leaf mobility, path admission, and probes use their own OOB
		// sequencing rules and are handled before the application DATA
		// reorder path. Leaf mobility requires a nonzero transaction-local
		// message sequence; admission and probes use sequence zero.
		if hdr.Type == proto.FrameCtrl {
			code := proto.CtrlCodeFromFlags(hdr.Flags)
			if isLeafMobilityCtrl(code) {
				if err := proto.ValidateLeafMobilityCtrlFlags(hdr.Flags); err != nil || hdr.Seq == 0 || hdr.Last {
					e.setCloseErr(fmt.Errorf("%w: malformed leaf mobility OOB header", ErrPeerProtocol))
					go e.Close()
					return
				}
				if err := e.routeLeafMobilityOOB(slot, hdr, payload); err != nil {
					_ = e.leafMobilityProtocolError(err)
					return
				}
				continue
			}
			if isPathAdmissionCtrl(code) || isPathAdmissionHandshakeCtrl(code) {
				if hdr.Flags != proto.FlagsForCtrl(code) || hdr.Seq != 0 || hdr.Last {
					e.setCloseErr(ErrPeerProtocol)
					go e.Close()
					return
				}
				if e.routePathAdmissionControl(slot, code, payload) {
					continue
				}
			}
			if code == proto.CtrlPathProbe {
				e.handlePathProbeRequest(slot, payload)
				continue
			}
			if code == proto.CtrlPathProbeReply {
				e.handlePathProbeReply(slot, payload)
				continue
			}
		}

		if !e.enqueueRecvFrame(
			slot, frameTopologyEpoch, hdr, payload, proto.DigestFrame(frame),
		) {
			return
		}
	}
}

// handlePathProbeRequest queues the echo on the same path so the reader never
// waits behind a blocked sender. The path writer treats a partial control frame
// as transport death because continuing would leave the framed carrier
// desynchronized.
func (e *Engine) handlePathProbeRequest(slot *pathSlot, payload []byte) {
	generation := pathProbeGenerationForSlot(slot)
	fenceEpoch := slot.txFenceEpoch.Load()
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlPathProbeReply),
		Seq:     0, // probes are out-of-band of the SEQ stream
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		return
	}
	copy(frame[proto.HeaderSize:], payload)
	if hook := slot.probeRequestBeforeSubmit; hook != nil {
		hook()
	}
	e.submitPathProbeControl(slot, frame, generation, fenceEpoch)
}

// handlePathProbeReply matches the reply against an outstanding
// probe and, if found, updates the path's quality with the measured
// RTT.
func (e *Engine) handlePathProbeReply(slot *pathSlot, payload []byte) {
	receivedAt := nowFn()
	if ack, ok := proto.DecodeAck(payload); ok {
		if e.notePeerAckAt(ack, receivedAt) && ack.Gap {
			e.requestGapReplay(ack.NextSeq)
		}
		return
	}
	p, err := proto.DecodeProbe(payload)
	if err != nil {
		return
	}
	_ = e.acceptPathProbeReply(slot, p, receivedAt)
}

func (e *Engine) notePeerAck(ack proto.AckPayload) bool {
	return e.notePeerAckAt(ack, nowFn())
}

func (e *Engine) notePeerAckAt(ack proto.AckPayload, receivedAt time.Time) bool {
	binding := e.localGraphBinding()
	if ack.SessionEpoch != proto.SessionEpoch(e.FlowID()) ||
		ack.Direction != senderDirection(e.side) ||
		ack.GraphRevision != binding.revision ||
		ack.GraphDigest != binding.digest ||
		ack.NextSeq > e.sendPublishedNext.Load() {
		return false
	}
	valid, application := e.acknowledgeSendFramesAt(ack.NextSeq, ack.Proof, receivedAt)
	if valid {
		e.noteTailReplayAck(ack.NextSeq)
	}
	if valid && e.publishReplayAck(ack.NextSeq, ack.Gap) {
		select {
		case e.replayAckWake <- struct{}{}:
		default:
		}
	}
	if valid && application {
		e.markPayload()
	}
	return valid
}

type ackRequest struct {
	nextSeq uint64
	gap     bool
	proof   proto.AckProof
	waiters []chan struct{}
}

func (e *Engine) sendAck(nextSeq uint64, gap bool, proof proto.AckProof) {
	if (nextSeq == 0 && !gap) || e.isClosed() {
		return
	}
	e.enqueueAck(ackRequest{nextSeq: nextSeq, gap: gap, proof: proof})
}

func (e *Engine) sendTerminalAck(nextSeq uint64, gap bool, proof proto.AckProof) {
	done := make(chan struct{})
	if !e.enqueueAck(ackRequest{nextSeq: nextSeq, gap: gap, proof: proof, waiters: []chan struct{}{done}}) {
		return
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	case <-e.closed:
	}
}

// retryPeerTerminalAck preserves the receiver's terminal receipt when the
// application closes immediately after observing peer EOF. The first receipt
// may have been accepted by a lossy carrier without reaching the peer; one
// synchronous idempotent replay precedes local teardown while paths still
// belong to the session.
func (e *Engine) retryPeerTerminalAck() {
	e.recvMu.Lock()
	if !e.recvTerminal || !errors.Is(e.recvFinalErr, io.EOF) {
		e.recvMu.Unlock()
		return
	}
	nextSeq := e.expectedRecvSeq
	gap := e.recvHasGapLocked()
	proof := e.recvProof
	e.recvMu.Unlock()
	if nextSeq != 0 || gap {
		e.sendTerminalAck(nextSeq, gap, proof)
	}
}

func (e *Engine) enqueueAck(request ackRequest) bool {
	if e.isClosed() {
		return false
	}
	e.ackMu.Lock()
	if e.ackPendingSet {
		pending := &e.ackPending
		switch {
		case request.nextSeq < pending.nextSeq:
			for _, waiter := range request.waiters {
				close(waiter)
			}
			e.ackMu.Unlock()
			return true
		case request.nextSeq == pending.nextSeq:
			pending.gap = pending.gap || request.gap
			pending.waiters = append(pending.waiters, request.waiters...)
			e.ackMu.Unlock()
			return true
		default:
			request.waiters = append(request.waiters, pending.waiters...)
		}
	}
	e.ackPending = request
	e.ackPendingSet = true
	e.ackMu.Unlock()
	select {
	case e.ackWake <- struct{}{}:
	default:
	}
	return true
}

func (e *Engine) ackWriterLoop() {
	for {
		select {
		case <-e.closed:
			return
		case <-e.ackWake:
		}
		for {
			e.ackMu.Lock()
			if !e.ackPendingSet {
				e.ackMu.Unlock()
				break
			}
			request := e.ackPending
			e.ackPending = ackRequest{}
			e.ackPendingSet = false
			e.ackMu.Unlock()
			e.writeAck(request)
			for _, waiter := range request.waiters {
				close(waiter)
			}
		}
	}
}

func (e *Engine) writeAck(request ackRequest) {
	nextSeq, gap := request.nextSeq, request.gap
	binding := e.peerGraphBinding()
	payload := proto.AckPayload{
		SessionEpoch:  proto.SessionEpoch(e.FlowID()),
		Direction:     peerSenderDirection(e.side),
		GraphRevision: binding.revision,
		GraphDigest:   binding.digest,
		NextSeq:       nextSeq,
		Gap:           gap,
		Proof:         request.proof,
	}.Encode()
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlPathProbeReply),
		Seq:     0,
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		return
	}
	copy(frame[proto.HeaderSize:], payload)

	e.pathsMu.RLock()
	slots := e.receiveSlotsLocked()
	e.pathsMu.RUnlock()
	terminal := len(request.waiters) != 0
	var results chan bool
	if terminal {
		results = make(chan bool, len(slots))
	}
	for _, slot := range slots {
		e.enqueuePathAck(slot, pathAckWrite{frame: frame, terminal: terminal, result: results})
	}
	if !terminal || len(slots) == 0 {
		return
	}
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	for range slots {
		select {
		case ok := <-results:
			if ok {
				return
			}
		case <-timer.C:
			return
		case <-e.closed:
			return
		}
	}
}

func (e *Engine) enqueuePathAck(slot *pathSlot, request pathAckWrite) {
	if slot == nil {
		return
	}
	slot.ackMu.Lock()
	if slot.ackClosed {
		if request.result != nil {
			select {
			case request.result <- false:
			default:
			}
		}
		slot.ackMu.Unlock()
		return
	}
	if slot.ackPendingSet {
		pending := &slot.ackPending
		if pending.terminal && !request.terminal {
			slot.ackMu.Unlock()
			return
		}
		if pending.result != nil {
			select {
			case pending.result <- false:
			default:
			}
		}
	}
	slot.ackPending = request
	slot.ackPendingSet = true
	if slot.ackRunning {
		slot.ackMu.Unlock()
		return
	}
	slot.ackRunning = true
	slot.ackWG.Add(1)
	slot.ackMu.Unlock()
	go func() {
		defer slot.ackWG.Done()
		e.pathAckWriter(slot)
	}()
}

func (e *Engine) pathAckWriter(slot *pathSlot) {
	for {
		slot.ackMu.Lock()
		if !slot.ackPendingSet {
			slot.ackRunning = false
			slot.ackMu.Unlock()
			return
		}
		request := slot.ackPending
		slot.ackPending = pathAckWrite{}
		slot.ackPendingSet = false
		slot.ackMu.Unlock()

		n, err := slot.writeFrame(request.frame)
		ok := err == nil && n == len(request.frame)
		if request.result != nil {
			select {
			case request.result <- ok:
			default:
			}
		}
		if !ok {
			select {
			case <-slot.quit:
				return
			case <-e.closed:
				return
			default:
			}
		}
	}
}

// enqueueRecvFrame hands one fully-decoded frame to the per-path recv
// queue. The queue is intentionally small so one fast path cannot run
// arbitrarily far ahead of a slower path and explode the reorder
// window. Returning false means the engine is closing and the caller
// should stop reading.
func (e *Engine) enqueueRecvFrame(
	slot *pathSlot,
	topologyEpoch uint64,
	hdr proto.Header,
	payload []byte,
	digest proto.FrameDigest,
) bool {
	select {
	case slot.recvQ <- recvFrame{
		slot: slot, topologyEpoch: topologyEpoch,
		hdr: hdr, payload: payload, digest: digest,
	}:
		select {
		case e.recvWake <- struct{}{}:
		default:
		}
		return true
	case <-slot.quit:
		return false
	case <-e.closed:
		return false
	}
}

// recvLoop is the sole mutator of the reorder buffer. It drains the
// per-path recv queues in a round-robin sweep so one path cannot
// monopolise ingress and strand lower SEQs behind hundreds of
// thousands of later frames.
func (e *Engine) recvLoop() {
	batch := make([]recvFrame, 0, recvBatchSize)
	slots := make([]*pathSlot, 0, 4)
	for {
		if e.fillRecvBatch(&batch, &slots) {
			e.onRecvBatch(batch)
			batch = batch[:0]
			continue
		}
		select {
		case <-e.closed:
			return
		case <-e.recvWake:
		}
	}
}

func (e *Engine) ackLoop() {
	ticker := time.NewTicker(recvAckMaxDelay)
	defer ticker.Stop()
	ticks := 0
	for {
		select {
		case <-e.closed:
			return
		case <-ticker.C:
			ticks++
			e.recvMu.Lock()
			nextSeq, gap, proof := e.receiveAckStateLocked(true)
			e.recvAckBurstOpen = false
			terminal := e.recvTerminal && errors.Is(e.recvFinalErr, io.EOF)
			if nextSeq == 0 && !gap && ticks%10 == 0 && e.expectedRecvSeq != 0 {
				// Cumulative receipts are intentionally persistent: a path write
				// can be accepted locally but lost before the peer observes it.
				// Repeating the current proof also releases replay credit after
				// an earlier ACK route recovered without a new DATA arrival.
				nextSeq = e.expectedRecvSeq
				proof = e.recvProof
			}
			e.recvMu.Unlock()
			if terminal || nextSeq != 0 || gap {
				e.sendAck(nextSeq, gap, proof)
			}
		}
	}
}

func (e *Engine) fillRecvBatch(batch *[]recvFrame, scratch *[]*pathSlot) bool {
	*scratch = e.recvSlotsSnapshotInto((*scratch)[:0])
	slots := *scratch
	if len(slots) == 0 {
		return false
	}
	start := int(e.recvPathCursor % uint64(len(slots)))
	progressed := false
	for len(*batch) < cap(*batch) {
		roundProgress := false
		for i := 0; i < len(slots) && len(*batch) < cap(*batch); i++ {
			slot := slots[(start+i)%len(slots)]
			select {
			case frame := <-slot.recvQ:
				*batch = append(*batch, frame)
				roundProgress = true
				progressed = true
			default:
			}
		}
		if !roundProgress {
			break
		}
		start = (start + 1) % len(slots)
	}
	if progressed {
		e.recvPathCursor = uint64(start)
	}
	return progressed
}

func (e *Engine) recvSlotsSnapshot() []*pathSlot {
	return e.recvSlotsSnapshotInto(nil)
}

func (e *Engine) recvSlotsSnapshotInto(dst []*pathSlot) []*pathSlot {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	return e.receiveSlotsAppendLocked(dst)
}

// receiveSlotsLocked includes staged and retained paths: both are deliberately
// TX-invisible but must keep accepting sequenced DATA and activation controls
// throughout the overlap window. Caller holds pathsMu for reading or writing.
func (e *Engine) receiveSlotsLocked() []*pathSlot {
	return e.receiveSlotsAppendLocked(nil)
}

func (e *Engine) receiveSlotsAppendLocked(slots []*pathSlot) []*pathSlot {
	for _, set := range []map[uint32]*pathSlot{e.paths, e.stagedPaths, e.retainedPaths} {
		for _, slot := range set {
			slots = append(slots, slot)
		}
	}
	if len(slots) == 0 {
		return nil
	}
	for i := 1; i < len(slots); i++ {
		for j := i; j > 0 && slots[j-1].id > slots[j].id; j-- {
			slots[j-1], slots[j] = slots[j], slots[j-1]
		}
	}
	return slots
}

// onRecvBatch inserts frames into the reorder buffer and drains any
// in-order suffix. Caller guarantees all work in batch belongs to the
// same Engine instance; the function takes recvMu once for the whole
// batch to amortise dedup/reorder cost at high packet rates.
func (e *Engine) onRecvBatch(batch []recvFrame) {
	if len(batch) == 0 {
		return
	}
	deliverPackets := make([]recvPacketDelivery, 0, len(batch))
	e.recvMu.Lock()
	wokeReader := false
	for _, frame := range batch {
		if e.recvTerminal || e.closing.Load() {
			break
		}
		if e.onFrameRecvDigestLocked(
			frame.slot, frame.topologyEpoch, frame.hdr,
			frame.payload, frame.digest, &deliverPackets,
		) {
			wokeReader = true
		}
	}
	for _, delivery := range deliverPackets {
		select {
		case e.recvPacketCh <- delivery.payload:
			e.commitUniqueTargetDeliveryLocked(
				delivery.cohort, delivery.topologyEpoch,
				delivery.attributable, delivery.demand, delivery.bytes,
			)
			e.markPayloadLocked()
		case <-e.closed:
			e.recvMu.Unlock()
			return
		}
	}
	ackNext, ackGap, ackProof := e.receiveAckStateLocked(e.recvTerminal || e.recvStreamEOF)
	if wokeReader || e.isClosed() {
		e.recvCond.Broadcast()
	}
	finalErr := e.takeRecvFinalLocked()
	e.recvMu.Unlock()
	e.finishReceiveProgress(ackNext, ackGap, ackProof, finalErr)
}

func (e *Engine) receiveAckStateLocked(force bool) (uint64, bool, proto.AckProof) {
	nextSeq := e.expectedRecvSeq
	gap := e.recvHasGapLocked()
	advanced := nextSeq > e.recvAckSent
	if !advanced && !gap {
		return 0, false, e.recvProof
	}
	if !force && !gap && !e.recvControlAckPending && !e.recvDataAckUrgent && nextSeq-e.recvAckSent < recvAckFrameThreshold {
		return 0, false, e.recvProof
	}
	if advanced {
		e.recvAckSent = nextSeq
	}
	e.recvControlAckPending = false
	e.recvDataAckUrgent = false
	return nextSeq, gap, e.recvProof
}

func (e *Engine) takeRecvFinalLocked() error {
	if e.recvFinalErr == nil || e.recvFinalHandled {
		return nil
	}
	e.recvFinalHandled = true
	return e.recvFinalErr
}

func (e *Engine) finishReceiveProgress(nextSeq uint64, gap bool, proof proto.AckProof, finalErr error) {
	if finalErr != nil {
		if errors.Is(finalErr, io.EOF) {
			// BYE is session-wide even though one physical slot carried the
			// frame. Mark every admitted receive route before publishing the
			// terminal ACK so the peer's ensuing all-path close is classified as
			// clean on siblings too, rather than spawning migration work.
			e.markPeerByeSeen()
		}
		if nextSeq != 0 || gap {
			e.sendTerminalAck(nextSeq, gap, proof)
		}
		if errors.Is(finalErr, io.EOF) {
			// BYE terminates the session; STREAM_FIN is the distinct operation
			// that preserves reverse writes. Publish the peer-BYE exception under
			// the same epoch lock as path preparation so a racing admission is
			// either rejected normally or retained solely as an ACK route.
			e.sessionEpochMu.Lock()
			e.policyLifecycleMu.Lock()
			e.policyStateMu.Lock()
			e.peerNormalBye.Store(true)
			e.sendWriteClosed.Store(true)
			e.sendClosing.Store(true)
			e.policyStateMu.Unlock()
			e.policyLifecycleMu.Unlock()
			e.sessionEpochMu.Unlock()
			e.schedulePeerByeClose()
			e.recvMu.Lock()
			e.recvCond.Broadcast()
			e.recvMu.Unlock()
			select {
			case e.recvPacketWake <- struct{}{}:
			default:
			}
			return
		}
		e.setCloseErr(finalErr)
		e.requestClose()
		return
	}
	if nextSeq != 0 || gap {
		e.sendAck(nextSeq, gap, proof)
	}
}

func (e *Engine) schedulePeerByeClose() {
	e.peerByeMu.Lock()
	if e.peerByeCloseDone != nil || e.closing.Load() {
		e.peerByeMu.Unlock()
		return
	}
	done := make(chan struct{})
	e.peerByeCloseDone = done
	e.peerByeMu.Unlock()

	retention := e.limits.MigrationBudget
	if retention > 2*time.Second {
		retention = 2 * time.Second
	}
	if retention <= 0 {
		retention = pathCloseTimeout
	}
	retention += pathCloseTimeout
	go func() {
		defer close(done)
		timer := time.NewTimer(retention)
		defer timer.Stop()
		select {
		case <-e.closed:
			return
		case <-timer.C:
			e.requestClose()
		}
	}()
}

func (e *Engine) markPeerByeSeen() {
	e.pathsMu.RLock()
	slots := e.receiveSlotsLocked()
	e.pathsMu.RUnlock()
	for _, slot := range slots {
		if marker, ok := slot.conn.(interface{ MarkByeSeen() }); ok {
			marker.MarkByeSeen()
		}
	}
}

func (e *Engine) recvHasGapLocked() bool {
	if e.recvDroppedThrough != 0 && e.expectedRecvSeq <= e.recvDroppedThrough {
		return true
	}
	if len(e.recvQueue) > 0 {
		if _, ok := e.recvQueue[e.expectedRecvSeq]; !ok {
			return true
		}
	}
	return e.packetized && e.recvPacketMarks > 0 && !e.packetHeadSeenLocked()
}

// onFrameRecvLocked inserts a frame into the reorder buffer and drains
// any now-contiguous suffix. Returns true if payload became readable
// by the application.
//
// The SEQ namespace is shared between data and ctrl frames (see
// each consumes one SEQ for the contiguous-stream invariant). The
// drainer dispatches each in turn so the application stream remains
// contiguous regardless of how ctrl frames are interleaved.
func (e *Engine) onFrameRecvLocked(slot *pathSlot, hdr proto.Header, payload []byte, deliverPackets *[][]byte) bool {
	deliveries := make([]recvPacketDelivery, 0, 1)
	topologyEpoch := e.currentPathTopologyEpoch()
	if slot != nil && slot.topologyEpoch.Load() != 0 {
		topologyEpoch = slot.topologyEpoch.Load()
	}
	woke := e.onFrameRecvDigestLocked(
		slot, topologyEpoch, hdr, payload, recvFrameDigest(hdr, payload), &deliveries,
	)
	for _, delivery := range deliveries {
		if deliverPackets != nil {
			*deliverPackets = append(*deliverPackets, delivery.payload)
		}
		e.commitUniqueTargetDeliveryLocked(
			delivery.cohort, delivery.topologyEpoch,
			delivery.attributable, delivery.demand, delivery.bytes,
		)
		e.markPayloadLocked()
	}
	return woke
}

func (e *Engine) onFrameRecvDigestLocked(
	slot *pathSlot,
	topologyEpoch uint64,
	hdr proto.Header,
	payload []byte,
	digest proto.FrameDigest,
	deliverPackets *[]recvPacketDelivery,
) bool {
	if e.recvTerminal || e.closing.Load() {
		return false
	}
	var cohort rootDeliveryCohort
	var attributable bool
	var demand bool
	if hdr.Type == proto.FrameData {
		var err error
		payload, cohort, attributable, demand, err = e.decodePeerApplicationPayload(slot, hdr.Flags, payload)
		if err != nil {
			e.publishRecvTerminalLocked(fmt.Errorf("%w: invalid DATA target attribution: %v", ErrPeerProtocol, err))
			return false
		}
	}
	if hdr.Seq < e.expectedRecvSeq {
		// Duplicate (race / redistribute) or out-of-window.
		e.recvDups++
		if slot != nil {
			slot.recvDups.Add(1)
		}
		if accepted, ok := e.recvDeliveredDigests[hdr.Seq]; ok && accepted != digest {
			e.publishRecvTerminalLocked(fmt.Errorf("%w: altered frame reused delivered sequence %d", ErrPeerProtocol, hdr.Seq))
			return false
		}
		// Policy phases are transaction-idempotent and cache their exact
		// responses. Re-deliver an already-sequenced phase to the policy
		// inbox so replaying the same outer SEQ can recover a lost response
		// without consuming another control slot. It does not advance the
		// receive proof or application sequence a second time.
		if hdr.Type == proto.FrameCtrl && isReplayableTransactionCtrl(proto.CtrlCodeFromFlags(hdr.Flags)) {
			if accepted, ok := e.policyReplayDigests[hdr.Seq]; ok {
				if accepted != digest {
					e.publishRecvTerminalLocked(fmt.Errorf("%w: altered policy frame reused sequence %d", ErrPeerProtocol, hdr.Seq))
					return false
				}
				e.applyPolicyCtrlAtCustodyLocked(hdr.Seq, recvItem{
					slot: slot, isCtrl: true, flags: hdr.Flags,
					payload: payload, digest: digest,
				})
			}
		}
		return false
	}

	if e.packetized && hdr.Type != proto.FrameCtrl {
		cap := e.packetSeenCapLocked()
		if cap > 0 {
			delta := hdr.Seq - e.expectedRecvSeq
			if delta >= cap || e.recvPacketMarks >= sendHistoryWindow {
				if hdr.Seq > e.recvDroppedThrough {
					e.recvDroppedThrough = hdr.Seq
				}
				return false
			}
			if delta < cap {
				if e.packetSeenLocked(hdr.Seq) {
					if accepted, ok := e.recvFrameProofs[hdr.Seq]; ok && accepted.digest != digest {
						e.publishRecvTerminalLocked(fmt.Errorf("%w: altered DATA reused packet sequence %d", ErrPeerProtocol, hdr.Seq))
						return false
					}
					e.recvDups++
					if slot != nil {
						slot.recvDups.Add(1)
					}
					return false
				}
				if _, exists := e.recvQueue[hdr.Seq]; exists {
					e.recvDups++
					if slot != nil {
						slot.recvDups.Add(1)
					}
					return false
				}
				if err := e.validateTargetDeliveryCohortLocked(cohort); err != nil {
					e.failTargetDeliveryAttributionLocked(err)
					return false
				}
				e.packetMarkSeenLocked(hdr.Seq)
				e.recvFrameProofs[hdr.Seq] = recvPacketProof{
					digest: digest, topologyEpoch: topologyEpoch,
					cohort: cohort, attributable: attributable, demand: demand,
					bytes: len(payload), deliverySeen: true,
				}
				e.recvPacketMarks++
				e.noteRecvDataForAckLocked()
				*deliverPackets = append(*deliverPackets, recvPacketDelivery{
					payload: payload, topologyEpoch: topologyEpoch,
					cohort: cohort, attributable: attributable,
					demand: demand, bytes: len(payload),
				})
				if n := len(e.recvQueue) + e.recvPacketMarks; n > e.recvQueueHWM {
					e.recvQueueHWM = n
				}

				e.drainContiguousLocked(deliverPackets)
				return true
			}
		}
	}

	if existing, exists := e.recvQueue[hdr.Seq]; exists {
		// Same SEQ already buffered (race-mode in-flight duplicate):
		// keep the first copy, count the second.
		if existing.digest != digest {
			e.publishRecvTerminalLocked(fmt.Errorf("%w: altered frame reused sequence %d", ErrPeerProtocol, hdr.Seq))
			return false
		}
		e.recvDups++
		if slot != nil {
			slot.recvDups.Add(1)
		}
		if existing.ctrlApplied && existing.isCtrl &&
			isPolicyCtrl(proto.CtrlCodeFromFlags(existing.flags)) {
			e.applyPolicyCtrlAtCustodyLocked(hdr.Seq, existing)
		}
		return false
	}

	if hdr.Seq != e.expectedRecvSeq && len(e.recvQueue) >= recvReorderWindowLimit {
		go func() {
			e.setCloseErr(ErrRecvWindowExceeded)
			_ = e.Close()
		}()
		return false
	}
	if hdr.Type == proto.FrameData {
		if err := e.validateTargetDeliveryCohortLocked(cohort); err != nil {
			e.failTargetDeliveryAttributionLocked(err)
			return false
		}
	}

	if hdr.Type != proto.FrameCtrl {
		e.noteRecvDataForAckLocked()
	}
	e.recvQueue[hdr.Seq] = recvItem{
		slot: slot, topologyEpoch: topologyEpoch,
		isCtrl: hdr.Type == proto.FrameCtrl, flags: hdr.Flags,
		cohort: cohort, attributable: attributable, demand: demand,
		bytes: len(payload), payload: payload, digest: digest,
	}
	if hdr.Type == proto.FrameCtrl && isPolicyCtrl(proto.CtrlCodeFromFlags(hdr.Flags)) {
		item := e.recvQueue[hdr.Seq]
		item.ctrlApplied = e.applyPolicyCtrlAtCustodyLocked(hdr.Seq, item)
		e.recvQueue[hdr.Seq] = item
	}
	if e.packetized && hdr.Type != proto.FrameCtrl {
		// Packet mode follows datagram semantics: preserve packet
		// boundaries, dedupe by SEQ, but do not block application
		// delivery behind an unrelated missing earlier SEQ. Keep a
		// lightweight marker in recvQueue so control-frame ordering and
		// duplicate suppression still have a shared SEQ view.
		item := e.recvQueue[hdr.Seq]
		*deliverPackets = append(*deliverPackets, recvPacketDelivery{
			payload: item.payload, topologyEpoch: item.topologyEpoch,
			cohort: item.cohort, attributable: item.attributable,
			demand: item.demand, bytes: item.bytes,
		})
		item.payload = nil
		item.delivered = true
		e.recvQueue[hdr.Seq] = item
	}
	if n := len(e.recvQueue) + e.recvPacketMarks; n > e.recvQueueHWM {
		e.recvQueueHWM = n
	}

	return e.drainContiguousLocked(deliverPackets)
}

func (e *Engine) noteRecvDataForAckLocked() {
	if e.recvAckBurstOpen {
		return
	}
	e.recvAckBurstOpen = true
	e.recvDataAckUrgent = true
}

func isPolicyCtrl(code proto.CtrlCode) bool {
	return code == proto.CtrlPolicyPrepare || code == proto.CtrlPolicyAck || code == proto.CtrlPolicyCommit
}

func isLeafMobilityCtrl(code proto.CtrlCode) bool {
	return code == proto.CtrlLeafMobilityPrepare || code == proto.CtrlLeafMobilityAck || code == proto.CtrlLeafMobilityCommit
}

func isReplayableTransactionCtrl(code proto.CtrlCode) bool {
	return isPolicyCtrl(code)
}

// applyPolicyCtrlAtCustodyLocked admits policy work as soon as its exact frame
// enters the bounded receive window. DATA delivery and cumulative ACK proof
// remain ordered by SEQ. This prevents an unrelated slow DATA frame from
// consuming the whole policy transaction TTL.
//
// PREPARE and ACK are causally self-contained. COMMIT is admitted early only
// after the matching PREPARE has entered the policy FIFO; otherwise it remains
// in recvQueue until that PREPARE arrives or normal SEQ order reaches it.
// Caller holds recvMu.
func (e *Engine) applyPolicyCtrlAtCustodyLocked(seq uint64, item recvItem) bool {
	if e.recvTerminal || e.closing.Load() || e.isClosed() {
		return false
	}
	code := proto.CtrlCodeFromFlags(item.flags)
	switch code {
	case proto.CtrlPolicyPrepare:
		prepare, err := proto.DecodePolicyPrepare(item.payload)
		if err != nil {
			e.failPolicyCtrlCustodyLocked("PREPARE", err)
			return false
		}
		digest, err := prepare.ProposalDigest()
		if err != nil {
			e.failPolicyCtrlCustodyLocked("PREPARE", err)
			return false
		}
		key := recvPolicyPhaseKey{
			kind: policyMessagePrepare, transactionID: prepare.TransactionID,
		}
		receipt := recvPolicyPhaseReceipt{
			seq: seq, frameDigest: item.digest, proposalDigest: digest,
		}
		if !e.validateRecvPolicyPhaseLocked(key, receipt) {
			return false
		}
		message := policyMessage{
			kind: policyMessagePrepare,
			key: policyMessageKey{
				kind: policyMessagePrepare, seq: seq, frameDigest: item.digest,
			},
			prepare: prepare,
		}
		if !e.enqueuePolicyMessageLocked(message) {
			return false
		}
		e.rememberRecvPolicyPhaseLocked(key, receipt)
		e.applyDeferredPolicyCommitsLocked(seq, prepare.TransactionID, digest)
		return true

	case proto.CtrlPolicyAck:
		ack, err := proto.DecodePolicyAck(item.payload)
		if err != nil {
			e.failPolicyCtrlCustodyLocked("ACK", err)
			return false
		}
		key := recvPolicyPhaseKey{
			kind: policyMessageAck, phase: ack.Phase, transactionID: ack.TransactionID,
		}
		receipt := recvPolicyPhaseReceipt{
			seq: seq, frameDigest: item.digest, proposalDigest: ack.ProposalDigest,
		}
		if !e.validateRecvPolicyPhaseLocked(key, receipt) {
			return false
		}
		message := policyMessage{
			kind: policyMessageAck,
			key: policyMessageKey{
				kind: policyMessageAck, seq: seq, frameDigest: item.digest,
			},
			ack: ack,
		}
		if !e.enqueuePolicyMessageLocked(message) {
			return false
		}
		e.rememberRecvPolicyPhaseLocked(key, receipt)
		return true

	case proto.CtrlPolicyCommit:
		commit, err := proto.DecodePolicyCommit(item.payload)
		if err != nil {
			e.failPolicyCtrlCustodyLocked("COMMIT", err)
			return false
		}
		key := recvPolicyPhaseKey{
			kind: policyMessageCommit, transactionID: commit.TransactionID,
		}
		receipt := recvPolicyPhaseReceipt{
			seq: seq, frameDigest: item.digest, proposalDigest: commit.ProposalDigest,
		}
		if !e.validateRecvPolicyPhaseLocked(key, receipt) {
			return false
		}
		prepare, ok := e.recvPolicyPhases[recvPolicyPhaseKey{
			kind: policyMessagePrepare, transactionID: commit.TransactionID,
		}]
		if !ok {
			if seq == e.expectedRecvSeq {
				e.failPolicyCtrlCustodyLocked("COMMIT", fmt.Errorf("matching PREPARE was not received at a lower sequence"))
			}
			return false
		}
		if prepare.proposalDigest != commit.ProposalDigest || prepare.seq >= seq {
			e.failPolicyCtrlCustodyLocked("COMMIT", fmt.Errorf("does not follow its exact PREPARE"))
			return false
		}
		message := policyMessage{
			kind: policyMessageCommit,
			key: policyMessageKey{
				kind: policyMessageCommit, seq: seq, frameDigest: item.digest,
			},
			commit: commit,
		}
		if !e.enqueuePolicyMessageLocked(message) {
			return false
		}
		e.rememberRecvPolicyPhaseLocked(key, receipt)
		return true
	}
	return false
}

func (e *Engine) validateRecvPolicyPhaseLocked(
	key recvPolicyPhaseKey,
	receipt recvPolicyPhaseReceipt,
) bool {
	if current, exists := e.recvPolicyPhases[key]; exists && current != receipt {
		e.failPolicyCtrlCustodyLocked("phase", fmt.Errorf("transaction phase changed sequence or payload"))
		return false
	}
	return true
}

func (e *Engine) rememberRecvPolicyPhaseLocked(
	key recvPolicyPhaseKey,
	receipt recvPolicyPhaseReceipt,
) {
	if _, exists := e.recvPolicyPhases[key]; exists {
		return
	}
	e.recvPolicyPhases[key] = receipt
	e.recvPolicyPhaseOrder = append(e.recvPolicyPhaseOrder, key)
	for len(e.recvPolicyPhaseOrder) > policyReplayDigestLimit {
		oldest := e.recvPolicyPhaseOrder[0]
		e.recvPolicyPhaseOrder = e.recvPolicyPhaseOrder[1:]
		delete(e.recvPolicyPhases, oldest)
	}
}

func (e *Engine) failPolicyCtrlCustodyLocked(phase string, err error) {
	if e.recvTerminal {
		return
	}
	e.publishRecvTerminalLocked(fmt.Errorf("%w: invalid POLICY_%s: %v", ErrPeerProtocol, phase, err))
}

// applyDeferredPolicyCommitsLocked preserves PREPARE-before-COMMIT FIFO
// causality when different paths deliver the outer SEQ frames out of order.
// Caller holds recvMu.
func (e *Engine) applyDeferredPolicyCommitsLocked(
	prepareSeq uint64,
	transactionID [16]byte,
	digest proto.PolicyProposalDigest,
) {
	seqs := make([]uint64, 0, 1)
	for seq, item := range e.recvQueue {
		if item.ctrlApplied || !item.isCtrl ||
			proto.CtrlCodeFromFlags(item.flags) != proto.CtrlPolicyCommit {
			continue
		}
		commit, err := proto.DecodePolicyCommit(item.payload)
		if err == nil && commit.TransactionID == transactionID &&
			commit.ProposalDigest == digest {
			if seq <= prepareSeq {
				e.failPolicyCtrlCustodyLocked("COMMIT", fmt.Errorf("sequence %d does not follow PREPARE sequence %d", seq, prepareSeq))
				return
			}
			seqs = append(seqs, seq)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for _, seq := range seqs {
		item, ok := e.recvQueue[seq]
		if !ok || item.ctrlApplied {
			continue
		}
		item.ctrlApplied = e.applyPolicyCtrlAtCustodyLocked(seq, item)
		e.recvQueue[seq] = item
		if e.recvTerminal || !item.ctrlApplied {
			return
		}
	}
}

func (e *Engine) drainContiguousLocked(deliverPackets *[]recvPacketDelivery) bool {
	wokeReader := false
	for {
		item, ok := e.recvQueue[e.expectedRecvSeq]
		if !ok {
			if e.packetized && e.packetHeadSeenLocked() {
				e.packetConsumeHeadLocked()
				e.expectedRecvSeq++
				continue
			}
			break
		}
		if !e.packetized && !item.isCtrl && len(e.recvDeliverFrames) >= streamRecvWindowFrames {
			break
		}
		ctrlCode := proto.CtrlCode(0)
		if item.isCtrl {
			ctrlCode = proto.CtrlCodeFromFlags(item.flags)
			if ctrlCode == proto.CtrlPathRetire && !e.enqueueSequencedPathRetirementLocked(item.payload) {
				// Do not advance the cumulative proof over control work the
				// bounded engine worker could not accept. The terminal path will
				// acknowledge only the prefix already owned by this engine.
				break
			}
			if isPolicyCtrl(ctrlCode) && !item.ctrlApplied {
				item.ctrlApplied = e.applyPolicyCtrlAtCustodyLocked(e.expectedRecvSeq, item)
				e.recvQueue[e.expectedRecvSeq] = item
				if !item.ctrlApplied {
					break
				}
			}
		}
		seq := e.expectedRecvSeq
		delete(e.recvQueue, seq)
		e.recvProof = proto.AdvanceAckProof(e.recvProof, item.digest)
		e.rememberDeliveredDigestLocked(seq, item.digest)
		e.expectedRecvSeq++
		if e.packetized {
			e.packetAdvanceHeadLocked()
		}
		if item.isCtrl {
			e.recvControlAckPending = true
			if isReplayableTransactionCtrl(ctrlCode) {
				e.rememberPolicyReplayDigestLocked(seq, item.digest)
			}
			if ctrlCode != proto.CtrlPathRetire && !isPolicyCtrl(ctrlCode) {
				e.applyCtrlLocked(item.slot, item.flags, item.payload, false)
			}
			if e.recvTerminal {
				break
			}
		} else {
			if e.recvStreamEOF {
				e.publishRecvTerminalLocked(fmt.Errorf("%w: DATA after STREAM_FIN", ErrPeerProtocol))
				break
			}
			if e.packetized {
				if !item.delivered {
					// DATA at the SEQ head may still be pending if it
					// arrived in-order; preserve boundaries 1:1.
					*deliverPackets = append(*deliverPackets, recvPacketDelivery{
						payload: item.payload, topologyEpoch: item.topologyEpoch,
						cohort: item.cohort, attributable: item.attributable,
						demand: item.demand, bytes: item.bytes,
					})
				}
			} else {
				e.commitUniqueTargetDeliveryLocked(
					item.cohort, item.topologyEpoch,
					item.attributable, item.demand, item.bytes,
				)
				e.recvDeliver = append(e.recvDeliver, item.payload...)
				e.recvDeliverFrames = append(e.recvDeliverFrames, len(item.payload))
				e.markPayloadLocked()
			}
			wokeReader = true
		}
	}
	return wokeReader
}

func rootHasImmediateChild(root proto.GraphNode, targetID proto.TargetID) bool {
	for _, childID := range root.Children {
		if childID == targetID {
			return true
		}
	}
	return false
}

func (e *Engine) rememberPolicyReplayDigestLocked(seq uint64, digest proto.FrameDigest) {
	if _, exists := e.policyReplayDigests[seq]; exists {
		return
	}
	e.policyReplayDigests[seq] = digest
	e.policyReplayOrder = append(e.policyReplayOrder, seq)
	for len(e.policyReplayOrder) > policyReplayDigestLimit {
		oldest := e.policyReplayOrder[0]
		e.policyReplayOrder = e.policyReplayOrder[1:]
		delete(e.policyReplayDigests, oldest)
	}
}

func recvFrameDigest(hdr proto.Header, payload []byte) proto.FrameDigest {
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		return proto.FrameDigest{}
	}
	copy(frame[proto.HeaderSize:], payload)
	return proto.DigestFrame(frame)
}

// applyCtrlLocked dispatches a control frame whose SEQ has reached
// the head of the reorder window. Caller holds recvMu.
//
// To avoid deadlocks against Close (which itself broadcasts the recv
// cond), heavyweight teardown work fires in a goroutine.
func (e *Engine) applyCtrlLocked(slot *pathSlot, flags uint16, payload []byte, replayed bool) {
	code := proto.CtrlCodeFromFlags(flags)
	switch code {
	case proto.CtrlBye:
		if e.recvTerminal {
			return
		}
		bye, err := proto.DecodeBye(payload)
		closeErr := error(ErrPeerProtocol)
		if err == nil {
			switch bye.Reason {
			case proto.ByeNormal:
				closeErr = io.EOF
				if pc, ok := slot.conn.(interface{ MarkByeSeen() }); ok {
					pc.MarkByeSeen()
				}
			case proto.ByeMigBudget:
				closeErr = ErrMigrationBudgetExceeded
			case proto.ByeZombie:
				closeErr = ErrZombie
			case proto.ByeProtoVer:
				closeErr = ErrPeerProtoVersion
			case proto.ByeAppRequest:
				closeErr = ErrPeerClosed
			}
		}
		e.publishRecvTerminalLocked(closeErr)

	case proto.CtrlStreamFin:
		if e.packetized || len(payload) != 0 || e.recvStreamEOF {
			e.publishRecvTerminalLocked(fmt.Errorf("%w: invalid STREAM_FIN", ErrPeerProtocol))
			return
		}
		e.recvStreamEOF = true
		e.recvCond.Broadcast()

	case proto.CtrlMigrateNotify,
		proto.CtrlHeartbeat,
		proto.CtrlPathQuality,
		proto.CtrlBridgeTag,
		proto.CtrlHello:
		// M1 ignores these on the read side; they consume a SEQ slot
		// purely to keep the reorder window contiguous.
		_ = payload
	}
}

func pathRefForSlot(slot *pathSlot) PathRef {
	if slot == nil {
		return PathRef{}
	}
	return PathRef{ID: slot.id, Owner: slot.owner}
}

func (e *Engine) markPayload() {
	e.zombieMu.Lock()
	e.zombieLeft = e.limits.ZombieMaxMigrations
	e.zombieLastMig = time.Time{}
	e.zombieGeneration++
	e.zombieMu.Unlock()
}

// markPayloadLocked refreshes the zombie counter when payload makes
// it through. Caller holds recvMu for receive-order state; zombie
// state remains independently serialised by zombieMu.
//
// Resetting zombieLastMig to zero is intentional: after payload, the
// NEXT migration will compute "cooldown expired" as false and start
// from a fresh full counter.
func (e *Engine) markPayloadLocked() {
	e.markPayload()
}
