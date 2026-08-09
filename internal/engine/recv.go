package engine

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const recvBatchSize = 64

const recvReorderWindowLimit = 16 * 1024
const streamRecvWindowFrames = sendHistoryWindow

// packetRecvWindowBits only needs to cover the sender's bounded unacknowledged
// ledger. A larger window lets a malicious peer pin the receive floor while
// forcing one frame-digest allocation per distant packet.
const packetRecvWindowBits = 512

// Keep transaction digests for the sender's entire bounded replay domain so an
// exact old phase can recover a lost receipt without being reclassified as an
// unsolicited new transaction.
const policyReplayDigestLimit = sendHistoryWindow + sendControlReserve

// recvItem is one frame waiting in the reorder buffer. Data frames
// hold the payload bytes; ctrl frames hold the flags so the in-order
// drainer can dispatch them after the SEQ space catches up.
type recvItem struct {
	slot    *pathSlot
	isCtrl  bool
	flags   uint16
	payload []byte
	digest  proto.FrameDigest
	// packet-mode data may be delivered as soon as the first copy
	// arrives; delivered tracks that early handoff so later SEQ-floor
	// advancement can retire the slot without delivering twice.
	delivered bool
}

// recvFrame is one decoded frame handed off by a path reader to the
// single recvLoop aggregator. Readers stay out of recvMu entirely;
// the aggregator batches reorder/dedup work so G3-scale fan-in no
// longer serialises four path goroutines on one mutex per frame.
type recvFrame struct {
	slot    *pathSlot
	hdr     proto.Header
	payload []byte
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
	if digest, ok := e.recvFrameProofs[e.expectedRecvSeq]; ok {
		e.recvProof = proto.AdvanceAckProof(e.recvProof, digest)
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
			ackNext, ackGap, ackProof := e.receiveAckStateLocked()
			finalErr := e.takeRecvFinalLocked()
			if wokeReader {
				e.recvCond.Broadcast()
			}
			e.recvMu.Unlock()
			e.finishReceiveProgress(ackNext, ackGap, ackProof, finalErr)
			return n, nil
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
		e.recvMu.Unlock()
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

	buf := make([]byte, MaxPayload+proto.HeaderSize)
	for {
		select {
		case <-slot.quit:
			return
		default:
		}

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

		if !e.enqueueRecvFrame(slot, hdr, payload) {
			return
		}
	}
}

// handlePathProbeRequest echoes the probe back on the same path so
// the peer can compute its RTT. Best-effort; a failed write just
// degrades quality measurement, it does not affect the application.
func (e *Engine) handlePathProbeRequest(slot *pathSlot, payload []byte) {
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
	_, _ = slot.writeFrame(frame)
}

// handlePathProbeReply matches the reply against an outstanding
// probe and, if found, updates the path's quality with the measured
// RTT.
func (e *Engine) handlePathProbeReply(slot *pathSlot, payload []byte) {
	if ack, ok := proto.DecodeAck(payload); ok {
		if e.notePeerAck(ack) && ack.Gap {
			e.requestGapReplay(ack.NextSeq)
		}
		return
	}
	p, err := proto.DecodeProbe(payload)
	if err != nil {
		return
	}
	e.probeMu.Lock()
	t0, ok := e.probeOutstanding[p.ID]
	if ok {
		delete(e.probeOutstanding, p.ID)
	}
	e.probeMu.Unlock()
	if !ok {
		return
	}
	rtt := nowFn().Sub(t0)
	if setter, ok := slot.conn.(interface {
		SetQuality(transport.PathQuality)
		Quality() transport.PathQuality
	}); ok {
		prev := setter.Quality()
		// Light jitter estimate: |new - prev| smoothed.
		jit := prev.Jitter
		if prev.RTT != 0 {
			diff := rtt - prev.RTT
			if diff < 0 {
				diff = -diff
			}
			jit = (jit*3 + diff) / 4
		}
		setter.SetQuality(transport.PathQuality{
			RTT:    rtt,
			Jitter: jit,
			LossPP: prev.LossPP,
			At:     nowFn(),
		})
	}
}

func (e *Engine) notePeerAck(ack proto.AckPayload) bool {
	binding := e.localGraphBinding()
	if ack.SessionEpoch != proto.SessionEpoch(e.FlowID()) ||
		ack.Direction != senderDirection(e.side) ||
		ack.GraphRevision != binding.revision ||
		ack.GraphDigest != binding.digest ||
		ack.NextSeq > e.sendPublishedNext.Load() {
		return false
	}
	valid, application := e.acknowledgeSendFrames(ack.NextSeq, ack.Proof)
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

func (e *Engine) enqueueAck(request ackRequest) bool {
	if e.isClosed() {
		return false
	}
	e.ackMu.Lock()
	if pending := e.ackPending; pending != nil {
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
	e.ackPending = &request
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
			request := e.ackPending
			e.ackPending = nil
			e.ackMu.Unlock()
			if request == nil {
				break
			}
			e.writeAck(*request)
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
	if pending := slot.ackPending; pending != nil {
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
	slot.ackPending = &request
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
		request := slot.ackPending
		slot.ackPending = nil
		if request == nil {
			slot.ackRunning = false
			slot.ackMu.Unlock()
			return
		}
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
func (e *Engine) enqueueRecvFrame(slot *pathSlot, hdr proto.Header, payload []byte) bool {
	select {
	case slot.recvQ <- recvFrame{slot: slot, hdr: hdr, payload: payload}:
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
	for {
		if e.fillRecvBatch(&batch) {
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
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	ticks := 0
	for {
		select {
		case <-e.closed:
			return
		case <-ticker.C:
			ticks++
			e.recvMu.Lock()
			nextSeq := e.expectedRecvSeq
			gap := e.recvHasGapLocked()
			proof := e.recvProof
			e.recvMu.Unlock()
			if gap || (nextSeq > 0 && ticks%10 == 0) {
				e.sendAck(nextSeq, gap, proof)
			}
		}
	}
}

func (e *Engine) fillRecvBatch(batch *[]recvFrame) bool {
	slots := e.recvSlotsSnapshot()
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
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	return e.receiveSlotsLocked()
}

// receiveSlotsLocked includes staged and retained paths: both are deliberately
// TX-invisible but must keep accepting sequenced DATA and activation controls
// throughout the overlap window. Caller holds pathsMu for reading or writing.
func (e *Engine) receiveSlotsLocked() []*pathSlot {
	ids := make([]uint32, 0, len(e.paths)+len(e.stagedPaths)+len(e.retainedPaths))
	slotsByID := make(map[uint32]*pathSlot, cap(ids))
	for _, set := range []map[uint32]*pathSlot{e.paths, e.stagedPaths, e.retainedPaths} {
		for id, slot := range set {
			ids = append(ids, id)
			slotsByID[id] = slot
		}
	}
	if len(ids) == 0 {
		return nil
	}
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
	slots := make([]*pathSlot, 0, len(ids))
	for _, id := range ids {
		slots = append(slots, slotsByID[id])
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
	deliverPackets := make([][]byte, 0, len(batch))
	e.recvMu.Lock()
	wokeReader := false
	for _, frame := range batch {
		if e.onFrameRecvLocked(frame.slot, frame.hdr, frame.payload, &deliverPackets) {
			wokeReader = true
		}
	}
	for _, pkt := range deliverPackets {
		select {
		case e.recvPacketCh <- pkt:
		case <-e.closed:
			e.recvMu.Unlock()
			return
		}
	}
	ackNext, ackGap, ackProof := e.receiveAckStateLocked()
	if wokeReader || e.isClosed() {
		e.recvCond.Broadcast()
	}
	finalErr := e.takeRecvFinalLocked()
	e.recvMu.Unlock()
	e.finishReceiveProgress(ackNext, ackGap, ackProof, finalErr)
}

func (e *Engine) receiveAckStateLocked() (uint64, bool, proto.AckProof) {
	ackNext := uint64(0)
	ackGap := false
	if e.expectedRecvSeq > e.recvAckSent {
		e.recvAckSent = e.expectedRecvSeq
		ackNext = e.expectedRecvSeq
	}
	if e.recvHasGapLocked() {
		ackNext = e.expectedRecvSeq
		ackGap = true
	}
	return ackNext, ackGap, e.recvProof
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
		if nextSeq != 0 || gap {
			e.sendTerminalAck(nextSeq, gap, proof)
		}
		e.setCloseErr(finalErr)
		e.requestClose()
		return
	}
	if nextSeq != 0 || gap {
		e.sendAck(nextSeq, gap, proof)
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
	digest := recvFrameDigest(hdr, payload)
	if hdr.Seq < e.expectedRecvSeq {
		// Duplicate (race / redistribute) or out-of-window.
		e.recvDups++
		if slot != nil {
			slot.recvDups.Add(1)
		}
		// Policy phases are transaction-idempotent and cache their exact
		// responses. Re-deliver an already-sequenced phase to the policy
		// inbox so replaying the same outer SEQ can recover a lost response
		// without consuming another control slot. It does not advance the
		// receive proof or application sequence a second time.
		if hdr.Type == proto.FrameCtrl && isReplayableTransactionCtrl(proto.CtrlCodeFromFlags(hdr.Flags)) {
			if accepted, ok := e.policyReplayDigests[hdr.Seq]; ok {
				if accepted != digest {
					e.recvFinalErr = fmt.Errorf("%w: altered policy frame reused sequence %d", ErrPeerProtocol, hdr.Seq)
					e.recvTerminal = true
					return false
				}
				e.applyCtrlLocked(slot, hdr.Flags, payload, true)
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
				e.packetMarkSeenLocked(hdr.Seq)
				e.recvFrameProofs[hdr.Seq] = digest
				e.recvPacketMarks++
				*deliverPackets = append(*deliverPackets, payload)
				e.markPayloadLocked()
				if n := len(e.recvQueue) + e.recvPacketMarks; n > e.recvQueueHWM {
					e.recvQueueHWM = n
				}

				e.drainContiguousLocked(deliverPackets)
				return true
			}
		}
	}

	if _, exists := e.recvQueue[hdr.Seq]; exists {
		// Same SEQ already buffered (race-mode in-flight duplicate):
		// keep the first copy, count the second.
		e.recvDups++
		if slot != nil {
			slot.recvDups.Add(1)
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

	e.recvQueue[hdr.Seq] = recvItem{
		slot:    slot,
		isCtrl:  hdr.Type == proto.FrameCtrl,
		flags:   hdr.Flags,
		payload: payload,
		digest:  digest,
	}
	if e.packetized && hdr.Type != proto.FrameCtrl {
		// Packet mode follows datagram semantics: preserve packet
		// boundaries, dedupe by SEQ, but do not block application
		// delivery behind an unrelated missing earlier SEQ. Keep a
		// lightweight marker in recvQueue so control-frame ordering and
		// duplicate suppression still have a shared SEQ view.
		item := e.recvQueue[hdr.Seq]
		*deliverPackets = append(*deliverPackets, item.payload)
		item.payload = nil
		item.delivered = true
		e.recvQueue[hdr.Seq] = item
		e.markPayloadLocked()
	}
	if n := len(e.recvQueue) + e.recvPacketMarks; n > e.recvQueueHWM {
		e.recvQueueHWM = n
	}

	return e.drainContiguousLocked(deliverPackets)
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

func (e *Engine) drainContiguousLocked(deliverPackets *[][]byte) bool {
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
		seq := e.expectedRecvSeq
		delete(e.recvQueue, seq)
		e.recvProof = proto.AdvanceAckProof(e.recvProof, item.digest)
		e.expectedRecvSeq++
		if e.packetized {
			e.packetAdvanceHeadLocked()
		}
		if item.isCtrl {
			if isReplayableTransactionCtrl(proto.CtrlCodeFromFlags(item.flags)) {
				e.rememberPolicyReplayDigestLocked(seq, item.digest)
			}
			e.applyCtrlLocked(item.slot, item.flags, item.payload, false)
			if e.recvTerminal {
				break
			}
		} else {
			if e.packetized {
				if !item.delivered {
					// DATA at the SEQ head may still be pending if it
					// arrived in-order; preserve boundaries 1:1.
					*deliverPackets = append(*deliverPackets, item.payload)
					e.markPayloadLocked()
				}
			} else {
				e.recvDeliver = append(e.recvDeliver, item.payload...)
				e.recvDeliverFrames = append(e.recvDeliverFrames, len(item.payload))
				e.markPayloadLocked()
			}
			wokeReader = true
		}
	}
	return wokeReader
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
		e.recvFinalErr = closeErr
		e.recvTerminal = true

	case proto.CtrlPolicyPrepare:
		prepare, err := proto.DecodePolicyPrepare(payload)
		var digest proto.PolicyProposalDigest
		if err == nil {
			digest, err = prepare.ProposalDigest()
		}
		message := policyMessage{
			kind:    policyMessagePrepare,
			key:     policyMessageKey{kind: policyMessagePrepare, transactionID: prepare.TransactionID, digest: digest},
			prepare: prepare,
		}
		if err != nil || !e.enqueuePolicyMessageLocked(message) {
			if err != nil {
				e.recvFinalErr = fmt.Errorf("%w: malformed POLICY_PREPARE: %v", ErrPeerProtocol, err)
				e.recvTerminal = true
			}
			return
		}

	case proto.CtrlPolicyAck:
		ack, err := proto.DecodePolicyAck(payload)
		message := policyMessage{
			kind: policyMessageAck,
			key:  policyMessageKey{kind: policyMessageAck, phase: ack.Phase, transactionID: ack.TransactionID, digest: ack.ProposalDigest},
			ack:  ack,
		}
		if err != nil || !e.enqueuePolicyMessageLocked(message) {
			if err != nil {
				e.recvFinalErr = fmt.Errorf("%w: malformed POLICY_ACK: %v", ErrPeerProtocol, err)
				e.recvTerminal = true
			}
			return
		}

	case proto.CtrlPolicyCommit:
		commit, err := proto.DecodePolicyCommit(payload)
		message := policyMessage{
			kind:   policyMessageCommit,
			key:    policyMessageKey{kind: policyMessageCommit, transactionID: commit.TransactionID, digest: commit.ProposalDigest},
			commit: commit,
		}
		if err != nil || !e.enqueuePolicyMessageLocked(message) {
			if err != nil {
				e.recvFinalErr = fmt.Errorf("%w: malformed POLICY_COMMIT: %v", ErrPeerProtocol, err)
				e.recvTerminal = true
			}
			return
		}

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
