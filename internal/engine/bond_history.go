package engine

import (
	"errors"
	"net"

	"github.com/FrankoonG/rendr/proto"
)

const (
	// sendHistoryWindow bounds the number of unacknowledged application
	// frames. The former 256-frame limit capped a 1 KiB packet stream at only
	// 256 KiB in flight, regardless of the path BDP.
	sendHistoryWindow = 8 * 1024
	// sendHistoryByteLimit independently bounds the immutable replay payload.
	// A frame limit alone lets large frames consume excessive memory, while a
	// byte limit alone lets zero/small packet floods allocate unbounded entry
	// metadata. Both credits must be available before publication.
	sendHistoryByteLimit = 64 << 20
)
const sendControlReserve = 8

type sendHistory struct {
	entries []sendHistoryEntry
	// reservedFrames counts acquired application-frame credits, including a
	// writer that is still waiting for byte credit or sendMu publication.
	reservedFrames int
	// reservedBytes includes application-frame credits acquired by writers
	// that have not yet appended their ledger entry. This closes the race where
	// concurrent writers could all pass the byte check before sendMu orders
	// publication.
	reservedBytes  int
	frameHighWater int
	byteHighWater  int
	creditWaiters  int
	backpressure   uint64
	generation     uint64
}

// ReplayStats is a coherent read-only snapshot of the bounded application
// replay-credit domain. Control-frame reserve is intentionally separate.
type ReplayStats struct {
	FrameLimit         uint64
	ByteLimit          uint64
	FramesInUse        uint64
	BytesInUse         uint64
	FramesHighWater    uint64
	BytesHighWater     uint64
	PublishedNext      uint64
	AckNext            uint64
	CreditWaiters      uint64
	BackpressureEvents uint64
	Generation         uint64
}

type sendHistoryEntry struct {
	seq         uint64
	frame       []byte
	application bool
	control     bool
	terminal    bool
	priorProof  proto.AckProof
	proof       proto.AckProof
}

// reserveSendFrame gives a sequence number a replay owner before any path can
// observe it. Caller holds sendMu, while ACK processing owns sendHistMu so it
// can release backpressure without waiting behind an in-flight path write.
func (e *Engine) reserveSendFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, false, false)
}

func (e *Engine) reserveTerminalFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, true, false)
}

// reserveOwnedSendFrame transfers an otherwise-unaliased frame to the replay
// ledger. PathConn.Write follows io.Writer and may neither retain nor mutate
// the borrowed bytes, so dispatch can read the ledger-owned frame directly.
func (e *Engine) reserveOwnedSendFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, false, true)
}

func (e *Engine) reserveOwnedTerminalFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, true, true)
}

func (e *Engine) reserveSendFrameClass(frame []byte, terminal, takeOwnership bool) error {
	if len(frame) < proto.HeaderSize {
		return proto.ErrBadHeader
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return err
	}
	ledgerFrame := frame
	if !takeOwnership {
		ledgerFrame = append([]byte(nil), frame...)
	}
	entry := sendHistoryEntry{
		seq:         hdr.Seq,
		frame:       ledgerFrame,
		application: hdr.Type == proto.FrameData && len(frame) > proto.HeaderSize,
		control:     hdr.Type == proto.FrameCtrl,
		terminal:    terminal,
		priorProof:  e.sendProof,
	}
	entry.proof = proto.AdvanceAckProof(e.sendProof, proto.DigestFrame(frame))

	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	if e.closing.Load() {
		return net.ErrClosed
	}
	limit := sendHistoryWindow + sendControlReserve
	if terminal {
		limit++
	}
	if len(e.sendHist.entries) >= limit {
		return errors.New("engine: replay ledger capacity invariant violated")
	}
	e.sendHist.entries = append(e.sendHist.entries, entry)
	e.sendProof = entry.proof
	return nil
}

// rollbackReservedSendFrame removes the unpublished tail entry. It is valid
// only while sendMu is held and before publishSendSeq makes the SEQ observable.
func (e *Engine) rollbackReservedSendFrame(seq uint64) bool {
	e.sendHistMu.Lock()
	if len(e.sendHist.entries) == 0 {
		e.sendHistMu.Unlock()
		return false
	}
	last := len(e.sendHist.entries) - 1
	entry := e.sendHist.entries[last]
	if entry.seq != seq || e.sendPublishedNext.Load() > seq {
		e.sendHistMu.Unlock()
		return false
	}
	e.sendProof = entry.priorProof
	e.sendHist.entries[last] = sendHistoryEntry{}
	e.sendHist.entries = e.sendHist.entries[:last]
	e.sendHistMu.Unlock()
	if !entry.terminal {
		e.releaseSendSlot(entry.control, len(entry.frame))
	}
	return true
}

func (e *Engine) acquireSendSlot(control bool, frameBytes int) error {
	slots := e.sendSlots
	if control {
		slots = e.sendControlSlots
	}
	if control {
		select {
		case slots <- struct{}{}:
			return nil
		case <-e.closed:
			return net.ErrClosed
		}
	}
	if frameBytes <= 0 || frameBytes > sendHistoryByteLimit {
		return errors.New("engine: invalid replay byte credit request")
	}
	waiting := false
	markWaiting := func() {
		if waiting {
			return
		}
		waiting = true
		e.sendHistMu.Lock()
		e.sendHist.creditWaiters++
		e.sendHist.backpressure++
		e.sendHist.generation++
		e.sendHistMu.Unlock()
	}
	defer func() {
		if !waiting {
			return
		}
		e.sendHistMu.Lock()
		if e.sendHist.creditWaiters > 0 {
			e.sendHist.creditWaiters--
		}
		e.sendHist.generation++
		e.sendHistMu.Unlock()
	}()
	select {
	case slots <- struct{}{}:
	default:
		markWaiting()
		select {
		case slots <- struct{}{}:
		case <-e.closed:
			return net.ErrClosed
		}
	}
	e.sendHistMu.Lock()
	if e.closing.Load() {
		e.sendHistMu.Unlock()
		select {
		case <-slots:
		default:
		}
		return net.ErrClosed
	}
	e.sendHist.reservedFrames++
	if e.sendHist.reservedFrames > e.sendHist.frameHighWater {
		e.sendHist.frameHighWater = e.sendHist.reservedFrames
	}
	e.sendHist.generation++
	e.sendHistMu.Unlock()
	for {
		e.sendHistMu.Lock()
		if e.closing.Load() {
			if e.sendHist.reservedFrames > 0 {
				e.sendHist.reservedFrames--
				e.sendHist.generation++
			}
			e.sendHistMu.Unlock()
			select {
			case <-slots:
			default:
			}
			return net.ErrClosed
		}
		if e.sendHist.reservedBytes <= sendHistoryByteLimit-frameBytes {
			e.sendHist.reservedBytes += frameBytes
			if e.sendHist.reservedBytes > e.sendHist.byteHighWater {
				e.sendHist.byteHighWater = e.sendHist.reservedBytes
			}
			e.sendHist.generation++
			e.sendHistMu.Unlock()
			return nil
		}
		wake := e.sendCreditWake
		e.sendHistMu.Unlock()
		markWaiting()
		select {
		case <-wake:
		case <-e.closed:
			e.sendHistMu.Lock()
			if e.sendHist.reservedFrames > 0 {
				e.sendHist.reservedFrames--
				e.sendHist.generation++
			}
			e.sendHistMu.Unlock()
			select {
			case <-slots:
			default:
			}
			return net.ErrClosed
		}
	}
}

func (e *Engine) releaseSendSlot(control bool, frameBytes int) {
	if control {
		e.sendHistMu.Lock()
		select {
		case <-e.sendControlSlots:
		default:
			if !e.closing.Load() {
				e.sendHistMu.Unlock()
				panic("engine: control replay credit invariant violated")
			}
		}
		e.sendHistMu.Unlock()
		return
	}
	e.sendHistMu.Lock()
	if frameBytes <= 0 || frameBytes > e.sendHist.reservedBytes || e.sendHist.reservedFrames <= 0 {
		closing := e.closing.Load()
		e.sendHistMu.Unlock()
		if !closing {
			panic("engine: replay byte credit invariant violated")
		}
		select {
		case <-e.sendSlots:
		default:
		}
		return
	}
	e.sendHist.reservedFrames--
	e.sendHist.reservedBytes -= frameBytes
	select {
	case <-e.sendSlots:
	default:
		if !e.closing.Load() {
			e.sendHistMu.Unlock()
			panic("engine: replay frame token invariant violated")
		}
	}
	e.sendHist.generation++
	wake := e.sendCreditWake
	e.sendCreditWake = make(chan struct{})
	close(wake)
	e.sendHistMu.Unlock()
}

// ReplayStats returns the current bounded application replay-credit state.
func (e *Engine) ReplayStats() ReplayStats {
	if e == nil {
		return ReplayStats{FrameLimit: sendHistoryWindow, ByteLimit: sendHistoryByteLimit}
	}
	e.sendHistMu.Lock()
	stats := ReplayStats{
		FrameLimit:         sendHistoryWindow,
		ByteLimit:          sendHistoryByteLimit,
		FramesInUse:        uint64(e.sendHist.reservedFrames),
		BytesInUse:         uint64(e.sendHist.reservedBytes),
		FramesHighWater:    uint64(e.sendHist.frameHighWater),
		BytesHighWater:     uint64(e.sendHist.byteHighWater),
		CreditWaiters:      uint64(e.sendHist.creditWaiters),
		BackpressureEvents: e.sendHist.backpressure,
		Generation:         e.sendHist.generation,
		PublishedNext:      e.sendPublishedNext.Load(),
		AckNext:            e.sendAckNext.Load(),
	}
	e.sendHistMu.Unlock()
	if hook := e.replayStatsAfterCreditSnapshot; hook != nil {
		hook()
	}
	return stats
}

// releaseReplayStateOnClose discards every replay owner after lifecycle
// cancellation has made future publication impossible. Waiting writers wake
// through both closed and the byte-credit generation channel; late releases
// are idempotent because close owns every remaining channel token.
func (e *Engine) releaseReplayStateOnClose() {
	e.cancelTailReplay()
	e.sendHistMu.Lock()
	for i := range e.sendHist.entries {
		e.sendHist.entries[i] = sendHistoryEntry{}
	}
	e.sendHist.entries = nil
	e.sendHist.reservedFrames = 0
	e.sendHist.reservedBytes = 0
	e.sendHist.generation++
	wake := e.sendCreditWake
	e.sendCreditWake = make(chan struct{})
	close(wake)
	for {
		select {
		case <-e.sendSlots:
		default:
			goto control
		}
	}

control:
	for {
		select {
		case <-e.sendControlSlots:
		default:
			e.sendHistMu.Unlock()
			return
		}
	}
}

func (e *Engine) sendHistorySnapshot(ackNext uint64) [][]byte {
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()

	if len(e.sendHist.entries) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(e.sendHist.entries))
	for _, entry := range e.sendHist.entries {
		if entry.seq >= ackNext {
			out = append(out, append([]byte(nil), entry.frame...))
		}
	}
	return out
}

func (e *Engine) sendHistoryRange(nextSeq, target uint64) [][]byte {
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	if len(e.sendHist.entries) == 0 || target <= nextSeq {
		return nil
	}
	out := make([][]byte, 0, len(e.sendHist.entries))
	for _, entry := range e.sendHist.entries {
		if entry.seq < nextSeq {
			continue
		}
		if entry.seq >= target {
			break
		}
		out = append(out, append([]byte(nil), entry.frame...))
	}
	return out
}

func (e *Engine) sendHistoryFrame(seq uint64) []byte {
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	for _, entry := range e.sendHist.entries {
		if entry.seq == seq {
			return append([]byte(nil), entry.frame...)
		}
		if entry.seq > seq {
			break
		}
	}
	return nil
}

// acknowledgeSendFrames releases every contiguous replay entry below nextSeq.
// It reports whether the ACK proves delivery of application payload; control
// progress alone must not refresh zombie protection.
func (e *Engine) acknowledgeSendFrames(nextSeq uint64, proof proto.AckProof) (valid bool, application bool) {
	e.sendHistMu.Lock()
	current := e.sendAckNext.Load()
	if nextSeq < current {
		e.sendHistMu.Unlock()
		return false, false
	}
	if nextSeq == current {
		valid = proof == e.sendAckProof
		e.sendHistMu.Unlock()
		return valid, false
	}

	var expected proto.AckProof
	found := false
	for _, entry := range e.sendHist.entries {
		if entry.seq+1 == nextSeq {
			expected = entry.proof
			found = true
			break
		}
	}
	if !found || proof != expected {
		e.sendHistMu.Unlock()
		return false, false
	}

	cut := 0
	for cut < len(e.sendHist.entries) && e.sendHist.entries[cut].seq < nextSeq {
		application = application || e.sendHist.entries[cut].application
		cut++
	}
	if cut == 0 {
		e.sendHistMu.Unlock()
		return false, application
	}
	released := append([]sendHistoryEntry(nil), e.sendHist.entries[:cut]...)
	copy(e.sendHist.entries, e.sendHist.entries[cut:])
	for i := len(e.sendHist.entries) - cut; i < len(e.sendHist.entries); i++ {
		e.sendHist.entries[i] = sendHistoryEntry{}
	}
	e.sendHist.entries = e.sendHist.entries[:len(e.sendHist.entries)-cut]
	e.sendAckProof = proof
	for _, entry := range released {
		if entry.terminal {
			continue
		}
		if entry.control {
			<-e.sendControlSlots
			continue
		}
		if len(entry.frame) <= 0 || len(entry.frame) > e.sendHist.reservedBytes || e.sendHist.reservedFrames <= 0 {
			e.sendHistMu.Unlock()
			panic("engine: acknowledged replay credit invariant violated")
		}
		e.sendHist.reservedFrames--
		e.sendHist.reservedBytes -= len(entry.frame)
		<-e.sendSlots
	}
	e.sendAckNext.Store(nextSeq)
	e.sendHist.generation++
	wake := e.sendCreditWake
	e.sendCreditWake = make(chan struct{})
	close(wake)
	e.sendHistMu.Unlock()
	return true, application
}
