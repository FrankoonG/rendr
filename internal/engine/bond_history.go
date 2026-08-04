package engine

import (
	"errors"
	"net"

	"github.com/FrankoonG/rendr/proto"
)

const sendHistoryWindow = 256
const sendControlReserve = 8

type sendHistory struct {
	entries []sendHistoryEntry
}

type sendHistoryEntry struct {
	seq         uint64
	frame       []byte
	application bool
	control     bool
	terminal    bool
	proof       proto.AckProof
}

// reserveSendFrame gives a sequence number a replay owner before any path can
// observe it. Caller holds sendMu, while ACK processing owns sendHistMu so it
// can release backpressure without waiting behind an in-flight path write.
func (e *Engine) reserveSendFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, false)
}

func (e *Engine) reserveTerminalFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, true)
}

func (e *Engine) reserveSendFrameClass(frame []byte, terminal bool) error {
	if len(frame) < proto.HeaderSize {
		return proto.ErrBadHeader
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return err
	}
	entry := sendHistoryEntry{
		seq:         hdr.Seq,
		frame:       append([]byte(nil), frame...),
		application: hdr.Type == proto.FrameData && len(frame) > proto.HeaderSize,
		control:     hdr.Type == proto.FrameCtrl,
		terminal:    terminal,
	}
	entry.proof = proto.AdvanceAckProof(e.sendProof, proto.DigestFrame(frame))

	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
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

func (e *Engine) acquireSendSlot(control bool) error {
	slots := e.sendSlots
	if control {
		slots = e.sendControlSlots
	}
	select {
	case slots <- struct{}{}:
		return nil
	case <-e.closed:
		return net.ErrClosed
	}
}

func (e *Engine) releaseSendSlot(control bool) {
	if control {
		<-e.sendControlSlots
		return
	}
	<-e.sendSlots
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
	e.sendAckNext.Store(nextSeq)
	e.sendHistMu.Unlock()
	for _, entry := range released {
		if !entry.terminal {
			e.releaseSendSlot(entry.control)
		}
	}
	return true, application
}
