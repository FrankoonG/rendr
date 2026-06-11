package engine

import "github.com/FrankoonG/rendr/proto"

const bondRedistributeWindow = 256

const sendHistoryWindow = 256

type sendHistory struct {
	ring [][]byte
	next int
	full bool
}

func (e *Engine) rememberSendFrame(frame []byte) {
	cp := append([]byte(nil), frame...)

	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()

	if len(e.sendHist.ring) < sendHistoryWindow {
		e.sendHist.ring = append(e.sendHist.ring, cp)
		return
	}
	e.sendHist.ring[e.sendHist.next] = cp
	e.sendHist.next = (e.sendHist.next + 1) % sendHistoryWindow
	e.sendHist.full = true
}

func (e *Engine) sendHistorySnapshot(ackNext uint64) [][]byte {
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()

	if len(e.sendHist.ring) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(e.sendHist.ring))
	if !e.sendHist.full {
		for _, frame := range e.sendHist.ring {
			if !bondFrameAcked(frame, ackNext) {
				out = append(out, append([]byte(nil), frame...))
			}
		}
		return out
	}
	for i := 0; i < len(e.sendHist.ring); i++ {
		idx := (e.sendHist.next + i) % len(e.sendHist.ring)
		if !bondFrameAcked(e.sendHist.ring[idx], ackNext) {
			out = append(out, append([]byte(nil), e.sendHist.ring[idx]...))
		}
	}
	return out
}

func (s *pathSlot) rememberBondFrame(frame []byte) {
	cp := append([]byte(nil), frame...)

	s.bondSendMu.Lock()
	defer s.bondSendMu.Unlock()

	if len(s.bondSendRing) < bondRedistributeWindow {
		s.bondSendRing = append(s.bondSendRing, cp)
		return
	}
	s.bondSendRing[s.bondSendNext] = cp
	s.bondSendNext = (s.bondSendNext + 1) % bondRedistributeWindow
	s.bondSendFull = true
}

func (s *pathSlot) bondSendHistorySnapshot(ackNext uint64) [][]byte {
	s.bondSendMu.Lock()
	defer s.bondSendMu.Unlock()

	if len(s.bondSendRing) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(s.bondSendRing))
	if !s.bondSendFull {
		for _, frame := range s.bondSendRing {
			if !bondFrameAcked(frame, ackNext) {
				out = append(out, append([]byte(nil), frame...))
			}
		}
		return out
	}
	for i := 0; i < len(s.bondSendRing); i++ {
		idx := (s.bondSendNext + i) % len(s.bondSendRing)
		if !bondFrameAcked(s.bondSendRing[idx], ackNext) {
			out = append(out, append([]byte(nil), s.bondSendRing[idx]...))
		}
	}
	return out
}

func bondFrameAcked(frame []byte, ackNext uint64) bool {
	if ackNext == 0 || len(frame) < proto.HeaderSize {
		return false
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return false
	}
	return hdr.Seq < ackNext
}
