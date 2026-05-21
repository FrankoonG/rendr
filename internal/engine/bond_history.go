package engine

const bondRedistributeWindow = 256

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

func (s *pathSlot) bondSendHistorySnapshot() [][]byte {
	s.bondSendMu.Lock()
	defer s.bondSendMu.Unlock()

	if len(s.bondSendRing) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(s.bondSendRing))
	if !s.bondSendFull {
		for _, frame := range s.bondSendRing {
			out = append(out, append([]byte(nil), frame...))
		}
		return out
	}
	for i := 0; i < len(s.bondSendRing); i++ {
		idx := (s.bondSendNext + i) % len(s.bondSendRing)
		out = append(out, append([]byte(nil), s.bondSendRing[idx]...))
	}
	return out
}
