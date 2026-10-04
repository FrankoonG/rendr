package session

import (
	"io"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// Read implements the application read side (L01, L02, L07). It returns
// io.EOF only when the peer's FIN is at the contiguous delivery point; a
// carrier error never surfaces. Precedence: local Close → net.ErrClosed;
// EOF condition → io.EOF; session end → its error; read deadline passed →
// os.ErrDeadlineExceeded, also while bytes are buffered (net.Conn: a call
// after the deadline fails instead of reading; the bytes stay readable once
// the deadline is moved); then the buffered bytes. The EOF condition and the
// end only arise when nothing is readable. The copy into p happens outside
// the session lock; the commit afterwards decides "Read won" (data
// returned) or "Close won" ((0, net.ErrClosed), data discarded).
func (s *Session) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	s.mu.Lock()
	st := &s.st
	if len(p) == 0 {
		closed := st.closed
		s.mu.Unlock()
		if closed {
			return 0, errClosed
		}
		return 0, nil
	}
	for {
		var err error
		switch {
		case st.closed:
			err = errClosed
		case st.peerFinSet && st.rRead == st.peerFin:
			err = io.EOF // the only EOF source (L02)
		case st.ended:
			err = st.endErr // never EOF for a carrier error (L01)
		case deadlinePassed(&st.rdl):
			err = errDeadline // before buffered bytes, as net.Conn (L06)
		case st.rRead < st.rTail:
		default:
			st.rwaiting = true
			s.mu.Unlock()
			<-st.rwake
			s.mu.Lock()
			st.rwaiting = false
			continue
		}
		if err != nil {
			s.mu.Unlock()
			return 0, err
		}
		break
	}
	// View up to maxViews in-order slices; copy them outside the lock while
	// rcopying keeps Close and the end from releasing them (L07).
	var views [maxViews][]byte
	nv := 0
	want := min(uint64(len(p)), st.rTail-st.rRead)
	for i, x := 0, st.rRead; i < st.inq.n && nv < maxViews && want > 0; i++ {
		sg := st.inq.at(i)
		if sg.end() <= x {
			continue
		}
		v := sg.b[x-sg.off:]
		v = v[:min(uint64(len(v)), want)]
		views[nv] = v
		nv++
		x += uint64(len(v))
		want -= uint64(len(v))
	}
	st.rcopying = true
	s.mu.Unlock()

	n := 0
	for _, v := range views[:nv] {
		n += copy(p[n:], v)
	}
	if h := s.env.Hooks; h != nil && h.ReadDequeued != nil {
		h.ReadDequeued()
	}

	s.mu.Lock()
	st.rcopying = false
	if st.closed {
		// Close won: the dequeued bytes are dropped; Close consumed them
		// and left their release to this Read.
		if st.rfreePending {
			st.rfreePending = false
			st.releaseConsumed()
		}
		s.mu.Unlock()
		return 0, errClosed
	}
	st.rRead += uint64(n)
	st.delivered += uint64(n)
	st.lastData = time.Now()
	st.releaseConsumed()
	if !st.ended {
		s.ackCadenceLocked()
		s.peerFinCheckLocked()
	} else if st.rfreePending {
		// The session ended during the copy (RST, no-path expiry): this
		// Read still returns its bytes; the next one returns the error.
		st.rfreePending = false
		st.releaseRecv()
	}
	s.mu.Unlock()
	return n, nil
}

// Write copies p into the send buffer and returns (L10, L17): reserve under
// the lock, copy outside it, commit under it, in rounds of at most 256 KiB.
// Precedence before each round: local Close or CloseWrite → net.ErrClosed;
// session end → its error; write deadline → os.ErrDeadlineExceeded. A
// partial acceptance returns (k, err); after a deadline the k bytes are
// delivered (L06), after a session failure they are not guaranteed.
func (s *Session) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	var poll *time.Timer
	n, err := s.write(p, &poll)
	if poll != nil {
		poll.Stop()
	}
	return n, err
}

// write runs Write's rounds; poll is the lazily created budget-poll timer.
func (s *Session) write(p []byte, poll **time.Timer) (int, error) {
	n := 0
	s.mu.Lock()
	if len(p) == 0 {
		st := &s.st
		var err error
		switch {
		case st.closed || st.fin.requested:
			err = errClosed
		case st.ended:
			err = st.endErr
		case deadlinePassed(&st.wdl):
			err = errDeadline
		}
		s.mu.Unlock()
		return 0, err
	}
	for len(p) > 0 {
		var chunks [maxRoundChunks]*carrier.Buf
		k, pos, err := s.writeRoundLocked(p, &chunks, poll)
		if err != nil {
			s.mu.Unlock()
			return n, err
		}
		s.mu.Unlock()

		if h := writeCopyHook.Load(); h != nil && h.s == s {
			h.fn()
		}
		// [end, end+k) is reserved: no carrier writer reads it before the
		// commit, and the chunks stay referenced until then (§4.2).
		src := p[:k]
		for j := 0; len(src) > 0; j++ {
			m := copy(chunks[j].B[pos:chunkSize], src)
			src, pos = src[m:], 0
		}

		s.mu.Lock()
		if err := s.commitRoundLocked(k); err != nil {
			s.mu.Unlock()
			return n, err // this round is not delivered
		}
		n += int(k)
		p = p[k:]
	}
	s.mu.Unlock()
	return n, nil
}

// CloseWrite half-closes (L04): idempotent; the FIN offset is fixed at the
// reserved end at the time of the first call, so a Write that already holds
// a reservation completes below it and every later Write returns
// net.ErrClosed. Reading continues until the peer's FIN.
//
// It returns nil, also when repeated or after Close, so concurrent closers
// all see the same result (L03).
func (s *Session) CloseWrite() error {
	s.mu.Lock()
	s.closeWriteLocked(time.Now())
	s.mu.Unlock()
	s.ringActor()
	return nil
}

// Close returns at once (L03): CloseWrite semantics, buffered and future
// received data is discarded, every blocked call is woken with
// net.ErrClosed, and the session lingers in the background (≤ Linger) to
// deliver what was written and exchange FIN/DONE, then ends — or sends RST
// (AbortClosed if the peer keeps sending to a closed application, AbortLinger
// at expiry). Idempotent.
//
// It returns nil, also when repeated, so concurrent closers all see the
// same result (L03).
func (s *Session) Close() error {
	s.mu.Lock()
	s.closeLocked(time.Now())
	s.mu.Unlock()
	s.ringActor()
	return nil
}

// SetReadDeadline implements net.Conn deadline semantics for reads (L06): a
// per-direction generation timer; every call wakes blocked readers to
// re-evaluate; the zero time clears; a past time fails pending and future
// reads at once. Deadlines never affect control frames, retransmissions or
// ACKs.
func (s *Session) SetReadDeadline(t time.Time) error {
	return s.setDeadline(true, t)
}

// SetWriteDeadline is SetReadDeadline for writes.
func (s *Session) SetWriteDeadline(t time.Time) error {
	return s.setDeadline(false, t)
}
