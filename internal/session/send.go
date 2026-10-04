package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// The send buffer (design §4.2): bytes enter refcounted 64 KiB chunks
// through reserve (under mu) → copy (outside every lock) → commit (under
// mu). [end, resEnd) is reserved by the one Write that is copying (wmu
// serializes Writes) and is invisible to carrier writers until the commit;
// a FIN fixed at resEnd can therefore never overtake that copy (D9, F1).
// The session holds one reference per chunk and drops it once the chunk is
// acknowledged; a carrier writer holds its own reference for as long as a
// write may read the chunk, so acknowledged memory is never reused while
// a write still reads it (L17, L43).

// writeCopyHook, when set by a test, runs in Write after a round's
// reservation and before its copy, outside every lock (L03: a Close racing
// the first Write's copy). It is nil in production.
var writeCopyHook func()

// sendRoomLocked is the send-buffer room: W minus the unacknowledged and
// reserved bytes.
func (s *Session) sendRoomLocked() int64 {
	return s.window() - int64(s.st.resEnd-s.st.sBase)
}

// reserveChunksLocked makes sure chunks cover [resEnd, resEnd+k), taking
// new ones from the pool while the Budget grants them (TryGet), and
// returns how many of the k bytes are covered (0: wait for the Budget).
func (s *Session) reserveChunksLocked(k int64) int64 {
	st := &s.st
	held := int64(st.cbase + uint64(st.chunks.n)*chunkSize - st.resEnd)
	for held < k && !st.chunks.full() {
		b := s.env.Carrier.Bufs.TryGet(chunkSize, s.env.Carrier.Budget)
		if b == nil {
			break
		}
		st.chunks.push(b)
		held += chunkSize
	}
	return min(k, held)
}

// writeRoundLocked waits until one round of p can be reserved and reserves
// it: k bytes at [resEnd, resEnd+k), whose chunks are returned in dst with
// the position of the first byte in dst[0]. err is set (k == 0) when the
// Write must return instead, with the precedence of §9: local Close or
// CloseWrite, session end, offset exhaustion, write deadline.
func (s *Session) writeRoundLocked(p []byte, dst *[maxRoundChunks]*carrier.Buf, poll **time.Timer) (k int64, pos int, err error) {
	st := &s.st
	for {
		switch {
		case st.closed || st.fin.requested:
			return 0, 0, errClosed
		case st.ended:
			return 0, 0, st.endErr
		case st.exhausted:
			return 0, 0, errExhausted()
		case deadlinePassed(&st.wdl):
			return 0, 0, errDeadline
		}
		budgetBlocked := false
		if room := s.sendRoomLocked(); room > 0 {
			k = min(int64(len(p)), room, maxRound)
			if st.resEnd+uint64(k) > s.offsetLimit() {
				st.exhausted = true
				st.facts |= factExhausted
				s.ringActor()
				return 0, 0, errExhausted()
			}
			if k = s.reserveChunksLocked(k); k > 0 {
				break
			}
			budgetBlocked = true
		}
		st.wwaiting = true
		s.mu.Unlock()
		if budgetBlocked {
			// D16: no waiter list; a budget-blocked writer re-checks on a
			// timer (also woken by every event a blocked Write waits for).
			if *poll == nil {
				*poll = time.NewTimer(budgetPoll)
			} else {
				(*poll).Reset(budgetPoll)
			}
			select {
			case <-st.wwake:
			case <-(*poll).C:
			}
		} else {
			<-st.wwake
		}
		s.mu.Lock()
		st.wwaiting = false
	}
	start := st.resEnd
	first := start - st.cbase
	idx := int(first / chunkSize)
	pos = int(first % chunkSize)
	for j := range (pos + int(k) + chunkSize - 1) / chunkSize {
		dst[j] = st.chunks.at(idx + j)
	}
	st.resEnd += uint64(k)
	st.wcopying = true
	return k, pos, nil
}

// commitRoundLocked makes the copied round [end, end+k) visible to the
// carrier writers (or, if the session ended during the copy, releases the
// chunks endLocked could not release) and returns the error the Write
// returns, if any.
func (s *Session) commitRoundLocked(k int64) error {
	st := &s.st
	st.wcopying = false
	if st.ended {
		if st.wfreePending {
			st.wfreePending = false
			st.releaseChunks()
		}
		return st.endErr
	}
	now := time.Now()
	outstanding := st.sBase != st.end
	st.end += uint64(k)
	st.txBytes += uint64(k)
	st.lastData = now
	if !outstanding {
		// W7: the commit that made data outstanding restarts the rescue
		// clock; in bond mode the actor arms its rescue check from it.
		st.lastAdvance = now
		if s.p.Mode == ModeBond {
			s.ringActor()
		}
	}
	s.wakeDataLocked(now)
	return nil
}

// advanceSendLocked moves the acknowledged front to to (> sBase, ≤ sNext):
// it trims every lane's in-flight spans and the retransmission queue, drops
// the session's reference on every chunk now fully acknowledged (and, once
// nothing is outstanding or reserved, on the partial tail chunk too: an idle
// session holds no send memory), restarts the rescue clock and wakes a
// writer waiting for room (D17 hysteresis).
func (s *Session) advanceSendLocked(to uint64, now time.Time) {
	st := &s.st
	st.sBase = to
	for _, l := range st.order {
		if len(l.infl.s) > 0 && l.infl.s[0].off < to {
			l.infl.trimBelow(to)
		}
	}
	st.retx.trimBelow(to)
	if st.rescue.set {
		if e := st.rescue.sp.end(); e <= to {
			st.rescue = rescueSlot{}
		} else if st.rescue.sp.off < to {
			st.rescue.sp = span{to, e - to}
		}
	}
	for st.chunks.n > 0 && st.cbase+chunkSize <= to {
		st.chunks.popFront().Release()
		st.cbase += chunkSize
	}
	if to == st.resEnd {
		st.releaseChunks()
		st.cbase = to / chunkSize * chunkSize
	}
	st.lastAdvance = now
	if st.wwaiting && s.sendRoomLocked() >= s.writerWakeRoom() {
		streamSignal(st.wwake)
	}
}

// pullableLocked returns the DATA bytes a data lane could send now:
// queued retransmissions plus new bytes inside the peer's window.
func (s *Session) pullableLocked() uint64 {
	st := &s.st
	n := st.retx.bytes()
	if lim := min(st.end, st.peerLimit); lim > st.sNext {
		n += lim - st.sNext
	}
	return n
}
