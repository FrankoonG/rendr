package session

import (
	"bytes"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// The stream: the session's data path (design §4.2–§4.13). This file holds
// its constants, the parameter accessors, the violation errors and the
// methods of the supporting types declared in state.go (spans, the chunk
// ring and the receive segments). Every method here runs with Session.mu
// held unless it says otherwise.

const (
	// chunkSize is C: the send-chunk span and the DATA segment cap.
	chunkSize = carrier.ChunkSize
	// maxRound bounds one Write round (reserve, copy, commit; §4.2).
	maxRound = 256 << 10
	// maxRoundChunks is the most chunks one round's copy can touch.
	maxRoundChunks = maxRound/chunkSize + 1
	// budgetPoll is how often a Write blocked by the Runtime budget
	// re-checks it (D16: there is no budget waiter list).
	budgetPoll = 20 * time.Millisecond
	// runSize is the payload capacity of a receive run: DATA payloads below
	// it are copied into runs under the session lock (P17); pieces of at
	// least this size are kept by reference.
	runSize = carrier.BigData
	// runCap is the class capacity a run charges (the 16 KiB class).
	runCap = carrier.BigData + carrier.ClassSlack
	// windowFloor is the window below which the actor re-advertises (D18)
	// and below which a placed ACK rings it (W6).
	windowFloor = 64 << 10
	// maxViews bounds the inq slices one Read copies from (§4.5).
	maxViews = 8

	defaultAckEvery    = 64 << 10
	defaultAckDelay    = 20 * time.Millisecond
	defaultPingBusy    = 50 * time.Millisecond
	defaultWindow      = 8 << 20
	defaultOffsetLimit = 1 << 62
)

// violation is an error returned by a lane's Data or Control: the carrier
// kills itself with CauseProtocolViolation and the error text as detail;
// the session is unaffected (L13, L15, invariant 6).
type violation string

func (v violation) Error() string { return "rendr/session: " + string(v) }

// Carrier violations detected by the stream.
var (
	errDataBeforeOpen    error = violation("session frame before the session opened")
	errDataLength        error = violation("DATA length or offset out of range")
	errWindow            error = violation("DATA beyond the advertised window")
	errDataBeyondFin     error = violation("DATA beyond the peer's FIN")
	errConflict          error = violation("conflicting duplicate DATA")
	errAckBeyondSent     error = violation("ACK beyond sent")
	errAckRegression     error = violation("ACK regression on carrier")
	errFinDeliveredEarly error = violation("FIN_DELIVERED before the FIN offset")
	errFinConflict       error = violation("FIN offset differs from an earlier FIN")
	errFinBelowData      error = violation("FIN below received data")
	errFinBeyondWindow   error = violation("FIN beyond the advertised window")
	errSchedOnDialer     error = violation("SCHED received by the dialer")
	errUnexpectedFrame   error = violation("unexpected session frame")
	errRxNextBeyondSent  error = violation("rxNext beyond sent")
)

// errExhausted is the Write error at the offset limit (L14); a fresh value
// each time, so an application cannot alter another caller's error.
func errExhausted() error {
	return &AbortError{Code: AbortExhausted, Msg: "stream offset limit reached"}
}

// Parameter accessors. Params is normalized by package rendr; the defaults
// here only keep a partially filled Params (unit tests) well defined.

func (s *Session) window() int64 {
	if s.p.Window > 0 {
		return s.p.Window
	}
	return defaultWindow
}

func (s *Session) ackEvery() uint64 {
	if s.p.AckEvery > 0 {
		return uint64(s.p.AckEvery)
	}
	return defaultAckEvery
}

func (s *Session) ackDelay() time.Duration {
	if s.p.AckDelay > 0 {
		return s.p.AckDelay
	}
	return defaultAckDelay
}

func (s *Session) offsetLimit() uint64 {
	if s.p.OffsetLimit > 0 {
		return s.p.OffsetLimit
	}
	return defaultOffsetLimit
}

func (s *Session) pingBusy() time.Duration {
	if t := s.env.Carrier.Timing.PingBusy; t > 0 {
		return t
	}
	return defaultPingBusy
}

// segment is the largest DATA payload Fill puts in one frame (≤ C).
func (s *Session) segment() uint64 {
	if seg := s.env.Carrier.Timing.Segment; seg > 0 && seg < chunkSize {
		return uint64(seg)
	}
	return chunkSize
}

// writerWakeRoom is the send-buffer room at which an ACK wakes a blocked
// application writer (D17 hysteresis).
func (s *Session) writerWakeRoom() int64 {
	return min(maxRound, s.window()/4)
}

// readvertiseFloor is D18's 64 KiB, capped by a smaller configured window
// (sched.AdvertiseWindow's floor yields to it the same way).
func (s *Session) readvertiseFloor() int64 {
	return min(windowFloor, s.window())
}

// streamSignal is a non-blocking send on a cap-1 wake channel.
func streamSignal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// ---------------------------------------------------------------- spans

func (sp span) end() uint64 { return sp.off + sp.n }

func (l *spanList) empty() bool { return len(l.s) == 0 }

func (l *spanList) reset() { l.s = l.s[:0] }

// bytes returns the bytes covered.
func (l *spanList) bytes() uint64 {
	var n uint64
	for _, sp := range l.s {
		n += sp.n
	}
	return n
}

// add inserts [off, off+n), merging it with every span it overlaps or
// touches, so the list stays ascending and coalesced. Appending at the end
// (the common case) is O(1); the backing array only grows.
func (l *spanList) add(off, n uint64) {
	if n == 0 {
		return
	}
	end := off + n
	s := l.s
	k := len(s)
	if k == 0 || s[k-1].end() < off {
		l.s = append(s, span{off, n})
		return
	}
	if last := &s[k-1]; last.off <= off {
		if end > last.end() {
			last.n = end - last.off
		}
		return
	}
	// i: the first span ending at or after off (touching counts).
	lo, hi := 0, k
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if s[m].end() < off {
			lo = m + 1
		} else {
			hi = m
		}
	}
	i := lo
	j := i // j: the first span starting after end
	for j < k && s[j].off <= end {
		j++
	}
	if i == j {
		s = append(s, span{})
		copy(s[i+1:], s[i:])
		s[i] = span{off, n}
		l.s = s
		return
	}
	nOff, nEnd := min(off, s[i].off), max(end, s[j-1].end())
	s[i] = span{nOff, nEnd - nOff}
	l.s = append(s[:i+1], s[j:]...)
}

// trimBelow removes every byte below x.
func (l *spanList) trimBelow(x uint64) {
	s := l.s
	i := 0
	for i < len(s) && s[i].end() <= x {
		i++
	}
	if i < len(s) && s[i].off < x {
		s[i].n -= x - s[i].off
		s[i].off = x
	}
	if i > 0 {
		l.s = s[:copy(s, s[i:])]
	}
}

// takeFront removes the first n bytes of the first span.
func (l *spanList) takeFront(n uint64) {
	s := l.s
	s[0].off += n
	s[0].n -= n
	if s[0].n == 0 {
		l.s = s[:copy(s, s[1:])]
	}
}

// ---------------------------------------------------------------- chunks

func (r *chunkRing) at(i int) *carrier.Buf { return r.b[(r.head+i)%len(r.b)] }

func (r *chunkRing) full() bool { return r.n == len(r.b) }

func (r *chunkRing) push(b *carrier.Buf) {
	r.b[(r.head+r.n)%len(r.b)] = b
	r.n++
}

func (r *chunkRing) popFront() *carrier.Buf {
	b := r.b[r.head]
	r.b[r.head] = nil
	r.head = (r.head + 1) % len(r.b)
	r.n--
	return b
}

// chunkFor returns the send chunk holding stream offset off (cbase ≤ off <
// cbase + n·C) and off's position in it.
func (st *stream) chunkFor(off uint64) (*carrier.Buf, int) {
	d := off - st.cbase
	return st.chunks.at(int(d / chunkSize)), int(d % chunkSize)
}

// chunkEnd returns the end of the chunk holding off.
func (st *stream) chunkEnd(off uint64) uint64 {
	return off + chunkSize - (off-st.cbase)%chunkSize
}

// releaseChunks drops the session's reference on every send chunk (a
// carrier writer still writing one keeps its own reference, §4.2).
func (st *stream) releaseChunks() {
	for st.chunks.n > 0 {
		st.chunks.popFront().Release()
	}
	st.chunks.head = 0
}

// ---------------------------------------------------------------- segments

func (sg *seg) end() uint64 { return sg.off + uint64(len(sg.b)) }

// segCap is the class capacity a segment's buffer charges (oooCap).
func segCap(sg *seg) int64 { return int64(cap(sg.buf.B)) }

func (r *segRing) at(i int) *seg { return &r.s[(r.head+i)&(len(r.s)-1)] }

func (r *segRing) back() *seg { return r.at(r.n - 1) }

// push appends sg; the ring doubles (power-of-two sizes) when full and
// never shrinks during a session.
func (r *segRing) push(sg seg) {
	if r.n == len(r.s) {
		ns := make([]seg, max(8, 2*len(r.s)))
		for i := range r.n {
			ns[i] = *r.at(i)
		}
		r.s, r.head = ns, 0
	}
	*r.at(r.n) = sg
	r.n++
}

func (r *segRing) popFront() seg {
	p := &r.s[r.head]
	sg := *p
	*p = seg{}
	r.head = (r.head + 1) & (len(r.s) - 1)
	r.n--
	return sg
}

// equal reports whether the held in-order bytes at [a, a+len(q)) equal q.
// The range must lie inside the held segments.
func (r *segRing) equal(a uint64, q []byte) bool {
	for i := 0; i < r.n && len(q) > 0; i++ {
		sg := r.at(i)
		if sg.end() <= a {
			continue
		}
		h := sg.b[a-sg.off:]
		m := min(len(h), len(q))
		if !bytes.Equal(h[:m], q[:m]) {
			return false
		}
		q = q[m:]
		a += uint64(m)
	}
	return true
}

// after returns the index of the first out-of-order segment ending after x.
func (l *segList) after(x uint64) int {
	s := l.s
	lo, hi := 0, len(s)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if s[m].end() <= x {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo
}

// equal reports whether p at offset off agrees with every out-of-order
// segment it overlaps.
func (l *segList) equal(off uint64, p []byte) bool {
	end := off + uint64(len(p))
	for i := l.after(off); i < len(l.s) && l.s[i].off < end; i++ {
		sg := &l.s[i]
		a, b := max(off, sg.off), min(end, sg.end())
		if !bytes.Equal(sg.b[a-sg.off:b-sg.off], p[a-off:b-off]) {
			return false
		}
	}
	return true
}

func (l *segList) insert(i int, sg seg) {
	l.s = append(l.s, seg{})
	copy(l.s[i+1:], l.s[i:])
	l.s[i] = sg
}

// removeFront drops the first k segments (their buffers are the caller's).
func (l *segList) removeFront(k int) {
	n := copy(l.s, l.s[k:])
	clear(l.s[n:])
	l.s = l.s[:n]
}

// highest returns the end of the highest held received byte.
func (st *stream) highest() uint64 {
	if n := len(st.ooq.s); n > 0 {
		return st.ooq.s[n-1].end()
	}
	return st.rTail
}
