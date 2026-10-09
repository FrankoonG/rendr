package session

import (
	"io"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// The packet application calls (M2 design §A5.2, §A5.3, §A5.6): WriteTo,
// ReadFrom and the packet Close. Session.Close branches to
// pktCloseLocked (app.go, WP6b); the root's PacketConn adds the logical
// address checks (§A5.14).

// writeTo is Session.WriteTo: one Session.mu section per datagram, never a
// wait (M2-D33, L40). A datagram of BigData or more is copied outside
// every lock into its own Buf first; a smaller one is copied into the
// queue's chunk under the lock (below 16 KiB, M1 P17). The checks before
// queueing have no side effect (L06). No seq is assigned here: a datagram
// a bound drops never consumes one (M2-D34).
func (s *Session) writeTo(p []byte) (int, error) {
	pk := s.pk
	env := s.env.Carrier
	n := len(p)
	var ext *carrier.Buf
	if n >= carrier.BigData && n <= pk.maxPayload {
		if ext = env.Bufs.TryGet(n, env.Budget); ext != nil {
			ext.B = ext.B[:copy(ext.B, p)]
		}
	}
	now := time.Now()
	s.mu.Lock()
	st := &s.st
	var err error
	switch {
	case st.closed || st.peerFinSet:
		err = errClosed // the peer's FIN closes both directions (PA-6)
	case st.ended:
		err = st.endErr
	case st.exhausted:
		err = errExhausted()
	case deadlinePassed(&st.wdl):
		err = errDeadline
	case n > pk.maxPayload:
		err = ErrPacketTooLarge
	}
	if err != nil {
		s.mu.Unlock()
		ext.Release()
		return 0, err
	}
	st.txBytes += uint64(n)
	st.lastData = now // the idle clock moves on every accepted WriteTo (M2-D41)
	if n >= carrier.BigData && ext == nil {
		// MaxBufferedBytes refused the datagram's buffer: dropped and
		// counted, never a wait (L40).
		pk.ctr.DropQueue++
		s.mu.Unlock()
		return n, nil
	}
	q := &pk.tx
	if pk.mixed && n > pk.dgMax {
		q = &pk.txBig // M2-D43: only a live stream lane can carry it
	}
	at := now.Sub(pk.base).Nanoseconds()
	s.pktAgeQueueLocked(q, at, false) // nothing older than MaxAge stays queued (M2-D35)
	slot, evicted, ok := q.push(n, at, ext, env.Bufs, env.Budget)
	pk.ctr.DropQueue += uint64(evicted)
	if !ok {
		pk.ctr.DropQueue++ // the chunk pool refused even after one eviction
	} else {
		copy(slot, p) // slot is nil for ext
		if pk.dgMin > 0 && n > pk.dgMin {
			q.back().wide = true // W4-REL-5: the smaller member leaves it to a larger one
		}
		if q == &pk.txBig {
			s.pktBigPushedLocked()
		}
		s.pktWakeLocked(now)
	}
	s.mu.Unlock()
	return n, nil
}

// readFrom is Session.ReadFrom with M1's Read linearization (M2-D38, L07):
// rsem for the call; the head detached under the lock with its own
// reference; the copy outside it; Hooks.ReadDequeued; a commit that
// re-checks closed (Close won → (0, net.ErrClosed), the datagram
// released). Precedence as Read and net.Conn: local Close → net.ErrClosed;
// the peer's FIN delivered with nothing queued → io.EOF (only after every
// queued datagram, L40); the end → its error; a passed read deadline →
// os.ErrDeadlineExceeded, also while datagrams are queued (net.Conn; they
// stay readable once the deadline moves, L06); then the head datagram.
func (s *Session) readFrom(p []byte) (int, error) {
	s.mu.Lock()
	sem, ok := s.acquireLocked(&s.rsem)
	if !ok {
		s.mu.Unlock()
		return 0, errClosed
	}
	defer releaseCall(sem)
	st := &s.st
	pk := s.pk
	for {
		var err error
		switch {
		case st.closed:
			err = errClosed
		case pk.rx.n == 0 && st.peerFinDelivered:
			err = io.EOF // the only io.EOF source (plan:371)
		case st.ended:
			err = st.endErr
		case deadlinePassed(&st.rdl):
			err = errDeadline
		case pk.rx.n > 0:
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
	data, buf := pk.rx.popRef()
	pk.rcopy = buf
	st.rcopying = true
	s.mu.Unlock()

	k := copy(p, data)
	if h := s.env.Hooks; h != nil && h.ReadDequeued != nil {
		h.ReadDequeued()
	}

	s.mu.Lock()
	st.rcopying = false
	pk.rcopy = nil
	buf.Release()
	if st.closed {
		s.mu.Unlock()
		return 0, errClosed // Close won: the datagram is dropped (L07)
	}
	st.delivered += uint64(k)
	now := time.Now()
	st.lastData = now // a datagram returned moves the idle clock (M2-D41)
	if pk.rx.n == 0 && !st.ended {
		s.pktFinCheckLocked(now)
	}
	s.mu.Unlock()
	if len(data) > len(p) {
		return k, io.ErrShortBuffer // the rest is discarded (L36)
	}
	return k, nil
}
