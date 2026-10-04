package session

import (
	"net"
	"os"
	"time"
)

// Application deadlines (design §3.6; L06). Each direction has one
// deadline {t, gen, timer} under s.mu. Every Set wakes that direction's
// blocked call to re-evaluate; a zero time clears; a time not after now
// fails pending and later calls at once. Like net.Conn (internal/poll),
// Set turns the deadline into a duration once: t is stored as now plus
// time.Until(t), which carries a monotonic reading even when the caller's
// t has none (time.Unix, time.Date, Round(0)), so a later wall-clock step
// neither delays nor advances the expiry. The timer is created by the first
// Set with a future time and reused (Reset) afterwards, so later Sets
// allocate nothing; its callback wakes the waiter only if the deadline it
// finds has passed, so the firing of a deadline that was extended (or
// cleared) in the meantime does nothing, and it re-arms itself if it ever
// fires before the deadline. Waiters always re-check the deadline
// themselves. Deadlines never affect control frames, retransmissions or
// ACKs, and a terminal session error takes precedence.

var (
	errClosed   = net.ErrClosed
	errDeadline = os.ErrDeadlineExceeded
)

// deadlinePassed reports whether d is set and not after now.
func deadlinePassed(d *deadline) bool {
	return !d.t.IsZero() && !time.Now().Before(d.t)
}

// setDeadline implements SetReadDeadline (read) and SetWriteDeadline.
func (s *Session) setDeadline(read bool, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	if st.closed {
		return errClosed
	}
	d := &st.wdl
	if read {
		d = &st.rdl
	}
	var wait time.Duration
	if !t.IsZero() {
		now := time.Now()
		wait = t.Sub(now)
		t = now.Add(wait) // monotonic from now on (see above)
	}
	d.t = t
	d.gen++
	if t.IsZero() || wait <= 0 || st.ended {
		if d.timer != nil {
			d.timer.Stop()
		}
	} else if d.timer == nil {
		d.timer = time.AfterFunc(wait, func() { s.deadlineFired(read) })
	} else {
		d.timer.Reset(wait)
	}
	s.wakeDirLocked(read)
	return nil
}

// deadlineFired is a deadline timer's callback.
func (s *Session) deadlineFired(read bool) {
	s.mu.Lock()
	d := &s.st.wdl
	if read {
		d = &s.st.rdl
	}
	if deadlinePassed(d) {
		s.wakeDirLocked(read)
	} else if !d.t.IsZero() && !s.st.ended {
		d.timer.Reset(time.Until(d.t)) // fired early: never strand a waiter
	}
	s.mu.Unlock()
}

// wakeDirLocked wakes the blocked Read (read) or Write, if any.
func (s *Session) wakeDirLocked(read bool) {
	st := &s.st
	if read {
		if st.rwaiting {
			streamSignal(st.rwake)
		}
	} else if st.wwaiting {
		streamSignal(st.wwake)
	}
}

// stopDeadlinesLocked stops both deadline timers (session end).
func (st *stream) stopDeadlinesLocked() {
	if t := st.rdl.timer; t != nil {
		t.Stop()
	}
	if t := st.wdl.timer; t != nil {
		t.Stop()
	}
}
