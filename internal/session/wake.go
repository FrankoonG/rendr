package session

import (
	"time"
)

// Directed wakeups of carrier writers (design §3.5, §4.11). A lane's idle
// bit says its writer's last Fill appended nothing, so the writer sleeps
// until woken; a busy writer runs Fill again after its write by itself
// (self-continuation), so producers wake only idle lanes. The bit is set
// and read under s.mu and the wake is a coalescing non-blocking send, so no
// wakeup is lost (§3.5).

// wakeDataLocked wakes data lanes for the bytes and FIN now sendable.
// Selector: the active lane, if idle. Bond: lanes in srtt order — skipping
// lanes that are not data-eligible or are write-blocked — waking idle ones
// until the summed spare capacity (Capacity − Inflight, busy lanes
// included) covers the pending bytes, so demand-limited traffic rides the
// fastest healthy member and backlogged traffic wakes every member. The
// walk usually visits one lane, whatever the lane count (L54). Race: every
// member carries every byte, so every idle data lane with something to
// place is woken (raceWakeDataLocked, M3-D30).
func (s *Session) wakeDataLocked(now time.Time) {
	st := &s.st
	if s.p.Mode == ModeRace {
		s.raceWakeDataLocked()
		return
	}
	if s.p.Mode != ModeBond {
		l := s.ctl.active
		if l == nil || !l.data || l.state == LaneDead {
			l = nil
			for _, o := range st.order {
				if o.data {
					l = o
					break
				}
			}
		}
		if l != nil && l.idle {
			l.idle = false
			l.port.Wake()
		}
		return
	}
	need := int64(s.pullableLocked())
	if st.rescue.set {
		need += int64(st.rescue.sp.n)
	}
	if need == 0 && s.finDueLocked() {
		need = 1
	}
	if need == 0 {
		return
	}
	s.refreshOrderLocked(now, false)
	var covered int64
	for _, l := range st.order {
		if !l.data || l.port.WriteBlocked() {
			continue
		}
		if l.idle {
			l.idle = false
			l.port.Wake()
		}
		if spare := l.port.Capacity() - l.port.Inflight(); spare > 0 {
			covered += spare
		}
		if covered >= need {
			return
		}
	}
}

// refreshOrderLocked re-sorts st.order by srtt (ascending, unknown last,
// stable) when it is older than PingBusy or force is set. It allocates
// nothing.
func (s *Session) refreshOrderLocked(now time.Time, force bool) {
	st := &s.st
	if !force && now.Sub(st.orderAt) < s.pingBusy() {
		return
	}
	st.orderAt = now
	o := st.order
	var keys [32]time.Duration
	if len(o) > len(keys) {
		return // beyond any carrier limit; keep the attach order
	}
	for i, l := range o {
		keys[i] = l.port.SRTT()
	}
	for i := 1; i < len(o); i++ {
		l, k := o[i], keys[i]
		j := i
		for j > 0 && srttBefore(k, keys[j-1]) {
			o[j], keys[j] = o[j-1], keys[j-1]
			j--
		}
		o[j], keys[j] = l, k
	}
}

// srttBefore orders a known (positive) srtt before an unknown one, then by
// value; equal keys keep their order.
func srttBefore(a, b time.Duration) bool {
	if (a > 0) != (b > 0) {
		return a > 0
	}
	return a > 0 && a < b
}

// orderRemove removes l from st.order, keeping the order of the others.
func (st *stream) orderRemove(l *lane) {
	for i, o := range st.order {
		if o == l {
			copy(st.order[i:], st.order[i+1:])
			st.order[len(st.order)-1] = nil
			st.order = st.order[:len(st.order)-1]
			return
		}
	}
}
