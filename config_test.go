package rendr

import (
	"fmt"
	"math"
	"math/rand/v2"
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestWindowInvariantAllConfigs_L15 proves L15's inequality — the most a
// sender can have in flight never exceeds the receiver's fatal threshold —
// for every configuration normalization admits (design §4.12; plan §3.7).
//
// Part 1 (static, every normalized config): the session window W is the
// same value for the receive window, the send-buffer bound and the
// carrier capacity ceiling; W fits the u32 window fields of OPEN, OPEN_ACK
// and ACK (no truncation on the wire); W is at least the 64 KiB floor of
// the memory-pressure rule, so an advertisement never exceeds W; the
// capacity floor is at most W; one full DATA segment fits a batch and the
// window.
//
// Part 2 (dynamic): a model of the byte-window protocol (sender bounded by
// its own W and by peerLimit = max over received Delivered + Window;
// receiver advertising rRead + AdvertiseWindow under memory pressure with
// a right edge that never retracts; FIFO lanes reordering against each
// other; lane deaths that lose in-flight frames and replay the requeued
// spans; JOIN rxNext trims) is driven by random schedules between the
// normalized parameters of two independently configured Runtimes — every
// boundary of Window, MaxBufferedBytes and MaxCarriersPerSession and
// random configurations — in both directions. Every DATA frame must arrive
// below the receiver's fatal threshold (the largest edge it advertised),
// peerLimit never exceeds that edge, the send buffer never exceeds W, and
// once pressure ends every byte is delivered in order. A deterministic
// replay burst (the v1 failure: fill the window, push the receiver to 100%
// memory, kill the carrier, replay everything on another) stays inside the
// threshold; the same scenario against a receiver that retracts its edge
// (P10 violated) must be caught, proving the check has teeth (L60).
func TestWindowInvariantAllConfigs_L15(t *testing.T) {
	cfgs := windowBoundaryConfigs()
	r := rand.New(rand.NewPCG(15, 15))
	for i := 0; i < 2000; i++ {
		cfgs = append(cfgs, randomConfig(r))
	}
	effs := make([]effective, len(cfgs))
	for i, c := range cfgs {
		effs[i], _ = normalize(c, nil)
		checkWindowStatic(t, effs[i])
	}
	if t.Failed() {
		t.FailNow()
	}

	var total wmStats
	nb := len(windowBoundaryConfigs())
	run := func(label string, s, rc *effective, seed uint64) {
		m := newWindowModel(t, wmEndsOf(s, rc), seed, false)
		m.run(1200)
		m.drain()
		total.add(m.stats)
		if t.Failed() {
			t.Fatalf("%s: sender %+v receiver window %d", label, m.cfg, rc.params.Window)
		}
	}
	for i := 0; i < nb; i++ {
		for j := 0; j < nb; j++ {
			run(fmt.Sprintf("boundary %d→%d", i, j), &effs[i], &effs[j], uint64(i*nb+j))
		}
	}
	for k := 0; k < 64; k++ {
		i, j := nb+r.IntN(len(effs)-nb), nb+r.IntN(len(effs)-nb)
		run(fmt.Sprintf("random %d→%d", i, j), &effs[i], &effs[j], uint64(1000+k))
	}
	// Stimulus and load: the schedules really filled windows, saturated
	// memory, killed carriers and replayed requeued data, and moved bytes.
	if total.windowLimited == 0 || total.pressureFull == 0 || total.kills == 0 || total.replayed == 0 || total.delivered == 0 {
		t.Fatalf("schedules did not exercise the window: %+v", total)
	}
	t.Logf("schedules: %+v", total)

	// The deterministic replay burst, at the extremes of the window range.
	for _, w := range []int{256 << 10, 64 << 20} {
		s, _ := normalize(Config{Window: w, MaxCarriersPerSession: 2}, nil)
		rc, _ := normalize(Config{Window: w, MaxCarriersPerSession: 2, MaxBufferedBytes: 64 << 20}, nil)
		ok := newWindowModel(t, wmEndsOf(&s, &rc), 1, false)
		ok.replayBurst()
		if ok.stats.violations != 0 || ok.stats.replayed < uint64(w) {
			t.Fatalf("window %d: replay burst violations %d replayed %d", w, ok.stats.violations, ok.stats.replayed)
		}
		ok.drain()
		bad := newWindowModel(t, wmEndsOf(&s, &rc), 1, true)
		bad.replayBurst()
		if bad.stats.violations == 0 {
			t.Fatalf("window %d: a retracting receiver went undetected", w)
		}
	}
}

// windowBoundaryConfigs crosses the boundaries of the window-relevant
// fields: Window (both clamp ends, the default and an unaligned value),
// MaxBufferedBytes (both ends) and MaxCarriersPerSession (both ends).
func windowBoundaryConfigs() []Config {
	var out []Config
	for _, w := range []int{256 << 10, 300001, 8 << 20, 64 << 20} {
		for _, b := range []int64{64 << 20, 64 << 30} {
			for _, n := range []int{1, 16} {
				out = append(out, Config{Window: w, MaxBufferedBytes: b, MaxCarriersPerSession: n})
			}
		}
	}
	return out
}

// checkWindowStatic is part 1 for one normalized configuration.
func checkWindowStatic(t *testing.T, e effective) {
	t.Helper()
	w := e.params.Window
	switch {
	case w < 256<<10 || w > 64<<20:
		t.Errorf("window %d outside [256 KiB, 64 MiB]", w)
	case w != e.timing.Window || int64(e.cfg.Window) != w:
		t.Errorf("receive window %d, capacity ceiling %d and Config.Window %d differ", w, e.timing.Window, e.cfg.Window)
	case w > math.MaxUint32:
		t.Errorf("window %d does not fit the u32 window fields", w)
	case w < 64<<10:
		t.Errorf("window %d below the 64 KiB pressure floor: an advertisement could exceed it", w)
	case e.timing.CapFloor > w:
		t.Errorf("capacity floor %d above the window %d", e.timing.CapFloor, w)
	case e.timing.Segment > e.timing.BatchBudget || int64(e.timing.Segment) > w:
		t.Errorf("segment %d does not fit the batch %d or the window %d", e.timing.Segment, e.timing.BatchBudget, w)
	}
	b := e.cfg.MaxBufferedBytes
	for _, used := range []int64{0, b / 2, b * 3 / 4, b*3/4 + 1, b * 9 / 10, b - 1, b} {
		if a := wmAdvertise(w, used, b); a < 0 || a > w {
			t.Errorf("advertisement %d for window %d at %d/%d outside [0, window]", a, w, used, b)
		}
	}
	if wmAdvertise(w, b, b) != 0 {
		t.Errorf("a full budget must advertise 0")
	}
}

// wmAdvertise is the plan §3.7 memory-pressure rule (design §4.12) as the
// model's receiver applies it: used ≤ 75% → W; used ≥ max → 0; between →
// max(64 KiB, W·(1 − used/max)/0.25).
func wmAdvertise(w, used, bmax int64) int64 {
	switch {
	case used*4 <= bmax*3:
		return w
	case used >= bmax:
		return 0
	}
	return max(64<<10, int64(float64(w)*(float64(bmax-used)/float64(bmax))/0.25))
}

// wmEnds is one direction of a session: the sending Runtime's window,
// segment and lanes, and the receiving Runtime's window and budget.
type wmEnds struct {
	ws, wr  int64
	bmax    int64
	lanes   int
	segment uint64
	first   uint64
}

func wmEndsOf(s, r *effective) wmEnds {
	return wmEnds{
		ws:      s.params.Window,
		wr:      r.params.Window,
		bmax:    r.cfg.MaxBufferedBytes,
		lanes:   min(s.cfg.MaxCarriersPerSession, r.cfg.MaxCarriersPerSession),
		segment: uint64(s.timing.Segment),
		first:   s.params.FirstOffset,
	}
}

type wmSpan struct{ off, n uint64 }

type wmAck struct {
	delivered uint64
	window    uint32 // the wire field
}

type wmLane struct {
	data    []wmSpan // DATA in flight to the receiver, FIFO
	acks    []wmAck  // ACKs in flight to the sender, FIFO
	infl    []wmSpan // sender: sent here, not acknowledged, ascending
	lastAck uint64   // sender: highest Delivered on this lane (P3)
}

type wmStats struct {
	violations, edgeBreaks                         int
	sent, replayed, delivered, kills, pressureFull uint64
	windowLimited, acks                            uint64
}

func (s *wmStats) add(o wmStats) {
	s.violations += o.violations
	s.edgeBreaks += o.edgeBreaks
	s.sent += o.sent
	s.replayed += o.replayed
	s.delivered += o.delivered
	s.kills += o.kills
	s.pressureFull += o.pressureFull
	s.windowLimited += o.windowLimited
	s.acks += o.acks
}

// windowModel is the byte-window protocol of design §4.2–§4.6 and §4.12
// for one direction, reduced to offsets.
type windowModel struct {
	t       *testing.T
	cfg     wmEnds
	r       *rand.Rand
	retract bool // negative control: the receiver lets its right edge retract

	sBase, sNext, end, peerLimit uint64   // sender
	retx                         []wmSpan // sender: requeued spans, ascending

	rRead, rTail, rightEdge uint64   // receiver; rightEdge is the fatal threshold
	ooo                     []wmSpan // receiver: received beyond rTail, ascending
	used                    int64    // receiver Runtime's budget usage

	lanes []*wmLane
	stats wmStats
}

func newWindowModel(t *testing.T, cfg wmEnds, seed uint64, retract bool) *windowModel {
	m := &windowModel{t: t, cfg: cfg, r: rand.New(rand.NewPCG(seed, 7)), retract: retract}
	f := cfg.first
	m.sBase, m.sNext, m.end, m.peerLimit = f, f, f, f
	m.rRead, m.rTail, m.rightEdge = f, f, f
	for i := 0; i < cfg.lanes; i++ {
		m.lanes = append(m.lanes, &wmLane{})
	}
	// OPEN / OPEN_ACK: the receiver's openWindowLocked, the sender's
	// peerWindowLocked (design §4.0).
	w := m.advertise()
	m.peerLimit = max(m.peerLimit, m.sBase+uint64(w))
	return m
}

// advertise is the receiver placing a window: rightEdge = max(rightEdge,
// rRead + AdvertiseWindow) (P10), returned as the u32 wire field.
func (m *windowModel) advertise() uint32 {
	edge := m.rRead + uint64(wmAdvertise(m.cfg.wr, m.used, m.cfg.bmax))
	if m.retract {
		m.rightEdge = edge
	} else {
		m.rightEdge = max(m.rightEdge, edge)
	}
	w := m.rightEdge - m.rRead
	if w > math.MaxUint32 {
		m.t.Fatalf("advertised window %d does not fit the wire", w)
	}
	return uint32(w)
}

func (m *windowModel) run(steps int) {
	deliverBias := 1 + m.r.IntN(4) // some schedules let windows fill up
	for i := 0; i < steps; i++ {
		l := m.r.IntN(len(m.lanes))
		switch k := m.r.IntN(100); {
		case k < 14:
			m.write()
		case k < 40:
			m.send(l)
		case k < 40+6*deliverBias:
			m.deliverData(l)
		case k < 70:
			m.read()
		case k < 80:
			m.placeAck(l)
		case k < 90:
			m.deliverAck(l)
		case k < 93:
			m.kill(l)
		default:
			m.pressure()
		}
		m.check()
	}
}

func (m *windowModel) write() {
	room := uint64(m.cfg.ws) - (m.end - m.sBase) // the send buffer holds at most W unacknowledged bytes
	if room > 0 {
		m.end += 1 + m.r.Uint64N(min(room, 256<<10))
	}
}

// send is Fill on one lane: requeued spans first (L10), then new data below
// min(end, peerLimit), one segment per frame.
func (m *windowModel) send(i int) {
	l := m.lanes[i]
	var sp wmSpan
	if len(m.retx) > 0 {
		sp = m.retx[0]
		sp.n = min(sp.n, m.cfg.segment)
		m.retx[0].off += sp.n
		m.retx[0].n -= sp.n
		if m.retx[0].n == 0 {
			m.retx = m.retx[1:]
		}
		m.stats.replayed += sp.n
	} else {
		lim := min(m.end, m.peerLimit)
		if m.sNext >= lim {
			if m.sNext < m.end {
				m.stats.windowLimited++
			}
			return
		}
		n := min(lim-m.sNext, 1+m.r.Uint64N(m.cfg.segment))
		sp = wmSpan{m.sNext, n}
		m.sNext += n
	}
	if sp.off+sp.n > m.peerLimit {
		m.t.Errorf("sender put [%d, %d) beyond the largest edge it received %d", sp.off, sp.off+sp.n, m.peerLimit)
	}
	l.data = append(l.data, sp)
	l.infl = wmInsert(l.infl, sp)
	m.stats.sent += sp.n
}

// deliverData is the receiver's window check (design §4.4 step 2): a frame
// ending beyond the fatal threshold would kill its carrier.
func (m *windowModel) deliverData(i int) {
	l := m.lanes[i]
	if len(l.data) == 0 {
		return
	}
	sp := l.data[0]
	l.data = l.data[1:]
	if end := sp.off + sp.n; end > m.rightEdge {
		m.stats.violations++
		if !m.retract {
			m.t.Errorf("DATA [%d, %d) beyond the receiver's fatal threshold %d", sp.off, end, m.rightEdge)
		}
		return
	}
	if sp.off+sp.n <= m.rTail {
		return // duplicate (a replay of delivered bytes)
	}
	m.ooo = wmInsert(m.ooo, wmSpan{max(sp.off, m.rTail), sp.off + sp.n - max(sp.off, m.rTail)})
	for len(m.ooo) > 0 && m.ooo[0].off <= m.rTail {
		m.stats.delivered += m.ooo[0].off + m.ooo[0].n - m.rTail
		m.rTail = m.ooo[0].off + m.ooo[0].n
		m.ooo = m.ooo[1:]
	}
}

func (m *windowModel) read() {
	if m.rTail > m.rRead {
		m.rRead += 1 + m.r.Uint64N(m.rTail-m.rRead)
	}
}

func (m *windowModel) placeAck(i int) {
	m.lanes[i].acks = append(m.lanes[i].acks, wmAck{m.rRead, m.advertise()})
}

// deliverAck is the sender's ACK handling (design §4.6 steps 1–4).
func (m *windowModel) deliverAck(i int) {
	l := m.lanes[i]
	if len(l.acks) == 0 {
		return
	}
	a := l.acks[0]
	l.acks = l.acks[1:]
	if a.delivered > m.sNext || a.delivered < l.lastAck {
		m.t.Errorf("ACK %d beyond sent %d or regressing below %d on its lane", a.delivered, m.sNext, l.lastAck)
	}
	l.lastAck = a.delivered
	m.trim(a.delivered)
	m.peerLimit = max(m.peerLimit, a.delivered+uint64(a.window))
	m.stats.acks++
}

// trim advances the acknowledged front (an ACK or a JOIN rxNext).
func (m *windowModel) trim(delivered uint64) {
	if delivered <= m.sBase {
		return
	}
	m.sBase = delivered
	m.retx = wmClip(m.retx, m.sBase)
	for _, l := range m.lanes {
		l.infl = wmClip(l.infl, m.sBase)
	}
}

// kill is a carrier death: frames in flight in both directions are lost,
// the lane's unacknowledged spans are requeued (L10), and a replacement
// lane joins with rxNext = the receiver's rRead (a trim that never touches
// peerLimit, design §4.0) and an urgent re-ACK.
func (m *windowModel) kill(i int) {
	for _, sp := range m.lanes[i].infl {
		m.retx = wmInsert(m.retx, sp)
	}
	m.lanes[i] = &wmLane{}
	m.stats.kills++
	m.trim(m.rRead)
	m.placeAck(i)
}

func (m *windowModel) pressure() {
	b := m.cfg.bmax
	switch m.r.IntN(6) {
	case 0:
		m.used = 0
	case 1:
		m.used = b * 3 / 4
	case 2, 3:
		m.used = b
		m.stats.pressureFull++
	case 4:
		m.used = b - 1
	default:
		m.used = m.r.Int64N(b + 1)
	}
}

func (m *windowModel) check() {
	if m.retract {
		return
	}
	switch {
	case m.peerLimit > m.rightEdge:
		m.stats.edgeBreaks++
		m.t.Errorf("peerLimit %d beyond the receiver's edge %d", m.peerLimit, m.rightEdge)
	case m.end-m.sBase > uint64(m.cfg.ws):
		m.t.Errorf("send buffer %d above the window %d", m.end-m.sBase, m.cfg.ws)
	case !(m.sBase <= m.sNext && m.sNext <= m.end && m.sNext <= m.peerLimit):
		m.t.Errorf("sender offsets base %d next %d end %d limit %d", m.sBase, m.sNext, m.end, m.peerLimit)
	case !(m.rRead <= m.rTail && m.rTail <= m.rightEdge):
		m.t.Errorf("receiver offsets read %d tail %d edge %d", m.rRead, m.rTail, m.rightEdge)
	}
	if m.t.Failed() {
		m.t.FailNow()
	}
}

// drain ends the pressure and runs the session to completion without
// deaths: everything written must be delivered in order and acknowledged.
func (m *windowModel) drain() {
	m.used = 0
	for iter := 0; m.rRead < m.end || m.sBase < m.end; iter++ {
		if iter > 1<<16 {
			m.t.Fatalf("stalled: base %d next %d end %d limit %d; read %d tail %d edge %d",
				m.sBase, m.sNext, m.end, m.peerLimit, m.rRead, m.rTail, m.rightEdge)
		}
		for i := range m.lanes {
			for before := m.stats.sent; ; before = m.stats.sent {
				m.send(i)
				if m.stats.sent == before {
					break
				}
			}
			for len(m.lanes[i].data) > 0 {
				m.deliverData(i)
			}
		}
		m.rRead = m.rTail
		m.placeAck(0)
		for i := range m.lanes {
			for len(m.lanes[i].acks) > 0 {
				m.deliverAck(i)
			}
		}
		m.check()
	}
	if len(m.retx) != 0 || len(m.ooo) != 0 || m.rTail != m.end {
		m.t.Fatalf("drained session holds retx %v ooo %v tail %d end %d", m.retx, m.ooo, m.rTail, m.end)
	}
}

// replayBurst fills the window on lane 0 without delivering anything,
// drives the receiver to 100% memory, lets it advertise (window 0), kills
// lane 0 and replays every requeued byte on lane 1.
func (m *windowModel) replayBurst() {
	m.end = m.sBase + uint64(m.cfg.ws)
	for before := m.stats.sent - 1; m.stats.sent != before; {
		before = m.stats.sent
		m.send(0)
	}
	m.lanes[0].data = nil // lost with the carrier
	m.used = m.cfg.bmax
	m.stats.pressureFull++
	m.placeAck(1)
	m.deliverAck(1)
	m.kill(0)
	for len(m.retx) > 0 {
		m.send(1)
	}
	for len(m.lanes[1].data) > 0 {
		m.deliverData(1)
	}
}

// wmInsert inserts sp into an ascending span list, merging overlaps.
func wmInsert(s []wmSpan, sp wmSpan) []wmSpan {
	if sp.n == 0 {
		return s
	}
	out := make([]wmSpan, 0, len(s)+1)
	lo, hi := sp.off, sp.off+sp.n
	placed := false
	for _, x := range s {
		xl, xh := x.off, x.off+x.n
		switch {
		case xh < lo:
			out = append(out, x)
		case xl > hi:
			if !placed {
				out = append(out, wmSpan{lo, hi - lo})
				placed = true
			}
			out = append(out, x)
		default:
			lo, hi = min(lo, xl), max(hi, xh)
		}
	}
	if !placed {
		out = append(out, wmSpan{lo, hi - lo})
	}
	return out
}

// wmClip removes everything below base.
func wmClip(s []wmSpan, base uint64) []wmSpan {
	out := s[:0]
	for _, x := range s {
		if x.off+x.n <= base {
			continue
		}
		if x.off < base {
			x = wmSpan{base, x.off + x.n - base}
		}
		out = append(out, x)
	}
	return out
}

// TestConfigOverridesReachWindowTimings is the testhooks side of L15: an
// override Window reaches the receive window, the send bound and the
// capacity ceiling together (one window, never two).
func TestConfigOverridesReachWindowTimings(t *testing.T) {
	e, _ := normalize(Config{Window: 1 << 20}, &testhooks.Overrides{Window: 96 << 10})
	if e.params.Window != 96<<10 || e.timing.Window != 96<<10 || e.cfg.Window != 96<<10 {
		t.Fatalf("override window: params %d timing %d cfg %d", e.params.Window, e.timing.Window, e.cfg.Window)
	}
}
