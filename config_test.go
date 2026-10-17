package rendr

import (
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
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
// Part 2 (dynamic) checks the design rule, not the session code: a test
// model of the byte-window protocol of design §4.2–§4.6 and §4.12 (sender
// bounded by its own W and by peerLimit = max over received Delivered +
// Window; receiver advertising rRead + sched.AdvertiseWindow (plan §3.7)
// with a right edge that never retracts, P10; FIFO lanes reordering
// against each other; lane deaths that lose in-flight frames and replay
// the requeued spans; JOIN rxNext trims) is driven by random schedules
// between the normalized parameters of two independently configured
// Runtimes — every boundary of Window, MaxBufferedBytes and
// MaxCarriersPerSession and random configurations — in both directions.
// Every DATA frame must arrive below the receiver's fatal threshold (the
// largest edge it advertised), peerLimit never exceeds that edge, the send
// buffer never exceeds W, and once pressure ends every byte is delivered in
// order. A deterministic replay burst (the v1 failure: fill the window,
// push the receiver to 100% memory, kill the carrier, replay everything on
// another) stays inside the threshold; the same scenario against a
// receiver that retracts its edge (P10 violated) must be caught, proving
// the check has teeth (L60). With the edge never retracting, the model
// keeps the property by construction, so part 2 shows that the rule P10
// suffices for every admitted configuration; that the session code
// implements the rule is proved in internal/session by
// TestRightEdgeNeverRetracts_L15 (with TestNoReaderBoundsAck_L15 and
// TestHeldHeadBoundsHeap_L15).
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
		a := sched.AdvertiseWindow(w, used, b)
		if a < 0 || a > w {
			t.Errorf("advertisement %d for window %d at %d/%d outside [0, window]", a, w, used, b)
		}
		if p := wmAdvertise(w, used, b); a != p {
			t.Errorf("sched.AdvertiseWindow(%d, %d, %d) = %d, the plan rule gives %d", w, used, b, a, p)
		}
	}
	if sched.AdvertiseWindow(w, b, b) != 0 {
		t.Errorf("a full budget must advertise 0")
	}
}

// wmAdvertise is the plan §3.7 memory-pressure rule (design §4.12) written
// independently of its production implementation: used ≤ 75% → W; used ≥
// max → 0; between → max(64 KiB, W·(1 − used/max)/0.25). The model's
// receiver applies sched.AdvertiseWindow; checkWindowStatic asserts that
// it agrees with this copy at the pressure boundaries of every config.
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
	edge := m.rRead + uint64(sched.AdvertiseWindow(m.cfg.wr, m.used, m.cfg.bmax))
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

// normField describes one clamped integer or duration field of Config for
// the table tests: its plan §4 default and range, whether a negative value
// selects zero, and a base that keeps every cross-parameter constraint
// quiet at both ends of the range (so each case expects exactly its own
// record).
type normField struct {
	name        string
	get         func(*Config) *int64 // nil for int fields
	geti        func(*Config) *int   // nil for duration/int64 fields
	dur         bool
	def, lo, hi int64
	negZero     bool
	base        func(*Config)
}

func normFields() []normField {
	d := func(name string, p func(*Config) *time.Duration, def, lo, hi time.Duration, negZero bool, base func(*Config)) normField {
		return normField{
			name: name, dur: true, def: int64(def), lo: int64(lo), hi: int64(hi), negZero: negZero, base: base,
			get: func(c *Config) *int64 { return (*int64)(p(c)) },
		}
	}
	i := func(name string, p func(*Config) *int, def, lo, hi int, negZero bool) normField {
		return normField{name: name, def: int64(def), lo: int64(lo), hi: int64(hi), negZero: negZero, geti: p}
	}
	return []normField{
		d("NoPathGrace", func(c *Config) *time.Duration { return &c.NoPathGrace }, 15*time.Second, 3*time.Second, 300*time.Second, false,
			func(c *Config) { c.RejoinBackoffMax = time.Second }),
		d("RejoinBackoffMax", func(c *Config) *time.Duration { return &c.RejoinBackoffMax }, 4*time.Second, time.Second, 8*time.Second, false,
			func(c *Config) { c.NoPathGrace = 20 * time.Second }),
		d("JoinStagger", func(c *Config) *time.Duration { return &c.JoinStagger }, time.Second, 100*time.Millisecond, 10*time.Second, false, nil),
		d("RetireGrace", func(c *Config) *time.Duration { return &c.RetireGrace }, 2*time.Second, 0, 30*time.Second, true, nil),
		d("Selector.Floor", func(c *Config) *time.Duration { return &c.Selector.Floor }, 5*time.Millisecond, 0, time.Second, true, nil),
		d("Selector.Dwell", func(c *Config) *time.Duration { return &c.Selector.Dwell }, 3*time.Second, 500*time.Millisecond, 60*time.Second, false, nil),
		d("Selector.Cooldown", func(c *Config) *time.Duration { return &c.Selector.Cooldown }, 15*time.Second, time.Second, 600*time.Second, false, nil),
		d("PingBusy", func(c *Config) *time.Duration { return &c.PingBusy }, 50*time.Millisecond, 10*time.Millisecond, 500*time.Millisecond, false, nil),
		d("PingIdle", func(c *Config) *time.Duration { return &c.PingIdle }, 10*time.Second, time.Second, 60*time.Second, false,
			func(c *Config) { c.Sessionless.Idle = time.Hour }),
		d("DeadMin", func(c *Config) *time.Duration { return &c.DeadMin }, 3*time.Second, 500*time.Millisecond, 10*time.Second, false,
			func(c *Config) { c.DeadMax, c.PacketPing = 30*time.Second, 200*time.Millisecond }),
		d("DeadMax", func(c *Config) *time.Duration { return &c.DeadMax }, 4*time.Second, 500*time.Millisecond, 30*time.Second, false,
			func(c *Config) {
				c.DeadMin, c.WriteStall, c.PacketPing = 500*time.Millisecond, 500*time.Millisecond, 200*time.Millisecond
			}),
		d("WriteStall", func(c *Config) *time.Duration { return &c.WriteStall }, 2*time.Second, 500*time.Millisecond, 30*time.Second, false,
			func(c *Config) { c.DeadMax = 30 * time.Second }),
		d("Probe.Interval", func(c *Config) *time.Duration { return &c.Probe.Interval }, 2*time.Second, 500*time.Millisecond, 30*time.Second, false,
			func(c *Config) { c.Probe.Fresh, c.Sessionless.Idle = 120*time.Second, time.Hour }),
		d("Probe.Fresh", func(c *Config) *time.Duration { return &c.Probe.Fresh }, 10*time.Second, time.Second, 120*time.Second, false,
			func(c *Config) { c.Probe.Interval = 500 * time.Millisecond }),
		d("Probe.BackoffMax", func(c *Config) *time.Duration { return &c.Probe.BackoffMax }, 4*time.Second, time.Second, 8*time.Second, false, nil),
		d("Probe.DialWait", func(c *Config) *time.Duration { return &c.Probe.DialWait }, 800*time.Millisecond, 0, 5*time.Second, true, nil),
		d("DialTimeout", func(c *Config) *time.Duration { return &c.DialTimeout }, 10*time.Second, time.Second, 60*time.Second, false, nil),
		d("Linger", func(c *Config) *time.Duration { return &c.Linger }, 30*time.Second, time.Second, 300*time.Second, false, nil),
		d("Handshake.Timeout", func(c *Config) *time.Duration { return &c.Handshake.Timeout }, 10*time.Second, time.Second, 60*time.Second, false, nil),
		{
			name: "MaxBufferedBytes", def: 1 << 30, lo: 64 << 20, hi: 64 << 30,
			get: func(c *Config) *int64 { return &c.MaxBufferedBytes },
		},
		i("Window", func(c *Config) *int { return &c.Window }, 8<<20, 256<<10, 64<<20, false),
		i("MaxCarriersPerSession", func(c *Config) *int { return &c.MaxCarriersPerSession }, 6, 1, 16, false),
		i("MaxSessions", func(c *Config) *int { return &c.MaxSessions }, 10000, 1, 1000000, false),
		i("Handshake.MaxConcurrent", func(c *Config) *int { return &c.Handshake.MaxConcurrent }, 256, 1, 65536, false),
		i("Handshake.MaxMetadata", func(c *Config) *int { return &c.Handshake.MaxMetadata }, 4096, 0, 65535, true),
		i("Handshake.EarlyDataMax", func(c *Config) *int { return &c.Handshake.EarlyDataMax }, 65536, 0, 65536, true),
		i("Sessionless.PerInstance", func(c *Config) *int { return &c.Sessionless.PerInstance }, 16, 1, 1024, false),
		i("Sessionless.Total", func(c *Config) *int { return &c.Sessionless.Total }, 1024, 1, 65536, false),
		d("Packet.MaxAge", func(c *Config) *time.Duration { return &c.Packet.MaxAge }, 100*time.Millisecond, 10*time.Millisecond, 2*time.Second, false, nil),
		{
			name: "Packet.Queue", def: 1 << 20, lo: 64 << 10, hi: 64 << 20,
			geti: func(c *Config) *int { return &c.Packet.Queue },
			base: func(c *Config) { c.Packet.MaxPayload = 512 }, // constraint 8 quiet at lo
		},
		i("Packet.MaxPayload", func(c *Config) *int { return &c.Packet.MaxPayload }, 65507, 512, 65507, false),
	}
}

func (f normField) set(c *Config, v int64) {
	if f.geti != nil {
		*f.geti(c) = int(v)
		return
	}
	*f.get(c) = v
}

func (f normField) value(c *Config) int64 {
	if f.geti != nil {
		return int64(*f.geti(c))
	}
	return *f.get(c)
}

func (f normField) format(v int64) string {
	if f.dur {
		return time.Duration(v).String()
	}
	return fmt.Sprint(v)
}

// TestConfigNormalize is the per-field table of design §10.4 step 1: for
// every clamped field, zero selects the default silently; exactly lo and
// exactly hi stay unrecorded; one unit below lo and above hi are clamped
// and recorded as "Field: old → new (range lo..hi)"; a negative value
// selects zero silently for the four zero-able fields and is clamped (and
// recorded) for every other one; the extreme values never overflow.
func TestConfigNormalize(t *testing.T) {
	for _, f := range normFields() {
		rangeOf := "range " + f.format(f.lo) + ".." + f.format(f.hi)
		type step struct {
			label string
			in    int64
			want  int64
			adj   []string
		}
		steps := []step{
			{"zero", 0, f.def, nil},
			{"default", f.def, f.def, nil},
			{"hi", f.hi, f.hi, nil},
			{"above", f.hi + 1, f.hi, []string{f.name + ": " + f.format(f.hi+1) + " → " + f.format(f.hi) + " (" + rangeOf + ")"}},
			{"max", math.MaxInt64, f.hi, []string{f.name + ": " + f.format(math.MaxInt64) + " → " + f.format(f.hi) + " (" + rangeOf + ")"}},
		}
		if f.geti != nil && math.MaxInt < math.MaxInt64 { // 32-bit int: the extreme is MaxInt
			steps[len(steps)-1] = step{"max", math.MaxInt, f.hi, []string{f.name + ": " + f.format(math.MaxInt) + " → " + f.format(f.hi) + " (" + rangeOf + ")"}}
		}
		// An input of 0 always selects the default, so the zero lower
		// bound of the zero-able fields is reached with a negative value,
		// and "one below" a lower bound of 1 is exercised by -1.
		if f.negZero {
			steps = append(steps,
				step{"negative", -1, 0, nil},
				step{"min", math.MinInt32, 0, nil})
		} else {
			steps = append(steps,
				step{"lo", f.lo, f.lo, nil},
				step{"negative", -1, f.lo, []string{f.name + ": " + f.format(-1) + " → " + f.format(f.lo) + " (" + rangeOf + ")"}})
			if f.lo > 1 {
				steps = append(steps, step{"below", f.lo - 1, f.lo, []string{f.name + ": " + f.format(f.lo-1) + " → " + f.format(f.lo) + " (" + rangeOf + ")"}})
			}
		}
		for _, s := range steps {
			t.Run(f.name+"/"+s.label, func(t *testing.T) {
				var c Config
				if f.base != nil {
					f.base(&c)
				}
				f.set(&c, s.in)
				e, adj := normalize(c, nil)
				if got := f.value(&e.cfg); got != s.want {
					t.Fatalf("%s: in %s → %s, want %s", f.name, f.format(s.in), f.format(got), f.format(s.want))
				}
				if !slices.Equal(adj, s.adj) {
					t.Fatalf("%s: adjustments %q, want %q", f.name, adj, s.adj)
				}
			})
		}
	}
}

// TestConfigNormalizeRecordFormat pins the exact text of
// Status.ConfigAdjustments records (design §10.4).
func TestConfigNormalizeRecordFormat(t *testing.T) {
	cases := []struct {
		name string
		set  func(*Config)
		want []string
	}{
		{"duration below", func(c *Config) { c.NoPathGrace, c.RejoinBackoffMax = time.Second, time.Second },
			[]string{"NoPathGrace: 1s → 3s (range 3s..5m0s)"}},
		{"duration above", func(c *Config) { c.Linger = time.Hour },
			[]string{"Linger: 1h0m0s → 5m0s (range 1s..5m0s)"}},
		{"bytes below", func(c *Config) { c.Window = 1 },
			[]string{"Window: 1 → 262144 (range 262144..67108864)"}},
		{"bytes above", func(c *Config) { c.MaxBufferedBytes = 1 << 40 },
			[]string{"MaxBufferedBytes: 1099511627776 → 68719476736 (range 67108864..68719476736)"}},
		{"count above", func(c *Config) { c.MaxCarriersPerSession = 17 },
			[]string{"MaxCarriersPerSession: 17 → 16 (range 1..16)"}},
		{"band below", func(c *Config) { c.Selector.Band = 0.01 },
			[]string{"Selector.Band: 0.01 → 0.05 (range 0.05..0.9)"}},
		{"band above", func(c *Config) { c.Selector.Band = 1.5 },
			[]string{"Selector.Band: 1.5 → 0.9 (range 0.05..0.9)"}},
		{"band negative", func(c *Config) { c.Selector.Band = -0.3 },
			[]string{"Selector.Band: -0.3 → 0.05 (range 0.05..0.9)"}},
		{"band NaN", func(c *Config) { c.Selector.Band = math.NaN() },
			[]string{"Selector.Band: NaN → 0.25 (range 0.05..0.9)"}},
		{"band +Inf", func(c *Config) { c.Selector.Band = math.Inf(1) },
			[]string{"Selector.Band: +Inf → 0.9 (range 0.05..0.9)"}},
		{"band -Inf", func(c *Config) { c.Selector.Band = math.Inf(-1) },
			[]string{"Selector.Band: -Inf → 0.05 (range 0.05..0.9)"}},
		{"idle short", func(c *Config) { c.IdleTimeout = time.Second },
			[]string{"IdleTimeout: 1s → 10s (range 0 or 10s..24h0m0s)"}},
		{"idle long", func(c *Config) { c.IdleTimeout = 25 * time.Hour },
			[]string{"IdleTimeout: 25h0m0s → 24h0m0s (range 0 or 10s..24h0m0s)"}},
		{"idle negative", func(c *Config) { c.IdleTimeout = -time.Second },
			[]string{"IdleTimeout: -1s → 0s (range 0 or 10s..24h0m0s)"}},
		{"range then constraint", func(c *Config) { c.RejoinBackoffMax = 9 * time.Second },
			[]string{
				"RejoinBackoffMax: 9s → 8s (range 1s..8s)",
				"RejoinBackoffMax: 8s → 7.5s (constraint 3: RejoinBackoffMax ≤ NoPathGrace/2)",
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			tc.set(&c)
			_, adj := normalize(c, nil)
			if !slices.Equal(adj, tc.want) {
				t.Fatalf("adjustments\n got %q\nwant %q", adj, tc.want)
			}
		})
	}
}

// TestConfigNormalizeBandAndIdle covers the two special fields: Band is a
// float (zero → default, exact bounds unrecorded) and IdleTimeout is "0
// (off) or 10 s–24 h" (zero stays off; exact bounds unrecorded).
func TestConfigNormalizeBandAndIdle(t *testing.T) {
	for _, tc := range []struct {
		in, want float64
		adj      bool
	}{{0, 0.25, false}, {0.05, 0.05, false}, {0.9, 0.9, false}, {0.5, 0.5, false}, {math.Copysign(0, -1), 0.25, false}, {0.049, 0.05, true}, {0.901, 0.9, true}} {
		e, adj := normalize(Config{Selector: SelectorPolicy{Band: tc.in}}, nil)
		if e.cfg.Selector.Band != tc.want || (len(adj) != 0) != tc.adj {
			t.Errorf("Band %v → %v %q, want %v (recorded %v)", tc.in, e.cfg.Selector.Band, adj, tc.want, tc.adj)
		}
	}
	for _, tc := range []struct {
		in, want time.Duration
		adj      bool
	}{{0, 0, false}, {10 * time.Second, 10 * time.Second, false}, {24 * time.Hour, 24 * time.Hour, false}, {time.Minute, time.Minute, false},
		{10*time.Second - 1, 10 * time.Second, true}, {24*time.Hour + 1, 24 * time.Hour, true}, {math.MinInt64, 0, true}, {math.MaxInt64, 24 * time.Hour, true}} {
		e, adj := normalize(Config{IdleTimeout: tc.in}, nil)
		if e.cfg.IdleTimeout != tc.want || (len(adj) != 0) != tc.adj {
			t.Errorf("IdleTimeout %v → %v %q, want %v (recorded %v)", tc.in, e.cfg.IdleTimeout, adj, tc.want, tc.adj)
		}
	}
	// Sessionless.Idle has no static range: zero selects 30 s; any value at
	// or above the constraint stays; a negative one is raised by it.
	for _, tc := range []struct {
		in, want time.Duration
		adj      bool
	}{{0, 30 * time.Second, false}, {30 * time.Second, 30 * time.Second, false}, {1000 * time.Hour, 1000 * time.Hour, false}, {-time.Second, 30 * time.Second, true}} {
		e, adj := normalize(Config{Sessionless: SessionlessLimits{Idle: tc.in}}, nil)
		if e.cfg.Sessionless.Idle != tc.want || (len(adj) != 0) != tc.adj {
			t.Errorf("Sessionless.Idle %v → %v %q, want %v (recorded %v)", tc.in, e.cfg.Sessionless.Idle, adj, tc.want, tc.adj)
		}
	}
}

// TestConfigNormalizeConstraints covers every cross-parameter rule of plan
// §3.6 (design §7.9, §10.4 step 2) at its boundary — exactly at the limit
// nothing changes; one nanosecond beyond it the dependent field is set to
// the limit and recorded with the constraint — and the fixed order in
// which they apply.
func TestConfigNormalizeConstraints(t *testing.T) {
	cases := []struct {
		name  string
		set   func(*Config)
		check func(Config) bool
		want  []string
	}{
		{"DeadMax ≥ DeadMin at limit", func(c *Config) { c.DeadMin, c.DeadMax, c.WriteStall = 5*time.Second, 5*time.Second, time.Second },
			func(c Config) bool { return c.DeadMax == 5*time.Second }, nil},
		{"DeadMax ≥ DeadMin beyond", func(c *Config) { c.DeadMin, c.DeadMax, c.WriteStall = 5*time.Second, 5*time.Second-1, time.Second },
			func(c Config) bool { return c.DeadMax == 5*time.Second },
			[]string{"DeadMax: 4.999999999s → 5s (constraint 1: DeadMax ≥ DeadMin)"}},
		{"WriteStall ≤ DeadMax at limit", func(c *Config) { c.WriteStall = 4 * time.Second },
			func(c Config) bool { return c.WriteStall == 4*time.Second }, nil},
		{"WriteStall ≤ DeadMax beyond", func(c *Config) { c.WriteStall = 4*time.Second + 1 },
			func(c Config) bool { return c.WriteStall == 4*time.Second },
			[]string{"WriteStall: 4.000000001s → 4s (constraint 1: WriteStall ≤ DeadMax)"}},
		{"WriteStall follows a raised DeadMax", func(c *Config) {
			c.DeadMin, c.DeadMax, c.WriteStall, c.PacketPing = time.Second, 500*time.Millisecond, 20*time.Second, 500*time.Millisecond
		},
			func(c Config) bool { return c.DeadMax == time.Second && c.WriteStall == time.Second },
			[]string{"DeadMax: 500ms → 1s (constraint 1: DeadMax ≥ DeadMin)", "WriteStall: 20s → 1s (constraint 1: WriteStall ≤ DeadMax)"}},
		{"PingBusy ≤ DeadMin/4 at limit", func(c *Config) {
			c.DeadMin, c.PingBusy, c.PacketPing = time.Second, 250*time.Millisecond, 500*time.Millisecond
		},
			func(c Config) bool { return c.PingBusy == 250*time.Millisecond }, nil},
		{"PingBusy ≤ DeadMin/4 beyond", func(c *Config) {
			c.DeadMin, c.PingBusy, c.PacketPing = time.Second, 250*time.Millisecond+1, 500*time.Millisecond
		},
			func(c Config) bool { return c.PingBusy == 250*time.Millisecond },
			[]string{"PingBusy: 250.000001ms → 250ms (constraint 2: PingBusy ≤ DeadMin/4)"}},
		{"PingBusy at the smallest DeadMin", func(c *Config) {
			c.DeadMin, c.PingBusy, c.PacketPing = 500*time.Millisecond, 500*time.Millisecond, 250*time.Millisecond
		},
			func(c Config) bool { return c.PingBusy == 125*time.Millisecond },
			[]string{"PingBusy: 500ms → 125ms (constraint 2: PingBusy ≤ DeadMin/4)"}},
		{"PacketPing ≤ DeadMin/2 at limit", func(c *Config) { c.DeadMin, c.PacketPing = time.Second, 500*time.Millisecond },
			func(c Config) bool { return c.PacketPing == 500*time.Millisecond }, nil},
		{"PacketPing ≤ DeadMin/2 beyond", func(c *Config) { c.DeadMin, c.PacketPing = time.Second, 500*time.Millisecond+1 },
			func(c Config) bool { return c.PacketPing == 500*time.Millisecond },
			[]string{"PacketPing: 500.000001ms → 500ms (constraint 2: PacketPing ≤ DeadMin/2)"}},
		{"PacketPing default at the smallest DeadMin", func(c *Config) { c.DeadMin = 500 * time.Millisecond },
			func(c Config) bool { return c.PacketPing == 250*time.Millisecond },
			[]string{"PacketPing: 1s → 250ms (constraint 2: PacketPing ≤ DeadMin/2)"}},
		{"Packet.Queue ≥ MaxPayload + 64 at limit", func(c *Config) { c.Packet.Queue, c.Packet.MaxPayload = 65571, 65507 },
			func(c Config) bool { return c.Packet.Queue == 65571 }, nil},
		{"Packet.Queue ≥ MaxPayload + 64 beyond", func(c *Config) { c.Packet.Queue, c.Packet.MaxPayload = 65570, 65507 },
			func(c Config) bool { return c.Packet.Queue == 65571 },
			[]string{"Packet.Queue: 65570 → 65571 (constraint 8: Packet.Queue ≥ Packet.MaxPayload + 64)"}},
		{"Packet.Queue follows a clamped MaxPayload", func(c *Config) { c.Packet.Queue, c.Packet.MaxPayload = 1, 1<<20 },
			func(c Config) bool { return c.Packet.Queue == 65571 && c.Packet.MaxPayload == 65507 },
			[]string{
				"Packet.Queue: 1 → 65536 (range 65536..67108864)",
				"Packet.MaxPayload: 1048576 → 65507 (range 512..65507)",
				"Packet.Queue: 65536 → 65571 (constraint 8: Packet.Queue ≥ Packet.MaxPayload + 64)",
			}},
		{"RejoinBackoffMax ≤ NoPathGrace/2 at limit", func(c *Config) { c.NoPathGrace, c.RejoinBackoffMax = 6*time.Second, 3*time.Second },
			func(c Config) bool { return c.RejoinBackoffMax == 3*time.Second }, nil},
		{"RejoinBackoffMax ≤ NoPathGrace/2 beyond", func(c *Config) { c.NoPathGrace, c.RejoinBackoffMax = 6*time.Second, 3*time.Second+1 },
			func(c Config) bool { return c.RejoinBackoffMax == 3*time.Second },
			[]string{"RejoinBackoffMax: 3.000000001s → 3s (constraint 3: RejoinBackoffMax ≤ NoPathGrace/2)"}},
		{"RejoinBackoffMax at the smallest grace", func(c *Config) { c.NoPathGrace = 3 * time.Second },
			func(c Config) bool { return c.RejoinBackoffMax == 1500*time.Millisecond },
			[]string{"RejoinBackoffMax: 4s → 1.5s (constraint 3: RejoinBackoffMax ≤ NoPathGrace/2)"}},
		{"Sessionless.Idle by PingIdle at limit", func(c *Config) { c.PingIdle, c.Sessionless.Idle = 20*time.Second, 60*time.Second },
			func(c Config) bool { return c.Sessionless.Idle == 60*time.Second }, nil},
		{"Sessionless.Idle by PingIdle beyond", func(c *Config) { c.PingIdle, c.Sessionless.Idle = 20*time.Second, 60*time.Second-1 },
			func(c Config) bool { return c.Sessionless.Idle == 60*time.Second },
			[]string{"Sessionless.Idle: 59.999999999s → 1m0s (constraint 5: Sessionless.Idle ≥ 3×max(PingIdle, Probe.Interval))"}},
		{"Sessionless.Idle by Probe.Interval", func(c *Config) {
			c.PingIdle, c.Probe.Interval, c.Probe.Fresh = time.Second, 25*time.Second, 50*time.Second
		},
			func(c Config) bool { return c.Sessionless.Idle == 75*time.Second },
			[]string{"Sessionless.Idle: 30s → 1m15s (constraint 5: Sessionless.Idle ≥ 3×max(PingIdle, Probe.Interval))"}},
		{"Probe.Fresh ≥ 2×Interval at limit", func(c *Config) { c.Probe.Interval, c.Probe.Fresh = 5*time.Second, 10*time.Second },
			func(c Config) bool { return c.Probe.Fresh == 10*time.Second }, nil},
		{"Probe.Fresh ≥ 2×Interval beyond", func(c *Config) { c.Probe.Interval, c.Probe.Fresh = 5*time.Second, 10*time.Second-1 },
			func(c Config) bool { return c.Probe.Fresh == 10*time.Second },
			[]string{"Probe.Fresh: 9.999999999s → 10s (constraint 7: Probe.Fresh ≥ 2×Probe.Interval)"}},
		{"order", func(c *Config) {
			c.DeadMin, c.DeadMax, c.WriteStall, c.PingBusy = 2*time.Second, time.Second, 10*time.Second, 500*time.Millisecond
			c.NoPathGrace, c.RejoinBackoffMax = 4*time.Second, 8*time.Second
			c.PingIdle, c.Probe.Interval, c.Probe.Fresh, c.Sessionless.Idle = 30*time.Second, 30*time.Second, 30*time.Second, 10*time.Second
		}, func(c Config) bool {
			return c.DeadMax == 2*time.Second && c.WriteStall == 2*time.Second && c.PingBusy == 500*time.Millisecond &&
				c.RejoinBackoffMax == 2*time.Second && c.Sessionless.Idle == 90*time.Second && c.Probe.Fresh == time.Minute
		}, []string{
			"DeadMax: 1s → 2s (constraint 1: DeadMax ≥ DeadMin)",
			"WriteStall: 10s → 2s (constraint 1: WriteStall ≤ DeadMax)",
			"RejoinBackoffMax: 8s → 2s (constraint 3: RejoinBackoffMax ≤ NoPathGrace/2)",
			"Sessionless.Idle: 10s → 1m30s (constraint 5: Sessionless.Idle ≥ 3×max(PingIdle, Probe.Interval))",
			"Probe.Fresh: 30s → 1m0s (constraint 7: Probe.Fresh ≥ 2×Probe.Interval)",
		}},
		{"all eight", func(c *Config) {
			c.DeadMin, c.DeadMax, c.WriteStall, c.PingBusy = time.Second, 500*time.Millisecond, 6*time.Second, 2*time.Second
			c.NoPathGrace, c.RejoinBackoffMax = 3*time.Second, 2*time.Second
			c.Probe.Interval, c.Probe.Fresh, c.Sessionless.Idle = 10*time.Second, 5*time.Second, 5*time.Second
			c.Packet.Queue, c.Packet.MaxPayload = 64<<10, 65507
		}, func(c Config) bool {
			return c.DeadMax == time.Second && c.WriteStall == time.Second && c.PingBusy == 250*time.Millisecond &&
				c.PacketPing == 500*time.Millisecond && c.RejoinBackoffMax == 1500*time.Millisecond &&
				c.Sessionless.Idle == 30*time.Second && c.Probe.Fresh == 20*time.Second && c.Packet.Queue == 65571
		}, []string{
			"PingBusy: 2s → 500ms (range 10ms..500ms)",
			"DeadMax: 500ms → 1s (constraint 1: DeadMax ≥ DeadMin)",
			"WriteStall: 6s → 1s (constraint 1: WriteStall ≤ DeadMax)",
			"PingBusy: 500ms → 250ms (constraint 2: PingBusy ≤ DeadMin/4)",
			"PacketPing: 1s → 500ms (constraint 2: PacketPing ≤ DeadMin/2)",
			"RejoinBackoffMax: 2s → 1.5s (constraint 3: RejoinBackoffMax ≤ NoPathGrace/2)",
			"Sessionless.Idle: 5s → 30s (constraint 5: Sessionless.Idle ≥ 3×max(PingIdle, Probe.Interval))",
			"Probe.Fresh: 5s → 20s (constraint 7: Probe.Fresh ≥ 2×Probe.Interval)",
			"Packet.Queue: 65536 → 65571 (constraint 8: Packet.Queue ≥ Packet.MaxPayload + 64)",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			tc.set(&c)
			e, adj := normalize(c, nil)
			if !tc.check(e.cfg) {
				t.Errorf("normalized config %+v does not satisfy the expectation", e.cfg)
			}
			if !slices.Equal(adj, tc.want) {
				t.Errorf("adjustments\n got %q\nwant %q", adj, tc.want)
			}
			checkNormalized(t, e.cfg)
		})
	}
}

// checkNormalized asserts that c satisfies every plan §4 range and every
// plan §3.6 cross-parameter constraint.
func checkNormalized(t *testing.T, c Config) {
	t.Helper()
	in := func(name string, v, lo, hi time.Duration) {
		if v < lo || v > hi {
			t.Errorf("%s = %v outside [%v, %v]", name, v, lo, hi)
		}
	}
	ini := func(name string, v, lo, hi int64) {
		if v < lo || v > hi {
			t.Errorf("%s = %d outside [%d, %d]", name, v, lo, hi)
		}
	}
	in("NoPathGrace", c.NoPathGrace, 3*time.Second, 300*time.Second)
	in("RejoinBackoffMax", c.RejoinBackoffMax, time.Second, min(8*time.Second, c.NoPathGrace/2))
	in("JoinStagger", c.JoinStagger, 100*time.Millisecond, 10*time.Second)
	in("RetireGrace", c.RetireGrace, 0, 30*time.Second)
	if !(c.Selector.Band >= 0.05 && c.Selector.Band <= 0.9) {
		t.Errorf("Selector.Band = %v outside [0.05, 0.9]", c.Selector.Band)
	}
	in("Selector.Floor", c.Selector.Floor, 0, time.Second)
	in("Selector.Dwell", c.Selector.Dwell, 500*time.Millisecond, 60*time.Second)
	in("Selector.Cooldown", c.Selector.Cooldown, time.Second, 600*time.Second)
	in("DeadMin", c.DeadMin, 500*time.Millisecond, 10*time.Second)
	in("DeadMax", c.DeadMax, c.DeadMin, 30*time.Second)
	in("WriteStall", c.WriteStall, 500*time.Millisecond, c.DeadMax)
	in("PingBusy", c.PingBusy, 10*time.Millisecond, min(500*time.Millisecond, c.DeadMin/4))
	in("PingIdle", c.PingIdle, time.Second, 60*time.Second)
	in("Probe.Interval", c.Probe.Interval, 500*time.Millisecond, 30*time.Second)
	in("Probe.Fresh", c.Probe.Fresh, 2*c.Probe.Interval, 120*time.Second)
	in("Probe.BackoffMax", c.Probe.BackoffMax, time.Second, 8*time.Second)
	in("Probe.DialWait", c.Probe.DialWait, 0, 5*time.Second)
	in("DialTimeout", c.DialTimeout, time.Second, 60*time.Second)
	in("Linger", c.Linger, time.Second, 300*time.Second)
	if c.IdleTimeout != 0 {
		in("IdleTimeout", c.IdleTimeout, 10*time.Second, 24*time.Hour)
	}
	ini("Window", int64(c.Window), 256<<10, 64<<20)
	ini("MaxCarriersPerSession", int64(c.MaxCarriersPerSession), 1, 16)
	ini("MaxSessions", int64(c.MaxSessions), 1, 1000000)
	ini("MaxBufferedBytes", c.MaxBufferedBytes, 64<<20, 64<<30)
	in("Handshake.Timeout", c.Handshake.Timeout, time.Second, 60*time.Second)
	ini("Handshake.MaxConcurrent", int64(c.Handshake.MaxConcurrent), 1, 65536)
	ini("Handshake.MaxMetadata", int64(c.Handshake.MaxMetadata), 0, 65535)
	ini("Handshake.EarlyDataMax", int64(c.Handshake.EarlyDataMax), 0, 65536)
	ini("Sessionless.PerInstance", int64(c.Sessionless.PerInstance), 1, 1024)
	ini("Sessionless.Total", int64(c.Sessionless.Total), 1, 65536)
	in("PacketPing", c.PacketPing, 200*time.Millisecond, min(10*time.Second, c.DeadMin/2))
	ini("Packet.MaxPayload", int64(c.Packet.MaxPayload), 512, 65507)
	ini("Packet.Queue", int64(c.Packet.Queue), max(64<<10, int64(c.Packet.MaxPayload)+64), 64<<20)
	in("Packet.MaxAge", c.Packet.MaxAge, 10*time.Millisecond, 2*time.Second)
	if lim := 3 * max(c.PingIdle, c.Probe.Interval); c.Sessionless.Idle < lim {
		t.Errorf("Sessionless.Idle = %v < 3×max(PingIdle, Probe.Interval) = %v", c.Sessionless.Idle, lim)
	}
}

// randomConfig draws a Config whose fields mix zero, in-range, boundary,
// out-of-range and extreme values (NaN and ±Inf for Band).
func randomConfig(r *rand.Rand) Config {
	dur := func(lo, hi time.Duration) time.Duration {
		switch r.IntN(10) {
		case 0:
			return 0
		case 1:
			return lo
		case 2:
			return hi
		case 3:
			return lo - time.Duration(r.Int64N(int64(lo)+1)) - 1
		case 4:
			return hi + time.Duration(r.Int64N(int64(hi)+1)) + 1
		case 5:
			return []time.Duration{math.MinInt64, math.MaxInt64, -1}[r.IntN(3)]
		}
		return lo + time.Duration(r.Int64N(int64(hi-lo)+1))
	}
	num := func(lo, hi int64) int64 {
		switch r.IntN(10) {
		case 0:
			return 0
		case 1:
			return lo
		case 2:
			return hi
		case 3:
			return lo - 1 - r.Int64N(lo+1)
		case 4:
			return hi + 1 + r.Int64N(hi+1)
		case 5:
			return []int64{math.MinInt32, math.MaxInt32, -1}[r.IntN(3)]
		}
		return lo + r.Int64N(hi-lo+1)
	}
	band := func() float64 {
		switch r.IntN(8) {
		case 0:
			return 0
		case 1:
			return math.NaN()
		case 2:
			return math.Inf(1 - 2*r.IntN(2))
		case 3:
			return -r.Float64()
		case 4:
			return 1 + r.Float64()
		}
		return 0.05 + 0.85*r.Float64()
	}
	return Config{
		NoPathGrace:      dur(3*time.Second, 300*time.Second),
		RejoinBackoffMax: dur(time.Second, 8*time.Second),
		JoinStagger:      dur(100*time.Millisecond, 10*time.Second),
		RetireGrace:      dur(time.Millisecond, 30*time.Second),
		Selector: SelectorPolicy{
			Band:     band(),
			Floor:    dur(time.Millisecond, time.Second),
			Dwell:    dur(500*time.Millisecond, 60*time.Second),
			Cooldown: dur(time.Second, 600*time.Second),
		},
		PingBusy:   dur(10*time.Millisecond, 500*time.Millisecond),
		PingIdle:   dur(time.Second, 60*time.Second),
		DeadMin:    dur(500*time.Millisecond, 10*time.Second),
		DeadMax:    dur(500*time.Millisecond, 30*time.Second),
		WriteStall: dur(500*time.Millisecond, 30*time.Second),
		Probe: ProbePolicy{
			Interval:   dur(500*time.Millisecond, 30*time.Second),
			Fresh:      dur(time.Second, 120*time.Second),
			BackoffMax: dur(time.Second, 8*time.Second),
			DialWait:   dur(time.Millisecond, 5*time.Second),
		},
		DialTimeout:           dur(time.Second, 60*time.Second),
		Linger:                dur(time.Second, 300*time.Second),
		IdleTimeout:           dur(10*time.Second, 24*time.Hour),
		Window:                int(num(256<<10, 64<<20)),
		MaxCarriersPerSession: int(num(1, 16)),
		MaxSessions:           int(num(1, 1000000)),
		MaxBufferedBytes:      []int64{0, 64 << 20, 64 << 30, 1, -1, math.MaxInt64, 1 << 33}[r.IntN(7)],
		Handshake: HandshakeLimits{
			Timeout:       dur(time.Second, 60*time.Second),
			MaxConcurrent: int(num(1, 65536)),
			MaxMetadata:   int(num(1, 65535)),
			EarlyDataMax:  int(num(1, 65536)),
		},
		Sessionless: SessionlessLimits{
			PerInstance: int(num(1, 1024)),
			Total:       int(num(1, 65536)),
			Idle:        dur(time.Second, time.Hour),
		},
		PacketPing: dur(200*time.Millisecond, 10*time.Second),
		Packet: PacketPolicy{
			Queue:      int(num(64<<10, 64<<20)),
			MaxAge:     dur(10*time.Millisecond, 2*time.Second),
			MaxPayload: int(num(512, 65507)),
		},
	}
}

// asInput turns a normalized Config back into the input that selects it:
// a zero in one of the five zero-able fields must be written as a negative
// value, because zero would select the default.
func asInput(c Config) Config {
	for _, p := range []*time.Duration{&c.RetireGrace, &c.Selector.Floor, &c.Probe.DialWait} {
		if *p == 0 {
			*p = -1
		}
	}
	for _, p := range []*int{&c.Handshake.MaxMetadata, &c.Handshake.EarlyDataMax} {
		if *p == 0 {
			*p = -1
		}
	}
	return c
}

// TestConfigNormalizeIdempotent is the normalization property (design
// §10.4: a pure function): for 5000 random configurations mixing zero,
// boundary, out-of-range and extreme values, the result satisfies every
// range and constraint, a second normalization of it changes and records
// nothing, and the function is deterministic.
func TestConfigNormalizeIdempotent(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 5000; i++ {
		c := randomConfig(r)
		e1, adj1 := normalize(c, nil)
		checkNormalized(t, e1.cfg)
		e2, adj2 := normalize(asInput(e1.cfg), nil)
		if len(adj2) != 0 {
			t.Fatalf("config %d: second normalization recorded %q", i, adj2)
		}
		if !reflect.DeepEqual(e2.cfg, e1.cfg) {
			t.Fatalf("config %d: second normalization changed\n%+v\n%+v", i, e1.cfg, e2.cfg)
		}
		e3, adj3 := normalize(c, nil)
		if !reflect.DeepEqual(e3.cfg, e1.cfg) || !slices.Equal(adj3, adj1) {
			t.Fatalf("config %d: normalize is not deterministic", i)
		}
		for _, s := range adj1 {
			if !strings.Contains(s, " → ") || !strings.HasSuffix(s, ")") || !(strings.Contains(s, "(range ") || strings.Contains(s, "(constraint ")) {
				t.Fatalf("config %d: malformed record %q", i, s)
			}
		}
		if t.Failed() {
			t.Fatalf("config %d: %+v", i, c)
		}
	}
}

// TestConfigNormalizeDefaults checks the zero Config against the plan §4
// defaults and the derived structures of design §10.4 step 3.
func TestConfigNormalizeDefaults(t *testing.T) {
	e, adj := normalize(Config{}, nil)
	if len(adj) != 0 {
		t.Fatalf("zero config recorded %q", adj)
	}
	want := Config{
		NoPathGrace: 15 * time.Second, RejoinBackoffMax: 4 * time.Second, JoinStagger: time.Second, RetireGrace: 2 * time.Second,
		Selector: SelectorPolicy{Band: 0.25, Floor: 5 * time.Millisecond, Dwell: 3 * time.Second, Cooldown: 15 * time.Second},
		PingBusy: 50 * time.Millisecond, PingIdle: 10 * time.Second,
		DeadMin: 3 * time.Second, DeadMax: 4 * time.Second, WriteStall: 2 * time.Second,
		Probe:       ProbePolicy{Interval: 2 * time.Second, Fresh: 10 * time.Second, BackoffMax: 4 * time.Second, DialWait: 800 * time.Millisecond},
		DialTimeout: 10 * time.Second, Linger: 30 * time.Second,
		Window: 8 << 20, MaxCarriersPerSession: 6, MaxSessions: 10000, MaxBufferedBytes: 1 << 30,
		Handshake:   HandshakeLimits{Timeout: 10 * time.Second, MaxConcurrent: 256, MaxMetadata: 4096, EarlyDataMax: 65536},
		Sessionless: SessionlessLimits{PerInstance: 16, Total: 1024, Idle: 30 * time.Second},
		PacketPing:  time.Second,
		Packet:      PacketPolicy{Queue: 1 << 20, MaxAge: 100 * time.Millisecond, MaxPayload: 65507},
	}
	if !reflect.DeepEqual(e.cfg, want) {
		t.Fatalf("defaults\n got %+v\nwant %+v", e.cfg, want)
	}
	wantTiming := carrier.Timing{
		PingBusy: 50 * time.Millisecond, PingIdle: 10 * time.Second, DeadMin: 3 * time.Second, DeadMax: 4 * time.Second,
		WriteStall: 2 * time.Second, DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second,
		ProbeInterval: 2 * time.Second, SessionlessIdle: 30 * time.Second, AbandonWait: time.Second,
		Window: 8 << 20, CapFloor: 128 << 10, BatchBudget: 256 << 10, Segment: 64 << 10,
		PacketPing: time.Second, PacketActive: 10 * time.Second, RelRTOInit: 300 * time.Millisecond,
		RelRTOMin: 200 * time.Millisecond, RelRTOMax: 2 * time.Second, MTUProbeEvery: 10, MTUProbeFails: 3,
	}
	if e.timing != wantTiming {
		t.Fatalf("timing\n got %+v\nwant %+v", e.timing, wantTiming)
	}
	if e.presets != (carrier.Presets{}) {
		t.Fatalf("presets %+v, want zero (production values)", e.presets)
	}
	h := e.health
	if h.Interval != 2*time.Second || h.Fresh != 10*time.Second || h.BackoffMax != 4*time.Second ||
		h.DialWait != 800*time.Millisecond || h.IdleStop != 5*time.Minute || h.LoadThreshold != 64<<10 ||
		h.Agg != sched.DefaultAggParams() || h.Rand == nil {
		t.Fatalf("health params %+v", h)
	}
	p := e.params
	wantSel := sched.SelectorParams{Band: 0.25, Floor: 5 * time.Millisecond, Dwell: 3 * time.Second, Cooldown: 15 * time.Second, Fresh: 10 * time.Second}
	if p.Window != 8<<20 || p.JoinStagger != time.Second || p.RetireGrace != 2*time.Second || p.Linger != 30*time.Second ||
		p.IdleTimeout != 0 || p.Selector != wantSel || p.MaxCarriers != 6 || p.AckEvery != 64<<10 ||
		p.AckDelay != 20*time.Millisecond || p.RescueMin != 300*time.Millisecond || p.WindowReadvertise != 200*time.Millisecond ||
		p.FirstOffset != 0 || p.OffsetLimit != 1<<62 || p.FirstEpoch != 1 {
		t.Fatalf("session template %+v", p)
	}
	if p.Role != 0 || p.Mode != 0 || p.Grace != 0 || p.Retain != 0 || p.BackoffMax != 0 || p.AcceptTimeout != 0 || p.TombstoneTTL != 0 {
		t.Fatalf("session template has per-session fields set: %+v", p)
	}
	if e.retainSlack != 5*time.Second || e.eventQueue != 256 || e.abandonLimit != 256 || e.firstCarrierID != 0 || e.rand == nil || e.hooks != nil {
		t.Fatalf("effective constants %+v", e)
	}
	if v := e.rand(); !(v >= 0 && v < 1) {
		t.Fatalf("rand() = %v outside [0, 1)", v)
	}
}

// TestConfigNormalizeOverrides checks design §10.4 step 5: overrides apply
// after the clamps and constraints, unclamped and unrecorded, reach every
// derived structure, and a zero field keeps the normalized value.
func TestConfigNormalizeOverrides(t *testing.T) {
	hooks := &testhooks.Hooks{}
	fixed := func() float64 { return 0.5 }
	ov := &testhooks.Overrides{
		NoPathGrace: 200 * time.Millisecond, RejoinBackoffMax: 20 * time.Second, JoinStagger: time.Millisecond, RetireGrace: 500 * time.Millisecond,
		PingBusy: time.Millisecond, PingIdle: 500 * time.Millisecond, DeadMin: 100 * time.Millisecond, DeadMax: 50 * time.Millisecond, WriteStall: time.Hour,
		ProbeInterval: 200 * time.Millisecond, ProbeFresh: 300 * time.Millisecond, ProbeBackoffMax: 20 * time.Second, ProbeDialWait: 9 * time.Second,
		DialTimeout: 100 * time.Millisecond, Linger: 10 * time.Second, IdleTimeout: time.Second,
		HandshakeTimeout: 50 * time.Millisecond, AcceptTimeout: 5 * time.Millisecond, SessionlessIdle: time.Millisecond,
		SelectorDwell: time.Second, SelectorCooldown: 2 * time.Second, SelectorFloor: 2 * time.Second, SelectorBand: 0.99,
		ProbeIdleStop: time.Minute, RetainSlack: 2 * time.Second,
		AckDelay: time.Millisecond, RescueMin: 7 * time.Millisecond, AbandonWait: 3 * time.Millisecond, WindowReadvertise: 9 * time.Millisecond,
		Window: 4 << 10, Segment: 1 << 10, BatchBudget: 2 << 10, AckEvery: 512, EventQueue: 4, AbandonLimit: 3,
		MaxCarriersPerSession: 40, MaxSessions: 2, CapFloor: 1 << 10, LoadThreshold: 7, MaxBufferedBytes: 1 << 20,
		AggWindow: 8, AggMinEarlier: 5, AggShiftRun: 4, AggSigmaK: 1.5, AggSigmaFloor: time.Microsecond,
		FirstFseq: 0xFFFFFFF0, FirstOffset: 1<<62 - 1<<20, FirstEpoch: 0xFFFFFFFE, FirstPingID: 0xFFFFFFFD, FirstCarrierID: 0xFFFFFFFC,
		OffsetLimit: 1 << 62, Rand: fixed, Hooks: hooks,
	}
	in := Config{Linger: time.Hour} // one clamp, recorded before the override replaces the value
	e, adj := normalize(in, ov)
	if want := []string{"Linger: 1h0m0s → 5m0s (range 1s..5m0s)"}; !slices.Equal(adj, want) {
		t.Fatalf("adjustments %q, want %q (overrides are never recorded)", adj, want)
	}
	c := e.cfg
	if c.NoPathGrace != 200*time.Millisecond || c.RejoinBackoffMax != 20*time.Second || c.JoinStagger != time.Millisecond ||
		c.RetireGrace != 500*time.Millisecond || c.PingBusy != time.Millisecond || c.PingIdle != 500*time.Millisecond ||
		c.DeadMin != 100*time.Millisecond || c.DeadMax != 50*time.Millisecond || c.WriteStall != time.Hour ||
		c.Probe != (ProbePolicy{Interval: 200 * time.Millisecond, Fresh: 300 * time.Millisecond, BackoffMax: 20 * time.Second, DialWait: 9 * time.Second}) ||
		c.DialTimeout != 100*time.Millisecond || c.Linger != 10*time.Second || c.IdleTimeout != time.Second ||
		c.Handshake.Timeout != 50*time.Millisecond || c.Sessionless.Idle != time.Millisecond ||
		c.Selector != (SelectorPolicy{Band: 0.99, Floor: 2 * time.Second, Dwell: time.Second, Cooldown: 2 * time.Second}) ||
		c.Window != 4<<10 || c.MaxCarriersPerSession != 40 || c.MaxSessions != 2 || c.MaxBufferedBytes != 1<<20 {
		t.Fatalf("overrides not folded into cfg (unclamped): %+v", c)
	}
	// Fields the overrides cannot reach keep their normalized values.
	if c.Handshake.MaxConcurrent != 256 || c.Handshake.MaxMetadata != 4096 || c.Sessionless.PerInstance != 16 || c.Sessionless.Total != 1024 {
		t.Fatalf("non-overridable fields changed: %+v", c)
	}
	wantTiming := carrier.Timing{
		PingBusy: time.Millisecond, PingIdle: 500 * time.Millisecond, DeadMin: 100 * time.Millisecond, DeadMax: 50 * time.Millisecond,
		WriteStall: time.Hour, DialTimeout: 100 * time.Millisecond, HandshakeTimeout: 50 * time.Millisecond,
		ProbeInterval: 200 * time.Millisecond, SessionlessIdle: time.Millisecond, AbandonWait: 3 * time.Millisecond,
		Window: 4 << 10, CapFloor: 1 << 10, BatchBudget: 2 << 10, Segment: 1 << 10,
		// M2 values the overrides above do not set: their defaults, and
		// PacketActive = the overridden PingIdle.
		PacketPing: time.Second, PacketActive: 500 * time.Millisecond, RelRTOInit: 300 * time.Millisecond,
		RelRTOMin: 200 * time.Millisecond, RelRTOMax: 2 * time.Second, MTUProbeEvery: 10, MTUProbeFails: 3,
	}
	if e.timing != wantTiming {
		t.Fatalf("timing\n got %+v\nwant %+v", e.timing, wantTiming)
	}
	if e.presets != (carrier.Presets{FirstFseq: 0xFFFFFFF0, FirstPingID: 0xFFFFFFFD}) {
		t.Fatalf("presets %+v", e.presets)
	}
	wantAgg := sched.AggParams{Window: 8, MinEarlier: 5, ShiftRun: 4, SigmaK: 1.5, SigmaFloor: time.Microsecond}
	h := e.health
	if h.Interval != 200*time.Millisecond || h.Fresh != 300*time.Millisecond || h.BackoffMax != 20*time.Second ||
		h.DialWait != 9*time.Second || h.IdleStop != time.Minute || h.LoadThreshold != 7 || h.Agg != wantAgg || h.Rand() != 0.5 {
		t.Fatalf("health params %+v", h)
	}
	p := e.params
	wantSel := sched.SelectorParams{Band: 0.99, Floor: 2 * time.Second, Dwell: time.Second, Cooldown: 2 * time.Second, Fresh: 300 * time.Millisecond}
	if p.Window != 4<<10 || p.JoinStagger != time.Millisecond || p.RetireGrace != 500*time.Millisecond || p.Linger != 10*time.Second ||
		p.IdleTimeout != time.Second || p.Selector != wantSel || p.MaxCarriers != 40 || p.AckEvery != 512 ||
		p.AckDelay != time.Millisecond || p.RescueMin != 7*time.Millisecond || p.WindowReadvertise != 9*time.Millisecond ||
		p.FirstOffset != 1<<62-1<<20 || p.OffsetLimit != 1<<62 || p.FirstEpoch != 0xFFFFFFFE {
		t.Fatalf("session template %+v", p)
	}
	if e.retainSlack != 2*time.Second || e.eventQueue != 4 || e.abandonLimit != 3 || e.firstCarrierID != 0xFFFFFFFC ||
		e.rand() != 0.5 || e.hooks != hooks {
		t.Fatalf("effective constants %+v", e)
	}

	// A zero Overrides changes nothing.
	e0, adj0 := normalize(Config{}, &testhooks.Overrides{})
	eNil, _ := normalize(Config{}, nil)
	if len(adj0) != 0 || !reflect.DeepEqual(e0.cfg, eNil.cfg) || e0.timing != eNil.timing || e0.presets != eNil.presets ||
		e0.health.Agg != eNil.health.Agg || e0.params != eNil.params || e0.retainSlack != eNil.retainSlack ||
		e0.eventQueue != eNil.eventQueue || e0.abandonLimit != eNil.abandonLimit || e0.hooks != nil {
		t.Fatalf("a zero Overrides changed the result")
	}
}

// TestNormalizeListen checks the ListenConfig normalization: defaults,
// both clamps with the "Listen[i]." prefix, the AcceptTimeout override and
// the Sources copy.
func TestNormalizeListen(t *testing.T) {
	cfg, adj := normalizeListen(0, ListenConfig{}, nil)
	if cfg.AcceptBacklog != 128 || cfg.AcceptTimeout != 10*time.Second || cfg.Sources != nil || len(adj) != 0 {
		t.Fatalf("defaults %+v %q", cfg, adj)
	}
	cfg, adj = normalizeListen(0, ListenConfig{AcceptBacklog: 1, AcceptTimeout: 100 * time.Millisecond}, nil)
	if cfg.AcceptBacklog != 1 || cfg.AcceptTimeout != 100*time.Millisecond || len(adj) != 0 {
		t.Fatalf("lower bounds %+v %q", cfg, adj)
	}
	cfg, adj = normalizeListen(3, ListenConfig{AcceptBacklog: 65537, AcceptTimeout: 99 * time.Millisecond}, nil)
	want := []string{
		"Listen[3].AcceptBacklog: 65537 → 65536 (range 1..65536)",
		"Listen[3].AcceptTimeout: 99ms → 100ms (range 100ms..1m0s)",
	}
	if cfg.AcceptBacklog != 65536 || cfg.AcceptTimeout != 100*time.Millisecond || !slices.Equal(adj, want) {
		t.Fatalf("clamps %+v %q, want %q", cfg, adj, want)
	}
	cfg, adj = normalizeListen(1, ListenConfig{AcceptBacklog: -5, AcceptTimeout: time.Hour}, &testhooks.Overrides{AcceptTimeout: 7 * time.Millisecond})
	want = []string{
		"Listen[1].AcceptBacklog: -5 → 1 (range 1..65536)",
		"Listen[1].AcceptTimeout: 1h0m0s → 1m0s (range 100ms..1m0s)",
	}
	if cfg.AcceptBacklog != 1 || cfg.AcceptTimeout != 7*time.Millisecond || !slices.Equal(adj, want) {
		t.Fatalf("override %+v %q", cfg, adj)
	}
	src := []Source{FromListener(nil), FromListener(nil)}
	cfg, _ = normalizeListen(0, ListenConfig{Sources: src}, nil)
	src[0] = nil
	if len(cfg.Sources) != 2 || cfg.Sources[0] == nil {
		t.Fatalf("Sources not copied: %v", cfg.Sources)
	}
}

// TestSessionParams checks design §10.4 step 4: the per-Dial grace clamp
// (3 s–300 s), the per-session backoff cap and announced retain, and the
// passive retain clamp [1 s, 400 s] with TombstoneTTL = retain + Linger.
func TestSessionParams(t *testing.T) {
	e, _ := normalize(Config{}, nil)
	for _, tc := range []struct {
		mode                Mode
		in                  time.Duration
		grace, back, retain time.Duration
		wantMode            session.Mode
	}{
		{0, 0, 15 * time.Second, 4 * time.Second, 15*time.Second + 10*time.Second + 4*time.Second + 5*time.Second, session.ModeSelector},
		{ModeBond, 0, 15 * time.Second, 4 * time.Second, 34 * time.Second, session.ModeBond},
		{ModeSelector, 3 * time.Second, 3 * time.Second, 1500 * time.Millisecond, 22 * time.Second, session.ModeSelector},
		{ModeSelector, 3*time.Second - 1, 3 * time.Second, 1500 * time.Millisecond, 22 * time.Second, session.ModeSelector},
		{ModeSelector, -time.Hour, 3 * time.Second, 1500 * time.Millisecond, 22 * time.Second, session.ModeSelector},
		{ModeSelector, 300 * time.Second, 300 * time.Second, 4 * time.Second, 319 * time.Second, session.ModeSelector},
		{ModeSelector, time.Hour, 300 * time.Second, 4 * time.Second, 319 * time.Second, session.ModeSelector},
		{ModeSelector, 5 * time.Second, 5 * time.Second, 2500 * time.Millisecond, 24 * time.Second, session.ModeSelector},
	} {
		p := e.dialerParams(tc.mode, tc.in)
		if p.Role != session.RoleDialer || p.Mode != tc.wantMode || p.Grace != tc.grace || p.BackoffMax != tc.back || p.Retain != tc.retain {
			t.Errorf("dialerParams(%v, %v) = role %v mode %v grace %v backoff %v retain %v; want %v %v %v",
				tc.mode, tc.in, p.Role, p.Mode, p.Grace, p.BackoffMax, p.Retain, tc.grace, tc.back, tc.retain)
		}
		if p.TombstoneTTL != 0 || p.AcceptTimeout != 0 {
			t.Errorf("dialer params carry passive fields: %+v", p)
		}
		if p.Window != e.params.Window || p.Selector != e.params.Selector || p.MaxCarriers != e.params.MaxCarriers {
			t.Errorf("dialer params lost the template: %+v", p)
		}
	}
	// The largest normalized retain stays inside the passive clamp.
	big, _ := normalize(Config{NoPathGrace: 300 * time.Second, PingIdle: time.Minute, DeadMax: 30 * time.Second}, nil)
	if r := big.dialerParams(0, 0).Retain; r != 395*time.Second || r > 400*time.Second {
		t.Errorf("largest announced retain %v, want 395s ≤ 400s", r)
	}
	for _, tc := range []struct {
		ms    uint32
		grace time.Duration
	}{
		{0, time.Second}, {1, time.Second}, {999, time.Second}, {1000, time.Second}, {7500, 7500 * time.Millisecond},
		{400000, 400 * time.Second}, {400001, 400 * time.Second}, {math.MaxUint32, 400 * time.Second},
	} {
		p := e.passiveParams(ModeBond, tc.ms, 3*time.Second)
		if p.Role != session.RolePassive || p.Mode != session.ModeBond || p.Grace != tc.grace ||
			p.TombstoneTTL != tc.grace+30*time.Second || p.AcceptTimeout != 3*time.Second || p.Retain != 0 || p.BackoffMax != 0 {
			t.Errorf("passiveParams(retain %d ms) = %+v, want grace %v", tc.ms, p, tc.grace)
		}
	}
	// The M1a fixture's numbers (design §11.3): grace 3 s, PingIdle 500 ms,
	// DeadMax 2 s, RetainSlack 2 s → the passive retains 7.5 s.
	fx, _ := normalize(Config{}, &testhooks.Overrides{PingIdle: 500 * time.Millisecond, DeadMin: time.Second, DeadMax: 2 * time.Second, RetainSlack: 2 * time.Second})
	if r := fx.dialerParams(0, 3*time.Second).Retain; r != 7500*time.Millisecond {
		t.Errorf("fixture retain %v, want 7.5s", r)
	}
	// An override grace below the clamp reaches dialer sessions that do not
	// override it per Dial (L18 tests use 200 ms).
	short, _ := normalize(Config{}, &testhooks.Overrides{NoPathGrace: 200 * time.Millisecond})
	if p := short.dialerParams(0, 0); p.Grace != 200*time.Millisecond || p.BackoffMax != 100*time.Millisecond {
		t.Errorf("override grace: %v backoff %v", p.Grace, p.BackoffMax)
	}
	// Derived sums saturate instead of wrapping.
	huge, _ := normalize(Config{}, &testhooks.Overrides{NoPathGrace: math.MaxInt64 - 1, Linger: math.MaxInt64})
	if r := huge.dialerParams(0, 0).Retain; r != math.MaxInt64 {
		t.Errorf("saturating retain %v", r)
	}
	if ttl := huge.passiveParams(ModeSelector, 1000, 0).TombstoneTTL; ttl != math.MaxInt64 {
		t.Errorf("saturating TTL %v", ttl)
	}
}

// TestPacketConfigNormalize: Config.PacketPing and Config.Packet (M2-D64,
// §A7.4): defaults 1 s, 1 MiB, 100 ms and 65,507; clamps 0.2–10 s, 64 KiB–
// 64 MiB, 10 ms–2 s and 512–65,507, each recorded; then constraint 2
// (PacketPing ≤ DeadMin/2, R1-29's wording) and constraint 8 (Queue ≥
// MaxPayload + 64). The normalized values reach the carrier Timing, the
// packet session template and the udpflow bounds — MaxFlows = min(65,536,
// MaxSessions × MaxCarriersPerSession + Sessionless.Total +
// Handshake.MaxConcurrent), tombstones for max(Handshake.Timeout,
// DialTimeout) + 2 s (M2-D59, R1-11, R1-21) — and the testhooks overrides
// reach all of them unclamped.
func TestPacketConfigNormalize(t *testing.T) {
	e, adj := normalize(Config{}, nil)
	if len(adj) != 0 {
		t.Fatalf("defaults recorded %q", adj)
	}
	if c := e.cfg; c.PacketPing != time.Second || c.Packet != (PacketPolicy{Queue: 1 << 20, MaxAge: 100 * time.Millisecond, MaxPayload: 65507}) {
		t.Fatalf("defaults %v %+v", c.PacketPing, c.Packet)
	}
	wantPk := session.PacketParams{MaxPayload: 65507, Queue: 1 << 20, MaxAge: 100 * time.Millisecond, PacketPing: time.Second,
		PackEvery: 256, FinWaitMax: time.Second, DedupBits: wire.DefaultSeqWindowBits}
	if e.packet != wantPk {
		t.Fatalf("packet template %+v, want %+v", e.packet, wantPk)
	}
	wantFlow := udpflow.Limits{MaxFlows: 10000*6 + 1024 + 256, PerSource: 32, PerSourceJoin: 32, Inbox: 512, TombstoneTTL: 12 * time.Second, Tombstones: 4096}
	if e.flow != wantFlow {
		t.Fatalf("flow limits %+v, want %+v", e.flow, wantFlow)
	}
	tm := e.timing
	if tm.PacketPing != time.Second || tm.PacketActive != 10*time.Second || tm.RelRTOInit != 300*time.Millisecond ||
		tm.RelRTOMin != 200*time.Millisecond || tm.RelRTOMax != 2*time.Second || tm.MTUProbeEvery != 10 || tm.MTUProbeFails != 3 {
		t.Fatalf("timing %+v", tm)
	}

	for _, tc := range []struct {
		name string
		in   Config
		want []string
		ok   func(Config) bool
	}{
		{"PacketPing below", Config{PacketPing: 199 * time.Millisecond}, []string{"PacketPing: 199ms → 200ms (range 200ms..10s)"},
			func(c Config) bool { return c.PacketPing == 200*time.Millisecond }},
		{"PacketPing above, then constraint 2", Config{PacketPing: time.Minute, DeadMin: 10 * time.Second, DeadMax: 10 * time.Second},
			[]string{"PacketPing: 1m0s → 10s (range 200ms..10s)", "PacketPing: 10s → 5s (constraint 2: PacketPing ≤ DeadMin/2)"},
			func(c Config) bool { return c.PacketPing == 5*time.Second }},
		{"PacketPing at DeadMin/2", Config{PacketPing: 1500 * time.Millisecond, DeadMin: 3 * time.Second}, nil,
			func(c Config) bool { return c.PacketPing == 1500*time.Millisecond }},
		{"MaxAge", Config{Packet: PacketPolicy{MaxAge: time.Hour}}, []string{"Packet.MaxAge: 1h0m0s → 2s (range 10ms..2s)"},
			func(c Config) bool { return c.Packet.MaxAge == 2*time.Second }},
		{"MaxPayload", Config{Packet: PacketPolicy{MaxPayload: 100}}, []string{"Packet.MaxPayload: 100 → 512 (range 512..65507)"},
			func(c Config) bool { return c.Packet.MaxPayload == 512 }},
		{"Queue at its floor with the largest MaxPayload", Config{Packet: PacketPolicy{Queue: 64 << 10}},
			[]string{"Packet.Queue: 65536 → 65571 (constraint 8: Packet.Queue ≥ Packet.MaxPayload + 64)"},
			func(c Config) bool { return c.Packet.Queue == 65571 }},
		{"Queue above", Config{Packet: PacketPolicy{Queue: 1 << 30}}, []string{"Packet.Queue: 1073741824 → 67108864 (range 65536..67108864)"},
			func(c Config) bool { return c.Packet.Queue == 64<<20 }},
	} {
		e, adj := normalize(tc.in, nil)
		if !slices.Equal(adj, tc.want) || !tc.ok(e.cfg) {
			t.Errorf("%s: adjustments %q, config %v %+v; want %q", tc.name, adj, e.cfg.PacketPing, e.cfg.Packet, tc.want)
		}
		if e.timing.PacketPing != e.cfg.PacketPing || e.packet.PacketPing != e.cfg.PacketPing || e.packet.Queue != e.cfg.Packet.Queue ||
			e.packet.MaxAge != e.cfg.Packet.MaxAge || e.packet.MaxPayload != e.cfg.Packet.MaxPayload {
			t.Errorf("%s: derived values differ from the config: timing %v, template %+v", tc.name, e.timing.PacketPing, e.packet)
		}
	}

	// The flow bounds follow the Runtime's limits.
	e, _ = normalize(Config{MaxSessions: 10, MaxCarriersPerSession: 4, Sessionless: SessionlessLimits{Total: 7}, Handshake: HandshakeLimits{MaxConcurrent: 3, Timeout: 20 * time.Second}}, nil)
	if e.flow.MaxFlows != 50 || e.flow.TombstoneTTL != 22*time.Second {
		t.Fatalf("flow limits %+v, want MaxFlows 50 and a 22 s tombstone", e.flow)
	}
	if n := flowCap(Config{MaxSessions: 1000000, MaxCarriersPerSession: 16, Sessionless: SessionlessLimits{Total: 1}, Handshake: HandshakeLimits{MaxConcurrent: 1}}); n != udpflow.MaxFlowsCap {
		t.Fatalf("flowCap %d, want the cap %d", n, udpflow.MaxFlowsCap)
	}

	// Overrides reach every derived structure, unclamped and unrecorded.
	ov := &testhooks.Overrides{
		PacketPing: 10 * time.Millisecond, PacketActive: 3 * time.Second, PacketMaxAge: time.Millisecond,
		RelRTOInit: 30 * time.Millisecond, RelRTOMin: 20 * time.Millisecond, RelRTOMax: 90 * time.Millisecond, FinWaitMax: 7 * time.Millisecond,
		PacketQueue: 4096, PacketMaxPayload: 100, PackEvery: 4, DedupBits: 128, MTUProbeEvery: 2, MTUProbeFails: 5,
		FlowMaxFlows: 9, FlowPerSource: 2, FlowPerSourceJoin: 3, FlowInbox: 6, FlowTombstoneTTL: 40 * time.Millisecond,
		FirstSeq: 1<<62 - 10, FirstCseq: 0xFFFFFFF0, PingIdle: 2 * time.Second,
	}
	e, adj = normalize(Config{}, ov)
	if len(adj) != 0 {
		t.Fatalf("overrides recorded %q", adj)
	}
	wantTm := carrier.Timing{PacketPing: 10 * time.Millisecond, PacketActive: 3 * time.Second, RelRTOInit: 30 * time.Millisecond,
		RelRTOMin: 20 * time.Millisecond, RelRTOMax: 90 * time.Millisecond, MTUProbeEvery: 2, MTUProbeFails: 5}
	got := e.timing
	got.PingBusy, got.PingIdle, got.DeadMin, got.DeadMax, got.WriteStall, got.DialTimeout, got.HandshakeTimeout = 0, 0, 0, 0, 0, 0, 0
	got.ProbeInterval, got.SessionlessIdle, got.AbandonWait, got.Window, got.CapFloor, got.BatchBudget, got.Segment = 0, 0, 0, 0, 0, 0, 0
	if got != wantTm {
		t.Fatalf("timing overrides %+v, want %+v", got, wantTm)
	}
	wantPk = session.PacketParams{MaxPayload: 100, Queue: 4096, MaxAge: time.Millisecond, PacketPing: 10 * time.Millisecond,
		PackEvery: 4, FinWaitMax: 7 * time.Millisecond, DedupBits: 128, FirstSeq: 1<<62 - 10}
	if e.packet != wantPk {
		t.Fatalf("packet overrides %+v, want %+v", e.packet, wantPk)
	}
	wantFlow = udpflow.Limits{MaxFlows: 9, PerSource: 2, PerSourceJoin: 3, Inbox: 6, TombstoneTTL: 40 * time.Millisecond, Tombstones: 4096}
	if e.flow != wantFlow || e.presets.FirstCseq != 0xFFFFFFF0 {
		t.Fatalf("flow overrides %+v (FirstCseq %#x), want %+v", e.flow, e.presets.FirstCseq, wantFlow)
	}
	// PacketActive follows an overridden PingIdle unless it is set itself.
	if e2, _ := normalize(Config{}, &testhooks.Overrides{PingIdle: 2 * time.Second}); e2.timing.PacketActive != 2*time.Second {
		t.Fatalf("PacketActive %v, want the overridden PingIdle", e2.timing.PacketActive)
	}

	// The per-session packet Params.
	p := e.packetParams(e.passiveParams(ModeBond, 30000, time.Second), 600)
	if p.Kind != wire.KindDatagram || p.Packet.MaxPayload != 600 || p.Packet.Queue != 4096 || p.Role != session.RolePassive || p.Mode != session.ModeBond {
		t.Fatalf("passive packet params %+v", p)
	}
}

// TestConfigAdjustmentsBounded (W4-L2-2): every Listen call whose
// ListenConfig is clamped records "Listen[i]." adjustments, and Status
// copies the list on every call. Under Listen and Close churn the list
// stays bounded: the Config's records are all kept, then at most
// maxListenAdjust Listen records, the latest ones, in call order.
func TestConfigAdjustmentsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt, err := NewRuntime(Config{Window: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close()
		const cycles = 1000
		for range cycles {
			ln, err := rt.Listen(ListenConfig{AcceptTimeout: time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if err := ln.Close(); err != nil {
				t.Fatal(err)
			}
		}
		// The latest call records one more adjustment than the others.
		if _, err := rt.Listen(ListenConfig{AcceptBacklog: -5, AcceptTimeout: time.Millisecond}); err != nil {
			t.Fatal(err)
		}
		adj := rt.Status().ConfigAdjustments
		if len(adj) > 1+maxListenAdjust {
			t.Fatalf("%d adjustments after %d Listen calls, want at most %d", len(adj), cycles+1, 1+maxListenAdjust)
		}
		if len(adj) != 1+maxListenAdjust || !strings.HasPrefix(adj[0], "Window: 1 → ") {
			t.Fatalf("adjustments %q: want the Config record first, then %d Listen records", adj, maxListenAdjust)
		}
		last := "Listen[" + strconv.Itoa(cycles) + "]."
		if !strings.HasPrefix(adj[len(adj)-2], last+"AcceptBacklog: -5 → 1 ") ||
			!strings.HasPrefix(adj[len(adj)-1], last+"AcceptTimeout: 1ms → 100ms ") {
			t.Fatalf("latest records %q, want the last Listen's two", adj[len(adj)-2:])
		}
		// The kept Listen records are the latest ones, in call order.
		first := cycles - (maxListenAdjust - 2)
		for k, a := range adj[1 : len(adj)-2] {
			want := "Listen[" + strconv.Itoa(first+k) + "].AcceptTimeout: 1ms → 100ms "
			if !strings.HasPrefix(a, want) {
				t.Fatalf("record %d %q, want prefix %q", k+1, a, want)
			}
		}
	})
}
