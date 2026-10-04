package carrier

import (
	"sync/atomic"
	"time"
)

// Gauge is the self-load gauge of one (Peer, factory) (design §8). It is fed
// by every dialer session carrier of that factory and read by the health
// layer when a probe PING is committed and when its PONG arrives. It is
// atomics only: no lock is shared across sessions. Carriers without a
// Gauge (passive, probe, sessionless, single-factory Peers) do no
// self-load accounting.
//
// It holds two kinds of state. The instantaneous load (inflight,
// backlogged, epoch) is each carrier's current contribution and returns to
// zero when the carriers end. The history (tx, rx, movedAt, calmAt) only
// moves forward: the DATA the carriers moved, when they last moved some and
// when the last backlog ended, which the health layer compares across a
// probe PING's flight (the volume rule, Health.volumeLoaded).
type Gauge struct {
	inflight   atomic.Int64  // Σ contributions: forward unproven bytes + reverse bound rxRate·srtt
	backlogged atomic.Int64  // carriers currently backlogged on either side
	epoch      atomic.Uint64 // 0 → 1 transitions of backlogged
	tx         atomic.Uint64 // DATA payload bytes written (counted when the write carrying them returned)
	rx         atomic.Uint64 // DATA payload bytes received (counted per verified DATA frame)
	movedAt    atomic.Int64  // when DATA last moved: nanoseconds after base; 0 = never
	calmAt     atomic.Int64  // when backlogged last fell to 0: nanoseconds after base; 0 = never
	base       time.Time
}

// NewGauge returns an idle gauge.
func NewGauge() *Gauge {
	return &Gauge{base: time.Now()}
}

// AddInflight adds delta to the aggregate in-flight estimate: forward bytes
// not yet proven by a PONG watermark plus the reverse bound rxRate × srtt of
// every contributing carrier (each carrier adds the change of its own
// contribution and removes all of it when it ends).
func (g *Gauge) AddInflight(delta int64) {
	g.inflight.Add(delta)
}

// SetBacklog reports a contributing carrier entering (true) or leaving
// (false) the backlogged state on either side (local writer backlog or the
// peer's PING BUSY flag). Each carrier reports transitions only.
func (g *Gauge) SetBacklog(on bool) {
	if !on {
		if g.backlogged.Add(-1) == 0 {
			g.calmAt.Store(g.stamp(time.Now()))
		}
		return
	}
	if g.backlogged.Add(1) == 1 {
		g.epoch.Add(1)
	}
}

// Loaded reports aggregate in-flight ≥ threshold while at least one carrier
// is backlogged, and an epoch that increases on every transition of the
// backlogged count from 0 to 1 (so a load episode shorter than one probe RTT
// is still detected).
func (g *Gauge) Loaded(threshold int64) (loaded bool, epoch uint64) {
	return g.inflight.Load() >= threshold && g.backlogged.Load() > 0, g.epoch.Load()
}

// AddTx counts n DATA payload bytes a contributing carrier wrote, in the
// write that returned at at: one call per batch write that carried DATA.
func (g *Gauge) AddTx(n int, at time.Time) {
	g.tx.Add(uint64(n))
	g.movedAt.Store(g.stamp(at))
}

// AddRx counts n DATA payload bytes a contributing carrier received in one
// verified DATA frame that arrived at at.
func (g *Gauge) AddRx(n int, at time.Time) {
	g.rx.Add(uint64(n))
	g.movedAt.Store(g.stamp(at))
}

// stamp converts at to the nanoseconds-after-base form of movedAt and
// calmAt (never 0). Carriers stamp concurrently, so a stamp can be
// overwritten by one taken a moment earlier: a reading may lag the newest
// event by that moment, never by more.
func (g *Gauge) stamp(at time.Time) int64 {
	return max(int64(at.Sub(g.base)), 1)
}

// gaugeState is one reading of a Gauge: its instantaneous load and its
// history (the health layer reads one at a probe PING's commit and one at
// its PONG's arrival).
type gaugeState struct {
	loaded     bool   // aggregate in-flight ≥ threshold while a carrier is backlogged
	backlogged bool   // a carrier is backlogged
	epoch      uint64 // 0 → 1 transitions of the backlogged count
	tx, rx     uint64 // DATA payload bytes written and received so far
	movedAt    time.Time
	calmAt     time.Time // the latest end of a backlog (zero: none)
}

// read returns the gauge's current state. The fields are read one by one,
// not as one snapshot; each is at most as old as the read.
func (g *Gauge) read(threshold int64) gaugeState {
	backlogged := g.backlogged.Load() > 0
	s := gaugeState{
		loaded:     backlogged && g.inflight.Load() >= threshold,
		backlogged: backlogged,
		epoch:      g.epoch.Load(),
		tx:         g.tx.Load(),
		rx:         g.rx.Load(),
	}
	if d := g.movedAt.Load(); d != 0 {
		s.movedAt = g.base.Add(time.Duration(d))
	}
	if d := g.calmAt.Load(); d != 0 {
		s.calmAt = g.base.Add(time.Duration(d))
	}
	return s
}
