package carrier

import "sync/atomic"

// Gauge is the self-load gauge of one (Peer, factory) (design §8). It is fed
// by every dialer session carrier of that factory and read by the health
// layer when a probe PING is committed and when its PONG arrives. It is
// atomics only: no lock is shared across sessions. Carriers without a
// Gauge (passive, probe, sessionless, single-factory Peers) do no
// self-load accounting.
type Gauge struct {
	inflight   atomic.Int64  // Σ contributions: forward unproven bytes + reverse bound rxRate·srtt
	backlogged atomic.Int64  // carriers currently backlogged on either side
	epoch      atomic.Uint64 // 0 → 1 transitions of backlogged
}

// NewGauge returns an idle gauge.
func NewGauge() *Gauge {
	return &Gauge{}
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
		g.backlogged.Add(-1)
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
