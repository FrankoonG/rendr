package carrier

// Gauge is the self-load gauge of one (Peer, factory) (design §8). It is fed
// by every dialer session carrier of that factory and read by the health
// layer when a probe PING is committed and when its PONG arrives. It is
// atomics only: no lock is shared across sessions. Carriers without a
// Gauge (passive, probe, sessionless, single-factory Peers) do no
// self-load accounting.
type Gauge struct {
	_ struct{} // unexported state (inflight, backlogged count, epoch) is defined by the implementation
}

// NewGauge returns an idle gauge.
func NewGauge() *Gauge {
	panic("unimplemented: M1b")
}

// AddInflight adds delta to the aggregate in-flight estimate: forward bytes
// not yet proven by a PONG watermark plus the reverse bound rxRate × srtt of
// every contributing carrier (each carrier adds the change of its own
// contribution and removes all of it when it ends).
func (g *Gauge) AddInflight(delta int64) {
	panic("unimplemented: M1b")
}

// SetBacklog reports a contributing carrier entering (true) or leaving
// (false) the backlogged state on either side (local writer backlog or the
// peer's PING BUSY flag). Each carrier reports transitions only.
func (g *Gauge) SetBacklog(on bool) {
	panic("unimplemented: M1b")
}

// Loaded reports aggregate in-flight ≥ threshold while at least one carrier
// is backlogged, and an epoch that increases on every transition of the
// backlogged count from 0 to 1 (so a load episode shorter than one probe RTT
// is still detected).
func (g *Gauge) Loaded(threshold int64) (loaded bool, epoch uint64) {
	panic("unimplemented: M1b")
}
