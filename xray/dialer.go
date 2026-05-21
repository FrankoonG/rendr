package xray

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/FrankoonG/rendr"
)

// Dialer wraps a Config and dials a rendr.Conn (which is a net.Conn)
// per call. It is the integration anchor for xray's
// transport.internet.Dialer contract: an embedder that imports
// xray-core wires this into the appropriate adapter. Standalone
// embedders can use it directly without any xray-core dependency.
type Dialer struct {
	cfg *Config

	// QUICTLS lets the embedder inject a real TLS config for QUIC
	// paths. When nil, the QUIC adapter falls back to a self-signed
	// dev cert (development only).
	QUICTLS *tls.Config
}

// NewDialer constructs a Dialer from cfg. The Config is validated;
// invalid configs return an error early so the embedder doesn't
// fail mid-dial.
func NewDialer(cfg *Config) (*Dialer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Dialer{cfg: cfg}, nil
}

// DialContext establishes a rendr.Conn following the Config's paths
// and mode. The returned value implements net.Conn; callers that
// also want migration / FlowID introspection can type-assert to
// rendr.Conn or rendr.AdminConn.
//
// dest is reserved for xray adapter use (xray supplies a
// net.Destination at this point). For now it is ignored - the
// destination is implicit in each PathSpec's Address.
func (d *Dialer) DialContext(ctx context.Context, dest net.Addr) (net.Conn, error) {
	conn, err := d.rendrDialer().Dial(ctx)
	if err != nil {
		return nil, err
	}
	if d.cfg.OnConn != nil {
		d.cfg.OnConn(conn)
	}
	return conn, nil
}

// rendrDialer packs the xray-side Config into a rendr.Dialer. Shared
// by DialContext and DialPacketContext.
func (d *Dialer) rendrDialer() *rendr.Dialer {
	mode := rendr.Mode(d.cfg.Mode)
	if mode == 0 {
		mode = rendr.ModePrime
	}
	return &rendr.Dialer{
		Mode:                   mode,
		Paths:                  toPathSpecs(d.cfg.Paths),
		Hysteresis:             d.cfg.Hysteresis,
		Dwell:                  d.cfg.Dwell,
		Cooldown:               d.cfg.Cooldown,
		MigrationBudget:        d.cfg.MigrationBudget,
		ProbeInterval:          d.cfg.ProbeInterval,
		ZombieMaxMigrations:    d.cfg.ZombieMaxMigrations,
		ZombieCooldown:         d.cfg.ZombieCooldown,
		BondStuckRTTMultiplier: d.cfg.BondStuckRTTMultiplier,
	}
}

// DialPacketContext mirrors DialContext but produces a net.PacketConn
// in packet-boundary mode. Each application WriteTo becomes exactly
// one rendr frame; each ReadFrom returns one frame's payload. Use
// this for xray protocols whose wire format is datagram-oriented
// (e.g. Hysteria UDP, WireGuard relay, Shadowsocks UDP-over-TCP).
//
// The peer must accept via a rendr packet-mode listener (see
// xray.ListenUDPFlow / rendr.ListenUDPFlowPacket). Stream-mode
// listeners reject this dial with a HELLO-caps mismatch.
func (d *Dialer) DialPacketContext(ctx context.Context, dest net.Addr) (net.PacketConn, error) {
	return d.rendrDialer().DialPacket(ctx)
}

// toPathSpecs converts the xray-side Config.PathSpec into the
// transport-package PathSpec the rendr Dialer consumes. The two
// structs intentionally have the same layout; they live in
// different packages so the xray surface can evolve without
// dragging the core API along.
func toPathSpecs(in []PathSpec) []rendr.PathSpec {
	out := make([]rendr.PathSpec, len(in))
	for i, p := range in {
		out[i] = rendr.PathSpec{
			Transport: p.Transport,
			Address:   p.Address,
			Local:     p.Local,
			Opts:      p.Opts,
			Weight:    p.Weight,
		}
	}
	return out
}
