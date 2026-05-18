package rendr

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
)

// enginePacketConn is the concrete rendr.PacketConn returned by
// Dialer.DialPacket and PacketListener.AcceptPacket. It wraps an
// engine in packet-boundary mode and exposes net.PacketConn plus the
// rendr-specific Paths/SetMode/FlowID methods.
//
// The wire format is identical to stream-mode rendr; the only
// difference is that SendPacket emits one DATA frame per call (no
// chunking) and RecvPacket pops one frame's payload per call (no
// concatenation). The peer must also be in packet mode for boundary
// preservation to hold; this is negotiated in HELLO via
// proto.CapsPacketMode.
type enginePacketConn struct {
	e    *engine.Engine
	mode atomic.Uint32

	lAddr   net.Addr
	rAddr   net.Addr
	closing atomic.Bool
}

func newEnginePacketConn(e *engine.Engine, mode Mode, lAddr, rAddr net.Addr) *enginePacketConn {
	pc := &enginePacketConn{e: e, lAddr: lAddr, rAddr: rAddr}
	pc.mode.Store(uint32(mode))
	e.SetMode(uint32(mode))
	return pc
}

func (c *enginePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, err := c.e.RecvPacket()
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, pkt)
	return n, c.rAddr, nil
}

// WriteTo ignores addr - rendr has only one peer per flow_id. Returns
// ErrPacketTooLarge if len(p) > engine.MaxPayload.
func (c *enginePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := c.e.SendPacket(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *enginePacketConn) Close() error {
	if !c.closing.Swap(true) && !c.e.IsClosed() {
		_ = c.e.SendBye(proto.ByeNormal)
	}
	return c.e.Close()
}

func (c *enginePacketConn) LocalAddr() net.Addr { return c.lAddr }

func (c *enginePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *enginePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *enginePacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *enginePacketConn) Paths() []PathInfo { return c.e.Paths() }
func (c *enginePacketConn) FlowID() [16]byte  { return c.e.FlowID() }

func (c *enginePacketConn) SetMode(m Mode) error {
	if !m.Valid() {
		return ErrModeSwitchIllegal
	}
	cur := Mode(c.mode.Load())
	if cur == m {
		return nil
	}
	if cur == ModeRace && m == ModeBond {
		return ErrModeSwitchIllegal
	}
	if cur == ModeBond && m == ModeRace {
		return ErrModeSwitchIllegal
	}
	c.mode.Store(uint32(m))
	c.e.SetMode(uint32(m))
	return nil
}

// Admin-style methods on enginePacketConn mirror the AdminConn
// surface on stream-mode connections. Applications that need them
// type-assert to AdminPacketConn (or its individual interfaces).
func (c *enginePacketConn) Migrate(id uint32) error    { return c.e.Migrate(id) }
func (c *enginePacketConn) ActivePath() uint32         { return c.e.ActivePath() }
func (c *enginePacketConn) State() string              { return c.e.State().String() }
func (c *enginePacketConn) RecvQueueHWM() int          { return c.e.RecvQueueHighWaterMark() }
func (c *enginePacketConn) RecvDups() uint64           { return c.e.RecvDups() }
func (c *enginePacketConn) BondStuckSkips() uint64     { return c.e.BondStuckSkips() }
func (c *enginePacketConn) MigrationCount() uint64     { return c.e.MigrationCount() }

// OnMigrate registers a callback fired on every active-path change.
func (c *enginePacketConn) OnMigrate(fn func(uint32, uint32, string)) func() {
	return c.e.OnMigrate(fn)
}
func (c *enginePacketConn) Mode() Mode                 { return Mode(c.mode.Load()) }
func (c *enginePacketConn) RemovePath(id uint32) error { return c.e.RemovePath(id) }

// AddPath dials and attaches a fresh path matching spec. Same
// semantics as AdminConn.AddPath on stream mode.
func (c *enginePacketConn) AddPath(spec PathSpec) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := dialPath(ctx, spec)
	if err != nil {
		return 0, err
	}
	if err := engine.PerformClientBridgeTag(pc, c.e.FlowID()); err != nil {
		_ = pc.Close()
		return 0, err
	}
	id, err := c.e.AttachPath(pc, spec)
	if err != nil {
		_ = pc.Close()
		return 0, err
	}
	return id, nil
}

// Stats returns the same coherent snapshot as AdminConn.Stats does
// for stream-mode Conn.
func (c *enginePacketConn) Stats() ConnStats {
	return ConnStats{
		FlowID:         c.e.FlowID(),
		State:          c.e.State().String(),
		Mode:           Mode(c.mode.Load()),
		ActivePath:     c.e.ActivePath(),
		Paths:          c.e.Paths(),
		RecvQueueHWM:   c.e.RecvQueueHighWaterMark(),
		RecvDups:       c.e.RecvDups(),
		BondStuckSkips: c.e.BondStuckSkips(),
		MigrationCount: c.e.MigrationCount(),
	}
}

// AdminPacketConn is the AdminConn analogue for packet-mode. It
// extends PacketConn with the same migration/observability surface
// stream-mode AdminConn exposes.
type AdminPacketConn interface {
	PacketConn
	Migrate(pathID uint32) error
	ActivePath() uint32
	AddPath(spec PathSpec) (uint32, error)
	RemovePath(pathID uint32) error
	State() string
	RecvQueueHWM() int
	RecvDups() uint64
	BondStuckSkips() uint64
	MigrationCount() uint64
	OnMigrate(fn func(oldID, newID uint32, cause string)) (cancel func())
	Mode() Mode
	Stats() ConnStats
}

// PacketListener accepts inbound rendr PacketConns. The udpflow
// listener implements both Listener and PacketListener: HELLO with
// CapsPacketMode routes to AcceptPacket, otherwise to Accept. A
// listener can therefore serve mixed packet- and stream-mode peers
// simultaneously without separate ports.
type PacketListener interface {
	AcceptPacket(ctx context.Context) (PacketConn, error)
	Close() error
	Addr() net.Addr
	FlowIDs() [][16]byte
}
