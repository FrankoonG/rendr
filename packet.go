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
