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
// Runtime.DialPacket and SessionListener.AcceptPacket. It wraps an
// engine in packet-boundary mode and exposes net.PacketConn plus the
// rendr-specific Paths/FlowID/Status methods.
//
// The wire format is identical to stream-mode rendr; the only
// difference is that SendPacket emits one DATA frame per call (no
// chunking) and RecvPacket pops one frame's payload per call (no
// concatenation). The peer must also be in packet mode for boundary
// preservation to hold; this is negotiated in HELLO via
// proto.CapsPacketMode.
type enginePacketConn struct {
	e           *engine.Engine
	mode        atomic.Uint32
	peak        *peakTransferController
	status      *pathStatusTracker
	resolver    *pathFactoryResolver
	carriers    map[string]CarrierFamily
	graph       compiledTargetGraph
	recovery    *pathRecoverySupervisor
	localStatus func() LocalStatus

	lAddr   net.Addr
	rAddr   net.Addr
	closing atomic.Bool
}

func newEnginePacketConn(e *engine.Engine, mode Mode, lAddr, rAddr net.Addr) *enginePacketConn {
	pc := &enginePacketConn{e: e, lAddr: lAddr, rAddr: rAddr}
	pc.mode.Store(uint32(mode))
	if kind, ok := mode.executionKind(); ok {
		_ = e.ConfigureExecution(kind)
	}
	e.StartSelector(nil, 0)
	return pc
}

func (c *enginePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, err := c.e.RecvPacket()
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, pkt)
	if n > 0 && c.peak != nil {
		c.peak.observeRead(n)
	}
	return n, c.rAddr, nil
}

// WriteTo ignores addr - rendr has only one peer per flow_id. Returns
// ErrPacketTooLarge if len(p) > engine.MaxPayload.
func (c *enginePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := c.e.SendPacket(p); err != nil {
		return 0, err
	}
	if c.peak != nil {
		c.peak.observeWrite(len(p))
	}
	return len(p), nil
}

func (c *enginePacketConn) Close() error {
	if c.peak != nil {
		c.peak.stopLoop()
	}
	c.closing.Store(true)
	if c.recovery != nil {
		c.recovery.stop()
	}
	return c.e.GracefulClose(proto.ByeNormal)
}

func (c *enginePacketConn) LocalAddr() net.Addr { return c.lAddr }

// SetDeadline / SetReadDeadline route through to the engine. Write
// deadline is currently a no-op; see engineBackedConn.SetWriteDeadline.
func (c *enginePacketConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}
func (c *enginePacketConn) SetReadDeadline(t time.Time) error  { return c.e.SetReadDeadline(t) }
func (c *enginePacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *enginePacketConn) Paths() []PathInfo { return c.e.Paths() }
func (c *enginePacketConn) FlowID() [16]byte  { return c.e.FlowID() }
func (c *enginePacketConn) Status() Status {
	local := coreLocalStatus()
	if c.localStatus != nil {
		local = c.localStatus()
	}
	return statusFromEngine(c.e, Mode(c.mode.Load()), c.status, c.carriers, local)
}

func (c *enginePacketConn) startPeakTransfer(plan compiledTarget, pathIDs []uint32) {
	c.peak = newPeakTransferController(c.e, func(m Mode) {
		c.mode.Store(uint32(m))
	}, plan, pathIDs)
	c.peak.start()
}

// Optional control and observation methods mirror stream-mode connections.
// Applications assert only the narrow interface they need.
func (c *enginePacketConn) Migrate(id uint32) error { return c.e.Migrate(id) }
func (c *enginePacketConn) ActivePath() uint32      { return c.e.ActivePath() }
func (c *enginePacketConn) State() string           { return c.e.State().String() }
func (c *enginePacketConn) RecvQueueHWM() int       { return c.e.RecvQueueHighWaterMark() }
func (c *enginePacketConn) RecvDups() uint64        { return c.e.RecvDups() }
func (c *enginePacketConn) BondStuckSkips() uint64  { return c.e.BondStuckSkips() }
func (c *enginePacketConn) MigrationCount() uint64  { return c.e.MigrationCount() }

// OnMigrate registers a callback fired on every active-path change.
func (c *enginePacketConn) OnMigrate(fn func(uint32, uint32, string)) func() {
	return c.e.OnMigrate(fn)
}
func (c *enginePacketConn) Mode() Mode                 { return Mode(c.mode.Load()) }
func (c *enginePacketConn) RemovePath(id uint32) error { return c.e.RemovePath(id) }

// AddPath dials through the session-bound factory resolver and attaches a
// fresh path matching spec.
func (c *enginePacketConn) AddPath(spec PathSpec) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolved, err := c.graph.resolvePathSpec(spec, c.e.Paths())
	if err != nil {
		return 0, err
	}
	id, err := c.addPath(ctx, resolved)
	if err == nil && c.recovery != nil {
		c.recovery.pathAdded(resolved, id)
	}
	return id, err
}

func (c *enginePacketConn) addPath(ctx context.Context, spec PathSpec) (uint32, error) {
	if c.closing.Load() {
		return 0, net.ErrClosed
	}
	spec, err := c.graph.resolvePathSpec(spec, c.e.Paths())
	if err != nil {
		return 0, err
	}
	pc, err := c.resolver.dialPath(ctx, spec)
	if err != nil {
		return 0, err
	}
	c.status.setMobilityForSpec(spec, planPathConnMobility(c.resolver.carrierFamily(spec.Transport), pc))
	if err := ctx.Err(); err != nil {
		_ = pc.Close()
		return 0, err
	}
	if c.closing.Load() {
		_ = pc.Close()
		return 0, net.ErrClosed
	}
	admission, err := engine.PerformClientBridgeAdmissionContext(ctx, pc, c.e, pathSpecName(spec), spec)
	if err != nil {
		_ = pc.Close()
		return 0, err
	}
	return admission.PathID, nil
}

func (c *enginePacketConn) startPathRecovery(desired []PathSpec, retry retryPolicy) {
	c.recovery = newPathRecoverySupervisor(c.e, c.resolver, c.addPath, desired, c.status, retry)
}

// Stats returns the same coherent snapshot as stream-mode Conn.
func (c *enginePacketConn) Stats() ConnStats {
	topology := c.e.TopologySnapshot()
	return ConnStats{
		FlowID:         c.e.FlowID(),
		State:          topology.State.String(),
		Mode:           Mode(c.mode.Load()),
		ActivePath:     topology.ActivePath,
		Paths:          topology.Paths,
		RecvQueueHWM:   c.e.RecvQueueHighWaterMark(),
		RecvDups:       c.e.RecvDups(),
		BondStuckSkips: c.e.BondStuckSkips(),
		MigrationCount: topology.MigrationCount,
		CreatedAt:      c.e.CreatedAt(),
		PeerCaps:       c.e.PeerCaps(),
		PeerInstanceID: c.e.PeerInstanceID(),
	}
}
