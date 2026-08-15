package rendr

import (
	"context"
	"io"
	"net"
	"sync"
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
	peak        *peakTransferController
	status      *pathStatusTracker
	resolver    *pathFactoryResolver
	carriers    map[string]CarrierFamily
	graph       compiledTargetGraph
	recovery    *pathRecoverySupervisor
	localStatus func() LocalStatus

	lAddr     net.Addr
	rAddr     net.Addr
	closing   atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func newEnginePacketConn(e *engine.Engine, lAddr, rAddr net.Addr) *enginePacketConn {
	pc := &enginePacketConn{e: e, lAddr: lAddr, rAddr: rAddr}
	e.StartSelector(0)
	return pc
}

func (c *enginePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, err := c.e.RecvPacket()
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, pkt)
	if n != len(pkt) {
		return n, c.rAddr, io.ErrShortBuffer
	}
	return n, c.rAddr, nil
}

// WriteTo ignores addr - rendr has only one peer per flow_id. Returns
// ErrPacketTooLarge if p plus the session framing envelope exceeds the
// engine or carrier frame budget.
func (c *enginePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.writePacket(p)
}

func (c *enginePacketConn) writePacket(p []byte) (int, error) {
	published, err := c.e.SendPacketAcceptedResult(p)
	if err != nil {
		if published {
			return len(p), err
		}
		return 0, err
	}
	return len(p), nil
}

func (c *enginePacketConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.shutdown(true) })
	return c.closeErr
}

func (c *enginePacketConn) abortDial() {
	c.closeOnce.Do(func() { c.closeErr = c.shutdown(true) })
}

func (c *enginePacketConn) shutdown(graceful bool) error {
	c.closing.Store(true)
	c.e.BeginGracefulClose()
	if c.peak != nil {
		c.peak.stopLoop()
	}
	if c.recovery != nil {
		c.recovery.stop()
	}
	if graceful {
		return c.e.GracefulClose(proto.ByeNormal)
	}
	return c.e.Close()
}

func (c *enginePacketConn) LocalAddr() net.Addr { return c.lAddr }

// SetDeadline / SetReadDeadline / SetWriteDeadline route through to the engine.
func (c *enginePacketConn) SetDeadline(t time.Time) error {
	if err := c.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.SetReadDeadline(t)
}
func (c *enginePacketConn) SetReadDeadline(t time.Time) error  { return c.e.SetReadDeadline(t) }
func (c *enginePacketConn) SetWriteDeadline(t time.Time) error { return c.e.SetWriteDeadline(t) }

func (c *enginePacketConn) Paths() []PathInfo { return c.e.Paths() }
func (c *enginePacketConn) FlowID() [16]byte  { return c.e.FlowID() }
func (c *enginePacketConn) Status() Status {
	local := coreLocalStatus()
	if c.localStatus != nil {
		local = c.localStatus()
	}
	status := statusFromEngine(c.e, c.status, c.carriers, local)
	if c.peak != nil {
		status.Issues = c.peak.statusIssues()
	}
	return status
}

func (c *enginePacketConn) startPeakTransfer(plan compiledTarget, pathIDs []uint32) error {
	c.peak = newPeakTransferController(c.e, plan, pathIDs)
	if err := c.peak.start(); err != nil {
		c.peak.stopLoop()
		return err
	}
	return nil
}

// Optional control and observation methods mirror stream-mode connections.
// Applications assert only the narrow interface they need.
func (c *enginePacketConn) SelectTarget(selectorName, targetName string) error {
	selectorID, targetID, err := c.graph.resolveSelectorChild(selectorName, targetName)
	if err != nil && len(c.graph.manifest.Nodes) == 0 {
		selectorID, targetID, err = resolveSelectorChild(c.e.LocalGraphManifest(), selectorName, targetName)
	}
	if err != nil {
		return err
	}
	return c.e.SelectExplicitTarget(selectorID, targetID, "explicit")
}
func (c *enginePacketConn) ActivePath() uint32     { return c.e.ActivePath() }
func (c *enginePacketConn) State() string          { return c.e.State().String() }
func (c *enginePacketConn) RecvQueueHWM() int      { return c.e.RecvQueueHighWaterMark() }
func (c *enginePacketConn) RecvDups() uint64       { return c.e.RecvDups() }
func (c *enginePacketConn) BondStuckSkips() uint64 { return c.e.BondStuckSkips() }
func (c *enginePacketConn) MigrationCount() uint64 { return c.e.MigrationCount() }

// OnMigrate registers a callback fired on every committed migration.
func (c *enginePacketConn) OnMigrate(fn func(uint32, uint32, string)) func() {
	return c.e.OnMigrate(fn)
}
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

// Stats uses the same topology/replay/root coherence boundary as stream mode;
// monotonic transport counters are point observations.
func (c *enginePacketConn) Stats() ConnStats {
	return connStatsFromEngine(c.e)
}
