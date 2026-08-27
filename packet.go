package rendr

import (
	"context"
	"encoding/hex"
	"errors"
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

	lAddr    net.Addr
	rAddr    net.Addr
	closing  atomic.Bool
	readGate sync.RWMutex
	// readPacketBeforeReturn is a deterministic package-test hook installed
	// before activity and never mutated concurrently.
	readPacketBeforeReturn func()
	// readPacketAfterOpenCheck is a deterministic package-test hook installed
	// before activity. It runs while ReadFrom owns readGate after observing the
	// connection open, which exposes the read-wins Close linearization boundary.
	readPacketAfterOpenCheck func()
	closeOnce                sync.Once
	closeErr                 error
}

func newEnginePacketConn(e *engine.Engine, lAddr net.Addr) *enginePacketConn {
	pc := &enginePacketConn{e: e, lAddr: lAddr, rAddr: newPacketSessionAddr(e.FlowID())}
	e.StartSelector(0)
	return pc
}

// packetSessionAddr is the immutable application-level identity of the remote
// endpoint for one framed packet session. It is deliberately independent of
// every opaque path token and physical leaf address, and therefore remains
// stable across fallback and migration on both endpoints.
type packetSessionAddr struct {
	flowID [16]byte
}

func newPacketSessionAddr(flowID [16]byte) packetSessionAddr {
	return packetSessionAddr{flowID: flowID}
}

func (packetSessionAddr) Network() string { return "rendr-packet" }
func (addr packetSessionAddr) String() string {
	return "rendr-packet:" + hex.EncodeToString(addr.flowID[:])
}

func (c *enginePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closing.Load() {
		return 0, nil, net.ErrClosed
	}
	pkt, err := c.e.RecvPacket()
	if err != nil {
		return 0, nil, err
	}
	if hook := c.readPacketBeforeReturn; hook != nil {
		hook()
	}
	c.readGate.RLock()
	defer c.readGate.RUnlock()
	if c.closing.Load() {
		return 0, nil, net.ErrClosed
	}
	if hook := c.readPacketAfterOpenCheck; hook != nil {
		hook()
	}
	n := copy(p, pkt)
	if n != len(pkt) {
		return n, c.rAddr, io.ErrShortBuffer
	}
	return n, c.rAddr, nil
}

// WriteTo accepts nil as shorthand for the session peer. A non-nil address
// must name the exact logical peer; rendr never silently redirects a datagram.
// ErrPacketTooLarge is returned if p plus the session framing envelope exceeds
// the engine or carrier frame budget.
func (c *enginePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !nilFactoryResult(addr) {
		expectedNetwork, expectedAddress, expected, expectedOK := packetSessionAddrIdentity(c.rAddr)
		actualNetwork, actualAddress, actual, actualOK := packetSessionAddrIdentity(addr)
		if !expectedOK || !actualOK || expected.flowID != actual.flowID {
			return 0, &PacketDestinationError{
				ExpectedNetwork: expectedNetwork,
				ExpectedAddress: expectedAddress,
				ActualNetwork:   actualNetwork,
				ActualAddress:   actualAddress,
			}
		}
	}
	return c.writePacket(p)
}

func packetSessionAddrIdentity(addr net.Addr) (network, address string, identity packetSessionAddr, ok bool) {
	identity, ok = addr.(packetSessionAddr)
	if !ok {
		return "", "", packetSessionAddr{}, false
	}
	return identity.Network(), identity.String(), identity, true
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
	c.readGate.Lock()
	c.closing.Store(true)
	c.readGate.Unlock()
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

func (c *enginePacketConn) LocalAddr() net.Addr  { return c.lAddr }
func (c *enginePacketConn) RemoteAddr() net.Addr { return c.rAddr }

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

func (c *enginePacketConn) startPeakTransfer(plan compiledTarget) error {
	c.peak = newPeakTransferController(c.e, plan)
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

// OnMigrationEvent registers a typed committed-migration callback.
func (c *enginePacketConn) OnMigrationEvent(fn func(MigrationEvent)) MigrationEventSubscription {
	if fn == nil {
		return c.e.OnMigrationEvent(nil)
	}
	return c.e.OnMigrationEvent(func(event engine.MigrationEvent) {
		fn(migrationEventFromEngine(event))
	})
}

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
	lease, err := c.resolver.dialPathForAdoption(ctx, spec)
	if err != nil {
		return 0, err
	}
	pc := lease.Path()
	if err := ctx.Err(); err != nil {
		return 0, errors.Join(err, lease.Close())
	}
	if c.closing.Load() {
		return 0, errors.Join(net.ErrClosed, lease.Close())
	}
	admission, err := engine.PerformClientBridgeAdmissionContext(ctx, pc, c.e, pathSpecName(spec), spec)
	if admission.EngineOwnsPath {
		err = errors.Join(err, lease.ReleaseToEngine())
	} else if err == nil {
		err = errors.New("rendr: successful bridge admission did not transfer path ownership")
	}
	if err != nil {
		if !admission.EngineOwnsPath {
			err = errors.Join(err, lease.Close())
		}
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
