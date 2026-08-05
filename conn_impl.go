package rendr

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
)

// engineBackedConn is the concrete rendr.Conn returned by Dial and
// Accept. It embeds the net.Conn surface provided by the engine and
// exposes the rendr-specific Paths/FlowID/Status methods.
type engineBackedConn struct {
	e    *engine.Engine
	conn *engine.Conn

	mode     atomic.Uint32 // Mode
	closing  atomic.Bool   // local-Close in flight; gates BYE send
	peak     *peakTransferController
	status   *pathStatusTracker
	resolver *pathFactoryResolver
	carriers map[string]CarrierFamily
	graph    compiledTargetGraph
	recovery *pathRecoverySupervisor
}

func newEngineBackedConn(e *engine.Engine, c *engine.Conn, mode Mode) *engineBackedConn {
	bc := &engineBackedConn{e: e, conn: c}
	bc.mode.Store(uint32(mode))
	if kind, ok := mode.executionKind(); ok {
		_ = e.ConfigureExecution(kind)
	}
	e.StartSelector(nil, 0)
	return bc
}

func (c *engineBackedConn) Read(p []byte) (int, error) {
	n, err := c.conn.Read(p)
	if n > 0 && c.peak != nil {
		c.peak.observeRead(n)
	}
	return n, err
}
func (c *engineBackedConn) Write(p []byte) (int, error) {
	n, err := c.conn.Write(p)
	if n > 0 && c.peak != nil {
		c.peak.observeWrite(n)
	}
	return n, err
}

// Close sends a CTRL_BYE on the active path so the peer surfaces a
// clean io.EOF rather than tripping its migration machinery, then
// tears the engine down. BYE failure is non-fatal: if the active
// path is already dead the peer will see ordinary transport silence
// up to its migration budget.
func (c *engineBackedConn) Close() error {
	if c.peak != nil {
		c.peak.stopLoop()
	}
	c.closing.Store(true)
	if c.recovery != nil {
		c.recovery.stop()
	}
	return c.e.GracefulClose(proto.ByeNormal)
}
func (c *engineBackedConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *engineBackedConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *engineBackedConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *engineBackedConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *engineBackedConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *engineBackedConn) Paths() []PathInfo {
	return c.e.Paths()
}

func (c *engineBackedConn) FlowID() [16]byte { return c.e.FlowID() }

func (c *engineBackedConn) Status() Status {
	return statusFromEngine(c.e, Mode(c.mode.Load()), c.status, c.carriers)
}

func (c *engineBackedConn) startPeakTransfer(plan compiledTarget, pathIDs []uint32) {
	c.peak = newPeakTransferController(c.e, func(m Mode) {
		c.mode.Store(uint32(m))
	}, plan, pathIDs)
	c.peak.start()
}

// Migrate switches the active path to id. Embedders request it through the
// narrow MigrationController interface.
func (c *engineBackedConn) Migrate(id uint32) error { return c.e.Migrate(id) }

// ActivePath returns the currently-active path id.
func (c *engineBackedConn) ActivePath() uint32 { return c.e.ActivePath() }

// State returns the bridge lifecycle stage as a short string.
func (c *engineBackedConn) State() string { return c.e.State().String() }

// RecvQueueHWM returns the reorder-buffer high-water mark.
func (c *engineBackedConn) RecvQueueHWM() int { return c.e.RecvQueueHighWaterMark() }

// RecvDups returns the cumulative count of duplicate frames reaped.
func (c *engineBackedConn) RecvDups() uint64 { return c.e.RecvDups() }

// BondStuckSkips returns the cumulative bond stuck-skip count.
func (c *engineBackedConn) BondStuckSkips() uint64 { return c.e.BondStuckSkips() }

// MigrationCount returns the cumulative active-path-change count.
func (c *engineBackedConn) MigrationCount() uint64 { return c.e.MigrationCount() }

// OnMigrate registers a callback fired on every active-path change.
func (c *engineBackedConn) OnMigrate(fn func(uint32, uint32, string)) func() {
	return c.e.OnMigrate(fn)
}

// Mode returns the current operational mode.
func (c *engineBackedConn) Mode() Mode { return Mode(c.mode.Load()) }

// Stats returns a coherent snapshot of the observable state.
// Paths is filled from engine.Paths() which is taken under a read
// lock, so the snapshot is consistent across the path set.
func (c *engineBackedConn) Stats() ConnStats {
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

// RemovePath gracefully detaches path id from the engine.
func (c *engineBackedConn) RemovePath(id uint32) error {
	return c.e.RemovePath(id)
}

// MigratePathLocalAddr asks path id to rebuild itself at newLocal.
func (c *engineBackedConn) MigratePathLocalAddr(id uint32, newLocal string) error {
	return c.e.MigratePathLocalAddr(id, newLocal)
}

// AddPath dials a path matching spec through the session-bound factory
// resolver and attaches it to this engine via BRIDGE_TAG. The new path joins
// the existing flow on the server side without breaking the application's
// Conn.
func (c *engineBackedConn) AddPath(spec PathSpec) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolved, err := c.graph.resolvePathSpec(spec, c.e.Paths())
	if err != nil {
		return 0, err
	}
	id, err := c.addPath(ctx, resolved)
	if err == nil && c.recovery != nil {
		// Re-enable the logical leaf even if the newly admitted physical path
		// dies before AddPath returns and is already absent from Engine.Paths.
		c.recovery.pathAdded(resolved, id)
	}
	return id, err
}

func (c *engineBackedConn) addPath(ctx context.Context, spec PathSpec) (uint32, error) {
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

func (c *engineBackedConn) startPathRecovery(desired []PathSpec, retry retryPolicy) {
	c.recovery = newPathRecoverySupervisor(c.e, c.resolver, c.addPath, desired, c.status, retry)
}
