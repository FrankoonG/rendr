package rendr

import (
	"context"
	"errors"
	"net"
	"sync"
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

	closing     atomic.Bool // local-Close in flight; gates BYE send
	closeOnce   sync.Once
	closeErr    error
	peak        *peakTransferController
	status      *pathStatusTracker
	resolver    *pathFactoryResolver
	carriers    map[string]CarrierFamily
	graph       compiledTargetGraph
	recovery    *pathRecoverySupervisor
	localStatus func() LocalStatus
}

func newEngineBackedConn(e *engine.Engine, c *engine.Conn) *engineBackedConn {
	bc := &engineBackedConn{e: e, conn: c}
	e.StartSelector(0)
	return bc
}

func (c *engineBackedConn) Read(p []byte) (int, error) {
	return c.conn.Read(p)
}
func (c *engineBackedConn) Write(p []byte) (int, error) {
	return c.conn.Write(p)
}

// CloseWrite half-closes the application stream. Callers may discover this
// optional extension with interface{ CloseWrite() error } while Conn remains a
// standard net.Conn.
func (c *engineBackedConn) CloseWrite() error { return c.conn.CloseWrite() }

// Close sends a CTRL_BYE on the active path so the peer surfaces a
// clean io.EOF rather than tripping its migration machinery, then
// tears the engine down. BYE failure is non-fatal: if the active
// path is already dead the peer will see ordinary transport silence
// up to its migration budget.
func (c *engineBackedConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.shutdown(true) })
	return c.closeErr
}

func (c *engineBackedConn) abortDial() {
	c.closeOnce.Do(func() { c.closeErr = c.shutdown(true) })
}

func (c *engineBackedConn) shutdown(graceful bool) error {
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

func (c *engineBackedConn) startPeakTransfer(plan compiledTarget) error {
	c.peak = newPeakTransferController(c.e, plan)
	if err := c.peak.start(); err != nil {
		c.peak.stopLoop()
		return err
	}
	return nil
}

// SelectTarget selects one immediate child of a selector in the frozen graph.
func (c *engineBackedConn) SelectTarget(selectorName, targetName string) error {
	selectorID, targetID, err := c.graph.resolveSelectorChild(selectorName, targetName)
	if err != nil && len(c.graph.manifest.Nodes) == 0 {
		selectorID, targetID, err = resolveSelectorChild(c.e.LocalGraphManifest(), selectorName, targetName)
	}
	if err != nil {
		return err
	}
	return c.e.SelectExplicitTarget(selectorID, targetID, "explicit")
}

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

// MigrationCount returns the cumulative committed-migration count.
func (c *engineBackedConn) MigrationCount() uint64 { return c.e.MigrationCount() }

// OnMigrationEvent registers a typed committed-migration callback.
func (c *engineBackedConn) OnMigrationEvent(fn func(MigrationEvent)) MigrationEventSubscription {
	if fn == nil {
		return c.e.OnMigrationEvent(nil)
	}
	return c.e.OnMigrationEvent(func(event engine.MigrationEvent) {
		fn(migrationEventFromEngine(event))
	})
}

// OnMigrate registers a callback fired on every committed migration.
func (c *engineBackedConn) OnMigrate(fn func(uint32, uint32, string)) func() {
	return c.e.OnMigrate(fn)
}

func migrationEventFromEngine(event engine.MigrationEvent) MigrationEvent {
	probeGenerations := make([]MigrationProbeGeneration, len(event.Evidence.ProbeGenerations))
	for index, generation := range event.Evidence.ProbeGenerations {
		probeGenerations[index] = MigrationProbeGeneration{
			PathID:             generation.PathID,
			PathOwner:          generation.PathOwner,
			PathGeneration:     generation.PathGeneration,
			RouteGeneration:    generation.RouteGeneration,
			EndpointGeneration: generation.EndpointGeneration,
			PeerMobilityEpoch:  generation.PeerMobilityEpoch,
			HealthRevision:     generation.HealthRevision,
		}
	}
	return MigrationEvent{
		OldPathID:   event.OldPathID,
		NewPathID:   event.NewPathID,
		Cause:       event.Cause,
		Ordinal:     event.Ordinal,
		CommittedAt: event.CommittedAt,
		Evidence: MigrationEvidence{
			Kind:                      MigrationEvidenceKind(event.Evidence.Kind),
			TransactionID:             event.Evidence.TransactionID,
			RefreshEvidenceGeneration: event.Evidence.RefreshEvidenceGeneration,
			SourceEndpointGeneration:  event.Evidence.SourceEndpointGeneration,
			ResultEndpointGeneration:  event.Evidence.ResultEndpointGeneration,
			TopologyEpoch:             event.Evidence.TopologyEpoch,
			HealthEpoch:               event.Evidence.HealthEpoch,
			Source:                    migrationPathBindingFromEngine(event.Evidence.Source),
			Result:                    migrationPathBindingFromEngine(event.Evidence.Result),
			Selector: MigrationSelectorBinding{
				SelectorID:        event.Evidence.Selector.SelectorID,
				TargetID:          event.Evidence.Selector.TargetID,
				Origin:            event.Evidence.Selector.Origin,
				CutoverGeneration: event.Evidence.Selector.CutoverGeneration,
				CapturedAt:        event.Evidence.Selector.CapturedAt,
				ValidUntil:        event.Evidence.Selector.ValidUntil,
			},
			Leaf: MigrationLeafBinding{
				RefreshReason:           event.Evidence.Leaf.RefreshReason,
				RefreshObservedAt:       event.Evidence.Leaf.RefreshObservedAt,
				RefreshSourceGeneration: event.Evidence.Leaf.RefreshSourceGeneration,
				RefreshSourceUsable:     event.Evidence.Leaf.RefreshSourceUsable,
				RefreshIncarnation:      event.Evidence.Leaf.RefreshIncarnation,
			},
			ProbeGenerations: probeGenerations,
		},
	}
}

func migrationPathBindingFromEngine(binding engine.MigrationPathBinding) MigrationPathBinding {
	return MigrationPathBinding{
		PathID:             binding.PathID,
		PathOwner:          binding.PathOwner,
		PathGeneration:     binding.PathGeneration,
		RouteGeneration:    binding.RouteGeneration,
		EndpointGeneration: binding.EndpointGeneration,
		PeerMobilityEpoch:  binding.PeerMobilityEpoch,
		HealthRevision:     binding.HealthRevision,
		LocalTargetID:      binding.LocalTargetID,
		PeerTargetID:       binding.PeerTargetID,
	}
}

// Stats binds topology, replay occupancy, and root-delivery evidence to one
// physical topology epoch. Monotonic transport counters remain point
// observations within that stable boundary.
func (c *engineBackedConn) Stats() ConnStats {
	return connStatsFromEngine(c.e)
}

func connStatsFromEngine(e *engine.Engine) ConnStats {
	if e == nil {
		return ConnStats{}
	}
	observation := e.ConnectionObservation()
	topology := observation.Topology
	return ConnStats{
		FlowID:         e.FlowID(),
		State:          topology.State.String(),
		ActivePath:     topology.ActivePath,
		EffectivePaths: append([]uint32(nil), topology.EffectivePaths...),
		Paths:          topology.Paths,
		RecvQueueHWM:   observation.RecvQueueHWM,
		RecvDups:       observation.RecvDups,
		BondStuckSkips: observation.BondStuckSkips,
		MigrationCount: topology.MigrationCount,
		CreatedAt:      e.CreatedAt(),
		PeerCaps:       e.PeerCaps(),
		PeerInstanceID: e.PeerInstanceID(),
		TXReplay:       replayStatsFromEngine(observation.Replay),
		RootDelivery:   rootDeliveryStatsFromSnapshot(observation.RootDelivery),
	}
}

func replayStatsFromEngine(stats engine.ReplayStats) ReplayStats {
	return ReplayStats{
		FrameLimit: stats.FrameLimit, ByteLimit: stats.ByteLimit,
		FramesInUse: stats.FramesInUse, BytesInUse: stats.BytesInUse,
		FramesHighWater: stats.FramesHighWater, BytesHighWater: stats.BytesHighWater,
		PublishedNext: stats.PublishedNext, AckNext: stats.AckNext,
		CreditWaiters: stats.CreditWaiters, BackpressureEvents: stats.BackpressureEvents,
		Generation: stats.Generation,
	}
}

func rootDeliveryStatsFromSnapshot(snapshot engine.TargetDeliverySnapshot) RootDeliveryStats {
	return RootDeliveryStats{
		TargetName: snapshot.TargetName, SelectorName: snapshot.SelectorName,
		SelectorGeneration: snapshot.SelectorGeneration,
		EvidenceEpoch:      snapshot.EvidenceEpoch, Attributable: snapshot.Attributable,
		PublishedBytes: snapshot.PublishedBytes, AckedBytes: snapshot.AckedBytes,
		DemandBytes: snapshot.DemandBytes,
	}
}

// RemovePath gracefully detaches path id from the engine.
func (c *engineBackedConn) RemovePath(id uint32) error {
	return c.e.RemovePath(id)
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

func (c *engineBackedConn) startPathRecovery(desired []PathSpec, retry retryPolicy) {
	c.recovery = newPathRecoverySupervisor(c.e, c.resolver, c.addPath, desired, c.status, retry)
}
