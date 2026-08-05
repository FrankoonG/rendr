package rendr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// sessionDialer freezes one Runtime and SessionConfig into the internal
// construction state for a single session. Callers enter through Runtime;
// this type deliberately is not part of the public API.
type sessionDialer struct {
	// Root is the target graph entry point compiled into the recursive
	// selector/race/bond execution manifest.
	Root Target

	// Hysteresis (selector only): the new path must beat the current by
	// this fraction of the current score before a switch is allowed.
	// Default 0.25.
	Hysteresis float64

	// Dwell (selector only): minimum time the engine must stay on a path
	// after attaching to it. Default 5s.
	Dwell time.Duration

	// Cooldown (selector only): minimum gap between two successive
	// migrations regardless of quality. Default 30s.
	Cooldown time.Duration

	// MigrationBudget caps how long the engine will hold a Conn open
	// after all paths have died. Default and maximum 90s, per
	// CLAUDE.md hard rule #4. Lower values are allowed; higher ones
	// will be clamped to 90s.
	MigrationBudget time.Duration

	// ProbeInterval is how often each attached path issues a
	// CtrlPathProbe to measure RTT. 0 = default 1s.
	ProbeInterval time.Duration

	// ZombieMaxMigrations: number of consecutive completed migrations
	// with zero application payload between them before the engine
	// declares the peer a zombie and tears down (CLAUDE.md hard rule
	// #5). Default 2; lower values trip earlier.
	ZombieMaxMigrations int

	// ZombieCooldown: how long the engine waits between zombie-
	// counter decrements. After ZombieCooldown elapsed since the
	// last migration, the counter resets to ZombieMaxMigrations.
	// Default 30s.
	ZombieCooldown time.Duration

	// BondStuckRTTMultiplier (bond only): a path whose latest probe
	// RTT exceeds best_path_rtt * Multiplier is skipped on bond
	// round-robin. Default 3.0. Set lower to be more aggressive
	// about bypassing slow paths.
	BondStuckRTTMultiplier float64

	// PreserveL3Identity advertises proto.CapsL3Identity in HELLO for
	// TUN/l3ingress flows that must carry original src/dst IP:port
	// metadata to peer-side egress hooks. It does not create a TUN
	// device by itself; ingress setup remains owned by the embedder.
	PreserveL3Identity bool

	// InstanceID identifies this runtime during HELLO/BRIDGE attach.
	// Zero means generate a fresh ephemeral runtime id.
	InstanceID InstanceID

	// Runtime is the immutable v1 policy configuration inherited from Runtime.
	Runtime RuntimeConfig

	// Primary names the path or group that should be used for the
	// initial HELLO. Empty means the first expanded leaf path.
	Primary string

	// PrimaryPolicy controls whether primary failure can fall back to
	// another path. Zero value prefers primary and permits fallback.
	PrimaryPolicy primaryPolicy

	// Retry controls background retry of optional failed paths. Zero
	// value enables bounded retry with conservative defaults.
	Retry retryPolicy

	// Factory maps are immutable snapshots of the owning Runtime registry.
	streamFactories map[string]streamPathFactory
	packetFactories map[string]packetPathFactory
	factoryCarriers map[string]CarrierFamily
}

// Dial establishes a rendr Conn using d's configuration. The engine
// performs the HELLO handshake on the first path; subsequent paths
// (attached during the same Dial call or later via the migration
// API) send BRIDGE_TAG carrying the same flow_id.
//
// The first usable compiled path establishes the session; the remainder are
// attached and dispatched by the recursive target executor.
func (d *sessionDialer) Dial(ctx context.Context) (Conn, error) {
	plan, err := d.compileDialPlan()
	if err != nil {
		return nil, err
	}
	mode, paths := plan.mode, plan.paths
	if len(paths) == 0 {
		return nil, errNoCompiledPath
	}
	resolver := d.snapshotFactoryResolver()
	tracker := newPathStatusTracker(paths, plan.primaryName)
	for index, spec := range paths {
		tracker.setMobility(index, planLeafMobility(spec, resolver))
	}

	flowID := engine.NewClientFlowID()
	instanceID := d.instanceID()
	e := engine.New(engine.SideClient, flowID, d.engineLimits())
	if err := e.ConfigureLocalGraph(plan.graphRevision, plan.graph.manifest); err != nil {
		_ = e.Close()
		return nil, err
	}
	e.SetLocalInstanceID(instanceID)
	if d.ProbeInterval > 0 {
		e.SetProbeIntervalForTest(d.ProbeInterval)
	}

	first, firstIndex, ack, firstID, err := d.dialInitialPath(ctx, e, instanceID, paths, plan, tracker, resolver, false)
	if err != nil {
		_ = e.Close()
		return nil, err
	}
	e.SetPeerKind(engine.PeerRendr)
	e.SetPeerCaps(ack.Caps)
	e.SetPeerInstanceID(ack.InstanceID)
	tracker.set(firstIndex, PathAttached, nil)
	pathIDs := []uint32{firstID}

	// Attach any additional paths as bridge-tagged add-ons. They sit
	// idle until Migrate switches to them or the active path dies.
	for i, ps := range paths {
		if i == firstIndex {
			continue
		}
		id, err := d.attachExtraPath(ctx, e, ps, i, tracker, resolver)
		if err != nil {
			continue
		}
		pathIDs = append(pathIDs, id)
	}

	c := &engine.Conn{
		E:     e,
		LAddr: addrFromString("rendr-client"),
		RAddr: addrFromString(first.Address),
	}
	bc := newEngineBackedConn(e, c, mode)
	bc.status = tracker
	bc.resolver = resolver
	bc.carriers = resolver.carrier
	bc.graph = plan.graph
	bc.startPathRecovery(paths, d.Retry)

	// Arm the selector scheduler now that all initial paths are
	// attached. CLAUDE.md hard rule #3 keeps active migration
	// triggers opt-in; here it is opt-in because the embedder
	// explicitly chose a Selector root.
	if plan.peakTransfer {
		bc.startPeakTransfer(plan, pathIDs)
	} else if mode == ModeSelector {
		e.StartSelector(nil, 0)
	}
	return bc, nil
}

// DialPacket establishes a rendr PacketConn using d's configuration.
// Each application WriteTo becomes one wire frame; each ReadFrom
// returns the payload of one wire frame. The peer (server) is
// notified via proto.CapsPacketMode in the HELLO so its engine also
// runs the packet-boundary drainer.
//
// The Root graph, selector knobs, and MigrationBudget apply identically to
// packet-mode connections; the underlying engine and path machinery are the
// same.
func (d *sessionDialer) DialPacket(ctx context.Context) (PacketConn, error) {
	plan, err := d.compileDialPlan()
	if err != nil {
		return nil, err
	}
	mode, paths := plan.mode, plan.paths
	if len(paths) == 0 {
		return nil, errNoCompiledPath
	}
	resolver := d.snapshotFactoryResolver()
	tracker := newPathStatusTracker(paths, plan.primaryName)
	for index, spec := range paths {
		tracker.setMobility(index, planLeafMobility(spec, resolver))
	}

	flowID := engine.NewClientFlowID()
	instanceID := d.instanceID()
	e := engine.New(engine.SideClient, flowID, d.engineLimits())
	if err := e.ConfigureLocalGraph(plan.graphRevision, plan.graph.manifest); err != nil {
		_ = e.Close()
		return nil, err
	}
	e.SetLocalInstanceID(instanceID)
	e.SetPacketMode()
	if d.ProbeInterval > 0 {
		e.SetProbeIntervalForTest(d.ProbeInterval)
	}

	first, firstIndex, ack, firstID, err := d.dialInitialPath(ctx, e, instanceID, paths, plan, tracker, resolver, true)
	if err != nil {
		_ = e.Close()
		return nil, err
	}
	e.SetPeerKind(engine.PeerRendr)
	e.SetPeerCaps(ack.Caps)
	e.SetPeerInstanceID(ack.InstanceID)
	tracker.set(firstIndex, PathAttached, nil)
	pathIDs := []uint32{firstID}

	for i, ps := range paths {
		if i == firstIndex {
			continue
		}
		id, err := d.attachExtraPath(ctx, e, ps, i, tracker, resolver)
		if err != nil {
			continue
		}
		pathIDs = append(pathIDs, id)
	}

	lAddr := addrFromString("rendr-client")
	rAddr := addrFromString(first.Address)
	bc := newEnginePacketConn(e, mode, lAddr, rAddr)
	bc.status = tracker
	bc.resolver = resolver
	bc.carriers = resolver.carrier
	bc.graph = plan.graph
	bc.startPathRecovery(paths, d.Retry)

	if plan.peakTransfer {
		bc.startPeakTransfer(plan, pathIDs)
	} else if mode == ModeSelector {
		e.StartSelector(nil, 0)
	}
	return bc, nil
}

func (d *sessionDialer) instanceID() InstanceID {
	if d.InstanceID != (InstanceID{}) {
		return d.InstanceID
	}
	return engine.NewInstanceID()
}

func (d *sessionDialer) compileDialPlan() (compiledTarget, error) {
	if d.Root == nil {
		return compiledTarget{}, errRootRequired
	}
	runtimeConfig, err := normalizeRuntimeConfig(d.Runtime)
	if err != nil {
		return compiledTarget{}, err
	}
	graph, err := compileTargetGraph(d.Root)
	if err != nil {
		return compiledTarget{}, fmt.Errorf("rendr: invalid SessionConfig: %w", err)
	}
	ct, err := graph.compileDialPlan()
	if err != nil {
		return compiledTarget{}, fmt.Errorf("rendr: invalid SessionConfig: %w", err)
	}
	ct.runtimeConfig = runtimeConfig
	ct, err = d.applyPrimary(ct, d.Root, d.Primary)
	if err != nil {
		return compiledTarget{}, fmt.Errorf("rendr: invalid SessionConfig: %w", err)
	}
	return ct, nil
}

func (d *sessionDialer) applyPrimary(ct compiledTarget, root Target, primary string) (compiledTarget, error) {
	if len(ct.paths) == 0 {
		return ct, nil
	}
	if primary == "" {
		ct.primaryName = pathSpecName(ct.paths[0])
		return ct, nil
	}
	leaf, ok := targetPrimaryLeafName(root, primary)
	if !ok {
		leaf = primary
	}
	idx := -1
	for i, ps := range ct.paths {
		if pathSpecName(ps) == leaf {
			idx = i
			break
		}
	}
	if idx < 0 {
		return compiledTarget{}, fmt.Errorf("rendr: primary target %q not found", primary)
	}
	ct.primaryName = leaf
	if idx == 0 {
		return ct, nil
	}
	ps := ct.paths[idx]
	copy(ct.paths[1:idx+1], ct.paths[0:idx])
	ct.paths[0] = ps
	if len(ct.pathPeak) == len(ct.paths) {
		peak := ct.pathPeak[idx]
		copy(ct.pathPeak[1:idx+1], ct.pathPeak[0:idx])
		ct.pathPeak[0] = peak
	}
	return ct, nil
}

func (d *sessionDialer) effectivePrimaryPolicy() primaryPolicy {
	if d.PrimaryPolicy == primaryRequire {
		return primaryRequire
	}
	return primaryPrefer
}

func (d *sessionDialer) dialInitialPath(
	ctx context.Context,
	e *engine.Engine,
	instanceID InstanceID,
	paths []PathSpec,
	plan compiledTarget,
	tracker *pathStatusTracker,
	resolver *pathFactoryResolver,
	packetMode bool,
) (PathSpec, int, proto.HelloAckPayload, uint32, error) {
	var lastErr error
	primaryPolicy := d.effectivePrimaryPolicy()
	for i, ps := range paths {
		tracker.set(i, PathDialing, nil)
		pc, err := resolver.dialPath(ctx, ps)
		if err != nil {
			tracker.set(i, PathUnavailable, err)
			lastErr = err
			if pathSpecName(ps) == plan.primaryName && primaryPolicy == primaryRequire {
				return PathSpec{}, -1, proto.HelloAckPayload{}, 0, fmt.Errorf("rendr: primary path %q unavailable: %w", plan.primaryName, err)
			}
			continue
		}
		tracker.set(i, PathHandshaking, nil)
		admission, err := engine.PerformClientHelloAdmissionContext(ctx, pc, e, instanceID, d.helloCaps(packetMode), pathSpecName(ps), ps)
		if err != nil {
			_ = pc.Close()
			state := pathStateForHandshakeError(err)
			tracker.set(i, state, err)
			lastErr = err
			if pathSpecName(ps) == plan.primaryName && primaryPolicy == primaryRequire {
				return PathSpec{}, -1, proto.HelloAckPayload{}, 0, fmt.Errorf("rendr: primary path %q handshake failed: %w", plan.primaryName, err)
			}
			continue
		}
		ack := admission.Ack
		if peerPacketMode := ack.Caps&proto.CapsPacketMode != 0; peerPacketMode != packetMode {
			err = fmt.Errorf("rendr: peer session kind mismatch: packet=%t", peerPacketMode)
			_ = e.Close()
			tracker.set(i, PathNative, err)
			lastErr = err
			if pathSpecName(ps) == plan.primaryName && primaryPolicy == primaryRequire {
				return PathSpec{}, -1, proto.HelloAckPayload{}, 0, err
			}
			continue
		}
		return ps, i, ack, admission.PathID, nil
	}
	if lastErr != nil {
		return PathSpec{}, -1, proto.HelloAckPayload{}, 0, fmt.Errorf("rendr: no usable path: %w", lastErr)
	}
	return PathSpec{}, -1, proto.HelloAckPayload{}, 0, errNoCompiledPath
}

func (d *sessionDialer) attachExtraPath(ctx context.Context, e *engine.Engine, ps PathSpec, index int, tracker *pathStatusTracker, resolver *pathFactoryResolver) (uint32, error) {
	tracker.set(index, PathDialing, nil)
	spc, err := resolver.dialPath(ctx, ps)
	if err != nil {
		tracker.set(index, PathUnavailable, err)
		return 0, err
	}
	tracker.set(index, PathHandshaking, nil)
	admission, err := engine.PerformClientBridgeAdmissionContext(ctx, spc, e, pathSpecName(ps), ps)
	if err != nil {
		_ = spc.Close()
		tracker.set(index, pathStateForHandshakeError(err), err)
		return 0, err
	}
	tracker.set(index, PathAttached, nil)
	return admission.PathID, nil
}

func pathStateForHandshakeError(err error) PathState {
	if err == nil {
		return PathAttached
	}
	return PathNative
}

func (d *sessionDialer) helloCaps(packetMode bool) uint32 {
	var caps uint32
	if packetMode {
		caps |= proto.CapsPacketMode
	}
	if d.PreserveL3Identity {
		caps |= proto.CapsL3Identity
	}
	return caps
}

// engineLimits packs the session knobs into engine.Limits. The
// engine clamps unset / out-of-range values back to project defaults
// (90 s migration budget, 2 zombie migrations, 30 s cooldown, etc.).
func (d *sessionDialer) engineLimits() engine.Limits {
	runtimeConfig, err := normalizeRuntimeConfig(d.Runtime)
	if err != nil {
		runtimeConfig = DefaultRuntimeConfig()
	}
	limits := engine.Limits{
		MigrationBudget:        runtimeConfig.Recovery.MigrationBudget,
		SelectorHysteresis:     runtimeConfig.Selector.LatencyBandRatio,
		SelectorLatencyFloor:   runtimeConfig.Selector.LatencyBandFloor,
		SelectorDwell:          runtimeConfig.Selector.QualityDwell,
		SelectorCooldown:       runtimeConfig.Selector.QualityCooldown,
		ZombieMaxMigrations:    d.ZombieMaxMigrations,
		ZombieCooldown:         d.ZombieCooldown,
		BondStuckRTTMultiplier: d.BondStuckRTTMultiplier,
	}
	// Transitional package-test knobs remain effective while the old direct
	// constructor coverage is migrated to Runtime fixtures.
	if d.MigrationBudget != 0 {
		limits.MigrationBudget = d.MigrationBudget
	}
	if d.Hysteresis != 0 {
		limits.SelectorHysteresis = d.Hysteresis
	}
	if d.Dwell != 0 {
		limits.SelectorDwell = d.Dwell
	}
	if d.Cooldown != 0 {
		limits.SelectorCooldown = d.Cooldown
	}
	return limits
}

// dialPath resolves spec to a transport.PathConn via the global
// transport.Default registry. Used by post-dial paths (AddPath) that
// don't have access to the originating Runtime's factory snapshot.
func dialPath(ctx context.Context, spec PathSpec) (transport.PathConn, error) {
	tp, err := transport.Default.Lookup(spec.Transport)
	if err != nil {
		return nil, err
	}
	return tp.DialPath(ctx, spec)
}

var (
	errRootRequired   = errors.New("rendr: invalid SessionConfig: Root target is required")
	errNoCompiledPath = errors.New("rendr: invalid SessionConfig: Root target contains no path leaves")
)

// stringAddr is a trivial net.Addr for the application-facing
// LocalAddr/RemoteAddr; M1 does not synthesise OS sockets so the
// addresses are descriptive strings only.
type stringAddr string

func (s stringAddr) Network() string { return "rendr" }
func (s stringAddr) String() string  { return string(s) }

func addrFromString(s string) stringAddr { return stringAddr(s) }

// Listener accepts inbound rendr Conns. The set of acceptable
// transports is determined by registering transport adapters on the
// Listener (see transport.Registry).
type Listener interface {
	Accept(ctx context.Context) (Conn, error)
	Close() error
	// Addr returns the listener's local network address, useful for
	// tests that bind ":0" and need to discover the chosen port.
	Addr() net.Addr
	// FlowIDs returns the live flow_id set for diagnostics.
	FlowIDs() [][16]byte
}
