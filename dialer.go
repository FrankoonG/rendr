package rendr

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/virtualif"
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
	streamFactories       map[string]streamPathFactory
	packetFactories       map[string]packetPathFactory
	framedFactories       map[string]transport.PathFactory
	factoryCarriers       map[string]CarrierFamily
	factoryCallbackBudget *factoryCallbackBudget
	mobilityLedger        *engine.LeafMobilityPeerLedger
	localStatus           func() LocalStatus
}

// Dial establishes a rendr Conn using d's configuration. The engine
// performs the HELLO handshake on the first usable path; subsequent paths
// attached by background recovery or the migration API send BRIDGE_TAG
// carrying the same flow_id.
//
// The first usable compiled path establishes the session; the remainder are
// attached and dispatched by the recursive target executor.
func (d *sessionDialer) Dial(ctx context.Context) (Conn, error) {
	plan, err := d.compileDialPlan()
	if err != nil {
		return nil, err
	}
	paths := plan.paths
	if len(paths) == 0 {
		return nil, errNoCompiledPath
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cleanupAuthority, err := reserveCanceledDialCleanup()
	if err != nil {
		return nil, err
	}
	defer func() { cleanupAuthority.release() }()
	resolver := d.snapshotFactoryResolver()
	mobilityCapabilities, err := resolver.mobilityCapabilities(paths, leafmobility.SessionStream)
	if err != nil {
		return nil, err
	}
	tracker := newPathStatusTracker(paths, plan.primaryName)

	instanceID := d.instanceID()
	e, first, firstIndex, ack, _, err := d.dialInitialPath(
		ctx, instanceID, paths, plan, tracker, resolver, &cleanupAuthority,
		mobilityCapabilities, false,
	)
	if err != nil {
		return nil, err
	}
	failureCleanup := newAdmittedDialFailureCleanup(e, cleanupAuthority)
	defer failureCleanup.finish()
	e.SetPeerKind(engine.PeerRendr)
	e.SetPeerCaps(ack.Caps)
	if err := e.SetPeerInstanceID(ack.InstanceID); err != nil {
		return nil, err
	}
	tracker.set(firstIndex, PathAttached, nil)
	if err := ctx.Err(); err != nil {
		failureCleanup.setCleanup(func() { _ = e.GracefulClose(proto.ByeNormal) })
		return nil, err
	}
	c := &engine.Conn{
		E:     e,
		LAddr: addrFromString("rendr-client"),
		RAddr: addrFromString(first.Address),
	}
	bc := newEngineBackedConn(e, c)
	bc.localStatus = d.localStatus
	bc.status = tracker
	bc.resolver = resolver
	bc.carriers = resolver.carrier
	bc.graph = plan.graph
	failureCleanup.setCleanup(bc.abortDial)
	// Every leaf that did not establish the session is optional startup work.
	// Recovery owns its context, retries, resolver snapshot, and Close
	// cancellation, so a slow optional factory cannot delay Dial or inherit the
	// caller's context after the usable session has already been established.
	bc.startPathRecovery(paths, d.Retry)

	// Arm peak-transfer policy from the graph. Optional leaves become eligible
	// as background recovery attaches them.
	if plan.peakTransfer {
		if err := bc.startPeakTransfer(plan); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	failureCleanup.disarm()
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
	paths := plan.paths
	if len(paths) == 0 {
		return nil, errNoCompiledPath
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cleanupAuthority, err := reserveCanceledDialCleanup()
	if err != nil {
		return nil, err
	}
	defer func() { cleanupAuthority.release() }()
	resolver := d.snapshotFactoryResolver()
	mobilityCapabilities, err := resolver.mobilityCapabilities(paths, leafmobility.SessionPacket)
	if err != nil {
		return nil, err
	}
	tracker := newPathStatusTracker(paths, plan.primaryName)

	instanceID := d.instanceID()
	e, _, firstIndex, ack, _, err := d.dialInitialPath(
		ctx, instanceID, paths, plan, tracker, resolver, &cleanupAuthority,
		mobilityCapabilities, true,
	)
	if err != nil {
		return nil, err
	}
	failureCleanup := newAdmittedDialFailureCleanup(e, cleanupAuthority)
	defer failureCleanup.finish()
	e.SetPeerKind(engine.PeerRendr)
	e.SetPeerCaps(ack.Caps)
	if err := e.SetPeerInstanceID(ack.InstanceID); err != nil {
		return nil, err
	}
	tracker.set(firstIndex, PathAttached, nil)
	if err := ctx.Err(); err != nil {
		failureCleanup.setCleanup(func() { _ = e.GracefulClose(proto.ByeNormal) })
		return nil, err
	}
	lAddr := addrFromString("rendr-client")
	bc := newEnginePacketConn(e, lAddr)
	bc.localStatus = d.localStatus
	bc.status = tracker
	bc.resolver = resolver
	bc.carriers = resolver.carrier
	bc.graph = plan.graph
	failureCleanup.setCleanup(bc.abortDial)
	// Optional packet leaves follow the same session-owned recovery lifecycle as
	// stream leaves and never consume the successful DialPacket caller context.
	bc.startPathRecovery(paths, d.Retry)

	if plan.peakTransfer {
		if err := bc.startPeakTransfer(plan); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	failureCleanup.disarm()
	return bc, nil
}

type admittedDialFailureCleanup struct {
	e         *engine.Engine
	authority *canceledDialCleanupReservation
	cleanup   func()
	armed     bool
}

func newAdmittedDialFailureCleanup(
	e *engine.Engine,
	authority *canceledDialCleanupReservation,
) *admittedDialFailureCleanup {
	return &admittedDialFailureCleanup{
		e: e, authority: authority, armed: true,
		cleanup: func() { _ = e.Close() },
	}
}

func (c *admittedDialFailureCleanup) setCleanup(cleanup func()) {
	if c != nil && cleanup != nil {
		c.cleanup = cleanup
	}
}

func (c *admittedDialFailureCleanup) disarm() {
	if c != nil {
		c.armed = false
	}
}

func (c *admittedDialFailureCleanup) finish() {
	if c == nil || !c.armed {
		return
	}
	c.armed = false
	cleanupCanceledDial(c.e, c.authority, c.cleanup)
}

const (
	canceledDialCleanupWorkerLimit = 64
	// Every in-flight Dial reserves one authority before consulting a factory.
	// This matches the process bridge baseline while keeping hostile cleanup
	// execution fixed at a much smaller concurrency limit.
	canceledDialCleanupAuthorityLimit = engine.DefaultBridgeTableCapacity
	canceledDialCleanupQueueCapacity  = canceledDialCleanupAuthorityLimit -
		canceledDialCleanupWorkerLimit
)

type canceledDialCleanupReservationState uint32

const (
	canceledDialCleanupReserved canceledDialCleanupReservationState = iota
	canceledDialCleanupSubmitted
	canceledDialCleanupReleased
	canceledDialCleanupCompleted
)

type canceledDialCleanupExecutor struct {
	workerLimit int
	permits     chan struct{}

	mu        sync.Mutex
	workers   int
	queue     []*canceledDialCleanupJob
	queueHead int
	queueLen  int
}

type canceledDialCleanupReservation struct {
	executor *canceledDialCleanupExecutor
	state    atomic.Uint32
}

type canceledDialCleanupJob struct {
	engine      *engine.Engine
	cleanup     func()
	reservation *canceledDialCleanupReservation
}

var processCanceledDialCleanupExecutor = newCanceledDialCleanupExecutor(
	canceledDialCleanupWorkerLimit,
	canceledDialCleanupQueueCapacity,
)

func newCanceledDialCleanupExecutor(workerLimit, queueCapacity int) *canceledDialCleanupExecutor {
	if workerLimit <= 0 || queueCapacity < 0 {
		panic("rendr: invalid canceled Dial cleanup executor limits")
	}
	authorityLimit := workerLimit + queueCapacity
	return &canceledDialCleanupExecutor{
		workerLimit: workerLimit,
		permits:     make(chan struct{}, authorityLimit),
		// A completed worker releases its authority before it dequeues the next
		// job. During that handoff a new Dial can legitimately reserve the freed
		// permit while every old queue cell is still occupied. Size storage to the
		// full authority limit; permits, not queue cells, remain the admission
		// bound and workerLimit remains the execution bound.
		queue: make([]*canceledDialCleanupJob, authorityLimit),
	}
}

func reserveCanceledDialCleanup() (*canceledDialCleanupReservation, error) {
	return processCanceledDialCleanupExecutor.reserve()
}

func (e *canceledDialCleanupExecutor) reserve() (*canceledDialCleanupReservation, error) {
	select {
	case e.permits <- struct{}{}:
		return &canceledDialCleanupReservation{executor: e}, nil
	default:
		return nil, ErrDialCleanupCapacity
	}
}

func (r *canceledDialCleanupReservation) release() {
	if r == nil || !r.state.CompareAndSwap(
		uint32(canceledDialCleanupReserved),
		uint32(canceledDialCleanupReleased),
	) {
		return
	}
	<-r.executor.permits
}

func (r *canceledDialCleanupReservation) submit(e *engine.Engine, cleanup func()) {
	if r == nil || !r.state.CompareAndSwap(
		uint32(canceledDialCleanupReserved),
		uint32(canceledDialCleanupSubmitted),
	) {
		panic("rendr: canceled Dial cleanup authority submitted without a reservation")
	}
	r.executor.submit(&canceledDialCleanupJob{
		engine: e, cleanup: cleanup, reservation: r,
	})
}

func (r *canceledDialCleanupReservation) complete() {
	if !r.state.CompareAndSwap(
		uint32(canceledDialCleanupSubmitted),
		uint32(canceledDialCleanupCompleted),
	) {
		panic("rendr: canceled Dial cleanup authority completed without ownership")
	}
	<-r.executor.permits
}

func (e *canceledDialCleanupExecutor) submit(job *canceledDialCleanupJob) {
	e.mu.Lock()
	if e.workers < e.workerLimit {
		e.workers++
		e.mu.Unlock()
		go e.runWorker(job)
		return
	}
	if e.queueLen >= len(e.queue) {
		e.mu.Unlock()
		panic("rendr: canceled Dial cleanup queue exceeded reserved capacity")
	}
	index := (e.queueHead + e.queueLen) % len(e.queue)
	e.queue[index] = job
	e.queueLen++
	e.mu.Unlock()
}

func (e *canceledDialCleanupExecutor) runWorker(job *canceledDialCleanupJob) {
	normalExit := false
	defer func() {
		_ = recover()
		if normalExit {
			return
		}
		// runtime.Goexit and an escaped internal panic both run this defer.
		// Replace this exact worker slot only when queued authority remains.
		if next := e.takeNextWorkerJob(); next != nil {
			go e.runWorker(next)
		}
	}()
	for job != nil {
		job.run()
		job = e.takeNextWorkerJob()
	}
	normalExit = true
}

func (e *canceledDialCleanupExecutor) takeNextWorkerJob() *canceledDialCleanupJob {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.queueLen == 0 {
		e.workers--
		return nil
	}
	job := e.queue[e.queueHead]
	e.queue[e.queueHead] = nil
	e.queueHead = (e.queueHead + 1) % len(e.queue)
	e.queueLen--
	return job
}

func (j *canceledDialCleanupJob) run() {
	returned := false
	defer func() {
		_ = recover()
		if !returned {
			// A panic or runtime.Goexit in the higher-level cleanup must not
			// abandon the already admitted engine. Close is idempotent and is
			// the final authority when graceful teardown exited abnormally.
			_ = j.engine.Close()
		}
		<-j.engine.Closed()
		j.reservation.complete()
	}()
	j.cleanup()
	returned = true
	<-j.engine.Closed()
}

// cleanupCanceledDial publishes the terminal boundary synchronously, then
// transfers the pre-reserved authority to the process-bounded cleanup
// executor. The caller never waits for the terminal ACK window; the authority
// is not reusable until the engine's full quiescence is proven.
func cleanupCanceledDial(
	e *engine.Engine,
	authority *canceledDialCleanupReservation,
	cleanup func(),
) {
	if e == nil {
		authority.release()
		return
	}
	e.BeginGracefulClose()
	authority.submit(e, cleanup)
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
	instanceID InstanceID,
	paths []PathSpec,
	plan compiledTarget,
	tracker *pathStatusTracker,
	resolver *pathFactoryResolver,
	cleanupAuthority **canceledDialCleanupReservation,
	mobilityCapabilities []leafmobility.Capability,
	packetMode bool,
) (*engine.Engine, PathSpec, int, proto.HelloAckPayload, uint32, error) {
	var lastErr error
	primaryPolicy := d.effectivePrimaryPolicy()
	for i, ps := range paths {
		tracker.set(i, PathDialing, nil)
		lease, err := resolver.dialPathForAdoption(ctx, ps)
		if err != nil {
			tracker.set(i, PathUnavailable, err)
			lastErr = err
			if pathSpecName(ps) == plan.primaryName && primaryPolicy == primaryRequire {
				return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0, fmt.Errorf("rendr: primary path %q unavailable: %w", plan.primaryName, err)
			}
			continue
		}
		pc := lease.Path()
		e := engine.New(engine.SideClient, engine.NewClientFlowID(), d.engineLimits())
		e.SetLeafMobilityPeerLedger(d.mobilityLedger)
		if err := e.ConfigureLocalMobilityCapabilities(mobilityCapabilities...); err != nil {
			err = errors.Join(err, lease.Close(), e.Close())
			return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0, err
		}
		if err := e.ConfigureLocalGraph(plan.graphRevision, plan.graph.manifest); err != nil {
			err = errors.Join(err, lease.Close(), e.Close())
			return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0, err
		}
		e.SetLocalInstanceID(instanceID)
		if packetMode {
			e.SetPacketMode()
		}
		tracker.set(i, PathHandshaking, nil)
		admission, err := engine.PerformClientHelloAdmissionContext(
			ctx, pc, e, instanceID, d.helloCaps(packetMode), pathSpecName(ps), ps,
			func(ack proto.HelloAckPayload) error { return d.validatePeerSessionCaps(ack.Caps) },
		)
		if admission.EngineOwnsPath {
			err = errors.Join(err, lease.ReleaseToEngine())
		} else if err == nil {
			err = errors.New("rendr: successful initial path admission did not transfer path ownership")
		}
		if err != nil {
			if d.PreserveL3Identity && errors.Is(err, engine.ErrPathAdmissionRejected) {
				err = errors.Join(d.validatePeerSessionCaps(0), err)
			}
			if !admission.EngineOwnsPath {
				err = errors.Join(err, lease.Close())
			}
			if admission.EngineOwnsPath {
				if ctxErr := ctx.Err(); ctxErr != nil {
					err = errors.Join(err, ctxErr)
				}
				tracker.set(i, pathStateForHandshakeError(err), err)
				cleanupCanceledDial(e, *cleanupAuthority, func() { _ = e.Close() })
				if ctx.Err() != nil {
					return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0,
						fmt.Errorf("rendr: initial path %q admission canceled: %w", pathSpecName(ps), err)
				}
				// COMMIT crossed the wire, so the listener may already have
				// published this session even though its terminal ACTIVATED proof
				// was lost. Starting a new proposal on another path would turn one
				// Dial into two server application sessions.
				if errors.Is(err, engine.ErrPathAdmissionOutcomeUnknown) {
					return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0,
						fmt.Errorf("rendr: initial path %q admission outcome is unknown: %w", pathSpecName(ps), err)
				}
				if pathSpecName(ps) == plan.primaryName && primaryPolicy == primaryRequire {
					return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0,
						fmt.Errorf("rendr: primary path %q handshake failed: %w", plan.primaryName, err)
				}
				lastErr = err
				if i+1 < len(paths) {
					nextAuthority, reserveErr := reserveCanceledDialCleanup()
					if reserveErr != nil {
						return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0,
							fmt.Errorf("rendr: reserve cleanup authority after path %q failed: %w",
								pathSpecName(ps), errors.Join(err, reserveErr))
					}
					*cleanupAuthority = nextAuthority
				}
				continue
			}
			err = errors.Join(err, e.Close())
			state := pathStateForHandshakeError(err)
			tracker.set(i, state, err)
			lastErr = err
			if errors.Is(err, engine.ErrPathAdmissionOutcomeUnknown) {
				return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0,
					fmt.Errorf("rendr: initial path %q admission outcome is unknown: %w", pathSpecName(ps), err)
			}
			if pathSpecName(ps) == plan.primaryName && primaryPolicy == primaryRequire {
				return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0, fmt.Errorf("rendr: primary path %q handshake failed: %w", plan.primaryName, err)
			}
			continue
		}
		return e, ps, i, admission.Ack, admission.PathID, nil
	}
	if lastErr != nil {
		return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0, fmt.Errorf("rendr: no usable path: %w", lastErr)
	}
	return nil, PathSpec{}, -1, proto.HelloAckPayload{}, 0, errNoCompiledPath
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

func (d *sessionDialer) validatePeerSessionCaps(peerCaps uint32) error {
	if !d.PreserveL3Identity || peerCaps&proto.CapsL3Identity != 0 {
		return nil
	}
	return &virtualif.Error{
		Op:     "l3 identity capability",
		Reason: virtualif.ReasonPeerL3IdentityUnsupported,
	}
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
		ProbeInterval:          d.ProbeInterval,
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
