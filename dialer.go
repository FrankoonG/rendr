package rendr

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
	"github.com/FrankoonG/rendr/transport/udpflow"
)

// Dialer is the entry point for constructing a rendr Conn.
//
// Dialer is intentionally minimal: the path set is fixed at dial
// time. The engine will not discover paths on its own; the embedder
// feeds candidate PathSpecs. Use AddPath / RemovePath on the
// returned AdminConn to mutate the path set after dial.
type Dialer struct {
	// Root is the v0.4 policy graph entry point. When set, it replaces
	// Mode+Paths for the initial dial. Selector/Race/Bond all compile
	// down to the current engine mode layer until the full nested runtime
	// policy executor lands.
	Root Target

	// Mode is the initial operational mode.
	Mode Mode

	// Paths are the candidate paths for this connection.
	Paths []PathSpec

	// Hysteresis (prime only): the new path must beat the current by
	// this fraction of the current score before a switch is allowed.
	// Default 0.25.
	Hysteresis float64

	// Dwell (prime only): minimum time the engine must stay on a path
	// after attaching to it. Default 5s.
	Dwell time.Duration

	// Cooldown (prime only): minimum gap between two successive
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

	// streamFactories / packetFactories are populated via
	// AddStreamPathFactory / AddPacketPathFactory. They override
	// transport.Default lookup for PathSpec.Transport names that
	// match a registered factory. See factory.go for the API.
	streamFactories map[string]StreamPathFactory
	packetFactories map[string]PacketPathFactory
}

// Dial establishes a rendr Conn using d's configuration. The engine
// performs the HELLO handshake on the first path; subsequent paths
// (attached during the same Dial call or later via the migration
// API) send BRIDGE_TAG carrying the same flow_id.
//
// M1 limits: prime mode only; the first path in d.Paths becomes the
// active path, the remainder are attached but kept idle until a
// migration trigger fires.
func (d *Dialer) Dial(ctx context.Context) (Conn, error) {
	mode, paths, peakTransfer, err := d.compileDialPlan()
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errNoPaths
	}

	flowID := engine.NewClientFlowID()
	e := engine.New(engine.SideClient, flowID, d.engineLimits())
	if d.ProbeInterval > 0 {
		e.SetProbeIntervalForTest(d.ProbeInterval)
	}

	// Dial the first path and run HELLO.
	first := paths[0]
	pc, err := d.dialPathWithFactories(ctx, first)
	if err != nil {
		_ = e.Close()
		return nil, err
	}
	if err := engine.PerformClientHello(pc, flowID, 0); err != nil {
		_ = pc.Close()
		_ = e.Close()
		return nil, err
	}
	if _, err := e.AttachPath(pc, first); err != nil {
		_ = pc.Close()
		_ = e.Close()
		return nil, err
	}

	// Attach any additional paths as bridge-tagged add-ons. They sit
	// idle until Migrate switches to them or the active path dies.
	for _, ps := range paths[1:] {
		spc, err := d.dialPathWithFactories(ctx, ps)
		if err != nil {
			// One bad extra path is not fatal for the Conn; warn
			// silently and continue.
			continue
		}
		if err := engine.PerformClientBridgeTag(spc, flowID); err != nil {
			_ = spc.Close()
			continue
		}
		if _, err := e.AttachPath(spc, ps); err != nil {
			_ = spc.Close()
			continue
		}
	}

	c := &engine.Conn{
		E:     e,
		LAddr: addrFromString("rendr-client"),
		RAddr: addrFromString(first.Address),
	}
	bc := newEngineBackedConn(e, c, mode)

	// Arm the prime scheduler now that all initial paths are
	// attached. CLAUDE.md hard rule #3 keeps active migration
	// triggers opt-in; here it is opt-in because the embedder
	// explicitly chose Mode == ModePrime.
	if mode == ModePrime && !peakTransfer {
		e.StartPrime(nil, 0)
	}
	return bc, nil
}

// DialPacket establishes a rendr PacketConn using d's configuration.
// Each application WriteTo becomes one wire frame; each ReadFrom
// returns the payload of one wire frame. The peer (server) is
// notified via proto.CapsPacketMode in the HELLO so its engine also
// runs the packet-boundary drainer.
//
// All Dialer fields (Mode, Paths, prime knobs, MigrationBudget) apply
// identically to packet-mode connections; the underlying engine and
// path machinery are the same.
func (d *Dialer) DialPacket(ctx context.Context) (PacketConn, error) {
	mode, paths, peakTransfer, err := d.compileDialPlan()
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errNoPaths
	}

	flowID := engine.NewClientFlowID()
	e := engine.New(engine.SideClient, flowID, d.engineLimits())
	e.SetPacketMode()
	if d.ProbeInterval > 0 {
		e.SetProbeIntervalForTest(d.ProbeInterval)
	}

	first := paths[0]
	pc, err := d.dialPathWithFactories(ctx, first)
	if err != nil {
		_ = e.Close()
		return nil, err
	}
	if err := engine.PerformClientHello(pc, flowID, proto.CapsPacketMode); err != nil {
		_ = pc.Close()
		_ = e.Close()
		return nil, err
	}
	if _, err := e.AttachPath(pc, first); err != nil {
		_ = pc.Close()
		_ = e.Close()
		return nil, err
	}

	for _, ps := range paths[1:] {
		spc, err := d.dialPathWithFactories(ctx, ps)
		if err != nil {
			continue
		}
		if err := engine.PerformClientBridgeTag(spc, flowID); err != nil {
			_ = spc.Close()
			continue
		}
		if _, err := e.AttachPath(spc, ps); err != nil {
			_ = spc.Close()
			continue
		}
	}

	lAddr := addrFromString("rendr-client")
	rAddr := addrFromString(first.Address)
	bc := newEnginePacketConn(e, mode, lAddr, rAddr)

	if mode == ModePrime && !peakTransfer {
		e.StartPrime(nil, 0)
	}
	return bc, nil
}

func (d *Dialer) compileDialPlan() (Mode, []PathSpec, bool, error) {
	if d.Root != nil {
		ct, err := compileTargetForDial(d.Root)
		if err != nil {
			return 0, nil, false, err
		}
		return ct.mode, ct.paths, ct.peakTransfer, nil
	}
	if len(d.Paths) == 0 {
		return 0, nil, false, errNoPaths
	}
	mode := d.Mode
	if !mode.Valid() {
		mode = ModePrime
	}
	ct, err := compileTargetForDial(legacyRootTarget(mode, d.Paths))
	if err != nil {
		return 0, nil, false, err
	}
	return ct.mode, ct.paths, ct.peakTransfer, nil
}

// engineLimits packs the Dialer-side knobs into engine.Limits. The
// engine clamps unset / out-of-range values back to project defaults
// (90 s migration budget, 2 zombie migrations, 30 s cooldown, etc.).
func (d *Dialer) engineLimits() engine.Limits {
	return engine.Limits{
		MigrationBudget:        d.MigrationBudget,
		PrimeHysteresis:        d.Hysteresis,
		PrimeDwell:             d.Dwell,
		PrimeCooldown:          d.Cooldown,
		ZombieMaxMigrations:    d.ZombieMaxMigrations,
		ZombieCooldown:         d.ZombieCooldown,
		BondStuckRTTMultiplier: d.BondStuckRTTMultiplier,
	}
}

// dialPath resolves spec to a transport.PathConn via the global
// transport.Default registry. Used by post-dial paths (AddPath) that
// don't have access to the originating Dialer's factory maps.
func dialPath(ctx context.Context, spec PathSpec) (transport.PathConn, error) {
	tp, err := transport.Default.Lookup(spec.Transport)
	if err != nil {
		return nil, err
	}
	return tp.DialPath(ctx, spec)
}

// dialPathWithFactories is the Dialer-side variant. Consults the
// Dialer's per-instance factory maps first, then falls back to
// dialPath. Stream factories wrap the returned net.Conn via tcp.Wrap;
// packet factories wrap the returned net.PacketConn via
// udpflow.WrapFromSpec (which resolves peer addr + flow_id from
// spec). Both wrappers reuse the same on-wire framing as the built-
// in tcp / udpflow adapters.
func (d *Dialer) dialPathWithFactories(ctx context.Context, spec PathSpec) (transport.PathConn, error) {
	if f, ok := d.streamFactories[spec.Transport]; ok {
		conn, err := f(ctx, spec.Address)
		if err != nil {
			return nil, err
		}
		return tcp.Wrap(conn), nil
	}
	if f, ok := d.packetFactories[spec.Transport]; ok {
		pc, err := f(ctx, spec.Address)
		if err != nil {
			return nil, err
		}
		return udpflow.WrapFromSpec(pc, spec)
	}
	return dialPath(ctx, spec)
}

var errNoPaths = errors.New("rendr: Dialer has no Paths")

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
