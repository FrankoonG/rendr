package rendr

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// Dialer is the entry point for constructing a rendr Conn.
//
// Dialer is intentionally minimal: the path set is fixed at dial
// time. The engine will not discover paths on its own; the embedder
// feeds candidate PathSpecs. Use AddPath / RemovePath on the
// returned AdminConn to mutate the path set after dial.
type Dialer struct {
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
	if len(d.Paths) == 0 {
		return nil, errNoPaths
	}
	mode := d.Mode
	if !mode.Valid() {
		mode = ModePrime
	}

	flowID := engine.NewClientFlowID()
	e := engine.New(engine.SideClient, flowID, d.engineLimits())
	if d.ProbeInterval > 0 {
		e.SetProbeIntervalForTest(d.ProbeInterval)
	}

	// Dial the first path and run HELLO.
	first := d.Paths[0]
	pc, err := dialPath(ctx, first)
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
	for _, ps := range d.Paths[1:] {
		spc, err := dialPath(ctx, ps)
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
	if mode == ModePrime {
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
	if len(d.Paths) == 0 {
		return nil, errNoPaths
	}
	mode := d.Mode
	if !mode.Valid() {
		mode = ModePrime
	}

	flowID := engine.NewClientFlowID()
	e := engine.New(engine.SideClient, flowID, d.engineLimits())
	e.SetPacketMode()
	if d.ProbeInterval > 0 {
		e.SetProbeIntervalForTest(d.ProbeInterval)
	}

	first := d.Paths[0]
	pc, err := dialPath(ctx, first)
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

	for _, ps := range d.Paths[1:] {
		spc, err := dialPath(ctx, ps)
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

	if mode == ModePrime {
		e.StartPrime(nil, 0)
	}
	return bc, nil
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

func dialPath(ctx context.Context, spec PathSpec) (transport.PathConn, error) {
	tp, err := transport.Default.Lookup(spec.Transport)
	if err != nil {
		return nil, err
	}
	return tp.DialPath(ctx, spec)
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
