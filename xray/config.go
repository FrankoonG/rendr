package xray

import "time"

// Mode mirrors rendr.Mode but is duplicated here so xray-side
// configuration can be marshalled without importing the parent
// package directly. Keep the integer values in sync.
type Mode uint8

const (
	ModeUnset Mode = 0
	ModePrime Mode = 1
	ModeBond  Mode = 2
	ModeRace  Mode = 3
)

// PathSpec describes one candidate path. For xray integration each
// PathSpec corresponds to a sub-transport already known to xray
// (tcp, quic, mkcp, ws, grpc, h2 ...). At build time the embedder
// supplies a TransportFactory that maps PathSpec.Transport ->
// transport.Transport implementation; rendr falls back to its own
// registry (tcp + quic) when no factory is registered.
type PathSpec struct {
	// Transport names the underlying xray transport ("tcp", "quic",
	// "ws", "grpc", "mkcp", "h2"). Default rendr registry only
	// supports "tcp" and "quic"; "ws"/"grpc"/"h2"/"mkcp" require the
	// embedder to register an adapter.
	Transport string

	// Address is the remote endpoint in transport-specific form
	// (host:port for tcp/quic; a URL for ws/grpc).
	Address string

	// Local optionally pins the source side endpoint.
	Local string

	// Opts is the transport-specific configuration blob. For TLS-
	// bearing transports (quic, ws over TLS), this carries server
	// name / ALPN / cert hints. rendr treats it as opaque.
	Opts map[string]string

	// Weight is an advisory hint to bond / race schedulers about
	// share of frames or duplication priority. prime ignores it.
	Weight uint16
}

// Config is the full xray-side description of one rendr Conn. xray
// callers populate this from their proto stream settings; non-xray
// embedders construct it directly.
//
// A Config is *transport-of-transports*: it doesn't carry its own
// wire format. Wire framing comes from each PathSpec's Transport.
// rendr layers SEQ / migration / dedup on top.
type Config struct {
	Mode  Mode
	Paths []PathSpec

	// Prime knobs. Zero values clamp to project defaults
	// (Hysteresis=0.25, Dwell=5s, Cooldown=30s).
	Hysteresis float64
	Dwell      time.Duration
	Cooldown   time.Duration

	// MigrationBudget. 0 = use the project default 90s. Values
	// above 90s are clamped down by the engine.
	MigrationBudget time.Duration

	// ProbeInterval: per-path RTT probe cadence. 0 = engine default 1s.
	ProbeInterval time.Duration

	// ZombieMaxMigrations: consecutive completed migrations with no
	// payload between them before the engine declares the peer dead.
	// 0 = engine default 2.
	ZombieMaxMigrations int

	// ZombieCooldown: zombie counter reset window. 0 = engine default 30s.
	ZombieCooldown time.Duration

	// BondStuckRTTMultiplier (bond only): a path whose RTT exceeds
	// best_rtt * Multiplier is bypassed in bond round-robin.
	// 0 = engine default 3.0.
	BondStuckRTTMultiplier float64
}

// Validate runs cheap structural checks. Embedders should call this
// before passing the Config into NewDialer / NewListener.
func (c *Config) Validate() error {
	if c == nil {
		return errNilConfig
	}
	if len(c.Paths) == 0 {
		return errNoPaths
	}
	switch c.Mode {
	case ModeUnset, ModePrime, ModeRace, ModeBond:
	default:
		return errUnknownMode
	}
	for i, p := range c.Paths {
		if p.Transport == "" {
			return errPathNoTransport(i)
		}
		if p.Address == "" {
			return errPathNoAddress(i, p.Transport)
		}
	}
	return nil
}
