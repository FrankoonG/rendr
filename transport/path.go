package transport

import "time"

// PathSpec is the declarative description of a candidate path. A
// transport adapter consumes it to dial a live PathConn.
type PathSpec struct {
	// Transport names the adapter ("tcp", "quic", ...).
	Transport string
	// Address is the remote address for the transport (interpretation
	// is transport-specific).
	Address string
	// Local optionally pins the local source endpoint.
	Local string
	// Opts carries transport-specific options (TLS config, ALPN, ...).
	// The engine treats it as opaque.
	Opts map[string]string
	// Weight is an advisory hint to the mode layer (bond/race) about
	// share of frames. prime ignores Weight.
	Weight uint16
}

// PathInfo is the engine's read-only snapshot of one attached path.
//
// Reads / Writes are cumulative frame counters; transports that
// don't instrument framing leave them at 0. Active is true iff this
// path is the current send target under prime mode (always one
// active path); under race/bond, Active flags the first path
// returned by dispatch's iteration order and should not be used
// for routing decisions.
type PathInfo struct {
	ID      uint32
	Spec    PathSpec
	Quality PathQuality
	Since   time.Time
	Reads   uint64
	Writes  uint64
	Active  bool
	// RecvDups: inbound frames on this path whose SEQ was already
	// delivered or buffered (race-mode duplicates, accidental
	// retransmits). Sum across all paths equals ConnStats.RecvDups.
	RecvDups uint64
	// LastRecvAt is the wall-clock time at which a frame was last
	// successfully received on this path (any type: data, ctrl,
	// probe). Zero if no frame has arrived. Distinct from
	// Quality.At which only updates on probe replies; LastRecvAt
	// surfaces "path is genuinely idle" as opposed to "probe-fresh
	// but no traffic" so monitoring can flag NAT keepalive timeouts.
	LastRecvAt time.Time
	// LastSendAt is the wall-clock time at which a frame was last
	// successfully written to this path's socket. Pair with
	// LastRecvAt to distinguish "I'm sending but peer is silent"
	// from "peer is sending but I'm idle".
	LastSendAt time.Time
}

// PathQuality is the most recent measurement of one path.
// Encoded on the wire as fixed-width integers (PATH_QUALITY control
// frame, see the proto package); these Go fields are ergonomic only.
type PathQuality struct {
	RTT    time.Duration
	Jitter time.Duration
	// LossPP is loss in parts-per-thousand (0-1000) so a uint16 wire
	// representation has enough resolution.
	LossPP uint16
	// At is the local clock at which the measurement was last updated.
	At time.Time
}
