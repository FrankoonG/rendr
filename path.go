package rendr

import "time"

// PathSpec is the declarative description of a candidate path.
// A PathSpec is given to a Transport (see transport package) to be
// dialed into a live PathConn.
type PathSpec struct {
	// Transport names the transport adapter ("tcp", "quic", "udp_opaque", ...).
	Transport string
	// Address is the remote address for the transport (interpretation
	// is transport-specific; tcp wants host:port, quic same, etc.).
	Address string
	// Local optionally pins the local source endpoint.
	Local string
	// Opts carries transport-specific options (TLS config, ALPN, etc.).
	// The engine treats it as opaque.
	Opts map[string]string
	// Weight is an advisory hint to the mode layer (bond/race) about
	// share of frames. prime ignores Weight.
	Weight uint16
}

// PathInfo is what the engine exposes to the application about a
// currently-attached path. It is a read-only snapshot.
type PathInfo struct {
	// ID is the per-Conn identifier the engine assigns at attach time.
	// It is stable across the lifetime of one PathConn but is not
	// preserved across reconnects.
	ID uint32
	// Spec is the PathSpec that produced this path.
	Spec PathSpec
	// Quality is the latest measurement.
	Quality PathQuality
	// Since is when the path attached to the current Conn.
	Since time.Time
}

// PathQuality is the measurement layer's view of a path. Encoded in
// PATH_QUALITY control frames (see proto package) as fixed-width
// integers; the Go fields use float64 / time.Duration for ergonomics
// only.
type PathQuality struct {
	RTT    time.Duration
	Jitter time.Duration
	// LossPP is loss in parts-per-thousand (0-1000) so a uint16 wire
	// representation has enough resolution.
	LossPP uint16
	// At is the local clock at which RTT/Jitter/Loss were last updated.
	At time.Time
}
