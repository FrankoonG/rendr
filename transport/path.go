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
	// share of frames. Selector ignores Weight.
	Weight uint16
}

// Clone returns an owned snapshot of the path specification. Opts is opaque to
// the engine, but it is still mutable caller-owned state and must not cross an
// asynchronous engine boundary by reference.
func (s PathSpec) Clone() PathSpec {
	clone := s
	if s.Opts != nil {
		clone.Opts = make(map[string]string, len(s.Opts))
		for key, value := range s.Opts {
			clone.Opts[key] = value
		}
	}
	return clone
}

// PathInfo is the engine's read-only snapshot of one attached path.
//
// Reads / Writes are cumulative frame counters; transports that
// don't instrument framing leave them at 0. Active is true iff this
// path is the current send target under selector mode (always one
// active path); under race/bond, Active flags the first path
// returned by dispatch's iteration order and should not be used
// for routing decisions.
type PathInfo struct {
	ID      uint32
	Spec    PathSpec
	Quality PathQuality
	Since   time.Time
	// LocalAddr and RemoteAddr are the current physical endpoints reported by
	// the PathConn. They may change while the logical path ID remains stable
	// during in-place leaf mobility (for example QUIC CID rebind).
	LocalAddr  string
	RemoteAddr string
	Reads      uint64
	Writes     uint64
	// DataWrites and ControlWrites split engine-framed egress so probes and
	// cumulative ACKs cannot masquerade as application throughput.
	DataWrites     uint64
	ControlWrites  uint64
	DataDispatches uint64
	// FirstDataDispatches counts successful DATA writes issued by the
	// frame's initial publication. DataDispatches also includes recovery
	// replay, so comparing the two exposes retransmission overhead without
	// letting replay masquerade as a scheduler route decision.
	FirstDataDispatches uint64
	// BatchWriteCalls, BatchWriteFrames, and BatchWriteMax report successful
	// engine-to-transport FrameBatchWriter submissions. They are zero for
	// ordinary writes and never include control or replay traffic.
	BatchWriteCalls  uint64
	BatchWriteFrames uint64
	BatchWriteMax    uint64
	Active           bool
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
	// IngressQueue reports a transport-owned receive queue when the path
	// implements IngressQueueObserver. It is zero for transports without a
	// distinct observable ingress queue.
	IngressQueue IngressQueueStats
	// DatagramAcceleration reports the selected UDP treatment and cumulative
	// socket evidence when the path implements DatagramAccelerationObserver.
	// Accepted paths may share listener-wide counters. The zero value means
	// that the transport doesn't expose datagram acceleration telemetry.
	DatagramAcceleration DatagramAccelerationStatus
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
