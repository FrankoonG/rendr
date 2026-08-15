package transport

import (
	"context"
	"io"
	"time"
)

// PathFactory opens one kind of already-framed network path. A factory is
// registered explicitly on a rendr Runtime under an opaque caller-chosen ID;
// the ID is not part of this interface and cannot select leaf mobility.
type PathFactory interface {
	// DialPath establishes a single PathConn for spec. The returned
	// PathConn is already past any TLS/handshake stage; if the
	// handshake itself fails, DialPath returns the error and no
	// PathConn.
	DialPath(ctx context.Context, spec PathSpec) (PathConn, error)

	// Probe returns the best estimate of path quality without
	// promoting the path to the active set. Implementations may
	// short-circuit by dialing and immediately closing if the
	// transport has no cheap probe primitive.
	Probe(ctx context.Context, spec PathSpec) (PathQuality, error)
}

// DeathCause classifies why a PathConn went down. See package doc
// for the strict semantic contract.
type DeathCause uint8

const (
	// CauseUnknown should be used only at the boundary, before any
	// classification has happened. It is never the final cause.
	CauseUnknown DeathCause = 0

	// CauseCleanClose means the remote side issued an orderly BYE
	// or the stream reached an application-visible EOF. The engine
	// does NOT migrate; it propagates EOF to the application.
	CauseCleanClose DeathCause = 1

	// CauseTransportError covers everything else: timeouts, RST,
	// quic.IdleTimeoutError, HandshakeTimeoutError, ApplicationError,
	// TransportError, "the underlying socket suddenly returned 0
	// bytes for no reason". The engine MUST migrate, not propagate.
	CauseTransportError DeathCause = 2
)

// PathConn is one live path. It MUST NOT surface migration-class
// errors via Read/Write; use OnDeath instead. Close MUST promptly unblock every
// concurrent Read and Write. Engine admission deadlines and bounded shutdown
// rely on this contract; adapters that cannot provide it are not conforming.
type PathConn interface {
	io.ReadWriteCloser

	// Quality returns the latest measurement for direct caller diagnostics.
	// May return a zero PathQuality if the transport has not yet probed. The
	// engine uses PathQualityReader instead so observation is cancellable.
	Quality() PathQuality

	// OnDeath registers a callback the transport invokes exactly
	// once when the path is no longer usable. The cause MUST be
	// CleanClose or TransportError - CauseUnknown is forbidden as a
	// final value. fn may be called from any goroutine.
	OnDeath(fn func(cause DeathCause, err error))

	// LocalAddr / RemoteAddr forward the underlying transport's
	// addresses for diagnostics. They are advisory; the engine does
	// not key off them.
	LocalAddr() string
	RemoteAddr() string
}

// PathQualityReader is the optional cancellable quality-observation extension
// used by the engine. Implementations must return promptly after ctx is done.
// The engine does not call PathConn.Quality because third-party legacy methods
// may block without a cancellation boundary.
type PathQualityReader interface {
	QualityContext(ctx context.Context) (PathQuality, error)
}

// FrameBatchWriter is an optional PathConn fast path for transports that can
// submit multiple already-framed packets through one physical write operation.
// Frames must be accepted in slice order. completed is the exact number of
// whole frames accepted from the prefix of frames.
//
// A return with completed < len(frames) must include a non-nil error. If the
// transport partially writes the next frame, that frame is not completed and
// the error applies to it and every suffix frame. A transport must never
// report a negative completed count or one greater than len(frames).
//
// PathConn.Write remains mandatory. The engine uses this extension only for
// bounded, immediately available packet DATA runs; stream, control, replay,
// and adapters without this interface retain ordinary Write behavior. Close
// must promptly unblock WriteFrameBatch under the same rule as PathConn.Write.
type FrameBatchWriter interface {
	WriteFrameBatch(frames [][]byte) (completed int, err error)
}

// OwnedFrameReader is an optional PathConn fast path for transports whose
// receive API already returns a uniquely owned frame allocation. The returned
// slice must remain immutable and valid after the next call; ownership passes
// to the engine. Implementations must not recycle or reuse its backing array.
//
// PathConn.Read remains mandatory for callers that don't understand this
// extension. The engine prefers ReadOwnedFrame when available to avoid an
// otherwise redundant full-frame allocation and copy on high-rate paths.
type OwnedFrameReader interface {
	ReadOwnedFrame() ([]byte, error)
}

// IngressQueueStats is a transport-owned receive queue snapshot. A zero
// Capacity means the transport has no observable ingress queue.
type IngressQueueStats struct {
	Depth     uint64
	HighWater uint64
	Capacity  uint64
}

// IngressQueueObserver is an optional PathConn observability extension used
// to distinguish transport ingress saturation from engine or application
// loss. It must be safe to call concurrently with Read and Close.
type IngressQueueObserver interface {
	IngressQueueStats() IngressQueueStats
}

// DatagramAccelerationMode identifies the socket send treatment selected by
// rendr. Selection does not prove that the protocol stack produced a batch;
// callers must use the counters to distinguish eligibility from actual use.
// It is observation only and cannot request or authorize an offload.
type DatagramAccelerationMode string

const (
	DatagramAccelerationUnknown  DatagramAccelerationMode = "unknown"
	DatagramAccelerationGSO      DatagramAccelerationMode = "gso_active"
	DatagramAccelerationOrdinary DatagramAccelerationMode = "ordinary_fallback"
)

// DatagramAccelerationStatus is a syscall-free snapshot of one UDP socket's
// selected treatment and actual send evidence. GSOSuperPackets counts only
// successful kernel writes carrying UDP_SEGMENT; a selected mode alone is not
// proof that the fast path was exercised.
type DatagramAccelerationStatus struct {
	Mode            DatagramAccelerationMode
	Cause           string
	ProbeGeneration uint64
	ProbedAt        time.Time
	// BatchCalls and BatchDatagrams prove actual multi-message UDP writes.
	// They are independent of GSO: one sendmmsg call may carry ordinary UDP
	// messages, GSO super-packets, or both.
	BatchCalls          uint64
	BatchDatagrams      uint64
	GSOAttempts         uint64
	GSOSuperPackets     uint64
	GSOSegments         uint64
	OrdinaryDatagrams   uint64
	FallbackTransitions uint64
}

// DatagramAccelerationObserver is an optional PathConn extension reporting
// its underlying UDP socket. Accepted QUIC paths share their listener socket,
// so those paths expose socket-wide aggregate counters rather than per-path
// counters. It must be safe to call concurrently with transport I/O and Close.
type DatagramAccelerationObserver interface {
	DatagramAccelerationStatus() DatagramAccelerationStatus
}
