package transport

import (
	"context"
	"io"
)

// Transport is the factory for one kind of underlying network
// path. Implementations are registered globally (or attached to a
// Dialer/Listener) and looked up by Name().
type Transport interface {
	// Name is the identifier the embedder uses in PathSpec.Transport.
	Name() string

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

	// Quality returns the latest measurement. May return a zero
	// PathQuality if the transport has not yet probed.
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
