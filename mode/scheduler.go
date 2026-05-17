package mode

import (
	"github.com/FrankoonG/rendr/transport"
)

// Scheduler dispatches outgoing frames across paths and reassembles
// incoming frames into a single ordered stream.
type Scheduler interface {
	// Submit accepts a frame from the engine and returns the subset
	// of paths that should carry it on this send. prime returns
	// exactly one path; race returns all paths; bond returns one
	// chosen per-path-weighted scheduling decision.
	//
	// seq is the engine's global 48-bit SEQ for this frame. Schedulers
	// MUST NOT rewrite seq; they may use it for their own bookkeeping.
	Submit(frame []byte, seq uint64) []transport.PathConn

	// OnRecv is called with each frame the transport layer received.
	// fromPath identifies the source. The Scheduler delivers
	// reordered / deduped frames to the deliver callback registered
	// via SetDeliver.
	OnRecv(frame []byte, fromSeq uint64, fromPath transport.PathConn)

	// SetDeliver registers the engine's frame sink. Called once at
	// startup; Schedulers do not allow re-registration.
	SetDeliver(fn func(frame []byte, seq uint64))

	// AttachPath / DetachPath are called by the engine when the set
	// of usable paths changes.
	AttachPath(p transport.PathConn)
	DetachPath(p transport.PathConn)
}
