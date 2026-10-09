package carrier

import (
	"context"
	"sync"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Pool is one Peer's set of dialer MUX trunks (M3 design §A5.8, §A5.9;
// M3-D16 … M3-D20). It is the fast path of the Peer's OPENs and JOINs: an
// attempt on a mux-eligible factory (Factory.Mux) takes a usable live trunk
// of that factory (a new view, no factory call), else waits for the
// factory's dial already in flight (coalescing: one dial per factory, not
// one per session), else dials itself with wire.OptMux. A pool never
// crosses Peers, keeps no idle trunk, never pre-dials, and closes a trunk
// at its last view.
//
// Locks: mu is per Pool and never taken under a session lock, Conn.mu or
// trunk.mx; it may take trunk.mx (Pool.mu → trunk.mx) to allocate a view.
type Pool struct {
	env *Env
	fs  []Factory // the Peer's factory snapshot; immutable

	mu      sync.Mutex
	trunks  [][]*Conn   // per factory: view 1 of each published trunk, oldest first
	dialing []*dialWait // per factory: the dial in flight that later attempts wait for (nil: none)
	closed  bool
	stats   PoolStats
}

// dialWait is one factory's dial in flight: its waiters block on done; err
// and release are set before done closes (M3-D18, R1-8).
type dialWait struct {
	done    chan struct{}
	err     error // the claimant's failure, counted once by each waiter (a transport or PREFACE failure)
	release bool  // the waiters retry at once without a failure (a session-level refusal, no mux, a discarded fresh trunk, a cancelled claimant)
}

// PoolStats are a Pool's counters (rendr.Status.Mux, dialer side).
type PoolStats struct {
	Carriers  int    // published trunks that are not closed
	Views     int    // views on them that are not gone
	FastPaths uint64 // OPENs and JOINs placed on a live trunk instead of dialling
	Coalesced uint64 // attempts that waited for another attempt's dial of the same factory
	MuxFull   uint64 // CAPACITY CodeMuxFull answers received
}

// NewPool returns the Pool of a Peer with factory snapshot fs.
func NewPool(env *Env, fs []Factory) *Pool {
	panic("unimplemented: M3")
}

// Attempt opens one carrier of factory f for a session (M3-D16): for a
// factory that is not mux-eligible it is Establish (M2); otherwise a fast
// path view on a usable trunk (M3-D17), a coalesced wait for the factory's
// dial in flight (bounded by ctx, M3-D18), or its own Establish with
// wire.OptMux, whose fresh trunk (Established.Fresh) the pool publishes
// when the session starts view 1 (M3-D19). cid is the CarrierID reserved
// for a dial (released when a fast path or a wait serves the attempt);
// kind and payload are the first frame (OPEN or JOIN); check verifies the
// PREFACE_ACK as for Establish; inst is the session's bound instance for a
// JOIN (zero for an OPEN); sess identifies the session (one unreaped view
// per trunk, R1-6). Errors are Establish's; a fast path that fails before
// its first frame was placed continues with a dial and counts no failure.
func (p *Pool) Attempt(ctx context.Context, f int, cid uint32, kind wire.Type, payload []byte, check func(*wire.PrefaceAck) error, inst [16]byte, sess uintptr) (*Established, error) {
	panic("unimplemented: M3")
}

// Close stops publishing and fast paths (Peer.Close keeps the pool's
// trunks until their last views end; Runtime.Close joins them).
// Idempotent.
func (p *Pool) Close() {
	panic("unimplemented: M3")
}

// Stats returns a snapshot of the pool's counters.
func (p *Pool) Stats() PoolStats {
	panic("unimplemented: M3")
}
