package session

import (
	"sync"
	"sync/atomic"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// mailbox is the session actor's inbox (design §3.4, D12): a mutex-guarded
// list of ownership-carrying commands with a closed flag, plus a cap-1
// doorbell. Facts that live in objects (carrier deaths, peer CLOSE/GOAWAY,
// stream facts, a new health snapshot, WriteBlocked) only ring the
// doorbell; the actor re-reads them from the objects it holds, so nothing
// is lost or applied twice.
//
// Every posted command is either handed to the actor exactly once (drain,
// or the final close) or refused (post returns false and the poster cleans
// up), so a command racing the actor's exit can never leak its conn (F9).
type mailbox struct {
	mu sync.Mutex
	// cmds holds the commands not yet drained, in arrival order. Bounded by
	// construction: at most one dial result per slot, one adopt per admitted
	// carrier and four application/admission commands.
	cmds    []command
	closed  bool          // set by the actor at exit (close); post fails afterwards
	started bool          // a passive session's Start ran (start)
	bell    chan struct{} // cap 1: the doorbell (also rung for facts); made by init
	// actor is the session's actor once Start published it (R1-7): every
	// ring kicks it. nil before Start: a ring then only leaves the token,
	// which the actor finds when it runs.
	actor atomic.Pointer[actor]
}

// The mailbox is the session's carrier.Doorbell (carrier.Conn.Start,
// carrier.Health.Subscribe).
var _ carrier.Doorbell = (*mailbox)(nil)

// init makes the doorbell. It is called once, before the session is
// visible to any other goroutine (Dial, NewPending). Until then ring does
// nothing (the stream's fake-lane unit tests run without it).
func (m *mailbox) init() {
	m.bell = make(chan struct{}, 1)
}

// start reports whether this is the first call: Start launches the actor
// once (a second call would start a second actor).
func (m *mailbox) start() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return false
	}
	m.started = true
	return true
}

// post queues c for the actor and rings the doorbell. It returns false,
// queueing nothing, once the actor closed the mailbox: the caller then
// cleans up itself (closes the conn c carries, replies an error). Commands
// posted before the actor starts wait in the mailbox.
func (m *mailbox) post(c command) bool {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false
	}
	m.cmds = append(m.cmds, c)
	m.mu.Unlock()
	m.ring()
	return true
}

// ring is a non-blocking, coalescing send on the doorbell: a token left
// while the actor is busy makes it run one more step. It then kicks the
// published actor (R1-7), so every post, Ring, ringActor and health
// notification reaches a parked actor. It takes no lock, so it may be
// called from any goroutine with any lock held.
func (m *mailbox) ring() {
	select {
	case m.bell <- struct{}{}:
	default:
	}
	if a := m.actor.Load(); a != nil {
		a.kick()
	}
}

// Ring implements carrier.Doorbell.
func (m *mailbox) Ring() { m.ring() }

// drain appends the queued commands to dst in arrival order, empties the
// queue and returns dst. It never blocks; after close it returns dst
// unchanged.
func (m *mailbox) drain(dst []command) []command {
	m.mu.Lock()
	dst = append(dst, m.cmds...)
	clear(m.cmds) // drop the references held by the reused backing array
	m.cmds = m.cmds[:0]
	m.mu.Unlock()
	return dst
}

// close is the actor's final drain at exit: it sets the closed flag, so
// every later post fails, and returns the commands still queued, which the
// actor cleans up (closes adopted and attempt conns once, replies errors).
// A second call returns nil.
func (m *mailbox) close() []command {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	rest := m.cmds
	m.cmds = nil
	return rest
}

// ringActor wakes the session actor; it is what the actor side provides to
// the stream (design §4.0). The data path calls it after recording a fact
// in st.facts (or ctl.schedIn) under s.mu; it never blocks and takes no
// lock.
func (s *Session) ringActor() { s.mb.ring() }

// command is one ownership-carrying message to the actor (design §3.4).
// The concrete types are pointers: *dialResult, *adopt, *confirm, *reject,
// *refuse, *shutdown and *withdraw. The actor handles them in arrival
// order.
type command interface{ isCommand() }

// dialResult is the outcome of one dial attempt (dialer). The attempt id
// makes a result of an attempt the slot no longer waits for stale (L21).
type dialResult struct {
	slot    int                  // factory slot index (carrier.Factory.Index)
	attempt uint64               // the slot's attempt id (sched.Cadence.Start)
	est     *carrier.Established // nil when err != nil; its Conn is unstarted
	err     error
}

// adoptKind says how a passive carrier reached a live session.
type adoptKind uint8

// Adopt kinds.
const (
	adoptOpen adoptKind = 1 // a duplicate OPEN (AttachOpen): parked while pending, else adopted with OPEN_ACK(OK)
	adoptJoin adoptKind = 2 // a JOIN (Join): adopted with JOIN_ACK(OK)
)

// adopt hands an unstarted passive carrier to the actor; it counts in
// ctl.adopting until handled (§6.3).
type adopt struct {
	conn *carrier.Conn
	kind adoptKind
	join wire.Join // adoptJoin: the JOIN as received
}

// confirm is PendingConn.Confirm. reply has capacity 1; the actor sends
// exactly one value and never blocks on it.
type confirm struct{ reply chan error }

// reject is PendingConn.Reject: OPEN_ACK(REJECTED, code, msg). reply as for
// confirm.
type reject struct {
	code  uint32
	msg   string
	reply chan error
}

// refuse is RefusePending: OPEN_ACK(status, code) on a pending session.
// reply (capacity 1) reports whether the session was still pending.
type refuse struct {
	status wire.AckStatus
	code   uint32
	reply  chan bool
}

// shutdown is Shutdown (Runtime.Close).
type shutdown struct{}

// withdraw: Dial's ctx ended before the opening phase succeeded.
type withdraw struct{}

func (*dialResult) isCommand() {}
func (*adopt) isCommand()      {}
func (*confirm) isCommand()    {}
func (*reject) isCommand()     {}
func (*refuse) isCommand()     {}
func (*shutdown) isCommand()   {}
func (*withdraw) isCommand()   {}
