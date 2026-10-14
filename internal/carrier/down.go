package carrier

import (
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The trunk death notice DOWN (M5 design, PA-86; F-7). When a MUX trunk
// dies, every session on it publishes its death SCHED, and on a datagram
// trunk each SCHED is one REL of a surviving trunk, whose window holds
// wire.RelWindow RELs for all the sessions it carries: without a trunk-level
// notice the k-th session's passive learns about floor(k/8) round trips
// late and keeps writing on the dead trunk (L45). One DOWN per death, on
// every other trunk of the pair, is O(1) and leaves SCHED alone: the dialer
// stays the only scheduler, and DOWN reports a transport fact, never a
// route.
//
// Sender. When an established MUX trunk (view 1 started: TrunkSet.add) dies
// with a cause its peer does not know (Cause.sendsDown: not retired, goaway
// or peer_down), DOWN(its CarrierID) is queued on every other live MUX
// trunk of its pair (TrunkSet.down) before the death record is published
// (setDeath), so before any session on the dead trunk can learn of the
// death. Each trunk's writer places its pending DOWNs ahead of its session
// frames: in its carrier control at the start of a round, and ahead of any
// reliable session frame reserved later in the round (Batch.addSessionRel's
// fence, for a DOWN queued while a round runs), so a DOWN precedes the
// death SCHEDs in the surviving trunk's REL order (datagram trunks) and in
// its byte stream (stream trunks). A held trunk (its first response not yet
// placed, M3-D8) places none until the response left. A trunk's pending
// DOWNs are deduplicated by ID and bounded by downCap; an overflow drops the
// oldest and counts it (downQueue.dropped).
//
// Receiver (onDown). A DOWN on a dedicated or probe carrier, or one naming
// the trunk it arrives on, is a protocol violation of the receiving
// carrier. Otherwise the ID is looked up in the receiving trunk's pair: a
// live MUX trunk that is not retiring is killed with CausePeerDown, exactly
// as by a local transport death (every view dies at once and each session
// reroutes by its own death rules); an unknown, dead, retiring or
// other-pair ID is ignored, because a DOWN races the receiver's own
// detection. A trunk killed by a DOWN sends none (Cause.sendsDown).
//
// Locks: TrunkSet.mu and downQueue.mu are leaves. A dying trunk calls the
// set with none of its own locks held (setDeath), the set copies the
// targets and releases its lock before a DOWN is queued on any of them,
// and a target's queue lock is taken under at most that target's own
// locks (Conn.mu in its carrier control, trunk.mx or a session lock under
// the fence), never under another trunk's. Nothing here runs per frame: a
// DOWN exists only at a death, and the writer's cost in steady state is
// one atomic load per reliable session frame.

// downCap bounds a trunk's pending DOWNs. A pool keeps one trunk per
// factory and session kind (M3-D17, KINDSPLIT) and a Peer has at most
// wire.MaxSchedIDs factories, so 2 × wire.MaxSchedIDs trunks of one pair
// can die between two writer rounds of a surviving trunk in the ordinary
// case; a burst beyond it drops the oldest pending DOWN, and the peer then
// learns that death by its own detection (its death deadline).
const downCap = 2 * wire.MaxSchedIDs

// downQueue is a trunk's pending DOWNs: the CarrierIDs of dead trunks of
// its pair whose DOWN its writer has not placed yet, oldest first, each at
// most once. Its lock is a leaf.
type downQueue struct {
	mu      sync.Mutex
	ids     [downCap]uint32 // a ring: ids[head], …, ids[head+n−1] (mod downCap)
	head, n int
	queued  uint64       // DOWNs queued over the trunk's life (the tests read it and dropped)
	dropped uint64       // DOWNs the bound dropped (the oldest at an overflow)
	pend    atomic.Int32 // n, read without mu by the writer's fence
}

// queueDown queues DOWN(id) on the trunk (PA-86) and wakes its writer: a
// no-op on a trunk that ended or wrote its CLOSE (nothing follows it) and
// for an ID already pending; at the bound the oldest pending DOWN is
// dropped and counted.
func (t *trunk) queueDown(id uint32) {
	q := &t.downs
	q.mu.Lock()
	if t.death.Load() != nil || t.closeSent.Load() {
		q.mu.Unlock()
		return
	}
	for i := range q.n {
		if q.ids[(q.head+i)%downCap] == id {
			q.mu.Unlock()
			return
		}
	}
	if q.n == downCap {
		q.head = (q.head + 1) % downCap
		q.n--
		q.dropped++
	}
	q.ids[(q.head+q.n)%downCap] = id
	q.n++
	q.queued++
	q.pend.Store(int32(q.n))
	q.mu.Unlock()
	t.wakeWriter()
}

// place appends the pending DOWNs to b, oldest first, while they fit (a
// full batch or, on a datagram batch, no REL room left stops it: the rest
// stays pending and keeps its order). It runs on the trunk's writer.
func (q *downQueue) place(b *Batch) {
	if q.pend.Load() == 0 {
		return
	}
	q.mu.Lock()
	for q.n > 0 && b.addDown(q.ids[q.head]) {
		q.ids[q.head] = 0
		q.head = (q.head + 1) % downCap
		q.n--
	}
	q.pend.Store(int32(q.n))
	q.mu.Unlock()
}

// onDown handles a DOWN dispatched on the reader (a stream frame or a REL's
// inner frame; PA-86). It returns the violation a malformed DOWN, a DOWN on
// a dedicated carrier (probe and sessionless carriers are dedicated) or
// one naming this trunk is; "" otherwise, after killing the trunk the ID
// names in this trunk's pair when that trunk is live and not retiring.
func (t *trunk) onDown(p []byte) (violation string) {
	id, err := wire.ParseDown(p)
	if err != nil {
		return "DOWN: " + err.Error()
	}
	if !t.mux {
		return "DOWN on a dedicated carrier"
	}
	if id == t.id {
		return "DOWN naming the trunk it arrives on"
	}
	if u := t.env.Trunks.lookup(t, id); u != nil && !u.retiringForDown() {
		u.view1.killCarrier(CausePeerDown, "the peer's DOWN on carrier "+strconv.FormatUint(uint64(t.id), 10))
	}
	return ""
}

// retiringForDown reports a planned retirement in progress — our CLOSE
// queued or written (a GOAWAY of ours included), or the peer's CLOSE
// received —, which a DOWN for the trunk does not cut short (L05).
func (t *trunk) retiringForDown() bool {
	if t.closeSent.Load() || t.peerClosed.Load() {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.st.retiring
}

// TrunkSet is a Runtime's index of its established MUX trunks by pair
// (PA-86): the Runtime hook through which a dying trunk queues DOWN on the
// other trunks of its pair (down) and a received DOWN finds the trunk it
// names (lookup). A pair is the peer Runtime's InstanceID and the
// direction: on the dialer the trunks of its pools whose PREFACE_ACK
// carried that instance, on the passive the trunks of its trunk set whose
// PREFACE did. Within a pair the CarrierIDs are the dialer's, which its
// IDAllocator reuses only after its counter wraps. A trunk enters when view
// 1 starts (Conn.Start) and leaves at its death (setDeath). The zero value
// is not usable: NewTrunkSet builds one. Its methods are no-ops on a nil
// set.
type TrunkSet struct {
	mu    sync.Mutex
	pairs map[trunkPair]map[uint32]*trunk
}

// trunkPair names a pair: the peer Runtime and whether this side dialed.
type trunkPair struct {
	peer   [16]byte
	dialer bool
}

// NewTrunkSet returns an empty set (NewRuntime builds the Runtime's).
func NewTrunkSet() *TrunkSet {
	return &TrunkSet{pairs: make(map[trunkPair]map[uint32]*trunk)}
}

// pair returns the trunk's pair: its PREFACE_ACK instance on the dialer, its
// PREFACE instance on the passive.
func (t *trunk) pair() trunkPair { return trunkPair{peer: t.peer, dialer: t.dialer} }

// add registers t, a MUX trunk whose view 1 started. A death that raced the
// registration (its setDeath removed nothing yet) takes it out again.
func (s *TrunkSet) add(t *trunk) {
	if s == nil {
		return
	}
	k := t.pair()
	s.mu.Lock()
	m := s.pairs[k]
	if m == nil {
		m = make(map[uint32]*trunk)
		s.pairs[k] = m
	}
	m[t.id] = t
	s.mu.Unlock()
	if t.death.Load() != nil {
		s.remove(t)
	}
}

// remove takes t out of the set (its death).
func (s *TrunkSet) remove(t *trunk) {
	if s == nil {
		return
	}
	k := t.pair()
	s.mu.Lock()
	if m := s.pairs[k]; m[t.id] == t {
		delete(m, t.id)
		if len(m) == 0 {
			delete(s.pairs, k)
		}
	}
	s.mu.Unlock()
}

// down queues DOWN(t.id) on every other trunk of t's pair; nothing when t
// is not in the set (never established, or its death already removed it).
// The targets are copied under the lock and served after it (one slice per
// death).
func (s *TrunkSet) down(t *trunk) {
	if s == nil {
		return
	}
	s.mu.Lock()
	m := s.pairs[t.pair()]
	if m[t.id] != t {
		s.mu.Unlock()
		return
	}
	to := make([]*trunk, 0, len(m)-1)
	for _, u := range m {
		if u != t {
			to = append(to, u)
		}
	}
	s.mu.Unlock()
	for _, u := range to {
		u.queueDown(t.id)
	}
}

// lookup returns the trunk with CarrierID id in t's pair, or nil.
func (s *TrunkSet) lookup(t *trunk, id uint32) *trunk {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pairs[t.pair()][id]
}
