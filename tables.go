package rendr

import (
	"container/heap"
	"hash/maphash"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
)

// Admission tables (design §3.2, §6.1–§6.5; plan §3.5, §3.7). Every lock
// here is a leaf: it is never held together with a session lock, a conn
// call, a channel operation or a callback. Methods take now explicitly so
// that the tables are pure and deterministic under test.

// tableShards is the number of session-table shards (design §3.2).
const tableShards = 16

// tableKey identifies a session in a Runtime's table. Passive sessions are
// keyed by (dialer InstanceID, SessionID), the OPEN idempotency key (L47);
// the Runtime's own dialer sessions by their SessionID alone, in a separate
// key space, so a Runtime that dials itself never collides with itself.
type tableKey struct {
	inst   InstanceID
	sid    SessionID
	dialer bool
}

// passiveKey is the key of the passive session (dialer, sid).
func passiveKey(dialer InstanceID, sid SessionID) tableKey { return tableKey{inst: dialer, sid: sid} }

// dialerKey is the key of this Runtime's dialer session sid.
func dialerKey(sid SessionID) tableKey { return tableKey{sid: sid, dialer: true} }

// keyFor is the key of a session from its immutable identity: the
// Registry derives it as keyFor(s.Role(), s.PeerInstance(), s.ID()).
func keyFor(role session.Role, peer, sid [16]byte) tableKey {
	if role == session.RoleDialer {
		return dialerKey(sid)
	}
	return passiveKey(peer, sid)
}

// sessionCategory is the SessionCounts category of a live session. The
// categories are disjoint, by precedence pending > lingering > orphaned >
// open, so that Open + Pending + Lingering + Orphaned is the number of live
// sessions (the fixture's serverSessions, design §11.3).
type sessionCategory uint8

const (
	catNone      sessionCategory = iota // a dialer placeholder (opening phase) or an ended session
	catOpen                             // open and in no other category
	catPending                          // passive: waiting for Confirm/Reject
	catLingering                        // the application closed the session; it has not ended
	catOrphaned                         // passive: inside a no-path episode
	numCategories
)

// tableEntry is one live session or one tombstone. The entry pointer is
// the table's generation token (L47): an update whose entry was replaced or
// ended is ignored.
type tableEntry[S comparable] struct {
	key tableKey
	ttl time.Duration // passive: tombstone lifetime once the session ends

	// Live state, guarded by the shard lock.
	sess      S    // the session; zero for a dialer placeholder and for tombstones
	attached  bool // sess is set (false only for a dialer placeholder)
	pending   bool
	lingering bool
	orphaned  bool

	// Tombstone state: tomb, verdict and expiry are written once under the
	// shard lock when the session ends and never change afterwards.
	tomb    bool
	verdict session.Verdict
	expiry  time.Time

	// Tombstone index links, guarded by tombIndex.mu.
	prev, next *tableEntry[S]
	heapIdx    int
}

func (e *tableEntry[S]) category() sessionCategory {
	switch {
	case e.tomb || !e.attached:
		return catNone
	case e.pending:
		return catPending
	case e.lingering:
		return catLingering
	case e.orphaned:
		return catOrphaned
	}
	return catOpen
}

// lookupResult is what the table knows about a key at one instant.
type lookupResult[S comparable] struct {
	found   bool            // a live entry or an unexpired tombstone exists
	sess    S               // live entry: its session (zero for a dialer placeholder)
	tomb    bool            // the entry is a tombstone: verdict is set
	verdict session.Verdict // a tombstone's answer (design §6.5)
}

type tableShard[S comparable] struct {
	mu sync.Mutex
	m  map[tableKey]*tableEntry[S]
}

// sessionTable is the Runtime's session table (design §6.2–§6.5): 16 shards
// mapping a tableKey to a live session or a tombstone, insert-or-get under
// the shard lock (exactly one live entry per key, L47), the MaxSessions
// units (open + pending + lingering + orphaned of both roles plus sessions
// still dialling), the disjoint category counts of Status.Sessions, and the
// tombstone index (FIFO ring capped at 2×MaxSessions, expiry after the
// session's TombstoneTTL). S is the session handle (*session.Session in
// production; tests use their own).
type sessionTable[S comparable] struct {
	seed     maphash.Seed
	shards   [tableShards]tableShard[S]
	maxUnits int64
	units    atomic.Int64                // MaxSessions units in use
	cnt      [numCategories]atomic.Int64 // live sessions per category (catNone unused)
	// moving counts category moves in progress and moves the finished
	// ones: counts reads the categories as one snapshot (their sum is the
	// number of live sessions), retrying a read that a move overlapped.
	moving atomic.Int64
	moves  atomic.Uint64
	tombs  tombIndex[S]
	// countsRead, when set (tests), runs inside counts between the read
	// of Open and the other categories.
	countsRead func()
}

// newSessionTable returns an empty table for maxSessions (≥ 1) sessions; it
// remembers at most 2×maxSessions tombstones (plan §3.7). The tombstone cap
// saturates at math.MaxInt instead of overflowing: an unclamped test
// override may pass a huge MaxSessions to mean "unlimited".
func newSessionTable[S comparable](maxSessions int) *sessionTable[S] {
	n := max(maxSessions, 1)
	t := &sessionTable[S]{seed: maphash.MakeSeed(), maxUnits: int64(n)}
	for i := range t.shards {
		t.shards[i].m = make(map[tableKey]*tableEntry[S])
	}
	t.tombs.limit = math.MaxInt
	if n <= math.MaxInt/2 {
		t.tombs.limit = 2 * n
	}
	return t
}

func (t *sessionTable[S]) shard(k tableKey) *tableShard[S] {
	return &t.shards[maphash.Comparable(t.seed, k)%tableShards]
}

// reserve takes one MaxSessions unit; false when all are in use. A unit is
// owned by the entry that consumes it (insertOrGet, placeDialer) until the
// session ends; a reservation that no entry consumed is returned with
// unreserve.
func (t *sessionTable[S]) reserve() bool {
	for {
		n := t.units.Load()
		if n >= t.maxUnits {
			return false
		}
		if t.units.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// unreserve returns a unit taken by reserve that no entry consumed.
func (t *sessionTable[S]) unreserve() { t.units.Add(-1) }

// lookup returns the live entry or unexpired tombstone of k. An expired
// tombstone is absent; lookup removes it from its shard.
func (t *sessionTable[S]) lookup(k tableKey, now time.Time) lookupResult[S] {
	sh := t.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return t.getLocked(sh, k, now)
}

func (t *sessionTable[S]) getLocked(sh *tableShard[S], k tableKey, now time.Time) lookupResult[S] {
	e := sh.m[k]
	switch {
	case e == nil:
		return lookupResult[S]{}
	case !e.tomb:
		return lookupResult[S]{found: true, sess: e.sess}
	case now.Before(e.expiry):
		return lookupResult[S]{found: true, tomb: true, verdict: e.verdict}
	}
	delete(sh.m, k) // expired: absent; the index drops it at its next prune
	return lookupResult[S]{}
}

// insertOrGet is the admission's check-and-insert under one shard lock
// (design §6.2, D28): if k has a live entry or an unexpired tombstone it is
// returned and nothing changes (inserted == false: the caller releases its
// reservation and routes its carrier against that entry); otherwise a live
// entry for s is inserted — pending for a passive key, open for a dialer
// key — and consumes the caller's reserved unit. ttl is the passive
// session's TombstoneTTL (ignored for dialer keys).
func (t *sessionTable[S]) insertOrGet(k tableKey, s S, ttl time.Duration, now time.Time) (lookupResult[S], bool) {
	sh := t.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if r := t.getLocked(sh, k, now); r.found {
		return r, false
	}
	e := &tableEntry[S]{key: k, ttl: ttl, sess: s, attached: true, pending: !k.dialer, heapIdx: -1}
	sh.m[k] = e
	t.cnt[e.category()].Add(1)
	return lookupResult[S]{found: true, sess: s}, true
}

// placeDialer reserves a MaxSessions unit for a dialer session that is
// still opening and inserts its placeholder (counted in no category). It
// returns false when MaxSessions units are exhausted (Peer.Dial:
// ErrCapacity) or, with negligible probability, when sid is already in use.
// The placeholder is completed by attach or removed by ended.
func (t *sessionTable[S]) placeDialer(sid SessionID) bool {
	if !t.reserve() {
		return false
	}
	k := dialerKey(sid)
	sh := t.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.m[k] != nil {
		t.unreserve()
		return false
	}
	sh.m[k] = &tableEntry[S]{key: k, heapIdx: -1}
	return true
}

// attach completes the placeholder of dialer session sid with s once Dial
// succeeded (the session counts as open from now on). It returns false if
// the placeholder is gone because the session already ended.
func (t *sessionTable[S]) attach(sid SessionID, s S) bool {
	k := dialerKey(sid)
	sh := t.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[k]
	if e == nil || e.attached {
		return false
	}
	e.sess, e.attached = s, true
	t.cnt[e.category()].Add(1)
	return true
}

// update applies f to the live entry of k if it belongs to s and moves the
// session between categories accordingly. A missing entry, a tombstone or
// another session's entry (a stale generation) is ignored.
func (t *sessionTable[S]) update(k tableKey, s S, f func(e *tableEntry[S])) bool {
	sh := t.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[k]
	if e == nil || e.tomb || !e.attached || e.sess != s {
		return false
	}
	old := e.category()
	f(e)
	t.move(old, e.category())
	return true
}

func (t *sessionTable[S]) move(old, cur sessionCategory) {
	if old == cur {
		return
	}
	t.moving.Add(1)
	if old != catNone {
		t.cnt[old].Add(-1)
	}
	if cur != catNone {
		t.cnt[cur].Add(1)
	}
	t.moves.Add(1)
	t.moving.Add(-1)
}

// opened records that passive session s left StatePending (Registry.Opened).
func (t *sessionTable[S]) opened(k tableKey, s S) bool {
	return t.update(k, s, func(e *tableEntry[S]) { e.pending = false })
}

// setLingering records that the application closed s (on) (Registry.Lingering).
func (t *sessionTable[S]) setLingering(k tableKey, s S, on bool) bool {
	return t.update(k, s, func(e *tableEntry[S]) { e.lingering = on })
}

// setOrphaned records that passive session s entered (on) or left (off) a
// no-path episode (Registry.Orphaned).
func (t *sessionTable[S]) setOrphaned(k tableKey, s S, on bool) bool {
	return t.update(k, s, func(e *tableEntry[S]) { e.orphaned = on })
}

// ended records the end of s (Registry.Ended) and releases its MaxSessions
// unit. A passive entry becomes a tombstone answering v for its
// TombstoneTTL from now (design §6.5); a dialer entry is removed. For a
// dialer placeholder (attached == false) the identity check is skipped, so
// Peer.Dial's failure path can call ended with the zero session; whichever
// of the session's own Ended and that call comes first removes the entry,
// the other finds nothing. It returns false when the entry was not found
// (already ended, or another session's).
func (t *sessionTable[S]) ended(k tableKey, s S, v session.Verdict, now time.Time) bool {
	sh := t.shard(k)
	sh.mu.Lock()
	e := sh.m[k]
	if e == nil || e.tomb || (e.attached && e.sess != s) {
		sh.mu.Unlock()
		return false
	}
	t.move(e.category(), catNone)
	t.units.Add(-1)
	var zero S
	e.sess = zero // a tombstone never keeps the session alive
	if k.dialer || e.ttl <= 0 {
		e.tomb = true
		delete(sh.m, k)
		sh.mu.Unlock()
		return true
	}
	e.tomb, e.verdict, e.expiry = true, v, now.Add(e.ttl)
	sh.mu.Unlock()
	t.drop(t.tombs.push(e, now))
	return true
}

// countsTries bounds counts' retries: under a continuous stream of moves
// Status still returns (Status never blocks), with the last read.
const countsTries = 64

// counts returns the session counts of Status.Sessions; expired tombstones
// are pruned first, so Tombstones counts exactly the unexpired ones. The
// four categories are one snapshot: a read that a category move overlapped
// (a move in progress, or one that finished during the read) is retried,
// so a session that moves between categories meanwhile is counted exactly
// once (their sum is the number of live sessions, SessionCounts).
func (t *sessionTable[S]) counts(now time.Time) SessionCounts {
	t.drop(t.tombs.prune(now))
	var c SessionCounts
	for try := 1; ; try++ {
		v := t.moves.Load()
		idle := t.moving.Load() == 0
		c.Open = int(t.cnt[catOpen].Load())
		if t.countsRead != nil {
			t.countsRead()
		}
		c.Pending = int(t.cnt[catPending].Load())
		c.Lingering = int(t.cnt[catLingering].Load())
		c.Orphaned = int(t.cnt[catOrphaned].Load())
		if (idle && t.moving.Load() == 0 && t.moves.Load() == v) || try == countsTries {
			break
		}
		runtime.Gosched()
	}
	c.Tombstones = t.tombs.len()
	return c
}

// inUse returns the MaxSessions units in use.
func (t *sessionTable[S]) inUse() int { return int(t.units.Load()) }

// live returns every live session (both roles; placeholders excluded),
// copied under each shard lock so that the caller acts on them with no
// table lock held (Runtime.Close: Shutdown every session).
func (t *sessionTable[S]) live() []S {
	var out []S
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		for _, e := range sh.m {
			if !e.tomb && e.attached {
				out = append(out, e.sess)
			}
		}
		sh.mu.Unlock()
	}
	return out
}

// drop deletes tombstones the index evicted or found expired from their
// shards. The pointer comparison skips a key that meanwhile holds another
// entry (a new session after the tombstone was already found expired).
func (t *sessionTable[S]) drop(victims []*tableEntry[S]) {
	for _, e := range victims {
		sh := t.shard(e.key)
		sh.mu.Lock()
		if sh.m[e.key] == e {
			delete(sh.m, e.key)
		}
		sh.mu.Unlock()
	}
}

// tombIndex orders the Runtime's tombstones twice: by insertion in a FIFO
// list (the oldest is evicted when more than limit exist, plan §3.7) and by
// expiry in a min-heap (pruned when expired). Both always hold the same
// set; entries leave both at once and are then deleted from their shard
// (sessionTable.drop) with no index lock held.
type tombIndex[S comparable] struct {
	mu         sync.Mutex
	limit      int            // 2×MaxSessions
	head, tail *tableEntry[S] // head = oldest
	n          int
	h          tombHeap[S]
}

// push indexes the new tombstone e and returns the entries that left the
// index: expired ones and, beyond the limit, the oldest.
func (x *tombIndex[S]) push(e *tableEntry[S], now time.Time) []*tableEntry[S] {
	x.mu.Lock()
	defer x.mu.Unlock()
	victims := x.pruneLocked(now, nil)
	e.prev, e.next = x.tail, nil
	if x.tail != nil {
		x.tail.next = e
	} else {
		x.head = e
	}
	x.tail = e
	x.n++
	heap.Push(&x.h, e)
	for x.n > x.limit && x.head != nil {
		v := x.head
		x.removeLocked(v)
		victims = append(victims, v)
	}
	return victims
}

// prune removes every expired tombstone and returns them.
func (x *tombIndex[S]) prune(now time.Time) []*tableEntry[S] {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.pruneLocked(now, nil)
}

func (x *tombIndex[S]) pruneLocked(now time.Time, victims []*tableEntry[S]) []*tableEntry[S] {
	for len(x.h) > 0 && !now.Before(x.h[0].expiry) {
		v := x.h[0]
		x.removeLocked(v)
		victims = append(victims, v)
	}
	return victims
}

func (x *tombIndex[S]) removeLocked(e *tableEntry[S]) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		x.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		x.tail = e.prev
	}
	e.prev, e.next = nil, nil
	x.n--
	heap.Remove(&x.h, e.heapIdx)
}

func (x *tombIndex[S]) len() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.n
}

// order returns the indexed tombstone keys in insertion order (tests).
func (x *tombIndex[S]) order() []tableKey {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := make([]tableKey, 0, x.n)
	for e := x.head; e != nil; e = e.next {
		out = append(out, e.key)
	}
	return out
}

// tombHeap is a min-heap of tombstones by expiry (container/heap).
type tombHeap[S comparable] []*tableEntry[S]

func (h tombHeap[S]) Len() int           { return len(h) }
func (h tombHeap[S]) Less(i, j int) bool { return h[i].expiry.Before(h[j].expiry) }
func (h tombHeap[S]) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIdx = i
	h[j].heapIdx = j
}

func (h *tombHeap[S]) Push(x any) {
	e := x.(*tableEntry[S])
	e.heapIdx = len(*h)
	*h = append(*h, e)
}

func (h *tombHeap[S]) Pop() any {
	old := *h
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	e.heapIdx = -1
	return e
}

// hsIO is the transport of an unfinished handshake (design §6.1): an
// accepted net.Conn, or the carrier.PacketIO of a datagram carrier (a
// HandlePacket conn or a raw-UDP flow; M2 design §A5.14). Eviction and
// Runtime.Close's drain close it with SetDeadline(now) and Close.
type hsIO interface {
	SetDeadline(t time.Time) error
	Close() error
}

// hsSlot is one occupied handshake slot (design §6.1): an accepted conn
// whose PREFACE and first frame (a datagram carrier: whose first datagram)
// are not yet parsed.
type hsSlot struct {
	nc         hsIO
	prev, next *hsSlot
	held       bool // in the LRU; false once released or evicted
}

// hsTable is the handshake slot LRU (plan §3.5, L48): at most limit
// unfinished handshakes per Runtime; when full, admitting a new one evicts
// the oldest (the caller closes its conn with closeWatched: SetDeadline(now)
// and Close on two watched goroutines, never in the accept loop) and counts
// the eviction. A new handshake is never refused while the Runtime runs;
// once drain ran (Runtime.Close) the table admits nothing more, so no
// handshake can start after the drain that was meant to close every one of
// them.
type hsTable struct {
	mu         sync.Mutex
	limit      int     // Handshake.MaxConcurrent
	head, tail *hsSlot // head = oldest
	n          int
	drained    bool // drain ran: admit refuses
	evictions  atomic.Uint64
}

// newHSTable returns an empty LRU of limit (≥ 1) slots.
func newHSTable(limit int) *hsTable { return &hsTable{limit: limit} }

// admit occupies a slot for nc. When all slots were taken, the oldest
// unfinished handshake is evicted and its conn returned for the caller to
// close; evicted is nil otherwise. When g is non-nil, an eviction adds one
// member to g under the table lock — the first of the two goroutines that
// will close the evicted conn; closeWatched adds the second outside the
// lock while the first is held — so that the member exists before a later
// drain returns (Runtime.Close joins g after its drain). After drain, admit
// occupies nothing and returns a nil slot: the caller closes nc itself.
func (h *hsTable) admit(nc hsIO, g *group) (s *hsSlot, evicted hsIO) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.drained {
		return nil, nil
	}
	s = &hsSlot{nc: nc, held: true}
	if h.n >= h.limit && h.head != nil {
		old := h.head
		h.unlinkLocked(old)
		evicted = old.nc
		h.evictions.Add(1)
		if g != nil {
			g.add() // a leaf lock under hsMu: group.mu never waits for hsMu
		}
	}
	s.prev = h.tail
	if h.tail != nil {
		h.tail.next = s
	} else {
		h.head = s
	}
	h.tail = s
	h.n++
	return s, evicted
}

// release frees s right after the first frame was parsed (L48: the slot is
// never held while waiting for the application). It returns false if s
// was evicted (its conn is being closed: the handshake must give up) or
// already released.
func (h *hsTable) release(s *hsSlot) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !s.held {
		return false
	}
	h.unlinkLocked(s)
	return true
}

func (h *hsTable) unlinkLocked(s *hsSlot) {
	if s.prev != nil {
		s.prev.next = s.next
	} else {
		h.head = s.next
	}
	if s.next != nil {
		s.next.prev = s.prev
	} else {
		h.tail = s.prev
	}
	s.prev, s.next, s.held = nil, nil, false
	h.n--
}

// drain releases every occupied slot and returns their conns, oldest first
// (Runtime.Close: close every unfinished handshake). Their handshakes see
// release return false. The drain is final: admit refuses from now on.
func (h *hsTable) drain() []hsIO {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drained = true
	out := make([]hsIO, 0, h.n)
	for h.head != nil {
		s := h.head
		h.unlinkLocked(s)
		out = append(out, s.nc)
	}
	return out
}

// len returns the occupied slots (Status.Handshakes).
func (h *hsTable) len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

// evicted returns the number of evictions (Status.HandshakeEvictions).
func (h *hsTable) evicted() uint64 { return h.evictions.Load() }

// slTable counts the sessionless (probe) carriers a passive Runtime holds,
// per dialer InstanceID and in total (plan §3.5, design §6.4). When a cap
// is reached the new carrier is refused with CLOSE(capacity); existing ones
// are never evicted.
type slTable struct {
	mu       sync.Mutex
	perMax   int
	totalMax int
	per      map[InstanceID]int
	total    int
}

// newSLTable returns an empty table with the two caps (≥ 1).
func newSLTable(perInstance, total int) *slTable {
	return &slTable{perMax: perInstance, totalMax: total, per: make(map[InstanceID]int)}
}

// acquire counts one more probe carrier of dialer inst, or returns false
// when inst already holds perMax or the Runtime totalMax.
func (t *slTable) acquire(inst InstanceID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.total >= t.totalMax || t.per[inst] >= t.perMax {
		return false
	}
	t.per[inst]++
	t.total++
	return true
}

// release uncounts one probe carrier of inst (at its Done). Releasing an
// instance that holds none is ignored.
func (t *slTable) release(inst InstanceID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.per[inst]
	if n == 0 {
		return
	}
	if n == 1 {
		delete(t.per, inst) // the map holds only instances with carriers
	} else {
		t.per[inst] = n - 1
	}
	t.total--
}

// len returns the probe carriers held (Status.Sessionless).
func (t *slTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

// held returns the probe carriers held for inst and the number of
// instances with at least one (tests, diagnostics).
func (t *slTable) held(inst InstanceID) (n, instances int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.per[inst], len(t.per)
}
