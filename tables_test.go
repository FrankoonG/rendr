package rendr

import (
	"encoding/binary"
	"math"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// tblSess stands in for *session.Session: a non-zero-size type, so
// distinct handles never compare equal.
type tblSess struct{ id int }

var tblDialer = InstanceID{0xd1}

func tblSID(i int) SessionID {
	var sid SessionID
	binary.BigEndian.PutUint64(sid[8:], uint64(i)+1)
	return sid
}

func tblKey(i int) tableKey { return passiveKey(tblDialer, tblSID(i)) }

var tblNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// admitPassive is the admission sequence of design §6.2 for one OPEN:
// reserve a unit, insert-or-get, release the unit when another entry won.
func admitPassive(t *testing.T, tab *sessionTable[*tblSess], k tableKey, s *tblSess, ttl time.Duration, now time.Time) {
	t.Helper()
	if !tab.reserve() {
		t.Fatalf("no MaxSessions unit for %v", k)
	}
	if _, ins := tab.insertOrGet(k, s, ttl, now); !ins {
		tab.unreserve()
		t.Fatalf("key %v already present", k)
	}
}

// TestSessionTableOneWinner_L47 races 64 goroutines admitting the same
// (dialer InstanceID, sid) at once, over 50 keys: each round has exactly
// one inserted session, every loser is handed that same session, and the
// losers' reservations are returned, so the units in use equal the number
// of keys (no unstarted loser leaks a MaxSessions unit, C8).
func TestSessionTableOneWinner_L47(t *testing.T) {
	const rounds, racers = 50, 64
	tab := newSessionTable[*tblSess](rounds * racers) // every racer gets a unit
	for round := 0; round < rounds; round++ {
		k := tblKey(round)
		start := make(chan struct{})
		var ready, wg sync.WaitGroup
		type outcome struct {
			mine     *tblSess
			got      *tblSess
			inserted bool
			reserved bool
		}
		out := make([]outcome, racers)
		for g := 0; g < racers; g++ {
			ready.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				mine := &tblSess{id: round*racers + g}
				ready.Done()
				<-start
				if !tab.reserve() {
					t.Error("no MaxSessions unit")
					return
				}
				r, ins := tab.insertOrGet(k, mine, time.Minute, tblNow)
				if !ins {
					tab.unreserve()
				}
				out[g] = outcome{mine: mine, got: r.sess, inserted: ins, reserved: true}
			}()
		}
		ready.Wait()
		close(start) // stimulus: all 64 admissions released together
		wg.Wait()
		var winner *tblSess
		reservedRacers := 0
		for _, o := range out {
			if !o.reserved {
				continue
			}
			reservedRacers++
			if o.inserted {
				if winner != nil {
					t.Fatalf("round %d: two sessions inserted for one key", round)
				}
				winner = o.mine
			}
		}
		if winner == nil || reservedRacers != racers {
			t.Fatalf("round %d: winner %v after %d of %d racers", round, winner, reservedRacers, racers)
		}
		for g, o := range out {
			if o.reserved && o.got != winner {
				t.Fatalf("round %d racer %d: handed %v, want the winner %v", round, g, o.got, winner)
			}
		}
		if r := tab.lookup(k, tblNow); !r.found || r.tomb || r.sess != winner {
			t.Fatalf("round %d: table holds %+v, want the winner", round, r)
		}
		if n := tab.inUse(); n != round+1 {
			t.Fatalf("round %d: %d units in use, want %d (a loser leaked its reservation)", round, n, round+1)
		}
	}
	if c := tab.counts(tblNow); c.Pending != rounds || c.Open != 0 || c.Tombstones != 0 {
		t.Fatalf("counts %+v, want %d pending", c, rounds)
	}
}

// TestSessionTableTombstoneVerdicts_L47 checks design §6.5: a passive
// session that opened answers UNKNOWN_SESSION; one that never opened
// repeats its verdict (REJECTED with code and message, CAPACITY with its
// reason, GOING_AWAY); a withdrawn one answers UNKNOWN_SESSION; a
// tombstone is never replaced by a new session while it lives (no
// resurrection); stale updates are ignored; a dialer session leaves no
// tombstone.
func TestSessionTableTombstoneVerdicts_L47(t *testing.T) {
	tab := newSessionTable[*tblSess](16)
	cases := []struct {
		name   string
		opened bool
		v      session.Verdict
		want   wire.OpenAck
	}{
		{"opened", true, session.Verdict{Opened: true}, wire.OpenAck{Status: wire.StatusUnknownSession}},
		{"rejected", false, session.Verdict{Status: wire.StatusRejected, Code: 7, Msg: "no route"},
			wire.OpenAck{Status: wire.StatusRejected, Code: 7, Msg: []byte("no route")}},
		{"accept timeout", false, session.Verdict{Status: wire.StatusCapacity, Code: wire.CodeAcceptTimeout},
			wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeAcceptTimeout}},
		{"going away", false, session.Verdict{Status: wire.StatusGoingAway},
			wire.OpenAck{Status: wire.StatusGoingAway}},
		{"withdrawn", false, session.Verdict{Status: wire.StatusUnknownSession},
			wire.OpenAck{Status: wire.StatusUnknownSession}},
	}
	for i, tc := range cases {
		k, s := tblKey(i), &tblSess{id: i}
		admitPassive(t, tab, k, s, time.Minute, tblNow)
		if tc.opened && !tab.opened(k, s) {
			t.Fatalf("%s: opened not applied", tc.name)
		}
		if !tab.ended(k, s, tc.v, tblNow) {
			t.Fatalf("%s: ended not applied", tc.name)
		}
		r := tab.lookup(k, tblNow.Add(time.Second))
		if !r.found || !r.tomb || r.sess != nil {
			t.Fatalf("%s: lookup %+v, want a tombstone holding no session", tc.name, r)
		}
		if a := r.verdict.OpenAck(); a.Status != tc.want.Status || a.Code != tc.want.Code || string(a.Msg) != string(tc.want.Msg) {
			t.Fatalf("%s: tombstone answers %+v, want %+v", tc.name, a, tc.want)
		}
		// A retried OPEN finds the tombstone; the session never resurrects.
		if !tab.reserve() {
			t.Fatal("no unit")
		}
		r2, ins := tab.insertOrGet(k, &tblSess{id: 100 + i}, time.Minute, tblNow.Add(time.Second))
		tab.unreserve()
		if ins || !r2.tomb || r2.verdict != r.verdict {
			t.Fatalf("%s: retried OPEN inserted %v / %+v, want the tombstone", tc.name, ins, r2)
		}
		// Stale updates of the ended session change nothing.
		if tab.opened(k, s) || tab.setLingering(k, s, true) || tab.setOrphaned(k, s, true) || tab.ended(k, s, session.Verdict{}, tblNow) {
			t.Fatalf("%s: a stale update was applied to a tombstone", tc.name)
		}
	}
	if c := tab.counts(tblNow); c.Tombstones != len(cases) || c.Open+c.Pending+c.Lingering+c.Orphaned != 0 || tab.inUse() != 0 {
		t.Fatalf("counts %+v, units %d", c, tab.inUse())
	}
	// A dialer session's end leaves no tombstone and returns its unit.
	sid := tblSID(99)
	ds := &tblSess{id: 99}
	if !tab.placeDialer(sid) || !tab.attach(sid, ds) {
		t.Fatal("dialer session not placed")
	}
	if !tab.ended(dialerKey(sid), ds, session.Verdict{Opened: true}, tblNow) {
		t.Fatal("dialer end not applied")
	}
	if r := tab.lookup(dialerKey(sid), tblNow); r.found || tab.inUse() != 0 {
		t.Fatalf("dialer end left %+v, units %d", r, tab.inUse())
	}
	// The dialer key space is separate from the passive one: a Runtime that
	// dials itself holds both entries for the same sid.
	if !tab.placeDialer(tblSID(0)) {
		t.Fatal("a dialer key collided with a passive key")
	}
}

// TestSessionTableTombstoneTTL_L47 checks expiry: a tombstone answers until
// exactly TombstoneTTL after the end and is absent from then on (a new
// session may then use the key); Status counts exactly the unexpired
// tombstones even when the oldest lives longest (the expiry heap, not the
// FIFO, decides).
func TestSessionTableTombstoneTTL_L47(t *testing.T) {
	tab := newSessionTable[*tblSess](16)
	k, s := tblKey(0), &tblSess{}
	admitPassive(t, tab, k, s, 10*time.Second, tblNow)
	tab.ended(k, s, session.Verdict{Status: wire.StatusRejected, Code: 1}, tblNow)
	if r := tab.lookup(k, tblNow.Add(10*time.Second-1)); !r.tomb {
		t.Fatalf("tombstone gone before its TTL: %+v", r)
	}
	if c := tab.counts(tblNow.Add(10*time.Second - 1)); c.Tombstones != 1 {
		t.Fatalf("counts before expiry %+v", c)
	}
	if r := tab.lookup(k, tblNow.Add(10*time.Second)); r.found {
		t.Fatalf("expired tombstone still answers: %+v", r)
	}
	if c := tab.counts(tblNow.Add(10 * time.Second)); c.Tombstones != 0 {
		t.Fatalf("counts after expiry %+v", c)
	}
	s2 := &tblSess{id: 2}
	admitPassive(t, tab, k, s2, 10*time.Second, tblNow.Add(11*time.Second))
	if r := tab.lookup(k, tblNow.Add(11*time.Second)); r.sess != s2 || r.tomb {
		t.Fatalf("new session after expiry: %+v", r)
	}

	// Mixed TTLs: the oldest tombstone lives 100 s, five later ones 1 s.
	tab = newSessionTable[*tblSess](16)
	for i := 0; i < 6; i++ {
		ttl := time.Second
		if i == 0 {
			ttl = 100 * time.Second
		}
		ki, si := tblKey(i), &tblSess{id: i}
		admitPassive(t, tab, ki, si, ttl, tblNow)
		tab.ended(ki, si, session.Verdict{Opened: true}, tblNow.Add(time.Duration(i)*time.Millisecond))
	}
	if c := tab.counts(tblNow.Add(500 * time.Millisecond)); c.Tombstones != 6 {
		t.Fatalf("before the short TTLs: %+v", c)
	}
	if c := tab.counts(tblNow.Add(2 * time.Second)); c.Tombstones != 1 {
		t.Fatalf("after the short TTLs: %+v, want only the long-lived oldest", c)
	}
	if !tab.lookup(tblKey(0), tblNow.Add(2*time.Second)).tomb || tab.lookup(tblKey(3), tblNow.Add(2*time.Second)).found {
		t.Fatal("wrong tombstones survived")
	}
	// An expired tombstone found by lookup first and then replaced by a new
	// session is not deleted by the later index prune (pointer guard).
	tab = newSessionTable[*tblSess](16)
	admitPassive(t, tab, k, s, time.Second, tblNow)
	tab.ended(k, s, session.Verdict{Opened: true}, tblNow)
	if tab.lookup(k, tblNow.Add(time.Second)).found {
		t.Fatal("expired tombstone found")
	}
	admitPassive(t, tab, k, s2, time.Second, tblNow.Add(time.Second))
	if c := tab.counts(tblNow.Add(time.Hour)); c.Tombstones != 0 || c.Pending != 1 {
		t.Fatalf("counts %+v", c)
	}
	if r := tab.lookup(k, tblNow.Add(time.Hour)); r.sess != s2 {
		t.Fatalf("the prune deleted the new session: %+v", r)
	}
}

// TestSessionTableTombstoneRingCap_L47 checks the bound of plan §3.7:
// tombstones are capped at 2×MaxSessions Runtime-wide, the oldest is
// dropped first (FIFO), expired ones are pruned before the cap evicts a
// live one, and memory returns once they are gone.
func TestSessionTableTombstoneRingCap_L47(t *testing.T) {
	const maxSessions = 3 // cap 6
	tab := newSessionTable[*tblSess](maxSessions)
	for i := 0; i < 10; i++ {
		k, s := tblKey(i), &tblSess{id: i}
		admitPassive(t, tab, k, s, time.Hour, tblNow)
		tab.ended(k, s, session.Verdict{Status: wire.StatusRejected, Code: uint32(i)}, tblNow)
		if n := tab.tombs.len(); n != min(i+1, 2*maxSessions) {
			t.Fatalf("after %d ends: %d tombstones, want %d", i+1, n, min(i+1, 2*maxSessions))
		}
	}
	var want []tableKey
	for i := 4; i < 10; i++ {
		want = append(want, tblKey(i))
	}
	if got := tab.tombs.order(); !slices.Equal(got, want) {
		t.Fatalf("FIFO order %v, want the newest 6 oldest first", got)
	}
	for i := 0; i < 10; i++ {
		r := tab.lookup(tblKey(i), tblNow)
		if (i >= 4) != r.tomb || (r.tomb && r.verdict.Code != uint32(i)) {
			t.Fatalf("key %d: %+v (evicted iff among the 4 oldest)", i, r)
		}
	}
	if c := tab.counts(tblNow); c.Tombstones != 6 || tab.inUse() != 0 {
		t.Fatalf("counts %+v units %d", c, tab.inUse())
	}
	// Expired tombstones leave first: with all six expired, six new ones
	// fit without evicting each other.
	later := tblNow.Add(2 * time.Hour)
	for i := 10; i < 16; i++ {
		k, s := tblKey(i), &tblSess{id: i}
		admitPassive(t, tab, k, s, time.Hour, later)
		tab.ended(k, s, session.Verdict{Opened: true}, later)
	}
	if c := tab.counts(later); c.Tombstones != 6 {
		t.Fatalf("after expiry and refill: %+v", c)
	}
	for i := 10; i < 16; i++ {
		if !tab.lookup(tblKey(i), later).tomb {
			t.Fatalf("new tombstone %d evicted", i)
		}
	}
	for i := 4; i < 10; i++ {
		if tab.lookup(tblKey(i), later).found {
			t.Fatalf("expired tombstone %d still present", i)
		}
	}
	// Everything gone after the last TTL: the shard maps are empty.
	tab.counts(later.Add(2 * time.Hour))
	for i := range tab.shards {
		if n := len(tab.shards[i].m); n != 0 {
			t.Fatalf("shard %d still holds %d entries", i, n)
		}
	}
}

// TestSessionTableHugeMaxSessions: an unclamped override MaxSessions near
// math.MaxInt (a test meaning "unlimited") saturates the 2×MaxSessions
// tombstone cap instead of overflowing it to a negative value, which would
// evict each new tombstone at once and then dereference the empty FIFO.
// As a backstop, an index with a non-positive limit only evicts what it
// holds.
func TestSessionTableHugeMaxSessions(t *testing.T) {
	for _, c := range []struct{ maxSessions, limit int }{
		{math.MaxInt, math.MaxInt},
		{math.MaxInt/2 + 1, math.MaxInt},
		{math.MaxInt / 2, math.MaxInt - 1},
		{1 << 20, 2 << 20},
	} {
		tab := newSessionTable[*tblSess](c.maxSessions)
		if tab.tombs.limit != c.limit {
			t.Fatalf("MaxSessions %d: tombstone cap %d, want %d", c.maxSessions, tab.tombs.limit, c.limit)
		}
		for i := 0; i < 3; i++ {
			k, s := tblKey(i), &tblSess{id: i}
			admitPassive(t, tab, k, s, time.Minute, tblNow)
			if !tab.ended(k, s, session.Verdict{Opened: true}, tblNow) {
				t.Fatalf("MaxSessions %d: end %d not applied", c.maxSessions, i)
			}
		}
		if n := tab.counts(tblNow).Tombstones; n != 3 || !tab.lookup(tblKey(0), tblNow).tomb {
			t.Fatalf("MaxSessions %d: %d tombstones kept, want 3 including the oldest", c.maxSessions, n)
		}
	}
	x := &tombIndex[*tblSess]{limit: -1}
	e := &tableEntry[*tblSess]{key: tblKey(0), tomb: true, expiry: tblNow.Add(time.Hour), heapIdx: -1}
	if v := x.push(e, tblNow); len(v) != 1 || v[0] != e || x.len() != 0 || x.head != nil || len(x.h) != 0 {
		t.Fatalf("push into a non-positive limit: victims %d, len %d", len(v), x.len())
	}
}

// TestSessionTableCategories checks the disjoint SessionCounts categories
// (precedence pending > lingering > orphaned > open), the MaxSessions units
// shared by both roles, and that updates of another session's entry are
// ignored (stale generation).
func TestSessionTableCategories(t *testing.T) {
	tab := newSessionTable[*tblSess](3)
	expect := func(step string, open, pending, lingering, orphaned int) {
		t.Helper()
		c := tab.counts(tblNow)
		if c.Open != open || c.Pending != pending || c.Lingering != lingering || c.Orphaned != orphaned {
			t.Fatalf("%s: counts %+v, want open %d pending %d lingering %d orphaned %d", step, c, open, pending, lingering, orphaned)
		}
	}
	k, s := tblKey(1), &tblSess{id: 1}
	admitPassive(t, tab, k, s, time.Minute, tblNow)
	expect("admitted", 0, 1, 0, 0)
	tab.setOrphaned(k, s, true) // a pending session's episode does not leave pending
	expect("pending orphaned", 0, 1, 0, 0)
	tab.setOrphaned(k, s, false)
	if tab.opened(k, &tblSess{id: 1}) {
		t.Fatal("an update for another session's entry was applied")
	}
	tab.opened(k, s)
	expect("opened", 1, 0, 0, 0)
	tab.setOrphaned(k, s, true)
	expect("orphaned", 0, 0, 0, 1)
	tab.setLingering(k, s, true)
	expect("lingering and orphaned", 0, 0, 1, 0)
	tab.setOrphaned(k, s, false)
	expect("lingering", 0, 0, 1, 0)
	tab.setLingering(k, s, false)
	expect("open again", 1, 0, 0, 0)

	sid := tblSID(7)
	ds := &tblSess{id: 7}
	if !tab.placeDialer(sid) {
		t.Fatal("dialer not placed")
	}
	expect("dialling", 1, 0, 0, 0) // a dialling session holds a unit but no category
	if tab.inUse() != 2 {
		t.Fatalf("units %d, want 2", tab.inUse())
	}
	tab.attach(sid, ds)
	expect("dialer open", 2, 0, 0, 0)
	tab.setLingering(dialerKey(sid), ds, true)
	expect("dialer lingering", 1, 0, 1, 0)

	if !tab.reserve() || tab.reserve() {
		t.Fatal("MaxSessions 3 must admit exactly one more unit")
	}
	tab.unreserve()
	if !tab.placeDialer(tblSID(8)) || tab.placeDialer(tblSID(9)) {
		t.Fatal("placeDialer must respect MaxSessions")
	}
	tab.ended(dialerKey(tblSID(8)), nil, session.Verdict{}, tblNow) // Dial failed
	tab.ended(dialerKey(sid), ds, session.Verdict{}, tblNow)
	tab.ended(k, s, session.Verdict{Opened: true}, tblNow)
	expect("all ended", 0, 0, 0, 0)
	if tab.inUse() != 0 {
		t.Fatalf("units %d after every end", tab.inUse())
	}
}

// TestSessionTableDialerPlaceholder checks the dialer's opening-phase
// races: the session's own end may come before or after Peer.Dial attaches
// it, and Dial's failure path may race the session's end; in every order
// exactly one end releases the unit and nothing is counted twice.
func TestSessionTableDialerPlaceholder(t *testing.T) {
	tab := newSessionTable[*tblSess](4)
	// End (from the session) before attach: attach reports the session gone.
	sid, s := tblSID(1), &tblSess{id: 1}
	tab.placeDialer(sid)
	if !tab.ended(dialerKey(sid), s, session.Verdict{}, tblNow) {
		t.Fatal("the session's end did not remove its placeholder")
	}
	if tab.attach(sid, s) {
		t.Fatal("attach succeeded after the session ended")
	}
	if tab.ended(dialerKey(sid), nil, session.Verdict{}, tblNow) {
		t.Fatal("Dial's failure path removed an entry twice")
	}
	// Failure path first, then the session's own end: one release.
	sid2, s2 := tblSID(2), &tblSess{id: 2}
	tab.placeDialer(sid2)
	tab.ended(dialerKey(sid2), nil, session.Verdict{}, tblNow)
	if tab.ended(dialerKey(sid2), s2, session.Verdict{}, tblNow) {
		t.Fatal("ended twice")
	}
	// Attached: only the attached session may end it.
	sid3, s3 := tblSID(3), &tblSess{id: 3}
	tab.placeDialer(sid3)
	tab.attach(sid3, s3)
	if tab.attach(sid3, s3) {
		t.Fatal("attached twice")
	}
	if tab.ended(dialerKey(sid3), nil, session.Verdict{}, tblNow) || tab.ended(dialerKey(sid3), &tblSess{id: 3}, session.Verdict{}, tblNow) {
		t.Fatal("an attached entry ended by another handle")
	}
	if c := tab.counts(tblNow); c.Open != 1 || tab.inUse() != 1 {
		t.Fatalf("counts %+v units %d", c, tab.inUse())
	}
	tab.ended(dialerKey(sid3), s3, session.Verdict{}, tblNow)
	if c := tab.counts(tblNow); c.Open != 0 || tab.inUse() != 0 {
		t.Fatalf("counts %+v units %d", c, tab.inUse())
	}
}

// TestSessionTableLive checks the Runtime.Close enumeration: every live
// session of both roles, no placeholder, no tombstone.
func TestSessionTableLive(t *testing.T) {
	tab := newSessionTable[*tblSess](64)
	var want []*tblSess
	for i := 0; i < 20; i++ {
		s := &tblSess{id: i}
		admitPassive(t, tab, tblKey(i), s, time.Minute, tblNow)
		if i%4 == 0 {
			tab.ended(tblKey(i), s, session.Verdict{Opened: true}, tblNow)
		} else {
			want = append(want, s)
		}
	}
	for i := 20; i < 25; i++ {
		s := &tblSess{id: i}
		tab.placeDialer(tblSID(i))
		if i != 24 {
			tab.attach(tblSID(i), s)
			want = append(want, s)
		}
	}
	got := tab.live()
	sortByID := func(a, b *tblSess) int { return a.id - b.id }
	slices.SortFunc(got, sortByID)
	slices.SortFunc(want, sortByID)
	if !slices.Equal(got, want) {
		t.Fatalf("live %d sessions, want %d", len(got), len(want))
	}
}

// TestSessionTableConcurrentLifecycles runs 64 goroutines through full
// passive and dialer lifecycles on distinct keys while others read Status
// (-race): every unit is returned and the categories end at zero.
func TestSessionTableConcurrentLifecycles(t *testing.T) {
	const workers, perWorker = 64, 50
	tab := newSessionTable[*tblSess](workers * perWorker)
	var wg, readerDone sync.WaitGroup
	stop := make(chan struct{})
	var reads atomic.Int64
	readerDone.Add(1)
	go func() {
		defer readerDone.Done()
		for {
			select {
			case <-stop:
				return
			default:
				c := tab.counts(tblNow)
				if c.Open < 0 || c.Pending < 0 || c.Lingering < 0 || c.Orphaned < 0 {
					t.Errorf("negative count %+v", c)
					return
				}
				reads.Add(1)
			}
		}
	}()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				n := w*perWorker + i
				s := &tblSess{id: n}
				if n%2 == 0 {
					k := tblKey(n)
					if !tab.reserve() {
						t.Error("no unit")
						return
					}
					if _, ins := tab.insertOrGet(k, s, time.Minute, tblNow); !ins {
						t.Error("duplicate key")
						return
					}
					tab.opened(k, s)
					tab.setOrphaned(k, s, true)
					tab.setLingering(k, s, true)
					tab.setOrphaned(k, s, false)
					tab.ended(k, s, session.Verdict{Opened: true}, tblNow)
				} else {
					sid := tblSID(n)
					if !tab.placeDialer(sid) {
						t.Error("no dialer unit")
						return
					}
					tab.attach(sid, s)
					tab.setLingering(dialerKey(sid), s, true)
					tab.ended(dialerKey(sid), s, session.Verdict{}, tblNow)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	readerDone.Wait()
	c := tab.counts(tblNow)
	if c.Open+c.Pending+c.Lingering+c.Orphaned != 0 || tab.inUse() != 0 || c.Tombstones != workers*perWorker/2 {
		t.Fatalf("after all lifecycles: %+v units %d", c, tab.inUse())
	}
	if reads.Load() == 0 {
		t.Fatal("no concurrent Status read happened")
	}
}

// hsConn stands in for an accepted conn (never called).
type hsConn struct {
	net.Conn
	id int
}

// TestHandshakeSlotsEvictOldest_L48 checks the handshake LRU of plan §3.5:
// a full table evicts the oldest unfinished handshake (never refusing the
// new one) and counts it; a released slot leaves the LRU at once; release
// tells a handshake whether it was evicted; drain hands back every
// unfinished one oldest first.
func TestHandshakeSlotsEvictOldest_L48(t *testing.T) {
	h := newHSTable(3)
	c := make([]*hsConn, 8)
	s := make([]*hsSlot, 8)
	for i := range c {
		c[i] = &hsConn{id: i}
	}
	for i := 0; i < 3; i++ {
		var ev net.Conn
		if s[i], ev = h.admit(c[i]); ev != nil {
			t.Fatalf("admit %d evicted %v below the limit", i, ev)
		}
	}
	admitEvicts := func(i, want int) {
		t.Helper()
		var ev net.Conn
		s[i], ev = h.admit(c[i])
		if ev != c[want] {
			t.Fatalf("admit %d evicted %v, want conn %d", i, ev, want)
		}
	}
	admitEvicts(3, 0)
	admitEvicts(4, 1)
	if !h.release(s[2]) { // finished handshake: its slot is free
		t.Fatal("release of a held slot failed")
	}
	if h.release(s[2]) {
		t.Fatal("released twice")
	}
	if _, ev := h.admit(c[5]); ev != nil {
		t.Fatalf("admit into a released slot evicted %v", ev)
	}
	admitEvicts(6, 3)
	if h.release(s[0]) || h.release(s[1]) || h.release(s[3]) {
		t.Fatal("an evicted handshake was told it still holds its slot")
	}
	if h.len() != 3 || h.evicted() != 3 {
		t.Fatalf("len %d evictions %d, want 3 and 3", h.len(), h.evicted())
	}
	got := h.drain()
	if want := []net.Conn{c[4], c[5], c[6]}; !slices.Equal(got, want) {
		t.Fatalf("drain %v, want conns 4, 5, 6", got)
	}
	if h.len() != 0 || h.release(s[4]) {
		t.Fatal("drain left a slot held")
	}
	if _, ev := h.admit(c[7]); ev != nil || h.len() != 1 {
		t.Fatal("the table is unusable after drain")
	}
}

// TestHandshakeSlotsConcurrent_L48 admits and releases from 64 goroutines
// into 8 slots: every conn ends exactly once — released by its handshake
// or handed out by exactly one eviction — the evictions counter matches,
// and the table never exceeds its limit. The stimulus does not depend on
// parallel scheduling: in a fill phase every worker holds its first slot
// until all 64 have admitted once, so 64 admissions meet 8 slots and
// exactly 56 evictions happen before any release, at any GOMAXPROCS; the
// churn that follows mixes admissions, evictions and releases.
func TestHandshakeSlotsConcurrent_L48(t *testing.T) {
	const workers, each, slots = 64, 200, 8
	h := newHSTable(slots)
	var evictedBy sync.Map
	var released, evictedSeen, overLimit atomic.Int64
	admit := func(c *hsConn) *hsSlot {
		s, ev := h.admit(c)
		if ev != nil {
			if _, dup := evictedBy.LoadOrStore(ev, true); dup {
				t.Error("a conn was evicted twice")
			}
			evictedSeen.Add(1)
		}
		if h.len() > slots {
			overLimit.Add(1)
		}
		return s
	}
	release := func(s *hsSlot) {
		if h.release(s) {
			released.Add(1)
		}
	}
	var wg, filled sync.WaitGroup
	gate := make(chan struct{})
	filled.Add(workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first := admit(&hsConn{id: w * each})
			filled.Done()
			<-gate // hold the first slot until every worker admitted once
			release(first)
			for i := 1; i < each; i++ {
				release(admit(&hsConn{id: w*each + i}))
			}
		}()
	}
	filled.Wait()
	held, fillEvictions := h.len(), h.evicted()
	close(gate)
	wg.Wait()
	// Stimulus: the fill phase reached the limit — 8 held, 56 evicted.
	if held != slots || fillEvictions != workers-slots {
		t.Fatalf("after the fill phase: %d slots held, %d evictions; want %d and %d", held, fillEvictions, slots, workers-slots)
	}
	if overLimit.Load() != 0 {
		t.Fatalf("the table exceeded %d slots %d times", slots, overLimit.Load())
	}
	if total := released.Load() + evictedSeen.Load(); total != workers*each {
		t.Fatalf("released %d + evicted %d = %d conns, want %d (each exactly once)", released.Load(), evictedSeen.Load(), total, workers*each)
	}
	if h.evicted() != uint64(evictedSeen.Load()) || h.len() != 0 {
		t.Fatalf("evictions counter %d, seen %d, len %d", h.evicted(), evictedSeen.Load(), h.len())
	}
	if evictedSeen.Load() < workers-slots {
		t.Fatalf("%d evictions, want at least %d", evictedSeen.Load(), workers-slots)
	}
}

// TestSessionlessCaps_L48 checks the sessionless limits of plan §3.5: per
// dialer instance and per Runtime, refusing new carriers (never evicting),
// and releasing at Done.
func TestSessionlessCaps_L48(t *testing.T) {
	sl := newSLTable(2, 3)
	a, b, c := InstanceID{1}, InstanceID{2}, InstanceID{3}
	if !sl.acquire(a) || !sl.acquire(a) {
		t.Fatal("instance a below its limit refused")
	}
	if sl.acquire(a) {
		t.Fatal("instance a beyond PerInstance admitted")
	}
	if !sl.acquire(b) {
		t.Fatal("instance b refused below the total")
	}
	if sl.acquire(c) {
		t.Fatal("instance c admitted beyond Total")
	}
	if n, inst := sl.held(a); n != 2 || inst != 2 || sl.len() != 3 {
		t.Fatalf("held a %d instances %d total %d", n, inst, sl.len())
	}
	sl.release(a)
	if !sl.acquire(c) {
		t.Fatal("instance c refused after a release")
	}
	sl.release(b)
	if n, inst := sl.held(b); n != 0 || inst != 2 {
		t.Fatalf("released instance kept: held %d instances %d", n, inst)
	}
	sl.release(b) // over-release is ignored
	if sl.len() != 2 {
		t.Fatalf("total %d after an over-release", sl.len())
	}
	sl.release(a)
	sl.release(c)
	if n, inst := sl.held(a); sl.len() != 0 || n != 0 || inst != 0 {
		t.Fatalf("total %d instances %d after releasing everything", sl.len(), inst)
	}
}

// TestKeyFor checks the Registry's key derivation: a passive session is
// keyed by its dialer's instance, a dialer session by its sid alone.
func TestKeyFor(t *testing.T) {
	inst, sid := InstanceID{7}, tblSID(3)
	if k := keyFor(session.RolePassive, inst, sid); k != passiveKey(inst, sid) {
		t.Fatalf("passive key %+v", k)
	}
	if k := keyFor(session.RoleDialer, inst, sid); k != dialerKey(sid) || k == passiveKey(inst, sid) {
		t.Fatalf("dialer key %+v", k)
	}
}
