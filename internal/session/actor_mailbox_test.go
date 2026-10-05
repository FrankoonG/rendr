package session

import (
	"sync"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// Mailbox unit tests (design §3.4). Every test runs inside a synctest bubble
// with the mailbox made in that bubble: a post or ring that blocked on the
// doorbell would leave every goroutine of the bubble durably blocked, so the
// test fails at once as a bubble deadlock instead of hanging until the test
// binary's timeout.

// mbNew returns an initialized mailbox; made inside a bubble, its doorbell
// belongs to that bubble.
func mbNew() *mailbox {
	m := new(mailbox)
	m.init()
	return m
}

// mbTakeToken consumes the doorbell token without blocking and reports
// whether there was one.
func mbTakeToken(m *mailbox) bool {
	select {
	case <-m.bell:
		return true
	default:
		return false
	}
}

func TestMailboxPostDrainInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := mbNew()
		want := []command{
			&dialResult{slot: 1, attempt: 7},
			&adopt{kind: adoptJoin},
			&confirm{reply: make(chan error, 1)},
			&refuse{reply: make(chan bool, 1)},
			&shutdown{},
		}
		for i, c := range want {
			if !m.post(c) {
				t.Fatalf("post %d refused by an open mailbox", i)
			}
		}
		if !mbTakeToken(m) {
			t.Fatal("post did not ring the doorbell")
		}
		if mbTakeToken(m) {
			t.Fatal("five posts left more than one doorbell token")
		}

		prior := &withdraw{}
		got := m.drain([]command{prior})
		if len(got) != 1+len(want) || got[0] != prior {
			t.Fatalf("drain returned %d commands (first %T), want the prior entry plus %d", len(got), got[0], len(want))
		}
		for i, c := range want {
			if got[1+i] != c {
				t.Fatalf("drained command %d is %T %p, want %T %p (arrival order)", i, got[1+i], got[1+i], c, c)
			}
		}
		// The mailbox keeps no reference to drained commands.
		for i, c := range m.cmds[:cap(m.cmds)] {
			if c != nil {
				t.Fatalf("backing array slot %d still references %T after drain", i, c)
			}
		}
		if again := m.drain(nil); len(again) != 0 {
			t.Fatalf("second drain returned %d commands, want 0", len(again))
		}
		if mbTakeToken(m) {
			t.Fatal("drain rang the doorbell")
		}

		// The emptied queue is reused: later posts drain in order too.
		a, b := &adopt{kind: adoptOpen}, &reject{code: 3, msg: "no", reply: make(chan error, 1)}
		m.post(a)
		m.post(b)
		if got := m.drain(nil); len(got) != 2 || got[0] != a || got[1] != b {
			t.Fatalf("drain after reuse returned %v, want [%p %p]", got, a, b)
		}
	})
}

func TestMailboxRingCoalescesAndNeverBlocks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := mbNew()
		for range 1000 {
			m.ring()
		}
		var d carrier.Doorbell = m
		d.Ring()
		if !mbTakeToken(m) {
			t.Fatal("ring left no token")
		}
		if mbTakeToken(m) {
			t.Fatal("1001 rings left more than one token")
		}

		// Concurrent rings from many goroutines with nobody receiving: none
		// blocks (a blocked ringer would deadlock the bubble, since Wait is
		// durably blocking for a WaitGroup used in it), and exactly one token
		// remains.
		const ringers = 8
		var wg sync.WaitGroup
		for range ringers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 1000 {
					m.ring()
				}
			}()
		}
		wg.Wait()
		if !mbTakeToken(m) || mbTakeToken(m) {
			t.Fatal("concurrent rings did not leave exactly one token")
		}
	})
}

func TestMailboxPostAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := mbNew()
		a := &adopt{kind: adoptOpen}
		if !m.post(a) {
			t.Fatal("post refused by an open mailbox")
		}
		mbTakeToken(m)

		rest := m.close()
		if len(rest) != 1 || rest[0] != a {
			t.Fatalf("close returned %v, want the queued %p for cleanup", rest, a)
		}
		b := &adopt{kind: adoptJoin}
		if m.post(b) {
			t.Fatal("post accepted after close: its conn would leak")
		}
		if mbTakeToken(m) {
			t.Fatal("a refused post rang the doorbell")
		}
		if got := m.drain(nil); len(got) != 0 {
			t.Fatalf("drain after close returned %d commands, want 0", len(got))
		}
		if again := m.close(); again != nil {
			t.Fatalf("second close returned %v, want nil", again)
		}
		// Still non-blocking and coalescing after close: the second ring
		// finds the doorbell full.
		m.ring()
		m.ring()
		if !mbTakeToken(m) || mbTakeToken(m) {
			t.Fatal("rings after close did not leave exactly one token")
		}
	})
}

// TestMailboxCloseRacingPosts checks the F9 property: posts racing the
// actor's drains and its final close are each either handed to the actor
// exactly once or refused, never both and never neither.
func TestMailboxCloseRacingPosts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			posters  = 8
			maxPosts = 4096 // bounds memory if the closer is slow to run
		)
		m := mbNew()
		accepted := make([][]command, posters)
		refused := make([]command, posters)
		closed := make(chan struct{}) // closed right after m.close
		var started, finished sync.WaitGroup
		started.Add(posters)
		for g := range posters {
			finished.Add(1)
			go func() {
				defer finished.Done()
				for i := 0; ; i++ {
					if i == maxPosts {
						<-closed // capped: the next post is after close and must fail
					}
					c := &dialResult{slot: g, attempt: uint64(i)}
					if !m.post(c) {
						refused[g] = c
						return
					}
					accepted[g] = append(accepted[g], c)
					if i == 0 {
						started.Done()
					}
					if i == maxPosts {
						return // accepted after close: reported below as "never refused"
					}
				}
			}()
		}
		allStarted := make(chan struct{})
		go func() {
			started.Wait()
			close(allStarted)
		}()

		// The actor: drain on every ring until every poster got its first
		// post in, then close while they keep posting.
		var seen []command
		for waiting := true; waiting; {
			select {
			case <-m.bell:
				seen = m.drain(seen)
			case <-allStarted:
				waiting = false
			}
		}
		seen = append(seen, m.close()...)
		close(closed)
		finished.Wait()

		count := make(map[command]int, len(seen))
		for _, c := range seen {
			count[c]++
		}
		total := 0
		for g := range posters {
			if len(accepted[g]) == 0 {
				t.Fatalf("poster %d had no accepted post before close", g)
			}
			if refused[g] == nil {
				t.Fatalf("poster %d was never refused", g)
			}
			if count[refused[g]] != 0 {
				t.Fatalf("poster %d: refused command was also handed to the actor", g)
			}
			for i, c := range accepted[g] {
				if count[c] != 1 {
					t.Fatalf("poster %d: accepted command %d handed to the actor %d times, want 1", g, i, count[c])
				}
			}
			total += len(accepted[g])
		}
		if len(seen) != total {
			t.Fatalf("actor saw %d commands, posters had %d accepted", len(seen), total)
		}
		if got := m.drain(nil); len(got) != 0 {
			t.Fatalf("drain after close returned %d commands", len(got))
		}
		t.Logf("%d posts accepted before close, %d refused", total, posters)
	})
}

func TestRingActorWithLockHeld(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := new(Session)
		s.mb.init()
		s.mu.Lock()
		for range 3 {
			s.ringActor() // nobody receives: must not block, also under s.mu
		}
		s.mu.Unlock()
		if !mbTakeToken(&s.mb) {
			t.Fatal("ringActor did not ring the doorbell")
		}
		if mbTakeToken(&s.mb) {
			t.Fatal("ringActor rings did not coalesce")
		}

		// Before init (as in the stream's fake-lane unit tests) ringing is a
		// no-op and posts still queue.
		z := new(Session)
		z.ringActor()
		c := &shutdown{}
		if !z.mb.post(c) {
			t.Fatal("post refused by an uninitialized mailbox")
		}
		if got := z.mb.drain(nil); len(got) != 1 || got[0] != c {
			t.Fatalf("uninitialized mailbox drained %v, want [%p]", got, c)
		}
	})
}
