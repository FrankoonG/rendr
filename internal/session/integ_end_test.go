package session

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// TestDoneThenPeerCloseIsCleanEnd (wave-2 integration regression, D4,
// §7.7): the passive's actor is held while both FINs are delivered, both
// DONEs cross and the dialer, ended by them, retires its carrier with
// CLOSE and closes it. The held actor then finds the dialer's DONE, its
// CLOSE and the carrier's end in one step (what GOMAXPROCS=1 produces with
// real carriers). The session must end cleanly in that step: carrier loss
// after the DONE exchange is no routing loss, so no no-path episode, no
// NoPathStart event and no Orphaned call on either end.
func TestDoneThenPeerCloseIsCleanEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l := w.link("p1")
		a, b := w.open(ModeSelector, nil, l)
		if we, re := acTransfer(a, b, 256<<10, 11, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}

		// Hold b's actor right before its next wait.
		var armed, held atomic.Bool
		release := make(chan struct{})
		hook := func(s *Session) {
			if s == b && armed.CompareAndSwap(true, false) {
				held.Store(true)
				<-release
			}
		}
		beforeWaitHook.Store(&hook)
		defer beforeWaitHook.Store(nil)
		armed.Store(true)
		b.ringActor()
		synctest.Wait()
		if !held.Load() {
			t.Fatal("the passive actor was not held (stimulus)")
		}

		// Both directions end; the data path delivers the FINs and DONEs
		// without the passive's actor.
		var wg sync.WaitGroup
		var errs [4]error
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs[0] = a.CloseWrite()
			_, errs[1] = a.Read(make([]byte, 1))
		}()
		go func() {
			defer wg.Done()
			errs[2] = b.CloseWrite()
			_, errs[3] = b.Read(make([]byte, 1))
		}()
		wg.Wait()
		if errs[0] != nil || errs[1] != io.EOF || errs[2] != nil || errs[3] != io.EOF {
			t.Fatalf("CloseWrite/Read: %v", errs)
		}
		acDone(t, a, 10*time.Second) // DONE both ways; its carrier retired and closed
		time.Sleep(2 * time.Second)  // the passive's carrier read the CLOSE and the end
		synctest.Wait()
		b.mu.Lock()
		peerDone, doneSent, lanes := b.st.peerDone, b.st.doneSent, len(b.lanes)
		peerClosed := lanes == 1 && b.lanes[0].c.PeerClosed()
		b.mu.Unlock()
		if !peerDone || !doneSent || !peerClosed {
			t.Fatalf("stimulus missing before the held step: peerDone %v doneSent %v, %d lanes, peer CLOSE %v", peerDone, doneSent, lanes, peerClosed)
		}

		close(release)
		acDone(t, b, 10*time.Second)
		for _, s := range []*Session{a, b} {
			st := s.Status()
			if st.State != StateEnded || st.Err != io.EOF || st.NoPathEpisodes != 0 || st.InNoPath {
				t.Errorf("%v: state %v err %v, episodes %d (in %v), want a clean end without an episode", s.Role(), st.State, st.Err, st.NoPathEpisodes, st.InNoPath)
			}
		}
		if n := len(w.b.ev.of(b.ID(), EventNoPathStart)) + len(w.a.ev.of(a.ID(), EventNoPathStart)); n != 0 {
			t.Errorf("%d NoPathStart events at a clean end", n)
		}
		w.b.reg.mu.Lock()
		orphaned := w.b.reg.orphaned[b]
		w.b.reg.mu.Unlock()
		if orphaned != 0 {
			t.Errorf("Orphaned(on) called %d times at a clean end", orphaned)
		}
		if v, ok := w.b.reg.endedVerdict(b); !ok || !v.Opened {
			t.Errorf("passive verdict %+v (ended %v)", v, ok)
		}
	})
}
