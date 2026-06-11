package engine

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendByeDoesNotBlockBehindSendMu(t *testing.T) {
	e := New(SideClient, [16]byte{1}, Limits{})
	e.sendMu.Lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			e.sendMu.Unlock()
			unlocked = true
		}
	}
	defer unlock()

	done := make(chan error, 1)
	go func() {
		done <- e.SendBye(0)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("SendBye error = %v, want net.ErrClosed", err)
		}
	case <-time.After(100 * time.Millisecond):
		unlock()
		err := <-done
		t.Fatalf("SendBye blocked behind sendMu; eventual error = %v", err)
	}
}

func TestPeerAckClampedToSentSeq(t *testing.T) {
	e := New(SideClient, [16]byte{2}, Limits{})
	atomic.StoreUint64(&e.sendSeq, 2)

	e.notePeerAck(3)
	if got := e.sendAckNext.Load(); got != 0 {
		t.Fatalf("future ACK advanced sendAckNext to %d, want 0", got)
	}

	e.notePeerAck(2)
	if got := e.sendAckNext.Load(); got != 2 {
		t.Fatalf("valid ACK advanced sendAckNext to %d, want 2", got)
	}
}

func TestPeerAckRefreshesZombieCounter(t *testing.T) {
	e := New(SideClient, [16]byte{3}, Limits{})
	atomic.StoreUint64(&e.sendSeq, 1)

	e.zombieMu.Lock()
	e.zombieLeft = 1
	e.zombieLastMig = nowFn()
	e.zombieMu.Unlock()

	e.notePeerAck(1)

	e.zombieMu.Lock()
	left := e.zombieLeft
	last := e.zombieLastMig
	e.zombieMu.Unlock()

	if left != e.limits.ZombieMaxMigrations {
		t.Fatalf("zombieLeft = %d, want %d", left, e.limits.ZombieMaxMigrations)
	}
	if !last.IsZero() {
		t.Fatalf("zombieLastMig = %v, want zero", last)
	}
}
