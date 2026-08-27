package engine

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecvPacketDeadlineUpdateBroadcastsToAllBlockedReaders(t *testing.T) {
	const readers = 8
	e := New(SideServer, NewClientFlowID(), Limits{})
	e.SetPacketMode()
	t.Cleanup(func() { _ = e.Close() })
	if err := e.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	ready := make(chan struct{})
	release := make(chan struct{})
	var arrived atomic.Int32
	var readyOnce sync.Once
	e.recvPacketBeforeWait = func() {
		if arrived.Add(1) == readers {
			readyOnce.Do(func() { close(ready) })
		}
		<-release
	}

	results := make(chan error, readers)
	for range readers {
		go func() {
			_, err := e.RecvPacket()
			results <- err
		}()
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("packet readers did not all capture the original deadline generation")
	}
	if err := e.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	close(release)

	for i := 0; i < readers; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrReadDeadlineExceeded) || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("reader %d error=%v, want rendr and OS deadline sentinels", i, err)
			}
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Fatalf("reader %d error=%v, want timeout net.Error", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("reader %d remained blocked after deadline generation changed", i)
		}
	}
}

func TestRecvPacketStaleDeadlineTimerCannotTimeoutAfterUpdate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		update func(*Engine) error
	}{
		{
			name: "clear",
			update: func(e *Engine) error {
				return e.SetReadDeadline(time.Time{})
			},
		},
		{
			name: "extend",
			update: func(e *Engine) error {
				return e.SetReadDeadline(time.Now().Add(time.Second))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := New(SideServer, NewClientFlowID(), Limits{})
			e.SetPacketMode()
			t.Cleanup(func() { _ = e.Close() })

			beforeRevalidate := make(chan struct{})
			releaseRevalidate := make(chan struct{})
			var hookOnce sync.Once
			e.recvPacketDeadlineBeforeRevalidate = func() {
				hookOnce.Do(func() {
					close(beforeRevalidate)
					<-releaseRevalidate
				})
			}
			if err := e.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}

			result := make(chan error, 1)
			go func() {
				_, err := e.RecvPacket()
				result <- err
			}()
			select {
			case <-beforeRevalidate:
			case <-time.After(time.Second):
				t.Fatal("reader-local deadline timer did not become ready")
			}
			if err := tc.update(e); err != nil {
				t.Fatal(err)
			}
			close(releaseRevalidate)

			select {
			case err := <-result:
				t.Fatalf("stale deadline returned after %s: %v", tc.name, err)
			case <-time.After(100 * time.Millisecond):
			}
			if err := e.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, ErrReadDeadlineExceeded) || !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("replacement deadline error=%v, want rendr and OS deadline sentinels", err)
				}
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					t.Fatalf("replacement deadline error=%v, want timeout net.Error", err)
				}
			case <-time.After(time.Second):
				t.Fatal("reader did not observe replacement deadline")
			}
		})
	}
}
