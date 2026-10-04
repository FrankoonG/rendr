package session

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"net"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// stBufferedReceiver returns a passive session holding data in order: a
// segment kept by reference (≥ 16 KiB) and a small copied run.
func stBufferedReceiver(t testing.TB, o stOpt) (*Session, *lane, []byte) {
	t.Helper()
	o.role = RolePassive
	s := stSession(o)
	l, _ := stAddLane(s, 1, false)
	data := stPattern(0, 40<<10+1000)
	if err := stDeliverData(l, 0, data[:40<<10]); err != nil {
		t.Fatal(err)
	}
	if err := l.Data(nil, 40<<10, data[40<<10:], nil); err != nil {
		t.Fatal(err)
	}
	return s, l, data
}

// TestReadCloseLinearization_L07: a Read racing Close has exactly one
// outcome. Read won (its commit came first): it returns the bytes and Close
// follows. Close won (it came between the copy and the commit, at
// Hooks.ReadDequeued): the Read returns (0, net.ErrClosed) and the dequeued
// bytes are dropped. After Close returned, every Read returns
// net.ErrClosed, never io.EOF. 1000 unsynchronized races keep the
// invariant and leak neither buffers nor goroutines.
func TestReadCloseLinearization_L07(t *testing.T) {
	for _, closeWins := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			hooks := &testhooks.Hooks{ReadDequeued: func() {
				close(entered)
				<-release
			}}
			s, _, data := stBufferedReceiver(t, stOpt{hooks: hooks})
			used := s.env.Carrier.Budget.Used()
			buf := make([]byte, len(data))
			done := make(chan stIO, 1)
			go func() {
				n, err := s.Read(buf)
				done <- stIO{n, err}
			}()
			<-entered // the bytes are copied out, the commit is pending
			var r stIO
			if closeWins {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				if u := s.env.Carrier.Budget.Used(); u != used {
					t.Fatalf("Close released %d bytes of buffers during the Read's copy", used-u)
				}
				close(release)
				r = <-done
				if r.n != 0 || !errors.Is(r.err, net.ErrClosed) {
					t.Fatalf("Close won, Read = (%d, %v), want (0, net.ErrClosed)", r.n, r.err)
				}
				if u := s.env.Carrier.Budget.Used(); u != 0 {
					t.Fatalf("the Read's commit left %d bytes held after Close won", u)
				}
			} else {
				close(release)
				r = <-done
				if r.n != len(data) || r.err != nil || !bytes.Equal(buf, data) {
					t.Fatalf("Read won, Read = (%d, %v), want all %d bytes", r.n, r.err, len(data))
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if n, err := s.Read(buf); n != 0 || !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Read after Close = (%d, %v), want (0, net.ErrClosed)", n, err)
				}
			}
			stEnd(s, errClosed)
			if u := s.env.Carrier.Budget.Used(); u != 0 {
				t.Fatalf("Budget.Used = %d after the end", u)
			}
		})
	}

	// Unsynchronized races (real goroutines, random yields in the window).
	runs := 1000
	baseline := runtime.NumGoroutine()
	readWon, closeWon := 0, 0
	for i := range runs {
		rng := rand.New(rand.NewPCG(uint64(i), 7))
		yields, readYields, closeYields := rng.IntN(4), rng.IntN(2), rng.IntN(16)
		hooks := &testhooks.Hooks{ReadDequeued: func() {
			for range yields {
				runtime.Gosched()
			}
		}}
		s, _, data := stBufferedReceiver(t, stOpt{hooks: hooks})
		buf := make([]byte, len(data))
		var wg sync.WaitGroup
		var r stIO
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range readYields {
				runtime.Gosched()
			}
			n, err := s.Read(buf)
			r = stIO{n, err}
		}()
		closed := make(chan struct{})
		go func() {
			defer wg.Done()
			for range closeYields {
				runtime.Gosched()
			}
			_ = s.Close()
			close(closed)
			// After Close returned, a Read can only fail with ErrClosed.
			if n, err := s.Read(make([]byte, 1)); n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Errorf("run %d: Read after Close returned = (%d, %v)", i, n, err)
			}
		}()
		wg.Wait()
		switch {
		case r.err == nil && r.n > 0:
			if !bytes.Equal(buf[:r.n], data[:r.n]) {
				t.Fatalf("run %d: Read won with corrupted bytes", i)
			}
			readWon++
		case r.n == 0 && errors.Is(r.err, net.ErrClosed):
			closeWon++
		default:
			t.Fatalf("run %d: Read racing Close = (%d, %v): neither outcome", i, r.n, r.err)
		}
		stEnd(s, errClosed)
		if u := s.env.Carrier.Budget.Used(); u != 0 {
			t.Fatalf("run %d: Budget.Used = %d after the end (leak)", i, u)
		}
	}
	t.Logf("%d races: Read won %d, Close won %d", runs, readWon, closeWon)
	for range 100 {
		if runtime.NumGoroutine() <= baseline {
			break
		}
		runtime.Gosched()
	}
	if g := runtime.NumGoroutine(); g > baseline {
		t.Fatalf("%d goroutines after the races, baseline %d", g, baseline)
	}
}

// TestRstDuringReadCopy_L07: an RST that ends the session while a Read
// copies out of the receive buffers frees nothing under the copy (the
// Budget is unchanged at the commit point, and buffers taken from the same
// pool meanwhile are never the ones being read — the race detector and the
// rendrdebug poison would see it); the Read still returns its bytes and
// the next Read returns the *AbortError.
func TestRstDuringReadCopy_L07(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		hooks := &testhooks.Hooks{ReadDequeued: func() {
			close(entered)
			<-release
		}}
		pool, budget := carrier.NewBufPool(), carrier.NewBudget(1<<30)
		s, l, data := stBufferedReceiver(t, stOpt{hooks: hooks, pool: pool, budget: budget})
		used := budget.Used()
		buf := make([]byte, len(data)+100)
		done := make(chan stIO, 1)
		go func() {
			n, err := s.Read(buf)
			done <- stIO{n, err}
		}()
		<-entered

		// Stimulus: the peer's RST arrives; the actor ends the session.
		var p [wire.RstFixedLen + 6]byte
		n := wire.PutRst(p[:], &wire.Rst{Code: wire.RstLinger, Msg: []byte("linger")})
		if err := l.Control(nil, stCtlHeader(wire.TypeRst, 0, n), p[:n]); err != nil {
			t.Fatalf("RST: %v", err)
		}
		rst := stLocked(s, func(st *stream) *wire.Rst {
			if st.facts&factRst == 0 {
				return nil
			}
			return st.rstIn
		})
		if rst == nil || rst.Code != wire.RstLinger || string(rst.Msg) != "linger" {
			t.Fatalf("RST not recorded for the actor: %+v", rst)
		}
		stEnd(s, &AbortError{Code: AbortCode(rst.Code), Msg: string(rst.Msg), Remote: true})
		if u := budget.Used(); u != used {
			t.Fatalf("the end released %d bytes of buffers under the Read's copy", used-u)
		}
		// Pool churn: a sibling session takes buffers of both classes and
		// writes into them; none may be a buffer the Read still holds.
		var churn []*carrier.Buf
		for range 8 {
			for _, n := range []int{carrier.BigData, 40<<10 + carrier.LookAhead} {
				b := pool.Get(n, budget)
				for i := range b.B {
					b.B[i] = 0xa5
				}
				churn = append(churn, b)
			}
		}
		close(release)
		r := <-done
		if r.n != len(data) || r.err != nil || !bytes.Equal(buf[:r.n], data) {
			t.Fatalf("Read overlapping the end = (%d, %v), want its %d bytes intact", r.n, r.err, len(data))
		}
		_, err := s.Read(buf)
		var ae *AbortError
		if !errors.As(err, &ae) || !ae.Remote || ae.Code != AbortLinger || !errors.Is(err, ErrAborted) {
			t.Fatalf("Read after the end = %v, want *AbortError{Linger, Remote}", err)
		}
		for _, b := range churn {
			b.Release()
		}
		if u := budget.Used(); u != 0 {
			t.Fatalf("Budget.Used = %d after the end", u)
		}
	})

	// Unsynchronized: the end lands anywhere in Read; under -race a buffer
	// released early and reused by the churn would be reported.
	for i := range 200 {
		pool, budget := carrier.NewBufPool(), carrier.NewBudget(1<<30)
		s, _, data := stBufferedReceiver(t, stOpt{pool: pool, budget: budget})
		buf := make([]byte, len(data))
		var wg sync.WaitGroup
		var r stIO
		wg.Add(2)
		go func() {
			defer wg.Done()
			n, err := s.Read(buf)
			r = stIO{n, err}
		}()
		go func() {
			defer wg.Done()
			for range i % 4 {
				runtime.Gosched()
			}
			stEnd(s, &AbortError{Code: AbortIdle, Remote: true})
			for range 4 {
				b := pool.Get(carrier.BigData, budget)
				clear(b.B)
				b.Release()
			}
		}()
		wg.Wait()
		if r.err == nil && !bytes.Equal(buf[:r.n], data[:r.n]) {
			t.Fatalf("run %d: bytes corrupted by a buffer released under the copy", i)
		}
		if r.err != nil && !errors.Is(r.err, ErrAborted) {
			t.Fatalf("run %d: Read = %v", i, r.err)
		}
		if u := budget.Used(); u != 0 {
			t.Fatalf("run %d: Budget.Used = %d after the end", i, u)
		}
	}
}
