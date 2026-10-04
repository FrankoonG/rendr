package session

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

type ioResult struct {
	n   int
	err error
}

// TestFinAboveGapNoEOF_L02: a FIN at 100 with [50,100) missing and the
// carrier that brought it dead never yields EOF; Read stays blocked until a
// second carrier fills the gap, then returns the 50 bytes and only then
// io.EOF (L02: EOF only at the contiguous FIN).
func TestFinAboveGapNoEOF_L02(t *testing.T) {
	for _, first := range []uint64{0, 1<<62 - 1<<20} {
		synctest.Test(t, func(t *testing.T) {
			s := newTestSession(sopt{role: RolePassive, first: first, limit: 1 << 62})
			la, _ := addLane(s, 1, false)
			lb, _ := addLane(s, 2, false)
			data := pattern(first, 100)

			// Stimulus: [0,50) and FIN(100) on lane A; [50,100) never arrives there.
			if err := la.Data(nil, first, data[:50], nil); err != nil {
				t.Fatalf("Data [0,50): %v", err)
			}
			if err := sendFin(la, first+100); err != nil {
				t.Fatalf("FIN(100): %v", err)
			}
			buf := make([]byte, 200)
			if n, err := s.Read(buf); n != 50 || err != nil || !bytes.Equal(buf[:n], data[:50]) {
				t.Fatalf("first Read = (%d, %v), want the 50 contiguous bytes", n, err)
			}
			done := make(chan ioResult, 1)
			go func() {
				n, err := s.Read(buf[50:])
				done <- ioResult{n, err}
			}()
			synctest.Wait()
			select {
			case r := <-done:
				t.Fatalf("Read returned (%d, %v) while [50,100) is missing below the FIN", r.n, r.err)
			default:
			}

			// Lane A's carrier dies (EOF): still no EOF and no error.
			killLane(s, la)
			synctest.Wait()
			select {
			case r := <-done:
				t.Fatalf("Read returned (%d, %v) after the FIN carrier died above a gap", r.n, r.err)
			default:
			}

			// Lane B fills the gap: the bytes, then EOF.
			if err := lb.Data(nil, first+50, data[50:], nil); err != nil {
				t.Fatalf("Data [50,100) on lane B: %v", err)
			}
			r := <-done
			if r.n != 50 || r.err != nil || !bytes.Equal(buf[50:100], data[50:]) {
				t.Fatalf("Read after the gap filled = (%d, %v), want the missing 50 bytes", r.n, r.err)
			}
			if n, err := s.Read(buf); n != 0 || err != io.EOF {
				t.Fatalf("Read at the FIN = (%d, %v), want (0, io.EOF)", n, err)
			}
			if n, err := s.Read(buf); n != 0 || err != io.EOF {
				t.Fatalf("repeated Read at the FIN = (%d, %v), want (0, io.EOF)", n, err)
			}
			// The FIN_DELIVERED ACK leaves on the surviving lane.
			fs, b := fill(lb, time.Now())
			b.ReleaseRefs()
			if len(fs) != 1 || fs[0].typ != wire.TypeAck || fs[0].flags&wire.FlagAckFinDelivered == 0 || fs[0].ack.Delivered != first+100 {
				t.Fatalf("survivor frames %v, want one ACK(100) with FIN_DELIVERED", fs)
			}
			endSession(s, io.EOF)
			if u := s.env.Carrier.Budget.Used(); u != 0 {
				t.Fatalf("Budget.Used = %d after the end", u)
			}
		})
	}
}

// TestCloseUnblocksWithoutCarriers_L03: with every carrier dead, a Write
// blocked on a full send buffer and a blocked Read both return
// net.ErrClosed as soon as Close is called (≤ 200 ms; virtual 0 here), and
// Close itself returns at once.
func TestCloseUnblocksWithoutCarriers_L03(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const w = 256 << 10
		s := newTestSession(sopt{window: w})
		l, _ := addLane(s, 1, true)
		killLane(s, l) // no carrier left

		// The send buffer accepts W without any carrier (L17), then blocks.
		if n, err := s.Write(make([]byte, w)); n != w || err != nil {
			t.Fatalf("Write of one window without carriers = (%d, %v), want (%d, nil)", n, err, w)
		}
		wDone, rDone := make(chan ioResult, 1), make(chan ioResult, 1)
		go func() {
			n, err := s.Write(make([]byte, 1000))
			wDone <- ioResult{n, err}
		}()
		go func() {
			n, err := s.Read(make([]byte, 10))
			rDone <- ioResult{n, err}
		}()
		synctest.Wait()
		if len(wDone) != 0 || len(rDone) != 0 {
			t.Fatal("Write or Read returned before Close with no carrier and a full buffer")
		}
		start := time.Now()
		if err := s.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		wr, rr := <-wDone, <-rDone
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("blocked calls returned %v after Close, want ≤ 200 ms", d)
		}
		if wr.n != 0 || !errors.Is(wr.err, net.ErrClosed) {
			t.Fatalf("blocked Write = (%d, %v), want (0, net.ErrClosed)", wr.n, wr.err)
		}
		if rr.n != 0 || !errors.Is(rr.err, net.ErrClosed) {
			t.Fatalf("blocked Read = (%d, %v), want (0, net.ErrClosed)", rr.n, rr.err)
		}
		if _, err := s.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after Close = %v, want net.ErrClosed", err)
		}
		if _, err := s.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read after Close = %v, want net.ErrClosed", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("second Close = %v, want nil (idempotent)", err)
		}
		facts := locked(s, func(st *stream) uint32 { return st.facts })
		if facts&factClose == 0 || facts&factCloseWrite == 0 {
			t.Fatalf("facts %#x lack factClose|factCloseWrite: the actor would not linger", facts)
		}
		fin := locked(s, func(st *stream) finState { return st.fin })
		if !fin.requested || fin.off != w {
			t.Fatalf("FIN %+v, want requested at the reserved end %d", fin, w)
		}
		endSession(s, errClosed)
		if u := s.env.Carrier.Budget.Used(); u != 0 {
			t.Fatalf("Budget.Used = %d after the end", u)
		}
	})
}

// TestCloseRacesFirstWrite_L03 (F1): Close during the first Write's copy
// fixes the FIN at the reserved end; no FIN(0) is ever sendable, the round
// commits below the FIN, and the peer reads every byte before io.EOF.
func TestCloseRacesFirstWrite_L03(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPair(sopt{}, sopt{}, 1)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		writeCopyHook = func() { once.Do(func() { close(entered); <-release }) }
		defer func() { writeCopyHook = nil }()

		msg := pattern(0, 1000)
		wres := make(chan ioResult, 1)
		go func() {
			n, err := p.a.Write(msg)
			wres <- ioResult{n, err}
		}()
		<-entered // the first round is reserved and its copy is in progress

		if err := p.a.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		st := locked(p.a, func(st *stream) [4]uint64 {
			return [4]uint64{st.fin.off, st.end, st.resEnd, b2u(st.fin.requested)}
		})
		if st[3] != 1 || st[0] != 1000 || st[1] != 0 || st[2] != 1000 {
			t.Fatalf("after Close during the copy: fin.off=%d end=%d resEnd=%d requested=%d, want 1000, 0, 1000, 1", st[0], st[1], st[2], st[3])
		}
		// A carrier writer running now finds neither DATA nor a FIN.
		fs, b := fill(p.al[0], time.Now())
		b.ReleaseRefs()
		for _, f := range fs {
			if f.typ == wire.TypeData || f.typ == wire.TypeFin {
				t.Fatalf("Fill during the copy appended %v: the FIN or uncommitted bytes overtook the copy", f)
			}
		}
		close(release)
		if r := <-wres; r.n != len(msg) || r.err != nil {
			t.Fatalf("Write racing Close = (%d, %v), want (%d, nil): a reserved round commits", r.n, r.err, len(msg))
		}
		p.pump(true)
		if len(p.errs) != 0 {
			t.Fatalf("violations: %v", p.errs)
		}
		// On the wire: DATA covering [0,1000), then exactly one FIN(1000).
		var dataEnd uint64
		fins := 0
		for _, f := range p.traceAB {
			switch f.typ {
			case wire.TypeData:
				if fins > 0 {
					t.Fatalf("DATA %v after the FIN", f)
				}
				dataEnd = max(dataEnd, f.off+uint64(f.n))
			case wire.TypeFin:
				fins++
				if f.off != 1000 {
					t.Fatalf("FIN at %d, want 1000 (the reserved end)", f.off)
				}
			}
		}
		if fins != 1 || dataEnd != 1000 {
			t.Fatalf("wire carried %d FINs and DATA up to %d, want 1 FIN after DATA up to 1000", fins, dataEnd)
		}
		got := readN(t, p.b, len(msg))
		if !bytes.Equal(got, msg) {
			t.Fatal("peer read corrupted bytes")
		}
		if n, err := p.b.Read(make([]byte, 10)); n != 0 || err != io.EOF {
			t.Fatalf("peer Read at the FIN = (%d, %v), want io.EOF only after all data", n, err)
		}
		p.close(t)
	})
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// TestCloseWriteIdempotent_L04: two CloseWrites put exactly one FIN on the
// wire at the end of the request; a later Write gets net.ErrClosed; the
// reverse direction stays usable until the peer's own FIN.
func TestCloseWriteIdempotent_L04(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPair(sopt{}, sopt{}, 1)
		req := pattern(0, 3000)
		if n, err := p.a.Write(req); n != len(req) || err != nil {
			t.Fatalf("Write = (%d, %v)", n, err)
		}
		if err := p.a.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite = %v", err)
		}
		if err := p.a.CloseWrite(); err != nil {
			t.Fatalf("second CloseWrite = %v, want nil", err)
		}
		if n, err := p.a.Write([]byte("late")); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after CloseWrite = (%d, %v), want (0, net.ErrClosed)", n, err)
		}
		p.pump(true)
		if got := readN(t, p.b, len(req)); !bytes.Equal(got, req) {
			t.Fatal("request corrupted")
		}
		if _, err := p.b.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("server Read after the request = %v, want io.EOF", err)
		}
		_ = p.a.CloseWrite() // a third call after the FIN was sent
		p.pump(true)
		if n := count(p.traceAB, wire.TypeFin); n != 1 {
			t.Fatalf("%d FINs on the wire, want exactly 1", n)
		}

		// The reverse direction is unaffected by our half-close.
		resp := pattern(1<<40, 200<<10)
		if n, err := p.b.Write(resp); n != len(resp) || err != nil {
			t.Fatalf("server Write = (%d, %v)", n, err)
		}
		if err := p.b.CloseWrite(); err != nil {
			t.Fatalf("server CloseWrite = %v", err)
		}
		done := readAsync(p.a, len(resp))
		for len(done) == 0 {
			p.pump(true)
			synctest.Wait()
		}
		if r := <-done; r.err != nil || !bytes.Equal(r.b, resp) {
			t.Fatalf("response: %v (corrupted: %v)", r.err, !bytes.Equal(r.b, resp))
		}
		if _, err := p.a.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("client Read after the response = %v, want io.EOF", err)
		}
		p.pump(true)
		if n := count(p.traceBA, wire.TypeFin); n != 1 {
			t.Fatalf("%d server FINs on the wire, want 1", n)
		}
		// Both FINs acknowledged, both delivered: DONE went both ways.
		for _, s := range []*Session{p.a, p.b} {
			done := locked(s, func(st *stream) bool { return st.doneSent && st.peerDone && st.fin.acked })
			if !done {
				t.Fatal("DONE was not exchanged after both half-closes completed")
			}
		}
		p.close(t)
	})
}
