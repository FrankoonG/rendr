package rendr

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestSilentHandshakesReleased_L48: the handshake deadline (accept time +
// Handshake.Timeout) covers the PREFACE read and the PREFACE_ACK write (plan
// §3.5, L48): 64 silent conns that never send a byte and 64 conns that send
// a PREFACE but never read its PREFACE_ACK (their passive write blocks) all
// occupy a slot (load proof: 128 handshakes at once), and every one is
// closed exactly at its deadline — not earlier (no eviction: 128 < 256
// slots), not later — leaving no slot, goroutine or state behind.
func TestSilentHandshakesReleased_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 2 * time.Second
		rt := wpTestRuntime(t, Config{Handshake: HandshakeLimits{Timeout: timeout}}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		const n = 128
		start := time.Now()
		released := make(chan time.Duration, n)
		var wg sync.WaitGroup
		for i := range n {
			d := wpConnect(t, ln, wpInst(0xa0), uint32(i+1))
			wg.Go(func() {
				defer d.close()
				if i%2 == 1 {
					// Write-blocked: the PREFACE is read by the passive, its
					// PREFACE_ACK is never read; this second write blocks
					// until the passive gives up and closes.
					if _, err := d.nc.Write(wpPreface(d.inst, d.id)); err != nil {
						t.Errorf("conn %d: PREFACE: %v", i, err)
					}
					if _, err := d.nc.Write([]byte{0}); !errors.Is(err, io.ErrClosedPipe) {
						t.Errorf("conn %d: blocked write ended with %v", i, err)
					}
				} else {
					var b [1]byte
					if n, err := d.nc.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
						t.Errorf("conn %d: silent conn read (%d, %v)", i, n, err)
					}
				}
				released <- time.Since(start)
			})
		}
		synctest.Wait()
		if st := rt.Status(); st.Handshakes != n {
			t.Fatalf("%d handshakes in progress, want %d", st.Handshakes, n)
		}
		wg.Wait()
		close(released)
		for d := range released {
			if d != timeout {
				t.Fatalf("a silent handshake was released after %v, want exactly %v", d, timeout)
			}
		}
		synctest.Wait()
		if st := rt.Status(); st.HandshakeEvictions != 0 || st.Abandoned != 0 {
			t.Fatalf("status %+v", st)
		}
		wpNoState(t, rt)
		rt.Close()
	})
}

// TestLegitAdmittedUnderSlowloris_L48: when every handshake slot is held
// by a silent conn, a new carrier is never refused or queued behind them:
// the oldest unfinished handshake is evicted (its conn closed at once) and
// the new one proceeds (plan §3.5, L48). 1000 silent conns fill the 256
// default slots and evict the 744 oldest (stimulus and load proof: exactly
// conns 0–743 see EOF, at once, and 256 slots stay held); then a legitimate
// probe carrier gets its PONG and a legitimate JOIN its answer within
// 100 ms (the probe evicts one more silent conn and frees its slot after
// its first frame, so the JOIN finds one free); Close releases the rest.
func TestLegitAdmittedUnderSlowloris_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		const silent, slots = 1000, 256
		evicted := make(chan int, silent)
		var wg sync.WaitGroup
		start := time.Now()
		for i := range silent {
			d := wpConnect(t, ln, wpInst(0xb0), uint32(i+1))
			wg.Go(func() {
				defer d.close()
				var b [1]byte
				if n, err := d.nc.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Errorf("silent conn %d: read (%d, %v)", i, n, err)
				}
				if time.Since(start) == 0 {
					evicted <- i
				}
			})
		}
		synctest.Wait()
		st := rt.Status()
		if st.Handshakes != slots || st.HandshakeEvictions != silent-slots {
			t.Fatalf("after %d silent conns: %d handshakes, %d evictions; want %d and %d", silent, st.Handshakes, st.HandshakeEvictions, slots, silent-slots)
		}
		if len(evicted) != silent-slots {
			t.Fatalf("%d silent conns closed at once, want %d", len(evicted), silent-slots)
		}
		for range silent - slots {
			if i := <-evicted; i >= silent-slots {
				t.Fatalf("conn %d was evicted, a newer one than the %d oldest", i, silent-slots)
			}
		}

		t0 := time.Now()
		p, f := wpProbe(t, rt, ln, wpInst(0xc0), 5000)
		if f.Type != wire.TypePong {
			t.Fatalf("legit probe answered %v, want PONG", f.Type)
		}
		if d := time.Since(t0); d > 100*time.Millisecond {
			t.Fatalf("legit probe admitted after %v", d)
		}
		j := wpConnect(t, ln, wpInst(0xc1), 5001)
		j.hello(rt)
		j.send(wire.TypeJoin, 0, wpJoin(wpSID(1), 1, 0))
		j.expectJoinAck(wire.StatusUnknownSession)
		if d := time.Since(t0); d > 100*time.Millisecond {
			t.Fatalf("legit JOIN answered after %v", d)
		}
		synctest.Wait()
		// The probe evicted one silent conn and released its slot right
		// after its first frame, so the JOIN found a free slot.
		if st := rt.Status(); st.HandshakeEvictions != silent-slots+1 || st.Handshakes != slots-1 || st.Sessionless != 1 {
			t.Fatalf("after the legit carriers: %+v", st)
		}
		p.close()
		j.close()
		rt.Close()
		wg.Wait()
		wpNoState(t, rt)
		if st := rt.Status(); st.Abandoned != 0 {
			t.Fatalf("abandoned %d", st.Abandoned)
		}
	})
}

// TestSessionlessCarrierLifecycle_L48: sessionless (probe) carriers are
// capped per dialer instance and per Runtime, refused with CLOSE(capacity)
// beyond either cap without evicting the existing ones, answer every PING
// with an echoing PONG (pad included), close after Sessionless.Idle without
// a PING, answer the dialer's CLOSE with their own, free their place only
// when their carrier is done, and get GOAWAY at Runtime.Close (design §6.4,
// plan §3.5, L48).
func TestSessionlessCarrierLifecycle_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = 30 * time.Second // the default Sessionless.Idle
		rt := wpTestRuntime(t, Config{Sessionless: SessionlessLimits{PerInstance: 2, Total: 3}}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		instA, instB, instC := wpInst(0xa1), wpInst(0xb1), wpInst(0xc1)
		admitted := map[*wpDialer]time.Time{} // when its first PONG came: its idle clock starts then
		probe := func(inst [16]byte, id uint32, want wire.Type) *wpDialer {
			t.Helper()
			d, f := wpProbe(t, rt, ln, inst, id)
			admitted[d] = time.Now()
			if f.Type != want {
				t.Fatalf("probe %d answered %v, want %v", id, f.Type, want)
			}
			if want == wire.TypeClose {
				if r, err := wire.ParseClose(f.Payload); err != nil || r != wire.CloseCapacity {
					t.Fatalf("probe %d refused with CLOSE %v (%v), want capacity", id, r, err)
				}
				d.expectEOF()
			}
			return d
		}
		a1 := probe(instA, 1, wire.TypePong)
		a2 := probe(instA, 2, wire.TypePong)
		probe(instA, 3, wire.TypeClose) // per-instance cap
		b1 := probe(instB, 4, wire.TypePong)
		probe(instC, 5, wire.TypeClose) // Runtime cap
		synctest.Wait()
		if n, insts := rt.slt.held(InstanceID(instA)); n != 2 || insts != 2 || rt.Status().Sessionless != 3 {
			t.Fatalf("held: %d for A over %d instances, %d in total", n, insts, rt.Status().Sessionless)
		}
		a1.pingPong(10, 0)
		a1.pingPong(11, 1000)

		// The dialer retires a1: the passive answers CLOSE, ends the carrier
		// and only then frees its place, which a new probe of A takes.
		a1.send(wire.TypeClose, 0, []byte{byte(wire.CloseRetire)})
		a1.expect(wire.TypeClose)
		a1.expectEOF()
		synctest.Wait()
		if n := rt.Status().Sessionless; n != 2 {
			t.Fatalf("%d sessionless carriers after a retirement, want 2", n)
		}
		a4 := probe(instA, 6, wire.TypePong)

		// b1 and a4 stay silent and are closed after Sessionless.Idle; a2
		// keeps PINGing and survives until it stops.
		idleClose := func(d *wpDialer) <-chan time.Duration {
			since := admitted[d]
			ch := make(chan time.Duration, 1)
			go func() {
				d.expect(wire.TypeClose)
				ch <- time.Since(since)
				d.close()
			}()
			return ch
		}
		bClosed, aClosed := idleClose(b1), idleClose(a4)
		for i := range 4 {
			time.Sleep(10 * time.Second)
			a2.pingPong(uint32(20+i), 0)
		}
		for _, ch := range []<-chan time.Duration{bClosed, aClosed} {
			if d := <-ch; d < idle || d > idle+time.Second {
				t.Fatalf("an idle probe carrier closed after %v, want %v", d, idle)
			}
		}
		synctest.Wait()
		if n := rt.Status().Sessionless; n != 1 {
			t.Fatalf("%d sessionless carriers after the idle closes, want 1 (the PINGing one)", n)
		}

		// Runtime.Close: GOAWAY, then CLOSE, on the remaining probe carrier.
		closed := make(chan error, 1)
		go func() {
			if f := a2.expect(wire.TypeGoAway); f.Handle != 0 || len(f.Payload) != 1 || f.Payload[0] != byte(wire.GoAwayShutdown) {
				closed <- errors.New("bad GOAWAY")
				return
			}
			a2.expect(wire.TypeClose)
			a2.close()
			closed <- nil
		}()
		rt.Close()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		wpNoState(t, rt)
		if n, insts := rt.slt.held(InstanceID(instA)); n != 0 || insts != 0 {
			t.Fatalf("sessionless counts left: %d over %d instances", n, insts)
		}
	})
}

// TestHandshakeClosesConnOnce_L51: an embedder conn is closed exactly once
// on every handshake path (L51), although eviction closes the conn of an
// unfinished handshake (SetDeadline(now) + Close, so that even a conn that
// ignores deadlines is released) while that handshake's ReadHello closes
// it too when its read fails: a silent conn evicted before its PREFACE, a
// conn evicted after PREFACE_ACK(OK) while it waits for its first frame, a
// sessionless carrier ended by Runtime.Close and a conn pushed after Close
// each see exactly one Close.
func TestHandshakeClosesConnOnce_L51(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{Handshake: HandshakeLimits{MaxConcurrent: 1}}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		var conns []*countConn
		connect := func(id uint32) *wpDialer {
			a, b := net.Pipe()
			c := &countConn{Conn: a}
			conns = append(conns, c)
			if err := ln.Handle(c); err != nil {
				t.Fatal(err)
			}
			return &wpDialer{t: t, nc: b, inst: wpInst(0xf1), id: id, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
		}
		d1 := connect(1) // silent
		d2 := connect(2) // evicts d1
		d1.expectEOF()
		d2.hello(rt) // OK: d2 now waits for its first frame in the only slot
		p := connect(3)
		d2.expectEOF() // evicted after PREFACE_ACK(OK)
		p.hello(rt)
		ping := wire.Ping{ID: 9, Nonce: 99}
		p.send(wire.TypePing, 0, wpPing(ping))
		p.expect(wire.TypePong)
		synctest.Wait()
		if st := rt.Status(); st.HandshakeEvictions != 2 || st.Sessionless != 1 {
			t.Fatalf("status %+v", st)
		}
		go func() {
			p.expect(wire.TypeGoAway)
			p.expect(wire.TypeClose)
			p.close()
		}()
		rt.Close()
		late, _ := net.Pipe()
		lc := &countConn{Conn: late}
		conns = append(conns, lc)
		if err := ln.Handle(lc); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Handle after Close: %v", err)
		}
		synctest.Wait()
		for i, c := range conns {
			if n := c.closes.Load(); n != 1 {
				t.Fatalf("conn %d closed %d times, want 1", i+1, n)
			}
		}
		d1.close()
		d2.close()
		wpNoState(t, rt)
	})
}
