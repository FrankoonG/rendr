package carrier

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestKillIdempotentSingleRing_L01: 1000 races of two Kill calls against
// the peer closing the conn (the reader then reports transport_error):
// exactly one death record, exactly one ring, at most one Kill call wins,
// and a lost race leaves the reader's transport_error. Every run joins
// (Done), returns its reader stage to the Budget and abandons nothing.
func TestKillIdempotentSingleRing_L01(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		causes := map[Cause]int{}
		for i := range 1000 {
			c, p := hPair(t, env, nil)
			var bell hBell
			c.Start(&hEP{}, &bell, StartOptions{})
			synctest.Wait() // the first PING is on the wire
			var wins atomic.Int32
			var wg sync.WaitGroup
			wg.Add(3)
			go func() {
				defer wg.Done()
				if c.Kill(CauseLocalClose, "kill a") {
					wins.Add(1)
				}
			}()
			go func() {
				defer wg.Done()
				if c.Kill(CauseProtocolViolation, "kill b") {
					wins.Add(1)
				}
			}()
			go func() {
				defer wg.Done()
				p.nc.Close() // EOF on the carrier's reader
			}()
			wg.Wait()
			hWait(t, c)
			p.close()
			dead, cause, detail, at := c.Death()
			if !dead || at.IsZero() || detail == "" {
				t.Fatalf("run %d: death record %v %v %q %v", i, dead, cause, detail, at)
			}
			if n := bell.n.Load(); n != 1 {
				t.Fatalf("run %d: %d rings, want exactly 1", i, n)
			}
			switch w := wins.Load(); {
			case w > 1:
				t.Fatalf("run %d: %d Kill calls won", i, w)
			case w == 0 && cause != CauseTransportError:
				t.Fatalf("run %d: no Kill call won but the cause is %v", i, cause)
			case w == 1 && cause == CauseTransportError:
				t.Fatalf("run %d: a Kill call won but the cause is transport_error", i)
			}
			if c.Kill(CauseLocalClose, "late") || bell.n.Load() != 1 {
				t.Fatalf("run %d: a late Kill changed the record or rang", i)
			}
			causes[cause]++
		}
		if env.Budget.Used() != 0 || env.Abandon.Len() != 0 {
			t.Fatalf("budget %d, abandoned %d after 1000 joined carriers", env.Budget.Used(), env.Abandon.Len())
		}
		t.Logf("causes: %v", causes)
	})
}

// TestRetireExchangesCloseBothWays_L05: a planned retirement between two
// carriers: CLOSE goes both ways (each the last frame of its side), the
// initiator's owner learns of the peer's CLOSE by a ring, both end as
// retired (not a death), the reader stages return to the Budget and
// nothing is abandoned.
func TestRetireExchangesCloseBothWays_L05(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		ca, cb := hConn(env, a), hConn(env, b)
		var bellA, bellB hBell
		ca.Start(&hEP{}, &bellA, StartOptions{})
		cb.Start(&hEP{}, &bellB, StartOptions{})
		synctest.Wait() // PING/PONG exchanged both ways
		if ca.SRTT() < 0 || ca.Stats().Frames == 0 {
			t.Fatal("no frames before retirement")
		}
		ca.Retire(wire.CloseRetire)
		synctest.Wait()
		if !ca.CloseSent() || !cb.PeerClosed() || bellB.n.Load() == 0 {
			t.Fatalf("after A's CLOSE: A sent %v, B peer-closed %v, B rings %d", ca.CloseSent(), cb.PeerClosed(), bellB.n.Load())
		}
		if dead, _, _, _ := ca.Death(); dead {
			t.Fatal("A ended before B's CLOSE")
		}
		cb.Retire(wire.CloseRetire) // B's owner reacts to the peer's CLOSE
		hWait(t, ca)
		hWait(t, cb)
		for name, c := range map[string]*Conn{"A": ca, "B": cb} {
			if dead, cause, _, _ := c.Death(); !dead || cause != CauseRetired || cause.Death() {
				t.Fatalf("%s: dead %v cause %v", name, dead, cause)
			}
			if !c.CloseSent() || !c.PeerClosed() {
				t.Fatalf("%s: CLOSE sent %v, peer closed %v", name, c.CloseSent(), c.PeerClosed())
			}
		}
		if env.Budget.Used() != 0 || env.Abandon.Len() != 0 {
			t.Fatalf("budget %d, abandoned %d", env.Budget.Used(), env.Abandon.Len())
		}
	})
}

// TestRetireDrainBound_L05: when the peer never answers our CLOSE, the
// retirement ends min(2·srtt + 100 ms, 1 s) after the CLOSE was written,
// as retired; CLOSE is the last frame we wrote.
func TestRetireDrainBound_L05(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		p.autoPong(func(uint32) time.Duration { return 200 * time.Millisecond })
		c.Start(&hEP{}, &hBell{}, StartOptions{})
		time.Sleep(time.Second) // srtt = 200 ms
		if s := c.SRTT(); s != 200*time.Millisecond {
			t.Fatalf("srtt %v", s)
		}
		var closedAt time.Time
		p.setHandler(func(f wire.Frame) {
			if f.Type == wire.TypeClose {
				closedAt = time.Now()
			}
		})
		c.Retire(wire.CloseRetire)
		hWait(t, c)
		p.close() // joins the peer's reader: closedAt is final
		dead, cause, _, at := c.Death()
		if !dead || cause != CauseRetired {
			t.Fatalf("cause %v", cause)
		}
		if got, want := at.Sub(closedAt), 500*time.Millisecond; got != want {
			t.Fatalf("retired %v after CLOSE, want the drain bound %v", got, want)
		}
		fr := p.received()
		if last := fr[len(fr)-1]; last.Type != wire.TypeClose || p.count(wire.TypeClose) != 1 {
			t.Fatalf("last frame %v, CLOSE frames %d", last.Type, p.count(wire.TypeClose))
		}
	})
}

// TestGoAwayPrecedesClose: GoAway queues GOAWAY ahead of every further
// frame, the endpoint's last frames (an RST here) follow, CLOSE is last.
func TestGoAwayPrecedesClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		ep := &hEP{}
		c.Start(ep, &hBell{}, StartOptions{})
		synctest.Wait()
		var once atomic.Bool
		ep.setFill(func(c *Conn, b *Batch) {
			if once.CompareAndSwap(false, true) {
				b.AddRst(wire.SessionHandle, &wire.Rst{Code: wire.RstGoingAway})
			}
		})
		c.GoAway()
		synctest.Wait()
		var order []wire.Type
		for _, f := range p.received() {
			if f.Type != wire.TypePing && f.Type != wire.TypePong {
				order = append(order, f.Type)
			}
		}
		want := []wire.Type{wire.TypeGoAway, wire.TypeRst, wire.TypeClose}
		if len(order) != 3 || order[0] != want[0] || order[1] != want[1] || order[2] != want[2] {
			t.Fatalf("frames %v, want %v", order, want)
		}
		if fr := p.received(); fr[len(fr)-1].Type != wire.TypeClose {
			t.Fatalf("a frame followed CLOSE: %v", fr[len(fr)-1].Type)
		}
		p.close() // EOF after our CLOSE ends the retirement
		hWait(t, c)
		if cause := hCause(c); cause != CauseRetired {
			t.Fatalf("cause %v", cause)
		}
	})
}

// TestWriterNeverFillsAfterOwnKill_C1: the writer that kills its carrier
// (ping timeout here) exits without calling Fill again (design §4.0, C1).
func TestWriterNeverFillsAfterOwnKill_C1(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Timing.DeadMin, env.Timing.DeadMax = time.Second, time.Second
		c, p := hPair(t, env, nil)
		ep := &hEP{}
		var after atomic.Int32
		ep.setFill(func(c *Conn, b *Batch) {
			if dead, _, _, _ := c.Death(); dead {
				after.Add(1)
			}
		})
		c.Start(ep, &hBell{}, StartOptions{}) // the peer never answers the PING
		start := time.Now()
		hWait(t, c)
		dead, cause, _, at := c.Death()
		if !dead || cause != CausePingTimeout || at.Sub(start) != time.Second {
			t.Fatalf("death %v %v after %v", dead, cause, at.Sub(start))
		}
		if after.Load() != 0 || ep.fills.Load() == 0 {
			t.Fatalf("Fill ran %d times after the writer's own Kill (%d fills)", after.Load(), ep.fills.Load())
		}
		p.close()
	})
}

// TestWriteAndCloseVerdict: an unstarted carrier writes exactly one verdict
// frame with its next fseq, then closes in the L05 order (the peer reads
// the frame, then EOF); it ends as local_close and joins.
func TestWriteAndCloseVerdict(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Presets.FirstFseq = 0xfffffffe
		c, p := hPair(t, env, nil)
		var oa [wire.OpenAckFixedLen + 4]byte
		n := wire.PutOpenAck(oa[:], &wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeBacklog, Msg: []byte("full")})
		c.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, oa[:n], time.Now().Add(time.Second))
		hWait(t, c)
		<-p.done
		fr := p.received()
		if len(fr) != 1 || fr[0].Type != wire.TypeOpenAck || fr[0].Fseq != 0xfffffffe {
			t.Fatalf("frames %+v", fr)
		}
		if a, err := wire.ParseOpenAck(fr[0].Payload); err != nil || a.Code != wire.CodeBacklog {
			t.Fatalf("OPEN_ACK %+v %v", a, err)
		}
		if err := p.readErr(); err != io.EOF {
			t.Fatalf("peer read %v, want EOF after the verdict", err)
		}
		if cause := hCause(c); cause != CauseLocalClose {
			t.Fatalf("cause %v", cause)
		}
		p.close()
	})
}

// TestStartAfterKill: an unstarted carrier is discarded with Kill (Done
// closes once the conn is closed); a later Start starts nothing and rings.
func TestStartAfterKill(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		if !c.Kill(CauseLocalClose, "discarded") {
			t.Fatal("Kill on an unstarted carrier lost")
		}
		hWait(t, c)
		var bell hBell
		c.Start(&hEP{}, &bell, StartOptions{})
		synctest.Wait()
		if bell.n.Load() != 1 || len(p.received()) != 0 {
			t.Fatalf("rings %d, frames %d", bell.n.Load(), len(p.received()))
		}
		p.close()
		if env.Budget.Used() != 0 {
			t.Fatalf("budget %d", env.Budget.Used())
		}
	})
}

// TestCarrierBidirectionalBulk (L08): two carriers over an unbuffered pipe
// send 8 MiB to each other at once, with PINGs and PONGs flowing both ways;
// readers never wait for their own writers, so neither side deadlocks, and
// both streams arrive intact.
func TestCarrierBidirectionalBulk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		ca, cb := hConn(env, a), hConn(env, b)
		sa, sb := newSource(env, ChunkSize, true), newSource(env, ChunkSize, true)
		sa.keepData, sb.keepData = true, true
		const total = 8 << 20
		sa.offer(total)
		sb.offer(total)
		ca.Start(sa, &hBell{}, StartOptions{})
		cb.Start(sb, &hBell{}, StartOptions{})
		for sa.rxBytes.Load() < total || sb.rxBytes.Load() < total {
			time.Sleep(50 * time.Millisecond)
			if dead, cause, detail, _ := ca.Death(); dead {
				t.Fatalf("A died: %v %s", cause, detail)
			}
		}
		hCheckReceived(t, &sa.hEP, total)
		hCheckReceived(t, &sb.hEP, total)
		if ca.Stats().SRTT == 0 && cb.Stats().MinRTT == 0 && ca.Stats().Frames == 0 {
			t.Fatal("no PING/PONG exchange")
		}
		ca.Kill(CauseLocalClose, "test end")
		hWait(t, ca)
		hWait(t, cb)
		sa.chunk.Release()
		sb.chunk.Release()
		if env.Budget.Used() != 0 {
			t.Fatalf("budget %d", env.Budget.Used())
		}
	})
}

// TestRetireFlushesBeforeClose_L05: Retire while the endpoint still has four
// batches of DATA: the writer keeps flushing round after round and appends
// CLOSE only in a round where the endpoint appended nothing, so every DATA
// byte precedes the single CLOSE and CLOSE is the last frame on the wire.
func TestRetireFlushesBeforeClose_L05(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		p.keep()
		src := newSource(env, ChunkSize, false)
		c.Start(src, &hBell{}, StartOptions{})
		synctest.Wait()
		src.offer(1 << 20) // four 256 KiB batches
		c.Retire(wire.CloseRetire)
		synctest.Wait()
		if got := hCheckData(t, p, 1<<20); got != 16 {
			t.Fatalf("%d DATA frames, want 16", got)
		}
		fr := p.received()
		if last := fr[len(fr)-1]; last.Type != wire.TypeClose || p.count(wire.TypeClose) != 1 {
			t.Fatalf("last frame %v, %d CLOSE frames", last.Type, p.count(wire.TypeClose))
		}
		if c.wr.coalesced < 5 {
			t.Fatalf("%d batches: the DATA did not need several rounds", c.wr.coalesced)
		}
		p.close() // EOF after our CLOSE ends the retirement
		hWait(t, c)
		if cause := hCause(c); cause != CauseRetired {
			t.Fatalf("cause %v", cause)
		}
		src.chunk.Release()
	})
}

// TestEndAfterPeerCloseIsRetirement_L05 (design §7.3): the peer sends
// nothing after its CLOSE — no PONG either — and closes the conn after its
// bounded drain, so a write that fails or stalls and a PING left
// unanswered after the peer's CLOSE end the planned retirement (cause
// retired: no failed mark, no immediate redial, no death migration), as a
// read error after a CLOSE already does; the same events without a CLOSE
// from the peer stay deaths with their own causes.
func TestEndAfterPeerCloseIsRetirement_L05(t *testing.T) {
	errBroken := errors.New("broken pipe")
	for _, tc := range []struct {
		name      string
		peerClose bool
		mode      string // "write error", "write stall" or "no PONG"
		want      Cause
		after     time.Duration // when the carrier ends, counted from the stimulus
	}{
		{"write error after the peer's CLOSE", true, "write error", CauseRetired, 0},
		{"write error", false, "write error", CauseTransportError, 0},
		{"write stall after the peer's CLOSE", true, "write stall", CauseRetired, 2 * time.Second},
		{"write stall", false, "write stall", CauseWriteStall, 2 * time.Second},
		{"no PONG after the peer's CLOSE", true, "no PONG", CauseRetired, 3 * time.Second},
		{"no PONG", false, "no PONG", CausePingTimeout, 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				var armed atomic.Bool
				release := make(chan struct{})
				var once sync.Once
				c, p := hPair(t, env, func(nc net.Conn) net.Conn {
					return &hookConn{
						Conn: nc,
						onWrite: func(nc net.Conn, b []byte) (int, error) {
							switch {
							case !armed.Load():
								return nc.Write(b)
							case tc.mode == "write stall":
								<-release // until the close
								return 0, net.ErrClosed
							}
							return 0, errBroken
						},
						onClose: func(nc net.Conn) error {
							once.Do(func() { close(release) })
							return nc.Close()
						},
					}
				})
				if tc.mode != "no PONG" {
					p.autoPong(nil)
				}
				ep := &hEP{}
				start := time.Now() // "no PONG": the first PING is committed now
				c.Start(ep, &hBell{}, StartOptions{})
				time.Sleep(time.Millisecond) // the first PING is answered (unless "no PONG") before the peer's CLOSE
				if tc.peerClose {
					if err := p.send(wire.TypeClose, 0, 0, []byte{byte(wire.CloseRetire)}); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if !c.PeerClosed() {
						t.Fatal("stimulus missing: the peer's CLOSE was not applied")
					}
				}
				if tc.mode != "no PONG" { // the endpoint has one more frame: an ACK
					start = time.Now()
					armed.Store(true)
					var sent atomic.Bool
					ep.setFill(func(c *Conn, b *Batch) {
						if sent.CompareAndSwap(false, true) {
							b.AddAck(wire.SessionHandle, 0, &wire.Ack{})
						}
					})
					c.Wake()
				}
				hWait(t, c)
				p.close()
				dead, cause, detail, at := c.Death()
				if !dead || cause != tc.want || at.Sub(start) != tc.after {
					t.Fatalf("death %v %v %q after %v, want %v after %v", dead, cause, detail, at.Sub(start), tc.want, tc.after)
				}
			})
		})
	}
}

// TestWriteAndCloseZeroDeadlineBounded: a verdict written with a zero
// deadline to a peer that never reads is bounded by the 1 s drain bound:
// the write gives up, the conn is closed exactly once, and Done closes then
// with nothing abandoned.
func TestWriteAndCloseZeroDeadlineBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		defer b.Close()
		hc := &hookConn{Conn: a}
		c := hConn(env, hc)
		start := time.Now()
		c.WriteAndClose(wire.TypeClose, 0, 0, []byte{byte(wire.CloseCapacity)}, time.Time{})
		hWait(t, c)
		if d := time.Since(start); d != time.Second {
			t.Fatalf("Done after %v, want the 1 s write bound", d)
		}
		if hc.writes.Load() != 1 || hc.closes.Load() != 1 || env.Abandon.Len() != 0 {
			t.Fatalf("writes %d, closes %d, abandoned %d", hc.writes.Load(), hc.closes.Load(), env.Abandon.Len())
		}
	})
}
