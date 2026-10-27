package l4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP4 (m6-design §A7, §A16.1): ForwardPacket over real packet sessions
// between two Runtimes in a synctest bubble (the kit of pfkit_test.go).

// TestForwardPacketBoundaries_L36 (M6-D14, L36): datagrams of 0, 5, 11,
// 257 and MaxPayload bytes cross a forwarded flow — client → dialer
// forward → session → passive forward → target, and back — each arriving
// exactly once with its exact length and bytes (boundaries kept, zero
// length forwarded, nothing merged or split), and nothing else arrives.
func TestForwardPacketBoundaries_L36(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPFWorld(t, pfOpts{})
		ch := w.chain(pfChainOpts{})
		mp := ch.dc.MaxPayload()
		if mp != pfMTU-25 || ch.pc.MaxPayload() != mp {
			t.Fatalf("MaxPayload %d and %d, want %d", mp, ch.pc.MaxPayload(), pfMTU-25)
		}
		sizes := []int{0, 5, 11, 257, mp}
		for i, dir := range []struct {
			name     string
			from, to *rendrtest.DatagramConn
		}{{"up", ch.client, ch.target}, {"down", ch.target, ch.client}} {
			for k, n := range sizes {
				pfSend(t, dir.from, pfData(n, byte(16*i+k)))
			}
			got := map[int][]byte{}
			for range sizes {
				b := pfRecv(t, dir.to)
				if _, dup := got[len(b)]; dup {
					t.Fatalf("%s: a second %d-byte datagram", dir.name, len(b))
				}
				got[len(b)] = b
			}
			for k, n := range sizes {
				if b, ok := got[n]; !ok || !bytes.Equal(b, pfData(n, byte(16*i+k))) {
					t.Fatalf("%s: the %d-byte datagram arrived %v, intact %v", dir.name, n, ok, ok && bytes.Equal(b, pfData(n, byte(16*i+k))))
				}
			}
			pfNone(t, dir.to)
		}
		in, out := ch.results()
		n := uint64(len(sizes))
		if in.ToSession != n || in.ToLocal != n || out.ToSession != n || out.ToLocal != n || in.TooLarge+out.TooLarge+in.LocalNoise+out.LocalNoise != 0 {
			t.Fatalf("results: dialer %+v, passive %+v", in, out)
		}
		w.shutdown()
	})
}

// pfShortConn wraps a datagram conn as a rendr PacketConn adapter would
// (R1-16): a datagram longer than the Read buffer returns
// (len(b), io.ErrShortBuffer) and its rest is discarded.
type pfShortConn struct {
	net.Conn
	buf []byte
}

func (c *pfShortConn) Read(b []byte) (int, error) {
	if c.buf == nil {
		c.buf = make([]byte, 64<<10)
	}
	n, err := c.Conn.Read(c.buf)
	if err != nil {
		return 0, err
	}
	if n > len(b) {
		return copy(b, c.buf[:n]), io.ErrShortBuffer
	}
	return copy(b, c.buf[:n]), nil
}

// TestForwardPacketOversize_L37_L71 (M6-D14, M6-D32, R1-16; L37, L71): a
// local datagram of MaxPayload bytes crosses whole; one of MaxPayload + 1
// bytes and one of 3,000 are dropped and counted TooLarge — with a
// Linux-style local conn (a longer datagram truncated to the buffer, nil
// error), a Windows-style one (WSAEMSGSIZE or EMSGSIZE with the buffer
// filled) and a rendr PacketConn adapter ((n, io.ErrShortBuffer)) — and
// nothing of them ever reaches the session, split or truncated; the next
// datagram is delivered and the flow goes on.
func TestForwardPacketOversize_L37_L71(t *testing.T) {
	for _, r := range []struct {
		name  string
		trunc rendrtest.TruncMode
		wrap  bool
	}{
		{"linux truncation", rendrtest.TruncLinux, false},
		{"windows WSAEMSGSIZE", rendrtest.TruncWindows, false},
		{"io.ErrShortBuffer", rendrtest.TruncLinux, true},
	} {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPFWorld(t, pfOpts{})
				dc, pc := w.dial(rendr.DialOptions{})
				mp := dc.MaxPayload()
				app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{Trunc: r.trunc})
				var l net.Conn = local
				if r.wrap {
					l = &pfShortConn{Conn: local}
				}
				ctx, cancel := context.WithCancel(context.Background())
				res := pfForward(ctx, dc, l, FlowIdle{})
				whole, next := pfData(mp, 0xA0), pfData(7, 0xC0)
				pfSend(t, app, whole)
				pfSend(t, app, pfData(mp+1, 0xB0))
				pfSend(t, app, pfData(3000, 0xB1))
				pfSend(t, app, next)
				for _, want := range [][]byte{whole, next} {
					got, err := pfRecvPC(t, pc)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("passive read %d bytes (%v), want the %d-byte datagram tagged %#x", len(got), err, len(want), tagOf(want))
					}
				}
				if got, err := pfRecvPC(t, pc); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("passive read a further %d-byte datagram (%v): an oversize one leaked", len(got), err)
				}
				// The flow goes on: the reverse direction too.
				back := pfData(9, 0xD0)
				pc.WriteTo(back, nil)
				pfExpect(t, app, back)
				cancel()
				out := <-res
				if out.TooLarge != 2 || out.ToSession != 2 || out.ToLocal != 1 || out.LocalErr != nil || !errors.Is(out.SessionErr, context.Canceled) {
					t.Fatalf("result %+v: want TooLarge 2, ToSession 2, ToLocal 1, ended by ctx", out)
				}
				if c := app.Counts(); c.Out != 4 {
					t.Fatalf("stimulus: the application sent %d datagrams, want 4", c.Out)
				}
				if r.trunc == rendrtest.TruncWindows {
					if c := local.Counts(); c.Truncated != 1 {
						t.Fatalf("stimulus: %d truncated reads, want the 3,000-byte one", c.Truncated)
					}
				}
				w.shutdown()
			})
		})
	}
}

// pfAbortIdle reports whether err is the peer side of an idle expiry.
func pfAbortIdle(err error) bool {
	c, remote, ok := abortCode(err)
	return ok && c == rendr.AbortIdle && remote
}

// TestForwardPacketIdleClasses_L30_L72 (M6-D8, M6-D9, M6-D10, R1-7,
// R1-19, R1-23; L30, L72): each forward sets Short on its session at once
// and Stream with one SetIdleTimeout call when the flow becomes a stream
// at its end; the end whose limit runs out first ends the flow
// (ErrIdleTimeout there, *AbortError{AbortIdle} at the other), no earlier
// than the limit after that end's last datagram and no later than
// PacketPing after that. The rows run with both Runtimes' Config.IdleTimeout at 60 s,
// which the forwards override. Rows:
//   - the default rule (promoteOnReply): an unreplied flow stays short and
//     ends 30 s after its datagram; a replied one is a stream from the
//     first reply at both ends and ends 180 s after the reply; a reply
//     3 s late is still a reply;
//   - O-1 (a) (promoteActive): one exchange, then silence, stays short and
//     ends 30 s after the reply; exchanges both ways every 500 ms for
//     2.5 s make a stream (one SetIdleTimeout(Stream) per end) that ends
//     180 s after its last datagram; a reply after a 3-s gap starts a new
//     activity period and does not promote;
//   - both rules: a negative Stream turns expiry off once the flow is a
//     stream, and a negative Short for both classes (no idle end in 24
//     virtual hours; the flow still carries datagrams).
//
// raceSkipsIdleRow are TestForwardPacketIdleClasses_L30_L72's rows that
// the race lane leaves to the non-race unit and sweep lanes (racebudget,
// M6 I1: the race-unit pass exceeded 280 s, R1-37; each runs 24 virtual
// hours of PINGs). Under -race each negative class still runs once under
// the rule in force (promoteActive): "active rule: negative Stream" and
// "active rule: negative Short"; every bound is unchanged.
var raceSkipsIdleRow = map[string]bool{
	"reply rule: negative Stream":                 true,
	"reply rule: negative Short":                  true,
	"active rule: a negative Short with a stream": true,
}

func TestForwardPacketIdleClasses_L30_L72(t *testing.T) {
	const s = time.Second
	type ex struct {
		at    time.Duration // after the first datagram
		reply bool          // the target writes (else the client)
	}
	exch := func(n int, every time.Duration) []ex { // n exchanges: a datagram and its reply, every apart
		var e []ex
		for i := range n {
			e = append(e, ex{time.Duration(i) * every, false}, ex{time.Duration(i)*every + 10*time.Millisecond, true})
		}
		return e
	}
	rows := []struct {
		name   string
		rule   promoteMode
		idle   FlowIdle
		steps  []ex
		stream bool          // both ends promoted
		ends   time.Duration // the idle limit the flow ends at, after its last datagram; 0: never (24 h)
	}{
		{"reply rule: unreplied", promoteOnReply, FlowIdle{}, []ex{{0, false}, {s, false}}, false, 30 * s},
		{"reply rule: replied", promoteOnReply, FlowIdle{}, exch(1, 0), true, 180 * s},
		{"reply rule: a reply 3 s late", promoteOnReply, FlowIdle{}, []ex{{0, false}, {3 * s, true}}, true, 180 * s},
		{"active rule: one exchange", promoteActive, FlowIdle{}, exch(1, 0), false, 30 * s},
		{"active rule: both ways for 2.5 s", promoteActive, FlowIdle{}, exch(6, 500*time.Millisecond), true, 180 * s},
		{"active rule: a reply after a 3-s gap", promoteActive, FlowIdle{}, []ex{{0, false}, {3 * s, true}}, false, 30 * s},
		{"reply rule: negative Stream", promoteOnReply, FlowIdle{Stream: -1}, exch(6, 500*time.Millisecond), true, 0},
		{"active rule: negative Stream", promoteActive, FlowIdle{Stream: -1}, exch(6, 500*time.Millisecond), true, 0},
		{"reply rule: negative Short", promoteOnReply, FlowIdle{Short: -1}, []ex{{0, false}}, false, 0},
		{"active rule: negative Short", promoteActive, FlowIdle{Short: -1}, []ex{{0, false}}, false, 0},
		{"active rule: a negative Short with a stream", promoteActive, FlowIdle{Short: -1}, exch(6, 500*time.Millisecond), true, 0},
	}
	for _, r := range rows {
		if raceEnabled && raceSkipsIdleRow[r.name] {
			continue // racebudget (M6 I1, R1-37): run in full outside -race
		}
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pfRule(t, r.rule)
				cfg := rendr.Config{IdleTimeout: time.Minute, PingIdle: time.Minute}
				w := newPFWorld(t, pfOpts{dcfg: cfg, pcfg: cfg, ov: func(o *testhooks.Overrides) { o.PingIdle = time.Minute }})
				var spyIn, spyOut *pfIdleSpy
				ch := w.chain(pfChainOpts{
					idleIn: r.idle, idleOut: r.idle,
					wrapIn:  func(p packetSession) packetSession { spyIn = &pfIdleSpy{packetSession: p}; return spyIn },
					wrapOut: func(p packetSession) packetSession { spyOut = &pfIdleSpy{packetSession: p}; return spyOut },
				})
				t0 := time.Now()
				var lastIn, lastOut time.Time // each end's last datagram (the dialer's, the passive's)
				for i, e := range r.steps {
					time.Sleep(time.Until(t0.Add(e.at)))
					d := pfData(32, byte(i))
					if e.reply {
						pfSend(t, ch.target, d)
						lastOut = time.Now() // the passive forward's WriteTo
						pfExpect(t, ch.client, d)
						lastIn = time.Now() // the dialer's arrival and ReadFrom (the clock's move may lag)
					} else {
						pfSend(t, ch.client, d)
						lastIn = time.Now()
						pfExpect(t, ch.target, d)
						lastOut = time.Now()
					}
				}
				short, stream := r.idle.limits()
				wantCalls := []time.Duration{short}
				if r.stream && stream != short {
					wantCalls = append(wantCalls, stream)
				}
				if r.ends == 0 {
					time.Sleep(24 * time.Hour)
					d := pfData(32, 0xEE)
					pfSend(t, ch.client, d)
					pfExpect(t, ch.target, d)
					select {
					case res := <-ch.in:
						t.Fatalf("the flow ended: %+v", res)
					default:
					}
					in, out := ch.results()
					if !errors.Is(in.SessionErr, context.Canceled) || !errors.Is(out.SessionErr, context.Canceled) || in.Stream != r.stream || out.Stream != r.stream {
						t.Fatalf("results after 24 h: dialer %+v, passive %+v", in, out)
					}
				} else {
					// Each end's result and the instant it came.
					var res [2]PacketResult
					var at [2]time.Time
					for range 2 {
						select {
						case res[0] = <-ch.in:
							at[0] = time.Now()
						case res[1] = <-ch.out:
							at[1] = time.Now()
						case <-time.After(r.ends + time.Hour):
							t.Fatal("the flow did not end")
						}
					}
					in, out := res[0], res[1]
					// The end whose limit runs out first expires; the other reads
					// AbortIdle, unless its own limit ran out within the abort's
					// transit (their last datagrams are one link delay apart): an
					// expired end ends no earlier than the limit after its own
					// last datagram and no later than PacketPing after that.
					const packetPing = time.Second
					last := [2]time.Time{lastIn, lastOut}
					expired := 0
					for k := range 2 {
						switch e := res[k].SessionErr; {
						case errors.Is(e, rendr.ErrIdleTimeout):
							expired++
							if at[k].Before(last[k].Add(r.ends)) || at[k].After(last[k].Add(r.ends+packetPing+50*time.Millisecond)) {
								t.Fatalf("end %d expired %v after its last datagram, want %v + ≤ PacketPing: dialer %+v, passive %+v", k, at[k].Sub(last[k]), r.ends, in, out)
							}
						case pfAbortIdle(e):
							if o := at[1-k]; !errors.Is(res[1-k].SessionErr, rendr.ErrIdleTimeout) || at[k].After(o.Add(pfOneWay+50*time.Millisecond)) {
								t.Fatalf("end %d read the peer's expiry at %v, the peer's end at %v: dialer %+v, passive %+v", k, at[k].Sub(t0), o.Sub(t0), in, out)
							}
						default:
							t.Fatalf("end %d: %v; want an idle end: dialer %+v, passive %+v", k, e, in, out)
						}
					}
					if expired == 0 {
						t.Fatalf("no end expired: dialer %+v, passive %+v", in, out)
					}
					if in.Stream != r.stream || out.Stream != r.stream {
						t.Fatalf("Stream: dialer %v, passive %v; want %v", in.Stream, out.Stream, r.stream)
					}
				}
				for _, sp := range []*pfIdleSpy{spyIn, spyOut} {
					if got := sp.snapshot(); !slices.Equal(got, wantCalls) {
						t.Fatalf("SetIdleTimeout calls %v, want %v", got, wantCalls)
					}
				}
				w.shutdown()
			})
		})
	}
}

// TestForwardPacketSessionEnds_L01_L02 (M6-D11, §A5.3; L01, L02): every
// deterministic end of the session ends the forward with that end as
// SessionErr — the peer's close (io.EOF, after the datagrams the peer sent
// before it), idle here and at the peer, no carrier for NoPathGrace
// (ErrNoPath at both ends), a peer restart (ErrSessionLost; the old
// passive's ErrNoPath), the peer Runtime's Close and the dialer Runtime's
// (AbortGoingAway at the other end; the closed side's own net.ErrClosed),
// this side's ctx (ctx.Err(); the peer reads io.EOF) —
// local is closed (its far end reads net.ErrClosed), and no transport
// failure ever becomes a datagram: the applications receive exactly the
// datagrams that were sent.
func TestForwardPacketSessionEnds_L01_L02(t *testing.T) {
	isAbort := func(code rendr.AbortCode, remote bool) func(error) bool {
		return func(err error) bool { c, r, ok := abortCode(err); return ok && c == code && r == remote }
	}
	is := func(target error) func(error) bool { return func(err error) bool { return errors.Is(err, target) } }
	rows := []struct {
		name        string
		idleIn      FlowIdle
		held        bool // the target sends 3 datagrams right before the end: delivered before io.EOF
		end         func(w *pfWorld, ch *pfChain)
		inOK, outOK func(error) bool // the dialer's and the passive's SessionErr
	}{
		{"peer closed", FlowIdle{Short: -1}, true, func(w *pfWorld, ch *pfChain) { ch.cancelOut() },
			is(io.EOF), is(context.Canceled)},
		{"this side's ctx", FlowIdle{Short: -1}, false, func(w *pfWorld, ch *pfChain) { ch.cancelIn() },
			is(context.Canceled), is(io.EOF)},
		{"idle", FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second}, false, func(w *pfWorld, ch *pfChain) {},
			is(rendr.ErrIdleTimeout), pfAbortIdle},
		{"no path", FlowIdle{Short: -1}, false, func(w *pfWorld, ch *pfChain) { w.links[0].Refuse(true); w.links[0].Kill() },
			is(rendr.ErrNoPath), is(rendr.ErrNoPath)},
		{"peer restart", FlowIdle{Short: -1}, false, func(w *pfWorld, ch *pfChain) { w.restart(); w.links[0].Kill() },
			is(rendr.ErrSessionLost), is(rendr.ErrNoPath)},
		{"peer runtime close", FlowIdle{Short: -1}, false, func(w *pfWorld, ch *pfChain) { w.p.Close() },
			isAbort(rendr.AbortGoingAway, true), is(net.ErrClosed)},
		{"dialer runtime close", FlowIdle{Short: -1}, false, func(w *pfWorld, ch *pfChain) { w.d.Close() },
			is(net.ErrClosed), isAbort(rendr.AbortGoingAway, true)},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPFWorld(t, pfOpts{})
				ch := w.chain(pfChainOpts{idleIn: r.idleIn, idleOut: FlowIdle{Short: -1}})
				up, down := pfData(100, 1), pfData(200, 2)
				pfSend(t, ch.client, up)
				pfExpect(t, ch.target, up)
				pfSend(t, ch.target, down)
				pfExpect(t, ch.client, down)
				toClient := uint64(1)
				if r.held {
					for k := range 3 {
						pfSend(t, ch.target, pfData(300+k, byte(3+k)))
					}
					synctest.Wait() // handed to the passive session, not yet at the dialer
					toClient += 3
				}
				r.end(w, ch)
				in, out := <-ch.in, <-ch.out
				if !r.inOK(in.SessionErr) || !r.outOK(out.SessionErr) || in.LocalErr != nil || out.LocalErr != nil {
					t.Fatalf("dialer %+v (session %v), passive %+v (session %v)", in, ch.dc.Status().Err, out, ch.pc.Status().Err)
				}
				synctest.Wait()
				for _, app := range []*rendrtest.DatagramConn{ch.client, ch.target} {
					if _, err := app.Read(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("an application end reads %v after the forward ended, want net.ErrClosed (local closed)", err)
					}
				}
				// Exactly the datagrams sent reached each application (read,
				// or still queued when its local end closed).
				c, g := ch.client.Counts(), ch.target.Counts()
				if in.ToLocal != toClient || c.In+c.Dropped != toClient || out.ToLocal != 1 || g.In+g.Dropped != 1 {
					t.Fatalf("delivered: to the client %d (read %d, dropped at close %d), to the target %d (%d, %d); want %d and 1",
						in.ToLocal, c.In, c.Dropped, out.ToLocal, g.In, g.Dropped, toClient)
				}
				w.shutdown()
			})
		})
	}
}

// pfBlockConn is a local conn whose Writes block until its deadline or
// Close (a socket whose send buffer never drains), or until release lets
// them through; Reads pass through.
type pfBlockConn struct {
	net.Conn
	mu      sync.Mutex
	dl      time.Time
	wake    chan struct{}
	blocked int
	pass    bool // released: Writes before the deadline go to the wrapped conn
}

func newPFBlockConn(c net.Conn) *pfBlockConn { return &pfBlockConn{Conn: c, wake: make(chan struct{})} }

func (c *pfBlockConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.blocked++
	for !c.pass && (c.dl.IsZero() || time.Now().Before(c.dl)) {
		wake := c.wake
		var tc <-chan time.Time
		if !c.dl.IsZero() {
			tc = time.After(time.Until(c.dl))
		}
		c.mu.Unlock()
		select {
		case <-wake:
		case <-tc:
		}
		c.mu.Lock()
	}
	pass := c.pass && (c.dl.IsZero() || time.Now().Before(c.dl))
	c.mu.Unlock()
	if pass {
		return c.Conn.Write(b)
	}
	return 0, &net.OpError{Op: "write", Net: "udp", Err: os.ErrDeadlineExceeded}
}

// release lets the blocked Write, and every later one, through.
func (c *pfBlockConn) release() {
	c.mu.Lock()
	c.pass = true
	close(c.wake)
	c.wake = make(chan struct{})
	c.mu.Unlock()
}

// writes returns how many Writes were called.
func (c *pfBlockConn) writes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.blocked
}

func (c *pfBlockConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.dl = t
	close(c.wake)
	c.wake = make(chan struct{})
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *pfBlockConn) Close() error {
	c.SetDeadline(time.Unix(1, 0))
	return c.Conn.Close()
}

// TestForwardPacketNeverBlocks_L40 (M6-D14; L40): the two directions of a
// forward never wait for each other, and neither waits for the far side.
//   - A local that never takes a datagram (its Write blocks): the passive
//     forward stops reading its session, whose receive queue drops its
//     oldest datagrams (counted, DropRecvQueue) while the dialer's WriteTo
//     calls never block; meanwhile the target's datagrams still cross to
//     the client, every one.
//   - A session whose far end never reads: the dialer forward keeps
//     reading its local conn (no datagram waits or is dropped there: the
//     pipe's drop counter stays 0) and WriteTo never blocks; the core
//     drops and counts.
//   - The session ends (the peer's close, idle) while the passive's local
//     Write never returns: the forward returns endWriteGrace after the
//     session's end (at once when its ctx is done in between) with that
//     end as SessionErr, local closed once; a Write that returns within
//     endWriteGrace still delivers its datagram.
func TestForwardPacketNeverBlocks_L40(t *testing.T) {
	is := func(target error) func(error) bool { return func(err error) bool { return errors.Is(err, target) } }
	for _, r := range []struct {
		name        string
		idleOut     FlowIdle
		end         func(ch *pfChain)
		inOK, outOK func(error) bool // the dialer's and the passive's SessionErr
		ctxAfter    bool             // the passive's ctx is done endWriteGrace/2 after the end: the forward returns then, still with the session's end
	}{
		{"peer closed", FlowIdle{Short: -1}, func(ch *pfChain) { ch.cancelIn() }, is(context.Canceled), is(io.EOF), false},
		{"idle", FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second}, func(*pfChain) {}, pfAbortIdle, is(rendr.ErrIdleTimeout), false},
		{"peer closed, then ctx", FlowIdle{Short: -1}, func(ch *pfChain) { ch.cancelIn() }, is(context.Canceled), is(io.EOF), true},
	} {
		t.Run("session ends under a blocked write/"+r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPFWorld(t, pfOpts{})
				var blk *pfBlockConn
				var spy *spyConn
				ch := w.chain(pfChainOpts{idleIn: FlowIdle{Short: -1}, idleOut: r.idleOut, localOut: func(c *rendrtest.DatagramConn) net.Conn {
					blk = newPFBlockConn(c)
					spy = &spyConn{Conn: blk}
					return spy
				}})
				pfSend(t, ch.client, pfData(100, 1))
				time.Sleep(pfWithin)
				if blk.writes() != 1 {
					t.Fatalf("stimulus: %d local Writes at the passive, want the one that blocks", blk.writes())
				}
				r.end(ch)
				<-ch.pc.Done()
				ended := time.Now()
				want := endWriteGrace
				if r.ctxAfter {
					want = endWriteGrace / 2
					time.Sleep(want)
					ch.cancelOut()
				}
				var out PacketResult
				select {
				case out = <-ch.out:
				case <-time.After(time.Hour):
					ch.cancelOut() // releases the forward, so that the bubble can end
					<-ch.out
					t.Fatalf("the passive forward did not return within an hour of its session's end (%v)", ch.pc.Status().Err)
				}
				if el := time.Since(ended); el < want || el > want+pfOneWay {
					t.Fatalf("the passive forward returned %v after its session's end, want %v", el, want)
				}
				if !r.outOK(out.SessionErr) || out.LocalErr != nil || out.ToLocal != 0 || out.ToSession != 0 {
					t.Fatalf("passive forward %+v (session %v): want the session's end, no local error, nothing moved", out, ch.pc.Status().Err)
				}
				if in := <-ch.in; !r.inOK(in.SessionErr) || in.LocalErr != nil || in.ToSession != 1 {
					t.Fatalf("dialer forward %+v", in)
				}
				synctest.Wait()
				if _, _, closes, _ := spy.snapshot(); closes != 1 {
					t.Fatalf("local closed %d times, want once", closes)
				}
				if _, err := ch.target.Read(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("the target reads %v, want net.ErrClosed (local closed)", err)
				}
				w.shutdown()
			})
		})
	}
	t.Run("a write that returns within the grace", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPFWorld(t, pfOpts{})
			var blk *pfBlockConn
			ch := w.chain(pfChainOpts{idleIn: FlowIdle{Short: -1}, idleOut: FlowIdle{Short: -1}, localOut: func(c *rendrtest.DatagramConn) net.Conn {
				blk = newPFBlockConn(c)
				return blk
			}})
			pfSend(t, ch.client, pfData(100, 1))
			time.Sleep(pfWithin)
			if blk.writes() != 1 {
				t.Fatalf("stimulus: %d local Writes at the passive, want the one that blocks", blk.writes())
			}
			ch.cancelIn()
			<-ch.pc.Done()
			time.Sleep(endWriteGrace / 2)
			blk.release()
			out := <-ch.out
			if !errors.Is(out.SessionErr, io.EOF) || out.LocalErr != nil || out.ToLocal != 1 {
				t.Fatalf("passive forward %+v: want the datagram delivered, then the peer's io.EOF", out)
			}
			synctest.Wait()
			if c := ch.target.Counts(); c.In+c.Dropped != 1 {
				t.Fatalf("the target's end got %d datagrams (read %d, dropped at close %d), want 1", c.In+c.Dropped, c.In, c.Dropped)
			}
			<-ch.in
			w.shutdown()
		})
	})
	t.Run("local never reads", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pcfg := rendr.Config{Packet: rendr.PacketPolicy{Queue: 64 << 10}}
			w := newPFWorld(t, pfOpts{pcfg: pcfg})
			var blk *pfBlockConn
			ch := w.chain(pfChainOpts{localOut: func(c *rendrtest.DatagramConn) net.Conn { blk = newPFBlockConn(c); return blk }})
			// 100 datagrams per millisecond: at most 500 on the 5-ms link,
			// within its queue, so every one reaches the passive.
			const n = 2000
			for i := range n {
				pfSend(t, ch.client, pfData(1000, byte(i)))
				if i%100 == 99 {
					time.Sleep(time.Millisecond)
				}
			}
			for k := range 100 {
				pfSend(t, ch.target, pfData(50+k, byte(k)))
			}
			for k := range 100 {
				pfExpect(t, ch.client, pfData(50+k, byte(k)))
			}
			time.Sleep(100 * time.Millisecond)
			ps := ch.pc.Status().Packet
			if ps.Received != n || ps.DropRecvQueue < n-100 || blk.writes() != 1 {
				t.Fatalf("passive packet counters %+v, %d Writes blocked: want all %d received, the receive queue's drops counted, one Write blocked", ps, blk.writes(), n)
			}
			if ds := ch.dc.Status().Packet; ds.DropQueue+ds.DropAge+ds.DropTooLarge != 0 {
				t.Fatalf("dialer send drops %+v: its WriteTo must not have backed up", ds)
			}
			ch.cancelOut()
			out := <-ch.out
			if !errors.Is(out.SessionErr, context.Canceled) || out.LocalErr != nil || out.ToSession != 100 || out.ToLocal != 0 {
				t.Fatalf("passive forward %+v (blocked writes %d)", out, blk.writes())
			}
			in := <-ch.in
			if in.ToSession != n || in.ToLocal != 100 {
				t.Fatalf("dialer forward %+v: want all %d client datagrams read", in, n)
			}
			w.shutdown()
		})
	})
	t.Run("session never reads", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pcfg := rendr.Config{Packet: rendr.PacketPolicy{Queue: 64 << 10}}
			w := newPFWorld(t, pfOpts{pcfg: pcfg})
			dc, pc := w.dial(rendr.DialOptions{})
			app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			ctx, cancel := context.WithCancel(context.Background())
			res := pfForward(ctx, dc, local, FlowIdle{})
			const n = 5000
			for i := range n {
				pfSend(t, app, pfData(1000, byte(i)))
				if i%100 == 99 {
					synctest.Wait() // the forward has read them: none waits in the pipe
					time.Sleep(time.Millisecond)
				}
			}
			synctest.Wait()
			if c := local.Counts(); c.In != n || c.Dropped != 0 {
				t.Fatalf("the forward's local end read %d of %d datagrams, %d dropped waiting", c.In, n, c.Dropped)
			}
			time.Sleep(time.Second)
			ps, ds := pc.Status().Packet, dc.Status().Packet
			if ps.Received != n || ps.DropRecvQueue < n-100 || w.links[0].Stats().Session.Lost != 0 {
				t.Fatalf("dialer %+v, passive %+v, link %+v: want every datagram at the passive and its receive queue's drops counted", ds, ps, w.links[0].Stats().Session)
			}
			cancel()
			if out := <-res; out.ToSession != n || out.LocalErr != nil {
				t.Fatalf("forward %+v: want all %d datagrams handed to the session", out, n)
			}
			w.shutdown()
		})
	})
}

// pfFaultConn wraps a local conn: the next Read or Write returns a count
// outside its buffer (readN, writeN: −1 or len(b) + 1) for the datagram it
// moves; zero passes through.
type pfFaultConn struct {
	net.Conn
	mu            sync.Mutex
	readN, writeN int // 0: pass; −1: return −1; 1: return len(b) + 1
}

func (c *pfFaultConn) take(p *int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := *p
	*p = 0
	return v
}

func (c *pfFaultConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	switch c.take(&c.readN) {
	case -1:
		return -1, nil
	case 1:
		return len(b) + 1, nil
	}
	return n, err
}

func (c *pfFaultConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	switch c.take(&c.writeN) {
	case -1:
		return -1, nil
	case 1:
		return len(b) + 1, nil
	}
	return n, err
}

// pfTimeoutErr is a net.Error that is a timeout and not an Errno.
type pfTimeoutErr struct{}

func (pfTimeoutErr) Error() string   { return "embedder timeout" }
func (pfTimeoutErr) Timeout() bool   { return true }
func (pfTimeoutErr) Temporary() bool { return true }

// TestForwardPacketFatalLocal_L42_L52 (M6-D14, M6-D15, R1-2; L42, L52):
// each fatal local outcome, on a Read and on a Write, ends the forward:
// every errno of the fatal set (pfFatalErrnos: the OS's symbols and the
// Windows numbers), net.ErrClosed, io.EOF, a deadline
// (os.ErrDeadlineExceeded) and an embedder's timeout, a count above the
// buffer or below 0, and an embedder conn's own error. The forward
// returns with that error as LocalErr (errBadDatagramCount for a count)
// and net.ErrClosed as SessionErr; the session is closed (the peer reads
// io.EOF after the datagrams sent before), local is closed exactly once,
// and the pump has ended (the call returned). The flow moved datagrams
// both ways before.
func TestForwardPacketFatalLocal_L42_L52(t *testing.T) {
	type stim struct {
		name string
		err  error // injected; nil: a bad count
		n    int   // the bad count's kind (−1, 1)
	}
	var stims []stim
	for _, e := range pfFatalErrnos() {
		stims = append(stims, stim{e.name, e.err, 0}, stim{e.name + " in OpError", &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", e.err)}, 0})
	}
	stims = append(stims,
		stim{"net.ErrClosed", &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}, 0},
		stim{"io.EOF", io.EOF, 0},
		stim{"deadline", &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}, 0},
		stim{"embedder timeout", pfTimeoutErr{}, 0},
		stim{"embedder error", errors.New("embedder conn failed"), 0},
		stim{"count above the buffer", nil, 1},
		stim{"count below 0", nil, -1},
	)
	for _, side := range []string{"read", "write"} {
		for _, s := range stims {
			t.Run(side+"/"+s.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					w := newPFWorld(t, pfOpts{})
					dc, pc := w.dial(rendr.DialOptions{})
					app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
					fault := &pfFaultConn{Conn: local}
					spy := &spyConn{Conn: fault}
					res := pfForward(context.Background(), dc, spy, FlowIdle{})
					up, down := pfData(40, 1), pfData(50, 2)
					pfSend(t, app, up)
					if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, up) {
						t.Fatalf("before: passive read %d bytes, %v", len(got), err)
					}
					pc.WriteTo(down, nil)
					pfExpect(t, app, down)

					switch {
					case side == "read" && s.err != nil:
						local.Inject(s.err, false)
					case side == "read":
						fault.mu.Lock()
						fault.readN = s.n
						fault.mu.Unlock()
						pfSend(t, app, pfData(60, 3))
					case s.err != nil:
						local.InjectWrite(s.err, 1)
						pc.WriteTo(pfData(70, 4), nil)
					default:
						fault.mu.Lock()
						fault.writeN = s.n
						fault.mu.Unlock()
						pc.WriteTo(pfData(70, 4), nil)
					}
					var r PacketResult
					select {
					case r = <-res:
					case <-time.After(10 * time.Second):
						t.Fatal("the forward did not end")
					}
					wantErr := s.err
					if wantErr == nil {
						wantErr = errBadDatagramCount
					}
					if !errors.Is(r.LocalErr, wantErr) || !errors.Is(r.SessionErr, net.ErrClosed) {
						t.Fatalf("result %+v: want LocalErr %v and SessionErr net.ErrClosed", r, wantErr)
					}
					if _, err := pfRecvPC(t, pc); !errors.Is(err, io.EOF) {
						t.Fatalf("the peer reads %v, want io.EOF (the session closed)", err)
					}
					synctest.Wait()
					if _, _, closes, _ := spy.snapshot(); closes != 1 {
						t.Fatalf("local closed %d times, want once", closes)
					}
					if _, err := app.Read(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("the application end reads %v, want net.ErrClosed", err)
					}
					w.shutdown()
				})
			})
		}
	}
}

// pfHoldConn holds the first local Read that fails (at the teardown: its
// deadline) until hold is closed: the pump is then still inside local.
type pfHoldConn struct {
	net.Conn
	hold chan struct{}
	held atomic.Bool
}

func (c *pfHoldConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && c.held.CompareAndSwap(false, true) {
		<-c.hold
	}
	return n, err
}

// pfHoldSession holds the first Close of the session (the watcher's, on
// ctx), after the session closed, until hold is closed: the watcher is then
// still inside pc.
type pfHoldSession struct {
	packetSession
	hold   chan struct{}
	closes atomic.Int32
}

func (s *pfHoldSession) Close() error {
	err := s.packetSession.Close()
	if s.closes.Add(1) == 1 {
		<-s.hold
	}
	return err
}

// TestForwardPacketJoins_L52 (§A7.1 teardown, L52): ForwardPacket returns
// only after both of its goroutines ended. The pump: its local Read, failed
// by the teardown's deadline, is held — the call must not return before
// that Read returned. The watcher: ctx's halt closes the session (the
// caller's loop ends) and is held inside that Close — the call must not
// return before the halt finished. Then the forward ends by ctx and the
// peer reads io.EOF.
func TestForwardPacketJoins_L52(t *testing.T) {
	for _, r := range []struct {
		name  string
		pump  bool // hold the pump (else the watcher)
		stage string
	}{{"pump", true, "its pump was in local's Read"}, {"watcher", false, "its watcher was in the session's Close"}} {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPFWorld(t, pfOpts{})
				dc, pc := w.dial(rendr.DialOptions{})
				_, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
				hold := make(chan struct{})
				var once sync.Once
				release := func() { once.Do(func() { close(hold) }) }
				defer release()
				var sess packetSession = dc
				var l net.Conn = local
				var held func() bool
				if r.pump {
					hc := &pfHoldConn{Conn: local, hold: hold}
					l, held = hc, hc.held.Load
				} else {
					hs := &pfHoldSession{packetSession: dc, hold: hold}
					sess, held = hs, func() bool { return hs.closes.Load() >= 1 }
				}
				ctx, cancel := context.WithCancel(context.Background())
				res := pfForward(ctx, sess, l, FlowIdle{})
				synctest.Wait()
				cancel()
				synctest.Wait()
				if !held() {
					t.Fatal("stimulus: nothing is held")
				}
				select {
				case got := <-res:
					t.Fatalf("the forward returned (%+v) while %s", got, r.stage)
				default:
				}
				release()
				if got := <-res; !errors.Is(got.SessionErr, context.Canceled) || got.LocalErr != nil {
					t.Fatalf("result %+v: want the end by ctx", got)
				}
				if _, err := pfRecvPC(t, pc); !errors.Is(err, io.EOF) {
					t.Fatalf("the peer reads %v, want io.EOF", err)
				}
				w.shutdown()
			})
		})
	}
}

// pfGateConn holds the first SetDeadline call (the teardown's) until gate
// is closed.
type pfGateConn struct {
	net.Conn
	gate chan struct{}
	held atomic.Bool
}

func (c *pfGateConn) SetDeadline(t time.Time) error {
	if c.held.CompareAndSwap(false, true) {
		<-c.gate
	}
	return c.Conn.SetDeadline(t)
}

// TestForwardPacketCtxDuringTeardown_L52 (§A7.1 teardown, §A7.2; L52): a
// ctx done while the forward tears down after a fatal local error changes
// nothing — the end already happened: LocalErr is that error, SessionErr
// net.ErrClosed (not ctx.Err()), local is closed once and the peer reads
// io.EOF. The teardown is held in local's SetDeadline while ctx is
// cancelled, so the watcher, still live, sees ctx first.
func TestForwardPacketCtxDuringTeardown_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPFWorld(t, pfOpts{})
		dc, pc := w.dial(rendr.DialOptions{})
		app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
		gc := &pfGateConn{Conn: local, gate: make(chan struct{})}
		var once sync.Once
		release := func() { once.Do(func() { close(gc.gate) }) }
		defer release()
		spy := &spyConn{Conn: gc}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		res := pfForward(ctx, dc, spy, FlowIdle{})
		fatal := errors.New("embedder conn failed") // fatal on every OS
		local.InjectWrite(fatal, 1)
		pc.WriteTo(pfData(70, 4), nil)
		// Step virtual time until the teardown holds: the datagram's
		// arrival (one way); the session has not ended then (its end waits
		// for the peer's read of io.EOF), so the watcher still watches ctx.
		for k := 0; !gc.held.Load(); k++ {
			if k == 1000 {
				t.Fatal("stimulus: the teardown did not reach local's SetDeadline")
			}
			time.Sleep(time.Millisecond)
		}
		select {
		case <-dc.Done():
			t.Fatal("stimulus: the session ended before ctx")
		default:
		}
		cancel()
		synctest.Wait()
		release()
		r := <-res
		if !errors.Is(r.LocalErr, fatal) || !errors.Is(r.SessionErr, net.ErrClosed) {
			t.Fatalf("result %+v: want LocalErr %v and SessionErr net.ErrClosed, ctx's end ignored", r, fatal)
		}
		if _, err := pfRecvPC(t, pc); !errors.Is(err, io.EOF) {
			t.Fatalf("the peer reads %v, want io.EOF", err)
		}
		synctest.Wait()
		if _, _, closes, _ := spy.snapshot(); closes != 1 {
			t.Fatalf("local closed %d times, want once", closes)
		}
		if _, err := app.Read(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("the application end reads %v, want net.ErrClosed", err)
		}
		w.shutdown()
	})
}

// pfLateSession refuses SetIdleTimeout(stream) with net.ErrClosed, as a
// session that ended an instant before the promotion does (§A5.4).
type pfLateSession struct {
	packetSession
	stream  time.Duration
	refused atomic.Int32
}

func (s *pfLateSession) SetIdleTimeout(d time.Duration) error {
	if d == s.stream {
		s.refused.Add(1)
		return net.ErrClosed
	}
	return s.packetSession.SetIdleTimeout(d)
}

// TestForwardPacketPromotionVsExpiry_L72 (§A5.4 "promotion vs expiry",
// M6-D9; L72): the promotion's SetIdleTimeout(Stream) returning
// net.ErrClosed is ignored — it is no local failure and ends nothing: the
// flow is a stream, keeps moving datagrams both ways, and ends by its
// session's end (here ctx).
func TestForwardPacketPromotionVsExpiry_L72(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pfRule(t, promoteOnReply)
		w := newPFWorld(t, pfOpts{})
		dc, pc := w.dial(rendr.DialOptions{})
		app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
		_, stream := FlowIdle{}.limits()
		late := &pfLateSession{packetSession: dc, stream: stream}
		ctx, cancel := context.WithCancel(context.Background())
		res := pfForward(ctx, late, local, FlowIdle{})
		for k := range 3 {
			up, down := pfData(20, byte(2*k)), pfData(30, byte(2*k+1))
			pfSend(t, app, up)
			if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, up) {
				t.Fatalf("exchange %d: the passive read %d bytes, %v", k, len(got), err)
			}
			pc.WriteTo(down, nil)
			pfExpect(t, app, down)
		}
		if late.refused.Load() != 1 {
			t.Fatalf("stimulus: %d SetIdleTimeout(Stream) calls refused, want the promotion's", late.refused.Load())
		}
		cancel()
		if r := <-res; !r.Stream || r.ToSession != 3 || r.ToLocal != 3 || r.LocalErr != nil || !errors.Is(r.SessionErr, context.Canceled) {
			t.Fatalf("result %+v: want a stream that moved 3 datagrams each way, ended by ctx", r)
		}
		w.shutdown()
	})
}

// TestForwardPacketSeedCounts_L72 (R1-10, M6-D9; L72): the passive's
// forward counts the first datagram that rode the OPEN — written to the
// target before Confirm, then handed to forwardPacket as its seed — toward
// its class: a flow whose only client datagram is that first one and
// whose target then streams to the client for 5 s becomes a stream at the
// passive under both rules, which without the seed sees one direction
// only.
func TestForwardPacketSeedCounts_L72(t *testing.T) {
	for _, rule := range []promoteMode{promoteOnReply, promoteActive} {
		t.Run(map[promoteMode]string{promoteOnReply: "reply rule", promoteActive: "active rule"}[rule], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pfRule(t, rule)
				w := newPFWorld(t, pfOpts{})
				tgtLocal, target := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
				served := w.serve(tgtLocal, FlowIdle{})
				first := pfData(29, 1)
				dc, err := DialUDP(context.Background(), w.peer, pfTarget, first, rendr.DialOptions{})
				if err != nil {
					t.Fatalf("DialUDP: %v", err)
				}
				s := <-served
				if s.err != nil || !bytes.Equal(s.req.First, first) {
					t.Fatalf("serve: %v, First %d bytes", s.err, len(s.req.First))
				}
				pfExpect(t, target, first)
				t0 := time.Now()
				sent := 0
				for time.Since(t0) < 5*time.Second {
					pfSend(t, target, pfData(100, 2))
					sent++
					if _, err := pfRecvPC(t, dc); err != nil {
						t.Fatalf("the client's read: %v", err)
					}
					time.Sleep(100 * time.Millisecond)
				}
				dc.Close()
				r := <-s.res
				if !r.Stream || r.ToSession != uint64(sent) || r.ToLocal != 0 || !errors.Is(r.SessionErr, io.EOF) {
					t.Fatalf("the passive's forward %+v: want a stream after %d target datagrams and the seed", r, sent)
				}
				w.shutdown()
			})
		})
	}
}
