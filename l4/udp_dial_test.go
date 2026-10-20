package l4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP4 (m6-design §A2.2, §A3.3, §A16.1; M6-D4, M6-D7, R1-4, R1-9): DialUDP.

// pfDialBegins counts the Dials that passed the dialer Runtime's entry
// checks (the metadata limit among them): the attempts that reach the
// network.
func pfDialBegins(n *atomic.Int64) func(*testhooks.Overrides) {
	return func(o *testhooks.Overrides) { o.Hooks = &testhooks.Hooks{DialBegin: func() { n.Add(1) }} }
}

// TestDialUDPFirstOnce_L47 (M6-D4, L47, L37): the first datagram reaches
// the target exactly once in both budget branches — it rides the OPEN
// when the whole metadata is at most 438 bytes (the passive's
// Request.First holds it, and it is written from there), else it follows
// the open by WriteTo (Request.First is nil) — the boundary included (425
// bytes of first datagram with the 13-byte IPv4 header ride, 426 do not),
// also when every datagram toward the passive is duplicated (the OPEN's
// REL copy included), over two links in race mode (the second carrier
// joins), and with the OPEN duplicated on a second carrier: link 0's
// answers are delayed beyond JoinStagger, so the second carrier sends its
// own OPEN (captured; it carries the first datagram when that rides) in
// race, selector and bond mode. The flow then carries the target's reply.
func TestDialUDPFirstOnce_L47(t *testing.T) {
	// 13 + 425 = 438 (M6-D4), written out rather than taken from
	// firstBudget, so a changed constant fails here too.
	sizes := []struct {
		n     int
		rides bool
	}{{29, true}, {425, true}, {426, false}, {600, false}}
	shapes := []struct {
		name   string
		links  int
		mode   rendr.Mode
		dup    bool // every datagram toward the passive duplicated
		second bool // link 0's answers delayed beyond JoinStagger: a second OPEN on link 1
	}{
		{"plain", 1, rendr.ModeSelector, false, false},
		{"duplicated", 1, rendr.ModeSelector, true, false},
		{"race", 2, rendr.ModeRace, false, false},
		{"second OPEN/race", 2, rendr.ModeRace, false, true},
		{"second OPEN/selector", 2, rendr.ModeSelector, false, true},
		{"second OPEN/bond", 2, rendr.ModeBond, false, true},
	}
	for _, sh := range shapes {
		for _, sz := range sizes {
			t.Run(sh.name+"/"+itoa(sz.n), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					w := newPFWorld(t, pfOpts{links: sh.links})
					if sh.dup {
						w.links[0].SetDuplicate(rendrtest.Up, 1)
					}
					tgtLocal, target := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
					served := w.serve(tgtLocal, FlowIdle{Short: -1})
					first := pfData(sz.n, 0x5A)
					var open1 <-chan []byte
					if sh.second {
						// The OPEN_ACK on link 0 comes after JoinStagger (1 s):
						// link 1's carrier sends its own OPEN meanwhile.
						w.links[0].SetDelay(rendrtest.Down, 1500*time.Millisecond, 0)
						open1 = w.links[1].CaptureNext(rendrtest.Up, rendrtest.FrameOpen)
					}
					pc, err := DialUDP(context.Background(), w.peer, pfTarget, first, rendr.DialOptions{Mode: sh.mode})
					if err != nil {
						t.Fatalf("DialUDP: %v", err)
					}
					if sh.second {
						select {
						case b := <-open1:
							if sz.rides && !bytes.Contains(b, first) {
								t.Fatal("stimulus: the second carrier's OPEN lacks the first datagram")
							}
						default:
							t.Fatal("stimulus: no OPEN on the second carrier before the open completed")
						}
						w.links[0].SetDelay(rendrtest.Down, pfOneWay, 0)
					}
					s := <-served
					if s.err != nil {
						t.Fatalf("serve: %v", s.err)
					}
					if rode := s.req.First != nil; rode != sz.rides || rode && !bytes.Equal(s.req.First, first) {
						t.Fatalf("the OPEN carried a %d-byte first datagram; want it to ride: %v", len(s.req.First), sz.rides)
					}
					pfExpect(t, target, first)
					pfNone(t, target)
					reply := pfData(10, 1)
					pfSend(t, target, reply)
					if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, reply) {
						t.Fatalf("the reply: %d bytes, %v", len(got), err)
					}
					if sh.dup {
						if st := w.links[0].Stats().Session; st.Duplicated == 0 {
							t.Fatalf("stimulus: no datagram duplicated: %+v", st)
						}
					}
					pc.Close()
					if r := <-s.res; r.ToLocal != map[bool]uint64{true: 0, false: 1}[sz.rides] || !errors.Is(r.SessionErr, io.EOF) {
						t.Fatalf("the passive's forward %+v", r)
					}
					if c := target.Counts(); c.In != 1 {
						t.Fatalf("the target read %d datagrams, want the first once", c.In)
					}
					w.shutdown()
				})
			})
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// TestDialUDPIdleDefault_L30 (M6-D7, plan:277; L30): a DialUDP session has
// DefaultFlowIdle (180 s) set: with both Runtimes' Config.IdleTimeout off
// and no forward, a flow that exchanged one datagram each way ends at the
// dialer 180 s after the reply was read (no earlier, at most PacketPing
// later) with ErrIdleTimeout, and the passive reads *AbortError{AbortIdle}.
func TestDialUDPIdleDefault_L30(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := rendr.Config{PingIdle: time.Minute}
		w := newPFWorld(t, pfOpts{dcfg: cfg, pcfg: cfg, ov: func(o *testhooks.Overrides) { o.PingIdle = time.Minute }})
		accepted := make(chan *rendr.PacketConn, 1)
		go func() {
			pend, err := w.ln.AcceptPacket(context.Background())
			if err != nil {
				accepted <- nil
				return
			}
			c, _ := pend.Confirm()
			accepted <- c
		}()
		dc, err := DialUDP(context.Background(), w.peer, pfTarget, nil, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("DialUDP: %v", err)
		}
		pc := <-accepted
		if pc == nil {
			t.Fatal("AcceptPacket/Confirm failed")
		}
		dc.WriteTo(pfData(20, 1), nil)
		if _, err := pfRecvPC(t, pc); err != nil {
			t.Fatal(err)
		}
		pc.WriteTo(pfData(20, 2), nil)
		if _, err := pfRecvPC(t, dc); err != nil {
			t.Fatal(err)
		}
		last := time.Now()
		select {
		case <-dc.Done():
		case <-time.After(time.Hour):
			t.Fatal("the flow did not end")
		}
		<-pc.Done()
		ended := time.Now() // Done follows the end decision at once here (no carrier to join for long)
		if !errors.Is(dc.Status().Err, rendr.ErrIdleTimeout) || !pfAbortIdle(pc.Status().Err) ||
			ended.Before(last.Add(DefaultFlowIdle)) || ended.After(last.Add(DefaultFlowIdle+time.Second+100*time.Millisecond)) {
			t.Fatalf("ended %v after the reply: dialer %v, passive %v; want ErrIdleTimeout at %v", ended.Sub(last), dc.Status().Err, pc.Status().Err, DefaultFlowIdle)
		}
		w.shutdown()
	})
}

// TestDialUDPErrors (M6-D7, R1-9; §A11): a bad target address fails
// ErrBadAddress, not ErrMetadataTooLarge, before any network I/O (no Dial
// began, no carrier was dialled); an o.Metadata of 65,530 bytes, which
// makes the flow's metadata longer than 65,535 bytes, fails
// ErrMetadataTooLarge (not ErrBadAddress), also before any; EarlyReturn
// is refused ErrProtocol, also before any; a first
// datagram that does not ride and is above the session's MaxPayload
// returns (nil, ErrPacketTooLarge) with the session closed (the passive
// reads io.EOF, the dialer Runtime keeps no session: no leak) and nothing
// sent to the target; DialUDP does not retain first (the caller
// overwrites it after the call, in both budget branches, and the target
// reads the original); an empty first is no first datagram; the passive's
// refusal is a *rendr.RejectError whose code CodeOf reports; a passive
// that never accepts packet sessions (a Server without UDP) answers
// ErrCapacity at its AcceptTimeout (10 s).
func TestDialUDPErrors(t *testing.T) {
	t.Run("before any I/O", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var begins atomic.Int64
			w := newPFWorld(t, pfOpts{ov: pfDialBegins(&begins)})
			for _, addr := range []string{"192.0.2.1", "192.0.2.1:0", ":53", "224.0.0.1:53", "255.255.255.255:53", "[fe80::1%eth0]:53", "[::ffff:224.0.0.1]:53", "a..b.test:53"} {
				if pc, err := DialUDP(context.Background(), w.peer, addr, pfData(20, 1), rendr.DialOptions{}); pc != nil || !errors.Is(err, ErrBadAddress) || errors.Is(err, rendr.ErrMetadataTooLarge) {
					t.Errorf("DialUDP(%q) = %v, %v; want ErrBadAddress alone", addr, pc, err)
				}
			}
			// The IPv4 header (11 bytes) and flen (2) + 65,530 = 65,543 > 65,535.
			big := rendr.DialOptions{Metadata: make([]byte, 65530)}
			for _, first := range [][]byte{nil, pfData(20, 1)} {
				if pc, err := DialUDP(context.Background(), w.peer, pfTarget, first, big); pc != nil || !errors.Is(err, rendr.ErrMetadataTooLarge) || errors.Is(err, ErrBadAddress) {
					t.Errorf("DialUDP with %d bytes of o.Metadata and a %d-byte first = %v, %v; want ErrMetadataTooLarge", len(big.Metadata), len(first), pc, err)
				}
			}
			if pc, err := DialUDP(context.Background(), w.peer, pfTarget, pfData(20, 1), rendr.DialOptions{EarlyReturn: true}); pc != nil || !errors.Is(err, rendr.ErrProtocol) {
				t.Errorf("DialUDP with EarlyReturn = %v, %v; want ErrProtocol", pc, err)
			}
			if n, dials := begins.Load(), w.links[0].Stats().Dials; n != 0 || dials != 0 {
				t.Fatalf("%d Dials began and %d carriers were dialled; want none", n, dials)
			}
			w.shutdown()
		})
	})
	t.Run("first above MaxPayload", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPFWorld(t, pfOpts{})
			tgtLocal, target := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			served := w.serve(tgtLocal, FlowIdle{Short: -1})
			first := pfData(pfMTU-25+1, 3)
			pc, err := DialUDP(context.Background(), w.peer, pfTarget, first, rendr.DialOptions{})
			if pc != nil || !errors.Is(err, rendr.ErrPacketTooLarge) {
				t.Fatalf("DialUDP with a %d-byte first datagram = %v, %v; want (nil, ErrPacketTooLarge)", len(first), pc, err)
			}
			s := <-served
			if s.err != nil {
				t.Fatalf("serve: %v", s.err)
			}
			if r := <-s.res; !errors.Is(r.SessionErr, io.EOF) || r.ToLocal != 0 {
				t.Fatalf("the passive's forward %+v: want the dialer's close (io.EOF) and nothing forwarded", r)
			}
			time.Sleep(time.Minute) // the end handshake and the lingering are over
			if st := w.d.Status().Sessions; st.Open+st.Lingering+st.Pending != 0 {
				t.Fatalf("the dialer Runtime holds sessions %+v: the closed session leaked", st)
			}
			if c := target.Counts(); c.In != 0 {
				t.Fatalf("the target read %d datagrams", c.In)
			}
			w.shutdown()
		})
	})
	t.Run("first not retained", func(t *testing.T) {
		for _, n := range []int{29, 600} {
			synctest.Test(t, func(t *testing.T) {
				w := newPFWorld(t, pfOpts{})
				tgtLocal, target := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
				served := w.serve(tgtLocal, FlowIdle{Short: -1})
				first := pfData(n, 7)
				want := bytes.Clone(first)
				pc, err := DialUDP(context.Background(), w.peer, pfTarget, first, rendr.DialOptions{})
				for i := range first {
					first[i] = 0xff
				}
				if err != nil {
					t.Fatalf("DialUDP: %v", err)
				}
				s := <-served
				if s.err != nil {
					t.Fatalf("serve: %v", s.err)
				}
				pfExpect(t, target, want)
				pc.Close()
				<-s.res
				w.shutdown()
			})
		}
	})
	t.Run("empty first", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPFWorld(t, pfOpts{})
			tgtLocal, target := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			served := w.serve(tgtLocal, FlowIdle{Short: -1})
			pc, err := DialUDP(context.Background(), w.peer, pfTarget, []byte{}, rendr.DialOptions{Metadata: []byte("app")})
			if err != nil {
				t.Fatalf("DialUDP: %v", err)
			}
			s := <-served
			if s.err != nil || s.req.First != nil || string(s.req.App) != "app" {
				t.Fatalf("serve: %+v", s)
			}
			pfNone(t, target)
			pc.Close()
			<-s.res
			w.shutdown()
		})
	})
	t.Run("refused", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPFWorld(t, pfOpts{})
			go func() {
				if pend, err := w.ln.AcceptPacket(context.Background()); err == nil {
					pend.Reject(uint32(CodeNotAllowed), "policy")
				}
			}()
			pc, err := DialUDP(context.Background(), w.peer, pfTarget, pfData(20, 1), rendr.DialOptions{})
			var re *rendr.RejectError
			if code, ok := CodeOf(err); pc != nil || !errors.As(err, &re) || !ok || code != CodeNotAllowed {
				t.Fatalf("DialUDP = %v, %v; want a *RejectError with CodeNotAllowed", pc, err)
			}
			w.shutdown()
		})
	})
	t.Run("no packet accept", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// NoPathGrace at its default (15 s), above the AcceptTimeout.
			w := newPFWorld(t, pfOpts{ov: func(o *testhooks.Overrides) { o.NoPathGrace = 0 }})
			t0 := time.Now()
			pc, err := DialUDP(context.Background(), w.peer, pfTarget, pfData(20, 1), rendr.DialOptions{})
			if el := time.Since(t0); pc != nil || !errors.Is(err, rendr.ErrCapacity) || el < 10*time.Second || el > 10*time.Second+100*time.Millisecond {
				t.Fatalf("DialUDP = %v, %v after %v; want ErrCapacity at the 10-s AcceptTimeout", pc, err, el)
			}
			w.shutdown()
		})
	})
}

// TestDialUDPMetadataLimitRetry_L37 (M6-D4, R1-4; L37): when the OPEN that
// carries a first datagram fails ErrMetadataTooLarge — this Runtime's
// Handshake.MaxMetadata (checked before any I/O) or the passive's
// (answered CodeMetadataSize after one round trip) — DialUDP opens exactly
// once more without it and writes it after the open: the flow opens, the
// target reads the datagram exactly once, and the passive's Request has no
// First. A limit below the header fails ErrMetadataTooLarge after exactly
// one retry. An OPEN without a first datagram, or one that fits, is never
// retried. Attempts are counted where they pass the entry checks
// (testhooks DialBegin).
func TestDialUDPMetadataLimitRetry_L37(t *testing.T) {
	rows := []struct {
		name        string
		local, peer int // the dialer's and the passive's Handshake.MaxMetadata (0: the default)
		first       int
		ok          bool
		begins      int64
	}{
		{"local 64, first 60", 64, 0, 60, true, 1},
		{"passive 256, first 300", 0, 256, 300, true, 2},
		{"passive 8: below the header", 0, 8, 20, false, 2},
		{"local 8: below the header", 8, 0, 20, false, 0},
		{"fits", 0, 0, 29, true, 1},
		{"passive 8, no first", 0, 8, 0, false, 1},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var begins atomic.Int64
				var dcfg, pcfg rendr.Config
				dcfg.Handshake.MaxMetadata, pcfg.Handshake.MaxMetadata = r.local, r.peer
				w := newPFWorld(t, pfOpts{dcfg: dcfg, pcfg: pcfg, ov: pfDialBegins(&begins)})
				tgtLocal, target := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
				var served <-chan pfServed
				if r.ok {
					served = w.serve(tgtLocal, FlowIdle{Short: -1})
				}
				first := pfData(r.first, 9)
				pc, err := DialUDP(context.Background(), w.peer, pfTarget, first, rendr.DialOptions{})
				if n := begins.Load(); n != r.begins {
					t.Fatalf("%d attempts reached the network, want %d (err %v)", n, r.begins, err)
				}
				if !r.ok {
					if pc != nil || !errors.Is(err, rendr.ErrMetadataTooLarge) {
						t.Fatalf("DialUDP = %v, %v; want ErrMetadataTooLarge", pc, err)
					}
					w.shutdown()
					return
				}
				if err != nil {
					t.Fatalf("DialUDP: %v", err)
				}
				s := <-served
				if s.err != nil || (r.begins == 2 || r.local != 0) != (s.req.First == nil) {
					t.Fatalf("serve: %v, Request.First %d bytes", s.err, len(s.req.First))
				}
				pfExpect(t, target, first)
				pfNone(t, target)
				pc.Close()
				<-s.res
				w.shutdown()
			})
		})
	}
}
