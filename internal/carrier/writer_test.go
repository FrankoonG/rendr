package carrier

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// hCheckData verifies that the DATA frames a peer received carry the
// hSource pattern, cover [0, n) in order without gaps or overlaps, and
// returns their count.
func hCheckData(t *testing.T, p *wirePeer, n uint64) int {
	t.Helper()
	var next uint64
	frames := 0
	for _, f := range p.received() {
		if f.Type != wire.TypeData {
			continue
		}
		off := binary.BigEndian.Uint64(f.Payload)
		if off != next {
			t.Fatalf("DATA at %d, want %d", off, next)
		}
		body := f.Payload[wire.DataPrefixLen:]
		for i, b := range body {
			if b != hPattern(off+uint64(i)) {
				t.Fatalf("DATA byte at %d is %#x, want %#x", off+uint64(i), b, hPattern(off+uint64(i)))
			}
		}
		next += uint64(len(body))
		frames++
	}
	if next != n {
		t.Fatalf("DATA covers [0, %d), want [0, %d)", next, n)
	}
	return frames
}

// TestBatchWriteCount_L41: 1000 queued DATA frames leave in at most
// ⌈bytes/256 KiB⌉ + 1 physical writes (one Write call per batch on a conn
// that is not an OwnedTCP), and the byte stream re-parses into exactly the
// queued frames with consecutive fseq and valid CRCs.
func TestBatchWriteCount_L41(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		var hookWrites, hookFrames atomic.Int64
		env.Hooks = &testhooks.Hooks{BeforeWrite: func(id uint32, frames, bytes int) {
			hookWrites.Add(1)
			hookFrames.Add(int64(frames))
		}}
		var hc *hookConn
		c, p := hPair(t, env, func(nc net.Conn) net.Conn { hc = &hookConn{Conn: nc}; return hc })
		p.keep()
		const frames, size = 1000, 4 << 10
		src := newSource(env, size, false)
		src.offer(frames * size)
		c.Start(src, &hBell{}, StartOptions{})
		synctest.Wait() // every batch written and read; the writer sleeps
		total := uint64(frames * size)
		if got := hCheckData(t, p, total); got != frames {
			t.Fatalf("%d DATA frames, want %d", got, frames)
		}
		budget := uint64(env.Timing.BatchBudget)
		limit := int64((total+budget-1)/budget) + 1
		if w := hookWrites.Load(); w > limit || int64(hc.writes.Load()) != w {
			t.Fatalf("%d batches (%d Write calls) for %d bytes, limit %d", w, hc.writes.Load(), total, limit)
		}
		if hookFrames.Load() != int64(len(p.received())) || c.Stats().Frames != uint64(len(p.received())) {
			t.Fatalf("frames: hook %d, Stats %d, received %d", hookFrames.Load(), c.Stats().Frames, len(p.received()))
		}
		if c.wr.coalesced != uint64(hookWrites.Load()) || c.wr.vectored != 0 {
			t.Fatalf("write shapes: coalesced %d vectored %d", c.wr.coalesced, c.wr.vectored)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
		src.chunk.Release()
	})
}

// vecConn offers the methods a careless runtime would type-assert for:
// a vectored write and CloseWrite.
type vecConn struct {
	net.Conn
	vec, cw atomic.Int32
}

func (v *vecConn) WriteBuffers(b *net.Buffers) (int64, error) { v.vec.Add(1); return b.WriteTo(v.Conn) }
func (v *vecConn) CloseWrite() error                          { v.cw.Add(1); return nil }

// xorWrap is an embedder's wrapper (obfuscation) around a conn that has
// those methods; embedding promotes them, so only an exact ownership check
// keeps rendr from bypassing the wrapper's Write (L41, L57).
type xorWrap struct {
	*vecConn
	writes atomic.Int32
}

func (x *xorWrap) Write(p []byte) (int, error) {
	x.writes.Add(1)
	q := make([]byte, len(p))
	for i, b := range p {
		q[i] = b ^ 0x5a
	}
	return x.vecConn.Write(q)
}

// xorRead undoes xorWrap on the peer's side.
type xorRead struct{ net.Conn }

func (x xorRead) Read(p []byte) (int, error) {
	n, err := x.Conn.Read(p)
	for i := range p[:n] {
		p[i] ^= 0x5a
	}
	return n, err
}

// TestEmbeddingWrapperNotBypassed_L41: every byte goes through the
// embedder's wrapper (one Write per batch), never through a promoted
// vectored-write or CloseWrite method, also during retirement; the peer
// undoes the wrapper and parses an intact stream.
func TestEmbeddingWrapperNotBypassed_L41(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		w := &xorWrap{vecConn: &vecConn{Conn: a}}
		c := hConn(env, w)
		if c.owned != nil {
			t.Fatal("a wrapper was taken for the ownership token")
		}
		p := startPeer(xorRead{b}, env.Presets.firstFseq())
		p.keep()
		src := newSource(env, ChunkSize, false)
		src.offer(1 << 20)
		c.Start(src, &hBell{}, StartOptions{})
		synctest.Wait()
		hCheckData(t, p, 1<<20)
		c.Retire(wire.CloseRetire)
		synctest.Wait()
		p.close()
		hWait(t, c)
		if hCause(c) != CauseRetired {
			t.Fatalf("cause %v", hCause(c))
		}
		if w.vec.Load() != 0 || w.cw.Load() != 0 {
			t.Fatalf("wrapper bypassed: %d vectored writes, %d CloseWrite calls", w.vec.Load(), w.cw.Load())
		}
		if got := int64(w.writes.Load()); got == 0 || uint64(got) != c.wr.coalesced {
			t.Fatalf("%d wrapper writes, %d batches", got, c.wr.coalesced)
		}
		src.chunk.Release()
	})
}

// TestInvalidWriteCounts_L42: the first batch write returns a scripted
// count. A short write with progress and no error is completed on the same
// carrier and the stream stays intact; (0, nil), a negative count, a count
// beyond the buffer and a short write with an error kill the carrier with
// transport_error, and the peer never sees a partial frame as a frame.
func TestInvalidWriteCounts_L42(t *testing.T) {
	errBoom := errors.New("boom")
	cases := []struct {
		name   string
		write  func(nc net.Conn, p []byte) (int, error)
		alive  bool
		detail string
	}{
		{"short-nil", func(nc net.Conn, p []byte) (int, error) { n, _ := nc.Write(p[:len(p)-3]); return n, nil }, true, ""},
		{"zero-nil", func(nc net.Conn, p []byte) (int, error) { return 0, nil }, false, "(0, nil)"},
		{"negative", func(nc net.Conn, p []byte) (int, error) { return -1, nil }, false, "invalid count -1"},
		{"beyond", func(nc net.Conn, p []byte) (int, error) { n, _ := nc.Write(p); return n + 1, nil }, false, "invalid count"},
		{"short-err", func(nc net.Conn, p []byte) (int, error) { n, _ := nc.Write(p[:len(p)-1]); return n, errBoom }, false, "boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				var calls atomic.Int32
				c, p := hPair(t, env, func(nc net.Conn) net.Conn {
					return &hookConn{Conn: nc, onWrite: func(nc net.Conn, b []byte) (int, error) {
						if calls.Add(1) == 1 {
							return tc.write(nc, b)
						}
						return nc.Write(b)
					}}
				})
				p.keep()
				src := newSource(env, 16<<10, false)
				src.offer(64 << 10)
				c.Start(src, &hBell{}, StartOptions{})
				synctest.Wait()
				dead, cause, detail, _ := c.Death()
				if tc.alive {
					if dead {
						t.Fatalf("died: %v %s", cause, detail)
					}
					if calls.Load() < 2 {
						t.Fatal("the remainder of the short write was not written")
					}
					hCheckData(t, p, 64<<10)
					c.Kill(CauseLocalClose, "test end")
				} else if !dead || cause != CauseTransportError || !strings.Contains(detail, tc.detail) {
					t.Fatalf("death %v %v %q, want transport_error containing %q", dead, cause, detail, tc.detail)
				}
				hWait(t, c)
				p.close()
				if err := p.readErr(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("the peer saw a broken frame: %v", err)
				}
				src.chunk.Release()
			})
		})
	}
}

// TestWatchdogRacesWriteCompletion_L08 (C6): stage 1 of the write watchdog
// reports WriteBlocked at most once per write and never leaves the flag set
// once the write completed, whichever runs first: a callback that fires
// while the write is blocked, one that runs after the write completed, and
// a late one of an earlier write running after a newer write was armed.
// Then the real writer with writes returning exactly at PingBusy. Then
// stage 2 (design §0.14 B15): a write that returns exactly at the end of
// its stall window races stage 2's callback, already started (Stop cannot
// stop it); the carrier stays alive in both orders in which the callback
// checks after the write returned: at once, where the generation check
// sees the write completed, and only after the next write was armed, where
// the due-time check sees that the newer write's window is not due yet.
// The control order, the check while the write is still in progress, is a
// stall and kills at exactly the window (L24).
func TestWatchdogRacesWriteCompletion_L08(t *testing.T) {
	t.Run("forced orders", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			c := hConn(env, a)
			ep := &hEP{}
			c.ep = ep
			c.writerInit()
			pb := c.tm.PingBusy
			stall := c.tm.WriteStall

			// Stage 1 fires while the write is in progress, then the write
			// completes; a duplicate late callback changes nothing.
			gen := c.wstate.Load() >> 1
			c.armWatchdog(gen, time.Now(), stall)
			time.Sleep(pb)
			synctest.Wait()
			if !c.WriteBlocked() || ep.blocked.Load() != 1 {
				t.Fatalf("blocked write: flag %v, reports %d", c.WriteBlocked(), ep.blocked.Load())
			}
			c.disarmWatchdog(gen)
			c.watchStage1()
			if c.WriteBlocked() || ep.blocked.Load() != 1 {
				t.Fatalf("after completion: flag %v, reports %d", c.WriteBlocked(), ep.blocked.Load())
			}

			// The write completes first; the callback runs late.
			gen = c.wstate.Load() >> 1
			c.armWatchdog(gen, time.Now(), stall)
			time.Sleep(pb - time.Millisecond)
			c.disarmWatchdog(gen)
			time.Sleep(time.Millisecond)
			c.watchStage1()
			if c.WriteBlocked() || ep.blocked.Load() != 1 {
				t.Fatalf("late callback: flag %v, reports %d", c.WriteBlocked(), ep.blocked.Load())
			}

			// A late callback of write g runs after write g+1 was armed: it
			// must neither act for g nor act early for g+1.
			gen = c.wstate.Load() >> 1
			c.armWatchdog(gen, time.Now(), stall)
			time.Sleep(pb - 10*time.Millisecond)
			c.disarmWatchdog(gen)
			c.armWatchdog(gen+1, time.Now(), stall)
			time.Sleep(10 * time.Millisecond) // write g's stage 1 would be due now
			c.watchStage1()
			if c.WriteBlocked() || ep.blocked.Load() != 1 {
				t.Fatalf("stale callback acted on a newer write: flag %v, reports %d", c.WriteBlocked(), ep.blocked.Load())
			}
			time.Sleep(pb) // write g+1 is now blocked for PingBusy
			synctest.Wait()
			if !c.WriteBlocked() || ep.blocked.Load() != 2 {
				t.Fatalf("write g+1 blocked: flag %v, reports %d", c.WriteBlocked(), ep.blocked.Load())
			}
			c.disarmWatchdog(gen + 1)
			if c.WriteBlocked() {
				t.Fatal("flag left set")
			}
			// Stage 2 of a completed generation never kills.
			c.watchStage2()
			if dead, _, _, _ := c.Death(); dead {
				t.Fatal("stage 2 killed a carrier whose write completed")
			}
		})
	})
	t.Run("writes return at PingBusy", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			var writes atomic.Int32
			c, p := hPair(t, env, func(nc net.Conn) net.Conn {
				return &hookConn{Conn: nc, onWrite: func(nc net.Conn, b []byte) (int, error) {
					writes.Add(1)
					time.Sleep(50 * time.Millisecond) // exactly PingBusy
					return nc.Write(b)
				}}
			})
			p.autoPong(nil)
			src := newSource(env, 8<<10, false)
			src.offer(8 << 10)
			c.Start(src, &hBell{}, StartOptions{})
			for range 100 {
				time.Sleep(120 * time.Millisecond)
				synctest.Wait()
				if c.WriteBlocked() {
					t.Fatal("WriteBlocked set while no write has been in progress for PingBusy")
				}
				src.offer(8 << 10)
				c.Wake()
			}
			synctest.Wait()
			if r, w := src.blocked.Load(), writes.Load(); r > w || w < 100 {
				t.Fatalf("%d WriteBlocked reports for %d writes", r, w)
			} else {
				t.Logf("%d WriteBlocked reports for %d writes that returned exactly at PingBusy", r, w)
			}
			if c.WriteBlocked() {
				t.Fatal("flag left set")
			}
			c.Kill(CauseLocalClose, "test end")
			hWait(t, c)
			p.close()
			src.chunk.Release()
		})
	})
	t.Run("writes return at the stall window", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			order int    // 0: the check after the return; 1: after the next write was armed; 2: before the return
			fault string // orders 0 and 1: what a kill means (the check that should have spared the carrier)
		}{
			{"check after the return", 0, "stage 2 acted on a completed generation"},
			{"check after the next write was armed", 1, "stage 2 acted on the newer write before its stall window was due (a late callback of the earlier write)"},
			{"control check before the return", 2, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					env := hEnv()
					a, b := net.Pipe()
					defer a.Close()
					defer b.Close()
					c := hConn(env, a)
					ep := &hEP{}
					c.ep = ep
					c.writerInit()
					// Stage 2's timer starts its callback at the end of the
					// stall window as the writer's does, but the callback's
					// check waits until the test lets it run, so the test
					// orders it against the write's return at that instant.
					started, check := make(chan struct{}), make(chan struct{})
					c.wd2.Stop()
					c.wd2 = time.AfterFunc(time.Hour, func() {
						started <- struct{}{}
						<-check
						c.watchStage2()
					})
					c.wd2.Stop()
					stall := c.tm.WriteStall
					gen := c.wstate.Load() >> 1
					start := time.Now()
					c.armWatchdog(gen, start, stall) // write g starts
					<-started
					if d := time.Since(start); d != stall || !c.WriteBlocked() || ep.blocked.Load() != 1 {
						t.Fatalf("stage 2 started after %v (blocked %v, %d reports); want it at the stall window %v with the write reported blocked once (stimulus)",
							d, c.WriteBlocked(), ep.blocked.Load(), stall)
					}
					switch tc.order {
					case 0:
						c.disarmWatchdog(gen) // write g returns
						close(check)
					case 1:
						c.disarmWatchdog(gen)                   // write g returns
						c.armWatchdog(gen+1, time.Now(), stall) // write g+1 starts
						close(check)
						synctest.Wait()
						time.Sleep(time.Millisecond)
						c.disarmWatchdog(gen + 1) // write g+1 returns inside its window
					case 2:
						close(check)
						synctest.Wait()
						c.disarmWatchdog(gen) // the write returns after the kill
					}
					synctest.Wait()
					time.Sleep(2 * stall) // nothing else is due
					synctest.Wait()
					dead, cause, _, at := c.Death()
					if tc.order == 2 {
						if !dead || cause != CauseWriteStall || at.Sub(start) != stall {
							t.Fatalf("stage 2 checked while the write was in progress: death %v %v after %v, want write_stall at %v", dead, cause, at.Sub(start), stall)
						}
					} else if dead {
						t.Fatalf("a write that returned exactly at the end of its stall window killed the carrier (%v): %s", cause, tc.fault)
					}
					if c.WriteBlocked() || ep.blocked.Load() != 1 {
						t.Fatalf("after the write returned: flag %v, %d reports; want the flag clear and 1 report", c.WriteBlocked(), ep.blocked.Load())
					}
					c.Kill(CauseLocalClose, "test end")
					hWait(t, c)
				})
			})
		}
	})
}

// TestWriteStallAndBlocked_L24: a write that never returns is reported as
// WriteBlocked after PingBusy (stage 1) and kills the carrier with
// write_stall exactly at its stall window (stage 2); the close unblocks the
// write and the carrier joins.
func TestWriteStallAndBlocked_L24(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		release := make(chan struct{})
		var calls atomic.Int32
		c, p := hPair(t, env, func(nc net.Conn) net.Conn {
			return &hookConn{
				Conn: nc,
				onWrite: func(nc net.Conn, b []byte) (int, error) {
					if calls.Add(1) == 2 {
						<-release
						return 0, net.ErrClosed
					}
					return nc.Write(b)
				},
				onClose: func(nc net.Conn) error {
					select {
					case <-release:
					default:
						close(release)
					}
					return nc.Close()
				},
			}
		})
		p.autoPong(nil)
		src := newSource(env, 4<<10, false)
		c.Start(src, &hBell{}, StartOptions{})
		synctest.Wait() // the first PING written
		start := time.Now()
		src.offer(4 << 10)
		c.Wake()
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		if !c.WriteBlocked() || src.blocked.Load() != 1 {
			t.Fatalf("after PingBusy: blocked %v, reports %d", c.WriteBlocked(), src.blocked.Load())
		}
		hWait(t, c)
		dead, cause, _, at := c.Death()
		if !dead || cause != CauseWriteStall || at.Sub(start) != env.Timing.WriteStall {
			t.Fatalf("death %v %v after %v, want write_stall after %v", dead, cause, at.Sub(start), env.Timing.WriteStall)
		}
		p.close()
		src.chunk.Release()
	})
}

// TestShortWritesKeepOneStallWindow_C23: a conn that keeps making slow
// progress with short writes cannot keep a batch alive past its single
// stall window (it is not re-armed per short write); the same short writes
// fast enough complete the batch on the same carrier.
func TestShortWritesKeepOneStallWindow_C23(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chunk int
		alive bool
	}{{"slow", 1, false}, {"fast", 1024, true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				var calls atomic.Int32
				c, p := hPair(t, env, func(nc net.Conn) net.Conn {
					return &hookConn{Conn: nc, onWrite: func(nc net.Conn, b []byte) (int, error) {
						if calls.Add(1) == 1 {
							return nc.Write(b) // the first PING
						}
						time.Sleep(10 * time.Millisecond)
						return nc.Write(b[:min(len(b), tc.chunk)])
					}}
				})
				p.keep()
				p.autoPong(nil)
				src := newSource(env, 16<<10, false)
				c.Start(src, &hBell{}, StartOptions{})
				synctest.Wait()
				start := time.Now()
				src.offer(16 << 10)
				c.Wake()
				time.Sleep(3 * time.Second)
				synctest.Wait()
				dead, cause, _, at := c.Death()
				if tc.alive {
					if dead {
						t.Fatalf("fast short writes died: %v", cause)
					}
					hCheckData(t, p, 16<<10)
					c.Kill(CauseLocalClose, "test end")
				} else if !dead || cause != CauseWriteStall || at.Sub(start) != env.Timing.WriteStall {
					t.Fatalf("slow short writes: %v %v after %v", dead, cause, at.Sub(start))
				}
				hWait(t, c)
				p.close()
				src.chunk.Release()
			})
		})
	}
}

// TestPingFloodCollapsesToOnePong_L08: 1000 PINGs arrive while the writer
// is blocked in a write; the reader handles all of them without waiting for
// the writer, and once the write returns exactly one PONG — with the
// latest id — is written.
func TestPingFloodCollapsesToOnePong_L08(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		gate := make(chan struct{})
		var calls atomic.Int32
		c, p := hPair(t, env, func(nc net.Conn) net.Conn {
			return &hookConn{Conn: nc, onWrite: func(nc net.Conn, b []byte) (int, error) {
				if calls.Add(1) == 2 {
					<-gate
				}
				return nc.Write(b)
			}}
		})
		src := newSource(env, 4<<10, false)
		c.Start(src, &hBell{}, StartOptions{})
		synctest.Wait() // the first PING written
		src.offer(4 << 10)
		c.Wake()
		synctest.Wait() // the writer is blocked in its second write
		start := time.Now()
		for id := uint32(1); id <= 1000; id++ {
			if err := p.ping(id, false); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if d := time.Since(start); d >= 100*time.Millisecond {
			t.Fatalf("1000 PINGs took %v behind a blocked write", d)
		}
		if p.count(wire.TypePong) != 0 {
			t.Fatal("a PONG was written while the writer was blocked")
		}
		close(gate)
		synctest.Wait()
		var pongs []wire.Ping
		for _, f := range p.received() {
			if f.Type == wire.TypePong {
				pg, err := wire.ParsePing(f.Payload)
				if err != nil {
					t.Fatal(err)
				}
				pongs = append(pongs, pg)
			}
		}
		if len(pongs) != 1 || pongs[0].ID != 1000 || pongs[0].Nonce != 1000*977 {
			t.Fatalf("PONGs %+v, want exactly one for PING 1000", pongs)
		}
		if dead, cause, _, _ := c.Death(); dead {
			t.Fatalf("died: %v", cause)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
		src.chunk.Release()
	})
}
