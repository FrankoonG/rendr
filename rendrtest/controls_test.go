package rendrtest

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// counterNames names every counter for failure messages.
var counterNames = [nCtr]string{"Killed", "Bytes", "Dropped", "Held", "Corrupted", "FramesCorrupted",
	"FramesDropped", "FramesInjected", "BufferLost", "MaxDelay", "scripted", "blocked", "panics", "overReads", "captured"}

// snapCounters reads every counter of every class (all, session, probe).
func snapCounters(l *Link) (s [3][nCtr]int64) {
	for c := range s {
		for k := range nCtr {
			s[c][k] = l.ctr[c][k].Load()
		}
	}
	return s
}

// controlsRig is a link carrying one session carrier and one probe carrier
// whose first frames have crossed.
type controlsRig struct {
	h            *harness
	sCli, sSrv   net.Conn
	pCli, pSrv   net.Conn
	sData, pPing []byte // one frame each side writes next
	sAck, pPong  []byte // one frame each passive end writes next
}

func newControlsRig(t *testing.T) *controlsRig {
	h := newHarness(t, LinkConfig{Name: "controls"})
	r := &controlsRig{h: h}
	r.sCli, r.sSrv = h.session()
	r.pCli, r.pSrv = h.probe()
	r.sData = frameBytes(FrameData, 2, dataPayload(0, make([]byte, 300)))
	r.pPing = frameBytes(FramePing, 2, pingPayload(2))
	r.sAck = frameBytes(FrameAck, 2, ackPayload(300))
	r.pPong = frameBytes(FramePong, 2, pingPayload(2))
	return r
}

// TestLinkControlsCount_L60: every link control has a stimulus counter, and
// the counters are split by carrier class (session = first frame OPEN/JOIN,
// probe = PING) so that a stimulus proof counts only what touched a session.
// Each row applies one control on a link carrying one session and one probe
// carrier and checks the exact per-class deltas; every counter obeys
// All = Session + Probe.
func TestLinkControlsCount_L60(t *testing.T) {
	type deltas map[ctr][2]int64 // counter → (session, probe) delta
	rows := []struct {
		name string
		act  func(t *testing.T, r *controlsRig) deltas
	}{
		{"Bytes", func(t *testing.T, r *controlsRig) deltas {
			write(t, r.sCli, r.sData)
			readFrame(t, r.sSrv)
			write(t, r.pCli, r.pPing)
			readFrame(t, r.pSrv)
			return deltas{cBytes: {int64(len(r.sData)), int64(len(r.pPing))}}
		}},
		{"Kill", func(t *testing.T, r *controlsRig) deltas {
			write(t, r.sCli, r.sData)
			write(t, r.pCli, r.pPing)
			synctest.Wait() // both frames sit in the link: the passive ends do not read
			if n := r.h.l.Kill(); n != 2 {
				t.Fatalf("Kill = %d, want 2", n)
			}
			return deltas{cKilled: {1, 1}, cBufferLost: {int64(len(r.sData)), int64(len(r.pPing))}}
		}},
		{"SetBlackhole", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.SetBlackhole(true)
			write(t, r.sCli, r.sData)
			write(t, r.pCli, r.pPing)
			return deltas{cDropped: {int64(len(r.sData)), int64(len(r.pPing))}}
		}},
		{"SetStall", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.SetStall(true)
			write(t, r.sCli, r.sData)
			write(t, r.pCli, r.pPing)
			synctest.Wait()
			return deltas{cHeld: {1, 1}}
		}},
		{"SetDelay", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.SetDelay(20*time.Millisecond, 0)
			write(t, r.sCli, r.sData)
			write(t, r.pCli, r.pPing)
			return deltas{cMaxDelay: {int64(20 * time.Millisecond), int64(20 * time.Millisecond)}}
		}},
		{"CorruptNext", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.CorruptNext(Up)
			write(t, r.sCli, r.sData)
			readFrame(t, r.sSrv)
			write(t, r.pCli, r.pPing)
			readFrame(t, r.pSrv)
			return deltas{cCorrupted: {1, 1}}
		}},
		{"CorruptNextFrame", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.CorruptNextFrame(Up, FrameData, CorruptPayload)
			write(t, r.sCli, r.sData)
			write(t, r.pCli, r.pPing) // a probe carrier sends no DATA
			return deltas{cFramesCorrupted: {1, 0}}
		}},
		{"DropNextFrame", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.DropNextFrame(Down, FramePong)
			write(t, r.sSrv, r.sAck)
			write(t, r.pSrv, r.pPong)
			return deltas{cFramesDropped: {0, 1}}
		}},
		{"InjectAfterNextFrame", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.InjectAfterNextFrame(Down, FrameAck, FrameAck, 0, 1, ackPayload(1<<30))
			write(t, r.sSrv, r.sAck)
			write(t, r.pSrv, r.pPong)
			return deltas{cFramesInjected: {1, 0}}
		}},
		{"InjectRaw", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.InjectRaw(Up, r.pPing)
			return deltas{cFramesInjected: {1, 1}}
		}},
		{"CaptureNextFrame", func(t *testing.T, r *controlsRig) deltas {
			ch := r.h.l.CaptureNextFrame(Up, FramePing)
			write(t, r.sCli, frameBytes(FramePing, 2, pingPayload(9)))
			synctest.Wait()
			write(t, r.pCli, r.pPing)
			if len(<-ch) == 0 {
				t.Fatal("empty capture")
			}
			return deltas{cCaptured: {1, 0}}
		}},
		{"ScriptWrites", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.ScriptWrites(Up, WriteResult{ZeroWrite: true})
			if n, err := r.sCli.Write(r.sData); n != 0 || err != nil {
				t.Fatalf("scripted Write = (%d, %v)", n, err)
			}
			r.h.l.ScriptWrites(Up, WriteResult{N: 1, Relative: true})
			if n, _ := r.pCli.Write(r.pPing); n != len(r.pPing)+1 {
				t.Fatalf("scripted Write = %d", n)
			}
			return deltas{cScripted: {1, 1}}
		}},
		{"BlockWrites", func(t *testing.T, r *controlsRig) deltas {
			r.h.l.BlockWrites(Up, BlockSoft)
			for _, c := range []net.Conn{r.sCli, r.pCli} {
				c.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := c.Write([]byte{1}); err == nil {
					t.Fatal("a Soft-blocked Write succeeded")
				}
			}
			return deltas{cBlocked: {1, 1}}
		}},
		{"PanicWrites", func(t *testing.T, r *controlsRig) deltas {
			for _, c := range []net.Conn{r.sCli, r.pCli} {
				r.h.l.PanicWrites(Up)
				func() {
					defer func() { recover() }()
					c.Write([]byte{1})
					t.Fatal("no panic")
				}()
			}
			return deltas{cPanics: {1, 1}}
		}},
		{"OverRead", func(t *testing.T, r *controlsRig) deltas {
			write(t, r.sCli, r.sData)
			write(t, r.pCli, r.pPing)
			for _, c := range []net.Conn{r.sSrv, r.pSrv} {
				r.h.l.OverRead(Down)
				if n, _ := c.Read(make([]byte, 8)); n != 9 {
					t.Fatalf("over-read reported %d, want 9", n)
				}
			}
			return deltas{cOverReads: {1, 1}}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newControlsRig(t)
				defer r.h.l.Close()
				synctest.Wait()
				before := snapCounters(r.h.l)
				want := row.act(t, r)
				synctest.Wait()
				after := snapCounters(r.h.l)
				for k := range nCtr {
					var d [3]int64
					for c := range d {
						d[c] = after[c][k] - before[c][k]
					}
					if k == cMaxDelay {
						d = [3]int64{after[0][k], after[1][k], after[2][k]}
					}
					w, ok := want[k]
					switch {
					case ok && (d[1] != w[0] || d[2] != w[1]):
						t.Errorf("%s: session %d, probe %d; want %d, %d", counterNames[k], d[1], d[2], w[0], w[1])
					case ok && w[0]+w[1] == 0:
						t.Errorf("%s: the row expects no stimulus", counterNames[k])
					case !ok && k != cBytes && (d[1] != 0 || d[2] != 0):
						t.Errorf("%s moved (session %d, probe %d) without its control", counterNames[k], d[1], d[2])
					}
					if k != cMaxDelay && d[0] != d[1]+d[2] {
						t.Errorf("%s: all %d != session %d + probe %d", counterNames[k], d[0], d[1], d[2])
					}
				}
			})
		})
	}
}

// TestLinkLevelCounters: the counters that are not per carrier — dial
// attempts and failures, and bytes through the rate limiter.
func TestLinkLevelCounters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "level"})
		defer h.l.Close()
		cli, srv := h.dial()
		h.l.SetRefuse(true)
		h.l.Dial(context.Background())
		h.l.SetRefuse(false)
		h.l.SetDial(DialError)
		h.l.Dial(context.Background())
		h.l.SetRate(1 << 20)
		write(t, cli, make([]byte, 1000))
		readN(t, srv, 1000)
		st := h.l.Stats()
		if st.Dials != 3 || st.DialFailures != 2 || st.Throttled != 1000 {
			t.Fatalf("Dials %d, DialFailures %d, Throttled %d; want 3, 2, 1000", st.Dials, st.DialFailures, st.Throttled)
		}
		h.l.SetRate(0)
		write(t, cli, make([]byte, 10))
		readN(t, srv, 10)
		if th := h.l.Stats().Throttled; th != 1000 {
			t.Fatalf("Throttled %d after the limit was lifted", th)
		}
	})
}
