package lessons3

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestTrickleAndSilenceNoMigration_L30: traffic patterns never trigger a
// migration (L30: death only from carrier errors and PING/ACK liveness; no
// default idle timeout; "每 30s 写 1 字节、持续 10 分钟，以及静默 5 分钟，都是 0
// 次迁移"). Over two equal paths with default timings, each end writes one
// byte every 30 s for 10 minutes (the passive's writes interleaved, like
// server-sent events), then the session is silent for 5 minutes. The
// active carrier never changes, no carrier dies, no no-path episode
// starts, both ends count zero migrations, every byte arrives, and the
// session is still open at the end.
func TestTrickleAndSilenceNoMigration_L30(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: 10 * time.Millisecond}, {name: "b", delay: 10 * time.Millisecond}},
		})
		dc, pc := w.open(w.peer(), rendr.ModeSelector)
		first := mustActive(t, dc, "dialer")
		quiet := func(stage string) {
			t.Helper()
			for _, e := range []struct {
				side string
				c    *rendr.Conn
			}{{"dialer", dc}, {"passive", pc}} {
				st := e.c.Status()
				if cs := mustActive(t, e.c, e.side); cs.ID != first.ID {
					t.Fatalf("%s: %s active %+v, want A %d", stage, e.side, cs, first.ID)
				}
				if st.State != rendr.StateOpen || st.NoPathEpisodes != 0 || st.Migrations != (rendr.MigrationCounts{}) {
					t.Fatalf("%s: %s state %v, %d no-path episodes, migrations %+v", stage, e.side, st.State, st.NoPathEpisodes, st.Migrations)
				}
				for _, cs := range st.Carriers {
					if cs.State == rendr.CarrierDead {
						t.Fatalf("%s: %s carrier %+v died", stage, e.side, cs)
					}
				}
			}
		}

		const n, gap = 20, 30 * time.Second // one byte every 30 s for 10 minutes
		up := w.startFlow("up", dc, pc, 301, flowOpts{n: n, chunk: 1, gap: gap, keepOpen: true})
		time.Sleep(gap / 2)
		down := w.startFlow("down", pc, dc, 302, flowOpts{n: n, chunk: 1, gap: gap, keepOpen: true})
		up.wait(t, 11*time.Minute)
		down.wait(t, time.Minute)
		trickled := time.Now()
		if up.writes.Load() != n || down.writes.Load() != n {
			t.Fatalf("stimulus: %d / %d single-byte writes, want %d each", up.writes.Load(), down.writes.Load(), n)
		}
		quiet("after the trickle")

		tx, rx := dc.Status().TxBytes, dc.Status().RxBytes
		time.Sleep(5 * time.Minute)
		if st := dc.Status(); st.TxBytes != tx || st.RxBytes != rx {
			t.Fatalf("stimulus: %d/%d bytes moved during the silence", st.TxBytes-tx, st.RxBytes-rx)
		}
		quiet("after the silence")
		if d := time.Since(trickled); d < 5*time.Minute {
			t.Fatalf("silence lasted %v", d)
		}
		finishSession(t, dc, pc)
		w.finish()
	})
}

// TestSwitchCyclesNoLeak_L30_L52: 200 planned switch cycles leave the
// goroutine and resource counts at their baseline (L30: "200 次切换循环后
// goroutine 和 fd 回到基线"; L52: every goroutine has an owner that joins
// it). Two paths alternate between fast and slow; each time the selector
// switches by quality to the fast one (a JOIN of a new carrier; the old
// active retires with CLOSE once its data is acknowledged) while small
// writes flow both ways. After every cycle the retired carrier must be
// gone. After the first two cycles and after the last one — each time at a
// quiescent point — the rendr goroutines (by entry function), the open
// link conns (the in-memory analogue of fds) and the abandoned goroutines
// must be equal, and the buffered bytes of both Runtimes must not have
// grown beyond what the data in flight explains. Both ends count exactly
// 200 quality migrations and the streams arrive intact.
func TestSwitchCyclesNoLeak_L30_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := testhooks.Overrides{
			SelectorDwell: 100 * time.Millisecond, SelectorCooldown: 100 * time.Millisecond,
			ProbeInterval: 20 * time.Millisecond, ProbeFresh: 200 * time.Millisecond,
		}
		const fast, slow = 2 * time.Millisecond, 20 * time.Millisecond
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: fast}, {name: "b", delay: slow}},
			dov:   &ov,
		})
		links := map[string]*rendrtest.Link{"a": w.link("a"), "b": w.link("b")}
		dc, pc := w.open(w.peer(), rendr.ModeSelector)
		up := w.startFlow("up", dc, pc, 303, flowOpts{chunk: kib, gap: 20 * time.Millisecond})
		down := w.startFlow("down", pc, dc, 304, flowOpts{chunk: kib, gap: 20 * time.Millisecond})

		const cycles = 200
		var base snapshot
		for i := 1; i <= cycles; i++ {
			old := mustActive(t, dc, "dialer")
			next := "a"
			if old.Name == "a" {
				next = "b"
			}
			links[old.Name].SetDelay(slow, 0)
			links[next].SetDelay(fast, 0)
			mark := w.dev.mark()
			ev := w.dev.wait(t, mark, 5*time.Second, fmt.Sprintf("quality switch %d", i), isKind(rendr.EventMigration, dc.ID()))
			cs := mustActive(t, dc, "dialer")
			if ev.Cause != rendr.CauseQuality || ev.From != old.ID || cs.Name != next || ev.To != cs.ID {
				t.Fatalf("cycle %d: migration %+v, active %+v; want a quality switch from %d to a carrier of %s", i, ev, cs, old.ID, next)
			}
			waitState(t, 5*time.Second, fmt.Sprintf("cycle %d: the retired carrier gone", i), func() (bool, string) {
				dead, ok := carrierByID(dc, old.ID)
				pd, pok := carrierByID(pc, old.ID)
				open := openSessionConns(links)
				return ok && dead.State == rendr.CarrierDead && (!pok || pd.State == rendr.CarrierDead) && open == 1,
					fmt.Sprintf("dialer %+v, passive %+v (found %v), %d session carriers open", dead, pd, pok, open)
			})
			switch i {
			case 2:
				base = takeSnapshot(w, links)
				t.Logf("baseline after 2 cycles: %s", base)
			case cycles:
				if got := takeSnapshot(w, links); !got.noGrowth(base) {
					t.Fatalf("after %d switch cycles the resources differ from the baseline after 2:\nbase %s\nnow  %s", cycles, base, got)
				}
			}
		}
		up.stop()
		down.stop()
		up.wait(t, 30*time.Second)
		down.wait(t, 30*time.Second)
		want := rendr.MigrationCounts{Quality: cycles}
		wantMigrations(t, "dialer", dc, want)
		waitFor(t, time.Second, "the passive counting every switch", func() bool { return pc.Status().Migrations == want })
		if n := len(sessionCarriers(links["a"])) + len(sessionCarriers(links["b"])); n != cycles+1 {
			t.Fatalf("stimulus: %d session carriers created, want %d (one per switch)", n, cycles+1)
		}
		if up.recvd.Load() < 4*mib/5 || down.recvd.Load() < 4*mib/5 {
			t.Fatalf("load: %d / %d bytes carried across the cycles", up.recvd.Load(), down.recvd.Load())
		}
		finishSession(t, dc, pc)
		w.finish()
	})
}

// snapshot is the resource state compared by TestSwitchCyclesNoLeak_L30_L52.
type snapshot struct {
	goroutines map[string]int // rendr goroutines by entry function
	conns      int            // open link conns (session and probe carriers)
	buffered   [2]int64       // BufferedBytes of the dialer and the passive Runtime
	abandoned  [2]int
}

// takeSnapshot samples at a quiescent point: every goroutine of the bubble
// is blocked.
func takeSnapshot(w *world, links map[string]*rendrtest.Link) snapshot {
	synctest.Wait()
	s := snapshot{goroutines: rendrGoroutines()}
	for _, l := range links {
		for _, ci := range l.Carriers() {
			if !ci.Closed {
				s.conns++
			}
		}
	}
	for i, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		s.buffered[i], s.abandoned[i] = st.BufferedBytes, st.Abandoned
	}
	return s
}

// inFlightSlack is how much more a Runtime's buffer accounting may hold at
// one quiescent instant than at another while small writes flow: one send
// chunk and one receive run being in use (§4.1). A leak of anything a cycle
// allocates — a carrier's reader stage, a chunk — would exceed it many
// times over 200 cycles.
const inFlightSlack = 64*kib + 64 + 16*kib + 64

// noGrowth reports whether s (after the cycles) holds no more than base:
// the same goroutines and open conns, nothing abandoned, and buffers that
// did not grow beyond what data in flight explains.
func (s snapshot) noGrowth(base snapshot) bool {
	for i := range s.buffered {
		if s.buffered[i] > base.buffered[i]+inFlightSlack {
			return false
		}
	}
	return s.equalCounts(base)
}

func (s snapshot) equalCounts(o snapshot) bool {
	if s.conns != o.conns || s.abandoned != o.abandoned || len(s.goroutines) != len(o.goroutines) {
		return false
	}
	for k, v := range s.goroutines {
		if o.goroutines[k] != v {
			return false
		}
	}
	return true
}

func (s snapshot) String() string {
	return fmt.Sprintf("conns %d, buffered %v, abandoned %v, goroutines %v", s.conns, s.buffered, s.abandoned, s.goroutines)
}

// openSessionConns counts the session carriers of links that are still
// open.
func openSessionConns(links map[string]*rendrtest.Link) int {
	n := 0
	for _, l := range links {
		for _, ci := range sessionCarriers(l) {
			if !ci.Closed {
				n++
			}
		}
	}
	return n
}

// rendrGoroutines counts the live goroutines running rendr's own code by
// entry function (the bottom frame of the stack, in this module but not in
// rendrtest or a test file).
func rendrGoroutines() map[string]int {
	buf := make([]byte, 16<<20)
	n := runtime.Stack(buf, true)
	by := make(map[string]int)
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		lines := strings.Split(strings.TrimRight(g, "\n"), "\n")
		var fn, file string
		for i := 1; i+1 < len(lines); i += 2 {
			if strings.HasPrefix(lines[i], "created by ") {
				break
			}
			fn, file = lines[i], lines[i+1]
		}
		if k := strings.LastIndex(fn, "("); k > 0 {
			fn = fn[:k]
		}
		if strings.HasPrefix(fn, "github.com/FrankoonG/rendr/v2") && !strings.Contains(fn, "/rendrtest.") && !strings.Contains(file, "_test.go:") {
			by[fn]++
		}
	}
	return by
}
