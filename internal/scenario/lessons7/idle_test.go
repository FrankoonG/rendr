package lessons7

import (
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestIdlePacketSessionWrites (M2 design §A8.3, §A4.3; M2-D65): an idle
// packet session costs one PING per PingIdle per carrier and nothing else.
// A selector session over one DatagramLink exchanges 50 datagrams each way,
// then nothing for 60 virtual seconds after its carriers left the packet-
// active cadence (PacketActive, 10 s). Over the minute, every datagram
// either end writes holds only PINGs and the PONGs that answer the peer's
// PINGs — no PACK, REL, RACK or DGRAM — each end's PINGs are PingIdle
// apart, and the carrier writers and session actors wake only for those
// datagrams (no timer while idle: an armed REL or PACK timer would wake
// them). The session then carries 50 datagrams each way intact.
func TestIdlePacketSessionWrites(t *testing.T) {
	runtime.SetBlockProfileRate(1) // before the goroutines whose waits are counted exist
	defer runtime.SetBlockProfileRate(0)
	synctest.Test(t, func(t *testing.T) {
		const owd = 5 * time.Millisecond
		w := newWorld(t, worldOpts{})
		_, car := w.addLink("a", owd)
		dc, pc := w.open(w.peer(car), rendr.DialOptions{})
		bw, ba := idleWakeups(idleWriterWait), idleWakeups(idleActorWait)
		burst(t, dc, pc, 1, 50, "before the idle minute: up")
		burst(t, pc, dc, 2, 50, "before the idle minute: down")
		if bw, ba = idleWakeups(idleWriterWait)-bw, idleWakeups(idleActorWait)-ba; bw < 50 || ba < 1 {
			// The measurement's own stimulus: 200 datagrams wake the writers
			// (the data plane runs without the actors, which see the
			// accounting).
			t.Fatalf("the block profile saw %d writer and %d actor wakeups for 200 datagrams", bw, ba)
		}
		time.Sleep(12 * time.Second) // PacketActive (10 s) ends the PacketPing cadence

		const pingIdle = 10 * time.Second // Timing.PingIdle's default
		from := time.Now()
		wr0, ac0 := idleWakeups(idleWriterWait), idleWakeups(idleActorWait)
		time.Sleep(time.Minute)
		to := time.Now()
		wr, ac := idleWakeups(idleWriterWait)-wr0, idleWakeups(idleActorWait)-ac0

		dtap, ptap := w.dconns.last(), w.pconns.last()
		var pings [2][]time.Time // per side: when it wrote a PING
		var pongs [2]int
		total := 0
		for side, tp := range []*tapPC{dtap, ptap} {
			_, writes := tp.snapshot()
			for _, d := range writes {
				if d.at.Before(from) || !d.at.Before(to) {
					continue
				}
				total++
				for _, f := range d.frames {
					switch f.typ {
					case wire.TypePing:
						pings[side] = append(pings[side], d.at)
					case wire.TypePong:
						pongs[side]++
					default:
						t.Fatalf("%s wrote %v at %v of the idle minute: only PING and PONG may leave an idle session",
							[2]string{"dialer", "passive"}[side], d.types(), d.at.Sub(from))
					}
				}
			}
		}
		t.Logf("idle minute: dialer PINGs %d, PONGs %d; passive PINGs %d, PONGs %d; %d datagrams; writer wakeups %d, actor wakeups %d",
			len(pings[0]), pongs[0], len(pings[1]), pongs[1], total, wr, ac)
		for side := range 2 {
			n := len(pings[side])
			if n < 5 || n > 6 {
				t.Fatalf("side %d: %d PINGs in the idle minute, want one per PingIdle (%v)", side, n, pingIdle)
			}
			for i := 1; i < n; i++ {
				if gap := pings[side][i].Sub(pings[side][i-1]); gap != pingIdle {
					t.Fatalf("side %d: PINGs %v apart, want PingIdle %v", side, gap, pingIdle)
				}
			}
			if peer := len(pings[1-side]); pongs[side] < peer-1 || pongs[side] > peer {
				t.Fatalf("side %d: %d PONGs for the peer's %d PINGs", side, pongs[side], peer)
			}
		}
		// Every wakeup of a writer or an actor is accounted for by a datagram
		// written or read: a timer armed while idle would add one per expiry.
		if limit := int64(2 * total); wr > limit || ac > limit {
			t.Fatalf("wakeups in the idle minute: writers %d, actors %d; want ≤ %d (two per datagram on the wire)", wr, ac, limit)
		}

		burst(t, dc, pc, 3, 50, "after the idle minute: up")
		burst(t, pc, dc, 4, 50, "after the idle minute: down")
		w.noViolation()
		if len(w.dev.of(rendr.EventCarrierDown))+len(w.pev.of(rendr.EventCarrierDown)) != 0 {
			t.Fatal("a carrier died while idle")
		}
		endPair(t, dc, pc, nil, nil)
		w.close()
	})
}

// Entry functions (innermost frame outside package runtime) of the waits
// whose resumptions idleWakeups counts.
const (
	idleActorWait  = "github.com/FrankoonG/rendr/v2/internal/session.(*actor).run"
	idleWriterWait = "github.com/FrankoonG/rendr/v2/internal/carrier.(*Conn).dgSleep"
)

// idleWakeups returns how often goroutines resumed from a blocking wait
// whose innermost non-runtime frame is fn, as recorded by the block profile
// (cumulative, process-wide: the package's tests do not run in parallel).
func idleWakeups(fn string) int64 {
	var recs []runtime.BlockProfileRecord
	for {
		n, _ := runtime.BlockProfile(nil)
		recs = make([]runtime.BlockProfileRecord, n+64)
		if n, ok := runtime.BlockProfile(recs); ok {
			recs = recs[:n]
			break
		}
	}
	var total int64
	for _, r := range recs {
		frames := runtime.CallersFrames(r.Stack())
		for {
			f, more := frames.Next()
			if !strings.HasPrefix(f.Function, "runtime.") {
				if f.Function == fn {
					total += r.Count
				}
				break
			}
			if !more {
				break
			}
		}
	}
	return total
}
