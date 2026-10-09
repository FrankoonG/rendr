package adversarial

import (
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Frame attacks on stream carriers: one Tamper operation on a carrier of a
// session that moves rowBytes dialer → passive. The receiving end of the
// attacked direction kills exactly that carrier (protocol_violation, the
// check the row names); the session replays from the ACK edge on its
// other or a redialled carrier, and the stream arrives byte for byte,
// once, up to io.EOF.

// rowBytes is what each session of a stream row moves dialer → passive.
func rowBytes() int64 {
	if raceEnabled {
		return 1 << 20
	}
	return 2 << 20
}

// streamAttack is one row's operation on a stream carrier.
type streamAttack struct {
	n    int64         // bytes per session (0: rowBytes)
	dir  rendrtest.Dir // the attacked direction: Up (the passive detects), Down (the dialer)
	typ  rendrtest.FrameType
	sch  bool                                // the frame is a SCHED: armed through schedTrigger
	arm  func(tm *rendrtest.Tamper, x *pair) // arms the operation on the picked carrier's tamper
	ops  func(tm *rendrtest.Tamper) int      // the stimulus counter of one tamper
	want []string                            // the receiving end's detail names one of these
}

// stat adapts a TamperStats counter to a stimulus counter.
func stat(f func(st rendrtest.TamperStats) int) func(tm *rendrtest.Tamper) int {
	return func(tm *rendrtest.Tamper) int { return f(tm.Stats()) }
}

// replays counts the replayed frames tm forwarded Up: frames whose index
// is below one forwarded before them. (Tamper.Stats counts a replay only
// once its write returned: a replayed frame that kills the carrier while
// the link still takes its bytes is in the Log, not in Replayed.)
func replays(tm *rendrtest.Tamper) int {
	k, top := 0, -1
	for _, r := range tm.Log(rendrtest.Up) {
		if r.Index < top {
			k++
		}
		top = max(top, r.Index)
	}
	return k
}

// fired sums the stimulus counter over every session tamper.
func (w *world) fired(count func(tm *rendrtest.Tamper) int) int {
	w.mu.Lock()
	rs := slices.Clone(w.tampers)
	w.mu.Unlock()
	k := 0
	for _, r := range rs {
		k += count(r.tm)
	}
	return k
}

// runStream runs attack a in setup s: s.sessions sessions on one Peer each
// move n bytes; at a quarter of the first session's transfer the
// operation is armed on the carrier the row picks (DATA and Up frames: the
// selector's active carrier or the member on "a"; ACK: the duty lane;
// SCHED: see schedTrigger); it must fire exactly once.
func runStream(t *testing.T, s setup, a streamAttack) {
	n := a.n
	if n == 0 {
		n = rowBytes()
	}
	w := newWorld(t, s, worldOpts{})
	peer := w.streamPeer()
	xs := make([]*pair, s.sessions)
	fs := make([]*sflow, s.sessions)
	for i := range xs {
		xs[i] = w.open(peer)
	}
	for i, x := range xs {
		fs[i] = startFlow(x.d, x.p, n, 4300+uint64(i))
	}
	x := xs[0]
	fs[0].reached(t, n/4, "a quarter of the transfer")
	deaths := uint64(1)
	switch {
	case a.sch:
		schedTrigger(t, w, x, func(tm *rendrtest.Tamper) { a.arm(tm, x) })
		deaths = 2
	case a.typ == rendrtest.FrameAck:
		a.arm(w.tamperOf(ackLane(t, w, x)), x)
	default:
		a.arm(w.tamperOf(target(t, s, x.d.Status())), x)
	}
	waitFor(t, 10*time.Second, "the operation (stimulus)", func() bool { return w.fired(a.ops) > 0 })
	w.disarm()
	hit := w.hit(t, a.ops)
	end := x.p
	if a.dir == rendrtest.Down {
		end = x.d
	}
	c := endDead(t, "the receiving end", end.Status, hit.id)
	violated(t, "the attacked carrier", c, a.want...)
	for i, f := range fs {
		f.wait(t, 2*time.Minute, fmt.Sprintf("session %d's transfer across the attack", i))
	}
	if k := w.fired(a.ops); k != 1 {
		t.Fatalf("the operation fired %d times, want once", k)
	}
	x.deathsAre(t, s, deaths)
	for _, x := range xs {
		x.endClean(t)
	}
	w.close()
}

// hit returns the session carrier whose tamper fired an operation (count);
// exactly one must have.
func (w *world) hit(t testing.TB, count func(tm *rendrtest.Tamper) int) *tamperRec {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	var out *tamperRec
	for _, r := range w.tampers {
		if count(r.tm) == 0 {
			continue
		}
		if out != nil {
			t.Fatalf("operations fired on carriers %d and %d", out.id, r.id)
		}
		out = r
	}
	if out == nil {
		t.Fatal("no operation fired")
	}
	return out
}

// ackLane returns the dialer carrier of x whose tamper forwards the
// passive's ACKs (the ACK duty lane): the one whose Down log gained the
// most ACK frames over 20 ms.
func ackLane(t testing.TB, w *world, x *pair) rendr.CarrierID {
	t.Helper()
	count := func(id rendr.CarrierID) int {
		k := 0
		for _, r := range w.tamperOf(id).Log(rendrtest.Down) {
			if r.Type == rendrtest.FrameAck {
				k++
			}
		}
		return k
	}
	lanes := liveOf(x.d.Status())
	before := make([]int, len(lanes))
	for i, c := range lanes {
		before[i] = count(c.ID)
	}
	time.Sleep(20 * time.Millisecond)
	best, gain := rendr.CarrierID(0), 0
	for i, c := range lanes {
		if g := count(c.ID) - before[i]; g > gain {
			best, gain = c.ID, g
		}
	}
	if best == 0 {
		t.Fatal("no carrier forwarded an ACK in 20 ms")
	}
	return best
}

// schedTrigger makes the dialer publish a SCHED on a carrier armed by arm.
// Bond and race: the member on "a" is armed and the members on "b" are
// killed (Link.Kill): the dialer publishes the shrunk member set on "a" at
// once. Selector: every session carrier dialled from now on is armed and
// the active carrier's link is killed: the failover carrier's first SCHED
// names it. Either way the attacked carrier is the second death of the
// row.
func schedTrigger(t testing.TB, w *world, x *pair, arm func(tm *rendrtest.Tamper)) {
	t.Helper()
	if w.s.members() {
		arm(w.tamperOf(target(t, w.s, x.d.Status())))
		if w.link("b").Kill() == 0 {
			t.Fatal("stimulus: no carrier on link b to kill")
		}
		return
	}
	var act string
	for _, c := range liveOf(x.d.Status()) {
		if c.State == rendr.CarrierActive {
			act = c.Name
		}
	}
	w.armNew(arm)
	if act == "" || w.link(act).Kill() == 0 {
		t.Fatalf("stimulus: no active carrier to kill (%q)", act)
	}
}

// TestAdvDroppedFrame_L43: DropFrame of one DATA (Up), one ACK (Down) and
// one SCHED (Up): the next frame shows the gap in the frame sequence, the
// receiving end kills that carrier (protocol_violation "fseq"), the
// session replays from the ACK edge and the stream arrives intact.
func TestAdvDroppedFrame_L43(t *testing.T) {
	for _, c := range []struct {
		name string
		dir  rendrtest.Dir
		typ  rendrtest.FrameType
	}{
		{"DATA", rendrtest.Up, rendrtest.FrameData},
		{"ACK", rendrtest.Down, rendrtest.FrameAck},
		{"SCHED", rendrtest.Up, rendrtest.FrameSched},
	} {
		t.Run(c.name, func(t *testing.T) {
			eachSetup(t, func(t *testing.T, s setup) {
				runStream(t, s, streamAttack{dir: c.dir, typ: c.typ, sch: c.typ == rendrtest.FrameSched,
					arm:  func(tm *rendrtest.Tamper, _ *pair) { tm.DropFrame(c.dir, rendrtest.NextOfType(c.typ)) },
					ops:  stat(func(st rendrtest.TamperStats) int { return st.Dropped }),
					want: []string{"fseq"}})
			})
		})
	}
}

// TestAdvDuplicatedFrame_L43: DuplicateFrame of a DATA (Up) and of an ACK
// (Down): the copy's fseq is not the next one, the receiving end kills
// the carrier (protocol_violation "fseq") and no byte is delivered twice
// (the verifier reads every byte once, in order).
func TestAdvDuplicatedFrame_L43(t *testing.T) {
	for _, c := range []struct {
		name string
		dir  rendrtest.Dir
		typ  rendrtest.FrameType
	}{
		{"DATA", rendrtest.Up, rendrtest.FrameData},
		{"ACK", rendrtest.Down, rendrtest.FrameAck},
	} {
		t.Run(c.name, func(t *testing.T) {
			eachSetup(t, func(t *testing.T, s setup) {
				runStream(t, s, streamAttack{dir: c.dir, typ: c.typ,
					arm:  func(tm *rendrtest.Tamper, _ *pair) { tm.DuplicateFrame(c.dir, rendrtest.NextOfType(c.typ)) },
					ops:  stat(func(st rendrtest.TamperStats) int { return st.Duplicated }),
					want: []string{"fseq"}})
			})
		})
	}
}

// TestAdvReplayedFrame_L43: ReplayFrame of a DATA frame re-sent 1 MiB of
// the carrier's frames later: its old fseq kills the carrier at the
// passive (protocol_violation "fseq") and nothing is delivered again.
func TestAdvReplayedFrame_L43(t *testing.T) {
	const later = 1 << 20
	// A bond member carries about half the stream: 1 MiB of its frames is
	// about 2 MiB of the stream, and the replay must still meet data in
	// flight (the same size under -race: the row is cheap).
	n := int64(6 << 20)
	eachSetup(t, func(t *testing.T, s setup) {
		runStream(t, s, streamAttack{n: n, dir: rendrtest.Up, typ: rendrtest.FrameData,
			arm: func(tm *rendrtest.Tamper, _ *pair) {
				// The frames that follow the replayed one up to 1 MiB, from
				// the carrier's frame sizes so far.
				log := tm.Log(rendrtest.Up)
				if len(log) < 2 {
					panic("no frames to size the replay distance")
				}
				first, last := log[0], log[len(log)-1]
				avg := (last.Off + int64(17+last.Len) - first.Off) / int64(len(log))
				tm.ReplayFrame(rendrtest.Up, rendrtest.NextOfType(rendrtest.FrameData), int(later/max(avg, 1))+1)
			},
			ops:  replays,
			want: []string{"fseq"}})
	})
}

// zeroingConn is an embedder carrier conn that scribbles over the buffer
// rendr handed to Write as soon as the Write returned (L43).
type zeroingConn struct {
	net.Conn
	zeroed *atomic.Int64
}

func (c *zeroingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	clear(p)
	c.zeroed.Add(int64(len(p)))
	return n, err
}

// TestAdvWriterBufferMutation_L43: every session carrier conn zeroes the
// buffer rendr passed to its Write right after the Write returned (the M1
// row, here in selector, bond and race sessions; the MUX half re-runs it
// on a shared trunk). At 40 % of the transfer the carriers that hold data
// in flight are cut — selector: the active carrier's link; bond: the
// member on "a"; race: both members, so that the session replays from the
// ACK edge instead of relying on the other member's copies —: the replay
// comes from rendr's own send buffer, so it is exact (a race copy compared
// with a mutated one would be a "race copy mismatch" violation), and the
// stream arrives intact.
func TestAdvWriterBufferMutation_L43(t *testing.T) {
	eachSetup(t, func(t *testing.T, s setup) {
		n := int64(4 << 20)
		if raceEnabled {
			n = 2 << 20
		}
		var zeroed atomic.Int64
		w := newWorld(t, s, worldOpts{wrap: func(_ string, c net.Conn) net.Conn { return &zeroingConn{Conn: c, zeroed: &zeroed} }})
		x := w.open(w.streamPeer())
		f := startFlow(x.d, x.p, n, 4303)
		f.reached(t, n*4/10, "40% delivered")
		cut, deaths := []string{"a"}, uint64(1)
		switch s.mode {
		case rendr.ModeSelector:
			for _, c := range liveOf(x.d.Status()) {
				if c.State == rendr.CarrierActive {
					cut = []string{c.Name}
				}
			}
		case rendr.ModeRace:
			cut, deaths = []string{"a", "b"}, 2
		}
		for _, name := range cut {
			if w.link(name).Kill() == 0 {
				t.Fatalf("stimulus: no carrier on link %s to cut", name)
			}
		}
		f.wait(t, 2*time.Minute, "the transfer across the cut")
		// The cut lost bytes in flight, and the stream still arrived
		// whole: they were sent again. Selector and bond count that
		// replay as retransmission; race re-places them on a new lane's
		// cursor (copies, M3-D35).
		var lost int64
		for _, name := range cut {
			lost += w.link(name).Stats().Session.BufferLost
		}
		if lost == 0 {
			t.Fatal("stimulus: the cut lost no byte in flight")
		}
		if ds := x.d.Status(); s.mode != rendr.ModeRace && ds.RetransmittedBytes == 0 {
			t.Fatal("stimulus: nothing was retransmitted after the cut")
		}
		if zeroed.Load() < n/2 {
			t.Fatalf("stimulus: the conns zeroed only %d bytes", zeroed.Load())
		}
		w.noViolation()
		x.deathsAre(t, s, deaths)
		x.endClean(t)
		w.close()
	})
}
