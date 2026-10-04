package lessons4

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Frame-level faults (L42, L43). Every scenario uses one carrier factory
// (no probe carrier), so one-shot frame controls can only touch the
// session's carrier; the session recovers by redialling that factory.

// singleWorld is a world with one link "a" (2 ms one-way, 16 MiB/s) and
// one session over it.
func singleWorld(t *testing.T, o worldOpts) (w *world, l *rendrtest.Link, dc, pc *rendr.Conn) {
	w = newWorld(t, o, "a")
	l = w.link("a")
	l.SetDelay(2*time.Millisecond, 0)
	l.SetRate(16 << 20)
	dc, pc = w.open(w.peer(nil, l), rendr.DialOptions{})
	return w, l, dc, pc
}

// sessionTap returns the passive end's tap of the link's first session
// carrier (its first frame was OPEN).
func sessionTap(t *testing.T, w *world) *tapConn {
	t.Helper()
	for _, c := range w.taps.all("") {
		if fr := c.snapshot(); fr.count[wire.TypeOpen] > 0 {
			return c
		}
	}
	t.Fatal("no tapped session carrier")
	return nil
}

// TestKillMidFrameExactlyOnce_L42: a carrier dies halfway through a frame
// — "write": the dialer's carrier Write transmits half a batch, ending
// inside a DATA frame, and fails; "kill": the path is cut while the
// passive's reader holds part of a frame —; the partial frame is never
// handed over, the session replays from the acknowledged front on a new
// carrier, and every byte reaches the application exactly once: the reader
// verifies the exact PRNG stream byte by byte (a lost, duplicated or
// zero-filled byte fails it) and requires io.EOF right after the last
// byte. The session's byte counters must agree (a sanity check: they count
// committed, in-order and read bytes, so they cannot see a duplicate).
func TestKillMidFrameExactlyOnce_L42(t *testing.T) {
	for _, mode := range []string{"write", "kill"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { killMidFrame(t, mode == "kill") })
		})
	}
}

// cutWatch is a dialer carrier conn of the "write" variant: for the one
// batch whose Write is scripted to fail halfway (flagged by BeforeWrite on
// the same writer goroutine just before), it records whether the cut lands
// strictly inside a DATA frame of that batch.
type cutWatch struct {
	net.Conn
	next   *atomic.Bool
	inside *atomic.Int32 // 1: inside a DATA frame; 2: not
}

func (c *cutWatch) Write(p []byte) (int, error) {
	if c.next.CompareAndSwap(true, false) {
		v := int32(2)
		if dataFrameAt(p, len(p)/2-1000) {
			v = 1
		}
		c.inside.Store(v)
	}
	return c.Conn.Write(p)
}

// dataFrameAt reports whether byte cut of a batch of whole frames lies
// strictly inside a DATA frame: after its first byte, before its last.
func dataFrameAt(b []byte, cut int) bool {
	for off := 0; off+wire.HeaderLen <= len(b); {
		h, err := wire.ParseHeader(b[off:])
		if err != nil {
			return false
		}
		end := off + wire.HeaderLen + int(h.Len) + wire.TrailerLen
		if cut < end {
			return h.Type == wire.TypeData && cut > off
		}
		off = end
	}
	return false
}

func killMidFrame(t *testing.T, kill bool) {
	n := int64(16 << 20)
	if raceEnabled {
		n = 6 << 20
	}
	var armed, next atomic.Bool
	var inside atomic.Int32
	var link atomic.Pointer[rendrtest.Link]
	hooks := &testhooks.Hooks{BeforeWrite: func(_ uint32, _, bytes int) {
		// The next physical write of a batch of at least two DATA frames
		// transmits up to 1000 bytes before its middle and fails.
		if bytes >= 128<<10 && armed.CompareAndSwap(true, false) {
			next.Store(true)
			link.Load().ScriptWrites(rendrtest.Up, rendrtest.WriteResult{N: -(bytes/2 + 1000), Relative: true, Transmit: true, Err: errInjected})
		}
	}}
	w := newWorld(t, worldOpts{tap: true, dHooks: hooks}, "a")
	l := w.link("a")
	l.SetDelay(2*time.Millisecond, 0)
	l.SetRate(16 << 20)
	link.Store(l)
	wrap := func(_ string, c net.Conn) net.Conn { return &cutWatch{Conn: c, next: &next, inside: &inside} }
	dc, pc := w.open(w.peer(wrap, l), rendr.DialOptions{})
	f := startFlow(dc, pc, n, 42, flowOpts{closeWrite: true, eof: true})
	waitFor(t, time.Minute, "30% delivered", func() bool { return f.got.Load() >= n*3/10 })
	tap := sessionTap(t, w)

	if kill {
		// Cut the path while the passive's reader holds part of a frame.
		waitFor(t, 5*time.Second, "a partial frame at the passive's reader", func() bool { return tap.snapshot().midFrame() })
		l.Kill()
		if fr := tap.snapshot(); !fr.midFrame() {
			t.Fatalf("the passive's reader of the cut carrier was not inside a frame: %+v", fr)
		}
	} else {
		// The writer stops inside a frame: the bytes it handed over before
		// the failure end strictly inside a DATA frame of the batch (the
		// link may still lose them with the carrier).
		armed.Store(true)
		waitFor(t, 5*time.Second, "the scripted half write", func() bool { return l.Stats().Session.WritesScripted == 1 })
		if v := inside.Load(); v != 1 {
			t.Fatalf("the scripted write did not end inside a DATA frame (%d)", v)
		}
	}
	waitFor(t, 5*time.Second, "the cut carrier's end at the passive", func() bool { return len(deadOf(pc.Status())) == 1 })
	// Exactly once: the PRNG verifier saw every byte once, in order, then EOF.
	f.wait(t, time.Minute, "exactly-once delivery across the cut (PRNG stream, then EOF)")
	waitFor(t, 5*time.Second, "the last ACK and the passive's death migration", func() bool {
		return dc.Status().AckedBytes == uint64(n) && pc.Status().Migrations.Death == 1
	})

	ds, ps := dc.Status(), pc.Status()
	if ps.RxBytes != uint64(n) || ps.DeliveredBytes != uint64(n) || ds.AckedBytes != uint64(n) || ds.TxBytes != uint64(n) {
		t.Fatalf("counters disagree with the verified stream (sanity check): dialer tx %d acked %d, passive rx %d delivered %d; want %d each",
			ds.TxBytes, ds.AckedBytes, ps.RxBytes, ps.DeliveredBytes, n)
	}
	if ds.RetransmittedBytes == 0 || ds.Migrations.Death != 1 || ps.Migrations.Death != 1 {
		t.Fatalf("no replay after the cut: retransmitted %d, migrations %+v / %+v", ds.RetransmittedBytes, ds.Migrations, ps.Migrations)
	}
	if d := deadOf(ds); len(d) != 1 || d[0].DeathCause != rendr.CauseTransportError {
		t.Fatalf("dialer dead carriers %+v, want one transport_error", d)
	}
	if d := deadOf(ps); len(d) != 1 || d[0].DeathCause != rendr.CauseTransportError {
		t.Fatalf("passive dead carriers %+v, want one transport_error", d)
	}
	if kill && l.Stats().Session.BufferLost == 0 {
		t.Fatal("the cut lost no byte in flight (stimulus)")
	}
	endClean(t, dc, pc)
	w.close()
}

// TestCorruptionKillsOnlyCarrier_L43: one damaged frame — its fseq
// (header), a payload bit, or its CRC trailer — of each kind of session
// and carrier frame (DATA and FIN of the dialer, ACK and PONG of the
// passive) kills exactly the carrier that delivered it, as a
// protocol_violation of the receiving end that names the check (fseq or
// crc); the session survives on a redialled carrier, both ends count the
// same single death migration, and the stream (and its FIN) arrives intact.
func TestCorruptionKillsOnlyCarrier_L43(t *testing.T) {
	frames := []struct {
		name string
		dir  rendrtest.Dir
		typ  rendrtest.FrameType
	}{
		{"DATA", rendrtest.Up, rendrtest.FrameData},
		{"ACK", rendrtest.Down, rendrtest.FrameAck},
		{"FIN", rendrtest.Up, rendrtest.FrameFin},
		{"PONG", rendrtest.Down, rendrtest.FramePong},
	}
	modes := []struct {
		name  string
		mode  rendrtest.CorruptMode
		check string
	}{
		{"header", rendrtest.CorruptHeader, "fseq"},
		{"payload", rendrtest.CorruptPayload, "crc mismatch"},
		{"trailer", rendrtest.CorruptTrailer, "crc mismatch"},
	}
	for _, fr := range frames {
		for _, m := range modes {
			t.Run(fr.name+"/"+m.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) { corruptOne(t, fr.dir, fr.typ, m.mode, m.check) })
			})
		}
	}
}

func corruptOne(t *testing.T, dir rendrtest.Dir, typ rendrtest.FrameType, mode rendrtest.CorruptMode, check string) {
	const n = 4 << 20
	w, l, dc, pc := singleWorld(t, worldOpts{})
	if typ == rendrtest.FrameFin {
		l.CorruptNextFrame(dir, typ, mode) // the FIN follows every DATA byte
	}
	f := startFlow(dc, pc, n, 43, flowOpts{closeWrite: true, eof: true})
	if typ != rendrtest.FrameFin {
		waitFor(t, time.Minute, "25% delivered", func() bool { return f.got.Load() >= n/4 })
		l.CorruptNextFrame(dir, typ, mode)
	}
	f.wait(t, time.Minute, "transfer across the damaged frame")
	if c := l.Stats().Session.FramesCorrupted; c != 1 {
		t.Fatalf("frames corrupted: %d, want 1 (stimulus)", c)
	}
	// The receiving end of the damaged frame killed its carrier; the other
	// end saw that carrier's end.
	recv, other := pc, dc
	if dir == rendrtest.Down {
		recv, other = dc, pc
	}
	waitFor(t, 5*time.Second, "both ends' death steps", func() bool {
		return len(deadOf(recv.Status())) == 1 && len(deadOf(other.Status())) == 1
	})
	// Both ends count the death once the dialer's SCHED reached the passive.
	waitFor(t, 5*time.Second, "both ends' death migration", func() bool {
		return recv.Status().Migrations.Death == 1 && other.Status().Migrations.Death == 1
	})
	rs, os := recv.Status(), other.Status()
	d := deadOf(rs)[0]
	if d.DeathCause != rendr.CauseProtocolViolation || !strings.Contains(d.DeathDetail, check) {
		t.Fatalf("%v: the damaged frame's carrier died of %v %q, want protocol_violation naming %q", rs.Role, d.DeathCause, d.DeathDetail, check)
	}
	if o := deadOf(os)[0]; o.ID != d.ID || o.DeathCause != rendr.CauseTransportError {
		t.Fatalf("%v: dead carrier %+v, want %d ended by its peer (transport_error)", os.Role, o, d.ID)
	}
	for _, s := range []rendr.SessionStatus{rs, os} {
		if s.Migrations != (rendr.MigrationCounts{Death: 1}) || s.State != rendr.StateOpen || len(dataCarriers(s)) != 1 {
			t.Fatalf("%v after the damaged frame: %+v", s.Role, s)
		}
	}
	endClean(t, dc, pc)
	w.close()
}

// TestDroppedFrameFseq_L43: a frame that vanishes inside a carrier — DATA
// of the dialer, ACK or PONG of the passive — leaves a gap in the frame
// sequence; the receiving end kills exactly that carrier at the next
// frame (protocol_violation "fseq"), and the session replays from the
// acknowledged front on a new carrier with every byte intact.
func TestDroppedFrameFseq_L43(t *testing.T) {
	for _, c := range []struct {
		name string
		dir  rendrtest.Dir
		typ  rendrtest.FrameType
	}{
		{"DATA", rendrtest.Up, rendrtest.FrameData},
		{"ACK", rendrtest.Down, rendrtest.FrameAck},
		{"PONG", rendrtest.Down, rendrtest.FramePong},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const n = 4 << 20
				w, l, dc, pc := singleWorld(t, worldOpts{})
				f := startFlow(dc, pc, n, 431, flowOpts{closeWrite: true, eof: true})
				waitFor(t, time.Minute, "25% delivered", func() bool { return f.got.Load() >= n/4 })
				l.DropNextFrame(c.dir, c.typ)
				f.wait(t, time.Minute, "transfer across the dropped frame")
				if d := l.Stats().Session.FramesDropped; d != 1 {
					t.Fatalf("frames dropped: %d, want 1 (stimulus)", d)
				}
				recv := pc
				if c.dir == rendrtest.Down {
					recv = dc
				}
				waitFor(t, 5*time.Second, "the receiving end's death step", func() bool { return len(deadOf(recv.Status())) == 1 })
				d := deadOf(recv.Status())[0]
				if d.DeathCause != rendr.CauseProtocolViolation || !strings.Contains(d.DeathDetail, "fseq") {
					t.Fatalf("the gapped carrier died of %v %q, want protocol_violation fseq", d.DeathCause, d.DeathDetail)
				}
				if c.typ == rendrtest.FrameData {
					if ds := dc.Status(); ds.RetransmittedBytes == 0 {
						t.Fatal("the dropped DATA was never replayed")
					}
				}
				waitFor(t, 5*time.Second, "both ends' death migration", func() bool {
					return dc.Status().Migrations.Death == 1 && pc.Status().Migrations.Death == 1
				})
				for _, s := range []rendr.SessionStatus{dc.Status(), pc.Status()} {
					if len(deadOf(s)) != 1 || s.Migrations != (rendr.MigrationCounts{Death: 1}) {
						t.Fatalf("%v: %+v, want exactly one dead carrier and one death migration", s.Role, s)
					}
				}
				endClean(t, dc, pc)
				w.close()
			})
		})
	}
}

// TestSplicedSessionsKilled_L43: a frame captured on session X's carrier
// is spliced, byte for byte, into session Y's carrier (a misbehaving
// relay): its fseq and CRC belong to another carrier, so Y's receiving end
// must kill Y's carrier (protocol_violation) and only that one; X's
// carrier lives on untouched, Y recovers on a new carrier, and both streams
// arrive intact. "lockstep": X and Y are identical sessions moving the
// same volume side by side and X's next DATA frame is spliced into Y
// (their carriers are at the same frame index); "offset": X's first DATA
// frame is spliced into Y once Y is many frames further. (The lockstep
// splice is the hard case: every M1 session uses handle 1 and the CRC32C
// covers only the frame, so only a per-carrier binding of the frames can
// tell X's frame from Y's own — each carrier direction numbers its frames
// from its own preface's CRC field, design §0.13 A6.)
func TestSplicedSessionsKilled_L43(t *testing.T) {
	for _, mode := range []string{"lockstep", "offset"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { splice(t, mode == "offset") })
		})
	}
}

func splice(t *testing.T, offset bool) {
	const n = 8 << 20
	w := newWorld(t, worldOpts{}, "x", "y")
	lx, ly := w.link("x"), w.link("y")
	for _, l := range []*rendrtest.Link{lx, ly} {
		l.SetDelay(2*time.Millisecond, 0)
		l.SetRate(16 << 20)
	}
	xd, xp := w.open(w.peer(nil, lx), rendr.DialOptions{})
	yd, yp := w.open(w.peer(nil, ly), rendr.DialOptions{})
	capture := func() []byte {
		select {
		case raw := <-lx.CaptureNextFrame(rendrtest.Up, rendrtest.FrameData):
			return raw
		case <-time.After(5 * time.Second):
			t.Fatal("no DATA frame captured on X")
			return nil
		}
	}
	var raw []byte
	var fx, fy *flow
	if offset {
		cp := lx.CaptureNextFrame(rendrtest.Up, rendrtest.FrameData)
		fx = startFlow(xd, xp, n, 4310, flowOpts{closeWrite: true, eof: true})
		raw = <-cp
		fy = startFlow(yd, yp, n, 4311, flowOpts{closeWrite: true, eof: true})
		waitFor(t, time.Minute, "25% delivered on Y", func() bool { return fy.got.Load() >= n/4 })
	} else {
		fx = startFlow(xd, xp, n, 4310, flowOpts{closeWrite: true, eof: true})
		fy = startFlow(yd, yp, n, 4311, flowOpts{closeWrite: true, eof: true})
		waitFor(t, time.Minute, "25% delivered on both", func() bool { return fx.got.Load() >= n/4 && fy.got.Load() >= n/4 })
		raw = capture()
	}
	h, err := wire.ParseHeader(raw)
	if err != nil || h.Type != wire.TypeData {
		t.Fatalf("captured %v (%v)", h, err)
	}
	ly.InjectRaw(rendrtest.Up, raw)
	waitFor(t, 5*time.Second, "the splice into Y's carrier", func() bool { return ly.Stats().Session.FramesInjected > 0 })
	if c, i := lx.Stats().Session.FramesCaptured, ly.Stats().Session.FramesInjected; c != 1 || i != 1 {
		t.Fatalf("captured %d on X, injected %d into Y; want 1 and 1 (stimulus)", c, i)
	}
	fx.wait(t, time.Minute, "X")
	fy.wait(t, time.Minute, "Y, with X's DATA frame (fseq "+itoa(h.Fseq)+") spliced into its carrier")
	waitFor(t, 5*time.Second, "Y's death steps and migrations", func() bool {
		return len(deadOf(yp.Status())) == 1 && len(deadOf(yd.Status())) == 1 &&
			yd.Status().Migrations.Death == 1 && yp.Status().Migrations.Death == 1
	})
	if d := deadOf(yp.Status())[0]; d.DeathCause != rendr.CauseProtocolViolation {
		t.Fatalf("Y's spliced carrier died of %v %q, want protocol_violation", d.DeathCause, d.DeathDetail)
	}
	for _, s := range []rendr.SessionStatus{xd.Status(), xp.Status()} {
		if d := deadOf(s); len(d) != 0 || s.Migrations != (rendr.MigrationCounts{}) {
			t.Fatalf("X (%v) was touched by Y's splice: dead %+v, migrations %+v", s.Role, d, s.Migrations)
		}
	}
	for _, s := range []rendr.SessionStatus{yd.Status(), yp.Status()} {
		if s.Migrations != (rendr.MigrationCounts{Death: 1}) || len(dataCarriers(s)) != 1 {
			t.Fatalf("Y (%v) did not recover once: %+v", s.Role, s)
		}
	}
	endClean(t, xd, xp)
	endClean(t, yd, yp)
	w.close()
}

// itoa formats a frame sequence number for messages.
func itoa(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

// dataInFlight returns the DATA bytes the dialer's active carrier sent
// that the passive has not received on it yet (0 without an active carrier
// on both ends).
func dataInFlight(dc, pc *rendr.Conn) int64 {
	a, ok := activeOf(dc.Status())
	if !ok {
		return 0
	}
	b, ok := carrierOf(pc.Status(), a.ID)
	if !ok {
		return 0
	}
	return int64(a.TxBytes) - int64(b.RxBytes)
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

// TestEmbedderMutatesAfterWrite_L43: what was handed to a Write is never
// the retransmission source. "app": the application zeroes its buffer as
// soon as Conn.Write returned; "conn": the carrier conn zeroes the batch
// buffer rendr passed to its Write right after the Write. The path is then
// cut with bytes in flight, so the session must replay them from its own
// send buffer: the replay is exact and the stream arrives intact.
func TestEmbedderMutatesAfterWrite_L43(t *testing.T) {
	for _, who := range []string{"app", "conn"} {
		t.Run(who, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := int64(16 << 20)
				if raceEnabled {
					n = 6 << 20
				}
				var zeroed atomic.Int64
				w := newWorld(t, worldOpts{}, "a")
				l := w.link("a")
				l.SetDelay(2*time.Millisecond, 0)
				l.SetRate(16 << 20)
				var wrap dialWrap
				if who == "conn" {
					wrap = func(_ string, c net.Conn) net.Conn { return &zeroingConn{Conn: c, zeroed: &zeroed} }
				}
				dc, pc := w.open(w.peer(wrap, l), rendr.DialOptions{})
				f := startFlow(dc, pc, n, 432, flowOpts{closeWrite: true, eof: true, clearAfter: who == "app"})
				waitFor(t, time.Minute, "40% delivered with DATA in flight", func() bool {
					return f.got.Load() >= n*4/10 && dataInFlight(dc, pc) >= 64<<10
				})
				l.Kill()
				f.wait(t, time.Minute, "transfer across the cut")
				ds := dc.Status()
				if ds.RetransmittedBytes == 0 || l.Stats().Session.BufferLost == 0 {
					t.Fatalf("no replay of lost bytes: retransmitted %d, lost %d (stimulus)", ds.RetransmittedBytes, l.Stats().Session.BufferLost)
				}
				if who == "conn" && zeroed.Load() < n/2 {
					t.Fatalf("the conn zeroed only %d bytes (stimulus)", zeroed.Load())
				}
				if d := deadOf(pc.Status()); len(d) != 1 || d[0].DeathCause != rendr.CauseTransportError {
					t.Fatalf("passive dead carriers %+v: a mutated retransmission source would be a conflicting duplicate", d)
				}
				endClean(t, dc, pc)
				w.close()
			})
		})
	}
}
