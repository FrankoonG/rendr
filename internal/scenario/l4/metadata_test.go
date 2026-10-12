package l4

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// recConn records every byte written to it.
type recConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recConn) Write(b []byte) (int, error) {
	n, err := r.Conn.Write(b)
	r.mu.Lock()
	r.buf.Write(b[:n])
	r.mu.Unlock()
	return n, err
}

// bytes returns a copy of what was written.
func (r *recConn) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf.Bytes())
}

// tapped is one carrier between the Link and the Listener: a Tamper that
// forwards it unchanged and logs its frames, and the bytes it forwarded
// in each direction.
type tapped struct {
	link     string
	tm       *rendrtest.Tamper
	up, down *recConn // Up: written toward the Listener; Down: toward the dialer
}

// TestL4MetadataOnlyInOpen_L37 (L37; M4-D23, M4-D26): the destination
// travels only in the OPEN, never in a JOIN, a migration or a retry. Two
// Links p1, p2 (default Props), every carrier passing a rendrtest.Tamper
// that logs its frames and a recorder of every byte it forwards both ways.
// One L4 session to an echo target with a distinctive 30-byte host name
// echoes 2 MiB each way (512 KiB under -race), paced over 4 s.
//
// Stimulus: the Link carrying the session's data is killed at +1 s, +2 s
// and +3 s; each kill must end a session carrier, the dialer counts ≥ 3
// death migrations, and the tampers logged ≥ 3 JOIN frames after the one
// OPEN.
//
// PASS: across every carrier and both directions the host name's bytes
// appear exactly once on the wire, inside the session's one OPEN frame
// (between that frame's offset and the next frame's); the echo is intact
// both ways (the destination's integrity: the target saw one connection
// for that address); nothing left after Runtime.Close.
func TestL4MetadataOnlyInOpen_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const host = "echo-l37-destination-probe.test"
		size := int64(2 << 20)
		if raceEnabled {
			size = 512 << 10
		}
		var mu sync.Mutex
		var taps []*tapped
		accept := func(name string, c net.Conn, handle func(net.Conn) error) error {
			a, b := net.Pipe()
			tp := &tapped{link: name, up: &recConn{Conn: a}, down: &recConn{Conn: c}}
			tp.tm = rendrtest.NewTamper(tp.down, tp.up)
			mu.Lock()
			taps = append(taps, tp)
			mu.Unlock()
			return handle(b)
		}
		w := newWorld(t, worldOpts{accept: accept}, linkSpec{name: "p1", rate: 8 << 20}, linkSpec{name: "p2", rate: 8 << 20})
		w.onClose(func() {
			mu.Lock()
			defer mu.Unlock()
			for _, tp := range taps {
				tp.tm.Close()
			}
		})
		echo := w.target("echo", rendrtest.TargetEcho())
		in := w.mustIngress(w.peer("p1", "p2"), host+":443", rendr.DialOptions{}, 0)
		deaths0 := in.c.Status().Migrations.Death
		start := time.Now()
		e := startEcho(in, rendr.ModeSelector, 81, size, 4*time.Second)
		for k := 1; k <= 3; k++ {
			sleepUntil(start.Add(time.Duration(k) * time.Second))
			l, _ := w.activeLink(in.c, 5*time.Second)
			before := l.Stats().Session.Killed
			l.Kill()
			if l.Stats().Session.Killed == before {
				t.Fatalf("stimulus: kill %d of %s ended no session carrier", k, l.Name())
			}
		}
		e.finish(t, size)
		if d := in.c.Status().Migrations.Death - deaths0; d < 3 {
			t.Fatalf("stimulus: %d death migrations for 3 kills, want ≥ 3", d)
		}
		checkEchoTarget(t, echo, size, 81)
		if a := echo.Counts().Conns[0].Addr; a != host+":443" {
			t.Fatalf("the target was dialled for %q, want %q", a, host+":443")
		}
		in.cli.Close()
		w.shutdown() // every carrier closed: the recordings are final

		mu.Lock()
		defer mu.Unlock()
		opens, joins, found := 0, 0, 0
		for i, tp := range taps {
			for _, d := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
				rec, log := tp.up, tp.tm.Log(rendrtest.Up)
				if d == rendrtest.Down {
					rec, log = tp.down, tp.tm.Log(rendrtest.Down)
				}
				for _, f := range log {
					switch {
					case f.Type == rendrtest.FrameOpen && d == rendrtest.Up:
						opens++
					case f.Type == rendrtest.FrameJoin && d == rendrtest.Up:
						joins++
					}
				}
				raw := rec.bytes()
				for off := 0; ; {
					j := bytes.Index(raw[off:], []byte(host))
					if j < 0 {
						break
					}
					pos := int64(off + j)
					off += j + 1
					found++
					fr, ok := frameAt(log, pos)
					if d != rendrtest.Up || !ok || fr.Type != rendrtest.FrameOpen {
						t.Errorf("carrier %d (%s): the destination at byte %d of direction %v, in frame %+v (found %v), want only inside the OPEN",
							i, tp.link, pos, d, fr, ok)
					}
				}
			}
		}
		if opens != 1 || joins < 3 || found != 1 {
			t.Fatalf("%d OPEN and %d JOIN frames on %d carriers; the destination appeared %d times; want one OPEN, ≥ 3 JOINs, once",
				opens, joins, len(taps), found)
		}
		t.Logf("%d carriers tapped, 1 OPEN, %d JOINs; the destination once, in the OPEN", len(taps), joins)
		w.close()
	})
}

// frameAt returns the logged frame whose bytes hold stream offset pos:
// the last frame starting at or before pos (frames follow each other
// without a gap after the PREFACE).
func frameAt(log []rendrtest.FrameRec, pos int64) (rendrtest.FrameRec, bool) {
	for i := len(log) - 1; i >= 0; i-- {
		if int64(log[i].Off) <= pos {
			return log[i], true
		}
	}
	return rendrtest.FrameRec{}, false
}
