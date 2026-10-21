package mux

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// idleEnds tallies how the sessions of one end of TestMuxDgramIdleEndReachesPeer_L30
// ended, with the instant of each end.
type idleEnds struct {
	mu    sync.Mutex
	kinds map[string]int
	at    map[string]time.Time // by session key
}

func newIdleEnds() *idleEnds {
	return &idleEnds{kinds: map[string]int{}, at: map[string]time.Time{}}
}

// add records session key's end err under its kind.
func (e *idleEnds) add(key string, err error) {
	var ae *rendr.AbortError
	k := "other: " + fmt.Sprint(err)
	switch {
	case errors.Is(err, rendr.ErrIdleTimeout):
		k = "ErrIdleTimeout"
	case errors.As(err, &ae) && ae.Code == rendr.AbortIdle && ae.Remote:
		k = "AbortIdle"
	case errors.Is(err, rendr.ErrNoPath):
		k = "ErrNoPath"
	case errors.Is(err, rendr.ErrSessionLost):
		k = "ErrSessionLost"
	}
	e.mu.Lock()
	e.kinds[k]++
	e.at[key] = time.Now()
	e.mu.Unlock()
}

func (e *idleEnds) count(kind string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.kinds[kind]
}

func (e *idleEnds) total() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.at)
}

func (e *idleEnds) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return fmt.Sprint(e.kinds)
}

// dgIdleArms are TestMuxDgramIdleEndReachesPeer_L30's arms: the datagram
// trunk arms (the defect) and the stream-trunk control arms, each with the
// dialer or the passive idling.
var dgIdleArms = []struct {
	name    string
	dgram   bool
	idler   int // 0 the dialer's Config.IdleTimeout, 1 the passive's
	viewCap int // the trunk kind's view cap (MuxMaxViewsDatagram, MuxMaxViews)
}{
	{"datagram/dialer-idles", true, 0, 64},
	{"datagram/passive-idles", true, 1, 64},
	{"stream/dialer-idles", false, 0, 256},
	{"stream/passive-idles", false, 1, 256},
}

// dgIdleSize is the number of sessions an arm of
// TestMuxDgramIdleEndReachesPeer_L30 opens at 500/s: 2,000 (the decision's
// row) in the datagram arms in every lane; the stream-trunk control arms
// run 500 under the race detector (M3 R1-11: the same criteria on a
// smaller volume, for the race lane's budget) and 2,000 elsewhere
// (TestMuxDgramIdleLaneSize).
func dgIdleSize(dgram, race bool) int {
	if dgram || !race {
		return 2000
	}
	return 500
}

// TestMuxDgramIdleLaneSize checks dgIdleSize's selection against the
// binary's lane, read from its build information (raceBuild), as
// TestRaceLaneSubtests does for bulkLinks.
func TestMuxDgramIdleLaneSize(t *testing.T) {
	race := raceBuild(t)
	if raceEnabled != race {
		t.Fatalf("raceEnabled is %v in a binary built with -race=%v: the race switch is inverted", raceEnabled, race)
	}
	want := 2000
	if race {
		want = 500
	}
	if got := dgIdleSize(false, raceEnabled); got != want {
		t.Errorf("the stream control arms open %d sessions in this lane (race %v), want %d", got, race, want)
	}
	if got := dgIdleSize(true, raceEnabled); got != 2000 {
		t.Errorf("the datagram arms open %d sessions in this lane (race %v), want 2,000", got, race)
	}
}

// TestMuxDgramIdleEndReachesPeer_L30 (L30; M3-D6, §A5.5; the m6-design
// decision on core defect A, 2026-10-21; I1's F3): an idle end crosses a
// shared trunk whatever the number of views that end together. 2,000 packet
// sessions are opened at 500/s over one factory, one datagram each way, and
// one Runtime's Config.IdleTimeout (10 s) ends every one of them 10 s after
// its exchange — on a datagram trunk 64 views share an 8-frame REL window,
// so the ends of one trunk's views (each an RST, then a DETACH) come faster
// than one RTT drains them. Every end must reach the peer as the idler's
// RST: the peer ends *AbortError{AbortIdle, Remote} within a second, never
// ErrNoPath at NoPathGrace (the RST lost and the DETACH or the trunk's
// CLOSE taken for a carrier loss) nor ErrSessionLost (the dialer's JOIN
// after the lane left, answered UNKNOWN_SESSION). The stream-trunk arms are
// the control: the same load on stream MUX trunks (no REL window).
//
// Premise: one factory call per trunk the load needs (⌈sessions / the view
// cap⌉: views of 64 on a datagram trunk, 256 on a stream trunk) and every
// session echoed. Under the race detector the stream arms open 500
// sessions (dgIdleSize).
// Stimulus: every session's last datagram is its echo; the idler's ends
// come at 500/s, 10 s after the exchanges.
// PASS: the idler ends every session ErrIdleTimeout; the peer ends every one
// AbortIdle (0 ErrNoPath, 0 ErrSessionLost), each within 1 s of its idler's
// end; one second after the last end neither Runtime holds a session (none
// orphaned) and every trunk closed at its last view; nothing is left after
// Close.
func TestMuxDgramIdleEndReachesPeer_L30(t *testing.T) {
	const (
		rate = 500
		idle = 10 * time.Second
	)
	for _, arm := range dgIdleArms {
		n := dgIdleSize(arm.dgram, raceEnabled)
		trunks := (n + arm.viewCap - 1) / arm.viewCap
		t.Run(arm.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lim := rendr.HandshakeLimits{MaxConcurrent: 4096}
				o := worldOpts{dcfg: rendr.Config{Handshake: lim}, pcfg: rendr.Config{Handshake: lim}}
				if arm.idler == 0 {
					o.dcfg.IdleTimeout = idle
				} else {
					o.pcfg.IdleTimeout = idle
				}
				w := newWorld(t, o, linkSpec{name: "u", oneWay: 5 * time.Millisecond, dgram: arm.dgram})
				peer := w.peer("u")
				ends := [2]*idleEnds{newIdleEnds(), newIdleEnds()}
				var wg sync.WaitGroup
				start := time.Now()
				for i := range n {
					sleepUntil(start.Add(time.Duration(i) * time.Second / rate))
					key := "i" + strconv.Itoa(i)
					wg.Go(func() {
						dc, err := peer.DialPacket(context.Background(), rendr.DialOptions{Metadata: []byte(key)})
						if err != nil {
							t.Errorf("DialPacket %s: %v", key, err)
							return
						}
						defer dc.Close()
						pc := <-w.packetCh(key)
						wg.Go(func() { // the passive: echo once, then wait for the end
							defer pc.Close()
							b := make([]byte, 2048)
							k, _, err := pc.ReadFrom(b)
							if err != nil {
								t.Errorf("passive %s: %v", key, err)
								return
							}
							if _, err := pc.WriteTo(b[:k], nil); err != nil {
								t.Errorf("passive %s echo: %v", key, err)
								return
							}
							_, _, err = pc.ReadFrom(b)
							ends[1].add(key, err)
						})
						if _, err := dc.WriteTo([]byte(key), nil); err != nil {
							t.Errorf("dialer %s: %v", key, err)
							return
						}
						b := make([]byte, 2048)
						dc.SetReadDeadline(time.Now().Add(2 * time.Second))
						if _, _, err := dc.ReadFrom(b); err != nil {
							t.Errorf("premise: %s not echoed: %v", key, err)
							return
						}
						dc.SetReadDeadline(time.Time{})
						_, _, err = dc.ReadFrom(b)
						ends[0].add(key, err)
					})
				}
				if t.Failed() {
					t.FailNow()
				}
				idler, peerEnd := ends[arm.idler], ends[1-arm.idler]
				waitFor(t, time.Since(start)+idle+5*time.Second, "every idler end", func() bool { return idler.total() == n })
				last := time.Now()
				// Wait past NoPathGrace (15 s) for the peer ends, so that a lost
				// end shows how it ended; the bound is judged per session below.
				for deadline := last.Add(20 * time.Second); peerEnd.total() < n && time.Now().Before(deadline); {
					time.Sleep(10 * time.Millisecond)
				}
				sleepUntil(last.Add(time.Second))
				t.Logf("%s: idler %s; peer %s; trunks dialled %d", arm.name, idler, peerEnd, w.dials("u"))
				if got := idler.count("ErrIdleTimeout"); got != n {
					t.Fatalf("stimulus: %d of %d idler ends ErrIdleTimeout: %s", got, n, idler)
				}
				if d := w.dials("u"); d != trunks {
					t.Errorf("premise: %d trunks dialled for %d sessions, want %d", d, n, trunks)
				}
				if got := peerEnd.count("AbortIdle"); got != n || peerEnd.total() != n {
					t.Fatalf("L30: %d of %d peer sessions ended AbortIdle (ErrNoPath %d, ErrSessionLost %d): %s",
						got, n, peerEnd.count("ErrNoPath"), peerEnd.count("ErrSessionLost"), peerEnd)
				}
				for key, at := range idler.at {
					if p := peerEnd.at[key]; p.Sub(at) > time.Second {
						t.Fatalf("L30: %s's peer ended %v after its idler", key, p.Sub(at))
					}
				}
				// Every peer ended within 1 s of its idler, so 1 s after the
				// last end neither Runtime may hold a session.
				for i, rt := range []*rendr.Runtime{w.d, w.p} {
					if sc := rt.Status().Sessions; sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 {
						t.Fatalf("%s holds sessions 1 s after the last end: %+v", side(i), sc)
					}
				}
				w.muxIdle(5 * time.Second)
				w.noViolation()
				wg.Wait()
				w.close()
			})
		})
	}
}
